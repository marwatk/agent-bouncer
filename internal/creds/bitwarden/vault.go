package bitwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/marwatk/agent-bouncer/internal/paths"
)

// Account is one Bitwarden login. Vaults for the same email and server
// are unlocked once and shared by every credential that points at them.
type Account struct {
	Email string
	// Server is the vault base URL. Empty means bitwarden.com.
	// A self-hosted URL such as https://vault.example.com is used as-is.
	Server string
	// PasswordEnv, when set, is an environment variable holding the master
	// password. Otherwise the password is prompted once per process.
	PasswordEnv string
}

// Query selects one field of one item.
type Query struct {
	Account
	Item   string
	Folder string
	Field  string
}

// Options configure a Vaults set.
type Options struct {
	// StateDir stores the device id and refresh token (mode 0600).
	// The decrypted vault is never written.
	StateDir string
	Logf     func(string, ...any)
	Prompt   Prompter
}

// Vaults pulls and unlocks Bitwarden accounts. An unlocked vault stays in
// memory until the process exits; nothing relocks it.
type Vaults struct {
	stateDir string
	logf     func(string, ...any)
	prompt   Prompter
	api      *api

	mu    sync.Mutex
	slots map[string]*slot
}

type slot struct {
	mu    sync.Mutex
	vault *unlocked
}

type unlocked struct {
	entries []entry
}

type entry struct {
	id, name, folder string
	username         string
	hasUsername      bool
	password         string
	hasPassword      bool
	totp             string
	hasTotp          bool
	notes            string
	hasNotes         bool
	privateKey       string
	hasPrivateKey    bool
	publicKey        string
	hasPublicKey     bool
	fingerprint      string
	hasFingerprint   bool
	fields           map[string]string
}

type accountState struct {
	DeviceID     string `json:"device_id"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

var (
	globalMu sync.Mutex
	global   *Vaults
)

// Configure installs the process-wide vault set. The daemon calls this
// with its state directory before the first unlock. Later calls replace
// the set, which drops any vault already unlocked.
func Configure(opt Options) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = New(opt)
}

func current() *Vaults {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global == nil {
		global = New(Options{StateDir: paths.StateDir(), Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}})
	}
	return global
}

// Unlock syncs and unlocks each distinct account. Accounts already
// unlocked in this process are left as they are.
func Unlock(ctx context.Context, accounts []Account) error {
	return current().Unlock(ctx, accounts)
}

// Get returns one field from an item, unlocking that account on first use.
func Get(ctx context.Context, q Query) (string, error) {
	return current().Get(ctx, q)
}

// New returns a vault set that does not share process-wide state.
func New(opt Options) *Vaults {
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	prompt := opt.Prompt
	if prompt == nil {
		prompt = stdPrompter{}
	}
	return &Vaults{
		stateDir: opt.StateDir,
		logf:     logf,
		prompt:   prompt,
		api:      newAPI(nil),
		slots:    map[string]*slot{},
	}
}

// Unlock syncs and unlocks each distinct account.
func (v *Vaults) Unlock(ctx context.Context, accounts []Account) error {
	seen := map[string]Account{}
	var keys []string
	for _, a := range accounts {
		k, err := accountKey(a)
		if err != nil {
			return fmt.Errorf("bitwarden: %w", err)
		}
		if prev, ok := seen[k]; ok {
			if prev.PasswordEnv != "" && a.PasswordEnv != "" && prev.PasswordEnv != a.PasswordEnv {
				return fmt.Errorf("bitwarden account %s: conflicting password_env %q and %q", normalizeEmail(a.Email), prev.PasswordEnv, a.PasswordEnv)
			}
			if prev.PasswordEnv == "" && a.PasswordEnv != "" {
				prev.PasswordEnv = a.PasswordEnv
				seen[k] = prev
			}
			continue
		}
		seen[k] = a
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := v.ensure(ctx, seen[k]); err != nil {
			return err
		}
	}
	return nil
}

// Get returns one field from an item, unlocking that account on first use.
func (v *Vaults) Get(ctx context.Context, q Query) (string, error) {
	u, err := v.ensure(ctx, q.Account)
	if err != nil {
		return "", err
	}
	field := q.Field
	if field == "" {
		field = "password"
	}
	return u.lookup(q.Item, q.Folder, field)
}

func (v *Vaults) ensure(ctx context.Context, a Account) (*unlocked, error) {
	key, err := accountKey(a)
	if err != nil {
		return nil, fmt.Errorf("bitwarden: %w", err)
	}
	v.mu.Lock()
	s := v.slots[key]
	if s == nil {
		s = &slot{}
		v.slots[key] = s
	}
	v.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault != nil {
		return s.vault, nil
	}
	u, err := v.unlock(ctx, a)
	if err != nil {
		return nil, err
	}
	s.vault = u
	return u, nil
}

func accountKey(a Account) (string, error) {
	email := normalizeEmail(a.Email)
	if email == "" {
		return "", errors.New("email is empty")
	}
	apiBase, identityBase, err := endpoints(a.Server)
	if err != nil {
		return "", err
	}
	return email + "\n" + apiBase + "\n" + identityBase, nil
}

func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func (a Account) label() string {
	email := normalizeEmail(a.Email)
	if strings.TrimSpace(a.Server) == "" {
		return email
	}
	return email + " (" + strings.TrimRight(strings.TrimSpace(a.Server), "/") + ")"
}

func (v *Vaults) unlock(ctx context.Context, a Account) (*unlocked, error) {
	email := normalizeEmail(a.Email)
	apiBase, identityBase, err := endpoints(a.Server)
	if err != nil {
		return nil, fmt.Errorf("bitwarden: %w", err)
	}
	v.logf("bitwarden: unlocking vault for %s", a.label())
	kdf, err := v.api.prelogin(ctx, identityBase, email)
	if err != nil {
		return nil, fmt.Errorf("bitwarden: %w", err)
	}
	st := v.loadState(email, apiBase)
	if st.DeviceID == "" {
		id, err := newDeviceID()
		if err != nil {
			return nil, fmt.Errorf("bitwarden: %w", err)
		}
		st.DeviceID = id
		v.saveState(email, apiBase, st)
	}

	var synced *syncResult
	refresh := st.RefreshToken
	fromRefresh := false
	if refresh != "" {
		access, next, rerr := v.api.refresh(ctx, identityBase, refresh)
		if rerr == nil {
			// Persist a rotated token even if the password is still wrong.
			// Refresh does not reveal the vault.
			st.RefreshToken = next
			refresh = next
			v.saveState(email, apiBase, st)
			if s, serr := v.api.sync(ctx, apiBase, access); serr == nil {
				synced = s
				fromRefresh = true
			}
		}
	}

	attempts := 3
	if a.PasswordEnv != "" {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("bitwarden: %w", err)
		}
		pw, err := v.masterPassword(a)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: %w", err)
		}
		id, err := deriveIdentity(email, pw, kdf)
		if err != nil {
			return nil, fmt.Errorf("bitwarden: %w", err)
		}
		if synced == nil {
			access, next, lerr := v.login(ctx, identityBase, email, st.DeviceID, id)
			if lerr != nil {
				id.keys.clear()
				clear(id.passwordHash)
				if errors.Is(lerr, errBadPassword) && attempt < attempts {
					lastErr = lerr
					v.logf("bitwarden: %s (attempt %d/%d)", lerr.Error(), attempt, attempts)
					continue
				}
				return nil, fmt.Errorf("bitwarden: %w", lerr)
			}
			s, serr := v.api.sync(ctx, apiBase, access)
			if serr != nil {
				id.keys.clear()
				clear(id.passwordHash)
				return nil, fmt.Errorf("bitwarden: %w", serr)
			}
			synced = s
			refresh = next
			fromRefresh = false
		}
		opened, oerr := openVault(id.keys, synced)
		id.keys.clear()
		clear(id.passwordHash)
		if oerr != nil {
			if fromRefresh && errors.Is(oerr, errBadMAC) && attempt < attempts {
				lastErr = errBadPassword
				v.logf("bitwarden: incorrect master password for %s (attempt %d/%d)", a.label(), attempt, attempts)
				continue
			}
			if errors.Is(oerr, errBadMAC) {
				return nil, fmt.Errorf("bitwarden: incorrect master password")
			}
			return nil, fmt.Errorf("bitwarden: %w", oerr)
		}
		st.RefreshToken = refresh
		v.saveState(email, apiBase, st)
		v.logf("bitwarden: unlocked vault for %s (%d items)", a.label(), len(opened.entries))
		return opened, nil
	}
	if lastErr == nil {
		lastErr = errBadPassword
	}
	return nil, fmt.Errorf("bitwarden: %w", lastErr)
}

func (v *Vaults) masterPassword(a Account) (string, error) {
	if a.PasswordEnv != "" {
		pw, ok := os.LookupEnv(a.PasswordEnv)
		if !ok || pw == "" {
			return "", fmt.Errorf("environment variable %s is not set", a.PasswordEnv)
		}
		return pw, nil
	}
	if v.prompt == nil {
		return "", fmt.Errorf("master password for %s required; set password_env or run `bouncer serve` in a terminal", a.label())
	}
	return v.prompt.MasterPassword(a.label())
}

func (v *Vaults) login(ctx context.Context, identityBase, email, deviceID string, id identity) (access, refresh string, err error) {
	hash := base64.StdEncoding.EncodeToString(id.passwordHash)
	access, refresh, err = v.api.login(ctx, identityBase, email, deviceID, hash, 0, "")
	var tf *twoFactorError
	if errors.As(err, &tf) {
		provider, method, ok := pickProvider(tf.providers)
		if !ok {
			return "", "", fmt.Errorf("unsupported two-factor method")
		}
		if v.prompt == nil {
			return "", "", fmt.Errorf("verification code (%s) required", method)
		}
		code, cerr := v.prompt.TwoFactorCode(email, method)
		if cerr != nil {
			return "", "", cerr
		}
		access, refresh, err = v.api.login(ctx, identityBase, email, deviceID, hash, provider, code)
	}
	return access, refresh, err
}

func openVault(master keys, s *syncResult) (*unlocked, error) {
	raw, err := decryptBytes(master, s.Profile.Key)
	if err != nil {
		return nil, err
	}
	user, err := keysFromMaterial(raw)
	clear(raw)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	defer user.clear()

	var priv *rsa.PrivateKey
	orgs := map[string]keys{}
	if len(s.Profile.Organizations) > 0 {
		if s.Profile.PrivateKey == "" {
			return nil, errors.New("vault has organization items but no account private key")
		}
		der, err := decryptBytes(user, s.Profile.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("account private key: %w", err)
		}
		priv, err = parsePrivateKey(der)
		clear(der)
		if err != nil {
			return nil, fmt.Errorf("account private key: %w", err)
		}
		for _, org := range s.Profile.Organizations {
			k, err := decryptOrgKey(user, priv, org.Key)
			if err != nil {
				return nil, fmt.Errorf("organization %s: %w", org.ID, err)
			}
			orgs[org.ID] = k
		}
		defer func() {
			for _, k := range orgs {
				k.clear()
			}
		}()
	}

	folders := map[string]string{}
	for _, f := range s.Folders {
		name, err := decryptString(user, f.Name)
		if err != nil {
			continue
		}
		folders[f.ID] = name
	}

	var entries []entry
	for _, c := range s.Ciphers {
		if c.deleted() {
			continue
		}
		e, err := decryptCipher(user, orgs, folders, c)
		if err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return &unlocked{entries: entries}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func decryptCipher(user keys, orgs map[string]keys, folders map[string]string, c syncCipher) (entry, error) {
	k := user
	if orgID := deref(c.OrganizationID); orgID != "" {
		ok, found := orgs[orgID]
		if !found {
			return entry{}, fmt.Errorf("no key for organization %s", orgID)
		}
		k = ok
	}
	if key := deref(c.Key); key != "" {
		raw, err := decryptBytes(k, key)
		if err != nil {
			return entry{}, err
		}
		k, err = keysFromMaterial(raw)
		clear(raw)
		if err != nil {
			return entry{}, err
		}
		defer k.clear()
	}
	name, err := decryptString(k, deref(c.Name))
	if err != nil {
		return entry{}, err
	}
	e := entry{id: deref(c.ID), name: name, folder: folders[deref(c.FolderID)], fields: map[string]string{}}
	if c.Login != nil {
		e.username, e.hasUsername = decryptField(k, c.Login.Username)
		e.password, e.hasPassword = decryptField(k, c.Login.Password)
		e.totp, e.hasTotp = decryptField(k, c.Login.Totp)
	}
	e.notes, e.hasNotes = decryptField(k, c.Notes)
	if c.SSHKey != nil {
		e.privateKey, e.hasPrivateKey = decryptField(k, c.SSHKey.PrivateKey)
		e.publicKey, e.hasPublicKey = decryptField(k, c.SSHKey.PublicKey)
		e.fingerprint, e.hasFingerprint = decryptField(k, c.SSHKey.Fingerprint)
	}
	for _, f := range c.Fields {
		n, ok := decryptField(k, f.Name)
		if !ok || n == "" {
			continue
		}
		val, ok := decryptField(k, f.Value)
		if !ok {
			continue
		}
		if _, exists := e.fields[n]; !exists {
			e.fields[n] = val
		}
	}
	return e, nil
}

func decryptField(k keys, s *string) (string, bool) {
	if s == nil || *s == "" {
		return "", false
	}
	pt, err := decryptString(k, *s)
	if err != nil {
		return "", false
	}
	return pt, true
}

func (u *unlocked) lookup(item, folder, field string) (string, error) {
	if field == "" {
		field = "password"
	}
	var matches []entry
	for _, e := range u.entries {
		if e.id != item && e.name != item {
			continue
		}
		if folder != "" && e.folder != folder {
			continue
		}
		matches = append(matches, e)
	}
	var byID []entry
	for _, e := range matches {
		if e.id == item {
			byID = append(byID, e)
		}
	}
	if len(byID) == 1 {
		matches = byID
	}
	switch len(matches) {
	case 0:
		if folder != "" {
			return "", fmt.Errorf("bitwarden: no item %q in folder %q", item, folder)
		}
		return "", fmt.Errorf("bitwarden: no item %q", item)
	case 1:
		return matches[0].field(field)
	default:
		names := make([]string, 0, len(matches))
		seen := map[string]bool{}
		for _, e := range matches {
			label := e.folder
			if label == "" {
				label = "(no folder)"
			}
			if !seen[label] {
				seen[label] = true
				names = append(names, label)
			}
		}
		sort.Strings(names)
		return "", fmt.Errorf("bitwarden: %d items named %q; set folder to one of: %s", len(matches), item, strings.Join(names, ", "))
	}
}

func (e entry) field(name string) (string, error) {
	var (
		v  string
		ok bool
	)
	switch name {
	case "password":
		v, ok = e.password, e.hasPassword
	case "username":
		v, ok = e.username, e.hasUsername
	case "notes":
		v, ok = e.notes, e.hasNotes
	case "totp":
		v, ok = e.totp, e.hasTotp
	case "private_key":
		v, ok = e.privateKey, e.hasPrivateKey
	case "public_key":
		v, ok = e.publicKey, e.hasPublicKey
	case "fingerprint":
		v, ok = e.fingerprint, e.hasFingerprint
	default:
		v, ok = e.fields[name]
	}
	if !ok {
		return "", fmt.Errorf("bitwarden: item %q has no field %q", e.name, name)
	}
	if v == "" {
		return "", fmt.Errorf("bitwarden: item %q field %q is empty", e.name, name)
	}
	return v, nil
}

func (v *Vaults) statePath(email, apiBase string) string {
	if v.stateDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(email + "\n" + apiBase))
	return filepath.Join(v.stateDir, "bitwarden", hex.EncodeToString(sum[:])+".json")
}

func (v *Vaults) loadState(email, apiBase string) accountState {
	path := v.statePath(email, apiBase)
	if path == "" {
		return accountState{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return accountState{}
	}
	var st accountState
	if json.Unmarshal(b, &st) != nil {
		return accountState{}
	}
	return st
}

func (v *Vaults) saveState(email, apiBase string, st accountState) {
	path := v.statePath(email, apiBase)
	if path == "" {
		return
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		v.logf("bitwarden: saving device state: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		v.logf("bitwarden: saving device state: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		v.logf("bitwarden: saving device state: %v", err)
	}
}

func newDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
