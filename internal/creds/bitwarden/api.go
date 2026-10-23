package bitwarden

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	clientID      = "cli"
	clientVersion = "2024.12.0" // vaultwarden omits SSH keys for older versions
	userAgent     = "agent-bouncer"
	syncBodyLimit = 64 << 20
	authBodyLimit = 1 << 20
)

// endpoints maps a configured server to the API and identity bases.
// An empty server is Bitwarden cloud. Any other URL is treated as a
// self-hosted vault, whose API lives at <server>/api and identity at
// <server>/identity (the same split rbw uses).
func endpoints(server string) (apiBase, identityBase string, err error) {
	raw := strings.TrimRight(strings.TrimSpace(server), "/")
	switch strings.ToLower(raw) {
	case "", "bitwarden.com", "https://bitwarden.com", "http://bitwarden.com",
		"https://vault.bitwarden.com", "https://api.bitwarden.com", "https://identity.bitwarden.com":
		return "https://api.bitwarden.com", "https://identity.bitwarden.com", nil
	case "bitwarden.eu", "https://bitwarden.eu", "https://vault.bitwarden.eu",
		"https://api.bitwarden.eu", "https://identity.bitwarden.eu":
		return "https://api.bitwarden.eu", "https://identity.bitwarden.eu", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, perr := url.Parse(raw)
	if perr != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("invalid bitwarden server %q", server)
	}
	base := u.Scheme + "://" + u.Host
	if p := strings.TrimRight(u.Path, "/"); p != "" {
		base += p
	}
	return base + "/api", base + "/identity", nil
}

func cliDeviceType() string {
	// Bitwarden CLI device types, matching client_id "cli".
	switch runtime.GOOS {
	case "windows":
		return "23"
	case "darwin":
		return "24"
	default:
		return "25"
	}
}

type api struct {
	http *http.Client
}

func newAPI(c *http.Client) *api {
	if c == nil {
		c = &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{Proxy: nil}}
	}
	return &api{http: c}
}

type preloginResponse struct {
	KDF           flexUint `json:"kdf"`
	KDFIterations flexUint `json:"kdfIterations"`
	KDFMemory     flexUint `json:"kdfMemory"`
	KDFParallel   flexUint `json:"kdfParallelism"`
}

// flexUint accepts a JSON number, a numeric string, or null. Prelogin
// responses use all three, depending on the server.
type flexUint uint32

func (n *flexUint) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		u, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return err
		}
		*n = flexUint(u)
		return nil
	}
	var u uint32
	if err := json.Unmarshal(b, &u); err != nil {
		return err
	}
	*n = flexUint(u)
	return nil
}

func (a *api) prelogin(ctx context.Context, identityBase, email string) (kdfParams, error) {
	body, status, err := a.do(ctx, http.MethodPost, identityBase+"/accounts/prelogin",
		strings.NewReader(`{"email":`+jsonString(email)+`}`),
		http.Header{"Content-Type": {"application/json"}}, authBodyLimit)
	if err != nil {
		return kdfParams{}, err
	}
	if status != http.StatusOK {
		return kdfParams{}, httpError("prelogin", status, body)
	}
	var res preloginResponse
	if err := decodeBW(body, &res); err != nil {
		return kdfParams{}, fmt.Errorf("prelogin: %w", err)
	}
	return kdfParams{kind: int(res.KDF), iterations: uint32(res.KDFIterations), memory: uint32(res.KDFMemory), parallelism: uint32(res.KDFParallel)}, nil
}

type tokenResponse struct {
	AccessToken           string          `json:"access_token"`
	RefreshToken          string          `json:"refresh_token"`
	Error                 string          `json:"error"`
	ErrorDescription      string          `json:"error_description"`
	ErrorDescriptionCamel string          `json:"errorDescription"`
	TwoFactorProviders    json.RawMessage `json:"twoFactorProviders"`
	ErrorModel            *struct {
		Message string `json:"message"`
	} `json:"errorModel"`
}

func (t tokenResponse) description() string {
	if t.ErrorDescription != "" {
		return t.ErrorDescription
	}
	return t.ErrorDescriptionCamel
}

// twoFactorError is returned when login needs a second factor.
type twoFactorError struct{ providers []int }

func (e *twoFactorError) Error() string { return "two-factor authentication required" }

func (a *api) login(ctx context.Context, identityBase, email, deviceID, passwordHash string, provider int, code string) (access, refresh string, err error) {
	form := url.Values{
		"grant_type":       {"password"},
		"username":         {email},
		"password":         {passwordHash},
		"scope":            {"api offline_access"},
		"client_id":        {clientID},
		"deviceType":       {cliDeviceType()},
		"deviceIdentifier": {deviceID},
		"deviceName":       {"agent-bouncer"},
	}
	if code != "" {
		form.Set("twoFactorToken", code)
		form.Set("twoFactorProvider", fmt.Sprintf("%d", provider))
		form.Set("twoFactorRemember", "1")
	}
	hdr := http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"},
		"auth-email":   {b64URL(email)},
	}
	body, status, err := a.do(ctx, http.MethodPost, identityBase+"/connect/token", strings.NewReader(form.Encode()), hdr, authBodyLimit)
	if err != nil {
		return "", "", err
	}
	return parseToken(body, status, true)
}

func (a *api) refresh(ctx context.Context, identityBase, refreshToken string) (access, refresh string, err error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	}
	hdr := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	body, status, err := a.do(ctx, http.MethodPost, identityBase+"/connect/token", strings.NewReader(form.Encode()), hdr, authBodyLimit)
	if err != nil {
		return "", "", err
	}
	access, refresh, err = parseToken(body, status, false)
	if err != nil {
		return "", "", err
	}
	if refresh == "" {
		refresh = refreshToken
	}
	return access, refresh, nil
}

func parseToken(body []byte, status int, allowChallenge bool) (access, refresh string, err error) {
	var res tokenResponse
	if jerr := decodeBW(body, &res); jerr != nil {
		if status != http.StatusOK {
			return "", "", httpError("login", status, body)
		}
		return "", "", fmt.Errorf("login: %w", jerr)
	}
	if status == http.StatusOK && res.AccessToken != "" && res.Error == "" {
		return res.AccessToken, res.RefreshToken, nil
	}
	if allowChallenge && res.Error == "invalid_grant" && res.description() == "Two factor required." {
		ps := parseProviders(res.TwoFactorProviders)
		if len(ps) > 0 {
			return "", "", &twoFactorError{providers: ps}
		}
	}
	if res.Error == "invalid_grant" && res.description() == "invalid_username_or_password" {
		msg := "incorrect master password"
		if res.ErrorModel != nil && res.ErrorModel.Message != "" {
			msg = res.ErrorModel.Message
		}
		return "", "", &passwordError{message: msg}
	}
	if res.ErrorModel != nil && (res.ErrorModel.Message == "Username or password is incorrect. Try again" || strings.HasPrefix(res.ErrorModel.Message, "Invalid TOTP code")) {
		return "", "", &passwordError{message: res.ErrorModel.Message}
	}
	if status != http.StatusOK {
		return "", "", httpError("login", status, body)
	}
	return "", "", errors.New("login: empty access token")
}

func parseProviders(raw json.RawMessage) []int {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var nums []int
	if json.Unmarshal(raw, &nums) == nil {
		return nums
	}
	var strs []string
	if json.Unmarshal(raw, &strs) == nil {
		for _, s := range strs {
			var n int
			if _, err := fmt.Sscan(s, &n); err == nil {
				nums = append(nums, n)
			}
		}
		return nums
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		for k := range obj {
			var n int
			if _, err := fmt.Sscan(k, &n); err == nil {
				nums = append(nums, n)
			}
		}
	}
	return nums
}

// pickProvider prefers an authenticator app, then a YubiKey, then email.
func pickProvider(ps []int) (id int, label string, ok bool) {
	names := map[int]string{0: "authenticator app", 3: "YubiKey", 1: "email"}
	for _, want := range []int{0, 3, 1} {
		for _, p := range ps {
			if p == want {
				return p, names[p], true
			}
		}
	}
	return 0, "", false
}

type syncResult struct {
	Ciphers []syncCipher `json:"ciphers"`
	Profile syncProfile  `json:"profile"`
	Folders []syncFolder `json:"folders"`
}

type syncProfile struct {
	Key           string    `json:"key"`
	PrivateKey    string    `json:"privateKey"`
	Organizations []syncOrg `json:"organizations"`
}

type syncOrg struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type syncFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type syncCipher struct {
	ID             *string         `json:"id"`
	OrganizationID *string         `json:"organizationId"`
	FolderID       *string         `json:"folderId"`
	Name           *string         `json:"name"`
	Notes          *string         `json:"notes"`
	Key            *string         `json:"key"`
	DeletedDate    json.RawMessage `json:"deletedDate"`
	Login          *syncLogin      `json:"login"`
	SSHKey         *syncSSH        `json:"sshKey"`
	Fields         []syncField     `json:"fields"`
}

func (c syncCipher) deleted() bool {
	b := bytes.TrimSpace(c.DeletedDate)
	return len(b) > 0 && string(b) != "null"
}

type syncLogin struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
	Totp     *string `json:"totp"`
}

type syncSSH struct {
	PrivateKey  *string `json:"privateKey"`
	PublicKey   *string `json:"publicKey"`
	Fingerprint *string `json:"keyFingerprint"`
}

type syncField struct {
	Name  *string `json:"name"`
	Value *string `json:"value"`
}

func (a *api) sync(ctx context.Context, apiBase, accessToken string) (*syncResult, error) {
	hdr := http.Header{"Authorization": {"Bearer " + accessToken}}
	body, status, err := a.do(ctx, http.MethodGet, apiBase+"/sync", nil, hdr, syncBodyLimit)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, errors.New("sync: unauthorized")
	}
	if status != http.StatusOK {
		return nil, httpError("sync", status, body)
	}
	var res syncResult
	if err := decodeBW(body, &res); err != nil {
		return nil, fmt.Errorf("sync: %w", err)
	}
	if res.Profile.Key == "" {
		return nil, errors.New("sync: response has no account key")
	}
	return &res, nil
}

func (a *api) do(ctx context.Context, method, rawURL string, body io.Reader, hdr http.Header, limit int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Bitwarden-Client-Name", clientID)
	req.Header.Set("Bitwarden-Client-Version", clientVersion)
	req.Header.Set("Device-Type", cliDeviceType())
	req.Header.Set("User-Agent", userAgent)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(b)) > limit {
		return nil, resp.StatusCode, errors.New("response is too large")
	}
	return b, resp.StatusCode, nil
}

func httpError(op string, status int, body []byte) error {
	var res tokenResponse
	if decodeBW(body, &res) == nil {
		if res.ErrorModel != nil && res.ErrorModel.Message != "" {
			return fmt.Errorf("%s: %s", op, res.ErrorModel.Message)
		}
		if d := res.description(); d != "" {
			return fmt.Errorf("%s: %s", op, d)
		}
		if res.Error != "" {
			return fmt.Errorf("%s: %s", op, res.Error)
		}
	}
	return fmt.Errorf("%s: HTTP %d", op, status)
}

// decodeBW accepts the PascalCase and camelCase field names Bitwarden servers send.
func decodeBW(body []byte, dest any) error {
	norm, err := canonicalize(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(norm, dest)
}

func canonicalize(body []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(rewriteKeys(v))
}

func rewriteKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[camelKey(k)] = rewriteKeys(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = rewriteKeys(t[i])
		}
		return t
	default:
		return v
	}
}

func camelKey(s string) string {
	if strings.EqualFold(s, "ssn") {
		return "ssn"
	}
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size == 0 {
		return s
	}
	return string(unicode.ToLower(r)) + s[size:]
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func b64URL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
