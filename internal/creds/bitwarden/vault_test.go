package bitwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	testEmail    = "user@example.com"
	testPassword = "correct horse battery staple"
)

func testIdentity(t *testing.T) identity {
	t.Helper()
	id, err := deriveIdentity(testEmail, testPassword, kdfParams{kind: kdfPBKDF2, iterations: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(id.passwordHash); got != "8vx9APjb5Q1wtLcQUtQiEautn2Wd5oBGzkZeyYe9tV4=" {
		t.Fatalf("password hash %s", got)
	}
	return id
}

func mustEnc(t *testing.T, k keys, s string) string {
	t.Helper()
	out, err := encryptSymmetric(k, []byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type fakeServer struct {
	mu            sync.Mutex
	passwordHash  string
	syncBody      []byte
	refreshToken  string
	requireSecond bool
	logins        int
	refreshes     int
	syncs         int
	devices       []string
	authEmails    []string
}

func (s *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/accounts/prelogin"):
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"Kdf":0,"KdfIterations":1000,"KdfMemory":null,"KdfParallelism":null}`)
	case strings.HasSuffix(r.URL.Path, "/connect/token"):
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			s.refreshes++
			if r.Form.Get("refresh_token") != s.refreshToken || r.Form.Get("client_id") != "cli" {
				writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "invalid refresh"})
				return
			}
			s.refreshToken = "refresh-2"
			writeJSON(w, 200, map[string]string{"access_token": "access-2", "refresh_token": "refresh-2"})
			return
		}
		s.logins++
		s.devices = append(s.devices, r.Form.Get("deviceIdentifier"))
		s.authEmails = append(s.authEmails, r.Header.Get("auth-email"))
		if r.Form.Get("client_id") != "cli" || r.Form.Get("scope") != "api offline_access" || r.Form.Get("deviceType") != cliDeviceType() {
			writeJSON(w, 400, map[string]string{"error": "invalid_client"})
			return
		}
		if r.Form.Get("username") != testEmail || r.Form.Get("password") != s.passwordHash {
			writeJSON(w, 400, map[string]any{
				"error":             "invalid_grant",
				"error_description": "invalid_username_or_password",
				"ErrorModel":        map[string]string{"Message": "Username or password is incorrect. Try again"},
			})
			return
		}
		if s.requireSecond && r.Form.Get("twoFactorToken") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":[0]}`)
			return
		}
		if s.requireSecond && r.Form.Get("twoFactorToken") != "123456" {
			writeJSON(w, 400, map[string]any{"errorModel": map[string]string{"message": "Invalid TOTP code"}})
			return
		}
		if s.refreshToken == "" {
			s.refreshToken = "refresh-1"
		}
		writeJSON(w, 200, map[string]string{"access_token": "access-1", "refresh_token": s.refreshToken})
	case strings.HasSuffix(r.URL.Path, "/sync"):
		if r.Header.Get("Authorization") == "" || r.Header.Get("Bitwarden-Client-Version") == "" {
			http.Error(w, "unauthorized", 401)
			return
		}
		s.syncs++
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.syncBody)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func buildVault(t *testing.T, id identity) []byte {
	t.Helper()
	userMaterial := make([]byte, 64)
	for i := range userMaterial {
		userMaterial[i] = byte(i + 1)
	}
	user, err := keysFromMaterial(userMaterial)
	if err != nil {
		t.Fatal(err)
	}
	protectedUser, err := encryptSymmetric(id.keys, userMaterial)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	encPriv := mustEnc(t, user, string(der))
	orgMaterial := bytesRepeat(0x42, 64)
	org, err := keysFromMaterial(orgMaterial)
	if err != nil {
		t.Fatal(err)
	}
	rsaCT, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &priv.PublicKey, orgMaterial, nil)
	if err != nil {
		t.Fatal(err)
	}
	orgKey := "4." + base64.StdEncoding.EncodeToString(rsaCT)

	itemMaterial := bytesRepeat(0x11, 64)
	itemKey, err := keysFromMaterial(itemMaterial)
	if err != nil {
		t.Fatal(err)
	}
	encItemKey := mustEnc(t, user, string(itemMaterial))

	body := map[string]any{
		"profile": map[string]any{
			"key":        protectedUser,
			"privateKey": encPriv,
			"organizations": []any{map[string]any{
				"id":  "org-1",
				"key": orgKey,
			}},
		},
		"folders": []any{
			map[string]any{"id": "folder-work", "name": mustEnc(t, user, "Work")},
			map[string]any{"id": "folder-personal", "name": mustEnc(t, user, "Personal")},
		},
		"ciphers": []any{
			loginCipher("id-work", "folder-work", "", user, "GitLab", "oauth2", "gl-token", "otp-secret", "a note", map[string]string{"token": "custom-token"}),
			loginCipher("id-personal", "folder-personal", "", user, "GitLab", "", "other-token", "", "", nil),
			map[string]any{
				"id": "id-ssh", "organizationId": nil, "folderId": nil,
				"name": mustEnc(t, user, "sandbox"),
				"sshKey": map[string]any{
					"privateKey":     mustEnc(t, user, "-----BEGIN OPENSSH PRIVATE KEY-----\nTEST\n"),
					"publicKey":      mustEnc(t, user, "ssh-ed25519 AAAAC3"),
					"keyFingerprint": mustEnc(t, user, "SHA256:abc"),
				},
			},
			loginCipher("id-org", "", "org-1", org, "Org Secret", "", "org-password", "", "", nil),
			map[string]any{
				"id": "id-wrapped", "name": mustEnc(t, itemKey, "Wrapped"), "key": encItemKey,
				"login": map[string]any{"password": mustEnc(t, itemKey, "from-item-key")},
			},
			map[string]any{
				"id": "id-gone", "name": mustEnc(t, user, "Gone"), "deletedDate": "2020-01-01T00:00:00.000Z",
				"login": map[string]any{"password": mustEnc(t, user, "nope")},
			},
			map[string]any{
				"id": "id-note", "name": mustEnc(t, user, "Runbook"), "notes": mustEnc(t, user, "do the thing"),
			},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loginCipher(id, folder, org string, k keys, name, user, pass, totp, notes string, fields map[string]string) map[string]any {
	c := map[string]any{
		"id": id, "name": mustEncT(k, name),
		"organizationId": nil, "folderId": nil,
		"login": map[string]any{},
	}
	if folder != "" {
		c["folderId"] = folder
	}
	if org != "" {
		c["organizationId"] = org
	}
	login := map[string]any{}
	if user != "" {
		login["username"] = mustEncT(k, user)
	}
	if pass != "" {
		login["password"] = mustEncT(k, pass)
	}
	if totp != "" {
		login["totp"] = mustEncT(k, totp)
	}
	c["login"] = login
	if notes != "" {
		c["notes"] = mustEncT(k, notes)
	}
	if len(fields) > 0 {
		var fs []any
		for n, v := range fields {
			fs = append(fs, map[string]any{"name": mustEncT(k, n), "value": mustEncT(k, v)})
		}
		c["fields"] = fs
	}
	return c
}

func mustEncT(k keys, s string) string {
	out, err := encryptSymmetric(k, []byte(s))
	if err != nil {
		panic(err)
	}
	return out
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

type memPrompt struct {
	passwords []string
	codes     []string
	nPass     int
	nCode     int
}

func (m *memPrompt) MasterPassword(string) (string, error) {
	if m.nPass >= len(m.passwords) {
		return "", errors.New("no more passwords")
	}
	s := m.passwords[m.nPass]
	m.nPass++
	return s, nil
}

func (m *memPrompt) TwoFactorCode(string, string) (string, error) {
	if m.nCode >= len(m.codes) {
		return "", errors.New("no more codes")
	}
	s := m.codes[m.nCode]
	m.nCode++
	return s, nil
}

func startVault(t *testing.T, second bool) (*httptest.Server, *fakeServer) {
	t.Helper()
	id := testIdentity(t)
	fake := &fakeServer{passwordHash: base64.StdEncoding.EncodeToString(id.passwordHash), syncBody: buildVault(t, id), requireSecond: second}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return srv, fake
}

func TestUnlockLookupAndReuse(t *testing.T) {
	srv, fake := startVault(t, false)
	dir := t.TempDir()
	t.Setenv("BW_MASTER", testPassword)
	v := New(Options{StateDir: dir, Prompt: &memPrompt{}})
	q := Query{Account: Account{Email: "User@Example.com", Server: srv.URL, PasswordEnv: "BW_MASTER"}, Item: "GitLab", Folder: "Work"}
	got, err := v.Get(context.Background(), q)
	if err != nil || got != "gl-token" {
		t.Fatalf("got %q, %v", got, err)
	}
	// A second read must not hit the network or the prompter again.
	if _, err := v.Get(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	if fake.logins != 1 || fake.syncs != 1 || fake.refreshes != 0 {
		t.Fatalf("logins=%d syncs=%d refreshes=%d", fake.logins, fake.syncs, fake.refreshes)
	}
	if len(fake.authEmails) != 1 || fake.authEmails[0] != "dXNlckBleGFtcGxlLmNvbQ" {
		t.Fatalf("auth-email %v", fake.authEmails)
	}
	fake.mu.Unlock()

	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "GitLab", Folder: "Work", Field: "username"}); err != nil || got != "oauth2" {
		t.Fatalf("username %q %v", got, err)
	}
	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "GitLab", Folder: "Work", Field: "token"}); err != nil || got != "custom-token" {
		t.Fatalf("custom %q %v", got, err)
	}
	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "GitLab", Folder: "Work", Field: "notes"}); err != nil || got != "a note" {
		t.Fatalf("notes %q %v", got, err)
	}
	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "GitLab", Folder: "Work", Field: "totp"}); err != nil || got != "otp-secret" {
		t.Fatalf("totp %q %v", got, err)
	}
	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "id-personal", Field: "password"}); err != nil || got != "other-token" {
		t.Fatalf("by id %q %v", got, err)
	}
	if _, err := v.Get(context.Background(), Query{Account: q.Account, Item: "GitLab"}); err == nil || !strings.Contains(err.Error(), "set folder") {
		t.Fatalf("duplicate: %v", err)
	}
	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "sandbox", Field: "private_key"}); err != nil || !strings.Contains(got, "BEGIN OPENSSH PRIVATE KEY") {
		t.Fatalf("ssh %q %v", got, err)
	}
	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "Org Secret"}); err != nil || got != "org-password" {
		t.Fatalf("org %q %v", got, err)
	}
	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "Wrapped"}); err != nil || got != "from-item-key" {
		t.Fatalf("item key %q %v", got, err)
	}
	if _, err := v.Get(context.Background(), Query{Account: q.Account, Item: "Gone"}); err == nil {
		t.Fatal("deleted item was returned")
	}
	if got, err := v.Get(context.Background(), Query{Account: q.Account, Item: "Runbook", Field: "notes"}); err != nil || got != "do the thing" {
		t.Fatalf("note %q %v", got, err)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "bitwarden", "*.json"))
	if len(matches) != 1 {
		t.Fatalf("state files: %v", matches)
	}
	info, err := os.Stat(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %o", info.Mode().Perm())
	}

	// A new process-shaped vault set reuses the refresh token and still
	// needs the master password to decrypt.
	v2 := New(Options{StateDir: dir})
	if _, err := v2.Get(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.logins != 1 || fake.refreshes != 1 || fake.syncs != 2 {
		t.Fatalf("after restart logins=%d refreshes=%d syncs=%d", fake.logins, fake.refreshes, fake.syncs)
	}
}

func TestWrongPasswordIsRetried(t *testing.T) {
	srv, fake := startVault(t, false)
	p := &memPrompt{passwords: []string{"nope", testPassword}}
	v := New(Options{StateDir: t.TempDir(), Prompt: p})
	got, err := v.Get(context.Background(), Query{
		Account: Account{Email: testEmail, Server: srv.URL},
		Item:    "GitLab", Folder: "Work",
	})
	if err != nil || got != "gl-token" {
		t.Fatalf("got %q %v", got, err)
	}
	if p.nPass != 2 {
		t.Fatalf("prompts %d", p.nPass)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.logins != 2 {
		t.Fatalf("logins %d", fake.logins)
	}
}

func TestPasswordEnvFailureDoesNotStick(t *testing.T) {
	srv, _ := startVault(t, false)
	v := New(Options{StateDir: t.TempDir(), Prompt: &memPrompt{}})
	t.Setenv("BW_MASTER", "nope")
	q := Query{Account: Account{Email: testEmail, Server: srv.URL, PasswordEnv: "BW_MASTER"}, Item: "sandbox", Field: "private_key"}
	if _, err := v.Get(context.Background(), q); err == nil || !strings.Contains(err.Error(), "incorrect") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv("BW_MASTER", testPassword)
	if _, err := v.Get(context.Background(), q); err != nil {
		t.Fatal(err)
	}
}

func TestTwoFactor(t *testing.T) {
	srv, fake := startVault(t, true)
	p := &memPrompt{passwords: []string{testPassword}, codes: []string{"123456"}}
	v := New(Options{StateDir: t.TempDir(), Prompt: p})
	got, err := v.Get(context.Background(), Query{Account: Account{Email: testEmail, Server: srv.URL}, Item: "Org Secret"})
	if err != nil || got != "org-password" {
		t.Fatalf("got %q %v", got, err)
	}
	if p.nCode != 1 {
		t.Fatalf("codes %d", p.nCode)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.logins != 2 {
		t.Fatalf("logins %d", fake.logins)
	}
}

func TestConflictingPasswordEnv(t *testing.T) {
	v := New(Options{StateDir: t.TempDir()})
	err := v.Unlock(context.Background(), []Account{
		{Email: "User@Example.com", PasswordEnv: "ONE"},
		{Email: "user@example.com", PasswordEnv: "TWO"},
	})
	if err == nil || !strings.Contains(err.Error(), "conflicting password_env") {
		t.Fatalf("err = %v", err)
	}
}
