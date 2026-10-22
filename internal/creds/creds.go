// Package creds fetches secrets from their configured sources.
package creds

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/creds/bitwarden"
)

// KeyringService is the service name under which secrets are stored in the OS keyring.
const KeyringService = "agent-bouncer"

const commandTimeout = 60 * time.Second

// Store resolves credentials by name, caching per each credential's TTL.
type Store struct {
	mu    sync.Mutex
	creds map[string]*config.Credential
	cache map[string]cached
	// fetch serializes concurrent fetches per credential so an interactive
	// command (e.g. a password manager unlock) only runs once.
	fetch map[string]*sync.Mutex
}

type cached struct {
	value   string
	expires time.Time
}

func NewStore(creds map[string]*config.Credential) *Store {
	return &Store{creds: creds, cache: map[string]cached{}, fetch: map[string]*sync.Mutex{}}
}

// ConfigureBitwarden sets where the process stores its Bitwarden device id
// and refresh token, and where unlock progress is logged. The decrypted
// vault is kept in memory only. Call this before the first fetch.
func ConfigureBitwarden(stateDir string, logf func(string, ...any)) {
	bitwarden.Configure(bitwarden.Options{StateDir: stateDir, Logf: logf})
}

// Prepare unlocks every Bitwarden vault the credential set uses, so the
// master password is requested once at startup rather than mid-request.
// Vaults stay unlocked until the process exits.
func (s *Store) Prepare(ctx context.Context, creds map[string]*config.Credential) error {
	var accounts []bitwarden.Account
	for _, c := range creds {
		if c == nil || c.Source != "bitwarden" || c.Bitwarden == nil {
			continue
		}
		accounts = append(accounts, bitwarden.Account{
			Email:       c.Bitwarden.Email,
			Server:      c.Bitwarden.Server,
			PasswordEnv: c.Bitwarden.PasswordEnv,
		})
	}
	if len(accounts) == 0 {
		return nil
	}
	return bitwarden.Unlock(ctx, accounts)
}

// Update swaps in a new credential set (on config reload), dropping cache
// entries whose definition changed.
func (s *Store) Update(creds map[string]*config.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, old := range s.creds {
		if nw, ok := creds[name]; !ok || fmt.Sprint(*nw) != fmt.Sprint(*old) {
			delete(s.cache, name)
		}
	}
	s.creds = creds
}

func (s *Store) lookup(name string) (*config.Credential, *sync.Mutex, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[name]
	if !ok {
		return nil, nil, fmt.Errorf("unknown credential %q", name)
	}
	m, ok := s.fetch[name]
	if !ok {
		m = &sync.Mutex{}
		s.fetch[name] = m
	}
	return c, m, nil
}

// Get returns the secret for a credential.
func (s *Store) Get(ctx context.Context, name string) (string, error) {
	c, m, err := s.lookup(name)
	if err != nil {
		return "", err
	}
	if c.Source == "ssh-agent" {
		return "", fmt.Errorf("credential %q is an ssh-agent credential and has no secret value", name)
	}
	m.Lock()
	defer m.Unlock()
	s.mu.Lock()
	if e, ok := s.cache[name]; ok && time.Now().Before(e.expires) {
		s.mu.Unlock()
		return e.value, nil
	}
	s.mu.Unlock()

	v, err := fetch(ctx, c)
	if err != nil {
		return "", fmt.Errorf("credential %q: %w", name, err)
	}
	if v == "" {
		return "", fmt.Errorf("credential %q: empty secret", name)
	}
	if ttl := c.CacheTTL(); ttl > 0 {
		s.mu.Lock()
		s.cache[name] = cached{value: v, expires: time.Now().Add(ttl)}
		s.mu.Unlock()
	}
	return v, nil
}

func fetch(ctx context.Context, c *config.Credential) (string, error) {
	switch c.Source {
	case "keyring":
		v, err := keyring.Get(KeyringService, c.KeyringAccount())
		if err == keyring.ErrNotFound {
			return "", fmt.Errorf("not in keyring; run: bouncer cred set %s", c.Name)
		}
		return v, err
	case "env":
		v, ok := os.LookupEnv(c.Env)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set in the bouncer daemon", c.Env)
		}
		return v, nil
	case "file":
		b, err := os.ReadFile(c.Path)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	case "command":
		ctx, cancel := context.WithTimeout(ctx, commandTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, c.Command[0], c.Command[1:]...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return "", fmt.Errorf("%s: %w: %s", c.Command[0], err, msg)
			}
			return "", fmt.Errorf("%s: %w", c.Command[0], err)
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	case "bitwarden":
		bw := c.Bitwarden
		if bw == nil {
			return "", errors.New("bitwarden block is missing")
		}
		return bitwarden.Get(ctx, bitwarden.Query{
			Account: bitwarden.Account{Email: bw.Email, Server: bw.Server, PasswordEnv: bw.PasswordEnv},
			Item:    bw.Item,
			Folder:  bw.Folder,
			Field:   bw.Field,
		})
	}
	return "", fmt.Errorf("unsupported source %q", c.Source)
}

// SSHSigners returns signers for an SSH credential: the parsed private key
// for secret-bearing sources, or keys from the running ssh-agent.
func (s *Store) SSHSigners(ctx context.Context, name string) ([]ssh.Signer, error) {
	c, _, err := s.lookup(name)
	if err != nil {
		return nil, err
	}
	if c.Source == "ssh-agent" {
		return agentSigners(c)
	}
	pemData, err := s.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey([]byte(pemData + "\n"))
	if err != nil {
		return nil, fmt.Errorf("credential %q: not a usable SSH private key (passphrase-protected keys must use source: ssh-agent): %w", name, err)
	}
	return []ssh.Signer{signer}, nil
}

func agentSigners(c *config.Credential) ([]ssh.Signer, error) {
	conn, err := dialAgent()
	if err != nil {
		return nil, fmt.Errorf("credential %q: connecting to ssh-agent: %w", c.Name, err)
	}
	// The connection must stay open while the signers are in use; it is
	// released when the process exits or the agent hangs up.
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if c.Fingerprint == "" {
		return signers, nil
	}
	for _, sg := range signers {
		if ssh.FingerprintSHA256(sg.PublicKey()) == c.Fingerprint {
			return []ssh.Signer{sg}, nil
		}
	}
	conn.Close()
	return nil, fmt.Errorf("credential %q: no agent key with fingerprint %s", c.Name, c.Fingerprint)
}

// SetKeyring stores a secret in the OS keyring under the credential's account.
func SetKeyring(account, value string) error { return keyring.Set(KeyringService, account, value) }

// DeleteKeyring removes a secret from the OS keyring.
func DeleteKeyring(account string) error { return keyring.Delete(KeyringService, account) }
