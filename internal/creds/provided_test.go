package creds

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/marwatk/agent-bouncer/internal/config"
)

func TestParseProvided(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(k, "")
	keyPEM := pem.EncodeToMemory(block)
	in := "# generated\n" +
		"gitlab: glpat-abc: #not a comment 'quoted'\n" +
		"\n" +
		"github:ghp_nospace\r\n" +
		"deploy-key:: " + base64.StdEncoding.EncodeToString(keyPEM) + "\n"
	got, err := ParseProvided(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if got["gitlab"] != "glpat-abc: #not a comment 'quoted'" || got["github"] != "ghp_nospace" {
		t.Fatalf("%q", got)
	}
	store := NewStore(map[string]*config.Credential{
		"gitlab":     {Name: "gitlab", Source: "keyring"},
		"deploy-key": {Name: "deploy-key", Source: "provided"},
		"other":      {Name: "other", Source: "provided"},
	})
	store.SetProvided(got)
	if v, err := store.Get(context.Background(), "gitlab"); err != nil || v != got["gitlab"] {
		t.Fatalf("provided value should override keyring: %q %v", v, err)
	}
	if signers, err := store.SSHSigners(context.Background(), "deploy-key"); err != nil || len(signers) != 1 {
		t.Fatalf("multi-line key via base64: %v", err)
	}
	if m := store.MissingProvided(); len(m) != 1 || m[0] != "other" {
		t.Fatalf("missing: %v", m)
	}
	if _, err := store.Get(context.Background(), "other"); err == nil || !strings.Contains(err.Error(), "--creds-from") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseProvidedErrors(t *testing.T) {
	for name, in := range map[string]string{
		"duplicate":  "a: 1\na: 2\n",
		"empty":      "a: \n",
		"no colon":   "just-a-secret\n",
		"bad name":   "bad name: x\n",
		"bad base64": "a:: !!!\n",
	} {
		_, err := ParseProvided(strings.NewReader(in))
		if err == nil {
			t.Errorf("%s: expected error", name)
		} else if strings.Contains(err.Error(), "just-a-secret") {
			t.Errorf("%s: error echoes input: %v", name, err)
		}
	}
}
