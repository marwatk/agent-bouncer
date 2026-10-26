package creds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/marwatk/agent-bouncer/internal/config"
)

func TestCommandSourceAndCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	counter := t.TempDir() + "/n"
	c := &config.Credential{Name: "x", Source: "command",
		Command: []string{"sh", "-c", "echo run >> " + counter + "; printf 'tok\\n'"}}
	s := NewStore(map[string]*config.Credential{"x": c})
	for i := 0; i < 3; i++ {
		v, err := s.Get(context.Background(), "x")
		if err != nil || v != "tok" {
			t.Fatalf("got %q, %v", v, err)
		}
	}
	// Changing the definition invalidates the cache.
	c2 := *c
	c2.Command = []string{"sh", "-c", "printf other"}
	s.Update(map[string]*config.Credential{"x": &c2})
	if v, _ := s.Get(context.Background(), "x"); v != "other" {
		t.Fatalf("cache not invalidated: %q", v)
	}
}

func TestCommandFailureIncludesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	s := NewStore(map[string]*config.Credential{"x": {Name: "x", Source: "command",
		Command: []string{"sh", "-c", "echo vault locked >&2; exit 1"}}})
	_, err := s.Get(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "vault locked") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnvSource(t *testing.T) {
	t.Setenv("BOUNCER_TEST_SECRET", "s3cret")
	s := NewStore(map[string]*config.Credential{"e": {Name: "e", Source: "env", Env: "BOUNCER_TEST_SECRET"}})
	if v, err := s.Get(context.Background(), "e"); err != nil || v != "s3cret" {
		t.Fatalf("got %q, %v", v, err)
	}
}

func TestBitwardenSourceWrapsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	ConfigureBitwarden(t.TempDir(), nil)
	s := NewStore(map[string]*config.Credential{"bw": {Name: "bw", Source: "bitwarden", Bitwarden: &config.Bitwarden{
		Email: "user@example.com", Server: srv.URL, Item: "GitLab",
	}}})
	_, err := s.Get(context.Background(), "bw")
	if err == nil || !strings.Contains(err.Error(), `credential "bw"`) || !strings.Contains(err.Error(), "prelogin") {
		t.Fatalf("err = %v", err)
	}
}
