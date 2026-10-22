package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, []byte("default_profile: p\nprofiles:\n  p: {}\n"), 0o644)
	d, err := New(Options{ConfigPath: cfg, StateDir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSessionTTL(t *testing.T) {
	d := newTestDaemon(t)
	short, err := d.CreateSession("", "short", 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	forever, _ := d.CreateSession("", "forever", 0)
	if len(short.ID) != 16 {
		t.Errorf("session ID %q should be 64 bits", short.ID)
	}
	if _, ok := d.Session(short.Token); !ok {
		t.Fatal("fresh session rejected")
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := d.Session(short.Token); ok {
		t.Fatal("expired session accepted")
	}
	if _, ok := d.Session(forever.Token); !ok {
		t.Fatal("session without ttl expired")
	}
	if n := len(d.listSessions()); n != 1 {
		t.Fatalf("expired session listed; got %d sessions", n)
	}
}
