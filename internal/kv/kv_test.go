package kv

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPersistAndTTL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kv.json")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.Incr("f", "pushes", 1, time.Hour); n != 1 {
		t.Fatal(n)
	}
	if n := s.Incr("f", "pushes", 1, time.Hour); n != 2 {
		t.Fatal(n)
	}
	s.Set("f", "short", "x", time.Millisecond)
	s.Set("other", "pushes", "separate namespace", 0)
	s.Close()
	time.Sleep(5 * time.Millisecond)

	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v, ok := s2.Get("f", "pushes"); !ok || v.(float64) != 2 {
		t.Fatalf("got %v %v", v, ok)
	}
	if _, ok := s2.Get("f", "short"); ok {
		t.Fatal("expired key survived")
	}
	if v, _ := s2.Get("other", "pushes"); v != "separate namespace" {
		t.Fatal("namespaces collided")
	}
}
