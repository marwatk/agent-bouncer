// Package kv is a small persistent key-value store for filter state
// (rate-limit counters and the like). Keys are namespaced per filter.
package kv

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type entry struct {
	Value   any       `json:"v"`
	Expires time.Time `json:"e,omitzero"`
}

func (e entry) expired(now time.Time) bool { return !e.Expires.IsZero() && now.After(e.Expires) }

// Store persists to a JSON file, flushed shortly after writes.
type Store struct {
	mu    sync.Mutex
	path  string
	data  map[string]entry
	dirty bool
	stop  chan struct{}
	done  chan struct{}
}

// Open loads (or creates) a store. An empty path gives an in-memory store.
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]entry{}, stop: make(chan struct{}), done: make(chan struct{})}
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := json.Unmarshal(b, &s.data); err != nil {
				return nil, err
			}
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	go s.loop()
	return s, nil
}

func key(ns, k string) string { return ns + "\x1f" + k }

func (s *Store) Get(ns, k string) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key(ns, k)]
	if !ok || e.expired(time.Now()) {
		return nil, false
	}
	return e.Value, true
}

// Set stores v; ttl <= 0 means no expiry.
func (s *Store) Set(ns, k string, v any, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := entry{Value: v}
	if ttl > 0 {
		e.Expires = time.Now().Add(ttl)
	}
	s.data[key(ns, k)] = e
	s.dirty = true
}

// Incr adds by to a numeric value and returns the result. The ttl applies
// only when the key is created, so a counter's window starts at its first
// increment.
func (s *Store) Incr(ns, k string, by float64, ttl time.Duration) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	e, ok := s.data[key(ns, k)]
	if !ok || e.expired(now) {
		e = entry{Value: 0.0}
		if ttl > 0 {
			e.Expires = now.Add(ttl)
		}
	}
	n, _ := e.Value.(float64)
	n += by
	e.Value = n
	s.data[key(ns, k)] = e
	s.dirty = true
	return n
}

func (s *Store) Delete(ns, k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key(ns, k))
	s.dirty = true
}

// Keys lists live keys in a namespace with the given prefix.
func (s *Store) Keys(ns, prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []string
	p := key(ns, prefix)
	for k, e := range s.data {
		if strings.HasPrefix(k, p) && !e.expired(now) {
			out = append(out, k[len(ns)+1:])
		}
	}
	return out
}

func (s *Store) loop() {
	defer close(s.done)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.Flush()
		case <-s.stop:
			s.Flush()
			return
		}
	}
}

// Flush writes pending changes, dropping expired entries.
func (s *Store) Flush() error {
	s.mu.Lock()
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	now := time.Now()
	for k, e := range s.data {
		if e.expired(now) {
			delete(s.data, k)
		}
	}
	b, err := json.Marshal(s.data)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Close flushes and stops the background writer.
func (s *Store) Close() error {
	close(s.stop)
	<-s.done
	return nil
}
