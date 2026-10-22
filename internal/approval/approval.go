// Package approval holds requests waiting on a human decision.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/marwatk/agent-bouncer/internal/chain"
)

// Pending is a request awaiting a decision.
type Pending struct {
	ID           string    `json:"id"`
	Prompt       string    `json:"prompt"`
	Request      string    `json:"request"`
	Filter       string    `json:"filter"`
	SessionID    string    `json:"session_id"`
	SessionLabel string    `json:"session_label"`
	Profile      string    `json:"profile"`
	Created      time.Time `json:"created"`
	Expires      time.Time `json:"expires"`

	key     string // remember key: session + ask key
	joinKey string // remember key + request text
	done    chan struct{}
	result  bool
}

// Event notifies subscribers of changes.
type Event struct {
	Type    string // "pending" or "resolved"
	Pending Pending
	Allowed bool
}

// Manager tracks pending approvals and remembered per-session decisions.
type Manager struct {
	mu         sync.Mutex
	timeout    time.Duration
	pending    map[string]*Pending
	byKey      map[string]*Pending
	remembered map[string]bool
	subs       map[chan Event]struct{}
	// Notify, if set, is called (in a goroutine) for each new pending approval.
	Notify func(p Pending)
}

func NewManager(timeout time.Duration) *Manager {
	return &Manager{timeout: timeout, pending: map[string]*Pending{}, byKey: map[string]*Pending{},
		remembered: map[string]bool{}, subs: map[chan Event]struct{}{}}
}

// SetTimeout changes the timeout for future asks.
func (m *Manager) SetTimeout(d time.Duration) {
	m.mu.Lock()
	m.timeout = d
	m.mu.Unlock()
}

func rememberKey(sessionID, key string) string { return sessionID + "\x00" + key }

// Ask blocks until the request is approved, denied, times out, or ctx ends.
// Identical concurrent asks from one session share a single prompt.
func (m *Manager) Ask(ctx context.Context, a chain.AskRequest) (bool, error) {
	// Without an explicit key, a decision covers only this exact request:
	// keying on the prompt alone would let one approval of a static prompt
	// cover unrelated requests.
	key := a.Key
	if key == "" {
		key = a.Prompt + "\x00" + a.Request
	}
	sid, label, profile := "", "", ""
	if a.Session != nil {
		sid, label, profile = a.Session.ID, a.Session.Label, a.Session.Profile
	}
	rk := rememberKey(sid, key)
	// Only identical requests share a pending prompt, so the human always
	// sees the request their answer applies to.
	jk := rk + "\x00" + a.Request

	m.mu.Lock()
	if v, ok := m.remembered[rk]; ok {
		m.mu.Unlock()
		return v, nil
	}
	p, existing := m.byKey[jk]
	if !existing {
		now := time.Now()
		p = &Pending{ID: newID(), Prompt: a.Prompt, Request: a.Request, Filter: a.Filter, SessionID: sid,
			SessionLabel: label, Profile: profile, Created: now, Expires: now.Add(m.timeout), key: rk, joinKey: jk, done: make(chan struct{})}
		m.pending[p.ID] = p
		m.byKey[jk] = p
		m.broadcast(Event{Type: "pending", Pending: *p})
	}
	timeout := time.Until(p.Expires)
	m.mu.Unlock()

	if !existing && m.Notify != nil {
		go m.Notify(*p)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.done:
		return p.result, nil
	case <-timer.C:
		m.resolve(p, false, false)
		return false, errors.New("approval timed out")
	case <-ctx.Done():
		// Only the original asker withdraws the prompt; joiners just leave.
		if !existing {
			m.resolve(p, false, false)
		}
		return false, ctx.Err()
	}
}

// Resolve answers a pending approval. remember applies the decision to
// identical requests for the rest of the session.
func (m *Manager) Resolve(id string, allow, remember bool) error {
	m.mu.Lock()
	p, ok := m.pending[id]
	m.mu.Unlock()
	if !ok {
		return errors.New("no such pending approval: " + id)
	}
	m.resolve(p, allow, remember)
	return nil
}

func (m *Manager) resolve(p *Pending, allow, remember bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pending[p.ID]; !ok {
		return
	}
	settle := func(q *Pending) {
		delete(m.pending, q.ID)
		delete(m.byKey, q.joinKey)
		q.result = allow
		close(q.done)
		m.broadcast(Event{Type: "resolved", Pending: *q, Allowed: allow})
	}
	settle(p)
	if remember {
		m.remembered[p.key] = allow
		// A session-wide answer also settles other pending asks it covers.
		for _, q := range m.pending {
			if q.key == p.key {
				settle(q)
			}
		}
	}
}

// List returns pending approvals, oldest first.
func (m *Manager) List() []Pending {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Pending, 0, len(m.pending))
	for _, p := range m.pending {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// ForgetSession drops remembered decisions for a session.
func (m *Manager) ForgetSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := sessionID + "\x00"
	for k := range m.remembered {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(m.remembered, k)
		}
	}
}

// Subscribe returns a channel of events and a cancel func.
func (m *Manager) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	m.mu.Lock()
	m.subs[ch] = struct{}{}
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		delete(m.subs, ch)
		m.mu.Unlock()
	}
}

func (m *Manager) broadcast(e Event) {
	for ch := range m.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

func newID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return hex.EncodeToString(b)
}
