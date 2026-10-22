// Package audit writes one JSON line per policy decision.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one audit record.
type Entry struct {
	Time       time.Time `json:"ts"`
	Session    string    `json:"session,omitempty"`
	Label      string    `json:"label,omitempty"`
	Profile    string    `json:"profile,omitempty"`
	Transport  string    `json:"transport"`
	Service    string    `json:"service,omitempty"`
	Request    string    `json:"request"`
	Decision   string    `json:"decision"` // allow, deny, tunnel, error
	By         string    `json:"by,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Status     int       `json:"status,omitempty"`
	DurationMS int64     `json:"duration_ms"`
}

// Log appends entries to a file and optionally mirrors a summary elsewhere.
type Log struct {
	mu     sync.Mutex
	w      io.WriteCloser
	mirror func(Entry)
}

// Open appends to path. An empty path discards entries.
func Open(path string, mirror func(Entry)) (*Log, error) {
	l := &Log{mirror: mirror}
	if path == "" {
		return l, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.w = f
	return l, nil
}

func (l *Log) Write(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if l.mirror != nil {
		l.mirror(e)
	}
	if l.w == nil {
		return
	}
	b, _ := json.Marshal(e)
	l.mu.Lock()
	l.w.Write(append(b, '\n'))
	l.mu.Unlock()
}

func (l *Log) Close() error {
	if l.w == nil {
		return nil
	}
	return l.w.Close()
}
