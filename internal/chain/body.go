package chain

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MaxBuffer bounds how much of a body filters can buffer in memory.
const MaxBuffer = 16 << 20

// ErrTooLarge is returned when a body exceeds MaxBuffer.
var ErrTooLarge = fmt.Errorf("body exceeds %d byte inspection limit", MaxBuffer)

var errConsumed = errors.New("body already sent upstream")

// Body is a request or response body that can be inspected without
// consuming it. Bytes read for inspection are retained and replayed when the
// body is finally forwarded.
type Body struct {
	mu       sync.Mutex
	src      io.ReadCloser
	buf      []byte
	eof      bool
	err      error
	consumed bool
}

// NewBody wraps src, which may be nil for an empty body.
func NewBody(src io.ReadCloser) *Body {
	b := &Body{src: src}
	if src == nil {
		b.eof = true
	}
	return b
}

// BytesBody returns a body with fixed contents.
func BytesBody(data []byte) *Body {
	return &Body{buf: append([]byte(nil), data...), eof: true}
}

// fill reads until at least n bytes are buffered, EOF, or an error. Caller holds mu.
func (b *Body) fill(n int) error {
	if b.consumed {
		return errConsumed
	}
	if n > MaxBuffer {
		n = MaxBuffer + 1
	}
	for len(b.buf) < n && !b.eof && b.err == nil {
		chunk := make([]byte, max(4096, min(n-len(b.buf), 64<<10)))
		k, err := b.src.Read(chunk)
		b.buf = append(b.buf, chunk[:k]...)
		if err == io.EOF {
			b.eof = true
		} else if err != nil {
			b.err = err
		}
	}
	if len(b.buf) > MaxBuffer {
		return ErrTooLarge
	}
	return b.err
}

// Peek returns up to the first n bytes without consuming them.
func (b *Body) Peek(n int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.fill(n); err != nil {
		return nil, err
	}
	return append([]byte(nil), b.buf[:min(n, len(b.buf))]...), nil
}

// ReadAll buffers and returns the entire body (bounded by MaxBuffer).
func (b *Body) ReadAll() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.fill(MaxBuffer + 1); err != nil {
		return nil, err
	}
	return append([]byte(nil), b.buf...), nil
}

// Set replaces the body contents.
func (b *Body) Set(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.src != nil {
		b.src.Close()
	}
	b.src, b.buf, b.eof, b.err, b.consumed = nil, append([]byte(nil), data...), true, nil, false
}

// Len returns the body length if fully known, or -1.
func (b *Body) Len() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.eof && b.err == nil {
		return int64(len(b.buf))
	}
	return -1
}

// Reader returns the body for forwarding: buffered bytes followed by the
// unread remainder. After Reader is called, the body can no longer be inspected.
func (b *Body) Reader() io.ReadCloser {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consumed = true
	head := bytes.NewReader(b.buf)
	if b.eof || b.src == nil {
		return io.NopCloser(head)
	}
	return &replay{r: io.MultiReader(head, b.src), c: b.src}
}

type replay struct {
	r io.Reader
	c io.Closer
}

func (r *replay) Read(p []byte) (int, error) { return r.r.Read(p) }
func (r *replay) Close() error               { return r.c.Close() }

// PeekReader returns a sequential reader over the body that does not consume
// it: everything it reads stays buffered for forwarding.
func (b *Body) PeekReader() io.Reader { return &peekReader{b: b} }

type peekReader struct {
	b   *Body
	off int
}

func (p *peekReader) Read(out []byte) (int, error) {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	if err := p.b.fill(p.off + 1); err != nil && p.off >= len(p.b.buf) {
		return 0, err
	}
	if p.off >= len(p.b.buf) {
		return 0, io.EOF
	}
	n := copy(out, p.b.buf[p.off:])
	p.off += n
	return n, nil
}

// Close releases the underlying source.
func (b *Body) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.src != nil {
		return b.src.Close()
	}
	return nil
}
