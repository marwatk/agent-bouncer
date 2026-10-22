// Package chain is bouncer's transport-independent policy core: the request
// model filters see, the servlet-style filter chain, and declarative rules.
package chain

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/marwatk/agent-bouncer/internal/gitproto"
	"github.com/marwatk/agent-bouncer/internal/gql"
)

const (
	TransportHTTP = "http"
	TransportSSH  = "ssh"
)

// Session identifies an agent session (one `bouncer exec`/`bouncer env`).
type Session struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Profile string `json:"profile"`
	// Shared marks a session used by many clients (the anonymous profile);
	// "for this session" approvals are not remembered for it.
	Shared bool `json:"-"`
}

// SSHInfo describes an SSH channel request.
type SSHInfo struct {
	Host string `json:"host"`
	User string `json:"user"`
	// Kind is git, exec, shell, sftp or forward.
	Kind      string `json:"kind"`
	Command   string `json:"command,omitempty"`
	Subsystem string `json:"subsystem,omitempty"`
	// Target is host:port for port forwards.
	Target string `json:"target,omitempty"`
	// Env holds the allowlisted environment variables the client set.
	Env map[string]string `json:"env,omitempty"`
}

// Request is what filters and rules evaluate. For HTTP it is an intercepted
// request; for SSH it is a channel request (exec, shell, ...).
type Request struct {
	Ctx       context.Context
	Transport string
	Session   *Session
	Profile   string
	Service   string

	// HTTP
	Method string
	URL    *url.URL
	Header http.Header
	// Body is the HTTP request body, or for SSH the client's stdin stream.
	Body *Body

	SSH *SSHInfo

	// AllowedBy records which rule or default let the request through, for the audit log.
	AllowedBy string

	gitOnce sync.Once
	git     *gitproto.Info

	pushOnce sync.Once
	push     *gitproto.Push
	pushErr  error

	gqlOnce sync.Once
	gqlOps  []gql.Operation
	gqlErr  error
}

// Host returns the upstream hostname (without port).
func (r *Request) Host() string {
	if r.SSH != nil {
		return r.SSH.Host
	}
	if r.URL == nil {
		return ""
	}
	return r.URL.Hostname()
}

// Path is the percent-decoded URL path.
func (r *Request) Path() string {
	if r.URL == nil {
		return ""
	}
	return r.URL.Path
}

// RawPath is the URL path as sent, with percent-encoding intact.
func (r *Request) RawPath() string {
	if r.URL == nil {
		return ""
	}
	return r.URL.EscapedPath()
}

// Git returns git protocol info if this is a git request, else nil.
func (r *Request) Git() *gitproto.Info {
	r.gitOnce.Do(func() {
		switch r.Transport {
		case TransportHTTP:
			if r.URL != nil {
				r.git, _ = gitproto.FromHTTP(r.URL.Path, r.URL.Query())
				// A push body is a push wherever it's sent: servers may route
				// URL shapes we don't recognize, and ref policy must still run.
				if r.isPushContent() && (r.git == nil || r.git.Service != gitproto.ServiceReceivePack) {
					repo := strings.TrimSuffix(strings.TrimRight(r.URL.Path, "/"), "/git-receive-pack")
					r.git = &gitproto.Info{Service: gitproto.ServiceReceivePack, Repo: strings.TrimSuffix(strings.Trim(repo, "/"), ".git")}
				}
			}
		case TransportSSH:
			if r.SSH != nil && r.SSH.Command != "" {
				r.git, _ = gitproto.FromSSHCommand(r.SSH.Command)
			}
		}
	})
	return r.git
}

// Push parses the ref updates of a git push. It returns an empty Push for
// git requests that carry no commands (e.g. the ref advertisement), and nil
// for non-push requests.
func (r *Request) Push() (*gitproto.Push, error) {
	g := r.Git()
	if g == nil || g.Service != gitproto.ServiceReceivePack {
		return nil, nil
	}
	r.pushOnce.Do(func() {
		if r.Transport == TransportHTTP && !r.IsPushRequest() {
			r.push = &gitproto.Push{}
			return
		}
		if r.Body == nil {
			r.push = &gitproto.Push{}
			return
		}
		var src io.Reader = r.Body.PeekReader()
		if r.Header != nil && strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			zr, err := gzip.NewReader(src)
			if err != nil {
				r.pushErr = fmt.Errorf("gzip push body: %w", err)
				return
			}
			src = zr
		}
		r.push, r.pushErr = gitproto.ParsePush(src)
	})
	return r.push, r.pushErr
}

func (r *Request) isPushContent() bool {
	if r.Header == nil {
		return false
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return ct == gitproto.PushContentType
}

// IsPushRequest reports whether an HTTP request carries push commands (as
// opposed to the ref advertisement that precedes a push).
func (r *Request) IsPushRequest() bool {
	if r.Transport != TransportHTTP || r.Method != http.MethodPost || r.URL == nil {
		return false
	}
	return strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "/git-receive-pack") || r.isPushContent()
}

// GraphQL summarizes the GraphQL operations in the request, or returns nil
// if it isn't a GraphQL request.
func (r *Request) GraphQL() ([]gql.Operation, error) {
	r.gqlOnce.Do(func() {
		if r.Transport != TransportHTTP {
			return
		}
		var body []byte
		if r.Method != http.MethodGet && r.Body != nil {
			body, r.gqlErr = r.Body.ReadAll()
			if r.gqlErr != nil {
				return
			}
			if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
				body, r.gqlErr = gunzip(body)
				if r.gqlErr != nil {
					return
				}
			}
		}
		r.gqlOps, r.gqlErr = gql.FromHTTP(r.Method, r.URL.Query(), r.Header, body)
	})
	return r.gqlOps, r.gqlErr
}

// gunzip decodes a gzip body, bounded like any inspected body.
func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("gzip body: %w", err)
	}
	out, err := io.ReadAll(io.LimitReader(zr, MaxBuffer+1))
	if err != nil {
		return nil, fmt.Errorf("gzip body: %w", err)
	}
	if len(out) > MaxBuffer {
		return nil, ErrTooLarge
	}
	return out, nil
}

// Describe is a short human description, used in prompts and logs.
func (r *Request) Describe() string {
	if r.SSH != nil {
		s := fmt.Sprintf("ssh %s@%s %s", r.SSH.User, r.SSH.Host, r.SSH.Kind)
		switch {
		case r.SSH.Command != "":
			s += ": " + r.SSH.Command
		case r.SSH.Subsystem != "":
			s += ": " + r.SSH.Subsystem
		case r.SSH.Target != "":
			s += " to " + r.SSH.Target
		}
		return s
	}
	if r.URL == nil {
		return r.Method
	}
	return r.Method + " " + r.URL.Host + r.URL.RequestURI()
}

// Response is what a chain produces: an upstream response, a synthetic
// response from a filter, or a denial.
type Response struct {
	Status int
	Header http.Header
	Body   *Body
	// Upgrade is the upstream connection after a 101 Switching Protocols.
	Upgrade io.ReadWriteCloser
	Denial  *Denial
}

// Denial explains why a request was refused.
type Denial struct {
	By     string
	Reason string
	Status int
}

// Deny builds a denial response.
func Deny(by, reason string) *Response {
	return &Response{Status: http.StatusForbidden, Denial: &Denial{By: by, Reason: reason, Status: http.StatusForbidden}}
}

// Allowed is the terminal response for transports with no upstream response to
// return through the chain (SSH channel requests).
func Allowed() *Response { return &Response{Status: http.StatusOK} }
