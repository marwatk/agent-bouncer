// Package proxy is bouncer's HTTP(S) proxy. Hosts with a configured service
// are intercepted (TLS terminated with a bouncer-issued certificate) and run
// through the filter chain; other hosts are tunneled or refused.
package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/marwatk/agent-bouncer/internal/audit"
	"github.com/marwatk/agent-bouncer/internal/ca"
	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/creds"
	"github.com/marwatk/agent-bouncer/internal/gitproto"
	"github.com/marwatk/agent-bouncer/internal/policy"
)

// Backend supplies sessions and compiled policy; implemented by the daemon.
type Backend interface {
	// Session resolves a session token. An empty token asks for the
	// anonymous session, if one is configured.
	Session(token string) (*chain.Session, bool)
	Profile(name string) (*policy.Profile, bool)
	// Control serves the /_bouncer/ API.
	Control() http.Handler
}

// Server is the proxy http.Handler.
type Server struct {
	Backend   Backend
	CA        *ca.Authority
	Creds     *creds.Store
	Audit     *audit.Log
	Transport http.RoundTripper
	Dialer    *net.Dialer
	Logf      func(format string, args ...any)

	tunnelOnce      sync.Once
	publicTransport http.RoundTripper
}

// NewTransport returns the upstream transport. It never uses a proxy from the
// environment: the daemon's own environment may point at itself.
func NewTransport() *http.Transport {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		s.handleConnect(w, r)
	case r.URL.IsAbs():
		s.handleAbsolute(w, r)
	case strings.HasPrefix(r.URL.Path, "/_bouncer/"):
		s.Backend.Control().ServeHTTP(w, r)
	case strings.HasPrefix(r.URL.Path, "/s/"):
		s.handleReverse(w, r)
	default:
		http.Error(w, "agent-bouncer: this is a proxy; set HTTPS_PROXY (see `bouncer env`)", http.StatusNotFound)
	}
}

// proxySession authenticates a proxy client from Proxy-Authorization. The
// token is the Basic auth password (or the username if the password is empty).
func (s *Server) proxySession(r *http.Request) (*chain.Session, bool) {
	token := ""
	if h := r.Header.Get("Proxy-Authorization"); strings.HasPrefix(h, "Basic ") {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic ")); err == nil {
			user, pass, _ := strings.Cut(string(raw), ":")
			token = pass
			if token == "" {
				token = user
			}
		}
	}
	return s.Backend.Session(token)
}

func proxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="agent-bouncer"`)
	http.Error(w, "agent-bouncer: missing or unknown session token (run your agent via `bouncer exec`, or source `bouncer env`)",
		http.StatusProxyAuthRequired)
}

func (s *Server) entry(sess *chain.Session, transport, service, request string) audit.Entry {
	e := audit.Entry{Transport: transport, Service: service, Request: request}
	if sess != nil {
		e.Session, e.Label, e.Profile = sess.ID, sess.Label, sess.Profile
	}
	return e
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sess, ok := s.proxySession(r)
	if !ok {
		proxyAuthRequired(w)
		return
	}
	prof, ok := s.Backend.Profile(sess.Profile)
	if !ok {
		http.Error(w, "agent-bouncer: session profile no longer exists", http.StatusForbidden)
		return
	}
	target := r.Host
	if _, port := config.SplitHostPort(target); port == "" {
		target = net.JoinHostPort(target, "443")
	}
	svc := prof.MatchService(target)
	if svc == nil && !prof.Tunnels(target) {
		e := s.entry(sess, "http", "", "CONNECT "+target)
		e.Decision, e.Reason, e.Status, e.DurationMS = "deny", "host not allowed by profile "+prof.Name, 403, time.Since(start).Milliseconds()
		s.Audit.Write(e)
		http.Error(w, "agent-bouncer: "+e.Reason, http.StatusForbidden)
		return
	}

	// Dial unmatched hosts before accepting the CONNECT so a refusal reaches
	// the client as a status code rather than a dead tunnel.
	var up net.Conn
	var err error
	if svc == nil {
		e := s.entry(sess, "http", "", "CONNECT "+target)
		up, err = s.tunnelDial(r.Context(), prof.AllowPrivate, target)
		if err != nil {
			e.Decision, e.Reason, e.Status = "deny", err.Error(), 403
			if !errors.Is(err, errNonPublic) {
				e.Decision, e.Status = "error", 502
			}
			s.Audit.Write(e)
			http.Error(w, "agent-bouncer: "+err.Error(), e.Status)
			return
		}
		e.Decision = "tunnel"
		s.Audit.Write(e)
	}

	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		return
	}
	client := &bufferedConn{Conn: conn, r: buf.Reader}

	if up != nil {
		splice(client, up)
		return
	}

	// Only TLS can be inspected; anything else to an intercepted host is refused.
	first, err := client.r.Peek(1)
	if err != nil {
		client.Close()
		return
	}
	if first[0] != 0x16 {
		e := s.entry(sess, "http", svc.Config.Name, "CONNECT "+target)
		e.Decision, e.Reason = "deny", "non-TLS traffic to an intercepted host"
		s.Audit.Write(e)
		client.Close()
		return
	}
	host, _ := config.SplitHostPort(target)
	tlsConn := tls.Server(client, &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.CA.Leaf(host)
		},
	})
	if err := tlsConn.HandshakeContext(r.Context()); err != nil {
		s.logf("TLS handshake with client for %s failed (does it trust the bouncer CA?): %v", host, err)
		tlsConn.Close()
		return
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, ir *http.Request) {
			if h, _ := config.SplitHostPort(ir.Host); ir.Host != "" && !strings.EqualFold(h, host) {
				http.Error(w, "agent-bouncer: Host header does not match CONNECT target", http.StatusMisdirectedRequest)
				return
			}
			u := &url.URL{Scheme: "https", Host: hostForURL(target, "443"), Path: ir.URL.Path, RawPath: ir.URL.RawPath, RawQuery: ir.URL.RawQuery}
			s.intercept(w, ir, sess, prof, svc, u)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          nil,
	}
	srv.Serve(newOneConnListener(tlsConn))
}

// hostForURL drops the default port.
func hostForURL(hostport, defPort string) string {
	h, p := config.SplitHostPort(hostport)
	if p == defPort || p == "" {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return net.JoinHostPort(h, p)
}

// handleAbsolute serves plain-HTTP proxy requests (GET http://host/...).
func (s *Server) handleAbsolute(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.proxySession(r)
	if !ok {
		proxyAuthRequired(w)
		return
	}
	prof, ok := s.Backend.Profile(sess.Profile)
	if !ok {
		http.Error(w, "agent-bouncer: session profile no longer exists", http.StatusForbidden)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "agent-bouncer: unsupported scheme "+r.URL.Scheme, http.StatusBadRequest)
		return
	}
	hostport := r.URL.Host
	if _, port := config.SplitHostPort(hostport); port == "" {
		hostport = net.JoinHostPort(hostport, "80")
	}
	u := *r.URL
	u.Host = hostForURL(hostport, "80")
	if svc := prof.MatchService(hostport); svc != nil {
		s.intercept(w, r, sess, prof, svc, &u)
		return
	}
	e := s.entry(sess, "http", "", r.Method+" "+u.String())
	if !prof.Tunnels(hostport) {
		e.Decision, e.Reason, e.Status = "deny", "host not allowed by profile "+prof.Name, 403
		s.Audit.Write(e)
		http.Error(w, "agent-bouncer: "+e.Reason, http.StatusForbidden)
		return
	}
	e.Decision = "tunnel"
	s.Audit.Write(e)
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL = &u
	removeHopHeaders(out.Header)
	resp, err := s.tunnelTransport(prof.AllowPrivate).RoundTrip(out)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errNonPublic) {
			status = http.StatusForbidden
		}
		http.Error(w, "agent-bouncer: upstream error: "+err.Error(), status)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	copyFlush(w, resp.Body)
}

// handleReverse serves /s/<token>/<host>/<path>: an escape hatch for tools
// that can't use a proxy. Only configured services are reachable this way.
func (s *Server) handleReverse(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/s/")
	token, rest, _ := strings.Cut(rest, "/")
	hostport, path, _ := strings.Cut(rest, "/")
	sess, ok := s.Backend.Session(token)
	if !ok || token == "" {
		http.Error(w, "agent-bouncer: unknown session token", http.StatusUnauthorized)
		return
	}
	prof, ok := s.Backend.Profile(sess.Profile)
	if !ok {
		http.Error(w, "agent-bouncer: session profile no longer exists", http.StatusForbidden)
		return
	}
	target := hostport
	if _, port := config.SplitHostPort(target); port == "" {
		target = net.JoinHostPort(target, "443")
	}
	svc := prof.MatchService(target)
	if svc == nil {
		http.Error(w, "agent-bouncer: "+hostport+" is not a configured service", http.StatusForbidden)
		return
	}
	u, err := url.Parse("https://" + hostForURL(target, "443") + "/" + path)
	if err != nil {
		http.Error(w, "agent-bouncer: bad path", http.StatusBadRequest)
		return
	}
	u.RawQuery = r.URL.RawQuery
	s.intercept(w, r, sess, prof, svc, u)
}

// intercept runs one request through a service's chain and writes the result.
func (s *Server) intercept(w http.ResponseWriter, r *http.Request, sess *chain.Session, prof *policy.Profile, svc *policy.Service, u *url.URL) {
	start := time.Now()
	header := r.Header.Clone()
	removeHopHeaders(header)
	keepUpgrade(r.Header, header)
	req := &chain.Request{
		Ctx: r.Context(), Transport: chain.TransportHTTP, Session: sess, Profile: prof.Name, Service: svc.Config.Name,
		Method: r.Method, URL: u, Header: header, Body: chain.NewBody(r.Body),
	}
	e := s.entry(sess, "http", svc.Config.Name, req.Describe())
	defer func() {
		e.DurationMS = time.Since(start).Milliseconds()
		s.Audit.Write(e)
	}()

	err := chain.CheckMethod(r.Method)
	if err == nil {
		err = chain.CheckPath(u.Path)
	}
	if err == nil {
		err = chain.CheckMethodOverride(req)
	}
	if err != nil {
		e.Decision, e.By, e.Reason, e.Status = "deny", "bouncer", err.Error(), 400
		writeDenial(w, &chain.Denial{By: "bouncer", Reason: err.Error(), Status: 400})
		return
	}
	h := chain.Build(svc.Filters, s.forwarder(svc, r.ContentLength))
	resp, _ := h(req)
	if resp.Denial != nil {
		e.Decision, e.By, e.Reason, e.Status = "deny", resp.Denial.By, resp.Denial.Reason, resp.Denial.Status
		if result := pushRejection(req, resp.Denial); result != nil {
			// Consume the pack so the client reads our response instead of
			// failing mid-upload.
			io.Copy(io.Discard, io.LimitReader(req.Body.Reader(), 1<<30))
			w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			w.Write(result)
			return
		}
		writeDenial(w, resp.Denial)
		if resp.Body != nil {
			resp.Body.Close()
		}
		return
	}
	e.Decision, e.By, e.Status = "allow", req.AllowedBy, resp.Status
	s.writeResponse(w, resp)
}

// pushRejection renders a denied git push as a receive-pack result, which
// git displays far better than an HTTP error.
func pushRejection(req *chain.Request, d *chain.Denial) []byte {
	if !req.IsPushRequest() {
		return nil
	}
	push, err := req.Push()
	if err != nil {
		return nil
	}
	return gitproto.RejectPush(push, fmt.Sprintf("denied by %s: %s", d.By, d.Reason))
}

func writeDenial(w http.ResponseWriter, d *chain.Denial) {
	status := d.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Bouncer-Denied-By", d.By)
	w.WriteHeader(status)
	fmt.Fprintf(w, "agent-bouncer: request denied by %s: %s\n", d.By, d.Reason)
}

func (s *Server) writeResponse(w http.ResponseWriter, resp *chain.Response) {
	if resp.Status == http.StatusSwitchingProtocols && resp.Upgrade != nil {
		s.writeUpgrade(w, resp)
		return
	}
	h := resp.Header
	removeHopHeaders(h)
	copyHeader(w.Header(), h)
	var body io.ReadCloser = io.NopCloser(strings.NewReader(""))
	if resp.Body != nil {
		body = resp.Body.Reader()
		if n := resp.Body.Len(); n >= 0 {
			w.Header().Set("Content-Length", fmt.Sprint(n))
		}
	}
	defer body.Close()
	w.WriteHeader(resp.Status)
	copyFlush(w, body)
}

func (s *Server) writeUpgrade(w http.ResponseWriter, resp *chain.Response) {
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		resp.Upgrade.Close()
		return
	}
	fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\n")
	resp.Header.Write(buf)
	buf.WriteString("\r\n")
	if err := buf.Flush(); err != nil {
		conn.Close()
		resp.Upgrade.Close()
		return
	}
	splice(&bufferedConn{Conn: conn, r: buf.Reader}, resp.Upgrade)
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// copyFlush streams a body, flushing as data arrives (for SSE and long polls).
func copyFlush(w http.ResponseWriter, r io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// keepUpgrade restores the headers needed to forward a protocol upgrade.
func keepUpgrade(orig, h http.Header) {
	if up := orig.Get("Upgrade"); up != "" && strings.Contains(strings.ToLower(orig.Get("Connection")), "upgrade") {
		h.Set("Connection", "Upgrade")
		h.Set("Upgrade", up)
	}
}

// splice copies bidirectionally until both directions finish.
func splice(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// bufferedConn is a hijacked conn whose reads go through the server's buffer.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// oneConnListener hands a single connection to http.Server and then blocks
// until that connection closes, so Serve returns when the client is done.
type oneConnListener struct {
	conn      net.Conn
	once      sync.Once
	closeOnce sync.Once
	closed    chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{closed: make(chan struct{})}
	l.conn = &notifyCloseConn{Conn: c, onClose: func() { l.Close() }}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyCloseConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *notifyCloseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}
