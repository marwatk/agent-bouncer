// Package sshproxy terminates SSH from agents and re-originates it upstream
// with the user's real key, applying policy to every channel request.
//
// Agents reach it through `bouncer ssh-connect` (an ssh ProxyCommand), which
// sends a one-line preamble naming the session and target before the SSH
// handshake begins.
package sshproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/marwatk/agent-bouncer/internal/audit"
	"github.com/marwatk/agent-bouncer/internal/ca"
	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/creds"
	"github.com/marwatk/agent-bouncer/internal/gitproto"
	"github.com/marwatk/agent-bouncer/internal/policy"
)

const preamblePrefix = "BOUNCER-SSH/1 "

// Preamble is sent by ssh-connect before the SSH stream.
type Preamble struct {
	Token string `json:"token"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	User  string `json:"user"`
}

// Backend supplies sessions and compiled policy.
type Backend interface {
	Session(token string) (*chain.Session, bool)
	Profile(name string) (*policy.Profile, bool)
}

// Server accepts preamble-prefixed SSH connections.
type Server struct {
	Backend Backend
	CA      *ca.Authority
	Creds   *creds.Store
	Audit   *audit.Log
	Logf    func(format string, args ...any)
	// Dial connects to upstream hosts; defaults to a 30s-timeout TCP dial.
	Dial func(network, addr string) (net.Conn, error)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Serve accepts connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// conn is one agent connection.
type conn struct {
	ctx      context.Context
	s        *Server
	sess     *chain.Session
	prof     *policy.Profile
	svc      *policy.SSHService
	host     string
	user     string
	upstream *ssh.Client
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(60 * time.Second))
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, preamblePrefix) {
		return
	}
	var p Preamble
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, preamblePrefix)), &p); err != nil {
		fmt.Fprintf(c, "ERR malformed preamble\n")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cn, err := s.prepare(ctx, &p)
	if err != nil {
		e := audit.Entry{Transport: "ssh", Request: fmt.Sprintf("ssh %s@%s connect", p.User, p.Host), Decision: "deny", Reason: err.Error()}
		if cn != nil && cn.sess != nil {
			e.Session, e.Label, e.Profile = cn.sess.ID, cn.sess.Label, cn.sess.Profile
		}
		s.Audit.Write(e)
		fmt.Fprintf(c, "ERR %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
		return
	}
	defer cn.upstream.Close()
	if _, err := fmt.Fprintf(c, "OK\n"); err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	signer, err := s.CA.SSHHostSigner(cn.host)
	if err != nil {
		s.logf("ssh host cert for %s: %v", cn.host, err)
		return
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-agent-bouncer"}
	cfg.AddHostKey(signer)
	sc, chans, reqs, err := ssh.NewServerConn(&bufConn{Conn: c, r: br}, cfg)
	if err != nil {
		s.logf("ssh handshake with agent for %s failed (is it using the bouncer known_hosts?): %v", cn.host, err)
		return
	}
	defer sc.Close()
	go cn.globalRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			go cn.session(nc)
		case "direct-tcpip":
			go cn.directTCPIP(nc)
		default:
			nc.Reject(ssh.UnknownChannelType, "agent-bouncer: channel type not supported")
		}
	}
}

// prepare authenticates the preamble and connects upstream, so failures can
// be reported to the agent as plain text before the SSH handshake.
func (s *Server) prepare(ctx context.Context, p *Preamble) (*conn, error) {
	sess, ok := s.Backend.Session(p.Token)
	if !ok || p.Token == "" {
		return nil, errors.New("unknown session token (run the agent via `bouncer exec` or source `bouncer env`)")
	}
	cn := &conn{ctx: ctx, s: s, sess: sess}
	prof, ok := s.Backend.Profile(sess.Profile)
	if !ok {
		return cn, errors.New("session profile no longer exists")
	}
	host := strings.ToLower(p.Host)
	svc := prof.MatchSSH(host)
	if svc == nil {
		return cn, fmt.Errorf("ssh to %s is not configured in profile %s", host, prof.Name)
	}
	user := p.User
	if svc.Config.User != "" {
		if user != "" && user != svc.Config.User {
			return cn, fmt.Errorf("ssh to %s is only allowed as user %s", host, svc.Config.User)
		}
		user = svc.Config.User
	}
	port := p.Port
	if svc.Config.Port != 0 {
		port = svc.Config.Port
	}
	if port == 0 {
		port = 22
	}
	cn.prof, cn.svc, cn.host, cn.user = prof, svc, host, user

	signers, err := s.Creds.SSHSigners(ctx, svc.Config.Credential)
	if err != nil {
		return cn, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	hkcb, algos, err := hostKeyCallback(svc.Config, addr)
	if err != nil {
		return cn, err
	}
	dial := s.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second}).Dial
	}
	raw, err := dial("tcp", addr)
	if err != nil {
		return cn, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(raw, addr, &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback:   hkcb,
		HostKeyAlgorithms: algos,
		Timeout:           30 * time.Second,
	})
	if err != nil {
		raw.Close()
		return cn, fmt.Errorf("upstream ssh to %s: %w", addr, err)
	}
	cn.upstream = ssh.NewClient(cc, chans, reqs)
	return cn, nil
}

// hostKeyCallback verifies the upstream host key against a pinned key or
// known_hosts files. It also returns the key algorithms known for the host so
// the handshake negotiates a key type we can actually verify.
func hostKeyCallback(svc *config.SSHService, addr string) (ssh.HostKeyCallback, []string, error) {
	if svc.HostKey != "" {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(svc.HostKey))
		if err != nil {
			return nil, nil, fmt.Errorf("ssh %s: host_key: %w", svc.Name, err)
		}
		return ssh.FixedHostKey(pk), []string{pk.Type()}, nil
	}
	files := svc.KnownHosts
	if len(files) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, err
		}
		files = []string{filepath.Join(home, ".ssh", "known_hosts")}
	}
	var existing []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			existing = append(existing, f)
		}
	}
	if len(existing) == 0 {
		return nil, nil, fmt.Errorf("ssh %s: no known_hosts file found (%s); connect once with plain ssh or set host_key", svc.Name, strings.Join(files, ", "))
	}
	cb, err := knownhosts.New(existing...)
	if err != nil {
		return nil, nil, err
	}
	// Probe with a throwaway key to learn which key types are on file.
	var algos []string
	tcp, _ := net.ResolveTCPAddr("tcp", addr)
	if err := cb(addr, tcp, probeKey{}); err != nil {
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) {
			if len(ke.Want) == 0 {
				return nil, nil, fmt.Errorf("ssh %s: %s is not in known_hosts; connect once with plain ssh or set host_key", svc.Name, addr)
			}
			for _, k := range ke.Want {
				algos = append(algos, hostKeyAlgorithms(k.Key.Type())...)
			}
		}
	}
	return cb, algos, nil
}

func hostKeyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

type probeKey struct{}

func (probeKey) Type() string                        { return "bouncer-probe" }
func (probeKey) Marshal() []byte                     { return []byte("bouncer-probe") }
func (probeKey) Verify([]byte, *ssh.Signature) error { return errors.New("probe") }

func (cn *conn) entry(req *chain.Request) audit.Entry {
	return audit.Entry{Session: cn.sess.ID, Label: cn.sess.Label, Profile: cn.sess.Profile, Transport: "ssh",
		Service: cn.svc.Config.Name, Request: req.Describe()}
}

// decide runs the chain for a channel request.
func (cn *conn) decide(req *chain.Request) *chain.Response {
	start := time.Now()
	h := chain.Build(cn.svc.Filters, func(*chain.Request) (*chain.Response, error) { return chain.Allowed(), nil })
	resp, _ := h(req)
	e := cn.entry(req)
	e.DurationMS = time.Since(start).Milliseconds()
	if resp.Denial != nil {
		e.Decision, e.By, e.Reason = "deny", resp.Denial.By, resp.Denial.Reason
	} else {
		e.Decision, e.By = "allow", req.AllowedBy
	}
	cn.s.Audit.Write(e)
	return resp
}

func (cn *conn) request(kind string) *chain.Request {
	return &chain.Request{Ctx: cn.ctx, Transport: chain.TransportSSH, Session: cn.sess, Profile: cn.prof.Name,
		Service: cn.svc.Config.Name, SSH: &chain.SSHInfo{Host: cn.host, User: cn.user, Kind: kind}}
}

func (cn *conn) globalRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.Type == "tcpip-forward" {
			req := cn.request(config.SSHKindForward)
			req.SSH.Target = "remote listen"
			e := cn.entry(req)
			e.Decision, e.By, e.Reason = "deny", "bouncer", "remote port forwarding is not supported"
			cn.s.Audit.Write(e)
		}
		if r.WantReply {
			r.Reply(false, nil)
		}
	}
}

func (cn *conn) directTCPIP(nc ssh.NewChannel) {
	var p struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
		nc.Reject(ssh.ConnectionFailed, "bad direct-tcpip request")
		return
	}
	req := cn.request(config.SSHKindForward)
	req.SSH.Target = net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
	if resp := cn.decide(req); resp.Denial != nil {
		nc.Reject(ssh.Prohibited, "agent-bouncer: "+resp.Denial.Reason)
		return
	}
	up, err := cn.upstream.Dial("tcp", req.SSH.Target)
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		up.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(up, ch); up.Close() }()
	go func() { defer wg.Done(); io.Copy(ch, up); ch.CloseWrite() }()
	wg.Wait()
	ch.Close()
}

// session handles one session channel: buffer setup requests (pty, env)
// until exec/shell/subsystem, decide, then bridge to an upstream channel.
func (cn *conn) session(nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	var setup []*ssh.Request
	env := map[string]string{}
	var up ssh.Channel
	var started bool
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			setup = append(setup, r)
			if r.WantReply {
				r.Reply(true, nil)
			}
		case "env":
			// Only allowlisted variables reach upstream; an arbitrary env
			// var could change what the remote command does.
			var e struct{ Name, Value string }
			ok := ssh.Unmarshal(r.Payload, &e) == nil && cn.svc.Config.EnvAllowed(e.Name)
			if ok {
				setup = append(setup, r)
				env[e.Name] = e.Value
			}
			if r.WantReply {
				r.Reply(ok, nil)
			}
		case "exec", "shell", "subsystem":
			if started {
				r.Reply(false, nil)
				continue
			}
			started = true
			up = cn.start(ch, r, setup, env)
			if up == nil {
				return
			}
			defer up.Close()
		case "window-change", "signal", "break":
			if up != nil {
				ok, _ := up.SendRequest(r.Type, r.WantReply, r.Payload)
				if r.WantReply {
					r.Reply(ok, nil)
				}
			} else if r.WantReply {
				r.Reply(false, nil)
			}
		default:
			// auth-agent-req@openssh.com, x11-req, and anything unknown are
			// refused: agent forwarding would hand the remote host our keys.
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}
}

// start decides on an exec/shell/subsystem request and, if allowed, wires up
// the upstream channel. It returns nil if the session is over.
func (cn *conn) start(ch ssh.Channel, r *ssh.Request, setup []*ssh.Request, env map[string]string) ssh.Channel {
	req := cn.request("")
	if len(env) > 0 {
		req.SSH.Env = env
	}
	switch r.Type {
	case "shell":
		req.SSH.Kind = config.SSHKindShell
	case "exec":
		var p struct{ Command string }
		ssh.Unmarshal(r.Payload, &p)
		req.SSH.Command = p.Command
		req.SSH.Kind = config.SSHKindExec
		if req.Git() != nil {
			req.SSH.Kind = config.SSHKindGit
		}
	case "subsystem":
		var p struct{ Name string }
		ssh.Unmarshal(r.Payload, &p)
		req.SSH.Subsystem = p.Name
		req.SSH.Kind = "subsystem"
		if p.Name == "sftp" {
			req.SSH.Kind = config.SSHKindSFTP
		}
	}

	// A push is decided after the agent sends its ref updates, which it does
	// only after seeing the upstream's ref advertisement, so the upstream
	// channel must be live while the filters run.
	isPush := req.Git() != nil && req.Git().Service == gitproto.ServiceReceivePack
	if !isPush {
		if resp := cn.decide(req); resp.Denial != nil {
			r.Reply(true, nil)
			refuse(ch, resp.Denial)
			return nil
		}
	}

	up, upReqs, err := cn.upstream.OpenChannel("session", nil)
	if err != nil {
		r.Reply(false, nil)
		fmt.Fprintf(ch.Stderr(), "agent-bouncer: upstream session: %v\r\n", err)
		return nil
	}
	for _, s := range setup {
		up.SendRequest(s.Type, false, s.Payload)
	}
	ok, err := up.SendRequest(r.Type, true, r.Payload)
	if err != nil || !ok {
		r.Reply(false, nil)
		up.Close()
		return nil
	}
	r.Reply(true, nil)

	// The client channel closes once upstream output is drained and its
	// request stream (carrying exit-status) has ended.
	var upstreamDone sync.WaitGroup
	upstreamDone.Add(3)
	go func() { defer upstreamDone.Done(); io.Copy(ch, up) }()
	go func() { defer upstreamDone.Done(); io.Copy(ch.Stderr(), up.Stderr()) }()
	go func() {
		defer upstreamDone.Done()
		for ur := range upReqs {
			ok, _ := ch.SendRequest(ur.Type, ur.WantReply, ur.Payload)
			if ur.WantReply {
				ur.Reply(ok, nil)
			}
		}
	}()

	var stdin io.Reader = ch
	if isPush {
		req.Body = chain.NewBody(io.NopCloser(ch))
		if resp := cn.decide(req); resp.Denial != nil {
			// Upstream never sees the commands, so no ref is touched.
			up.Close()
			push, _ := req.Push()
			if result := gitproto.RejectPush(push, fmt.Sprintf("denied by %s: %s", resp.Denial.By, resp.Denial.Reason)); result != nil {
				ch.Write(result)
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				ch.CloseWrite()
				ch.Close()
				return nil
			}
			refuse(ch, resp.Denial)
			return nil
		}
		stdin = req.Body.Reader()
	}
	go func() {
		io.Copy(up, stdin)
		up.CloseWrite()
	}()
	go func() {
		upstreamDone.Wait()
		ch.CloseWrite()
		ch.Close()
	}()
	return up
}

func refuse(ch ssh.Channel, d *chain.Denial) {
	fmt.Fprintf(ch.Stderr(), "agent-bouncer: denied by %s: %s\r\n", d.By, d.Reason)
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
	ch.CloseWrite()
	ch.Close()
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
