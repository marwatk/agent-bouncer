package sshproxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/marwatk/agent-bouncer/internal/audit"
	"github.com/marwatk/agent-bouncer/internal/ca"
	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/creds"
	"github.com/marwatk/agent-bouncer/internal/gitproto"
	"github.com/marwatk/agent-bouncer/internal/policy"
)

type backend struct{ set *policy.Set }

func (b backend) Session(tok string) (*chain.Session, bool) {
	if tok == "tok" {
		return &chain.Session{ID: "s1", Profile: "p"}, true
	}
	return nil, false
}
func (b backend) Profile(n string) (*policy.Profile, bool) { p, ok := b.set.Profiles[n]; return p, ok }

// upstream is a fake SSH server standing in for gitlab.com.
type upstream struct {
	addr     string
	hostKey  ssh.PublicKey
	mu       sync.Mutex
	received map[string][]byte
}

func startUpstream(t *testing.T, clientKey ssh.PublicKey) *upstream {
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hk)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), clientKey.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("unauthorized")
	}}
	cfg.AddHostKey(hs)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	u := &upstream{addr: l.Addr().String(), hostKey: hs.PublicKey(), received: map[string][]byte{}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go u.serve(ch, creqs)
				}
			}()
		}
	}()
	return u
}

func (u *upstream) serve(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			r.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		ssh.Unmarshal(r.Payload, &p)
		r.Reply(true, nil)
		switch {
		case p.Command == "echo hi":
			io.WriteString(ch, "hi\n")
		case strings.HasPrefix(p.Command, "git-receive-pack"):
			ch.Write(gitproto.EncodePkt(strings.Repeat("a", 40) + " refs/heads/main\x00report-status\n"))
			ch.Write(gitproto.Flush)
			data, _ := io.ReadAll(ch)
			u.mu.Lock()
			u.received[p.Command] = data
			u.mu.Unlock()
			io.WriteString(ch, "pushed\n")
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

func setup(t *testing.T) (*upstream, string, *ca.Authority) {
	dir := t.TempDir()
	_, ck, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(ck, "")
	keyPath := filepath.Join(dir, "id")
	os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600)
	cs, _ := ssh.NewSignerFromKey(ck)
	up := startUpstream(t, cs.PublicKey())
	_, port, _ := net.SplitHostPort(up.addr)

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
credentials:
  key: {source: file, path: %s}
profiles:
  p:
    ssh:
      - name: up
        hosts: [127.0.0.1]
        port: %s
        user: git
        credential: key
        host_key: %q
        allow: [git, exec]
        default: allow
        rules:
          - action: deny
            reason: main is protected
            git: {service: receive-pack, refs: [refs/heads/main]}
`, keyPath, port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(up.hostKey))))), filepath.Join(dir, "c.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.Compile(cfg, &chain.Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := ca.LoadOrCreate(filepath.Join(dir, "state"))
	log, _ := audit.Open("", nil)
	srv := &Server{Backend: backend{set}, CA: authority, Creds: creds.NewStore(cfg.Credentials), Audit: log}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { l.Close() })
	go srv.Serve(l)
	return up, l.Addr().String(), authority
}

func client(t *testing.T, bouncer string, authority *ca.Authority, token string) (*ssh.Client, error) {
	c, err := Dial(bouncer, Preamble{Token: token, Host: "127.0.0.1", Port: 22, User: "git"})
	if err != nil {
		return nil, err
	}
	checker := &ssh.CertChecker{IsHostAuthority: func(k ssh.PublicKey, _ string) bool {
		return bytes.Equal(k.Marshal(), authority.SSHCAPublicKey().Marshal())
	}}
	cc, chans, reqs, err := ssh.NewClientConn(c, "127.0.0.1:22", &ssh.ClientConfig{User: "git", HostKeyCallback: checker.CheckHostKey})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

func run(t *testing.T, cl *ssh.Client, cmd string, stdin []byte) (string, string, error) {
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	if stdin != nil {
		s.Stdin = bytes.NewReader(stdin)
	}
	if cmd == "" {
		err = s.Shell()
		if err == nil {
			err = s.Wait()
		}
	} else {
		err = s.Run(cmd)
	}
	return out.String(), errb.String(), err
}

func TestSSHPolicy(t *testing.T) {
	up, addr, authority := setup(t)
	cl, err := client(t, addr, authority, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if out, _, err := run(t, cl, "echo hi", nil); err != nil || out != "hi\n" {
		t.Fatalf("exec: %q %v", out, err)
	}
	if _, stderr, err := run(t, cl, "", nil); err == nil || !strings.Contains(stderr, "ssh shell is not in the allow list") {
		t.Fatalf("shell should be denied: %q %v", stderr, err)
	}

	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	ok := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/feature"}}, []string{"report-status"}, nil)
	out, _, err := run(t, cl, "git-receive-pack 'g/feature.git'", ok)
	if err != nil || out == "" || !strings.HasSuffix(out, "pushed\n") {
		t.Fatalf("allowed push: %q %v", out, err)
	}
	up.mu.Lock()
	got := up.received["git-receive-pack 'g/feature.git'"]
	up.mu.Unlock()
	if !bytes.Equal(got, ok) {
		t.Fatalf("upstream received %q, want %q", got, ok)
	}

	bad := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/main"}}, []string{"report-status"}, nil)
	// Denied pushes come back as a receive-pack status report so git shows
	// "! [remote rejected] main -> main (...)".
	out, _, _ = run(t, cl, "git-receive-pack 'g/main.git'", bad)
	if !strings.Contains(out, "ng refs/heads/main denied by rules:up rules[0]: main is protected") {
		t.Fatalf("push to main should be rejected with a status report: %q", out)
	}
	// Without report-status, the agent just gets an error on stderr.
	bare := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/main"}}, nil, nil)
	_, stderr, err := run(t, cl, "git-receive-pack 'g/main.git'", bare)
	if err == nil || !strings.Contains(stderr, "main is protected") {
		t.Fatalf("push to main should be denied: %q %v", stderr, err)
	}
	up.mu.Lock()
	leaked := up.received["git-receive-pack 'g/main.git'"]
	up.mu.Unlock()
	if len(leaked) != 0 {
		t.Fatalf("upstream saw commands for a denied push: %q", leaked)
	}

	if _, err := cl.Dial("tcp", "10.0.0.1:80"); err == nil {
		t.Fatal("port forward should be denied")
	}
}

func TestSSHUnknownToken(t *testing.T) {
	_, addr, authority := setup(t)
	if _, err := client(t, addr, authority, "nope"); err == nil || !strings.Contains(err.Error(), "unknown session token") {
		t.Fatalf("err = %v", err)
	}
}
