package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/marwatk/agent-bouncer/internal/audit"
	"github.com/marwatk/agent-bouncer/internal/ca"
	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/creds"
	"github.com/marwatk/agent-bouncer/internal/policy"
)

type fakeBackend struct {
	set      *policy.Set
	sessions map[string]*chain.Session
}

func (b *fakeBackend) Session(token string) (*chain.Session, bool) {
	s, ok := b.sessions[token]
	return s, ok
}
func (b *fakeBackend) Profile(name string) (*policy.Profile, bool) {
	p, ok := b.set.Profiles[name]
	return p, ok
}
func (b *fakeBackend) Control() http.Handler { return http.NotFoundHandler() }

type env struct {
	upstream *httptest.Server
	proxy    *httptest.Server
	client   *http.Client
	audit    []audit.Entry
	port     string
}

func setup(t *testing.T, profileYAML string) *env {
	t.Helper()
	e := &env{}
	e.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upgrade" {
			conn, buf, _ := http.NewResponseController(w).Hijack()
			buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
			buf.Flush()
			io.Copy(conn, buf)
			conn.Close()
			return
		}
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "widget=%s auth=%s private=%s path=%s query=%s body=%s", r.Header.Get("X-Widget-Key"), r.Header.Get("Authorization"), r.Header.Get("Private-Token"), r.URL.EscapedPath(), r.URL.RawQuery, body)
	}))
	t.Cleanup(e.upstream.Close)
	_, e.port, _ = net.SplitHostPort(e.upstream.Listener.Addr().String())

	t.Setenv("BOUNCER_TEST_TOKEN", "real-secret")
	// Patterns without a port mean :443; pin the test upstream's port.
	profileYAML = strings.ReplaceAll(profileYAML, "hosts: [localhost]", `hosts: ["localhost:`+e.port+`"]`)
	cfg, err := config.Parse([]byte(`
credentials:
  tok: {source: env, env: BOUNCER_TEST_TOKEN}
profiles:
`+profileYAML), t.TempDir()+"/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	set, err := policy.Compile(cfg, &chain.Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTransport()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	log, _ := audit.Open("", func(en audit.Entry) { e.audit = append(e.audit, en) })
	srv := &Server{
		Backend:   &fakeBackend{set: set, sessions: map[string]*chain.Session{"tok123": {ID: "s1", Profile: "p"}}},
		CA:        authority,
		Creds:     creds.NewStore(cfg.Credentials),
		Audit:     log,
		Transport: tr,
		Dialer:    &net.Dialer{},
	}
	e.proxy = httptest.NewServer(srv)
	t.Cleanup(e.proxy.Close)

	roots := x509.NewCertPool()
	roots.AddCert(authority.Cert())
	roots.AddCert(e.upstream.Certificate())
	proxyURL, _ := url.Parse(e.proxy.URL)
	proxyURL.User = url.UserPassword("bouncer", "tok123")
	e.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	return e
}

func (e *env) get(t *testing.T, method, rawURL string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, rawURL, strings.NewReader("payload"))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const scopedProfile = `
  p:
    unmatched: tunnel
    services:
      - name: api
        hosts: [localhost]
        credential: tok
        inject: {bearer: true}
        rules:
          - action: allow
            gitlab_project: group/proj
`

func TestInterceptInjectAndDeny(t *testing.T) {
	e := setup(t, scopedProfile)
	base := "https://localhost:" + e.port

	status, body := e.get(t, "POST", base+"/api/v4/projects/group%2Fproj/issues?x=1", nil)
	if status != 200 || !strings.Contains(body, "auth=Bearer real-secret") || !strings.Contains(body, "path=/api/v4/projects/group%2Fproj/issues") || !strings.Contains(body, "body=payload") {
		t.Fatalf("allowed request: %d %s", status, body)
	}
	status, body = e.get(t, "GET", base+"/api/v4/projects/group%2Fother", nil)
	if status != 403 || !strings.Contains(body, "denied by rules:api") || strings.Contains(body, "real-secret") {
		t.Fatalf("denied request: %d %s", status, body)
	}
	status, _ = e.get(t, "GET", base+"/api/v4/projects/group%2Fproj/../../other", nil)
	if status != 400 {
		t.Fatalf("dot-segment path: %d", status)
	}
	var decisions []string
	for _, a := range e.audit {
		decisions = append(decisions, a.Decision)
	}
	if strings.Join(decisions, ",") != "allow,deny,deny" {
		t.Errorf("audit decisions: %v", decisions)
	}
}

func TestPlaceholderReplacement(t *testing.T) {
	e := setup(t, `
  p:
    services:
      - name: api
        hosts: [localhost]
        credential: tok
`)
	base := "https://localhost:" + e.port
	ph := config.Placeholder("tok")
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:"+ph))
	_, body := e.get(t, "GET", base+"/x?title="+ph, map[string]string{"Authorization": basic, "Private-Token": ph, "X-Widget-Key": ph})
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2:real-secret"))
	if !strings.Contains(body, "auth="+wantBasic) || !strings.Contains(body, "private=real-secret") {
		t.Fatalf("auth header placeholders not replaced: %s", body)
	}
	// A placeholder anywhere an API might store and echo it back must stay a
	// placeholder, or the agent could read the secret out of, say, an issue title.
	if !strings.Contains(body, "query=title="+ph) || !strings.Contains(body, "widget="+ph) || strings.Count(body, "real-secret") != 1 {
		t.Fatalf("placeholder replaced outside auth headers: %s", body)
	}
}

func TestInjectQuery(t *testing.T) {
	e := setup(t, `
  p:
    services:
      - name: api
        hosts: [localhost]
        credential: tok
        inject: {query: api_key}
`)
	_, body := e.get(t, "GET", "https://localhost:"+e.port+"/x?a=1", nil)
	if !strings.Contains(body, "api_key=real-secret") || !strings.Contains(body, "a=1") {
		t.Fatalf("%s", body)
	}
}

func TestTunnelAndUnmatchedDeny(t *testing.T) {
	// The test upstream is on loopback, so reaching it unmatched needs allow_private.
	e := setup(t, strings.Replace(scopedProfile, "unmatched: tunnel", "unmatched: tunnel\n    allow_private: true", 1))
	// 127.0.0.1 is not a configured service: tunneled untouched, using the
	// upstream's own certificate.
	status, body := e.get(t, "GET", "https://127.0.0.1:"+e.port+"/anything", nil)
	if status != 200 || !strings.Contains(body, "auth= ") {
		t.Fatalf("tunnel: %d %s", status, body)
	}

	e2 := setup(t, strings.Replace(scopedProfile, "unmatched: tunnel", "unmatched: deny", 1))
	_, err := e2.client.Get("https://127.0.0.1:" + e2.port + "/anything")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("expected CONNECT to be refused, got %v", err)
	}
}

func TestTunnelRefusesNonPublicByDefault(t *testing.T) {
	e := setup(t, scopedProfile)
	// CONNECT to loopback is refused with a status, not a dead tunnel.
	if _, err := e.client.Get("https://127.0.0.1:" + e.port + "/"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("CONNECT to loopback: %v", err)
	}
	// Plain-HTTP forwarding to loopback is refused too.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "reached") }))
	defer plain.Close()
	status, body := e.get(t, "GET", plain.URL+"/", nil)
	if status != 403 || strings.Contains(body, "reached") {
		t.Fatalf("plain http to loopback: %d %s", status, body)
	}
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.100.1.1", "::1", "fe80::1", "0.0.0.0"} {
		if !nonPublic(net.ParseIP(ip)) {
			t.Errorf("%s should be non-public", ip)
		}
	}
	if nonPublic(net.ParseIP("140.82.112.3")) {
		t.Error("public address flagged")
	}
}

func TestMissingSessionToken(t *testing.T) {
	e := setup(t, scopedProfile)
	proxyURL, _ := url.Parse(e.proxy.URL)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	_, err := c.Get("https://localhost:" + e.port + "/")
	if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Fatalf("expected 407, got %v", err)
	}
}

func TestNoCredentialsOverPlainHTTP(t *testing.T) {
	var gotAuth []string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
	}))
	defer plain.Close()
	_, port, _ := net.SplitHostPort(plain.Listener.Addr().String())
	e := setup(t, `
  p:
    allow_private: true
    services:
      - name: api
        hosts: ["127.0.0.1:`+port+`"]
        credential: tok
        inject: {bearer: true}
      - name: dev
        hosts: ["localhost:`+port+`"]
        credential: tok
        insecure: true
        inject: {bearer: true}
`)
	status, _ := e.get(t, "GET", plain.URL+"/x", nil)
	if status != 403 {
		t.Fatalf("plain HTTP to a credentialed service: %d", status)
	}
	e.get(t, "GET", "http://localhost:"+port+"/x", nil)
	if len(gotAuth) != 1 || gotAuth[0] != "Bearer real-secret" {
		t.Fatalf("insecure: true should allow injection; upstream saw %q", gotAuth)
	}
}

func TestCredentialErrorsStayInTheLog(t *testing.T) {
	e := setup(t, scopedProfile)
	t.Setenv("BOUNCER_TEST_TOKEN", "")
	os.Unsetenv("BOUNCER_TEST_TOKEN")
	_, body := e.get(t, "GET", "https://localhost:"+e.port+"/api/v4/projects/group%2Fproj", nil)
	if !strings.Contains(body, "unavailable; see the bouncer log") || strings.Contains(body, "BOUNCER_TEST_TOKEN") {
		t.Fatalf("agent saw credential error details: %s", body)
	}
}

func TestReverseMode(t *testing.T) {
	e := setup(t, scopedProfile)
	resp, err := http.Get(e.proxy.URL + "/s/tok123/localhost:" + e.port + "/api/v4/projects/group%2Fproj")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "auth=Bearer real-secret") || !strings.Contains(string(b), "path=/api/v4/projects/group%2Fproj") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp, _ = http.Get(e.proxy.URL + "/s/wrong/localhost:" + e.port + "/x")
	if resp.StatusCode != 401 {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
}

func TestUpgradeRefusedOnCredentialedService(t *testing.T) {
	e := setup(t, `
  p:
    services:
      - name: api
        hosts: [localhost]
        credential: tok
`)
	status, body := e.get(t, "GET", "https://localhost:"+e.port+"/upgrade", map[string]string{"Connection": "Upgrade", "Upgrade": "echo"})
	if status != 403 || !strings.Contains(body, "allow_upgrade") {
		t.Fatalf("%d %s", status, body)
	}
}

func TestUpgradePassthrough(t *testing.T) {
	e := setup(t, `
  p:
    services:
      - name: api
        hosts: [localhost]
`)
	req, _ := http.NewRequest("GET", "https://localhost:"+e.port+"/upgrade", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	rwc := resp.Body.(io.ReadWriteCloser)
	rwc.Write([]byte("ping"))
	buf := make([]byte, 4)
	io.ReadFull(rwc, buf)
	if string(buf) != "ping" {
		t.Fatalf("echo: %q", buf)
	}
	rwc.Close()
}
