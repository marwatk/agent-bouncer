// Package daemon wires bouncer's components into the long-running process
// behind `bouncer serve`.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marwatk/agent-bouncer/internal/approval"
	"github.com/marwatk/agent-bouncer/internal/audit"
	"github.com/marwatk/agent-bouncer/internal/ca"
	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/creds"
	"github.com/marwatk/agent-bouncer/internal/kv"
	"github.com/marwatk/agent-bouncer/internal/notify"
	"github.com/marwatk/agent-bouncer/internal/policy"
	"github.com/marwatk/agent-bouncer/internal/proxy"
	"github.com/marwatk/agent-bouncer/internal/sshproxy"
)

// Options configure a daemon.
type Options struct {
	ConfigPath string
	StateDir   string
	// Logf receives operational messages; Decision receives audit entries
	// for display (they are always written to the audit log too).
	Logf     func(format string, args ...any)
	Decision func(audit.Entry)
	// Provided are secrets supplied at startup (--creds-from). They override
	// configured sources and are held only in memory.
	Provided map[string]string
}

// Daemon is a running bouncer.
type Daemon struct {
	opts      Options
	CA        *ca.Authority
	Approvals *approval.Manager
	creds     *creds.Store
	kv        *kv.Store
	audit     *audit.Log
	env       *chain.Env
	transport *http.Transport
	admin     string

	mu       sync.RWMutex
	cfg      *config.Config
	set      *policy.Set
	sessions map[string]*SessionRecord // by token

	resolved sync.Map // resolver cache key -> resolvedID

	proxyAddr, sshAddr string
}

// SessionRecord is a registered agent session.
type SessionRecord struct {
	chain.Session
	Token   string    `json:"token"`
	Created time.Time `json:"created"`
	// Expires is zero for sessions that last until revoked.
	Expires time.Time `json:"expires,omitzero"`
}

func (s *SessionRecord) expired() bool { return !s.Expires.IsZero() && time.Now().After(s.Expires) }

// NewSession is the control API's reply to session creation: everything a
// client needs to build the agent's environment without parsing the config.
type NewSession struct {
	SessionRecord
	ProxyAddr string `json:"proxy_addr"`
	SSHAddr   string `json:"ssh_addr"`
	// Placeholders maps environment variable names to placeholder values.
	Placeholders map[string]string `json:"placeholders"`
	// SSHHosts lists every configured SSH service host pattern, the only
	// hosts the generated known_hosts trusts the bouncer SSH CA for.
	SSHHosts []string `json:"ssh_hosts"`
}

// Runtime describes a running daemon; written to the state dir so clients
// can find it even when the config file is mid-edit.
type Runtime struct {
	ProxyAddr string `json:"proxy_addr"`
	SSHAddr   string `json:"ssh_addr"`
	PID       int    `json:"pid"`
	Config    string `json:"config"`
}

// RuntimePath is the runtime file in a state dir.
func RuntimePath(stateDir string) string { return filepath.Join(stateDir, "daemon.json") }

type resolvedID struct {
	id      int64
	expires time.Time
}

// New loads config and state. It does not start listening.
func New(opts Options) (*Daemon, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, err
	}
	d := &Daemon{opts: opts, sessions: map[string]*SessionRecord{}, transport: proxy.NewTransport()}
	var err error
	if d.CA, err = ca.LoadOrCreate(opts.StateDir); err != nil {
		return nil, err
	}
	if err := d.CA.WriteBundle(); err != nil {
		opts.Logf("warning: writing CA bundle: %v", err)
	}
	if d.admin, err = LoadOrCreateAdminToken(opts.StateDir); err != nil {
		return nil, err
	}
	if d.kv, err = kv.Open(filepath.Join(opts.StateDir, "kv.json")); err != nil {
		return nil, err
	}
	if d.audit, err = audit.Open(filepath.Join(opts.StateDir, "audit.jsonl"), opts.Decision); err != nil {
		return nil, err
	}
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	d.Approvals = approval.NewManager(cfg.Approvals.TimeoutOrDefault())
	d.env = &chain.Env{
		Approver: d.Approvals,
		Resolver: d.resolveGitLabProject,
		Log: func(filter, msg string, fields map[string]any) {
			if len(fields) > 0 {
				b, _ := json.Marshal(fields)
				opts.Logf("[%s] %s %s", filter, msg, b)
			} else {
				opts.Logf("[%s] %s", filter, msg)
			}
		},
	}
	d.creds = creds.NewStore(cfg.Credentials)
	d.creds.SetProvided(opts.Provided)
	if err := d.apply(cfg); err != nil {
		return nil, err
	}
	d.loadSessions()
	return d, nil
}

// Config returns the active config.
func (d *Daemon) Config() *config.Config {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cfg
}

// checkProvided ensures startup-provided secrets and the config agree:
// every provided name is a configured credential, and every source:
// provided credential has a value.
func (d *Daemon) checkProvided(cfg *config.Config) error {
	var unknown, missing []string
	for name := range d.opts.Provided {
		if _, ok := cfg.Credentials[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	for name, c := range cfg.Credentials {
		if _, ok := d.opts.Provided[name]; c.Source == "provided" && !ok {
			missing = append(missing, name)
		}
	}
	// "a: x" + "b: y" printed without a newline between them parses as a
	// single value for a; catch it when b is a configured name.
	for name, v := range d.opts.Provided {
		for other := range cfg.Credentials {
			if other != name && strings.Contains(v, other+": ") {
				return fmt.Errorf("--creds-from value for %s contains %q; is a newline missing between entries?", name, other+": ")
			}
		}
	}
	sort.Strings(unknown)
	sort.Strings(missing)
	switch {
	case len(unknown) > 0:
		return fmt.Errorf("--creds-from names credentials not in the config: %s", strings.Join(unknown, ", "))
	case len(missing) > 0:
		return fmt.Errorf("credentials with source: provided have no value from --creds-from: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (d *Daemon) apply(cfg *config.Config) error {
	if err := d.checkProvided(cfg); err != nil {
		return err
	}
	set, err := policy.Compile(cfg, d.env, d.kv)
	if err != nil {
		return err
	}
	d.creds.Update(cfg.Credentials)
	d.Approvals.SetTimeout(cfg.Approvals.TimeoutOrDefault())
	if cfg.Approvals.NotifyEnabled() {
		d.Approvals.Notify = func(p approval.Pending) {
			notify.Send("agent-bouncer: approval needed", approval.Display(p.Prompt, 150)+"\n"+approval.Display(p.Request, 150))
		}
	} else {
		d.Approvals.Notify = nil
	}
	d.mu.Lock()
	d.cfg, d.set = cfg, set
	d.mu.Unlock()
	return nil
}

// Reload re-reads the config, keeping the old one if the new one is invalid.
func (d *Daemon) Reload() error {
	old := d.Config()
	cfg, err := config.Load(d.opts.ConfigPath)
	if err == nil {
		err = d.apply(cfg)
	}
	if err != nil {
		d.opts.Logf("reload failed, keeping previous config: %v", err)
		return err
	}
	if old != nil && (old.Listen != cfg.Listen || old.SSHListen != cfg.SSHListen) {
		d.opts.Logf("listen address changes take effect after restart")
	}
	d.opts.Logf("config reloaded")
	return nil
}

// Session implements proxy.Backend and sshproxy.Backend.
func (d *Daemon) Session(token string) (*chain.Session, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if token == "" {
		if d.cfg.AnonymousProfile == "" {
			return nil, false
		}
		return &chain.Session{ID: "anonymous", Label: "anonymous", Profile: d.cfg.AnonymousProfile, Shared: true}, true
	}
	s, ok := d.sessions[token]
	if !ok || s.expired() {
		return nil, false
	}
	sess := s.Session
	return &sess, true
}

// Profile implements proxy.Backend and sshproxy.Backend.
func (d *Daemon) Profile(name string) (*policy.Profile, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.set.Profiles[name]
	return p, ok
}

// CreateSession registers a new agent session.
// A ttl of 0 means the session lasts until revoked.
func (d *Daemon) CreateSession(profile, label string, ttl time.Duration) (*SessionRecord, error) {
	d.mu.Lock()
	if profile == "" {
		profile = d.cfg.DefaultProfile
	}
	if profile == "" {
		d.mu.Unlock()
		return nil, errors.New("no profile given and no default_profile configured")
	}
	if _, ok := d.cfg.Profiles[profile]; !ok {
		d.mu.Unlock()
		return nil, fmt.Errorf("unknown profile %q", profile)
	}
	rec := &SessionRecord{Session: chain.Session{ID: randHex(8), Label: label, Profile: profile}, Token: randHex(24), Created: time.Now()}
	if ttl > 0 {
		rec.Expires = rec.Created.Add(ttl)
	}
	for tok, s := range d.sessions {
		if s.expired() {
			delete(d.sessions, tok)
		}
	}
	if rec.Label == "" {
		rec.Label = rec.ID
	}
	d.sessions[rec.Token] = rec
	d.mu.Unlock()
	d.saveSessions()
	return rec, nil
}

// Placeholders lists the export_env variables of every credential.
func (d *Daemon) Placeholders() map[string]string {
	out := map[string]string{}
	for _, c := range d.Config().Credentials {
		for _, k := range c.ExportEnv {
			out[k] = c.Placeholder()
		}
	}
	return out
}

// SSHHosts lists the host patterns of every configured SSH service.
func (d *Daemon) SSHHosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range d.Config().Profiles {
		for _, s := range p.SSH {
			for _, h := range s.Hosts {
				if !seen[h] {
					seen[h] = true
					out = append(out, h)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// EndSession removes a session by ID.
func (d *Daemon) EndSession(id string) bool {
	d.mu.Lock()
	found := false
	for tok, s := range d.sessions {
		if s.ID == id {
			delete(d.sessions, tok)
			found = true
		}
	}
	d.mu.Unlock()
	if found {
		d.Approvals.ForgetSession(id)
		d.saveSessions()
	}
	return found
}

func (d *Daemon) listSessions() []SessionRecord {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]SessionRecord, 0, len(d.sessions))
	for _, s := range d.sessions {
		if s.expired() {
			continue
		}
		r := *s
		r.Token = ""
		out = append(out, r)
	}
	return out
}

func (d *Daemon) sessionsFile() string { return filepath.Join(d.opts.StateDir, "sessions.json") }

// Sessions survive daemon restarts so running agents keep working.
func (d *Daemon) loadSessions() {
	b, err := os.ReadFile(d.sessionsFile())
	if err != nil {
		return
	}
	var recs []*SessionRecord
	if json.Unmarshal(b, &recs) != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range recs {
		if _, ok := d.cfg.Profiles[r.Profile]; ok {
			d.sessions[r.Token] = r
		}
	}
}

func (d *Daemon) saveSessions() {
	d.mu.RLock()
	recs := make([]*SessionRecord, 0, len(d.sessions))
	for _, s := range d.sessions {
		recs = append(recs, s)
	}
	d.mu.RUnlock()
	b, _ := json.MarshalIndent(recs, "", "  ")
	tmp := d.sessionsFile() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, d.sessionsFile())
	}
}

// resolveGitLabProject looks up a project's numeric ID using the service's credential.
func (d *Daemon) resolveGitLabProject(ctx context.Context, service, host, project string) (int64, error) {
	key := service + "\x00" + host + "\x00" + project
	if v, ok := d.resolved.Load(key); ok {
		if r := v.(resolvedID); time.Now().Before(r.expires) {
			return r.id, nil
		}
	}
	var svc *config.Service
	d.mu.RLock()
	for _, p := range d.set.Profiles {
		for _, s := range p.Services {
			if s.Config.Name == service && config.HostMatches(s.Config.Hosts, host) {
				svc = s.Config
			}
		}
	}
	d.mu.RUnlock()
	if svc == nil {
		return 0, fmt.Errorf("unknown service %q", service)
	}
	u, _ := url.Parse("https://" + host + "/api/v4/projects/" + url.PathEscape(project))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	if svc.Credential != "" {
		secret, err := d.creds.Get(ctx, svc.Credential)
		if err != nil {
			return 0, err
		}
		spec := svc.Inject
		if spec == nil {
			spec = &config.Inject{Bearer: true}
		}
		proxy.Inject(req.Header, req.URL, svc.Credential, spec, secret)
	}
	resp, err := d.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	var body struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return 0, err
	}
	d.resolved.Store(key, resolvedID{id: body.ID, expires: time.Now().Add(time.Hour)})
	return body.ID, nil
}

// Run serves until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	cfg := d.Config()
	httpL, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	sshL, err := net.Listen("tcp", cfg.SSHListen)
	if err != nil {
		httpL.Close()
		return fmt.Errorf("ssh listen: %w", err)
	}
	px := &proxy.Server{Backend: d, CA: d.CA, Creds: d.creds, Audit: d.audit, Transport: d.transport,
		Dialer: &net.Dialer{Timeout: 30 * time.Second}, Logf: d.opts.Logf}
	httpSrv := &http.Server{Handler: px, ReadHeaderTimeout: 30 * time.Second}
	sshSrv := &sshproxy.Server{Backend: d, CA: d.CA, Creds: d.creds, Audit: d.audit, Logf: d.opts.Logf}

	stopWatch, err := d.watch()
	if err != nil {
		d.opts.Logf("warning: config watching disabled: %v", err)
	} else {
		defer stopWatch()
	}

	errc := make(chan error, 2)
	go func() { errc <- httpSrv.Serve(httpL) }()
	go func() { errc <- sshSrv.Serve(sshL) }()
	d.proxyAddr, d.sshAddr = httpL.Addr().String(), sshL.Addr().String()
	rt, _ := json.Marshal(Runtime{ProxyAddr: d.proxyAddr, SSHAddr: d.sshAddr, PID: os.Getpid(), Config: cfg.Path})
	if err := os.WriteFile(RuntimePath(d.opts.StateDir), rt, 0o600); err != nil {
		d.opts.Logf("warning: writing runtime file: %v", err)
	}
	defer os.Remove(RuntimePath(d.opts.StateDir))
	d.opts.Logf("proxy listening on %s, ssh on %s", httpL.Addr(), sshL.Addr())
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	httpL.Close()
	sshL.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
	d.kv.Close()
	d.audit.Close()
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// AdminTokenPath is where the control API token lives.
func AdminTokenPath(stateDir string) string { return filepath.Join(stateDir, "admin-token") }

// LoadOrCreateAdminToken returns the control API token, creating it if needed.
func LoadOrCreateAdminToken(stateDir string) (string, error) {
	p := AdminTokenPath(stateDir)
	if b, err := os.ReadFile(p); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	}
	t := randHex(32)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	return t, os.WriteFile(p, []byte(t+"\n"), 0o600)
}
