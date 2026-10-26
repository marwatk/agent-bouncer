// Command smoke checks that a Vaultwarden item can be injected through bouncer.
//
// The vault has to already exist and already contain the named login item.
// This program prompts for the master password, builds bouncer, and sends one
// plain HTTP request through the proxy at a local service. The service must
// see Authorization: Bearer <that item's field>. The secret is not printed.
//
//	go run ./ad_hoc/issue-3/smoke \
//	  -server https://vault.example.com \
//	  -email you@example.com \
//	  -item smoke
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/marwatk/agent-bouncer/internal/config"
)

const masterEnv = "BOUNCER_SMOKE_MASTER"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "smoke:", err)
		os.Exit(1)
	}
}

func run() error {
	server := flag.String("server", os.Getenv("VAULTWARDEN_SERVER"), "Vaultwarden base URL (the one you open in a browser)")
	email := flag.String("email", os.Getenv("VAULTWARDEN_EMAIL"), "Vaultwarden account email")
	item := flag.String("item", os.Getenv("VAULTWARDEN_ITEM"), "login item name or id already in the vault")
	folder := flag.String("folder", os.Getenv("VAULTWARDEN_FOLDER"), "folder, when several items share the name")
	field := flag.String("field", "password", "item field to inject (password, username, notes, or a custom field)")
	flag.Parse()

	var missing []string
	if strings.TrimSpace(*server) == "" {
		missing = append(missing, "-server (or VAULTWARDEN_SERVER)")
	}
	if strings.TrimSpace(*email) == "" {
		missing = append(missing, "-email (or VAULTWARDEN_EMAIL)")
	}
	if strings.TrimSpace(*item) == "" {
		missing = append(missing, "-item (or VAULTWARDEN_ITEM)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("vaultwarden vault required; set %s", strings.Join(missing, ", "))
	}

	password, err := promptPassword(*email)
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	tmp, err := os.MkdirTemp("", "bouncer-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	echoAddr, echoHits, err := serveEcho()
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(tmp, "config.yaml")
	if err := writeConfig(cfgPath, echoAddr, *server, *email, *item, *folder, *field); err != nil {
		return err
	}

	root, err := moduleRoot()
	if err != nil {
		return err
	}
	bin := filepath.Join(tmp, "bouncer")
	fmt.Fprintln(os.Stderr, "building bouncer")
	if err := buildBouncer(ctx, root, bin); err != nil {
		return err
	}

	home := filepath.Join(tmp, "home")
	logs := &tap{ready: make(chan string, 1)}
	cmd := exec.CommandContext(ctx, bin, "serve", "-c", cfgPath)
	cmd.Dir = tmp
	cmd.Stdin = os.Stdin
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.Env = childEnv(home, password)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start bouncer: %w", err)
	}
	waitErr := make(chan error, 1)
	exited := make(chan struct{})
	go func() {
		waitErr <- cmd.Wait()
		close(exited)
	}()
	defer stopBouncer(cmd, exited)

	var proxyAddr string
	select {
	case proxyAddr = <-logs.ready:
	case err := <-waitErr:
		return fmt.Errorf("bouncer exited before listening: %w\n%s", err, logs.tail())
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Minute):
		return fmt.Errorf("bouncer did not start listening\n%s", logs.tail())
	}

	token, err := sessionToken(ctx, home, proxyAddr)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, logs.tail())
	}
	secretLen, err := inject(ctx, proxyAddr, token, echoAddr, echoHits, *field)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, logs.tail())
	}
	fmt.Printf("ok: http://%s saw Authorization: Bearer <vault %s, %d bytes>\n", echoAddr, *field, secretLen)
	return nil
}

func stopBouncer(cmd *exec.Cmd, exited <-chan struct{}) {
	select {
	case <-exited:
		return
	default:
	}
	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-exited
	}
}

func promptPassword(email string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("master password prompt needs a terminal")
	}
	fmt.Fprintf(os.Stderr, "Vaultwarden master password for %s: ", strings.TrimSpace(email))
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("empty master password")
	}
	return string(b), nil
}

func serveEcho() (string, *authSeen, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	seen := &authSeen{}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen.record(r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok\n")
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go srv.Serve(ln)
	return ln.Addr().String(), seen, nil
}

type authSeen struct {
	mu    sync.Mutex
	hits  int
	value string
}

func (a *authSeen) record(v string) {
	a.mu.Lock()
	a.hits++
	a.value = v
	a.mu.Unlock()
}

func (a *authSeen) get() (int, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hits, a.value
}

func writeConfig(path, echoAddr, server, email, item, folder, field string) error {
	bw := map[string]string{
		"email":        strings.TrimSpace(email),
		"server":       strings.TrimSpace(server),
		"item":         strings.TrimSpace(item),
		"field":        field,
		"password_env": masterEnv,
	}
	if strings.TrimSpace(folder) != "" {
		bw["folder"] = strings.TrimSpace(folder)
	}
	doc := map[string]any{
		"listen":          "127.0.0.1:0",
		"ssh_listen":      "127.0.0.1:0",
		"default_profile": "smoke",
		"approvals":       map[string]any{"terminal": false, "notify": false},
		"credentials": map[string]any{
			"smoke": map[string]any{
				"source":    "bitwarden",
				"bitwarden": bw,
			},
		},
		"profiles": map[string]any{
			"smoke": map[string]any{
				"unmatched": "deny",
				"services": []any{
					map[string]any{
						"name":       "fake",
						"hosts":      []string{echoAddr},
						"credential": "smoke",
						"insecure":   true,
						"inject":     map[string]any{"bearer": true},
					},
				},
			},
		},
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func moduleRoot() (string, error) {
	var starts []string
	if _, file, _, ok := runtime.Caller(0); ok {
		starts = append(starts, filepath.Dir(file))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	for _, start := range starts {
		dir := start
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				if _, err := os.Stat(filepath.Join(dir, "cmd", "bouncer")); err == nil {
					return dir, nil
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", errors.New("could not find the agent-bouncer module (run this from the repo)")
}

func buildBouncer(ctx context.Context, root, bin string) error {
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/bouncer")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("build bouncer: %w", err)
		}
		return fmt.Errorf("build bouncer: %w\n%s", err, msg)
	}
	return nil
}

func childEnv(home, password string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "BOUNCER_HOME" || k == masterEnv || k == "HTTP_PROXY" || k == "HTTPS_PROXY" || k == "http_proxy" || k == "https_proxy" {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "BOUNCER_HOME="+home, masterEnv+"="+password)
}

// tap copies bouncer's output straight through and reports the listen address.
// Line buffering would hide a two-factor prompt that has no trailing newline.
type tap struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan string
	once  sync.Once
}

func (t *tap) Write(p []byte) (int, error) {
	_, _ = os.Stderr.Write(p)
	t.mu.Lock()
	t.buf.Write(p)
	s := t.buf.String()
	t.mu.Unlock()
	const mark = "proxy listening on "
	if i := strings.Index(s, mark); i >= 0 {
		rest := s[i+len(mark):]
		if strings.Contains(rest, ",") {
			addr, _, _ := strings.Cut(rest, ",")
			addr = strings.TrimSpace(addr)
			if addr != "" {
				t.once.Do(func() { t.ready <- addr })
			}
		}
	}
	return len(p), nil
}

func (t *tap) tail() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.buf.String()
	if len(s) > 4000 {
		s = s[len(s)-4000:]
	}
	return strings.TrimSpace(s)
}

func sessionToken(ctx context.Context, home, proxyAddr string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(home, "state", "admin-token"))
	if err != nil {
		return "", fmt.Errorf("read admin token: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"profile": "smoke", "label": "smoke", "ttl": "1m"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+proxyAddr+"/_bouncer/sessions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("create session: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var rec struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return "", err
	}
	if rec.Token == "" {
		return "", errors.New("create session: empty token")
	}
	return rec.Token, nil
}

func inject(ctx context.Context, proxyAddr, token, echoAddr string, seen *authSeen, field string) (int, error) {
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("bouncer", token)}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+echoAddr+"/", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request through bouncer: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	hits, got := seen.get()
	if hits == 0 {
		return 0, fmt.Errorf("fake service was not reached (%s): %s", resp.Status, oneLine(body))
	}
	secret, ok := strings.CutPrefix(got, "Bearer ")
	if !ok || secret == "" || secret == config.Placeholder("smoke") || strings.Contains(secret, "bouncer-placeholder-") {
		return 0, fmt.Errorf("fake service did not receive the vault %s", field)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("fake service returned %s", resp.Status)
	}
	return len(secret), nil
}

func oneLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		cancel()
	}
}
