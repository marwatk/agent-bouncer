// Package envexport builds the environment that routes an agent's traffic
// through bouncer, and formats it for various shells.
package envexport

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Params describe one session's environment.
type Params struct {
	ProxyAddr  string
	SSHAddr    string
	Token      string
	SessionID  string
	CACert     string // PEM file with only the bouncer CA
	CABundle   string // PEM file with system roots + bouncer CA
	SSHConfig  string // generated ssh_config, "" if SSH files couldn't be written
	ShimDir    string // directory holding the ssh shim, "" if none
	SSHCommand string // command for GIT_SSH_COMMAND
	// Placeholders maps variable names to credential placeholders (export_env).
	Placeholders map[string]string
}

// Env is an ordered set of variables plus an optional PATH prefix.
type Env struct {
	Vars        [][2]string
	PathPrepend string
}

// Build computes the environment for a session.
func Build(p Params) Env {
	proxyURL := (&url.URL{Scheme: "http", User: url.UserPassword("bouncer", p.Token), Host: p.ProxyAddr}).String()
	e := Env{}
	add := func(k, v string) { e.Vars = append(e.Vars, [2]string{k, v}) }
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		add(k, proxyURL)
	}
	add("NO_PROXY", "localhost,127.0.0.1,::1")
	add("no_proxy", "localhost,127.0.0.1,::1")
	// Node.js >= 24 honors the proxy variables for fetch/http only with this set.
	add("NODE_USE_ENV_PROXY", "1")
	// Variables that replace the trust store get the combined bundle so
	// tunneled hosts still verify; NODE_EXTRA_CA_CERTS appends, so it gets just the CA.
	for _, k := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"} {
		add(k, p.CABundle)
	}
	add("NODE_EXTRA_CA_CERTS", p.CACert)
	if p.SSHCommand != "" {
		add("GIT_SSH_COMMAND", p.SSHCommand)
	}
	add("BOUNCER_SESSION", p.Token)
	add("BOUNCER_SESSION_ID", p.SessionID)
	add("BOUNCER_PROXY", "http://"+p.ProxyAddr)
	add("BOUNCER_SSH_ADDR", p.SSHAddr)
	// Base URL for tools that can't use a proxy: $BOUNCER_BASE/<host>/<path>.
	add("BOUNCER_BASE", "http://"+p.ProxyAddr+"/s/"+p.Token)

	names := make([]string, 0, len(p.Placeholders))
	for n := range p.Placeholders {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add(n, p.Placeholders[n])
	}
	e.PathPrepend = p.ShimDir
	return e
}

// Apply merges the environment into base (os.Environ format).
func (e Env) Apply(base []string) []string {
	set := map[string]string{}
	for _, kv := range e.Vars {
		set[envKey(kv[0])] = kv[0] + "=" + kv[1]
	}
	var out []string
	for _, b := range base {
		k, v, _ := strings.Cut(b, "=")
		if envKey(k) == "PATH" && e.PathPrepend != "" {
			out = append(out, k+"="+e.PathPrepend+string(os.PathListSeparator)+v)
			continue
		}
		if s, ok := set[envKey(k)]; ok {
			out = append(out, s)
			delete(set, envKey(k))
			continue
		}
		out = append(out, b)
	}
	for _, kv := range e.Vars {
		if s, ok := set[envKey(kv[0])]; ok {
			out = append(out, s)
			delete(set, envKey(kv[0]))
		}
	}
	return out
}

// envKey normalizes variable names; Windows treats them case-insensitively.
func envKey(k string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(k)
	}
	return k
}

// DefaultShell guesses the user's shell syntax.
func DefaultShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	if strings.HasSuffix(os.Getenv("SHELL"), "fish") {
		return "fish"
	}
	return "sh"
}

// Format renders the environment as shell commands to be eval'd/sourced.
func (e Env) Format(shell string) (string, error) {
	var b strings.Builder
	vars := e.Vars
	if runtime.GOOS == "windows" && (shell == "powershell" || shell == "cmd") {
		// Duplicate-case names collapse into one variable on Windows.
		vars = nil
		seen := map[string]bool{}
		for _, kv := range e.Vars {
			if !seen[strings.ToUpper(kv[0])] {
				seen[strings.ToUpper(kv[0])] = true
				vars = append(vars, kv)
			}
		}
	}
	switch shell {
	case "sh", "bash", "zsh":
		for _, kv := range vars {
			fmt.Fprintf(&b, "export %s=%s\n", kv[0], shQuote(kv[1]))
		}
		if e.PathPrepend != "" {
			fmt.Fprintf(&b, "export PATH=%s:\"$PATH\"\n", shQuote(e.PathPrepend))
		}
	case "fish":
		for _, kv := range vars {
			fmt.Fprintf(&b, "set -gx %s %s\n", kv[0], fishQuote(kv[1]))
		}
		if e.PathPrepend != "" {
			fmt.Fprintf(&b, "set -gx PATH %s $PATH\n", fishQuote(e.PathPrepend))
		}
	case "powershell", "pwsh":
		for _, kv := range vars {
			fmt.Fprintf(&b, "$env:%s = %s\n", kv[0], psQuote(kv[1]))
		}
		if e.PathPrepend != "" {
			fmt.Fprintf(&b, "$env:PATH = %s + [IO.Path]::PathSeparator + $env:PATH\n", psQuote(e.PathPrepend))
		}
	case "cmd":
		for _, kv := range vars {
			fmt.Fprintf(&b, "set \"%s=%s\"\n", kv[0], kv[1])
		}
		if e.PathPrepend != "" {
			fmt.Fprintf(&b, "set \"PATH=%s;%%PATH%%\"\n", e.PathPrepend)
		}
	default:
		return "", fmt.Errorf("unknown shell %q (want sh, bash, zsh, fish, powershell, cmd)", shell)
	}
	return b.String(), nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
func fishQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// SSHFiles writes the generated ssh_config, known_hosts and ssh shim into
// stateDir/ssh. They are static: the session token reaches
// `bouncer ssh-connect` through the environment.
type SSHFiles struct {
	Config  string
	ShimDir string
	Command string
}

// WriteSSHFiles generates the SSH routing files. exe is the bouncer binary.
func WriteSSHFiles(stateDir, exe, knownHostsLine string) (*SSHFiles, error) {
	dir := filepath.Join(stateDir, "ssh")
	shimDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(shimDir, 0o700); err != nil {
		return nil, err
	}
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte(knownHostsLine), 0o644); err != nil {
		return nil, err
	}
	devNull := "/dev/null"
	if runtime.GOOS == "windows" {
		devNull = "NUL"
	}
	cfg := filepath.Join(dir, "config")
	body := fmt.Sprintf(`# Generated by agent-bouncer; regenerated on every `+"`bouncer env`/`bouncer exec`"+`.
# Routes all ssh through the bouncer, which holds the real keys.
Host *
  ProxyCommand "%s" ssh-connect %%h %%p %%r
  UserKnownHostsFile "%s"
  GlobalKnownHostsFile %s
  StrictHostKeyChecking yes
  CheckHostIP no
  UpdateHostKeys no
  ForwardAgent no
  ForwardX11 no
  IdentityAgent none
  IdentitiesOnly yes
  PubkeyAuthentication no
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  ControlMaster no
  ControlPath none
`, slash(exe), slash(kh), devNull)
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		return nil, err
	}
	files := &SSHFiles{Config: cfg}

	realSSH := findRealSSH(shimDir)
	if realSSH == "" {
		files.Command = fmt.Sprintf(`ssh -F "%s"`, slash(cfg))
		return files, nil
	}
	files.Command = fmt.Sprintf(`"%s" -F "%s"`, slash(realSSH), slash(cfg))
	if runtime.GOOS == "windows" {
		shim := fmt.Sprintf("@\"%s\" -F \"%s\" %%*\r\n", realSSH, cfg)
		if err := os.WriteFile(filepath.Join(shimDir, "ssh.cmd"), []byte(shim), 0o755); err != nil {
			return nil, err
		}
	} else {
		shim := fmt.Sprintf("#!/bin/sh\n# Generated by agent-bouncer.\nexec %s -F %s \"$@\"\n", shQuote(realSSH), shQuote(cfg))
		if err := os.WriteFile(filepath.Join(shimDir, "ssh"), []byte(shim), 0o755); err != nil {
			return nil, err
		}
	}
	files.ShimDir = shimDir
	return files, nil
}

// findRealSSH locates ssh on PATH, skipping the shim directory.
func findRealSSH(shimDir string) string {
	name := "ssh"
	if runtime.GOOS == "windows" {
		name = "ssh.exe"
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.Clean(dir) == filepath.Clean(shimDir) {
			continue
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil && filepath.Dir(p) != shimDir {
		return p
	}
	return ""
}

// slash uses forward slashes, which ssh_config and git accept on Windows too.
func slash(p string) string { return filepath.ToSlash(p) }
