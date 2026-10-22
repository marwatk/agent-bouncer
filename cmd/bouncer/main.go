// Command bouncer is a policy-enforcing credential broker for AI agents.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/daemon"
	"github.com/marwatk/agent-bouncer/internal/paths"
)

var version = "dev"

var configPath string

func main() {
	root := &cobra.Command{
		Use:   "bouncer",
		Short: "A credential broker for AI agents with programmable policy",
		Long: `bouncer holds your credentials and sits between AI agents and the services
they use. Agents get placeholder tokens; bouncer injects the real ones only
for requests your rules and filters allow.

  bouncer init                 write a starter config
  bouncer serve                run the daemon (keep this terminal open for approvals)
  bouncer exec -- claude       run an agent through it
  eval "$(bouncer env)"        or route the current shell through it`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&configPath, "config", "c", paths.ConfigFile(), "config file")
	root.AddCommand(serveCmd(), envCmd(), execCmd(), sshConnectCmd(), caCmd(), credCmd(),
		approvalsCmd(), approveCmd(true), approveCmd(false), sessionsCmd(), reloadCmd(),
		checkCmd(), testCmd(), initCmd(), versionCmd())
	if err := root.Execute(); err != nil {
		// Exit codes passed through from a child process need no message.
		var ec exitCode
		if errors.As(err, &ec) {
			os.Exit(int(ec))
		}
		fmt.Fprintln(os.Stderr, "bouncer:", err)
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print the version", Run: func(*cobra.Command, []string) {
		fmt.Println("bouncer", version)
	}}
}

// client talks to the daemon's control API.
type client struct {
	base  string
	token string
	http  *http.Client
}

// newClient locates the daemon from its runtime file, falling back to the
// config's listen address, so it works even while the config is mid-edit.
func newClient() (*client, error) {
	addr := ""
	var rt daemon.Runtime
	if b, err := os.ReadFile(daemon.RuntimePath(paths.StateDir())); err == nil && json.Unmarshal(b, &rt) == nil {
		addr = rt.ProxyAddr
	} else if cfg, err := config.Load(configPath); err == nil {
		addr = cfg.Listen
	} else {
		return nil, fmt.Errorf("bouncer doesn't appear to be running (no %s) and the config can't be read: %w", daemon.RuntimePath(paths.StateDir()), err)
	}
	tok, err := os.ReadFile(daemon.AdminTokenPath(paths.StateDir()))
	if err != nil {
		return nil, fmt.Errorf("reading admin token (has `bouncer serve` run yet?): %w", err)
	}
	return &client{
		base:  "http://" + addr,
		token: strings.TrimSpace(string(tok)),
		// Never route control calls through a proxy, least of all ourselves.
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}, nil
}

func (c *client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("contacting bouncer at %s (is `bouncer serve` running?): %w", c.base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s", strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
