package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marwatk/agent-bouncer/internal/ca"
	"github.com/marwatk/agent-bouncer/internal/daemon"
	"github.com/marwatk/agent-bouncer/internal/envexport"
	"github.com/marwatk/agent-bouncer/internal/paths"
	"github.com/marwatk/agent-bouncer/internal/sshproxy"
)

type sessionFlags struct{ profile, label, ttl string }

func (f *sessionFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.profile, "profile", "p", "", "policy profile (default: default_profile from config)")
	cmd.Flags().StringVarP(&f.label, "label", "l", "", "label for this session in logs and prompts")
}

// sessionEnv registers a session with the daemon and builds its environment.
func sessionEnv(f sessionFlags) (*client, *daemon.SessionRecord, envexport.Env, error) {
	c, err := newClient()
	if err != nil {
		return nil, nil, envexport.Env{}, err
	}
	var rec daemon.NewSession
	if err := c.do("POST", "/_bouncer/sessions", map[string]string{"profile": f.profile, "label": f.label, "ttl": f.ttl}, &rec); err != nil {
		return nil, nil, envexport.Env{}, err
	}
	state := paths.StateDir()
	authority, err := ca.LoadOrCreate(state)
	if err != nil {
		return nil, nil, envexport.Env{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, envexport.Env{}, err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	p := envexport.Params{
		ProxyAddr: rec.ProxyAddr, SSHAddr: rec.SSHAddr, Token: rec.Token, SessionID: rec.ID,
		CACert: authority.CertPath(), CABundle: authority.BundlePath(), Placeholders: rec.Placeholders,
	}
	if files, err := envexport.WriteSSHFiles(state, exe, authority.SSHKnownHostsLine()); err != nil {
		fmt.Fprintf(os.Stderr, "bouncer: warning: ssh routing disabled: %v\n", err)
	} else {
		p.SSHConfig, p.ShimDir, p.SSHCommand = files.Config, files.ShimDir, files.Command
	}
	return c, &rec.SessionRecord, envexport.Build(p), nil
}

func envCmd() *cobra.Command {
	var f sessionFlags
	var shell string
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Print shell commands that route this shell through bouncer",
		Long: `Registers a session and prints environment settings for it. Use it for
agents bouncer doesn't launch itself:

  eval "$(bouncer env --profile default --label my-agent)"      # sh/bash/zsh
  bouncer env --shell fish | source                              # fish
  bouncer env --shell powershell | Invoke-Expression             # PowerShell

The session expires after --ttl (default 24h) or when revoked with
` + "`bouncer sessions end <id>`" + `.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if shell == "" {
				shell = envexport.DefaultShell()
			}
			_, rec, env, err := sessionEnv(f)
			if err != nil {
				return err
			}
			out, err := env.Format(shell)
			if err != nil {
				return err
			}
			comment := "#"
			if shell == "cmd" {
				comment = "rem"
			}
			fmt.Printf("%s agent-bouncer session %s (profile %s). Revoke with: bouncer sessions end %s\n%s", comment, rec.ID, rec.Profile, rec.ID, out)
			return nil
		},
	}
	f.add(cmd)
	cmd.Flags().StringVar(&f.ttl, "ttl", "24h", "session lifetime (0 = until revoked)")
	cmd.Flags().StringVar(&shell, "shell", "", "output syntax: sh, bash, zsh, fish, powershell, cmd (default: detected)")
	return cmd
}

func execCmd() *cobra.Command {
	var f sessionFlags
	cmd := &cobra.Command{
		Use:   "exec [flags] -- command [args...]",
		Short: "Run a command (your agent) with its traffic routed through bouncer",
		Long: `Runs the command in a new session whose HTTP(S) and SSH traffic goes through
bouncer. The session is revoked when the command exits.

  bouncer exec -- claude
  bouncer exec --profile locked-down --label review -- codex`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.label == "" {
				f.label = filepath.Base(args[0])
			}
			c, rec, env, err := sessionEnv(f)
			if err != nil {
				return err
			}
			defer c.do("DELETE", "/_bouncer/sessions/"+rec.ID, nil, nil)

			childEnv := env.Apply(os.Environ())
			// Resolve the program with the child's PATH so `bouncer exec -- ssh`
			// finds the shim.
			prog := args[0]
			if env.PathPrepend != "" && !strings.ContainsAny(prog, `/\`) {
				if p, err := exec.LookPath(filepath.Join(env.PathPrepend, prog)); err == nil {
					prog = p
				}
			}
			child := exec.Command(prog, args[1:]...)
			child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
			child.Env = childEnv
			// The terminal delivers Ctrl-C to the whole process group; the
			// child handles it, and we must outlive the child to revoke the session.
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, os.Interrupt)
			defer signal.Stop(sigs)
			go func() {
				for range sigs {
				}
			}()
			if err := child.Run(); err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return exitCode(ee.ExitCode())
				}
				return err
			}
			return nil
		},
	}
	f.add(cmd)
	return cmd
}

func sshConnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "ssh-connect host port user",
		Short:  "ssh ProxyCommand that tunnels to the bouncer SSH listener",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := os.Getenv("BOUNCER_SESSION")
			addr := os.Getenv("BOUNCER_SSH_ADDR")
			if token == "" || addr == "" {
				return errors.New("BOUNCER_SESSION/BOUNCER_SSH_ADDR not set; run ssh via `bouncer exec` or after `bouncer env`")
			}
			port, _ := strconv.Atoi(args[1])
			err := sshproxy.Connect(addr, sshproxy.Preamble{Token: token, Host: args[0], Port: port, User: args[2]}, os.Stdin, os.Stdout)
			if err != nil {
				fmt.Fprintln(os.Stderr, "agent-bouncer:", err)
				return exitCode(255)
			}
			return nil
		},
	}
}
