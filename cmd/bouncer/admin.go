package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/marwatk/agent-bouncer/internal/approval"
	"github.com/marwatk/agent-bouncer/internal/ca"
	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/creds"
	"github.com/marwatk/agent-bouncer/internal/daemon"
	"github.com/marwatk/agent-bouncer/internal/paths"
	"github.com/marwatk/agent-bouncer/internal/policy"
)

func caCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Show or install the bouncer CA certificate",
		Long: `bouncer intercepts TLS for configured services using a local CA. ` + "`bouncer env`" + `
points most tools at it via environment variables; tools that only use the OS
trust store (Go programs such as gh and glab on macOS/Windows, browsers) need
` + "`bouncer ca install`" + `.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			a, err := ca.LoadOrCreate(paths.StateDir())
			if err != nil {
				return err
			}
			fmt.Printf("certificate: %s\nbundle:      %s\n", a.CertPath(), a.BundlePath())
			return nil
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Trust the bouncer CA in the current user's OS trust store",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			a, err := ca.LoadOrCreate(paths.StateDir())
			if err != nil {
				return err
			}
			c, err := a.InstallCommand()
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "running: %s\n", strings.Join(c.Args, " "))
			c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
			return c.Run()
		},
	}, &cobra.Command{
		Use:   "pem",
		Short: "Print the CA certificate",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			a, err := ca.LoadOrCreate(paths.StateDir())
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(a.CertPEM())
			return err
		},
	})
	return cmd
}

func credCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cred", Short: "Manage credentials"}
	account := func(name string) string {
		if cfg, err := config.Load(configPath); err == nil {
			if c, ok := cfg.Credentials[name]; ok {
				if c.Source != "keyring" {
					fmt.Fprintf(os.Stderr, "bouncer: note: credential %q uses source %q in the config, not keyring\n", name, c.Source)
				}
				return c.KeyringAccount()
			}
		}
		return name
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "set NAME",
		Short: "Store a secret in the OS keyring (reads stdin when piped)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var secret string
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stderr, "secret for %s: ", args[0])
				b, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return err
				}
				secret = string(b)
			} else {
				b, err := io.ReadAll(bufio.NewReader(os.Stdin))
				if err != nil {
					return err
				}
				secret = strings.TrimRight(string(b), "\r\n")
			}
			if secret == "" {
				return errors.New("empty secret")
			}
			if err := creds.SetKeyring(account(args[0]), secret); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "stored %s in the OS keyring\n", args[0])
			return nil
		},
	}, &cobra.Command{
		Use:   "rm NAME",
		Short: "Remove a secret from the OS keyring",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return creds.DeleteKeyring(account(args[0]))
		},
	}, &cobra.Command{
		Use:   "test NAME",
		Short: "Fetch a credential from its source and report whether it worked (never prints it)",
		Long: `Fetches the credential as the daemon would, from this process. Note that
source: env reads this shell's environment, which may differ from the daemon's.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			c, ok := cfg.Credentials[args[0]]
			if !ok {
				return fmt.Errorf("no credential %q in %s", args[0], cfg.Path)
			}
			store := creds.NewStore(cfg.Credentials)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			if c.Source == "ssh-agent" || c.Source == "file" {
				if signers, err := store.SSHSigners(ctx, args[0]); err == nil {
					for _, s := range signers {
						fmt.Printf("ok: ssh key %s %s\n", s.PublicKey().Type(), ssh.FingerprintSHA256(s.PublicKey()))
					}
					return nil
				} else if c.Source == "ssh-agent" {
					return err
				}
			}
			v, err := store.Get(ctx, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("ok: %d characters from %s\n", len(v), c.Source)
			return nil
		},
	})
	return cmd
}

func approvalsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "approvals",
		Short: "List pending approvals",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var list []approval.Pending
			if err := c.do("GET", "/_bouncer/approvals", nil, &list); err != nil {
				return err
			}
			if len(list) == 0 {
				fmt.Println("no pending approvals")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSESSION\tPROMPT\tREQUEST\tEXPIRES")
			for _, p := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.SessionLabel, p.Prompt, p.Request, time.Until(p.Expires).Round(time.Second))
			}
			return w.Flush()
		},
	}
}

func approveCmd(allow bool) *cobra.Command {
	var session bool
	use, short := "approve ID", "Approve a pending request"
	if !allow {
		use, short = "deny ID", "Deny a pending request"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("POST", "/_bouncer/approvals/"+args[0], map[string]bool{"allow": allow, "remember": session}, nil)
		},
	}
	cmd.Flags().BoolVarP(&session, "session", "s", false, "apply to identical requests for the rest of the session")
	return cmd
}

func sessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "List agent sessions",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var list []daemon.SessionRecord
			if err := c.do("GET", "/_bouncer/sessions", nil, &list); err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tLABEL\tPROFILE\tCREATED")
			for _, s := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.ID, s.Label, s.Profile, s.Created.Format(time.DateTime))
			}
			return w.Flush()
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "end ID",
		Short: "Revoke a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("DELETE", "/_bouncer/sessions/"+args[0], nil, nil)
		},
	})
	return cmd
}

func reloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Reload the config now (it also reloads automatically on change)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("POST", "/_bouncer/reload", nil, nil)
		},
	}
}

func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Validate the config and compile every filter",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			set, err := policy.Compile(cfg, &chain.Env{}, nil)
			if err != nil {
				return err
			}
			for name, p := range set.Profiles {
				fmt.Printf("profile %-14s %d services, %d ssh services, unmatched=%s\n", name, len(p.Services), len(p.SSH), p.Unmatched)
			}
			fmt.Printf("ok: %s\n", cfg.Path)
			return nil
		},
	}
}
