package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marwatk/agent-bouncer/internal/audit"
	"github.com/marwatk/agent-bouncer/internal/daemon"
	"github.com/marwatk/agent-bouncer/internal/paths"
)

func serveCmd() *cobra.Command {
	var showTunnels, quiet bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the bouncer daemon",
		Long: `Run the proxy and SSH listeners. Decisions are printed here and appended to
the audit log; when this terminal is interactive, approvals are prompted here.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := log.New(os.Stderr, "", log.Ltime)
			d, err := daemon.New(daemon.Options{
				ConfigPath: configPath,
				StateDir:   paths.StateDir(),
				Logf:       logger.Printf,
				Decision: func(e audit.Entry) {
					if quiet || (e.Decision == "tunnel" && !showTunnels) {
						return
					}
					logger.Print(formatDecision(e))
				},
			})
			if err != nil {
				return err
			}
			cfg := d.Config()
			logger.Printf("config %s", cfg.Path)
			logger.Printf("CA certificate %s (run `bouncer ca install` once so Go/OS-verifier tools trust it)", d.CA.CertPath())
			interactive := term.IsTerminal(int(os.Stdin.Fd()))
			if cfg.Approvals.TerminalEnabled() && interactive {
				go d.RunTerminalApprover(os.Stdin, os.Stderr)
			} else if cfg.Approvals.CLIEnabled() {
				logger.Printf("answer approvals with `bouncer approvals` / `bouncer approve <id>`")
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return d.Run(ctx)
		},
	}
	cmd.Flags().BoolVar(&showTunnels, "show-tunnels", false, "also print tunneled (uninspected) connections")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "don't print decisions (they are still audited)")
	return cmd
}

func formatDecision(e audit.Entry) string {
	who := e.Label
	if who == "" {
		who = e.Session
	}
	s := fmt.Sprintf("%-6s [%s] %s", strings.ToUpper(e.Decision), who, e.Request)
	if e.Status != 0 && e.Decision == "allow" {
		s += fmt.Sprintf(" -> %d", e.Status)
	}
	switch {
	case e.Decision == "deny" || e.Decision == "error":
		s += fmt.Sprintf("  (%s: %s)", e.By, e.Reason)
	case e.By != "":
		s += fmt.Sprintf("  (%s)", e.By)
	}
	return s
}
