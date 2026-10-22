// Package paths locates bouncer's configuration and state directories.
package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// Home is the root directory for bouncer's config and state. It honors
// BOUNCER_HOME, falling back to <user config dir>/agent-bouncer.
func Home() string {
	if h := os.Getenv("BOUNCER_HOME"); h != "" {
		return h
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "agent-bouncer")
}

// ConfigFile is the default config file path.
func ConfigFile() string { return filepath.Join(Home(), "config.yaml") }

// StateDir holds generated material: CA keys, sessions, KV data, audit log.
func StateDir() string { return filepath.Join(Home(), "state") }

// Expand resolves a leading ~ and makes relative paths relative to base.
func Expand(p, base string) string {
	if p == "" {
		return p
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	if !filepath.IsAbs(p) && base != "" {
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}
