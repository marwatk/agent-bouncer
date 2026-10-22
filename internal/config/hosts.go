package config

import (
	"net"
	"strings"
)

// HostMatches reports whether host (optionally host:port) matches any pattern.
// Patterns are exact hostnames or "*.example.com" (one or more labels), and
// may carry a ":port" suffix that must then match exactly. A pattern without
// a port matches only the default HTTPS port (or a bare host, as for SSH),
// so "gitlab.com" never matches plain-HTTP gitlab.com:80.
func HostMatches(patterns []string, hostport string) bool {
	host, port := SplitHostPort(hostport)
	host = asciiLower(strings.TrimSuffix(host, "."))
	for _, p := range patterns {
		ph, pp := SplitHostPort(p)
		ph = asciiLower(ph)
		if pp == "" {
			pp = "443"
		}
		if port != "" && pp != port {
			continue
		}
		if strings.HasPrefix(ph, "*.") {
			if strings.HasSuffix(host, ph[1:]) && len(host) > len(ph)-1 {
				return true
			}
			continue
		}
		if ph == host {
			return true
		}
	}
	return false
}

// asciiLower lowercases ASCII letters only, leaving other bytes unchanged,
// so no non-ASCII rune can case-fold onto an ASCII hostname.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// SplitHostPort splits "host:port", tolerating a missing port and IPv6 brackets.
func SplitHostPort(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return strings.Trim(s, "[]"), ""
}
