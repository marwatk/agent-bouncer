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
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range patterns {
		ph, pp := SplitHostPort(p)
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

// SplitHostPort splits "host:port", tolerating a missing port and IPv6 brackets.
func SplitHostPort(s string) (host, port string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return strings.Trim(s, "[]"), ""
}
