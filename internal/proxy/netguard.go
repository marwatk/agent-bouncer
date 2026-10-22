package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// nonPublic reports whether ip is an address an agent must not reach
// through a tunnel by default: the host itself, its LAN, link-local
// (including cloud metadata endpoints), CGNAT/overlay ranges, and the like.
func nonPublic(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip)
}

// publicDialer refuses non-public destinations. The check runs on the
// address actually being connected to, after DNS resolution, so a name that
// resolves (or re-resolves) to an internal address is caught too.
func publicDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || nonPublic(ip) {
				return fmt.Errorf("%w: %s", errNonPublic, host)
			}
			return nil
		},
	}
}

type nonPublicError struct{}

func (nonPublicError) Error() string {
	return "destination is a loopback, private or link-local address (set allow_private: true on the profile to permit)"
}

var errNonPublic error = nonPublicError{}

// tunnelDial dials an unmatched host for a profile.
func (s *Server) tunnelDial(ctx context.Context, allowPrivate bool, addr string) (net.Conn, error) {
	if allowPrivate {
		return s.Dialer.DialContext(ctx, "tcp", addr)
	}
	return publicDialer().DialContext(ctx, "tcp", addr)
}

// tunnelTransport forwards plain-HTTP requests to unmatched hosts.
func (s *Server) tunnelTransport(allowPrivate bool) http.RoundTripper {
	s.tunnelOnce.Do(func() {
		t := NewTransport()
		t.DialContext = publicDialer().DialContext
		s.publicTransport = t
	})
	if allowPrivate {
		return s.Transport
	}
	return s.publicTransport
}
