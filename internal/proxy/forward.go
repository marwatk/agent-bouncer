package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/policy"
)

// forwarder is the terminal handler: inject the credential and send upstream.
// It runs only after every filter and rule has allowed the request, so
// filters never see the secret.
func (s *Server) forwarder(svc *policy.Service, origLength int64) chain.Handler {
	return func(req *chain.Request) (*chain.Response, error) {
		header := req.Header.Clone()
		// Let the transport negotiate (and transparently decode) compression
		// so response filters always see plain bodies.
		header.Del("Accept-Encoding")
		u := *req.URL
		if name := svc.Config.Credential; name != "" {
			if u.Scheme != "https" && !svc.Config.Insecure {
				return synthetic(http.StatusForbidden, "agent-bouncer: refusing to send credentials over plain HTTP; use https (or set insecure: true on the service for local development)"), nil
			}
			secret, err := s.Creds.Get(req.Ctx, name)
			if err != nil {
				// Source errors can carry password-manager output; keep them
				// in the daemon log, not in the agent's response.
				s.logf("credential for service %s: %v", svc.Config.Name, err)
				return synthetic(http.StatusBadGateway, "agent-bouncer: credential for "+svc.Config.Name+" is unavailable; see the bouncer log"), nil
			}
			Inject(header, &u, name, svc.Config.Inject.For(req.Git() != nil), secret)
		}

		length := req.Body.Len()
		if length < 0 {
			length = origLength
		}
		var body io.ReadCloser = http.NoBody
		if length != 0 {
			body = req.Body.Reader()
		}
		out, err := http.NewRequestWithContext(req.Ctx, req.Method, u.String(), body)
		if err != nil {
			return synthetic(http.StatusBadGateway, "agent-bouncer: "+err.Error()), nil
		}
		out.Header = header
		out.ContentLength = length
		out.Host = u.Host

		resp, err := s.Transport.RoundTrip(out)
		if err != nil {
			return synthetic(http.StatusBadGateway, "agent-bouncer: upstream error: "+err.Error()), nil
		}
		r := &chain.Response{Status: resp.StatusCode, Header: resp.Header}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			if rwc, ok := resp.Body.(io.ReadWriteCloser); ok {
				r.Upgrade = rwc
				return r, nil
			}
		}
		r.Body = chain.NewBody(resp.Body)
		return r, nil
	}
}

func synthetic(status int, msg string) *chain.Response {
	return &chain.Response{Status: status, Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body: chain.BytesBody([]byte(msg + "\n"))}
}

// Inject replaces the credential's placeholder in authentication headers
// (including inside Basic auth), then applies the explicit inject spec.
//
// Placeholders are replaced only in Authorization, Private-Token, the
// spec's header, and headers it lists in placeholder_headers. Anywhere an
// API might store and echo a value back (other headers, the query string,
// the body), a substituted secret would end up readable by the agent.
func Inject(h http.Header, u *url.URL, credName string, spec *config.Inject, secret string) {
	ph := config.Placeholder(credName)
	for _, k := range placeholderHeaders(spec) {
		vs := h.Values(k)
		for i, v := range vs {
			if strings.HasPrefix(v, "Basic ") && strings.EqualFold(k, "Authorization") {
				if raw, err := base64.StdEncoding.DecodeString(v[len("Basic "):]); err == nil && strings.Contains(string(raw), ph) {
					vs[i] = "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(string(raw), ph, secret)))
					continue
				}
			}
			if strings.Contains(v, ph) {
				vs[i] = strings.ReplaceAll(v, ph, secret)
			}
		}
	}
	if spec == nil {
		return
	}
	switch {
	case spec.Bearer:
		h.Set("Authorization", "Bearer "+secret)
	case spec.Basic != nil:
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(spec.Basic.Username+":"+secret)))
	case spec.Header != "":
		v := spec.Value
		if v == "" {
			v = "{{secret}}"
		}
		h.Set(spec.Header, strings.ReplaceAll(v, "{{secret}}", secret))
	}
	if spec.Query != "" {
		q := u.Query()
		q.Set(spec.Query, secret)
		u.RawQuery = q.Encode()
	}
}

// placeholderHeaders lists the headers in which placeholders are replaced.
func placeholderHeaders(spec *config.Inject) []string {
	out := []string{"Authorization", "Private-Token"}
	if spec != nil {
		if spec.Header != "" {
			out = append(out, spec.Header)
		}
		out = append(out, spec.PlaceholderHeaders...)
	}
	return out
}
