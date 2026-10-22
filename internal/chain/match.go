package chain

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/marwatk/agent-bouncer/internal/config"
)

// CheckPath rejects paths whose meaning could differ between bouncer and the
// upstream server: dot segments (literal or encoded), empty segments,
// backslashes and NULs. Rules match decoded paths, so ambiguity here would
// let a request match one rule while reaching a different endpoint.
func CheckPath(decoded string) error {
	if decoded == "" || decoded == "/" {
		return nil
	}
	if strings.ContainsAny(decoded, "\\\x00") {
		return errors.New("path contains a backslash or NUL")
	}
	if strings.Contains(decoded, "//") {
		return errors.New("path contains an empty segment")
	}
	for _, seg := range strings.Split(decoded, "/") {
		if seg == "." || seg == ".." {
			return errors.New("path contains a dot segment")
		}
	}
	return nil
}

// CheckMethod rejects HTTP methods that aren't upper-case tokens. Method
// names are case-sensitive, but some servers fold them, so a method that
// differs only in case from one a rule names could be evaluated as one
// method and executed as another.
func CheckMethod(m string) error {
	if m == "" {
		return errors.New("empty method")
	}
	for _, c := range m {
		if c < 'A' || c > 'Z' {
			return fmt.Errorf("non-canonical method %q (methods must be upper-case letters)", m)
		}
	}
	return nil
}

// Glob matches a slash-separated name against a pattern where "*" matches
// within one segment (path.Match syntax) and "**" matches any number of
// segments, including none.
func Glob(pattern, name string) bool {
	return globSegs(strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(name, "/"), "/"))
}

func globSegs(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for i := 0; i <= len(segs); i++ {
				if globSegs(pat[1:], segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if ok, err := path.Match(pat[0], segs[0]); err != nil || !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

// rawSegments splits an escaped path into decoded segments, keeping
// encoded slashes (%2F) inside their segment.
func rawSegments(raw string) ([]string, error) {
	parts := strings.Split(strings.TrimPrefix(raw, "/"), "/")
	for i, p := range parts {
		d, err := url.PathUnescape(p)
		if err != nil {
			return nil, err
		}
		parts[i] = d
	}
	return parts, nil
}

// apiProject splits a GitLab API path (/api/v4/projects/:id/rest...) into
// the decoded project identifier and the remaining subpath. ok is false if
// this isn't a project path.
func apiProject(raw string) (id, subpath string, ok bool, err error) {
	segs, err := rawSegments(raw)
	if err != nil {
		return "", "", false, err
	}
	if len(segs) >= 4 && segs[0] == "api" && segs[1] == "v4" && segs[2] == "projects" && segs[3] != "" {
		return segs[3], strings.Join(segs[4:], "/"), true, nil
	}
	return "", "", false, nil
}

// matchGitLabProject reports whether req targets the given project via the
// REST API or git (HTTP or SSH). Numeric project IDs are resolved through the
// Env resolver when the rule doesn't pin an ID. With subpaths, only REST
// endpoints under the project whose subpath matches a glob qualify.
func matchGitLabProject(req *Request, env *Env, p *config.ProjectRef) (bool, error) {
	if g := req.Git(); g != nil {
		return len(p.Subpaths) == 0 && p.Path != "" && strings.EqualFold(g.Repo, p.Path), nil
	}
	if req.Transport != TransportHTTP {
		return false, nil
	}
	seg, sub, ok, err := apiProject(req.RawPath())
	if err != nil || !ok {
		return false, err
	}
	if len(p.Subpaths) > 0 && !slices.ContainsFunc(p.Subpaths, func(g string) bool { return Glob(g, sub) }) {
		return false, nil
	}
	if n, err := strconv.ParseInt(seg, 10, 64); err == nil {
		if p.ID != 0 {
			return n == p.ID, nil
		}
		if p.Path == "" || env == nil || env.Resolver == nil {
			return false, nil
		}
		id, err := env.Resolver(req.Ctx, req.Service, req.URL.Host, p.Path)
		if err != nil {
			return false, fmt.Errorf("resolving GitLab project %q: %w", p.Path, err)
		}
		return n == id, nil
	}
	return p.Path != "" && strings.EqualFold(seg, p.Path), nil
}

// matchGitHubRepo reports whether req targets owner/repo via the REST API
// (github.com or GHES /api/v3) or git.
func matchGitHubRepo(req *Request, repo string) (bool, error) {
	if g := req.Git(); g != nil {
		return strings.EqualFold(g.Repo, repo), nil
	}
	if req.Transport != TransportHTTP {
		return false, nil
	}
	segs, err := rawSegments(req.RawPath())
	if err != nil {
		return false, err
	}
	if len(segs) >= 2 && segs[0] == "api" && segs[1] == "v3" {
		segs = segs[2:]
	}
	if len(segs) >= 3 && segs[0] == "repos" {
		return strings.EqualFold(segs[1]+"/"+segs[2], repo), nil
	}
	return false, nil
}
