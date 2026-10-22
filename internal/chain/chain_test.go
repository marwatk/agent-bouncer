package chain

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/gitproto"
)

func httpReq(t *testing.T, method, rawURL string, body []byte) *Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return &Request{Ctx: context.Background(), Transport: TransportHTTP, Method: method, URL: u,
		Header: http.Header{}, Body: BytesBody(body), Service: "gitlab"}
}

func upstreamOK(*Request) (*Response, error) { return &Response{Status: 200}, nil }

func loadRules(t *testing.T, yml string) *config.Service {
	t.Helper()
	cfg, err := config.Parse([]byte(`
credentials: {gl: {source: keyring}}
profiles:
  p:
    services:
      - name: gitlab
        hosts: [gitlab.com]
        credential: gl
`+yml), "/tmp/c.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Profiles["p"].Services[0]
}

func TestGitLabProjectScope(t *testing.T) {
	svc := loadRules(t, `
        rules:
          - action: allow
            gitlab_project: mygroup/myproj
          - action: allow
            methods: [GET]
            path: /api/v4/user
`)
	env := &Env{Resolver: func(_ context.Context, _, _, p string) (int64, error) {
		if p == "mygroup/myproj" {
			return 4242, nil
		}
		return 0, nil
	}}
	h := Build([]Filter{NewRules(svc, env)}, upstreamOK)
	cases := []struct {
		method, url string
		allow       bool
	}{
		{"GET", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj", true},
		{"GET", "https://gitlab.com/api/v4/projects/MyGroup%2FMyProj/merge_requests", true},
		{"GET", "https://gitlab.com/api/v4/projects/4242/issues", true},
		{"GET", "https://gitlab.com/api/v4/projects/4243/issues", false},
		{"GET", "https://gitlab.com/api/v4/projects/mygroup%2Fother/issues", false},
		{"GET", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj-evil", false},
		{"GET", "https://gitlab.com/api/v4/projects", false},
		{"GET", "https://gitlab.com/api/v4/user", true},
		{"POST", "https://gitlab.com/api/v4/user", false},
		{"GET", "https://gitlab.com/api/v4/groups/mygroup", false},
		{"POST", "https://gitlab.com/api/graphql", false},
		{"GET", "https://gitlab.com/mygroup/myproj.git/info/refs?service=git-upload-pack", true},
		{"POST", "https://gitlab.com/mygroup/other.git/git-upload-pack", false},
	}
	for _, c := range cases {
		resp, err := h(httpReq(t, c.method, c.url, nil))
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.Denial == nil; got != c.allow {
			t.Errorf("%s %s: allowed=%v want %v (%+v)", c.method, c.url, got, c.allow, resp.Denial)
		}
	}
}

func TestGitLabProjectSubpaths(t *testing.T) {
	svc := loadRules(t, `
        rules:
          - action: deny
            reason: secrets and membership are off-limits
            gitlab_project: {path: mygroup/myproj, subpaths: ["variables/**", "members/**"]}
          - action: deny
            methods: [DELETE, PUT]
            gitlab_project: {path: mygroup/myproj, subpaths: [""]}
          - action: allow
            gitlab_project: mygroup/myproj
`)
	h := Build([]Filter{NewRules(svc, &Env{Resolver: func(context.Context, string, string, string) (int64, error) { return 7, nil }})}, upstreamOK)
	for _, c := range []struct {
		method, url string
		allow       bool
	}{
		{"GET", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj", true},
		{"DELETE", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj", false},
		{"DELETE", "https://gitlab.com/api/v4/projects/7", false},
		{"DELETE", "https://gitlab.com/api/v4/projects/7/issues/3", true},
		{"GET", "https://gitlab.com/api/v4/projects/7/variables", false},
		{"GET", "https://gitlab.com/api/v4/projects/mygroup%2Fmyproj/variables/KEY", false},
		{"POST", "https://gitlab.com/api/v4/projects/7/members", false},
		{"GET", "https://gitlab.com/mygroup/myproj.git/info/refs?service=git-upload-pack", true},
	} {
		resp, _ := h(httpReq(t, c.method, c.url, nil))
		if got := resp.Denial == nil; got != c.allow {
			t.Errorf("%s %s: allowed=%v want %v", c.method, c.url, got, c.allow)
		}
	}
}

func TestGitPushRefRule(t *testing.T) {
	svc := loadRules(t, `
        default: allow
        rules:
          - action: deny
            reason: protected branch
            git: {service: receive-pack, refs: [refs/heads/main, refs/heads/release/*]}
          - action: deny
            git: {service: receive-pack, updates: [delete]}
`)
	h := Build([]Filter{NewRules(svc, nil)}, upstreamOK)
	a := strings.Repeat("a", 40)
	b := strings.Repeat("b", 40)
	push := func(ups ...gitproto.RefUpdate) []byte { return gitproto.BuildPush(ups, []string{"report-status"}, nil) }
	cases := []struct {
		name  string
		body  []byte
		allow bool
	}{
		{"feature", push(gitproto.RefUpdate{OldOID: a, NewOID: b, Ref: "refs/heads/feature"}), true},
		{"main among many", push(gitproto.RefUpdate{OldOID: a, NewOID: b, Ref: "refs/heads/feature"}, gitproto.RefUpdate{OldOID: a, NewOID: b, Ref: "refs/heads/main"}), false},
		{"release glob", push(gitproto.RefUpdate{OldOID: a, NewOID: b, Ref: "refs/heads/release/1.0"}), false},
		{"delete", push(gitproto.RefUpdate{OldOID: a, NewOID: gitproto.ZeroOID, Ref: "refs/heads/feature"}), false},
	}
	for _, c := range cases {
		req := httpReq(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", c.body)
		resp, _ := h(req)
		if got := resp.Denial == nil; got != c.allow {
			t.Errorf("%s: allowed=%v want %v", c.name, got, c.allow)
		}
		// The body must still be forwarded intact after inspection.
		fwd, _ := io.ReadAll(req.Body.Reader())
		if !bytes.Equal(fwd, c.body) {
			t.Errorf("%s: body altered by inspection", c.name)
		}
	}
	// Ref advertisement for a push carries no commands and is allowed.
	resp, _ := h(httpReq(t, "GET", "https://gitlab.com/g/p.git/info/refs?service=git-receive-pack", nil))
	if resp.Denial != nil {
		t.Errorf("info/refs denied: %+v", resp.Denial)
	}
}

func TestGraphQLRule(t *testing.T) {
	svc := loadRules(t, `
        default: allow
        rules:
          - action: deny
            path: /graphql
            graphql: {operations: [mutation], fields: [deleteRepository]}
`)
	h := Build([]Filter{NewRules(svc, nil)}, upstreamOK)
	req := httpReq(t, "POST", "https://api.github.com/graphql",
		[]byte(`{"query":"mutation { ...F } fragment F on Mutation { deleteRepository(input:{}) { clientMutationId } }"}`))
	if resp, _ := h(req); resp.Denial == nil {
		t.Error("fragment-hidden deleteRepository allowed")
	}
	req = httpReq(t, "POST", "https://api.github.com/graphql", []byte(`{"query":"not graphql {"}`))
	if resp, _ := h(req); resp.Denial == nil {
		t.Error("unparseable graphql should fail closed")
	}
	req = httpReq(t, "POST", "https://api.github.com/graphql", []byte(`{"query":"{ viewer { login } }"}`))
	if resp, _ := h(req); resp.Denial != nil {
		t.Errorf("query denied: %+v", resp.Denial)
	}
}

func TestGitHubRepo(t *testing.T) {
	svc := loadRules(t, `
        rules:
          - action: allow
            github_repo: octo/hello
`)
	h := Build([]Filter{NewRules(svc, nil)}, upstreamOK)
	for url, want := range map[string]bool{
		"https://api.github.com/repos/octo/hello/pulls":      true,
		"https://ghe.corp/api/v3/repos/Octo/Hello":           true,
		"https://api.github.com/repos/octo/hello2":           false,
		"https://github.com/octo/hello.git/git-upload-pack":  true,
		"https://github.com/octo/other.git/git-receive-pack": false,
		"https://api.github.com/repositories/123/pulls":      false,
		"https://api.github.com/user/repos":                  false,
	} {
		resp, _ := h(httpReq(t, "GET", url, nil))
		if got := resp.Denial == nil; got != want {
			t.Errorf("%s: allowed=%v want %v", url, got, want)
		}
	}
}

func TestAskRule(t *testing.T) {
	svc := loadRules(t, `
        rules:
          - action: ask
            prompt: merge?
            methods: [PUT]
`)
	answer := false
	var asked string
	env := &Env{Approver: approverFunc(func(a AskRequest) bool { asked = a.Prompt; return answer })}
	h := Build([]Filter{NewRules(svc, env)}, upstreamOK)
	if resp, _ := h(httpReq(t, "PUT", "https://gitlab.com/x", nil)); resp.Denial == nil || asked != "merge?" {
		t.Errorf("expected denial after no; asked=%q", asked)
	}
	answer = true
	if resp, _ := h(httpReq(t, "PUT", "https://gitlab.com/x", nil)); resp.Denial != nil {
		t.Error("expected allow after yes")
	}
}

type approverFunc func(AskRequest) bool

func (f approverFunc) Ask(_ context.Context, a AskRequest) (bool, error) { return f(a), nil }

func TestCheckPath(t *testing.T) {
	for p, ok := range map[string]bool{
		"/api/v4/projects/x":        true,
		"/a/../b":                   false,
		"/a/./b":                    false,
		"/a//b":                     false,
		"/a\\b":                     false,
		"/api/v4/projects/a/../../": false,
	} {
		if got := CheckPath(p) == nil; got != ok {
			t.Errorf("CheckPath(%q) ok=%v want %v", p, got, ok)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pat, name string
		want      bool
	}{
		{"/api/v4/user", "/api/v4/user", true},
		{"/api/*/user", "/api/v4/user", true},
		{"/api/**", "/api/v4/user", true},
		{"/api/**", "/api", true},
		{"/api/**/user", "/api/v4/x/user", true},
		{"refs/heads/release/*", "refs/heads/release/1.0", true},
		{"refs/heads/release/*", "refs/heads/release/1.0/hotfix", false},
		{"refs/heads/*", "refs/tags/v1", false},
	} {
		if got := Glob(c.pat, c.name); got != c.want {
			t.Errorf("Glob(%q, %q) = %v", c.pat, c.name, got)
		}
	}
}

func TestBuildFailsClosed(t *testing.T) {
	boom := filterFunc(func(*Request, Handler) (*Response, error) { panic("boom") })
	resp, err := Build([]Filter{boom}, upstreamOK)(httpReq(t, "GET", "https://x/", nil))
	if err != nil || resp.Denial == nil {
		t.Fatalf("panic should deny: %+v %v", resp, err)
	}
}

type filterFunc func(*Request, Handler) (*Response, error)

func (f filterFunc) Name() string                                    { return "func" }
func (f filterFunc) Handle(r *Request, n Handler) (*Response, error) { return f(r, n) }
