package jsfilter

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/gitproto"
	"github.com/marwatk/agent-bouncer/internal/kv"
)

func writeFilter(t *testing.T, dir, name, src string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func load(t *testing.T, src string, opts Options) *Filter {
	t.Helper()
	opts.Path = writeFilter(t, t.TempDir(), "f.ts", src)
	f, err := Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func req(t *testing.T, method, raw string, body []byte) *chain.Request {
	u, _ := url.Parse(raw)
	return &chain.Request{Ctx: context.Background(), Transport: chain.TransportHTTP, Method: method, URL: u,
		Header: http.Header{}, Body: chain.BytesBody(body), Session: &chain.Session{ID: "s1"}}
}

func upstream(body string) chain.Handler {
	return func(*chain.Request) (*chain.Response, error) {
		return &chain.Response{Status: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: chain.BytesBody([]byte(body))}, nil
	}
}

func TestGitPushFilter(t *testing.T) {
	f := load(t, `
import { defineFilter, deny } from "bouncer";
export default defineFilter<{ branches: string[] }>({
  async onRequest(req, next, ctx) {
    if (req.git?.service === "receive-pack") {
      const updates = await req.git.refUpdates();
      const hit = updates.find(u => ctx.config.branches.includes(u.ref.replace("refs/heads/", "")));
      if (hit) return deny(`+"`push to ${hit.ref} blocked`"+`);
    }
    return next(req);
  },
});`, Options{Config: map[string]any{"branches": []any{"foo"}}})
	h := chain.Build([]chain.Filter{f}, upstream("ok"))
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	body := gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/feature"}, {OldOID: a, NewOID: b, Ref: "refs/heads/foo"}}, nil, nil)
	resp, err := h(req(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Denial == nil || resp.Denial.Reason != "push to refs/heads/foo blocked" || resp.Denial.By != "f" {
		t.Fatalf("expected denial, got %+v", resp.Denial)
	}
	body = gitproto.BuildPush([]gitproto.RefUpdate{{OldOID: a, NewOID: b, Ref: "refs/heads/feature"}}, nil, nil)
	resp, _ = h(req(t, "POST", "https://gitlab.com/g/p.git/git-receive-pack", body))
	if resp.Denial != nil {
		t.Fatalf("unexpected denial %+v", resp.Denial)
	}
}

func TestNestedFiltersAndResponseRewrite(t *testing.T) {
	outer := load(t, `
import { defineFilter } from "bouncer";
export default defineFilter({
  name: "outer",
  async onRequest(req, next) {
    req.headers.set("X-Outer", "1");
    const res = await next(req);
    const text = await res.body.text();
    res.body.set(text.replace("SECRET", "[redacted]"));
    res.headers.set("X-Seen", String(res.status));
    return res;
  },
});`, Options{})
	inner := load(t, `
export default {
  name: "inner",
  async onRequest(req, next) {
    if (req.headers.get("x-outer") !== "1") throw new Error("outer header missing");
    const res = await next(req);
    res.setStatus(201);
    return res;
  },
};`, Options{})
	h := chain.Build([]chain.Filter{outer, inner}, upstream("token=SECRET"))
	resp, err := h(req(t, "GET", "https://x/", nil))
	if err != nil || resp.Denial != nil {
		t.Fatalf("%+v %v", resp, err)
	}
	b, _ := io.ReadAll(resp.Body.Reader())
	if string(b) != "token=[redacted]" || resp.Status != 201 || resp.Header.Get("X-Seen") != "201" {
		t.Fatalf("status=%d body=%q headers=%v", resp.Status, b, resp.Header)
	}
}

func TestOnResponseHook(t *testing.T) {
	f := load(t, `
import { defineFilter, deny } from "bouncer";
export default defineFilter({
  async onResponse(res, req) {
    if ((await res.body.text()).includes("BEGIN PRIVATE KEY")) return deny("response contained a private key");
  },
});`, Options{})
	h := chain.Build([]chain.Filter{f}, upstream("-----BEGIN PRIVATE KEY-----"))
	if resp, _ := h(req(t, "GET", "https://x/", nil)); resp.Denial == nil {
		t.Fatal("expected denial")
	}
	h = chain.Build([]chain.Filter{f}, upstream("fine"))
	if resp, _ := h(req(t, "GET", "https://x/", nil)); resp.Denial != nil || resp.Status != 200 {
		t.Fatalf("unexpected %+v", resp)
	}
}

func TestRespondAndJSONBody(t *testing.T) {
	f := load(t, `
import { defineFilter, respond } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    const body = await req.body.json();
    if (body.channel !== "#agent-bot") return respond(422, { ok: false, error: "channel not allowed" }, { "Content-Type": "application/json" });
    return next(req);
  },
});`, Options{})
	h := chain.Build([]chain.Filter{f}, upstream("posted"))
	resp, _ := h(req(t, "POST", "https://slack.com/api/chat.postMessage", []byte(`{"channel":"#general"}`)))
	b, _ := io.ReadAll(resp.Body.Reader())
	if resp.Status != 422 || string(b) != `{"ok":false,"error":"channel not allowed"}` || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d body=%s", resp.Status, b)
	}
}

func TestKVAndAsk(t *testing.T) {
	store, _ := kv.Open("")
	defer store.Close()
	var prompts []string
	env := &chain.Env{Approver: approver(func(a chain.AskRequest) bool { prompts = append(prompts, a.Prompt); return a.Prompt == "push #2?" })}
	f := load(t, `
import { defineFilter, deny, ask, kv } from "bouncer";
export default defineFilter({
  async onRequest(req, next) {
    const n = kv.incr("count", { ttl: "1h" });
    if (n > 1 && !(await ask("push #" + n + "?"))) return deny("not approved");
    return next(req);
  },
});`, Options{Env: env, KV: store})
	h := chain.Build([]chain.Filter{f}, upstream("ok"))
	for i, want := range []bool{true, true, false} {
		resp, _ := h(req(t, "GET", "https://x/", nil))
		if got := resp.Denial == nil; got != want {
			t.Errorf("call %d: allowed=%v want %v (%+v)", i+1, got, want, resp.Denial)
		}
	}
	if len(prompts) != 2 {
		t.Errorf("prompts: %v", prompts)
	}
}

type approver func(chain.AskRequest) bool

func (a approver) Ask(_ context.Context, r chain.AskRequest) (bool, error) { return a(r), nil }

func TestTimeoutFailsClosedAndExcludesBlockedTime(t *testing.T) {
	spin := load(t, `export default { onRequest() { for (;;) {} } };`, Options{Timeout: 50 * time.Millisecond})
	start := time.Now()
	resp, _ := chain.Build([]chain.Filter{spin}, upstream("ok"))(req(t, "GET", "https://x/", nil))
	if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "CPU budget") {
		t.Fatalf("expected timeout denial, got %+v", resp.Denial)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout did not interrupt")
	}
	// A slow upstream must not count against the filter's budget.
	pass := load(t, `export default { async onRequest(req, next) { return next(req); } };`, Options{Timeout: 20 * time.Millisecond})
	slow := func(*chain.Request) (*chain.Response, error) {
		time.Sleep(100 * time.Millisecond)
		return &chain.Response{Status: 200}, nil
	}
	if resp, _ := chain.Build([]chain.Filter{pass}, slow)(req(t, "GET", "https://x/", nil)); resp.Denial != nil {
		t.Fatalf("blocked time counted against budget: %+v", resp.Denial)
	}
}

func TestGetAllReturnsArrays(t *testing.T) {
	f := load(t, `import { deny } from "bouncer";
export default { onRequest(req, next) {
  const q = req.query.getAll("missing"), h = req.headers.getAll("X-Missing");
  if (!Array.isArray(q) || q.length || !Array.isArray(h) || h.length) return deny("not empty arrays");
  return next(req);
} };`, Options{})
	if resp, _ := chain.Build([]chain.Filter{f}, upstream("ok"))(req(t, "GET", "https://x/", nil)); resp.Denial != nil {
		t.Fatal(resp.Denial.Reason)
	}
}

func TestHostCallLoopStillHitsBudget(t *testing.T) {
	f := load(t, `export default { async onRequest(req, next) { for (;;) { await req.body.peek(1); } } };`, Options{Timeout: 100 * time.Millisecond})
	start := time.Now()
	resp, _ := chain.Build([]chain.Filter{f}, upstream("ok"))(req(t, "POST", "https://x/", []byte("abc")))
	if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "CPU budget") {
		t.Fatalf("expected budget denial, got %+v", resp.Denial)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("100ms budget took %v: in-memory host calls aren't being counted", elapsed)
	}
}

func TestErrorsFailClosedWithSourceLocation(t *testing.T) {
	f := load(t, `
import { defineFilter } from "bouncer";
interface X { a: number }
export default defineFilter({
  onRequest(req, next) {
    const x: X = { a: 1 };
    throw new Error("kaboom " + x.a);
  },
});`, Options{})
	resp, _ := chain.Build([]chain.Filter{f}, upstream("ok"))(req(t, "GET", "https://x/", nil))
	if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "kaboom 1") {
		t.Fatalf("%+v", resp.Denial)
	}
	if !strings.Contains(resp.Denial.Reason, "f.ts:7") {
		t.Errorf("stack should point at the TS source line: %s", resp.Denial.Reason)
	}

	noReturn := load(t, `export default { onRequest(req, next) { next(req); } };`, Options{})
	resp, _ = chain.Build([]chain.Filter{noReturn}, upstream("ok"))(req(t, "GET", "https://x/", nil))
	if resp.Denial == nil || !strings.Contains(resp.Denial.Reason, "returned nothing") {
		t.Fatalf("%+v", resp.Denial)
	}
}

func TestRelativeImportsAndGraphQL(t *testing.T) {
	dir := t.TempDir()
	writeFilter(t, dir, "lib.ts", `export const DANGEROUS = new Set(["deleteRepository"]);`)
	p := writeFilter(t, dir, "gql.ts", `
import { defineFilter, deny } from "bouncer";
import { DANGEROUS } from "./lib";
export default defineFilter({
  async onRequest(req, next) {
    const ops = await req.graphql();
    for (const op of ops ?? []) for (const f of op.fields) if (DANGEROUS.has(f)) return deny(f);
    return next(req);
  },
});`)
	f, err := Load(Options{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	h := chain.Build([]chain.Filter{f}, upstream("ok"))
	resp, _ := h(req(t, "POST", "https://api.github.com/graphql", []byte(`{"query":"mutation { deleteRepository(input:{}) { clientMutationId } }"}`)))
	if resp.Denial == nil || resp.Denial.Reason != "deleteRepository" {
		t.Fatalf("%+v", resp.Denial)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"syntax.ts":  `export default { onRequest( };`,
		"nohooks.ts": `export default { name: "x" };`,
		"nodef.ts":   `export const x = 1;`,
		"import.ts":  `import x from "./missing"; export default x;`,
	} {
		if _, err := Load(Options{Path: writeFilter(t, dir, name, src)}); err == nil {
			t.Errorf("%s: expected load error", name)
		}
	}
}

func TestConcurrentRequestsUseSeparateVMs(t *testing.T) {
	f := load(t, `export default { async onRequest(req, next) { const r = await next(req); return r; } };`, Options{})
	h := chain.Build([]chain.Filter{f}, func(*chain.Request) (*chain.Response, error) {
		time.Sleep(10 * time.Millisecond)
		return &chain.Response{Status: 200}, nil
	})
	done := make(chan bool)
	for i := 0; i < 20; i++ {
		go func() {
			resp, _ := h(req(t, "GET", "https://x/", nil))
			done <- resp.Denial == nil
		}()
	}
	for i := 0; i < 20; i++ {
		if !<-done {
			t.Fatal("concurrent request denied")
		}
	}
}
