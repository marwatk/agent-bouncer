# Design notes

Decisions behind agent-bouncer and why they were made. Read the README
first for what it does.

## Goals

1. Agents never hold real credentials.
2. Users extend policy without recompiling: servlet-filter-style code that
   can inspect, modify, short-circuit or post-process a request.
3. Policy can reach into protocol payloads (git push ref updates, GraphQL
   operations), not just URLs.
4. Works for any agent; known agents are a convenience, not a requirement.
5. One developer, one machine; macOS, Linux and Windows.

## Language choices

**Host: Go.** The deciding factors were the proxy and SSH building blocks:
`net/http`, `crypto/tls`, `x/crypto/ssh` (both client and server, which is
what makes SSH termination feasible), plus single static binaries that
cross-compile to all three OSes. Rust's advantages (performance,
wasmtime-grade sandboxing) don't matter for a per-developer broker, given v1
treats filters as trusted.

**Filters: TypeScript, executed by goja, bundled by esbuild.** Both are
pure Go, so there's no cgo and cross-compiles stay simple.
* Bundling and stripping types happen in-process at load time, so users
  write `.ts` with no build step and get editor completion from
  `types/bouncer.d.ts`.
* esbuild bundles relative imports and pure-JS npm packages, and its
  inline source maps make stack traces point at TypeScript lines.
* TS was chosen over Lua and Starlark for familiarity, ecosystem, and how
  reliably both humans and AI agents write it. The middleware shape
  (`async (req, next) => ...`) is already idiomatic.

**No filter sandbox in v1** (an explicit decision: rules are trusted).
The host API surface is narrow (request/response objects, `ask`, `kv`,
`log`) so a later move to QuickJS-in-WASM (wazero) or a WASM ABI wouldn't
change filter code.

## Filter execution model

goja runtimes aren't goroutine-safe and have no event loop. Instead of
writing one, every host call that might block (`next()`, `ask()`, body
reads, `refUpdates()`, `graphql()`) *runs synchronously* and returns an
already-settled promise. goja drains its job queue when the outermost call
returns, so `await` works naturally and the hook's promise has always
settled by the time the call returns. A promise that's still pending is
reported as an error.

Each request borrows a VM from a per-filter pool, so `next()` calling the
next filter never re-enters the same VM. As a result, module-level JS state
is per-VM, which is why `kv` exists for shared state.

The CPU watchdog interrupts a VM after its budget (default 2s), with the
timer paused during host calls, so a slow upstream or a pending approval
doesn't count against the filter. An interrupted VM is thrown away.

The chain fails closed: a throw, a timeout, a panic, a missing return value
or a rule evaluation error all deny the request, attributed to the filter
responsible.

## Request model

`chain.Request` is transport-independent. HTTP and SSH both produce one, and
the same filters and rules evaluate both: `req.git` is identical for git over
HTTPS and over SSH. Bodies are `chain.Body`, a buffer that supports peeking:
bytes read for inspection are kept and replayed when the request is
forwarded. Git push parsing uses a non-consuming reader over that buffer, so
a filter can read the full command list (not just the first N bytes) without
disturbing the packfile.

Rules match the *decoded* path, but first every intercepted request goes
through `CheckPath`, which rejects encodings whose meaning could differ
between bouncer and the upstream: dot segments (literal or `%2e`), empty
segments, backslashes and NULs. GitLab's `%2F`-encoded project IDs are why
matchers that care about segment boundaries (`gitlab_project`) work on the
raw path instead.

## Credentials

The credential is injected after the chain allows the request, in Go, so
filters never see secrets.

Placeholder replacement is limited to authentication headers. Replacing
placeholders in arbitrary headers or the query string would let an agent
smuggle a placeholder into a field the API stores and echoes back (an issue
title, say) and read the real secret out of the response.

Sources are keyring (go-keyring: Keychain, Credential Manager, Secret
Service), `bitwarden` (sync a vault and unlock it for the life of the
process; see `internal/creds/bitwarden`), `provided` (`bouncer serve
--creds-from`, which can also override any other source), `command` (the
escape hatch for any password manager CLI), `env`, `file` and `ssh-agent`.
Concurrent fetches
of one credential are serialized, so an interactive unlock prompt appears
once. Bitwarden accounts are unlocked up front, when the daemon loads
config, so the prompt does not race the approval prompt.

## Transports

**HTTP(S)**: standard forward proxy. Hosts that match a service get
`CONNECT`-and-terminate with a leaf cert minted by the local CA; other hosts
are spliced through untouched, or refused under `unmatched: deny`, except
those in the `tunnel:` list.
* The CONNECT target is authoritative: a mismatched `Host` header gets a
  421, which prevents domain fronting onto a credentialed service.
* Upstream `Accept-Encoding` is dropped so Go negotiates and transparently
  decodes compression, which means response filters always see plain bodies.
* Denied git pushes are answered with a real receive-pack status report, so
  git prints `! [remote rejected] main -> main (reason)` instead of
  `RPC failed; HTTP 403`.
* The reverse-proxy mode (`/s/<token>/<host>/...`) is the escape hatch for
  tools that can't use a proxy.

**SSH**: bouncer must *terminate* SSH, not relay it, or it couldn't see
requests or inject keys. `bouncer ssh-connect` is the `ProxyCommand`; it
sends a one-line preamble (session token, target host, port, user) and then
the raw SSH stream.
* Upstream connection, authentication and host-key verification
  (known_hosts or a pinned key) all happen before the agent's handshake, so
  failures reach the agent as plain error text.
* The agent verifies bouncer through a host certificate signed by bouncer's
  SSH CA, trusted via `@cert-authority` in a generated known_hosts file.
* For pushes, the upstream channel opens *before* the decision: the agent
  only sends ref updates after it sees the upstream's ref advertisement.
  Filters then read the commands, and a denied push never reaches upstream.
* Agent forwarding and remote port forwarding are always refused. Local
  forwards need `forward` in the service's allow list.

## Sessions, control and approvals

A session maps an unguessable token to a profile. The token rides in the
proxy URL's userinfo (HTTP) and `BOUNCER_SESSION` (SSH).
* Sessions persist across daemon restarts so running agents keep working,
  and `bouncer exec` revokes its session when the child exits.
* The CLI finds the daemon through `state/daemon.json`, and session creation
  returns everything needed to build the environment, so `bouncer exec`
  works even while the config is mid-edit.
* The control API sits on the proxy port under `/_bouncer/` and requires the
  admin token in the state directory.

Approvals are queued in the daemon, then prompted in the `serve` terminal,
via desktop notification, or answered through the CLI. Identical concurrent
asks from one session share a single prompt (git makes several requests per
push), and "for this session" decisions are remembered per session and key.

## Testing strategy

* Package tests cover the parsers and the pieces that are easy to get
  subtly wrong: pkt-lines, push certificates, GraphQL fragments, path
  canonicalization, matchers, VM concurrency and timeouts.
* End-to-end tests run a real TLS client through the proxy to an `httptest`
  upstream, and a real SSH client through `sshproxy` to an in-process SSH
  server.
* Every example filter and the example config ship with `*.test.yaml`
  specs, which `go test` runs.

## Not done yet / next steps

* Sandboxing filters (QuickJS-in-WASM via wazero) for untrusted rule packs.
* Remote port forwarding (`-R`) over SSH.
* `github_repo` `subpaths`, and resolving GitHub's numeric `/repositories/:id`.
* Presets for known agents (e.g. writing a Claude Code sandbox config that
  allows only the bouncer ports and denies reading the state directory).
* HTTP/2 between the agent and bouncer.
* End-to-end runs on Linux and Windows.
