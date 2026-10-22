# agent-bouncer

A credential broker for AI agents with policy you can program.

Agents never hold your tokens or keys. They talk to services through
`bouncer`, which checks every request against your rules and filters and
injects the real credential only when the request is allowed. Filters are
TypeScript files loaded at runtime, so you can add a rule like "block any git
push to `main`" or "this GitLab token may only touch one project" without
recompiling anything.

Inspired by [Infisical's agent-vault](https://github.com/Infisical/agent-vault),
with servlet-filter-style extensibility, SSH support and human-in-the-loop approvals.

```
 agent ──HTTPS_PROXY──▶ bouncer ──(filters → rules → inject credential)──▶ gitlab.com
   │                       │
   └──ssh (ProxyCommand)──▶│──(filters → rules → your SSH key)──────────▶ git@gitlab.com
                           │
                           └──▶ hosts with no service: tunneled untouched, or denied
```

## Quick start

```sh
go install github.com/marwatk/agent-bouncer/cmd/bouncer@latest   # or: go build ./cmd/bouncer

bouncer init                 # writes config.yaml + example filters, prints where; edit it
bouncer cred set gitlab      # store a secret in the OS keyring
bouncer serve                # run the daemon; keep this terminal for approvals
bouncer ca install           # once: trust the CA for tools using the OS trust store

bouncer exec -- claude       # run an agent through the bouncer
```

`bouncer test` runs the example policy tests; `bouncer check` validates the
config and compiles every filter.

## How it works

* **HTTP(S).** Agents use bouncer as their proxy. For hosts that match a
  configured *service*, bouncer terminates TLS with a certificate from its
  local CA and runs the request through the service's chain:
  profile filters, then service filters, then declarative rules. If the
  chain allows the request, bouncer injects the credential and forwards it.
  Hosts with no service are tunneled untouched by default, or refused when
  the profile sets `unmatched: deny`.
* **SSH.** `ssh` (and git over SSH) reaches bouncer through a generated
  `ssh_config` whose `ProxyCommand` is `bouncer ssh-connect`. bouncer
  terminates the agent's SSH session with a host certificate from its SSH CA
  and checks each channel request (git, exec, shell, sftp, port forward).
  Allowed requests run on an upstream connection that bouncer opens with
  your real key. Agent forwarding is always refused.
* **Sessions.** Each `bouncer exec` (or `bouncer env`) registers a session
  tied to a *profile*. The session token travels in the proxy URL and in
  `BOUNCER_SESSION`, so different agents can run under different policies at once.
* **Fail closed.** If a filter throws, times out or returns nothing, the
  request is denied. The same goes for rule evaluation errors and unparseable
  GraphQL or push data. Every decision is appended to `state/audit.jsonl`.

## Routing agents

| Situation | Use |
|---|---|
| You launch the agent | `bouncer exec [--profile p] [--label l] -- <command>`: sets everything below, then revokes the session on exit |
| The agent is launched some other way | `eval "$(bouncer env)"` (`--shell fish\|powershell\|cmd` too), then start it from that shell; the session expires after `--ttl` (default 24h) |
| The tool ignores proxy variables | Point its base URL at `$BOUNCER_BASE/<host>`, e.g. `$BOUNCER_BASE/gitlab.com/api/v4` (reverse-proxy mode; configured services only) |
| The tool can't send proxy credentials | Set `anonymous_profile:`; any local client without a token gets that profile |
| Your own ssh config is in play | `Include` the generated `state/ssh/config`, or use `GIT_SSH_COMMAND` from `bouncer env` |

What `bouncer env` sets:

* `HTTPS_PROXY` and friends, with the session token.
* `NODE_USE_ENV_PROXY=1` (Node 24+).
* CA variables:
  * `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` point at a bundle of system roots plus the bouncer CA. These variables *replace* the trust store, so the bundle keeps tunneled hosts working.
  * `NODE_EXTRA_CA_CERTS` points at just the bouncer CA, because it *appends*.
* SSH routing: `GIT_SSH_COMMAND`, and an `ssh` shim prepended to `PATH`.
* Placeholder tokens for each credential's `export_env`, so CLIs like `glab` and `gh` think they're logged in.

Go programs on macOS and Windows (including `gh` and `glab`) only trust the
OS store, so run `bouncer ca install` once.

**Known agents.** Nothing here is agent-specific: anything that honors
proxy variables works. For Claude Code, `bouncer exec -- claude` is enough.
Put `api.anthropic.com` in `tunnel:` for profiles with `unmatched: deny`.

## Credentials

```yaml
credentials:
  gitlab:   {source: keyring, export_env: [GITLAB_TOKEN]}      # bouncer cred set gitlab
  github:   {source: command, command: [bw, get, password, gh-agent], cache: 15m}
  onepass:  {source: command, command: [op, read, "op://dev/gitlab/token"]}
  ci:       {source: env, env: CI_TOKEN}                        # the daemon's environment
  sandbox:  {source: file, path: ~/.ssh/id_ed25519_sandbox}     # SSH keys must be unencrypted...
  gitlab-ssh: {source: ssh-agent, fingerprint: "SHA256:..."}    # ...or come from your ssh-agent
```

The `command` source is the escape hatch: anything that prints the secret on
stdout works (Bitwarden, 1Password, `pass`, `security find-generic-password -w`,
`vault kv get -field=...`). Secrets are cached per `cache` (default 5m).
`bouncer cred test NAME` fetches a credential without printing it.

**Bulk, at startup (containers, CI, no keyring):**

```sh
bouncer serve --creds-from <(gen_creds.sh)     # or a file, or - for stdin
```

```bash
#!/bin/bash
# gen_creds.sh: one "name: value" per line; the value is taken verbatim.
printf 'gitlab: %s\n' "$(rbw get gitlab)"
printf 'github: %s\n' "$(rbw get github)"
printf 'deploy-key:: %s\n' "$(base64 < ~/.ssh/deploy_key | tr -d '\n')"   # "::" = base64, for multi-line values
```

Values are read once and kept only in memory. They override any configured
source, so one config can use the keyring on your laptop and injected values
in a container. Mark a credential `source: provided` to require it from
`--creds-from`. Startup fails on an unknown name, a duplicate, a missing
`provided` value, or input that looks like a missing `\n`.

**Injection.** `inject:` sets `bearer: true`, `basic: {username}`,
`header` + `value` (with `{{secret}}`), or `query: param`. `inject.git`
overrides this for git smart-HTTP, which usually needs Basic auth even when
the API takes a token header. Credentials are never sent over plain HTTP
unless the service sets `insecure: true` (for local development only).

Bouncer also swaps the credential's placeholder (`bouncer-placeholder-<name>`)
for the real secret, so tools that must send a token themselves keep
working. The swap happens only in `Authorization` (Basic included),
`Private-Token`, `inject.header` and headers listed in
`inject.placeholder_headers`. That restriction is deliberate: an API that
stores and echoes back other fields (an issue title, say) would otherwise
hand the secret to the agent.

## Policy

```yaml
profiles:
  default:
    unmatched: tunnel            # or deny
    tunnel: [api.anthropic.com]  # passed through even when unmatched: deny
    allow_private: false         # tunnels may not reach loopback/LAN/metadata (default)
    filters: [filters/redact-response.ts]   # every intercepted request in this profile
    services:
      - name: gitlab
        hosts: [gitlab.com]                 # exact or *.wildcard; no port means :443
        credential: gitlab
        inject: {header: PRIVATE-TOKEN, git: {basic: {username: oauth2}}}
        filters:
          - path: filters/git-protect-branches.ts
            config: {branches: [main, "release/*"]}
        rules:                              # first match wins
          - action: deny
            gitlab_project: {path: mygroup/myproject, subpaths: ["variables/**", "members/**"]}
          - action: allow
            gitlab_project: mygroup/myproject
        # default: deny when rules exist, allow otherwise
    ssh:
      - name: sandbox
        hosts: [sandbox.dev.internal]
        user: agent
        credential: sandbox
        allow: [shell, exec, sftp]          # git (default), exec, shell, sftp, forward
        rules:
          - action: ask
            prompt: "Let the agent into the sandbox? Once in, it can do anything there."
  locked-down:
    extends: default                        # inherits filters, services, ssh
    unmatched: deny
```

A rule's matchers are ANDed together:

| Matcher | Matches |
|---|---|
| `methods: [GET, HEAD]` | HTTP method |
| `path: /api/v4/user`, `path_regex:` | decoded path; in globs `*` is one segment, `**` is any |
| `gitlab_project: group/proj` or `{path, id, subpaths}` | GitLab REST (by path, or by numeric ID, resolved automatically) and git over HTTPS/SSH |
| `github_repo: owner/repo` | GitHub REST (`/repos/...`, including GHES `/api/v3`) and git |
| `git: {service, refs, updates}` | git service (`receive-pack` = push), ref globs, `create`/`update`/`delete` |
| `graphql: {operations, fields}` | GraphQL operation type and top-level fields (fragments expanded); combine with `path` |
| `ssh: {kinds, command}` | SSH channel kind and exec command regex |

Actions are `allow`, `deny` and `ask`. Before any rules run, bouncer rejects
requests whose meaning could differ between it and the upstream:
* paths with dot segments (literal or encoded), empty segments, backslashes or NULs
* methods that aren't upper-case
* method overrides (`X-HTTP-Method-Override` and similar headers, `_method`
  query or form fields). Checking form bodies means POSTed forms are buffered,
  up to 16 MiB.

## Writing filters

A filter is a TypeScript or JavaScript module. Imports of other relative
files and of pure-JS npm packages get bundled automatically.

```ts
import { defineFilter, deny, ask } from "bouncer";

export default defineFilter<{ branches: string[] }>({
  async onRequest(req, next, ctx) {
    if (req.git?.service === "receive-pack") {
      for (const u of await req.git.refUpdates()) {
        if (ctx.config.branches.includes(u.ref.replace("refs/heads/", ""))) {
          return deny(`pushes to ${u.ref} are blocked`);
        }
      }
    }
    const res = await next(req);           // the rest of the chain, then upstream
    res.headers.set("X-Checked-By", ctx.name);
    return res;
  },
  async onSSH(req, next) { /* same idea: req.ssh, req.git */ return next(req); },
});
```

| API | |
|---|---|
| `req.method/url/path/rawPath/query/headers/host/service/session` | request basics; mutate `headers` in place |
| `req.body.peek(n)`, `peekText(n)`, `text()`, `json()`, `bytes()`, `set()` | inspect without consuming (buffering is capped at 16 MiB) |
| `req.git.service/repo`, `await req.git.refUpdates()` | parsed git protocol, the same over HTTP and SSH |
| `await req.graphql()` | operations with top-level fields, fragments expanded |
| `next(req)` → `Response` with `status`, `setStatus`, `headers`, `body`, `denied` | servlet-style continuation; post-process the response |
| `onResponse(res, req, ctx)` | response-only hook; return nothing to keep the response |
| `deny(reason, {status})`, `respond(status, body, headers)` | short-circuit |
| `await ask(prompt, {key})` | human approval; `key` groups "allow for this session" |
| `kv.get/set/incr/delete/keys` with `{ttl}` | persistent, per-filter state |
| `log(msg, fields)`, `console.log` | goes to the `bouncer serve` output |

Full types are in [`types/bouncer.d.ts`](types/bouncer.d.ts). `bouncer init`
copies them next to your filters with a `tsconfig.json`, so editors get
completion. Each filter gets a 2s CPU budget per request (`timeout:`
overrides it); time spent waiting in `next()`, `ask()` or body reads doesn't count.

**Examples** live in [`examples/filters/`](examples/filters):

* `git-protect-branches`: protected branches over HTTPS and SSH.
* `first-100-bytes`: the literal raw-bytes version, and why the parsed helper is better.
* `gitlab-project-scope`: project scoping written as code.
* `github-graphql-guard`: blocks dangerous GraphQL mutations.
* `read-only`: allows reads only.
* `npm-no-publish`: allows installs but never publishing.
* `slack-channel-allowlist`: posting only to listed channels.
* `push-rate-limit`: kv state plus `ask`.
* `redact-response`: scrubs secrets from responses.
* `ssh-read-only`: git fetch only over SSH.
* `require-approval-merge`: asks before merging.

### Testing policy

Each `*.test.yaml` spec targets either one filter or a profile of a config,
against a mocked upstream:

```yaml
filter: git-protect-branches.ts          # or: config: config.yaml + profile: default
filter_config: {branches: [main]}
cases:
  - name: push to main is blocked
    request:
      method: POST
      url: https://gitlab.com/group/proj.git/git-receive-pack
      git_push: [{ref: refs/heads/main}]  # synthesizes a receive-pack body
    expect: deny
    expect_reason: protected branch
  - name: over ssh too
    ssh: {host: gitlab.com, user: git, command: "git-receive-pack 'group/proj.git'", git_push: [{ref: refs/heads/main}]}
    expect: deny
```

Cases can also set `upstream:` (a mocked response), `approve:` (the answer
to `ask`), `expect_status`, `expect_body_contains`/`excludes` and
`expect_asked`. Cases in one file share kv state. Run them with
`bouncer test [paths...]`; `go test ./...` runs the shipped examples.

## Approvals

`ask` rules and filters pause the request until a human answers. The
`bouncer serve` terminal prompts with `[y]` allow once, `[s]` allow for the
session, `[n]` deny, or `[d]` deny for the session. A desktop notification
fires too. From another terminal, use `bouncer approvals` and
`bouncer approve|deny <id> [--session]`. Unanswered asks are denied after
`approvals.timeout` (default 2m). Concurrent identical asks from one session
share a single prompt; different requests always get their own. "For the
session" covers identical requests only, unless a filter passes an explicit
`key` to `ask()` to group related requests on purpose.

## Threat model and limits

Read this before relying on bouncer.

* **The agent must be confined.** bouncer only sees traffic sent to it.
  An agent that can open direct connections (ignoring `HTTPS_PROXY`, or
  using hosts in `NO_PROXY`) or read your files bypasses it. Run the agent in
  a sandbox whose network allows only the bouncer ports, and that can't read
  your keyring, SSH keys or bouncer's state directory. Claude Code's sandbox,
  a container or a VM all work. The admin token in `state/admin-token`
  controls sessions and approvals; set `approvals.cli: false` if the agent
  might reach that file.
* **Tunnels only reach public addresses.** Unmatched traffic can't reach
  loopback, private, link-local (including cloud metadata), CGNAT or
  multicast addresses. The check runs on the resolved IP, so DNS tricks
  don't get around it. Set `allow_private: true` on a profile to lift it.
  Configured services are unaffected.
* **Filters are trusted code.** They run in-process with no sandbox, by
  design for v1. Only load filters you'd run yourself.
* **Scoping has edges.** GraphQL can't be scoped by URL; allowing it opens
  everything the token can reach (the GraphQL guard limits *what*, not
  *where*). `gitlab_project` scopes *which* project; use `subpaths` rules to
  limit what the agent may do inside it. Push rejection only sees ref names,
  not history, so it can't tell a force push from a normal one.
* **The CA can impersonate any site.** `bouncer ca install` makes the
  bouncer CA a trusted root for your user (browsers included), and its key
  sits in the state directory. Treat that directory like your SSH keys:
  keep it out of backups you don't trust and away from the agent. On
  Windows, Unix file modes don't apply, so check its ACLs. If the key leaks,
  delete `ca.pem`/`ca-key.pem`, restart, and reinstall. The SSH CA is only
  trusted for the configured SSH hosts.
* **Interception is HTTP/1.1 to the client.** Upstream connections use
  HTTP/2 where available. Apps that pin certificates won't work through
  interception; tunnel them or leave them out.
* **Platforms.** Developed and exercised end to end on macOS: real git, ssh,
  curl, Python and Node through the daemon. Linux and Windows builds compile
  and pass `go vet`, but haven't been exercised end to end yet. The Windows
  paths most likely to need fixes are the ssh shim (`ssh.cmd`), the
  `ProxyCommand` quoting and the PowerShell env output.

## Layout

```
cmd/bouncer/        CLI
internal/chain      request model, filter chain, declarative rules, matchers
internal/jsfilter   goja + esbuild runtime for TS/JS filters
internal/proxy      HTTP(S) proxy, TLS interception, credential injection
internal/sshproxy   SSH termination and re-origination
internal/daemon     wiring, sessions, control API, hot reload, approvals prompt
internal/...        config, ca, creds, gitproto, gql, approval, kv, audit, envexport, testrunner
types/bouncer.d.ts  filter API types
examples/           config, filters, and their tests
docs/DESIGN.md      decisions and rationale
```
