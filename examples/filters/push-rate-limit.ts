// Limit how many git pushes a session can make per time window, then ask
// the human before allowing more. Uses kv for state that survives restarts
// and is shared across concurrent requests.
//
// config:
//   max:    pushes allowed per window without asking (default 10)
//   window: window length (default "1h")
import { defineFilter, deny, ask, kv, type HttpRequest, type SshRequest } from "bouncer";

interface Config {
  max?: number;
  window?: string;
}

async function limit(req: HttpRequest | SshRequest, cfg: Config) {
  if (req.git?.service !== "receive-pack") return null;
  const updates = await req.git.refUpdates();
  if (updates.length === 0) return null; // ref advertisement, not an actual push
  const key = `pushes:${req.session?.id ?? "anonymous"}`;
  const n = kv.incr(key, { ttl: cfg.window ?? "1h" });
  const max = cfg.max ?? 10;
  if (n <= max) return null;
  const ok = await ask(`Agent has pushed ${n} times this ${cfg.window ?? "1h"} (limit ${max}). Allow another push to ${req.git.repo}?`, {
    key: `push-limit:${req.git.repo}`,
  });
  return ok ? null : deny(`push limit of ${max} per ${cfg.window ?? "1h"} reached`, { status: 429 });
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    return (await limit(req, ctx.config)) ?? next(req);
  },
  async onSSH(req, next, ctx) {
    return (await limit(req, ctx.config)) ?? next(req);
  },
});
