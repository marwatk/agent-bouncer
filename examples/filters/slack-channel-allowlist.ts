// Only let the agent post to specific Slack channels. Slack's Web API
// accepts both JSON and form-encoded bodies, so both are parsed.
//
// config:
//   channels: channel IDs or names the agent may post to
//   methods:  Web API methods that post messages (default below)
import { defineFilter, deny, type HttpRequest } from "bouncer";

interface Config {
  channels: string[];
  methods?: string[];
}

const POSTING = ["chat.postMessage", "chat.postEphemeral", "chat.scheduleMessage", "chat.update", "chat.meMessage", "files.completeUploadExternal"];

const CHANNEL_KEYS = ["channel", "channel_id", "channels"];

// channelOf returns the target channel, or throws if the request names it
// more than once (query and body, duplicate keys): which one Slack would use
// is its parser's business, so ambiguity is refused rather than guessed.
async function channelOf(req: HttpRequest): Promise<string | null> {
  const found: string[] = [];
  for (const k of CHANNEL_KEYS) found.push(...req.query.getAll(k));
  const type = (req.headers.get("content-type") ?? "").split(";")[0].trim();
  const text = await req.body.text();
  if (type === "application/json") {
    // JSON.parse keeps the last duplicate key; count keys in the raw text.
    const keys = text.match(/"channel(_id|s)?"\s*:/g) ?? [];
    if (keys.length > 1) throw new Error("channel given more than once");
    const body = JSON.parse(text || "{}");
    for (const k of CHANNEL_KEYS) if (body[k] !== undefined) found.push(String(body[k]));
  } else if (text) {
    for (const pair of text.split("&")) {
      const [k, v = ""] = pair.split("=");
      if (CHANNEL_KEYS.includes(decodeURIComponent(k))) found.push(decodeURIComponent(v.replace(/\+/g, " ")));
    }
  }
  if (found.length > 1) throw new Error("channel given more than once");
  return found[0] ?? null;
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    const method = req.path.replace(/^\/api\//, "");
    if (!(ctx.config.methods ?? POSTING).includes(method)) return next(req);
    let channel;
    try {
      channel = await channelOf(req);
    } catch (e) {
      return deny(`${method}: ${(e as Error).message}`);
    }
    if (!channel) return deny(`${method} without a channel`);
    // files.completeUploadExternal takes a comma-separated list.
    const targets = String(channel).split(",").map((c) => c.trim());
    const bad = targets.filter((c) => !ctx.config.channels.includes(c));
    if (bad.length) return deny(`posting to ${bad.join(", ")} is not allowed; allowed: ${ctx.config.channels.join(", ")}`);
    return next(req);
  },
});
