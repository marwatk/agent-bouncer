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

async function channelOf(req: HttpRequest): Promise<string | null> {
  const fromQuery = req.query.get("channel") ?? req.query.get("channel_id");
  if (fromQuery) return fromQuery;
  const type = (req.headers.get("content-type") ?? "").split(";")[0].trim();
  const text = await req.body.text();
  if (type === "application/json") {
    const body = JSON.parse(text || "{}");
    return body.channel ?? body.channel_id ?? body.channels ?? null;
  }
  for (const pair of text.split("&")) {
    const [k, v = ""] = pair.split("=");
    if (k === "channel" || k === "channel_id" || k === "channels") {
      return decodeURIComponent(v.replace(/\+/g, " "));
    }
  }
  return null;
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    const method = req.path.replace(/^\/api\//, "");
    if (!(ctx.config.methods ?? POSTING).includes(method)) return next(req);
    const channel = await channelOf(req);
    if (!channel) return deny(`${method} without a channel`);
    // files.completeUploadExternal takes a comma-separated list.
    const targets = String(channel).split(",").map((c) => c.trim());
    const bad = targets.filter((c) => !ctx.config.channels.includes(c));
    if (bad.length) return deny(`posting to ${bad.join(", ")} is not allowed; allowed: ${ctx.config.channels.join(", ")}`);
    return next(req);
  },
});
