// Scrub secrets out of API responses before the agent sees them, e.g. CI
// variables, job logs or issue bodies that contain tokens. Only textual
// responses are touched; binary bodies stream through untouched.
//
// config:
//   patterns: extra regexes (strings) to redact
import { defineFilter } from "bouncer";

const BUILTIN = [
  /glpat-[A-Za-z0-9_\-]{20,}/g, // GitLab personal access tokens
  /gh[pousr]_[A-Za-z0-9]{36,}/g, // GitHub tokens
  /github_pat_[A-Za-z0-9_]{60,}/g,
  /xox[abprs]-[A-Za-z0-9-]{10,}/g, // Slack
  /AKIA[0-9A-Z]{16}/g, // AWS access key IDs
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

const TEXTUAL = /^(text\/|application\/(json|xml|x-ndjson|graphql-response\+json|.*\+json))/;

interface Config {
  patterns?: string[];
}

export default defineFilter<Config>({
  async onResponse(res, req, ctx) {
    const type = res.headers.get("content-type") ?? "";
    if (!TEXTUAL.test(type)) return;
    const patterns = [...BUILTIN, ...(ctx.config.patterns ?? []).map((p) => new RegExp(p, "g"))];
    const original = await res.body.text();
    let redacted = original;
    for (const re of patterns) redacted = redacted.replace(re, "[redacted by agent-bouncer]");
    if (redacted !== original) res.body.set(redacted);
  },
});
