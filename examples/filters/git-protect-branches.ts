// Block pushes to protected branches, over both HTTPS and SSH.
//
// config:
//   branches:     globs of branch names to protect (default: ["main", "master"])
//   allowCreate:  allow creating a protected branch that doesn't exist yet (default: false)
//   blockDeletes: also block deleting ANY branch (default: true)
import { defineFilter, deny, type Git } from "bouncer";

interface Config {
  branches?: string[];
  allowCreate?: boolean;
  blockDeletes?: boolean;
}

// Minimal glob: "*" matches within one path segment.
function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]");
  return new RegExp(`^${escaped}$`);
}

async function check(git: Git | null, cfg: Config) {
  if (git?.service !== "receive-pack") return null;
  const protectedRe = (cfg.branches ?? ["main", "master"]).map(globToRegExp);
  for (const u of await git.refUpdates()) {
    if (u.type === "delete" && (cfg.blockDeletes ?? true)) {
      return deny(`deleting ${u.ref} is not allowed`);
    }
    if (!u.ref.startsWith("refs/heads/")) continue;
    const branch = u.ref.slice("refs/heads/".length);
    if (u.type === "create" && cfg.allowCreate) continue;
    if (protectedRe.some((re) => re.test(branch))) {
      return deny(`pushing to protected branch '${branch}' is not allowed; push a feature branch and open a merge request`);
    }
  }
  return null;
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    return (await check(req.git, ctx.config)) ?? next(req);
  },
  async onSSH(req, next, ctx) {
    return (await check(req.git, ctx.config)) ?? next(req);
  },
});
