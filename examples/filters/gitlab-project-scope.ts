// Code version of the declarative `gitlab_project` rule: allow only the
// listed projects (REST API and git), plus a few account endpoints tools
// need. Everything else on the host is denied.
//
// The declarative rule in config.yaml is shorter; this shows how to do it
// by hand, and is a starting point when you need logic rules can't express.
//
// config:
//   projects: ["group/project", ...]       (paths, case-insensitive)
//   ids:      {"group/project": 1234}      (numeric IDs, if tools use them)
//   allow:    ["GET /api/v4/user", ...]    (extra "METHOD /path" endpoints)
import { defineFilter, deny } from "bouncer";

interface Config {
  projects: string[];
  ids?: Record<string, number>;
  allow?: string[];
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    const projects = new Set(ctx.config.projects.map((p) => p.toLowerCase()));
    const ids = new Set(Object.values(ctx.config.ids ?? {}).map(String));

    // git over HTTPS: the helper extracts the repo path.
    if (req.git) {
      return projects.has(req.git.repo.toLowerCase()) ? next(req) : deny(`repository ${req.git.repo} is out of scope`);
    }

    // REST API: /api/v4/projects/:id where :id is numeric or a URL-encoded
    // path. Use rawPath: in the decoded path, "group%2Fproj" and
    // "group/proj" look the same and the segment boundaries are lost.
    const segs = req.rawPath.split("/");
    if (segs[1] === "api" && segs[2] === "v4" && segs[3] === "projects" && segs[4]) {
      const id = decodeURIComponent(segs[4]).toLowerCase();
      if (projects.has(id) || ids.has(id)) return next(req);
      return deny(`project ${id} is out of scope`);
    }

    const endpoint = `${req.method} ${req.path}`;
    if ((ctx.config.allow ?? []).includes(endpoint)) return next(req);
    return deny(`${endpoint} is not allowed; only projects ${[...projects].join(", ")} are in scope`);
  },
});
