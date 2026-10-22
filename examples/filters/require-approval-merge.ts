// Ask the human before the agent merges anything: GitLab merge requests,
// GitHub pull requests (REST and GraphQL). Approving with "allow for
// session" covers later merges of the same MR/PR only.
import { defineFilter, deny, ask, type HttpRequest } from "bouncer";

async function mergeTarget(req: HttpRequest): Promise<string | null> {
  // GitLab: PUT /api/v4/projects/:id/merge_requests/:iid/merge
  let m = req.method === "PUT" && req.rawPath.match(/^\/api\/v4\/projects\/([^/]+)\/merge_requests\/(\d+)\/merge$/);
  if (m) return `GitLab MR !${m[2]} in ${decodeURIComponent(m[1])}`;
  // GitHub: PUT /repos/:owner/:repo/pulls/:n/merge
  m = req.method === "PUT" && req.path.match(/^\/repos\/([^/]+\/[^/]+)\/pulls\/(\d+)\/merge$/);
  if (m) return `GitHub PR #${m[2]} in ${m[1]}`;
  // GitHub GraphQL
  if (req.path === "/graphql") {
    const ops = await req.graphql();
    if (ops?.some((op) => op.type === "mutation" && op.fields.includes("mergePullRequest"))) {
      return "a GitHub pull request (GraphQL mergePullRequest)";
    }
  }
  return null;
}

export default defineFilter({
  async onRequest(req, next) {
    const target = await mergeTarget(req);
    if (target && !(await ask(`Agent wants to merge ${target}. Allow?`, { key: `merge:${req.describe()}` }))) {
      return deny(`merging ${target} was not approved`);
    }
    return next(req);
  },
});
