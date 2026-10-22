// Block dangerous GitHub GraphQL mutations. Fragments are expanded by
// req.graphql(), so a mutation can't hide inside a fragment spread.
// Unparseable or persisted (hash-only) queries are denied: we can't vet them.
//
// config:
//   deny:   mutation fields to block (default: a destructive set below)
//   onlyQueries: if true, block every mutation and subscription
import { defineFilter, deny } from "bouncer";

const DEFAULT_DENY = [
  "deleteRepository",
  "archiveRepository",
  "transferRepository",
  "updateRepository",
  "mergePullRequest",
  "deleteRef",
  "updateRef",
  "updateBranchProtectionRule",
  "deleteBranchProtectionRule",
  "createDeployment",
  "addCollaborator",
];

interface Config {
  deny?: string[];
  onlyQueries?: boolean;
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    // github.com serves /graphql; GitHub Enterprise Server serves /api/graphql.
    if (!/^(\/api)?\/graphql\/*$/.test(req.path)) return next(req);
    let ops;
    try {
      ops = await req.graphql();
    } catch (e) {
      return deny(`cannot inspect GraphQL request: ${e}`);
    }
    const blocked = new Set(ctx.config.deny ?? DEFAULT_DENY);
    for (const op of ops ?? []) {
      if (op.type === "query") continue;
      if (ctx.config.onlyQueries) return deny(`GraphQL ${op.type} ${op.name || "(anonymous)"} is not allowed`);
      const bad = op.fields.filter((f) => blocked.has(f));
      if (bad.length) return deny(`GraphQL mutation ${bad.join(", ")} is not allowed`);
    }
    return next(req);
  },
});
