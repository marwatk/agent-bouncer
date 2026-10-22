// Allow only safe (read) methods. Attach to services the agent should be
// able to look at but never change, e.g. Jira or Confluence.
//
// config:
//   methods: allowed methods (default: GET, HEAD, OPTIONS)
//   except:  ["METHOD /path/glob*", ...] writes that are allowed anyway
//            (a trailing * matches any suffix)
//   gitFetch: allow git clone/fetch, which use POST (default: true)
import { defineFilter, deny } from "bouncer";

interface Config {
  methods?: string[];
  except?: string[];
  gitFetch?: boolean;
}

export default defineFilter<Config>({
  onRequest(req, next, ctx) {
    const methods = ctx.config.methods ?? ["GET", "HEAD", "OPTIONS"];
    if (methods.includes(req.method)) return next(req);
    if ((ctx.config.gitFetch ?? true) && req.git?.service === "upload-pack") return next(req);
    const endpoint = `${req.method} ${req.path}`;
    for (const e of ctx.config.except ?? []) {
      if (e.endsWith("*") ? endpoint.startsWith(e.slice(0, -1)) : endpoint === e) return next(req);
    }
    return deny(`${req.host} is read-only (${req.method} not allowed)`, { status: 405 });
  },
});
