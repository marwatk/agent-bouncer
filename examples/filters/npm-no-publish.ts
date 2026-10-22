// Let the agent install packages but never publish, unpublish, deprecate or
// change dist-tags. Attach to a credential-less service for the registry so
// the traffic is intercepted:
//
//   - name: npm
//     hosts: [registry.npmjs.org]
//     filters: [filters/npm-no-publish.ts]
import { defineFilter, deny } from "bouncer";

export default defineFilter({
  onRequest(req, next) {
    // npm publish/deprecate/unpublish/dist-tag/owner/access are all PUT or DELETE.
    if (req.method === "PUT" || req.method === "DELETE") {
      return deny(`npm registry writes are not allowed (${req.method} ${req.path})`);
    }
    // Logins and token creation would mint new credentials the bouncer doesn't control.
    if (req.method === "POST" && /^\/-\/(v1\/login|npm\/v1\/tokens)/.test(req.path)) {
      return deny("npm login/token creation is not allowed");
    }
    return next(req);
  },
});
