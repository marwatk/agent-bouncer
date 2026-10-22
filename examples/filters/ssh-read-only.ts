// Over SSH, allow git fetch/clone/archive but not push, and nothing else
// (no shells, no arbitrary commands).
import { defineFilter, deny } from "bouncer";

export default defineFilter({
  onSSH(req, next) {
    if (req.ssh.kind !== "git" || !req.git) {
      return deny(`only git fetch is allowed over ssh to ${req.host}`);
    }
    if (req.git.service === "receive-pack") {
      return deny(`pushing to ${req.git.repo} over ssh is not allowed`);
    }
    return next(req);
  },
});
