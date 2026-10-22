// The literal version of "if the first 100 bytes look like a git push to a
// branch named 'foo', block it", using raw body access.
//
// This is here to show req.body.peek(); prefer git-protect-branches.ts for
// real use. A push that updates several refs can put 'foo' well past byte
// 100, and a crafted ref like refs/heads/foobar would need care. The
// req.git.refUpdates() helper parses the whole command list properly.
import { defineFilter, deny } from "bouncer";

export default defineFilter({
  async onRequest(req, next) {
    const isPush =
      req.method === "POST" &&
      req.path.endsWith("/git-receive-pack") &&
      req.headers.get("content-type") === "application/x-git-receive-pack-request";
    if (isPush) {
      // "First 100 bytes" is just short: the 4-byte pkt-line length, two
      // 40-char object IDs, two spaces and "refs/heads/foo" add up to
      // exactly 100, so the terminator that distinguishes foo from foobar
      // is byte 101. Peek a little further.
      const head = await req.body.peekText(128);
      // Each command is "<old-oid> <new-oid> <ref>" followed by NUL (first
      // command, before capabilities) or newline.
      if (/ refs\/heads\/foo[\0\n]/.test(head)) {
        return deny("pushes to 'foo' are blocked");
      }
    }
    return next(req);
  },
});
