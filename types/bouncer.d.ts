// Type definitions for agent-bouncer filters.
//
// Filters are TypeScript (or JavaScript) modules that default-export
// `defineFilter({...})`. They run inside the bouncer daemon; host calls such
// as `next()`, `ask()` and body reads block the filter, not the daemon, so
// `await` behaves exactly as you'd expect.

declare module "bouncer" {
  export interface Session {
    id: string;
    label: string;
    profile: string;
  }

  export interface Headers {
    /** All values joined with ", ", or null if absent. Case-insensitive. */
    get(name: string): string | null;
    getAll(name: string): string[];
    has(name: string): boolean;
    set(name: string, value: string): void;
    append(name: string, value: string): void;
    delete(name: string): void;
    /** [lowercased name, value] pairs. */
    entries(): [string, string][];
  }

  export interface Body {
    /** Up to the first n bytes, without consuming the body. */
    peek(n: number): Promise<Uint8Array>;
    /** Like peek, decoded as UTF-8 (invalid sequences become U+FFFD). */
    peekText(n: number): Promise<string>;
    /** The whole body (buffered; limited to 16 MiB). */
    bytes(): Promise<Uint8Array>;
    text(): Promise<string>;
    json(): Promise<any>;
    /** Replace the body. Objects are JSON-encoded. */
    set(body: string | Uint8Array | object): void;
  }

  export interface RefUpdate {
    ref: string;
    oldOid: string;
    newOid: string;
    type: "create" | "update" | "delete";
  }

  export interface Push {
    updates: RefUpdate[];
    capabilities: string[];
    pushOptions: string[];
    signed: boolean;
  }

  export interface Git {
    service: "receive-pack" | "upload-pack" | "upload-archive" | "lfs";
    /** Repository path, e.g. "group/sub/project" (no leading slash, no .git). */
    repo: string;
    /** The ref updates in a push; [] for non-push requests and ref advertisements. */
    refUpdates(): Promise<RefUpdate[]>;
    /** The full push command section, or null if this isn't a receive-pack request. */
    push(): Promise<Push | null>;
  }

  export interface GraphQLOperation {
    type: "query" | "mutation" | "subscription";
    name: string;
    /** Top-level field names, with fragments expanded. */
    fields: string[];
  }

  interface BaseRequest {
    host: string;
    /** Name of the matched service (or ssh service) in the config. */
    service: string;
    profile: string;
    session: Session | null;
    /** Non-null for git over HTTP or SSH. */
    git: Git | null;
    /** One-line description, e.g. "POST gitlab.com/api/v4/projects/1/issues". */
    describe(): string;
  }

  export interface HttpRequest extends BaseRequest {
    transport: "http";
    method: string;
    url: string;
    /** Percent-decoded path. */
    path: string;
    /** Path as sent, with percent-encoding intact (e.g. %2F in GitLab project IDs). */
    rawPath: string;
    query: {
      get(name: string): string | null;
      getAll(name: string): string[];
      has(name: string): boolean;
    };
    headers: Headers;
    body: Body;
    /** Operations in a GraphQL request, or null if the request isn't GraphQL. Rejects on parse errors. */
    graphql(): Promise<GraphQLOperation[] | null>;
  }

  export interface SshInfo {
    host: string;
    user: string;
    kind: "git" | "exec" | "shell" | "sftp" | "forward";
    command?: string;
    subsystem?: string;
    /** host:port for port forwards. */
    target?: string;
  }

  export interface SshRequest extends BaseRequest {
    transport: "ssh";
    ssh: SshInfo;
  }

  export interface Response {
    readonly status: number;
    setStatus(status: number): void;
    headers: Headers;
    body: Body;
    /** Set when a later filter or rule denied the request. */
    denied: { by: string; reason: string } | null;
  }

  /** Opaque result of deny() / respond(). */
  export interface Decision {
    readonly __bouncer: "deny" | "respond";
  }

  export type Result = Response | Decision;

  export interface Context<C = Record<string, any>> {
    /** Filter name (its `name` field, or the file name). */
    name: string;
    /** The `config:` block given to this filter in config.yaml. */
    config: C;
  }

  export interface FilterDefinition<C = Record<string, any>> {
    name?: string;
    /** HTTP requests. Call next(req) to continue, or return deny()/respond(). */
    onRequest?(req: HttpRequest, next: (req?: HttpRequest) => Promise<Response>, ctx: Context<C>): Promise<Result> | Result;
    /** HTTP responses, after the rest of the chain. Return nothing to keep the response. */
    onResponse?(res: Response, req: HttpRequest, ctx: Context<C>): Promise<Result | void> | Result | void;
    /** SSH channel requests (exec, shell, sftp, forward). next() continues; deny() refuses. */
    onSSH?(req: SshRequest, next: (req?: SshRequest) => Promise<Response>, ctx: Context<C>): Promise<Result> | Result;
  }

  export function defineFilter<C = Record<string, any>>(def: FilterDefinition<C>): FilterDefinition<C>;

  /** Refuse the request. HTTP clients get `status` (default 403) and the reason as text. */
  export function deny(reason: string, opts?: { status?: number }): Decision;

  /** Answer the request directly without contacting upstream. */
  export function respond(status: number, body?: string | Uint8Array | object, headers?: Record<string, string>): Decision;

  /**
   * Ask the human. Resolves true if approved. Times out (denying) after the
   * configured approval timeout. `key` groups identical decisions so
   * "allow for this session" applies to them; it defaults to the prompt.
   */
  export function ask(prompt: string, opts?: { key?: string; timeout?: string | number }): Promise<boolean>;

  export function log(message: string, fields?: Record<string, any>): void;

  /** Persistent key-value storage, namespaced per filter. TTLs are "1h"-style strings or seconds. */
  export const kv: {
    get<T = any>(key: string): T | undefined;
    set(key: string, value: any, opts?: { ttl?: string | number }): void;
    /** Add `by` (default 1); ttl applies when the key is created. Returns the new value. */
    incr(key: string, opts?: { by?: number; ttl?: string | number }): number;
    delete(key: string): void;
    keys(prefix?: string): string[];
  };
}
