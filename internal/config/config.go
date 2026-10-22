// Package config defines bouncer's YAML configuration.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/marwatk/agent-bouncer/internal/paths"
)

const (
	DefaultListen    = "127.0.0.1:8228"
	DefaultSSHListen = "127.0.0.1:8229"
)

// Actions a rule (or a service default) can take.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
	ActionAsk   = "ask"
)

// Unmatched-traffic modes for a profile.
const (
	UnmatchedTunnel = "tunnel"
	UnmatchedDeny   = "deny"
)

// SSH capability kinds.
const (
	SSHKindGit     = "git"
	SSHKindExec    = "exec"
	SSHKindShell   = "shell"
	SSHKindSFTP    = "sftp"
	SSHKindForward = "forward"
)

type Config struct {
	Listen    string `yaml:"listen"`
	SSHListen string `yaml:"ssh_listen"`
	// DefaultProfile is used by `bouncer env`/`bouncer exec` when no --profile is given.
	DefaultProfile string `yaml:"default_profile"`
	// AnonymousProfile, if set, applies to proxy clients that don't present a
	// session token. Empty means such clients are rejected.
	AnonymousProfile string                 `yaml:"anonymous_profile"`
	Approvals        Approvals              `yaml:"approvals"`
	Credentials      map[string]*Credential `yaml:"credentials"`
	Profiles         map[string]*Profile    `yaml:"profiles"`

	// Dir is the directory containing the config file; relative paths resolve against it.
	Dir string `yaml:"-"`
	// Path is the config file that was loaded.
	Path string `yaml:"-"`
}

type Approvals struct {
	// Timeout after which an unanswered ask is denied. Default 2m.
	Timeout Duration `yaml:"timeout"`
	// Notify sends a desktop notification when an approval is pending. Default true.
	Notify *bool `yaml:"notify"`
	// Terminal prompts on the `bouncer serve` terminal when it is interactive. Default true.
	Terminal *bool `yaml:"terminal"`
	// CLI allows answering via `bouncer approve`/`bouncer deny` (control API). Default true.
	CLI *bool `yaml:"cli"`
}

func (a Approvals) NotifyEnabled() bool   { return a.Notify == nil || *a.Notify }
func (a Approvals) TerminalEnabled() bool { return a.Terminal == nil || *a.Terminal }
func (a Approvals) CLIEnabled() bool      { return a.CLI == nil || *a.CLI }
func (a Approvals) TimeoutOrDefault() time.Duration {
	if a.Timeout.D <= 0 {
		return 2 * time.Minute
	}
	return a.Timeout.D
}

// Credential describes where a secret comes from. The agent never sees it;
// it only sees the placeholder.
type Credential struct {
	// Source is one of: keyring, command, env, file, ssh-agent, bitwarden.
	Source string `yaml:"source"`
	// Command (source: command) is an argv run to fetch the secret, e.g.
	// ["bw", "get", "password", "gitlab"]. Stdout, minus trailing newlines, is the secret.
	Command []string `yaml:"command"`
	// Env (source: env) names an environment variable of the bouncer daemon.
	Env string `yaml:"env"`
	// Path (source: file) is a file containing the secret (e.g. an SSH private key).
	Path string `yaml:"path"`
	// Account (source: keyring) overrides the keyring account name (default: credential name).
	Account string `yaml:"account"`
	// Fingerprint (source: ssh-agent) selects a key from the agent by SHA256 fingerprint.
	Fingerprint string `yaml:"fingerprint"`
	// Bitwarden (source: bitwarden) selects an item in a vault. The vault is
	// synced and unlocked once, and stays unlocked for the life of the process.
	Bitwarden *Bitwarden `yaml:"bitwarden"`
	// Cache controls how long a fetched secret is kept in memory. Default 5m; 0s disables.
	Cache *Duration `yaml:"cache"`
	// ExportEnv lists environment variables `bouncer env` sets to this
	// credential's placeholder so agent tooling believes it has a token.
	ExportEnv []string `yaml:"export_env"`

	Name string `yaml:"-"`
}

// Bitwarden selects a field in a Bitwarden vault. Several credentials can
// share one vault; the master password is requested once per email and server.
type Bitwarden struct {
	// Email is the Bitwarden account.
	Email string `yaml:"email"`
	// Server is the vault base URL. Empty means bitwarden.com. A self-hosted
	// server is the URL you open in a browser, for example https://vault.example.com.
	Server string `yaml:"server"`
	// Item is the item's name or id.
	Item string `yaml:"item"`
	// Folder disambiguates items that share a name.
	Folder string `yaml:"folder"`
	// Field is password (default), username, notes, totp, private_key,
	// public_key, fingerprint, or the name of a custom field.
	// totp is the stored secret, not a live code.
	Field string `yaml:"field"`
	// PasswordEnv names an environment variable holding the master password.
	// When empty, `bouncer serve` prompts for it at startup.
	PasswordEnv string `yaml:"password_env"`
}

// Placeholder is the stand-in value the agent uses in place of the secret.
func (c *Credential) Placeholder() string { return Placeholder(c.Name) }

// Placeholder is the stand-in value for the named credential.
func Placeholder(name string) string { return "bouncer-placeholder-" + name }

func (c *Credential) CacheTTL() time.Duration {
	if c.Cache == nil {
		return 5 * time.Minute
	}
	return c.Cache.D
}

type Profile struct {
	// Extends names a parent profile whose filters and services are inherited.
	Extends string `yaml:"extends"`
	// Unmatched controls HTTPS traffic to hosts with no service: tunnel (default) or deny.
	Unmatched string `yaml:"unmatched"`
	// Tunnel lists hosts passed through uninspected even when unmatched is
	// deny (e.g. the agent's own LLM API).
	Tunnel []string `yaml:"tunnel"`
	// Filters run on every intercepted request in this profile, before service filters.
	Filters  []FilterRef   `yaml:"filters"`
	Services []*Service    `yaml:"services"`
	SSH      []*SSHService `yaml:"ssh"`

	Name string `yaml:"-"`
}

// Service is an upstream HTTP(S) API the bouncer intercepts.
type Service struct {
	Name  string   `yaml:"name"`
	Hosts []string `yaml:"hosts"`
	// Credential to inject (optional; a service with no credential is still filtered).
	Credential string  `yaml:"credential"`
	Inject     *Inject `yaml:"inject"`
	// Default action when no rule matches. If omitted: deny when rules exist, allow otherwise.
	Default string      `yaml:"default"`
	Rules   []Rule      `yaml:"rules"`
	Filters []FilterRef `yaml:"filters"`
}

func (s *Service) DefaultAction() string {
	if s.Default != "" {
		return s.Default
	}
	if len(s.Rules) > 0 {
		return ActionDeny
	}
	return ActionAllow
}

// Inject describes how the credential is attached to upstream requests.
// With no inject block, bouncer replaces the credential's placeholder where
// it appears in authentication headers (Authorization, including Basic, and
// headers named like *token*, *key*, *auth*, *secret*).
type Inject struct {
	// Header and Value set a header; "{{secret}}" in Value is replaced. Value defaults to "{{secret}}".
	Header string `yaml:"header"`
	Value  string `yaml:"value"`
	// Bearer sets "Authorization: Bearer <secret>".
	Bearer bool `yaml:"bearer"`
	// Basic sets HTTP Basic auth with the secret as password.
	Basic *BasicInject `yaml:"basic"`
	// Query sets a query parameter to the secret, for APIs that require it.
	Query string `yaml:"query"`
	// Git overrides injection for git smart-HTTP requests, which usually
	// need Basic auth even where the API takes a token header.
	Git *Inject `yaml:"git"`
}

// For returns the inject spec that applies to a request.
func (i *Inject) For(isGit bool) *Inject {
	if i != nil && isGit && i.Git != nil {
		return i.Git
	}
	return i
}

type BasicInject struct {
	Username string `yaml:"username"`
}

// SSHService is an upstream SSH host the bouncer terminates and re-originates.
type SSHService struct {
	Name  string   `yaml:"name"`
	Hosts []string `yaml:"hosts"`
	// User, if set, restricts (and defaults) the upstream username.
	User string `yaml:"user"`
	Port int    `yaml:"port"`
	// Credential must resolve to an SSH private key, or be source: ssh-agent.
	Credential string `yaml:"credential"`
	// Allow lists permitted capabilities: git, exec, shell, sftp, forward. Default [git].
	Allow []string `yaml:"allow"`
	// KnownHosts files used to verify the upstream host key. Default ~/.ssh/known_hosts.
	KnownHosts []string `yaml:"known_hosts"`
	// HostKey optionally pins the upstream host key (authorized_keys format).
	HostKey string      `yaml:"host_key"`
	Default string      `yaml:"default"`
	Rules   []Rule      `yaml:"rules"`
	Filters []FilterRef `yaml:"filters"`
}

func (s *SSHService) DefaultAction() string {
	if s.Default != "" {
		return s.Default
	}
	if len(s.Rules) > 0 {
		return ActionDeny
	}
	return ActionAllow
}

func (s *SSHService) Allows(kind string) bool {
	allow := s.Allow
	if len(allow) == 0 {
		allow = []string{SSHKindGit}
	}
	for _, a := range allow {
		if a == kind {
			return true
		}
	}
	return false
}

// Rule is a declarative policy rule. All present matchers must match; the
// first matching rule decides.
type Rule struct {
	Action string `yaml:"action"`
	Reason string `yaml:"reason"`
	// Prompt is shown for action: ask. Defaults to a description of the request.
	Prompt string `yaml:"prompt"`

	Methods   []string `yaml:"methods"`
	Path      string   `yaml:"path"`       // glob over the decoded path; * = one segment, ** = any
	PathRegex string   `yaml:"path_regex"` // regex over the decoded path

	GitLabProject *ProjectRef  `yaml:"gitlab_project"`
	GitHubRepo    string       `yaml:"github_repo"`
	Git           *GitMatch    `yaml:"git"`
	GraphQL       *GraphQLRule `yaml:"graphql"`
	SSH           *SSHMatch    `yaml:"ssh"`

	PathRegexp *regexp.Regexp `yaml:"-"`
}

// ProjectRef identifies a GitLab project by path and optionally numeric ID.
// It accepts a scalar ("group/project") or a mapping ({path, id, subpaths}).
type ProjectRef struct {
	Path string `yaml:"path"`
	ID   int64  `yaml:"id"`
	// Subpaths restricts the match to REST API endpoints under the project,
	// as globs relative to /api/v4/projects/:id/ ("" is the project itself,
	// "variables/**" its CI variables). Git requests never match a rule
	// with subpaths.
	Subpaths []string `yaml:"subpaths"`
}

func (p *ProjectRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		p.Path = n.Value
		return nil
	}
	type plain ProjectRef
	return n.Decode((*plain)(p))
}

type GitMatch struct {
	// Service is receive-pack (push), upload-pack (fetch), or upload-archive.
	Service string `yaml:"service"`
	// Refs are globs (refs/heads/main, refs/heads/release/*) matched against pushed refs.
	Refs []string `yaml:"refs"`
	// Updates restricts to update kinds: create, update, delete.
	Updates []string `yaml:"updates"`
}

type GraphQLRule struct {
	// Operations restricts to operation types: query, mutation, subscription.
	Operations []string `yaml:"operations"`
	// Fields matches top-level fields (after expanding fragments).
	Fields []string `yaml:"fields"`
}

type SSHMatch struct {
	Kinds   []string `yaml:"kinds"`
	Command string   `yaml:"command"` // regex over the exec command

	CommandRegexp *regexp.Regexp `yaml:"-"`
}

// FilterRef points at a TypeScript/JavaScript filter. It accepts a scalar
// path or a mapping with per-filter config.
type FilterRef struct {
	Path    string         `yaml:"path"`
	Config  map[string]any `yaml:"config"`
	Timeout Duration       `yaml:"timeout"`
}

func (f *FilterRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		f.Path = n.Value
		return nil
	}
	type plain FilterRef
	return n.Decode((*plain)(f))
}

// Duration is a time.Duration that unmarshals from strings like "5m".
type Duration struct{ D time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q: %w", n.Line, n.Value, err)
	}
	d.D = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.D.String(), nil }

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

// Parse parses config YAML. path is used to resolve relative filter paths.
func Parse(data []byte, path string) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	c.Path = path
	c.Dir = filepath.Dir(path)
	if err := c.normalize(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) normalize() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.SSHListen == "" {
		c.SSHListen = DefaultSSHListen
	}
	if c.Credentials == nil {
		c.Credentials = map[string]*Credential{}
	}
	if c.Profiles == nil {
		c.Profiles = map[string]*Profile{}
	}
	for name, cr := range c.Credentials {
		if cr == nil {
			return fmt.Errorf("credential %q: empty", name)
		}
		cr.Name = name
		if cr.Bitwarden != nil && cr.Source != "bitwarden" {
			return fmt.Errorf("credential %q: bitwarden block requires source bitwarden", name)
		}
		switch cr.Source {
		case "keyring", "ssh-agent":
		case "command":
			if len(cr.Command) == 0 {
				return fmt.Errorf("credential %q: source command requires command", name)
			}
		case "env":
			if cr.Env == "" {
				return fmt.Errorf("credential %q: source env requires env", name)
			}
		case "file":
			if cr.Path == "" {
				return fmt.Errorf("credential %q: source file requires path", name)
			}
			cr.Path = paths.Expand(cr.Path, c.Dir)
		case "bitwarden":
			if cr.Bitwarden == nil || strings.TrimSpace(cr.Bitwarden.Email) == "" || strings.TrimSpace(cr.Bitwarden.Item) == "" {
				return fmt.Errorf("credential %q: source bitwarden requires bitwarden.email and bitwarden.item", name)
			}
			if cr.Bitwarden.Field == "" {
				cr.Bitwarden.Field = "password"
			}
		default:
			return fmt.Errorf("credential %q: unknown source %q (want keyring, command, env, file, ssh-agent, bitwarden)", name, cr.Source)
		}
	}
	for name, p := range c.Profiles {
		if p == nil {
			p = &Profile{}
			c.Profiles[name] = p
		}
		p.Name = name
		if p.Extends != "" {
			if _, ok := c.Profiles[p.Extends]; !ok {
				return fmt.Errorf("profile %q extends unknown profile %q", name, p.Extends)
			}
		}
	}
	// Detect extends cycles before resolving.
	for name := range c.Profiles {
		seen := map[string]bool{}
		for cur := name; cur != ""; cur = c.Profiles[cur].Extends {
			if seen[cur] {
				return fmt.Errorf("profile %q: extends cycle", name)
			}
			seen[cur] = true
		}
	}
	for name, p := range c.Profiles {
		if err := c.validateProfile(p); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
	}
	if c.DefaultProfile != "" {
		if _, ok := c.Profiles[c.DefaultProfile]; !ok {
			return fmt.Errorf("default_profile %q does not exist", c.DefaultProfile)
		}
	}
	if c.AnonymousProfile != "" {
		if _, ok := c.Profiles[c.AnonymousProfile]; !ok {
			return fmt.Errorf("anonymous_profile %q does not exist", c.AnonymousProfile)
		}
	}
	return nil
}

func (c *Config) validateProfile(p *Profile) error {
	switch p.Unmatched {
	case "", UnmatchedTunnel, UnmatchedDeny:
	default:
		return fmt.Errorf("unmatched must be tunnel or deny, got %q", p.Unmatched)
	}
	if err := c.normalizeFilters(p.Filters); err != nil {
		return err
	}
	for i, h := range p.Tunnel {
		p.Tunnel[i] = strings.ToLower(h)
	}
	for i, s := range p.Services {
		if s == nil {
			return fmt.Errorf("services[%d]: empty", i)
		}
		if s.Name == "" {
			return fmt.Errorf("services[%d]: name is required", i)
		}
		if len(s.Hosts) == 0 {
			return fmt.Errorf("service %q: hosts is required", s.Name)
		}
		for j, h := range s.Hosts {
			s.Hosts[j] = strings.ToLower(h)
		}
		if s.Credential != "" {
			if _, ok := c.Credentials[s.Credential]; !ok {
				return fmt.Errorf("service %q: unknown credential %q", s.Name, s.Credential)
			}
		}
		if s.Inject != nil && s.Credential == "" {
			return fmt.Errorf("service %q: inject requires credential", s.Name)
		}
		if err := validateAction(s.Default, true); err != nil {
			return fmt.Errorf("service %q default: %w", s.Name, err)
		}
		if err := normalizeRules(s.Rules); err != nil {
			return fmt.Errorf("service %q: %w", s.Name, err)
		}
		if err := c.normalizeFilters(s.Filters); err != nil {
			return fmt.Errorf("service %q: %w", s.Name, err)
		}
	}
	for i, s := range p.SSH {
		if s == nil {
			return fmt.Errorf("ssh[%d]: empty", i)
		}
		if s.Name == "" {
			return fmt.Errorf("ssh[%d]: name is required", i)
		}
		if len(s.Hosts) == 0 {
			return fmt.Errorf("ssh %q: hosts is required", s.Name)
		}
		for j, h := range s.Hosts {
			s.Hosts[j] = strings.ToLower(h)
		}
		if s.Credential == "" {
			return fmt.Errorf("ssh %q: credential is required", s.Name)
		}
		if _, ok := c.Credentials[s.Credential]; !ok {
			return fmt.Errorf("ssh %q: unknown credential %q", s.Name, s.Credential)
		}
		for _, k := range s.Allow {
			switch k {
			case SSHKindGit, SSHKindExec, SSHKindShell, SSHKindSFTP, SSHKindForward:
			default:
				return fmt.Errorf("ssh %q: unknown allow kind %q", s.Name, k)
			}
		}
		for j, kh := range s.KnownHosts {
			s.KnownHosts[j] = paths.Expand(kh, c.Dir)
		}
		if err := validateAction(s.Default, true); err != nil {
			return fmt.Errorf("ssh %q default: %w", s.Name, err)
		}
		if err := normalizeRules(s.Rules); err != nil {
			return fmt.Errorf("ssh %q: %w", s.Name, err)
		}
		if err := c.normalizeFilters(s.Filters); err != nil {
			return fmt.Errorf("ssh %q: %w", s.Name, err)
		}
	}
	return nil
}

func (c *Config) normalizeFilters(fs []FilterRef) error {
	for i := range fs {
		if fs[i].Path == "" {
			return fmt.Errorf("filters[%d]: path is required", i)
		}
		fs[i].Path = paths.Expand(fs[i].Path, c.Dir)
	}
	return nil
}

func validateAction(a string, allowEmpty bool) error {
	switch a {
	case ActionAllow, ActionDeny, ActionAsk:
		return nil
	case "":
		if allowEmpty {
			return nil
		}
	}
	return fmt.Errorf("action must be allow, deny or ask, got %q", a)
}

func normalizeRules(rules []Rule) error {
	for i := range rules {
		r := &rules[i]
		if err := validateAction(r.Action, false); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		for j, m := range r.Methods {
			r.Methods[j] = strings.ToUpper(m)
		}
		if r.PathRegex != "" {
			re, err := regexp.Compile(r.PathRegex)
			if err != nil {
				return fmt.Errorf("rules[%d]: path_regex: %w", i, err)
			}
			r.PathRegexp = re
		}
		if r.GitLabProject != nil {
			r.GitLabProject.Path = strings.Trim(strings.ToLower(r.GitLabProject.Path), "/")
			if r.GitLabProject.Path == "" && r.GitLabProject.ID == 0 {
				return fmt.Errorf("rules[%d]: gitlab_project needs path or id", i)
			}
		}
		r.GitHubRepo = strings.Trim(strings.ToLower(r.GitHubRepo), "/")
		if r.Git != nil {
			switch r.Git.Service {
			case "", "receive-pack", "upload-pack", "upload-archive":
			default:
				return fmt.Errorf("rules[%d]: git.service must be receive-pack, upload-pack or upload-archive", i)
			}
			for _, u := range r.Git.Updates {
				switch u {
				case "create", "update", "delete":
				default:
					return fmt.Errorf("rules[%d]: git.updates must be create, update or delete", i)
				}
			}
		}
		if r.GraphQL != nil {
			for _, o := range r.GraphQL.Operations {
				switch o {
				case "query", "mutation", "subscription":
				default:
					return fmt.Errorf("rules[%d]: graphql.operations must be query, mutation or subscription", i)
				}
			}
		}
		if r.SSH != nil && r.SSH.Command != "" {
			re, err := regexp.Compile(r.SSH.Command)
			if err != nil {
				return fmt.Errorf("rules[%d]: ssh.command: %w", i, err)
			}
			r.SSH.CommandRegexp = re
		}
	}
	return nil
}

// ResolvedProfile returns a profile with its extends chain flattened: parent
// filters first, and services/ssh entries overridden by name in the child.
func (c *Config) ResolvedProfile(name string) (*Profile, error) {
	p, ok := c.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", name)
	}
	if p.Extends == "" {
		return p, nil
	}
	parent, err := c.ResolvedProfile(p.Extends)
	if err != nil {
		return nil, err
	}
	out := &Profile{Name: p.Name, Unmatched: p.Unmatched, Tunnel: append(append([]string{}, parent.Tunnel...), p.Tunnel...)}
	if out.Unmatched == "" {
		out.Unmatched = parent.Unmatched
	}
	out.Filters = append(append([]FilterRef{}, parent.Filters...), p.Filters...)
	out.Services = mergeByName(parent.Services, p.Services, func(s *Service) string { return s.Name })
	out.SSH = mergeByName(parent.SSH, p.SSH, func(s *SSHService) string { return s.Name })
	return out, nil
}

// mergeByName puts child entries first (so they win host matching), followed
// by parent entries the child didn't override.
func mergeByName[T any](parent, child []T, name func(T) string) []T {
	seen := map[string]bool{}
	var out []T
	for _, c := range child {
		seen[name(c)] = true
		out = append(out, c)
	}
	for _, p := range parent {
		if !seen[name(p)] {
			out = append(out, p)
		}
	}
	return out
}

// UnmatchedMode returns the effective unmatched mode.
func (p *Profile) UnmatchedMode() string {
	if p.Unmatched == "" {
		return UnmatchedTunnel
	}
	return p.Unmatched
}

// KeyringAccount is the OS keyring account the credential is stored under.
func (c *Credential) KeyringAccount() string {
	if c.Account != "" {
		return c.Account
	}
	return c.Name
}
