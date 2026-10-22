package chain

import (
	"fmt"
	"slices"

	"github.com/marwatk/agent-bouncer/internal/config"
)

// Rules evaluates declarative rules: first match wins, else the default.
type Rules struct {
	name    string
	rules   []config.Rule
	def     string
	env     *Env
	ssh     bool
	sshSvc  *config.SSHService
	service string
}

// NewRules builds the rules filter for an HTTP service.
func NewRules(svc *config.Service, env *Env) *Rules {
	return &Rules{name: "rules:" + svc.Name, rules: svc.Rules, def: svc.DefaultAction(), env: env, service: svc.Name}
}

// NewSSHRules builds the rules filter for an SSH service. It also enforces the
// service's capability allowlist before any rule is consulted.
func NewSSHRules(svc *config.SSHService, env *Env) *Rules {
	return &Rules{name: "rules:" + svc.Name, rules: svc.Rules, def: svc.DefaultAction(), env: env, ssh: true, sshSvc: svc, service: svc.Name}
}

func (r *Rules) Name() string { return r.name }

func (r *Rules) Handle(req *Request, next Handler) (*Response, error) {
	if r.ssh && req.SSH != nil && !r.sshSvc.Allows(req.SSH.Kind) {
		return Deny(r.name, fmt.Sprintf("ssh %s is not in the allow list for %s", req.SSH.Kind, r.service)), nil
	}
	for i := range r.rules {
		rule := &r.rules[i]
		ok, err := Match(req, rule, r.env)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		if ok {
			return r.act(req, next, rule.Action, fmt.Sprintf("%s rules[%d]", r.name, i), rule.Reason, rule.Prompt)
		}
	}
	return r.act(req, next, r.def, r.name+" default", "", "")
}

func (r *Rules) act(req *Request, next Handler, action, by, reason, prompt string) (*Response, error) {
	switch action {
	case config.ActionAllow:
		req.AllowedBy = by
		return next(req)
	case config.ActionAsk:
		if r.env == nil || r.env.Approver == nil {
			return Deny(by, "approval required but no approver is configured"), nil
		}
		if prompt == "" {
			prompt = "Allow " + req.Describe() + "?"
		}
		ok, err := r.env.Approver.Ask(req.Ctx, AskRequest{Session: req.Session, Filter: r.name, Prompt: prompt, Request: req.Describe()})
		if err != nil {
			return Deny(by, "approval failed: "+err.Error()), nil
		}
		if !ok {
			if reason == "" {
				reason = "denied by user"
			}
			return Deny(by, reason), nil
		}
		req.AllowedBy = by + " (approved)"
		return next(req)
	default:
		if reason == "" {
			reason = "no rule allows " + req.Describe()
			if by != r.name+" default" {
				reason = "denied by " + by
			}
		}
		return Deny(by, reason), nil
	}
}

// Match reports whether all of a rule's matchers match req.
func Match(req *Request, rule *config.Rule, env *Env) (bool, error) {
	isHTTP := req.Transport == TransportHTTP
	if len(rule.Methods) > 0 && (!isHTTP || !slices.Contains(rule.Methods, req.Method)) {
		return false, nil
	}
	if rule.Path != "" && (!isHTTP || !Glob(rule.Path, req.Path())) {
		return false, nil
	}
	if rule.PathRegexp != nil && (!isHTTP || !rule.PathRegexp.MatchString(req.Path())) {
		return false, nil
	}
	if rule.SSH != nil {
		if req.SSH == nil {
			return false, nil
		}
		if len(rule.SSH.Kinds) > 0 && !slices.Contains(rule.SSH.Kinds, req.SSH.Kind) {
			return false, nil
		}
		if rule.SSH.CommandRegexp != nil && !rule.SSH.CommandRegexp.MatchString(req.SSH.Command) {
			return false, nil
		}
	}
	if p := rule.GitLabProject; p != nil {
		ok, err := matchGitLabProject(req, env, p)
		if err != nil || !ok {
			return false, err
		}
	}
	if rule.GitHubRepo != "" {
		ok, err := matchGitHubRepo(req, rule.GitHubRepo)
		if err != nil || !ok {
			return false, err
		}
	}
	if g := rule.Git; g != nil {
		ok, err := matchGit(req, g)
		if err != nil || !ok {
			return false, err
		}
	}
	if q := rule.GraphQL; q != nil {
		ok, err := matchGraphQL(req, q)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func matchGit(req *Request, g *config.GitMatch) (bool, error) {
	info := req.Git()
	if info == nil {
		return false, nil
	}
	if g.Service != "" && info.Service != g.Service {
		return false, nil
	}
	if len(g.Refs) == 0 && len(g.Updates) == 0 {
		return true, nil
	}
	push, err := req.Push()
	if err != nil || push == nil {
		return false, err
	}
	for _, u := range push.Updates {
		if len(g.Updates) > 0 && !slices.Contains(g.Updates, u.Type) {
			continue
		}
		if len(g.Refs) > 0 && !slices.ContainsFunc(g.Refs, func(p string) bool { return Glob(p, u.Ref) }) {
			continue
		}
		return true, nil
	}
	return false, nil
}

func matchGraphQL(req *Request, q *config.GraphQLRule) (bool, error) {
	ops, err := req.GraphQL()
	if err != nil || ops == nil {
		return false, err
	}
	for _, op := range ops {
		if len(q.Operations) > 0 && !slices.Contains(q.Operations, op.Type) {
			continue
		}
		if len(q.Fields) == 0 {
			return true, nil
		}
		for _, f := range op.Fields {
			if slices.Contains(q.Fields, f) {
				return true, nil
			}
		}
	}
	return false, nil
}
