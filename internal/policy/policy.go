// Package policy compiles a config into per-profile filter chains.
package policy

import (
	"fmt"

	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/config"
	"github.com/marwatk/agent-bouncer/internal/jsfilter"
	"github.com/marwatk/agent-bouncer/internal/kv"
)

// Set is a compiled config.
type Set struct {
	Config   *config.Config
	Profiles map[string]*Profile
}

// Profile is a compiled profile.
type Profile struct {
	Name      string
	Unmatched string
	Tunnel    []string
	// AllowPrivate permits tunnels to non-public addresses.
	AllowPrivate bool
	Services     []*Service
	SSH          []*SSHService
}

// Service is an intercepted HTTP service with its full filter chain:
// profile filters, then service filters, then the service's rules.
type Service struct {
	Config  *config.Service
	Filters []chain.Filter
}

// SSHService is a terminated SSH service with its filter chain.
type SSHService struct {
	Config  *config.SSHService
	Filters []chain.Filter
}

// Compile loads every filter referenced by cfg. Each (profile, filter path)
// pair is loaded once, so a filter attached at several levels still gets
// its own config and pool.
func Compile(cfg *config.Config, env *chain.Env, store *kv.Store) (*Set, error) {
	set := &Set{Config: cfg, Profiles: map[string]*Profile{}}
	for name := range cfg.Profiles {
		rp, err := cfg.ResolvedProfile(name)
		if err != nil {
			return nil, err
		}
		p := &Profile{Name: name, Unmatched: rp.UnmatchedMode(), Tunnel: rp.Tunnel, AllowPrivate: rp.AllowPrivate != nil && *rp.AllowPrivate}
		load := func(refs []config.FilterRef) ([]chain.Filter, error) {
			var out []chain.Filter
			for _, ref := range refs {
				f, err := jsfilter.Load(jsfilter.Options{Path: ref.Path, Config: ref.Config, Timeout: ref.Timeout.D, Env: env, KV: store})
				if err != nil {
					return nil, fmt.Errorf("profile %q: %w", name, err)
				}
				out = append(out, f)
			}
			return out, nil
		}
		profileFilters, err := load(rp.Filters)
		if err != nil {
			return nil, err
		}
		for _, s := range rp.Services {
			sf, err := load(s.Filters)
			if err != nil {
				return nil, err
			}
			fs := append(append(append([]chain.Filter{}, profileFilters...), sf...), chain.NewRules(s, env))
			p.Services = append(p.Services, &Service{Config: s, Filters: fs})
		}
		for _, s := range rp.SSH {
			sf, err := load(s.Filters)
			if err != nil {
				return nil, err
			}
			fs := append(append(append([]chain.Filter{}, profileFilters...), sf...), chain.NewSSHRules(s, env))
			p.SSH = append(p.SSH, &SSHService{Config: s, Filters: fs})
		}
		set.Profiles[name] = p
	}
	return set, nil
}

// MatchService returns the first service whose hosts match host[:port].
func (p *Profile) MatchService(hostport string) *Service {
	for _, s := range p.Services {
		if config.HostMatches(s.Config.Hosts, hostport) {
			return s
		}
	}
	return nil
}

// Tunnels reports whether an unmatched host may be tunneled.
func (p *Profile) Tunnels(hostport string) bool {
	return p.Unmatched != config.UnmatchedDeny || config.HostMatches(p.Tunnel, hostport)
}

// MatchSSH returns the first SSH service whose hosts match host.
func (p *Profile) MatchSSH(host string) *SSHService {
	for _, s := range p.SSH {
		if config.HostMatches(s.Config.Hosts, host) {
			return s
		}
	}
	return nil
}
