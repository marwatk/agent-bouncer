package config

import "testing"

func TestHostMatches(t *testing.T) {
	cases := []struct {
		pats []string
		host string
		want bool
	}{
		{[]string{"gitlab.com"}, "gitlab.com", true},
		{[]string{"gitlab.com"}, "GitLab.com:443", true},
		{[]string{"gitlab.com"}, "evilgitlab.com", false},
		{[]string{"*.github.com"}, "api.github.com", true},
		{[]string{"*.github.com"}, "github.com", false},
		{[]string{"*.github.com"}, "a.b.github.com", true},
		{[]string{"example.com:8443"}, "example.com:443", false},
		{[]string{"example.com:8443"}, "example.com:8443", true},
	}
	for _, c := range cases {
		if got := HostMatches(c.pats, c.host); got != c.want {
			t.Errorf("HostMatches(%v, %q) = %v, want %v", c.pats, c.host, got, c.want)
		}
	}
}

func TestParseAndExtends(t *testing.T) {
	cfg, err := Parse([]byte(`
credentials:
  gl: {source: keyring}
profiles:
  base:
    unmatched: deny
    filters: [a.ts]
    services:
      - name: gitlab
        hosts: [gitlab.com]
        credential: gl
        rules:
          - action: allow
            gitlab_project: Group/Proj
  child:
    extends: base
    filters:
      - path: b.ts
        config: {x: 1}
    services:
      - name: gitlab
        hosts: [gitlab.com]
        credential: gl
`), "/tmp/cfg/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := cfg.ResolvedProfile("child")
	if err != nil {
		t.Fatal(err)
	}
	if p.UnmatchedMode() != UnmatchedDeny {
		t.Errorf("unmatched not inherited: %q", p.Unmatched)
	}
	if len(p.Filters) != 2 || p.Filters[0].Path != "/tmp/cfg/a.ts" || p.Filters[1].Config["x"] != 1 {
		t.Errorf("filters: %+v", p.Filters)
	}
	if len(p.Services) != 1 || len(p.Services[0].Rules) != 0 {
		t.Errorf("child service should override parent: %+v", p.Services)
	}
	if got := cfg.Profiles["base"].Services[0].Rules[0].GitLabProject.Path; got != "group/proj" {
		t.Errorf("project path not normalized: %q", got)
	}
	if cfg.Profiles["base"].Services[0].DefaultAction() != ActionDeny {
		t.Error("service with rules should default to deny")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte("profiles:\n  p:\n    servics: []\n"), "x.yaml"); err == nil {
		t.Fatal("expected error for misspelled field")
	}
}
