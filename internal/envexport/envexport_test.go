package envexport

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func params() Params {
	return Params{ProxyAddr: "127.0.0.1:8228", SSHAddr: "127.0.0.1:8229", Token: "t0k'x", SessionID: "abcd",
		CACert: "/s/ca.pem", CABundle: "/s/ca-bundle.pem", ShimDir: "/s/ssh/bin", SSHCommand: `"/usr/bin/ssh" -F "/s/ssh/config"`,
		Placeholders: map[string]string{"GITLAB_TOKEN": "bouncer-placeholder-gitlab"}}
}

func TestShellOutputEvaluates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	out, err := Build(params()).Format("sh")
	if err != nil {
		t.Fatal(err)
	}
	script := out + `printf '%s|%s|%s|%s' "$HTTPS_PROXY" "$GITLAB_TOKEN" "$GIT_SSH_COMMAND" "${PATH%%:*}"`
	got, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := `http://bouncer:t0k%27x@127.0.0.1:8228|bouncer-placeholder-gitlab|"/usr/bin/ssh" -F "/s/ssh/config"|/s/ssh/bin`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	for _, sh := range []string{"fish", "powershell", "cmd"} {
		if _, err := Build(params()).Format(sh); err != nil {
			t.Error(err)
		}
	}
}

func TestApply(t *testing.T) {
	env := Build(params()).Apply([]string{"PATH=/usr/bin", "HTTPS_PROXY=old", "HOME=/h"})
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "PATH=/s/ssh/bin"+string(os.PathListSeparator)+"/usr/bin") || strings.Contains(joined, "HTTPS_PROXY=old") || !strings.Contains(joined, "HOME=/h") {
		t.Fatal(joined)
	}
}

func TestWriteSSHFiles(t *testing.T) {
	dir := t.TempDir()
	f, err := WriteSSHFiles(dir, "/opt/bouncer", "@cert-authority * ssh-ed25519 AAAA\n")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.Config)
	if !strings.Contains(string(b), `ProxyCommand "/opt/bouncer" ssh-connect %h %p %r`) {
		t.Fatal(string(b))
	}
	if f.ShimDir != "" {
		if _, err := os.Stat(filepath.Join(f.ShimDir, "ssh")); err != nil && runtime.GOOS != "windows" {
			t.Fatal(err)
		}
	}
}
