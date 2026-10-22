package gitproto

import (
	"bytes"
	"io"
	"net/url"
	"strings"
	"testing"
)

const a = "1111111111111111111111111111111111111111"
const b = "2222222222222222222222222222222222222222"

func TestParsePush(t *testing.T) {
	body := BuildPush([]RefUpdate{
		{OldOID: a, NewOID: b, Ref: "refs/heads/main"},
		{OldOID: ZeroOID, NewOID: b, Ref: "refs/heads/feature"},
		{OldOID: a, NewOID: ZeroOID, Ref: "refs/heads/old"},
	}, []string{"report-status", "side-band-64k"}, []string{"ci.skip"})
	r := bytes.NewReader(body)
	p, err := ParsePush(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Updates) != 3 {
		t.Fatalf("updates: %+v", p.Updates)
	}
	want := []string{UpdateUpdate, UpdateCreate, UpdateDelete}
	for i, u := range p.Updates {
		if u.Type != want[i] {
			t.Errorf("update %d type %s, want %s", i, u.Type, want[i])
		}
	}
	if !p.HasCapability("report-status") || len(p.PushOptions) != 1 || p.PushOptions[0] != "ci.skip" {
		t.Errorf("caps/options: %+v", p)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.HasPrefix(rest, []byte("PACK")) {
		t.Errorf("parser consumed packfile; rest=%q", rest)
	}
}

func TestParsePushManyRefsBeyond100Bytes(t *testing.T) {
	var ups []RefUpdate
	for i := 0; i < 50; i++ {
		ups = append(ups, RefUpdate{OldOID: a, NewOID: b, Ref: "refs/heads/branch-" + strings.Repeat("x", i)})
	}
	ups = append(ups, RefUpdate{OldOID: a, NewOID: b, Ref: "refs/heads/foo"})
	p, err := ParsePush(bytes.NewReader(BuildPush(ups, nil, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Updates[len(p.Updates)-1].Ref != "refs/heads/foo" {
		t.Fatal("last ref not parsed")
	}
}

func TestParsePushSigned(t *testing.T) {
	var buf bytes.Buffer
	for _, l := range []string{
		"push-cert\x00report-status\n", "certificate version 0.1\n", "pusher A <a@x> 1 +0000\n", "\n",
		a + " " + b + " refs/heads/main\n", "-----BEGIN PGP SIGNATURE-----\n", "sig\n", "-----END PGP SIGNATURE-----\n",
		"push-cert-end\n",
	} {
		buf.Write(EncodePkt(l))
	}
	buf.Write(Flush)
	p, err := ParsePush(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Signed || len(p.Updates) != 1 || p.Updates[0].Ref != "refs/heads/main" {
		t.Fatalf("%+v", p)
	}
}

func TestParsePushMalformed(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(EncodePkt("garbage\n"))
	buf.Write(Flush)
	if _, err := ParsePush(&buf); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParsePush(strings.NewReader("zzzz")); err == nil {
		t.Fatal("expected error for bad length")
	}
}

func TestFromHTTP(t *testing.T) {
	cases := []struct {
		path, query string
		svc, repo   string
	}{
		{"/group/proj.git/info/refs", "service=git-receive-pack", ServiceReceivePack, "group/proj"},
		{"/group/sub/proj.git/git-upload-pack", "", ServiceUploadPack, "group/sub/proj"},
		{"/group/proj/git-receive-pack", "", ServiceReceivePack, "group/proj"},
		{"/group/proj.git/info/lfs/objects/batch", "", ServiceLFS, "group/proj"},
	}
	for _, c := range cases {
		q, _ := url.ParseQuery(c.query)
		info, ok := FromHTTP(c.path, q)
		if !ok || info.Service != c.svc || info.Repo != c.repo {
			t.Errorf("FromHTTP(%q) = %+v, %v", c.path, info, ok)
		}
	}
	if _, ok := FromHTTP("/api/v4/projects", nil); ok {
		t.Error("non-git path recognized")
	}
}

func TestFromSSHCommand(t *testing.T) {
	info, ok := FromSSHCommand("git-receive-pack '/group/proj.git'")
	if !ok || info.Service != ServiceReceivePack || info.Repo != "group/proj" {
		t.Fatalf("%+v %v", info, ok)
	}
	info, ok = FromSSHCommand("git upload-pack 'proj.git'")
	if !ok || info.Service != ServiceUploadPack || info.Repo != "proj" {
		t.Fatalf("%+v %v", info, ok)
	}
	for _, bad := range []string{"git-receive-pack 'a.git'; rm -rf ~", "git-receive-pack a.git && x", "ls", "git-receive-pack 'a'b'"} {
		if _, ok := FromSSHCommand(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRejectPushSideband(t *testing.T) {
	p := &Push{Updates: []RefUpdate{{Ref: "refs/heads/main"}}, Capabilities: []string{"report-status", "side-band-64k"}}
	out := RejectPush(p, "nope\nreally")
	r := bytes.NewReader(out)
	var bands [3][]byte
	for {
		payload, special, err := ReadPkt(r)
		if err != nil {
			t.Fatal(err)
		}
		if special == "flush" {
			break
		}
		bands[payload[0]] = append(bands[payload[0]], payload[1:]...)
	}
	if string(bands[2]) != "agent-bouncer: nope really\n" {
		t.Fatalf("band 2: %q", bands[2])
	}
	if !bytes.Contains(bands[1], []byte("ng refs/heads/main nope really\n")) || !bytes.Contains(bands[1], []byte("unpack ok")) {
		t.Fatalf("band 1: %q", bands[1])
	}
	if RejectPush(&Push{Updates: p.Updates}, "x") != nil {
		t.Fatal("no report-status capability should yield nil")
	}
}
