// Package gitproto parses the parts of the git wire protocol that policy
// cares about: which service a request is for, which repository, and which
// refs a push updates.
package gitproto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	ServiceReceivePack   = "receive-pack"
	ServiceUploadPack    = "upload-pack"
	ServiceUploadArchive = "upload-archive"
	ServiceLFS           = "lfs"
)

// Update kinds for a RefUpdate.
const (
	UpdateCreate = "create"
	UpdateUpdate = "update"
	UpdateDelete = "delete"
)

// RefUpdate is one "<old> <new> <ref>" command from a push.
type RefUpdate struct {
	Ref    string `json:"ref"`
	OldOID string `json:"oldOid"`
	NewOID string `json:"newOid"`
	Type   string `json:"type"`
}

// Push is the command section of a receive-pack request.
type Push struct {
	Updates      []RefUpdate `json:"updates"`
	Capabilities []string    `json:"capabilities"`
	PushOptions  []string    `json:"pushOptions"`
	Signed       bool        `json:"signed"`
}

// MaxCommandBytes bounds how much of a push we will read looking for the end
// of the command list.
const MaxCommandBytes = 4 << 20

var oidRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func isZero(oid string) bool { return strings.Trim(oid, "0") == "" }

// Info identifies a git request.
type Info struct {
	Service string `json:"service"`
	// Repo is the repository path with leading "/" and trailing ".git" removed.
	Repo string `json:"repo"`
}

// FromHTTP recognizes git smart-HTTP and LFS requests from a decoded URL path and query.
func FromHTTP(path string, query url.Values) (*Info, bool) {
	svcFromQuery := func() string {
		return strings.TrimPrefix(query.Get("service"), "git-")
	}
	type suffix struct {
		s       string
		service func() string
	}
	for _, sf := range []suffix{
		{"/info/refs", svcFromQuery},
		{"/git-upload-pack", func() string { return ServiceUploadPack }},
		{"/git-receive-pack", func() string { return ServiceReceivePack }},
		{"/git-upload-archive", func() string { return ServiceUploadArchive }},
	} {
		if strings.HasSuffix(path, sf.s) {
			svc := sf.service()
			if svc != ServiceUploadPack && svc != ServiceReceivePack && svc != ServiceUploadArchive {
				return nil, false
			}
			return &Info{Service: svc, Repo: cleanRepo(strings.TrimSuffix(path, sf.s))}, true
		}
	}
	if i := strings.Index(path, "/info/lfs/"); i > 0 {
		return &Info{Service: ServiceLFS, Repo: cleanRepo(path[:i])}, true
	}
	return nil, false
}

// FromSSHCommand recognizes "git-receive-pack 'group/repo.git'" style exec commands.
func FromSSHCommand(cmd string) (*Info, bool) {
	cmd = strings.TrimSpace(cmd)
	var svc, rest string
	for _, s := range []string{ServiceReceivePack, ServiceUploadPack, ServiceUploadArchive} {
		for _, prefix := range []string{"git-" + s + " ", "git " + s + " "} {
			if strings.HasPrefix(cmd, prefix) {
				svc, rest = s, strings.TrimSpace(cmd[len(prefix):])
			}
		}
	}
	if svc == "" {
		return nil, false
	}
	// The argument is usually single-quoted by git; anything shell-trickier
	// than a single quoted or bare word is rejected rather than guessed at.
	arg := rest
	if len(arg) >= 2 && arg[0] == '\'' && arg[len(arg)-1] == '\'' {
		arg = arg[1 : len(arg)-1]
		if strings.ContainsRune(arg, '\'') {
			return nil, false
		}
	} else if strings.ContainsAny(arg, " \t'\"\\;&|$`") {
		return nil, false
	}
	return &Info{Service: svc, Repo: cleanRepo(arg)}, true
}

func cleanRepo(p string) string {
	p = strings.TrimPrefix(p, "~")
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, ".git")
	return strings.Trim(p, "/")
}

// ReadPkt reads one pkt-line. It returns special="flush"/"delim"/"response-end"
// for the special packets, otherwise the payload.
func ReadPkt(r io.Reader) (payload []byte, special string, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, "", err
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
	if err != nil {
		return nil, "", fmt.Errorf("invalid pkt-line length %q", hdr[:])
	}
	switch n {
	case 0:
		return nil, "flush", nil
	case 1:
		return nil, "delim", nil
	case 2:
		return nil, "response-end", nil
	case 3:
		return nil, "", errors.New("invalid pkt-line length 3")
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, "", err
	}
	return buf, "", nil
}

// ParsePush reads the command list (and push options, when negotiated) from
// the start of a receive-pack request body. It reads only as far as needed;
// the packfile is left unread.
func ParsePush(r io.Reader) (*Push, error) {
	// ReadPkt never reads ahead, so the packfile after the commands is untouched.
	lr := &io.LimitedReader{R: r, N: MaxCommandBytes}
	p := &Push{}
	first := true
	inCert := false
	for {
		payload, special, err := ReadPkt(lr)
		if err != nil {
			if lr.N <= 0 {
				return nil, errors.New("push command list exceeds size limit")
			}
			if err == io.EOF && first {
				// Empty body (e.g. a ref advertisement probe).
				return p, nil
			}
			return nil, fmt.Errorf("reading push commands: %w", err)
		}
		if special == "flush" {
			break
		}
		if special != "" {
			return nil, fmt.Errorf("unexpected %s packet in push commands", special)
		}
		line := strings.TrimSuffix(string(payload), "\n")
		if first {
			first = false
			if i := strings.IndexByte(line, 0); i >= 0 {
				p.Capabilities = strings.Fields(line[i+1:])
				line = line[:i]
			}
			if line == "push-cert" {
				p.Signed, inCert = true, true
				continue
			}
		}
		if inCert {
			if line == "push-cert-end" {
				inCert = false
				continue
			}
			// Commands inside a push certificate appear after the header
			// block; any line shaped like a command is one.
			if u, ok := parseCommand(line); ok {
				p.Updates = append(p.Updates, u)
			}
			continue
		}
		if strings.HasPrefix(line, "shallow ") {
			continue
		}
		u, ok := parseCommand(line)
		if !ok {
			return nil, fmt.Errorf("malformed push command %q", line)
		}
		p.Updates = append(p.Updates, u)
	}
	if inCert {
		return nil, errors.New("unterminated push certificate")
	}
	if p.HasCapability("push-options") && len(p.Updates) > 0 {
		for {
			payload, special, err := ReadPkt(lr)
			if err != nil {
				return nil, fmt.Errorf("reading push options: %w", err)
			}
			if special == "flush" {
				break
			}
			p.PushOptions = append(p.PushOptions, strings.TrimSuffix(string(payload), "\n"))
		}
	}
	return p, nil
}

func parseCommand(line string) (RefUpdate, bool) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || !oidRe.MatchString(parts[0]) || !oidRe.MatchString(parts[1]) || parts[2] == "" {
		return RefUpdate{}, false
	}
	u := RefUpdate{OldOID: parts[0], NewOID: parts[1], Ref: parts[2], Type: UpdateUpdate}
	switch {
	case isZero(u.OldOID):
		u.Type = UpdateCreate
	case isZero(u.NewOID):
		u.Type = UpdateDelete
	}
	return u, true
}

// HasCapability reports whether the client requested a capability.
func (p *Push) HasCapability(name string) bool {
	for _, c := range p.Capabilities {
		if c == name || strings.HasPrefix(c, name+"=") {
			return true
		}
	}
	return false
}

// EncodePkt encodes one pkt-line.
func EncodePkt(payload string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(payload)+4, payload))
}

// Flush is the flush-pkt.
var Flush = []byte("0000")

const ZeroOID = "0000000000000000000000000000000000000000"

// BuildPush synthesizes a receive-pack request body: commands, flush, then a
// stub packfile. Used by tests and `bouncer test` fixtures.
func BuildPush(updates []RefUpdate, caps []string, pushOptions []string) []byte {
	var b bytes.Buffer
	if len(pushOptions) > 0 {
		caps = append(caps, "push-options")
	}
	for i, u := range updates {
		line := u.OldOID + " " + u.NewOID + " " + u.Ref
		if i == 0 {
			line += "\x00" + strings.Join(caps, " ")
		}
		b.Write(EncodePkt(line + "\n"))
	}
	b.Write(Flush)
	if len(pushOptions) > 0 {
		for _, o := range pushOptions {
			b.Write(EncodePkt(o + "\n"))
		}
		b.Write(Flush)
	}
	b.WriteString("PACK\x00\x00\x00\x02\x00\x00\x00\x00")
	return b.Bytes()
}

// RejectPush encodes a receive-pack result rejecting every ref in p, so git
// shows "! [remote rejected] <ref> (<reason>)" and, over side-band, prints
// the reason as a "remote:" line. It returns nil if the client didn't ask
// for status reports, in which case the caller should fail the request.
func RejectPush(p *Push, reason string) []byte {
	if p == nil || len(p.Updates) == 0 || !(p.HasCapability("report-status") || p.HasCapability("report-status-v2")) {
		return nil
	}
	reason = strings.Join(strings.Fields(reason), " ")
	var report bytes.Buffer
	report.Write(EncodePkt("unpack ok\n"))
	for _, u := range p.Updates {
		report.Write(EncodePkt("ng " + u.Ref + " " + reason + "\n"))
	}
	report.Write(Flush)

	chunk := 0
	switch {
	case p.HasCapability("side-band-64k"):
		chunk = 65515
	case p.HasCapability("side-band"):
		chunk = 995
	default:
		return report.Bytes()
	}
	var out bytes.Buffer
	band := func(n byte, data []byte) {
		for len(data) > 0 {
			k := min(chunk, len(data))
			out.Write(EncodePkt(string(append([]byte{n}, data[:k]...))))
			data = data[k:]
		}
	}
	band(2, []byte("agent-bouncer: "+reason+"\n"))
	band(1, report.Bytes())
	out.Write(Flush)
	return out.Bytes()
}
