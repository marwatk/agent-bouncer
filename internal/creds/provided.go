package creds

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ParseProvided reads startup credentials, one per line:
//
//	name: value        value is taken verbatim to the end of the line
//	name:: base64      for multi-line or binary values (e.g. SSH keys)
//
// Blank lines and lines starting with # are ignored. Duplicate names and
// empty values are errors, so a malformed generator script fails loudly.
func ParseProvided(r io.Reader) (map[string]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return nil, err
	}
	// A generator that forgets "\n" glues lines together; refusing an
	// unterminated last line catches that instead of yielding a wrong secret.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("input does not end with a newline (missing \\n in a printf?)")
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !nameRe.MatchString(name) {
			// Don't echo the line: it may contain a secret.
			return nil, fmt.Errorf("line %d: expected `name: value` or `name:: base64`", n)
		}
		if strings.HasPrefix(value, ":") {
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[1:]))
			if err != nil {
				return nil, fmt.Errorf("line %d (%s): invalid base64: %w", n, name, err)
			}
			value = strings.TrimRight(string(raw), "\r\n")
		} else {
			value = strings.TrimPrefix(value, " ")
		}
		if value == "" {
			return nil, fmt.Errorf("line %d (%s): empty value", n, name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("line %d: %s given more than once", n, name)
		}
		out[name] = value
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
