package bitwarden

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Prompter supplies the master password and, when the server asks, a
// second factor. The password is requested again on each attempt.
type Prompter interface {
	MasterPassword(label string) (string, error)
	TwoFactorCode(label, method string) (string, error)
}

// stdPrompter reads the master password from the controlling terminal.
// It refuses a redirected stdin so a prompt cannot swallow other input.
type stdPrompter struct {
	in  *os.File
	out io.Writer
}

func (p stdPrompter) MasterPassword(label string) (string, error) {
	in := p.in
	if in == nil {
		in = os.Stdin
	}
	out := p.out
	if out == nil {
		out = os.Stderr
	}
	if !term.IsTerminal(int(in.Fd())) {
		return "", fmt.Errorf("master password for %s required; set password_env or run `bouncer serve` in a terminal", label)
	}
	fmt.Fprintf(out, "Bitwarden master password for %s: ", label)
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("empty master password")
	}
	return string(b), nil
}

func (p stdPrompter) TwoFactorCode(label, method string) (string, error) {
	in := p.in
	if in == nil {
		in = os.Stdin
	}
	out := p.out
	if out == nil {
		out = os.Stderr
	}
	if !term.IsTerminal(int(in.Fd())) {
		return "", fmt.Errorf("verification code (%s) for %s required; run `bouncer serve` in a terminal", method, label)
	}
	fmt.Fprintf(out, "Bitwarden verification code (%s) for %s: ", method, label)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", errors.New("empty verification code")
	}
	return line, nil
}
