//go:build windows

package creds

import (
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
)

func dialAgent() (net.Conn, error) {
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if c, err := net.Dial("unix", sock); err == nil {
			return c, nil
		}
	}
	timeout := 5 * time.Second
	return winio.DialPipe(`\\.\pipe\openssh-ssh-agent`, &timeout)
}
