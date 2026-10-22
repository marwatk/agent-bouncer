package sshproxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Dial connects to the bouncer SSH listener and completes the preamble,
// returning a connection ready for the SSH handshake.
func Dial(addr string, p Preamble) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to bouncer at %s (is `bouncer serve` running?): %w", addr, err)
	}
	b, _ := json.Marshal(p)
	if _, err := fmt.Fprintf(c, "%s%s\n", preamblePrefix, b); err != nil {
		c.Close()
		return nil, err
	}
	// Read the reply byte by byte so no SSH data is consumed.
	var line strings.Builder
	one := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(90 * time.Second))
	for {
		if _, err := c.Read(one); err != nil {
			c.Close()
			return nil, fmt.Errorf("reading bouncer reply: %w", err)
		}
		if one[0] == '\n' {
			break
		}
		line.WriteByte(one[0])
		if line.Len() > 4096 {
			c.Close()
			return nil, errors.New("bouncer reply too long")
		}
	}
	c.SetReadDeadline(time.Time{})
	reply := line.String()
	if reply == "OK" {
		return c, nil
	}
	c.Close()
	return nil, errors.New(strings.TrimPrefix(reply, "ERR "))
}

// Connect is the ProxyCommand body: dial, then shuttle stdin/stdout.
func Connect(addr string, p Preamble, stdin io.Reader, stdout io.Writer) error {
	c, err := Dial(addr, p)
	if err != nil {
		return err
	}
	defer c.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(stdout, bufio.NewReader(c))
	}()
	io.Copy(c, stdin)
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	wg.Wait()
	return nil
}
