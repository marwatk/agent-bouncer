package daemon

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/marwatk/agent-bouncer/internal/approval"
)

// RunTerminalApprover prompts for approvals on an interactive terminal,
// one at a time, in arrival order. Approvals answered elsewhere (the CLI)
// are dropped from the queue.
func (d *Daemon) RunTerminalApprover(in io.Reader, out io.Writer) {
	events, cancel := d.Approvals.Subscribe()
	defer cancel()
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- strings.TrimSpace(sc.Text())
		}
		close(lines)
	}()

	var queue []approval.Pending
	var showing *approval.Pending
	showNext := func() {
		showing = nil
		if len(queue) == 0 {
			return
		}
		p := queue[0]
		queue = queue[1:]
		showing = &p
		session := p.SessionLabel
		if session == "" {
			session = p.SessionID
		}
		d := approval.Display
		fmt.Fprintf(out, "\n=== approval needed [%s] session=%s profile=%s filter=%s\n  %s\n  request: %s\n  [y] allow once  [s] allow for session  [n] deny  [d] deny for session > ",
			p.ID, d(session, 60), d(p.Profile, 60), d(p.Filter, 60), d(p.Prompt, 300), d(p.Request, 300))
	}
	for {
		select {
		case ev := <-events:
			switch ev.Type {
			case "pending":
				queue = append(queue, ev.Pending)
				if showing == nil {
					showNext()
				}
			case "resolved":
				for i, q := range queue {
					if q.ID == ev.Pending.ID {
						queue = append(queue[:i], queue[i+1:]...)
						break
					}
				}
				if showing != nil && showing.ID == ev.Pending.ID {
					verdict := "denied"
					if ev.Allowed {
						verdict = "allowed"
					}
					fmt.Fprintf(out, "\n  [%s] %s\n", ev.Pending.ID, verdict)
					showNext()
				}
			}
		case line, ok := <-lines:
			if !ok {
				return
			}
			if showing == nil {
				continue
			}
			var allow, remember bool
			switch strings.ToLower(line) {
			case "y", "yes":
				allow = true
			case "s":
				allow, remember = true, true
			case "n", "no":
			case "d":
				remember = true
			default:
				fmt.Fprint(out, "  answer y, s, n or d > ")
				continue
			}
			d.Approvals.Resolve(showing.ID, allow, remember)
		}
	}
}
