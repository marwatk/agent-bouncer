package approval

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/marwatk/agent-bouncer/internal/chain"
)

func TestAskResolveAndCoalesce(t *testing.T) {
	m := NewManager(time.Minute)
	events, cancel := m.Subscribe()
	defer cancel()
	sess := &chain.Session{ID: "s1"}
	var wg sync.WaitGroup
	results := make([]bool, 3)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "push?"})
		}(i)
	}
	ev := <-events
	if ev.Type != "pending" {
		t.Fatal(ev)
	}
	time.Sleep(20 * time.Millisecond)
	if n := len(m.List()); n != 1 {
		t.Fatalf("expected one coalesced prompt, got %d", n)
	}
	if err := m.Resolve(ev.Pending.ID, true, true); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for i, r := range results {
		if !r {
			t.Errorf("waiter %d not approved", i)
		}
	}
	// Remembered for the session, not for others.
	if ok, _ := m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "push?"}); !ok {
		t.Error("remembered approval not applied")
	}
	m.ForgetSession("s1")
	ctx, c := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer c()
	if ok, _ := m.Ask(ctx, chain.AskRequest{Session: sess, Prompt: "push?"}); ok {
		t.Error("forgotten session still approved")
	}
}

func TestTimeoutDenies(t *testing.T) {
	m := NewManager(10 * time.Millisecond)
	ok, err := m.Ask(context.Background(), chain.AskRequest{Prompt: "x"})
	if ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if len(m.List()) != 0 {
		t.Fatal("timed-out approval still pending")
	}
}

func TestDifferentRequestsDontShareAPrompt(t *testing.T) {
	m := NewManager(time.Minute)
	sess := &chain.Session{ID: "s1"}
	ask := func(req string, key string, out chan bool) {
		ok, _ := m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: req, Key: key})
		out <- ok
	}
	harmless, dangerous := make(chan bool, 1), make(chan bool, 1)
	go ask("ssh agent@sandbox exec: ls", "", harmless)
	go ask("ssh agent@sandbox exec: rm -rf /srv", "", dangerous)
	time.Sleep(20 * time.Millisecond)
	list := m.List()
	if len(list) != 2 {
		t.Fatalf("expected two separate prompts, got %d", len(list))
	}
	for _, p := range list {
		m.Resolve(p.ID, p.Request == "ssh agent@sandbox exec: ls", true)
	}
	if !<-harmless || <-dangerous {
		t.Fatal("answers applied to the wrong requests")
	}
	// The remembered allow (no explicit key) covers only the identical request.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if ok, _ := m.Ask(ctx, chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: "ssh agent@sandbox exec: cat /etc/shadow"}); ok {
		t.Fatal("remembered approval leaked to a different request")
	}
	if ok, _ := m.Ask(context.Background(), chain.AskRequest{Session: sess, Prompt: "Let the agent in?", Request: "ssh agent@sandbox exec: ls"}); !ok {
		t.Fatal("identical request should reuse the remembered approval")
	}

	// An explicit key groups on purpose: separate prompts, and a
	// session-wide answer to one settles the others.
	a, b := make(chan bool, 1), make(chan bool, 1)
	go ask("push 1", "push-limit", a)
	go ask("push 2", "push-limit", b)
	time.Sleep(20 * time.Millisecond)
	list = m.List()
	if len(list) != 2 {
		t.Fatalf("explicit key: expected two prompts, got %d", len(list))
	}
	m.Resolve(list[0].ID, true, true)
	if !<-a || !<-b {
		t.Fatal("session-wide approval should settle both")
	}
}

func TestSharedSessionsDontRemember(t *testing.T) {
	m := NewManager(time.Minute)
	anon := &chain.Session{ID: "anonymous", Shared: true}
	events, cancel := m.Subscribe()
	defer cancel()
	done := make(chan bool, 1)
	go func() {
		ok, _ := m.Ask(context.Background(), chain.AskRequest{Session: anon, Prompt: "x", Request: "r"})
		done <- ok
	}()
	m.Resolve((<-events).Pending.ID, true, true)
	<-done
	ctx, c := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer c()
	if ok, _ := m.Ask(ctx, chain.AskRequest{Session: anon, Prompt: "x", Request: "r"}); ok {
		t.Fatal("approval remembered for a shared session")
	}
}
