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
