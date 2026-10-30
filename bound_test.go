package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

func boundCalls(f *fakeHost) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, m := range f.bound {
		out = append(out, m["sister"].(string)+"|"+m["session_id"].(string)+"|"+map[bool]string{true: "bound", false: "unbound"}[m["bound"].(bool)])
	}
	return out
}

// Rubi Home is told about every binding change, so the sister tools inside Claude Code can name her.
func TestRubiHomeIsToldAboutBindings(t *testing.T) {
	f, s, code := boundFixture(t)
	if got := boundCalls(f); !slices.Equal(got, []string{"Citri|cli-1|bound"}) {
		t.Fatalf("after binding: %v", got)
	}
	// The Bot ends the binding.
	if _, err := s.unbindTool(context.Background(), f, unbindIn{Sister: "Citri", BindCode: code}); err != nil {
		t.Fatal(err)
	}
	if got := boundCalls(f); !slices.Equal(got, []string{"Citri|cli-1|bound", "Citri|cli-1|unbound"}) {
		t.Fatalf("after unbind: %v", got)
	}
	// Binding again to another session of the same Bot: the old one is released first, then the new one is set.
	bindAs(t, f, s, "Citri", "local_a")
	f.mu.Lock()
	f.bound = nil
	f.mu.Unlock()
	bindAs(t, f, s, "Citri", "cli-2")
	if got := boundCalls(f); !slices.Equal(got, []string{"Citri|cli-1|unbound", "Citri|cli-2|bound"}) {
		t.Fatalf("after re-binding: %v", got)
	}
	// The user unbinds in the panel.
	f.mu.Lock()
	f.bound = nil
	f.mu.Unlock()
	if _, err := s.panel(f, "unbind", json.RawMessage(`{"sister":"citri"}`)); err != nil {
		t.Fatal(err)
	}
	if got := boundCalls(f); !slices.Equal(got, []string{"Citri|cli-2|unbound"}) {
		t.Fatalf("after the panel's unbind: %v", got)
	}
	// Unbinding what isn't bound tells nobody.
	f.mu.Lock()
	f.bound = nil
	f.mu.Unlock()
	_, _ = s.panel(f, "unbind", json.RawMessage(`{"sister":"Citri"}`))
	if got := boundCalls(f); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestRubiHomeIsToldWhenABindingFollowsItsSession(t *testing.T) {
	f, s, code := boundFixture(t)
	f.mu.Lock()
	f.sessions[0].SessionID = "cli-1b"
	f.bound = nil
	f.mu.Unlock()
	if _, err := s.sendTool(context.Background(), f, sendIn{Sister: "Citri", BindCode: code, Text: "again"}); err != nil {
		t.Fatal(err)
	}
	if got := boundCalls(f); !slices.Equal(got, []string{"Citri|cli-1|unbound", "Citri|cli-1b|bound"}) {
		t.Fatalf("after following: %v", got)
	}
}

func TestBoundCallsAreToleratedByAnOldRubiHome(t *testing.T) {
	f := &fakeHost{devices: []rubiplugin.HomeDevice{mac}, sessions: []session{mainSess, subSess, otherSess}, oldHome: true}
	s := newSisters(&store{})
	if err := s.st.load(f); err != nil {
		t.Fatal(err)
	}
	bindAs(t, f, s, "Citri", "local_a")
	bindAs(t, f, s, "Vega", "cli-2")
	if len(s.st.bindings()) != 2 {
		t.Fatal("binding failed on an old Rubi Home")
	}
	f.mu.Lock()
	n := 0
	for _, l := range f.logs {
		if strings.Contains(l, "too old to tell Claude Code") {
			n++
		}
	}
	calls := 0
	for _, op := range f.ops {
		if op == opBound {
			calls++
		}
	}
	f.mu.Unlock()
	if n != 1 || calls != 1 {
		t.Fatalf("logged %d times, called %d times: it is tried and logged once per computer", n, calls)
	}
	// Sending still works.
	b := s.st.bindings()[0]
	if _, err := s.sendTool(context.Background(), f, sendIn{Sister: b.Sister, BindCode: b.Code, Text: "hi"}); err != nil {
		t.Fatal(err)
	}
}

// A watcher syncs the bindings it already has when it starts polling a computer (bindings made before Rubi
// Home knew the operation).
func TestWatcherSyncsBindingsOnStart(t *testing.T) {
	f, s, _ := boundFixture(t)
	f.mu.Lock()
	f.bound = nil
	f.next = func(ctx context.Context, _ string) (*request, error) { <-ctx.Done(); return nil, ctx.Err() }
	f.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { newWatcher(f, s).run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(boundCalls(f)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got := boundCalls(f); len(got) == 0 || got[0] != "Citri|cli-1|bound" {
		t.Fatalf("%v", got)
	}
}

// What the sister tools queue in Rubi Home reaches the bound Bot through the routes that exist: an ask as
// claude_ask, an explicit reply (To = the message's sender, in_reply_to the message) as claude_reply.
func TestToolMadeAsksAndRepliesRoute(t *testing.T) {
	f, s, _ := boundFixture(t)
	ctx := context.Background()
	n := len(f.events)
	s.route(ctx, f, mac, outMsg{ID: "co_1", Kind: "ask", SessionID: "cli-1", Cwd: "/work", AskKind: "audit", Text: "check the diff on branch x"})
	s.route(ctx, f, mac, outMsg{ID: "co_2", Kind: "reply", SessionID: "cli-1", To: "Citri", InReplyTo: []string{"cm_9"}, Text: "early answer"})
	s.route(ctx, f, mac, outMsg{ID: "co_3", Kind: "reply", SessionID: "cli-1", To: "Mallory", InReplyTo: []string{"cm_8"}, Text: "x"})
	got := f.events[n:]
	if len(got) != 2 || got[0]["_type"] != eventAsk || got[0]["kind"] != "audit" || got[0]["_agent"] != "Citri" ||
		got[1]["_type"] != eventReply || got[1]["text"] != "early answer" {
		t.Fatalf("routed: %+v", got)
	}
	if r, _ := got[1]["in_reply_to"].([]string); len(r) != 1 || r[0] != "cm_9" {
		t.Fatalf("in_reply_to: %+v", got[1]["in_reply_to"])
	}
}

// Anything addressed to a local sender (rubi-home claude-send) is dropped, never forwarded to a Bot, whatever
// kind it is and whichever Bot the session is bound to.
func TestEntriesForLocalSendersAreNeverRouted(t *testing.T) {
	f, s, _ := boundFixture(t)
	ctx := context.Background()
	n := len(f.events)
	for _, to := range []string{"local:Citri", "LOCAL:x", "local:"} {
		s.route(ctx, f, mac, outMsg{ID: "co_9", Kind: "reply", SessionID: "cli-1", To: to, InReplyTo: []string{"cm_9"}, Text: "private answer"})
		s.route(ctx, f, mac, outMsg{ID: "cm_9", Kind: "status", State: "answered", SessionID: "cli-1", To: to})
	}
	if got := f.events[n:]; len(got) != 0 {
		t.Fatalf("routed: %+v", got)
	}
}

// A Rubi Home that was updated is asked again when polling (re-)starts.
func TestBoundIsRetriedAfterRubiHomeIsUpdated(t *testing.T) {
	f := &fakeHost{devices: []rubiplugin.HomeDevice{mac}, sessions: []session{mainSess, subSess, otherSess}, oldHome: true}
	s := newSisters(&store{})
	if err := s.st.load(f); err != nil {
		t.Fatal(err)
	}
	bindAs(t, f, s, "Citri", "local_a")
	if len(boundCalls(f)) != 0 {
		t.Fatal("an old Rubi Home accepted it")
	}
	f.mu.Lock()
	f.oldHome = false // Rubi Home was updated
	f.mu.Unlock()
	s.syncBound(context.Background(), f, mac.ID)
	if got := boundCalls(f); !slices.Equal(got, []string{"Citri|cli-1|bound"}) {
		t.Fatalf("after the re-poll: %v", got)
	}
}

// A Rubi Home that never answers delays nothing for long.
func TestBoundCallHasATimeout(t *testing.T) {
	old := boundTimeout
	boundTimeout = 50 * time.Millisecond
	defer func() { boundTimeout = old }()
	f, s, _ := boundFixture(t)
	f.mu.Lock()
	f.hangBound = true
	f.mu.Unlock()
	start := time.Now()
	s.tellBound(context.Background(), f, s.st.bindings()[0], true)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}
