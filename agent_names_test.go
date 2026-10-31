package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

func approve(t *testing.T, f *fakeHost) json.RawMessage {
	t.Helper()
	raw, _ := json.Marshal(lastSubmit(t, f).Payload)
	return raw
}

func TestAgentRename(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	code := agentBind(t, f, s, "Alice", "s-1")
	_ = code
	// The Bot's own bound session: no approval; the runner and Rubi both get the name.
	n := len(f.submits)
	res, err := s.renameTool(ctx, f, renameIn{VerifiedAgent: "Alice", Name: "release prep"})
	if err != nil || len(f.submits) != n {
		t.Fatalf("%v %v", res, err)
	}
	if m := res.(map[string]any); m["renamed"] != true || m["name"] != "release prep" {
		t.Fatalf("%v", m)
	}
	c := f.agent.called(opAgentRename)
	if len(c) != 1 || c[0]["project"] != "p1" || c[0]["id"] != "s-1" || c[0]["name"] != "release prep" {
		t.Fatalf("%v", c)
	}
	if a, ok := s.st.aliasFor("dev_mac", session{SessionID: "s-1"}); !ok || a.Name != "release prep" || a.Project != "p1" || a.SetBy != "Alice" {
		t.Fatalf("%+v %v", a, ok)
	}
	// The alias shows in the list and works as a name for bind.
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Bob", Name: "Release Prep"}); err == nil || !strings.Contains(err.Error(), "bound to Alice") {
		t.Fatalf("bind by alias: %v", err)
	}
	// Alias rules hold: unique per computer, not like an id, no hidden characters.
	if _, err := s.renameTool(ctx, f, renameIn{VerifiedAgent: "Alice", SessionID: "s-2", Name: "RELEASE PREP"}); err == nil {
		// s-2 is another session: a tap from the user, but the name is taken so the executor refuses.
		raw := approve(t, f)
		var tk renameTicket
		_ = json.Unmarshal(raw, &tk)
		if _, err := s.executeRename(ctx, f, tk, "bot", "user approved", nil); err == nil || !strings.Contains(err.Error(), "already called") {
			t.Fatalf("duplicate name: %v", err)
		}
	}
	for _, bad := range []string{"s-1", "0123456789abcdef", "a‮b"} {
		if _, err := s.renameTool(ctx, f, renameIn{VerifiedAgent: "Alice", Name: bad}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// Another session: a tap (kindRename), and nothing happens before it.
	n = len(f.submits)
	before := len(f.agent.called(opAgentRename))
	if _, err := s.renameTool(ctx, f, renameIn{VerifiedAgent: "Alice", SessionID: "s-2", Project: "p1", Name: "other"}); err != nil {
		t.Fatal(err)
	}
	r := lastSubmit(t, f)
	if len(f.submits) != n+1 || r.Kind != kindRename || len(f.agent.called(opAgentRename)) != before {
		t.Fatalf("%+v", r)
	}
	var tk renameTicket
	_ = json.Unmarshal(approve(t, f), &tk)
	if tk.Project != "p1" || tk.SessionID != "s-2" {
		t.Fatalf("%+v", tk)
	}
	if _, err := s.executeRename(ctx, f, tk, "bot", "user approved", nil); err != nil {
		t.Fatal(err)
	}
	if c := f.agent.called(opAgentRename); len(c) != before+1 || c[before]["id"] != "s-2" {
		t.Fatalf("%v", c)
	}
	// A name the user set is not the Bot's to change on its own session.
	if _, err := s.st.setAlias("dev_mac", "Mac", session{SessionID: "s-1", Source: "agent", RepoKey: "agent:p1"}, "users choice", "user", s.now()); err != nil {
		t.Fatal(err)
	}
	n = len(f.submits)
	if _, err := s.renameTool(ctx, f, renameIn{VerifiedAgent: "Alice", Name: "mine now"}); err != nil || len(f.submits) != n+1 {
		t.Fatalf("%v", err)
	}
	// Clearing removes the alias only.
	if _, err := s.executeRename(ctx, f, renameTicket{Sister: "Alice", Device: "dev_mac", SessionID: "s-1", Clear: true, Project: "p1"}, "user", "panel", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.st.aliasFor("dev_mac", session{SessionID: "s-1"}); ok {
		t.Fatal("alias remained")
	}
	// A runner that fails changes nothing.
	f.agent.failOp = map[string]error{opAgentRename: context.DeadlineExceeded}
	if _, err := s.executeRename(ctx, f, renameTicket{Sister: "Alice", Device: "dev_mac", SessionID: "s-1", Name: "later", Project: "p1"}, "bot", "x", nil); err == nil {
		t.Fatal("failure hidden")
	}
	if _, ok := s.st.aliasFor("dev_mac", session{SessionID: "s-1"}); ok {
		t.Fatal("alias set though the runner failed")
	}
}

// Agent aliases are not dropped by the hook path's session sweep.
func TestAgentAliasSurvivesTheHookSweep(t *testing.T) {
	f, s, _ := agentFixture(t)
	if _, err := s.st.setAlias("dev_mac", "Mac", session{SessionID: "s-1", Source: "agent", RepoKey: "agent:p1"}, "kept", "user", s.now()); err != nil {
		t.Fatal(err)
	}
	f.sessions = []session{mainSess}
	later := s.now().Add(2 * aliasTTL)
	s.now = func() time.Time { return later }
	s.sweep(f, []deviceSessions{{device: mac, list: []session{mainSess}}}, true)
	if len(s.st.aliases()) != 1 {
		t.Fatal("dropped")
	}
}

func TestAgentFork(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	agentBind(t, f, s, "Alice", "s-1")
	// Its own session: a tap.
	if _, err := s.forkTool(ctx, f, forkIn{VerifiedAgent: "Alice", Name: "experiment"}); err != nil {
		t.Fatal(err)
	}
	r := lastSubmit(t, f)
	if r.Kind != kindForkOwn || len(f.agent.called(opAgentFork)) != 0 {
		t.Fatalf("%+v", r)
	}
	var tk forkTicket
	_ = json.Unmarshal(approve(t, f), &tk)
	res, err := s.executeFork(ctx, f, tk)
	if err != nil {
		t.Fatal(err)
	}
	c := f.agent.called(opAgentFork)
	if len(c) != 1 || c[0]["project"] != "p1" || c[0]["id"] != "s-1" || c[0]["name"] != "experiment" {
		t.Fatalf("%v", c)
	}
	if m := res.(map[string]any); m["forked"] != true || m["session_id"] != "s-fork" || m["name"] != "experiment" {
		t.Fatalf("%v", m)
	}
	if a, ok := s.st.aliasFor("dev_mac", session{SessionID: "s-fork"}); !ok || a.Name != "experiment" {
		t.Fatalf("%+v", a)
	}
	// Any other session: strong.
	if _, err := s.forkTool(ctx, f, forkIn{VerifiedAgent: "Alice", Project: "p1", Session: "s-2"}); err != nil {
		t.Fatal(err)
	}
	if r := lastSubmit(t, f); r.Kind != kindFork {
		t.Fatalf("%+v", r)
	}
	// A Bot not bound to it asks strongly too; a name already taken is refused up front; no session, no fork.
	if _, err := s.forkTool(ctx, f, forkIn{VerifiedAgent: "Bob", Project: "p1", Session: "s-1"}); err != nil || lastSubmit(t, f).Kind != kindFork {
		t.Fatalf("%v", err)
	}
	if _, err := s.forkTool(ctx, f, forkIn{VerifiedAgent: "Alice", Session: "s-2", Name: "experiment"}); err == nil {
		t.Fatal("duplicate name")
	}
	if _, err := s.forkTool(ctx, f, forkIn{VerifiedAgent: "Carol"}); err == nil {
		t.Fatal("unbound Bot without a session")
	}
	if _, err := s.forkTool(ctx, f, forkIn{VerifiedAgent: "Alice", Session: "nope"}); err == nil {
		t.Fatal("unknown session")
	}
	if _, err := s.forkTool(ctx, f, forkIn{Session: "s-1"}); err == nil {
		t.Fatal("unverified Bot")
	}
	m := manifest()
	if a, ok := m.Action(kindForkOwn); !ok || a.DefaultLevel != rubiplugin.Tap {
		t.Fatalf("%+v", a)
	}
}
