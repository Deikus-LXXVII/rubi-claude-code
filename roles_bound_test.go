package main

import (
	"context"
	"testing"
)

// A binding to a role's session carries the role: every call names it, and the legacy role or another role's
// events and sessions never reach the Bot.
func TestBindingCarriesTheRole(t *testing.T) {
	f, s, _ := agentFixture(t)
	twoRoles(f)
	ctx := context.Background()
	code := agentBind(t, f, s, "Alice", "rs-1")
	b := s.st.bindings()[0]
	if b.Role != "r_aaaaaaaa" || b.Project != "p1" || b.SessionID != "rs-1" {
		t.Fatalf("%+v", b)
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Alice", BindCode: code, Text: "hi"}); err != nil {
		t.Fatal(err)
	}
	if c := f.agent.called(opAgentSend); len(c) != 1 || c[0]["role"] != "r_aaaaaaaa" {
		t.Fatalf("send: %v", c)
	}
	st, err := s.statusTool(ctx, f, statusIn{Sister: "Alice", BindCode: code})
	if err != nil {
		t.Fatal(err)
	}
	if m := st.(map[string]any); m["state"] != "busy" || m["in_slot"] != true || m["role"] != "r_aaaaaaaa" {
		t.Fatalf("%v", m)
	}
	// The status read the sessions of the role, not of the legacy role.
	last := f.agent.called(opAgentSessions)
	if r := last[len(last)-1]["role"]; r != "r_aaaaaaaa" {
		t.Fatalf("sessions asked without the role: %v", last)
	}

	// Events: only the bound role's session reaches the Bot; the legacy role's session with the same id doesn't.
	n := len(f.events)
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", Role: "p1", SessionID: "rs-1", To: "Alice", Text: "from the legacy role"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", SessionID: "rs-1", To: "Alice", Text: "no role at all"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", Role: "r_bbbbbbbb", SessionID: "rs-1", To: "Alice", Text: "another role"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", Role: "r_aaaaaaaa", SessionID: "rs-1", To: "Alice", Text: "mine"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "sister_ask", Project: "p1", Role: "r_aaaaaaaa", SessionID: "rs-1", AskKind: "audit", Text: "look"})
	got := f.events[n:]
	if len(got) != 2 || got[0]["text"] != "mine" || got[0]["role"] != "r_aaaaaaaa" || got[1]["_type"] != eventAsk {
		t.Fatalf("%+v", got)
	}
	askID := got[1]["ask_id"].(string)
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Alice", BindCode: code, Text: "ok", ReplyToAsk: askID}); err != nil {
		t.Fatal(err)
	}
	if c := f.agent.called(opAgentSend); len(c) != 2 || c[1]["role"] != "r_aaaaaaaa" || c[1]["id"] != "rs-1" {
		t.Fatalf("reply: %v", c)
	}
	// An ask handed out for another role's binding can't be answered through this one.
	s.mu.Lock()
	s.asks["ask_x"] = askRef{device: b.Device, session: "rs-1", sister: "Alice", project: "p1", role: ""}
	s.mu.Unlock()
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Alice", BindCode: code, Text: "ok", ReplyToAsk: "ask_x"}); err == nil {
		t.Fatal("an ask of the legacy role was answered through a role binding")
	}
}

func TestLegacyBindingHasNoRole(t *testing.T) {
	f, s, _ := agentFixture(t)
	twoRoles(f)
	f.agent.mu.Lock()
	f.agent.sessions = map[string][]agentSess{"p1": {{ID: "s-1", Mode: "default"}}}
	f.agent.mu.Unlock()
	code := agentBind(t, f, s, "Alice", "s-1")
	if b := s.st.bindings()[0]; b.Role != "" {
		t.Fatalf("%+v", b)
	}
	if _, err := s.sendTool(context.Background(), f, sendIn{Sister: "Alice", BindCode: code, Text: "hi"}); err != nil {
		t.Fatal(err)
	}
	if c := f.agent.called(opAgentSend); len(c) != 1 || c[0]["role"] != nil {
		t.Fatalf("%v", c)
	}
}

func TestClearStaleApprovals(t *testing.T) {
	cur := &role{MCP: []roleMCP{{Name: "kept", Type: "stdio", Command: "x", Args: []string{"a"}, Approval: "apr_cur"}},
		Plugins: []rolePlugin{{Name: "p", Source: "s", Approval: "apr_cur"}}}
	next := &role{
		MCP: []roleMCP{{Name: "kept", Type: "stdio", Command: "x", Args: []string{"a"}, Approval: "apr_old"},
			{Name: "kept2", Type: "stdio", Command: "x", Args: []string{"b"}, Approval: "apr_old"},
			{Name: "kept", Type: "stdio", Command: "x", Args: []string{"changed"}, Approval: "apr_old"}},
		Plugins: []rolePlugin{{Name: "p", Source: "s", Approval: "apr_old"}, {Name: "q", Source: "s", Approval: "apr_old"}}}
	clearStaleApprovals(cur, next)
	if next.MCP[0].Approval != "apr_cur" || next.MCP[1].Approval != "" || next.MCP[2].Approval != "" {
		t.Fatalf("%+v", next.MCP)
	}
	if next.Plugins[0].Approval != "apr_cur" || next.Plugins[1].Approval != "" {
		t.Fatalf("%+v", next.Plugins)
	}
}
