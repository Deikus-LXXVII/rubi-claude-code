package main

import (
	"context"
	"fmt"
	"strings"
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

// The approval for an MCP server shows its type and the whole command line, so a change of the args alone is
// visible, and the reasons say the same.
func TestMCPApprovalShowsCommandAndArgs(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	set := func(args ...string) map[string]any {
		return asMap(t)(s.roleMCPSetTool(context.Background(), f, roleMCPSetIn{roleWho: who(botA), Role: id,
			MCP: []roleMCPIn{{Name: "docs", Type: "stdio", Command: "npx", Args: args}}}))
	}
	if m := set("-y", "@docs/server"); status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	p := lastSubmit(t, f).Preview.(map[string]any)
	if ch := fmt.Sprint(p["changes"]); !strings.Contains(ch, `docs: stdio npx "-y" "@docs/server"`) {
		t.Fatalf("changes: %s", ch)
	}
	if why := fmt.Sprint(p["why_you_are_asked"]); !strings.Contains(why, `adds the MCP server docs: stdio npx "-y" "@docs/server"`) {
		t.Fatalf("why: %s", why)
	}
	asMap(t)(s.executeRoleChange(context.Background(), f, lastTicket(t, f)))
	if len(fr.current(id).MCP) != 1 {
		t.Fatal("not applied")
	}
	// Same name, same command, other args: it must show, and it is a change of the server.
	if m := set("-y", "@evil/server"); status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	p = lastSubmit(t, f).Preview.(map[string]any)
	ch := fmt.Sprint(p["changes"])
	if !strings.Contains(ch, `-mcp docs: stdio npx "-y" "@docs/server"`) || !strings.Contains(ch, `+mcp docs: stdio npx "-y" "@evil/server"`) {
		t.Fatalf("changes: %s", ch)
	}
	if why := fmt.Sprint(p["why_you_are_asked"]); !strings.Contains(why, `changes the MCP server docs: stdio npx "-y" "@evil/server"`) {
		t.Fatalf("why: %s", why)
	}
	// Long args are clipped one by one.
	set(strings.Repeat("x", 200))
	if ch := fmt.Sprint(lastSubmit(t, f).Preview.(map[string]any)["changes"]); strings.Contains(ch, strings.Repeat("x", 61)) {
		t.Fatalf("an arg is not clipped: %s", ch)
	}
}

// The headline of an approval starts with what widens, not with the pile of small changes before it.
func TestApprovalHeadlinePutsWideningFirst(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	var tools []string
	tools = append(tools, "Read", "Edit", "Write", "Glob", "Grep", "Bash", "Agent", "Skill", "WebFetch", "WebSearch", "CronCreate")
	m := asMap(t)(s.roleToolsSetTool(context.Background(), f, roleToolsSetIn{roleWho: who(botA), Role: id, Tools: &tools,
		Deny: &[]string{"Bash(git push:*)", "Bash(rm:*)", "Bash(curl:*)", "Bash(sudo:*)", "Bash(ssh:*)", "Bash(scp:*)", "Bash(dd:*)"}}))
	if status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	sub := lastSubmit(t, f)
	if !strings.Contains(sub.Summary, "adds the tool CronCreate") || strings.Index(sub.Summary, "CronCreate") > strings.Index(sub.Summary, "+tool Skill") {
		t.Fatalf("headline: %s", sub.Summary)
	}
	if ch := fmt.Sprint(sub.Preview.(map[string]any)["changes"]); !strings.Contains(ch, "+deny Bash(dd:*)") {
		t.Fatalf("the full list is in the preview: %s", ch)
	}
}
