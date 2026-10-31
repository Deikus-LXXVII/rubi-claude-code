package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRoleStartUnderTrustNeedsNoApproval(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	m := asMap(t)(s.roleStartTool(context.Background(), f, roleStartIn{roleWho: who(botA), Role: id, Prompt: "make the logo", Name: "logo work"}))
	if len(f.submits) != 0 || m["started"] != true || m["session_id"] != "s-new" || m["role"] != id || !strings.Contains(m["approval"].(string), "none needed") {
		t.Fatalf("%v submits %d", m, len(f.submits))
	}
	st := f.agent.called(opAgentStart)
	if len(st) != 1 || st[0]["role"] != id || st[0]["project"] != "p1" || st[0]["prompt"] != "make the logo" || st[0]["bot"] != botA || st[0]["mode"] != fr.current(id).DefaultMode {
		t.Fatalf("%v", st)
	}
	if r := f.agent.called(opAgentRename); len(r) != 1 || r[0]["name"] != "logo work" || r[0]["id"] != "s-new" {
		t.Fatalf("%v", r)
	}
	if a := auditsOf(f, auditMandateAll); len(a) != 1 || a[0]["action"] != "claude_code_role_start" {
		t.Fatalf("%v", a)
	}
}

func TestRoleStartAsksWithoutTheBotsTrust(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	trustBot(t, s, "bot-b", "p1")
	// bot-b's trust is not bot-a's: bot-c has none at all.
	m := asMap(t)(s.roleStartTool(context.Background(), f, roleStartIn{roleWho: who("bot-c"), Role: id, Prompt: "hello"}))
	sub := lastSubmit(t, f)
	if sub.Kind != kindStart || m["status"] != "awaiting_approval" || len(f.agent.called(opAgentStart)) != 0 {
		t.Fatalf("%v", m)
	}
	p := sub.Preview.(map[string]any)
	if p["role"] != "design" || p["role_id"] != id || p["bot"] != "bot-c" || p["first_message_from_bot"] != "hello" {
		t.Fatalf("%v", p)
	}
	b, _ := json.Marshal(sub.Payload)
	var tk startTicket
	_ = json.Unmarshal(b, &tk)
	if tk.Role != id || tk.Sister != "bot-c" || tk.Project != "p1" {
		t.Fatalf("%+v", tk)
	}
	res := asMap(t)(s.executeStart(context.Background(), f, tk))
	if st := f.agent.called(opAgentStart); len(st) != 1 || st[0]["role"] != id || res["role"] != id {
		t.Fatalf("%v %v", st, res)
	}
	if bs := s.st.bindings(); len(bs) != 1 || bs[0].Role != id || bs[0].SessionID != "s-new" {
		t.Fatalf("the Bot is not bound to the role's session: %+v", bs)
	}
	// The ordinary start carries no role.
	if tk2 := (startTicket{Sister: botA, Device: "dev_mac", Task: "x", Project: "p1", Mode: "default"}); true {
		asMap(t)(s.executeStart(context.Background(), f, tk2))
		if st := f.agent.called(opAgentStart); len(st) != 2 || st[1]["role"] != nil {
			t.Fatalf("%v", st)
		}
	}
}

func TestRoleStartNeverSkipsPromptsUnderTrust(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	asMap(t)(s.roleUpdateTool(context.Background(), f, roleUpdateIn{roleWho: who(botA), Role: id, DefaultMode: ptr("bypassPermissions")}))
	m := asMap(t)(s.roleStartTool(context.Background(), f, roleStartIn{roleWho: who(botA), Role: id, Prompt: "go"}))
	if lastSubmit(t, f).Kind != kindStart || len(f.agent.called(opAgentStart)) != 0 || m["status"] != "awaiting_approval" {
		t.Fatalf("%v", m)
	}
	// A looser mode than the ladder of the old tools ("auto") starts through the approval too.
	asMap(t)(s.roleUpdateTool(context.Background(), f, roleUpdateIn{roleWho: who(botA), Role: id, DefaultMode: ptr("auto")}))
	m = asMap(t)(s.roleStartTool(context.Background(), f, roleStartIn{roleWho: who(botA), Role: id, Prompt: "go"}))
	if m["started"] != true || f.agent.called(opAgentStart)[0]["mode"] != "auto" {
		t.Fatalf("%v", m)
	}
}

func TestRoleStartChecks(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	for name, in := range map[string]roleStartIn{
		"empty prompt": {roleWho: who(botA), Role: id, Prompt: "  "},
		"long prompt":  {roleWho: who(botA), Role: id, Prompt: strings.Repeat("x", maxStartTask+1)},
		"hidden text":  {roleWho: who(botA), Role: id, Prompt: "a​b"},
		"legacy role":  {roleWho: who(botA), Role: "p1", Prompt: "x"},
		"unknown role": {roleWho: who(botA), Role: "r_zzzzzzzz", Prompt: "x"},
		"bad name":     {roleWho: who(botA), Role: id, Prompt: "x", Name: strings.Repeat("n", 100)},
	} {
		if _, err := s.roleStartTool(context.Background(), f, in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	asMap(t)(s.roleArchiveTool(context.Background(), f, roleRefIn{who(botA), id}, true))
	if _, err := s.roleStartTool(context.Background(), f, roleStartIn{roleWho: who(botA), Role: id, Prompt: "x"}); err == nil || !strings.Contains(err.Error(), "archived") {
		t.Fatalf("%v", err)
	}
	if len(f.agent.called(opAgentStart)) != 0 {
		t.Fatal("started")
	}
}

// The approval is for the version of the role the user was shown: a role changed since then doesn't start.
func TestRoleStartPinsTheApprovedVersion(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	ctx := context.Background()
	m := asMap(t)(s.roleStartTool(ctx, f, roleStartIn{roleWho: who("bot-c"), Role: id, Prompt: "hello"}))
	if m["status"] != "awaiting_approval" {
		t.Fatalf("%v", m)
	}
	b, _ := json.Marshal(lastSubmit(t, f).Payload)
	var tk startTicket
	_ = json.Unmarshal(b, &tk)
	if tk.RoleVersion != 1 {
		t.Fatalf("%+v", tk)
	}
	// The owner loosens the mode before the user answers.
	asMap(t)(s.roleUpdateTool(ctx, f, roleUpdateIn{roleWho: who(botA), Role: id, DefaultMode: ptr("acceptEdits")}))
	if _, err := s.executeStart(ctx, f, tk); err == nil || !strings.Contains(err.Error(), "the role changed since you approved; ask again") {
		t.Fatalf("%v", err)
	}
	if len(f.agent.called(opAgentStart)) != 0 {
		t.Fatal("a session was started")
	}
	// Asked again, the new version starts. A ticket without a version is refused.
	asMap(t)(s.roleStartTool(ctx, f, roleStartIn{roleWho: who("bot-c"), Role: id, Prompt: "hello"}))
	b, _ = json.Marshal(lastSubmit(t, f).Payload)
	_ = json.Unmarshal(b, &tk)
	if tk.RoleVersion != 2 || tk.Mode != "acceptEdits" {
		t.Fatalf("%+v", tk)
	}
	bad := tk
	bad.RoleVersion = 0
	if _, err := s.executeStart(ctx, f, bad); err == nil {
		t.Fatal("a ticket without a version started")
	}
	asMap(t)(s.executeStart(ctx, f, tk))
	if len(f.agent.called(opAgentStart)) != 1 {
		t.Fatal("not started")
	}
}
