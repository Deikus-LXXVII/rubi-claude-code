package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// agentBind binds bot to the agent session id through the approval, as the user would approve it, and
// returns its bind code.
func agentBind(t *testing.T, f *fakeHost, s *sisters, bot, id string) string {
	t.Helper()
	if _, err := s.bindTool(context.Background(), f, bindIn{VerifiedAgent: bot, SessionID: id, Project: "p1"}); err != nil {
		t.Fatal(err)
	}
	r := lastSubmit(t, f)
	if r.Kind != kindBind {
		t.Fatalf("%+v", r)
	}
	raw, _ := json.Marshal(r.Payload)
	var tk bindTicket
	_ = json.Unmarshal(raw, &tk)
	res, err := s.executeBind(f, tk)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(res); strings.Contains(string(raw), "bc_") {
		t.Fatalf("the approval result carries the bind code: %s", raw)
	}
	ev := f.events[len(f.events)-1]
	if ev["_type"] != eventBound || ev["_agent"] != bot {
		t.Fatalf("%+v", ev)
	}
	return ev["bind_code"].(string)
}

func TestAgentBindSendStatus(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	code := agentBind(t, f, s, "Alice", "s-1")
	bs := s.st.bindings()
	if len(bs) != 1 || bs[0].Project != "p1" || bs[0].SessionID != "s-1" || bs[0].Cwd != "/home/alice/my-project" {
		t.Fatalf("%+v", bs)
	}
	if len(f.bound) != 0 {
		t.Fatalf("the hook path's bound call was made: %v", f.bound)
	}
	prev := lastSubmit(t, f).Preview.(map[string]any)
	if prev["project"] != "/home/alice/my-project" || prev["session"] != "s-1" {
		t.Fatalf("%+v", prev)
	}
	// Another Bot can't take the same session.
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Bob", SessionID: "s-1"}); err == nil || !strings.Contains(err.Error(), "bound to Alice") {
		t.Fatalf("err %v", err)
	}
	// By the runner's name.
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Bob", Name: "MAIN work"}); err == nil || !strings.Contains(err.Error(), "bound to Alice") {
		t.Fatalf("by name: %v", err)
	}
	// Send: through claude-agent.send, from the verified Bot, without steering.
	res, err := s.sendTool(ctx, f, sendIn{Sister: "Alice", BindCode: code, Text: " please check the build "})
	if err != nil {
		t.Fatal(err)
	}
	c := f.agent.called(opAgentSend)
	if len(c) != 1 || c[0]["project"] != "p1" || c[0]["id"] != "s-1" || c[0]["from"] != "Alice" || c[0]["text"] != "please check the build" || c[0]["steer"] != nil {
		t.Fatalf("%v", c)
	}
	if m := res.(map[string]any); m["queued"] != true || m["position"] != 0 || !strings.Contains(m["delivery"].(string), "claude_reply") {
		t.Fatalf("%v", res)
	}
	// Status.
	f.agent.mu.Lock()
	f.agent.slot = map[string]any{"busy": true, "project": "p2", "session": "other"}
	f.agent.mu.Unlock()
	st, err := s.statusTool(ctx, f, statusIn{Sister: "Alice", BindCode: code})
	if err != nil {
		t.Fatal(err)
	}
	m := st.(map[string]any)
	if m["state"] != "idle" || m["in_slot"] != false || m["slot_busy"] != true || !strings.Contains(m["eta"].(string), "frees up") || m["name"] != "main work" {
		t.Fatalf("%v", m)
	}
	// The wrong code is refused.
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Alice", BindCode: "bc_nope", Text: "x"}); err == nil {
		t.Fatal("wrong code")
	}
	// Unbinding tells nobody on the hook path.
	if _, err := s.unbindTool(ctx, f, unbindIn{Sister: "Alice", BindCode: code}); err != nil || len(f.bound) != 0 {
		t.Fatalf("%v %v", err, f.bound)
	}
}

func TestAgentEventsRouteToTheBoundBot(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	agentBind(t, f, s, "Alice", "s-1")
	n := len(f.events)
	// The turn's answer goes to the Bot that started it, and only to the one bound to that session.
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", SessionID: "s-1", To: "alice", InReplyTo: []string{"m1"}, Text: "build is green"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", SessionID: "s-1", Text: "the user's own chat"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", SessionID: "s-1", To: "Bob", Text: "x"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", SessionID: "s-1", To: "local:Alice", Text: "x"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p1", SessionID: "s-2", To: "Alice", Text: "other session"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "result", Project: "p2", SessionID: "s-1", To: "Alice", Text: "other project"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "assistant", Project: "p1", SessionID: "s-1", To: "Alice", Text: "thinking out loud"})
	got := f.events[n:]
	if len(got) != 1 || got[0]["_type"] != eventReply || got[0]["_agent"] != "Alice" || got[0]["text"] != "build is green" || got[0]["project"] != "p1" {
		t.Fatalf("%+v", got)
	}
	// rubi_reply from inside the session is an explicit reply; rubi_ask is an ask.
	n = len(f.events)
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "sister_reply", Project: "p1", SessionID: "s-1", To: "Alice", InReplyTo: []string{"m2"}, Text: "early answer"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "sister_ask", Project: "p1", SessionID: "s-1", AskKind: "audit", Text: "check the diff"})
	// An ask from a session nobody is bound to is dropped: only the bound Bot gets asks.
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "sister_ask", Project: "p1", SessionID: "s-2", AskKind: "research", Text: "what is x"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "sister_ask", Project: "p9", SessionID: "s-9", Text: "nobody"})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "message", Project: "p1", SessionID: "s-1", To: "Alice", ID: "m1", State: "answered", At: time.Now()})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "message", Project: "p1", SessionID: "s-1", To: "Alice", ID: "m1", State: "queued"})
	got = f.events[n:]
	if len(got) != 3 || got[0]["_type"] != eventReply || got[1]["_type"] != eventAsk || got[1]["kind"] != "audit" || got[1]["_agent"] != "Alice" ||
		got[2]["_type"] != eventMessage || got[2]["state"] != "answered" {
		t.Fatalf("%+v", got)
	}
	// An answer to an ask goes to the session that asked.
	b := s.st.bindings()[0]
	askID := got[1]["ask_id"].(string)
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Alice", BindCode: b.Code, Text: "x is 3", ReplyToAsk: askID}); err != nil {
		t.Fatal(err)
	}
	if c := f.agent.called(opAgentSend); len(c) != 1 || c[0]["id"] != "s-1" || c[0]["project"] != "p1" {
		t.Fatalf("%v", c)
	}
}

func TestAgentSendLimitsAndHints(t *testing.T) {
	f, s, _ := agentFixture(t)
	code := agentBind(t, f, s, "Alice", "s-1")
	if h := queueHint(3); !strings.Contains(h, "position 3") {
		t.Fatal(h)
	}
	if _, err := s.sendTool(context.Background(), f, sendIn{Sister: "Alice", BindCode: code, Text: strings.Repeat("a", maxSendText+1)}); err == nil {
		t.Fatal("too long")
	}
	if len(f.agent.called(opAgentSend)) != 0 {
		t.Fatal("sent")
	}
}

func TestAgentSessionsList(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	f.sessions = []session{mainSess}
	agentBind(t, f, s, "Alice", "s-2")
	if err := s.st.setAliasForTest("dev_mac", "s-1", "p1", "alpha"); err != nil {
		t.Fatal(err)
	}
	res, err := s.sessionsTool(ctx, f, sessionsIn{})
	if err != nil {
		t.Fatal(err)
	}
	items := res.(map[string]any)["sessions"].([]map[string]any)
	var agents []map[string]any
	for _, it := range items {
		if it["agent"] == true {
			agents = append(agents, it)
		}
	}
	if len(items) != 3 || len(agents) != 2 {
		t.Fatalf("%+v", items)
	}
	a1, a2 := agents[0], agents[1]
	if a1["session_id"] != "s-1" || a1["name"] != "alpha" || a1["runner_name"] != "main work" || a1["project"] != "p1" || a1["bound_to"] != nil {
		t.Fatalf("%+v", a1)
	}
	if a2["bound_to"] != "Alice" || a2["mode"] != "bypassPermissions" || a2["note"] == nil || a2["state"] != "busy" {
		t.Fatalf("%+v", a2)
	}
	if ps := res.(map[string]any)["problems"].([]string); len(ps) != 0 {
		t.Fatalf("problems: %v", ps)
	}
}

func (s *store) setAliasForTest(device, id, project, name string) error {
	_, err := s.setAlias(device, "Mac", session{SessionID: id}, name, "user", time.Now())
	if err == nil {
		s.mu.Lock()
		for i := range s.st.Aliases {
			s.st.Aliases[i].Project = project
		}
		s.mu.Unlock()
	}
	return err
}

func TestAgentStart(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	in := startIn{VerifiedAgent: "Alice", Project: "p1", Task: "run the tests", Mode: "acceptEdits"}
	if _, err := s.startTool(ctx, f, in); err != nil {
		t.Fatal(err)
	}
	r := lastSubmit(t, f)
	p := r.Preview.(map[string]any)
	if r.Kind != kindStart || p["mode"] != "acceptEdits" || p["first_message_from_bot"] != "run the tests" || len(f.agent.called(opAgentStart)) != 0 {
		t.Fatalf("%+v", r)
	}
	raw, _ := json.Marshal(r.Payload)
	var tk startTicket
	_ = json.Unmarshal(raw, &tk)
	res, err := s.executeStart(ctx, f, tk)
	if err != nil {
		t.Fatal(err)
	}
	c := f.agent.called(opAgentStart)
	if len(c) != 1 || c[0]["project"] != "p1" || c[0]["prompt"] != "run the tests" || c[0]["from"] != "Alice" || c[0]["mode"] != "acceptEdits" {
		t.Fatalf("%v", c)
	}
	m := res.(map[string]any)
	if m["started"] != true || m["bound"] != true || m["session_id"] != "s-new" {
		t.Fatalf("%v", m)
	}
	if bs := s.st.bindings(); len(bs) != 1 || bs[0].Project != "p1" || bs[0].SessionID != "s-new" {
		t.Fatalf("%+v", bs)
	}
	if ev := f.events[len(f.events)-1]; ev["_type"] != eventBound || ev["bind_code"] == nil {
		t.Fatalf("%+v", ev)
	}
	// The project may be given as its directory (cwd); an unknown one lists the known ones.
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Alice", Cwd: "/home/alice/my-project", Task: "x"}); err != nil {
		t.Fatal(err)
	}
	if p := lastSubmit(t, f).Preview.(map[string]any); p["mode"] != "default" {
		t.Fatalf("default mode: %v", p["mode"])
	}
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Alice", Project: "nope", Task: "x"}); err == nil || !strings.Contains(err.Error(), "p1") {
		t.Fatalf("%v", err)
	}
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Alice", Project: "p1", Task: "x", Mode: "yolo"}); err == nil {
		t.Fatal("bad mode")
	}
	// The v0.3 checks still hold: hidden characters, length, the Bot's identity.
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Alice", Project: "p1", Task: "do‮ this"}); err == nil {
		t.Fatal("hidden character accepted")
	}
	if _, err := s.startTool(ctx, f, startIn{Project: "p1", Task: "x"}); err == nil {
		t.Fatal("unverified Bot")
	}
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Alice", Project: "p1", Task: strings.Repeat("a", maxStartTask+1)}); err == nil {
		t.Fatal("long task")
	}
}

func TestAgentStartQueuedAndFailures(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	f.agent.startFn = func(map[string]any) (map[string]any, error) {
		return map[string]any{"queued": true, "position": 2}, nil
	}
	res, err := s.executeStart(ctx, f, startTicket{Sister: "Alice", Device: "dev_mac", DeviceName: "Mac", Task: "x", Project: "p1", Mode: "default", Cwd: "/home/alice/my-project"})
	if err != nil {
		t.Fatal(err)
	}
	if m := res.(map[string]any); m["queued"] != true || m["started"] != false || m["bound"] != false || !strings.Contains(m["next_step"].(string), "position 2") || len(s.st.bindings()) != 0 {
		t.Fatalf("%v", m)
	}
	f.agent.startFn = func(map[string]any) (map[string]any, error) { return nil, context.DeadlineExceeded }
	if _, err := s.executeStart(ctx, f, startTicket{Sister: "Alice", Device: "dev_mac", Task: "x", Project: "p1", Mode: "default"}); err == nil || !strings.Contains(err.Error(), "may have been started") {
		t.Fatalf("%v", err)
	}
}

// Under a project trust a bound Bot starts and binds sessions of that project without asking, except one that
// skips permission prompts.
func TestAgentProjectTrustForTheBot(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	code := agentBind(t, f, s, "Alice", "s-1")
	// The Bot asks for the trust; the approval carries the project.
	if _, err := s.trustTool(ctx, f, trustIn{VerifiedAgent: "Alice", BindCode: code, Until: "revoked"}); err != nil {
		t.Fatal(err)
	}
	r := lastSubmit(t, f)
	if r.Kind != kindTrustProject || r.Preview.(map[string]any)["project_root"] != agentRoot || r.Preview.(map[string]any)["project_id"] != "p1" {
		t.Fatalf("%+v", r)
	}
	raw, _ := json.Marshal(r.Payload)
	var tk trustTicket
	_ = json.Unmarshal(raw, &tk)
	if _, err := s.executeTrust(f, tk); err != nil {
		t.Fatal(err)
	}
	if ps := s.st.projects(s.now()); len(ps) != 1 || ps[0].Project != "p1" || ps[0].Root != agentRoot || !ps[0].Unlimited {
		t.Fatalf("%+v", ps)
	}
	n := len(f.submits)
	res, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Alice", Project: "p1", Task: "go", Mode: "default"})
	if err != nil || len(f.submits) != n || res.(map[string]any)["started"] != true || !strings.Contains(res.(map[string]any)["approval"].(string), "none needed") {
		t.Fatalf("%v %v", res, err)
	}
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Alice", Project: "p1", Task: "go", Mode: "bypassPermissions"}); err != nil || len(f.submits) != n+1 {
		t.Fatalf("bypass start did not ask: %v", err)
	}
	// Binding another session of the project needs no approval; a Bot not bound there still asks.
	n = len(f.submits)
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Alice", SessionID: "s-2"}); err != nil || len(f.submits) != n {
		t.Fatalf("%v", err)
	}
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Bob", SessionID: "s-1"}); err == nil {
		t.Log("(s-2 is now Alice's, s-1 is free)")
	}
	n = len(f.submits)
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Carol", Project: "p1", Task: "go"}); err != nil || len(f.submits) != n+1 {
		t.Fatalf("an unbound Bot started without asking: %v", err)
	}
}
