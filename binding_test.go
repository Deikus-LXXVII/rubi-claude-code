package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

var mainSess = session{SessionID: "cli-1", AppSessionID: "local_a", Title: "Rubi main", Cwd: "/Users/v/rubi", RepoKey: "github.com/v/rubi", Role: "main", Source: "desktop", PermissionMode: "default", State: "idle"}
var subSess = session{SessionID: "cli-2", AppSessionID: "local_b", Title: "Rubi sub", Cwd: "/Users/v/rubi/.claude/worktrees/x", RepoKey: "github.com/v/rubi", Role: "sub", Parent: "local_a", Source: "desktop", State: "busy"}
var otherSess = session{SessionID: "cli-3", Title: "Other", Cwd: "/Users/v/other", RepoKey: "github.com/v/other", Role: "main", Source: "transcript", PermissionMode: "bypassPermissions", State: "idle"}

func boundFixture(t *testing.T) (*fakeHost, *sisters, string) {
	t.Helper()
	f := &fakeHost{devices: []rubiplugin.HomeDevice{mac}, sessions: []session{mainSess, subSess, otherSess}}
	s := newSisters(&store{})
	if err := s.st.load(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: "local_a"}); err != nil {
		t.Fatal(err)
	}
	if len(f.submits) != 1 || f.submits[0].Kind != kindBind {
		t.Fatalf("bind didn't ask for approval: %+v", f.submits)
	}
	raw, _ := json.Marshal(f.submits[0].Payload)
	var tk bindTicket
	_ = json.Unmarshal(raw, &tk)
	res, err := s.executeBind(f, tk)
	if err != nil {
		t.Fatal(err)
	}
	// The approval's result goes to whoever follows approvals: the code must never be in it.
	if raw, _ := json.Marshal(res); strings.Contains(string(raw), "bc_") || strings.Contains(string(raw), `"bind_code"`) {
		t.Fatalf("the approval result carries the bind code: %s", raw)
	}
	ev := f.events[len(f.events)-1]
	if ev["_type"] != eventBound || ev["_agent"] != "Citri" {
		t.Fatalf("the code didn't go to the sister alone: %+v", ev)
	}
	code := ev["bind_code"].(string)
	return f, s, code
}

func TestBindSendRoute(t *testing.T) {
	f, s, code := boundFixture(t)
	ctx := context.Background()
	if f.events[0]["_type"] != eventBound || f.events[0]["_agent"] != "Citri" || f.events[0]["bind_code"] != code {
		t.Fatalf("bound event: %+v", f.events[0])
	}
	// The binding is saved and survives a restart.
	s2 := newSisters(&store{})
	if err := s2.st.load(f); err != nil || len(s2.st.bindings()) != 1 {
		t.Fatalf("saved bindings: %v %+v", err, s2.st.bindings())
	}

	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: "wrong", Text: "hi"}); err == nil {
		t.Fatal("send with a wrong code went through")
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Other", BindCode: code, Text: "hi"}); err == nil {
		t.Fatal("another Bot sent with the code")
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: strings.Repeat("x", maxSendText+1)}); err == nil {
		t.Fatal("bulky text went through")
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: "audit done: 2 findings"}); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 1 || f.sent[0]["session_id"] != "cli-1" || f.sent[0]["from"] != "Citri" {
		t.Fatalf("sent: %+v", f.sent)
	}

	// The app restarted the session under a new Claude Code id: the binding follows the app id.
	f.mu.Lock()
	f.sessions[0].SessionID = "cli-1b"
	f.mu.Unlock()
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: "again"}); err != nil {
		t.Fatal(err)
	}
	if f.sent[1]["session_id"] != "cli-1b" || !slices.Contains(f.audits, "binding_followed") {
		t.Fatalf("binding didn't follow: %+v %v", f.sent[1], f.audits)
	}

	n := len(f.events)
	s.route(ctx, f, mac, outMsg{ID: "o1", Kind: "reply", SessionID: "cli-1b", To: "Citri", Text: "thanks, fixed"})
	s.route(ctx, f, mac, outMsg{ID: "o2", Kind: "reply", SessionID: "cli-1b", To: "Mallory", Text: "x"})
	s.route(ctx, f, mac, outMsg{ID: "o3", Kind: "reply", SessionID: "cli-3", To: "Citri", Text: "x"})
	got := f.events[n:]
	if len(got) != 1 || got[0]["_type"] != eventReply || got[0]["_agent"] != "Citri" || got[0]["text"] != "thanks, fixed" {
		t.Fatalf("replies routed: %+v", got)
	}

	// A sub-session of the same project asks; the answer goes back to it.
	s.route(ctx, f, mac, outMsg{ID: "o4", Kind: "ask", SessionID: "cli-2", AskKind: "research", Text: "latest x?"})
	s.route(ctx, f, mac, outMsg{ID: "o5", Kind: "ask", SessionID: "cli-3", AskKind: "research", Text: "other project"})
	got = f.events[n+1:]
	if len(got) != 1 || got[0]["_type"] != eventAsk || got[0]["role"] != "sub" {
		t.Fatalf("asks routed: %+v", got)
	}
	askID := got[0]["ask_id"].(string)
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: "v2", ReplyToAsk: askID}); err != nil {
		t.Fatal(err)
	}
	if f.sent[2]["session_id"] != "cli-2" {
		t.Fatalf("answer went to %v", f.sent[2]["session_id"])
	}
}

func TestBindOneBotPerSession(t *testing.T) {
	f, s, code := boundFixture(t)
	ctx := context.Background()
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Other", SessionID: "cli-1"}); err == nil {
		t.Fatal("a second Bot could ask to bind the same session")
	}
	if _, err := s.unbindTool(ctx, f, unbindIn{Sister: "Citri", BindCode: "nope"}); err == nil {
		t.Fatal("unbind without the code")
	}
	if _, err := s.unbindTool(ctx, f, unbindIn{Sister: "Citri", BindCode: code}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: "hi"}); err == nil {
		t.Fatal("sent after unbinding")
	}
}

func TestSessionsTool(t *testing.T) {
	f, s, _ := boundFixture(t)
	out, err := s.sessionsTool(context.Background(), f, sessionsIn{})
	if err != nil {
		t.Fatal(err)
	}
	items := out.(map[string]any)["sessions"].([]map[string]any)
	if len(items) != 3 || items[0]["bound_to"] != "Citri" || items[1]["bound_to"] != nil || items[2]["note"] != bypassPermsNote {
		t.Fatalf("sessions: %+v", items)
	}
}

func TestSendRateLimit(t *testing.T) {
	f, s, code := boundFixture(t)
	for i := range sendsPerHour {
		if _, err := s.sendTool(context.Background(), f, sendIn{Sister: "Citri", BindCode: code, Text: "x"}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if _, err := s.sendTool(context.Background(), f, sendIn{Sister: "Citri", BindCode: code, Text: "x"}); err == nil {
		t.Fatal("no rate limit")
	}
}

// A trusted session's plain command is allowed by the plugin itself and audited; push still asks.
func TestWatcherMandate(t *testing.T) {
	f := &fakeHost{devices: []rubiplugin.HomeDevice{mac}, states: []string{"pending"}}
	s := newSisters(&store{})
	_ = s.st.load(f)
	r := newRequest("go test ./...")
	tk, _ := json.Marshal(ticket{Device: mac.ID, ID: r.ID, SessionID: r.SessionID, Digest: r.Digest, Cwd: r.Cwd})
	res, err := runApproved(context.Background(), f, s, optionTrust, tk)
	if err != nil || res.(map[string]any)["trusted"] != true {
		t.Fatalf("trust: %v %+v", err, res)
	}
	w := newWatcher(f, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r2 := newRequest("go vet ./... && go test -race ./...")
	r2.ID = "cc_2"
	r2.Cwd += "/internal"
	w.handle(ctx, mac, r2)
	if len(f.submits) != 0 || len(f.decided) != 2 || f.decided[1].Behavior != "allow" || f.decided[1].ID != "cc_2" {
		t.Fatalf("not auto-allowed: submits %d, decided %+v", len(f.submits), f.decided)
	}
	if !slices.Contains(f.audits, auditMandateAll) {
		t.Fatalf("not audited: %v", f.audits)
	}

	for i, c := range []string{"git push", "ls && git push --force", "sudo make"} {
		r3 := newRequest(c)
		r3.ID = "cc_p" + string(rune('0'+i))
		ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
		w.handle(ctx2, mac, r3)
		cancel2()
	}
	if len(f.submits) != 3 || len(f.decided) < 2 {
		t.Fatalf("refused commands didn't ask: %d submits", len(f.submits))
	}
	for _, d := range f.decided[2:] {
		if d.Behavior == "allow" {
			t.Fatalf("refused command allowed: %+v", d)
		}
	}
	if p := f.submits[0].Preview.(map[string]any); p["mandate"] == nil {
		t.Fatalf("no mandate note: %+v", p)
	}

	// Another session isn't covered.
	r4 := newRequest("go test ./...")
	r4.SessionID = "sess-2"
	ctx3, cancel3 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	w.handle(ctx3, mac, r4)
	cancel3()
	if len(f.submits) != 4 {
		t.Fatal("another session was auto-allowed")
	}

	// Revoked: asks again.
	if n, _ := s.st.revoke("all"); n != 1 {
		t.Fatalf("revoked %d", n)
	}
	ctx4, cancel4 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	w.handle(ctx4, mac, r2)
	cancel4()
	if len(f.submits) != 5 {
		t.Fatal("revoked mandate still allowed")
	}
}

func TestPanel(t *testing.T) {
	f, s, _ := boundFixture(t)
	now := time.Now()
	_ = s.st.issue(mandate{ID: "md_x", Device: mac.ID, SessionID: "s", Cwd: "/p", Expires: now.Add(time.Hour), MaxUses: 5}, now)
	v, err := s.panel(f, "view", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), "md_x") || !strings.Contains(string(b), "Citri") {
		t.Fatalf("view: %s", b)
	}
	if _, err := s.panel(f, "revoke", json.RawMessage(`{"id":"md_x"}`)); err != nil || len(s.st.mandates(now)) != 0 {
		t.Fatal("revoke from the panel failed")
	}
	if _, err := s.panel(f, "unbind", json.RawMessage(`{"sister":"Citri"}`)); err != nil || len(s.st.bindings()) != 0 {
		t.Fatal("unbind from the panel failed")
	}
}

// The binding is made for the Bot Rubi verified, never for a name the caller typed; a call Rubi verified
// as another Bot can't use someone else's binding.
func TestBindNeedsTheVerifiedBot(t *testing.T) {
	f, s, code := boundFixture(t)
	ctx := context.Background()
	n := len(f.submits)
	if _, err := s.bindTool(ctx, f, bindIn{Agent: "Mallory", SessionID: "cli-3"}); err == nil || !strings.Contains(err.Error(), "rubi_agent_code") {
		t.Fatalf("a self-declared name bound: %v", err)
	}
	if len(f.submits) != n {
		t.Fatal("an unverified bind asked the user")
	}
	if _, err := s.bindTool(ctx, f, bindIn{Agent: "Mallory", VerifiedAgent: "Vega", SessionID: "cli-3"}); err != nil {
		t.Fatal(err)
	}
	var tk bindTicket
	raw, _ := json.Marshal(f.submits[len(f.submits)-1].Payload)
	_ = json.Unmarshal(raw, &tk)
	if tk.Sister != "Vega" || f.submits[len(f.submits)-1].Preview.(map[string]any)["bot"] != "Vega" {
		t.Fatalf("bound for %q, not the verified Bot", tk.Sister)
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: "hi", VerifiedAgent: "Vega"}); err == nil {
		t.Fatal("another verified Bot used Citri's binding")
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: "hi", VerifiedAgent: "citri"}); err != nil {
		t.Fatalf("the binding's own Bot: %v", err)
	}
	if _, err := s.unbindTool(ctx, f, unbindIn{Sister: "Citri", BindCode: code, VerifiedAgent: "Vega"}); err == nil {
		t.Fatal("another verified Bot unbound Citri")
	}
}

// Session messages come through their own poll (claude-sessions.next), not with permission requests.
func TestWatcherPollsSessionsSeparately(t *testing.T) {
	f, s, _ := boundFixture(t)
	f.mu.Lock()
	f.outs = []outMsg{{ID: "o1", Kind: "reply", SessionID: "cli-1", To: "Citri", Text: "done"}}
	f.next = func(ctx context.Context, _ string) (*request, error) { <-ctx.Done(); return nil, ctx.Err() }
	n := len(f.events)
	f.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { newWatcher(f, s).run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		got := len(f.events) > n
		f.mu.Unlock()
		if got || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) <= n || f.events[n]["_type"] != eventReply || f.events[n]["_agent"] != "Citri" {
		t.Fatalf("reply not routed: %+v", f.events[n:])
	}
	if !slices.Contains(f.ops, "claude.next") || !slices.Contains(f.ops, "claude-sessions.next") {
		t.Fatalf("ops: %v", f.ops)
	}
}

// A computer whose Rubi Home doesn't answer the list becomes a problem in the answer, in time.
func TestSessionsToolStuckComputer(t *testing.T) {
	old := listTimeout
	listTimeout = 50 * time.Millisecond
	defer func() { listTimeout = old }()
	f, s, _ := boundFixture(t)
	f.listHang = true
	start := time.Now()
	out, err := s.sessionsTool(context.Background(), f, sessionsIn{})
	if err != nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
	probs := out.(map[string]any)["problems"].([]string)
	if len(probs) != 1 || !strings.Contains(probs[0], "no session list within") {
		t.Fatalf("problems: %v", probs)
	}
}

// TestBindUndoneWhenTheCodeCantBeDelivered: when the addressed claude_bound event can't reach the
// sister, the binding isn't made (or the earlier one stays) and the error carries no code.
func TestBindUndoneWhenTheCodeCantBeDelivered(t *testing.T) {
	f, s, code := boundFixture(t)
	ctx := context.Background()
	f.mu.Lock()
	f.emitToErr = errors.New("no Bot named Citri is connected")
	f.mu.Unlock()
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: "cli-3"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.submits[len(f.submits)-1].Payload)
	var tk bindTicket
	_ = json.Unmarshal(raw, &tk)
	res, err := s.executeBind(f, tk)
	if err == nil || res != nil || strings.Contains(err.Error(), "bc_") {
		t.Fatalf("undelivered bind: %v %v", res, err)
	}
	bs := s.st.bindings()
	if len(bs) != 1 || bs[0].SessionID != "cli-1" || bs[0].Code != code || !slices.Contains(f.audits, "binding_undone") {
		t.Fatalf("the earlier binding should stay: %+v %v", bs, f.audits)
	}

	// A first binding that can't be delivered leaves nothing behind.
	if _, err := s.unbindTool(ctx, f, unbindIn{Sister: "Citri", BindCode: code, VerifiedAgent: "Citri"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.executeBind(f, tk); err == nil || len(s.st.bindings()) != 0 {
		t.Fatalf("a binding without a delivered code was kept: %v %+v", err, s.st.bindings())
	}
}

// TestSendSaysWhenClaudeReads: claude_code_send reports the session's state and when Claude is likely
// to read the message; a message to an ended session isn't queued at all.
func TestSendSaysWhenClaudeReads(t *testing.T) {
	f, s, code := boundFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	set := func(state string, last time.Time) {
		f.mu.Lock()
		f.sessions[0].State, f.sessions[0].LastActivity = state, last
		f.mu.Unlock()
	}
	send := func() map[string]any {
		t.Helper()
		res, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: "hi"})
		if err != nil {
			t.Fatal(err)
		}
		return res.(map[string]any)
	}

	set("idle", now.Add(-30*time.Minute))
	r := send()
	if r["session_state"] != "idle" || !strings.Contains(r["delivery"].(string), "idle for 30m") ||
		!strings.Contains(r["delivery"].(string), "next prompts it") || r["last_activity"] != "2026-10-30T11:30:00Z" {
		t.Fatalf("idle: %+v", r)
	}
	set("busy", now.Add(-time.Minute))
	if r := send(); r["session_state"] != "busy" || !strings.Contains(r["delivery"].(string), "next stop") {
		t.Fatalf("busy: %+v", r)
	}
	set("unknown", time.Time{})
	if r := send(); r["session_state"] != "unknown" || r["last_activity"] != nil || !strings.Contains(r["delivery"].(string), "doesn't know") {
		t.Fatalf("unknown: %+v", r)
	}
	n := len(f.sent)
	set("ended", now.Add(-time.Hour))
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: code, Text: "hi"}); err == nil || !strings.Contains(err.Error(), "ended") || len(f.sent) != n {
		t.Fatalf("ended session: %v, sent %d", err, len(f.sent)-n)
	}
}

// TestSisterNameIgnoresCase: Rubi's Bot names don't depend on case, so "citri" uses Citri's binding;
// the code is still what proves it, and another name is still another Bot.
func TestSisterNameIgnoresCase(t *testing.T) {
	f, s, code := boundFixture(t)
	ctx := context.Background()
	for _, name := range []string{"citri", " CITRI "} {
		if _, err := s.sendTool(ctx, f, sendIn{Sister: name, BindCode: code, Text: "hi", VerifiedAgent: "Citri"}); err != nil {
			t.Fatalf("%q: %v", name, err)
		}
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "citri", BindCode: "bc_wrong", Text: "hi"}); err == nil {
		t.Fatal("a wrong code went through")
	}
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citrine", BindCode: code, Text: "hi"}); err == nil {
		t.Fatal("another Bot's name went through")
	}
	if _, err := s.unbindTool(ctx, f, unbindIn{Sister: "CITRI", BindCode: code, VerifiedAgent: "citri"}); err != nil || len(s.st.bindings()) != 0 {
		t.Fatalf("unbind by another case: %v %+v", err, s.st.bindings())
	}
}

// bindAs binds bot to a session through the approval, as the user would approve it.
func bindAs(t *testing.T, f *fakeHost, s *sisters, bot, sessionID string) {
	t.Helper()
	if _, err := s.bindTool(context.Background(), f, bindIn{VerifiedAgent: bot, SessionID: sessionID}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.submits[len(f.submits)-1].Payload)
	var tk bindTicket
	_ = json.Unmarshal(raw, &tk)
	if _, err := s.executeBind(f, tk); err != nil {
		t.Fatal(err)
	}
}

// TestAskFromUnboundSessionPicksOneBinding: an ask from an unbound session of a project with several
// bound sessions goes to the Bot of its parent session, else to the Bot of the main session, not to
// whichever binding happens to be last.
func TestAskFromUnboundSessionPicksOneBinding(t *testing.T) {
	f, s, _ := boundFixture(t) // Citri: the main session local_a
	ctx := context.Background()
	later := time.Now().Add(time.Hour)
	s.now = func() time.Time { return later }
	bindAs(t, f, s, "Vega", "local_b") // Vega: the sub-session, bound later
	orphan := session{SessionID: "cli-5", Title: "loose", Cwd: "/Users/v/rubi/tmp", RepoKey: "github.com/v/rubi", Role: "sub", Source: "transcript", State: "busy"}
	child := session{SessionID: "cli-6", Title: "child of sub", Cwd: "/Users/v/rubi/.claude/worktrees/y", RepoKey: "github.com/v/rubi", Role: "sub", Parent: "local_b", Source: "transcript", State: "busy"}
	f.mu.Lock()
	f.sessions = append(f.sessions, orphan, child)
	f.mu.Unlock()

	n := len(f.events)
	s.route(ctx, f, mac, outMsg{ID: "a1", Kind: "ask", SessionID: "cli-5", AskKind: "research", Text: "q1"})
	s.route(ctx, f, mac, outMsg{ID: "a2", Kind: "ask", SessionID: "cli-6", AskKind: "research", Text: "q2"})
	got := f.events[n:]
	if len(got) != 2 || got[0]["_agent"] != "Citri" || got[1]["_agent"] != "Vega" {
		t.Fatalf("asks went to: %+v", got)
	}
}
