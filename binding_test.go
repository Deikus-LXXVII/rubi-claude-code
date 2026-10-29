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
	if _, err := s.bindTool(ctx, f, bindIn{Sister: "Citri", SessionID: "local_a"}); err != nil {
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
	code := res.(map[string]any)["bind_code"].(string)
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
	if _, err := s.bindTool(ctx, f, bindIn{Sister: "Other", SessionID: "cli-1"}); err == nil {
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
