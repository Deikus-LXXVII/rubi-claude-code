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

func startFixture(t *testing.T) (*fakeHost, *sisters) {
	t.Helper()
	f := &fakeHost{devices: []rubiplugin.HomeDevice{mac}, sessions: []session{mainSess}}
	s := newSisters(&store{})
	if err := s.st.load(f); err != nil {
		t.Fatal(err)
	}
	return f, s
}

func ticketOf(t *testing.T, f *fakeHost) startTicket {
	t.Helper()
	last := f.submits[len(f.submits)-1]
	if last.Kind != kindStart {
		t.Fatalf("kind %q", last.Kind)
	}
	raw, _ := json.Marshal(last.Payload)
	var tk startTicket
	if err := json.Unmarshal(raw, &tk); err != nil {
		t.Fatal(err)
	}
	return tk
}

func TestStartAsksPlainly(t *testing.T) {
	f, s := startFixture(t)
	res, err := s.startTool(context.Background(), f, startIn{VerifiedAgent: "Citri", Cwd: "/Users/v/newproj", Task: "Please run the tests & report"})
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]any)["status"] != "awaiting_approval" || len(f.submits) != 1 {
		t.Fatalf("%v %d", res, len(f.submits))
	}
	r := f.submits[0]
	raw, _ := json.Marshal(r.Preview)
	text := string(raw)
	for _, want := range []string{
		"Starts a NEW Claude Code session on Mac in /Users/v/newproj", "Please run the tests & report", "from Citri", "not yours",
		"bypassPermissions", "can run any command there without asking", "Rubi's reference for this request: <code>", "--- message from Citri ---", "first_message_from_bot", "Rubi approvals don't apply", "Citri is bound",
	} {
		if !strings.Contains(strings.NewReplacer(`\u0026`, "&", `\u003c`, "<", `\u003e`, ">").Replace(text), want) {
			t.Errorf("approval text lacks %q:\n%s", want, text)
		}
	}
	if !strings.Contains(r.Summary, "Mac") || !strings.Contains(r.Summary, "Citri") || len(f.creates) != 0 {
		t.Fatalf("summary %q, creates %d (nothing may start before the approval)", r.Summary, len(f.creates))
	}
	if tk := ticketOf(t, f); tk.Sister != "Citri" || tk.Device != "dev_mac" || tk.Cwd != "/Users/v/newproj" || tk.Task != "Please run the tests & report" {
		t.Fatalf("%+v", tk)
	}
	// The manifest asks for the strongest, locked approval.
	for _, a := range manifest().Actions {
		if a.Kind == kindStart && (a.DefaultLevel != rubiplugin.Strong || !a.Locked) {
			t.Fatalf("action %+v", a)
		}
	}
	if !slices.Contains(manifest().Home, "claude-start") || opCreate != "claude-start.create" {
		t.Fatalf("the manifest must declare the claude-start capability: %v", manifest().Home)
	}
}

func TestStartChecksItsInput(t *testing.T) {
	f, s := startFixture(t)
	ctx := context.Background()
	ok := startIn{VerifiedAgent: "Citri", Cwd: "/w", Task: "x"}
	for name, in := range map[string]startIn{
		"unverified": {Cwd: "/w", Task: "x"},
		"no task":    {VerifiedAgent: "Citri", Cwd: "/w", Task: "  "},
		"long task":  {VerifiedAgent: "Citri", Cwd: "/w", Task: strings.Repeat("x", maxStartTask+1)},
		"relative":   {VerifiedAgent: "Citri", Cwd: "w", Task: "x"},
		"no cwd":     {VerifiedAgent: "Citri", Task: "x"},
		"control":    {VerifiedAgent: "Citri", Cwd: "/w\n", Task: "x"},
		"no device":  {VerifiedAgent: "Citri", Cwd: "/w", Task: "x", Device: "Nope"},
		"zero width": {VerifiedAgent: "Citri", Cwd: "/w", Task: "run\u200B the tests"},
		"bidi":       {VerifiedAgent: "Citri", Cwd: "/w", Task: "a\u202Eb"},
		"tag chars":  {VerifiedAgent: "Citri", Cwd: "/w", Task: "a\U000E0041b"},
		"private":    {VerifiedAgent: "Citri", Cwd: "/w", Task: "a\ue000b"},
		"C1":         {VerifiedAgent: "Citri", Cwd: "/w", Task: "a\u0085b"},
		"escape":     {VerifiedAgent: "Citri", Cwd: "/w", Task: "a\x1b[0mb"},
		"blank run":  {VerifiedAgent: "Citri", Cwd: "/w", Task: "a\n\n\n\nb"},
		"many lines": {VerifiedAgent: "Citri", Cwd: "/w", Task: strings.Repeat("x\n", maxStartLines+1) + "x"},
	} {
		if _, err := s.startTool(ctx, f, in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if len(f.submits) != 0 {
		t.Fatalf("asked for approval anyway: %d", len(f.submits))
	}
	long := ok
	long.Task = strings.Repeat("é", maxStartTask)
	if _, err := s.startTool(ctx, f, long); err != nil {
		t.Fatalf("2000 characters: %v", err)
	}
	// Two computers need a choice.
	f.devices = []rubiplugin.HomeDevice{mac, {ID: "dev_pc", Name: "PC"}}
	if _, err := s.startTool(ctx, f, ok); err == nil || !strings.Contains(err.Error(), "which computer") {
		t.Fatalf("%v", err)
	}
	ok.Device = "PC"
	if _, err := s.startTool(ctx, f, ok); err != nil || ticketOf(t, f).Device != "dev_pc" {
		t.Fatalf("by name: %v", err)
	}
}

func TestStartIsRateLimitedPerBot(t *testing.T) {
	f, s := startFixture(t)
	for i := 0; i < startsPerHour; i++ {
		if _, err := s.startTool(context.Background(), f, startIn{VerifiedAgent: "Citri", Cwd: "/w", Task: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.startTool(context.Background(), f, startIn{VerifiedAgent: "citri", Cwd: "/w", Task: "x"}); err == nil {
		t.Fatal("no limit")
	}
	if _, err := s.startTool(context.Background(), f, startIn{VerifiedAgent: "Vega", Cwd: "/w", Task: "x"}); err != nil {
		t.Fatalf("another Bot: %v", err)
	}
	// Across Bots: 5 + 1 so far, 4 more fit, the next is refused whoever asks.
	for i := 0; i < startsGlobal-startsPerHour-1; i++ {
		if _, err := s.startTool(context.Background(), f, startIn{VerifiedAgent: "Bot" + string(rune('A'+i)), Cwd: "/w", Task: "x"}); err != nil {
			t.Fatalf("bot %d: %v", i, err)
		}
	}
	if _, err := s.startTool(context.Background(), f, startIn{VerifiedAgent: "Zed", Cwd: "/w", Task: "x"}); err == nil || !strings.Contains(err.Error(), "in all") {
		t.Fatalf("no global limit: %v", err)
	}
}

func approvedStart(t *testing.T, f *fakeHost, s *sisters) startTicket {
	t.Helper()
	if _, err := s.startTool(context.Background(), f, startIn{VerifiedAgent: "Citri", Cwd: "/Users/v/rubi", Task: "run the tests"}); err != nil {
		t.Fatal(err)
	}
	return ticketOf(t, f)
}

func TestStartBindsTheNewSession(t *testing.T) {
	f, s := startFixture(t)
	tk := approvedStart(t, f, s)
	f.createFn = func(_ context.Context, a map[string]any) (map[string]any, error) {
		return map[string]any{"launched": true, "session_id": "cli-1", "cwd": a["cwd"], "permission_mode": "bypassPermissions"}, nil
	}
	res, err := s.executeStart(context.Background(), f, tk)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.creates) != 1 || f.creates[0]["cwd"] != "/Users/v/rubi" || f.creates[0]["prompt"] != "run the tests" || f.creates[0]["from"] != "Citri" {
		t.Fatalf("create args %v", f.creates)
	}
	bs := s.st.bindings()
	if len(bs) != 1 || bs[0].Sister != "Citri" || bs[0].SessionID != "cli-1" || bs[0].AppSessionID != "local_a" || bs[0].RepoKey != "github.com/v/rubi" {
		t.Fatalf("binding %+v", bs)
	}
	ev := f.events[len(f.events)-1]
	if ev["_type"] != eventBound || ev["_agent"] != "Citri" || ev["bind_code"] != bs[0].Code {
		t.Fatalf("the code didn't go to the sister alone: %+v", ev)
	}
	// The approval's result is handed to whoever follows approvals: no code in it.
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), bs[0].Code) || strings.Contains(string(raw), `"bind_code"`) || strings.Contains(string(raw), "bc_") {
		t.Fatalf("the approval result carries the bind code: %s", raw)
	}
	m := res.(map[string]any)
	if m["started"] != true || m["bound"] != true || m["session_id"] != "cli-1" || m["warning"] != bypassPermsNote {
		t.Fatalf("result %v", m)
	}
	if got := boundCalls(f); !slices.Equal(got, []string{"Citri|cli-1|bound"}) {
		t.Fatalf("Rubi Home wasn't told: %v", got)
	}
	if !slices.Contains(f.audits, "session_started") || !slices.Contains(f.audits, "binding_created") {
		t.Fatalf("audits %v", f.audits)
	}
	// The bound Bot can send to it.
	if _, err := s.sendTool(context.Background(), f, sendIn{Sister: "Citri", BindCode: bs[0].Code, Text: "hi"}); err != nil {
		t.Fatal(err)
	}
}

func TestStartBindsEvenBeforeTheStoreKnowsTheSession(t *testing.T) {
	f, s := startFixture(t)
	f.sessions = nil // the desktop store hasn't picked it up yet
	tk := approvedStart(t, f, s)
	f.createFn = func(_ context.Context, a map[string]any) (map[string]any, error) {
		return map[string]any{"launched": true, "session_id": "cli-new", "cwd": a["cwd"], "permission_mode": "default"}, nil
	}
	res, err := s.executeStart(context.Background(), f, tk)
	if err != nil {
		t.Fatal(err)
	}
	bs := s.st.bindings()
	if len(bs) != 1 || bs[0].SessionID != "cli-new" || bs[0].Cwd != "/Users/v/rubi" || res.(map[string]any)["warning"] != nil {
		t.Fatalf("%+v %v", bs, res)
	}
}

func TestStartTimeoutLeavesNoBinding(t *testing.T) {
	f, s := startFixture(t)
	tk := approvedStart(t, f, s)
	f.createFn = func(_ context.Context, a map[string]any) (map[string]any, error) {
		return map[string]any{"launched": true, "session_id": "", "cwd": a["cwd"], "note": "launched, but no new session reported itself within 45 seconds"}, nil
	}
	n := len(f.events)
	res, err := s.executeStart(context.Background(), f, tk)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	next, _ := m["next_step"].(string)
	if m["started"] != true || m["bound"] != false || !strings.Contains(next, "claude_code_sessions") || !strings.Contains(next, "claude_code_bind") ||
		!strings.Contains(m["note"].(string), "no new session") {
		t.Fatalf("result %v", m)
	}
	if len(s.st.bindings()) != 0 || len(f.events) != n {
		t.Fatalf("bound without a session: %+v %d events", s.st.bindings(), len(f.events)-n)
	}
}

func TestStartFailuresAreReported(t *testing.T) {
	f, s := startFixture(t)
	tk := approvedStart(t, f, s)
	// An old Rubi Home.
	if _, err := s.executeStart(context.Background(), f, tk); err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("old home: %v", err)
	}
	// The helper refuses the directory.
	f.createFn = func(context.Context, map[string]any) (map[string]any, error) {
		return nil, &rubiplugin.Error{Code: rubiplugin.CodeHomeFailed, Message: "Mac: Rubi Home doesn't start sessions in that directory"}
	}
	if _, err := s.executeStart(context.Background(), f, tk); err == nil || !strings.Contains(err.Error(), "no session was started") || !strings.Contains(err.Error(), "doesn't start sessions") {
		t.Fatalf("refused: %v", err)
	}
	if len(s.st.bindings()) != 0 {
		t.Fatal("bound after a failure")
	}
	// The request went out and the connection dropped: the session may exist.
	f.createFn = func(context.Context, map[string]any) (map[string]any, error) {
		return nil, &rubiplugin.Error{Code: rubiplugin.CodeHomeOffline, Message: "Mac: Rubi Home didn't answer"}
	}
	if _, err := s.executeStart(context.Background(), f, tk); err == nil || !strings.Contains(err.Error(), "may have been started") || !strings.Contains(err.Error(), "check the Claude desktop app") {
		t.Fatalf("dropped call: %v", err)
	}
	if _, err := s.executeStart(context.Background(), f, startTicket{}); err == nil {
		t.Fatal("empty payload accepted")
	}
}

func TestStartKeepsTheSessionWhenTheCodeCantBeDelivered(t *testing.T) {
	f, s := startFixture(t)
	tk := approvedStart(t, f, s)
	f.createFn = func(_ context.Context, a map[string]any) (map[string]any, error) {
		return map[string]any{"launched": true, "session_id": "cli-1", "cwd": a["cwd"]}, nil
	}
	f.emitToErr = errors.New("no Bot named Citri is connected")
	res, err := s.executeStart(context.Background(), f, tk)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["started"] != true || m["bound"] != false || !strings.Contains(m["note"].(string), "started, but not bound") || len(s.st.bindings()) != 0 {
		t.Fatalf("%v %+v", m, s.st.bindings())
	}
}

func TestStartCallIsBounded(t *testing.T) {
	old := createTimeout
	createTimeout = 50 * time.Millisecond
	defer func() { createTimeout = old }()
	f, s := startFixture(t)
	tk := approvedStart(t, f, s)
	f.createFn = func(ctx context.Context, _ map[string]any) (map[string]any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	if _, err := s.executeStart(context.Background(), f, tk); err == nil || !strings.Contains(err.Error(), "may have been started") || time.Since(start) > 2*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
}
