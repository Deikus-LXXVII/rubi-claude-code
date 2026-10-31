package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

// fakeSetup plays the agent-setup operations of Rubi Home.
type fakeSetup struct {
	mu     sync.Mutex
	status map[string]any
	calls  []fakeCall
	failOp map[string]error
}

func (f *fakeSetup) called(op string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, c := range f.calls {
		if c.op == op {
			out = append(out, c.args)
		}
	}
	return out
}

func (f *fakeSetup) call(op string, args, out any) error {
	m := map[string]any{}
	if args != nil {
		b, _ := json.Marshal(args)
		_ = json.Unmarshal(b, &m)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{op, m})
	if err := f.failOp[op]; err != nil {
		return err
	}
	var v any = map[string]any{"started": true}
	if op == opSetupStatus {
		v = f.status
	}
	if out == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, out)
}

func step(id, state, reason, action string, extra map[string]any) map[string]any {
	m := map[string]any{"id": id, "state": state, "reason": reason}
	if action != "" {
		m["action"] = action
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func row(state, reason, action string) map[string]any {
	m := map[string]any{"dir": "/home/alice/my-project", "id": "p1", "state": state}
	if reason != "" {
		m["reason"] = reason
	}
	if action != "" {
		m["action"] = action
	}
	return m
}

// allDone is a status in Rubi Home's shape: steps 1 to 5 done, the project not signed in and not tested.
func allDone(extra ...map[string]any) map[string]any {
	steps := []map[string]any{step("container", "done", "Installed 1.2", "", nil), step("service", "done", "Running", "", nil), step("network", "done", "Host-only", "", nil),
		step("image", "done", "Built", "", nil), step("projects", "done", "1 folder", "add", map[string]any{"projects": []any{row("done", "", "remove")}}),
		step("login", "needs_user", "Not signed in", "", map[string]any{"projects": []any{row("needs_user", "Not signed in", "login")}}),
		step("selftest", "todo", "Not run", "", map[string]any{"projects": []any{row("todo", "Not run", "selftest")}})}
	st := map[string]any{"steps": steps}
	for _, e := range extra {
		for k, v := range e {
			st[k] = v
		}
	}
	return st
}

func setupFixture(t *testing.T, st map[string]any) (*fakeHost, *sisters) {
	t.Helper()
	f, s, _ := agentFixture(t)
	f.setup = &fakeSetup{status: st}
	return f, s
}

func allActions(page map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, sec := range page["sections"].([]map[string]any) {
		sa, _ := sec["actions"].([]map[string]any)
		for _, a := range sa {
			out[a["label"].(string)] = a
		}
		its, _ := sec["items"].([]map[string]any)
		for _, it := range its {
			as, _ := it["actions"].([]map[string]any)
			for _, a := range as {
				out[a["label"].(string)] = a
			}
		}
	}
	return out
}

func setupView(t *testing.T, s *sisters, f *fakeHost) map[string]any {
	t.Helper()
	return view(t, s, f, `{"page":"setup","device":"dev_mac"}`)
}

func TestSetupEntryNeedsCapability(t *testing.T) {
	f, s, _ := agentFixture(t)
	for _, sec := range view(t, s, f, `{}`)["sections"].([]map[string]any) {
		if sec["title"] == "First-time setup" {
			t.Fatal("entry without the capability")
		}
	}
	f.setup = &fakeSetup{status: allDone()}
	s = newSisters(&store{})
	_ = s.st.load(f)
	main := view(t, s, f, `{}`)
	secs := main["sections"].([]map[string]any)
	if secs[0]["title"] != "Claude in project VMs" || secs[1]["title"] != "First-time setup" {
		t.Fatalf("%v", secs)
	}
	open := items(t, main, 1)[0]["actions"].([]map[string]any)[0]["open"].(map[string]any)
	if open["page"] != "setup" || open["device"] != "dev_mac" {
		t.Fatalf("%v", open)
	}
	// The setup page of a computer without it is an error.
	f.setup = nil
	s = newSisters(&store{})
	if _, err := s.panel(context.Background(), f, "view", json.RawMessage(`{"page":"setup","device":"dev_mac"}`)); err == nil {
		t.Error("page without the capability")
	}
}

func TestSetupPageStates(t *testing.T) {
	// Nothing done: only the first step has a button, the rest wait for it.
	st := map[string]any{"steps": []any{step("container", "todo", "Not installed", "install", nil), step("service", "todo", "Needs step 1 first", "", nil),
		step("network", "todo", "Needs step 1 first", "", nil), step("image", "todo", "Needs step 2 first", "", nil), step("projects", "todo", "No folder", "", nil),
		step("login", "todo", "Needs step 5 first", "", nil), step("selftest", "todo", "Needs step 6 first", "", nil)}}
	f, s := setupFixture(t, st)
	pg := setupView(t, s, f)
	if _, r := pg["refresh"]; r {
		t.Error("refresh while idle")
	}
	a := allActions(pg)
	for _, want := range []string{"Install", "Refresh"} {
		if a[want] == nil {
			t.Errorf("no %q", want)
		}
	}
	for _, no := range []string{"Start", "Create", "Build", "Add a folder", "Set up everything", "Cancel", "Run self-test"} {
		if a[no] != nil {
			t.Errorf("%q shown", no)
		}
	}
	// Failed and needs_user are warned; an upgrade offered on a done step.
	st = allDone()
	steps := st["steps"].([]map[string]any)
	steps[1] = step("service", "failed", "Didn't start", "start", nil)
	steps[0] = step("container", "done", "Old", "upgrade", nil)
	steps[3] = step("image", "needs_user", "Do something", "build", nil)
	steps[2] = step("network", "failed", "Proxy address set", "use_auto_address", nil)
	f, s = setupFixture(t, st)
	pg = setupView(t, s, f)
	secs := pg["sections"].([]map[string]any)
	if secs[2]["items"].([]map[string]any)[0]["warn"] != true || secs[4]["items"].([]map[string]any)[0]["warn"] != true {
		t.Error("no warn on failed/needs_user")
	}
	a = allActions(pg)
	if a["Upgrade"] == nil || a["Start"] == nil || a["Build"] == nil || a["Use the automatic address"] == nil || a["Set up everything"] != nil {
		t.Fatalf("%v", a)
	}
	// All done: sign-in buttons per project, self-test, no step buttons but Add a folder.
	f, s = setupFixture(t, allDone())
	a = allActions(setupView(t, s, f))
	if a["Sign in with a Claude subscription"] == nil || a["Sign in with an Anthropic Console account"] == nil || a["Run self-test"] == nil || a["Remove"] == nil || a["Add a folder"] == nil || a["Set up everything"] == nil {
		t.Fatalf("%v", a)
	}
	if a["Install"] != nil || a["Start"] != nil || a["Check the sign-in"] != nil {
		t.Error("button on a done step")
	}
	// A project row that Home says to check, and one that may sign in again.
	st = allDone()
	st["steps"].([]map[string]any)[5] = step("login", "todo", "Check", "", map[string]any{"projects": []any{row("todo", "Not checked", "check")}})
	st["steps"].([]map[string]any)[6] = step("selftest", "done", "Passed", "", map[string]any{"projects": []any{row("done", "", "")}})
	f.setup.status = st
	a = allActions(setupView(t, s, f))
	if a["Check the sign-in"] == nil || a["Run self-test"] != nil || a["Sign in with a Claude subscription"] != nil {
		t.Fatalf("%v", a)
	}
	st["steps"].([]map[string]any)[5] = step("login", "done", "Signed in", "", map[string]any{"projects": []any{row("done", "", "login_again")}})
	if a = allActions(setupView(t, s, f)); a["Sign in with an Anthropic Console account"] == nil {
		t.Fatalf("%v", a)
	}
}

func TestSetupPageWorkingAndSignIn(t *testing.T) {
	lines := make([]any, 30)
	for i := range lines {
		lines[i] = "line " + string(rune('a'+i%26)) + strings.Repeat("x", 300)
	}
	st := allDone(map[string]any{"job": map[string]any{"step": "login", "project": "p1", "started": "now"},
		"login": map[string]any{"project": "p1", "url": "https://claude.com/oauth?state=abc", "wants_code": true}})
	steps := st["steps"].([]map[string]any)
	steps[5] = step("login", "working", "Signing in", "", map[string]any{"progress": lines, "projects": []any{row("working", "", "")}})
	f, s := setupFixture(t, st)
	pg := setupView(t, s, f)
	if pg["refresh"] != 3 {
		t.Errorf("refresh %v", pg["refresh"])
	}
	a := allActions(pg)
	for _, want := range []string{"Cancel", "Open the sign-in page", "Paste the code"} {
		if a[want] == nil {
			t.Errorf("no %q", want)
		}
	}
	for _, no := range []string{"Sign in with a Claude subscription", "Run self-test", "Set up everything", "Remove", "Install"} {
		if a[no] != nil {
			t.Errorf("%q while a job runs", no)
		}
	}
	pr := a["Paste the code"]["prompt"].(map[string]any)
	if pr["arg"] != "code" || pr["label"] != "Paste the code shown on the Claude page" || pr["value"] != "" {
		t.Fatalf("%v", pr)
	}
	low := strings.ToLower(pr["label"].(string))
	for _, bad := range []string{"password", "passkey", "pin", "rubi"} {
		if strings.Contains(low, bad) {
			t.Errorf("label mentions %s", bad)
		}
	}
	// Progress: the last 20 lines, each clipped; the link only as item text.
	secs := pg["sections"].([]map[string]any)
	var login []map[string]any
	for _, sec := range secs {
		if strings.HasPrefix(sec["title"].(string), "6.") {
			login = sec["items"].([]map[string]any)
		}
	}
	n := 0
	var link string
	for _, it := range login {
		if _, has := it["actions"]; !has {
			n++
			if len([]rune(it["title"].(string))) > setupLineRunes {
				t.Error("line not clipped")
			}
		}
		if d, _ := it["detail"].(string); strings.Contains(d, "https://claude.com") {
			link = d
		}
	}
	if n != 20 || link == "" {
		t.Errorf("progress %d link %q", n, link)
	}
	for _, aa := range a {
		if strings.Contains(aa["label"].(string), "claude.com") {
			t.Error("link in a label")
		}
	}
	// A link that isn't https is not shown and not offered.
	st["login"] = map[string]any{"project": "p1", "url": "javascript:alert(1)", "wants_code": false}
	f.setup.status = st
	a = allActions(setupView(t, s, f))
	if a["Open the sign-in page"] != nil || a["Paste the code"] != nil {
		t.Error("buttons for an unusable link")
	}
}

func TestSetupTolerantParsing(t *testing.T) {
	f, s := setupFixture(t, map[string]any{"steps": []any{map[string]any{"id": "container", "state": 7, "progress": "no"}, map[string]any{}, "x"}})
	pg := setupView(t, s, f)
	if len(pg["sections"].([]map[string]any)) < 2 {
		t.Fatal("no sections")
	}
	f, s = setupFixture(t, map[string]any{})
	if pg = setupView(t, s, f); pg["sections"] == nil {
		t.Fatal("empty status")
	}
}

func TestSetupOpsRouteToHome(t *testing.T) {
	f, s := setupFixture(t, allDone())
	ctx := context.Background()
	do := func(op, args string) (any, error) { return s.panel(ctx, f, op, json.RawMessage(args)) }
	cases := []struct {
		op, args, homeOp string
		want             map[string]any
	}{
		{"setup_run", `{"device":"dev_mac","step":"service"}`, opSetupRun, map[string]any{"step": "service"}},
		{"setup_run", `{"device":"dev_mac","step":"image"}`, opSetupRun, map[string]any{"step": "image"}},
		{"setup_run", `{"device":"dev_mac","step":"selftest","project":"p1"}`, opSetupRun, map[string]any{"step": "selftest", "project": "p1"}},
		{"setup_run", `{"device":"dev_mac","step":"all"}`, opSetupRun, map[string]any{"step": "all"}},
		{"setup_run", `{"device":"dev_mac","step":"network","option":"auto-address"}`, opSetupRun, map[string]any{"step": "network", "option": "auto-address"}},
		{"setup_run", `{"device":"dev_mac","step":"login","project":"p1"}`, opSetupRun, map[string]any{"step": "login", "project": "p1"}},
		{"setup_run", `{"device":"dev_mac","step":"login","project":"p1","method":"claudeai"}`, opSetupRun, map[string]any{"step": "login", "project": "p1", "method": "claudeai"}},
		{"setup_run", `{"device":"dev_mac","step":"login","project":"p1","method":"console"}`, opSetupRun, map[string]any{"step": "login", "project": "p1", "method": "console"}},
		{"setup_open", `{"device":"dev_mac","project":"p1"}`, opSetupOpen, map[string]any{"project": "p1"}},
		{"setup_remove", `{"device":"dev_mac","project":"p1"}`, opSetupRemove, map[string]any{"dir": "/home/alice/my-project"}},
		{"setup_cancel", `{"device":"dev_mac"}`, opSetupCancel, map[string]any{}},
	}
	for _, c := range cases {
		before := len(f.setup.called(c.homeOp))
		if _, err := do(c.op, c.args); err != nil {
			t.Fatalf("%s %s: %v", c.op, c.args, err)
		}
		got := f.setup.called(c.homeOp)
		if len(got) != before+1 {
			t.Fatalf("%s: no call", c.op)
		}
		b1, _ := json.Marshal(got[len(got)-1])
		b2, _ := json.Marshal(c.want)
		if string(b1) != string(b2) {
			t.Errorf("%s: sent %s, want %s", c.op, b1, b2)
		}
	}
	if len(f.submits) != 0 {
		t.Errorf("approvals asked for the no-approval buttons: %v", f.submits)
	}
	// Refused: the steps that need an approval can't be run directly, bad input.
	for _, c := range [][2]string{{"setup_run", `{"device":"dev_mac","step":"container"}`}, {"setup_run", `{"device":"dev_mac","step":"network"}`},
		{"setup_run", `{"device":"dev_mac","step":"network","option":"other"}`}, {"setup_run", `{"device":"dev_mac","step":"selftest"}`},
		{"setup_run", `{"device":"dev_mac","step":"login"}`}, {"setup_run", `{"device":"dev_mac","step":"login","project":"p1","method":"x"}`},
		{"setup_login", `{"device":"dev_mac","project":"p1","method":"claudeai"}`}, {"setup_remove", `{"device":"dev_mac","project":"nope"}`},
		{"setup_run", `{"device":"dev_nope","step":"service"}`}} {
		n := len(f.setup.calls)
		if _, err := do(c[0], c[1]); err == nil {
			t.Errorf("%s %s accepted", c[0], c[1])
		}
		for _, call := range f.setup.calls[n:] {
			if call.op == opSetupRun || call.op == opSetupRemove {
				t.Errorf("%s %s reached Home", c[0], c[1])
			}
		}
	}
	if len(f.auditLog) == 0 {
		t.Error("no audit")
	}
}

func TestSetupAllNeverSkipsApprovals(t *testing.T) {
	st := allDone()
	st["steps"].([]map[string]any)[2] = step("network", "todo", "No network", "create", nil)
	f, s := setupFixture(t, st)
	if _, err := s.panel(context.Background(), f, "setup_run", json.RawMessage(`{"device":"dev_mac","step":"all"}`)); err == nil {
		t.Fatal("all ran with the network step not done")
	}
	if len(f.setup.called(opSetupRun)) != 0 {
		t.Error("reached Home")
	}
	if allActions(setupView(t, s, f))["Set up everything"] != nil {
		t.Error("offered")
	}
}

func TestSetupApprovals(t *testing.T) {
	f, s := setupFixture(t, allDone())
	ctx := context.Background()
	for _, c := range []struct{ op, kind, homeOp, key string }{
		{"setup_install", kindSetupInstall, opSetupRun, "container"},
		{"setup_network", kindSetupNetwork, opSetupRun, "network"},
		{"setup_add", kindSetupProject, opSetupAdd, ""},
	} {
		if _, err := s.panel(ctx, f, c.op, json.RawMessage(`{"device":"dev_mac"}`)); err != nil {
			t.Fatal(err)
		}
		r := lastSubmit(t, f)
		if r.Kind != c.kind {
			t.Errorf("%s: kind %s", c.op, r.Kind)
		}
		if len(f.setup.called(c.homeOp)) != 0 {
			t.Errorf("%s: Home called before the approval", c.op)
		}
		// Approved: the execute step makes the call.
		b, _ := json.Marshal(r.Payload)
		var tk setupTicket
		_ = json.Unmarshal(b, &tk)
		var err error
		switch c.op {
		case "setup_install":
			_, err = s.executeSetupInstall(ctx, f, tk)
		case "setup_network":
			_, err = s.executeSetupNetwork(ctx, f, tk)
		default:
			_, err = s.executeSetupProject(ctx, f, tk)
		}
		if err != nil {
			t.Fatal(err)
		}
		got := f.setup.called(c.homeOp)
		if len(got) != 1 || c.key != "" && got[0]["step"] != c.key {
			t.Errorf("%s: %v", c.op, got)
		}
		f.setup.calls = nil
	}
	if _, err := s.executeSetupInstall(ctx, f, setupTicket{}); err == nil {
		t.Error("empty payload")
	}
	// The manifest lists the three kinds as strong and locked.
	kinds := map[string]bool{}
	for _, a := range manifest().Actions {
		if a.Kind == kindSetupInstall || a.Kind == kindSetupNetwork || a.Kind == kindSetupProject {
			kinds[a.Kind] = a.DefaultLevel == rubiplugin.Strong && a.Locked
		}
	}
	if len(kinds) != 3 || !kinds[kindSetupInstall] || !kinds[kindSetupNetwork] || !kinds[kindSetupProject] {
		t.Errorf("%v", kinds)
	}
}

func TestSetupCodeIsNeverKept(t *testing.T) {
	f, s := setupFixture(t, allDone())
	ctx := context.Background()
	const code = "ZXQ9-secret_code.123"
	// A panel that doesn't send the key is refused.
	if _, err := s.panel(ctx, f, "setup_code", json.RawMessage(`{"device":"dev_mac","project":"p1"}`)); err == nil {
		t.Fatal("missing key accepted")
	}
	for _, bad := range []string{"", "  ", "has space", "tab\tx", "é", strings.Repeat("a", 513)} {
		raw, _ := json.Marshal(map[string]any{"device": "dev_mac", "project": "p1", "code": bad})
		if _, err := s.panel(ctx, f, "setup_code", raw); err == nil {
			t.Errorf("code %q accepted", bad)
		} else if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("error echoes the code: %v", err)
		}
	}
	if len(f.setup.called(opSetupCode)) != 0 {
		t.Fatal("a bad code was sent")
	}
	raw, _ := json.Marshal(map[string]any{"device": "dev_mac", "project": "p1", "code": " " + code + "\n"})
	if _, err := s.panel(ctx, f, "setup_code", raw); err != nil {
		t.Fatal(err)
	}
	got := f.setup.called(opSetupCode)
	if len(got) != 1 || got[0]["code"] != code || got[0]["project"] != "p1" {
		t.Fatalf("%v", got)
	}
	// Home failing must not echo it either.
	f.setup.failOp = map[string]error{opSetupCode: errors.New("no sign-in waits")}
	if _, err := s.panel(ctx, f, "setup_code", raw); err == nil || strings.Contains(err.Error(), code) {
		t.Errorf("%v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	everything, _ := json.Marshal([]any{f.auditLog, f.audits, f.logs, f.state, f.submits, f.events, f.sent})
	if strings.Contains(string(everything), code) {
		t.Errorf("the code was kept: %s", everything)
	}
	if !strings.Contains(string(everything), "sign-in code sent") {
		t.Error("no audit line")
	}
}
