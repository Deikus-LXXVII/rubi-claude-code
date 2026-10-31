package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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
		step("login", "todo", "Not signed in", "login", nil),
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
	old := setupStatusReuse
	setupStatusReuse = 0 // every view reads the status again
	t.Cleanup(func() { setupStatusReuse = old })
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
	// All done but the sign-in: one sign-in button for the computer (no Console one), self-test per project.
	f, s = setupFixture(t, allDone())
	a = allActions(setupView(t, s, f))
	if a["Sign in with a Claude subscription"] == nil || a["Run self-test"] == nil || a["Remove"] == nil || a["Add a folder"] == nil || a["Set up everything"] == nil {
		t.Fatalf("%v", a)
	}
	if a["Sign in with an Anthropic Console account"] != nil || a["Sign out"] != nil || a["Install"] != nil || a["Start"] != nil || a["Check the sign-in"] != nil {
		t.Error("button that doesn't belong")
	}
	// The sign-in row Home says to check, and one that is signed in (sign in again, sign out).
	st = allDone()
	st["steps"].([]map[string]any)[5] = step("login", "todo", "Check", "check", nil)
	st["steps"].([]map[string]any)[6] = step("selftest", "done", "Passed", "", map[string]any{"projects": []any{row("done", "", "")}})
	f.setup.status = st
	a = allActions(setupView(t, s, f))
	if a["Check the sign-in"] == nil || a["Run self-test"] != nil || a["Sign in with a Claude subscription"] != nil {
		t.Fatalf("%v", a)
	}
	st["steps"].([]map[string]any)[5] = step("login", "done", "Signed in", "login_again", map[string]any{"action2": "sign_out"})
	a = allActions(setupView(t, s, f))
	if a["Sign in again with a Claude subscription"] == nil || a["Sign out"] == nil {
		t.Fatalf("%v", a)
	}
	so := a["Sign out"]
	if so["confirm"] != "Sign out every project on this computer? To revoke the token fully, also remove it at claude.ai settings." || so["args"].(map[string]any)["step"] != "signout" {
		t.Errorf("%v", so)
	}
}

func TestSetupPageWorkingAndSignIn(t *testing.T) {
	lines := make([]any, 30)
	for i := range lines {
		lines[i] = "line " + string(rune('a'+i%26)) + strings.Repeat("x", 300)
	}
	st := allDone(map[string]any{"job": map[string]any{"step": "login", "started": "now"},
		"login": map[string]any{"url": "https://claude.com/oauth?state=abc", "wants_code": true}})
	steps := st["steps"].([]map[string]any)
	steps[5] = step("login", "working", "Signing in", "", map[string]any{"progress": lines})
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
	st["login"] = map[string]any{"url": "javascript:alert(1)", "wants_code": false}
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
		{"setup_run", `{"device":"dev_mac","step":"login"}`, opSetupRun, map[string]any{"step": "login"}},
		{"setup_run", `{"device":"dev_mac","step":"login","method":"claudeai"}`, opSetupRun, map[string]any{"step": "login", "method": "claudeai"}},
		{"setup_run", `{"device":"dev_mac","step":"signout"}`, opSetupRun, map[string]any{"step": "signout"}},
		{"setup_open", `{"device":"dev_mac"}`, opSetupOpen, map[string]any{}},
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
		{"setup_run", `{"device":"dev_mac","step":"login","method":"console"}`}, {"setup_run", `{"device":"dev_mac","step":"login","method":"x"}`},
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
	if _, err := s.panel(ctx, f, "setup_code", json.RawMessage(`{"device":"dev_mac"}`)); err == nil {
		t.Fatal("missing key accepted")
	}
	for _, bad := range []string{"", "  ", "has space", "tab\tx", "é", strings.Repeat("a", 513)} {
		raw, _ := json.Marshal(map[string]any{"device": "dev_mac", "code": bad})
		if _, err := s.panel(ctx, f, "setup_code", raw); err == nil {
			t.Errorf("code %q accepted", bad)
		} else if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("error echoes the code: %v", err)
		}
	}
	if len(f.setup.called(opSetupCode)) != 0 {
		t.Fatal("a bad code was sent")
	}
	raw, _ := json.Marshal(map[string]any{"device": "dev_mac", "code": " " + code + "\n"})
	if _, err := s.panel(ctx, f, "setup_code", raw); err != nil {
		t.Fatal(err)
	}
	got := f.setup.called(opSetupCode)
	if len(got) != 1 || got[0]["code"] != code || len(got[0]) != 1 {
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

func TestSetupAutoAddressOnlyWhenOffered(t *testing.T) {
	ctx := context.Background()
	run := `{"device":"dev_mac","step":"network","option":"auto-address"}`
	// A network that isn't there (or any other action) is not created by this button.
	for _, action := range []string{"create", "", "use_auto_address "} {
		st := allDone()
		st["steps"].([]map[string]any)[2] = step("network", "todo", "No network", action, nil)
		f, s := setupFixture(t, st)
		if _, err := s.panel(ctx, f, "setup_run", json.RawMessage(run)); err == nil {
			t.Errorf("action %q: accepted", action)
		}
		if len(f.setup.called(opSetupRun)) != 0 {
			t.Errorf("action %q: reached Home", action)
		}
	}
	// Plain run of the network step is refused too.
	f, s := setupFixture(t, allDone())
	if _, err := s.panel(ctx, f, "setup_run", json.RawMessage(`{"device":"dev_mac","step":"network"}`)); err == nil {
		t.Error("plain network run accepted")
	}
	// Offered by Home: it goes through, without an approval.
	st := allDone()
	st["steps"].([]map[string]any)[2] = step("network", "failed", "Proxy address set", "use_auto_address", nil)
	f, s = setupFixture(t, st)
	if _, err := s.panel(ctx, f, "setup_run", json.RawMessage(run)); err != nil {
		t.Fatal(err)
	}
	got := f.setup.called(opSetupRun)
	if len(got) != 1 || got[0]["step"] != "network" || got[0]["option"] != "auto-address" || len(f.submits) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestSetupProjectIDsAreChecked(t *testing.T) {
	f, s := setupFixture(t, allDone())
	ctx := context.Background()
	for _, id := range []string{"nope", "", "p1 ", "p1/../x", strings.Repeat("p", 200), "p1\u202e"} {
		for _, c := range []struct{ op, extra string }{{"setup_run", `"step":"selftest",`}} {
			raw := `{"device":"dev_mac",` + c.extra + `"project":"` + id + `"}`
			if _, err := s.panel(ctx, f, c.op, json.RawMessage(raw)); err == nil {
				t.Errorf("%s %s accepted", c.op, raw)
			}
		}
	}
	for _, op := range []string{opSetupRun} {
		if len(f.setup.called(op)) != 0 {
			t.Errorf("%s reached Home", op)
		}
	}
}

func TestSetupProbeIsSharedAndSlowDoesNotHide(t *testing.T) {
	f, s := setupFixture(t, allDone())
	setupStatusReuse = time.Minute
	main := view(t, s, f, `{}`)
	if len(items(t, main, 1)) != 1 {
		t.Fatal("no entry")
	}
	view(t, s, f, `{"page":"setup","device":"dev_mac"}`)
	if n := len(f.setup.called(opSetupStatus)); n != 1 {
		t.Errorf("%d status calls for the entry and the page", n)
	}
	// An action reads a fresh status.
	if _, err := s.panel(context.Background(), f, "setup_run", json.RawMessage(`{"device":"dev_mac","step":"selftest","project":"p1"}`)); err != nil {
		t.Fatal(err)
	}
	if n := len(f.setup.called(opSetupStatus)); n != 2 {
		t.Errorf("%d status calls", n)
	}
	// Known recently: a probe that times out later doesn't hide the entry; one never answered does.
	now := time.Now()
	s.now = func() time.Time { return now }
	s.setupCaps = map[string]setupCap{"dev_mac": {ok: true, at: now.Add(-10 * time.Minute)}}
	f.setup.failOp = map[string]error{opSetupStatus: context.DeadlineExceeded}
	if len(s.setupDevices(context.Background(), f)) != 1 {
		t.Error("a slow probe hid a known computer")
	}
	s.setupCaps = map[string]setupCap{"dev_mac": {ok: true, at: now.Add(-2 * time.Hour)}}
	if len(s.setupDevices(context.Background(), f)) != 0 {
		t.Error("a long-gone answer kept the entry")
	}
	s.setupCaps = nil
	if len(s.setupDevices(context.Background(), f)) != 0 {
		t.Error("never answered, yet listed")
	}
	if setupProbeWait < 15*time.Second || setupAddWait < 11*time.Minute {
		t.Error("waits too short")
	}
}

func TestSetupLongNameAndLink(t *testing.T) {
	long := "https://claude.com/oauth/authorize?state=" + strings.Repeat("a", 900)
	st := allDone(map[string]any{"login": map[string]any{"url": long, "wants_code": false}})
	f, s := setupFixture(t, st)
	f.devices = []rubiplugin.HomeDevice{{ID: "dev_mac", Name: strings.Repeat("N", 200)}}
	pg := view(t, s, f, `{"page":"setup","device":"dev_mac"}`)
	found := false
	for _, sec := range pg["sections"].([]map[string]any) {
		its, _ := sec["items"].([]map[string]any)
		for _, it := range its {
			if d, _ := it["detail"].(string); strings.Contains(d, "https://claude.com/") {
				found = true
				if len([]rune(d)) > 600 || !strings.Contains(d, "shortened") {
					t.Errorf("link detail %d runes", len([]rune(d)))
				}
			}
		}
	}
	if !found {
		t.Error("no link")
	}
	if _, err := s.panel(context.Background(), f, "setup_install", json.RawMessage(`{"device":"dev_mac"}`)); err != nil {
		t.Fatal(err)
	}
	r := lastSubmit(t, f)
	if len([]rune(r.Summary)) > 100 || len([]rune(r.Preview.(map[string]any)["computer"].(string))) > 60 {
		t.Errorf("name not clipped: %q", r.Summary)
	}
}

func TestSetupModeSection(t *testing.T) {
	f, s := setupFixture(t, allDone())
	// The fake agent reports no usage default: nothing to show.
	pg := setupView(t, s, f)
	secs := pg["sections"].([]map[string]any)
	if secs[len(secs)-1]["title"] == "Usage mode" {
		t.Error("section without a default mode")
	}
	f.agent.slots = []map[string]any{}
	f.agent.modes = map[string]any{"default": "medium"}
	pg = setupView(t, s, f)
	secs = pg["sections"].([]map[string]any)
	sec := secs[len(secs)-1]
	if sec["title"] != "Usage mode" {
		t.Fatalf("%v", sec["title"])
	}
	its := sec["items"].([]map[string]any)
	if len(its) != 3 || !strings.HasPrefix(its[0]["title"].(string), "Maximum") || its[1]["title"] != "Medium (Recommended) (the current default)" || its[2]["title"] != "Light" {
		t.Fatalf("%v", its)
	}
	for _, want := range []string{"fastest", "up to 4 sessions", "1 session"} {
		found := false
		for _, it := range its {
			found = found || strings.Contains(strings.ToLower(it["detail"].(string)), want)
		}
		if !found {
			t.Errorf("no %q in the descriptions", want)
		}
	}
	btn := its[2]["actions"].([]map[string]any)[0]
	if btn["label"] != "Use for all Bots" || btn["op"] != "usage_mode" {
		t.Fatalf("%v", btn)
	}
	raw, _ := json.Marshal(btn["args"])
	if _, err := s.panel(context.Background(), f, "usage_mode", raw); err != nil {
		t.Fatal(err)
	}
	got := f.agent.called(opAgentUsageMode)
	if len(got) != 1 || got[0]["mode"] != "light" || got[0]["all"] != true {
		t.Fatalf("%v", got)
	}
	// Without the claude-agent capability the section is hidden (the setup page still works).
	f.agent.failOp = map[string]error{opAgentStatus: errors.New("Rubi Home doesn't do claude-agent.status")}
	s = newSisters(&store{})
	pg = setupView(t, s, f)
	secs = pg["sections"].([]map[string]any)
	if secs[len(secs)-1]["title"] == "Usage mode" {
		t.Error("section shown without claude-agent")
	}
}
