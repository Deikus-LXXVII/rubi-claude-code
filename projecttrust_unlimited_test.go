package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// grantForever plays a run approval where the user picks "until I revoke it", and returns the trust's id.
func grantForever(t *testing.T, f *fakeHost, s *sisters, session, cwd string) string {
	t.Helper()
	newWatcher(f, s).handle(context.Background(), mac, reqIn(session, cwd, "go test ./..."))
	payload, _ := json.Marshal(f.submits[len(f.submits)-1].Payload)
	res, err := runApproved(context.Background(), f, s, optionTrustForever, payload)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["trusted"] != true {
		t.Fatalf("not trusted: %v", m)
	}
	return m["mandate"].(string)
}

func TestUnlimitedTrustViaOption(t *testing.T) {
	f, s, _ := ptFixture(t)
	newWatcher(f, s).handle(context.Background(), mac, reqIn("cli-2", ptSub.Cwd, "go test ./..."))
	sub := f.submits[0]
	o := sub.Options[3]
	if o.Key != optionTrustForever || o.Label != "Allow and trust the project "+ptRoot+" until I revoke it" {
		t.Fatalf("option %+v", o)
	}
	for _, want := range []string{"UNTIL REVOKED — no end time", "across restarts", "across days", "no time limit", "revoke it in the panel", "claude_code_mandates",
		"locked", "bypassPermissions", "start a Claude Code session", ptRoot, "Still asks", "git push", "--no-update-refs", "counted and audited", "without asking"} {
		if !strings.Contains(o.Meaning, want) {
			t.Errorf("meaning lacks %q:\n%s", want, o.Meaning)
		}
	}
	if strings.Contains(o.Meaning+o.Label, "04:00") || strings.Contains(o.Meaning, "at most 2000") {
		t.Errorf("the unlimited text names an end or a cap: %s", o.Meaning)
	}
	// The 04:00 option is untouched and still the third.
	if !strings.HasSuffix(sub.Options[2].Label, "04:00 CET") {
		t.Errorf("04:00 option %q", sub.Options[2].Label)
	}
	if p := sub.Preview.(map[string]any); !strings.Contains(fmt.Sprint(p["project_trust_until_revoked"]), "UNTIL REVOKED") {
		t.Errorf("preview %v", p)
	}
	if len(s.st.projects(s.now())) != 0 {
		t.Fatal("trusted before the user approved")
	}
	id := grantForever(t, f, s, "cli-2", ptSub.Cwd)
	pts := s.st.projects(s.now())
	if len(pts) != 1 || pts[0].ID != id || !pts[0].Unlimited || !pts[0].Expires.IsZero() || pts[0].MaxUses != 0 || pts[0].Root != ptRoot || pts[0].BranchPattern != "citri/*" {
		t.Fatalf("saved %+v", pts)
	}
	if a := f.auditLog[slices.Index(f.audits, "project_trust_issued")]; a["mode"] != "until_revoked" || a["mandate"] != id {
		t.Fatalf("audit %v", a)
	}
	// The result for the approval shows no end time.
	payload, _ := json.Marshal(f.submits[len(f.submits)-1].Payload)
	res, _ := runApproved(context.Background(), f, s, optionTrustForever, payload)
	if m := res.(map[string]any); m["until"] != "revoked" || m["expires"] != nil {
		t.Fatalf("result %v", m)
	}
	// Other sessions of the project run plain commands; each is audited with the trust's id and counted.
	if asks(f, s, "cli-1", ptRoot, "go vet ./...") || asks(f, s, "cli-9", ptRoot+"/x", "git commit -am x") {
		t.Fatal("an unlimited trust asked")
	}
	if a := f.auditLog[len(f.auditLog)-1]; f.audits[len(f.audits)-1] != auditMandateAll || a["project"] != ptRoot || a["uses"] == nil {
		t.Fatalf("audit %v", a)
	}
}

func TestOptionAndOfferModesMustMatch(t *testing.T) {
	f, s, _ := ptFixture(t)
	newWatcher(f, s).handle(context.Background(), mac, reqIn("cli-1", ptRoot, "go test ./..."))
	var tk ticket
	raw, _ := json.Marshal(f.submits[0].Payload)
	_ = json.Unmarshal(raw, &tk)
	// The "until revoked" option with the timed offer in its place (or the reverse) grants nothing.
	bad := []struct {
		opt string
		mod func(*ticket)
	}{
		{optionTrustForever, func(t *ticket) { t.Forever = t.Project }},
		{optionTrustForever, func(t *ticket) { t.Forever = nil }},
		{optionTrustProject, func(t *ticket) { t.Project = t.Forever }},
		{optionTrustProject, func(t *ticket) { t.Project = nil }},
	}
	for i, c := range bad {
		x := tk
		c.mod(&x)
		p, _ := json.Marshal(x)
		res, err := runApproved(context.Background(), f, s, c.opt, p)
		if m := res.(map[string]any); err != nil || m["trusted"] != false || m["allowed"] != true {
			t.Errorf("case %d: %v %v", i, res, err)
		}
	}
	if len(s.st.projects(s.now())) != 0 {
		t.Fatal("a mismatched option granted a trust")
	}
	// A forged unlimited offer with an end time is refused.
	o := *tk.Forever
	o.Expires = s.now().Add(time.Hour)
	if _, err := s.grantProject(f, "dev_mac", "Mac", "", o); err == nil {
		t.Error("an unlimited offer with an end time was granted")
	}
}

func TestUnlimitedTrustViaTool(t *testing.T) {
	f, s, code := ptBot(t)
	ctx := context.Background()
	if _, err := s.trustTool(ctx, f, trustIn{VerifiedAgent: "Citri", BindCode: code, Until: "forever"}); err == nil {
		t.Fatal("a made-up until accepted")
	}
	if len(f.submits) != 0 {
		t.Fatal("asked for a refused call")
	}
	// The default and "0400" stay as before.
	res, err := s.trustTool(ctx, f, trustIn{VerifiedAgent: "Citri", BindCode: code, Until: "0400"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" || f.submits[0].Options[0].Key != optionTrustProject {
		t.Fatalf("%v %v", res, err)
	}
	f.submits = nil
	res, err = s.trustTool(ctx, f, trustIn{VerifiedAgent: "Citri", BindCode: code, Until: " Revoked "})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" || len(f.submits) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	sub := f.submits[0]
	if sub.Kind != kindTrustProject || len(sub.Options) != 1 || sub.Options[0].Key != optionTrustForever {
		t.Fatalf("%+v", sub)
	}
	text, _ := json.Marshal(sub.Preview)
	for _, want := range []string{"UNTIL REVOKED — no end time", ptRoot, "Citri", "Still asks"} {
		if !strings.Contains(string(text)+sub.Summary+sub.Options[0].Label+sub.Options[0].Meaning, want) {
			t.Errorf("approval lacks %q: %s", want, text)
		}
	}
	if strings.Contains(string(text)+sub.Summary, "04:00") {
		t.Errorf("an end time in the approval: %s %s", text, sub.Summary)
	}
	if len(s.st.projects(s.now())) != 0 {
		t.Fatal("granted before the approval")
	}
	var tk trustTicket
	raw, _ := json.Marshal(sub.Payload)
	_ = json.Unmarshal(raw, &tk)
	out, err := s.executeTrust(f, tk)
	if err != nil {
		t.Fatal(err)
	}
	pts := s.st.projects(s.now())
	if len(pts) != 1 || !pts[0].Unlimited || pts[0].Sister != "Citri" || out.(map[string]any)["until"] != "revoked" {
		t.Fatalf("%+v %v", pts, out)
	}
	// A late answer is no problem for a trust without an end, and a Bot's own start under it needs no approval.
	late := s.now().Add(90 * 24 * time.Hour)
	s.now = func() time.Time { return late }
	if _, err := s.executeTrust(f, tk); err != nil {
		t.Errorf("a regrant of the same offer: %v", err)
	}
}

func TestUnlimitedTrustLastsAcrossRestartsAndTime(t *testing.T) {
	f, s, now := ptFixture(t)
	id := grantForever(t, f, s, "cli-1", ptRoot)
	for _, d := range []time.Duration{time.Hour, 25 * time.Hour, 8 * 24 * time.Hour, 31 * 24 * time.Hour, 400 * 24 * time.Hour} {
		at := now.Add(d)
		s.now = func() time.Time { return at }
		if asks(f, s, "cli-2", ptSub.Cwd, "go test ./...") {
			t.Fatalf("asked after %v", d)
		}
		// A restart of the plugin on the way: the record is loaded from the saved state.
		s2 := newSisters(&store{})
		if err := s2.st.load(f); err != nil {
			t.Fatal(err)
		}
		s2.loc, s2.now = s.loc, s.now
		if pts := s2.st.projects(at); len(pts) != 1 || pts[0].ID != id || !pts[0].Unlimited {
			t.Fatalf("after %v and a restart: %+v", d, pts)
		}
		if asks(f, s2, "cli-1", ptRoot, "ls") {
			t.Fatalf("the restarted plugin asks after %v", d)
		}
	}
	// No use cap: far past the 2000 a timed trust gets.
	s.st.mu.Lock()
	s.st.st.Projects[0].Uses = ptMaxUses * 5
	s.st.mu.Unlock()
	if asks(f, s, "cli-1", ptRoot, "ls") {
		t.Fatal("an unlimited trust ended by count")
	}
	// A timed trust still ends by time and by count (not weakened).
	f2, s2, now2 := ptFixture(t)
	grantViaOption(t, f2, s2, "cli-1", ptRoot)
	later := now2.Add(25 * time.Hour)
	s2.now = func() time.Time { return later }
	if !asks(f2, s2, "cli-1", ptRoot, "ls") {
		t.Fatal("a timed trust outlived its time")
	}
}

func TestUnlimitedTrustEndsOnRevoke(t *testing.T) {
	for _, how := range []string{"tool", "panel", "all"} {
		f, s, _ := ptFixture(t)
		id := grantForever(t, f, s, "cli-1", ptRoot)
		if asks(f, s, "cli-2", ptSub.Cwd, "go test ./...") {
			t.Fatal("asked")
		}
		var err error
		switch how {
		case "tool":
			_, err = s.mandatesTool(f, mandatesIn{Revoke: id})
		case "panel":
			_, err = s.panel(context.Background(), f, "revoke", json.RawMessage(`{"id":"`+id+`"}`))
		case "all":
			_, err = s.mandatesTool(f, mandatesIn{Revoke: "all"})
		}
		if err != nil {
			t.Fatal(err)
		}
		if !asks(f, s, "cli-2", ptSub.Cwd, "go test ./...") || len(s.st.projects(s.now())) != 0 {
			t.Fatalf("%s: the revoked trust still allows", how)
		}
		// And after a restart it stays gone.
		s2 := newSisters(&store{})
		_ = s2.st.load(f)
		if len(s2.st.projects(s2.now())) != 0 {
			t.Fatalf("%s: the revoked trust came back", how)
		}
		if i := slices.Index(f.audits, "mandate_revoked"); i < 0 {
			t.Fatalf("%s: no revoke audit", how)
		}
	}
}

func TestUnlimitedTrustStillAsks(t *testing.T) {
	f, s, _ := ptFixture(t)
	grantForever(t, f, s, "cli-1", ptRoot)
	still := []struct{ cwd, cmd string }{
		{ptRoot, "git push"},
		{ptRoot, "git push origin citri/x"},
		{ptRoot, "git tag v1.0.0"},
		{ptRoot, "git status && git push --force"},
		{ptRoot, "git commit --amend && git push --force-with-lease"},
		{ptRoot, "sudo ls"},
		{ptRoot, "curl https://example.com"},
		{ptRoot, "npm install left-pad"},
		{"/Users/v/other", "ls"},                  // outside the root
		{ptRoot, "rm -rf ../x"},                   // writes outside
		{ptRoot, "git switch main"},               // a foreign branch
		{ptRoot, "git checkout -b dev"},           // creating one
		{ptRoot, "git rebase main"},               // rebase without --no-update-refs
		{ptRoot, "git rebase --update-refs main"}, // with --update-refs
		{ptRoot, "cat ~/.ssh/id_rsa"},             // credentials
	}
	for _, c := range still {
		if !asks(f, s, "cli-2", c.cwd, c.cmd) {
			t.Errorf("%s: %q was allowed by the unlimited trust", c.cwd, c.cmd)
		}
	}
	for _, ok := range []string{"git switch citri/ok", "git rebase --no-update-refs main"} {
		if asks(f, s, "cli-2", ptRoot, ok) {
			t.Errorf("%q asked", ok)
		}
	}
	// Even a year later nothing about the list changes.
	s.now = func() time.Time { return time.Date(2027, 10, 30, 10, 0, 0, 0, s.loc) }
	if !asks(f, s, "cli-2", ptRoot, "git push") || asks(f, s, "cli-2", ptRoot, "go test ./...") {
		t.Fatal("a year later")
	}
}

func TestTrustShowsItsAgeAndUses(t *testing.T) {
	f, s, now := ptFixture(t)
	id := grantForever(t, f, s, "cli-1", ptRoot)
	asks(f, s, "cli-2", ptSub.Cwd, "ls")
	asks(f, s, "cli-2", ptSub.Cwd, "ls")
	at := now.Add(3*24*time.Hour + 4*time.Hour + 5*time.Minute)
	s.now = func() time.Time { return at }
	list, err := s.mandatesTool(f, mandatesIn{})
	if err != nil {
		t.Fatal(err)
	}
	pl := list.(map[string]any)["project_trusts"].([]map[string]any)
	if len(pl) != 1 || pl[0]["id"] != id || pl[0]["granted_ago"] != "3 d 4 h ago" || pl[0]["uses"] != 2 || pl[0]["until"] != "revoked" ||
		pl[0]["expires"] != nil || !strings.Contains(fmt.Sprint(pl[0]["note"]), "UNTIL REVOKED") || pl[0]["granted"] == nil {
		t.Fatalf("list %v", pl)
	}
	view, err := s.panel(context.Background(), f, "view", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(view)
	for _, want := range []string{"UNTIL REVOKED — no end time", "3 d 4 h ago", "2 commands used", "stays on across restarts and days", id, "Trusted projects (until 04:00, or until revoked)"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("panel lacks %q: %s", want, raw)
		}
	}
	// A timed trust shows its age too.
	f2, s2, now2 := ptFixture(t)
	grantViaOption(t, f2, s2, "cli-1", ptRoot)
	at2 := now2.Add(2*time.Hour + 5*time.Minute)
	s2.now = func() time.Time { return at2 }
	l2, _ := s2.mandatesTool(f2, mandatesIn{})
	if p := l2.(map[string]any)["project_trusts"].([]map[string]any); p[0]["granted_ago"] != "2 h 5 min ago" || p[0]["expires"] == nil || p[0]["max_uses"] != ptMaxUses {
		t.Fatalf("%v", p)
	}
	v2, _ := s2.panel(context.Background(), f2, "view", nil)
	if r, _ := json.Marshal(v2); !strings.Contains(string(r), "granted 2 h 5 min ago") {
		t.Errorf("panel: %s", r)
	}
	for in, want := range map[time.Duration]string{0: "0 min ago", 7 * time.Minute: "7 min ago", 90 * time.Minute: "1 h 30 min ago", 49 * time.Hour: "2 d 1 h ago", -time.Hour: "0 min ago"} {
		if got := ageText(now.Add(-in), *now); got != want && in >= 0 {
			t.Errorf("ageText(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestReplacementBetweenModes(t *testing.T) {
	f, s, _ := ptFixture(t)
	timed := grantViaOption(t, f, s, "cli-1", ptRoot)
	forever := grantForever(t, f, s, "cli-1", ptRoot)
	pts := s.st.projects(s.now())
	if len(pts) != 1 || pts[0].ID != forever || !pts[0].Unlimited {
		t.Fatalf("%+v", pts)
	}
	i := slices.Index(f.audits, "project_trust_replaced")
	if i < 0 || f.auditLog[i]["mandate"] != timed || f.auditLog[i]["by"] != forever || f.auditLog[i]["mode"] != "until_0400" {
		t.Fatalf("audit %v", f.auditLog)
	}
	// And back: a 04:00 trust replaces the unlimited one (the user chose the shorter one), audited.
	timed2 := grantViaOption(t, f, s, "cli-2", ptSub.Cwd)
	pts = s.st.projects(s.now())
	if len(pts) != 1 || pts[0].ID != timed2 || pts[0].Unlimited || pts[0].Expires.IsZero() || pts[0].MaxUses != ptMaxUses {
		t.Fatalf("%+v", pts)
	}
	last := len(f.audits) - 1
	for j := last; j >= 0; j-- {
		if f.audits[j] == "project_trust_replaced" {
			if f.auditLog[j]["mandate"] != forever || f.auditLog[j]["mode"] != "until_revoked" || f.auditLog[j]["by"] != timed2 {
				t.Fatalf("audit %v", f.auditLog[j])
			}
			break
		}
	}
	// Through the Bot's tool the preview says what an unlimited one is replaced.
	g, s2, code := ptBot(t)
	grantForever(t, g, s2, "cli-1", ptRoot)
	g.submits = nil
	if _, err := s2.trustTool(context.Background(), g, trustIn{VerifiedAgent: "Citri", BindCode: code}); err != nil {
		t.Fatal(err)
	}
	if p := g.submits[0].Preview.(map[string]any); !strings.Contains(fmt.Sprint(p["replaces"]), "until revoked") {
		t.Errorf("preview %v", p)
	}
}

func TestUnlimitedTrustIsNeverPruned(t *testing.T) {
	f, s, now := ptFixture(t)
	// 19 unlimited and one timed trust fill the list; a new grant evicts the timed one, not an unlimited one.
	for i := range maxProjectTrusts - 1 {
		o, _ := s.offerFor(fmt.Sprintf("/Users/v/p%d", i), "github.com/v/p", "", "Mac")
		if _, err := s.grantProject(f, "dev_mac", "Mac", "", o.forever()); err != nil {
			t.Fatal(err)
		}
	}
	o, _ := s.offerFor("/Users/v/timed", "github.com/v/p", "", "Mac")
	if _, err := s.grantProject(f, "dev_mac", "Mac", "", o); err != nil {
		t.Fatal(err)
	}
	o, _ = s.offerFor("/Users/v/new", "github.com/v/p", "", "Mac")
	if _, err := s.grantProject(f, "dev_mac", "Mac", "", o.forever()); err != nil {
		t.Fatal(err)
	}
	pts := s.st.projects(*now)
	if len(pts) != maxProjectTrusts {
		t.Fatalf("%d trusts", len(pts))
	}
	for _, p := range pts {
		if p.Root == "/Users/v/timed" {
			t.Fatal("the timed trust stayed while the list was full")
		}
	}
	i := slices.Index(f.audits, "project_trust_replaced")
	if i < 0 || f.auditLog[i]["root"] != "/Users/v/timed" {
		t.Fatalf("eviction audit %v", f.auditLog)
	}
	// All 20 are unlimited now: a 21st project is refused and nothing changes.
	before, _ := json.Marshal(s.st.projects(*now))
	o, _ = s.offerFor("/Users/v/twentyfirst", "github.com/v/p", "", "Mac")
	if _, err := s.grantProject(f, "dev_mac", "Mac", "", o); err == nil {
		t.Fatal("a 21st trust evicted an unlimited one")
	}
	if after, _ := json.Marshal(s.st.projects(*now)); string(after) != string(before) {
		t.Fatal("a refused grant changed the list")
	}
	// Replacing one of the same root still works at the cap.
	o, _ = s.offerFor("/Users/v/p3", "github.com/v/p", "", "Mac")
	if _, err := s.grantProject(f, "dev_mac", "Mac", "", o); err != nil {
		t.Fatalf("replacing at the cap: %v", err)
	}
	// Reading the lists (which prunes) years later drops no unlimited trust.
	later := now.Add(5 * 365 * 24 * time.Hour)
	n := 0
	for _, p := range s.st.projects(later) {
		if p.Unlimited {
			n++
		}
	}
	if n != maxProjectTrusts-1 {
		t.Fatalf("%d unlimited trusts left, want %d", n, maxProjectTrusts-1)
	}
	// (The timed trust that replaced p3 ended in those years, as it should.)
	if n2 := len(s.st.projects(later)); n2 != maxProjectTrusts-1 {
		t.Fatalf("%d", n2)
	}
}

func TestFailedSaveOfAnUnlimitedGrantChangesNothing(t *testing.T) {
	f, s, now := ptFixture(t)
	id := grantViaOption(t, f, s, "cli-1", ptRoot)
	f.saveErr = fmt.Errorf("disk full")
	newWatcher(f, s).handle(context.Background(), mac, reqIn("cli-1", ptRoot, "go test ./..."))
	payload, _ := json.Marshal(f.submits[len(f.submits)-1].Payload)
	res, _ := runApproved(context.Background(), f, s, optionTrustForever, payload)
	if m := res.(map[string]any); m["trusted"] != false || m["allowed"] != true {
		t.Fatalf("%v", m)
	}
	if ps := s.st.projects(*now); len(ps) != 1 || ps[0].ID != id || ps[0].Unlimited {
		t.Fatalf("the old trust was replaced by one that wasn't saved: %+v", ps)
	}
}
