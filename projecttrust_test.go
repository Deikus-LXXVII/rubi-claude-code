package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const ptRoot = "/Users/v/rubi"

var (
	ptMain = session{SessionID: "cli-1", AppSessionID: "local_a", Title: "Rubi main", Cwd: ptRoot, ProjectRoot: ptRoot, RepoKey: "github.com/v/rubi", Role: "main", Source: "desktop", State: "idle"}
	ptSub  = session{SessionID: "cli-2", AppSessionID: "local_b", Title: "Rubi sub", Cwd: ptRoot + "/.claude/worktrees/x", ProjectRoot: ptRoot, RepoKey: "github.com/v/rubi", Role: "sub", Parent: "local_a", Source: "desktop", State: "busy"}
	ptOut  = session{SessionID: "cli-3", Title: "Other", Cwd: "/Users/v/other", ProjectRoot: "/Users/v/other", RepoKey: "github.com/v/other", Role: "main", Source: "transcript", State: "idle"}
)

func berlin(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no time zone database:", err)
	}
	return loc
}

// ptFixture is a Rubi with three sessions (two in one project, one elsewhere), the clock at 2026-10-30
// 10:00 in Berlin, so a trust granted now ends Sat 31 Oct 04:00 CET.
func ptFixture(t *testing.T) (*fakeHost, *sisters, *time.Time) {
	t.Helper()
	f := &fakeHost{devices: []rubiplugin.HomeDevice{mac}, sessions: []session{ptMain, ptSub, ptOut}, states: []string{"executed"}}
	s := newSisters(&store{})
	if err := s.st.load(f); err != nil {
		t.Fatal(err)
	}
	loc := berlin(t)
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, loc)
	s.loc, s.now = loc, func() time.Time { return now }
	return f, s, &now
}

func reqIn(session, cwd, command string) request {
	r := newRequest(command)
	r.SessionID, r.Cwd = session, cwd
	return r
}

// grantViaOption plays a run approval where the user picks trust_project, and returns the trust's id.
func grantViaOption(t *testing.T, f *fakeHost, s *sisters, session, cwd string) string {
	t.Helper()
	newWatcher(f, s).handle(context.Background(), mac, reqIn(session, cwd, "go test ./..."))
	last := f.submits[len(f.submits)-1]
	payload, _ := json.Marshal(last.Payload)
	res, err := runApproved(context.Background(), f, s, optionTrustProject, payload)
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["trusted"] != true {
		t.Fatalf("not trusted: %v", m)
	}
	return m["mandate"].(string)
}

func TestTrustExpiry(t *testing.T) {
	loc := berlin(t)
	at := func(y int, m time.Month, d, h, mi int) time.Time { return time.Date(y, m, d, h, mi, 0, 0, loc) }
	cases := []struct {
		name      string
		now, want time.Time
	}{
		{"daytime", at(2026, 10, 30, 10, 0), at(2026, 10, 31, 4, 0)},
		{"after midnight", at(2026, 10, 30, 2, 0), at(2026, 10, 30, 4, 0)},
		{"at 04:00 exactly", at(2026, 10, 30, 4, 0), at(2026, 10, 31, 4, 0)},
		{"just before", at(2026, 10, 30, 3, 59), at(2026, 10, 30, 4, 0)},
		{"spring forward (23 h day)", at(2026, 3, 28, 22, 0), at(2026, 3, 29, 4, 0)},
		{"fall back (25 h day)", at(2026, 10, 24, 22, 0), at(2026, 10, 25, 4, 0)},
		{"month end", at(2026, 12, 31, 12, 0), at(2027, 1, 1, 4, 0)},
	}
	for _, c := range cases {
		got := trustExpiry(c.now, loc)
		if !got.Equal(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if got.Hour() != 4 && got.Sub(c.now) != ptMaxTTL {
			t.Errorf("%s: %v is neither 04:00 nor 24 h", c.name, got)
		}
	}
	// 24 hours is the most: 04:00:01 before a 25 hour day would end at 04:00 the day after (24 h 59 min).
	now := time.Date(2026, 10, 24, 4, 0, 1, 0, loc)
	if got := trustExpiry(now, loc); got.Sub(now) != ptMaxTTL {
		t.Errorf("not capped: %v (%v)", got, got.Sub(now))
	}
	// Every hour of two years: after now, within 24 hours, at 04:00 or capped; in zones with and without DST.
	for _, name := range []string{"Europe/Berlin", "America/New_York", "Asia/Tokyo", "UTC", "Australia/Lord_Howe"} {
		l, err := time.LoadLocation(name)
		if err != nil {
			continue
		}
		for n := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); n.Year() < 2028; n = n.Add(37 * time.Minute) {
			got := trustExpiry(n, l)
			if !got.After(n) || got.Sub(n) > ptMaxTTL {
				t.Fatalf("%s %v -> %v", name, n, got)
			}
			if lt := got.In(l); (lt.Hour() != 4 || lt.Minute() != 0) && got.Sub(n) != ptMaxTTL {
				t.Fatalf("%s %v -> %v", name, n, got)
			}
		}
	}
}

func TestReleaseBuildHasNoExpiryHook(t *testing.T) {
	if (projectTrustExpiryHook != nil || clockHook != nil) && !testBuiltWithE2E {
		t.Fatal("a test-only hook (expiry, clock) is present in a build without the rubie2e tag")
	}
}

func TestRunApprovalOffersProjectTrust(t *testing.T) {
	f, s, _ := ptFixture(t)
	newWatcher(f, s).handle(context.Background(), mac, reqIn("cli-2", ptSub.Cwd, "go test ./..."))
	if len(f.submits) != 1 {
		t.Fatalf("submits %d", len(f.submits))
	}
	sub := f.submits[0]
	if len(sub.Options) != 4 || sub.Options[0].Key != optionAllow || sub.Options[1].Key != optionTrust || sub.Options[2].Key != optionTrustProject || sub.Options[3].Key != optionTrustForever {
		t.Fatalf("options %+v", sub.Options)
	}
	o := sub.Options[2]
	if o.Label != "Allow and trust the project /Users/v/rubi until Sat 31 Oct 2026 04:00 CET" {
		t.Fatalf("label %q", o.Label)
	}
	for _, want := range []string{"Sat 31 Oct 2026 04:00 CET", ptRoot, "Mac", "citri/*", "Europe/Berlin", "CET, UTC+01:00", "Rubi Home doesn't report this computer's own", "bypassPermissions), its commands never ask", "may be main", "--no-update-refs", "Symlinks already in the project", "up to an hour before 04:00",
		"Still asks", "git push", "git tag", "--force", "sudo", "outside " + ptRoot, "bypassPermissions", "project's own code", "start a Claude Code session", "claude_code_mandates", "at most 2000"} {
		if !strings.Contains(o.Meaning, want) {
			t.Errorf("meaning lacks %q:\n%s", want, o.Meaning)
		}
	}
	raw, _ := json.Marshal(sub.Payload)
	var tk ticket
	_ = json.Unmarshal(raw, &tk)
	if tk.Project == nil || tk.Project.Root != ptRoot || tk.Project.Pattern != "citri/*" || !tk.Project.Expires.Equal(time.Date(2026, 10, 31, 4, 0, 0, 0, berlin(t))) {
		t.Fatalf("ticket %+v", tk.Project)
	}
	// Nothing is trusted before the approval.
	if len(s.st.projects(s.now())) != 0 {
		t.Fatal("trusted before the user approved")
	}
}

func TestProjectTrustIsNotOfferedWithoutAGoodRoot(t *testing.T) {
	bad := map[string]session{
		"no root":   {SessionID: "cli-9", Cwd: "/Users/v/x/y", RepoKey: "local:/Users/v/x/y"},
		"no key":    {SessionID: "cli-9", Cwd: "/Users/v/x/y", ProjectRoot: "/Users/v/x/y"},
		"home dir":  {SessionID: "cli-9", Cwd: "/Users/v/x", ProjectRoot: "/Users/v", RepoKey: "local:/Users/v"},
		"top":       {SessionID: "cli-9", Cwd: "/Users/v", ProjectRoot: "/", RepoKey: "local:/"},
		"cwd above": {SessionID: "cli-9", Cwd: "/Users/v/x", ProjectRoot: "/Users/v/x/y", RepoKey: "local:/Users/v/x/y"},
		"secret":    {SessionID: "cli-9", Cwd: "/Users/v/.ssh/p", ProjectRoot: "/Users/v/.ssh/p", RepoKey: "local:/Users/v/.ssh/p"},
	}
	for name, sess := range bad {
		f, s, _ := ptFixture(t)
		f.sessions = []session{sess}
		newWatcher(f, s).handle(context.Background(), mac, reqIn("cli-9", sess.Cwd, "go test ./..."))
		if len(f.submits) != 1 || len(f.submits[0].Options) != 2 {
			t.Errorf("%s: options %+v", name, f.submits[0].Options)
		} else if p := f.submits[0].Preview.(map[string]any); !strings.HasPrefix(fmt.Sprint(p["project_trust"]), "not offered: ") {
			t.Errorf("%s: the approval doesn't say why: %v", name, p["project_trust"])
		}
	}
	// Rubi Home that can't answer the list: still two options, and the approval still goes out.
	f, s, _ := ptFixture(t)
	f.listHang = true
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if o, why := s.projectOffer(ctx, f, mac, reqIn("cli-1", ptRoot, "ls")); o != nil || why == "" {
		t.Fatalf("offer from a silent Rubi Home: %+v %q", o, why)
	}
}

func TestProjectTrustViaOptionAllowsOtherSessions(t *testing.T) {
	f, s, _ := ptFixture(t)
	id := grantViaOption(t, f, s, "cli-1", ptRoot)
	if !strings.HasPrefix(id, "pt_") {
		t.Fatalf("id %q", id)
	}
	// The command itself was allowed through execute, then the trust saved and audited.
	if len(f.decided) != 1 || f.decided[0].Behavior != "allow" {
		t.Fatalf("decided %+v", f.decided)
	}
	pts := s.st.projects(s.now())
	if len(pts) != 1 || pts[0].Root != ptRoot || pts[0].Device != "dev_mac" || pts[0].BranchPattern != "citri/*" ||
		!pts[0].Expires.Equal(time.Date(2026, 10, 31, 4, 0, 0, 0, berlin(t))) || pts[0].MaxUses != ptMaxUses {
		t.Fatalf("saved %+v", pts)
	}
	if !slices.Contains(f.audits, "project_trust_issued") {
		t.Fatalf("audits %v", f.audits)
	}
	// Two different sessions in the project, neither the one that asked in the sub-session's case: no question.
	for _, c := range []struct{ sess, cwd, cmd string }{
		{"cli-2", ptSub.Cwd, "go vet ./... && go test -race ./..."},
		{"cli-1", ptRoot, "git add -A && git commit -m 'x'"},
		{"cli-7", ptRoot + "/internal", "ls -la"},
		{"cli-8", ptRoot + "/.claude/worktrees/y/cmd", "make test"},
	} {
		before := len(f.submits)
		newWatcher(f, s).handle(context.Background(), mac, reqIn(c.sess, c.cwd, c.cmd))
		if len(f.submits) != before {
			t.Errorf("%s %q asked", c.sess, c.cmd)
		}
		d := f.decided[len(f.decided)-1]
		if d.Behavior != "allow" || d.SessionID != c.sess {
			t.Errorf("%s %q: %+v", c.sess, c.cmd, d)
		}
		a := f.auditLog[len(f.auditLog)-1]
		if f.audits[len(f.audits)-1] != auditMandateAll || a["mandate"] != id || a["session"] != c.sess || a["project"] != ptRoot {
			t.Errorf("audit %v %v", f.audits[len(f.audits)-1], a)
		}
	}
	if got := s.st.projects(s.now())[0].Uses; got != 4 {
		t.Errorf("uses %d", got)
	}
}

func asks(f *fakeHost, s *sisters, sess, cwd, cmd string) bool {
	f.mu.Lock()
	f.states = []string{"denied"}
	before := len(f.submits)
	f.mu.Unlock()
	newWatcher(f, s).handle(context.Background(), mac, reqIn(sess, cwd, cmd))
	return len(f.submits) > before
}

func TestProjectTrustStillAsks(t *testing.T) {
	f, s, _ := ptFixture(t)
	grantViaOption(t, f, s, "cli-1", ptRoot)
	still := []struct{ cwd, cmd string }{
		{"/Users/v/other", "ls"},                                // outside the root
		{"/Users/v", "ls"},                                      // above it
		{ptRoot + "2", "ls"},                                    // a sibling that shares the prefix
		{ptRoot, "git push"},                                    // push
		{ptRoot, "git push origin citri/x"},                     // push of an allowed branch
		{ptRoot, "git status && git push --force"},              // force
		{ptRoot, "git tag v1.0.0"},                              // tags
		{ptRoot, "git tag -a v1 -m release"},                    // annotated tag
		{ptRoot, "git push origin v1"},                          // a release push
		{ptRoot, "gh release create v1"},                        // releases
		{ptRoot, "sudo ls"},                                     // sudo
		{ptRoot, "curl https://example.com"},                    // network
		{ptRoot, "npm install left-pad"},                        // installs
		{ptRoot, "pip install x"},                               // installs
		{ptRoot, "rm -rf ../x"},                                 // writes outside
		{ptRoot, "cat x > /tmp/y"},                              // writes outside
		{ptRoot, "git switch main"},                             // a branch outside the pattern
		{ptRoot, "git checkout -b dev"},                         // creating one
		{ptRoot, "git checkout main && go test ./..."},          // a switch in a chain
		{ptRoot, "cat ~/.ssh/id_rsa"},                           // credentials
		{ptRoot + "/internal", "cd .. && cd .. && rm -rf x"},    // leaving the root
		{ptRoot + "/internal", "cd /Users/v/other && rm -rf x"}, // leaving the root
	}
	for _, c := range still {
		if !asks(f, s, "cli-2", c.cwd, c.cmd) {
			t.Errorf("%s: %q was allowed by the project trust", c.cwd, c.cmd)
		}
	}
	// The question says why this trust didn't cover it.
	if p := f.submits[len(f.submits)-1].Preview.(map[string]any); !strings.Contains(fmt.Sprint(p["mandate"]), "trust") {
		t.Errorf("no note: %v", p)
	}
	if asks(f, s, "cli-2", ptRoot, "git switch citri/ok") {
		t.Error("a branch inside the pattern asked")
	}
}

func TestBranchRule(t *testing.T) {
	const pat = "citri/*"
	allowed := []string{
		"git switch citri/x", "git switch -c citri/x", "git switch --create citri/x", "git switch --create=citri/x", "git switch -c citri/x main",
		"git switch --detach citri/x",
		"git checkout citri/x", "git checkout -b citri/x", "git checkout -bcitri/x", "git checkout -B citri/x main", "git checkout --detach citri/x",
		"git branch", "git branch -a", "git branch -vv", "git branch --list 'ma*'", "git branch --show-current", "git branch --merged main",
		"git branch citri/x", "git branch citri/x main", "git branch -m citri/a citri/b", "git branch -c citri/a citri/b", "git branch -d citri/a",
		"git worktree add -b citri/wt wt/x", "git worktree add --detach wt/w main", "git worktree list",
		"git stash branch citri/x", "git stash", "git rebase --no-update-refs main citri/x", "git rebase --no-update-refs --root citri/x", "git rebase --no-update-refs main",
		"git status", "git commit -m x", "git merge main", "git cherry-pick abc1234", "git -C . switch citri/x", "nohup git switch citri/x",
		"go test ./... && git switch -c citri/y && git commit -m z",
	}
	for _, c := range allowed {
		if ok, why := mandateAllowsBranch(c, root, root, pat); !ok {
			t.Errorf("%q asks: %s", c, why)
		}
	}
	asked := []string{
		"git switch main", "git switch -c main2", "git switch --create main", "git switch --create=main", "git switch -", "git switch citri/x/y", "git switch citri",
		"git switch --orphan dev", "git switch -t origin/citri/x", "git switch 'citri/*'", "git switch citri/../main",
		"git checkout main", "git checkout -b dev", "git checkout -B dev", "git checkout -bdev", "git checkout --orphan dev", "git checkout HEAD~1", "git checkout -",
		"git branch dev", "git branch dev citri/x", "git branch -m citri/a dev", "git branch -m dev citri/a", "git branch -d main", "git branch -c main citri/b",
		"git worktree add -b dev wt/x", "git worktree add wt/x", "git worktree add wt/x main",
		"git stash branch dev", "git rebase --no-update-refs main dev", "git rebase --no-update-refs --root dev", "git rebase --no-update-refs --onto main a dev",
		// a detached switch names a commit that may be main's tip: it asks
		"git switch --detach main", "git switch -d HEAD~1", "git checkout --detach main", "git switch --detach origin/main",
		"git -C . switch main", "nohup git switch main", "command git checkout main", "CI=1 git checkout dev",
		"git switch citri/x && git switch main", "ls | git switch main", "git status; git checkout -b dev",
		"git branch -r -d origin/main", "git branch -dr origin/main", "git branch --remotes -d origin/main", "git branch -r -m origin/main citri/x", "git branch -a -d main",
		"|", // what follows is refused by the option tables with or without the pattern
		"git rebase main citri/x", "git rebase --update-refs --onto main a", "git rebase --update-refs --no-update-refs main", "git rebase --no-update-refs --update-refs main",
		"git tag v1", "git tag -a v1 -m x", "git push", "git push origin citri/x", "git branch -D citri/x", "git switch -C citri/x", "git reset --hard",
	}
	tables := false
	for _, c := range asked {
		if c == "|" {
			tables = true
			continue
		}
		if ok, _ := mandateAllowsBranch(c, root, root, pat); ok {
			t.Errorf("%q was allowed", c)
		}
		// The pattern is what makes the branch commands ask: without it they are plain mandate commands.
		if ok, why := mandateAllows(c, root, root); ok == tables {
			t.Errorf("%q: without a pattern allowed=%v (%s); the case sits in the wrong group", c, ok, why)
		}
	}
	// A 2-hour trust has no branch rule: only the pattern makes it.
	for _, c := range []string{"git switch main", "git checkout -b dev", "git branch dev"} {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("without a pattern %q asks: %s", c, why)
		}
	}
	// Another pattern.
	if ok, _ := mandateAllowsBranch("git switch feature/x", root, root, "feature/*"); !ok {
		t.Error("feature/* refused feature/x")
	}
	if ok, _ := mandateAllowsBranch("git switch citri/x", root, root, "feature/*"); ok {
		t.Error("feature/* allowed citri/x")
	}
}

func TestCheckPattern(t *testing.T) {
	for in, want := range map[string]string{"": "citri/*", "  ": "citri/*", "feature/*": "feature/*", "citri/*-x": "citri/*-x", "r[0-9]": "r[0-9]"} {
		if got, err := checkPattern(in); err != nil || got != want {
			t.Errorf("%q -> %q %v", in, got, err)
		}
	}
	for _, in := range []string{"*", "ma*", "m?in", "[a-z]*", "dev*", "master", "trunk", "[", "a b", "-x", "/x", "a/../b", "x\ny", "a;b", "$x", strings.Repeat("a", 81), "é/*"} {
		if _, err := checkPattern(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestProjectTrustEnds(t *testing.T) {
	f, s, now := ptFixture(t)
	id := grantViaOption(t, f, s, "cli-1", ptRoot)
	if asks(f, s, "cli-2", ptSub.Cwd, "go test ./...") {
		t.Fatal("live trust asked")
	}
	// Expired: the next command asks, and the trust is gone from the list.
	later := now.Add(18 * time.Hour)
	s.now = func() time.Time { return later }
	if !asks(f, s, "cli-2", ptSub.Cwd, "go test ./...") {
		t.Fatal("an expired trust allowed a command")
	}
	if len(s.st.projects(later)) != 0 {
		t.Fatal("expired trust still listed")
	}
	_ = id
	// A trust used up asks too.
	s.now = func() time.Time { return *now }
	grantViaOption(t, f, s, "cli-1", ptRoot)
	s.st.mu.Lock()
	s.st.st.Projects[0].MaxUses = 2
	s.st.mu.Unlock()
	for i := range 2 {
		if asks(f, s, "cli-1", ptRoot, "ls") {
			t.Fatalf("use %d asked", i)
		}
	}
	if !asks(f, s, "cli-1", ptRoot, "ls") {
		t.Fatal("a used-up trust allowed")
	}
}

func TestProjectTrustRevokeAndCoexistence(t *testing.T) {
	f, s, now := ptFixture(t)
	// A 2-hour trust for the sub-session, then a project trust.
	md := mandate{ID: "md_1", Device: "dev_mac", SessionID: "cli-2", Cwd: ptSub.Cwd, Issued: *now, Expires: now.Add(2 * time.Hour), MaxUses: 300}
	if err := s.st.issue(md, *now); err != nil {
		t.Fatal(err)
	}
	pt := grantViaOption(t, f, s, "cli-1", ptRoot)
	// Which one allows is told by the audit: the session's own mandate first.
	asks(f, s, "cli-2", ptSub.Cwd, "ls")
	if a := f.auditLog[len(f.auditLog)-1]; a["mandate"] != "md_1" {
		t.Fatalf("audit %v", a)
	}
	// Only the project trust covers the main session and a command outside the sub-session's directory.
	if asks(f, s, "cli-1", ptRoot, "ls") || asks(f, s, "cli-2", ptRoot+"/cmd", "ls") {
		t.Fatal("project trust didn't allow")
	}
	// Revoking the project trust leaves the 2-hour one.
	res, err := s.mandatesTool(f, mandatesIn{Revoke: pt})
	if err != nil || res.(map[string]any)["revoked"] != 1 {
		t.Fatalf("%v %v", res, err)
	}
	if !asks(f, s, "cli-1", ptRoot, "ls") {
		t.Error("revoked project trust still allowed")
	}
	if asks(f, s, "cli-2", ptSub.Cwd, "ls") {
		t.Error("revoking the project trust ended the 2-hour trust")
	}
	// And the other way round.
	pt = grantViaOption(t, f, s, "cli-1", ptRoot)
	if _, err := s.mandatesTool(f, mandatesIn{Revoke: "md_1"}); err != nil {
		t.Fatal(err)
	}
	if asks(f, s, "cli-1", ptRoot, "ls") {
		t.Error("revoking the 2-hour trust ended the project trust")
	}
	// The list shows it, the panel's revoke ends it, and "all" ends everything.
	list, _ := s.mandatesTool(f, mandatesIn{})
	pl := list.(map[string]any)["project_trusts"].([]map[string]any)
	if len(pl) != 1 || pl[0]["id"] != pt || pl[0]["project_root"] != ptRoot || pl[0]["branches"] != "citri/*" || pl[0]["uses"] == nil {
		t.Fatalf("list %v", list)
	}
	view, err := s.panel(f, "view", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(view)
	for _, want := range []string{"Trusted projects", ptRoot, "citri/*", "Sat 31 Oct 04:00 CET", "\"op\":\"revoke\"", pt} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("panel lacks %q: %s", want, raw)
		}
	}
	if _, err := s.panel(f, "revoke", json.RawMessage(`{"id":"`+pt+`"}`)); err != nil || len(s.st.projects(*now)) != 0 {
		t.Fatalf("panel revoke: %v %v", err, s.st.projects(*now))
	}
	grantViaOption(t, f, s, "cli-1", ptRoot)
	if r, _ := s.mandatesTool(f, mandatesIn{Revoke: "all"}); r.(map[string]any)["revoked"] != 1 || len(s.st.projects(*now)) != 0 {
		t.Fatalf("revoke all: %v", r)
	}
}

func TestProjectTrustReplacesTheOldOne(t *testing.T) {
	f, s, _ := ptFixture(t)
	first := grantViaOption(t, f, s, "cli-1", ptRoot)
	second := grantViaOption(t, f, s, "cli-2", ptSub.Cwd)
	pts := s.st.projects(s.now())
	if len(pts) != 1 || pts[0].ID != second || first == second {
		t.Fatalf("%+v", pts)
	}
	var replaced map[string]any
	for i, a := range f.audits {
		if a == "project_trust_replaced" {
			replaced = f.auditLog[i]
		}
	}
	if replaced == nil || replaced["mandate"] != first || replaced["by"] != second {
		t.Fatalf("replace audit %v (%v)", replaced, f.audits)
	}
	// Another project (or computer) is a trust of its own.
	if err := func() error {
		_, err := s.st.issueProject(projectTrust{ID: "pt_x", Device: "dev_mac", Root: "/Users/v/other", BranchPattern: "citri/*", Expires: s.now().Add(time.Hour), MaxUses: 5}, s.now())
		return err
	}(); err != nil || len(s.st.projects(s.now())) != 2 {
		t.Fatalf("%v %v", err, s.st.projects(s.now()))
	}
}

func TestProjectTrustSurvivesARestart(t *testing.T) {
	f, s, now := ptFixture(t)
	id := grantViaOption(t, f, s, "cli-1", ptRoot)
	asks(f, s, "cli-2", ptSub.Cwd, "ls") // a use, saved
	// The plugin starts again and loads the saved state.
	s2 := newSisters(&store{})
	if err := s2.st.load(f); err != nil {
		t.Fatal(err)
	}
	s2.loc, s2.now = s.loc, s.now
	pts := s2.st.projects(*now)
	if len(pts) != 1 || pts[0].ID != id || pts[0].Uses != 1 {
		t.Fatalf("after restart: %+v", pts)
	}
	if asks(f, s2, "cli-1", ptRoot, "go test ./...") {
		t.Error("the restarted plugin asks")
	}
	// An expired one is dropped on load.
	later := now.Add(48 * time.Hour)
	s3 := newSisters(&store{})
	_ = s3.st.load(f)
	if len(s3.st.projects(later)) != 0 {
		t.Error("expired trust survived")
	}
}

func TestAuditNamesTheTrust(t *testing.T) {
	f, s, _ := ptFixture(t)
	id := grantViaOption(t, f, s, "cli-1", ptRoot)
	asks(f, s, "cli-2", ptSub.Cwd, "go test ./...")
	a := f.auditLog[len(f.auditLog)-1]
	if f.audits[len(f.audits)-1] != auditMandateAll || a["mandate"] != id || a["command"] != "go test ./..." || a["directory"] != ptSub.Cwd {
		t.Fatalf("audit %v %v", f.audits, a)
	}
}

// ---- the Bot ----

// ptBot is the fixture with Citri bound to the project's main session.
func ptBot(t *testing.T) (*fakeHost, *sisters, string) {
	t.Helper()
	f, s, _ := ptFixture(t)
	bindAs(t, f, s, "Citri", "local_a")
	code := f.events[len(f.events)-1]["bind_code"].(string)
	f.submits = nil
	return f, s, code
}

func TestTrustProjectToolAsksStrongAndGrantsOnApproval(t *testing.T) {
	f, s, code := ptBot(t)
	ctx := context.Background()
	if _, err := s.trustTool(ctx, f, trustIn{BindCode: code}); err == nil {
		t.Fatal("unverified caller accepted")
	}
	if _, err := s.trustTool(ctx, f, trustIn{VerifiedAgent: "Citri", BindCode: "bc_wrong"}); err == nil {
		t.Fatal("wrong bind code accepted")
	}
	if _, err := s.trustTool(ctx, f, trustIn{VerifiedAgent: "Vega", BindCode: code}); err == nil {
		t.Fatal("another Bot used Citri's code")
	}
	if _, err := s.trustTool(ctx, f, trustIn{VerifiedAgent: "Citri", BindCode: code, BranchPattern: "a b"}); err == nil {
		t.Fatal("bad pattern accepted")
	}
	if len(f.submits) != 0 || len(s.st.projects(s.now())) != 0 {
		t.Fatal("something was asked or granted by a refused call")
	}
	res, err := s.trustTool(ctx, f, trustIn{VerifiedAgent: "Citri", BindCode: code, BranchPattern: "citri/*"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" || len(f.submits) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	sub := f.submits[0]
	if sub.Kind != kindTrustProject || len(sub.Options) != 1 || sub.Options[0].Key != optionTrustProject {
		t.Fatalf("%+v", sub)
	}
	text, _ := json.Marshal(sub.Preview)
	for _, want := range []string{"Sat 31 Oct 2026 04:00 CET", ptRoot, "Mac", "citri/*", "Citri", "Europe/Berlin", "Still asks", "github.com/v/rubi"} {
		if !strings.Contains(string(text)+sub.Options[0].Label+sub.Options[0].Meaning, want) {
			t.Errorf("approval lacks %q: %s", want, text)
		}
	}
	for _, a := range manifest().Actions {
		if a.Kind == kindTrustProject && (a.DefaultLevel != rubiplugin.Strong || !a.Locked) {
			t.Fatalf("action %+v", a)
		}
	}
	if len(s.st.projects(s.now())) != 0 {
		t.Fatal("granted before the approval")
	}
	payload, _ := json.Marshal(sub.Payload)
	var tk trustTicket
	_ = json.Unmarshal(payload, &tk)
	out, err := s.executeTrust(f, tk)
	if err != nil {
		t.Fatal(err)
	}
	pts := s.st.projects(s.now())
	if len(pts) != 1 || pts[0].Root != ptRoot || pts[0].Sister != "Citri" || out.(map[string]any)["mandate"] != pts[0].ID {
		t.Fatalf("%+v %v", pts, out)
	}
	// Commands of the project's sessions are allowed now, by this trust.
	if asks(f, s, "cli-2", ptSub.Cwd, "go test ./...") {
		t.Error("asked")
	}
	// A second grant (with another pattern) replaces it, both audited.
	if _, err := s.trustTool(ctx, f, trustIn{VerifiedAgent: "Citri", BindCode: code, BranchPattern: "feature/*"}); err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(f.submits[len(f.submits)-1].Payload)
	_ = json.Unmarshal(payload, &tk)
	if p := f.submits[len(f.submits)-1].Preview.(map[string]any); p["replaces"] == nil {
		t.Errorf("no replace note: %v", p)
	}
	if _, err := s.executeTrust(f, tk); err != nil {
		t.Fatal(err)
	}
	if pts = s.st.projects(s.now()); len(pts) != 1 || pts[0].BranchPattern != "feature/*" || !slices.Contains(f.audits, "project_trust_replaced") {
		t.Fatalf("%+v %v", pts, f.audits)
	}
	// An approval answered after the trust's end time grants nothing.
	late := s.now().Add(30 * time.Hour)
	s.now = func() time.Time { return late }
	if _, err := s.executeTrust(f, tk); err == nil {
		t.Error("a late approval granted a trust")
	}
}

func TestTrustProjectToolRefusesWithoutAProject(t *testing.T) {
	f, s, code := ptBot(t)
	f.sessions = []session{{SessionID: "cli-1", AppSessionID: "local_a", Cwd: "/Users/v", ProjectRoot: "/Users/v", RepoKey: "local:/Users/v", State: "idle"}}
	if _, err := s.trustTool(context.Background(), f, trustIn{VerifiedAgent: "Citri", BindCode: code}); err == nil || !strings.Contains(err.Error(), "too high") {
		t.Fatalf("%v", err)
	}
	f.sessions = []session{{SessionID: "cli-1", AppSessionID: "local_a", Cwd: ptRoot, State: "idle"}}
	if _, err := s.trustTool(context.Background(), f, trustIn{VerifiedAgent: "Citri", BindCode: code}); err == nil {
		t.Fatal("a session without a project")
	}
	f.sessions = []session{{SessionID: "cli-1", AppSessionID: "local_a", Cwd: ptRoot, ProjectRoot: ptRoot, RepoKey: "local:" + ptRoot, State: "ended"}}
	if _, err := s.trustTool(context.Background(), f, trustIn{VerifiedAgent: "Citri", BindCode: code}); err == nil {
		t.Fatal("an ended session")
	}
	if len(f.submits) != 0 {
		t.Fatal("asked")
	}
}

func TestBotStartsAndBindsInATrustedProjectWithoutAsking(t *testing.T) {
	f, s, code := ptBot(t)
	ctx := context.Background()
	f.createFn = func(_ context.Context, a map[string]any) (map[string]any, error) {
		return map[string]any{"launched": true, "session_id": "cli-new", "cwd": a["cwd"], "permission_mode": "default"}, nil
	}
	// Before the trust: it asks.
	if res, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Citri", Cwd: ptRoot + "/sub", Task: "x"}); err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatalf("%v %v", res, err)
	}
	f.submits = nil
	pt := grantViaOption(t, f, s, "cli-1", ptRoot)
	f.submits = nil

	f.sessions = append(f.sessions, session{SessionID: "cli-new", Title: "new", Cwd: ptRoot + "/sub", ProjectRoot: ptRoot, RepoKey: "github.com/v/rubi", Role: "sub", Source: "hook", State: "idle"})
	res, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Citri", Cwd: ptRoot + "/sub", Task: "run the tests"})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if len(f.submits) != 0 || m["started"] != true || m["bound"] != true || m["session_id"] != "cli-new" || !strings.Contains(fmt.Sprint(m["approval"]), pt) {
		t.Fatalf("submits %d, result %v", len(f.submits), m)
	}
	if len(f.creates) != 1 || f.creates[0]["cwd"] != ptRoot+"/sub" || f.creates[0]["from"] != "Citri" {
		t.Fatalf("creates %v", f.creates)
	}
	if bs := s.st.bindings(); len(bs) != 1 || bs[0].SessionID != "cli-new" {
		t.Fatalf("not bound to the new session: %+v", bs)
	}
	// Audited with the trust's id.
	var found bool
	for i, a := range f.audits {
		if a == auditMandateAll && f.auditLog[i]["mandate"] == pt && f.auditLog[i]["action"] == "claude_code_start" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audits %v", f.audits)
	}
	// The new binding's code is a new one: the Bot is still bound inside the project, so it can go on.
	code = f.events[len(f.events)-1]["bind_code"].(string)

	s.hits = map[string][]time.Time{} // the hourly limits are tested in start_test.go
	// Outside the project it asks; so does a Bot that isn't bound inside it; the input checks still apply.
	f.submits = nil
	for _, c := range []struct{ bot, cwd string }{{"Citri", "/Users/v/other"}, {"Citri", ptRoot + "2"}, {"Citri", "/Users/v"}, {"Vega", ptRoot + "/sub"}} {
		res, err := s.startTool(ctx, f, startIn{VerifiedAgent: c.bot, Cwd: c.cwd, Task: "x"})
		if err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
			t.Errorf("%s %s: %v %v", c.bot, c.cwd, res, err)
		}
	}
	if len(f.creates) != 1 {
		t.Errorf("a session was started without approval: %v", f.creates)
	}
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Citri", Cwd: ptRoot + "/sub", Task: "bad\u202etext"}); err == nil {
		t.Error("the text check was skipped")
	}
	if _, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Citri", Cwd: ptRoot + "/../other", Task: "x"}); err != nil {
		// path.Clean puts it outside the root: it asks, it doesn't start.
		t.Errorf("%v", err)
	}
	if len(f.creates) != 1 {
		t.Errorf("a dotted path started a session: %v", f.creates)
	}

	// Bind to another session of the project: no approval; to one outside: asks.
	f.submits = nil
	res, err = s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: "local_b"})
	if err != nil || len(f.submits) != 0 || res.(map[string]any)["bound"] != true || !strings.Contains(fmt.Sprint(res.(map[string]any)["approval"]), pt) {
		t.Fatalf("bind in project: %v %v (%d submits)", res, err, len(f.submits))
	}
	if bs := s.st.bindings(); len(bs) != 1 || bs[0].AppSessionID != "local_b" {
		t.Fatalf("%+v", bs)
	}
	res, err = s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: "cli-3"})
	if err != nil || len(f.submits) != 1 || res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatalf("bind outside: %v %v", res, err)
	}
	// A Bot with no binding in the project still has to ask.
	f.submits = nil
	if res, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", SessionID: "local_a"}); err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatalf("another Bot: %v %v", res, err)
	}
	// Audit of the bind carries the trust.
	var bindAudit bool
	for i, a := range f.audits {
		if a == auditMandateAll && f.auditLog[i]["mandate"] == pt && f.auditLog[i]["action"] == "claude_code_bind" {
			bindAudit = true
		}
	}
	if !bindAudit {
		t.Errorf("no audit of the bind: %v", f.audits)
	}
	// Send and status never needed an approval.
	f.submits = nil
	b := s.st.bindings()[0]
	if _, err := s.sendTool(ctx, f, sendIn{Sister: "Citri", BindCode: b.Code, Text: "hi"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.statusTool(ctx, f, statusIn{Sister: "Citri", BindCode: b.Code}); err != nil {
		t.Fatal(err)
	}
	if len(f.submits) != 0 {
		t.Fatal("send or status asked")
	}
	_ = code
}

func TestBotNeedsApprovalAfterTheTrustEnds(t *testing.T) {
	f, s, _ := ptBot(t)
	ctx := context.Background()
	pt := grantViaOption(t, f, s, "cli-1", ptRoot)
	f.submits = nil
	// Revoked.
	if _, err := s.mandatesTool(f, mandatesIn{Revoke: pt}); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: "local_b"}); res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatal("bind without a trust")
	}
	// Expired.
	grantViaOption(t, f, s, "cli-1", ptRoot)
	s.now = func() time.Time { return time.Date(2026, 10, 31, 4, 0, 1, 0, s.zone()) }
	f.submits = nil
	if res, _ := s.startTool(ctx, f, startIn{VerifiedAgent: "Citri", Cwd: ptRoot, Task: "x"}); res.(map[string]any)["status"] != "awaiting_approval" || len(f.creates) != 0 {
		t.Fatal("start with an expired trust")
	}
}

func TestProjectTrustTextIsHonest(t *testing.T) {
	m := manifest()
	run, _ := m.Action(kindRun)
	if len(run.Options) != 4 || run.Options[2].Key != optionTrustProject || run.Options[3].Key != optionTrustForever {
		t.Fatalf("run options %+v", run.Options)
	}
	for _, want := range []string{"04:00", "24 hours", "still ask", "git tag", "start and bind sessions", "revoke"} {
		if !strings.Contains(run.Options[2].Meaning, want) {
			t.Errorf("manifest meaning lacks %q", want)
		}
	}
}

// ---- review fixes ----

func TestRebaseNeedsNoUpdateRefs(t *testing.T) {
	// git rebase --update-refs (or rebase.updateRefs in the config) moves other branches, main included.
	bad := []string{"git rebase --update-refs --onto main a", "git rebase --update-refs --onto main a citri/x", "git rebase main", "git rebase --onto main a",
		"git rebase --no-update-refs --update-refs main", "git rebase --update-refs --no-update-refs main", "git rebase --update-refs", "git rebase"}
	for _, c := range bad {
		if ok, _ := mandateAllows(c, root, root); ok {
			t.Errorf("md: %q allowed", c)
		}
		if ok, _ := mandateAllowsBranch(c, root, root, "citri/*"); ok {
			t.Errorf("pt: %q allowed", c)
		}
	}
	for _, c := range []string{"git rebase --no-update-refs main", "git rebase --no-update-refs --onto main a", "git rebase --continue", "git rebase --abort", "git rebase --skip"} {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("md: %q asks: %s", c, why)
		}
	}
	if ok, why := mandateAllowsBranch("git rebase --no-update-refs main citri/x", root, root, "citri/*"); !ok {
		t.Errorf("%s", why)
	}
}

func TestBranchRemoteDeleteIsChecked(t *testing.T) {
	for _, c := range []string{"git branch -r -d origin/main", "git branch -dr origin/main", "git branch --remotes -d origin/main", "git branch -d -r origin/main",
		"git branch -a -d main", "git branch -r -m origin/main x", "git branch --all -c main citri/x"} {
		if ok, _ := mandateAllowsBranch(c, root, root, "citri/*"); ok {
			t.Errorf("%q allowed", c)
		}
	}
	// Listing remote branches is still a listing.
	for _, c := range []string{"git branch -r", "git branch -a", "git branch -r --list 'origin/*'"} {
		if ok, why := mandateAllowsBranch(c, root, root, "citri/*"); !ok {
			t.Errorf("%q asks: %s", c, why)
		}
	}
}

// A live 2-hour trust must not be a way around the project trust's branch rule.
func TestTwoHourTrustHonoursTheBranchRule(t *testing.T) {
	f, s, now := ptFixture(t)
	md := mandate{ID: "md_1", Device: "dev_mac", SessionID: "cli-2", Cwd: ptSub.Cwd, Issued: *now, Expires: now.Add(2 * time.Hour), MaxUses: 300}
	if err := s.st.issue(md, *now); err != nil {
		t.Fatal(err)
	}
	if asks(f, s, "cli-2", ptSub.Cwd, "git switch main") {
		t.Fatal("without a project trust the 2-hour trust allows a switch (as before)")
	}
	grantViaOption(t, f, s, "cli-1", ptRoot)
	if !asks(f, s, "cli-2", ptSub.Cwd, "git switch main") || !asks(f, s, "cli-2", ptSub.Cwd, "git checkout -b dev") {
		t.Fatal("the 2-hour trust allowed a branch the project trust forbids")
	}
	if asks(f, s, "cli-2", ptSub.Cwd, "git switch -c citri/ok") {
		t.Fatal("a branch inside the pattern asked")
	}
	// A session elsewhere keeps its own 2-hour trust as it was.
	md2 := mandate{ID: "md_2", Device: "dev_mac", SessionID: "cli-3", Cwd: "/Users/v/other", Issued: *now, Expires: now.Add(time.Hour), MaxUses: 300}
	_ = s.st.issue(md2, *now)
	if asks(f, s, "cli-3", "/Users/v/other", "git switch main") {
		t.Fatal("a trust outside the project was restricted")
	}
}

func TestRootBreadth(t *testing.T) {
	cases := []struct {
		root, key string
		ok        bool
	}{
		{"/Users/v/rubi", "github.com/v/rubi", true},
		{"/Users/v/Documents/stuff", "local:/Users/v/Documents/stuff", false}, // no remote, 4 parts is fine, but...
		{"/Users/v/Documents", "github.com/v/docs", false},
		{"/Users/v/Downloads", "local:/Users/v/Downloads", false},
		{"/Users/v/Dev", "local:/Users/v/Dev", false},
		{"/Users/v/Dev/proj", "local:/Users/v/Dev/proj", true},
		{"/Volumes/Crucial", "local:/Volumes/Crucial", false},
		{"/Volumes/Crucial/proj", "local:/Volumes/Crucial/proj", false},
		{"/Volumes/Crucial/Projects/x", "local:/Volumes/Crucial/Projects/x", true},
		{"/Users/v", "github.com/v/home", false},
		{"/", "local:/", false},
		{"/Users/v/rubi", "", false},
	}
	for _, c := range cases {
		why := rootProblem(c.root, c.key)
		want := c.ok
		if c.root == "/Users/v/Documents/stuff" {
			want = true // deeper than a documents folder: fine
		}
		if (why == "") != want {
			t.Errorf("%s (%s): %q", c.root, c.key, why)
		}
	}
}

func TestSymlinkedSessionDirectoryIsNotTrusted(t *testing.T) {
	// Rubi Home resolved the session's directory: it leads outside the project.
	f, s, _ := ptFixture(t)
	f.sessions = []session{{SessionID: "cli-1", AppSessionID: "local_a", Cwd: ptRoot + "/link", ProjectRoot: ptRoot, RealRoot: ptRoot,
		RealCwd: "/Users/v/elsewhere", RepoKey: "github.com/v/rubi", State: "idle"}}
	newWatcher(f, s).handle(context.Background(), mac, reqIn("cli-1", ptRoot+"/link", "go test ./..."))
	if len(f.submits[0].Options) != 2 || !strings.Contains(fmt.Sprint(f.submits[0].Preview.(map[string]any)["project_trust"]), "symlinks") {
		t.Fatalf("%+v %v", f.submits[0].Options, f.submits[0].Preview)
	}
	// A root that is itself a symlink path: the real directory is under the real root, which is fine.
	f.sessions = []session{{SessionID: "cli-1", Cwd: ptRoot + "/sub", ProjectRoot: ptRoot, RealRoot: "/private/v/rubi", RealCwd: "/private/v/rubi/sub", RepoKey: "github.com/v/rubi"}}
	if o, why := s.projectOffer(context.Background(), f, mac, reqIn("cli-1", ptRoot+"/sub", "ls")); o == nil || o.RealRoot != "/private/v/rubi" {
		t.Fatalf("%v %v", o, why)
	}
}

func TestBotChecksUnderTheShortcut(t *testing.T) {
	ctx := context.Background()
	f, s, _ := ptBot(t)
	grantViaOption(t, f, s, "cli-1", ptRoot)
	f.submits = nil
	f.createFn = func(_ context.Context, a map[string]any) (map[string]any, error) {
		return map[string]any{"launched": true, "session_id": "cli-new", "cwd": "/Users/v/elsewhere", "permission_mode": "default"}, nil
	}
	// A dotted path is sent cleaned, and one that leaves the root asks.
	res, err := s.startTool(ctx, f, startIn{VerifiedAgent: "Citri", Cwd: ptRoot + "/a/../../other", Task: "x"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" || len(f.creates) != 0 {
		t.Fatalf("%v %v %v", res, err, f.creates)
	}
	// Rubi Home started it somewhere else (a symlink inside the project): the Bot is unbound and told.
	f.submits = nil
	_, err = s.startTool(ctx, f, startIn{VerifiedAgent: "Citri", Cwd: ptRoot + "/a/./b", Task: "x"})
	if err == nil || !strings.Contains(err.Error(), "outside the trusted project") || len(f.creates) != 1 || f.creates[0]["cwd"] != ptRoot+"/a/b" {
		t.Fatalf("%v %v", err, f.creates)
	}
	if len(s.st.bindings()) != 0 || !slices.Contains(f.audits, "project_trust_start_outside") {
		t.Fatalf("bindings %v audits %v", s.st.bindings(), f.audits)
	}
}

func TestShortcutNeedsALiveBoundSessionInsideTheRoot(t *testing.T) {
	ctx := context.Background()
	f, s, _ := ptBot(t)
	grantViaOption(t, f, s, "cli-1", ptRoot)
	f.submits = nil
	// The bound session ended.
	f.sessions[0].State = "ended"
	if res, _ := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: "local_b"}); res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatal("bind with an ended bound session")
	}
	// It moved out of the project.
	f.sessions[0].State, f.sessions[0].Cwd = "idle", "/Users/v/other"
	f.submits = nil
	if res, _ := s.startTool(ctx, f, startIn{VerifiedAgent: "Citri", Cwd: ptRoot + "/sub", Task: "x"}); res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatal("start with a bound session outside the root")
	}
	// The target session resolves outside the real root.
	f.sessions[0].Cwd = ptRoot
	f.sessions[1].RealCwd = "/Users/v/other"
	f.sessions[0].RealRoot = ""
	f.submits = nil
	s.st.mu.Lock()
	s.st.st.Projects[0].RealRoot = ptRoot
	s.st.mu.Unlock()
	if res, _ := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: "local_b"}); res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatal("bind to a session whose real directory is outside")
	}
}

func TestBindUnderTrustIsRateLimited(t *testing.T) {
	ctx := context.Background()
	f, s, _ := ptBot(t)
	grantViaOption(t, f, s, "cli-1", ptRoot)
	f.submits = nil
	for i := 0; i < bindsUnderTrustPerHour; i++ {
		f.sessions[0], f.sessions[1] = f.sessions[1], f.sessions[0]
		id := "local_b"
		if s.st.bindings()[0].AppSessionID == "local_b" {
			id = "local_a"
		}
		res, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: id})
		if err != nil || res.(map[string]any)["bound"] != true {
			t.Fatalf("bind %d: %v %v", i, res, err)
		}
	}
	res, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Citri", SessionID: "local_b"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatalf("past the limit: %v %v", res, err)
	}
}

func TestFailedSaveChangesNothing(t *testing.T) {
	f, s, now := ptFixture(t)
	md := mandate{ID: "md_1", Device: "dev_mac", SessionID: "cli-2", Cwd: ptSub.Cwd, Issued: *now, Expires: now.Add(time.Hour), MaxUses: 300}
	if err := s.st.issue(md, *now); err != nil {
		t.Fatal(err)
	}
	id := grantViaOption(t, f, s, "cli-1", ptRoot)
	f.saveErr = errors.New("disk full")
	if err := s.st.issue(mandate{ID: "md_2", Device: "dev_mac", SessionID: "cli-1", Cwd: ptRoot, Expires: now.Add(time.Hour), MaxUses: 300}, *now); err == nil {
		t.Fatal("save error ignored")
	}
	if _, err := s.st.issueProject(projectTrust{ID: "pt_new", Device: "dev_mac", Root: ptRoot, BranchPattern: "citri/*", Expires: now.Add(time.Hour), MaxUses: 5}, *now); err == nil {
		t.Fatal("save error ignored")
	}
	if ms := s.st.mandates(*now); len(ms) != 1 || ms[0].ID != "md_1" {
		t.Fatalf("mandates %+v", ms)
	}
	if ps := s.st.projects(*now); len(ps) != 1 || ps[0].ID != id {
		t.Fatalf("the old trust was replaced by one that wasn't saved: %+v", ps)
	}
	// And through the approval: not trusted, and the command is still allowed (it was approved).
	newWatcher(f, s).handle(context.Background(), mac, reqIn("cli-1", ptRoot, "go test ./..."))
	payload, _ := json.Marshal(f.submits[len(f.submits)-1].Payload)
	res, _ := runApproved(context.Background(), f, s, optionTrustProject, payload)
	if m := res.(map[string]any); m["trusted"] != false || m["allowed"] != true {
		t.Fatalf("%v", m)
	}
}

func TestExpiryBeyond24HoursIsRefused(t *testing.T) {
	f, s, _ := ptFixture(t)
	o, err := s.offerFor(ptRoot, "github.com/v/rubi", "", "Mac")
	if err != nil {
		t.Fatal(err)
	}
	o.Expires = s.now().Add(25 * time.Hour)
	if _, err := s.grantProject(f, "dev_mac", "Mac", "", o); err == nil {
		t.Fatal("a 25 hour trust was granted")
	}
	o.Expires = s.now().Add(24 * time.Hour)
	if _, err := s.grantProject(f, "dev_mac", "Mac", "", o); err != nil {
		t.Fatal(err)
	}
}

func TestCapEvictionIsAudited(t *testing.T) {
	f, s, _ := ptFixture(t)
	for i := range maxProjectTrusts + 1 {
		o, _ := s.offerFor(fmt.Sprintf("/Users/v/p%d", i), "github.com/v/p", "", "Mac")
		if _, err := s.grantProject(f, "dev_mac", "Mac", "", o); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.st.projects(s.now())) != maxProjectTrusts || !slices.Contains(f.audits, "project_trust_replaced") {
		t.Fatalf("%d trusts, audits %v", len(s.st.projects(s.now())), f.audits)
	}
}

func TestLabelNamesTheRootAndShortensIt(t *testing.T) {
	_, s, _ := ptFixture(t)
	long := "/Users/v/" + strings.Repeat("deep/", 12) + "project"
	o, err := s.offerFor(long, "github.com/v/p", "", "Mac")
	if err != nil {
		t.Fatal(err)
	}
	l := s.trustLabel(o)
	if !strings.Contains(l, "…") || !strings.HasSuffix(l, "project until Sat 31 Oct 2026 04:00 CET") || len([]rune(l)) > 100 {
		t.Fatalf("%q", l)
	}
	if m := s.trustMeaning(o, true); !strings.Contains(m, long) || strings.Contains(m, "changes nothing") {
		t.Fatalf("meaning: %s", m)
	}
	// A local zone is shown by its abbreviation and offset, never as "Local".
	s.loc = nil
	o2, _ := s.offerFor(ptRoot, "github.com/v/rubi", "", "Mac")
	if n := s.zoneNote(o2); strings.Contains(n, "Local") || !strings.Contains(n, "UTC") {
		t.Fatalf("%s", n)
	}
}
