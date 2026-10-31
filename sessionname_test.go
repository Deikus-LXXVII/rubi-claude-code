package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

func TestCheckAliasName(t *testing.T) {
	ok := []struct{ in, want string }{
		{"api work", "api work"},
		{"  padded  ", "padded"},
		{"\tTabs outside\n", "Tabs outside"},
		{"Привет, мир", "Привет, мир"},
		{"日本語のセッション", "日本語のセッション"},
		{strings.Repeat("x", 64), strings.Repeat("x", 64)},
		{strings.Repeat("я", 64), strings.Repeat("я", 64)},
		{"fix-123", "fix-123"},
		{"localhost", "localhost"},
		{"local-notes", "local-notes"},
		{"deadbee", "deadbee"}, // seven hex characters: not id-like
		{"md_", "md_"},
		{"café", "caf\u00e9"}, // precomposed
		{"build #3 (v2) - 100%", "build #3 (v2) - 100%"},
		{"rocket \U0001F680", "rocket \U0001F680"},
		{"ß and ǅ", "ß and ǅ"},
	}
	for _, c := range ok {
		if got, err := checkAliasName(c.in); err != nil || got != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	bad := map[string]string{
		"empty":              "",
		"spaces only":        "   \t ",
		"65 runes":           strings.Repeat("x", 65),
		"65 cyrillic":        strings.Repeat("я", 65),
		"newline inside":     "a\nb",
		"tab inside":         "a\tb",
		"NUL":                "a\x00b",
		"escape":             "a\x1bb",
		"C1 control":         "a\u0085b",
		"zero width space":   "a\u200bb",
		"zero width joiner":  "a\u200db",
		"bidi override":      "a\u202eb",
		"bidi isolate":       "\u2066a\u2069",
		"bom":                "\ufeffname",
		"soft hyphen":        "a\u00adb",
		"word joiner":        "a\u2060b",
		"line separator":     "a\u2028b",
		"paragraph sep":      "a\u2029b",
		"tag character":      "a\U000e0041b",
		"private use":        "a\ue000b",
		"nbsp inside":        "a\u00a0b",
		"ideographic space":  "a\u3000b",
		"double space":       "a  b",
		"invalid utf8":       "a\xffb",
		"local_ prefix":      "local_notes",
		"LOCAL_ upper":       "LOCAL_abc",
		"local_ uuid":        "local_0c3f1d2e-aaaa-bbbb-cccc-1234567890ab",
		"uuid":               "0c3f1d2e-9a41-4f6e-8d3b-5b6a7c8d9e0f",
		"uuid upper":         "0C3F1D2E-9A41-4F6E-8D3B-5B6A7C8D9E0F",
		"uuid without dash":  "0c3f1d2e9a414f6e8d3b5b6a7c8d9e0f",
		"hex id prefix":      "0c3f1d2e",
		"digits only id":     "12345678",
		"mandate id":         "md_abcdefghijklmnop",
		"project trust id":   "pt_ABCDEFGHIJKLMNOP",
		"bind code":          "bc_0123456789abcdef",
		"ask id":             "ask_0123456789abcdef",
		"request id":         "cc_0123456789abcdef",
		"nbsp-only after tr": "\u200b",
		"combining acute":    "e\u0301",
		"combining only":     "\u0301",
		"variation selector": "a\ufe0fb",
		"vs15":               "a\ufe0e",
		"hangul choseong":    "a\u115fb",
		"hangul jungseong":   "a\u1160b",
		"hangul filler":      "a\u3164b",
		"halfwidth filler":   "a\uffa0b",
		"khmer vowel 1":      "a\u17b4b",
		"khmer vowel 2":      "a\u17b5b",
		"braille blank":      "a\u2800b",
		"mongolian vs":       "a\u180eb",
		"unassigned":         "a\u0378b",
		"emoji zwj sequence": "\U0001F468\u200d\U0001F469",
		"noncharacter":       "a\ufffeb",
		"surrogate":          "a\xed\xa0\x80b",
	}
	for why, in := range bad {
		if got, err := checkAliasName(in); err == nil {
			t.Errorf("%s: %q accepted as %q", why, in, got)
		}
	}
	// The 64 limit counts characters, not bytes.
	if _, err := checkAliasName(strings.Repeat("é", 64)); err != nil {
		t.Errorf("64 two-byte characters refused: %v", err)
	}
}

// renameFixture is boundFixture: Alice is bound to the main session (local_a / cli-1).
func renameFixture(t *testing.T) (*fakeHost, *sisters) {
	t.Helper()
	f, s, _ := boundFixture(t)
	f.submits = nil
	return f, s
}

func rename(s *sisters, f *fakeHost, bot string, in renameIn) (any, error) {
	in.VerifiedAgent = bot
	return s.renameTool(context.Background(), f, in)
}

func nameOf(s *sisters, d string, sess session) string {
	a, _ := s.st.aliasFor(d, sess)
	return a.Name
}

func TestRenameOwnSessionNeedsNoApproval(t *testing.T) {
	f, s := renameFixture(t)
	// With no session given, the Bot names the session it is bound to.
	res, err := rename(s, f, "Alice", renameIn{Name: "  Rubi core "})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if len(f.submits) != 0 || m["renamed"] != true || m["name"] != "Rubi core" || !strings.Contains(m["approval"].(string), "none needed") {
		t.Fatalf("submits %d, result %v", len(f.submits), m)
	}
	if nameOf(s, mac.ID, mainSess) != "Rubi core" {
		t.Fatalf("aliases %+v", s.st.aliases())
	}
	// Audited, with who did it.
	last := f.auditLog[len(f.auditLog)-1]
	if f.audits[len(f.audits)-1] != auditRenamed || last["by"] != "bot" || last["sister"] != "Alice" || last["new"] != "Rubi core" || last["approval"] != "own bound session" {
		t.Fatalf("audit %v %v", f.audits, last)
	}
	// The same session by its id or app id, and by its name: also its own, also without approval.
	for _, in := range []renameIn{{SessionID: "cli-1", Name: "Rubi main"}, {SessionID: "local_a", Name: "Rubi again"}, {SessionName: "rubi again", Name: "Final"}} {
		if _, err := rename(s, f, "Alice", in); err != nil || len(f.submits) != 0 {
			t.Fatalf("%+v: %v (submits %d)", in, err, len(f.submits))
		}
	}
	if nameOf(s, mac.ID, mainSess) != "Final" || len(s.st.aliases()) != 1 {
		t.Fatalf("aliases %+v", s.st.aliases())
	}
	// Clearing its own name.
	if res, err := rename(s, f, "Alice", renameIn{Clear: true}); err != nil || res.(map[string]any)["cleared"] != true || len(s.st.aliases()) != 0 || len(f.submits) != 0 {
		t.Fatalf("%v %v", res, err)
	}
	if res, err := rename(s, f, "Alice", renameIn{Clear: true}); err != nil || res.(map[string]any)["cleared"] != false || len(f.submits) != 0 {
		t.Fatalf("clearing a name that isn't there: %v %v", res, err)
	}
}

func TestRenameChecksTheCaller(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	if _, err := s.renameTool(ctx, f, renameIn{Name: "x"}); err == nil {
		t.Fatal("an unverified caller renamed")
	}
	// A Bot that is bound nowhere has no "own" session and must name one.
	if _, err := rename(s, f, "Vega", renameIn{Name: "x"}); err == nil {
		t.Fatal("an unbound Bot renamed 'its own' session")
	}
	// Another Bot's session is not its own: it asks.
	res, err := rename(s, f, "Vega", renameIn{SessionID: "local_a", Name: "mine now"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" || len(f.submits) != 1 || nameOf(s, mac.ID, mainSess) != "" {
		t.Fatalf("%v %v (submits %d)", res, err, len(f.submits))
	}
	if _, err := rename(s, f, "Alice", renameIn{Name: "x", Clear: true}); err == nil {
		t.Fatal("name and clear together")
	}
	if _, err := rename(s, f, "Alice", renameIn{}); err == nil {
		t.Fatal("neither name nor clear")
	}
	if _, err := rename(s, f, "Alice", renameIn{SessionID: "nope", Name: "x"}); err == nil {
		t.Fatal("unknown session")
	}
	if _, err := rename(s, f, "Alice", renameIn{SessionID: "cli-1", SessionName: "x", Name: "x"}); err == nil {
		t.Fatal("both session_id and session_name")
	}
}

func TestRenameOtherSessionAsksAndRunsOnApproval(t *testing.T) {
	f, s := renameFixture(t)
	res, err := rename(s, f, "Alice", renameIn{SessionID: "cli-3", Name: "Other project"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" || len(f.submits) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	sub := f.submits[0]
	if sub.Kind != kindRename || nameOf(s, mac.ID, otherSess) != "" {
		t.Fatalf("%+v / named before approval", sub)
	}
	text, _ := json.Marshal(sub.Preview)
	for _, want := range []string{"Other project", "Alice", "Mac", "cli-3", "/Users/alice/other", "changes nothing in Claude Code"} {
		if !strings.Contains(string(text)+sub.Summary, want) {
			t.Errorf("approval lacks %q: %s %s", want, text, sub.Summary)
		}
	}
	// The action is a locked tap: not strong (a label is low-risk), and the user can't lower it.
	for _, a := range manifest().Actions {
		if a.Kind == kindRename && (a.DefaultLevel != rubiplugin.Tap || !a.Locked) {
			t.Fatalf("action %+v", a)
		}
	}
	raw, _ := json.Marshal(sub.Payload)
	var tk renameTicket
	_ = json.Unmarshal(raw, &tk)
	if _, err := s.executeRename(context.Background(), f, tk, "bot", "user approved", nil); err != nil {
		t.Fatal(err)
	}
	if nameOf(s, mac.ID, otherSess) != "Other project" {
		t.Fatalf("aliases %+v", s.st.aliases())
	}
	// Clearing it asks too.
	f.submits = nil
	if res, err := rename(s, f, "Alice", renameIn{SessionName: "other project", Clear: true}); err != nil || res.(map[string]any)["status"] != "awaiting_approval" || len(f.submits) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	// A refused approval changes nothing (nothing runs).
	if nameOf(s, mac.ID, otherSess) != "Other project" {
		t.Fatal("cleared before approval")
	}
}

func TestRenameByAProjectTrustNeedsNoApproval(t *testing.T) {
	f, s, _ := ptBot(t) // Alice is bound to the main session of /Users/alice/rubi
	ctx := context.Background()
	// Outside a trust the sub-session asks.
	res, err := rename(s, f, "Alice", renameIn{SessionID: "cli-2", Name: "worker"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatalf("%v %v", res, err)
	}
	f.submits = nil
	pt := grantViaOption(t, f, s, "cli-1", ptRoot)
	f.submits = nil
	res, err = rename(s, f, "Alice", renameIn{SessionID: "cli-2", Name: "worker"})
	if err != nil || len(f.submits) != 0 || res.(map[string]any)["renamed"] != true || !strings.Contains(res.(map[string]any)["approval"].(string), pt) {
		t.Fatalf("%v %v (submits %d)", res, err, len(f.submits))
	}
	var found bool
	for i, a := range f.audits {
		if a == auditMandateAll && f.auditLog[i]["mandate"] == pt && f.auditLog[i]["action"] == "claude_code_rename" {
			found = true
		}
	}
	if !found || nameOf(s, mac.ID, ptSub) != "worker" {
		t.Fatalf("audits %v, aliases %+v", f.audits, s.st.aliases())
	}
	// A session outside the root still asks, and so does a Bot that isn't bound inside it.
	f.submits = nil
	for _, c := range []struct{ bot, id string }{{"Alice", "cli-3"}, {"Vega", "cli-2"}} {
		res, err := rename(s, f, c.bot, renameIn{SessionID: c.id, Name: "elsewhere " + c.bot})
		if err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
			t.Fatalf("%+v: %v %v", c, res, err)
		}
	}
	_ = ctx
}

func TestRenameUniqueness(t *testing.T) {
	f, s := renameFixture(t)
	if _, err := rename(s, f, "Alice", renameIn{Name: "Main"}); err != nil {
		t.Fatal(err)
	}
	// The same name on another session of the computer is refused, ignoring case, at the tool ...
	pend := func(name string) error {
		f.submits = nil
		res, err := rename(s, f, "Alice", renameIn{SessionID: "cli-3", Name: name})
		if err != nil {
			return err
		}
		// ... and again when the approved rename runs (state may have changed since it was asked).
		_ = res
		raw, _ := json.Marshal(f.submits[0].Payload)
		var tk renameTicket
		_ = json.Unmarshal(raw, &tk)
		_, err = s.executeRename(context.Background(), f, tk, "bot", "user approved", nil)
		return err
	}
	for _, n := range []string{"Main", "main", "MAIN", "mAiN "} {
		if err := pend(n); err == nil || !strings.Contains(err.Error(), "already called") {
			t.Errorf("%q: %v", n, err)
		}
	}
	// A session may re-use its own name (change the case).
	if _, err := rename(s, f, "Alice", renameIn{Name: "main"}); err != nil || nameOf(s, mac.ID, mainSess) != "main" {
		t.Fatalf("%v %q", err, nameOf(s, mac.ID, mainSess))
	}
	// A different computer may use the same name.
	other := rubiplugin.HomeDevice{ID: "dev_pc", Name: "PC"}
	if _, err := s.st.setAlias(other.ID, other.Name, session{SessionID: "pc-1"}, "Main", "user", s.now()); err != nil {
		t.Fatalf("same name on another computer: %v", err)
	}
	// Taking another name frees the old one.
	if _, err := rename(s, f, "Alice", renameIn{Name: "Core"}); err != nil {
		t.Fatal(err)
	}
	if err := pend("main"); err != nil {
		t.Fatalf("a freed name: %v", err)
	}
	// A name that is a session id on the computer is refused.
	for _, id := range []string{"cli-3", "CLI-1"} {
		if _, err := rename(s, f, "Alice", renameIn{Name: id}); err == nil {
			t.Errorf("name %q equal to a session id accepted", id)
		}
	}
}

func TestBindByName(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	if _, err := rename(s, f, "Alice", renameIn{Name: "Rubi core"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.setAlias(mac.ID, mac.Name, subSess, "worker", "user", s.now()); err != nil {
		t.Fatal(err)
	}
	// Vega binds by name (case-insensitive); the approval names the session and its real id.
	res, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", Name: "WORKER"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" || len(f.submits) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	var tk bindTicket
	raw, _ := json.Marshal(f.submits[0].Payload)
	_ = json.Unmarshal(raw, &tk)
	if tk.SessionID != "cli-2" || tk.Sister != "Vega" {
		t.Fatalf("ticket %+v", tk)
	}
	// The session_id form is as before; both, or neither, is an error.
	f.submits = nil
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", SessionID: "cli-2"}); err != nil || len(f.submits) != 1 {
		t.Fatalf("by id: %v", err)
	}
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", SessionID: "cli-2", Name: "worker"}); err == nil {
		t.Fatal("both session_id and name")
	}
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega"}); err == nil {
		t.Fatal("neither session_id nor name")
	}
	// Unknown name: the error lists the names there are.
	_, err = s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", Name: "nothing"})
	if err == nil || !strings.Contains(err.Error(), `no session is named "nothing"`) || !strings.Contains(err.Error(), `"worker"`) {
		t.Fatalf("unknown name: %v", err)
	}
	// An id isn't a name.
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", Name: "cli-2"}); err == nil {
		t.Fatal("an id worked as a name")
	}
	// A name whose session has gone says so.
	f.mu.Lock()
	f.sessions = []session{mainSess, otherSess}
	f.mu.Unlock()
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", Name: "worker"}); err == nil || !strings.Contains(err.Error(), "isn't there any more") {
		t.Fatalf("vanished session: %v", err)
	}
}

func TestBindByNameAmbiguousAcrossComputers(t *testing.T) {
	f, s := renameFixture(t)
	pc := rubiplugin.HomeDevice{ID: "dev_pc", Name: "PC"}
	f.devices = []rubiplugin.HomeDevice{mac, pc}
	if _, err := s.st.setAlias(mac.ID, mac.Name, subSess, "worker", "user", s.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.setAlias(pc.ID, pc.Name, session{SessionID: "pc-1"}, "Worker", "user", s.now()); err != nil {
		t.Fatal(err)
	}
	_, err := s.bindTool(context.Background(), f, bindIn{VerifiedAgent: "Vega", Name: "worker"})
	if err == nil || !strings.Contains(err.Error(), "several computers") || !strings.Contains(err.Error(), "PC") {
		t.Fatalf("ambiguous: %v", err)
	}
	// Naming the computer resolves it (by name or id).
	for _, dev := range []string{"Mac", "dev_mac"} {
		if res, err := s.bindTool(context.Background(), f, bindIn{VerifiedAgent: "Vega", Name: "worker", Device: dev}); err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
			t.Fatalf("%s: %v %v", dev, res, err)
		}
	}
	if _, err := s.bindTool(context.Background(), f, bindIn{VerifiedAgent: "Vega", Name: "worker", Device: "Nowhere"}); err == nil {
		t.Fatal("unknown computer")
	}
}

func TestSessionsToolShowsNamesAndStatusToo(t *testing.T) {
	f, s, code := boundFixture(t)
	ctx := context.Background()
	if _, err := s.renameTool(ctx, f, renameIn{VerifiedAgent: "Alice", Name: "Rubi core"}); err != nil {
		t.Fatal(err)
	}
	out, err := s.sessionsTool(ctx, f, sessionsIn{})
	if err != nil {
		t.Fatal(err)
	}
	items := out.(map[string]any)["sessions"].([]map[string]any)
	if len(items) != 3 || items[0]["name"] != "Rubi core" || items[0]["title"] != "Rubi main" || items[1]["name"] != nil {
		t.Fatalf("sessions: %+v", items)
	}
	st, err := s.statusTool(ctx, f, statusIn{Sister: "Alice", BindCode: code})
	if err != nil || st.(map[string]any)["name"] != "Rubi core" {
		t.Fatalf("status: %v %v", st, err)
	}
	// An archived session is still left out unless asked for, though the list reads them to keep names fresh.
	f.mu.Lock()
	f.sessions[2].Archived = true
	f.mu.Unlock()
	out, _ = s.sessionsTool(ctx, f, sessionsIn{})
	if n := len(out.(map[string]any)["sessions"].([]map[string]any)); n != 2 {
		t.Fatalf("archived listed: %d", n)
	}
	out, _ = s.sessionsTool(ctx, f, sessionsIn{IncludeArchived: true})
	if n := len(out.(map[string]any)["sessions"].([]map[string]any)); n != 3 {
		t.Fatalf("archived not listed when asked: %d", n)
	}
}

func TestBindResultCarriesTheName(t *testing.T) {
	f, s := renameFixture(t)
	_, _ = rename(s, f, "Alice", renameIn{Name: "Rubi core"})
	res, err := s.executeBind(f, bindTicket{Sister: "Alice", Device: mac.ID, DeviceName: mac.Name, SessionID: "cli-1", AppSessionID: "local_a", Cwd: mainSess.Cwd})
	if err != nil || res.(map[string]any)["name"] != "Rubi core" {
		t.Fatalf("%v %v", res, err)
	}
}

func TestNamesPersistAcrossARestart(t *testing.T) {
	f, s := renameFixture(t)
	if _, err := rename(s, f, "Alice", renameIn{Name: "Rubi core"}); err != nil {
		t.Fatal(err)
	}
	s2 := newSisters(&store{})
	if err := s2.st.load(f); err != nil {
		t.Fatal(err)
	}
	if nameOf(s2, mac.ID, mainSess) != "Rubi core" {
		t.Fatalf("not saved: %+v", s2.st.aliases())
	}
	_, sess, _, err := s2.resolveSession(context.Background(), f, "", "", "rubi CORE")
	if err != nil || sess.SessionID != "cli-1" {
		t.Fatalf("%v %+v", err, sess)
	}
	// A failed save changes nothing.
	f.mu.Lock()
	f.saveErr = context.DeadlineExceeded
	f.mu.Unlock()
	if _, err := rename(s2, f, "Alice", renameIn{Name: "Other"}); err == nil || nameOf(s2, mac.ID, mainSess) != "Rubi core" {
		t.Fatalf("%v %q", err, nameOf(s2, mac.ID, mainSess))
	}
}

func TestNameFollowsTheSessionsNewId(t *testing.T) {
	f, s := renameFixture(t)
	_, _ = rename(s, f, "Alice", renameIn{Name: "Rubi core"})
	// The app restarts the session under a new Claude Code id: the name stays (by the app id).
	f.mu.Lock()
	f.sessions[0].SessionID = "cli-1b"
	f.mu.Unlock()
	if _, sess, _, err := s.resolveSession(context.Background(), f, "", "", "Rubi core"); err != nil || sess.SessionID != "cli-1b" {
		t.Fatalf("%v %+v", err, sess)
	}
	if a := s.st.aliases()[0]; a.SessionID != "cli-1b" {
		t.Fatalf("alias not updated: %+v", a)
	}
}

func TestStaleNamesExpire(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	_, _ = rename(s, f, "Alice", renameIn{Name: "Rubi core"})
	// A session that is gone, named 29 days ago: the name stays; 31 days: it goes (and is audited).
	if _, err := s.st.setAlias(mac.ID, mac.Name, session{SessionID: "cli-gone", AppSessionID: "local_gone"}, "Old work", "user", now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(29 * 24 * time.Hour)
	if _, err := s.sessionsTool(ctx, f, sessionsIn{}); err != nil || len(s.st.aliases()) != 2 {
		t.Fatalf("%v %+v", err, s.st.aliases())
	}
	now = now.Add(2 * 24 * time.Hour)
	if _, err := s.sessionsTool(ctx, f, sessionsIn{}); err != nil {
		t.Fatal(err)
	}
	al := s.st.aliases()
	if len(al) != 1 || al[0].Name != "Rubi core" {
		t.Fatalf("aliases after 31 days: %+v", al)
	}
	if f.audits[len(f.audits)-1] != "session_name_expired" {
		t.Fatalf("audits %v", f.audits)
	}
	// The name of a session that is still there is kept, and its last-seen time moves on.
	if al[0].Seen.Before(now.Add(-time.Minute)) {
		t.Fatalf("seen not refreshed: %+v", al[0])
	}
	// The expiry is saved.
	s2 := newSisters(&store{})
	_ = s2.st.load(f)
	if len(s2.st.aliases()) != 1 {
		t.Fatalf("saved %+v", s2.st.aliases())
	}
}

func TestStaleNamesStayWhenTheListIsIncomplete(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if _, err := s.st.setAlias(mac.ID, mac.Name, session{SessionID: "cli-gone"}, "Old work", "user", now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(40 * 24 * time.Hour)
	// The computer doesn't answer: nothing is known about its sessions, so no name goes.
	f.hangOn = map[string]bool{mac.ID: true}
	old := listTimeout
	listTimeout = 50 * time.Millisecond
	defer func() { listTimeout = old }()
	if _, err := s.sessionsTool(ctx, f, sessionsIn{}); err != nil || len(s.st.aliases()) != 1 {
		t.Fatalf("%v %+v", err, s.st.aliases())
	}
	// A filtered list (a repo) is not complete either.
	f.hangOn = nil
	if _, err := s.sessionsTool(ctx, f, sessionsIn{Repo: "rubi"}); err != nil || len(s.st.aliases()) != 1 {
		t.Fatalf("%v %+v", err, s.st.aliases())
	}
	// A full list that lacks the session drops it.
	if _, err := s.sessionsTool(ctx, f, sessionsIn{}); err != nil || len(s.st.aliases()) != 0 {
		t.Fatalf("%v %+v", err, s.st.aliases())
	}
}

func TestNameOfAnUnpairedComputerExpires(t *testing.T) {
	f, s := renameFixture(t)
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if _, err := s.st.setAlias("dev_gone", "Old PC", session{SessionID: "x-1"}, "Old", "user", now); err != nil {
		t.Fatal(err)
	}
	_, _ = s.sessionsTool(context.Background(), f, sessionsIn{})
	if len(s.st.aliases()) != 1 {
		t.Fatal("dropped too early")
	}
	now = now.Add(31 * 24 * time.Hour)
	_, _ = s.sessionsTool(context.Background(), f, sessionsIn{})
	if len(s.st.aliases()) != 0 {
		t.Fatalf("kept: %+v", s.st.aliases())
	}
}

func TestPanelRenameAndClear(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	call := func(args string) (any, error) { return s.panel(ctx, f, "rename", json.RawMessage(args)) }

	// The user names any session directly: no approval, audited as the user's.
	res, err := call(`{"device":"dev_mac","session_id":"local_b","name":" Sub work "}`)
	if err != nil || res.(map[string]any)["name"] != "Sub work" || len(f.submits) != 0 {
		t.Fatalf("%v %v", res, err)
	}
	last := f.auditLog[len(f.auditLog)-1]
	if f.audits[len(f.audits)-1] != auditRenamed || last["by"] != "user" || last["new"] != "Sub work" {
		t.Fatalf("audit %v %v", f.audits, last)
	}
	// The same rules apply to the user.
	for _, bad := range []string{`"a\u200bb"`, `"local_x"`, `"` + strings.Repeat("x", 65) + `"`, `"sub WORK"`, `"cli-3"`} {
		if _, err := call(`{"device":"dev_mac","session_id":"cli-3","name":` + bad + `}`); err == nil {
			t.Errorf("panel accepted %s", bad)
		}
	}
	// A missing name key (a panel without prompt support) must not clear anything.
	if _, err := call(`{"device":"dev_mac","session_id":"local_b"}`); err == nil || nameOf(s, mac.ID, subSess) != "Sub work" {
		t.Fatalf("a call without a name: %v / %q", err, nameOf(s, mac.ID, subSess))
	}
	if _, err := call(`{"device":"dev_mac","session_id":"nope","name":"x"}`); err == nil {
		t.Fatal("renamed a session that isn't there")
	}
	// An empty name clears it.
	if res, err := call(`{"device":"dev_mac","session_id":"local_b","name":""}`); err != nil || res.(map[string]any)["cleared"] != true || nameOf(s, mac.ID, subSess) != "" {
		t.Fatalf("%v %v", res, err)
	}
	// A name whose session is gone can be removed.
	_, _ = s.st.setAlias(mac.ID, mac.Name, session{SessionID: "cli-gone"}, "Ghost", "user", s.now())
	if res, err := call(`{"device":"dev_mac","forget":"ghost"}`); err != nil || res.(map[string]any)["cleared"] != true || len(s.st.aliases()) != 0 {
		t.Fatalf("%v %v", res, err)
	}
}

func TestPanelPageListsSessionsWithRenameButtons(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	_, _ = rename(s, f, "Alice", renameIn{Name: "Rubi core"})
	_, _ = s.st.setAlias(mac.ID, mac.Name, session{SessionID: "cli-gone"}, "Ghost", "user", s.now())
	v, err := s.panel(ctx, f, "view", nil)
	if err != nil {
		t.Fatal(err)
	}
	var sec map[string]any
	for _, x := range v.(map[string]any)["sections"].([]map[string]any) {
		if x["title"] == "Session names" {
			sec = x
		}
	}
	if sec == nil {
		t.Fatal("no Session names section")
	}
	items := sec["items"].([]map[string]any)
	raw, _ := json.Marshal(items)
	if len(items) != 4 { // 3 sessions + the ghost
		t.Fatalf("%d items: %s", len(items), raw)
	}
	if items[0]["title"] != "Rubi core" || !strings.Contains(string(raw), `"prompt"`) || !strings.Contains(string(raw), "Clear name") || !strings.Contains(string(raw), "Remove name") {
		t.Fatalf("%s", raw)
	}
	// The first (named) item's Rename button asks for the name and carries the current one.
	pr := items[0]["actions"].([]map[string]any)[0]["prompt"].(map[string]any)
	if pr["arg"] != "name" || pr["value"] != "Rubi core" {
		t.Fatalf("prompt %v", pr)
	}
	// The list is reused for a few minutes (the page reloads every 30 s) ...
	calls := f.listCalls
	if _, err := s.panel(ctx, f, "view", nil); err != nil || f.listCalls != calls {
		t.Fatalf("the page read the list again within the reuse time: %d -> %d (%v)", calls, f.listCalls, err)
	}
	// ... and a computer that doesn't answer doesn't hold the page up forever.
	s.dropNameList()
	f.hangOn = map[string]bool{mac.ID: true}
	old := listTimeout
	listTimeout = 50 * time.Millisecond
	defer func() { listTimeout = old }()
	v, err = s.panel(ctx, f, "view", nil)
	if err != nil || !strings.Contains(mustJSON(v), "didn't answer") {
		t.Fatalf("%v %v", err, mustJSON(v))
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestRenameIsRateLimited(t *testing.T) {
	f, s := renameFixture(t)
	for i := range renamesPerHour {
		if _, err := rename(s, f, "Alice", renameIn{Name: "n" + string(rune('a'+i))}); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if _, err := rename(s, f, "Alice", renameIn{Name: "one more"}); err == nil {
		t.Fatal("no rate limit")
	}
}

func TestTooManyNames(t *testing.T) {
	f, s := renameFixture(t)
	for i := range maxAliases {
		if _, err := s.st.setAlias(mac.ID, mac.Name, session{SessionID: "x-" + string(rune('A'+i%26)) + string(rune('a'+i/26%26)) + string(rune('0'+i/676))}, "name "+string(rune('A'+i%26))+string(rune('a'+i/26%26))+string(rune('0'+i/676)), "user", s.now()); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if _, err := rename(s, f, "Alice", renameIn{Name: "one more"}); err == nil {
		t.Fatal("no cap")
	}
}

func TestNamesFoldCaseConsistently(t *testing.T) {
	for _, c := range [][2]string{{"Straße", "STRASSE"}, {"ΟΔΟΣ", "οδος"}, {"Main", "mAIN"}, {"İstanbul", "i\u0307stanbul"}} {
		_ = c
	}
	if !sameName("Main", "mAIN") || !sameName("ΣΑΣ", "σας") {
		t.Fatal("simple fold")
	}
	if sameName("Main", "Maine") {
		t.Fatal("different names equal")
	}
	f, s := renameFixture(t)
	if _, err := rename(s, f, "Alice", renameIn{Name: "ΟΔΟΣ"}); err != nil {
		t.Fatal(err)
	}
	// The same name in another case (final sigma) is taken, in the store, in lookup and in the panel's check.
	if _, err := s.panel(context.Background(), f, "rename", json.RawMessage(`{"device":"dev_mac","session_id":"local_b","name":"οδοσ"}`)); err == nil {
		t.Fatal("a case variant was accepted as a different name")
	}
	if _, sess, _, err := s.resolveSession(context.Background(), f, "", "", "οδος"); err != nil || sess.SessionID != "cli-1" {
		t.Fatalf("lookup: %v %+v", err, sess)
	}
}

func TestNamesNeverDropFromATruncatedList(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	// A live session beyond Home's cut: named, but not in the list the cut produced.
	live := session{SessionID: "cli-live", AppSessionID: "local_live", Title: "Far away", Cwd: "/Users/alice/far", RepoKey: "github.com/alice/far", Role: "main", State: "idle"}
	f.mu.Lock()
	f.sessions = append(f.sessions, live)
	f.mu.Unlock()
	if _, err := s.st.setAlias(mac.ID, mac.Name, live, "Far", "user", now); err != nil {
		t.Fatal(err)
	}
	// The session drops out of the list (Home cut it), and Home says so.
	f.mu.Lock()
	f.sessions = []session{mainSess, subSess, otherSess}
	f.listCut = true
	f.mu.Unlock()
	now = now.Add(45 * 24 * time.Hour)
	if _, err := s.sessionsTool(ctx, f, sessionsIn{}); err != nil || len(s.st.aliases()) != 1 {
		t.Fatalf("a name was dropped from a truncated list: %v %+v", err, s.st.aliases())
	}
	// Binding by name does not say "gone": it uses the stored ids and what was last seen.
	res, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", Name: "far"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatalf("bind by name on a cut list: %v %v", res, err)
	}
	var tk bindTicket
	raw, _ := json.Marshal(f.submits[len(f.submits)-1].Payload)
	_ = json.Unmarshal(raw, &tk)
	if tk.SessionID != "cli-live" || tk.AppSessionID != "local_live" || tk.Cwd != "/Users/alice/far" || tk.Title != "Far away" {
		t.Fatalf("ticket %+v", tk)
	}
	if note := f.submits[len(f.submits)-1].Preview.(map[string]any)["note"]; note == nil {
		t.Fatal("the approval doesn't say the details are from the saved copy")
	}
	// The same list, whole: the name goes (and the miss is an error).
	f.mu.Lock()
	f.listCut = false
	f.mu.Unlock()
	if _, err := s.bindTool(ctx, f, bindIn{VerifiedAgent: "Vega", Name: "far"}); err == nil || !strings.Contains(err.Error(), "isn't there any more") {
		t.Fatalf("a whole list should call it gone: %v", err)
	}
	if len(s.st.aliases()) != 0 {
		t.Fatalf("not dropped from a whole list: %+v", s.st.aliases())
	}
}

func TestSweepReadsArchivedOnlyWhenDue(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	arch := func() []bool { f.mu.Lock(); defer f.mu.Unlock(); return append([]bool(nil), f.listArch...) }
	// No names: the plain list, no archived read.
	f.mu.Lock()
	f.listArch = nil
	f.mu.Unlock()
	_, _ = s.sessionsTool(ctx, f, sessionsIn{})
	if a := arch(); len(a) != 1 || a[0] {
		t.Fatalf("with no names: %v", a)
	}
	_, _ = rename(s, f, "Alice", renameIn{Name: "Rubi core"})
	f.mu.Lock()
	f.listArch = nil
	f.mu.Unlock()
	_, _ = s.sessionsTool(ctx, f, sessionsIn{}) // due: the first sweep
	_, _ = s.sessionsTool(ctx, f, sessionsIn{}) // not due
	now = now.Add(5 * time.Minute)
	_, _ = s.sessionsTool(ctx, f, sessionsIn{}) // still not
	if a := arch(); len(a) != 3 || !a[0] || a[1] || a[2] {
		t.Fatalf("archived reads %v", a)
	}
	now = now.Add(6 * time.Minute)
	_, _ = s.sessionsTool(ctx, f, sessionsIn{})
	if a := arch(); len(a) != 4 || !a[3] {
		t.Fatalf("archived reads %v", a)
	}
	// A repo filter never reads archived for the sweep.
	now = now.Add(time.Hour)
	f.mu.Lock()
	f.listArch = nil
	f.mu.Unlock()
	_, _ = s.sessionsTool(ctx, f, sessionsIn{Repo: "rubi"})
	if a := arch(); len(a) != 1 || a[0] {
		t.Fatalf("filtered: %v", a)
	}
}

func TestPanelReusesTheSessionList(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	_, _ = s.panel(ctx, f, "view", nil)
	n := f.listCalls
	for range 5 {
		now = now.Add(30 * time.Second)
		_, _ = s.panel(ctx, f, "view", nil)
	}
	if f.listCalls != n {
		t.Fatalf("the page listed again within 5 minutes: %d -> %d", n, f.listCalls)
	}
	now = now.Add(5 * time.Minute)
	_, _ = s.panel(ctx, f, "view", nil)
	if f.listCalls != n+1 {
		t.Fatalf("not listed again after the reuse time: %d -> %d", n, f.listCalls)
	}
	// A rename shows at once.
	_, _ = s.panel(ctx, f, "rename", json.RawMessage(`{"device":"dev_mac","session_id":"local_b","name":"Fresh"}`))
	v, _ := s.panel(ctx, f, "view", nil)
	if !strings.Contains(mustJSON(v), `"Fresh"`) {
		t.Fatal("a rename isn't on the page")
	}
}

func TestPanelPageKeepsNamesOfCutRowsOutOfTheOrphans(t *testing.T) {
	f, s := renameFixture(t)
	for i := range maxNameItems + 10 {
		id := fmt.Sprintf("x-%03d", i)
		f.sessions = append(f.sessions, session{SessionID: id, AppSessionID: "local_" + id, Title: id, Cwd: "/w", Role: "main", State: "idle", LastActivity: time.Now().Add(-time.Duration(i) * time.Minute)})
	}
	// A named session that sorts after the cut would be a ghost if "seen" were built from the shown rows only.
	last := f.sessions[len(f.sessions)-1]
	if _, err := s.st.setAlias(mac.ID, mac.Name, last, "Last one", "user", s.now()); err != nil {
		t.Fatal(err)
	}
	v, err := s.panel(context.Background(), f, "view", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(mustJSON(v), "its session isn't listed") {
		t.Fatal("a name with a live session is shown as an orphan")
	}
}

func TestBotNeedsATapToReplaceTheUsersName(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	// The user names the Bot's own session in the panel.
	if _, err := s.panel(ctx, f, "rename", json.RawMessage(`{"device":"dev_mac","session_id":"local_a","name":"Mine"}`)); err != nil {
		t.Fatal(err)
	}
	res, err := rename(s, f, "Alice", renameIn{Name: "Alice's pick"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" || len(f.submits) != 1 || nameOf(s, mac.ID, mainSess) != "Mine" {
		t.Fatalf("a Bot replaced the user's name without a tap: %v %v", res, err)
	}
	if p := f.submits[0].Preview.(map[string]any); p["current_name"] != "Mine" || p["current_name_set_by"] != "user" {
		t.Fatalf("preview %v", p)
	}
	// Clearing it asks too.
	f.submits = nil
	if res, err := rename(s, f, "Alice", renameIn{Clear: true}); err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatalf("%v %v", res, err)
	}
	// Once the user approved, the Bot's own name can be changed again without asking, and the result shows the old one.
	f.submits = nil
	raw, _ := json.Marshal(mustTicket(t, f, s, "Alice's pick"))
	var tk renameTicket
	_ = json.Unmarshal(raw, &tk)
	if _, err := s.executeRename(ctx, f, tk, "bot", "user approved", nil); err != nil {
		t.Fatal(err)
	}
	res, err = rename(s, f, "Alice", renameIn{Name: "Alice again"})
	m, _ := res.(map[string]any)
	if err != nil || m["renamed"] != true || m["previous_name"] != "Alice's pick" || len(f.submits) != 0 {
		t.Fatalf("%v %v", res, err)
	}
	// A project trust doesn't change that: the user's name stays the user's.
	f2, s2, _ := ptBot(t)
	_, _ = s2.panel(ctx, f2, "rename", json.RawMessage(`{"device":"dev_mac","session_id":"local_b","name":"User's sub"}`))
	grantViaOption(t, f2, s2, "cli-1", ptRoot)
	f2.submits = nil
	res, err = rename(s2, f2, "Alice", renameIn{SessionID: "cli-2", Name: "Bot's sub"})
	if err != nil || res.(map[string]any)["status"] != "awaiting_approval" {
		t.Fatalf("under a trust: %v %v", res, err)
	}
}

func mustTicket(t *testing.T, f *fakeHost, s *sisters, name string) renameTicket {
	t.Helper()
	return renameTicket{Sister: "Alice", Device: mac.ID, DeviceName: mac.Name, SessionID: "cli-1", AppSessionID: "local_a", Name: name}
}

func TestRenameRateLimitCountsOnlyRealSessions(t *testing.T) {
	f, s := renameFixture(t)
	for range renamesPerHour + 5 {
		if _, err := rename(s, f, "Alice", renameIn{SessionID: "no-such", Name: "x"}); err == nil {
			t.Fatal("unknown session accepted")
		}
	}
	if _, err := rename(s, f, "Alice", renameIn{Name: "still fine"}); err != nil {
		t.Fatalf("failed lookups used up the hour: %v", err)
	}
}

func TestApprovedRenameChecksTheNameAgainstSessionIds(t *testing.T) {
	f, s := renameFixture(t)
	ctx := context.Background()
	// The name passed the tool, then a session with exactly that id appeared before the approval was answered.
	if _, err := rename(s, f, "Alice", renameIn{SessionID: "cli-3", Name: "newcomer"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.submits[0].Payload)
	var tk renameTicket
	_ = json.Unmarshal(raw, &tk)
	f.mu.Lock()
	f.sessions = append(f.sessions, session{SessionID: "NewComer", Cwd: "/w", Role: "main", State: "idle"})
	f.mu.Unlock()
	if _, err := s.executeRename(ctx, f, tk, "bot", "user approved", nil); err == nil || !strings.Contains(err.Error(), "id of a session") {
		t.Fatalf("the approved rename stored an id-like name: %v", err)
	}
	if nameOf(s, mac.ID, otherSess) != "" {
		t.Fatal("stored")
	}
	// Home unreachable at that moment: refused, not stored unchecked.
	f.mu.Lock()
	f.sessions = []session{mainSess, subSess, otherSess}
	f.hangOn = map[string]bool{mac.ID: true}
	f.mu.Unlock()
	old := listTimeout
	listTimeout = 30 * time.Millisecond
	defer func() { listTimeout = old }()
	if _, err := s.executeRename(ctx, f, tk, "bot", "user approved", nil); err == nil {
		t.Fatal("stored without being able to check")
	}
}
