package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLibrary plays core's library.get: an admitted or deprecated version with its signature and the latest admitted
// number; anything else is "no admitted skill", as core answers for withdrawn, rejected, proposed and unknown alike.
type fakeLibrary struct {
	mu      sync.Mutex
	entries map[string][]*fakeLibVersion
	err     error // every call fails with this (Rubi locked, no answer)
	calls   int
}

type fakeLibVersion struct {
	version int
	state   string
	content string
	verdict string
	badSig  bool
}

func newFakeLibrary() *fakeLibrary { return &fakeLibrary{entries: map[string][]*fakeLibVersion{}} }

// publish adds the next version of a skill in a state.
func (l *fakeLibrary) publish(id, state, content string) *fakeLibVersion {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := &fakeLibVersion{version: len(l.entries[id]) + 1, state: state, content: content, verdict: "pass"}
	l.entries[id] = append(l.entries[id], v)
	return v
}

func (l *fakeLibrary) setState(id string, version int, state string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries[id][version-1].state = state
}

// fakeLibSig is what the fake Home accepts as the signature of a skill: bound to its id, version and hash, like the
// real one, and shaped like a token (URL-safe base64).
func fakeLibSig(id, version, sha string) string {
	return base64.RawURLEncoding.EncodeToString([]byte("fake:" + id + ":" + version + ":" + sha))
}

func (l *fakeLibrary) get(id string, version int) (map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.err != nil {
		return nil, l.err
	}
	vs := l.entries[id]
	latest := 0
	for _, v := range vs {
		if v.state == "admitted" {
			latest = v.version
		}
	}
	none := fmt.Errorf("no admitted skill %s", id)
	if version == 0 {
		if version = latest; version == 0 {
			return nil, none
		}
	}
	if version < 1 || version > len(vs) || vs[version-1].state != "admitted" && vs[version-1].state != "deprecated" {
		return nil, none
	}
	v := vs[version-1]
	sha := shaOf(v.content)
	sig := fakeLibSig(id, strconv.Itoa(v.version), sha)
	if v.badSig {
		sig = fakeLibSig(id, "99", sha)
	}
	return map[string]any{"id": id, "version": v.version, "state": v.state, "content": v.content, "sha256": sha, "signature": sig,
		"description": "d", "tags": []string{}, "admitted_by": "curator", "scan_verdict": v.verdict, "scanner_version": "1", "latest_admitted": latest}, nil
}

func libFixture(t *testing.T) (*fakeHost, *sisters, *fakeRoles, *fakeLibrary, string) {
	t.Helper()
	f, s, fr := roleFixture(t)
	lib := newFakeLibrary()
	f.library = lib
	lib.publish("design-tokens", "admitted", "---\nname: design-tokens\ndescription: tokens\n---\nUse tokens v1.")
	trustBot(t, s, botA, "p1")
	return f, s, fr, lib, mustCreate(t, s, f, botA, "design")
}

func addLib(t *testing.T, s *sisters, h sisterHost, id, ref string) map[string]any {
	t.Helper()
	return asMap(t)(s.roleSkillsAddTool(context.Background(), h, roleSkillsAddIn{roleWho: who(botA), Role: id, Library: ref}))
}

func libSkill(t *testing.T, fr *fakeRoles, id, name string) roleSkill {
	t.Helper()
	for _, k := range fr.current(id).Skills {
		if k.Name == name {
			return k
		}
	}
	t.Fatalf("no skill %s in %+v", name, fr.current(id).Skills)
	return roleSkill{}
}

func TestLibrarySkillAddFollowsOrPins(t *testing.T) {
	f, s, fr, lib, id := libFixture(t)
	lib.publish("design-tokens", "admitted", "Use tokens v2.")
	m := addLib(t, s, f, id, "design-tokens")
	if status(m) != "applied" || m["tier"] != 1 || len(f.submits) != 0 {
		t.Fatalf("admitted means trusted, tier 1: %v", m)
	}
	k := libSkill(t, fr, id, "design-tokens")
	if k.Source != "library" || k.LibraryID != "design-tokens" || k.Pin != "" || k.Resolved != "2" || k.AddedBy != botA ||
		k.Sig != fakeLibSig("design-tokens", "2", shaOf("Use tokens v2.")) || k.SHA256 != shaOf("Use tokens v2.") {
		t.Fatalf("follows the latest admitted: %+v", k)
	}
	if k.State != "active" {
		t.Fatalf("%+v", k)
	}
	// "id@1" pins version 1 and replaces the entry.
	m = addLib(t, s, f, id, "design-tokens@1")
	k = libSkill(t, fr, id, "design-tokens")
	if status(m) != "applied" || k.Pin != "1" || k.Resolved != "1" || len(fr.current(id).Skills) != 1 {
		t.Fatalf("%v %+v", m, k)
	}
	// The same again changes nothing.
	if m := addLib(t, s, f, id, "design-tokens@1"); m["unchanged"] != true {
		t.Fatalf("%v", m)
	}
	// The audit names the skill, never its text.
	for _, a := range auditsOf(f, "role.change") {
		if strings.Contains(fmt.Sprint(a), "Use tokens") {
			t.Fatalf("text in the audit: %v", a)
		}
	}
}

func TestLibraryRefusesWhatIsNotAdmitted(t *testing.T) {
	f, s, fr, lib, id := libFixture(t)
	lib.publish("old-notes", "deprecated", "Old.")
	lib.publish("gone", "withdrawn", "Gone.")
	lib.publish("draft", "proposed", "Draft.")
	for ref, want := range map[string]string{
		"old-notes@1":       "deprecated",
		"gone@1":            "not an admitted library skill",
		"draft":             "not an admitted library skill",
		"nothing-here":      "not an admitted library skill",
		"design-tokens@7":   "not an admitted library skill",
		"Bad Id":            "library must be a skill id",
		"design-tokens@0":   "library must be a skill id",
		"design-tokens@1@2": "library must be a skill id",
	} {
		m := addLib(t, s, f, id, ref)
		if status(m) != "rejected" || !strings.Contains(strings.Join(m["reasons"].([]string), " "), want) {
			t.Errorf("%s: %v", ref, m)
		}
	}
	if len(fr.current(id).Skills) != 0 || len(f.submits) != 0 {
		t.Fatalf("nothing attached: %+v", fr.current(id).Skills)
	}
	// A name taken by an ad-hoc skill is not overwritten.
	asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Name: "design-tokens", Description: "d", Content: "mine"}))
	m := addLib(t, s, f, id, "design-tokens")
	if status(m) != "rejected" || !strings.Contains(strings.Join(m["reasons"].([]string), " "), "isn't from the library") {
		t.Fatalf("%v", m)
	}
	// A locked library or no answer is an error for the Bot to retry, not a verdict on the skill.
	lib.err = errors.New("Rubi is locked")
	if _, err := s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Library: "other"}); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("%v", err)
	}
}

func TestLibraryAnswerIsCheckedByThePlugin(t *testing.T) {
	f, s, fr, lib, id := libFixture(t)
	v := lib.publish("tampered", "admitted", "text")
	v.verdict = "reject"
	if _, err := s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Library: "tampered"}); err == nil {
		t.Fatal("a reject verdict was attached")
	}
	// A signature for another version: Home refuses and the Bot hears why.
	bad := lib.publish("badsig", "admitted", "text")
	bad.badSig = true
	m := addLib(t, s, f, id, "badsig")
	if status(m) != "rejected" || !strings.Contains(strings.Join(m["reasons"].([]string), " "), "signature refused") || len(fr.current(id).Skills) != 0 {
		t.Fatalf("%v", m)
	}
	// A host with no library method.
	if _, err := s.roleSkillsAddTool(context.Background(), struct{ sisterHost }{f}, roleSkillsAddIn{roleWho: who(botA), Role: id, Library: "design-tokens"}); err == nil || !strings.Contains(err.Error(), "can't read the skill library") {
		t.Fatalf("%v", err)
	}
	// A reserved name can't be a Bot.
	if _, err := s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: roleWho{VerifiedAgent: libraryActor}, Role: id, Library: "design-tokens"}); err == nil {
		t.Fatal("a Bot called library")
	}
}

func TestLibraryAddOnAProjectWithoutTrustAsks(t *testing.T) {
	f, s, fr, _, _ := libFixture(t)
	// bot-b holds no trust of p1: its role change is the strong approval, and the text travels in the ticket.
	m := asMap(t)(s.roleCreateTool(context.Background(), f, roleCreateIn{roleWho: who("bot-b"), Project: "p1", Name: "other"}))
	if status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	if _, err := s.executeRoleChange(context.Background(), f, lastTicket(t, f)); err != nil {
		t.Fatal(err)
	}
	var id string
	for k, vs := range fr.roles {
		if vs[0].Name == "other" {
			id = k
		}
	}
	m = asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who("bot-b"), Role: id, Library: "design-tokens"}))
	if status(m) != "needs_approval" || lastSubmit(t, f).Kind != kindRoleForeign || len(fr.current(id).Skills) != 0 {
		t.Fatalf("%v", m)
	}
	tk := lastTicket(t, f)
	if len(tk.Blobs) != 1 {
		t.Fatalf("%+v", tk)
	}
	if _, err := s.executeRoleChange(context.Background(), f, tk); err != nil {
		t.Fatal(err)
	}
	if k := libSkill(t, fr, id, "design-tokens"); k.Resolved != "1" || k.Source != "library" {
		t.Fatalf("%+v", k)
	}
}

func TestFollowingRoleIsRematerializedWhenANewVersionIsAdmitted(t *testing.T) {
	f, s, fr, lib, id := libFixture(t)
	addLib(t, s, f, id, "design-tokens")
	// A second role pins version 1: it stays.
	pinned := mustCreate(t, s, f, botA, "pinned")
	addLib(t, s, f, pinned, "design-tokens@1")
	calls := 20
	if ch, err := s.followLibrary(context.Background(), f, "dev_mac", id, &calls); err != nil || ch != nil {
		t.Fatalf("nothing new yet: %v %v", ch, err)
	}
	v1 := fr.current(id).Version
	lib.publish("design-tokens", "admitted", "Use tokens v2.")
	ch, err := s.followLibrary(context.Background(), f, "dev_mac", id, &calls)
	if err != nil || len(ch) != 1 || ch[0].text() != "design-tokens 1 -> 2" {
		t.Fatalf("%v %v", ch, err)
	}
	r := fr.current(id)
	k := libSkill(t, fr, id, "design-tokens")
	if r.Version != v1+1 || r.ChangedBy != libraryActor || k.Resolved != "2" || k.Pin != "" || k.SHA256 != shaOf("Use tokens v2.") || k.AddedBy != botA {
		t.Fatalf("%+v %+v", r, k)
	}
	if r.Change == nil || r.Change.Summary != "design-tokens 1 -> 2" || r.Change.Op != "role.library.follow" || r.Change.Tier != 1 {
		t.Fatalf("%+v", r.Change)
	}
	// Nothing else moved, and no approval was asked.
	if len(f.submits) != 0 || len(r.Tools) != len(fr.roles[id][0].Tools) || len(r.Hosts) != 0 || len(r.MCP) != 0 {
		t.Fatalf("%+v", r)
	}
	if a := auditsOf(f, "role.change"); a[len(a)-1]["by"] != libraryActor || a[len(a)-1]["summary"] != "design-tokens 1 -> 2" {
		t.Fatalf("%v", a[len(a)-1])
	}
	// The pinned role did not move.
	if _, err := s.followLibrary(context.Background(), f, "dev_mac", pinned, &calls); err != nil {
		t.Fatal(err)
	}
	if k := libSkill(t, fr, pinned, "design-tokens"); k.Resolved != "1" || k.Pin != "1" {
		t.Fatalf("%+v", k)
	}
	// Rollback is a revert to the version before: allowed at once, and the old signature is still good.
	if _, err := s.panelRoleRevert(context.Background(), f, "dev_mac", id, v1); err != nil {
		t.Fatal(err)
	}
	if k := libSkill(t, fr, id, "design-tokens"); k.Resolved != "1" || fr.current(id).Version != v1+2 {
		t.Fatalf("%+v", k)
	}
	// The diff the History shows exists as a version pair.
	if got := fr.roles[id][v1].Parent; got != v1 {
		t.Fatalf("parent %d", got)
	}
}

func TestDeprecatedStaysWithdrawnIsDropped(t *testing.T) {
	f, s, fr, lib, id := libFixture(t)
	lib.publish("other", "admitted", "Other v1.")
	addLib(t, s, f, id, "design-tokens")
	addLib(t, s, f, id, "other@1")
	calls := 20
	// Deprecated: kept, and a following role does not move off it.
	lib.setState("design-tokens", 1, "deprecated")
	if ch, err := s.followLibrary(context.Background(), f, "dev_mac", id, &calls); err != nil || ch != nil {
		t.Fatalf("deprecated is kept: %v %v", ch, err)
	}
	if len(fr.current(id).Skills) != 2 {
		t.Fatal("dropped a deprecated skill")
	}
	// Withdrawn: dropped at the next materialization, each audited per role, whether it followed or was pinned.
	lib.setState("design-tokens", 1, "withdrawn")
	lib.setState("other", 1, "withdrawn")
	ch, err := s.followLibrary(context.Background(), f, "dev_mac", id, &calls)
	if err != nil || len(ch) != 2 {
		t.Fatalf("%v %v", ch, err)
	}
	r := fr.current(id)
	if len(r.Skills) != 0 || !strings.Contains(r.Change.Summary, "design-tokens 1 withdrawn, dropped") || !strings.Contains(r.Change.Summary, "other 1 withdrawn, dropped") {
		t.Fatalf("%+v %+v", r.Skills, r.Change)
	}
	drops := auditsOf(f, auditLibraryDropped)
	if len(drops) != 2 || drops[0]["role"] != id || drops[0]["skill"] == nil {
		t.Fatalf("%v", drops)
	}
}

func TestLibraryFailuresLeaveSkillsAlone(t *testing.T) {
	f, s, fr, lib, id := libFixture(t)
	addLib(t, s, f, id, "design-tokens")
	v := fr.current(id).Version
	calls := 20
	// Rubi locked or silent is not a withdrawal.
	lib.err = errors.New("Rubi is locked")
	if ch, err := s.followLibrary(context.Background(), f, "dev_mac", id, &calls); err != nil || ch != nil || fr.current(id).Version != v {
		t.Fatalf("%v %v", ch, err)
	}
	lib.err = nil
	// No budget, no calls.
	lib.setState("design-tokens", 1, "withdrawn")
	zero := 0
	if ch, _ := s.followLibrary(context.Background(), f, "dev_mac", id, &zero); ch != nil || fr.current(id).Version != v {
		t.Fatalf("%v", ch)
	}
	// A host with no library: nothing happens either.
	if got := s.followOnView(context.Background(), struct{ sisterHost }{f}, "dev_mac", id); got != nil || fr.current(id).Version != v {
		t.Fatalf("%v", got)
	}
}

func TestLibraryCheckOnViewAndPeriodicAreBounded(t *testing.T) {
	f, s, fr, lib, id := libFixture(t)
	addLib(t, s, f, id, "design-tokens")
	clock := time.Now()
	s.now = func() time.Time { return clock }
	lib.publish("design-tokens", "admitted", "Use tokens v2.")
	// Opening the page brings the role up to date and says so.
	pg := view(t, s, f, `{"page":"role","device":"dev_mac","role":"`+id+`"}`)
	if k := libSkill(t, fr, id, "design-tokens"); k.Resolved != "2" {
		t.Fatalf("%+v", k)
	}
	if n := section(t, pg, "Skills")["note"].(string); !strings.Contains(n, "design-tokens 1 -> 2") {
		t.Fatalf("%s", n)
	}
	// Again at once: no new library calls.
	n := lib.calls
	view(t, s, f, `{"page":"role","device":"dev_mac","role":"`+id+`"}`)
	if lib.calls != n {
		t.Fatalf("%d calls", lib.calls-n)
	}
	// The periodic check runs once per interval and looks at the roles with library skills.
	lib.publish("design-tokens", "admitted", "Use tokens v3.")
	s.libraryTick(context.Background(), f, []string{"dev_mac"})
	if k := libSkill(t, fr, id, "design-tokens"); k.Resolved != "3" {
		t.Fatalf("the periodic check: %+v", k)
	}
	lib.publish("design-tokens", "admitted", "Use tokens v4.")
	s.libraryTick(context.Background(), f, []string{"dev_mac"})
	if k := libSkill(t, fr, id, "design-tokens"); k.Resolved != "3" {
		t.Fatalf("too soon: %+v", k)
	}
	clock = clock.Add(libraryEvery + time.Second)
	s.libraryTick(context.Background(), f, []string{"dev_mac"})
	if k := libSkill(t, fr, id, "design-tokens"); k.Resolved != "4" {
		t.Fatalf("%+v", k)
	}
	// The watcher's refresh starts the check.
	lib.publish("design-tokens", "admitted", "Use tokens v5.")
	clock = clock.Add(libraryEvery + time.Second)
	f.next = func(ctx context.Context, _ string) (*request, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	w := newWatcher(f, s)
	w.refresh(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && libSkill(t, fr, id, "design-tokens").Resolved != "5" {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	w.wg.Wait()
	if k := libSkill(t, fr, id, "design-tokens"); k.Resolved != "5" {
		t.Fatalf("%+v", k)
	}
}

func TestLibraryPinAndFollowButtons(t *testing.T) {
	f, s, fr, lib, id := libFixture(t)
	addLib(t, s, f, id, "design-tokens")
	asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Name: "plain", Description: "d", Content: "text"}))
	pg := view(t, s, f, `{"page":"role","device":"dev_mac","role":"`+id+`"}`)
	allLabels(t, pg)
	it := findItem(t, pg, "Skills", "design-tokens")
	if !strings.Contains(it["detail"].(string), "following the latest admitted, now version 1") {
		t.Fatalf("%v", it)
	}
	if plain := findItem(t, pg, "Skills", "plain"); len(plain["actions"].([]map[string]any)) != 1 {
		t.Fatalf("an ad-hoc skill has no pin: %v", plain)
	}
	if n := section(t, pg, "Skills")["note"].(string); !strings.Contains(n, "rubi_library_submit") {
		t.Fatal("the page doesn't say how a skill reaches the library")
	}
	// Pin: a new version is made with the pin; the content is the same.
	op, args := actionOp(t, it, "Pin to this version")
	if op != "role_skill_pin" {
		t.Fatal(op)
	}
	v := fr.current(id).Version
	lib.publish("design-tokens", "admitted", "Use tokens v2.")
	if _, err := click(t, s, f, actionByLabel(t, it, "Pin to this version"), nil); err != nil {
		t.Fatal(err)
	}
	_ = args
	if k := libSkill(t, fr, id, "design-tokens"); k.Pin != "1" || k.Resolved != "1" || fr.current(id).Version != v+1 || fr.current(id).ChangedBy != "user" {
		t.Fatalf("%+v", k)
	}
	// The pinned skill does not follow on a view.
	pg = view(t, s, f, `{"page":"role","device":"dev_mac","role":"`+id+`"}`)
	it = findItem(t, pg, "Skills", "design-tokens")
	if !strings.Contains(it["detail"].(string), "design-tokens@1 (pinned)") || libSkill(t, fr, id, "design-tokens").Resolved != "1" {
		t.Fatalf("%v", it)
	}
	// Follow: back to following, and caught up at once.
	res, err := click(t, s, f, actionByLabel(t, it, "Follow the latest"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if k := libSkill(t, fr, id, "design-tokens"); k.Pin != "" || k.Resolved != "2" {
		t.Fatalf("%+v", k)
	}
	if m := res.(map[string]any); m["library_update"] != "design-tokens 1 -> 2" {
		t.Fatalf("%v", m)
	}
	// Pin on something that isn't a library skill.
	if _, err := s.panelRoleItem(context.Background(), f, "role_skill_pin", "dev_mac", id, "plain", "", nil, nil); err == nil {
		t.Fatal("pinned an ad-hoc skill")
	}
}
