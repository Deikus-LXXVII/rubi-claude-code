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

func sshFixture(t *testing.T) (*fakeHost, *sisters, *fakeRoles, *fakeSSH) {
	t.Helper()
	f, s, fr := roleFixture(t)
	fs := newFakeSSH()
	f.agent.ssh = fs
	trustBot(t, s, botA, "p1")
	return f, s, fr, fs
}

func sshTicketOf(t *testing.T, f *fakeHost) sshTicket {
	t.Helper()
	b, _ := json.Marshal(lastSubmit(t, f).Payload)
	var tk sshTicket
	if err := json.Unmarshal(b, &tk); err != nil {
		t.Fatal(err)
	}
	return tk
}

// addTarget walks the panel's whole path: Add, Check the host key (the strong approval), approve (execute).
func addTarget(t *testing.T, s *sisters, f *fakeHost, name string, steps ...string) map[string]any {
	t.Helper()
	pok(t, s, f, "ssh_add", `{"device":"dev_mac","text":"`+name+` web.example.com deploy 2222"}`)
	for _, st := range steps {
		pok(t, s, f, "ssh_draft_cmd", `{"device":"dev_mac","item":"`+name+`","text":"`+st+`"}`)
	}
	pok(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"`+name+`","text":""}`)
	res, err := s.executeSSHRegister(context.Background(), f, sshTicketOf(t, f))
	if err != nil {
		t.Fatal(err)
	}
	return res.(map[string]any)
}

func TestSSHRegisterFlowScanApprovalRegisterPublicKey(t *testing.T) {
	f, s, _, fs := sshFixture(t)
	pok(t, s, f, "ssh_add", `{"device":"dev_mac","text":"web-1 Web.Example.com deploy 2222"}`)
	pok(t, s, f, "ssh_draft_cmd", `{"device":"dev_mac","item":"web-1","text":"uptime"}`)
	// Nothing is registered, scanned or asked yet.
	if len(fs.called(opSSHScan)) != 0 || len(f.submits) != 0 || len(fs.registeredNames()) != 0 {
		t.Fatal("something happened before the host key was confirmed")
	}
	pg := view(t, s, f, `{"page":"ssh"}`)
	allLabels(t, pg)
	dr := findItem(t, pg, "Targets being added", "web-1")
	if d := dr["detail"].(string); !strings.Contains(d, "deploy@web.example.com:2222") || !strings.Contains(d, "only uptime") || !strings.Contains(d, "asks you for each command") {
		t.Fatalf("%s", d)
	}
	// Check the host key: the scan, then the strong approval that carries the fingerprint and everything the user chose.
	res := pok(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":""}`)
	if res["approval_id"] == nil || len(fs.called(opSSHScan)) != 1 || len(fs.registeredNames()) != 0 {
		t.Fatalf("%v", res)
	}
	if sc := fs.called(opSSHScan)[0]; sc["host"] != "web.example.com" || sc["port"] != float64(2222) {
		t.Fatalf("%v", sc)
	}
	req := lastSubmit(t, f)
	pv := req.Preview.(map[string]any)
	if req.Kind != kindSSHTarget || pv["host_key_fingerprint"] != fpGood || pv["host"] != "web.example.com" || pv["port"] != 2222 || pv["user"] != "deploy" || pv["ask_each_time"] != true ||
		fmt.Sprint(pv["allowed_commands"]) != "[uptime]" || !strings.Contains(req.Summary, fpGood) || pv["compare_the_fingerprint"] == nil {
		t.Fatalf("%+v", req)
	}
	tk := sshTicketOf(t, f)
	if tk.Fingerprint != fpGood || tk.Name != "web-1" || tk.Port != 2222 || tk.User != "deploy" || !tk.AskEachTime || tk.Reuse {
		t.Fatalf("%+v", tk)
	}
	// Approve: Home registers with the fingerprint the user saw, and the public key line comes back as item text to copy.
	out, err := s.executeSSHRegister(context.Background(), f, tk)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	line, _ := m["public_key_line"].(string)
	if !strings.HasPrefix(line, `restrict,command="uptime" ssh-ed25519 AAAA`) || m["info"] != line {
		t.Fatalf("%v", m)
	}
	reg := fs.registers[0]
	if reg["fingerprint"] != fpGood || reg["host"] != "web.example.com" || reg["user"] != "deploy" || reg["ask_each_time"] != true || reg["reuse"] != nil || fmt.Sprint(reg["allowed_commands"]) != "[uptime]" {
		t.Fatalf("%v", reg)
	}
	if a := auditsOf(f, auditSSHRegistered); len(a) != 1 || a[0]["target"] != "web-1" || a[0]["fingerprint"] != fpGood || strings.Contains(fmt.Sprint(a[0]), "AAAA") {
		t.Fatalf("%v", a)
	}
	// The page lists the target (host key, allowed commands, ask each time) and shows the key line to install.
	pg = view(t, s, f, `{"page":"ssh"}`)
	allLabels(t, pg)
	row := findItem(t, pg, "SSH targets", "web-1")
	d := row["detail"].(string)
	for _, want := range []string{"deploy@web.example.com:2222", fpGood, "only uptime", "asks you for each command", "no role has it"} {
		if !strings.Contains(d, want) {
			t.Errorf("detail lacks %q: %s", want, d)
		}
	}
	key := findItem(t, pg, "Install the public key", "authorized_keys line for web-1")
	if key["info"] != line || !strings.Contains(key["detail"].(string), "ssh-ed25519 AAAA") {
		t.Fatalf("%v", key)
	}
	for _, sec := range pg["sections"].([]map[string]any) {
		if sec["title"] == "Targets being added" {
			t.Fatal("the draft is still listed after the registration")
		}
	}
	if _, args := actionOp(t, row, "Remove"); args["item"] != "web-1" || actionByLabel(t, row, "Remove")["confirm"] == nil || actionByLabel(t, row, "Remove")["danger"] != true {
		t.Fatalf("%v", row)
	}
}

func TestSSHRegisterRefusesWhatTheUserDidNotConfirm(t *testing.T) {
	f, s, _, fs := sshFixture(t)
	pok(t, s, f, "ssh_add", `{"device":"dev_mac","text":"web-1 web.example.com deploy"}`)
	// A typed fingerprint that isn't the server's: no approval is even asked.
	if _, err := pcall(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":"`+fpOther+`"}`); err == nil || !strings.Contains(err.Error(), fpGood) || len(f.submits) != 0 {
		t.Fatalf("%v", err)
	}
	// The matching one is noted in the approval.
	pok(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":"`+fpGood+`"}`)
	if lastSubmit(t, f).Preview.(map[string]any)["matches_the_fingerprint_you_typed"] != true {
		t.Fatal("not noted")
	}
	// The server's key changes between the approval and the execution: Home refuses, nothing is registered.
	tk := sshTicketOf(t, f)
	fs.live = fpOther
	if _, err := s.executeSSHRegister(context.Background(), f, tk); err == nil || !strings.Contains(err.Error(), "not registered") || len(fs.registeredNames()) != 0 {
		t.Fatalf("%v", err)
	}
	// A bad payload and bad input are refused before Home hears of them.
	bad := tk
	bad.Fingerprint = "SHA256:short"
	n := len(fs.registers)
	if _, err := s.executeSSHRegister(context.Background(), f, bad); err == nil || len(fs.registers) != n {
		t.Fatal("registered with a bad fingerprint")
	}
	for _, text := range []string{"", "a b", "Web-1 h u", "web-1 bad_host!! u", "web-1 h.example.com bad;user", "web-1 h.example.com u 0", "web-1 h.example.com u 99999", "web-1 h.example.com u x", "web-1 h.example.com u 22 extra", "web-1 -oProxy=x u"} {
		raw, _ := json.Marshal(map[string]any{"device": "dev_mac", "text": text})
		if _, err := pcall(t, s, f, "ssh_add", string(raw)); err == nil {
			t.Errorf("%q was taken", text)
		}
	}
	// A scan that fails says so.
	fs.scanErr = homeRefusal("connection refused")
	if _, err := pcall(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":""}`); err == nil || !strings.Contains(err.Error(), "couldn't read the server's host key") {
		t.Fatalf("%v", err)
	}
	// No Bot tool can register or scan, and a Home without SSH answers plainly.
	for _, n := range roleToolNames {
		if strings.Contains(n, "register") || strings.Contains(n, "scan") {
			t.Fatalf("a Bot tool %s", n)
		}
	}
	f.agent.ssh = nil
	if _, err := pcall(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":""}`); err == nil || !strings.Contains(err.Error(), "doesn't do SSH targets") {
		t.Fatalf("%v", err)
	}
	if pg := view(t, s, f, `{"page":"ssh"}`); !strings.Contains(pageText(pg), "doesn't do SSH targets") {
		t.Fatalf("%v", pg)
	}
}

func TestSSHDraftOptionsAndLimits(t *testing.T) {
	f, s, _, fs := sshFixture(t)
	pok(t, s, f, "ssh_add", `{"device":"dev_mac","text":"web-1 web.example.com deploy"}`)
	pok(t, s, f, "ssh_draft_cmd", `{"device":"dev_mac","item":"web-1","text":"tail -n *"}`)
	pok(t, s, f, "ssh_draft_ask", `{"device":"dev_mac","item":"web-1","on":false}`)
	for _, bad := range []string{"", "a\nb", "rm ‮-rf", strings.Repeat("x", 201)} {
		raw, _ := json.Marshal(map[string]any{"device": "dev_mac", "item": "web-1", "text": bad})
		if _, err := pcall(t, s, f, "ssh_draft_cmd", string(raw)); err == nil {
			t.Errorf("command %q taken", bad)
		}
	}
	pok(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":""}`)
	if tk := sshTicketOf(t, f); tk.AskEachTime || len(tk.Allowed) != 1 || tk.Allowed[0] != "tail -n *" {
		t.Fatalf("%+v", tk)
	}
	// Any command clears the list; a discarded draft can't be confirmed.
	pok(t, s, f, "ssh_draft_anycmd", `{"device":"dev_mac","item":"web-1"}`)
	pok(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":""}`)
	if tk := sshTicketOf(t, f); len(tk.Allowed) != 0 {
		t.Fatalf("%+v", tk)
	}
	pok(t, s, f, "ssh_draft_discard", `{"device":"dev_mac","item":"web-1"}`)
	if _, err := pcall(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":""}`); err == nil {
		t.Fatal("confirmed a discarded draft")
	}
	// Drafts are bounded and expire.
	clock := time.Now()
	s.now = func() time.Time { return clock }
	for i := 0; i < maxSSHDrafts+3; i++ {
		clock = clock.Add(time.Second)
		pok(t, s, f, "ssh_add", fmt.Sprintf(`{"device":"dev_mac","text":"t%d h.example.com u"}`, i))
	}
	if n := len(s.draftsOf("dev_mac")); n != maxSSHDrafts {
		t.Fatalf("%d drafts", n)
	}
	clock = clock.Add(sshDraftLife + time.Second)
	if n := len(s.draftsOf("dev_mac")); n != 0 {
		t.Fatalf("%d drafts after an hour", n)
	}
	_ = fs
}

func TestSSHReuseOfARemovedNameNeedsTheStrongApprovalToSayIt(t *testing.T) {
	f, s, _, fs := sshFixture(t)
	addTarget(t, s, f, "web-1")
	pok(t, s, f, "ssh_remove", `{"device":"dev_mac","item":"web-1"}`)
	// Adding the name again without reuse: Home refuses at the approval's execution, and the message says what to do.
	pok(t, s, f, "ssh_add", `{"device":"dev_mac","text":"web-1 web.example.com deploy"}`)
	pok(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":""}`)
	_, err := s.executeSSHRegister(context.Background(), f, sshTicketOf(t, f))
	if err == nil || !strings.Contains(err.Error(), "Reuse a removed name") {
		t.Fatalf("%v", err)
	}
	if fs.registers[len(fs.registers)-1]["reuse"] != nil {
		t.Fatal("reuse sent without the user saying so")
	}
	// With the switch on, the approval says so and only then is reuse sent.
	pok(t, s, f, "ssh_draft_reuse", `{"device":"dev_mac","item":"web-1","on":true}`)
	pok(t, s, f, "ssh_confirm", `{"device":"dev_mac","item":"web-1","text":""}`)
	if lastSubmit(t, f).Preview.(map[string]any)["reuses_the_name_of_a_removed_target"] != true {
		t.Fatal("the approval doesn't say it")
	}
	if _, err := s.executeSSHRegister(context.Background(), f, sshTicketOf(t, f)); err != nil {
		t.Fatal(err)
	}
	if fs.registers[len(fs.registers)-1]["reuse"] != true || len(fs.registeredNames()) != 1 {
		t.Fatalf("%v", fs.registers)
	}
}

func TestSSHGrantAndRevokeTiers(t *testing.T) {
	f, s, fr, fs := sshFixture(t)
	id := mustCreate(t, s, f, botA, "design")
	// An unregistered target is rejected: nothing is applied and nobody is asked.
	m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "web-1"}, true))
	if status(m) != "rejected" || !strings.Contains(strings.Join(m["reasons"].([]string), " "), "isn't registered") || len(fr.current(id).SSH) != 0 || len(f.submits) != 0 {
		t.Fatalf("%v", m)
	}
	addTarget(t, s, f, "web-1")
	n := len(f.submits)
	// A registered one is tier 1: applied at once, audited, the role record has it.
	m = asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "web-1"}, true))
	if status(m) != "applied" || m["tier"] != 1 || len(f.submits) != n || len(fr.current(id).SSH) != 1 || fr.current(id).SSH[0] != "web-1" {
		t.Fatalf("%v", m)
	}
	if a := auditsOf(f, "role.change"); a[len(a)-1]["summary"] != "+ssh web-1" || a[len(a)-1]["tier"] != 1 || a[len(a)-1]["by"] != botA {
		t.Fatalf("%v", a[len(a)-1])
	}
	// The list shows which roles have the target.
	if pg := view(t, s, f, `{"page":"ssh"}`); !strings.Contains(findItem(t, pg, "SSH targets", "web-1")["detail"].(string), "granted to design") {
		t.Fatalf("%v", pg)
	}
	// Revoking is tier 1 as well; a name that isn't registered can be revoked (cleaning up).
	if m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "web-1"}, false)); status(m) != "applied" || len(fr.current(id).SSH) != 0 {
		t.Fatalf("%v", m)
	}
	// Bad names, and a Home with no SSH, fail plainly.
	if m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "Bad Name"}, true)); status(m) != "rejected" {
		t.Fatalf("%v", m)
	}
	f.agent.ssh = nil
	if _, err := s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "web-1"}, true); err == nil || !strings.Contains(err.Error(), "doesn't do SSH targets") {
		t.Fatalf("%v", err)
	}
	// The tier engine's backstop: a grant of an unregistered target from any path asks for the strong approval.
	f.agent.ssh = fs
	cur := fr.current(id)
	next := cur.clone()
	next.SSH = []string{"ghost"}
	res := asMap(t)(s.changeRole(context.Background(), f, roleChangeReq{Bot: botA, Dev: mac, Op: "x", Cur: cur, Next: next, Lim: defaultRoleLimits()}))
	if status(res) != "needs_approval" || lastSubmit(t, f).Kind != kindRoleWiden {
		t.Fatalf("%v", res)
	}
}

func TestSSHPanelGrantRevokeAndRemoveClearsGrants(t *testing.T) {
	f, s, fr, fs := sshFixture(t)
	id := mustCreate(t, s, f, botA, "design")
	addTarget(t, s, f, "web-1")
	addTarget(t, s, f, "db-1")
	pg := view(t, s, f, fmt.Sprintf(`{"page":"role","device":"dev_mac","role":"%s"}`, id))
	allLabels(t, pg)
	web := findItem(t, pg, "SSH grants", "web-1")
	if !strings.Contains(web["detail"].(string), "not granted") {
		t.Fatalf("%v", web)
	}
	if _, err := click(t, s, f, actionByLabel(t, web, "Grant"), nil); err != nil {
		t.Fatal(err)
	}
	if r := fr.current(id); len(r.SSH) != 1 || r.ChangedBy != "user" || r.Change.Tier != 1 {
		t.Fatalf("%+v", r)
	}
	pg = view(t, s, f, fmt.Sprintf(`{"page":"role","device":"dev_mac","role":"%s"}`, id))
	web = findItem(t, pg, "SSH grants", "web-1")
	if !strings.Contains(web["detail"].(string), "this role may use it") {
		t.Fatalf("%v", web)
	}
	if _, err := click(t, s, f, actionByLabel(t, web, "Revoke"), nil); err != nil || len(fr.current(id).SSH) != 0 {
		t.Fatalf("%v", err)
	}
	// Granting a name that isn't registered is refused on the panel too.
	if _, err := s.panelRoleItem(context.Background(), f, "role_ssh_grant", "dev_mac", id, "ghost", "", nil, nil); err == nil || len(f.submits) > 4 {
		t.Fatalf("%v", err)
	}
	// Removing a target: Home deletes it, streams are cut, and every role that names it loses the grant (as the
	// user's change), so a later target with the same name starts with no grants.
	other := mustCreate(t, s, f, botA, "other")
	for _, r := range []string{id, other} {
		if _, err := s.panelRoleItem(context.Background(), f, "role_ssh_grant", "dev_mac", r, "web-1", "", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.panelRoleItem(context.Background(), f, "role_ssh_grant", "dev_mac", other, "db-1", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	res := pok(t, s, f, "ssh_remove", `{"device":"dev_mac","item":"web-1"}`)
	if res["removed"] != "web-1" || res["closed_streams"] != 1 || res["grants_removed"] != 2 || res["note"] != nil {
		t.Fatalf("%v", res)
	}
	if len(fr.current(id).SSH) != 0 || len(fr.current(other).SSH) != 1 || fr.current(other).SSH[0] != "db-1" || fr.current(other).ChangedBy != "user" {
		t.Fatalf("%+v %+v", fr.current(id), fr.current(other))
	}
	if got := fs.registeredNames(); len(got) != 1 || got[0] != "db-1" {
		t.Fatalf("%v", got)
	}
	if a := auditsOf(f, auditSSHRemoved); len(a) != 1 || a[0]["target"] != "web-1" || a[0]["grants_removed"] != 2 {
		t.Fatalf("%v", a)
	}
	if _, err := pcall(t, s, f, "ssh_remove", `{"device":"dev_mac","item":"web-1"}`); err == nil {
		t.Fatal("removed twice")
	}
	if _, err := pcall(t, s, f, "ssh_remove", `{"device":"dev_mac","item":"../x"}`); err == nil {
		t.Fatal("bad name")
	}
	// The registry cache forgot the name: a Bot can't grant it any more.
	if m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "web-1"}, true)); status(m) != "rejected" {
		t.Fatalf("%v", m)
	}
}

func TestSSHPagesShowUntrustedTextAsTextAndWarnOnAChangedKey(t *testing.T) {
	f, s, fr, fs := sshFixture(t)
	id := seedRole(t, f, s, fr)
	addTarget(t, s, f, "web-1")
	fs.mu.Lock()
	fs.targets["web-1"].HostKeyChanged = true
	fs.targets["web-1"].AllowedCommands = []string{injection}
	fs.audit = []sshAuditEntry{
		{Stream: "st_1", Role: id, Project: "p1", Bot: botA, Target: "web-1", Command: "uptime " + injection + "‮", Start: "2026-10-31T10:00:00Z", End: "2026-10-31T10:00:02Z", BytesIn: 5, BytesOut: 99, Result: "ok", Exit: new(int)},
		{Stream: "", Role: id, Project: "p1", Bot: botA, Target: "web-1", Command: "rm -rf /", Start: "2026-10-31T10:01:00Z", Result: "host key changed", Reason: "pinned key differs"},
	}
	fs.mu.Unlock()
	pg := view(t, s, f, `{"page":"ssh"}`)
	acts := allLabels(t, pg, injection, "web-1")
	row := findItem(t, pg, "SSH targets", "web-1")
	if row["warn"] != true || !strings.Contains(row["detail"].(string), "HOST KEY CHANGED") || !strings.Contains(row["detail"].(string), injection) {
		t.Fatalf("%v", row)
	}
	for _, a := range acts {
		if a["prompt"] != nil && strings.Contains(fmt.Sprint(a["prompt"]), "web-1") {
			t.Fatalf("a target's name in a prompt: %v", a)
		}
	}
	// The role page warns too.
	rp := view(t, s, f, fmt.Sprintf(`{"page":"role","device":"dev_mac","role":"%s"}`, id))
	if g := findItem(t, rp, "SSH grants", "web-1"); g["warn"] != true || !strings.HasPrefix(g["detail"].(string), "HOST KEY CHANGED") {
		t.Fatalf("%v", g)
	}
	// The audit page: text only, clipped, with the failed attempt marked, and no hidden characters.
	_, args := actionOp(t, row, "Audit")
	_ = args
	ap := view(t, s, f, `{"page":"ssh_audit","device":"dev_mac","target":"web-1"}`)
	its := ap["sections"].([]map[string]any)[0]["items"].([]map[string]any)
	if len(its) != 2 || its[0]["warn"] != true || its[1]["warn"] == true || !strings.Contains(its[0]["title"].(string), "host key changed") {
		t.Fatalf("%v", its)
	}
	if strings.ContainsRune(pageText(ap), '‮') || !strings.Contains(its[1]["detail"].(string), "command: uptime IGNORE ALL") {
		t.Fatalf("%v", its)
	}
	if _, err := pcall(t, s, f, "view", `{"page":"ssh_audit","device":"dev_mac","target":"../x"}`); err == nil {
		t.Fatal("bad target")
	}
}

func TestSSHAuditIsCopiedOncePerEntry(t *testing.T) {
	f, s, _, fs := sshFixture(t)
	exit := 0
	fs.audit = []sshAuditEntry{{Stream: "st_1", Role: "r_aaaaaaaa", Project: "p1", Bot: botA, Target: "web-1", Command: "uptime", Start: "t1", Result: "ok", Exit: &exit},
		{Stream: "st_2", Role: "r_aaaaaaaa", Project: "p1", Bot: botA, Target: "web-1", Command: "ls", Start: "t2", Result: "denied", Reason: "not granted"}}
	clock := time.Now()
	s.now = func() time.Time { return clock }
	s.sshAuditTick(context.Background(), f, []string{"dev_mac"})
	a := auditsOf(f, auditSSHStream)
	if len(a) != 2 || a[0]["command"] != "uptime" || a[0]["exit"] != 0 || a[1]["result"] != "denied" || a[1]["reason"] != "not granted" {
		t.Fatalf("%v", a)
	}
	s.sshAuditTick(context.Background(), f, []string{"dev_mac"}) // too soon
	clock = clock.Add(sshAuditEvery + time.Second)
	fs.audit = append(fs.audit, sshAuditEntry{Stream: "st_3", Target: "web-1", Command: "df", Start: "t3", Result: "ok"})
	s.sshAuditTick(context.Background(), f, []string{"dev_mac"})
	if a := auditsOf(f, auditSSHStream); len(a) != 3 || a[2]["command"] != "df" {
		t.Fatalf("each entry once: %v", a)
	}
}

// ---- ssh.ask ----

func sshAskItem(id, role string, in map[string]any) agentItem {
	b, _ := json.Marshal(in)
	return agentItem{Type: "ssh.ask", AskID: id, Project: "p1", Role: role, SessionID: "rs-1", Host: "web.example.com", Op: "ssh", Input: b, Mode: "bypassPermissions", ExpiresAt: time.Now().Add(time.Minute)}
}

func goodSSHInput(cmd string) map[string]any {
	return map[string]any{"target": "web-1", "host": "web.example.com", "port": 2222, "user": "deploy", "command": cmd}
}

func TestSSHAskReachesAStrongApprovalWithTheRoleAndCommand(t *testing.T) {
	f, s, w := agentFixture(t)
	s.rc.set("dev_mac", &roleDev{at: time.Now(), roles: map[string]*role{"r_aaaaaaaa": {ID: "r_aaaaaaaa", Name: "deployer"}}})
	f.next = func(ctx context.Context, _ string) (*request, error) { <-ctx.Done(); return nil, ctx.Err() }
	f.agent.items = []agentItem{sshAskItem("k1", "r_aaaaaaaa", goodSSHInput("systemctl status app"))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.submits)
		f.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	r := lastSubmit(t, f)
	p := r.Preview.(map[string]any)
	// Strong, one option, in bypassPermissions too (nothing allowed by itself), and the user reads everything.
	if r.Kind != kindRun || len(r.Options) != 1 || p["role"] != "deployer (r_aaaaaaaa)" || p["ssh_target"] != "web-1" || p["ssh_host"] != "web.example.com" || p["ssh_user"] != "deploy" ||
		p["ssh_port"] != 2222 || p["ssh_command"] != "systemctl status app" || p["always_asks"] == nil || p["host"] != nil || p["repository_path"] != nil ||
		!strings.Contains(fmt.Sprint(p["command"]), "ssh web-1 (deploy@web.example.com:2222): systemctl status app") || !strings.Contains(r.Summary, "systemctl status app") {
		t.Fatalf("%+v", r)
	}
	if d := f.agent.decided(); len(d) != 0 {
		t.Fatalf("answered by itself: %+v", d)
	}
	// Approving answers Home with allow; the ticket names the ask.
	tk := ticket{}
	b, _ := json.Marshal(r.Payload)
	_ = json.Unmarshal(b, &tk)
	if tk.AskID != "k1" {
		t.Fatalf("%+v", tk)
	}
	if _, err := allow(context.Background(), f, b); err != nil {
		t.Fatal(err)
	}
	if d := f.agent.decided(); len(d) != 1 || d[0].AskID != "k1" || d[0].Behavior != "allow" {
		t.Fatalf("%+v", d)
	}
}

func TestSSHAskIsCheckedBeforeAnyoneIsAsked(t *testing.T) {
	cases := map[string]agentItem{
		"no input":        {Type: "ssh.ask", AskID: "a", Project: "p1"},
		"bad json":        {Type: "ssh.ask", AskID: "a", Project: "p1", Input: json.RawMessage(`[1]`)},
		"bad target":      sshAskItem("a", "r_aaaaaaaa", map[string]any{"target": "Web 1", "host": "h.example.com", "port": 22, "user": "u", "command": "ls"}),
		"bad host":        sshAskItem("a", "r_aaaaaaaa", map[string]any{"target": "web-1", "host": "h/..", "port": 22, "user": "u", "command": "ls"}),
		"bad user":        sshAskItem("a", "r_aaaaaaaa", map[string]any{"target": "web-1", "host": "h.example.com", "port": 22, "user": "u;x", "command": "ls"}),
		"bad port":        sshAskItem("a", "r_aaaaaaaa", map[string]any{"target": "web-1", "host": "h.example.com", "port": 0, "user": "u", "command": "ls"}),
		"empty command":   sshAskItem("a", "r_aaaaaaaa", goodSSHInput("  ")),
		"huge command":    sshAskItem("a", "r_aaaaaaaa", goodSSHInput(strings.Repeat("x", 1001))),
		"bidi command":    sshAskItem("a", "r_aaaaaaaa", goodSSHInput("ls ‮-la")),
		"control command": sshAskItem("a", "r_aaaaaaaa", goodSSHInput("ls \x1b[2J")),
		"bad role":        sshAskItem("a", "r_x‮", goodSSHInput("ls")),
	}
	for name, it := range cases {
		f, _, w := agentFixture(t)
		w.handleAsk(context.Background(), mac, it)
		if d := f.agent.decided(); len(d) != 1 || d[0].Behavior != "deny" || len(f.submits) != 0 {
			t.Errorf("%s: %+v", name, d)
		}
	}
	// A second line can't pass for part of the first: newlines are marked.
	f, _, w := agentFixture(t)
	w.handleAsk(context.Background(), mac, sshAskItem("m", "r_aaaaaaaa", goodSSHInput("ls\nrm -rf /srv")))
	if c := lastSubmit(t, f).Preview.(map[string]any)["ssh_command"]; c != "ls⏎rm -rf /srv" {
		t.Fatalf("%v", c)
	}
	// Spaces are kept as typed, and a command with our marks is refused.
	f3, _, w3 := agentFixture(t)
	w3.handleAsk(context.Background(), mac, sshAskItem("x", "r_aaaaaaaa", goodSSHInput("echo  a\tb")))
	if c := lastSubmit(t, f3).Preview.(map[string]any)["ssh_command"]; c != "echo  a⇥b" {
		t.Fatalf("%v", c)
	}
	f4, _, w4 := agentFixture(t)
	w4.handleAsk(context.Background(), mac, sshAskItem("y", "r_aaaaaaaa", goodSSHInput("ls ⏎ rm")))
	if d := f4.agent.decided(); len(d) != 1 || d[0].Behavior != "deny" {
		t.Fatalf("%+v", d)
	}
	// The legacy role (its id is its project's) names no role.
	f2, _, w2 := agentFixture(t)
	w2.handleAsk(context.Background(), mac, sshAskItem("l", "p1", goodSSHInput("ls")))
	if p := lastSubmit(t, f2).Preview.(map[string]any); p["role"] != nil {
		t.Fatalf("%v", p)
	}
}

func TestBashSSHAlwaysAsksAndNoTrustCoversIt(t *testing.T) {
	for _, cmd := range []string{"ssh web-1 uptime", "rubi-ssh web-1 uptime", "/usr/local/bin/ssh web-1 ls", "cd src && ssh web-1 ls", "ls | rubi-ssh web-1 cat",
		"command ssh web-1 ls", "env ssh web-1 ls", "SSH_X=1 ssh web-1 ls", "ssh web-1"} {
		for _, mode := range []string{"bypassPermissions", "acceptEdits", "default"} {
			f, _, w := agentFixture(t)
			w.handleAsk(context.Background(), mac, bashAsk("a", cmd, mode))
			if d := f.agent.decided(); len(d) != 0 {
				t.Errorf("%s (%s): answered by itself: %+v", cmd, mode, d)
				continue
			}
			r := lastSubmit(t, f)
			if r.Kind != kindRun || len(r.Options) != 1 {
				t.Errorf("%s (%s): %+v", cmd, mode, r)
			}
		}
	}
	// The wording for ssh says what it is.
	if why := bashAlwaysAsk("rubi-ssh web-1 uptime", agentRoot); !strings.Contains(why, "over SSH") {
		t.Fatalf("%s", why)
	}
	if why := bashAlwaysAsk("ssh web-1 uptime", agentRoot); !strings.Contains(why, "over SSH") {
		t.Fatalf("%s", why)
	}
	// A live project trust and a 2-hour trust cover plain commands, never these.
	f, s, w := agentFixture(t)
	trustBot(t, s, botA, "p1")
	now := time.Now()
	if err := s.st.issue(mandate{ID: "md_1", Device: "dev_mac", SessionID: "s-1", Cwd: agentRoot, Project: "p1", Issued: now, Expires: now.Add(time.Hour), MaxUses: 50}, now); err != nil {
		t.Fatal(err)
	}
	w.handleAsk(context.Background(), mac, bashAsk("b", "rubi-ssh web-1 uptime", "default"))
	if d := f.agent.decided(); len(d) != 0 || len(f.submits) != 1 {
		t.Fatalf("a trust covered an ssh command: %+v", d)
	}
	if ok, why := classify("ssh web-1 uptime"); ok || why == "" {
		t.Fatal("classified safe")
	}
	if ok, _ := classify("rubi-ssh web-1 uptime"); ok {
		t.Fatal("classified safe")
	}
}

var _ rubiplugin.HomeDevice

func TestSSHTargetKindIsStrongAndLocked(t *testing.T) {
	var found bool
	for _, a := range manifest().Actions {
		if a.Kind == kindSSHTarget {
			found = true
			if a.DefaultLevel != rubiplugin.Strong || !a.Locked || len(a.Options) != 1 {
				t.Fatalf("%+v", a)
			}
		}
	}
	if !found || kindSSHTarget != "claude-code.ssh_target" {
		t.Fatal("the kind is not in the manifest")
	}
}

func TestSSHGrantOfATargetThatAllowsAnyCommandIsTier2(t *testing.T) {
	f, s, fr, fs := sshFixture(t)
	id := mustCreate(t, s, f, botA, "design")
	addTarget(t, s, f, "web-1")
	for name, allowed := range map[string][]string{"open-1": nil, "star-1": {"*"}, "dstar-1": {"tail **"}, "narrow-1": {"tail -n *"}} {
		fs.targets[name] = &sshTarget{Name: name, Host: "h.example.com", Port: 22, User: "deploy", AllowedCommands: allowed}
	}
	for _, name := range []string{"open-1", "star-1", "dstar-1"} {
		n := len(f.submits)
		m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: name}, true))
		if status(m) != "needs_approval" || len(f.submits) != n+1 || lastSubmit(t, f).Kind != kindRoleWiden || len(fr.current(id).SSH) != 0 {
			t.Fatalf("%s: %v", name, m)
		}
		if sum := lastSubmit(t, f).Summary; !strings.Contains(sum, name) || !strings.Contains(sum, "deploy@h.example.com:22") || !strings.Contains(sum, "any command") {
			t.Fatalf("%s", sum)
		}
	}
	// Restricted commands, and ask-each-time, stay tier 1.
	for _, name := range []string{"narrow-1", "web-1"} {
		if m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: name}, true)); status(m) != "applied" || m["tier"] != 1 {
			t.Fatalf("%s: %v", name, m)
		}
	}
}

func TestSSHAuditUsesAfterSeqAndRemembersIt(t *testing.T) {
	f, s, _, fs := sshFixture(t)
	fs.numbered = true
	fs.refusals = map[string]int{"not_granted": 2}
	fs.audit = []sshAuditEntry{{Stream: "st_1", Target: "web-1", Command: "uptime", Start: "t1", Result: "ok"},
		{Stream: "st_2", Target: "web-1", Command: "ls", Start: "t1", Result: "denied", Reason: "not granted"}}
	clock := time.Now()
	s.now = func() time.Time { return clock }
	s.sshAuditTick(context.Background(), f, []string{"dev_mac"})
	if a := auditsOf(f, auditSSHStream); len(a) != 2 || a[0]["seq"] != int64(1) || a[1]["seq"] != int64(2) || s.st.sshAuditSeq("dev_mac") != 2 {
		t.Fatalf("%v", a)
	}
	if c := auditsOf(f, auditSSHCopy); len(c) != 1 || c[0]["copied"] != 2 || c[0]["refused"] != 1 || c[0]["refusals"] == nil {
		t.Fatalf("%v", c)
	}
	// A restart forgets the in-memory dedupe; the saved seq keeps entries from being copied twice, and the call asks after it.
	s.sshSeen = nil
	clock = clock.Add(sshAuditEvery + time.Second)
	fs.audit = append(fs.audit, sshAuditEntry{Stream: "st_3", Target: "web-1", Command: "df", Start: "t1", Result: "ok"})
	s.sshAuditTick(context.Background(), f, []string{"dev_mac"})
	if a := auditsOf(f, auditSSHStream); len(a) != 3 || a[2]["command"] != "df" {
		t.Fatalf("%v", a)
	}
	var asked []map[string]any
	for _, c := range fs.called(opSSHAudit) {
		asked = append(asked, c)
	}
	if last := asked[len(asked)-1]; fmt.Sprint(last["after_seq"]) != "2" {
		t.Fatalf("%v", last)
	}
}
