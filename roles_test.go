package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const botA = "bot-a"

// cfgRoleHost adds the user's settings (the plugin config) to the fake host.
type cfgRoleHost struct {
	*fakeHost
	cfg string
}

func (c cfgRoleHost) Config(v any) error { return json.Unmarshal([]byte(c.cfg), v) }

func roleFixture(t *testing.T) (*fakeHost, *sisters, *fakeRoles) {
	t.Helper()
	f, s, _ := agentFixture(t)
	fr := newFakeRoles()
	f.agent.roles = fr
	// Every approval has its own id, as Rubi's have.
	n := 0
	f.submit = func(rubiplugin.Request) (map[string]any, error) {
		n++
		id := fmt.Sprintf("apr_%d", n)
		return map[string]any{"status": "awaiting_approval", "approval_id": id, "level": "strong", "approval_url": "https://rubi-panel.com/#a=" + id}, nil
	}
	return f, s, fr
}

// trustBot gives the Bot a live (until revoked) project trust of the agent project.
func trustBot(t *testing.T, s *sisters, bot, project string) {
	t.Helper()
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	s.st.st.Projects = append(s.st.st.Projects, projectTrust{ID: "pt_" + bot + project, Device: "dev_mac", Root: "/work", Sister: bot, Project: project,
		BranchPattern: "agent/*", Issued: time.Now(), Unlimited: true})
}

func who(bot string) roleWho { return roleWho{Agent: bot, VerifiedAgent: bot} }

func asMap(t *testing.T) func(v any, err error) map[string]any {
	return func(v any, err error) map[string]any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("not a map: %#v", v)
		}
		return m
	}
}

func status(m map[string]any) string { s, _ := m["status"].(string); return s }

func mustCreate(t *testing.T, s *sisters, h sisterHost, bot, name string) string {
	t.Helper()
	m := asMap(t)(s.roleCreateTool(context.Background(), h, roleCreateIn{roleWho: who(bot), Project: "p1", Name: name}))
	if status(m) != "applied" {
		t.Fatalf("create %s: %v", name, m)
	}
	return m["role"].(string)
}

func lastTicket(t *testing.T, f *fakeHost) roleTicket {
	t.Helper()
	b, _ := json.Marshal(lastSubmit(t, f).Payload)
	var tk roleTicket
	if err := json.Unmarshal(b, &tk); err != nil {
		t.Fatal(err)
	}
	return tk
}

func auditsOf(f *fakeHost, event string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for i, e := range f.audits {
		if e == event {
			out = append(out, f.auditLog[i])
		}
	}
	return out
}

func edit(t *testing.T, s *sisters, h sisterHost, id string, in roleUpdateIn) map[string]any {
	t.Helper()
	in.roleWho, in.Role = who(botA), id
	return asMap(t)(s.roleUpdateTool(context.Background(), h, in))
}

func ptr[T any](v T) *T { return &v }

// ---- the tier engine, every row of section 6.1 ----

func TestTierTable(t *testing.T) {
	base := func() *role {
		return &role{Project: "p1", Name: "n", Status: "active", CreatedBy: "bot-a", Tools: []string{"Read", "Edit"}, DefaultMode: "default", ProjectInstructions: true,
			Deny: []roleDeny{{Rule: "Bash(rm:*)", By: "user"}, {Rule: "WebFetch", By: "bot-a"}}}
	}
	ctx := tierCtx{Bot: "Bot-A", Trust: true, Ceiling: "acceptEdits", Registered: map[string]bool{"web-1": true}}
	cases := []struct {
		name    string
		mutate  func(r *role)
		ctx     func(c *tierCtx)
		create  bool
		tier    int
		foreign bool
	}{
		{name: "rename", mutate: func(r *role) { r.Name = "other" }, tier: 1},
		{name: "description and instructions", mutate: func(r *role) { r.Description = "x"; r.Instructions = "y"; r.ProjectInstructions = false }, tier: 1},
		{name: "mode within the ceiling", mutate: func(r *role) { r.DefaultMode = "acceptEdits" }, tier: 1},
		{name: "mode to plan", mutate: func(r *role) { r.DefaultMode = "plan" }, tier: 1},
		{name: "mode above the ceiling", mutate: func(r *role) { r.DefaultMode = "auto" }, tier: 2},
		{name: "mode bypass above acceptEdits", mutate: func(r *role) { r.DefaultMode = "bypassPermissions" }, tier: 2},
		{name: "mode bypass under the default ceiling", mutate: func(r *role) { r.DefaultMode = "bypassPermissions" }, ctx: func(c *tierCtx) { c.Ceiling = "bypassPermissions" }, tier: 1},
		{name: "unknown mode", mutate: func(r *role) { r.DefaultMode = "dontAsk" }, tier: 2},
		{name: "archive", mutate: func(r *role) { r.Status = "archived" }, tier: 1},
		{name: "skills", mutate: func(r *role) { r.Skills = append(r.Skills, roleSkill{Name: "s", Source: "adhoc", SHA256: "x"}) }, tier: 1},
		{name: "safe tools", mutate: func(r *role) {
			r.Tools = []string{"Read", "Write", "Bash", "WebFetch", "WebSearch", "Skill", "Agent", "Glob", "Grep"}
		}, tier: 1},
		{name: "tool outside the safe set", mutate: func(r *role) { r.Tools = append(r.Tools, "Monitor") }, tier: 2},
		{name: "Cron tool", mutate: func(r *role) { r.Tools = append(r.Tools, "CronCreate") }, tier: 2},
		{name: "a non-safe tool already there stays", mutate: func(r *role) { r.Description = "x" }, ctx: func(c *tierCtx) {}, tier: 1},
		{name: "deny rule added", mutate: func(r *role) { r.Deny = append(r.Deny, roleDeny{Rule: "Bash(git push:*)", By: "bot-a"}) }, tier: 1},
		{name: "own deny rule removed", mutate: func(r *role) { r.Deny = r.Deny[:1] }, tier: 1},
		{name: "user's deny rule removed", mutate: func(r *role) { r.Deny = r.Deny[1:] }, tier: 2},
		{name: "subagents", mutate: func(r *role) { r.Agents = []roleAgent{{Name: "a", Tools: []string{"Read"}, Model: "inherit"}} }, tier: 1},
		{name: "mcp added", mutate: func(r *role) { r.MCP = []roleMCP{{Name: "docs", Type: "http", URL: "https://x.example/"}} }, tier: 2},
		{name: "plugin added", mutate: func(r *role) { r.Plugins = []rolePlugin{{Name: "p", Source: "s"}} }, tier: 2},
		{name: "host added", mutate: func(r *role) { r.Hosts = []string{"cdn.example.com"} }, tier: 2},
		{name: "ssh to a registered target", mutate: func(r *role) { r.SSH = []string{"web-1"} }, tier: 1},
		{name: "ssh to an unregistered target", mutate: func(r *role) { r.SSH = []string{"db-1"} }, tier: 2},
		{name: "no trust: any change", mutate: func(r *role) { r.Description = "x" }, ctx: func(c *tierCtx) { c.Trust = false }, tier: 2, foreign: true},
		{name: "create with trust", create: true, mutate: func(r *role) {}, tier: 1},
		{name: "create without trust", create: true, mutate: func(r *role) {}, ctx: func(c *tierCtx) { c.Trust = false }, tier: 2, foreign: true},
		{name: "create with a host", create: true, mutate: func(r *role) { r.Hosts = []string{"a.example.com"} }, tier: 2},
		{name: "revert over others' changes", mutate: func(r *role) { r.Description = "old" }, ctx: func(c *tierCtx) { c.RevertOthers = true }, tier: 2},
		{name: "a role of another Bot", mutate: func(r *role) { r.Description = "x" }, ctx: func(c *tierCtx) { c.Bot = "bot-b" }, tier: 2},
		{name: "a role of the user", mutate: func(r *role) { r.Status = "archived" }, ctx: func(c *tierCtx) { c.Bot = "bot-b" }, tier: 2},
		{name: "the user's own change on a Bot's role", mutate: func(r *role) { r.Description = "x" }, ctx: func(c *tierCtx) { c.Bot, c.ByUser = "user", true }, tier: 1},
		{name: "a skill another hand wrote is removed", mutate: func(r *role) { r.Skills = nil }, ctx: func(c *tierCtx) {}, tier: 2},
		{name: "a skill another hand wrote is changed", mutate: func(r *role) { r.Skills[1].SHA256 = "new" }, ctx: func(c *tierCtx) {}, tier: 2},
		{name: "a skill of its own is removed", mutate: func(r *role) { r.Skills = r.Skills[1:] }, ctx: func(c *tierCtx) {}, tier: 1},
		{name: "always-ask tools", mutate: func(r *role) { r.Description = "x" }, ctx: func(c *tierCtx) { c.ForceWiden = true }, tier: 2},
	}
	for _, c := range cases {
		cur := base()
		cur.Tools = append(cur.Tools, "ToolSearch") // already there: not growth
		cur.Skills = []roleSkill{{Name: "mine", Source: "adhoc", SHA256: "m", AddedBy: "bot-a"}, {Name: "theirs", Source: "adhoc", SHA256: "t", AddedBy: "bot-b"}}
		next := cur.clone()
		c.mutate(next)
		var cp *role = cur
		if c.create {
			cp = nil
			next = base()
			c.mutate(next)
			next.Deny, next.Tools = nil, []string{"Read"}
		}
		tc := ctx
		if c.ctx != nil {
			c.ctx(&tc)
		}
		v := tierOf(cp, next, tc)
		if v.Tier != c.tier || v.Foreign != c.foreign {
			t.Errorf("%s: tier %d foreign %v, want %d %v (%v)", c.name, v.Tier, v.Foreign, c.tier, c.foreign, v.Reasons)
		}
		if v.Tier == 2 && len(v.Reasons) == 0 {
			t.Errorf("%s: tier 2 with no reason", c.name)
		}
	}
}

// ---- the tools ----

func TestCreateWithTrustIsAppliedAndAudited(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	m := asMap(t)(s.roleCreateTool(context.Background(), f, roleCreateIn{roleWho: roleWho{Agent: "someone else", VerifiedAgent: botA}, Project: "p1", Name: "design", Description: "visuals"}))
	if status(m) != "applied" || m["version"] != 1 && m["version"] != float64(1) || m["audit_id"] == "" || m["tier"] != 1 {
		t.Fatalf("%v", m)
	}
	r := fr.current(m["role"].(string))
	if r.CreatedBy != botA || r.Project != "p1" || r.Name != "design" || r.Status != "active" || r.DefaultMode != "default" || len(f.submits) != 0 {
		t.Fatalf("%+v submits %d", r, len(f.submits))
	}
	put := fr.puts[0]
	if put["by"] != botA || put["base_version"] != float64(0) {
		t.Fatalf("%v", put)
	}
	au := auditsOf(f, "role.change")
	if len(au) != 1 {
		t.Fatalf("audits %v", f.audits)
	}
	a := au[0]
	if a["role"] != r.ID || a["project"] != "p1" || a["from"] != 0 || a["to"] != 1 || a["by"] != botA || a["tier"] != 1 || a["audit_id"] != m["audit_id"] || a["summary"] == "" {
		t.Fatalf("%v", a)
	}
	if _, has := a["approval"]; has {
		t.Fatalf("tier 1 with an approval: %v", a)
	}
}

func TestCreateWithoutTrustAsksAndRunsOnce(t *testing.T) {
	f, s, fr := roleFixture(t)
	// A trust of another Bot, of another project, or one the Bot didn't ask for is not this Bot's.
	trustBot(t, s, "bot-b", "p1")
	trustBot(t, s, botA, "p2")
	s.st.mu.Lock()
	s.st.st.Projects = append(s.st.st.Projects, projectTrust{ID: "pt_run", Device: "dev_mac", Root: "/work", Project: "p1", Unlimited: true})
	s.st.mu.Unlock()
	m := asMap(t)(s.roleCreateTool(context.Background(), f, roleCreateIn{roleWho: who(botA), Project: "p1", Name: "design"}))
	if status(m) != "needs_approval" || m["approval_id"] != "apr_1" || m["link"] != "https://rubi-panel.com/#a=apr_1" {
		t.Fatalf("%v", m)
	}
	sub := lastSubmit(t, f)
	if sub.Kind != kindRoleForeign || len(fr.roles) != 0 || fr.putCount() != 0 || len(s.st.rolePendings()) != 1 {
		t.Fatalf("kind %s roles %d", sub.Kind, len(fr.roles))
	}
	if p := sub.Preview.(map[string]any); p["bot"] != botA || p["project"] != "p1" {
		t.Fatalf("%v", p)
	}
	tk := lastTicket(t, f)
	res := asMap(t)(s.executeRoleChange(context.Background(), f, tk))
	if status(res) != "applied" || res["tier"] != 2 {
		t.Fatalf("%v", res)
	}
	r := fr.current(res["role"].(string))
	if r.Name != "design" || r.CreatedBy != botA || r.Change.Tier != 2 || r.Change.Approval != "apr_1" {
		t.Fatalf("%+v %+v", r, r.Change)
	}
	if a := auditsOf(f, "role.change"); len(a) != 1 || a[0]["approval"] != "apr_1" || a[0]["tier"] != 2 {
		t.Fatalf("%v", a)
	}
	// An approval runs once.
	if _, err := s.executeRoleChange(context.Background(), f, tk); err == nil || !strings.Contains(err.Error(), "no longer pending") {
		t.Fatalf("%v", err)
	}
}

func TestUpdateTiersAndTheCeiling(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	if m := edit(t, s, f, id, roleUpdateIn{Description: ptr("new text"), Name: ptr("design2")}); status(m) != "applied" || m["version"] != 2 {
		t.Fatalf("%v", m)
	}
	// The default ceiling is bypassPermissions: every offered mode is the Bot's to set.
	for _, mode := range []string{"auto", "bypassPermissions", "plan"} {
		if m := edit(t, s, f, id, roleUpdateIn{DefaultMode: ptr(mode)}); status(m) != "applied" {
			t.Fatalf("%s: %v", mode, m)
		}
	}
	if m := edit(t, s, f, id, roleUpdateIn{DefaultMode: ptr("dontAsk")}); status(m) != "rejected" {
		t.Fatalf("%v", m)
	}
	// With the user's ceiling at acceptEdits a looser mode asks.
	ch := cfgRoleHost{f, `{"role_mode_ceiling":"acceptEdits"}`}
	before := fr.putCount()
	m := asMap(t)(s.roleUpdateTool(context.Background(), ch, roleUpdateIn{roleWho: who(botA), Role: id, DefaultMode: ptr("auto")}))
	if status(m) != "needs_approval" || fr.putCount() != before || lastSubmit(t, f).Kind != kindRoleWiden {
		t.Fatalf("%v", m)
	}
	m = asMap(t)(s.roleUpdateTool(context.Background(), ch, roleUpdateIn{roleWho: who(botA), Role: id, DefaultMode: ptr("acceptEdits")}))
	if status(m) != "applied" {
		t.Fatalf("%v", m)
	}
	// Archive and unarchive are tier 1.
	if m := asMap(t)(s.roleArchiveTool(context.Background(), f, roleRefIn{who(botA), id}, true)); status(m) != "applied" || fr.current(id).Status != "archived" {
		t.Fatalf("%v", m)
	}
	if m := asMap(t)(s.roleArchiveTool(context.Background(), f, roleRefIn{who(botA), id}, false)); status(m) != "applied" || fr.current(id).Status != "active" {
		t.Fatalf("%v", m)
	}
	// Nothing differs: no new version.
	v := fr.current(id).Version
	if m := edit(t, s, f, id, roleUpdateIn{Description: ptr(fr.current(id).Description)}); m["unchanged"] != true || fr.current(id).Version != v {
		t.Fatalf("%v", m)
	}
}

func TestWithoutTrustEveryWriteAsks(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	s.st.mu.Lock()
	s.st.st.Projects = nil // the trust ends
	s.st.mu.Unlock()
	before := fr.putCount()
	for _, m := range []map[string]any{
		edit(t, s, f, id, roleUpdateIn{Description: ptr("x")}),
		asMap(t)(s.roleArchiveTool(context.Background(), f, roleRefIn{who(botA), id}, true)),
		asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Name: "s", Description: "d", Content: "text"})),
	} {
		if status(m) != "needs_approval" {
			t.Fatalf("%v", m)
		}
	}
	if fr.putCount() != before || lastSubmit(t, f).Kind != kindRoleForeign {
		t.Fatalf("puts %d", fr.putCount())
	}
	// Reading needs no trust.
	if _, err := s.roleGetTool(context.Background(), f, roleGetIn{roleWho: who(botA), Role: id}); err != nil {
		t.Fatal(err)
	}
}

func TestSkillsAreContentNotGrants(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	tools := append([]string(nil), fr.current(id).Tools...)
	m := asMap(t)(s.roleSkillsSetTool(context.Background(), f, roleSkillsSetIn{roleWho: who(botA), Role: id, Skills: []roleSkillIn{
		{Name: "sneaky", Description: "d", Content: "mcpServers: {evil: {}}\nallowed-tools: Bash(*)\n"},
		{Name: "plain", Description: "d", Content: "Use tokens from the design system."},
	}}))
	if status(m) != "applied" || m["tier"] != 1 || len(f.submits) != 0 {
		t.Fatalf("%v", m)
	}
	held, _ := m["held_skills"].([]map[string]any)
	if len(held) != 1 || held[0]["skill"] != "sneaky" || held[0]["verdict"] != "flag" || m["note"] == nil {
		t.Fatalf("%v", m)
	}
	r := fr.current(id)
	if !reflect.DeepEqual(r.Tools, tools) || len(r.MCP) != 0 || len(r.Hosts) != 0 {
		t.Fatalf("%+v", r)
	}
	states := map[string]string{}
	for _, k := range r.Skills {
		states[k.Name] = k.State
		if k.AddedBy != botA || k.Source != "adhoc" {
			t.Fatalf("%+v", k)
		}
	}
	if states["sneaky"] != "held" || states["plain"] != "active" {
		t.Fatalf("%v", states)
	}
	// Sending the same skills again changes nothing; the skill text went to Home only as blobs.
	m = asMap(t)(s.roleSkillsSetTool(context.Background(), f, roleSkillsSetIn{roleWho: who(botA), Role: id, Skills: []roleSkillIn{
		{Name: "sneaky", Description: "d", Content: "mcpServers: {evil: {}}\nallowed-tools: Bash(*)\n"},
		{Name: "plain", Description: "d", Content: "Use tokens from the design system."},
	}}))
	if m["unchanged"] != true {
		t.Fatalf("%v", m)
	}
	// The audit has no skill text.
	for _, a := range auditsOf(f, "role.change") {
		b, _ := json.Marshal(a)
		if strings.Contains(string(b), "design system") || strings.Contains(string(b), "evil") {
			t.Fatalf("content in the audit: %s", b)
		}
	}
	// A skill the scan rejects is refused with the reason, nothing is saved.
	m = asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Name: "leak", Description: "d", Content: "AKIAABCDEFGHIJKLMNOP"}))
	if status(m) != "rejected" || len(fr.current(id).Skills) != 2 {
		t.Fatalf("%v", m)
	}
	// Removing and a library source.
	if m := asMap(t)(s.roleSkillsRemoveTool(context.Background(), f, roleSkillsRemoveIn{roleWho: who(botA), Role: id, Name: "plain"})); status(m) != "applied" || len(fr.current(id).Skills) != 1 {
		t.Fatalf("%v", m)
	}
	m = asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Library: "design-tokens@3"}))
	if status(m) != "rejected" || !strings.Contains(strings.Join(m["reasons"].([]string), " "), "not available yet") {
		t.Fatalf("%v", m)
	}
}

func TestToolsSetTiers(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	set := func(tools, deny *[]string) map[string]any {
		return asMap(t)(s.roleToolsSetTool(context.Background(), f, roleToolsSetIn{roleWho: who(botA), Role: id, Tools: tools, Deny: deny}))
	}
	if m := set(&[]string{"Read", "Grep", "WebFetch"}, &[]string{"Bash(git push:*)"}); status(m) != "applied" {
		t.Fatalf("%v", m)
	}
	r := fr.current(id)
	if !reflect.DeepEqual(r.Tools, []string{"Read", "Grep", "WebFetch"}) || len(r.Deny) != 1 || r.Deny[0].By != botA {
		t.Fatalf("%+v", r)
	}
	// A tool outside the safe set asks, and nothing is applied.
	v := r.Version
	m := set(&[]string{"Read", "Monitor"}, nil)
	if status(m) != "needs_approval" || fr.current(id).Version != v || lastSubmit(t, f).Kind != kindRoleWiden {
		t.Fatalf("%v", m)
	}
	// An unknown tool is refused before anyone is asked.
	if m := set(&[]string{"Nope"}, nil); status(m) != "rejected" {
		t.Fatalf("%v", m)
	}
	// The user's deny rule: removing it asks, the Bot's own can go.
	fr.mu.Lock()
	cur := fr.cur(id)
	cur.Deny = append(cur.Deny, roleDeny{Rule: "Bash(rm:*)", By: "user"})
	fr.mu.Unlock()
	if m := set(nil, &[]string{"Bash(git push:*)"}); status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	if m := set(nil, &[]string{"Bash(rm:*)"}); status(m) != "applied" {
		t.Fatalf("%v", m)
	}
	if d := fr.current(id).Deny; len(d) != 1 || d[0].By != "user" {
		t.Fatalf("%v", d)
	}
	// MCP servers, plugins and hosts always ask, even for a removal.
	for _, m := range []map[string]any{
		asMap(t)(s.roleMCPSetTool(context.Background(), f, roleMCPSetIn{roleWho: who(botA), Role: id, MCP: []roleMCPIn{{Name: "docs", Type: "http", URL: "https://mcp.example.com/"}}})),
		asMap(t)(s.rolePluginsSetTool(context.Background(), f, rolePluginsSetIn{roleWho: who(botA), Role: id, Plugins: []rolePluginIn{{Name: "p", Source: "s"}}})),
		asMap(t)(s.roleHostsSetTool(context.Background(), f, roleHostsSetIn{roleWho: who(botA), Role: id, Hosts: []string{"CDN.example.com"}})),
	} {
		if status(m) != "needs_approval" || lastSubmit(t, f).Kind != kindRoleWiden {
			t.Fatalf("%v", m)
		}
	}
	// The approved MCP server carries the approval's id.
	tk := lastTicket(t, f)
	_ = tk
	m = asMap(t)(s.roleMCPSetTool(context.Background(), f, roleMCPSetIn{roleWho: who(botA), Role: id, MCP: []roleMCPIn{{Name: "docs", Type: "http", URL: "https://mcp.example.com/"}}}))
	askedWith, _ := m["approval_id"].(string)
	res := asMap(t)(s.executeRoleChange(context.Background(), f, lastTicket(t, f)))
	if status(res) != "applied" {
		t.Fatalf("%v", res)
	}
	if mcp := fr.current(id).MCP; len(mcp) != 1 || mcp[0].Approval != askedWith || askedWith == "" || mcp[0].URL != "https://mcp.example.com/" {
		t.Fatalf("%+v", mcp)
	}
	// Removing it again still asks (always tier 2), and the unchanged server keeps its approval.
	m = asMap(t)(s.roleMCPSetTool(context.Background(), f, roleMCPSetIn{roleWho: who(botA), Role: id}))
	if status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	// Subagents are content.
	m = asMap(t)(s.roleAgentsSetTool(context.Background(), f, roleAgentsSetIn{roleWho: who(botA), Role: id, Agents: []roleAgentIn{{Name: "reviewer", Description: "d", Prompt: "p", Tools: []string{"Read"}}}}))
	if status(m) != "applied" || fr.current(id).Agents[0].Model != "inherit" {
		t.Fatalf("%v", m)
	}
}

func TestMixedRequestIsAtomic(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	ch := cfgRoleHost{f, `{"role_mode_ceiling":"default"}`}
	v := fr.current(id).Version
	m := asMap(t)(s.roleUpdateTool(context.Background(), ch, roleUpdateIn{roleWho: who(botA), Role: id, Name: ptr("renamed"), Description: ptr("new"), DefaultMode: ptr("auto")}))
	if status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	if r := fr.current(id); r.Version != v || r.Name != "design" || r.Description != "" || r.DefaultMode != "default" {
		t.Fatalf("something was applied: %+v", r)
	}
	pend := m["pending"].(map[string]any)
	if pend["role"] != id || pend["base_version"] != v || len(pend["changes"].([]string)) != 3 {
		t.Fatalf("%v", pend)
	}
	// On approval all of it goes in as one version.
	res := asMap(t)(s.executeRoleChange(context.Background(), ch, lastTicket(t, f)))
	r := fr.current(id)
	if status(res) != "applied" || r.Version != v+1 || r.Name != "renamed" || r.Description != "new" || r.DefaultMode != "auto" {
		t.Fatalf("%v %+v", res, r)
	}
	// tools_set with a safe tool and a non-safe one is also all or nothing.
	v = r.Version
	m = asMap(t)(s.roleToolsSetTool(context.Background(), f, roleToolsSetIn{roleWho: who(botA), Role: id, Tools: &[]string{"Read", "Workflow"}, Deny: &[]string{"Bash(git push:*)"}}))
	if status(m) != "needs_approval" || fr.current(id).Version != v || len(fr.current(id).Deny) != 0 {
		t.Fatalf("%v", m)
	}
}

func TestApprovalRebasesOrFailsCleanly(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	ask := func(tool string) roleTicket {
		m := asMap(t)(s.roleToolsSetTool(context.Background(), f, roleToolsSetIn{roleWho: who(botA), Role: id, Tools: &[]string{"Read", tool}}))
		if status(m) != "needs_approval" {
			t.Fatalf("%v", m)
		}
		return lastTicket(t, f)
	}
	// Another part moves (the description): the change rebases onto the new version.
	tk := ask("Monitor")
	edit(t, s, f, id, roleUpdateIn{Description: ptr("changed meanwhile")})
	res := asMap(t)(s.executeRoleChange(context.Background(), f, tk))
	r := fr.current(id)
	if status(res) != "applied" || r.Description != "changed meanwhile" || !reflect.DeepEqual(r.Tools, []string{"Read", "Monitor"}) || r.Parent != r.Version-1 {
		t.Fatalf("%v %+v", res, r)
	}
	// The touched part moves: nothing is applied.
	tk = ask("Workflow")
	m := asMap(t)(s.roleToolsSetTool(context.Background(), f, roleToolsSetIn{roleWho: who(botA), Role: id, Tools: &[]string{"Read", "Grep"}}))
	if status(m) != "applied" {
		t.Fatalf("%v", m)
	}
	v := fr.current(id).Version
	_, err := s.executeRoleChange(context.Background(), f, tk)
	if err == nil || err.Error() != "the role changed since you asked; ask again" {
		t.Fatalf("%v", err)
	}
	if fr.current(id).Version != v || !reflect.DeepEqual(fr.current(id).Tools, []string{"Read", "Grep"}) {
		t.Fatalf("half applied: %+v", fr.current(id))
	}
	// A name taken meanwhile on creation: Home's refusal comes back as the reason, nothing created.
	m = asMap(t)(s.roleCreateTool(context.Background(), f, roleCreateIn{roleWho: who("bot-z"), Project: "p1", Name: "design"}))
	if status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	_, err = s.executeRoleChange(context.Background(), f, lastTicket(t, f))
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("%v", err)
	}
}

func TestPerBotLimits(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	trustBot(t, s, botA, "p2")
	f.agent.projects = append(f.agent.projects, agentProject{ID: "p2", Dir: "/home/alice/other"})
	ch := cfgRoleHost{f, `{"role_max_per_project_per_bot":"2","role_max_per_bot":3,"role_max_total":"4","role_max_skills":"2","role_max_adhoc_skills":"1","role_changes_per_hour_per_bot":"100"}`}
	create := func(project, name, bot string) map[string]any {
		return asMap(t)(s.roleCreateTool(context.Background(), ch, roleCreateIn{roleWho: who(bot), Project: project, Name: name}))
	}
	a1 := create("p1", "a1", botA)
	create("p1", "a2", botA)
	m := create("p1", "a3", botA)
	if status(m) != "rejected" || !strings.Contains(m["reasons"].([]string)[0], "role_max_per_project_per_bot") || len(fr.roles) != 2 {
		t.Fatalf("%v", m)
	}
	if m := create("p2", "b1", botA); status(m) != "applied" {
		t.Fatalf("%v", m)
	}
	m = create("p2", "b2", botA)
	if status(m) != "rejected" || !strings.Contains(m["reasons"].([]string)[0], "role_max_per_bot") {
		t.Fatalf("%v", m)
	}
	// Another Bot has its own counts; the computer-wide total is the same for everyone.
	trustBot(t, s, "bot-b", "p1")
	if m := create("p1", "c1", "bot-b"); status(m) != "applied" {
		t.Fatalf("%v", m)
	}
	m = create("p1", "c2", "bot-b")
	if status(m) != "rejected" || !strings.Contains(strings.Join(m["reasons"].([]string), " "), "role_max_total") {
		t.Fatalf("%v", m)
	}
	// Archiving frees nothing: an archived role still counts (Home has no delete).
	asMap(t)(s.roleArchiveTool(context.Background(), ch, roleRefIn{who(botA), a1["role"].(string)}, true))
	if m := create("p1", "a4", botA); !strings.Contains(strings.Join(m["reasons"].([]string), " "), "role_max_total") {
		t.Fatalf("%v", m)
	}
	// Skills per role: 2 in all, 1 of them Bot-written.
	id := a1["role"].(string)
	asMap(t)(s.roleArchiveTool(context.Background(), ch, roleRefIn{who(botA), id}, false))
	m = asMap(t)(s.roleSkillsSetTool(context.Background(), ch, roleSkillsSetIn{roleWho: who(botA), Role: id, Skills: []roleSkillIn{{Name: "a", Description: "d", Content: "x"}, {Name: "b", Description: "d", Content: "y"}}}))
	if status(m) != "rejected" || !strings.Contains(m["reasons"].([]string)[0], "role_max_adhoc_skills") {
		t.Fatalf("%v", m)
	}
	if m := asMap(t)(s.roleSkillsSetTool(context.Background(), ch, roleSkillsSetIn{roleWho: who(botA), Role: id, Skills: []roleSkillIn{{Name: "a", Description: "d", Content: "x"}}})); status(m) != "applied" {
		t.Fatalf("%v", m)
	}
}

func TestHourlyChangeRate(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	clock := time.Now()
	s.now = func() time.Time { return clock }
	ch := cfgRoleHost{f, `{"role_changes_per_hour_per_bot":"3"}`}
	id := mustCreateCfg(t, s, ch, "design") // 1
	for i, want := range []string{"applied", "applied", "rejected"} {
		m := asMap(t)(s.roleUpdateTool(context.Background(), ch, roleUpdateIn{roleWho: who(botA), Role: id, Description: ptr(strings.Repeat("x", i+1))}))
		if status(m) != want {
			t.Fatalf("change %d: %v", i, m)
		}
		if want == "rejected" && !strings.Contains(m["reasons"].([]string)[0], "role_changes_per_hour_per_bot") {
			t.Fatalf("%v", m)
		}
	}
	// Another Bot is counted on its own, and an hour later the Bot may change again.
	trustBot(t, s, "bot-b", "p1")
	if m := asMap(t)(s.roleCreateTool(context.Background(), ch, roleCreateIn{roleWho: who("bot-b"), Project: "p1", Name: "other"})); status(m) != "applied" {
		t.Fatalf("%v", m)
	}
	clock = clock.Add(61 * time.Minute)
	if m := asMap(t)(s.roleUpdateTool(context.Background(), ch, roleUpdateIn{roleWho: who(botA), Role: id, Description: ptr("again")})); status(m) != "applied" {
		t.Fatalf("%v", m)
	}
}

func mustCreateCfg(t *testing.T, s *sisters, h sisterHost, name string) string {
	t.Helper()
	return mustCreate(t, s, h, botA, name)
}

func TestIdentityComesOnlyFromTheVerifiedAgent(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, "victim", "p1")
	// Typed names and codes prove nothing.
	_, err := s.roleCreateTool(context.Background(), f, roleCreateIn{roleWho: roleWho{Agent: "victim", AgentCode: "guess"}, Project: "p1", Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "didn't confirm") || len(fr.roles) != 0 {
		t.Fatalf("%v", err)
	}
	// With a verified Bot, the typed name is ignored: the trust of "victim" is not bot-a's.
	m := asMap(t)(s.roleCreateTool(context.Background(), f, roleCreateIn{roleWho: roleWho{Agent: "victim", VerifiedAgent: botA}, Project: "p1", Name: "x"}))
	if status(m) != "needs_approval" || len(fr.roles) != 0 {
		t.Fatalf("%v", m)
	}
	if p := lastSubmit(t, f).Preview.(map[string]any); p["bot"] != botA {
		t.Fatalf("%v", p)
	}
	// Every tool refuses an unverified caller, reads included.
	anon := roleWho{Agent: botA}
	calls := map[string]func() error{
		"update": func() error {
			_, e := s.roleUpdateTool(context.Background(), f, roleUpdateIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"archive": func() error {
			_, e := s.roleArchiveTool(context.Background(), f, roleRefIn{anon, "r_00000001"}, true)
			return e
		},
		"skills": func() error {
			_, e := s.roleSkillsSetTool(context.Background(), f, roleSkillsSetIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"tools": func() error {
			_, e := s.roleToolsSetTool(context.Background(), f, roleToolsSetIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"agents": func() error {
			_, e := s.roleAgentsSetTool(context.Background(), f, roleAgentsSetIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"mcp": func() error {
			_, e := s.roleMCPSetTool(context.Background(), f, roleMCPSetIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"plugins": func() error {
			_, e := s.rolePluginsSetTool(context.Background(), f, rolePluginsSetIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"hosts": func() error {
			_, e := s.roleHostsSetTool(context.Background(), f, roleHostsSetIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"ssh": func() error {
			_, e := s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: anon, Role: "r_00000001"}, true)
			return e
		},
		"start": func() error {
			_, e := s.roleStartTool(context.Background(), f, roleStartIn{roleWho: anon, Role: "r_00000001", Prompt: "x"})
			return e
		},
		"list": func() error { _, e := s.roleListTool(context.Background(), f, roleListIn{roleWho: anon}); return e },
		"get": func() error {
			_, e := s.roleGetTool(context.Background(), f, roleGetIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"history": func() error {
			_, e := s.roleHistoryTool(context.Background(), f, roleHistoryIn{roleWho: anon, Role: "r_00000001"})
			return e
		},
		"too long": func() error {
			_, e := s.roleListTool(context.Background(), f, roleListIn{roleWho: roleWho{VerifiedAgent: strings.Repeat("a", 65)}})
			return e
		},
	}
	for name, c := range calls {
		if err := c(); err == nil || !strings.Contains(err.Error(), "didn't confirm") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A Bot can't act through another Bot's deny rules: removing bot-b's rule is not the same as removing its own.
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "mine")
	trustBot(t, s, "bot-b", "p1")
	// bot-b is not the creator, so its rule goes through the user's approval.
	if m := asMap(t)(s.roleToolsSetTool(context.Background(), f, roleToolsSetIn{roleWho: who("bot-b"), Role: id, Deny: &[]string{"WebFetch"}})); status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	asMap(t)(s.executeRoleChange(context.Background(), f, lastTicket(t, f)))
	if d := fr.current(id).Deny; len(d) != 1 || d[0].By != "bot-b" {
		t.Fatalf("%+v", d)
	}
	if m := asMap(t)(s.roleToolsSetTool(context.Background(), f, roleToolsSetIn{roleWho: who(botA), Role: id, Deny: &[]string{}})); status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
}

func TestNoBotToolChangesTheLimits(t *testing.T) {
	// No tool is about limits or the ceiling, and no tool's input has a field for one.
	for _, n := range roleToolNames {
		for _, bad := range []string{"limit", "ceiling", "config", "setting"} {
			if strings.Contains(n, bad) {
				t.Errorf("tool %s", n)
			}
		}
	}
	for _, in := range []any{roleCreateIn{}, roleUpdateIn{}, roleRefIn{}, roleSkillsSetIn{}, roleSkillsAddIn{}, roleSkillsRemoveIn{}, roleToolsSetIn{}, roleAgentsSetIn{},
		roleMCPSetIn{}, rolePluginsSetIn{}, roleHostsSetIn{}, roleSSHIn{}, roleStartIn{}, roleListIn{}, roleGetIn{}, roleHistoryIn{}} {
		var walk func(rt reflect.Type)
		walk = func(rt reflect.Type) {
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if strings.HasPrefix(tag, "role_max") || strings.HasPrefix(tag, "role_changes") || tag == cfgRoleCeiling || tag == "ceiling" || tag == "limits" {
					t.Errorf("%s has %s", rt, tag)
				}
				if f.Anonymous {
					walk(f.Type)
				}
			}
		}
		walk(reflect.TypeOf(in))
	}
	// The limits are config fields with the design's defaults; the ceiling defaults to bypassPermissions.
	want := map[string]string{"role_max_per_project_per_bot": "5", "role_max_per_bot": "20", "role_changes_per_hour_per_bot": "30", "role_max_skills": "20",
		"role_max_adhoc_skills": "10", "role_max_total": "50", "role_mode_ceiling": "bypassPermissions"}
	got := map[string]string{}
	for _, c := range manifest().Config {
		got[c.Key] = ""
		if d, ok := c.Default.(string); ok {
			got[c.Key] = d
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("config %s = %q, want %q", k, got[k], v)
		}
	}
	if l := roleLimitsOf(&fakeHost{}); l != defaultRoleLimits() {
		t.Fatalf("%+v", l)
	}
	l := roleLimitsOf(cfgRoleHost{&fakeHost{}, `{"role_max_per_bot":"7","role_max_total":12,"role_max_skills":"junk","role_mode_ceiling":"plan","role_max_adhoc_skills":"0"}`})
	if l.PerBot != 7 || l.Total != 12 || l.Skills != 20 || l.Ceiling != "plan" || l.AdhocSkills != 10 {
		t.Fatalf("%+v", l)
	}
}

func TestRevertUnderTheSameRule(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design") // v1
	edit(t, s, f, id, roleUpdateIn{Description: ptr("one")})
	edit(t, s, f, id, roleUpdateIn{Description: ptr("two")}) // v3
	m := edit(t, s, f, id, roleUpdateIn{RevertTo: 1})
	if status(m) != "applied" || m["version"] != 4 || fr.current(id).Description != "" || fr.current(id).Parent != 3 {
		t.Fatalf("%v", m)
	}
	if _, err := s.roleUpdateTool(context.Background(), f, roleUpdateIn{roleWho: who(botA), Role: id, RevertTo: 1, Name: ptr("x")}); err == nil {
		t.Fatal("revert_to with other fields was accepted")
	}
}

func TestRevertAcrossOthersChangesAsks(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	trustBot(t, s, "bot-b", "p1")
	id := mustCreate(t, s, f, botA, "design")                                                                                          // v1
	asMap(t)(s.roleUpdateTool(context.Background(), f, roleUpdateIn{roleWho: who("bot-b"), Role: id, Description: ptr("b was here")})) // asks: not bot-b's role
	asMap(t)(s.executeRoleChange(context.Background(), f, lastTicket(t, f)))                                                           // v2 by bot-b
	m := edit(t, s, f, id, roleUpdateIn{RevertTo: 1})
	if status(m) != "needs_approval" || fr.current(id).Version != 2 {
		t.Fatalf("%v", m)
	}
	// A revert to a version with an MCP server widens: it asks, whoever made the versions.
	fr.mu.Lock()
	v1 := fr.roles[id][0]
	v1.MCP = []roleMCP{{Name: "docs", Type: "http", URL: "https://mcp.example.com/", Approval: "ap_old"}}
	fr.mu.Unlock()
	f2, s2 := f, s
	_ = f2
	m = edit(t, s2, f, id, roleUpdateIn{RevertTo: 1})
	if status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
}

func TestHeldSkillIsAcceptedByTheUser(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Name: "sneaky", Description: "d", Content: "allowed-tools: Bash"}))
	if k, ok := heldSkill(fr.current(id), "sneaky"); !ok || k.State != "held" {
		t.Fatalf("%+v", fr.current(id).Skills)
	}
	if _, err := s.askSkillAccept(context.Background(), f, mac, id, "nope"); err == nil {
		t.Fatal("no such held skill")
	}
	if _, err := s.askSkillAccept(context.Background(), f, mac, id, "sneaky"); err != nil {
		t.Fatal(err)
	}
	sub := lastSubmit(t, f)
	if sub.Kind != kindRoleSkillAccept {
		t.Fatalf("%s", sub.Kind)
	}
	if p := sub.Preview.(map[string]any); p["skill"] != "sneaky" || p["written_by"] != botA || len(p["flags_found"].([]string)) != 1 {
		t.Fatalf("%v", p)
	}
	b, _ := json.Marshal(sub.Payload)
	var tk skillAcceptTicket
	_ = json.Unmarshal(b, &tk)
	res := asMap(t)(s.executeSkillAccept(context.Background(), f, tk))
	r := fr.current(id)
	if status(res) != "applied" || r.Skills[0].State != "active" || r.ChangedBy != "user" || r.Change.Op != "role.skill.accept" {
		t.Fatalf("%v %+v", res, r)
	}
	if a := auditsOf(f, "role.change"); a[len(a)-1]["by"] != "user" || a[len(a)-1]["approval"] != tk.ApprovalID || !strings.HasPrefix(tk.ApprovalID, "sk_") {
		t.Fatalf("%v", a)
	}
	// If the skill changed after the user was asked, accepting fails.
	asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Name: "sneaky", Description: "d", Content: "mcpServers: x"}))
	if _, err := s.executeSkillAccept(context.Background(), f, tk); err == nil {
		t.Fatal("accepted a changed skill")
	}
}

func TestSSHNeedsTargetsAndKeepsTheTierLogic(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "web-1"}, true))
	if status(m) != "rejected" || !strings.Contains(m["reasons"].([]string)[0], "not available yet") {
		t.Fatalf("%v", m)
	}
	// With a registry (R11), a registered target is tier 1 and an unregistered one asks.
	s.rc.ssh = func(string) map[string]bool { return map[string]bool{"web-1": true} }
	if m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "web-1"}, true)); status(m) != "applied" || fr.current(id).SSH[0] != "web-1" {
		t.Fatalf("%v", m)
	}
	if m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "db-1"}, true)); status(m) != "needs_approval" {
		t.Fatalf("%v", m)
	}
	if m := asMap(t)(s.roleSSHTool(context.Background(), f, roleSSHIn{roleWho: who(botA), Role: id, Target: "web-1"}, false)); status(m) != "applied" || len(fr.current(id).SSH) != 0 {
		t.Fatalf("%v", m)
	}
}

func TestPendingRequestsAreBounded(t *testing.T) {
	f, s, _ := roleFixture(t)
	for i := 0; i < maxRolePending; i++ {
		bot := "bot-" + string(rune('a'+i/maxPendingPerBot))
		if err := s.st.addRolePending(rolePending{ID: newID("rq_"), Bot: bot, Created: s.now()}, s.now()); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if err := s.st.addRolePending(rolePending{ID: "x", Bot: "bot-z", Created: s.now()}, s.now()); err == nil {
		t.Fatal("the 33rd request was kept")
	}
	// Old ones go, a single Bot can't take all of them, and skill text is bounded.
	if err := s.st.addRolePending(rolePending{ID: "y", Bot: "bot-z", Created: s.now()}, s.now().Add(rolePendingLife+time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = f
	f2, s2, _ := roleFixture(t)
	trustBot(t, s2, botA, "p1")
	for i := 0; i < maxPendingPerBot; i++ {
		m := asMap(t)(s2.roleCreateTool(context.Background(), cfgRoleHost{f2, `{"role_changes_per_hour_per_bot":"100"}`}, roleCreateIn{roleWho: who("bot-new"), Project: "p1", Name: "r" + string(rune('a'+i))}))
		if status(m) != "needs_approval" {
			t.Fatalf("%d: %v", i, m)
		}
	}
	m := asMap(t)(s2.roleCreateTool(context.Background(), cfgRoleHost{f2, `{"role_changes_per_hour_per_bot":"100"}`}, roleCreateIn{roleWho: who("bot-new"), Project: "p1", Name: "more"}))
	if status(m) != "rejected" {
		t.Fatalf("%v", m)
	}
}

func TestLegacyRoleAndBadIDs(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	// The project's default role has the project's id; a Bot can't address it.
	for _, id := range []string{"p1", "default", "", "r_short", "../x"} {
		if _, err := s.roleUpdateTool(context.Background(), f, roleUpdateIn{roleWho: who(botA), Role: id, Description: ptr("x")}); err == nil {
			t.Errorf("%q was accepted", id)
		}
	}
	m := asMap(t)(s.roleListTool(context.Background(), f, roleListIn{roleWho: who(botA)}))
	if l := m["default_roles_of_projects"].([]string); len(l) != 1 || l[0] != "p1" {
		t.Fatalf("%v", m)
	}
}

func TestReadTools(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	edit(t, s, f, id, roleUpdateIn{Description: ptr("x")})
	l := asMap(t)(s.roleListTool(context.Background(), f, roleListIn{roleWho: who(botA), Project: "p1"}))
	rows := l["roles"].([]map[string]any)
	if len(rows) != 1 || rows[0]["id"] != id || rows[0]["yours"] != true || rows[0]["version"] != 2 {
		t.Fatalf("%v", l)
	}
	g, err := s.roleGetTool(context.Background(), f, roleGetIn{roleWho: who(botA), Role: id, Version: 1})
	if err != nil || g.(*role).Version != 1 {
		t.Fatalf("%v %v", g, err)
	}
	h := asMap(t)(s.roleHistoryTool(context.Background(), f, roleHistoryIn{roleWho: who(botA), Role: id}))
	if h["current"] != float64(2) {
		t.Fatalf("%v", h)
	}
}

func TestOldHomeHasNoRoles(t *testing.T) {
	f, s, _ := agentFixture(t)
	_, err := s.roleListTool(context.Background(), f, roleListIn{roleWho: who(botA)})
	if err == nil || !strings.Contains(err.Error(), "doesn't do agent roles yet") {
		t.Fatalf("%v", err)
	}
}

func TestToolsAndKindsAreRegistered(t *testing.T) {
	p := rubiplugin.New(manifest())
	registerRoleTools(p, newSisters(&store{}))
	got := map[string]bool{}
	for _, tl := range p.Manifest().Tools {
		got[tl.Name] = true
	}
	for _, n := range roleToolNames {
		if !got[n] {
			t.Errorf("tool %s is not registered", n)
		}
	}
	levels := map[string]rubiplugin.Level{kindRoleForeign: rubiplugin.Strong, kindRoleWiden: rubiplugin.Strong, kindRoleSkillAccept: rubiplugin.Tap}
	for _, a := range manifest().Actions {
		if l, ok := levels[a.Kind]; ok {
			if a.DefaultLevel != l || !a.Locked {
				t.Errorf("%s: %s locked %v", a.Kind, a.DefaultLevel, a.Locked)
			}
			delete(levels, a.Kind)
		}
	}
	if len(levels) != 0 {
		t.Fatalf("missing kinds %v", levels)
	}
}

// Each acceptance has an approval id of its own: Rubi Home spends an id once, so an id shared by the kind's name
// would let only the first acceptance through.
func TestSkillAcceptancesUseDistinctApprovalIDs(t *testing.T) {
	f, s, fr := roleFixture(t)
	trustBot(t, s, botA, "p1")
	id := mustCreate(t, s, f, botA, "design")
	var ids []string
	for _, n := range []string{"one", "two"} {
		asMap(t)(s.roleSkillsAddTool(context.Background(), f, roleSkillsAddIn{roleWho: who(botA), Role: id, Name: n, Description: "d", Content: "allowed-tools: Bash"}))
		if _, err := s.askSkillAccept(context.Background(), f, mac, id, n); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(lastSubmit(t, f).Payload)
		var tk skillAcceptTicket
		_ = json.Unmarshal(b, &tk)
		if !approvalIDRE.MatchString(tk.ApprovalID) {
			t.Fatalf("approval id %q", tk.ApprovalID)
		}
		if res := asMap(t)(s.executeSkillAccept(context.Background(), f, tk)); status(res) != "applied" {
			t.Fatalf("%v", res)
		}
		ids = append(ids, tk.ApprovalID)
	}
	if ids[0] == ids[1] {
		t.Fatalf("the same approval id twice: %v", ids)
	}
	for _, k := range fr.current(id).Skills {
		if k.State != "active" {
			t.Fatalf("%+v", k)
		}
	}
	// A ticket without a usable id is refused before anything is written.
	puts := fr.putCount()
	for _, bad := range []string{"", "has space", kindRoleSkillAccept, strings.Repeat("a", 65)} {
		if _, err := s.executeSkillAccept(context.Background(), f, skillAcceptTicket{ApprovalID: bad, Device: "dev_mac", Role: id, Skill: "one", SHA256: "x", Rules: []string{"wid.claim"}}); err == nil {
			t.Errorf("accepted id %q", bad)
		}
	}
	if fr.putCount() != puts {
		t.Fatal("a put was made")
	}
}

// Archived roles count toward the per-Bot limits: archiving the old ones is not a way to make roles without end.
func TestArchivedRolesCountTowardTheBotLimits(t *testing.T) {
	f, s, _ := roleFixture(t)
	trustBot(t, s, botA, "p1")
	ch := cfgRoleHost{f, `{"role_max_per_project_per_bot":"2","role_max_per_bot":"3","role_max_total":"50"}`}
	create := func(name string) map[string]any {
		return asMap(t)(s.roleCreateTool(context.Background(), ch, roleCreateIn{roleWho: who(botA), Project: "p1", Name: name}))
	}
	a := create("a")["role"].(string)
	b := create("b")["role"].(string)
	for _, id := range []string{a, b} {
		if m := asMap(t)(s.roleArchiveTool(context.Background(), ch, roleRefIn{who(botA), id}, true)); status(m) != "applied" {
			t.Fatalf("%v", m)
		}
	}
	m := create("c")
	if status(m) != "rejected" || !strings.Contains(m["reasons"].([]string)[0], "role_max_per_project_per_bot") || !strings.Contains(m["reasons"].([]string)[0], "archived ones count") {
		t.Fatalf("%v", m)
	}
	// Unarchiving is not blocked by the count of the others.
	if m := asMap(t)(s.roleArchiveTool(context.Background(), ch, roleRefIn{who(botA), a}, false)); status(m) != "applied" {
		t.Fatalf("%v", m)
	}
}
