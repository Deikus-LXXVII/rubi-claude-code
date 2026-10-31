package main

// Agent roles (docs/design/agent-roles.md in the Rubi repository): named profiles on one project of the Rubi Home
// agent path. Rubi Home keeps the role records (role.* operations of the claude-agent capability); this plugin
// keeps the tier policy, the per-Bot limits, the approvals and the audit. This file holds the plugin's view of a
// role, the cache of the role list, the limits (user config) and the tier engine. The tools are in roles_tools.go,
// the apply/approve machinery in roles_change.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

// Home operations (capability claude-agent).
const (
	opRoleList    = "claude-agent.role.list"
	opRoleGet     = "claude-agent.role.get"
	opRoleHistory = "claude-agent.role.history"
	opRoleDiff    = "claude-agent.role.diff"
	opRolePut     = "claude-agent.role.put"
)

// Approval kinds of this file's tier 2 changes.
const (
	kindRoleForeign     = "claude-code.role_foreign"      // a role on a project the Bot holds no trust for (strong, locked)
	kindRoleWiden       = "claude-code.role_widen"        // a change that widens a role (strong, locked)
	kindRoleSkillAccept = "claude-code.role_skill_accept" // a held skill the user accepts (tap, locked)
)

// The tool lists must match Rubi Home's (internal/home/agent/roles/validate.go). A name outside SafeTools is a
// tier 2 change; a name outside knownRoleTools is refused before anyone is asked.
var (
	safeRoleTools  = []string{"Read", "Edit", "Write", "Glob", "Grep", "Bash", "Agent", "Skill", "WebFetch", "WebSearch"}
	knownRoleTools = append(slices.Clone(safeRoleTools),
		"CronCreate", "CronDelete", "CronList", "ScheduleWakeup", "Monitor", "Workflow", "SendMessage",
		"EnterWorktree", "ExitWorktree", "TaskStop", "ToolSearch", "NotebookEdit")
	// defaultRoleTools is what a new role gets (all safe).
	defaultRoleTools = []string{"Read", "Edit", "Write", "Glob", "Grep", "Bash", "Agent"}
)

// roleModeRank is the ladder of section 6.3, strictest first. dontAsk is not offered for roles.
var roleModeRank = map[string]int{"plan": 0, "default": 1, "acceptEdits": 2, "auto": 3, "bypassPermissions": 4}

// approvalIDRE is what Rubi Home takes as an approval id (internal/home/agent/roles/validate.go approvalRE).
var approvalIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const (
	roleIDPrefix       = "r_"
	maxRolePending     = 32
	rolePendingLife    = 6 * time.Hour
	maxPendingPerBot   = 8
	roleCacheLife      = 30 * time.Second
	maxPendingBlobs    = 96 << 10   // skill text one pending request may carry
	maxAllPendingBlobs = 1536 << 10 // and all pending requests together (state is one 4 MiB message)
	maxSkillBytes      = 32 << 10
)

// ---- the plugin's view of a role (the JSON of Rubi Home's role record) ----

type roleSkill struct {
	Name      string          `json:"name"`
	Source    string          `json:"source"`
	LibraryID string          `json:"library_id,omitempty"`
	Pin       string          `json:"pin,omitempty"`
	Resolved  string          `json:"resolved,omitempty"`
	SHA256    string          `json:"sha256"`
	Sig       string          `json:"sig,omitempty"`
	AddedBy   string          `json:"added_by,omitempty"`
	Accepted  []string        `json:"accepted,omitempty"`
	Scan      json.RawMessage `json:"scan,omitempty"`
	State     string          `json:"state,omitempty"`
}

type roleAgent struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Prompt      string   `json:"prompt"`
	Tools       []string `json:"tools"`
	Model       string   `json:"model"`
}

type roleDeny struct {
	Rule string `json:"rule"`
	By   string `json:"by,omitempty"`
}

type roleMCP struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	URL      string   `json:"url,omitempty"`
	Command  string   `json:"command,omitempty"`
	Args     []string `json:"args,omitempty"`
	Approval string   `json:"approval"`
}

type rolePlugin struct {
	Name     string `json:"name"`
	Source   string `json:"source"`
	Approval string `json:"approval"`
}

type roleChangeInfo struct {
	Op       string `json:"op,omitempty"`
	Tier     int    `json:"tier,omitempty"`
	Approval string `json:"approval,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

// role is one version of a role. The field set is exactly Home's: role.put refuses unknown keys.
type role struct {
	ID                  string          `json:"id"`
	Project             string          `json:"project"`
	Name                string          `json:"name"`
	Description         string          `json:"description"`
	Status              string          `json:"status"`
	Version             int             `json:"version"`
	Parent              int             `json:"parent"`
	Instructions        string          `json:"instructions"`
	ProjectInstructions bool            `json:"project_instructions"`
	Skills              []roleSkill     `json:"skills"`
	Agents              []roleAgent     `json:"agents"`
	Tools               []string        `json:"tools"`
	Deny                []roleDeny      `json:"deny"`
	MCP                 []roleMCP       `json:"mcp"`
	Plugins             []rolePlugin    `json:"plugins"`
	Hosts               []string        `json:"hosts"`
	SSH                 []string        `json:"ssh"`
	DefaultMode         string          `json:"default_mode"`
	CreatedBy           string          `json:"created_by"`
	CreatedAt           string          `json:"created_at"`
	ChangedBy           string          `json:"changed_by"`
	ChangedAt           string          `json:"changed_at"`
	Change              *roleChangeInfo `json:"change"`
}

// roleRow is one line of role.list.
type roleRow struct {
	ID          string `json:"id"`
	Project     string `json:"project"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Version     int    `json:"version"`
	ChangedBy   string `json:"changed_by,omitempty"`
	ChangedAt   string `json:"changed_at,omitempty"`
	Legacy      bool   `json:"legacy,omitempty"`
}

// roleFields are the fields a change can touch, in a fixed order.
var roleFields = []string{"name", "description", "status", "instructions", "project_instructions", "skills", "agents",
	"tools", "deny", "mcp", "plugins", "hosts", "ssh", "default_mode"}

// fieldValue is a field of r as JSON (nil lists and empty lists are the same; skills compare by identity, not by
// the scan Home added).
func (r *role) fieldValue(f string) json.RawMessage {
	var v any
	switch f {
	case "name":
		v = r.Name
	case "description":
		v = r.Description
	case "status":
		v = r.Status
	case "instructions":
		v = r.Instructions
	case "project_instructions":
		v = r.ProjectInstructions
	case "skills":
		type id struct {
			Name, Source, Lib, Pin, SHA string
		}
		ids := []id{}
		for _, s := range r.Skills {
			ids = append(ids, id{s.Name, s.Source, s.LibraryID, s.Pin, s.SHA256})
		}
		v = ids
	case "agents":
		v = nz(r.Agents)
	case "tools":
		v = nz(r.Tools)
	case "deny":
		v = nz(r.Deny)
	case "mcp":
		v = nz(r.MCP)
	case "plugins":
		v = nz(r.Plugins)
	case "hosts":
		v = nz(r.Hosts)
	case "ssh":
		v = nz(r.SSH)
	case "default_mode":
		v = r.DefaultMode
	}
	b, _ := json.Marshal(v)
	return b
}

// nz turns a nil slice into an empty one so both marshal alike.
func nz[T any](x []T) []T {
	if x == nil {
		return []T{}
	}
	return x
}

// fieldDiffers lists the fields in which a and b differ. A nil a is an empty role.
func fieldDiffers(a, b *role) []string {
	if a == nil {
		a = &role{}
	}
	var out []string
	for _, f := range roleFields {
		if string(a.fieldValue(f)) != string(b.fieldValue(f)) {
			out = append(out, f)
		}
	}
	return out
}

// clone is a deep copy (through JSON, which is the type's whole definition).
func (r *role) clone() *role {
	b, _ := json.Marshal(r)
	c := &role{}
	_ = json.Unmarshal(b, c)
	return c
}

// ---- limits (user config) ----

// roleLimits are the per-Bot limits and the mode ceiling of section 6.4. They are user config fields: no Bot tool
// changes them, and changing them is the plugin config's strong approval.
type roleLimits struct {
	PerProjectPerBot int
	PerBot           int
	ChangesPerHour   int
	Skills           int
	AdhocSkills      int
	Total            int
	Ceiling          string
}

const (
	cfgRolePerProject = "role_max_per_project_per_bot"
	cfgRolePerBot     = "role_max_per_bot"
	cfgRoleChanges    = "role_changes_per_hour_per_bot"
	cfgRoleSkills     = "role_max_skills"
	cfgRoleAdhoc      = "role_max_adhoc_skills"
	cfgRoleTotal      = "role_max_total"
	cfgRoleCeiling    = "role_mode_ceiling"
)

func defaultRoleLimits() roleLimits {
	return roleLimits{PerProjectPerBot: 5, PerBot: 20, ChangesPerHour: 30, Skills: 20, AdhocSkills: 10, Total: 50, Ceiling: "bypassPermissions"}
}

// roleConfigFields are the manifest's config fields for the limits.
func roleConfigFields() []rubiplugin.ConfigField {
	d := defaultRoleLimits()
	num := func(key, label string, def int, help string) rubiplugin.ConfigField {
		return rubiplugin.ConfigField{Key: key, Label: label, Type: "text", Default: fmt.Sprint(def), Help: help}
	}
	var modes []rubiplugin.Option
	for _, m := range roleModeLadder() {
		modes = append(modes, rubiplugin.Option{Key: m, Label: m})
	}
	return []rubiplugin.ConfigField{
		num(cfgRolePerProject, "Agent roles: most roles one Bot may have on one project", d.PerProjectPerBot, "Bots create and change roles themselves within this and the next limits; a role on a project you haven't trusted for that Bot, or one that widens a role, always asks you."),
		num(cfgRolePerBot, "Agent roles: most roles one Bot may have in all", d.PerBot, ""),
		num(cfgRoleChanges, "Agent roles: most role changes per hour for one Bot", d.ChangesPerHour, ""),
		num(cfgRoleSkills, "Agent roles: most skills in one role", d.Skills, ""),
		num(cfgRoleAdhoc, "Agent roles: most Bot-written (ad-hoc) skills in one role", d.AdhocSkills, ""),
		num(cfgRoleTotal, "Agent roles: most roles on one computer", d.Total, ""),
		{Key: cfgRoleCeiling, Label: "Agent roles: loosest permission mode a Bot may give a role without asking you", Type: "choice", Default: d.Ceiling, Options: modes,
			Help: "Strictest first. A Bot that sets a looser mode on a role has to ask you (one strong approval). The VM is the boundary; Rubi Home's own switch for bypassPermissions stays the hard floor."},
	}
}

func roleModeLadder() []string {
	out := make([]string, 0, len(roleModeRank))
	for m := range roleModeRank {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return roleModeRank[out[i]] < roleModeRank[out[j]] })
	return out
}

// roleLimitsOf reads the user's limits; a host without settings, or a bad value, gets the default.
func roleLimitsOf(h sisterHost) roleLimits {
	l := defaultRoleLimits()
	c, ok := h.(interface{ Config(v any) error })
	if !ok {
		return l
	}
	var cfg map[string]any
	if c.Config(&cfg) != nil {
		return l
	}
	for key, dst := range map[string]*int{cfgRolePerProject: &l.PerProjectPerBot, cfgRolePerBot: &l.PerBot, cfgRoleChanges: &l.ChangesPerHour,
		cfgRoleSkills: &l.Skills, cfgRoleAdhoc: &l.AdhocSkills, cfgRoleTotal: &l.Total} {
		var n float64
		switch v := cfg[key].(type) {
		case float64:
			n = v
		case string:
			if _, err := fmt.Sscanf(strings.TrimSpace(v), "%g", &n); err != nil {
				continue
			}
		default:
			continue
		}
		if n >= 1 && n <= 100000 {
			*dst = int(n)
		}
	}
	if m, _ := cfg[cfgRoleCeiling].(string); m != "" {
		if _, ok := roleModeRank[m]; ok {
			l.Ceiling = m
		}
	}
	return l
}

// ---- the cache ----

// roleDev is one computer's roles as the plugin last saw them (at most role_max_total plus slack).
type roleDev struct {
	at     time.Time
	roles  map[string]*role // by id, stored roles only
	legacy map[string]bool  // project ids (the legacy role has the project's id)
}

type roleCache struct {
	mu   sync.Mutex
	devs map[string]*roleDev
	// ssh says which SSH targets of a computer are registered (nil: none; the registry comes with R11).
	ssh func(device string) map[string]bool
}

// stale makes the next read of a computer's roles ask Home again (what is cached stays for the version check).
func (c *roleCache) stale(device string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d := c.devs[device]; d != nil {
		d.at = time.Time{}
	}
}

func (c *roleCache) get(device string) *roleDev {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.devs[device]
}

func (c *roleCache) set(device string, d *roleDev) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.devs == nil {
		c.devs = map[string]*roleDev{}
	}
	c.devs[device] = d
}

func (c *roleCache) forget(device string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.devs, device)
}

// roleHomeErr turns a Home failure into a sentence for the Bot.
func roleHomeErr(what string, err error) error {
	if isUnknownOp(err) {
		return fmt.Errorf("this computer's Rubi Home doesn't do agent roles yet; the user updates it (%s)", what)
	}
	return fmt.Errorf("%s: %v", what, err)
}

// refreshRoles brings the cache of a computer up to date from role.list (and role.get for what changed).
func (s *sisters) refreshRoles(ctx context.Context, h sisterHost, device string, force bool) (*roleDev, error) {
	if d := s.rc.get(device); d != nil && !force && s.now().Sub(d.at) < roleCacheLife {
		return d, nil
	}
	var lr struct {
		Roles []roleRow `json:"roles"`
	}
	lctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(lctx, device, opRoleList, map[string]any{}, &lr); err != nil {
		return nil, roleHomeErr("couldn't list the roles", err)
	}
	old := s.rc.get(device)
	nd := &roleDev{at: s.now(), roles: map[string]*role{}, legacy: map[string]bool{}}
	for _, row := range lr.Roles {
		if row.Legacy {
			nd.legacy[row.Project] = true
			continue
		}
		if old != nil {
			if r := old.roles[row.ID]; r != nil && r.Version == row.Version {
				nd.roles[row.ID] = r
				continue
			}
		}
		r, err := s.getRole(ctx, h, device, row.ID, 0)
		if err != nil {
			return nil, err
		}
		nd.roles[row.ID] = r
	}
	s.rc.set(device, nd)
	return nd, nil
}

// getRole reads one version of a role from Home (0: the current one).
func (s *sisters) getRole(ctx context.Context, h sisterHost, device, id string, version int) (*role, error) {
	var r role
	gctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(gctx, device, opRoleGet, map[string]any{"id": id, "version": version}, &r); err != nil {
		return nil, roleHomeErr("couldn't read the role", err)
	}
	if r.ID != id {
		return nil, fmt.Errorf("Rubi Home answered with another role than %q", id)
	}
	return &r, nil
}

// ---- Bot trust ----

// botTrust is a live project trust of the agent project that this Bot asked for (not consumed, not counted).
func (s *sisters) botTrust(device, bot, project string) *projectTrust {
	for _, p := range s.st.projects(s.now()) {
		if p.Device == device && p.Project == project && p.Project != "" && p.Sister != "" && sameBot(p.Sister, bot) && p.live(s.now()) {
			c := p
			return &c
		}
	}
	return nil
}

// ---- the tier engine (section 6.1, last paragraph) ----

// tierCtx is what the verdict depends on besides the two versions.
type tierCtx struct {
	Bot        string
	Trust      bool            // the Bot holds a live project trust for the role's project
	Ceiling    string          // role_mode_ceiling
	Registered map[string]bool // registered SSH targets (none until R11)
	// Revert: the change reverts to an older version; Foreign history says some version after it is not this
	// Bot's own tier 1 change.
	RevertOthers bool
	// ForceWiden: the tool always asks (mcp_set, plugins_set, hosts_set).
	ForceWiden bool
	// ByUser: the change is the user's own, from the panel: the rules about what other Bots made don't apply.
	ByUser bool
}

// tierVerdict is the result of comparing the current version with the proposed one.
type tierVerdict struct {
	Tier    int
	Foreign bool     // role_foreign: a project this Bot holds no trust for
	Widen   bool     // role_widen: something grows
	Reasons []string // why tier 2, for the approval and the Bot
	// Widening is the part of Reasons that says what grows, shortest form first: the headline of an approval, which
	// a long list of small changes must not push out of the first 100 characters.
	Widening []string
}

func (v *tierVerdict) widen(format string, args ...any) {
	v.Widen = true
	r := fmt.Sprintf(format, args...)
	v.Reasons = append(v.Reasons, r)
	v.Widening = append(v.Widening, r)
}

// headline is the summary of a tier 2 approval: what widens first, then (for a project without trust) that the
// project isn't trusted, then the other changes. The full list of changes is in the approval's preview.
func (v tierVerdict) headline(lines []string, n int) string {
	var parts []string
	parts = append(parts, v.Widening...)
	if v.Foreign {
		parts = append(parts, "project not trusted")
	}
	return joinSummary(append(parts, lines...), n)
}

// tierOf compares cur with next (cur nil: a new role) and says which tier the change is. The tier comes from the
// difference, never from the tool's name: any growth in mcp, plugins or hosts, a new tool outside the safe set, a
// removed deny rule the Bot didn't set, a default mode above the ceiling, an SSH grant of an unregistered target,
// or any change to a role of a project this Bot holds no trust for makes it tier 2. Content (instructions,
// skills, subagents, names) is tier 1: a skill carries no grants.
func tierOf(cur, next *role, c tierCtx) tierVerdict {
	var v tierVerdict
	base := cur
	if base == nil {
		base = &role{}
	}
	if !c.Trust {
		v.Foreign = true
		v.Reasons = append(v.Reasons, "the project is one you hold no trust for, so the user has to agree to any role there")
	}
	for _, m := range next.MCP {
		if !slices.ContainsFunc(base.MCP, func(o roleMCP) bool { return sameMCP(o, m) }) {
			verb := "adds"
			if slices.ContainsFunc(base.MCP, func(o roleMCP) bool { return o.Name == m.Name }) {
				verb = "changes"
			}
			v.widen("%s the MCP server %s", verb, mcpDesc(m))
		}
	}
	for _, p := range next.Plugins {
		if !slices.ContainsFunc(base.Plugins, func(o rolePlugin) bool { return o.Name == p.Name && o.Source == p.Source }) {
			v.widen("adds the Claude plugin %s from %s", clipOne(p.Name, 40), clipOne(p.Source, 100))
		}
	}
	for _, h := range next.Hosts {
		if !slices.Contains(base.Hosts, h) {
			v.widen("allows the network host %s", clipOne(h, 80))
		}
	}
	for _, t := range next.Tools {
		if !slices.Contains(safeRoleTools, t) && !slices.Contains(base.Tools, t) {
			v.widen("adds the tool %s, which is outside the safe set", clipOne(t, 40))
		}
	}
	me := botID(c.Bot)
	if cur != nil && !c.ByUser {
		// A Bot changes, archives and unarchives only the roles it created; the others' (the user's too) are the
		// user's to agree to. What other hands put in a role it created is protected the same way.
		if cur.CreatedBy != me {
			v.widen("changes the role %s, which %s created, not you", clipOne(cur.Name, 40), whoSet(cur.CreatedBy))
		}
		for _, k := range cur.Skills {
			j := slices.IndexFunc(next.Skills, func(n roleSkill) bool { return n.Name == k.Name })
			switch {
			case k.AddedBy == me:
			case j < 0:
				v.widen("removes the skill %s that %s wrote", clipOne(k.Name, 48), whoSet(k.AddedBy))
			case next.Skills[j].SHA256 != k.SHA256 || next.Skills[j].Pin != k.Pin:
				v.widen("changes the skill %s that %s wrote", clipOne(k.Name, 48), whoSet(k.AddedBy))
			}
		}
	}
	for _, d := range base.Deny {
		if !slices.ContainsFunc(next.Deny, func(n roleDeny) bool { return n.Rule == d.Rule }) && (d.By == "" || d.By != me) {
			v.widen("removes the deny rule %s that %s set", clipOne(d.Rule, 60), whoSet(d.By))
		}
	}
	if next.DefaultMode != base.DefaultMode {
		to, ok := roleModeRank[next.DefaultMode]
		ceil, cok := roleModeRank[c.Ceiling]
		if !ok || !cok || to > ceil {
			v.widen("sets the permission mode %s, above the ceiling %s", clipOne(next.DefaultMode, 30), c.Ceiling)
		}
	}
	for _, t := range next.SSH {
		if !slices.Contains(base.SSH, t) && !c.Registered[t] {
			v.widen("grants the SSH target %s, which isn't registered", clipOne(t, 40))
		}
	}
	if c.RevertOthers {
		v.widen("reverts changes that weren't your own tier 1 changes")
	}
	if c.ForceWiden && !v.Widen {
		v.widen("MCP servers, Claude plugins and network hosts always need the user's approval")
	}
	v.Tier = 1
	if v.Foreign || v.Widen {
		v.Tier = 2
	}
	return v
}

func whoSet(by string) string {
	if by == "" || by == "user" {
		return "the user"
	}
	return clipOne(by, 40)
}

func sameMCP(a, b roleMCP) bool {
	return a.Name == b.Name && a.Type == b.Type && a.URL == b.URL && a.Command == b.Command && slices.Equal(nz(a.Args), nz(b.Args))
}

// clipOne is one short line of untrusted text.
func clipOne(s string, n int) string { return oneLine(s, n) }

func validRoleMode(m string) bool { _, ok := roleModeRank[m]; return ok }
