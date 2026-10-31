package main

// The panel pages of agent roles (docs/design/agent-roles.md section 11): the roles of each project, one role's
// detail, its history with the diff of a version and the revert button. They are the user's own page: a button is
// the user's own request. A change the user makes here is computed by the same tier engine as a Bot's: what widens
// the role (a tool outside the safe set, a mode above the ceiling, removing a deny rule a Bot or a library set)
// goes through the existing strong approval kinds, anything else is applied at once; every change is audited with
// by:"user". Role names, descriptions, skill names, rules, hosts and MCP specs come from Bots: they are clipped
// and shown as item text, never in a button label, a prompt or a confirmation.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	pageRoles       = "roles"
	pageRole        = "role"
	pageRoleHistory = "role_history"
	pageRoleDiff    = "role_diff"

	maxRoleItems  = 100 // items one section of a role page shows
	maxDiffRunes  = 580 // one diff block, cut
	maxHistory    = 40
	panelRolesDoc = "A role is a profile of one project: its own skills, tools, hosts and instructions, in a VM of its own, so what one role is given never reaches another. The project's default role is the repository's own .claude and can't be changed here."
)

// unknownRolesMsg is what a computer without roles shows.
const unknownRolesMsg = "This computer's Rubi Home doesn't do agent roles yet; update it."

// roleDeviceFor finds a computer with the claude-agent capability by id.
func (s *sisters) roleDeviceFor(ctx context.Context, h sisterHost, id string) (rubiplugin.HomeDevice, error) {
	cctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	for _, d := range s.agentDevices(cctx, h) {
		if d.ID == id {
			return d, nil
		}
	}
	return rubiplugin.HomeDevice{}, errors.New("that computer doesn't report the claude-agent capability")
}

func checkRoleID(id string) error {
	if !roleIDRE.MatchString(strings.TrimSpace(id)) {
		return errors.New("no such role")
	}
	return nil
}

// ---- small renderings ----

// skillTag says where a skill came from and what the user still has to do with it.
func skillTag(k roleSkill) string {
	var parts []string
	switch k.Source {
	case "library":
		if k.Pin != "" {
			parts = append(parts, "library "+clipOne(k.LibraryID, 40)+"@"+clipOne(k.Pin, 12)+" (pinned)")
		} else {
			parts = append(parts, "library "+clipOne(k.LibraryID, 40)+" (following the latest admitted, now version "+clipOne(k.Resolved, 12)+")")
		}
	case "adhoc":
		parts = append(parts, "written by "+clipOne(firstNonEmpty(k.AddedBy, "a Bot"), 40))
	default:
		parts = append(parts, clipOne(firstNonEmpty(k.Source, "unknown source"), 30))
	}
	switch {
	case k.State == "held":
		parts = append(parts, "HELD: the scan flagged it, so it isn't used until you accept it")
	case skillUnreviewed(k):
		parts = append(parts, "unreviewed")
	}
	if v := k.scan().Verdict; v != "" {
		parts = append(parts, "scan: "+clipOne(v, 12))
	}
	if ids := ruleIDs(k.scan()); len(ids) > 0 {
		parts = append(parts, "rules "+clipOne(strings.Join(ids, ", "), 80))
	}
	return strings.Join(parts, " · ")
}

// skillUnreviewed: a Bot-written skill that passed the scan and that no person has looked at.
func skillUnreviewed(k roleSkill) bool {
	return k.Source == "adhoc" && k.State != "held" && k.AddedBy != panelUser && len(k.Accepted) == 0
}

func ifElseAction(c bool, a, b map[string]any) map[string]any {
	if c {
		return a
	}
	return b
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// toolsSummary: how many tools, and the ones outside the safe set by name.
func toolsSummary(r *role) string {
	var extra []string
	for _, t := range r.Tools {
		if !slices.Contains(safeRoleTools, t) {
			extra = append(extra, clipOne(t, 24))
		}
	}
	out := plural(len(r.Tools), "tool", "tools")
	if len(extra) > 0 {
		out += " (outside the safe set: " + strings.Join(extra, ", ") + ")"
	}
	return out
}

// roleCounts counts the skills a person has to look at.
func roleCounts(r *role) (unreviewed, held int) {
	for _, k := range r.Skills {
		switch {
		case k.State == "held":
			held++
		case skillUnreviewed(k):
			unreviewed++
		}
	}
	return
}

// ---- the roles page ----

// rolesPage lists the roles of every project: the default role first, then the isolated ones.
func (s *sisters) rolesPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	var sections []map[string]any
	devs := s.agentDevices(ctx, h)
	for _, d := range devs {
		if p.Device != "" && d.ID != p.Device {
			continue
		}
		prefix := ifElse(len(devs) > 1, d.Name+": ", "")
		rd, err := s.refreshRoles(ctx, h, d.ID, false)
		if err != nil {
			sections = append(sections, map[string]any{"title": d.Name, "empty": ifElse(isUnknownOp(err), unknownRolesMsg, "Couldn't read the roles: "+oneLine(err.Error(), 160))})
			continue
		}
		projects, perr := s.agentProjects(ctx, h, d.ID)
		if perr != nil {
			sections = append(sections, map[string]any{"title": d.Name, "empty": "Couldn't read the projects: " + oneLine(perr.Error(), 160)})
			continue
		}
		st, _ := s.agentStatus(ctx, h, d.ID)
		running := map[string]int{} // by role id; "" the legacy role
		for _, sl := range st.slotList() {
			running[sl.Project+"/"+normRole(sl.Project, sl.Role)]++
		}
		seen := map[string]bool{}
		for _, pr := range projects {
			if seen[pr.ID] || p.Project != "" && pr.ID != p.Project {
				continue
			}
			seen[pr.ID] = true
			var items []map[string]any
			legacyRun := running[pr.ID+"/"]
			items = append(items, map[string]any{"title": "default (the project's own .claude)",
				"detail": fmt.Sprintf("Shared with everyone working in the repository; Rubi can't version or isolate it. %s running. Convert makes a new isolated role on this project; the sessions it already has stay with this role.", plural(legacyRun, "session", "sessions")),
				"actions": []map[string]any{
					{"label": "Start session", "op": "new", "args": panelPage{Device: d.ID, Project: pr.ID}.args(),
						"prompt": map[string]any{"arg": "text", "label": "First message for Claude in the default role (sent as you)", "value": ""}},
					{"label": "Convert to a new role", "op": "role_convert", "args": panelPage{Device: d.ID, Project: pr.ID}.args(),
						"prompt": map[string]any{"arg": "text", "label": "Name for the new role (a-z, 0-9 and -, up to 32 characters)", "value": ""}},
				}})
			var mine []*role
			for _, r := range rd.roles {
				if r.Project == pr.ID {
					mine = append(mine, r)
				}
			}
			slices.SortFunc(mine, func(a, b *role) int {
				if (a.Status == "active") != (b.Status == "active") {
					if a.Status == "active" {
						return -1
					}
					return 1
				}
				return strings.Compare(a.Name+"/"+a.ID, b.Name+"/"+b.ID)
			})
			for _, r := range mine {
				items = append(items, s.roleRow(d.ID, r, running[pr.ID+"/"+r.ID]))
			}
			sections = append(sections, map[string]any{"title": prefix + firstNonEmpty(pr.Dir, pr.ID),
				"note": panelRolesDoc, "empty": "", "items": items,
				"actions": []map[string]any{{"label": "New role", "op": "role_new", "args": panelPage{Device: d.ID, Project: pr.ID}.args(),
					"prompt": map[string]any{"arg": "text", "label": "Name for the new role (a-z, 0-9 and -, up to 32 characters)", "value": ""}}}})
		}
	}
	if len(sections) == 0 {
		sections = []map[string]any{{"title": "Roles", "empty": "No computer reports the claude-agent capability."}}
	}
	return map[string]any{"title": "Agent roles", "refresh": 15,
		"up":       map[string]any{"label": "Projects", "open": panelPage{Page: pageAgent}.open()},
		"sections": sections}, nil
}

func (s *sisters) roleRow(device string, r *role, running int) map[string]any {
	un, held := roleCounts(r)
	detail := fmt.Sprintf("%s · version %d · %s · %s · mode %s", clipOne(r.Status, 12), r.Version, plural(len(r.Skills), "skill", "skills"), toolsSummary(r), clipOne(r.DefaultMode, 20))
	if held > 0 {
		detail += fmt.Sprintf(" · %d HELD (need your accept)", held)
	}
	if un > 0 {
		detail += fmt.Sprintf(" · %d unreviewed", un)
	}
	if running > 0 {
		detail += " · " + plural(running, "session", "sessions") + " running"
	}
	if r.Description != "" {
		detail += " · " + clipOne(r.Description, 160)
	}
	args := panelPage{Device: device, Role: r.ID}.args()
	actions := []map[string]any{{"label": "Open", "open": panelPage{Page: pageRole, Device: device, Role: r.ID, Project: r.Project}.open()}}
	if r.Status == "active" {
		actions = append(actions,
			map[string]any{"label": "Start session", "op": "new", "args": panelPage{Device: device, Project: r.Project, Role: r.ID}.args(),
				"prompt": map[string]any{"arg": "text", "label": "First message for Claude in this role (sent as you)", "value": ""}},
			map[string]any{"label": "Archive", "op": "role_archive", "args": args, "danger": true, "confirm": "Archive this role? Nothing is deleted; it can't start sessions until you unarchive it."})
	} else {
		actions = append(actions, map[string]any{"label": "Unarchive", "op": "role_unarchive", "args": args})
	}
	it := map[string]any{"title": clipOne(r.Name, 40) + ifElse(r.Status != "active", " (archived)", ""), "detail": oneLine(detail, 500), "actions": actions}
	if held > 0 {
		it["warn"] = true
	}
	return it
}

// ---- the role detail page ----

func (s *sisters) rolePage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	if err := checkRoleID(p.Role); err != nil {
		return nil, err
	}
	d, err := s.roleDeviceFor(ctx, h, p.Device)
	if err != nil {
		return nil, err
	}
	// A role that follows library skills is brought up to date when it is looked at (the check is bounded).
	updated := s.followOnView(ctx, h, d.ID, p.Role)
	r, err := s.getRole(ctx, h, d.ID, p.Role, 0)
	if err != nil {
		return nil, err
	}
	lim := roleLimitsOf(h)
	args := func(extra ...any) map[string]any {
		m := panelPage{Device: d.ID, Role: r.ID}.args()
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i].(string)] = extra[i+1]
		}
		return m
	}
	remove := func(op, item string, extra ...map[string]any) []map[string]any {
		acts := []map[string]any{{"label": "Remove", "op": op, "args": args("item", item), "danger": true}}
		return append(acts, extra...)
	}
	cap100 := func(items []map[string]any) []map[string]any {
		if len(items) > maxRoleItems {
			return items[:maxRoleItems]
		}
		return items
	}
	un, held := roleCounts(r)
	var sections []map[string]any

	over := fmt.Sprintf("%s · version %d · created by %s · last changed by %s", clipOne(r.Status, 12), r.Version, clipOne(firstNonEmpty(r.CreatedBy, "unknown"), 40), clipOne(firstNonEmpty(r.ChangedBy, "unknown"), 40))
	if r.Description != "" {
		over += " · " + clipOne(r.Description, 200)
	}
	acts := []map[string]any{
		{"label": "History", "open": panelPage{Page: pageRoleHistory, Device: d.ID, Role: r.ID, Project: r.Project}.open()},
	}
	if r.Status == "active" {
		acts = append(acts,
			map[string]any{"label": "Start session", "op": "new", "args": panelPage{Device: d.ID, Project: r.Project, Role: r.ID}.args(),
				"prompt": map[string]any{"arg": "text", "label": "First message for Claude in this role (sent as you)", "value": ""}},
			map[string]any{"label": "Archive", "op": "role_archive", "args": args(), "danger": true, "confirm": "Archive this role? Nothing is deleted; it can't start sessions until you unarchive it."})
	} else {
		acts = append(acts, map[string]any{"label": "Unarchive", "op": "role_unarchive", "args": args()})
	}
	sections = append(sections, map[string]any{"title": "Role", "empty": "", "items": []map[string]any{
		{"title": clipOne(r.Name, 40), "detail": oneLine(over, 500), "actions": acts},
		{"title": "Instructions", "detail": fmt.Sprintf("%d characters of text written by Bots or by you elsewhere. The panel's boxes hold 200 characters, so instructions and skill text are not edited or shown here; read and revert them through History.", len([]rune(r.Instructions)))},
	}})

	var skills []map[string]any
	for _, k := range r.Skills {
		it := map[string]any{"title": clipOne(k.Name, 48), "detail": oneLine(skillTag(k), 400)}
		if k.State == "held" {
			it["warn"] = true
			it["actions"] = remove("role_skill_remove", k.Name, map[string]any{"label": "Accept", "op": "role_skill_accept", "args": args("item", k.Name)})
		} else if k.Source == "library" {
			it["actions"] = remove("role_skill_remove", k.Name,
				ifElseAction(k.Pin == "", map[string]any{"label": "Pin to this version", "op": "role_skill_pin", "args": args("item", k.Name)},
					map[string]any{"label": "Follow the latest", "op": "role_skill_follow", "args": args("item", k.Name)}))
		} else {
			it["actions"] = remove("role_skill_remove", k.Name)
		}
		skills = append(skills, it)
	}
	skNote := "A skill is text Claude reads; it grants no tools, hosts or permissions. Bots add skills; you can remove them, and accept a held one. A library skill is shared and signed by Rubi: one that follows the latest is updated here when a newer version is admitted (the History shows each update and can revert it) and dropped if the curator withdraws it; pinning keeps its version. A Bot shares a skill it wrote by submitting it to the library (rubi_library_submit), which the curator Bot then admits; nothing on this page does that."
	if len(updated) > 0 {
		var parts []string
		for _, c := range updated {
			parts = append(parts, c.text())
		}
		skNote += " Just updated from the library: " + strings.Join(parts, "; ") + "."
	}
	if held+un > 0 {
		skNote += fmt.Sprintf(" %d held, %d unreviewed.", held, un)
	}
	sections = append(sections, map[string]any{"title": "Skills", "note": skNote, "empty": "No skills.", "items": cap100(skills)})

	var tools []map[string]any
	names := slices.Clone(knownRoleTools)
	for _, t := range r.Tools {
		if !slices.Contains(names, t) {
			names = append(names, t)
		}
	}
	for _, t := range names {
		on := slices.Contains(r.Tools, t)
		safe := slices.Contains(safeRoleTools, t)
		it := map[string]any{"title": clipOne(t, 40), "detail": ifElse(on, "allowed", "not allowed") + ifElse(safe, "", " · outside the safe set")}
		switch {
		case on:
			it["actions"] = []map[string]any{{"label": "Turn off", "op": "role_tool", "args": args("item", t, "on", false)}}
		case safe:
			it["actions"] = []map[string]any{{"label": "Turn on", "op": "role_tool", "args": args("item", t, "on", true)}}
		default:
			it["actions"] = []map[string]any{{"label": "Turn on (asks you)", "op": "role_tool", "args": args("item", t, "on", true)}}
		}
		tools = append(tools, it)
	}
	sections = append(sections, map[string]any{"title": "Tools", "note": "The safe set turns on at once. A tool outside it asks for your strong approval first, and so does anything else that widens the role.", "empty": "", "items": tools})

	var deny []map[string]any
	for _, x := range r.Deny {
		label := "Remove"
		if x.By != panelUser {
			label = "Remove (asks you)"
		}
		deny = append(deny, map[string]any{"title": clipOne(x.Rule, 120), "detail": "set by " + clipOne(firstNonEmpty(x.By, "unknown"), 40),
			"actions": []map[string]any{{"label": label, "op": "role_deny_remove", "args": args("item", x.Rule), "danger": true}}})
	}
	sections = append(sections, map[string]any{"title": "Deny rules", "note": "Claude is never allowed what a deny rule names. Removing one you set is immediate; removing one a Bot or the library set asks for your strong approval.", "empty": "None.", "items": cap100(deny),
		"actions": []map[string]any{{"label": "Add a deny rule", "op": "role_deny_add", "args": args(),
			"prompt": map[string]any{"arg": "text", "label": "Deny rule, such as WebFetch or Bash(git push:*) (up to 200 characters)", "value": ""}}}})

	var mcp []map[string]any
	for _, m := range r.MCP {
		mcp = append(mcp, map[string]any{"title": clipOne(m.Name, 48), "detail": oneLine(m.Type+" · "+firstNonEmpty(m.URL, m.Command)+" · approval "+firstNonEmpty(m.Approval, "none"), 300), "actions": remove("role_mcp_remove", m.Name)})
	}
	sections = append(sections, map[string]any{"title": "MCP servers", "note": "MCP servers run code. A server's address and command don't fit the panel's 200-character box, so the panel only removes them; Bots add them (each needs your strong approval).", "empty": "None.", "items": cap100(mcp)})

	var plugins []map[string]any
	for _, x := range r.Plugins {
		plugins = append(plugins, map[string]any{"title": clipOne(x.Name, 48), "detail": oneLine("from "+x.Source+" · approval "+firstNonEmpty(x.Approval, "none"), 300), "actions": remove("role_plugin_remove", x.Name)})
	}
	sections = append(sections, map[string]any{"title": "Claude plugins", "note": "Adding a Claude plugin is done by Bots and asks for your strong approval; the panel only removes them.", "empty": "None.", "items": cap100(plugins)})

	var hosts []map[string]any
	for _, x := range r.Hosts {
		hosts = append(hosts, map[string]any{"title": clipOne(x, 80), "detail": "the role's VM may reach this host", "actions": remove("role_host_remove", x)})
	}
	sections = append(sections, map[string]any{"title": "Network hosts", "note": "Beyond the base list. Adding a host asks for your strong approval when a Bot asks; the panel only removes them.", "empty": "None.", "items": cap100(hosts)})

	sshItems, sshNote := s.sshGrantItems(ctx, h, d.ID, r, args)
	sections = append(sections, map[string]any{"title": "SSH grants", "note": sshNote, "empty": "No SSH targets are registered.", "items": sshItems,
		"actions": []map[string]any{{"label": "SSH targets", "open": panelPage{Page: pageSSH, Device: d.ID}.open()}}})

	var agents []map[string]any
	for _, a := range r.Agents {
		agents = append(agents, map[string]any{"title": clipOne(a.Name, 48), "detail": oneLine(fmt.Sprintf("model %s · tools %s · %s", firstNonEmpty(a.Model, "inherit"), strings.Join(a.Tools, ", "), a.Description), 300), "actions": remove("role_agent_remove", a.Name)})
	}
	sections = append(sections, map[string]any{"title": "Subagents", "note": "A subagent can't have more tools than the role.", "empty": "None.", "items": cap100(agents)})

	var modeActs []map[string]any
	ceil := roleModeRank[lim.Ceiling]
	for _, m := range roleModeLadder() {
		if m == r.DefaultMode {
			continue
		}
		label := m
		if roleModeRank[m] > ceil {
			label += " (asks you)"
		}
		modeActs = append(modeActs, map[string]any{"label": label, "op": "role_mode", "args": args("mode", m)})
	}
	sections = append(sections, map[string]any{"title": "Mode and project instructions", "empty": "", "items": []map[string]any{
		{"title": "Default permission mode: " + clipOne(r.DefaultMode, 20), "detail": "The mode a session of this role starts in. Up to the ceiling set in the plugin's settings (" + clipOne(lim.Ceiling, 20) + ") it changes at once; above it asks for your strong approval.", "actions": modeActs},
		{"title": "Project instructions: " + ifElse(r.ProjectInstructions, "on", "off"), "detail": "Whether Claude reads the repository's own CLAUDE.md in this role.",
			"actions": []map[string]any{{"label": ifElse(r.ProjectInstructions, "Turn off", "Turn on"), "op": "role_pinstr", "args": args("on", !r.ProjectInstructions)}}},
	}})
	return map[string]any{"title": "Role " + clipOne(r.Name, 40), "refresh": 30,
		"up":       map[string]any{"label": "Roles", "open": panelPage{Page: pageRoles, Device: d.ID, Project: r.Project}.open()},
		"sections": sections}, nil
}

// ---- history and diff ----

type roleHistEntry struct {
	Version   int             `json:"version"`
	Parent    int             `json:"parent"`
	ChangedBy string          `json:"changed_by"`
	ChangedAt string          `json:"changed_at"`
	Change    *roleChangeInfo `json:"change"`
}

func (s *sisters) roleHistoryPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	if err := checkRoleID(p.Role); err != nil {
		return nil, err
	}
	d, err := s.roleDeviceFor(ctx, h, p.Device)
	if err != nil {
		return nil, err
	}
	var hist struct {
		Current  int             `json:"current"`
		Versions []roleHistEntry `json:"versions"`
	}
	hctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(hctx, d.ID, opRoleHistory, map[string]any{"id": p.Role, "limit": maxHistory}, &hist); err != nil {
		return nil, roleHomeErr("couldn't read the history", err)
	}
	var items []map[string]any
	for _, v := range hist.Versions {
		detail := fmt.Sprintf("by %s · %s", clipOne(firstNonEmpty(v.ChangedBy, "unknown"), 40), clipOne(firstNonEmpty(v.ChangedAt, "unknown time"), 30))
		if c := v.Change; c != nil {
			if c.Tier != 0 {
				detail += fmt.Sprintf(" · tier %d (%s)", c.Tier, ifElse(c.Tier == 2, "you approved it or made it", "no approval needed"))
			}
			if c.Approval != "" {
				detail += " · approval " + clipOne(c.Approval, 40)
			}
			if c.Op != "" {
				detail += " · " + clipOne(c.Op, 40)
			}
			if c.Summary != "" {
				detail += " · " + clipOne(c.Summary, 220)
			}
		}
		acts := []map[string]any{{"label": "Show changes", "open": panelPage{Page: pageRoleDiff, Device: d.ID, Role: p.Role, Version: v.Version}.open()}}
		title := fmt.Sprintf("Version %d", v.Version)
		if v.Version == hist.Current {
			title += " (current)"
		} else {
			acts = append(acts, revertAction(d.ID, p.Role, v.Version))
		}
		items = append(items, map[string]any{"title": title, "detail": oneLine(detail, 500), "actions": acts})
	}
	return map[string]any{"title": "History of the role", "refresh": 30,
		"up": map[string]any{"label": "Role", "open": panelPage{Page: pageRole, Device: d.ID, Role: p.Role}.open()},
		"sections": []map[string]any{{"title": "Versions, newest first", "empty": "No versions.", "items": items,
			"note": "A revert is a new version; nothing is erased from the history. A revert that gives the role something it doesn't have now (an MCP server, a host, a tool outside the safe set, a looser mode) asks for your strong approval; any other revert is applied at once."}}}, nil
}

func revertAction(device, role string, version int) map[string]any {
	return map[string]any{"label": "Revert to this version", "op": "role_revert", "args": panelPage{Device: device, Role: role, Version: version}.args(), "danger": true,
		"confirm": "Make a new version with this version's content? Anything it gives the role that the current version lacks asks for your strong approval."}
}

func (s *sisters) roleDiffPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	if err := checkRoleID(p.Role); err != nil {
		return nil, err
	}
	if p.Version < 1 {
		return nil, errors.New("no version")
	}
	d, err := s.roleDeviceFor(ctx, h, p.Device)
	if err != nil {
		return nil, err
	}
	v, err := s.getRole(ctx, h, d.ID, p.Role, p.Version)
	if err != nil {
		return nil, err
	}
	cur, err := s.getRole(ctx, h, d.ID, p.Role, 0)
	if err != nil {
		return nil, err
	}
	up := map[string]any{"label": "History", "open": panelPage{Page: pageRoleHistory, Device: d.ID, Role: p.Role}.open()}
	var acts []map[string]any
	if v.Version != cur.Version {
		acts = append(acts, revertAction(d.ID, p.Role, v.Version))
	}
	head := fmt.Sprintf("Version %d, by %s", v.Version, clipOne(firstNonEmpty(v.ChangedBy, "unknown"), 40))
	if v.Parent == 0 {
		return map[string]any{"title": "Version " + fmt.Sprint(v.Version), "up": up,
			"sections": []map[string]any{{"title": head, "note": "The first version of the role: there is nothing before it to compare with.", "empty": "", "items": []map[string]any{}, "actions": acts}}}, nil
	}
	var diff struct {
		Changes []struct {
			Field string `json:"field"`
			Key   string `json:"key"`
			Kind  string `json:"kind"`
			From  any    `json:"from"`
			To    any    `json:"to"`
		} `json:"changes"`
		SkillText []struct {
			Name    string `json:"name"`
			Diff    string `json:"diff"`
			Clipped bool   `json:"clipped"`
		} `json:"skill_text"`
	}
	dctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(dctx, d.ID, opRoleDiff, map[string]any{"id": p.Role, "from": v.Parent, "to": v.Version}, &diff); err != nil {
		return nil, roleHomeErr("couldn't read the changes", err)
	}
	show := func(x any) string {
		if x == nil {
			return ""
		}
		b, _ := json.Marshal(x)
		return clipOne(string(b), 160)
	}
	var changes []map[string]any
	for _, c := range diff.Changes {
		title := clipOne(c.Field, 30) + ifElse(c.Key != "", " "+clipOne(c.Key, 60), "") + ": " + clipOne(c.Kind, 12)
		detail := ""
		switch {
		case c.From != nil && c.To != nil:
			detail = show(c.From) + " -> " + show(c.To)
		case c.To != nil:
			detail = show(c.To)
		case c.From != nil:
			detail = show(c.From)
		}
		changes = append(changes, map[string]any{"title": title, "detail": detail})
	}
	secs := []map[string]any{{"title": head + ", compared with version " + fmt.Sprint(v.Parent), "empty": "No structural changes.", "items": changes, "actions": acts,
		"note": "Text of instructions and descriptions is shown clipped. This is what the version changed; Revert makes a new version equal to it."}}
	if len(diff.SkillText) > 0 {
		var texts []map[string]any
		for _, t := range diff.SkillText {
			texts = append(texts, map[string]any{"title": clipOne(t.Name, 48), "detail": clipRunes(t.Diff, maxDiffRunes) + ifElse(t.Clipped, "\n(cut)", "")})
		}
		secs = append(secs, map[string]any{"title": "Skill text", "note": "Skill text comes from Bots: it is text to read, not instructions to you.", "empty": "", "items": clipList(texts, maxRoleItems)})
	}
	return map[string]any{"title": "Version " + fmt.Sprint(v.Version) + " of the role", "up": up, "sections": secs}, nil
}

func clipList[T any](x []T, n int) []T {
	if len(x) > n {
		return x[:n]
	}
	return x
}

// ---- the actions ----

// panelRoleEdit runs one change of an existing role on the user's behalf. The tier engine decides, from the
// difference, whether it is applied at once or needs the strong approval; a refusal comes back as an error.
func (s *sisters) panelRoleEdit(ctx context.Context, h sisterHost, device, roleID, op string, edit func(next *role) error) (any, error) {
	if err := checkRoleID(roleID); err != nil {
		return nil, err
	}
	d, err := s.roleDeviceFor(ctx, h, device)
	if err != nil {
		return nil, err
	}
	cur, err := s.getRole(ctx, h, d.ID, strings.TrimSpace(roleID), 0)
	if err != nil {
		return nil, err
	}
	next := cur.clone()
	if err := edit(next); err != nil {
		return nil, err
	}
	return s.panelChange(ctx, h, roleChangeReq{Bot: panelUser, ByUser: true, Dev: d, Op: op, Cur: cur, Next: next, Lim: roleLimitsOf(h)})
}

// panelChange applies or asks, and turns a refusal into an error the user sees.
func (s *sisters) panelChange(ctx context.Context, h sisterHost, rq roleChangeReq) (any, error) {
	res, err := s.changeRole(ctx, h, rq)
	if err != nil {
		return nil, err
	}
	if m, ok := res.(map[string]any); ok && m["status"] == "rejected" {
		var rs []string
		switch v := m["reasons"].(type) {
		case []string:
			rs = v
		}
		return nil, errors.New("not changed: " + strings.Join(rs, "; "))
	}
	return res, nil
}

// panelRoleCreate makes a new isolated role on a project. convert is the default role's button; the sessions it
// already has stay with it.
func (s *sisters) panelRoleCreate(ctx context.Context, h sisterHost, device, project string, text *string, convert bool) (any, error) {
	if text == nil {
		return nil, errors.New("this Rubi's panel can't ask for a name; update Rubi")
	}
	name := strings.TrimSpace(*text)
	if !roleNameRE.MatchString(name) || name == "default" {
		return nil, errors.New("the name is 1 to 32 characters of a-z, 0-9 and -, and not 'default'")
	}
	d, err := s.roleDeviceFor(ctx, h, device)
	if err != nil {
		return nil, err
	}
	projects, err := s.agentProjects(ctx, h, d.ID)
	if err != nil {
		return nil, err
	}
	proj, ok := matchProject(projects, project)
	if !ok || proj.ID != project {
		return nil, errors.New("no such project on that computer")
	}
	next := &role{Project: proj.ID, Name: name, Status: "active", ProjectInstructions: true, Tools: slices.Clone(defaultRoleTools), DefaultMode: "default", CreatedBy: panelUser}
	if convert {
		next.Description = "Made on the panel from the project's default role"
	}
	res, err := s.panelChange(ctx, h, roleChangeReq{Bot: panelUser, ByUser: true, Dev: d, Op: ifElse(convert, "role.convert", "role.create"), Next: next, Lim: roleLimitsOf(h)})
	if m, ok := res.(map[string]any); ok && convert {
		m["note"] = "A new isolated role was made on the project. The default role isn't changed or removed, and the sessions it already has stay with it."
	}
	return res, err
}

func removeBy[T any](list []T, drop func(T) bool) ([]T, bool) {
	out := make([]T, 0, len(list))
	for _, x := range list {
		if !drop(x) {
			out = append(out, x)
		}
	}
	return out, len(out) != len(list)
}

var errNoItem = errors.New("the role has no such item (it may have changed; reload the page)")

// panelRoleItem is the panel's single entry for the editing buttons: op names the change, item what it is about.
func (s *sisters) panelRoleItem(ctx context.Context, h sisterHost, op, device, roleID, item, mode string, on *bool, text *string) (any, error) {
	edit := func(f func(next *role) error) (any, error) {
		return s.panelRoleEdit(ctx, h, device, roleID, "role.panel."+strings.TrimPrefix(op, "role_"), f)
	}
	switch op {
	case "role_archive", "role_unarchive":
		st := ifElse(op == "role_archive", "archived", "active")
		return edit(func(n *role) error { n.Status = st; return nil })
	case "role_skill_remove":
		return edit(func(n *role) error {
			var ok bool
			if n.Skills, ok = removeBy(n.Skills, func(k roleSkill) bool { return k.Name == item }); !ok {
				return errNoItem
			}
			return nil
		})
	case "role_tool":
		if on == nil || *on && !slices.Contains(knownRoleTools, item) || !roleToolRE.MatchString(item) {
			return nil, errors.New("pick a tool and on or off")
		}
		return edit(func(n *role) error {
			has := slices.Contains(n.Tools, item)
			switch {
			case *on && !has:
				n.Tools = append(slices.Clone(n.Tools), item)
			case !*on && has:
				n.Tools, _ = removeBy(n.Tools, func(t string) bool { return t == item })
			}
			return nil
		})
	case "role_deny_add":
		if text == nil {
			return nil, errors.New("this Rubi's panel can't ask for text; update Rubi")
		}
		rule := strings.TrimSpace(*text)
		if !roleDenyRE.MatchString(rule) {
			return nil, errors.New("a deny rule is a tool name, or a tool name with a pattern in brackets, such as Bash(git push:*)")
		}
		return edit(func(n *role) error {
			if slices.ContainsFunc(n.Deny, func(d roleDeny) bool { return d.Rule == rule }) {
				return errors.New("the role already has that deny rule")
			}
			n.Deny = append(slices.Clone(n.Deny), roleDeny{Rule: rule, By: panelUser})
			return nil
		})
	case "role_deny_remove":
		return edit(func(n *role) error {
			var ok bool
			if n.Deny, ok = removeBy(n.Deny, func(d roleDeny) bool { return d.Rule == item }); !ok {
				return errNoItem
			}
			return nil
		})
	case "role_mcp_remove":
		return edit(func(n *role) error {
			var ok bool
			if n.MCP, ok = removeBy(n.MCP, func(m roleMCP) bool { return m.Name == item }); !ok {
				return errNoItem
			}
			return nil
		})
	case "role_plugin_remove":
		return edit(func(n *role) error {
			var ok bool
			if n.Plugins, ok = removeBy(n.Plugins, func(p rolePlugin) bool { return p.Name == item }); !ok {
				return errNoItem
			}
			return nil
		})
	case "role_host_remove":
		return edit(func(n *role) error {
			var ok bool
			if n.Hosts, ok = removeBy(n.Hosts, func(x string) bool { return x == item }); !ok {
				return errNoItem
			}
			return nil
		})
	case "role_agent_remove":
		return edit(func(n *role) error {
			var ok bool
			if n.Agents, ok = removeBy(n.Agents, func(a roleAgent) bool { return a.Name == item }); !ok {
				return errNoItem
			}
			return nil
		})
	case "role_skill_pin", "role_skill_follow":
		return edit(func(n *role) error {
			i := slices.IndexFunc(n.Skills, func(k roleSkill) bool { return k.Name == item && k.Source == "library" })
			if i < 0 {
				return errNoItem
			}
			if op == "role_skill_pin" {
				n.Skills[i].Pin = n.Skills[i].Resolved
			} else {
				n.Skills[i].Pin = ""
			}
			return nil
		})
	case "role_ssh_grant", "role_ssh_revoke":
		if !sshNameRE.MatchString(item) {
			return nil, errors.New("no such target")
		}
		if op == "role_ssh_grant" {
			// Only a registered target can be granted.
			if err := s.refreshSSH(ctx, h, device); err != nil {
				return nil, err
			}
			if !s.registeredSSH(device)[item] {
				return nil, errors.New("that target isn't registered")
			}
		}
		return edit(func(n *role) error {
			if op == "role_ssh_grant" {
				n.SSH = append(slices.Clone(n.SSH), item)
				slices.Sort(n.SSH)
				n.SSH = slices.Compact(n.SSH)
				return nil
			}
			var ok bool
			if n.SSH, ok = removeBy(n.SSH, func(x string) bool { return x == item }); !ok {
				return errNoItem
			}
			return nil
		})
	case "role_mode":
		if !validRoleMode(mode) {
			return nil, errors.New("pick one of " + strings.Join(roleModeLadder(), ", "))
		}
		return edit(func(n *role) error { n.DefaultMode = mode; return nil })
	case "role_pinstr":
		if on == nil {
			return nil, errors.New("say on or off")
		}
		return edit(func(n *role) error { n.ProjectInstructions = *on; return nil })
	}
	return nil, fmt.Errorf("unknown op %q", op)
}

// panelSkillAccept asks for the tap that accepts a held skill; nothing is accepted without it.
func (s *sisters) panelSkillAccept(ctx context.Context, h sisterHost, device, roleID, skill string) (any, error) {
	if err := checkRoleID(roleID); err != nil {
		return nil, err
	}
	d, err := s.roleDeviceFor(ctx, h, device)
	if err != nil {
		return nil, err
	}
	return s.askSkillAccept(ctx, h, d, strings.TrimSpace(roleID), skill)
}

// panelRoleRevert makes a new version with an older version's content: at once when it widens nothing, with the
// strong approval when it does (the same diff-based tier as a Bot's change).
func (s *sisters) panelRoleRevert(ctx context.Context, h sisterHost, device, roleID string, version int) (any, error) {
	if err := checkRoleID(roleID); err != nil {
		return nil, err
	}
	d, err := s.roleDeviceFor(ctx, h, device)
	if err != nil {
		return nil, err
	}
	cur, err := s.getRole(ctx, h, d.ID, strings.TrimSpace(roleID), 0)
	if err != nil {
		return nil, err
	}
	if version < 1 || version >= cur.Version {
		return nil, fmt.Errorf("pick an older version than the current one (%d)", cur.Version)
	}
	old, err := s.getRole(ctx, h, d.ID, cur.ID, version)
	if err != nil {
		return nil, err
	}
	next := old.clone()
	next.ID, next.Version, next.Parent, next.Project = cur.ID, cur.Version, cur.Version, cur.Project
	next.CreatedBy, next.CreatedAt = cur.CreatedBy, cur.CreatedAt
	clearStaleApprovals(cur, next)
	return s.panelChange(ctx, h, roleChangeReq{Bot: panelUser, ByUser: true, Dev: d, Op: fmt.Sprintf("role.revert(%d)", version), Cur: cur, Next: next, Lim: roleLimitsOf(h)})
}

// panelRoleSession is the role of a session the user starts from the panel: it must be an active role of the
// project, and the session starts in the role's own mode.
func (s *sisters) panelRoleSession(ctx context.Context, h sisterHost, device, project, roleID string) (mode string, err error) {
	if err := checkRoleID(roleID); err != nil {
		return "", err
	}
	r, err := s.getRole(ctx, h, device, strings.TrimSpace(roleID), 0)
	if err != nil {
		return "", err
	}
	switch {
	case r.Project != project:
		return "", errors.New("that role belongs to another project")
	case r.Status != "active":
		return "", errors.New("the role is archived: unarchive it first")
	case !validRoleMode(r.DefaultMode):
		return "", errors.New("the role's mode isn't one a session can start in")
	}
	return r.DefaultMode, nil
}
