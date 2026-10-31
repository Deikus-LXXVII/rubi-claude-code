package main

// Applying a role change: the tier decides whether it goes to Rubi Home at once (tier 1, audited) or waits for the
// user's approval (tier 2). A change is atomic: if any part is tier 2 nothing is applied. When the approval runs
// the change is rebased onto the current version, and it fails cleanly if the parts it touches have moved.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	auditRoleChange = "role.change"
	roleCallTimeout = 30 * time.Second
)

var errRoleMoved = errors.New("the role changed since you asked; ask again")

// roleTicket is the payload of a tier 2 role approval: the touched fields with the value they had when the change
// was asked (Before, compared on execution) and the value to write (After), plus the new skill text.
type roleTicket struct {
	ID         string                     `json:"id"`
	Bot        string                     `json:"bot"`
	Device     string                     `json:"device"`
	DeviceName string                     `json:"device_name,omitempty"`
	ByUser     bool                       `json:"by_user,omitempty"` // the user's own change from the panel (Bot is "user")
	Role       string                     `json:"role,omitempty"`    // "" creates a role
	Project    string                     `json:"project"`
	Op         string                     `json:"op"`
	Base       int                        `json:"base"`
	Before     map[string]json.RawMessage `json:"before,omitempty"`
	After      map[string]json.RawMessage `json:"after"`
	Blobs      map[string]string          `json:"blobs,omitempty"`
	Summary    string                     `json:"summary"`
	Reasons    []string                   `json:"reasons,omitempty"`
}

func (r *role) fullValue(f string) json.RawMessage {
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
		v = nz(r.Skills)
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

func (r *role) setField(f string, raw json.RawMessage) error {
	var dst any
	switch f {
	case "name":
		dst = &r.Name
	case "description":
		dst = &r.Description
	case "status":
		dst = &r.Status
	case "instructions":
		dst = &r.Instructions
	case "project_instructions":
		dst = &r.ProjectInstructions
	case "skills":
		dst = &r.Skills
	case "agents":
		dst = &r.Agents
	case "tools":
		dst = &r.Tools
	case "deny":
		dst = &r.Deny
	case "mcp":
		dst = &r.MCP
	case "plugins":
		dst = &r.Plugins
	case "hosts":
		dst = &r.Hosts
	case "ssh":
		dst = &r.SSH
	case "default_mode":
		dst = &r.DefaultMode
	default:
		return fmt.Errorf("bad payload: field %q", f)
	}
	return json.Unmarshal(raw, dst)
}

// ---- describing a change (no skill text, no instructions: names and short facts) ----

func setLines(prefix string, before, after []string, n int) []string {
	var out []string
	for _, a := range after {
		if !slices.Contains(before, a) {
			out = append(out, "+"+prefix+" "+clipOne(a, n))
		}
	}
	for _, b := range before {
		if !slices.Contains(after, b) {
			out = append(out, "-"+prefix+" "+clipOne(b, n))
		}
	}
	return out
}

func describeRoleChange(cur, next *role) []string {
	base := cur
	if base == nil {
		base = &role{}
	}
	var out []string
	for _, f := range fieldDiffers(cur, next) {
		switch f {
		case "name":
			out = append(out, fmt.Sprintf("name %q -> %q", clipOne(base.Name, 40), clipOne(next.Name, 40)))
		case "description":
			out = append(out, "description changed")
		case "status":
			out = append(out, "status "+clipOne(base.Status, 20)+" -> "+clipOne(next.Status, 20))
		case "instructions":
			out = append(out, fmt.Sprintf("instructions changed (%d characters)", len([]rune(next.Instructions))))
		case "project_instructions":
			out = append(out, fmt.Sprintf("project instructions %t -> %t", base.ProjectInstructions, next.ProjectInstructions))
		case "skills":
			bs, as := map[string]roleSkill{}, map[string]roleSkill{}
			var bn, an []string
			for _, s := range base.Skills {
				bs[s.Name] = s
				bn = append(bn, s.Name)
			}
			for _, s := range next.Skills {
				as[s.Name] = s
				an = append(an, s.Name)
			}
			out = append(out, setLines("skill", bn, an, 48)...)
			for _, n := range an {
				if b, ok := bs[n]; ok && (b.SHA256 != as[n].SHA256 || b.Pin != as[n].Pin) {
					out = append(out, "~skill "+clipOne(n, 48)+" changed")
				}
			}
		case "agents":
			var bn, an []string
			for _, a := range base.Agents {
				bn = append(bn, a.Name)
			}
			for _, a := range next.Agents {
				an = append(an, a.Name)
			}
			l := setLines("subagent", bn, an, 48)
			if len(l) == 0 {
				l = []string{"subagent definitions changed"}
			}
			out = append(out, l...)
		case "tools":
			out = append(out, setLines("tool", base.Tools, next.Tools, 40)...)
		case "deny":
			var bn, an []string
			for _, d := range base.Deny {
				bn = append(bn, d.Rule)
			}
			for _, d := range next.Deny {
				an = append(an, d.Rule)
			}
			out = append(out, setLines("deny", bn, an, 60)...)
		case "mcp":
			var bn, an []string
			for _, m := range base.MCP {
				bn = append(bn, m.Name+" ("+firstNonEmpty(m.URL, m.Command)+")")
			}
			for _, m := range next.MCP {
				an = append(an, m.Name+" ("+firstNonEmpty(m.URL, m.Command)+")")
			}
			out = append(out, setLines("mcp", bn, an, 100)...)
		case "plugins":
			var bn, an []string
			for _, p := range base.Plugins {
				bn = append(bn, p.Name+" ("+p.Source+")")
			}
			for _, p := range next.Plugins {
				an = append(an, p.Name+" ("+p.Source+")")
			}
			out = append(out, setLines("plugin", bn, an, 100)...)
		case "hosts":
			out = append(out, setLines("host", base.Hosts, next.Hosts, 80)...)
		case "ssh":
			out = append(out, setLines("ssh", base.SSH, next.SSH, 40)...)
		case "default_mode":
			out = append(out, "default mode "+clipOne(base.DefaultMode, 30)+" -> "+clipOne(next.DefaultMode, 30))
		}
	}
	return out
}

func joinSummary(lines []string, n int) string {
	return oneLine(strings.Join(lines, "; "), n)
}

// ---- the change request ----

type roleChangeReq struct {
	Bot          string
	Dev          rubiplugin.HomeDevice
	Op           string // role.create, role.update, ...
	Cur          *role  // nil: a new role
	Next         *role
	Blobs        map[string]string
	Lim          roleLimits
	ForceWiden   bool
	RevertOthers bool
	// ByUser is the user's own change from the panel (Bot is panelUser): the Bot-only rules (trust of the project,
	// the per-Bot counts and the hourly rate) don't apply, the diff-based tier does.
	ByUser bool
}

// panelUser is the "Bot" of a change the user made on the panel. It is a reserved name: a Bot can't take it.
const panelUser = "user"

func rejected(reasons ...string) map[string]any {
	return map[string]any{"status": "rejected", "reasons": reasons}
}

// roleRefused is Rubi Home's refusal of a put (the validation reasons, or a conflict).
type roleRefused struct{ msg string }

func (e roleRefused) Error() string { return e.msg }

func refusalReasons(msg string) []string {
	msg = strings.TrimPrefix(msg, "role refused: ")
	var out []string
	for _, r := range strings.Split(msg, "; ") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, oneLine(r, 200))
		}
	}
	if len(out) == 0 {
		out = []string{"Rubi Home refused the change"}
	}
	return out
}

// roleCount counts a Bot's active roles (project "": on the whole computer).
func roleCount(d *roleDev, creator, project, except string) int {
	n := 0
	for id, r := range d.roles {
		if id != except && r.Status == "active" && r.CreatedBy == creator && (project == "" || r.Project == project) {
			n++
		}
	}
	return n
}

// limitReasons names every per-Bot limit the proposed role would pass.
func (s *sisters) limitReasons(ctx context.Context, h sisterHost, rq roleChangeReq, fields []string) ([]string, error) {
	var out []string
	next, lim := rq.Next, rq.Lim
	if slices.Contains(fields, "default_mode") {
		if _, ok := roleModeRank[next.DefaultMode]; !ok {
			out = append(out, "default_mode must be one of "+strings.Join(roleModeLadder(), ", ")+" (dontAsk isn't offered for roles)")
		}
	}
	if slices.Contains(fields, "skills") {
		adhoc := 0
		for _, k := range next.Skills {
			if k.Source == "adhoc" {
				adhoc++
			}
		}
		if len(next.Skills) > lim.Skills {
			out = append(out, fmt.Sprintf("%s: a role may have %d skills, this would make %d", cfgRoleSkills, lim.Skills, len(next.Skills)))
		}
		if adhoc > lim.AdhocSkills {
			out = append(out, fmt.Sprintf("%s: a role may have %d Bot-written skills, this would make %d", cfgRoleAdhoc, lim.AdhocSkills, adhoc))
		}
	}
	creating := rq.Cur == nil
	perBot := !rq.ByUser
	activating := rq.Cur != nil && rq.Cur.Status != "active" && next.Status == "active"
	if creating || activating {
		d, err := s.refreshRoles(ctx, h, rq.Dev.ID, true)
		if err != nil {
			return nil, err
		}
		creator := botID(rq.Bot)
		if rq.Cur != nil {
			creator = rq.Cur.CreatedBy
		}
		except := ""
		if rq.Cur != nil {
			except = rq.Cur.ID
		}
		if creating && len(d.roles) >= lim.Total {
			out = append(out, fmt.Sprintf("%s: this computer already has %d roles (the limit)", cfgRoleTotal, len(d.roles)))
		}
		if n := roleCount(d, creator, next.Project, except); perBot && n >= lim.PerProjectPerBot {
			out = append(out, fmt.Sprintf("%s: %d active roles of the same Bot on this project already (the limit)", cfgRolePerProject, n))
		}
		if n := roleCount(d, creator, "", except); perBot && n >= lim.PerBot {
			out = append(out, fmt.Sprintf("%s: %d active roles of the same Bot already (the limit)", cfgRolePerBot, n))
		}
	}
	return out, nil
}

// changeRole is the common path of every role-changing tool: tier, limits, then apply or ask.
func (s *sisters) changeRole(ctx context.Context, h sisterHost, rq roleChangeReq) (any, error) {
	next := rq.Next
	fields := fieldDiffers(rq.Cur, next)
	if rq.Cur != nil && len(fields) == 0 {
		return map[string]any{"status": "applied", "unchanged": true, "role": rq.Cur.ID, "version": rq.Cur.Version,
			"note": "nothing differs from the current version, so no new version was made"}, nil
	}
	reasons, err := s.limitReasons(ctx, h, rq, fields)
	if err != nil {
		return nil, err
	}
	if len(reasons) > 0 {
		return rejected(reasons...), nil
	}
	project := next.Project
	v := tierOf(rq.Cur, next, tierCtx{Bot: rq.Bot, Trust: rq.ByUser || s.botTrust(rq.Dev.ID, rq.Bot, project) != nil, Ceiling: rq.Lim.Ceiling,
		Registered: s.registeredSSH(rq.Dev.ID), RevertOthers: rq.RevertOthers, ForceWiden: rq.ForceWiden})
	if !rq.ByUser && !s.allow("rolechg|"+strings.ToLower(strings.TrimSpace(rq.Bot)), rq.Lim.ChangesPerHour) {
		return rejected(fmt.Sprintf("%s: at most %d role changes per hour for one Bot", cfgRoleChanges, rq.Lim.ChangesPerHour)), nil
	}
	lines := describeRoleChange(rq.Cur, next)
	summary := joinSummary(lines, 200)
	if v.Tier == 1 {
		base, id := 0, ""
		if rq.Cur != nil {
			base, id = rq.Cur.Version, rq.Cur.ID
		}
		res, err := s.putRole(ctx, h, rq.Dev.ID, id, base, next, rq.Blobs, botID(rq.Bot), roleChangeInfo{Op: rq.Op, Tier: 1, Summary: summary})
		var rf roleRefused
		if errors.As(err, &rf) {
			return rejected(refusalReasons(rf.msg)...), nil
		}
		if err != nil {
			return nil, err
		}
		return s.applied(h, rq.Bot, rq.Dev.ID, rq.Cur, next, res, 1, "", summary), nil
	}
	return s.askRoleChange(ctx, h, rq, next, fields, v, lines, summary)
}

func (s *sisters) registeredSSH(device string) map[string]bool {
	if s.rc.ssh == nil {
		return nil
	}
	return s.rc.ssh(device)
}

type putResult struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Skills  []struct {
		Name    string `json:"name"`
		State   string `json:"state"`
		Verdict string `json:"verdict"`
	} `json:"skills"`
}

// putRole writes a version through role.put. A refusal by Rubi Home comes back as a roleRefused.
func (s *sisters) putRole(ctx context.Context, h sisterHost, device, id string, base int, spec *role, blobs map[string]string, by string, ch roleChangeInfo) (putResult, error) {
	args := map[string]any{"base_version": base, "spec": spec, "by": by, "change": ch}
	if id != "" {
		args["id"] = id
	}
	if len(blobs) > 0 {
		args["blobs"] = blobs
	}
	var res putResult
	pctx, cancel := context.WithTimeout(ctx, roleCallTimeout)
	defer cancel()
	err := h.HomeCall(pctx, device, opRolePut, args, &res)
	s.rc.stale(device)
	if err != nil {
		if isUnknownOp(err) {
			return res, roleHomeErr("couldn't save the role", err)
		}
		if rubiplugin.ErrorCode(err) == rubiplugin.CodeHomeFailed {
			if strings.Contains(err.Error(), "the role changed") {
				return res, roleRefused{errRoleMoved.Error()}
			}
			return res, roleRefused{err.Error()}
		}
		return res, fmt.Errorf("no answer from Rubi Home (%v): the change may have been saved; read the role before trying again", err)
	}
	return res, nil
}

// applied audits a written version and builds the answer.
func (s *sisters) applied(h sisterHost, bot, device string, cur, next *role, res putResult, tier int, approval, summary string) map[string]any {
	from := 0
	if cur != nil {
		from = cur.Version
	}
	auditID := newID("au_")
	fields := map[string]any{"audit_id": auditID, "role": res.ID, "project": next.Project, "from": from, "to": res.Version, "by": bot,
		"tier": tier, "summary": summary, "device": device}
	if approval != "" {
		fields["approval"] = approval
	}
	h.Audit(auditRoleChange, fields)
	out := map[string]any{"status": "applied", "role": res.ID, "version": res.Version, "audit_id": auditID, "tier": tier}
	var held []map[string]any
	for _, k := range res.Skills {
		if k.State == "held" {
			held = append(held, map[string]any{"skill": k.Name, "verdict": k.Verdict})
		}
	}
	if len(held) > 0 {
		out["held_skills"] = held
		out["note"] = "A held skill is saved but not active: its text matched the skill scan's flags, so the user has to accept it (Rubi's panel) before the role uses it."
	}
	return out
}

// ---- tier 2: ask ----

func (s *sisters) askRoleChange(ctx context.Context, h sisterHost, rq roleChangeReq, next *role, fields []string, v tierVerdict, lines []string, summary string) (any, error) {
	t := roleTicket{ID: newID("rq_"), Bot: rq.Bot, ByUser: rq.ByUser, Device: rq.Dev.ID, DeviceName: rq.Dev.Name, Project: next.Project, Op: rq.Op,
		After: map[string]json.RawMessage{}, Blobs: rq.Blobs, Summary: summary, Reasons: v.Reasons}
	if rq.Cur != nil {
		t.Role, t.Base = rq.Cur.ID, rq.Cur.Version
		t.Before = map[string]json.RawMessage{}
	}
	for _, f := range fields {
		t.After[f] = next.fullValue(f)
		if rq.Cur != nil {
			t.Before[f] = rq.Cur.fieldValue(f)
		}
	}
	blobBytes := 0
	for _, b := range rq.Blobs {
		blobBytes += len(b)
	}
	if blobBytes > maxPendingBlobs {
		return rejected(fmt.Sprintf("the skill text is %d KiB; a change that needs the user's approval may carry at most %d KiB of it", blobBytes>>10, maxPendingBlobs>>10)), nil
	}
	p := rolePending{ID: t.ID, Bot: rq.Bot, Device: rq.Dev.ID, Role: t.Role, Project: t.Project, Op: rq.Op, Summary: summary, Base: t.Base,
		BlobBytes: blobBytes, Created: s.now()}
	if err := s.st.addRolePending(p, s.now()); err != nil {
		return rejected(err.Error()), nil
	}
	kind := kindRoleWiden
	if v.Foreign {
		kind = kindRoleForeign
	}
	name := next.Name
	where := rq.Dev.Name
	asker := rq.Bot
	if rq.ByUser {
		asker = "you, on Rubi's panel"
	}
	preview := map[string]any{"bot": asker, "computer": where, "project": next.Project, "role": name, "role_id": t.Role, "base_version": t.Base,
		"changes": lines, "why_you_are_asked": v.Reasons, "what_it_does": "Changes the agent role " + clipOne(name, 40) + " on the project " + next.Project + ". Nothing is applied until you approve; if the role changes before you do, the request fails and the Bot has to ask again. Skill text is not shown here: a skill is only context, it grants nothing."}
	if rq.Cur == nil {
		preview["what_it_does"] = "Creates the agent role " + clipOne(name, 40) + " on the project " + next.Project + ". Nothing is created until you approve."
	}
	res, err := h.Submit(ctx, rubiplugin.Request{Kind: kind,
		Summary: "Role " + oneLine(name, 40) + " on " + oneLine(next.Project, 40) + " for " + asker + ": " + oneLine(summary, 100),
		Preview: preview, Payload: t})
	if err != nil {
		s.st.takeRolePending(t.ID, s.now())
		return nil, err
	}
	approval, _ := res["approval_id"].(string)
	s.st.setRoleApproval(t.ID, approval)
	out := map[string]any{"status": "needs_approval", "approval_id": approval, "link": firstNonEmptyAny(res["approval_url"], res["link"]),
		"reasons": v.Reasons, "pending": map[string]any{"role": firstNonEmpty(t.Role, name), "base_version": t.Base, "changes": lines}}
	return out, nil
}

func firstNonEmptyAny(xs ...any) any {
	for _, x := range xs {
		if s, ok := x.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// ---- tier 2: execute ----

// executeRoleChange runs an approved role change: rebase onto the current version, write, audit.
func (s *sisters) executeRoleChange(ctx context.Context, h sisterHost, t roleTicket) (any, error) {
	if t.ID == "" || t.Bot == "" || t.Device == "" || t.Project == "" || len(t.After) == 0 {
		return nil, errors.New("bad payload")
	}
	p, ok := s.st.takeRolePending(t.ID, s.now())
	if !ok || p.Bot != t.Bot || p.Device != t.Device || p.Role != t.Role {
		return nil, errors.New("this role change is no longer pending (it was too old, or already done); the Bot has to ask again")
	}
	approval := firstNonEmpty(p.Approval, t.ID)
	var cur, next *role
	if t.Role == "" {
		next = &role{Project: t.Project, Status: "active", DefaultMode: "default", ProjectInstructions: true}
	} else {
		var err error
		if cur, err = s.getRole(ctx, h, t.Device, t.Role, 0); err != nil {
			return nil, err
		}
		if cur.Project != t.Project {
			return nil, errRoleMoved
		}
		if cur.Version != t.Base {
			// Rebase: the parts this change touches must be what they were when it was asked.
			for f, before := range t.Before {
				if string(cur.fieldValue(f)) != string(before) {
					return nil, errRoleMoved
				}
			}
		}
		next = cur.clone()
	}
	for f, raw := range t.After {
		if !slices.Contains(roleFields, f) {
			return nil, errors.New("bad payload")
		}
		if err := next.setField(f, raw); err != nil {
			return nil, errors.New("bad payload")
		}
	}
	for i := range next.MCP {
		if next.MCP[i].Approval == "" {
			next.MCP[i].Approval = approval
		}
	}
	for i := range next.Plugins {
		if next.Plugins[i].Approval == "" {
			next.Plugins[i].Approval = approval
		}
	}
	if cur == nil {
		// A new role: the limits hold when the user answers, not only when the Bot asked.
		rq := roleChangeReq{Bot: t.Bot, ByUser: t.ByUser, Dev: rubiplugin.HomeDevice{ID: t.Device, Name: t.DeviceName}, Next: next, Lim: roleLimitsOf(h)}
		reasons, err := s.limitReasons(ctx, h, rq, []string{"name"})
		if err != nil {
			return nil, err
		}
		if len(reasons) > 0 {
			return nil, errors.New("not created: " + strings.Join(reasons, "; "))
		}
	}
	base, id := 0, ""
	if cur != nil {
		base, id = cur.Version, cur.ID
	}
	res, err := s.putRole(ctx, h, t.Device, id, base, next, t.Blobs, botID(t.Bot), roleChangeInfo{Op: t.Op, Tier: 2, Approval: approval, Summary: oneLine(t.Summary, 200)})
	var rf roleRefused
	if errors.As(err, &rf) {
		return nil, errors.New("not applied: " + strings.Join(refusalReasons(rf.msg), "; "))
	}
	if err != nil {
		return nil, err
	}
	return s.applied(h, t.Bot, t.Device, cur, next, res, 2, approval, t.Summary), nil
}

// ---- held skills ----

// skillAcceptTicket is the payload of a role_skill_accept approval.
type skillAcceptTicket struct {
	Device     string   `json:"device"`
	DeviceName string   `json:"device_name,omitempty"`
	Role       string   `json:"role"`
	Project    string   `json:"project"`
	Skill      string   `json:"skill"`
	SHA256     string   `json:"sha256"`
	Rules      []string `json:"rules"`
}

type scanView struct {
	Verdict string `json:"verdict"`
	Rules   []struct {
		ID      string `json:"id"`
		Line    int    `json:"line"`
		Excerpt string `json:"excerpt"`
	} `json:"rules"`
}

func (k roleSkill) scan() scanView {
	var v scanView
	_ = json.Unmarshal(k.Scan, &v)
	return v
}

func heldSkill(r *role, name string) (roleSkill, bool) {
	for _, k := range r.Skills {
		if k.Name == name && k.Source == "adhoc" && k.State == "held" {
			return k, true
		}
	}
	return roleSkill{}, false
}

func ruleIDs(v scanView) []string {
	var ids []string
	for _, r := range v.Rules {
		if !slices.Contains(ids, r.ID) {
			ids = append(ids, r.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

// askSkillAccept asks the user (a tap) to accept a held skill, showing what the scan flagged. It is for the panel
// (R7); no Bot tool calls it, because a Bot can't accept its own skill.
func (s *sisters) askSkillAccept(ctx context.Context, h sisterHost, dev rubiplugin.HomeDevice, roleID, skill string) (any, error) {
	r, err := s.getRole(ctx, h, dev.ID, roleID, 0)
	if err != nil {
		return nil, err
	}
	k, ok := heldSkill(r, skill)
	if !ok {
		return nil, fmt.Errorf("the role has no held skill %q", skill)
	}
	sc := k.scan()
	var hits []string
	for _, x := range sc.Rules {
		hits = append(hits, fmt.Sprintf("%s (line %d): %s", clipOne(x.ID, 20), x.Line, clipOne(x.Excerpt, 80)))
	}
	t := skillAcceptTicket{Device: dev.ID, DeviceName: dev.Name, Role: r.ID, Project: r.Project, Skill: k.Name, SHA256: k.SHA256, Rules: ruleIDs(sc)}
	preview := map[string]any{"computer": dev.Name, "project": r.Project, "role": r.Name, "skill": k.Name, "written_by": firstNonEmpty(k.AddedBy, "unknown"),
		"flags_found": hits, "what_it_does": "Lets the role use this skill. A skill is only context for Claude: it grants no tools, hosts or permissions. The scan flagged the lines above; the text is not shown here."}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindRoleSkillAccept,
		Summary: "Accept the skill " + oneLine(k.Name, 40) + " in the role " + oneLine(r.Name, 40) + " on " + oneLine(r.Project, 40),
		Preview: preview, Payload: t})
}

// executeSkillAccept runs once the user accepted: the flags the user saw are acknowledged in a new version.
func (s *sisters) executeSkillAccept(ctx context.Context, h sisterHost, t skillAcceptTicket) (any, error) {
	if t.Device == "" || t.Role == "" || t.Skill == "" || t.SHA256 == "" || len(t.Rules) == 0 {
		return nil, errors.New("bad payload")
	}
	cur, err := s.getRole(ctx, h, t.Device, t.Role, 0)
	if err != nil {
		return nil, err
	}
	k, ok := heldSkill(cur, t.Skill)
	if !ok || k.SHA256 != t.SHA256 || !slices.Equal(ruleIDs(k.scan()), t.Rules) {
		return nil, errors.New("the skill changed since you were asked; it needs a new request")
	}
	next := cur.clone()
	for i := range next.Skills {
		if next.Skills[i].Name == t.Skill {
			next.Skills[i].Accepted = slices.Clone(t.Rules)
		}
	}
	summary := "accepted skill " + clipOne(t.Skill, 48) + " (rules " + strings.Join(t.Rules, ", ") + ")"
	res, err := s.putRole(ctx, h, t.Device, cur.ID, cur.Version, next, nil, "user", roleChangeInfo{Op: "role.skill.accept", Tier: 2, Approval: kindRoleSkillAccept, Summary: summary})
	var rf roleRefused
	if errors.As(err, &rf) {
		return nil, errors.New("not accepted: " + strings.Join(refusalReasons(rf.msg), "; "))
	}
	if err != nil {
		return nil, err
	}
	return s.applied(h, "user", t.Device, cur, next, res, 2, kindRoleSkillAccept, summary), nil
}
