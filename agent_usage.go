package main

// Usage modes of the agent path, per Bot (docs in Rubi's docs/design/rubi-home.md, "Usage modes, per Bot"): the
// panel page that shows each Bot's mode with live counters and lets the USER change it. Rubi Home keeps the
// table and enforces it. The change is a plain button on the user's own page; there is deliberately no Bot tool
// for it (a Bot must not raise its own limits), and the plugin never changes a mode by itself.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	opAgentUsageMode = "claude-agent.usage_mode"
	pageModes        = "modes"
	auditUsageMode   = "agent_usage_mode_changed"
)

// usageModes: what the user chooses between, in plain words (quota against speed).
var usageModes = []struct{ Key, Label, About string }{
	{"maximum", "Maximum", "Fastest, and uses your Claude quota fastest: no limit on sessions or subagents."},
	{"medium", "Medium (Recommended)", "A balance: up to 4 sessions at once for the Bot, up to 4 subagents in each."},
	{"light", "Light", "Saves quota, slower: 1 session at a time, up to 2 subagents in each."},
}

func modeLabel(key string) string {
	for _, m := range usageModes {
		if m.Key == key {
			return m.Label
		}
	}
	return firstNonEmpty(oneLine(key, 30), "unknown")
}

// botID is the stable id of a Bot for Rubi Home (letters, digits and _ . : @ -, starting with a letter or
// digit, at most 64): its name in lower case with other characters turned into "-". A name that leaves
// nothing, or is too long, gets a short hash. Two names that differ only in such characters share an id.
func botID(sister string) string {
	name := strings.ToLower(strings.TrimSpace(sister))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', strings.ContainsRune("_.:@-", r):
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	id := strings.TrimLeft(b.String(), "_.:@-")
	if id == "" || len(id) > 64 {
		sum := sha256.Sum256([]byte(name))
		id = "bot-" + hex.EncodeToString(sum[:])[:16]
	}
	return id
}

// botTitle is a Bot's name on the page: the name the user knows it by when a binding has it.
func (s *sisters) botTitle(id string) string {
	if id == "" {
		return "You (sessions started from this panel)"
	}
	for _, b := range s.st.bindings() {
		if botID(b.Sister) == id {
			return oneLine(b.Sister, 60)
		}
	}
	return oneLine(id, 64)
}

func (s *sisters) modesPage(ctx context.Context, h sisterHost) (any, error) {
	var sections []map[string]any
	for _, d := range s.agentDevices(ctx, h) {
		st, err := s.agentStatus(ctx, h, d.ID)
		if err != nil {
			sections = append(sections, map[string]any{"title": d.Name, "empty": "Couldn't read the status: " + oneLine(err.Error(), 160)})
			continue
		}
		if st.Usage.Default == "" {
			sections = append(sections, map[string]any{"title": d.Name, "empty": "This computer's Rubi Home doesn't have usage modes yet; update it."})
			continue
		}
		running := st.slotList()
		total := "no limit"
		if st.Limits.Total > 0 {
			total = fmt.Sprint(st.Limits.Total)
		}
		var about []string
		for _, m := range usageModes {
			about = append(about, m.Label+": "+m.About)
		}
		var allActions, defActions []map[string]any
		for _, m := range usageModes {
			allActions = append(allActions, map[string]any{"label": "All Bots: " + m.Label, "op": "usage_mode", "args": map[string]any{"device": d.ID, "all": true, "mode": m.Key},
				"confirm": "Set every Bot, and the default for new Bots, to " + m.Label + "? Running sessions are not stopped; the change applies to new ones."})
			if m.Key != st.Usage.Default {
				defActions = append(defActions, map[string]any{"label": "Default: " + m.Label, "op": "usage_mode", "args": map[string]any{"device": d.ID, "default": true, "mode": m.Key}})
			}
		}
		sections = append(sections,
			map[string]any{"title": d.Name + ": modes", "note": strings.Join(about, " ") + " The limits are per Bot: a Bot on Light never limits another on Medium. A change applies to new sessions; nothing running is stopped, and when lowered the extra sessions finish and new work waits. Only you change this: Bots cannot.",
				"empty": "", "items": []map[string]any{
					{"title": fmt.Sprintf("Default for new Bots and your own sessions: %s", modeLabel(st.Usage.Default)), "detail": fmt.Sprintf("Sessions running on this computer: %d of %s (a cap set in Rubi Home's configuration), one per project at a time unless configured.", len(running), total), "actions": defActions},
					{"title": "Set one mode for all Bots", "detail": "Applies to every Bot Rubi Home knows and to the default. Afterwards you can change Bots one by one again.", "actions": allActions},
				}})
		var items []map[string]any
		for _, b := range st.Usage.Bots {
			limit := "no limit"
			if b.SessionsLimit > 0 {
				limit = fmt.Sprint(b.SessionsLimit)
			}
			sub := "no limit"
			if b.SubagentsPerSession > 0 {
				sub = fmt.Sprint(b.SubagentsPerSession)
			}
			title := s.botTitle(b.ID) + ": " + modeLabel(b.Mode)
			detail := fmt.Sprintf("Sessions %d of %s · subagents per session: %s", b.SessionsRunning, limit, sub)
			for _, r := range running {
				if r.Bot == b.ID {
					detail += fmt.Sprintf(" · %s: %d running", oneLine(firstNonEmpty(s.st.nameOf(d.ID, r.Session), r.Session, "starting"), 40), r.Subagents)
				}
			}
			it := map[string]any{"title": title}
			if b.Custom {
				title += " · Custom"
				it["title"] = title
				detail += " · Custom: a limit set in Rubi Home's configuration overrides this mode."
			}
			it["detail"] = oneLine(detail, 500)
			if b.ID != "" {
				var acts []map[string]any
				for _, m := range usageModes {
					if m.Key != b.Mode {
						acts = append(acts, map[string]any{"label": m.Label, "op": "usage_mode", "args": map[string]any{"device": d.ID, "bot": b.ID, "mode": m.Key}})
					}
				}
				it["actions"] = acts
			}
			items = append(items, it)
		}
		sections = append(sections, map[string]any{"title": d.Name + ": Bots", "empty": "No Bot has used the agent path yet; a new Bot gets the default mode.", "items": items})
	}
	if len(sections) == 0 {
		sections = []map[string]any{{"title": "Usage modes", "empty": "No computer reports the claude-agent capability."}}
	}
	return map[string]any{"title": "Usage modes", "refresh": 15, "up": upMain, "sections": sections}, nil
}

// panelAgentUsage sets a mode for one Bot, the default, or every Bot. Only the panel reaches it.
func (s *sisters) panelAgentUsage(ctx context.Context, h sisterHost, device, bot string, def, all bool, mode string) (any, error) {
	known := false
	for _, mm := range usageModes {
		known = known || mm.Key == mode
	}
	n := 0
	for _, set := range []bool{bot != "", def, all} {
		if set {
			n++
		}
	}
	if !known || n != 1 {
		return nil, errors.New("pick a mode and who it is for")
	}
	var dev *rubiplugin.HomeDevice
	cctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	for _, d := range s.agentDevices(cctx, h) {
		if d.ID == device {
			dev = &d
		}
	}
	if dev == nil {
		return nil, errors.New("that computer doesn't report the claude-agent capability")
	}
	args := map[string]any{"mode": mode}
	who := "all"
	switch {
	case bot != "":
		args["bot"], who = bot, bot
	case def:
		args["default"], who = true, "default"
	default:
		args["all"] = true
	}
	if err := h.HomeCall(cctx, dev.ID, opAgentUsageMode, args, nil); err != nil {
		h.Audit(auditUsageMode, map[string]any{"device": dev.ID, "who": who, "mode": mode, "by": "user", "failed": oneLine(err.Error(), 160)})
		return nil, err
	}
	h.Audit(auditUsageMode, map[string]any{"device": dev.ID, "who": who, "mode": mode, "by": "user"})
	return map[string]any{"ok": true, "mode": mode, "who": who}, nil
}

// panelAgentNew starts a new session in a project as the user (no Bot: it counts under the default mode),
// with the first message the user typed in the panel's box.
func (s *sisters) panelAgentNew(ctx context.Context, h sisterHost, device, project, roleID string, text *string) (any, error) {
	if text == nil {
		return nil, errors.New("this Rubi's panel can't ask for text; update Rubi")
	}
	t := strings.TrimSpace(*text)
	if t == "" {
		return nil, errors.New("nothing to send: write the first message")
	}
	if len([]rune(t)) > panelSendRunes {
		return nil, fmt.Errorf("at most %d characters", panelSendRunes)
	}
	if device == "" || project == "" {
		return nil, errors.New("no project")
	}
	lctx, lcancel := context.WithTimeout(ctx, panelListTimeout)
	defer lcancel()
	projects, err := s.agentProjects(lctx, h, device)
	if err != nil {
		return nil, err
	}
	proj, ok := matchProject(projects, project)
	if !ok || proj.ID != project {
		return nil, errors.New("no such project on that computer")
	}
	mode := "default"
	if roleID != "" {
		var err error
		if mode, err = s.panelRoleSession(lctx, h, device, proj.ID, roleID); err != nil {
			return nil, err
		}
	}
	var res struct {
		ID       string `json:"id"`
		Queued   bool   `json:"queued"`
		Position int    `json:"position"`
		Reason   string `json:"reason"`
	}
	cctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()
	// default mode: Claude asks before commands; the first message is the user's own (no `from`, no `bot`).
	if err := h.HomeCall(cctx, device, opAgentStart, withRole(map[string]any{"project": proj.ID, "prompt": t, "mode": mode}, roleID), &res); err != nil {
		h.Audit(auditPanelAgent, withRole(map[string]any{"action": "start", "device": device, "project": proj.ID, "by": "user", "failed": oneLine(err.Error(), 160)}, roleID))
		return nil, err
	}
	h.Audit(auditPanelAgent, withRole(map[string]any{"action": "start", "device": device, "project": proj.ID, "session": res.ID, "by": "user", "queued": res.Queued, "chars": len([]rune(t)), "mode": mode}, roleID))
	out := map[string]any{"started": !res.Queued, "queued": res.Queued, "position": res.Position}
	if res.ID != "" {
		out["session_id"] = res.ID
	}
	if res.Reason != "" {
		out["reason"] = oneLine(res.Reason, 200)
	}
	return out, nil
}
