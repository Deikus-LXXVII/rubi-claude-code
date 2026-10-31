package main

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

type mandatesIn struct {
	Revoke string `json:"revoke,omitempty" jsonschema:"a mandate id to revoke, or all"`
}

func mandateView(m mandate, now time.Time) map[string]any {
	return map[string]any{"id": m.ID, "computer": firstNonEmpty(m.DeviceName, m.Device), "session_id": m.SessionID,
		"directory": m.Cwd, "expires": m.Expires, "minutes_left": int(m.Expires.Sub(now).Minutes()), "uses": m.Uses, "max_uses": m.MaxUses}
}

func projectView(p projectTrust, now time.Time) map[string]any {
	v := map[string]any{"id": p.ID, "computer": firstNonEmpty(p.DeviceName, p.Device), "project_root": p.Root, "branches": p.BranchPattern,
		"uses": p.Uses, "granted": p.Issued, "granted_ago": ageText(p.Issued, now)}
	if p.Unlimited {
		v["until"] = untilRevoked
		v["note"] = "UNTIL REVOKED — no end time; no limit on the number of commands"
		return v
	}
	v["expires"], v["minutes_left"], v["max_uses"] = p.Expires, int(p.Expires.Sub(now).Minutes()), p.MaxUses
	return v
}

func (s *sisters) mandatesTool(h sisterHost, in mandatesIn) (any, error) {
	if in.Revoke != "" {
		n, err := s.st.revoke(in.Revoke)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			h.Audit("mandate_revoked", map[string]any{"mandate": in.Revoke, "count": n, "by": "bot"})
		}
		return map[string]any{"revoked": n}, nil
	}
	now := s.now()
	var list []map[string]any
	for _, m := range s.st.mandates(now) {
		list = append(list, mandateView(m, now))
	}
	var projects []map[string]any
	for _, p := range s.st.projects(now) {
		projects = append(projects, projectView(p, now))
	}
	return map[string]any{"mandates": list, "project_trusts": projects}, nil
}

// panel is the plugin's page: the live mandates and the bindings, with buttons to end them.
func (s *sisters) panel(ctx context.Context, h sisterHost, op string, args json.RawMessage) (any, error) {
	var a struct {
		ID        string  `json:"id"`
		Sister    string  `json:"sister"`
		Device    string  `json:"device"`
		SessionID string  `json:"session_id"`
		Name      *string `json:"name"`
		Forget    string  `json:"forget"`
		Project   string  `json:"project"`
		Mode      string  `json:"mode"`
		Page      string  `json:"page"`
		Text      *string `json:"text"`
		Step      string  `json:"step"`
		Method    string  `json:"method"`
		Option    string  `json:"option"`
		Code      *string `json:"code"`
		Bot       string  `json:"bot"`
		Default   bool    `json:"default"`
		All       bool    `json:"all"`
	}
	if len(args) > 0 && string(args) != "null" {
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, errors.New("bad arguments")
		}
	}
	switch op {
	case "view":
		if a.Page != "" {
			return s.agentPage(ctx, h, panelPage{Page: a.Page, Device: a.Device, Project: a.Project, Session: a.SessionID})
		}
	case "setup_install", "setup_network", "setup_add", "setup_run", "setup_open", "setup_code", "setup_remove", "setup_cancel":
		return s.panelSetup(ctx, h, op, setupArgs{Device: a.Device, Step: a.Step, Project: a.Project, Method: a.Method, Option: a.Option, Code: a.Code})
	case "interrupt", "close":
		return s.panelAgentSimple(ctx, h, "claude-agent."+op, a.Device, a.Project, a.SessionID)
	case "fork":
		return s.panelAgentFork(ctx, h, a.Device, a.Project, a.SessionID)
	case "new": // a new session in a project, the first message typed on the page
		return s.panelAgentNew(ctx, h, a.Device, a.Project, a.Text)
	case "usage_mode": // the user's own switch; no Bot tool exists for it
		return s.panelAgentUsage(ctx, h, a.Device, a.Bot, a.Default, a.All, a.Mode)
	case "send":
		return s.panelAgentSend(ctx, h, a.Device, a.Project, a.SessionID, a.Text)
	case "revoke":
		n, err := s.st.revoke(a.ID)
		if err != nil {
			return nil, err
		}
		h.Audit("mandate_revoked", map[string]any{"mandate": a.ID, "count": n, "by": "user"})
		return map[string]any{"revoked": n}, nil
	case "unbind":
		var was []binding
		for _, b := range s.st.bindings() {
			if sameBot(b.Sister, a.Sister) {
				was = append(was, b)
			}
		}
		ok, err := s.st.unbind(a.Sister)
		if err != nil {
			return nil, err
		}
		if ok {
			h.Audit("binding_removed", map[string]any{"sister": a.Sister, "by": "user"})
			for _, b := range was {
				s.tellBound(context.Background(), h, b, false)
			}
		}
		return map[string]any{"unbound": ok}, nil
	case "rename":
		if a.Project != "" {
			return s.panelAgentRename(ctx, h, a.Device, a.Project, a.SessionID, a.Name)
		}
		return s.panelRename(ctx, h, a.Device, a.SessionID, a.Name, a.Forget)
	case "mode": // an agent session's mode: stricter at once, looser as a strong approval (the page for it is M6)
		return s.changeMode(ctx, h, "", a.Device, a.Project, a.SessionID, a.Mode, true)
	default:
		return nil, fmt.Errorf("unknown op %q", op)
	}
	now := s.now()
	var mitems []map[string]any
	for _, m := range s.st.mandates(now) {
		mitems = append(mitems, map[string]any{
			"title":   fmt.Sprintf("%s — %s", firstNonEmpty(m.DeviceName, m.Device), m.Cwd),
			"detail":  fmt.Sprintf("Session %s · %d of %d commands · %d min left", m.SessionID, m.Uses, m.MaxUses, int(m.Expires.Sub(now).Minutes())),
			"actions": []map[string]any{{"label": "Revoke", "op": "revoke", "args": map[string]any{"id": m.ID}, "danger": true}},
		})
	}
	if len(mitems) > 0 {
		mitems = append(mitems, map[string]any{"title": "All of them", "actions": []map[string]any{
			{"label": "Revoke all", "op": "revoke", "args": map[string]any{"id": "all"}, "danger": true, "confirm": "Revoke every trust, 2-hour and project?"}}})
	}
	var pitems []map[string]any
	for _, p := range s.st.projects(now) {
		title := fmt.Sprintf("%s — %s", firstNonEmpty(p.DeviceName, p.Device), p.Root)
		detail := fmt.Sprintf("Branches %s · %d of %d commands · until %s (%d min left) · granted %s", p.BranchPattern, p.Uses, p.MaxUses, s.expiryTime(trustOffer{Expires: p.Expires}).Format("Mon 2 Jan 15:04 MST"), int(p.Expires.Sub(now).Minutes()), ageText(p.Issued, now))
		if p.Unlimited {
			title = "UNTIL REVOKED — " + title
			detail = fmt.Sprintf("UNTIL REVOKED — no end time, stays on across restarts and days · Branches %s · %d commands used (no limit) · granted %s", p.BranchPattern, p.Uses, ageText(p.Issued, now))
		}
		pitems = append(pitems, map[string]any{
			"title":   title,
			"detail":  detail,
			"actions": []map[string]any{{"label": "Revoke", "op": "revoke", "args": map[string]any{"id": p.ID}, "danger": true}},
		})
	}
	if len(pitems) > 0 {
		pitems = append(pitems, map[string]any{"title": "All of them", "actions": []map[string]any{
			{"label": "Revoke all", "op": "revoke", "args": map[string]any{"id": "all"}, "danger": true, "confirm": "Revoke every trust, 2-hour and project?"}}})
	}
	var bitems []map[string]any
	for _, b := range s.st.bindings() {
		bitems = append(bitems, map[string]any{
			"title":   b.Sister + " → " + firstNonEmpty(b.Title, b.Cwd),
			"detail":  fmt.Sprintf("%s · %s · session %s · since %s", firstNonEmpty(b.DeviceName, b.Device), b.RepoKey, b.SessionID, b.Since.Format(time.DateTime)),
			"actions": []map[string]any{{"label": "Unbind", "op": "unbind", "args": map[string]any{"sister": b.Sister}, "danger": true, "confirm": "Unbind " + b.Sister + "?"}},
		})
	}
	nameItems, nameNote := s.nameItems(ctx, h)
	agent := append(s.agentLinkSection(ctx, h), s.setupLinkSection(ctx, h)...)
	return map[string]any{"title": "Claude Code", "refresh": 30,
		"note": "Sessions running with bypassPermissions never ask, so approvals and trusts here don't apply to them (their messages to and from Bots still work).",
		"sections": append(agent, []map[string]any{
			{"title": "Trusted sessions (2 hours)", "note": "Rubi allows these sessions' plain, listed commands by itself, including builds and tests that run the project's own code; push, --force, sudo, network commands, credential paths and writing outside the directory or into .git still ask.", "empty": "None.", "items": mitems},
			{"title": "Trusted projects (until 04:00, or until revoked)", "note": "A trust marked UNTIL REVOKED has no end time and no command limit: it stays on across restarts and days until you revoke it here (or with claude_code_mandates). Every Claude Code session on that computer inside the project: Rubi allows plain, listed commands by itself, including builds and tests that run the project's own code, and a Bot bound to a session of the project can start and bind sessions in it. Push and every remote git command, --force, sudo, network commands, tags, credential paths, writing outside the project and branches outside the pattern still ask.", "empty": "None.", "items": pitems},
			{"title": "Session names", "note": nameNote, "empty": "No sessions.", "items": nameItems},
			{"title": "Bots bound to sessions", "note": "Each Bot talks only to its session.", "empty": "None.", "items": bitems},
		}...)}, nil
}

// panelRename is the user's own rename (or clear) from the panel: no approval, the page is the user's. name
// nil means the panel did not send one (a Rubi too old to ask for it), which must not read as "clear".
func (s *sisters) panelRename(ctx context.Context, h sisterHost, device, sessionID string, name *string, forget string) (any, error) {
	if forget != "" {
		ok, err := s.st.clearAliasExact(device, forget)
		if err != nil {
			return nil, err
		}
		if ok {
			h.Audit(auditRenamed, map[string]any{"device": device, "old": oneLine(forget, maxNameRunes), "new": "", "by": "user", "approval": "panel (session gone)"})
		}
		return map[string]any{"cleared": ok}, nil
	}
	if name == nil {
		return nil, errors.New("this Rubi's panel can't ask for a name; update Rubi")
	}
	if sessionID == "" {
		return nil, errors.New("no session")
	}
	ctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	d, sess, all, err := lookupSession(ctx, h, device, sessionID)
	if err != nil {
		return nil, err
	}
	t := renameTicket{Device: d.ID, DeviceName: d.Name, SessionID: sess.SessionID, AppSessionID: sess.AppSessionID}
	if strings.TrimSpace(*name) == "" {
		t.Clear = true
	} else {
		if t.Name, err = checkAliasName(*name); err != nil {
			return nil, err
		}
		if err := freeName(t.Name, all, d.ID); err != nil {
			return nil, err
		}
	}
	return s.executeRename(ctx, h, t, "user", "panel", all)
}

const maxNameItems = 60

// nameItems lists the live sessions, each with a button to name it, and the names whose session isn't
// listed. A computer that doesn't answer in time is said in the note, not waited for.
func (s *sisters) nameItems(ctx context.Context, h sisterHost) ([]map[string]any, string) {
	note := "A name is a label kept in Rubi: it shows in session lists and a Bot can use it instead of the session's id. Claude Code itself isn't changed (rename there with /rename). 1 to 64 plain characters, unique on a computer. Clear the box to remove a name."
	ctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	all, err := s.nameSessions(ctx, h)
	if err != nil {
		return nil, note + " Couldn't read the sessions: " + oneLine(err.Error(), 120)
	}
	type row struct {
		d rubiplugin.HomeDevice
		x session
	}
	var rows []row
	listed := map[string]bool{}
	for _, ds := range all {
		if ds.err != nil {
			note += " " + ds.device.Name + " didn't answer."
			continue
		}
		listed[ds.device.ID] = !ds.partial // a name is called orphaned only against a whole list
		for _, x := range ds.list {
			if x.Archived || x.State == "ended" {
				if _, ok := s.st.aliasFor(ds.device.ID, x); !ok {
					continue
				}
			}
			rows = append(rows, row{ds.device, x})
		}
	}
	slices.SortStableFunc(rows, func(a, b row) int {
		_, an := s.st.aliasFor(a.d.ID, a.x)
		_, bn := s.st.aliasFor(b.d.ID, b.x)
		switch {
		case an != bn && an:
			return -1
		case an != bn:
			return 1
		}
		return b.x.LastActivity.Compare(a.x.LastActivity)
	})
	// Which names have a session is decided over all the rows, not only the ones shown.
	seen := map[string]bool{}
	for _, r := range rows {
		if a, ok := s.st.aliasFor(r.d.ID, r.x); ok {
			seen[a.Device+"|"+foldName(a.Name)] = true
		}
	}
	var items []map[string]any
	for _, r := range rows {
		if len(items) >= maxNameItems {
			note += fmt.Sprintf(" Showing %d of %d sessions: the named ones and the most recent.", maxNameItems, len(rows))
			break
		}
		a, named := s.st.aliasFor(r.d.ID, r.x)
		cur := ""
		if named {
			cur = a.Name
		}
		args := map[string]any{"device": r.d.ID, "session_id": firstNonEmpty(r.x.AppSessionID, r.x.SessionID)}
		actions := []map[string]any{{"label": ifElse(named, "Rename", "Name"), "op": "rename", "args": args,
			"prompt": map[string]any{"arg": "name", "label": "Name for this session (up to 64 characters; leave empty to remove the name)", "value": cur}}}
		if named {
			actions = append(actions, map[string]any{"label": "Clear name", "op": "rename", "args": map[string]any{"device": r.d.ID, "session_id": args["session_id"], "name": ""}, "danger": true})
		}
		items = append(items, map[string]any{
			"title":   firstNonEmpty(cur, oneLine(r.x.Title, 80), r.x.Cwd, r.x.SessionID),
			"detail":  oneLine(fmt.Sprintf("%s · %s · %s · %s%s", firstNonEmpty(r.d.Name, r.d.ID), firstNonEmpty(r.x.RepoKey, r.x.Cwd), r.x.Role, r.x.State, ifElse(named, " · title: "+r.x.Title, "")), 300),
			"actions": actions})
	}
	for _, a := range s.st.aliases() {
		if seen[a.Device+"|"+foldName(a.Name)] || !listed[a.Device] {
			continue
		}
		items = append(items, map[string]any{"title": a.Name,
			"detail":  fmt.Sprintf("%s · its session isn't listed (last seen %s)", firstNonEmpty(a.DeviceName, a.Device), a.Seen.Format(time.DateOnly)),
			"actions": []map[string]any{{"label": "Remove name", "op": "rename", "args": map[string]any{"device": a.Device, "forget": a.Name}, "danger": true}}})
	}
	return items, note
}

func ifElse(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

// nameSessions is the full session list (archived included) the name page shows. The page reloads itself every
// 30 seconds, so the last list is reused for nameListReuse; a rename or a clear drops it.
func (s *sisters) nameSessions(ctx context.Context, h sisterHost) ([]deviceSessions, error) {
	s.mu.Lock()
	if s.nameList != nil && s.now().Sub(s.nameListAt) < nameListReuse {
		all := s.nameList
		s.mu.Unlock()
		return all, nil
	}
	s.mu.Unlock()
	all, err := listSessions(ctx, h, "", true)
	if err != nil {
		return nil, err
	}
	ok := true
	for _, ds := range all {
		ok = ok && ds.err == nil
	}
	if ok { // a computer that didn't answer is not cached: the page asks again soon
		s.mu.Lock()
		s.nameList, s.nameListAt = all, s.now()
		s.mu.Unlock()
	}
	return all, nil
}

func (s *sisters) dropNameList() {
	s.mu.Lock()
	s.nameList = nil
	s.mu.Unlock()
}
