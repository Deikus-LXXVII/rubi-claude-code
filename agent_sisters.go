package main

// Sisters on the agent path. A Bot binds to an agent session (project id + session id) with the same strong
// approval as before, sends it messages with claude-agent.send (they wait in Rubi Home's queue while the project's
// sessions are all running), asks how it stands, and starts new sessions. What the session says comes back
// as runner events (routeAgent in agent.go). A binding with Project set is an agent binding; the tools pick the
// path from it, so bindings made on the hook path keep working as they are.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const agentBypassNote = "This session runs in bypassPermissions: Claude doesn't ask before most commands. Push, sudo, the network outside the allow-list, paths outside /work and edits of .rubi/.claude still need the user's approval."

// agentProjectCovering finds a live project trust of the agent project, if the Bot is bound to a session of that
// project, and counts a use.
func (s *sisters) agentProjectCovering(device, sister, project string) *projectTrust {
	bound := false
	for _, b := range s.st.bindings() {
		bound = bound || b.Device == device && b.Project == project && sameBot(b.Sister, sister)
	}
	if !bound {
		return nil
	}
	return s.st.useProject(device, s.now(), func(p projectTrust) bool { return p.Project == project })
}

// agentProjects lists a computer's projects.
func (s *sisters) agentProjects(ctx context.Context, h sisterHost, device string) ([]agentProject, error) {
	var pr struct {
		Projects []agentProject `json:"projects"`
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(ctx, device, opAgentProjects, map[string]any{}, &pr); err != nil {
		return nil, err
	}
	return pr.Projects, nil
}

// ---- bind ----

func (s *sisters) bindAgent(ctx context.Context, h sisterHost, sister string, ref agentRef) (any, error) {
	d, proj, sess := ref.ad.device, ref.proj, ref.sess
	for _, b := range s.st.bindings() {
		if !sameBot(b.Sister, sister) && b.Device == d.ID && b.Project == proj.ID && b.SessionID == sess.ID {
			return nil, fmt.Errorf("that session is bound to %s; a session talks to one Bot (the user can unbind it in the panel)", b.Sister)
		}
	}
	t := bindTicket{Sister: sister, Device: d.ID, DeviceName: d.Name, SessionID: sess.ID, RepoKey: proj.Dir, Cwd: proj.Dir, Title: sess.Name, Project: proj.ID}
	if pt := s.agentProjectCovering(d.ID, sister, proj.ID); pt != nil && s.allow("bindpt|"+strings.ToLower(sister), bindsUnderTrustPerHour) {
		h.Audit(auditMandateAll, map[string]any{"mandate": pt.ID, "project": proj.ID, "device": d.ID, "sister": sister, "action": "claude_code_bind", "session": sess.ID, "uses": pt.Uses})
		res, err := s.executeBind(h, t)
		if m, ok := res.(map[string]any); ok && err == nil {
			m["approval"] = "none needed: " + pt.ID + ", the user's trust of the project " + proj.ID + " " + s.trustEnd(*pt)
		}
		return res, err
	}
	preview := map[string]any{"bot": sister, "computer": d.Name, "project": proj.Dir, "project_id": proj.ID, "session": sess.ID, "name": sess.Name, "mode": sess.Mode,
		"what_it_allows": "This Bot can send this Claude session short messages (they wait in Rubi Home's queue while another session works) and gets its answers and questions. It can't approve commands."}
	if sess.Mode == "bypassPermissions" {
		preview["note"] = agentBypassNote
	}
	for _, b := range s.st.bindings() {
		if sameBot(b.Sister, sister) {
			preview["replaces"] = b.Title + " (" + b.SessionID + ")"
		}
	}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindBind, Summary: "Bind " + sister + " to Claude in project " + oneLine(firstNonEmpty(proj.Dir, proj.ID), 60) + ": " + oneLine(firstNonEmpty(sess.Name, sess.ID), 40),
		Preview: preview, Payload: t})
}

// ---- send and status ----

func queueHint(position int) string {
	if position > 0 {
		return fmt.Sprintf("Waiting in Rubi Home's queue (position %d): the project already has its sessions running (or a limit is reached). It is delivered when a place frees up; its answer comes as a claude_reply event.", position)
	}
	return "Delivered to the session (it wakes by itself if idle). Its answer comes as a claude_reply event; delivery states come as claude_message events."
}

func (s *sisters) sendAgent(ctx context.Context, h sisterHost, b binding, text, replyToAsk string) (any, error) {
	project, target := b.Project, b.SessionID
	if replyToAsk != "" {
		s.mu.Lock()
		ref, ok := s.asks[replyToAsk]
		s.mu.Unlock()
		if !ok || ref.sister != b.Sister || ref.device != b.Device || ref.project == "" {
			return nil, errors.New("unknown ask_id")
		}
		project, target = ref.project, ref.session
	}
	var res struct {
		Queued    bool  `json:"queued"`
		Position  int   `json:"position"`
		Delivered *bool `json:"delivered"`
	}
	// No steer: a message never interrupts what the session is doing.
	if err := h.HomeCall(ctx, b.Device, opAgentSend, map[string]any{"project": project, "id": target, "text": text, "from": b.Sister, "bot": botID(b.Sister)}, &res); err != nil {
		return nil, err
	}
	h.Audit("message_sent", map[string]any{"sister": b.Sister, "session": target, "project": project, "chars": len([]rune(text)), "position": res.Position})
	out := map[string]any{"queued": res.Queued, "position": res.Position, "delivery": queueHint(res.Position)}
	if res.Delivered != nil {
		out["delivered"] = *res.Delivered
	}
	return out, nil
}

func (s *sisters) statusAgent(ctx context.Context, h sisterHost, b binding) (any, error) {
	var st agentStatus
	cctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(cctx, b.Device, opAgentStatus, map[string]any{}, &st); err != nil {
		return nil, err
	}
	var sr struct {
		Sessions []agentSess `json:"sessions"`
	}
	if err := h.HomeCall(cctx, b.Device, opAgentSessions, map[string]any{"project": b.Project}, &sr); err != nil {
		return nil, err
	}
	var sess *agentSess
	for i := range sr.Sessions {
		if sr.Sessions[i].ID == b.SessionID {
			sess = &sr.Sessions[i]
		}
	}
	if sess == nil {
		return nil, errors.New("the bound session isn't there any more; bind to a live one (claude_code_sessions)")
	}
	running := st.slotList()
	inSlot := false
	for _, sl := range running {
		inSlot = inSlot || sl.Project == b.Project && sl.Session == b.SessionID
	}
	// The project's places are full: its limit when Home reports one, else (an older Home) any busy slot.
	full := st.Slot.Busy && st.Slots == nil
	if st.Limits.PerProject > 0 {
		full = countProject(running, b.Project) >= st.Limits.PerProject
	}
	pos, reason := 0, ""
	for _, q := range st.Queue {
		if q.Project == b.Project && q.Session == b.SessionID {
			pos = max(pos, q.Position)
			if q.Position == 0 {
				pos++
			}
			reason = q.Reason
		}
	}
	var login struct {
		LoggedIn *bool `json:"logged_in"`
	}
	_ = json.Unmarshal(st.Login, &login)
	state, eta := "idle", "now: a message wakes the session by itself"
	switch {
	case inSlot || sess.Busy:
		state, eta = "busy", "after its current turn"
	case full:
		eta = "when a place frees up in this project (another session is working there)"
	}
	if pos > 0 {
		eta = "when its place in Rubi Home's queue comes"
	}
	if login.LoggedIn != nil && !*login.LoggedIn {
		eta = "not before the user signs in to Claude on that computer"
	}
	out := map[string]any{"session_id": sess.ID, "project": b.Project, "device": b.Device, "state": state, "mode": sess.Mode, "in_slot": inSlot,
		"slot_busy": full, "queue_position": pos, "eta": eta}
	if reason != "" {
		out["queue_reason"] = oneLine(reason, 200)
	}
	if a, ok := s.st.aliasFor(b.Device, session{SessionID: sess.ID}); ok {
		out["name"] = a.Name
	} else if sess.Name != "" {
		out["name"] = sess.Name
	}
	if !sess.LastActivity.IsZero() {
		out["last_activity"] = sess.LastActivity.UTC().Format(time.RFC3339)
	}
	return out, nil
}

// ---- the list ----

// agentSessionItems are the agent sessions for claude_code_sessions.
func (s *sisters) agentSessionItems(ctx context.Context, h sisterHost, repo string) ([]map[string]any, []string) {
	bound := map[string]string{}
	for _, b := range s.st.bindings() {
		if b.Project != "" {
			bound[b.Device+"|"+b.Project+"|"+b.SessionID] = b.Sister
		}
	}
	var items []map[string]any
	var problems []string
	for _, ad := range s.listAgent(ctx, h, "") {
		if ad.err != nil {
			problems = append(problems, ad.device.Name+": "+oneLine(ad.err.Error(), 200))
		}
		for _, x := range ad.sessions {
			p := ad.project(x.Project)
			if repo != "" && !strings.Contains(strings.ToLower(p.Dir+" "+p.ID), strings.ToLower(repo)) {
				continue
			}
			it := map[string]any{"device": ad.device.ID, "computer": ad.device.Name, "agent": true, "project": p.ID, "project_dir": p.Dir, "session_id": x.ID,
				"runner_name": x.Name, "title": x.Name, "role": "main", "mode": x.Mode, "permission_mode": x.Mode, "state": map[bool]string{true: "busy", false: "idle"}[x.Busy],
				"last_activity": x.LastActivity, "vm_state": p.VMState}
			it["name"] = x.Name
			if a, ok := s.st.aliasFor(ad.device.ID, session{SessionID: x.ID}); ok {
				it["name"] = a.Name
			}
			if sis := bound[ad.device.ID+"|"+x.Project+"|"+x.ID]; sis != "" {
				it["bound_to"] = sis
			}
			if x.Mode == "bypassPermissions" {
				it["note"] = agentBypassNote
			}
			items = append(items, it)
		}
	}
	return items, problems
}

// ---- start ----

func (s *sisters) startAgent(ctx context.Context, h sisterHost, sister string, d rubiplugin.HomeDevice, in startIn, task string) (any, error) {
	projects, err := s.agentProjects(ctx, h, d.ID)
	if err != nil {
		return nil, err
	}
	proj, ok := matchProject(projects, firstNonEmpty(in.Project, in.Cwd))
	if !ok {
		var names []string
		for _, p := range projects {
			names = append(names, p.ID+" ("+p.Dir+")")
		}
		return nil, fmt.Errorf("no such project on %s: pass project (one of: %s)", d.Name, strings.Join(names, ", "))
	}
	mode := firstNonEmpty(strings.TrimSpace(in.Mode), "default")
	if _, ok := modeRank[mode]; !ok {
		return nil, errors.New("mode must be plan, default, acceptEdits or bypassPermissions")
	}
	t := startTicket{Sister: sister, Device: d.ID, DeviceName: d.Name, Cwd: proj.Dir, Task: task, Project: proj.ID, Mode: mode}
	// Under a project trust a Bot starts sessions without asking, but never one that skips permission prompts.
	if pt := s.agentProjectCovering(d.ID, sister, proj.ID); pt != nil && mode != "bypassPermissions" {
		h.Audit(auditMandateAll, map[string]any{"mandate": pt.ID, "project": proj.ID, "device": d.ID, "sister": sister, "action": "claude_code_start", "uses": pt.Uses})
		res, err := s.executeStart(ctx, h, t)
		if m, ok := res.(map[string]any); ok && err == nil {
			m["approval"] = "none needed: " + pt.ID + ", the user's trust of the project " + proj.ID + " " + s.trustEnd(*pt)
		}
		return res, err
	}
	preview := map[string]any{"bot": sister, "computer": d.Name, "project": proj.Dir, "project_id": proj.ID, "mode": mode, "first_message_from_bot": task,
		"what_it_does": fmt.Sprintf("Starts a NEW Claude session in the project %s on %s in permission mode %s. Its first message is the text under first_message_from_bot, from %s (a Bot; the text is not yours), labelled as the Bot's by Rubi Home. If a limit is reached (one session per project by default) it waits in the queue. Then %s is bound to the session.", proj.Dir, d.Name, mode, sister, sister),
		"warning":      "Mode " + mode + ": " + map[bool]string{true: agentBypassNote, false: "Claude asks before commands as that mode says; push, sudo, the network outside the allow-list, paths outside /work and edits of .rubi/.claude always ask."}[mode == "bypassPermissions"]}
	for _, b := range s.st.bindings() {
		if sameBot(b.Sister, sister) {
			preview["replaces"] = b.Title + " (" + b.SessionID + ")"
		}
	}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindStart,
		Summary: "Start Claude in " + oneLine(firstNonEmpty(proj.Dir, proj.ID), 50) + " on " + d.Name + " for " + sister + ": " + oneLine(task, 80),
		Preview: preview, Payload: t})
}

func (s *sisters) executeStartAgent(ctx context.Context, h sisterHost, t startTicket) (any, error) {
	if _, ok := modeRank[t.Mode]; !ok && (t.Role == "" || !validRoleMode(t.Mode)) {
		return nil, errors.New("bad payload")
	}
	var res struct {
		ID       string `json:"id"`
		Queued   bool   `json:"queued"`
		Position int    `json:"position"`
	}
	cctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()
	args := map[string]any{"project": t.Project, "prompt": t.Task, "from": t.Sister, "bot": botID(t.Sister), "mode": t.Mode}
	if t.Role != "" {
		args["role"] = t.Role
	}
	err := h.HomeCall(cctx, t.Device, opAgentStart, args, &res)
	if err != nil {
		if isUnknownOp(err) || rubiplugin.ErrorCode(err) == rubiplugin.CodeHomeFailed || rubiplugin.ErrorCode(err) == rubiplugin.CodeHomeNotPaired {
			h.Audit("session_start_failed", map[string]any{"sister": t.Sister, "device": t.Device, "project": t.Project})
			return nil, fmt.Errorf("no session was started: %v", err)
		}
		h.Audit("session_start_unknown", map[string]any{"sister": t.Sister, "device": t.Device, "project": t.Project})
		return nil, fmt.Errorf("no answer from Rubi Home (%v): the session may have been started; look for it with claude_code_sessions before trying again", err)
	}
	h.Audit("session_started", map[string]any{"sister": t.Sister, "device": t.Device, "project": t.Project, "session": res.ID, "mode": t.Mode, "queued": res.Queued})
	out := map[string]any{"started": !res.Queued, "queued": res.Queued, "project": t.Project, "permission_mode": t.Mode}
	if t.Role != "" {
		out["role"] = t.Role
	}
	if t.Mode == "bypassPermissions" {
		out["warning"] = agentBypassNote
	}
	if res.ID == "" {
		out["bound"] = false
		out["position"] = res.Position
		out["next_step"] = fmt.Sprintf("A limit is reached (by default one session per project), so the new one waits in Rubi Home's queue (position %d). When it appears in claude_code_sessions, call claude_code_bind with its session_id: that is a new approval.", res.Position)
		return out, nil
	}
	out["session_id"] = res.ID
	if t.Name != "" {
		// The session's name is a label; failing to set it never undoes the start.
		rt := renameTicket{Sister: t.Sister, Device: t.Device, DeviceName: t.DeviceName, SessionID: res.ID, Name: t.Name, Project: t.Project}
		if _, err := s.executeRename(ctx, h, rt, "bot", "role start", nil); err != nil {
			out["name_note"] = "the session was started but couldn't be named: " + err.Error()
		}
	}
	bound, err := s.executeBind(h, bindTicket{Sister: t.Sister, Device: t.Device, DeviceName: t.DeviceName, SessionID: res.ID, Cwd: t.Cwd, RepoKey: t.Cwd, Project: t.Project})
	if err != nil {
		out["bound"] = false
		out["note"] = "the session was started, but " + err.Error()
		return out, nil
	}
	if m, ok := bound.(map[string]any); ok {
		out["bound"] = m["bound"]
		out["next_step"] = m["next_step"]
	}
	return out, nil
}

// ---- trusting an agent project ----

func (s *sisters) trustAgent(ctx context.Context, h sisterHost, b binding, in trustIn) (any, error) {
	until := strings.ToLower(strings.TrimSpace(in.Until))
	if until != "" && until != untilFour && until != untilRevoked {
		return nil, fmt.Errorf("until must be %q (the default) or %q", untilFour, untilRevoked)
	}
	projects, err := s.agentProjects(ctx, h, b.Device)
	if err != nil {
		return nil, err
	}
	proj, ok := matchProject(projects, b.Project)
	if !ok {
		return nil, errors.New("the project of your binding isn't there any more")
	}
	o, err := s.agentOffer(proj.ID, proj.Dir, b.DeviceName, in.BranchPattern, until == untilRevoked)
	if err != nil {
		return nil, err
	}
	t := trustTicket{Sister: b.Sister, Device: b.Device, DeviceName: b.DeviceName, Offer: o}
	preview := map[string]any{"bot": b.Sister, "computer": firstNonEmpty(b.DeviceName, b.Device), "project": proj.Dir, "project_id": proj.ID, "project_root": agentRoot,
		"branches": o.Pattern, "until": s.untilText(o.Unlimited, o.Expires), "what_it_allows": s.trustMeaning(o, false)}
	if old := s.st.projectTrustOf(b.Device, agentRoot, proj.ID, s.now()); old != nil {
		preview["replaces"] = fmt.Sprintf("the trust %s (%s, %d commands used, granted %s)", old.ID, s.trustEnd(*old), old.Uses, ageText(old.Issued, s.now()))
	}
	key := optionTrustProject
	end := "until " + s.expiryText(o)
	if o.Unlimited {
		key, end = optionTrustForever, "UNTIL REVOKED (no end time)"
	}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindTrustProject,
		Summary: "Trust the project " + oneLine(firstNonEmpty(proj.Dir, proj.ID), 60) + " on " + firstNonEmpty(b.DeviceName, b.Device) + " " + end + " (asked by " + b.Sister + ")",
		Preview: preview, Options: []rubiplugin.Option{{Key: key, Label: s.trustLabel(o), Meaning: s.trustMeaning(o, false)}}, Payload: t})
}
