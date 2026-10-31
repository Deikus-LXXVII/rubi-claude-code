package main

// The panel pages of the agent path (Claude through the Agent SDK in project VMs): projects, a project's
// sessions, a session's chat, and usage and sign-in. They are pages of the plugin's "view" (the panel asks
// op "view" with args {page, device, project, session_id}; an action's open {..} holds the next page's args).
// Everything on them is the user's own request: no approval, except that a looser mode goes through the
// plugin's strong approval like a Bot's request does (changeMode).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	opAgentMessages  = "claude-agent.messages"
	opAgentInterrupt = "claude-agent.interrupt"
	opAgentClose     = "claude-agent.close"

	pageAgent    = "agent"
	pageSessions = "sessions"
	pageChat     = "chat"
	pageUsage    = "usage"

	chatMessages   = 100  // the last messages the chat shows
	chatTextRunes  = 4000 // one message, cut
	panelSendRunes = 4000 // what the user may send from the chat box
	maxSessItems   = 60

	defaultUsageWarnUSD = 10.0
	auditPanelAgent     = "agent_panel_action"
)

// panelPage is the args of a drill-down page and of the agent actions.
type panelPage struct {
	Page    string
	Device  string
	Project string
	Session string
}

func (p panelPage) open() map[string]any {
	m := map[string]any{"page": p.Page}
	if p.Device != "" {
		m["device"] = p.Device
	}
	if p.Project != "" {
		m["project"] = p.Project
	}
	if p.Session != "" {
		m["session_id"] = p.Session
	}
	return m
}

func (p panelPage) args() map[string]any {
	m := p.open()
	delete(m, "page")
	return m
}

// agentDevices lists the computers with the capability.
func (s *sisters) agentDevices(ctx context.Context, h sisterHost) []rubiplugin.HomeDevice {
	devs, err := h.HomeDevices()
	if err != nil {
		return nil
	}
	var out []rubiplugin.HomeDevice
	for _, d := range devs {
		if s.agentCapable(ctx, h, d.ID) {
			out = append(out, d)
		}
	}
	return out
}

// agentLinkSection is the entry on the plugin's main page; empty when no computer has the capability.
func (s *sisters) agentLinkSection(ctx context.Context, h sisterHost) []map[string]any {
	ctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	if len(s.agentDevices(ctx, h)) == 0 {
		return nil
	}
	return []map[string]any{{"title": "Claude in project VMs", "note": "Claude run through the Agent SDK in a VM per project on your computer: the agent slot and queue, sessions with their chat, usage and sign-in.", "empty": "",
		"items": []map[string]any{
			{"title": "Projects and sessions", "detail": "VM state, who holds the agent slot, the queue, and each project's sessions.", "actions": []map[string]any{{"label": "Open", "open": panelPage{Page: pageAgent}.open()}}},
			{"title": "Usage and sign-in", "detail": "Today's estimate and whether Claude is signed in.", "actions": []map[string]any{{"label": "Open", "open": panelPage{Page: pageUsage}.open()}}},
		}}}
}

type agentStatus struct {
	Login json.RawMessage `json:"login"`
	Slot  struct {
		Busy    bool   `json:"busy"`
		Project string `json:"project"`
		Session string `json:"session"`
	} `json:"slot"`
	Queue []struct {
		Project  string `json:"project"`
		Session  string `json:"session"`
		Position int    `json:"position"`
	} `json:"queue"`
	Usage json.RawMessage `json:"usage_today"`
}

func (s *sisters) agentStatus(ctx context.Context, h sisterHost, device string) (agentStatus, error) {
	var st agentStatus
	ctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	err := h.HomeCall(ctx, device, opAgentStatus, map[string]any{}, &st)
	return st, err
}

// sessLabel is what a session is called on the pages: the user's or a Bot's alias, else the runner's name, else the id.
func (s *sisters) sessLabel(device string, x agentSess) string {
	if a, ok := s.st.aliasFor(device, session{SessionID: x.ID}); ok && a.Name != "" {
		return a.Name
	}
	return firstNonEmpty(oneLine(x.Name, 80), x.ID)
}

// agentPage answers the view of a drill-down page.
func (s *sisters) agentPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	switch p.Page {
	case pageAgent:
		return s.projectsPage(ctx, h)
	case pageSessions:
		return s.sessionsPage(ctx, h, p)
	case pageChat:
		return s.chatPage(ctx, h, p)
	case pageUsage:
		return s.usagePage(ctx, h)
	}
	return nil, fmt.Errorf("unknown page %q", p.Page)
}

var upMain = map[string]any{"label": "Claude Code", "open": map[string]any{}}

func (s *sisters) projectsPage(ctx context.Context, h sisterHost) (any, error) {
	var sections []map[string]any
	for _, d := range s.agentDevices(ctx, h) {
		projects, err := s.agentProjects(ctx, h, d.ID)
		if err != nil {
			sections = append(sections, map[string]any{"title": d.Name, "empty": "Couldn't read the projects: " + oneLine(err.Error(), 160)})
			continue
		}
		st, serr := s.agentStatus(ctx, h, d.ID)
		note := ""
		if serr != nil {
			note = "Couldn't read the agent slot: " + oneLine(serr.Error(), 160)
		}
		var items []map[string]any
		for _, pr := range projects {
			detail := "VM: " + firstNonEmpty(pr.VMState, "unknown")
			switch {
			case st.Slot.Busy && st.Slot.Project == pr.ID:
				detail += " · agent slot: busy with " + oneLine(firstNonEmpty(s.st.nameOf(d.ID, st.Slot.Session), st.Slot.Session), 60)
			case st.Slot.Busy:
				detail += " · agent slot: held by another project"
			case serr == nil:
				detail += " · agent slot: free"
			}
			var waiting []string
			for _, q := range st.Queue {
				if q.Project == pr.ID {
					waiting = append(waiting, fmt.Sprintf("#%d %s", max(q.Position, 1), oneLine(firstNonEmpty(s.st.nameOf(d.ID, q.Session), q.Session), 40)))
				}
			}
			switch {
			case len(waiting) > 0:
				detail += " · queue: " + strings.Join(waiting, ", ")
			case pr.Queue > 0:
				detail += fmt.Sprintf(" · %d waiting in the queue", pr.Queue)
			}
			items = append(items, map[string]any{"title": firstNonEmpty(pr.Dir, pr.ID), "detail": oneLine(detail, 400),
				"actions": []map[string]any{{"label": "Sessions", "open": panelPage{Page: pageSessions, Device: d.ID, Project: pr.ID}.open()}}})
		}
		sections = append(sections, map[string]any{"title": d.Name, "note": note, "empty": "No projects.", "items": items})
	}
	if len(sections) == 0 {
		sections = []map[string]any{{"title": "Projects", "empty": "No computer reports the claude-agent capability."}}
	}
	return map[string]any{"title": "Claude in project VMs", "refresh": 15, "up": upMain, "sections": sections}, nil
}

func (s *sisters) sessionsPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	if p.Device == "" || p.Project == "" {
		return nil, errors.New("no project")
	}
	lctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	ads := s.listAgent(lctx, h, p.Device)
	if len(ads) == 0 {
		return nil, errors.New("that computer doesn't report the claude-agent capability")
	}
	ad := ads[0]
	if ad.err != nil && len(ad.sessions) == 0 {
		return nil, errors.New("couldn't read the sessions: " + oneLine(ad.err.Error(), 160))
	}
	proj := ad.project(p.Project)
	var list []agentSess
	for _, x := range ad.sessions {
		if x.Project == proj.ID {
			list = append(list, x)
		}
	}
	slices.SortStableFunc(list, func(a, b agentSess) int { return b.LastActivity.Compare(a.LastActivity) })
	note := "Sessions of this project. A stricter mode applies at once; a looser one asks for your strong approval."
	if len(list) > maxSessItems {
		note += fmt.Sprintf(" Showing %d of %d: the most recent.", maxSessItems, len(list))
		list = list[:maxSessItems]
	}
	var items []map[string]any
	for _, x := range list {
		base := panelPage{Device: p.Device, Project: proj.ID, Session: x.ID}
		sister := ""
		for _, b := range s.st.bindings() {
			if b.Device == p.Device && b.Project == proj.ID && b.SessionID == x.ID {
				sister = b.Sister
			}
		}
		state := "idle"
		if x.Busy {
			state = "busy"
		}
		detail := fmt.Sprintf("Sister: %s · mode %s · %s", firstNonEmpty(oneLine(sister, 60), "none"), firstNonEmpty(x.Mode, "unknown"), state)
		cur := ""
		if a, ok := s.st.aliasFor(p.Device, session{SessionID: x.ID}); ok {
			cur = a.Name
		}
		actions := []map[string]any{
			{"label": "Open chat", "open": panelPage{Page: pageChat, Device: p.Device, Project: proj.ID, Session: x.ID}.open()},
			{"label": "Rename", "op": "rename", "args": base.args(), "prompt": map[string]any{"arg": "name", "label": "Name for this session (up to 64 characters; leave empty to remove the name)", "value": cur}},
			{"label": "Fork", "op": "fork", "args": base.args(), "confirm": "Make a branch of this conversation as a new, idle session?"},
		}
		if x.Busy {
			actions = append(actions, map[string]any{"label": "Interrupt", "op": "interrupt", "args": base.args()})
		}
		cr, known := modeRank[x.Mode]
		for _, m := range []string{"plan", "default", "acceptEdits", "bypassPermissions"} {
			if m == x.Mode {
				continue
			}
			label := "Mode: " + m
			if !known || modeRank[m] > cr {
				label += " (asks you)"
			}
			args := base.args()
			args["mode"] = m
			actions = append(actions, map[string]any{"label": label, "op": "mode", "args": args})
		}
		actions = append(actions, map[string]any{"label": "Close", "op": "close", "args": base.args(), "danger": true, "confirm": "Close this session? Its history stays; it stops running."})
		items = append(items, map[string]any{"title": s.sessLabel(p.Device, x), "detail": oneLine(detail, 300), "actions": actions})
	}
	return map[string]any{"title": firstNonEmpty(oneLine(proj.Dir, 80), proj.ID) + ": sessions", "refresh": 15,
		"up":       map[string]any{"label": "Projects", "open": panelPage{Page: pageAgent}.open()},
		"sections": []map[string]any{{"title": "Sessions", "note": note, "empty": "No sessions.", "items": items}}}, nil
}

// chatItem is one line of the chat as the panel draws it.
type chatItem struct {
	Role      string `json:"role"`
	Author    string `json:"author,omitempty"`
	Text      string `json:"text"`
	Untrusted bool   `json:"untrusted,omitempty"`
}

type rawMessage struct {
	Type    string          `json:"type"`
	Role    string          `json:"role"`
	From    string          `json:"from"`
	Text    string          `json:"text"`
	Message json.RawMessage `json:"message"`
}

type contentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// chatItems reads the runner's messages leniently (the SDK's shape: {type, message:{role, content}}, plus the
// sender Home recorded as from). A message from a sister is marked as such and as untrusted text; text is never
// interpreted. Tool calls become one-line summaries; tool results are not shown.
func chatItems(raw []json.RawMessage) []chatItem {
	var out []chatItem
	for _, r := range raw {
		var m rawMessage
		if json.Unmarshal(r, &m) != nil {
			continue
		}
		role := firstNonEmpty(m.Type, m.Role)
		var inner struct {
			Role    string          `json:"role"`
			From    string          `json:"from"`
			Content json.RawMessage `json:"content"`
		}
		if len(m.Message) > 0 {
			_ = json.Unmarshal(m.Message, &inner)
			role = firstNonEmpty(role, inner.Role)
		}
		from := firstNonEmpty(m.From, inner.From)
		text := m.Text
		var blocks []contentBlock
		if len(inner.Content) > 0 {
			var s string
			if json.Unmarshal(inner.Content, &s) == nil {
				text = firstNonEmpty(text, s)
			} else {
				_ = json.Unmarshal(inner.Content, &blocks)
			}
		}
		emit := func(it chatItem) {
			it.Text = clipRunes(it.Text, chatTextRunes)
			it.Author = oneLine(it.Author, 60)
			out = append(out, it)
		}
		who := func() chatItem {
			switch {
			case role == "assistant":
				return chatItem{Role: "assistant", Author: "Claude"}
			case from != "":
				return chatItem{Role: "sister", Author: from, Untrusted: true}
			}
			return chatItem{Role: "user", Author: "you"}
		}
		if strings.TrimSpace(text) != "" {
			it := who()
			it.Text = text
			emit(it)
		}
		for _, b := range blocks {
			switch b.Type {
			case "text":
				if strings.TrimSpace(b.Text) != "" {
					it := who()
					it.Text = b.Text
					emit(it)
				}
			case "tool_use":
				emit(chatItem{Role: "tool", Text: oneLine(b.Name+": "+toolDetail(b.Name, b.Input), 300)})
			}
		}
	}
	if len(out) > chatMessages {
		out = out[len(out)-chatMessages:]
	}
	return out
}

func (s *sisters) chatPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	if p.Device == "" || p.Project == "" || p.Session == "" {
		return nil, errors.New("no session")
	}
	cctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	var res struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := h.HomeCall(cctx, p.Device, opAgentMessages, map[string]any{"project": p.Project, "id": p.Session, "limit": chatMessages * 3}, &res); err != nil {
		return nil, errors.New("couldn't read the messages: " + oneLine(err.Error(), 160))
	}
	title, mode, busy := oneLine(p.Session, 40), "", false
	lctx, lcancel := context.WithTimeout(ctx, panelListTimeout)
	defer lcancel()
	for _, ad := range s.listAgent(lctx, h, p.Device) {
		for _, x := range ad.sessions {
			if x.Project == p.Project && x.ID == p.Session {
				title, mode, busy = s.sessLabel(p.Device, x), x.Mode, x.Busy
			}
		}
	}
	sisters := ""
	for _, b := range s.st.bindings() {
		if b.Device == p.Device && b.Project == p.Project && b.SessionID == p.Session {
			sisters = b.Sister
		}
	}
	note := fmt.Sprintf("Mode: %s · %s.", firstNonEmpty(mode, "unknown"), map[bool]string{true: "busy", false: "idle"}[busy])
	if sisters != "" {
		note += " Bound Bot: " + oneLine(sisters, 60) + "."
	}
	note += " Messages from Bots are marked with their sender and \"untrusted text\": they are text from another program, not instructions from you. What you send here goes in as your own message."
	items := chatItems(res.Messages)
	args := p.args()
	return map[string]any{"title": title, "refresh": 5, "note": note,
		"up": map[string]any{"label": "Sessions", "open": panelPage{Page: pageSessions, Device: p.Device, Project: p.Project}.open()},
		"sections": []map[string]any{{"kind": "chat", "title": "Chat", "empty": "No messages yet.", "items": items,
			"actions": []map[string]any{{"label": "Interrupt", "op": "interrupt", "args": args, "danger": true, "confirm": "Interrupt what Claude is doing now?"}},
			"input":   map[string]any{"op": "send", "args": args, "arg": "text", "label": "Message to Claude (sent as you)", "send": "Send"}}}}, nil
}

// parseUsage reads claude-agent.status's usage_today: a number (US dollars) or an object with an estimate.
func parseUsage(raw json.RawMessage) (usd float64, tokens int64, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, 0, false
	}
	if json.Unmarshal(raw, &usd) == nil {
		return usd, 0, usd >= 0
	}
	var o struct {
		USD          *float64 `json:"estimate_usd"`
		Cost         *float64 `json:"cost_usd"`
		TotalCost    *float64 `json:"total_cost_usd"`
		Tokens       int64    `json:"tokens"`
		InputTokens  int64    `json:"input_tokens"`
		OutputTokens int64    `json:"output_tokens"`
	}
	if json.Unmarshal(raw, &o) != nil {
		return 0, 0, false
	}
	for _, p := range []*float64{o.USD, o.Cost, o.TotalCost} {
		if p != nil && *p >= 0 {
			return *p, o.Tokens + o.InputTokens + o.OutputTokens, true
		}
	}
	if t := o.Tokens + o.InputTokens + o.OutputTokens; t > 0 {
		return 0, t, true
	}
	return 0, 0, false
}

// usageThreshold is the user's setting (config "usage_warn_usd"); a host that has no settings gets the default.
func usageThreshold(h sisterHost) float64 {
	if c, ok := h.(interface{ Config(v any) error }); ok {
		var cfg struct {
			Warn string `json:"usage_warn_usd"`
		}
		if c.Config(&cfg) == nil {
			var v float64
			if _, err := fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cfg.Warn), "$")), "%g", &v); err == nil && v > 0 {
				return v
			}
		}
	}
	return defaultUsageWarnUSD
}

const signInHint = "To sign in, use Anthropic's own sign-in on the computer that runs Rubi Home (Claude's /login, in the project's setup). Rubi never asks for, sees or stores your password or token, and this page has no sign-in button."

func (s *sisters) usagePage(ctx context.Context, h sisterHost) (any, error) {
	warn := usageThreshold(h)
	var usage, login []map[string]any
	for _, d := range s.agentDevices(ctx, h) {
		st, err := s.agentStatus(ctx, h, d.ID)
		if err != nil {
			usage = append(usage, map[string]any{"title": d.Name, "detail": "Couldn't read the status: " + oneLine(err.Error(), 160)})
			continue
		}
		if usd, tok, ok := parseUsage(st.Usage); ok {
			it := map[string]any{"title": fmt.Sprintf("%s: about $%.2f today", d.Name, usd)}
			detail := "An estimate; Anthropic's own numbers are the real ones."
			if tok > 0 {
				detail += fmt.Sprintf(" About %d tokens.", tok)
			}
			if usd > warn {
				it["warn"] = true
				it["title"] = fmt.Sprintf("%s: a lot used today, about $%.2f", d.Name, usd)
				detail += fmt.Sprintf(" Above your warning level of $%.2f. Nothing is blocked.", warn)
			}
			it["detail"] = detail
			usage = append(usage, it)
		} else {
			usage = append(usage, map[string]any{"title": d.Name, "detail": "This computer reports no usage yet."})
		}
		var l struct {
			LoggedIn *bool  `json:"logged_in"`
			Account  string `json:"account"`
			Plan     string `json:"plan"`
		}
		_ = json.Unmarshal(st.Login, &l)
		switch {
		case l.LoggedIn == nil:
			login = append(login, map[string]any{"title": d.Name + ": sign-in unknown", "detail": "This computer doesn't report it. " + signInHint})
		case *l.LoggedIn:
			login = append(login, map[string]any{"title": d.Name + ": signed in" + ifElse(l.Plan != "", ", plan "+oneLine(l.Plan, 40), ""),
				"detail": ifElse(l.Account != "", "Account "+oneLine(l.Account, 80)+". ", "") + "Sign-in lives on that computer only."})
		default:
			login = append(login, map[string]any{"title": d.Name + ": not signed in", "detail": signInHint})
		}
	}
	return map[string]any{"title": "Usage and sign-in", "refresh": 60, "up": upMain,
		"sections": []map[string]any{
			{"title": "Today", "note": fmt.Sprintf("A yellow notice shows above $%.2f (set it in the plugin's settings). It never blocks anything.", warn), "empty": "No computer reports the claude-agent capability.", "items": usage},
			{"title": "Sign-in", "empty": "No computer reports the claude-agent capability.", "items": login},
		}}, nil
}

// ---- the actions ----

// panelAgentRename renames or clears an agent session's name for the user.
func (s *sisters) panelAgentRename(ctx context.Context, h sisterHost, device, project, id string, name *string) (any, error) {
	if name == nil {
		return nil, errors.New("this Rubi's panel can't ask for a name; update Rubi")
	}
	lctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	ref, found, err := s.resolveAgent(lctx, h, device, project, id, "")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("no such agent session")
	}
	t := renameTicket{Device: ref.ad.device.ID, DeviceName: ref.ad.device.Name, SessionID: ref.sess.ID, Project: ref.proj.ID}
	if strings.TrimSpace(*name) == "" {
		t.Clear = true
	} else if t.Name, err = checkAliasName(*name); err != nil {
		return nil, err
	}
	return s.executeRename(ctx, h, t, "user", "panel", asDeviceSessions([]agentDevice{ref.ad}))
}

func (s *sisters) panelAgentFork(ctx context.Context, h sisterHost, device, project, id string) (any, error) {
	lctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	ref, found, err := s.resolveAgent(lctx, h, device, project, id, "")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("no such agent session")
	}
	if _, ok := modeRank[ref.sess.Mode]; !ok {
		return nil, errors.New("Rubi Home didn't report that session's permission mode, so a fork could end up looser than it; try again later")
	}
	return s.executeFork(ctx, h, forkTicket{Device: ref.ad.device.ID, DeviceName: ref.ad.device.Name, Project: ref.proj.ID, SessionID: ref.sess.ID, Mode: ref.sess.Mode})
}

// panelAgentSimple is interrupt and close: one call to Rubi Home, audited.
func (s *sisters) panelAgentSimple(ctx context.Context, h sisterHost, op, device, project, id string) (any, error) {
	if device == "" || project == "" || id == "" {
		return nil, errors.New("no session")
	}
	cctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	if err := h.HomeCall(cctx, device, op, map[string]any{"project": project, "id": id}, nil); err != nil {
		return nil, err
	}
	h.Audit(auditPanelAgent, map[string]any{"action": strings.TrimPrefix(op, "claude-agent."), "device": device, "project": project, "session": id, "by": "user"})
	return map[string]any{"ok": true}, nil
}

// panelAgentSend queues the user's own message (no sender: Rubi Home treats it as the user's).
func (s *sisters) panelAgentSend(ctx context.Context, h sisterHost, device, project, id string, text *string) (any, error) {
	if text == nil {
		return nil, errors.New("this Rubi's panel can't send text; update Rubi")
	}
	t := strings.TrimSpace(*text)
	if t == "" {
		return nil, errors.New("nothing to send")
	}
	if utf8.RuneCountInString(t) > panelSendRunes {
		return nil, fmt.Errorf("at most %d characters", panelSendRunes)
	}
	if device == "" || project == "" || id == "" {
		return nil, errors.New("no session")
	}
	var res struct {
		Queued   bool `json:"queued"`
		Position int  `json:"position"`
	}
	cctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	if err := h.HomeCall(cctx, device, opAgentSend, map[string]any{"project": project, "id": id, "text": t}, &res); err != nil {
		return nil, err
	}
	h.Audit("message_sent", map[string]any{"by": "user", "session": id, "project": project, "chars": utf8.RuneCountInString(t), "position": res.Position})
	return map[string]any{"queued": res.Queued, "position": res.Position}, nil
}

// nameOf is the alias of an agent session, "" when it has none.
func (st *store) nameOf(device, id string) string {
	if a, ok := st.aliasFor(device, session{SessionID: id}); ok {
		return a.Name
	}
	return ""
}
