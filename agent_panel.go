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
	"regexp"
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
	return []map[string]any{{"title": "Claude in project VMs", "note": "Claude run through the Agent SDK in a VM per project on your computer: the running sessions and queue, sessions with their chat, usage modes, usage and sign-in.", "empty": "",
		"items": []map[string]any{
			{"title": "Projects and sessions", "detail": "Each project's sessions with the running ones marked, what is waiting and why, and a button to start a new session.", "actions": []map[string]any{{"label": "Open", "open": panelPage{Page: pageAgent}.open()}}},
			{"title": "Usage modes", "detail": "How much each Bot may run at once: Maximum, Medium (Recommended) or Light. Only you change it.", "actions": []map[string]any{{"label": "Open", "open": panelPage{Page: pageModes}.open()}}},
			{"title": "Usage and sign-in", "detail": "Today's estimate and whether Claude is signed in.", "actions": []map[string]any{{"label": "Open", "open": panelPage{Page: pageUsage}.open()}}},
		}}}
}

// agentSlot is a running top-level session (claude-agent.status "slots").
type agentSlot struct {
	Project    string `json:"project"`
	Session    string `json:"session"`
	Bot        string `json:"bot"`
	Busy       bool   `json:"busy"`
	Background int    `json:"background"`
	Subagents  int    `json:"subagents"`
}

// botUsage is one Bot's row of claude-agent.status "usage.bots".
type botUsage struct {
	ID                  string `json:"id"`
	Mode                string `json:"mode"`
	Custom              bool   `json:"custom"`
	SessionsRunning     int    `json:"sessions_running"`
	SessionsLimit       int    `json:"sessions_limit"`
	SubagentsPerSession int    `json:"subagents_per_session"`
}

type agentStatus struct {
	Login json.RawMessage `json:"login"`
	// Slot is the single slot of an older Rubi Home (the first busy one); Slots and Limits are the per-project
	// slots of a newer one (nil Slots = an older Home).
	Slot struct {
		Busy    bool   `json:"busy"`
		Project string `json:"project"`
		Session string `json:"session"`
	} `json:"slot"`
	Slots  []agentSlot `json:"slots"`
	Limits struct {
		PerProject int `json:"per_project"`
		Total      int `json:"total"` // on the computer, 0 = no cap
	} `json:"limits"`
	Usage struct {
		Default string     `json:"default"`
		Bots    []botUsage `json:"bots"`
	} `json:"usage"`
	Queue []struct {
		Project  string `json:"project"`
		Session  string `json:"session"`
		Op       string `json:"op"`
		From     string `json:"from"`
		Position int    `json:"position"`
		Reason   string `json:"reason"`
	} `json:"queue"`
	UsageToday json.RawMessage `json:"usage_today"`
}

// slotList is the running sessions: "slots", else the older single "slot".
func (st agentStatus) slotList() []agentSlot {
	if st.Slots != nil || !st.Slot.Busy {
		return st.Slots
	}
	return []agentSlot{{Project: st.Slot.Project, Session: st.Slot.Session, Busy: true}}
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
	case pageModes:
		return s.modesPage(ctx, h)
	}
	return nil, fmt.Errorf("unknown page %q", p.Page)
}

var upMain = map[string]any{"label": "Claude Code", "open": map[string]any{}}

const maxProjectSessions = 12 // the sessions one project's section lists; Manage shows the rest

// projectsPage lists the sessions grouped by project, one section per project, the running ones marked, with
// what waits in the queue and why, and a button to start a new session in the project.
func (s *sisters) projectsPage(ctx context.Context, h sisterHost) (any, error) {
	var sections []map[string]any
	for _, d := range s.agentDevices(ctx, h) {
		lctx, cancel := context.WithTimeout(ctx, panelListTimeout)
		lists := s.listAgent(lctx, h, d.ID)
		cancel()
		if len(lists) == 0 || lists[0].err != nil && len(lists[0].projects) == 0 {
			msg := "no answer"
			if len(lists) > 0 {
				msg = oneLine(lists[0].err.Error(), 160)
			}
			sections = append(sections, map[string]any{"title": d.Name, "empty": "Couldn't read the projects: " + msg})
			continue
		}
		ad := lists[0]
		st, serr := s.agentStatus(ctx, h, d.ID)
		running := st.slotList()
		summary := map[string]any{"title": d.Name, "empty": ""}
		switch {
		case serr != nil:
			summary["note"] = "Couldn't read the running sessions: " + oneLine(serr.Error(), 160)
		default:
			total := "no cap"
			if st.Limits.Total > 0 {
				total = fmt.Sprint(st.Limits.Total)
			}
			note := fmt.Sprintf("%d session%s running of %s on this computer", len(running), ifElse(len(running) == 1, "", "s"), total)
			if st.Limits.PerProject > 0 {
				note += fmt.Sprintf(", %d at a time per project", st.Limits.PerProject)
			}
			summary["note"] = note + ". A new session over a limit waits in the queue and says what it waits for."
		}
		sections = append(sections, summary)
		for _, pr := range ad.projects {
			var items []map[string]any
			var mine []agentSess
			for _, x := range ad.sessions {
				if x.Project == pr.ID {
					mine = append(mine, x)
				}
			}
			slices.SortStableFunc(mine, func(a, b agentSess) int { return b.LastActivity.Compare(a.LastActivity) })
			more := 0
			if len(mine) > maxProjectSessions {
				more, mine = len(mine)-maxProjectSessions, mine[:maxProjectSessions]
			}
			for _, x := range mine {
				var slot *agentSlot
				for i := range running {
					if running[i].Project == pr.ID && running[i].Session == x.ID {
						slot = &running[i]
					}
				}
				state := "idle"
				switch {
				case slot != nil:
					state = "RUNNING now"
					if slot.Subagents > 0 {
						state += fmt.Sprintf(" · %d subagent%s", slot.Subagents, ifElse(slot.Subagents == 1, "", "s"))
					}
				case x.Busy:
					state = "busy"
				}
				items = append(items, map[string]any{"title": s.sessLabel(d.ID, x), "detail": oneLine(fmt.Sprintf("%s · mode %s", state, firstNonEmpty(x.Mode, "unknown")), 200),
					"actions": []map[string]any{{"label": "Open chat", "open": panelPage{Page: pageChat, Device: d.ID, Project: pr.ID, Session: x.ID}.open()}}})
			}
			for _, sl := range running { // a running session the list doesn't have yet (just started)
				if sl.Project != pr.ID {
					continue
				}
				seen := false
				for _, x := range mine {
					seen = seen || x.ID == sl.Session
				}
				if !seen && sl.Session != "" && more == 0 {
					items = append(items, map[string]any{"title": oneLine(sl.Session, 60), "detail": "RUNNING now",
						"actions": []map[string]any{{"label": "Open chat", "open": panelPage{Page: pageChat, Device: d.ID, Project: pr.ID, Session: sl.Session}.open()}}})
				}
			}
			for _, q := range st.Queue {
				if q.Project != pr.ID {
					continue
				}
				what := "a new session"
				if q.Op == "send" || q.Op == "" && q.Session != "" {
					name := q.Session
					for _, x := range mine {
						if x.ID == q.Session {
							name = s.sessLabel(d.ID, x)
						}
					}
					what = "a message to " + oneLine(name, 40)
				}
				items = append(items, map[string]any{"title": fmt.Sprintf("Waiting #%d: %s", max(q.Position, 1), what),
					"detail": oneLine(firstNonEmpty(q.Reason, "waiting for a free place")+ifElse(q.From != "", " · from "+oneLine(q.From, 40), " · from you"), 300), "warn": true})
			}
			if pr.Queue > 0 && len(st.Queue) == 0 {
				items = append(items, map[string]any{"title": fmt.Sprintf("%d waiting in the queue", pr.Queue), "detail": "Rubi Home gave no reason."})
			}
			title := firstNonEmpty(pr.Dir, pr.ID)
			note := fmt.Sprintf("VM: %s · %d running", firstNonEmpty(pr.VMState, "unknown"), countProject(running, pr.ID))
			if pr.SessionsRunning > countProject(running, pr.ID) { // an older reading of the same
				note = fmt.Sprintf("VM: %s · %d running", firstNonEmpty(pr.VMState, "unknown"), pr.SessionsRunning)
			}
			if st.Limits.PerProject > 0 {
				note += fmt.Sprintf(" of %d at a time", st.Limits.PerProject)
			}
			if more > 0 {
				note += fmt.Sprintf(" · %d older sessions are under Manage", more)
			}
			sections = append(sections, map[string]any{"title": title, "note": note, "empty": "No sessions yet.", "items": items,
				"actions": []map[string]any{
					{"label": "New session", "op": "new", "args": panelPage{Device: d.ID, Project: pr.ID}.args(),
						"prompt": map[string]any{"arg": "text", "label": "First message for Claude in this project (sent as you)", "value": ""}},
					{"label": "Manage", "open": panelPage{Page: pageSessions, Device: d.ID, Project: pr.ID}.open()},
				}})
		}
	}
	if len(sections) == 0 {
		sections = []map[string]any{{"title": "Projects", "empty": "No computer reports the claude-agent capability."}}
	}
	return map[string]any{"title": "Claude in project VMs", "refresh": 15, "up": upMain, "sections": sections}, nil
}

func countProject(slots []agentSlot, project string) int {
	n := 0
	for _, sl := range slots {
		if sl.Project == project {
			n++
		}
	}
	return n
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

// senderLine is the first line the runner writes into a message that came from a Bot or a local sender.
var senderLine = regexp.MustCompile(`^\s*\[message from ([^\]\n]{0,200})\][ \t]*\n?`)

// senderAuthor names a sender for the chat: "Bot: x" (a sender that says what it is, like "local: x", keeps it).
func senderAuthor(from string) string {
	from = oneLine(from, 60)
	if from == "" {
		return "unknown sender"
	}
	if strings.HasPrefix(from, "local:") || strings.HasPrefix(from, "Bot:") {
		return from
	}
	return "Bot: " + from
}

// chatItems reads the runner's messages. A user-role message is the user's own only when it has no `from` and its
// text does not start with the runner's "[message from X]" line (docs/design/agent-runner.md); anything with
// either, and any shape this does not know, is shown as another sender's and as untrusted text. Tool calls become
// one-line summaries; tool results are not shown.
func chatItems(raw []json.RawMessage) []chatItem {
	var out []chatItem
	emit := func(it chatItem) {
		it.Text = clipRunes(it.Text, chatTextRunes)
		it.Author = oneLine(it.Author, 80)
		out = append(out, it)
	}
	for _, r := range raw {
		var m rawMessage
		if json.Unmarshal(r, &m) != nil {
			emit(chatItem{Role: "sister", Author: "unknown sender", Untrusted: true, Text: "(a message in a shape the panel doesn't know)"})
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
		var texts []string
		var blocks []contentBlock
		if m.Text != "" {
			texts = append(texts, m.Text)
		}
		if len(inner.Content) > 0 {
			var str string
			if json.Unmarshal(inner.Content, &str) == nil {
				texts = append(texts, str)
			} else {
				_ = json.Unmarshal(inner.Content, &blocks)
			}
		}
		for _, b := range blocks {
			if b.Type == "text" {
				texts = append(texts, b.Text)
			}
		}
		for _, text := range texts {
			if strings.TrimSpace(text) == "" {
				continue
			}
			it := chatItem{Text: text}
			switch role {
			case "assistant":
				it.Role, it.Author = "assistant", "Claude"
			case "user":
				sender := from
				if mm := senderLine.FindStringSubmatch(text); mm != nil {
					sender, it.Text = firstNonEmpty(from, mm[1]), text[len(mm[0]):]
					if sender == "" {
						sender = "unknown"
					}
				}
				if sender != "" {
					it.Role, it.Author, it.Untrusted = "sister", senderAuthor(sender), true
				} else {
					it.Role, it.Author = "user", "you"
				}
			default: // a role this does not know: not the user's, not Claude's
				it.Role, it.Author, it.Untrusted = "sister", "unknown sender", true
			}
			emit(it)
		}
		if role == "assistant" {
			for _, b := range blocks {
				if b.Type == "tool_use" {
					emit(chatItem{Role: "tool", Text: oneLine(b.Name+": "+toolDetail(b.Name, b.Input), 300)})
				}
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
		if usd, tok, ok := parseUsage(st.UsageToday); ok {
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
	action := strings.TrimPrefix(op, "claude-agent.")
	if err := h.HomeCall(cctx, device, op, map[string]any{"project": project, "id": id}, nil); err != nil {
		h.Audit(auditPanelAgent, map[string]any{"action": action, "device": device, "project": project, "session": id, "by": "user", "failed": oneLine(err.Error(), 160)})
		return nil, err
	}
	h.Audit(auditPanelAgent, map[string]any{"action": action, "device": device, "project": project, "session": id, "by": "user"})
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
	lctx, lcancel := context.WithTimeout(ctx, panelListTimeout)
	defer lcancel()
	ref, found, err := s.resolveAgent(lctx, h, device, project, id, "")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("no such agent session")
	}
	device, project, id = ref.ad.device.ID, ref.proj.ID, ref.sess.ID
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
