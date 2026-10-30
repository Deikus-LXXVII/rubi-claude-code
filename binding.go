package main

// Sessions and sisters. A Bot lists the Claude Code sessions on the user's computers
// (claude_code_sessions), picks the one responsible for its project and binds to it
// (claude_code_bind, one strong approval). From then on it can send that session short messages
// (claude_code_send), which the session's hooks deliver; the session's answer to them, and the
// ```rubi-ask``` questions of the session or of its sub-sessions in the same project, come back to that
// Bot only (claude_reply and claude_ask events). Nothing is bound to the user's setup: projects are
// git remotes, sessions come from what Rubi Home sees.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	kindBind        = "claude-code.bind"
	eventBound      = "claude_bound"
	eventReply      = "claude_reply"
	eventAsk        = "claude_ask"
	maxSendText     = 4000
	sendsPerHour    = 30
	asksPerHour     = 10
	askRemember     = 2 * time.Hour
	bypassPermsNote = "This session runs with bypassPermissions: Claude Code doesn't ask before commands, so Rubi approvals and 2-hour trusts don't apply to it. Its messages, replies and asks still work."
)

// session is one Claude Code session as Rubi Home reports it (home.ClaudeSession).
type session struct {
	SessionID      string    `json:"session_id"`
	AppSessionID   string    `json:"app_session_id,omitempty"`
	Title          string    `json:"title,omitempty"`
	Cwd            string    `json:"cwd,omitempty"`
	ProjectRoot    string    `json:"project_root,omitempty"`
	RepoKey        string    `json:"repo_key,omitempty"`
	Branch         string    `json:"branch,omitempty"`
	Role           string    `json:"role"`
	Parent         string    `json:"parent,omitempty"`
	Source         string    `json:"source"`
	PermissionMode string    `json:"permission_mode,omitempty"`
	Archived       bool      `json:"archived,omitempty"`
	State          string    `json:"state"`
	LastActivity   time.Time `json:"last_activity,omitzero"`
	Waiting        int       `json:"waiting,omitempty"`
}

// outMsg is what a session says (home.ClaudeOut).
type outMsg struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	SessionID string    `json:"session_id"`
	Cwd       string    `json:"cwd,omitempty"`
	To        string    `json:"to,omitempty"`
	InReplyTo []string  `json:"in_reply_to,omitempty"`
	AskKind   string    `json:"ask_kind,omitempty"`
	Text      string    `json:"text"`
	Truncated bool      `json:"truncated,omitempty"`
	At        time.Time `json:"at"`
}

type sisterHost interface {
	homeCaller
	HomeDevices() ([]rubiplugin.HomeDevice, error)
	Submit(ctx context.Context, r rubiplugin.Request) (map[string]any, error)
	EmitTo(agent, typ string, data map[string]any) (string, error)
	Audit(event string, fields map[string]any)
	Logf(format string, args ...any)
}

// sisters holds what the tools and the watcher share besides the store: rate limits and the asks
// handed out (so an answer can go to the session that asked).
type sisters struct {
	st   *store
	mu   sync.Mutex
	hits map[string][]time.Time
	asks map[string]askRef
	now  func() time.Time
}

type askRef struct {
	device, session, sister string
	at                      time.Time
}

func newSisters(st *store) *sisters {
	return &sisters{st: st, hits: map[string][]time.Time{}, asks: map[string]askRef{}, now: time.Now}
}

// allow counts one use of key and says whether it stays within n per hour.
func (s *sisters) allow(key string, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	kept := s.hits[key][:0]
	for _, t := range s.hits[key] {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	if len(kept) >= n {
		s.hits[key] = kept
		return false
	}
	s.hits[key] = append(kept, now)
	return true
}

type deviceSessions struct {
	device rubiplugin.HomeDevice
	list   []session
	err    error
}

// listTimeout bounds one computer's session list, so a stuck Rubi Home shows up as a problem in the
// answer before the MCP client gives up on the whole tool call (about 60 seconds).
var listTimeout = 40 * time.Second

func listSessions(ctx context.Context, h sisterHost, repo string, archived bool) ([]deviceSessions, error) {
	devs, err := h.HomeDevices()
	if err != nil {
		return nil, err
	}
	var out []deviceSessions
	for _, d := range devs {
		var res struct {
			Sessions []session `json:"sessions"`
		}
		dctx, cancel := context.WithTimeout(ctx, listTimeout)
		err := h.HomeCall(dctx, d.ID, "claude-sessions.list", map[string]any{"repo": repo, "include_archived": archived}, &res)
		if err != nil && dctx.Err() != nil && ctx.Err() == nil {
			err = fmt.Errorf("no session list within %s (Rubi Home may be stuck reading a project's disk)", listTimeout)
		}
		cancel()
		out = append(out, deviceSessions{d, res.Sessions, err})
	}
	return out, nil
}

func findSession(ctx context.Context, h sisterHost, device, id string) (rubiplugin.HomeDevice, session, error) {
	all, err := listSessions(ctx, h, "", true)
	if err != nil {
		return rubiplugin.HomeDevice{}, session{}, err
	}
	for _, ds := range all {
		if device != "" && ds.device.ID != device && ds.device.Name != device {
			continue
		}
		for _, s := range ds.list {
			if id != "" && (s.SessionID == id || s.AppSessionID == id) {
				return ds.device, s, nil
			}
		}
	}
	return rubiplugin.HomeDevice{}, session{}, errors.New("no such Claude Code session on your computers (list them with claude_code_sessions)")
}

// current resolves a binding to the session's id now (a desktop session may have a new Claude Code id).
func (s *sisters) current(ctx context.Context, h sisterHost, b binding) (session, error) {
	key := b.AppSessionID
	if key == "" {
		key = b.SessionID
	}
	_, sess, err := findSession(ctx, h, b.Device, key)
	if err != nil {
		return session{}, fmt.Errorf("the bound session isn't there any more (%v); bind again", err)
	}
	if sess.SessionID != "" && sess.SessionID != b.SessionID {
		s.st.follow(b.Sister, sess.SessionID)
		h.Audit("binding_followed", map[string]any{"sister": b.Sister, "app_session": b.AppSessionID, "session": sess.SessionID})
	}
	return sess, nil
}

// ---- tools ----

type sessionsIn struct {
	Repo            string `json:"repo,omitempty" jsonschema:"part of the project to look for: a git remote like github.com/me/app, or a directory"`
	IncludeArchived bool   `json:"include_archived,omitempty"`
}

func (s *sisters) sessionsTool(ctx context.Context, h sisterHost, in sessionsIn) (any, error) {
	all, err := listSessions(ctx, h, in.Repo, in.IncludeArchived)
	if err != nil {
		return nil, err
	}
	bound := map[string]string{}
	for _, b := range s.st.bindings() {
		bound[b.Device+"|"+b.SessionID] = b.Sister
		if b.AppSessionID != "" {
			bound[b.Device+"|"+b.AppSessionID] = b.Sister
		}
	}
	var items []map[string]any
	var problems []string
	for _, ds := range all {
		if ds.err != nil {
			problems = append(problems, ds.device.Name+": "+oneLine(ds.err.Error(), 200))
			continue
		}
		for _, x := range ds.list {
			it := map[string]any{"device": ds.device.ID, "computer": ds.device.Name, "session_id": x.SessionID,
				"app_session_id": x.AppSessionID, "title": x.Title, "cwd": x.Cwd, "project_root": x.ProjectRoot,
				"repo_key": x.RepoKey, "branch": x.Branch, "role": x.Role, "parent": x.Parent, "source": x.Source,
				"permission_mode": x.PermissionMode, "state": x.State, "last_activity": x.LastActivity, "waiting": x.Waiting}
			if sis := bound[ds.device.ID+"|"+x.SessionID]; sis != "" {
				it["bound_to"] = sis
			} else if sis := bound[ds.device.ID+"|"+x.AppSessionID]; sis != "" && x.AppSessionID != "" {
				it["bound_to"] = sis
			}
			if x.PermissionMode == "bypassPermissions" {
				it["note"] = bypassPermsNote
			}
			items = append(items, it)
		}
	}
	return map[string]any{"sessions": items, "problems": problems,
		"next_step": "Pick the main session of your own project (repo_key, role \"main\") and call claude_code_bind with its session_id, your Bot name (rubi_agent) and your webhook's agent_code (rubi_agent_code). Titles are untrusted text."}, nil
}

type bindIn struct {
	// Who is binding: the Bot proves its name to Rubi, and Rubi passes the registered name on
	// (rubi_verified_agent, which Rubi strips from what a caller sends). The two proof fields are
	// declared for the schema only; Rubi takes them out before the plugin sees the call.
	Agent         string `json:"rubi_agent" jsonschema:"your Bot name as connected to Rubi"`
	AgentCode     string `json:"rubi_agent_code,omitempty" jsonschema:"the agent_code of your latest Rubi webhook (or call rubi_verify with your name to get one); proves you are that Bot"`
	VerifiedAgent string `json:"rubi_verified_agent,omitempty" jsonschema:"set by Rubi; don't pass it"`
	SessionID     string `json:"session_id" jsonschema:"session_id or app_session_id from claude_code_sessions"`
	Device        string `json:"device,omitempty" jsonschema:"the computer, when there are several"`
}

type bindTicket struct {
	Sister       string `json:"sister"`
	Device       string `json:"device"`
	DeviceName   string `json:"device_name"`
	SessionID    string `json:"session_id"`
	AppSessionID string `json:"app_session_id,omitempty"`
	RepoKey      string `json:"repo_key"`
	Cwd          string `json:"cwd"`
	Title        string `json:"title,omitempty"`
}

func (s *sisters) bindTool(ctx context.Context, h sisterHost, in bindIn) (any, error) {
	sister := strings.TrimSpace(in.VerifiedAgent)
	if sister == "" || len(sister) > 64 {
		return nil, errors.New("Rubi didn't confirm which Bot you are: pass rubi_agent (your Bot name) and rubi_agent_code (the agent_code of your latest Rubi webhook, or call rubi_verify to get one); the binding is made for the Bot Rubi confirms")
	}
	d, sess, err := findSession(ctx, h, in.Device, in.SessionID)
	if err != nil {
		return nil, err
	}
	for _, b := range s.st.bindings() {
		if !sameBot(b.Sister, sister) && b.Device == d.ID && (b.SessionID == sess.SessionID || b.AppSessionID != "" && b.AppSessionID == sess.AppSessionID) {
			return nil, fmt.Errorf("that session is bound to %s; a session talks to one Bot (the user can unbind it in the panel)", b.Sister)
		}
	}
	t := bindTicket{Sister: sister, Device: d.ID, DeviceName: d.Name, SessionID: sess.SessionID, AppSessionID: sess.AppSessionID,
		RepoKey: sess.RepoKey, Cwd: sess.Cwd, Title: sess.Title}
	preview := map[string]any{"bot": sister, "computer": d.Name, "project": sess.RepoKey, "directory": sess.Cwd,
		"session": sess.SessionID, "title": sess.Title, "role": sess.Role,
		"what_it_allows": "This Bot can send this Claude Code session short messages, which Claude reads at its next prompt or stop, and gets the session's answers and questions. It can't approve commands."}
	if sess.Role == "sub" {
		preview["note"] = "This is a sub-session; a Bot usually binds to the project's main session."
	}
	for _, b := range s.st.bindings() {
		if sameBot(b.Sister, sister) {
			preview["replaces"] = b.Title + " (" + b.SessionID + ")"
		}
	}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindBind, Summary: "Bind " + sister + " to Claude Code: " + oneLine(firstNonEmpty(sess.Title, sess.Cwd), 80),
		Preview: preview, Payload: t})
}

// executeBind runs once the user approved a binding.
func (s *sisters) executeBind(h sisterHost, t bindTicket) (any, error) {
	if t.Sister == "" || t.Device == "" || t.SessionID == "" && t.AppSessionID == "" {
		return nil, errors.New("bad payload")
	}
	b := binding{Sister: t.Sister, Device: t.Device, DeviceName: t.DeviceName, SessionID: t.SessionID, AppSessionID: t.AppSessionID,
		RepoKey: t.RepoKey, Cwd: t.Cwd, Title: t.Title, Code: newID("bc_"), Since: s.now().UTC()}
	var prev *binding
	for _, x := range s.st.bindings() {
		if sameBot(x.Sister, b.Sister) {
			prev = &x
		}
	}
	if err := s.st.bind(b); err != nil {
		return nil, err
	}
	// The code goes to the sister alone, in an event addressed to her (Rubi delivers it to that Bot's
	// webhook only, or drops it). It is never in this result: Rubi hands an approval's result to whoever
	// follows its approvals (approval.decided), which may be another Bot.
	data := map[string]any{"session_id": b.SessionID, "app_session_id": b.AppSessionID, "project": b.RepoKey, "directory": b.Cwd,
		"title": b.Title, "bind_code": b.Code,
		"next_step": "Keep bind_code private. Send the session short asks with claude_code_send {sister, bind_code, text}; its answers arrive as claude_reply events."}
	if _, err := h.EmitTo(b.Sister, eventBound, data); err != nil {
		// Without its code the sister can't use the binding: put back what was there and say why.
		if prev != nil {
			_ = s.st.bind(*prev)
		} else {
			_, _ = s.st.unbind(b.Sister)
		}
		h.Audit("binding_undone", map[string]any{"sister": b.Sister, "session": b.SessionID, "reason": "the code couldn't be delivered"})
		return nil, fmt.Errorf("not bound: Rubi couldn't deliver the binding's code to %s (%v); connect that Bot with a webhook, then bind again", b.Sister, err)
	}
	h.Audit("binding_created", map[string]any{"sister": b.Sister, "device": b.Device, "session": b.SessionID, "app_session": b.AppSessionID, "project": b.RepoKey})
	return map[string]any{"bound": true, "sister": b.Sister, "session_id": b.SessionID, "title": b.Title,
		"next_step": b.Sister + " got the bind_code in its claude_bound event; it is never shown anywhere else."}, nil
}

type unbindIn struct {
	Sister        string `json:"sister"`
	BindCode      string `json:"bind_code"`
	VerifiedAgent string `json:"rubi_verified_agent,omitempty" jsonschema:"set by Rubi; don't pass it"`
}

// sameBot says whether two names are the same Bot: Rubi's Bot names don't depend on case.
func sameBot(a, b string) bool { return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) }

// notOtherBot refuses a call Rubi verified as coming from a Bot other than the binding's.
func notOtherBot(sister, verified string) error {
	if verified != "" && !sameBot(sister, verified) {
		return fmt.Errorf("Rubi confirmed you as %s; this binding belongs to another Bot", verified)
	}
	return nil
}

func (s *sisters) unbindTool(_ context.Context, h sisterHost, in unbindIn) (any, error) {
	if err := notOtherBot(in.Sister, in.VerifiedAgent); err != nil {
		return nil, err
	}
	b, ok := s.st.bindingOf(in.Sister, in.BindCode)
	if !ok {
		return nil, errors.New("no binding with that sister and code (the user can unbind in the panel)")
	}
	if _, err := s.st.unbind(b.Sister); err != nil {
		return nil, err
	}
	h.Audit("binding_removed", map[string]any{"sister": b.Sister, "by": "bot"})
	return map[string]any{"unbound": true}, nil
}

type sendIn struct {
	Sister     string `json:"sister"`
	BindCode   string `json:"bind_code"`
	Text       string `json:"text" jsonschema:"a short ask (at most 4000 characters); bulky work goes to Claude as a task, not a message"`
	ReplyToAsk string `json:"reply_to_ask,omitempty" jsonschema:"the ask_id of a claude_ask you answer: the answer goes to the session that asked"`
	// Set by Rubi when the caller proved its name; a mismatch is refused.
	VerifiedAgent string `json:"rubi_verified_agent,omitempty" jsonschema:"set by Rubi; don't pass it"`
}

func (s *sisters) sendTool(ctx context.Context, h sisterHost, in sendIn) (any, error) {
	if err := notOtherBot(in.Sister, in.VerifiedAgent); err != nil {
		return nil, err
	}
	b, ok := s.st.bindingOf(in.Sister, in.BindCode)
	if !ok {
		return nil, errors.New("not bound: bind to a session first (claude_code_bind), then pass the bind_code you got")
	}
	text := strings.TrimSpace(in.Text)
	if text == "" {
		return nil, errors.New("text is empty")
	}
	if n := len([]rune(text)); n > maxSendText {
		return nil, fmt.Errorf("text has %d characters, at most %d: send a short ask, not a task", n, maxSendText)
	}
	if !s.allow("send|"+b.Sister, sendsPerHour) {
		return nil, fmt.Errorf("at most %d messages an hour", sendsPerHour)
	}
	target := ""
	if in.ReplyToAsk != "" {
		s.mu.Lock()
		ref, ok := s.asks[in.ReplyToAsk]
		s.mu.Unlock()
		if !ok || ref.sister != b.Sister || ref.device != b.Device {
			return nil, errors.New("unknown ask_id")
		}
		target = ref.session
	}
	var sess session
	if target == "" {
		var err error
		if sess, err = s.current(ctx, h, b); err != nil {
			return nil, err
		}
		target = sess.SessionID
	} else if _, found, err := findSession(ctx, h, b.Device, target); err == nil {
		sess = found
	}
	if sess.State == "ended" {
		return nil, errors.New("that Claude Code session has ended, so nobody would read the message; bind to a live one (claude_code_sessions)")
	}
	var res struct {
		Queued  bool   `json:"queued"`
		ID      string `json:"id"`
		Waiting int    `json:"waiting"`
	}
	if err := h.HomeCall(ctx, b.Device, "claude-sessions.send", map[string]any{"session_id": target, "from": b.Sister, "text": text}, &res); err != nil {
		return nil, err
	}
	h.Audit("message_sent", map[string]any{"sister": b.Sister, "session": target, "message": res.ID, "chars": len([]rune(text))})
	out := map[string]any{"queued": res.Queued, "message_id": res.ID, "waiting": res.Waiting,
		"session_state": sess.State, "delivery": deliveryHint(sess, s.now())}
	if !sess.LastActivity.IsZero() {
		out["last_activity"] = sess.LastActivity.UTC().Format(time.RFC3339)
	}
	return out, nil
}

// deliveryHint says when Claude is likely to read a queued message, from the session's state: a busy
// session reads it at its next stop, an idle one only when the user prompts it again.
func deliveryHint(sess session, now time.Time) string {
	const answer = " Its answer comes as a claude_reply event."
	switch sess.State {
	case "busy":
		return "The session is working: Claude reads it at its next stop, usually within minutes." + answer
	case "idle":
		since := ""
		if !sess.LastActivity.IsZero() {
			since = fmt.Sprintf(" (idle for %s)", now.Sub(sess.LastActivity).Round(time.Minute))
		}
		return "The session is idle" + since + ": Claude reads it only when the user next prompts it, which may be hours. Don't wait on it." + answer
	}
	return "Claude reads it when the session next stops or gets a prompt; Rubi doesn't know when that will be." + answer
}

// ---- what sessions say ----

// askBinding picks which of the project's bindings gets an ask from an unbound session: the one bound
// to the asking session's parent, else one bound to a main session, else the oldest.
func askBinding(ctx context.Context, h sisterHost, device string, asker session, cands []binding) binding {
	if len(cands) == 1 {
		return cands[0]
	}
	role := map[string]string{}
	if all, err := listSessions(ctx, h, "", true); err == nil {
		for _, ds := range all {
			if ds.device.ID != device {
				continue
			}
			for _, x := range ds.list {
				role[x.SessionID] = x.Role
				if x.AppSessionID != "" {
					role[x.AppSessionID] = x.Role
				}
			}
		}
	}
	score := func(b binding) int {
		if asker.Parent != "" && (b.AppSessionID == asker.Parent || b.SessionID == asker.Parent) {
			return 2
		}
		if role[b.SessionID] == "main" || b.AppSessionID != "" && role[b.AppSessionID] == "main" {
			return 1
		}
		return 0
	}
	best := cands[0]
	for _, b := range cands[1:] {
		if sb, sbest := score(b), score(best); sb > sbest || sb == sbest && b.Since.Before(best.Since) {
			best = b
		}
	}
	return best
}

// route sends a session's reply or ask to the Bot bound to it (or, for an ask from a sub-session, to
// the Bot bound to a session of the same project). Nothing bound: nothing goes out.
func (s *sisters) route(ctx context.Context, h sisterHost, d rubiplugin.HomeDevice, o outMsg) {
	var target *binding
	var sess session
	for _, b := range s.st.bindings() {
		if b.Device == d.ID && b.SessionID == o.SessionID {
			b := b
			target = &b
			break
		}
	}
	if target == nil {
		_, found, err := findSession(ctx, h, d.ID, o.SessionID)
		if err == nil {
			sess = found
			var sameProject []binding
			for _, b := range s.st.bindings() {
				if b.Device != d.ID {
					continue
				}
				if b.AppSessionID != "" && b.AppSessionID == found.AppSessionID {
					b := b
					target = &b
					s.st.follow(b.Sister, found.SessionID)
					break
				}
				if o.Kind == "ask" && found.RepoKey != "" && b.RepoKey == found.RepoKey {
					sameProject = append(sameProject, b)
				}
			}
			if target == nil && len(sameProject) > 0 {
				b := askBinding(ctx, h, d.ID, found, sameProject)
				target = &b
				if len(sameProject) > 1 {
					h.Logf("%s: ask from %s matches %d bindings of %s; it goes to %s", d.Name, found.SessionID, len(sameProject), found.RepoKey, b.Sister)
				}
			}
		}
	}
	if target == nil {
		h.Logf("%s: %s from unbound session %s dropped", d.Name, o.Kind, o.SessionID)
		return
	}
	switch o.Kind {
	case "reply":
		if !sameBot(o.To, target.Sister) {
			h.Logf("%s: reply for %s from a session bound to %s dropped", d.Name, o.To, target.Sister)
			return
		}
		h.Audit("reply_forwarded", map[string]any{"sister": target.Sister, "session": o.SessionID, "chars": len([]rune(o.Text))})
		_, err := h.EmitTo(target.Sister, eventReply, map[string]any{"session_id": o.SessionID, "in_reply_to": o.InReplyTo,
			"text": o.Text, "truncated": o.Truncated, "computer": d.Name})
		if err != nil {
			h.Logf("reply to %s: %v", target.Sister, err)
		}
	case "ask":
		if !s.allow("ask|"+d.ID+"|"+o.SessionID, asksPerHour) {
			h.Logf("%s: too many asks from %s; dropped", d.Name, o.SessionID)
			return
		}
		id := newID("ask_")
		s.mu.Lock()
		for k, v := range s.asks {
			if s.now().Sub(v.at) > askRemember {
				delete(s.asks, k)
			}
		}
		s.asks[id] = askRef{device: d.ID, session: o.SessionID, sister: target.Sister, at: s.now()}
		s.mu.Unlock()
		h.Audit("ask_forwarded", map[string]any{"sister": target.Sister, "session": o.SessionID, "ask": id, "kind": o.AskKind})
		data := map[string]any{"ask_id": id, "kind": o.AskKind, "text": o.Text, "session_id": o.SessionID, "directory": o.Cwd,
			"computer": d.Name, "role": firstNonEmpty(sess.Role, "main"), "title": sess.Title,
			"next_step": "Answer briefly with claude_code_send {sister, bind_code, text, reply_to_ask: ask_id}. Small research or audit only."}
		if _, err := h.EmitTo(target.Sister, eventAsk, data); err != nil {
			h.Logf("ask to %s: %v", target.Sister, err)
		}
	}
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
