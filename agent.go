package main

// The Rubi Home agent path (capability "claude-agent"): Claude runs through the Agent SDK in a project VM on the
// user's computer and Rubi Home relays it. This file holds the contract types, the capability probe, the
// listing of projects and sessions, the poll of claude-agent.next and the routing of the runner's events to
// Bots. Permissions are in agent_perm.go, the sister tools in agent_sisters.go. The old hook path
// (watch.go, binding.go ...) is untouched and still used by a computer that doesn't report the capability.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	opAgentProjects = "claude-agent.projects"
	opAgentSessions = "claude-agent.sessions"
	opAgentStart    = "claude-agent.start"
	opAgentSend     = "claude-agent.send"
	opAgentRename   = "claude-agent.rename"
	opAgentFork     = "claude-agent.fork"
	opAgentMode     = "claude-agent.mode"
	opAgentNext     = "claude-agent.next"
	opAgentDecide   = "claude-agent.decide"
	opAgentStatus   = "claude-agent.status"

	agentRoot = "/work" // the project's directory inside its VM

	capYes       = 5 * time.Minute // how long "has the capability" is remembered
	capNo        = time.Minute     // and "has not"
	capProbeWait = 5 * time.Second
	askLife      = 280 * time.Second // Rubi Home denies a question that long unanswered
)

// Permission modes, from the strictest to the loosest.
var modeRank = map[string]int{"plan": 0, "default": 1, "acceptEdits": 2, "bypassPermissions": 3}

// isUnknownOp says whether err is Rubi's way of saying the computer's Rubi Home doesn't do an operation.
func isUnknownOp(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "doesn't do") || strings.Contains(m, "unknown op") || strings.Contains(m, "doesn't allow")
}

type capEntry struct {
	ok bool
	at time.Time
}

// agentCapable says whether the computer's Rubi Home has the claude-agent capability: claude-agent.status
// answers. The answer is remembered for a few minutes.
func (s *sisters) agentCapable(ctx context.Context, h homeCaller, device string) bool {
	return s.capProbe(ctx, h, device, device, opAgentStatus)
}

// capProbe asks a computer's Rubi Home an operation that every Rubi Home with a capability answers and remembers
// the answer under key.
func (s *sisters) capProbe(ctx context.Context, h homeCaller, device, key, op string) bool {
	s.mu.Lock()
	e, ok := s.caps[key]
	now := s.now()
	if ok && now.Sub(e.at) < map[bool]time.Duration{true: capYes, false: capNo}[e.ok] {
		s.mu.Unlock()
		return e.ok
	}
	s.mu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, capProbeWait)
	defer cancel()
	err := h.HomeCall(pctx, device, op, map[string]any{}, nil)
	if err != nil && ctx.Err() != nil {
		return false
	}
	s.mu.Lock()
	if s.caps == nil {
		s.caps = map[string]capEntry{}
	}
	// "No" is remembered only when Rubi Home says it doesn't do the operation; a timeout or a dropped connection
	// is not an answer, so a computer that is only slow is not written off for a minute.
	if err == nil || isUnknownOp(err) {
		s.caps[key] = capEntry{ok: err == nil, at: now}
	} else {
		delete(s.caps, key)
	}
	s.mu.Unlock()
	return err == nil
}

// agentKnown says whether the computer is known (not probed now) to have the capability.
func (s *sisters) agentKnown(device string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.caps[device].ok
}

// ---- projects and sessions ----

type agentProject struct {
	ID       string `json:"id"`
	Dir      string `json:"dir"`
	VMState  string `json:"vm_state,omitempty"`
	SlotBusy bool   `json:"slot_busy,omitempty"`
	Queue    int    `json:"queue,omitempty"`
}

// agentSess is one agent session (claude-agent.sessions). Name is the runner's (renameSession); the Rubi alias
// is kept in the plugin's store.
type agentSess struct {
	ID           string    `json:"id"`
	Name         string    `json:"name,omitempty"`
	Created      time.Time `json:"created,omitzero"`
	LastActivity time.Time `json:"last_activity,omitzero"`
	Mode         string    `json:"mode,omitempty"`
	Busy         bool      `json:"busy,omitempty"`
	Project      string    `json:"-"`
}

type agentDevice struct {
	device   rubiplugin.HomeDevice
	projects []agentProject
	sessions []agentSess
	err      error
}

// listAgent lists the projects and sessions of every computer with the capability (device narrows it to one).
func (s *sisters) listAgent(ctx context.Context, h sisterHost, device string) []agentDevice {
	devs, err := h.HomeDevices()
	if err != nil {
		return nil
	}
	var out []agentDevice
	for _, d := range devs {
		if device != "" && d.ID != device && d.Name != device {
			continue
		}
		if s.agentCapable(ctx, h, d.ID) {
			out = append(out, agentDevice{device: d})
		}
	}
	var wg sync.WaitGroup
	for i := range out {
		wg.Go(func() {
			dctx, cancel := context.WithTimeout(ctx, listTimeout)
			defer cancel()
			ad := &out[i]
			var pr struct {
				Projects []agentProject `json:"projects"`
			}
			if ad.err = h.HomeCall(dctx, ad.device.ID, opAgentProjects, map[string]any{}, &pr); ad.err != nil {
				return
			}
			ad.projects = pr.Projects
			for _, p := range pr.Projects {
				var sr struct {
					Sessions []agentSess `json:"sessions"`
				}
				if err := h.HomeCall(dctx, ad.device.ID, opAgentSessions, map[string]any{"project": p.ID}, &sr); err != nil {
					ad.err = fmt.Errorf("project %s: %w", p.ID, err)
					continue
				}
				for _, x := range sr.Sessions {
					x.Project = p.ID
					ad.sessions = append(ad.sessions, x)
				}
			}
		})
	}
	wg.Wait()
	return out
}

func (ad agentDevice) project(id string) agentProject {
	for _, p := range ad.projects {
		if p.ID == id {
			return p
		}
	}
	return agentProject{ID: id}
}

// matchProject finds a project by id or directory.
func matchProject(ps []agentProject, ref string) (agentProject, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return agentProject{}, false
	}
	for _, p := range ps {
		if p.ID == ref || p.Dir != "" && path.Clean(p.Dir) == path.Clean(ref) {
			return p, true
		}
	}
	return agentProject{}, false
}

// asSession shows an agent session the way the hook path's code sees one (names, ids and aliases work on that).
func (x agentSess) asSession(dir string) session {
	return session{SessionID: x.ID, Title: x.Name, Cwd: dir, ProjectRoot: dir, RepoKey: "agent:" + x.Project, Role: "main",
		Source: "agent", PermissionMode: x.Mode, State: map[bool]string{true: "busy", false: "idle"}[x.Busy], LastActivity: x.LastActivity}
}

// asDeviceSessions turns agent lists into the shape freeName reads.
func asDeviceSessions(all []agentDevice) []deviceSessions {
	var out []deviceSessions
	for _, ad := range all {
		ds := deviceSessions{device: ad.device, err: ad.err}
		for _, x := range ad.sessions {
			ds.list = append(ds.list, x.asSession(ad.project(x.Project).Dir))
		}
		out = append(out, ds)
	}
	return out
}

type agentRef struct {
	ad   agentDevice
	proj agentProject
	sess agentSess
}

// resolveAgent finds the agent session a Bot means, by id or by name (the runner's name or a Rubi alias), on the
// computers that have the capability. found is false when none matches, which leaves the hook path to try.
func (s *sisters) resolveAgent(ctx context.Context, h sisterHost, device, project, id, name string) (agentRef, bool, error) {
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	if id == "" && name == "" {
		return agentRef{}, false, nil
	}
	var hits []agentRef
	for _, ad := range s.listAgent(ctx, h, device) {
		for _, x := range ad.sessions {
			p := ad.project(x.Project)
			if project != "" {
				if want, ok := matchProject(ad.projects, project); !ok || want.ID != p.ID {
					continue
				}
			}
			match := id != "" && x.ID == id
			if !match && name != "" {
				match = x.Name != "" && sameName(x.Name, name)
				for _, a := range s.st.aliasesNamed(ad.device.ID, name) {
					match = match || a.SessionID == x.ID
				}
			}
			if match {
				hits = append(hits, agentRef{ad, p, x})
			}
		}
	}
	switch len(hits) {
	case 0:
		return agentRef{}, false, nil
	case 1:
		return hits[0], true, nil
	}
	return agentRef{}, false, errors.New("that matches several agent sessions: pass device and project")
}

// ---- the poll ----

// agentItem is one entry of claude-agent.next: a question for the plugin (perm.ask, cred.ask) or an event.
type agentItem struct {
	Type      string          `json:"type"` // perm.ask, cred.ask, event
	AskID     string          `json:"ask_id,omitempty"`
	Project   string          `json:"project,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
	AgentID   string          `json:"agent_id,omitempty"`
	AgentType string          `json:"agent_type,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Cwd       string          `json:"cwd,omitempty"`
	Mode      string          `json:"mode,omitempty"`
	ExpiresAt time.Time       `json:"expires_at,omitzero"`
	// cred.ask and net.ask: the remote's host and repository path and the operation (push, connect). These come
	// from Claude's own git remote or connection, so they are untrusted text.
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
	Op   string `json:"op,omitempty"`
	// Event is an event item's payload as Rubi Home nests it; its fields are read into the ones below.
	Event  json.RawMessage `json:"event,omitempty"`
	detail string          // set by handleAsk: what the approval shows for a question without a tool input
	// event: Kind is the runner's (assistant, tool, result, sister_reply, sister_ask, message, status, error ...)
	Kind      string    `json:"kind,omitempty"`
	ID        string    `json:"id,omitempty"`
	Text      string    `json:"text,omitempty"`
	To        string    `json:"to,omitempty"`
	InReplyTo []string  `json:"in_reply_to,omitempty"`
	AskKind   string    `json:"ask_kind,omitempty"`
	State     string    `json:"state,omitempty"`
	IsError   bool      `json:"is_error,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
	At        time.Time `json:"at,omitzero"`
}

// UnmarshalJSON reads an item, and an event item's nested payload into its flat fields.
func (it *agentItem) UnmarshalJSON(b []byte) error {
	type plain agentItem
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if len(p.Event) > 0 {
		var ev plain
		if err := json.Unmarshal(p.Event, &ev); err != nil {
			return err
		}
		ev.Type, ev.Project, ev.Event = p.Type, p.Project, p.Event
		if ev.SessionID == "" {
			ev.SessionID = p.SessionID
		}
		p = ev
	}
	*it = agentItem(p)
	return nil
}

// pollAgent asks one computer for the agent's questions and events until ctx ends, the computer is unpaired or
// its Rubi Home turns out not to have the capability (the next refresh probes again).
func (w *watcher) pollAgent(ctx context.Context, d rubiplugin.HomeDevice) {
	failures := 0
	for ctx.Err() == nil {
		var out struct {
			Items []agentItem `json:"items"`
		}
		err := w.h.HomeCall(ctx, d.ID, opAgentNext, map[string]any{"wait_seconds": int(pollWait / time.Second)}, &out)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if rubiplugin.ErrorCode(err) == rubiplugin.CodeHomeNotPaired || isUnknownOp(err) {
				w.h.Logf("%s: %v", d.Name, err)
				w.s.mu.Lock()
				delete(w.s.caps, d.ID)
				w.s.mu.Unlock()
				return
			}
			failures++
			if failures == 1 || failures%10 == 0 {
				w.h.Logf("%s: %v", d.Name, err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(w.backoff(failures)):
			}
			continue
		}
		failures = 0
		for _, it := range out.Items {
			switch it.Type {
			case "perm.ask", "cred.ask":
				w.wg.Go(func() { w.handleAsk(ctx, d, it) })
			case "event":
				w.wg.Go(func() { w.s.routeAgent(ctx, w.h, d, it) })
			}
		}
	}
}

// ---- events to Bots ----

// agentBinding finds the binding to a session of a project.
func (s *sisters) agentBinding(device, project, session string) *binding {
	for _, b := range s.st.bindings() {
		if b.Device == device && b.Project == project && b.SessionID == session {
			b := b
			return &b
		}
	}
	return nil
}

// routeAgent sends a runner event to the Bot it is for. A turn's final text goes to a Bot only when Rubi Home
// marks the turn as started by that Bot (To): the user's own chat with the session is never forwarded.
func (s *sisters) routeAgent(ctx context.Context, h sisterHost, d rubiplugin.HomeDevice, it agentItem) {
	if len(it.To) >= len("local:") && strings.EqualFold(it.To[:len("local:")], "local:") {
		return
	}
	target := s.agentBinding(d.ID, it.Project, it.SessionID)
	switch it.Kind {
	case "result", "sister_reply":
		if it.Text == "" || target == nil || it.To == "" || !sameBot(it.To, target.Sister) {
			return
		}
		h.Audit("reply_forwarded", map[string]any{"sister": target.Sister, "session": it.SessionID, "project": it.Project, "chars": len([]rune(it.Text))})
		if _, err := h.EmitTo(target.Sister, eventReply, map[string]any{"session_id": it.SessionID, "project": it.Project, "in_reply_to": it.InReplyTo,
			"text": it.Text, "truncated": it.Truncated, "computer": d.Name}); err != nil {
			h.Logf("reply to %s: %v", target.Sister, err)
		}
	case "message":
		// Delivery states of a message a Bot sent ("queued" is skipped: the send result said so).
		if target == nil || !sameBot(it.To, target.Sister) || it.ID == "" || it.State == "" || it.State == "queued" {
			return
		}
		if _, err := h.EmitTo(target.Sister, eventMessage, map[string]any{"id": it.ID, "session_id": it.SessionID, "state": it.State, "at": it.At.UTC().Format(time.RFC3339)}); err != nil {
			h.Logf("message state to %s: %v", target.Sister, err)
		}
	case "sister_ask":
		if target == nil {
			h.Logf("%s: ask from unbound agent session %s dropped", d.Name, it.SessionID)
			return
		}
		if !s.allow("ask|"+d.ID+"|"+it.SessionID, asksPerHour) {
			h.Logf("%s: too many asks from %s; dropped", d.Name, it.SessionID)
			return
		}
		id := newID("ask_")
		s.mu.Lock()
		for k, v := range s.asks {
			if s.now().Sub(v.at) > askRemember {
				delete(s.asks, k)
			}
		}
		s.asks[id] = askRef{device: d.ID, session: it.SessionID, sister: target.Sister, at: s.now(), project: it.Project}
		s.mu.Unlock()
		h.Audit("ask_forwarded", map[string]any{"sister": target.Sister, "session": it.SessionID, "ask": id, "kind": it.AskKind})
		data := map[string]any{"ask_id": id, "kind": it.AskKind, "text": it.Text, "session_id": it.SessionID, "project": it.Project,
			"directory": agentRoot, "computer": d.Name, "role": "main", "title": "",
			"next_step": "Answer briefly with claude_code_send {sister, bind_code, text, reply_to_ask: ask_id}. Small research or audit only."}
		if _, err := h.EmitTo(target.Sister, eventAsk, data); err != nil {
			h.Logf("ask to %s: %v", target.Sister, err)
		}
	}
	// assistant, tool, status, rate_limit, background, error, ask: shown in the panel (M6), not forwarded.
}
