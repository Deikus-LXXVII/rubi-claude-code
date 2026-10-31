package main

// Permission modes of agent sessions (claude_code_mode and the panel's mode op). The order, strictest first, is
// plan, default, acceptEdits, bypassPermissions. A change to a stricter mode needs no approval; to a looser one it
// needs a strong approval (a passkey). Rubi Home forwards a mode to the runner only when this plugin asked for it.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	kindMode      = "claude-code.mode"
	modesPerHour  = 20
	auditModeSet  = "agent_mode_changed"
	modeNoteLoose = "A looser mode asks Claude's questions less: bypassPermissions lets it run almost anything in the project's VM without asking (push, sudo, the network outside the allow-list, paths outside /work and .rubi/.claude edits still ask)."
)

type modeIn struct {
	Agent         string `json:"rubi_agent" jsonschema:"your Bot name as connected to Rubi"`
	AgentCode     string `json:"rubi_agent_code,omitempty" jsonschema:"the agent_code of your latest Rubi webhook; proves you are that Bot"`
	VerifiedAgent string `json:"rubi_verified_agent,omitempty" jsonschema:"set by Rubi; don't pass it"`
	Device        string `json:"device,omitempty" jsonschema:"the computer, when there are several"`
	Project       string `json:"project" jsonschema:"the project (id or directory, as claude_code_sessions shows it)"`
	Session       string `json:"session" jsonschema:"the session's id or name"`
	Mode          string `json:"mode" jsonschema:"plan, default, acceptEdits or bypassPermissions"`
}

type modeTicket struct {
	Sister     string `json:"sister,omitempty"`
	Device     string `json:"device"`
	DeviceName string `json:"device_name"`
	Project    string `json:"project"`
	SessionID  string `json:"session_id"`
	From       string `json:"from"`
	To         string `json:"to"`
}

func (s *sisters) modeTool(ctx context.Context, h sisterHost, in modeIn) (any, error) {
	sister := strings.TrimSpace(in.VerifiedAgent)
	if sister == "" || len(sister) > 64 {
		return nil, errors.New("Rubi didn't confirm which Bot you are: pass rubi_agent (your Bot name) and rubi_agent_code (the agent_code of your latest Rubi webhook, or call rubi_verify to get one)")
	}
	return s.changeMode(ctx, h, sister, in.Device, in.Project, in.Session, in.Mode, false)
}

// changeMode sets a session's mode: at once when it gets stricter (a Bot must be bound in that project; the user
// in the panel needs no binding), after a strong approval when it gets looser.
func (s *sisters) changeMode(ctx context.Context, h sisterHost, sister, device, project, session, mode string, byUser bool) (any, error) {
	to, ok := modeRank[mode]
	if !ok {
		return nil, errors.New("mode must be plan, default, acceptEdits or bypassPermissions")
	}
	ref, found, err := s.resolveAgent(ctx, h, device, project, session, session)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("no such agent session (list them with claude_code_sessions)")
	}
	if !byUser && !s.allow("mode|"+strings.ToLower(sister), modesPerHour) {
		return nil, fmt.Errorf("at most %d mode changes an hour", modesPerHour)
	}
	from, known := modeRank[ref.sess.Mode]
	if known && from == to {
		return map[string]any{"changed": false, "mode": mode}, nil
	}
	t := modeTicket{Sister: sister, Device: ref.ad.device.ID, DeviceName: ref.ad.device.Name, Project: ref.proj.ID, SessionID: ref.sess.ID, From: ref.sess.Mode, To: mode}
	if known && to < from { // stricter
		if !byUser {
			bound := false
			for _, b := range s.st.bindings() {
				bound = bound || sameBot(b.Sister, sister) && b.Device == t.Device && b.Project == t.Project
			}
			if !bound {
				return nil, errors.New("you are not bound to a session in that project")
			}
		}
		return s.executeMode(ctx, h, t, "no approval: stricter")
	}
	// Looser, or the current mode unknown: the user decides.
	who := firstNonEmpty(sister, "the user")
	preview := map[string]any{"bot": sister, "computer": ref.ad.device.Name, "project": ref.proj.Dir, "session": ref.sess.ID, "name": ref.sess.Name,
		"from": firstNonEmpty(ref.sess.Mode, "unknown"), "to": mode, "what_it_does": "Changes this session's permission mode from " + firstNonEmpty(ref.sess.Mode, "unknown") + " to " + mode + ". " + modeNoteLoose}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindMode, Summary: fmt.Sprintf("Loosen a Claude session to %s on %s (asked by %s)", mode, ref.ad.device.Name, who),
		Preview: preview, Payload: t})
}

// executeMode asks Rubi Home to change the mode; it runs for a stricter change at once and for a looser one once approved.
func (s *sisters) executeMode(ctx context.Context, h sisterHost, t modeTicket, why string) (any, error) {
	if _, ok := modeRank[t.To]; !ok || t.Device == "" || t.Project == "" || t.SessionID == "" {
		return nil, errors.New("bad payload")
	}
	if err := h.HomeCall(ctx, t.Device, opAgentMode, map[string]any{"project": t.Project, "id": t.SessionID, "mode": t.To}, nil); err != nil {
		return nil, err
	}
	h.Audit(auditModeSet, map[string]any{"device": t.Device, "project": t.Project, "session": t.SessionID, "from": t.From, "to": t.To, "sister": t.Sister, "approval": why})
	return map[string]any{"changed": true, "mode": t.To, "from": t.From}, nil
}
