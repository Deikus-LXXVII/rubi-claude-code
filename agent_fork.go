package main

// Forking an agent session (claude_code_fork): a branch of the conversation, idle until something is sent to it.
// The approval is a tap when the Bot forks the session it is bound to and a strong one for any other session.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	kindFork     = "claude-code.fork"     // any session: strong
	kindForkOwn  = "claude-code.fork_own" // the Bot's own bound session: a tap
	forksPerHour = 10
	auditForked  = "session_forked"
)

type forkIn struct {
	Agent         string `json:"rubi_agent" jsonschema:"your Bot name as connected to Rubi"`
	AgentCode     string `json:"rubi_agent_code,omitempty" jsonschema:"the agent_code of your latest Rubi webhook (or call rubi_verify with your name to get one); proves you are that Bot"`
	VerifiedAgent string `json:"rubi_verified_agent,omitempty" jsonschema:"set by Rubi; don't pass it"`
	Device        string `json:"device,omitempty" jsonschema:"the computer, when there are several"`
	Project       string `json:"project,omitempty" jsonschema:"the project (id or directory), as claude_code_sessions shows it"`
	Session       string `json:"session,omitempty" jsonschema:"the session's id or name; leave out for the session you are bound to"`
	Name          string `json:"name,omitempty" jsonschema:"a name for the fork (1 to 64 plain characters, unique on the computer)"`
}

type forkTicket struct {
	Sister     string `json:"sister"`
	Device     string `json:"device"`
	DeviceName string `json:"device_name"`
	Project    string `json:"project"`
	SessionID  string `json:"session_id"`
	Name       string `json:"name,omitempty"`
}

func (s *sisters) forkTool(ctx context.Context, h sisterHost, in forkIn) (any, error) {
	sister := strings.TrimSpace(in.VerifiedAgent)
	if sister == "" || len(sister) > 64 {
		return nil, errors.New("Rubi didn't confirm which Bot you are: pass rubi_agent (your Bot name) and rubi_agent_code (the agent_code of your latest Rubi webhook, or call rubi_verify to get one)")
	}
	name := ""
	if strings.TrimSpace(in.Name) != "" {
		var err error
		if name, err = checkAliasName(in.Name); err != nil {
			return nil, err
		}
	}
	device, project, id, nm := in.Device, in.Project, strings.TrimSpace(in.Session), ""
	if id == "" {
		var mine *binding
		for _, b := range s.st.bindings() {
			if sameBot(b.Sister, sister) && b.Project != "" {
				b := b
				mine = &b
			}
		}
		if mine == nil {
			return nil, errors.New("you are not bound to an agent session: pass session (its id or name) and project")
		}
		device, project, id = mine.Device, mine.Project, mine.SessionID
	} else {
		nm = id
	}
	ref, found, err := s.resolveAgent(ctx, h, device, project, id, nm)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("no such agent session (list them with claude_code_sessions)")
	}
	d, proj, sess := ref.ad.device, ref.proj, ref.sess
	if name != "" {
		if len(s.st.aliasesNamed(d.ID, name)) > 0 {
			return nil, fmt.Errorf("another session on %s is already called %q", d.Name, name)
		}
		if err := freeName(name, asDeviceSessions([]agentDevice{ref.ad}), d.ID); err != nil {
			return nil, err
		}
	}
	if !s.allow("fork|"+strings.ToLower(sister), forksPerHour) {
		return nil, fmt.Errorf("at most %d forks an hour", forksPerHour)
	}
	own := false
	for _, b := range s.st.bindings() {
		own = own || sameBot(b.Sister, sister) && b.Device == d.ID && b.Project == proj.ID && b.SessionID == sess.ID
	}
	t := forkTicket{Sister: sister, Device: d.ID, DeviceName: d.Name, Project: proj.ID, SessionID: sess.ID, Name: name}
	kind := kindFork
	if own {
		kind = kindForkOwn
	}
	preview := map[string]any{"bot": sister, "computer": d.Name, "project": proj.Dir, "session": sess.ID, "session_name": sess.Name, "mode": sess.Mode, "new_name": name,
		"own_session":  own,
		"what_it_does": "Makes a branch of this Claude session's conversation as a new session. It stays idle until a message is sent to it, and then runs in the same project VM and permission mode as Rubi Home gives new sessions. It is not bound to anyone."}
	return h.Submit(ctx, rubiplugin.Request{Kind: kind, Summary: fmt.Sprintf("Fork a Claude session on %s for %s: %s", d.Name, sister, oneLine(firstNonEmpty(sess.Name, sess.ID), 60)),
		Preview: preview, Payload: t})
}

// executeFork runs once the fork was approved.
func (s *sisters) executeFork(ctx context.Context, h sisterHost, t forkTicket) (any, error) {
	if t.Device == "" || t.Project == "" || t.SessionID == "" {
		return nil, errors.New("bad payload")
	}
	var res struct {
		ID string `json:"id"`
	}
	args := map[string]any{"project": t.Project, "id": t.SessionID}
	if t.Name != "" {
		args["name"] = t.Name
	}
	if err := h.HomeCall(ctx, t.Device, opAgentFork, args, &res); err != nil {
		return nil, fmt.Errorf("no fork was made: %v", err)
	}
	h.Audit(auditForked, map[string]any{"device": t.Device, "project": t.Project, "session": t.SessionID, "fork": res.ID, "sister": t.Sister, "name": oneLine(t.Name, maxNameRunes)})
	out := map[string]any{"forked": true, "session_id": res.ID, "from": t.SessionID, "project": t.Project,
		"next_step": "The fork is idle. Bind to it with claude_code_bind (a new approval unless the project is trusted) and send it a message to start it."}
	if t.Name != "" {
		// The runner got the name; Rubi keeps the alias too, if the name is still free.
		sess := session{SessionID: res.ID, Source: "agent", RepoKey: "agent:" + t.Project}
		if _, err := s.st.setAlias(t.Device, t.DeviceName, sess, t.Name, t.Sister, s.now().UTC()); err != nil {
			out["note"] = "the fork is named in Claude, but Rubi couldn't keep the name: " + err.Error()
		} else {
			out["name"] = t.Name
		}
	}
	return out, nil
}
