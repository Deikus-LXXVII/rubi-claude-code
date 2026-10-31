package main

// claude_code_role_start: a session in a role's own VM. The approval rule is claude_code_start's: one strong
// approval, or none inside a project the user trusts for this Bot (never for a mode that skips permission prompts).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

func (s *sisters) roleStartTool(ctx context.Context, h sisterHost, in roleStartIn) (any, error) {
	c, err := s.who(h, in.roleWho)
	if err != nil {
		return nil, err
	}
	task := strings.TrimSpace(in.Prompt)
	switch {
	case task == "":
		return nil, errors.New("prompt is empty")
	case len([]rune(task)) > maxStartTask:
		return nil, fmt.Errorf("prompt is longer than %d characters: start the session with a short prompt and send the details with claude_code_send", maxStartTask)
	}
	if err := checkStartText(task); err != nil {
		return nil, err
	}
	name := ""
	if strings.TrimSpace(in.Name) != "" {
		if name, err = checkAliasName(in.Name); err != nil {
			return nil, err
		}
	}
	r, err := s.roleFor(ctx, h, c, in.Role)
	if err != nil {
		return nil, err
	}
	if r.Status != "active" {
		return nil, errors.New("the role is archived: unarchive it first")
	}
	proj, err := s.projectOf(ctx, h, c, r.Project)
	if err != nil {
		return nil, err
	}
	mode := firstNonEmpty(r.DefaultMode, "default")
	if !validRoleMode(mode) {
		return nil, errors.New("the role's mode isn't one a session can start in")
	}
	if !s.allow("start|"+strings.ToLower(c.Bot), startsPerHour) {
		return nil, fmt.Errorf("at most %d session starts per hour", startsPerHour)
	}
	if !s.allow("start|*", startsGlobal) {
		return nil, fmt.Errorf("at most %d session starts per hour in all", startsGlobal)
	}
	t := startTicket{Sister: c.Bot, Device: c.Dev.ID, DeviceName: c.Dev.Name, Cwd: proj.Dir, Task: task, Project: proj.ID, Mode: mode,
		Role: r.ID, RoleName: r.Name, Name: name}
	// Under a project trust held by this Bot a session starts without asking, but never one that skips prompts.
	if pt := s.botTrust(c.Dev.ID, c.Bot, proj.ID); pt != nil && mode != "bypassPermissions" {
		used := s.st.useProject(c.Dev.ID, s.now(), func(p projectTrust) bool { return p.ID == pt.ID })
		if used != nil {
			h.Audit(auditMandateAll, map[string]any{"mandate": used.ID, "project": proj.ID, "device": c.Dev.ID, "sister": c.Bot, "action": "claude_code_role_start", "role": r.ID, "uses": used.Uses})
			res, err := s.executeStart(ctx, h, t)
			if m, ok := res.(map[string]any); ok && err == nil {
				m["approval"] = "none needed: " + used.ID + ", the user's trust of the project " + proj.ID + " " + s.trustEnd(*used)
			}
			return res, err
		}
	}
	preview := map[string]any{"bot": c.Bot, "computer": c.Dev.Name, "project": proj.Dir, "project_id": proj.ID, "role": r.Name, "role_id": r.ID, "role_version": r.Version, "mode": mode,
		"first_message_from_bot": task,
		"what_it_does": fmt.Sprintf("Starts a NEW Claude session in the role %s of the project %s on %s, in its own VM with only that role's skills, tools and hosts, in permission mode %s. Its first message is the text under first_message_from_bot, from %s (a Bot; the text is not yours), labelled as the Bot's by Rubi Home. If a limit is reached it waits in the queue. Then %s is bound to the session.",
			oneLine(r.Name, 40), proj.Dir, c.Dev.Name, mode, c.Bot, c.Bot),
		"warning": "Mode " + mode + ": " + map[bool]string{true: agentBypassNote, false: "Claude asks before commands as that mode says; push, sudo, the network outside the allow-list, paths outside /work and edits of .rubi/.claude always ask."}[mode == "bypassPermissions"]}
	for _, b := range s.st.bindings() {
		if sameBot(b.Sister, c.Bot) {
			preview["replaces"] = b.Title + " (" + b.SessionID + ")"
		}
	}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindStart,
		Summary: "Start Claude in the role " + oneLine(r.Name, 30) + " of " + oneLine(firstNonEmpty(proj.Dir, proj.ID), 40) + " on " + c.Dev.Name + " for " + c.Bot + ": " + oneLine(task, 80),
		Preview: preview, Payload: t})
}
