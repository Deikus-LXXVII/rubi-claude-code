package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
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
func (s *sisters) panel(h sisterHost, op string, args json.RawMessage) (any, error) {
	var a struct {
		ID     string `json:"id"`
		Sister string `json:"sister"`
	}
	if len(args) > 0 && string(args) != "null" {
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, errors.New("bad arguments")
		}
	}
	switch op {
	case "view":
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
	return map[string]any{"title": "Claude Code", "refresh": 30,
		"note": "Sessions running with bypassPermissions never ask, so approvals and trusts here don't apply to them (their messages to and from Bots still work).",
		"sections": []map[string]any{
			{"title": "Trusted sessions (2 hours)", "note": "Rubi allows these sessions' plain, listed commands by itself, including builds and tests that run the project's own code; push, --force, sudo, network commands, credential paths and writing outside the directory or into .git still ask.", "empty": "None.", "items": mitems},
			{"title": "Trusted projects (until 04:00, or until revoked)", "note": "A trust marked UNTIL REVOKED has no end time and no command limit: it stays on across restarts and days until you revoke it here (or with claude_code_mandates). Every Claude Code session on that computer inside the project: Rubi allows plain, listed commands by itself, including builds and tests that run the project's own code, and a Bot bound to a session of the project can start and bind sessions in it. Push and every remote git command, --force, sudo, network commands, tags, credential paths, writing outside the project and branches outside the pattern still ask.", "empty": "None.", "items": pitems},
			{"title": "Bots bound to sessions", "note": "Each Bot talks only to its session.", "empty": "None.", "items": bitems},
		}}, nil
}
