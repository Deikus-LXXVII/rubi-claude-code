package main

import (
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
	return map[string]any{"mandates": list}, nil
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
		ok, err := s.st.unbind(a.Sister)
		if err != nil {
			return nil, err
		}
		if ok {
			h.Audit("binding_removed", map[string]any{"sister": a.Sister, "by": "user"})
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
			{"label": "Revoke all", "op": "revoke", "args": map[string]any{"id": "all"}, "danger": true, "confirm": "Revoke every 2-hour trust?"}}})
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
			{"title": "Bots bound to sessions", "note": "Each Bot talks only to its session.", "empty": "None.", "items": bitems},
		}}, nil
}
