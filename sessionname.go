package main

// Session names (claude_code_rename). Claude Code has no documented way for another process to rename a
// session (/rename and --name work from inside Claude Code only; the desktop app's titles and
// ~/.claude/sessions are not ours to write), so a name here is an alias Rubi keeps for a session on a
// computer: it shows in claude_code_sessions next to the title, and claude_code_bind accepts it instead of a
// session id. It never reaches Claude Code.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	kindRename       = "claude-code.rename"
	maxNameRunes     = 64
	maxAliases       = 500
	aliasTTL         = 30 * 24 * time.Hour // an alias whose session was not listed this long is dropped
	aliasSeenEvery   = time.Hour           // how often a listing refreshes an alias's last-seen time
	sweepEvery       = 10 * time.Minute    // how often a full list is read to look for stale names
	nameListReuse    = 5 * time.Minute     // how long the panel's name page reuses the session list
	renamesPerHour   = 20
	panelListTimeout = 10 * time.Second
	auditRenamed     = "session_renamed"
)

// alias is a user- or Bot-chosen name for one session on one computer. The session is known by its Claude
// Code id and, for a desktop session, the app's id, which stays when the app restarts it under a new one.
type alias struct {
	Device       string `json:"device"`
	DeviceName   string `json:"device_name,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	AppSessionID string `json:"app_session_id,omitempty"`
	Name         string `json:"name"`
	SetBy        string `json:"set_by,omitempty"` // "user" (the panel) or the Bot's name; empty for older records
	// What the session looked like when last listed, so a name can still be resolved when Rubi Home's
	// list is cut short and doesn't hold the session.
	Cwd     string    `json:"cwd,omitempty"`
	RepoKey string    `json:"repo_key,omitempty"`
	Title   string    `json:"title,omitempty"`
	Set     time.Time `json:"set"`
	Seen    time.Time `json:"seen"`
}

func (a alias) is(device string, s session) bool {
	return a.Device == device && (a.SessionID != "" && a.SessionID == s.SessionID ||
		a.AppSessionID != "" && a.AppSessionID == s.AppSessionID)
}

var (
	uuidLike  = regexp.MustCompile(`^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$`)
	hexOnly   = regexp.MustCompile(`^[0-9a-f]{8,}$`)
	rubiIDLik = regexp.MustCompile(`^(md|pt|bc|ask|cc)_[0-9a-z]{6,}$`)
)

// foldName is the form names are compared in (uniqueness, lookup, the panel): case-insensitive through a round
// trip that also folds characters like the final sigma or the Turkish dotless i.
func foldName(s string) string { return strings.ToLower(strings.ToUpper(s)) }

func sameName(a, b string) bool { return foldName(a) == foldName(b) }

// nameRuneOK allows letters, numbers, punctuation, symbols and the ASCII space. Marks (combining characters,
// variation selectors), format and control characters, separators, private-use and unassigned code points
// are out, and so are the look-alike blanks that are letters or symbols by category. There is no Unicode
// normalization in the standard library, so decomposed text (a letter plus a combining mark) is refused rather
// than normalized: type precomposed characters.
func nameRuneOK(r rune) bool {
	switch r {
	case 0x115F, 0x1160, 0x3164, 0xFFA0, // Hangul fillers (letters that draw nothing)
		0x2800,         // braille blank
		0x17B4, 0x17B5, // Khmer inherent vowels (invisible)
		0x180E:
		return false
	}
	return r == ' ' || unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsPunct(r) || unicode.IsSymbol(r)
}

// checkAliasName returns the trimmed name, or says why it is refused. It rejects instead of repairing: the
// user approves what the name says, so what is stored must be what was shown.
func checkAliasName(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", errors.New("the name is not valid text")
	}
	name = strings.TrimSpace(name)
	n := utf8.RuneCountInString(name)
	switch {
	case n == 0:
		return "", errors.New("the name is empty (to remove a name, clear it)")
	case n > maxNameRunes:
		return "", fmt.Errorf("the name has %d characters, at most %d", n, maxNameRunes)
	}
	prev := rune(0)
	for _, r := range name {
		switch {
		case r == ' ' && prev == ' ':
			return "", errors.New("the name has two spaces in a row")
		case !nameRuneOK(r):
			return "", fmt.Errorf("the name contains a character that isn't allowed (U+%04X): use letters, digits, punctuation, symbols and ordinary spaces, with precomposed accents", r)
		}
		prev = r
	}
	low := strings.ToLower(name)
	switch {
	case strings.HasPrefix(low, "local_"):
		return "", errors.New(`a name can't start with "local_" (that is how desktop session ids look)`)
	case uuidLike.MatchString(low), hexOnly.MatchString(low), rubiIDLik.MatchString(low):
		return "", errors.New("the name looks like an id; choose a descriptive name")
	}
	return name, nil
}

// ---- store ----

// aliasFor is the alias of a session on a computer.
func (s *store) aliasFor(device string, sess session) (alias, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.st.Aliases {
		if a.is(device, sess) {
			return a, true
		}
	}
	return alias{}, false
}

func (s *store) aliases() []alias {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]alias(nil), s.st.Aliases...)
}

// aliasesNamed finds the aliases called name (case-insensitive), on one computer or, with device "", on any.
func (s *store) aliasesNamed(device, name string) []alias {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []alias
	for _, a := range s.st.Aliases {
		if (device == "" || a.Device == device) && sameName(a.Name, name) {
			out = append(out, a)
		}
	}
	return out
}

// setAlias names a session (replacing its old name) and returns the old alias (zero when it had none). by is
// who sets it: "user" or a Bot's name. The name must be free on the computer; if saving fails nothing changed.
func (s *store) setAlias(device, deviceName string, sess session, name, by string, now time.Time) (alias, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := append([]alias(nil), s.st.Aliases...)
	var old alias
	found := -1
	for i, a := range s.st.Aliases {
		if a.is(device, sess) {
			old, found = a, i
			continue
		}
		if a.Device == device && sameName(a.Name, name) {
			return alias{}, fmt.Errorf("another session on %s is already called %q; names are unique per computer, ignoring case", firstNonEmpty(deviceName, device), oneLine(a.Name, maxNameRunes))
		}
	}
	na := alias{Device: device, DeviceName: deviceName, SessionID: sess.SessionID, AppSessionID: sess.AppSessionID, Name: name, SetBy: by,
		Cwd: sess.Cwd, RepoKey: sess.RepoKey, Title: oneLine(sess.Title, 200), Set: now, Seen: now}
	if found >= 0 {
		s.st.Aliases[found] = na
	} else {
		if len(s.st.Aliases) >= maxAliases {
			return alias{}, fmt.Errorf("there are already %d session names; clear some in the Rubi panel first", maxAliases)
		}
		s.st.Aliases = append(s.st.Aliases, na)
	}
	if err := s.saveLocked(); err != nil {
		s.st.Aliases = before
		return alias{}, err
	}
	return old, nil
}

// clearAlias removes a session's name and returns it ("" when it had none).
func (s *store) clearAlias(device string, sess session) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := append([]alias(nil), s.st.Aliases...)
	old := ""
	kept := make([]alias, 0, len(s.st.Aliases))
	for _, a := range s.st.Aliases {
		if a.is(device, sess) {
			old = a.Name
			continue
		}
		kept = append(kept, a)
	}
	if old == "" {
		return "", nil
	}
	s.st.Aliases = kept
	if err := s.saveLocked(); err != nil {
		s.st.Aliases = before
		return "", err
	}
	return old, nil
}

// clearAliasExact removes an alias record itself (a name whose session is gone).
func (s *store) clearAliasExact(device, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := append([]alias(nil), s.st.Aliases...)
	kept := make([]alias, 0, len(s.st.Aliases))
	found := false
	for _, a := range s.st.Aliases {
		if a.Device == device && sameName(a.Name, name) {
			found = true
			continue
		}
		kept = append(kept, a)
	}
	if !found {
		return false, nil
	}
	s.st.Aliases = kept
	if err := s.saveLocked(); err != nil {
		s.st.Aliases = before
		return false, err
	}
	return true, nil
}

// deviceList is one computer's session list. Complete means it holds every session (archived included) and
// the computer answered, so a session missing from it is gone, not just filtered out.
type deviceList struct {
	device   string
	sessions []session
	complete bool
}

// sweepAliases records which named sessions were just seen (refreshing their ids and last-seen time) and
// drops the names of sessions missing from a complete list, or of a computer that wasn't asked at all, for
// longer than aliasTTL. It returns the dropped ones.
func (s *store) sweepAliases(now time.Time, lists []deviceList) []alias {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.st.Aliases) == 0 {
		return nil
	}
	byDev := map[string]deviceList{}
	for _, l := range lists {
		byDev[l.device] = l
	}
	var dropped []alias
	changed := false
	kept := make([]alias, 0, len(s.st.Aliases))
	for _, a := range s.st.Aliases {
		l, asked := byDev[a.Device]
		var hit *session
		for i := range l.sessions {
			if a.is(a.Device, l.sessions[i]) {
				hit = &l.sessions[i]
				break
			}
		}
		switch {
		case hit != nil:
			if hit.SessionID != "" && hit.SessionID != a.SessionID || hit.AppSessionID != "" && hit.AppSessionID != a.AppSessionID ||
				now.Sub(a.Seen) >= aliasSeenEvery {
				a.SessionID, a.AppSessionID = firstNonEmpty(hit.SessionID, a.SessionID), firstNonEmpty(hit.AppSessionID, a.AppSessionID)
				a.Cwd, a.RepoKey, a.Title = firstNonEmpty(hit.Cwd, a.Cwd), firstNonEmpty(hit.RepoKey, a.RepoKey), firstNonEmpty(oneLine(hit.Title, 200), a.Title)
				a.Seen = now
				changed = true
			}
		case (!asked || l.complete) && now.Sub(a.Seen) > aliasTTL:
			dropped = append(dropped, a)
			changed = true
			continue
		}
		kept = append(kept, a)
	}
	if changed {
		s.st.Aliases = kept
		_ = s.saveLocked()
	}
	return dropped
}

// ---- resolving a name ----

// lookupSession finds a session by Claude Code id or app id and returns the computers' lists it read, so the
// caller can check names against them and sweep stale names.
func lookupSession(ctx context.Context, h sisterHost, device, id string) (rubiplugin.HomeDevice, session, []deviceSessions, error) {
	all, err := listSessions(ctx, h, "", true)
	if err != nil {
		return rubiplugin.HomeDevice{}, session{}, nil, err
	}
	for _, ds := range all {
		if device != "" && ds.device.ID != device && ds.device.Name != device {
			continue
		}
		for _, s := range ds.list {
			if id != "" && (s.SessionID == id || s.AppSessionID == id) {
				return ds.device, s, all, nil
			}
		}
	}
	return rubiplugin.HomeDevice{}, session{}, all, errors.New("no such Claude Code session on your computers (list them with claude_code_sessions)")
}

// sweepWanted says whether a full list (archived sessions included) should be read now to look for stale
// names: only when names exist, and at most every sweepEvery.
func (s *sisters) sweepWanted() bool {
	if len(s.st.aliases()) == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Sub(s.lastSweep) >= sweepEvery
}

// sweep feeds session lists to the alias bookkeeping: every listed named session is noted as seen. Names are
// dropped only when full says the lists hold every session (no repo filter, archived included) and a list is
// whole: its computer answered and Rubi Home did not say it was cut or stale. A list that is not whole never
// proves a session gone.
func (s *sisters) sweep(h sisterHost, all []deviceSessions, full bool) {
	var lists []deviceList
	whole := full
	for _, ds := range all {
		ok := full && ds.err == nil && !ds.partial
		whole = whole && ok
		lists = append(lists, deviceList{device: ds.device.ID, sessions: ds.list, complete: ok})
	}
	if full && len(all) > 0 && whole {
		s.mu.Lock()
		s.lastSweep = s.now()
		s.mu.Unlock()
	}
	for _, a := range s.st.sweepAliases(s.now(), lists) {
		h.Audit("session_name_expired", map[string]any{"device": a.Device, "name": oneLine(a.Name, maxNameRunes), "session": a.SessionID})
	}
}

// resolveSession finds the session a Bot means by session_id or by a name (not both). A name is looked up
// among the aliases of the computer (device narrows it; without one a name used on several computers is
// ambiguous). Errors say what to do.
func (s *sisters) resolveSession(ctx context.Context, h sisterHost, device, id, name string) (rubiplugin.HomeDevice, session, []deviceSessions, error) {
	none := rubiplugin.HomeDevice{}
	id, name = strings.TrimSpace(id), strings.TrimSpace(name)
	switch {
	case id != "" && name != "":
		return none, session{}, nil, errors.New("pass session_id or name, not both")
	case id == "" && name == "":
		return none, session{}, nil, errors.New("pass session_id, or the name of a named session (claude_code_sessions shows both)")
	case id != "":
		d, sess, all, err := lookupSession(ctx, h, device, id)
		if all != nil {
			s.sweep(h, all, s.sweepWanted())
		}
		return d, sess, all, err
	}
	devID := ""
	if device != "" {
		d, err := s.pickDevice(h, device)
		if err != nil {
			return none, session{}, nil, err
		}
		devID = d.ID
	}
	found := s.st.aliasesNamed(devID, name)
	switch len(found) {
	case 0:
		return none, session{}, nil, fmt.Errorf("no session is named %q%s", oneLine(name, maxNameRunes), s.knownNames(devID))
	case 1:
	default:
		var where []string
		for _, a := range found {
			where = append(where, firstNonEmpty(a.DeviceName, a.Device))
		}
		return none, session{}, nil, fmt.Errorf("%q names sessions on several computers (%s): pass device", oneLine(name, maxNameRunes), strings.Join(where, ", "))
	}
	a := found[0]
	d, sess, all, err := lookupSession(ctx, h, a.Device, firstNonEmpty(a.AppSessionID, a.SessionID))
	if err != nil && a.AppSessionID != "" && a.SessionID != "" {
		d, sess, all, err = lookupSession(ctx, h, a.Device, a.SessionID)
	}
	if all != nil {
		s.sweep(h, all, s.sweepWanted())
	}
	if err != nil {
		// Not in the list. If the computer's list can't prove it (cut, stale, or the computer didn't answer), the
		// stored ids are the best there is: use them, with what the session looked like when last seen.
		for _, ds := range all {
			if ds.device.ID == a.Device && (ds.partial || ds.err != nil) {
				return ds.device, session{SessionID: a.SessionID, AppSessionID: a.AppSessionID, Title: a.Title, Cwd: a.Cwd, RepoKey: a.RepoKey,
					Role: "unknown", State: "unknown"}, all, nil
			}
		}
		return none, session{}, all, fmt.Errorf("the session named %q isn't there any more (a name goes after %d days without its session); list sessions with claude_code_sessions", oneLine(name, maxNameRunes), int(aliasTTL.Hours()/24))
	}
	return d, sess, all, nil
}

func (s *sisters) knownNames(device string) string {
	var names []string
	for _, a := range s.st.aliases() {
		if device == "" || a.Device == device {
			names = append(names, fmt.Sprintf("%q", oneLine(a.Name, maxNameRunes)))
		}
	}
	slices.Sort(names)
	if len(names) == 0 {
		return " (no session has a name yet; use claude_code_rename or the Rubi panel)"
	}
	if len(names) > 10 {
		names = append(names[:10], "…")
	}
	return " (named sessions: " + strings.Join(names, ", ") + ")"
}

// ---- the tool ----

type renameIn struct {
	Agent         string `json:"rubi_agent" jsonschema:"your Bot name as connected to Rubi"`
	AgentCode     string `json:"rubi_agent_code,omitempty" jsonschema:"the agent_code of your latest Rubi webhook (or call rubi_verify with your name to get one); proves you are that Bot"`
	VerifiedAgent string `json:"rubi_verified_agent,omitempty" jsonschema:"set by Rubi; don't pass it"`
	SessionID     string `json:"session_id,omitempty" jsonschema:"the session to name: session_id or app_session_id from claude_code_sessions. Leave out (with session_name) for the session you are bound to"`
	SessionName   string `json:"session_name,omitempty" jsonschema:"the session's current name, instead of session_id"`
	Device        string `json:"device,omitempty" jsonschema:"the computer, when there are several"`
	Name          string `json:"name,omitempty" jsonschema:"the new name: 1 to 64 plain characters, unique on that computer (ignoring case), not like an id"`
	Clear         bool   `json:"clear,omitempty" jsonschema:"remove the session's name instead of setting one"`
}

type renameTicket struct {
	Sister       string `json:"sister"`
	Device       string `json:"device"`
	DeviceName   string `json:"device_name"`
	SessionID    string `json:"session_id"`
	AppSessionID string `json:"app_session_id,omitempty"`
	Name         string `json:"name,omitempty"`
	Clear        bool   `json:"clear,omitempty"`
}

// freeName checks a name against the session ids the list showed (a name that equals an id is refused).
func freeName(name string, all []deviceSessions, device string) error {
	for _, ds := range all {
		if ds.device.ID != device {
			continue
		}
		for _, x := range ds.list {
			if sameName(name, x.SessionID) || x.AppSessionID != "" && sameName(name, x.AppSessionID) {
				return errors.New("the name is the id of a session; choose a descriptive name")
			}
		}
	}
	return nil
}

func (s *sisters) renameTool(ctx context.Context, h sisterHost, in renameIn) (any, error) {
	sister := strings.TrimSpace(in.VerifiedAgent)
	if sister == "" || len(sister) > 64 {
		return nil, errors.New("Rubi didn't confirm which Bot you are: pass rubi_agent (your Bot name) and rubi_agent_code (the agent_code of your latest Rubi webhook, or call rubi_verify to get one)")
	}
	name := ""
	if in.Clear {
		if strings.TrimSpace(in.Name) != "" {
			return nil, errors.New("pass name or clear, not both")
		}
	} else {
		var err error
		if name, err = checkAliasName(in.Name); err != nil {
			return nil, err
		}
	}
	var (
		d    rubiplugin.HomeDevice
		sess session
		all  []deviceSessions
		err  error
	)
	if in.SessionID == "" && in.SessionName == "" {
		// The Bot's own session.
		var mine *binding
		for _, b := range s.st.bindings() {
			if sameBot(b.Sister, sister) && (in.Device == "" || b.Device == in.Device || b.DeviceName == in.Device) {
				b := b
				mine = &b
			}
		}
		if mine == nil {
			return nil, errors.New("you are not bound to a session: pass session_id (or session_name) of the session to name")
		}
		key := firstNonEmpty(mine.AppSessionID, mine.SessionID)
		if d, sess, all, err = lookupSession(ctx, h, mine.Device, key); err != nil {
			return nil, fmt.Errorf("the session you are bound to isn't there any more (%v)", err)
		}
		s.sweep(h, all, s.sweepWanted())
	} else {
		id, nm := strings.TrimSpace(in.SessionID), strings.TrimSpace(in.SessionName)
		if d, sess, all, err = s.resolveSession(ctx, h, in.Device, id, nm); err != nil {
			return nil, err
		}
	}
	// Counted only now, for a real session: a typo in an id doesn't use up the hour.
	if !s.allow("rename|"+strings.ToLower(sister), renamesPerHour) {
		return nil, fmt.Errorf("at most %d renames per hour", renamesPerHour)
	}
	if !in.Clear {
		if err := freeName(name, all, d.ID); err != nil {
			return nil, err
		}
	}
	t := renameTicket{Sister: sister, Device: d.ID, DeviceName: d.Name, SessionID: sess.SessionID, AppSessionID: sess.AppSessionID, Name: name, Clear: in.Clear}
	old, _ := s.st.aliasFor(d.ID, sess)
	if in.Clear && old.Name == "" {
		return map[string]any{"cleared": false, "session_id": sess.SessionID, "note": "that session has no name"}, nil
	}
	// A name the user (or another Bot, with the user's tap) gave is not the Bot's to replace or remove on its
	// own, even on its own session or under a project trust: that is the user's call.
	mayAlone := old.Name == "" || sameBot(old.SetBy, sister)

	// 1. The session the Bot is bound to: no approval.
	for _, b := range s.st.bindings() {
		if mayAlone && sameBot(b.Sister, sister) && b.Device == d.ID && (b.SessionID == sess.SessionID || b.AppSessionID != "" && b.AppSessionID == sess.AppSessionID) {
			res, err := s.executeRename(ctx, h, t, "bot", "own bound session", all)
			if m, ok := res.(map[string]any); ok && err == nil {
				m["approval"] = "none needed: you are bound to this session"
			}
			return res, err
		}
	}
	// 2. A session inside a project the user trusts, for a Bot bound inside it.
	if mayAlone {
		if pt := s.projectCovering(ctx, h, d.ID, sister, sess.Cwd, sess.RealCwd); pt != nil {
			h.Audit(auditMandateAll, map[string]any{"mandate": pt.ID, "project": pt.Root, "device": d.ID, "sister": sister, "action": "claude_code_rename",
				"session": sess.SessionID, "directory": sess.Cwd, "uses": pt.Uses})
			res, err := s.executeRename(ctx, h, t, "bot", "project trust "+pt.ID, all)
			if m, ok := res.(map[string]any); ok && err == nil {
				m["approval"] = "none needed: " + pt.ID + ", the user's trust of " + pt.Root
			}
			return res, err
		}
	}
	// 3. Anything else is the user's call.
	what := fmt.Sprintf("Names this session %q in Rubi", name)
	summary := fmt.Sprintf("Name a Claude Code session on %s %q for %s", d.Name, oneLine(name, 40), sister)
	if in.Clear {
		what = "Removes this session's name in Rubi"
		summary = fmt.Sprintf("Remove the name of a Claude Code session on %s for %s", d.Name, sister)
	}
	preview := map[string]any{"bot": sister, "computer": d.Name, "session": sess.SessionID, "title": sess.Title, "directory": sess.Cwd,
		"current_name": old.Name, "new_name": name,
		"what_it_does": what + ". It is a label kept in Rubi, shown in session lists and usable instead of the session's id; it changes nothing in Claude Code or the desktop app."}
	if old.Name != "" {
		preview["current_name_set_by"] = firstNonEmpty(old.SetBy, "unknown")
	}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindRename, Summary: summary, Preview: preview, Payload: t})
}

// executeRename sets or clears the name once it is allowed (by being the Bot's own session, a trust, an
// approval or the user in the panel). by and why go to the audit log. all is the computer's session list when
// the caller has one; without it (an approval that was answered later) the list is read again, because the
// name must still not equal a session's id by the time it is stored.
func (s *sisters) executeRename(ctx context.Context, h sisterHost, t renameTicket, by, why string, all []deviceSessions) (any, error) {
	if t.Device == "" || t.SessionID == "" && t.AppSessionID == "" {
		return nil, errors.New("bad payload")
	}
	sess := session{SessionID: t.SessionID, AppSessionID: t.AppSessionID}
	if t.Clear {
		old, err := s.st.clearAlias(t.Device, sess)
		if err != nil {
			return nil, err
		}
		if old != "" {
			h.Audit(auditRenamed, map[string]any{"device": t.Device, "session": t.SessionID, "old": oneLine(old, maxNameRunes), "new": "", "by": by, "sister": t.Sister, "approval": why})
		}
		s.dropNameList()
		return map[string]any{"cleared": old != "", "session_id": t.SessionID, "previous_name": old}, nil
	}
	name, err := checkAliasName(t.Name)
	if err != nil {
		return nil, err
	}
	if all == nil {
		lctx, cancel := context.WithTimeout(ctx, panelListTimeout)
		defer cancel()
		var lerr error
		_, _, all, lerr = lookupSession(lctx, h, t.Device, firstNonEmpty(t.AppSessionID, t.SessionID))
		got := false
		for _, ds := range all {
			if ds.device.ID == t.Device {
				if ds.err != nil {
					lerr = ds.err
				} else {
					got = true
				}
			}
		}
		if !got {
			return nil, fmt.Errorf("couldn't check the name against the computer's sessions (%v); try again", lerr)
		}
	}
	if err := freeName(name, all, t.Device); err != nil {
		return nil, err
	}
	setBy := t.Sister
	if by == "user" {
		setBy = "user"
	}
	old, err := s.st.setAlias(t.Device, t.DeviceName, sess, name, setBy, s.now().UTC())
	if err != nil {
		return nil, err
	}
	h.Audit(auditRenamed, map[string]any{"device": t.Device, "session": t.SessionID, "old": oneLine(old.Name, maxNameRunes), "new": name, "by": by, "sister": t.Sister, "approval": why})
	s.dropNameList()
	out := map[string]any{"renamed": true, "session_id": t.SessionID, "name": name,
		"next_step": "claude_code_sessions now shows this name, and claude_code_bind accepts it as name."}
	if old.Name != "" {
		out["previous_name"] = old.Name
	}
	return out, nil
}
