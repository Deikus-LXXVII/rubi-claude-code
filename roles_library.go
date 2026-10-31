package main

// Library skills in roles (docs/design/agent-roles.md section 8, "In roles"). Rubi's core keeps the shared skill
// library and signs what its curator admits; this plugin reads it through the host method library.get, puts the
// skill into a role with source "library" and the signature, and Rubi Home verifies the signature against the key it
// pinned. Attaching an admitted skill is tier 1 (admitted means trusted). A role that follows a skill (no pin) is
// re-materialized as a new version when a newer version is admitted; a withdrawn version is dropped at the next
// materialization; a deprecated one stays but is not attached anew. Updates change skill text only, never tools,
// hosts or MCP servers. Nothing here writes to the library: submitting a skill is a Bot tool in core
// (rubi_library_submit).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// libraryActor is the "Bot" of an automatic update. It is reserved (a Bot can't take the name) and its changes are
	// the user's standing choice to follow a skill, so the Bot-only rules (project trust, rate limit) don't apply.
	libraryActor = "library"

	auditLibraryDropped = "role.library_dropped"

	libraryEvery       = 10 * time.Minute // the periodic check of every role that follows or pins a library skill
	libraryViewEvery   = 30 * time.Second // the least time between two checks of one role on its page
	maxLibRolesPerTick = 12               // roles one periodic check looks at
	maxLibCallsPerTick = 40               // library.get calls one periodic check makes
	maxLibCallsPerView = 12
)

// libraryHost is the part of the host that reads the shared skill library: the read-only host method library.get
// {id, version?} of a plugin that declares the claude-agent capability (version 0 asks for the latest admitted). The
// host in tests implements it; Rubi's SDK Host needs a method of this shape.
type libraryHost interface {
	LibraryGet(ctx context.Context, id string, version int, out any) error
}

// libInfo is the answer of library.get.
type libInfo struct {
	ID             string   `json:"id"`
	Version        int      `json:"version"`
	State          string   `json:"state"`
	Description    string   `json:"description"`
	Tags           []string `json:"tags"`
	SHA256         string   `json:"sha256"`
	Content        string   `json:"content"`
	AdmittedBy     string   `json:"admitted_by"`
	SelfAdmitted   bool     `json:"self_admitted"`
	ScanVerdict    string   `json:"scan_verdict"`
	Signature      string   `json:"signature"`
	LatestAdmitted int      `json:"latest_admitted"`
}

var (
	libRefRE = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,47})(?:@([1-9][0-9]{0,5}))?$`)
	libSigRE = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{1,600}$`)
	shaHexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

	errLibraryUnavailable = errors.New("this build of the plugin can't read the skill library; update Rubi and the claude-code plugin")
)

// errNotAdmitted is core's answer for a skill or version that isn't admitted (withdrawn, rejected, proposed or
// unknown look the same to a plugin). Any other failure (Rubi locked, no answer) is not that.
type errNotAdmitted struct{ msg string }

func (e errNotAdmitted) Error() string { return e.msg }

// libraryGet reads one version (0: the latest admitted) and checks what came back before anyone relies on it.
func libraryGet(ctx context.Context, h sisterHost, id string, version int) (libInfo, error) {
	lh, ok := h.(libraryHost)
	if !ok {
		return libInfo{}, errLibraryUnavailable
	}
	var in libInfo
	gctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := lh.LibraryGet(gctx, id, version, &in); err != nil {
		if strings.Contains(err.Error(), "no admitted skill") || strings.Contains(err.Error(), "has no admitted version") {
			return libInfo{}, errNotAdmitted{oneLine(err.Error(), 160)}
		}
		return libInfo{}, fmt.Errorf("couldn't read the skill library: %s", oneLine(err.Error(), 160))
	}
	if err := checkLibInfo(in, id, version); err != nil {
		return libInfo{}, err
	}
	return in, nil
}

// checkLibInfo is what the plugin verifies itself (Rubi Home verifies the signature): the answer is for the skill
// asked, the text is what the hash says, and the signature has the shape Home takes.
func checkLibInfo(in libInfo, id string, version int) error {
	switch {
	case in.ID != id:
		return errors.New("the library answered with another skill than " + id)
	case in.Version < 1 || in.Version > 999999 || version != 0 && in.Version != version:
		return errors.New("the library answered with another version than asked")
	case in.State != "admitted" && in.State != "deprecated":
		return errNotAdmitted{"no admitted skill " + id}
	case !shaHexRE.MatchString(in.SHA256) || !utf8.ValidString(in.Content) || len(in.Content) == 0 || len(in.Content) > maxSkillBytes:
		return errors.New("the library's text for " + id + " isn't usable")
	case func() bool { sum := sha256.Sum256([]byte(in.Content)); return hex.EncodeToString(sum[:]) != in.SHA256 }():
		return errors.New("the library's text for " + id + " doesn't match its hash")
	case !libSigRE.MatchString(in.Signature):
		return errors.New("the library gave no usable signature for " + id)
	case in.ScanVerdict != "pass" && in.ScanVerdict != "flag":
		return errors.New("the library's scan verdict for " + id + " isn't pass or flag")
	}
	return nil
}

// librarySkill is the role entry for an info (pin "" follows the latest admitted).
func librarySkill(in libInfo, pin, addedBy string) roleSkill {
	return roleSkill{Name: in.ID, Source: "library", LibraryID: in.ID, Pin: pin, Resolved: strconv.Itoa(in.Version),
		SHA256: in.SHA256, Sig: in.Signature, AddedBy: addedBy}
}

// roleSkillsAddLibrary puts an admitted library skill into a role ("id" follows the latest admitted, "id@3" pins).
func (s *sisters) roleSkillsAddLibrary(ctx context.Context, h sisterHost, in roleSkillsAddIn) (any, error) {
	m := libRefRE.FindStringSubmatch(strings.TrimSpace(in.Library))
	if m == nil {
		if _, err := s.who(h, in.roleWho); err != nil {
			return nil, err
		}
		return rejected("library must be a skill id such as design-tokens (follows the latest admitted version) or design-tokens@3 (pins version 3)"), nil
	}
	id, pin := m[1], m[2]
	want := 0
	if pin != "" {
		want, _ = strconv.Atoi(pin)
	}
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.skills.add", false, func(c roleCaller, cur, next *role) (map[string]string, []string, error) {
		old := slices.IndexFunc(cur.Skills, func(k roleSkill) bool { return k.Name == id })
		exists := old >= 0
		if exists && cur.Skills[old].Source != "library" {
			return nil, []string{"the role has a skill named " + id + " that isn't from the library; remove it first"}, nil
		}
		info, err := libraryGet(ctx, h, id, want)
		var na errNotAdmitted
		switch {
		case errors.As(err, &na):
			return nil, []string{id + ifElse(pin != "", "@"+pin, "") + " is not an admitted library skill, so it can't be attached (" + na.msg + ")"}, nil
		case err != nil:
			return nil, nil, err
		case info.State != "admitted":
			return nil, []string{id + "@" + strconv.Itoa(info.Version) + " is deprecated: it keeps working in roles that already have it, but takes no new attachments; use a newer version"}, nil
		}
		entry := librarySkill(info, pin, botID(c.Bot))
		if exists {
			prev := cur.Skills[old]
			entry.AddedBy = prev.AddedBy
			if prev.SHA256 == entry.SHA256 && prev.Pin == entry.Pin && prev.Sig == entry.Sig {
				return nil, nil, nil // nothing differs; changeRole says so
			}
			next.Skills = slices.Clone(cur.Skills)
			next.Skills[old] = entry
		} else {
			next.Skills = append(slices.Clone(cur.Skills), entry)
		}
		return map[string]string{info.SHA256: info.Content}, nil, nil
	})
}

// ---- following ----

// libChange is one thing a check found.
type libChange struct {
	Name     string
	From, To int
	Dropped  bool
	Reason   string
}

func (c libChange) text() string {
	if c.Dropped {
		return fmt.Sprintf("%s %d withdrawn, dropped", clipOne(c.Name, 48), c.From)
	}
	return fmt.Sprintf("%s %d -> %d", clipOne(c.Name, 48), c.From, c.To)
}

// planLibrary looks at each library skill of cur and returns the role it should become (nil: nothing to do), the new
// texts and what changed. calls is the budget of library.get calls left. A failure that isn't "not admitted" (the
// library is locked, no answer) leaves that skill alone.
func (s *sisters) planLibrary(ctx context.Context, h sisterHost, cur *role, calls *int) (*role, map[string]string, []libChange) {
	var next *role
	blobs := map[string]string{}
	var changes []libChange
	get := func(id string, version int) (libInfo, error) {
		if *calls <= 0 {
			return libInfo{}, errors.New("budget")
		}
		*calls--
		return libraryGet(ctx, h, id, version)
	}
	for _, k := range cur.Skills {
		if k.Source != "library" || k.LibraryID == "" {
			continue
		}
		resolved, err := strconv.Atoi(k.Resolved)
		if err != nil || resolved < 1 {
			continue
		}
		if next == nil {
			next = cur.clone()
		}
		drop := func() {
			changes = append(changes, libChange{Name: k.Name, From: resolved, Dropped: true})
			next.Skills = slices.DeleteFunc(next.Skills, func(x roleSkill) bool { return x.Name == k.Name })
		}
		if k.Pin == "" {
			info, err := get(k.LibraryID, 0)
			var na errNotAdmitted
			if err == nil && info.State == "admitted" && info.Version > resolved {
				e := librarySkill(info, "", k.AddedBy)
				next.Skills[slices.IndexFunc(next.Skills, func(x roleSkill) bool { return x.Name == k.Name })] = e
				blobs[info.SHA256] = info.Content
				changes = append(changes, libChange{Name: k.Name, From: resolved, To: info.Version})
				continue
			}
			if err != nil && !errors.As(err, &na) {
				continue
			}
		}
		// The version the role has: still admitted or deprecated, or gone.
		if _, err := get(k.LibraryID, resolved); errors.As(err, new(errNotAdmitted)) {
			drop()
		}
	}
	if len(changes) == 0 {
		return nil, nil, nil
	}
	return next, blobs, changes
}

// followLibrary re-materializes a role whose library skills moved: a newer admitted version for a following skill,
// a withdrawn version dropped. It is the plugin's own change (libraryActor), audited per role.
func (s *sisters) followLibrary(ctx context.Context, h sisterHost, dev string, roleID string, calls *int) ([]libChange, error) {
	d, err := s.roleDeviceFor(ctx, h, dev)
	if err != nil {
		return nil, err
	}
	cur, err := s.getRole(ctx, h, d.ID, roleID, 0)
	if err != nil {
		return nil, err
	}
	if cur.Status != "active" || !slices.ContainsFunc(cur.Skills, func(k roleSkill) bool { return k.Source == "library" }) {
		return nil, nil
	}
	next, blobs, changes := s.planLibrary(ctx, h, cur, calls)
	if next == nil {
		return nil, nil
	}
	var parts []string
	for _, c := range changes {
		parts = append(parts, c.text())
	}
	res, err := s.changeRole(ctx, h, roleChangeReq{Bot: libraryActor, ByUser: true, Dev: d, Op: "role.library.follow", Cur: cur, Next: next, Blobs: blobs,
		Lim: roleLimitsOf(h), Summary: strings.Join(parts, "; ")})
	if err != nil {
		return nil, err
	}
	m, _ := res.(map[string]any)
	if m["status"] != "applied" {
		return nil, fmt.Errorf("the library update of role %s wasn't applied: %v", cur.ID, firstNonEmptyAny(m["reasons"], m["status"]))
	}
	for _, c := range changes {
		if c.Dropped {
			h.Audit(auditLibraryDropped, map[string]any{"role": cur.ID, "project": cur.Project, "skill": c.Name, "version": c.From, "device": d.ID, "audit_id": m["audit_id"]})
		}
	}
	return changes, nil
}

// followOnView is the check when a role's page is opened: at most every libraryViewEvery per role.
func (s *sisters) followOnView(ctx context.Context, h sisterHost, dev, roleID string) []libChange {
	if _, ok := h.(libraryHost); !ok {
		return nil
	}
	s.mu.Lock()
	if s.libSeen == nil {
		s.libSeen = map[string]time.Time{}
	}
	if t, ok := s.libSeen[roleID]; ok && s.now().Sub(t) < libraryViewEvery {
		s.mu.Unlock()
		return nil
	}
	if len(s.libSeen) > 200 {
		s.libSeen = map[string]time.Time{}
	}
	s.libSeen[roleID] = s.now()
	s.mu.Unlock()
	calls := maxLibCallsPerView
	ch, err := s.followLibrary(ctx, h, dev, roleID, &calls)
	if err != nil {
		h.Logf("library update of %s: %v", roleID, err)
	}
	return ch
}

// libraryTick is the periodic check, called from the watcher's refresh: at most once per libraryEvery, bounded in
// roles and in library.get calls.
func (s *sisters) libraryTick(ctx context.Context, h sisterHost, devices []string) {
	if _, ok := h.(libraryHost); !ok {
		return
	}
	s.mu.Lock()
	if !s.libTickAt.IsZero() && s.now().Sub(s.libTickAt) < libraryEvery {
		s.mu.Unlock()
		return
	}
	s.libTickAt = s.now()
	s.mu.Unlock()
	calls, roles := maxLibCallsPerTick, 0
	for _, dev := range devices {
		rd, err := s.refreshRoles(ctx, h, dev, false)
		if err != nil {
			continue
		}
		var ids []string
		for id, r := range rd.roles {
			if r.Status == "active" && slices.ContainsFunc(r.Skills, func(k roleSkill) bool { return k.Source == "library" }) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			if roles >= maxLibRolesPerTick || calls <= 0 || ctx.Err() != nil {
				return
			}
			roles++
			if _, err := s.followLibrary(ctx, h, dev, id, &calls); err != nil {
				h.Logf("library update of %s: %v", id, err)
			}
		}
	}
}

// ---- the panel's Pin and Follow ----

// panelSkillPin pins a following library skill to the version it has now, or makes a pinned one follow the latest.
func (s *sisters) panelSkillPin(ctx context.Context, h sisterHost, device, roleID, skill string, pin bool) (any, error) {
	res, err := s.panelRoleItem(ctx, h, ifElse(pin, "role_skill_pin", "role_skill_follow"), device, roleID, skill, "", nil, nil)
	if err != nil || pin {
		return res, err
	}
	// Following: catch up at once.
	calls := maxLibCallsPerView
	ch, ferr := s.followLibrary(ctx, h, device, roleID, &calls)
	if m, ok := res.(map[string]any); ok && len(ch) > 0 {
		var parts []string
		for _, c := range ch {
			parts = append(parts, c.text())
		}
		m["library_update"] = strings.Join(parts, "; ")
	} else if ferr != nil {
		if m, ok := res.(map[string]any); ok {
			m["library_note"] = "couldn't check for a newer version now: " + oneLine(ferr.Error(), 120)
		}
	}
	return res, nil
}
