package main

// Project trust: one approval trusts a whole project until 04:00. Where a 2-hour trust (md_…, mandate.go)
// is one Claude Code session in one directory, a project trust (pt_…) covers every session on that
// computer whose directory is inside the project's root: the one that asked, the others, the ones started
// later, and the Bot bound to a session of the project (it may start and bind sessions in the project
// without a new approval). The command check is the same one the 2-hour trust uses (mandateAllows) with
// one more rule: a command that switches to or creates a git branch is allowed only for a name that
// matches the trust's branch pattern (default agent/*). Push and every remote operation, --force, sudo,
// the network, installs, tags, writes outside the root and credential paths still ask.
//
// The root is the project's top directory as Rubi Home reports it (claude-sessions.list project_root). It
// ends at 04:00 local time (the next one, at most 24 hours ahead) or after ptMaxUses allowed commands.
// Rubi Home doesn't tell its computer's time zone, so the plugin uses the zone of the machine Rubi runs on
// and the approval says so. It lives in the plugin's saved state like a 2-hour trust, so a restart of Rubi
// Home, of the plugin or of Rubi keeps it until it ends or is revoked.
//
// A project trust can also be given "until revoked" (Unlimited): it has no end time and no count limit, and
// only a revoke (the panel, claude_code_mandates) or a locked Rubi stops it; it is never pruned. It is the
// same trust in every other respect (same check, same branch rule, same always-ask list, each allow audited
// and counted), and the approval says in capitals that it has no end.

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	optionTrustProject     = "trust_project"
	optionTrustForever     = "trust_project_until_revoked"
	untilFour              = "0400"    // claude_code_trust_project until=: the default, as before
	untilRevoked           = "revoked" // claude_code_trust_project until=: no end time
	kindTrustProject       = "claude-code.trust_project"
	ptMaxUses              = 2000
	maxProjectTrusts       = 20
	defaultBranchPattern   = "agent/*"
	ptRefreshHour          = 4
	ptMaxTTL               = 24 * time.Hour
	maxPatternLen          = 80
	bindsUnderTrustPerHour = 20 // binds a Bot makes under a project trust, without an approval
	trustsPerHour          = 5  // asks for a project trust per Bot (each one is a strong approval)
	rootLookupWait         = 5 * time.Second
)

// projectTrustExpiryHook lets the end-to-end test shorten a trust (rubie2e builds only; nil in a release).
var projectTrustExpiryHook func(now time.Time) (time.Time, bool)

type projectTrust struct {
	ID            string    `json:"id"`
	Device        string    `json:"device"`
	DeviceName    string    `json:"device_name,omitempty"`
	Root          string    `json:"root"`
	BranchPattern string    `json:"branch_pattern"`
	Sister        string    `json:"sister,omitempty"` // the Bot whose tool asked for it ("" when granted on a run approval)
	Zone          string    `json:"zone,omitempty"`
	RealRoot      string    `json:"real_root,omitempty"` // Root with symlinks resolved, as Rubi Home reported it
	Issued        time.Time `json:"issued"`
	Expires       time.Time `json:"expires"`
	MaxUses       int       `json:"max_uses"`
	Uses          int       `json:"uses"`
	// Unlimited: "until revoked". Expires stays zero and MaxUses 0, so a plugin that doesn't know the field
	// reads the record as ended and drops it (it fails closed).
	Unlimited bool `json:"unlimited,omitempty"`
	// Project is the Rubi Home agent project (claude-agent) the trust is for; Root is then "/work", the
	// project's directory inside its VM. "" for a Claude Code session seen through the hook.
	Project string `json:"project,omitempty"`
}

// live: a timed trust ends at Expires or after MaxUses; an unlimited one only when it is revoked.
func (p projectTrust) live(now time.Time) bool {
	if p.Unlimited {
		return true
	}
	return now.Before(p.Expires) && p.Uses < p.MaxUses
}

func (p projectTrust) covers(device, cwd string) bool {
	return p.Device == device && within(p.Root, cwd)
}

// trustExpiry is the next 04:00 after now in loc, at most 24 hours ahead. time.Date does the calendar
// arithmetic in the zone, so a day of 23 or 25 hours (daylight saving) still ends at 04:00.
func trustExpiry(now time.Time, loc *time.Location) time.Time {
	if projectTrustExpiryHook != nil {
		if t, ok := projectTrustExpiryHook(now); ok {
			return t
		}
	}
	n := now.In(loc)
	t := time.Date(n.Year(), n.Month(), n.Day(), ptRefreshHour, 0, 0, 0, loc)
	if !t.After(n) {
		t = time.Date(n.Year(), n.Month(), n.Day()+1, ptRefreshHour, 0, 0, 0, loc)
	}
	if limit := n.Add(ptMaxTTL); t.After(limit) {
		t = limit
	}
	return t
}

// homeFolders are the folders a person keeps things in; none is a project, whatever sits inside them.
var homeFolders = map[string]bool{"documents": true, "desktop": true, "downloads": true, "library": true, "pictures": true,
	"music": true, "movies": true, "public": true, "applications": true, "dropbox": true, "icloud drive": true}

// rootProblem says why dir can't be a trusted project root ("" when it can): it is what Rubi Home reported
// as the project's top directory, and must be a real place, not a home directory, a disk or a folder of
// documents. repoKey "local:…" means the folder has no remote (a plain folder or a repository without
// origin), which the plugin can't tell from each other, so such a root must be deeper.
func rootProblem(root, repoKey string) string {
	parts := strings.Split(strings.Trim(root, "/"), "/")
	switch {
	case root == "":
		return "Rubi Home doesn't know this session's project directory"
	case repoKey == "":
		return "Rubi Home doesn't report a project for this session"
	case !path.IsAbs(root) || path.Clean(root) != root:
		return "the project directory isn't a clean absolute path"
	case strings.ContainsFunc(root, func(r rune) bool { return unicode.IsControl(r) }):
		return "the project directory has a control character in its name"
	case len(parts) < 3:
		return "the project directory (" + root + ") is too high up (a home directory, a disk or higher) to trust as a project"
	case parts[0] == "Volumes" && len(parts) < 4 && strings.HasPrefix(repoKey, "local:"):
		return "the project directory (" + root + ") is a disk, not a project"
	case homeFolders[strings.ToLower(parts[len(parts)-1])] && len(parts) <= 4:
		return "the project directory (" + root + ") is a folder of documents, not a project"
	case strings.HasPrefix(repoKey, "local:") && len(parts) < 4:
		return "the project directory (" + root + ") has no git remote and is too high up to tell a project from an ordinary folder; use a project with a remote, or a deeper folder"
	case secretPath(root) != "":
		return "the project directory (" + root + ") names a credential path"
	}
	return ""
}

// realProblem: with symlinks resolved the session's directory must still be inside the project's root (both
// are reported by newer Rubi Homes; an older one reports neither, and the lexical check is all there is).
func realProblem(realRoot, realCwd string) string {
	if realRoot != "" && realCwd != "" && !within(realRoot, realCwd) {
		return "with symlinks resolved the session's directory (" + realCwd + ") is outside the project (" + realRoot + ")"
	}
	return ""
}

// protectedBranches are names no pattern may match: the branches work ends up on.
var protectedBranches = []string{"main", "master", "trunk", "develop", "development", "dev", "release", "stable", "production", "prod"}

// checkPattern returns the branch pattern to use ("" means the default) or why it is refused. Only plain
// characters are allowed, so the approval text shows exactly what is trusted.
func checkPattern(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return defaultBranchPattern, nil
	}
	if len(p) > maxPatternLen || strings.HasPrefix(p, "-") || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return "", errors.New("branch_pattern must be a short branch pattern like agent/* (no leading - or /, no ..)")
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-/*?[]^", r)) {
			return "", fmt.Errorf("branch_pattern has a character (%q) that isn't allowed; use letters, digits and ._-/*?[]", r)
		}
	}
	if _, err := path.Match(p, "x"); err != nil {
		return "", errors.New("branch_pattern isn't a valid pattern (path.Match syntax, like agent/*)")
	}
	for _, n := range protectedBranches {
		if ok, _ := path.Match(p, n); ok {
			return "", fmt.Errorf("branch_pattern %q would let Claude switch to %s; use a prefix like agent/*", p, n)
		}
	}
	return p, nil
}

// trustOffer is what a project trust approval shows and grants; it travels in the approval's payload, so
// what the user read is what is granted.
type trustOffer struct {
	Root       string    `json:"root"`
	Pattern    string    `json:"pattern"`
	Expires    time.Time `json:"expires"`
	Zone       string    `json:"zone"` // the zone name the expiry was shown in
	DeviceName string    `json:"device_name,omitempty"`
	RepoKey    string    `json:"repo_key,omitempty"`
	RealRoot   string    `json:"real_root,omitempty"`
	Unlimited  bool      `json:"unlimited,omitempty"` // "until revoked": Expires is zero
	Project    string    `json:"project,omitempty"`   // a Rubi Home agent project (Root is /work)
}

// forever is the same offer without an end: the project trust "until I revoke it".
func (o trustOffer) forever() trustOffer {
	o.Unlimited, o.Expires, o.Zone = true, time.Time{}, ""
	return o
}

// offerFor builds the offer for root on a computer now, or says why there is none.
func (s *sisters) offerFor(root, repoKey, pattern, deviceName string) (trustOffer, error) {
	if why := rootProblem(root, repoKey); why != "" {
		return trustOffer{}, errors.New(why)
	}
	pattern, err := checkPattern(pattern)
	if err != nil {
		return trustOffer{}, err
	}
	loc := s.zone()
	now := s.now()
	return trustOffer{Root: root, Pattern: pattern, Expires: trustExpiry(now, loc).UTC(), Zone: loc.String(), DeviceName: deviceName, RepoKey: repoKey}, nil
}

// agentOffer is the offer for a project of Rubi Home's agent path: its root is /work, the project's directory
// inside its VM, and the trust is for that project only.
func (s *sisters) agentOffer(project, dir, deviceName, pattern string, unlimited bool) (trustOffer, error) {
	pattern, err := checkPattern(pattern)
	if err != nil {
		return trustOffer{}, err
	}
	loc := s.zone()
	o := trustOffer{Root: agentRoot, Pattern: pattern, Expires: trustExpiry(s.now(), loc).UTC(), Zone: loc.String(),
		DeviceName: deviceName + ", project " + oneLine(firstNonEmpty(dir, project), 60), Project: project}
	if unlimited {
		o = o.forever()
	}
	return o, nil
}

func (s *sisters) zone() *time.Location {
	if s.loc != nil {
		return s.loc
	}
	return time.Local
}

func (s *sisters) expiryTime(o trustOffer) time.Time {
	loc, err := time.LoadLocation(o.Zone)
	if err != nil || o.Zone == "Local" || o.Zone == "" {
		loc = s.zone()
	}
	return o.Expires.In(loc)
}

func (s *sisters) expiryText(o trustOffer) string {
	return s.expiryTime(o).Format("Mon 2 Jan 2006 15:04 MST")
}

// shortRoot keeps a long path readable in a button: the end of it, which names the project.
func shortRoot(root string) string {
	r := []rune(root)
	if len(r) <= 40 {
		return root
	}
	return "…" + string(r[len(r)-39:])
}

// trustLabel is the option's button: it names the project and the exact end (or that there is none).
func (s *sisters) trustLabel(o trustOffer) string {
	if o.Unlimited {
		return "Allow and trust the project " + shortRoot(o.Root) + " until I revoke it"
	}
	return "Allow and trust the project " + shortRoot(o.Root) + " until " + s.expiryText(o)
}

func (s *sisters) zoneNote(o trustOffer) string {
	name := o.Zone
	if name == "" || name == "Local" {
		name = ""
	} else {
		name += ", "
	}
	return "in the time zone of the machine Rubi runs on (" + name + s.expiryTime(o).Format("MST, UTC-07:00") + "), because Rubi Home doesn't report this computer's own"
}

// untilText says when a trust ends, for a line of a preview or a message.
func (s *sisters) untilText(unlimited bool, expires time.Time) string {
	if unlimited {
		return "UNTIL REVOKED — no end time"
	}
	return s.expiryText(trustOffer{Expires: expires})
}

// ageText is how long ago a trust was granted: "3 d 4 h ago", "2 h 5 min ago", "7 min ago".
func ageText(since, now time.Time) string {
	d := max(now.Sub(since), 0)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d d %d h ago", int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour))
	case d >= time.Hour:
		return fmt.Sprintf("%d h %d min ago", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
	return fmt.Sprintf("%d min ago", int(d/time.Minute))
}

// trustMeaning is the approval's text: what is trusted, where, until when, what it allows and what asks.
func (s *sisters) trustMeaning(o trustOffer, command bool) string {
	var b strings.Builder
	if command {
		b.WriteString("Claude Code runs this command. ")
	}
	ends := "until then"
	if o.Unlimited {
		ends = "until you revoke it"
		fmt.Fprintf(&b, "UNTIL REVOKED — no end time. This trust stays on across restarts of Rubi, of the plugin and of Rubi Home and across days and weeks, until you revoke it in the panel or with claude_code_mandates (while Rubi is locked nothing is allowed, but it is still there when you unlock). Nothing else ends it: there is no time limit and no limit on the number of commands (each use is still counted and audited). Rubi allows plain, listed commands by itself in every Claude Code session on %s whose directory is inside %s, including sessions started later. ",
			firstNonEmpty(o.DeviceName, "that computer"), o.Root)
	} else {
		fmt.Fprintf(&b, "Until %s (%s; at most 24 hours, so on a daylight-saving change it can end up to an hour before 04:00), Rubi allows plain, listed commands by itself in every Claude Code session on %s whose directory is inside %s, including sessions started later, each one audited (at most %d). ",
			s.expiryText(o), s.zoneNote(o), firstNonEmpty(o.DeviceName, "that computer"), o.Root, ptMaxUses)
	}
	b.WriteString("It uses the same check as the 2-hour trust: every option of a listed program is checked against a list, and that includes builds and tests (make, go test, npm run) and scripts, which run the project's own code with your rights, including network access and writing anywhere; Claude may have just written that code, so choose this only if you trust Claude with your rights in this project. Symlinks already in the project are followed by the commands that use them, and a directory counts by its path. ")
	fmt.Fprintf(&b, "Switching to or creating a git branch is allowed only for a name matching %s (a detached switch names a commit and asks unless it matches); commits, merges and rebases go to the branch a session is on, which may be main. git rebase needs an explicit --no-update-refs, because Rubi can't see your git configuration. ", o.Pattern)
	fmt.Fprintf(&b, "A Bot bound to a session in this project can also start a Claude Code session in it, or bind to another session in it, without a new approval %s. A session a Bot starts runs with the Claude desktop app's permission settings: if those skip permission prompts (bypassPermissions), its commands never ask and no trust or approval applies to it. ", ends)
	fmt.Fprintf(&b, "Still asks: git push and every remote git command, --force, sudo, network commands and installs, options that run another program, credential paths, writing outside %s or into .git, git tag, and switching to a branch outside %s. ", o.Root, o.Pattern)
	b.WriteString("Sessions already running with bypassPermissions never ask, so this trust does not apply to them; they run every command without you. ")
	if o.Unlimited {
		b.WriteString("Because it has no end, it covers every day's work in this project, builds and scripts that run the project's own code included, and a Bot that can open sessions in the project without asking (sessions that may skip permission prompts): look at the panel's list of trusted projects now and then and revoke what you no longer need. ")
	}
	b.WriteString("Revoke it in the panel or with claude_code_mandates")
	return b.String()
}

// runOptions are the options of a run approval; with an offer the third one is the project trust until
// 04:00 and the fourth the same trust until revoked.
func (s *sisters) runOptions(offer *trustOffer) []rubiplugin.Option {
	opts := manifestRunOptions()
	if offer != nil {
		f := offer.forever()
		opts = append(opts, rubiplugin.Option{Key: optionTrustProject, Label: s.trustLabel(*offer), Meaning: s.trustMeaning(*offer, true)},
			rubiplugin.Option{Key: optionTrustForever, Label: s.trustLabel(f), Meaning: s.trustMeaning(f, true)})
	}
	return opts
}

// projectOffer looks up the project root of the session behind r (Rubi Home reports it) and builds the
// offer. When it can't be offered (no root, an unsuitable root, a Rubi Home that doesn't say) it returns nil
// and why, which the approval shows.
func (s *sisters) projectOffer(ctx context.Context, h sisterHost, device rubiplugin.HomeDevice, r request) (*trustOffer, string) {
	ctx, cancel := context.WithTimeout(ctx, rootLookupWait)
	defer cancel()
	var res struct {
		Sessions []session `json:"sessions"`
	}
	if err := h.HomeCall(ctx, device.ID, "claude-sessions.list", map[string]any{"repo": r.Cwd}, &res); err != nil {
		return nil, "Rubi Home didn't list the sessions (" + oneLine(err.Error(), 100) + ")"
	}
	for _, x := range res.Sessions {
		if x.SessionID != r.SessionID {
			continue
		}
		if x.RepoKey == "" || !within(x.ProjectRoot, r.Cwd) {
			return nil, "Rubi Home doesn't report a project that holds this directory"
		}
		if why := realProblem(x.RealRoot, x.RealCwd); why != "" {
			return nil, why
		}
		o, err := s.offerFor(x.ProjectRoot, x.RepoKey, "", device.Name)
		if err != nil {
			return nil, err.Error()
		}
		o.RealRoot = x.RealRoot
		return &o, ""
	}
	return nil, "Rubi Home doesn't know this session yet"
}

// grantProject saves a project trust from an offer the user approved and audits it (and the one it replaced).
func (s *sisters) grantProject(h sisterHost, device, deviceName, sister string, o trustOffer) (projectTrust, error) {
	now := s.now().UTC()
	if o.Unlimited {
		if !o.Expires.IsZero() {
			return projectTrust{}, errors.New("a trust until revoked has no end time")
		}
	} else {
		if !now.Before(o.Expires) {
			return projectTrust{}, errors.New("the approval came after the trust's end time, so nothing was trusted; ask again")
		}
		if o.Expires.After(now.Add(ptMaxTTL)) {
			return projectTrust{}, errors.New("the trust's end time is more than 24 hours away")
		}
	}
	if o.Project != "" {
		if o.Root != agentRoot {
			return projectTrust{}, errors.New("an agent project's trust is for " + agentRoot)
		}
	} else if why := rootProblem(o.Root, o.RepoKey); why != "" {
		return projectTrust{}, errors.New(why)
	}
	pattern, err := checkPattern(o.Pattern)
	if err != nil {
		return projectTrust{}, err
	}
	pt := projectTrust{ID: newID("pt_"), Device: device, DeviceName: deviceName, Root: o.Root, BranchPattern: pattern, Sister: sister,
		Zone: o.Zone, RealRoot: o.RealRoot, Issued: now, Expires: o.Expires, MaxUses: ptMaxUses, Project: o.Project}
	if o.Unlimited {
		pt.MaxUses, pt.Unlimited = 0, true // no end time, no count limit; every allow is still audited
	}
	replaced, err := s.st.issueProject(pt, now)
	if err != nil {
		return projectTrust{}, err
	}
	for _, old := range replaced {
		h.Audit("project_trust_replaced", map[string]any{"mandate": old.ID, "by": pt.ID, "device": old.Device, "root": old.Root, "uses": old.Uses, "mode": trustMode(old), "age": ageText(old.Issued, now)})
	}
	h.Audit("project_trust_issued", map[string]any{"mandate": pt.ID, "device": pt.Device, "root": pt.Root, "branches": pt.BranchPattern,
		"mode": trustMode(pt), "expires": pt.Expires, "sister": sister})
	return pt, nil
}

// trustMode names a trust's mode for the audit.
func trustMode(p projectTrust) string {
	if p.Unlimited {
		return "until_revoked"
	}
	return "until_0400"
}

// ---- the sister tool ----

type trustIn struct {
	// Who is asking: as in claude_code_bind, Rubi confirms the Bot's name and passes it on.
	Agent         string `json:"rubi_agent" jsonschema:"your Bot name as connected to Rubi"`
	AgentCode     string `json:"rubi_agent_code,omitempty" jsonschema:"the agent_code of your latest Rubi webhook (or call rubi_verify with your name to get one); proves you are that Bot"`
	VerifiedAgent string `json:"rubi_verified_agent,omitempty" jsonschema:"set by Rubi; don't pass it"`
	BindCode      string `json:"bind_code" jsonschema:"the bind_code you got when you were bound"`
	BranchPattern string `json:"branch_pattern,omitempty" jsonschema:"branches Claude may switch to or create without asking, path.Match syntax; default agent/*"`
	Until         string `json:"until,omitempty" jsonschema:"how long the trust lasts: 0400 (the default: until the next 04:00, at most 24 hours) or revoked (no end time: until the user revokes it; the approval says so in capitals; ask for it only when the user wants it)"`
}

type trustTicket struct {
	Sister     string     `json:"sister"`
	Device     string     `json:"device"`
	DeviceName string     `json:"device_name"`
	Offer      trustOffer `json:"offer"`
}

func (s *sisters) trustTool(ctx context.Context, h sisterHost, in trustIn) (any, error) {
	sister := strings.TrimSpace(in.VerifiedAgent)
	if sister == "" || len(sister) > 64 {
		return nil, errors.New("Rubi didn't confirm which Bot you are: pass rubi_agent (your Bot name) and rubi_agent_code (the agent_code of your latest Rubi webhook, or call rubi_verify to get one)")
	}
	b, ok := s.st.ownBinding(sister, in.VerifiedAgent, in.BindCode)
	if !ok {
		return nil, errors.New("not bound: bind to a session first (claude_code_bind), then pass the bind_code you got")
	}
	if !s.allow("trust|"+strings.ToLower(b.Sister), trustsPerHour) {
		return nil, fmt.Errorf("at most %d project trust requests an hour", trustsPerHour)
	}
	if b.Project != "" {
		return s.trustAgent(ctx, h, b, in)
	}
	sess, err := s.current(ctx, h, b)
	if err != nil {
		return nil, err
	}
	if sess.State == "ended" {
		return nil, errors.New("that Claude Code session has ended; bind to a live one (claude_code_sessions)")
	}
	if sess.RepoKey == "" {
		return nil, errors.New("Rubi Home doesn't know the project of that session")
	}
	if !within(sess.ProjectRoot, sess.Cwd) {
		return nil, errors.New("that session's directory isn't inside the project Rubi Home reports")
	}
	if why := realProblem(sess.RealRoot, sess.RealCwd); why != "" {
		return nil, errors.New(why)
	}
	until := strings.ToLower(strings.TrimSpace(in.Until))
	if until != "" && until != untilFour && until != untilRevoked {
		return nil, fmt.Errorf("until must be %q (the default) or %q", untilFour, untilRevoked)
	}
	o, err := s.offerFor(sess.ProjectRoot, sess.RepoKey, in.BranchPattern, b.DeviceName)
	if err != nil {
		return nil, err
	}
	o.RealRoot = sess.RealRoot
	if until == untilRevoked {
		o = o.forever()
	}
	t := trustTicket{Sister: b.Sister, Device: b.Device, DeviceName: b.DeviceName, Offer: o}
	preview := map[string]any{"bot": b.Sister, "computer": firstNonEmpty(b.DeviceName, b.Device), "project": sess.RepoKey, "project_root": o.Root,
		"branches": o.Pattern, "until": s.untilText(o.Unlimited, o.Expires),
		"what_it_allows": s.trustMeaning(o, false)}
	if !o.Unlimited {
		preview["time_zone"] = s.zoneNote(o)
	}
	if old := s.st.projectTrustOf(b.Device, o.Root, "", s.now()); old != nil {
		preview["replaces"] = fmt.Sprintf("the trust %s (%s, %d commands used, granted %s)", old.ID, s.trustEnd(*old), old.Uses, ageText(old.Issued, s.now()))
	}
	key := optionTrustProject
	if o.Unlimited {
		key = optionTrustForever
	}
	opt := rubiplugin.Option{Key: key, Label: s.trustLabel(o), Meaning: s.trustMeaning(o, false)}
	end := "until " + s.expiryText(o)
	if o.Unlimited {
		end = "UNTIL REVOKED (no end time)"
	}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindTrustProject,
		Summary: "Trust the project " + oneLine(o.Root, 80) + " on " + firstNonEmpty(b.DeviceName, b.Device) + " " + end + " (asked by " + b.Sister + ")",
		Preview: preview, Options: []rubiplugin.Option{opt}, Payload: t})
}

// executeTrust runs once the user approved a project trust from a Bot.
func (s *sisters) executeTrust(h sisterHost, t trustTicket) (any, error) {
	if t.Sister == "" || t.Device == "" || t.Offer.Root == "" {
		return nil, errors.New("bad payload")
	}
	pt, err := s.grantProject(h, t.Device, t.DeviceName, t.Sister, t.Offer)
	if err != nil {
		return nil, err
	}
	return grantResult(pt), nil
}

// grantResult is what an approval's execute step answers for a trust it granted.
func grantResult(pt projectTrust) map[string]any {
	m := map[string]any{"trusted": true, "mandate": pt.ID, "root": pt.Root, "branches": pt.BranchPattern}
	if pt.Unlimited {
		m["until"] = untilRevoked
	} else {
		m["expires"] = pt.Expires
	}
	return m
}

// trustEnd says when a granted trust ends, for a note.
func (s *sisters) trustEnd(p projectTrust) string {
	if p.Unlimited {
		return "until revoked, no end time"
	}
	return "until " + s.expiryTime(trustOffer{Expires: p.Expires}).Format("Mon 2 Jan 15:04 MST")
}

// ---- what the Bot may do inside a trusted project ----

// projectCovering finds a live project trust on device whose root holds dir and a live session the Bot is
// bound to (its directory now, as Rubi Home lists it, lexically and with symlinks resolved), and counts a
// use. It returns nil when there is none.
func (s *sisters) projectCovering(ctx context.Context, h sisterHost, device, sister, dir, realDir string) *projectTrust {
	if len(s.st.projects(s.now())) == 0 {
		return nil
	}
	type where struct{ cwd, real string }
	var bound []where
	for _, b := range s.st.bindings() {
		if b.Device != device || !sameBot(b.Sister, sister) || b.Project != "" {
			continue
		}
		cur, err := s.current(ctx, h, b)
		if err != nil || cur.State == "ended" || cur.Cwd == "" {
			continue
		}
		bound = append(bound, where{cur.Cwd, cur.RealCwd})
	}
	if len(bound) == 0 {
		return nil
	}
	return s.st.useProject(device, s.now(), func(p projectTrust) bool {
		realRoot := firstNonEmpty(p.RealRoot, p.Root)
		if p.Project != "" {
			return false // a trust of an agent project covers that project only (agentProjectCovering)
		}
		if !within(p.Root, dir) || realDir != "" && !within(realRoot, realDir) {
			return false
		}
		for _, c := range bound {
			if within(p.Root, c.cwd) && (c.real == "" || within(realRoot, c.real)) {
				return true
			}
		}
		return false
	})
}
