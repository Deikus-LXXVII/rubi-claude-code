package main

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// pluginState is what the plugin keeps in Rubi (encrypted): mandates and bindings.
type pluginState struct {
	Mandates []mandate      `json:"mandates,omitempty"`
	Projects []projectTrust `json:"project_trusts,omitempty"`
	Bindings []binding      `json:"bindings,omitempty"`
	Aliases  []alias        `json:"session_names,omitempty"`
	// RolePending are the role changes waiting for the user's approval (roles_change.go); bounded.
	RolePending []rolePending `json:"role_pending,omitempty"`
}

// binding ties one Bot (a "sister") to one Claude Code session: the Bot's messages reach only that
// session, and what the session (or a sub-session of the same project) says goes only to that Bot. It
// is made by an approval and stays until unbound. A desktop session is followed by the app's id, so the
// binding survives the app restarting the session under a new Claude Code id.
type binding struct {
	Sister       string    `json:"sister"`
	Device       string    `json:"device"`
	DeviceName   string    `json:"device_name,omitempty"`
	SessionID    string    `json:"session_id"`
	AppSessionID string    `json:"app_session_id,omitempty"`
	RepoKey      string    `json:"repo_key,omitempty"`
	Cwd          string    `json:"cwd,omitempty"`
	Title        string    `json:"title,omitempty"`
	Code         string    `json:"code"`
	Since        time.Time `json:"since"`
	// Project is the Rubi Home agent project (claude-agent) whose session this is; SessionID is then the agent
	// session's id. "" for a Claude Code session seen through the hooks.
	Project string `json:"project,omitempty"`
}

type stateHost interface {
	LoadState(v any) error
	SaveState(v any) error
}

type store struct {
	mu sync.Mutex
	st pluginState
	h  stateHost
}

func (s *store) load(h stateHost) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h = h
	return h.LoadState(&s.st)
}

func (s *store) saveLocked() error {
	if s.h == nil {
		return nil
	}
	return s.h.SaveState(s.st)
}

func (s *store) pruneLocked(now time.Time) {
	kept := s.st.Mandates[:0]
	for _, m := range s.st.Mandates {
		if m.live(now) {
			kept = append(kept, m)
		}
	}
	s.st.Mandates = kept
	pkept := s.st.Projects[:0]
	for _, p := range s.st.Projects {
		if p.live(now) {
			pkept = append(pkept, p)
		}
	}
	s.st.Projects = pkept
}

// issue adds a mandate (the oldest goes when there are too many). If saving fails nothing changed.
func (s *store) issue(m mandate, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.st
	before.Mandates = append([]mandate(nil), s.st.Mandates...)
	before.Projects = append([]projectTrust(nil), s.st.Projects...)
	s.pruneLocked(now)
	if len(s.st.Mandates) >= maxMandates {
		s.st.Mandates = s.st.Mandates[1:]
	}
	s.st.Mandates = append(s.st.Mandates, m)
	if err := s.saveLocked(); err != nil {
		s.st = before
		return err
	}
	return nil
}

// allowance is the trust that let a command through: a 2-hour mandate or a project trust.
type allowance struct {
	ID      string
	Uses    int
	Project bool
	Root    string
}

// use finds a live mandate or project trust covering r that allows its command and counts the use. A
// 2-hour mandate is tried first; when one covers r but refuses the command, why says why.
func (s *store) use(device string, r request, now time.Time) (*allowance, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	why := ""
	for i := range s.st.Mandates {
		m := &s.st.Mandates[i]
		if !m.live(now) || !m.covers(device, r) {
			continue
		}
		ok, reason := mandateAllows(r.Command, m.Cwd, r.Cwd)
		// A project trust that covers the directory holds every allow to its branch rule, this one too.
		for _, p := range s.st.Projects {
			if ok && p.live(now) && p.Project == r.Project && p.covers(device, r.Cwd) {
				ok, reason = mandateAllowsBranch(r.Command, m.Cwd, r.Cwd, p.BranchPattern)
			}
		}
		if !ok {
			why = "your 2-hour trust for this session doesn't cover this: " + reason
			continue
		}
		m.Uses++
		_ = s.saveLocked()
		return &allowance{ID: m.ID, Uses: m.Uses}, ""
	}
	for i := range s.st.Projects {
		p := &s.st.Projects[i]
		if !p.live(now) || p.Project != r.Project || !p.covers(device, r.Cwd) {
			continue
		}
		ok, reason := mandateAllowsBranch(r.Command, p.Root, r.Cwd, p.BranchPattern)
		if !ok {
			why = "your trust for the project " + p.Root + " doesn't cover this: " + reason
			continue
		}
		p.Uses++
		_ = s.saveLocked()
		return &allowance{ID: p.ID, Uses: p.Uses, Project: true, Root: p.Root}, ""
	}
	return nil, why
}

// issueProject adds a project trust; a live one for the same computer and root is replaced, and the oldest
// goes when there are too many (both returned, for the audit). If saving fails nothing changed.
func (s *store) issueProject(p projectTrust, now time.Time) ([]projectTrust, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.st
	before.Mandates = append([]mandate(nil), s.st.Mandates...)
	before.Projects = append([]projectTrust(nil), s.st.Projects...)
	s.pruneLocked(now)
	var replaced []projectTrust
	kept := s.st.Projects[:0]
	for _, x := range s.st.Projects {
		if x.Device == p.Device && x.Root == p.Root && x.Project == p.Project {
			replaced = append(replaced, x)
			continue
		}
		kept = append(kept, x)
	}
	s.st.Projects = kept
	if len(s.st.Projects) >= maxProjectTrusts {
		// The oldest timed trust goes; an unlimited one only ends on a revoke, so if they all are, nothing is
		// granted (and nothing changed).
		i := slices.IndexFunc(s.st.Projects, func(x projectTrust) bool { return !x.Unlimited })
		if i < 0 {
			s.st = before
			return nil, fmt.Errorf("there are already %d project trusts until revoked; revoke one first", maxProjectTrusts)
		}
		replaced = append(replaced, s.st.Projects[i])
		s.st.Projects = slices.Delete(s.st.Projects, i, i+1)
	}
	s.st.Projects = append(s.st.Projects, p)
	if err := s.saveLocked(); err != nil {
		s.st = before
		return nil, err
	}
	return replaced, nil
}

// projectTrustOf is the live project trust of a computer's root, or nil.
func (s *store) projectTrustOf(device, root, project string, now time.Time) *projectTrust {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.st.Projects {
		if p.Device == device && p.Root == root && p.Project == project && p.live(now) {
			return &p
		}
	}
	return nil
}

// useProject finds a live project trust on device that ok accepts and counts a use.
func (s *store) useProject(device string, now time.Time, ok func(projectTrust) bool) *projectTrust {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.Projects {
		p := &s.st.Projects[i]
		if p.Device == device && p.live(now) && ok(*p) {
			p.Uses++
			_ = s.saveLocked()
			c := *p
			return &c
		}
	}
	return nil
}

func (s *store) projects(now time.Time) []projectTrust {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	return append([]projectTrust(nil), s.st.Projects...)
}

func (s *store) mandates(now time.Time) []mandate {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	return append([]mandate(nil), s.st.Mandates...)
}

// revoke ends one mandate or project trust, or all of both kinds with "all". It returns how many ended.
func (s *store) revoke(id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	kept := s.st.Mandates[:0]
	for _, m := range s.st.Mandates {
		if id == "all" || m.ID == id {
			n++
			continue
		}
		kept = append(kept, m)
	}
	s.st.Mandates = kept
	pkept := s.st.Projects[:0]
	for _, p := range s.st.Projects {
		if id == "all" || p.ID == id {
			n++
			continue
		}
		pkept = append(pkept, p)
	}
	s.st.Projects = pkept
	if n == 0 {
		return 0, nil
	}
	return n, s.saveLocked()
}

// bind replaces the sister's binding.
func (s *store) bind(b binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.st.Bindings[:0]
	for _, x := range s.st.Bindings {
		if !sameBot(x.Sister, b.Sister) {
			kept = append(kept, x)
		}
	}
	s.st.Bindings = append(kept, b)
	return s.saveLocked()
}

func (s *store) unbind(sister string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.st.Bindings[:0]
	found := false
	for _, x := range s.st.Bindings {
		if sameBot(x.Sister, sister) {
			found = true
			continue
		}
		kept = append(kept, x)
	}
	s.st.Bindings = kept
	if !found {
		return false, nil
	}
	return true, s.saveLocked()
}

func (s *store) bindings() []binding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]binding(nil), s.st.Bindings...)
}

// bindingOf returns the sister's binding if code is its code.
func (s *store) bindingOf(sister, code string) (binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.st.Bindings {
		if sameBot(b.Sister, sister) && code != "" && subtle.ConstantTimeCompare([]byte(b.Code), []byte(code)) == 1 {
			return b, true
		}
	}
	return binding{}, false
}

// follow records the session's current Claude Code id for a binding by app id.
func (s *store) follow(sister, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.Bindings {
		if sameBot(s.st.Bindings[i].Sister, sister) && s.st.Bindings[i].SessionID != sessionID {
			s.st.Bindings[i].SessionID = sessionID
			_ = s.saveLocked()
		}
	}
}

func newID(prefix string) string { return prefix + rand.Text()[:16] }

// ---- pending role changes ----

// rolePending is the record of a role change that waits for approval. The change itself travels in the approval's
// payload; this is what bounds the waiting and says which payloads are still wanted.
type rolePending struct {
	ID        string    `json:"id"`
	Approval  string    `json:"approval,omitempty"`
	Bot       string    `json:"bot"`
	Device    string    `json:"device"`
	Role      string    `json:"role,omitempty"`
	Project   string    `json:"project"`
	Op        string    `json:"op"`
	Summary   string    `json:"summary,omitempty"`
	Base      int       `json:"base"`
	BlobBytes int       `json:"blob_bytes,omitempty"`
	Created   time.Time `json:"created"`
}

// addRolePending records a pending change. It fails when 32 wait (after dropping the stale ones), when the Bot
// already has maxPendingPerBot, or when the skill text waiting would be too much for the plugin's state.
func (s *store) addRolePending(p rolePending, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.st.RolePending[:0]
	bytes, mine := 0, 0
	for _, x := range s.st.RolePending {
		if now.Sub(x.Created) >= rolePendingLife {
			continue
		}
		kept = append(kept, x)
		bytes += x.BlobBytes
		if sameBot(x.Bot, p.Bot) {
			mine++
		}
	}
	s.st.RolePending = kept
	switch {
	case len(kept) >= maxRolePending:
		return fmt.Errorf("%d role changes already wait for the user; they have to be answered (or expire) first", maxRolePending)
	case mine >= maxPendingPerBot:
		return fmt.Errorf("%d of your role changes already wait for the user; ask again when they are answered", maxPendingPerBot)
	case bytes+p.BlobBytes > maxAllPendingBlobs:
		return errors.New("too much skill text waits for the user already; ask again when those requests are answered")
	}
	s.st.RolePending = append(s.st.RolePending, p)
	if err := s.saveLocked(); err != nil {
		s.st.RolePending = s.st.RolePending[:len(s.st.RolePending)-1]
		return err
	}
	return nil
}

func (s *store) setRoleApproval(id, approval string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.RolePending {
		if s.st.RolePending[i].ID == id {
			s.st.RolePending[i].Approval = approval
			_ = s.saveLocked()
		}
	}
}

// takeRolePending removes and returns a pending change that is still wanted: an approval runs once.
func (s *store) takeRolePending(id string, now time.Time) (rolePending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.st.RolePending {
		if x.ID == id {
			s.st.RolePending = slices.Delete(s.st.RolePending, i, i+1)
			_ = s.saveLocked()
			return x, now.Sub(x.Created) < rolePendingLife
		}
	}
	return rolePending{}, false
}

func (s *store) rolePendings() []rolePending {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rolePending(nil), s.st.RolePending...)
}
