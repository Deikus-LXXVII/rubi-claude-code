package main

// The setup page of the agent path: Rubi Home's agent-setup.* operations (docs/design/home-setup-wizard.md in the
// Rubi repository) behind buttons, so nobody types a command in a terminal. Everything here is the user's own
// request from the panel. Two buttons ask for a strong approval first (the container install, a
// folder), and "Set up everything" is offered only once the container step is done, so it can't reach it without
// the approval. Bots get no tool for any of it. What Rubi Home reports (reasons, progress, the sign-in link) is
// untrusted text: it is clipped, shown as item text only, never in a button label or a prompt.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	opSetupStatus  = "agent-setup.status"
	opSetupRun     = "agent-setup.run"
	opSetupCode    = "agent-setup.login.code"
	opSetupOpen    = "agent-setup.login.open"
	opSetupAdd     = "agent-setup.project.add"
	opSetupRemove  = "agent-setup.project.remove"
	opSetupCancel  = "agent-setup.cancel"
	pageSetup      = "setup"
	auditSetup     = "agent_setup_action"
	setupProbeWait = 15 * time.Second // a status call probes the whole machine
	setupGrace     = 30 * time.Minute // a computer known to have the capability stays listed through a slow probe that long
	setupURLRunes  = 450              // the panel cuts an item's detail at 600 characters
	setupAddWait   = 11 * time.Minute // Rubi Home's folder chooser waits 10 minutes for the user
	setupProgress  = 20               // progress lines shown per step
	setupLineRunes = 200
	setupMaxCode   = 512

	kindSetupInstall = "claude-code.setup.install"
	kindSetupProject = "claude-code.setup.project"
)

// setupProject is one project row of the projects, login and selftest steps; ID is the project id (job and
// login name a project by it).
type setupProject struct {
	ID       string   `json:"id"`
	Dir      string   `json:"dir"`
	State    string   `json:"state"`
	Reason   string   `json:"reason"`
	Progress []string `json:"progress"`
	Action   string   `json:"action"`
}

type setupStep struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	State    string         `json:"state"`
	Reason   string         `json:"reason"`
	Progress []string       `json:"progress"`
	Action   string         `json:"action"`
	Action2  string         `json:"action2"`
	Projects []setupProject `json:"projects"`
}

type setupStatus struct {
	Steps []setupStep `json:"steps"`
	Job   *struct {
		Step    string `json:"step"`
		Project string `json:"project"`
	} `json:"job"`
	Login *struct {
		URL       string `json:"url"`
		WantsCode bool   `json:"wants_code"`
	} `json:"login"`
}

// decodeSetup reads a status answer leniently: a field of the wrong type is skipped, not fatal.
func decodeSetup(raw json.RawMessage) setupStatus {
	var st setupStatus
	var te *json.UnmarshalTypeError
	if err := json.Unmarshal(raw, &st); err != nil && !errors.As(err, &te) {
		return setupStatus{}
	}
	if len(st.Steps) > 12 {
		st.Steps = st.Steps[:12]
	}
	return st
}

func stepKey(id string) string { return id }

func (st setupStatus) step(key string) (setupStep, bool) {
	for _, x := range st.Steps {
		if stepKey(x.ID) == key {
			return x, true
		}
	}
	return setupStep{}, false
}

func (st setupStatus) busy() bool {
	if st.Job != nil {
		return true
	}
	for _, x := range st.Steps {
		if x.State == "working" {
			return true
		}
	}
	return false
}

var setupTitles = map[string]string{"container": "Apple container", "service": "Container service",
	"image": "Runner image", "projects": "Projects", "login": "Claude sign-in", "selftest": "Self-test"}

var setupStates = map[string]string{"todo": "not done", "working": "working", "done": "done", "failed": "failed", "needs_user": "needs you"}

// setupStatusReuse is how long a status is reused: the entry's probe and the page it opens share one. A var so
// tests can switch it off.
var setupStatusReuse = 2 * time.Second

// setupCap is what is remembered of a computer's agent-setup capability and of its last status.
type setupCap struct {
	ok    bool
	at    time.Time
	st    setupStatus
	stAt  time.Time
	hasSt bool
}

// fetchSetup asks for the status (a full probe of the machine, so it gets a long wait) and remembers the answer.
func (s *sisters) fetchSetup(ctx context.Context, h sisterHost, device string) (setupStatus, error) {
	pctx, cancel := context.WithTimeout(ctx, setupProbeWait)
	defer cancel()
	var raw json.RawMessage
	err := h.HomeCall(pctx, device, opSetupStatus, map[string]any{}, &raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setupCaps == nil {
		s.setupCaps = map[string]setupCap{}
	}
	now := s.now()
	switch {
	case err == nil:
		st := decodeSetup(raw)
		s.setupCaps[device] = setupCap{ok: true, at: now, st: st, stAt: now, hasSt: true}
		return st, nil
	case isUnknownOp(err):
		s.setupCaps[device] = setupCap{at: now}
	}
	return setupStatus{}, err
}

// setupCapable says whether the computer's Rubi Home has the capability. A slow or failed probe does not hide a
// computer that was known to have it recently.
func (s *sisters) setupCapable(ctx context.Context, h sisterHost, device string) bool {
	s.mu.Lock()
	e := s.setupCaps[device]
	now := s.now()
	s.mu.Unlock()
	if e.ok && now.Sub(e.at) < capYes || !e.ok && !e.at.IsZero() && now.Sub(e.at) < capNo {
		return e.ok
	}
	if _, err := s.fetchSetup(ctx, h, device); err == nil {
		return true
	} else if isUnknownOp(err) || ctx.Err() != nil {
		return false
	}
	return e.ok && now.Sub(e.at) < setupGrace
}

// setupDevices lists the computers whose Rubi Home has the agent-setup capability.
func (s *sisters) setupDevices(ctx context.Context, h sisterHost) []rubiplugin.HomeDevice {
	devs, err := h.HomeDevices()
	if err != nil {
		return nil
	}
	var out []rubiplugin.HomeDevice
	for _, d := range devs {
		if s.setupCapable(ctx, h, d.ID) {
			out = append(out, d)
		}
	}
	return out
}

// setupDevice resolves the page's computer; none named is fine when exactly one has the capability.
func (s *sisters) setupDevice(ctx context.Context, h sisterHost, device string) (rubiplugin.HomeDevice, error) {
	ds := s.setupDevices(ctx, h)
	for _, d := range ds {
		if device == "" && len(ds) == 1 || device != "" && (d.ID == device || d.Name == device) {
			return d, nil
		}
	}
	return rubiplugin.HomeDevice{}, errors.New("that computer doesn't report the agent-setup capability")
}

// setupLinkSection is the entry on the plugin's first page; empty when no computer has the capability.
func (s *sisters) setupLinkSection(ctx context.Context, h sisterHost) []map[string]any {
	var items []map[string]any
	for _, d := range s.setupDevices(ctx, h) {
		items = append(items, map[string]any{"title": "Set up the agent path", "detail": oneLine("On "+d.Name+": Apple's container tool, the runner image, a folder, Claude's sign-in and a self-test, with buttons only.", 300),
			"actions": []map[string]any{{"label": "Open", "open": panelPage{Page: pageSetup, Device: d.ID}.open()}}})
	}
	if len(items) == 0 {
		return nil
	}
	return []map[string]any{{"title": "First-time setup", "empty": "", "items": items}}
}

// setupStatus is the computer's status: the one the entry's probe just read, unless fresh is asked for.
func (s *sisters) setupStatus(ctx context.Context, h sisterHost, device string, fresh bool) (setupStatus, error) {
	s.mu.Lock()
	e := s.setupCaps[device]
	ok := !fresh && e.hasSt && s.now().Sub(e.stAt) < setupStatusReuse
	s.mu.Unlock()
	if ok {
		return e.st, nil
	}
	return s.fetchSetup(ctx, h, device)
}

// hasProject says whether a project id is one of the status' rows.
func (st setupStatus) hasProject(id string) bool {
	for _, x := range st.Steps {
		for _, pr := range x.Projects {
			if pr.ID == id {
				return true
			}
		}
	}
	return false
}

// checkProject refuses a project id of a odd shape or one the computer's fresh status doesn't list.
func (s *sisters) checkProject(ctx context.Context, h sisterHost, device, id string) error {
	if id == "" || len(id) > 128 || strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-") != "" {
		return errors.New("no such project")
	}
	st, err := s.setupStatus(ctx, h, device, true)
	if err != nil {
		return errors.New("couldn't read the setup status: " + oneLine(err.Error(), 160))
	}
	if !st.hasProject(id) {
		return errors.New("no such project")
	}
	return nil
}

func act(label, op string, args map[string]any) map[string]any {
	return map[string]any{"label": label, "op": op, "args": args}
}

func (s *sisters) setupPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	d, err := s.setupDevice(ctx, h, p.Device)
	if err != nil {
		return nil, err
	}
	st, err := s.setupStatus(ctx, h, d.ID, false)
	if err != nil {
		return nil, errors.New("couldn't read the setup status: " + oneLine(err.Error(), 160))
	}
	dev := func() map[string]any { return map[string]any{"device": d.ID} }
	busy := st.busy()
	name := func(id, dir string) string {
		return firstNonEmpty(oneLine(dir, 120), oneLine(id, 60))
	}
	var dirs []setupProject // the folders, for names
	if ps, ok := st.step("projects"); ok {
		dirs = ps.Projects
	}
	dirOf := func(id string) string {
		for _, x := range dirs {
			if x.ID == id {
				return name(x.ID, x.Dir)
			}
		}
		return oneLine(id, 60)
	}

	// The top section: what runs now, Cancel, Refresh, Set up everything.
	var top []map[string]any
	if busy {
		it := map[string]any{"title": "Something is running on the computer", "detail": "The buttons below wait until it ends."}
		if st.Job != nil {
			title := setupTitles[stepKey(st.Job.Step)]
			if title == "" {
				title = "a step"
			}
			it["title"] = "Working on: " + title
			if st.Job.Project != "" {
				it["detail"] = "Folder " + dirOf(st.Job.Project) + ". The buttons below wait until it ends."
			}
		}
		it["actions"] = []map[string]any{{"label": "Cancel", "op": "setup_cancel", "args": dev(), "danger": true, "confirm": "Stop what is running now? A step that is half done continues when you press its button again."}}
		top = append(top, it)
	}
	var topActions []map[string]any
	c, cok := st.step("container")
	if !busy && cok && c.State == "done" {
		topActions = append(topActions, act("Set up everything", "setup_run", map[string]any{"device": d.ID, "step": "all"}))
	}
	topActions = append(topActions, map[string]any{"label": "Refresh", "open": panelPage{Page: pageSetup, Device: d.ID}.open()})
	allNote := "\"Set up everything\" appears once the container tool is done: that step asks for your approval, and it never skips it."
	sections := []map[string]any{{"title": "Setup", "note": allNote, "empty": "Nothing is running now.", "items": top, "actions": topActions}}

	for i, step := range st.Steps {
		key := stepKey(step.ID)
		title := fmt.Sprintf("%d. %s", i+1, firstNonEmpty(setupTitles[key], oneLine(step.Title, 60), oneLine(step.ID, 40)))
		label, known := setupStates[step.State]
		if !known {
			label = "unknown"
		}
		head := map[string]any{"title": title + ": " + label, "detail": oneLine(step.Reason, 300)}
		if step.State == "failed" || step.State == "needs_user" {
			head["warn"] = true
		}
		// Rubi Home names the one button of a row in action (none while it works or waits on an earlier step).
		can := !busy && known && step.State != "working"
		var actions []map[string]any
		if can {
			switch step.Action {
			case "install", "upgrade":
				actions = append(actions, act(ifElse(step.Action == "upgrade", "Upgrade", "Install"), "setup_install", dev()))
			case "start":
				actions = append(actions, act("Start", "setup_run", map[string]any{"device": d.ID, "step": "service"}))
			case "build":
				actions = append(actions, act(ifElse(step.State == "done", "Update", "Build"), "setup_run", map[string]any{"device": d.ID, "step": "image"}))
			case "add":
				actions = append(actions, act("Add a folder", "setup_add", dev()))
			case "check":
				actions = append(actions, act("Check the sign-in", "setup_run", map[string]any{"device": d.ID, "step": "login"}))
			case "login", "login_again":
				actions = append(actions, act(ifElse(step.Action == "login_again", "Sign in again with a Claude subscription", "Sign in with a Claude subscription"), "setup_run", map[string]any{"device": d.ID, "step": "login", "method": "claudeai"}))
			}
			if step.Action2 == "sign_out" {
				actions = append(actions, map[string]any{"label": "Sign out", "op": "setup_run", "args": map[string]any{"device": d.ID, "step": "signout"}, "danger": true,
					"confirm": "Sign out every project on this computer? To revoke the token fully, also remove it at claude.ai settings."})
			}
		}
		head["actions"] = actions
		items := []map[string]any{head}

		lines := step.Progress
		if len(lines) > setupProgress {
			lines = lines[len(lines)-setupProgress:]
		}
		for _, l := range lines {
			if l = oneLine(l, setupLineRunes); l != "" {
				items = append(items, map[string]any{"title": l})
			}
		}

		projects := step.Projects
		if len(projects) > 20 {
			projects = projects[:20]
		}
		for _, pr := range projects {
			if key != "projects" && key != "selftest" { // the sign-in is one row for the computer
				break
			}
			it := map[string]any{"title": name(pr.ID, pr.Dir)}
			lab, ok := setupStates[pr.State]
			if !ok {
				lab = "unknown"
			}
			it["detail"] = oneLine(lab+ifElse(strings.TrimSpace(pr.Reason) != "", ". "+pr.Reason, ""), 300)
			if pr.State == "failed" || pr.State == "needs_user" {
				it["warn"] = true
			}
			pargs := map[string]any{"device": d.ID, "project": pr.ID}
			var pact []map[string]any
			if can && pr.ID != "" && pr.State != "working" {
				run := func(step, method string) map[string]any {
					m := map[string]any{"device": d.ID, "project": pr.ID, "step": step}
					if method != "" {
						m["method"] = method
					}
					return m
				}
				switch pr.Action {
				case "remove":
					pact = append(pact, map[string]any{"label": "Remove", "op": "setup_remove", "args": pargs, "danger": true, "confirm": "Remove this folder from the agent projects? Its files stay where they are."})
				case "selftest":
					pact = append(pact, act("Run self-test", "setup_run", run("selftest", "")))
				}
			}
			it["actions"] = pact
			items = append(items, it)
			for _, l := range pr.Progress[max(0, len(pr.Progress)-setupProgress):] {
				if l = oneLine(l, setupLineRunes); l != "" {
					items = append(items, map[string]any{"title": l})
				}
			}
		}

		// A sign-in that waits for the browser: the link as text, and the buttons that use it.
		if key == "login" && st.Login != nil {
			w := map[string]any{"title": "Sign-in waiting for the browser"}
			detail := "Waiting for Claude's sign-in link."
			var wact []map[string]any
			if u := strings.TrimSpace(st.Login.URL); strings.HasPrefix(u, "https://") {
				detail = "Sign-in page (open it with the button): " + oneLine(u, setupURLRunes)
				if utf8.RuneCountInString(u) > setupURLRunes {
					detail += " (shortened here; the button opens the whole link)"
				}
				wact = append(wact, act("Open the sign-in page", "setup_open", dev()))
			}
			if st.Login.WantsCode {
				detail += " Claude shows a code on its page: paste it here."
				wact = append(wact, map[string]any{"label": "Paste the code", "op": "setup_code", "args": dev(),
					"prompt": map[string]any{"arg": "code", "label": "Paste the code shown on the Claude page", "value": ""}})
			}
			w["detail"], w["actions"] = detail, wact
			items = append(items, w)
		}
		sections = append(sections, map[string]any{"title": title, "empty": "", "items": items})
	}
	if len(st.Steps) == 0 {
		sections = append(sections, map[string]any{"title": "Steps", "empty": "This computer reported no steps."})
	}
	if sec := s.setupModeSection(ctx, h, d.ID); sec != nil {
		sections = append(sections, sec)
	}
	page := map[string]any{"title": "Set up the agent path: " + oneLine(d.Name, 60), "up": upMain,
		"note": "The sign-in is one for every project on this computer, with a Claude subscription, for your own personal use under Anthropic's terms. The token stays in Rubi Home on that computer: the agents' VMs never hold it, Rubi Home adds it to their requests to Anthropic. Install shows macOS's own administrator dialog on the computer: this page never asks for a password. Install and Add a folder ask for your strong approval first.", "sections": sections}
	if busy || st.Login != nil {
		page["refresh"] = 3
	}
	return page, nil
}

// ---- the actions ----

type setupArgs struct {
	Device, Step, Project, Method, Option string
	Code                                  *string
}

type setupTicket struct {
	Device     string `json:"device"`
	DeviceName string `json:"device_name"`
}

func (s *sisters) panelSetup(ctx context.Context, h sisterHost, op string, a setupArgs) (any, error) {
	d, err := s.setupDevice(ctx, h, a.Device)
	if err != nil {
		return nil, err
	}
	d.Name = oneLine(d.Name, 60)
	switch op {
	case "setup_install":
		return s.askSetup(ctx, h, d, kindSetupInstall, "Install Apple's container tool on "+d.Name,
			"Rubi Home on that computer downloads Apple's signed container installer (a pinned release, checked by size, hash and signature) and installs it. macOS then shows its own administrator dialog on that computer.")
	case "setup_add":
		return s.askSetup(ctx, h, d, kindSetupProject, "Add a folder as an agent project on "+d.Name,
			"A folder chooser opens on that computer. The folder you pick becomes a project: Claude in its VM can read and write everything in it.")
	case "setup_run":
		args := map[string]any{"step": a.Step}
		switch a.Step {
		case "service", "image":
		case "selftest":
			if err := s.checkProject(ctx, h, d.ID, a.Project); err != nil {
				return nil, err
			}
		case "login": // one sign-in for the computer; no method only checks it (Rubi Home refuses a Console sign-in)
			if a.Method != "" && a.Method != "claudeai" {
				return nil, errors.New("no such sign-in method")
			}
			if a.Method != "" {
				args["method"] = a.Method
			}
		case "signout":
		case "all":
			// The container asks for an approval first: refuse unless it is done now. (Rubi Home's
			// "all" no longer runs those two steps at all, so this is a second lock, not the only one.)
			st, err := s.setupStatus(ctx, h, d.ID, true)
			if err != nil {
				return nil, errors.New("couldn't read the setup status: " + oneLine(err.Error(), 160))
			}
			c, cok := st.step("container")
			if !cok || c.State != "done" {
				return nil, errors.New("install the container tool first: it asks for your approval")
			}
		default:
			return nil, errors.New("unknown step")
		}
		project := ""
		if a.Step == "selftest" {
			project = a.Project
			args["project"] = project
		}
		return s.setupCall(ctx, h, d, opSetupRun, args, "run "+a.Step, project)
	case "setup_open":
		return s.setupCall(ctx, h, d, opSetupOpen, map[string]any{}, "open the sign-in page", "")
	case "setup_code":
		if a.Code == nil {
			return nil, errors.New("this Rubi's panel can't ask for the code; update Rubi")
		}
		code := strings.TrimSpace(*a.Code)
		if code == "" {
			return nil, errors.New("no code")
		}
		if len(code) > setupMaxCode {
			return nil, fmt.Errorf("at most %d characters", setupMaxCode)
		}
		for _, r := range code {
			if r <= ' ' || r > '~' {
				return nil, errors.New("the code is plain characters without spaces")
			}
		}
		// The code goes to Rubi Home and nowhere else: the audit and every error leave it out.
		return s.setupCall(ctx, h, d, opSetupCode, map[string]any{"code": code}, "sign-in code sent", "")
	case "setup_remove":
		st, err := s.setupStatus(ctx, h, d.ID, true)
		if err != nil {
			return nil, errors.New("couldn't read the setup status: " + oneLine(err.Error(), 160))
		}
		ps, _ := st.step("projects")
		for _, pr := range ps.Projects {
			if pr.ID != "" && pr.ID == a.Project && pr.Dir != "" {
				return s.setupCall(ctx, h, d, opSetupRemove, map[string]any{"dir": pr.Dir}, "remove a folder", pr.ID)
			}
		}
		return nil, errors.New("no such project")
	case "setup_cancel":
		return s.setupCall(ctx, h, d, opSetupCancel, map[string]any{}, "cancel", "")
	}
	return nil, fmt.Errorf("unknown op %q", op)
}

func (s *sisters) askSetup(ctx context.Context, h sisterHost, d rubiplugin.HomeDevice, kind, summary, what string) (any, error) {
	return h.Submit(ctx, rubiplugin.Request{Kind: kind, Summary: summary,
		Preview: map[string]any{"computer": d.Name, "what_it_does": what}, Payload: setupTicket{Device: d.ID, DeviceName: d.Name}})
}

// setupCall is one call to Rubi Home for the user, audited by what it did (never by what was sent).
func (s *sisters) setupCall(ctx context.Context, h sisterHost, d rubiplugin.HomeDevice, op string, args map[string]any, action, project string) (any, error) {
	cctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	return s.setupDo(cctx, h, d, op, args, action, project, "user")
}

func (s *sisters) setupDo(ctx context.Context, h sisterHost, d rubiplugin.HomeDevice, op string, args map[string]any, action, project, by string) (any, error) {
	var res map[string]any
	fields := map[string]any{"action": action, "device": d.ID, "by": by}
	if project != "" {
		fields["project"] = oneLine(project, 80)
	}
	if err := h.HomeCall(ctx, d.ID, op, args, &res); err != nil {
		fields["failed"] = oneLine(err.Error(), 160)
		h.Audit(auditSetup, fields)
		return nil, errors.New(oneLine(err.Error(), 200))
	}
	h.Audit(auditSetup, fields)
	if res == nil {
		res = map[string]any{"ok": true}
	}
	return res, nil
}

func (s *sisters) executeSetupInstall(ctx context.Context, h sisterHost, t setupTicket) (any, error) {
	return s.executeSetup(ctx, h, t, opSetupRun, map[string]any{"step": "container"}, "install the container tool", panelListTimeout)
}

func (s *sisters) executeSetupProject(ctx context.Context, h sisterHost, t setupTicket) (any, error) {
	return s.executeSetup(ctx, h, t, opSetupAdd, map[string]any{}, "add a folder", setupAddWait)
}

func (s *sisters) executeSetup(ctx context.Context, h sisterHost, t setupTicket, op string, args map[string]any, action string, wait time.Duration) (any, error) {
	if t.Device == "" {
		return nil, errors.New("bad payload")
	}
	cctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return s.setupDo(cctx, h, rubiplugin.HomeDevice{ID: t.Device, Name: t.DeviceName}, op, args, action, "", "user approved")
}

// setupModeSection is the usage mode of the computer (the default and what "all Bots" means), set here once for
// all Bots: the user's own button, the same op as the modes page. Hidden when the computer lacks claude-agent.
func (s *sisters) setupModeSection(ctx context.Context, h sisterHost, device string) map[string]any {
	cctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	if !s.agentCapable(cctx, h, device) {
		return nil
	}
	st, err := s.agentStatus(cctx, h, device)
	if err != nil {
		return map[string]any{"title": "Usage mode", "empty": "Couldn't read the usage mode: " + oneLine(err.Error(), 160)}
	}
	if st.Usage.Default == "" {
		return nil
	}
	var items []map[string]any
	for _, m := range usageModes {
		title := m.Label
		if m.Key == st.Usage.Default {
			title += " (the current default)"
		}
		items = append(items, map[string]any{"title": title, "detail": m.About,
			"actions": []map[string]any{{"label": "Use for all Bots", "op": "usage_mode", "args": map[string]any{"device": device, "all": true, "mode": m.Key},
				"confirm": "Set every Bot, and the default for new Bots, to " + m.Label + "? Running sessions are not stopped; the change applies to new ones."}}})
	}
	return map[string]any{"title": "Usage mode", "empty": "", "items": items,
		"note": "How much of your Claude quota the agents may use. This sets one mode for every Bot and for new ones; you can change a single Bot later on the usage modes page. Only you change it: Bots cannot."}
}
