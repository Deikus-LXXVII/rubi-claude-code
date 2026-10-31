package main

// The setup page of the agent path: Rubi Home's agent-setup.* operations (docs/design/home-setup-wizard.md in the
// Rubi repository) behind buttons, so nobody types a command in a terminal. Everything here is the user's own
// request from the panel. Three buttons ask for a strong approval first (the container install, the network, a
// folder), and "Set up everything" is offered only once those two steps are done, so it can't reach them without
// the approval. Bots get no tool for any of it. What Rubi Home reports (reasons, progress, the sign-in link) is
// untrusted text: it is clipped, shown as item text only, never in a button label or a prompt.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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
	setupStatusMax = 20 * time.Second // a status call probes the whole machine
	setupAddWait   = 5 * time.Minute  // the folder chooser waits for the user
	setupProgress  = 20               // progress lines shown per step
	setupLineRunes = 200
	setupMaxCode   = 512

	kindSetupInstall = "claude-code.setup.install"
	kindSetupNetwork = "claude-code.setup.network"
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
	Projects []setupProject `json:"projects"`
}

type setupStatus struct {
	Steps []setupStep `json:"steps"`
	Job   *struct {
		Step    string `json:"step"`
		Project string `json:"project"`
	} `json:"job"`
	Login *struct {
		Project   string `json:"project"`
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

var setupTitles = map[string]string{"container": "Apple container", "service": "Container service", "network": "Host-only network",
	"image": "Runner image", "projects": "Projects", "login": "Claude sign-in", "selftest": "Self-test"}

var setupStates = map[string]string{"todo": "not done", "working": "working", "done": "done", "failed": "failed", "needs_user": "needs you"}

// setupDevices lists the computers whose Rubi Home has the agent-setup capability.
func (s *sisters) setupDevices(ctx context.Context, h sisterHost) []rubiplugin.HomeDevice {
	devs, err := h.HomeDevices()
	if err != nil {
		return nil
	}
	var out []rubiplugin.HomeDevice
	for _, d := range devs {
		if s.capProbe(ctx, h, d.ID, "setup|"+d.ID, opSetupStatus) {
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
	ctx, cancel := context.WithTimeout(ctx, panelListTimeout)
	defer cancel()
	var items []map[string]any
	for _, d := range s.setupDevices(ctx, h) {
		items = append(items, map[string]any{"title": "Set up the agent path", "detail": oneLine("On "+d.Name+": Apple's container tool, the network, the runner image, a folder, Claude's sign-in and a self-test, with buttons only.", 300),
			"actions": []map[string]any{{"label": "Open", "open": panelPage{Page: pageSetup, Device: d.ID}.open()}}})
	}
	if len(items) == 0 {
		return nil
	}
	return []map[string]any{{"title": "First-time setup", "empty": "", "items": items}}
}

func (s *sisters) setupStatus(ctx context.Context, h sisterHost, device string) (setupStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, setupStatusMax)
	defer cancel()
	var raw json.RawMessage
	if err := h.HomeCall(ctx, device, opSetupStatus, map[string]any{}, &raw); err != nil {
		return setupStatus{}, err
	}
	return decodeSetup(raw), nil
}

func act(label, op string, args map[string]any) map[string]any {
	return map[string]any{"label": label, "op": op, "args": args}
}

func (s *sisters) setupPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	d, err := s.setupDevice(ctx, h, p.Device)
	if err != nil {
		return nil, err
	}
	st, err := s.setupStatus(ctx, h, d.ID)
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
	n, nok := st.step("network")
	if !busy && cok && nok && c.State == "done" && n.State == "done" {
		topActions = append(topActions, act("Set up everything", "setup_run", map[string]any{"device": d.ID, "step": "all"}))
	}
	topActions = append(topActions, map[string]any{"label": "Refresh", "open": panelPage{Page: pageSetup, Device: d.ID}.open()})
	allNote := "\"Set up everything\" appears once the container tool and the network are done: those two ask for your approval, and it never skips them."
	sections := []map[string]any{{"title": "Setup", "note": allNote, "empty": "", "items": top, "actions": topActions}}

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
			case "create":
				actions = append(actions, act("Create", "setup_network", dev()))
			case "use_auto_address":
				actions = append(actions, act("Use the automatic address", "setup_run", map[string]any{"device": d.ID, "step": "network", "option": "auto-address"}))
			case "build":
				actions = append(actions, act(ifElse(step.State == "done", "Update", "Build"), "setup_run", map[string]any{"device": d.ID, "step": "image"}))
			case "add":
				actions = append(actions, act("Add a folder", "setup_add", dev()))
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
			if key != "projects" && key != "login" && key != "selftest" {
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
				case "check":
					pact = append(pact, act("Check the sign-in", "setup_run", run("login", "")))
				case "login", "login_again":
					pact = append(pact, act("Sign in with a Claude subscription", "setup_run", run("login", "claudeai")), act("Sign in with an Anthropic Console account", "setup_run", run("login", "console")))
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
		if key == "login" && st.Login != nil && st.Login.Project != "" {
			w := map[string]any{"title": "Sign-in waiting for the browser: " + dirOf(st.Login.Project)}
			detail := "Waiting for Claude's sign-in link."
			var wact []map[string]any
			if u := strings.TrimSpace(st.Login.URL); strings.HasPrefix(u, "https://") {
				detail = "Sign-in page (open it with the button): " + oneLine(u, 300)
				wact = append(wact, act("Open the sign-in page", "setup_open", map[string]any{"device": d.ID, "project": st.Login.Project}))
			}
			if st.Login.WantsCode {
				detail += " Claude shows a code on its page: paste it here."
				wact = append(wact, map[string]any{"label": "Paste the code", "op": "setup_code", "args": map[string]any{"device": d.ID, "project": st.Login.Project},
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
	page := map[string]any{"title": "Set up the agent path: " + oneLine(d.Name, 60), "up": upMain,
		"note": "Signing in with a Claude subscription is for your own personal use under Anthropic's terms; an Anthropic Console account is billed per token. Install shows macOS's own administrator dialog on the computer: this page never asks for a password. Install, Create (network) and Add a folder ask for your strong approval first.", "sections": sections}
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
	switch op {
	case "setup_install":
		return s.askSetup(ctx, h, d, kindSetupInstall, "Install Apple's container tool on "+d.Name,
			"Rubi Home on that computer downloads Apple's signed container installer (a pinned release, checked by size, hash and signature) and installs it. macOS then shows its own administrator dialog on that computer.")
	case "setup_network":
		return s.askSetup(ctx, h, d, kindSetupNetwork, "Create the host-only network for the agent path on "+d.Name,
			"Rubi Home on that computer creates the internal network the project VMs use. It never deletes a network.")
	case "setup_add":
		return s.askSetup(ctx, h, d, kindSetupProject, "Add a folder as an agent project on "+d.Name,
			"A folder chooser opens on that computer. The folder you pick becomes a project: Claude in its VM can read and write everything in it.")
	case "setup_run":
		args := map[string]any{"step": a.Step}
		switch a.Step {
		case "service", "image":
		case "network": // only the option that clears the proxy settings; creating the network needs the approval
			if a.Option != "auto-address" {
				return nil, errors.New("creating the network asks for your approval")
			}
			args["option"] = a.Option
		case "selftest":
			if a.Project == "" {
				return nil, errors.New("no project")
			}
		case "login": // no method only checks the sign-in
			if a.Project == "" || a.Method != "" && a.Method != "claudeai" && a.Method != "console" {
				return nil, errors.New("no project or sign-in method")
			}
			if a.Method != "" {
				args["method"] = a.Method
			}
		case "all":
			// The container and the network ask for an approval first: refuse unless both are done now.
			st, err := s.setupStatus(ctx, h, d.ID)
			if err != nil {
				return nil, errors.New("couldn't read the setup status: " + oneLine(err.Error(), 160))
			}
			c, cok := st.step("container")
			n, nok := st.step("network")
			if !cok || !nok || c.State != "done" || n.State != "done" {
				return nil, errors.New("install the container tool and create the network first: they ask for your approval")
			}
		default:
			return nil, errors.New("unknown step")
		}
		if a.Project != "" {
			args["project"] = a.Project
		}
		return s.setupCall(ctx, h, d, opSetupRun, args, "run "+a.Step, a.Project)
	case "setup_open":
		if a.Project == "" {
			return nil, errors.New("no project")
		}
		return s.setupCall(ctx, h, d, opSetupOpen, map[string]any{"project": a.Project}, "open the sign-in page", a.Project)
	case "setup_code":
		if a.Code == nil {
			return nil, errors.New("this Rubi's panel can't ask for the code; update Rubi")
		}
		code := strings.TrimSpace(*a.Code)
		if a.Project == "" || code == "" {
			return nil, errors.New("no project or no code")
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
		return s.setupCall(ctx, h, d, opSetupCode, map[string]any{"project": a.Project, "code": code}, "sign-in code sent", a.Project)
	case "setup_remove":
		st, err := s.setupStatus(ctx, h, d.ID)
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

func (s *sisters) executeSetupNetwork(ctx context.Context, h sisterHost, t setupTicket) (any, error) {
	return s.executeSetup(ctx, h, t, opSetupRun, map[string]any{"step": "network"}, "create the network", panelListTimeout)
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
