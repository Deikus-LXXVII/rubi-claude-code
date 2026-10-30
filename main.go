// Command claude-code is a Rubi plugin that lets you approve Claude Code's shell commands from Rubi.
//
// Claude Code's PermissionRequest hook (rubi-home claude-hook) hands each Bash command that needs
// permission to the Rubi Home helper on that computer. This plugin picks the requests up (claude.next),
// asks you to approve them in Rubi, and answers the helper (claude.decide): allow once you approved,
// deny when you deny, cancel or let the approval expire. The helper denies by itself when Rubi doesn't
// answer in time or is locked. Bots can also bind to a session and message it (claude-sessions.list,
// .send, .next; Rubi Home's "claude-sessions" capability). See README.md.
package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

// PublisherKey is the Rubi-Project plugin signing key (public half, publisher-key.pub.pem). A var, not a
// const, only so the end-to-end test can sign with a throwaway key (-X main.PublisherKey=...).
var PublisherKey = "MCowBQYDK2VwAyEAxeDfKAkO77JdARN7Y2jJT3tXw9mN+GqqH8R5mhcxt8c="

const (
	kindRun  = "claude-code.run"      // any command: passkey or password in the Rubi panel
	kindSafe = "claude-code.run_safe" // a read-only command on the short list (classify)
	// eventNeeded tells the agent to send you the approval link.
	eventNeeded = "approval_needed"
)

// manifestRunOptions are the first two options of a run approval: one command, or the session for 2 hours.
func manifestRunOptions() []rubiplugin.Option {
	return []rubiplugin.Option{{Key: optionAllow, Label: "Allow", Meaning: "Claude Code runs this command once"},
		{Key: optionTrust, Label: "Allow and trust this session for 2 hours",
			Meaning: "Claude Code runs this command. For 2 hours Rubi also allows this session's plain, listed commands in this directory by itself, each one audited. Every option of a listed program is checked against a list, and an unknown option asks. That includes builds and tests (make, go test, npm run) and scripts: they run the project's own code with your rights, including network access and writing anywhere; Claude may have just written that code, so choose this only if you trust Claude with your rights in this project. Builds and go mod tidy may fetch declared dependencies, files outside the directory (except credential paths) can be read, and the check does not follow symlinks already in the project. Push, --force, sudo, network commands, options that run another program, credential paths and writing outside the directory or into .git still ask, and so does git rebase unless it says --no-update-refs (Rubi cannot see your git configuration). Revoke it in the panel"}}
}

func manifest() rubiplugin.Manifest {
	opts := []rubiplugin.Option{{Key: optionAllow, Label: "Allow", Meaning: "Claude Code runs this command once"}}
	trust := append(manifestRunOptions(), rubiplugin.Option{Key: optionTrustProject, Label: "Allow and trust this project until 04:00",
		Meaning: "Claude Code runs this command. Until the next 04:00 (at most 24 hours, so on a daylight-saving change it can end up to an hour earlier; the approval names the exact time, date, time zone and project directory) Rubi allows the plain, listed commands of every Claude Code session on this computer whose directory is inside this project, each one audited, with the same checks as the 2-hour trust, including builds and tests that run the project's own code with your rights. Switching to or creating a git branch is allowed only for names like citri/*; commits, merges and rebases go to the branch a session is on, which may be main. A Bot bound to a session in the project can also start and bind sessions in it without a new approval; a session it starts runs with the Claude desktop app's permission settings, and if those skip permission prompts its commands never ask. Push and every remote git command, --force, sudo, network commands, installs, git tag, credential paths, writing outside the project or into .git, branches outside the pattern, and git rebase without --no-update-refs still ask. Offered when Rubi Home reports the project; revoke it in the panel"},
		rubiplugin.Option{Key: optionTrustForever, Label: "Allow and trust this project until I revoke it", Meaning: "Claude Code runs this command. UNTIL REVOKED — no end time: this trust has no time or count limit, stays on across restarts of Rubi, of the plugin and of Rubi Home and across days and weeks, and only a revoke (the panel, or claude_code_mandates) ends it; while Rubi is locked nothing is allowed. Rubi allows the plain, listed commands of every Claude Code session on this computer whose directory is inside this project, each one audited and counted, with the same checks as the 2-hour trust, including builds and tests that run the project's own code with your rights. Switching to or creating a git branch is allowed only for names like citri/*; commits, merges and rebases go to the branch a session is on, which may be main. A Bot bound to a session in the project can also start and bind sessions in it, without a new approval, until you revoke it; a session it starts runs with the Claude desktop app's permission settings, and if those skip permission prompts its commands never ask. Push and every remote git command, --force, sudo, network commands, installs, git tag, credential paths, writing outside the project or into .git, branches outside the pattern, and git rebase without --no-update-refs still ask. Because nothing ends it by itself, look at the panel from time to time and revoke what you no longer need. Offered when Rubi Home reports the project"})
	// Version is the last release; a release build replaces it with its tag (rubiplugin.Version, set
	// with -ldflags in .github/workflows/release.yml).
	return rubiplugin.Manifest{
		ID: "claude-code", Name: "Claude Code", Version: "v0.2.1",
		Description: "Approve the shell commands Claude Code asks to run on your computer.",
		Needs:       "Rubi Home on the computer where Claude Code runs, and Claude Code's hook set up (see the plugin's README).",
		Publisher:   rubiplugin.Publisher{Name: "Rubi-Project", Key: PublisherKey},
		Source:      "https://github.com/Deikus-LXXVII/rubi-claude-code",
		// v0.13.0: Rubi Home's "claude-start" capability (a v0.12 core refuses the manifest), the panel's
		// view prompt (Rename), claude-sessions.bound and the list's truncated/real_project_root; v0.12.0
		// brought "claude-sessions", strict delivery of addressed events and rubi_verified_agent.
		MinRubi: "v0.13.0",
		Entry:   "claude-code",
		Actions: []rubiplugin.Action{
			{Kind: kindRun, Title: "Run a command in Claude Code", DefaultLevel: rubiplugin.Strong, Locked: true, Options: trust},
			// Read-only commands: a tap on the passkey is enough, no Face ID. (Chat would need the agent to
			// show the buttons.) You can change it in the panel.
			{Kind: kindSafe, Title: "Run a read-only command in Claude Code (ls, cat, pwd, git status/diff/log)",
				DefaultLevel: rubiplugin.Tap, Options: opts},
			{Kind: kindBind, Title: "Let a Bot talk to a Claude Code session", DefaultLevel: rubiplugin.Strong, Locked: true,
				Options: []rubiplugin.Option{{Key: "bind", Label: "Bind", Meaning: "The Bot can send this session short messages and gets its answers and questions; it can't approve commands"}}},
			{Kind: kindTrustProject, Title: "Let a Bot's project be trusted (until 04:00, or until revoked)", DefaultLevel: rubiplugin.Strong, Locked: true,
				Options: []rubiplugin.Option{{Key: optionTrustProject, Label: "Trust this project until 04:00",
					Meaning: "Until the next 04:00 (at most 24 hours; the approval names the exact time, date, time zone, the project directory, the computer and the branches) Rubi allows the plain, listed commands of every Claude Code session on that computer inside the project, and lets the Bot start and bind sessions in it without a new approval; a session it starts runs with the Claude desktop app's permission settings, and if those skip permission prompts its commands never ask. Commits go to the branch a session is on, which may be main. Push and every remote git command, --force, sudo, network commands, installs, tags, credential paths, writing outside the project and branches outside the pattern still ask"},
					{Key: optionTrustForever, Label: "Trust this project until I revoke it",
						Meaning: "UNTIL REVOKED — no end time: this trust has no time or count limit, stays on across restarts of Rubi, of the plugin and of Rubi Home and across days and weeks, and only a revoke (the panel, or claude_code_mandates) ends it; while Rubi is locked nothing is allowed. Rubi allows the plain, listed commands of every Claude Code session on that computer whose directory is inside this project, each one audited and counted, with the same checks as the 2-hour trust, including builds and tests that run the project's own code with your rights. Switching to or creating a git branch is allowed only for names like citri/*; commits, merges and rebases go to the branch a session is on, which may be main. A Bot bound to a session in the project can also start and bind sessions in it, without a new approval, until you revoke it; a session it starts runs with the Claude desktop app's permission settings, and if those skip permission prompts its commands never ask. Push and every remote git command, --force, sudo, network commands, installs, git tag, credential paths, writing outside the project or into .git, branches outside the pattern, and git rebase without --no-update-refs still ask. Because nothing ends it by itself, look at the panel from time to time and revoke what you no longer need."}}},
			{Kind: kindRename, Title: "Let a Bot name a Claude Code session", DefaultLevel: rubiplugin.Tap, Locked: true,
				Options: []rubiplugin.Option{{Key: "rename", Label: "Rename", Meaning: "Gives (or removes) the session's name in Rubi. It is a label shown in session lists and usable instead of the session's id; it changes nothing in Claude Code or the desktop app"}}},
			{Kind: kindStart, Title: "Let a Bot start a new Claude Code session", DefaultLevel: rubiplugin.Strong, Locked: true,
				Options: []rubiplugin.Option{{Key: "start", Label: "Start", Meaning: "Starts a new Claude Code session on your computer with the Bot's task as its first message, and binds the Bot to it. The session runs with the Claude desktop app's permission settings: if those skip permission prompts, Claude can run any command there without asking, and Rubi approvals don't apply to it"}}},
		},
		Events: []rubiplugin.EventType{
			{Type: eventNeeded, Untrusted: []string{"command", "directory", "claude_says", "computer"}},
			{Type: eventBound, Untrusted: []string{"title", "directory", "project"}},
			{Type: eventReply, Untrusted: []string{"text", "computer"}},
			{Type: eventMessage},
			{Type: eventAsk, Untrusted: []string{"text", "kind", "title", "directory", "computer"}},
		},
		Panel: "view",
		Home:  []string{"claude", "claude-sessions", "claude-start"},
	}
}

func main() {
	p := rubiplugin.New(manifest())
	st := &store{}
	sis := newSisters(st)
	var stop context.CancelFunc
	var done chan struct{}
	p.Start = func(h *rubiplugin.Host) error {
		if err := st.load(h); err != nil {
			h.Logf("reading the saved mandates and bindings: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stop, done = cancel, make(chan struct{})
		w := newWatcher(h, sis)
		go func() {
			defer close(done)
			w.run(ctx)
		}()
		return nil
	}
	p.Stop = func() {
		if stop != nil {
			stop()
			<-done
		}
	}
	p.OnExecute(kindRun, func(ctx context.Context, h *rubiplugin.Host, option string, payload json.RawMessage) (any, error) {
		return runApproved(ctx, h, sis, option, payload)
	})
	p.OnExecute(kindSafe, func(ctx context.Context, h *rubiplugin.Host, _ string, payload json.RawMessage) (any, error) {
		return allow(ctx, h, payload)
	})
	p.OnExecute(kindBind, func(_ context.Context, h *rubiplugin.Host, _ string, payload json.RawMessage) (any, error) {
		var t bindTicket
		if err := json.Unmarshal(payload, &t); err != nil {
			return nil, fmt.Errorf("bad payload")
		}
		return sis.executeBind(h, t)
	})
	p.OnExecute(kindTrustProject, func(_ context.Context, h *rubiplugin.Host, _ string, payload json.RawMessage) (any, error) {
		var t trustTicket
		if err := json.Unmarshal(payload, &t); err != nil {
			return nil, fmt.Errorf("bad payload")
		}
		return sis.executeTrust(h, t)
	})
	p.OnExecute(kindStart, func(ctx context.Context, h *rubiplugin.Host, _ string, payload json.RawMessage) (any, error) {
		var t startTicket
		if err := json.Unmarshal(payload, &t); err != nil {
			return nil, fmt.Errorf("bad payload")
		}
		return sis.executeStart(ctx, h, t)
	})
	p.OnExecute(kindRename, func(ctx context.Context, h *rubiplugin.Host, _ string, payload json.RawMessage) (any, error) {
		var t renameTicket
		if err := json.Unmarshal(payload, &t); err != nil {
			return nil, fmt.Errorf("bad payload")
		}
		return sis.executeRename(ctx, h, t, "bot", "user approved", nil)
	})
	p.OnPanel = func(ctx context.Context, h *rubiplugin.Host, op string, args json.RawMessage) (any, error) {
		return sis.panel(ctx, h, op, args)
	}
	rubiplugin.AddTool(p, "claude_code_sessions", "List the Claude Code sessions on the user's computers (desktop app and terminal), with project (git remote), main or sub-session, state and which Bot each is bound to. Use it to find the session responsible for your project before claude_code_bind.",
		func(ctx context.Context, h *rubiplugin.Host, in sessionsIn) (any, error) {
			return sis.sessionsTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_bind", "Ask the user (one strong approval) to bind you to one Claude Code session (session_id, or name of a named session), usually the main session of your project. After that you can message it with claude_code_send and you get its answers (claude_reply) and questions (claude_ask). Binding again replaces your binding.",
		func(ctx context.Context, h *rubiplugin.Host, in bindIn) (any, error) { return sis.bindTool(ctx, h, in) })
	rubiplugin.AddTool(p, "claude_code_start", "Ask the user (one strong approval) to start a NEW Claude Code session on their computer in a project directory, with your task as its first message, when no session exists for your project. On approval you are bound to the new session automatically (claude_bound event with your bind_code) and can use claude_code_send. The directory must be one of the user's existing Claude Code projects (see claude_code_sessions) or a folder they allowed. The session may run without permission prompts; keep the task small and specific. At most 5 requests an hour.",
		func(ctx context.Context, h *rubiplugin.Host, in startIn) (any, error) {
			return sis.startTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_rename", "Give a Claude Code session a name in Rubi (an alias: Claude Code itself is not changed), or remove it (clear). The name shows in claude_code_sessions and claude_code_bind accepts it instead of session_id. 1 to 64 plain characters, unique on the computer ignoring case, not like an id. Without session_id or session_name it names the session you are bound to, which needs no approval; any other session needs a tap from the user (none inside a project the user trusts if you are bound inside it).",
		func(ctx context.Context, h *rubiplugin.Host, in renameIn) (any, error) {
			return sis.renameTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_trust_project", "Ask the user (one strong approval) to trust the whole project of the Claude Code session you are bound to until the next 04:00 (at most 24 hours; pass until=revoked for no end time: it then lasts until the user revokes it, with no time or count limit, and the approval says so in capitals - ask for that only when the user wants it; default until=0400). While it lasts Rubi allows the plain, listed commands of every Claude Code session inside the project without asking, and you can claude_code_start sessions in it and claude_code_bind to its other sessions without a new approval (a session you start runs with the desktop app's permission settings: if those skip prompts, its commands never ask; commits, merges and rebases go to the branch it is on, maybe main). Push and every remote operation, --force, sudo, the network, installs, tags, writes outside the project and branches outside branch_pattern (default citri/*) still ask. Needs your bind_code.",
		func(ctx context.Context, h *rubiplugin.Host, in trustIn) (any, error) {
			return sis.trustTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_unbind", "End your binding to a Claude Code session.",
		func(ctx context.Context, h *rubiplugin.Host, in unbindIn) (any, error) {
			return sis.unbindTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_send", "Send a short message (at most 4000 characters) to the Claude Code session you are bound to; Claude reads it at its next stop or prompt (an idle session with a waiter hook is woken within seconds) and its answer comes as a claude_reply event; its delivery states come as claude_message events. For findings, answers to its claude_ask and small asks, not bulky tasks.",
		func(ctx context.Context, h *rubiplugin.Host, in sendIn) (any, error) { return sis.sendTool(ctx, h, in) })
	rubiplugin.AddTool(p, "claude_code_status", "How the Claude Code session you are bound to stands (busy, idle) and when a message to it would be read. Messages' own states (delivered, answered, expired) arrive as claude_message events.",
		func(ctx context.Context, h *rubiplugin.Host, in statusIn) (any, error) {
			return sis.statusTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_mandates", "List the 2-hour trusts (md_…) and the project trusts (pt_…, until 04:00 or until revoked, with when each was granted and how often it was used) the user gave Claude Code (what Rubi allows by itself), or revoke one (revoke: its id, or \"all\"). Revoking needs no approval.",
		func(_ context.Context, h *rubiplugin.Host, in mandatesIn) (any, error) {
			return sis.mandatesTool(h, in)
		})
	p.Main()
}

// runApproved answers the helper for an approved command and, with the trust option, gives the session
// a mandate.
func runApproved(ctx context.Context, h sisterHost, s *sisters, option string, payload json.RawMessage) (any, error) {
	res, err := allow(ctx, h, payload)
	if err != nil || option != optionTrust && option != optionTrustProject && option != optionTrustForever {
		return res, err
	}
	var t ticket
	_ = json.Unmarshal(payload, &t)
	if option == optionTrustProject || option == optionTrustForever {
		// The offer the user read for this option is the one granted; its mode must be the option's.
		offer := t.Project
		if option == optionTrustForever {
			offer = t.Forever
		}
		if offer == nil || offer.Unlimited != (option == optionTrustForever) || t.SessionID == "" || !within(offer.Root, t.Cwd) {
			return map[string]any{"allowed": true, "trusted": false, "why": "the request had no project"}, nil
		}
		pt, err := s.grantProject(h, t.Device, t.DeviceName, "", *offer)
		if err != nil {
			h.Logf("saving a project trust: %v", err)
			return map[string]any{"allowed": true, "trusted": false, "why": err.Error()}, nil
		}
		out := grantResult(pt)
		out["allowed"] = true
		return out, nil
	}
	if t.SessionID == "" || !within(t.Cwd, t.Cwd) {
		return map[string]any{"allowed": true, "trusted": false, "why": "the request had no session or directory"}, nil
	}
	now := s.now().UTC()
	m := mandate{ID: newID("md_"), Device: t.Device, DeviceName: t.DeviceName, SessionID: t.SessionID, Cwd: t.Cwd,
		Issued: now, Expires: now.Add(mandateTTL), MaxUses: mandateMaxUses}
	if err := s.st.issue(m, now); err != nil {
		h.Logf("saving a mandate: %v", err)
		return map[string]any{"allowed": true, "trusted": false, "why": "couldn't save it"}, nil
	}
	h.Audit("mandate_issued", map[string]any{"mandate": m.ID, "device": m.Device, "session": m.SessionID, "directory": m.Cwd, "expires": m.Expires})
	return map[string]any{"allowed": true, "trusted": true, "mandate": m.ID, "expires": m.Expires}, nil
}

// allow answers the helper once you approved: Claude Code runs the command.
func allow(ctx context.Context, h homeCaller, payload json.RawMessage) (any, error) {
	var t ticket
	if err := json.Unmarshal(payload, &t); err != nil || t.ID == "" {
		return nil, fmt.Errorf("bad payload")
	}
	if err := h.HomeCall(ctx, t.Device, "claude.decide", answer{ID: t.ID, SessionID: t.SessionID, Digest: t.Digest, Behavior: "allow"}, nil); err != nil {
		return nil, fmt.Errorf("Claude Code is no longer waiting for this command (%v)", err)
	}
	return map[string]any{"allowed": true}, nil
}
