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

func manifest() rubiplugin.Manifest {
	opts := []rubiplugin.Option{{Key: optionAllow, Label: "Allow", Meaning: "Claude Code runs this command once"}}
	trust := append(opts, rubiplugin.Option{Key: optionTrust, Label: "Allow and trust this session for 2 hours",
		Meaning: "Claude Code runs this command. For 2 hours Rubi also allows this session's plain, listed commands in this directory by itself, each one audited. Every option of a listed program is checked against a list, and an unknown option asks. That includes builds and tests (make, go test, npm run) and scripts: they run the project's own code with your rights, including network access and writing anywhere; Claude may have just written that code, so choose this only if you trust Claude with your rights in this project. Builds and go mod tidy may fetch declared dependencies, files outside the directory (except credential paths) can be read, and the check does not follow symlinks already in the project. Push, --force, sudo, network commands, options that run another program, credential paths and writing outside the directory or into .git still ask. Revoke it in the panel"})
	// Version is the last release; a release build replaces it with its tag (rubiplugin.Version, set
	// with -ldflags in .github/workflows/release.yml).
	return rubiplugin.Manifest{
		ID: "claude-code", Name: "Claude Code", Version: "v0.2.1",
		Description: "Approve the shell commands Claude Code asks to run on your computer.",
		Needs:       "Rubi Home on the computer where Claude Code runs, and Claude Code's hook set up (see the plugin's README).",
		Publisher:   rubiplugin.Publisher{Name: "Rubi-Project", Key: PublisherKey},
		Source:      "https://github.com/Deikus-LXXVII/rubi-claude-code",
		// v0.12.0: Rubi Home's "claude-sessions" capability, strict delivery of addressed events and the
		// verified caller (rubi_verified_agent) that binding relies on.
		MinRubi: "v0.12.0",
		Entry:   "claude-code",
		Actions: []rubiplugin.Action{
			{Kind: kindRun, Title: "Run a command in Claude Code", DefaultLevel: rubiplugin.Strong, Locked: true, Options: trust},
			// Read-only commands: a tap on the passkey is enough, no Face ID. (Chat would need the agent to
			// show the buttons.) You can change it in the panel.
			{Kind: kindSafe, Title: "Run a read-only command in Claude Code (ls, cat, pwd, git status/diff/log)",
				DefaultLevel: rubiplugin.Tap, Options: opts},
			{Kind: kindBind, Title: "Let a Bot talk to a Claude Code session", DefaultLevel: rubiplugin.Strong, Locked: true,
				Options: []rubiplugin.Option{{Key: "bind", Label: "Bind", Meaning: "The Bot can send this session short messages and gets its answers and questions; it can't approve commands"}}},
		},
		Events: []rubiplugin.EventType{
			{Type: eventNeeded, Untrusted: []string{"command", "directory", "claude_says", "computer"}},
			{Type: eventBound, Untrusted: []string{"title", "directory", "project"}},
			{Type: eventReply, Untrusted: []string{"text", "computer"}},
			{Type: eventMessage},
			{Type: eventAsk, Untrusted: []string{"text", "kind", "title", "directory", "computer"}},
		},
		Panel: "view",
		Home:  []string{"claude", "claude-sessions"},
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
	p.OnPanel = func(_ context.Context, h *rubiplugin.Host, op string, args json.RawMessage) (any, error) {
		return sis.panel(h, op, args)
	}
	rubiplugin.AddTool(p, "claude_code_sessions", "List the Claude Code sessions on the user's computers (desktop app and terminal), with project (git remote), main or sub-session, state and which Bot each is bound to. Use it to find the session responsible for your project before claude_code_bind.",
		func(ctx context.Context, h *rubiplugin.Host, in sessionsIn) (any, error) {
			return sis.sessionsTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_bind", "Ask the user (one strong approval) to bind you to one Claude Code session, usually the main session of your project. After that you can message it with claude_code_send and you get its answers (claude_reply) and questions (claude_ask). Binding again replaces your binding.",
		func(ctx context.Context, h *rubiplugin.Host, in bindIn) (any, error) { return sis.bindTool(ctx, h, in) })
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
	rubiplugin.AddTool(p, "claude_code_mandates", "List the 2-hour trusts the user gave Claude Code sessions (what Rubi allows by itself), or revoke one (revoke: its id, or \"all\"). Revoking needs no approval.",
		func(_ context.Context, h *rubiplugin.Host, in mandatesIn) (any, error) {
			return sis.mandatesTool(h, in)
		})
	p.Main()
}

// runApproved answers the helper for an approved command and, with the trust option, gives the session
// a mandate.
func runApproved(ctx context.Context, h sisterHost, s *sisters, option string, payload json.RawMessage) (any, error) {
	res, err := allow(ctx, h, payload)
	if err != nil || option != optionTrust {
		return res, err
	}
	var t ticket
	_ = json.Unmarshal(payload, &t)
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
