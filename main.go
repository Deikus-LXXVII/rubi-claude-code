// Command claude-code is a Rubi plugin that lets you approve Claude Code's shell commands from Rubi.
//
// Claude Code's PermissionRequest hook (rubi-home claude-hook) hands each Bash command that needs
// permission to the Rubi Home helper on that computer. This plugin picks the requests up (claude.next),
// asks you to approve them in Rubi, and answers the helper (claude.decide): allow once you approved,
// deny when you deny, cancel or let the approval expire. The helper denies by itself when Rubi doesn't
// answer in time or is locked. See README.md.
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
	opts := []rubiplugin.Option{{Key: "allow", Label: "Allow", Meaning: "Claude Code runs this command once"}}
	return rubiplugin.Manifest{
		ID: "claude-code", Name: "Claude Code", Version: "v0.1.0",
		Description: "Approve the shell commands Claude Code asks to run on your computer.",
		Needs:       "Rubi Home on the computer where Claude Code runs, and Claude Code's hook set up (see the plugin's README).",
		Publisher:   rubiplugin.Publisher{Name: "Rubi-Project", Key: PublisherKey},
		Source:      "https://github.com/Deikus-LXXVII/rubi-claude-code",
		// The first core with Rubi Home's "claude" capability, approval.wait and the tap level (unreleased;
		// see go.mod).
		MinRubi: "v0.11.0",
		Entry:   "claude-code",
		Actions: []rubiplugin.Action{
			{Kind: kindRun, Title: "Run a command in Claude Code", DefaultLevel: rubiplugin.Strong, Locked: true, Options: opts},
			// Read-only commands: a tap on the passkey is enough, no Face ID. (Chat would need the agent to
			// show the buttons.) You can change it in the panel.
			{Kind: kindSafe, Title: "Run a read-only command in Claude Code (ls, cat, pwd, git status/diff/log)",
				DefaultLevel: rubiplugin.Tap, Options: opts},
		},
		Events: []rubiplugin.EventType{{Type: eventNeeded, Untrusted: []string{"command", "directory", "claude_says", "computer"}}},
		Home:   []string{"claude"},
	}
}

func main() {
	p := rubiplugin.New(manifest())
	var stop context.CancelFunc
	var done chan struct{}
	p.Start = func(h *rubiplugin.Host) error {
		ctx, cancel := context.WithCancel(context.Background())
		stop, done = cancel, make(chan struct{})
		w := newWatcher(h)
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
	exec := func(ctx context.Context, h *rubiplugin.Host, _ string, payload json.RawMessage) (any, error) {
		return allow(ctx, h, payload)
	}
	p.OnExecute(kindRun, exec)
	p.OnExecute(kindSafe, exec)
	p.Main()
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
