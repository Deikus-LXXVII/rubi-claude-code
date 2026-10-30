package main

import (
	"encoding/json"
	"os"
	"testing"
)

// The example policy is what users copy to their Mac; a typo there means the hook never runs.
func TestManagedSettingsExample(t *testing.T) {
	b, err := os.ReadFile("examples/managed-settings.json")
	if err != nil {
		t.Fatal(err)
	}
	type hook struct {
		Type, Command, OnFailure string
		Args                     []string
		Timeout                  int
		AsyncRewake              bool
	}
	var s struct {
		AllowManagedHooksOnly bool
		DisableAutoMode       string
		Permissions           struct {
			DisableBypassPermissionsMode string
			Deny                         []string
		}
		Hooks map[string][]struct {
			Matcher string
			Hooks   []hook
		}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if !s.AllowManagedHooksOnly || s.DisableAutoMode != "disable" {
		t.Fatalf("the policy must keep users and Claude from replacing the hook or skipping it: %+v", s)
	}
	// bypassPermissions stays allowed by default (the owner's choice); turning it off is the optional
	// hardening the README describes.
	if s.Permissions.DisableBypassPermissionsMode != "" {
		t.Fatalf("the default example turns off bypassPermissions: %q", s.Permissions.DisableBypassPermissionsMode)
	}
	// Users keep their own allow rules (a deliberate tradeoff, see the README).
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	if _, ok := raw["allowManagedPermissionRulesOnly"]; ok {
		t.Error("the example sets allowManagedPermissionRulesOnly; the README says it doesn't")
	}
	pr := s.Hooks["PermissionRequest"]
	if len(pr) != 1 || pr[0].Matcher != "^Bash$" || len(pr[0].Hooks) != 1 {
		t.Fatalf("PermissionRequest: %+v", pr)
	}
	// rubi-home waits 280 seconds for Rubi by default (claude-hook gives up at 295): the hook's timeout
	// must be longer, and a timeout or failure must block.
	if h := pr[0].Hooks[0]; h.Type != "command" || h.Command != "/usr/local/bin/rubi-home" ||
		len(h.Args) != 1 || h.Args[0] != "claude-hook" || h.Timeout != 300 || h.OnFailure != "block" {
		t.Fatalf("PermissionRequest hook: %+v", h)
	}
	// The session hooks bring the Bots' messages in and the answers out. They must never block Claude
	// Code: a short timeout and no onFailure (rubi-home prints nothing when it can't reach the helper).
	for _, ev := range []string{"SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"} {
		hs := s.Hooks[ev]
		if len(hs) != 1 || len(hs[0].Hooks) != 1+btoi(ev == "Stop") {
			t.Fatalf("%s: %+v", ev, hs)
		}
		if h := hs[0].Hooks[0]; h.Command != "/usr/local/bin/rubi-home" || len(h.Args) != 1 || h.Args[0] != "claude-hook" ||
			h.Timeout == 0 || h.Timeout > 15 || h.OnFailure != "" {
			t.Fatalf("%s hook: %+v", ev, h)
		}
	}
	// The second Stop hook is the waiter: it runs in the background (asyncRewake) and wakes an idle
	// session when a message arrives, so its timeout is long; it never blocks Claude Code.
	if h := s.Hooks["Stop"][0].Hooks[1]; h.Type != "command" || h.Command != "/usr/local/bin/rubi-home" ||
		len(h.Args) != 2 || h.Args[0] != "claude-hook" || h.Args[1] != "--wait" || !h.AsyncRewake || h.Timeout != 3600 || h.OnFailure != "" {
		t.Fatalf("Stop waiter hook: %+v", h)
	}
	if cc := s.Hooks["ConfigChange"]; len(cc) != 1 || len(cc[0].Hooks) != 1 {
		t.Fatalf("ConfigChange: %+v", cc)
	}
	want := map[string]bool{"Edit(~/.claude/**)": false, "Edit(//Library/Application Support/ClaudeCode/**)": false,
		"Edit(//usr/local/bin/rubi-home)": false}
	for _, d := range s.Permissions.Deny {
		if _, ok := want[d]; ok {
			want[d] = true
		}
	}
	for rule, found := range want {
		if !found {
			t.Errorf("deny rule %s is missing", rule)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
