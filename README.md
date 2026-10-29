# Claude Code approvals for Rubi

A [Rubi](https://github.com/Deikus-LXXVII/rubi) plugin: when Claude Code on your Mac asks to run a shell
command, you approve or deny it in the Rubi panel (with your passkey), from wherever you are.

How it works: a `PermissionRequest` hook in Claude Code's managed settings runs `rubi-home claude-hook`.
That hands the request to [Rubi Home](https://github.com/Deikus-LXXVII/rubi/blob/main/docs/design/rubi-home.md)
on the same Mac and waits. This plugin, running in your Rubi, collects the request from Rubi Home, asks you
to approve it, and answers. Rubi Home's local socket can only ask; an answer comes only from your Rubi over
the paired, encrypted channel, bound to that request's id, session and exact command.

Everything that isn't your approval is a **deny**, with a reason Claude sees:

| What happened | Claude Code is told |
|---|---|
| You approved | allow |
| You denied | "Rubi: you denied this command in Rubi." |
| No answer within 280 seconds | "Rubi: no answer in time, so the command was denied." |
| Rubi is locked, offline or not paired | "Rubi: Rubi isn't connected to this computer …" or "Rubi: Rubi stopped answering …" |
| Rubi Home isn't running, or the hook fails or times out | deny (the hook prints one; `onFailure: block` covers the rest) |

Only Bash commands go through Rubi. Edits and other tools keep Claude Code's own prompt. Commands Claude
Code runs without asking (its read-only set, or allow rules in managed settings) never reach the hook.

## Permissions

- **Rubi Home: `claude`.** The plugin can answer Claude Code's permission requests on your paired
  computers. The install screen says so.
- **No network access**, no files, no secrets.
- **Actions.** `claude-code.run` (any command; passkey or password, and you can't lower it) and
  `claude-code.run_safe` (a few read-only commands such as `ls`, `cat`, `git status` with plain
  arguments; passkey by default, and you may lower it). Anything the classifier isn't sure about is
  `run`.
- Its approvals have their own hourly budget (60), apart from the 30 per hour your other actions share.

The approval link reaches you through your Bot: subscribe it to the plugin's `approval_needed` event (Rubi
asks you to approve that once). The event carries the command and Claude's own description, marked as
untrusted.

## Set up on a Mac

You need Rubi v0.11.0 or later with this plugin installed, and Claude Code v2.1.295 or later (for
`onFailure`).

1. **Install Rubi Home** (skip if you have it):

   ```sh
   curl -fsSL https://rubi-panel.com/install-home.sh | sh
   ```

   It installs `~/.rubi-home/bin/rubi-home`, starts it at login and prints a pairing code.

2. **Put the hook's binary where Claude can't replace it** (owned by root):

   ```sh
   sudo install -o root -g wheel -m 755 ~/.rubi-home/bin/rubi-home /usr/local/bin/rubi-home
   ```

   Repeat after each Rubi Home update. `claude-hook` only talks to the running helper; it reads no
   configuration and writes nothing.

3. **Pair it with Rubi.** Run `rubi-home pair` if the code has expired, then in the Rubi panel open
   Settings > Rubi Home > Add a home computer, paste the code and approve. Check that the fingerprint
   matches `rubi-home status`.

4. **Install the plugin.** Ask your agent: "Install the Claude Code plugin from the Rubi store", approve
   the install screen (it names the `claude` capability), and let your Bot subscribe to its events.

5. **Install the managed settings** (they apply to every Claude Code session on this Mac, and users can't
   override them):

   ```sh
   sudo mkdir -p "/Library/Application Support/ClaudeCode"
   sudo install -o root -g wheel -m 644 examples/managed-settings.json \
     "/Library/Application Support/ClaudeCode/managed-settings.json"
   ```

   If you already have a managed settings file, merge the keys instead of replacing it.
   [`examples/managed-settings.json`](examples/managed-settings.json):
   - runs `/usr/local/bin/rubi-home claude-hook` for every Bash permission request, with a 300-second
     timeout and `onFailure: block` (Rubi Home gives up at 280 seconds, so Claude Code's timeout never
     decides);
   - `allowManagedHooksOnly` and `allowManagedPermissionRulesOnly`: hooks and allow rules from your own,
     project or local settings don't apply, so neither you nor Claude can add one that skips Rubi;
   - turns off bypass-permissions and auto mode;
   - denies Claude's edits to `~/.claude`, `~/.claude.json`, a project's `.claude/`, the managed settings
     directory, the hook binary and Rubi Home's files;
   - a `ConfigChange` hook that keeps settings edits from applying to a running session.

6. **Try it.** Restart Claude Code and ask it to run `rm -rf /tmp/rubi-test`. The Rubi approval link
   arrives through your Bot; approve it and the command runs. Lock Rubi and try again: it is denied.

To turn it off, remove the two hooks (or the file) from the managed settings. Without them, Claude Code
asks in its own prompt again.

### Limits

- The boundary is your macOS user account. Another program running as you can talk to Rubi Home's socket
  (it can only ask) or change Rubi Home's files; it can't answer for you.
- Read and Edit deny rules cover Claude's file tools and the file commands Claude Code recognizes in Bash,
  not every program a command starts. That is why every Bash command needs your approval.
- `git diff` and `git log` honour the repository's configuration (for example an external diff tool), and
  `cat` follows symlinks; an approval for `run_safe` still shows the exact command and directory.

## Development

```sh
go build -o claude-code . && go test -race ./...
e2e/run.sh   # Linux, needs `unshare -rn`: a real Rubi, Rubi Home and this plugin, offline
```

`go.mod` points at `../rubi` (`replace`) until a Rubi release has `Host.WaitApproval` and Rubi Home's
`claude` capability; drop the `replace` then. The release build sets the publisher key with
`-ldflags "-X main.PublisherKey=…"`.

The end-to-end test builds everything with `-race`, runs it in a network namespace with only loopback,
installs the plugin from a signed local store, pairs Rubi Home through the panel API and checks four
endings through the real `rubi-home claude-hook`: approve → allow, deny → deny with the reason, no answer
→ deny, and Rubi locked → deny.

## License

[MIT](LICENSE)
