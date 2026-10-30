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
  computers.
- **Rubi Home: `claude-sessions`.** The plugin can list the Claude Code sessions on your paired computers
  and pass messages to and from them; this part can't approve anything. The install screen shows both.
- **No network access**, no files, no secrets.
- **Actions.** `claude-code.run` (any command; passkey or password, and you can't lower it) and
  `claude-code.run_safe` (a few read-only commands such as `ls`, `cat`, `git status` with plain
  arguments; a passkey **tap** by default, no Face ID, and you may change it). Anything the classifier
  isn't sure about is `run`. On a security key the tap is just a touch; iPhone and Mac passkeys may still
  ask for Face ID or Touch ID, which Rubi accepts too. A tap never approves a `run` command.
- `claude-code.bind` (passkey or password, can't be lowered): lets one Bot talk to one Claude Code
  session; see [Bots and sessions](#bots-and-sessions).
- Its approvals count toward Rubi's limit of 30 approved actions per hour, shared with your other actions.

The approval link reaches you through your Bot: subscribe it to the plugin's `approval_needed` event (Rubi
asks you to approve that once). The event carries the command and Claude's own description, marked as
untrusted.

## Trust a session for 2 hours

A `run` approval has a second button, **Allow and trust this session for 2 hours**. For two hours (or 300
commands) Rubi then allows that session's commands in that directory (and below it) by itself, each one
written to Rubi's audit log, as long as every part of the command line (`&&`, `||`, `;`, `|`, `&`,
newlines) is a plain command on the plugin's list. Every option of a listed program is checked against
that program's list of known options (what each takes: a flag, a value, a file it reads, a file it writes,
a program to run); an option that isn't on the list asks. These always ask, whatever the trust:

- `git push` in any spelling, `--force`, `reset --hard` and other git commands that throw work away or
  change config or remotes (`git restore` only unstages; `git checkout` of a branch or `-b` is allowed, and because a single name can't be told from a branch, checking out a path can still overwrite working files);
- `sudo`, shells and wrappers (`sh -c`, `eval`, `env`, `xargs`), substitutions, variables, backticks,
  escapes, subshells, here documents;
- the network (`curl`, `ssh`, `gh`, installs, `go run x@latest`, publishing or deploy targets);
- options that name another program or code to run (`git grep -O`, `go test -exec`, `make --eval`,
  `cargo --config`, `npm --script-shell`);
- writing or deleting outside the directory (redirections, output options such as `sort -o`,
  `go build -o`, `cp -t`, report and cache paths of build tools, `git worktree add`) or into `.git`
  (a hook written there runs at the next commit);
- paths that hold credentials or run at login (`.ssh`, `.env`, keys, tokens, `.zshrc` and other shell
  startup files, `.config`, browser cookies);
- environment variables set in front of a command, except a short list of harmless ones (`CI`, `TZ`,
  `GOOS`, `CGO_ENABLED` ...), and `cd` that is not joined to the next command by `&&`;
- `go generate`, `go mod download`, `npm outdated` and other commands whose purpose is to fetch or run something;
- programs by path (`./script.sh`), interpreters and anything not on the list.

The check reads the command line only. A build, test or script it starts (`make`, `go test`, `npm run`,
`pytest`) runs the project's own code and can do anything you can, including network access and writing
outside the directory, and Claude may have just written that code. So a trust is only as safe as trusting
Claude with your rights in that project, and the approval says so. Builds and `go mod tidy` may also fetch the
project's declared dependencies. Reading files is allowed anywhere on disk except credential paths (`cat /etc/hosts`
works); only writes are held to the directory. The `jq` filter check for `env` is a hint, not a barrier. The check does not look at your disk: a symlink already in the project that points
outside is followed by the commands that use it, and `cd NAME` can land elsewhere if your own zsh
configuration sets `cdablevars` or `CDPATH`. Use the plugin's page in the Rubi panel to see and
revoke trusts; your Bot can list and revoke them too
(`claude_code_mandates`), but never add one.

### Sessions with bypassPermissions

The example managed settings leave `bypassPermissions` allowed (a mode the Claude desktop app can set per
session). Such a session never asks before a command, so the `PermissionRequest` hook never runs there:
**neither Rubi approvals nor 2-hour trusts apply to it**, and Claude runs every command without you.
Its session hooks still run (`SessionStart`, `UserPromptSubmit`, `Stop`, `SessionEnd`), so it shows up in
`claude_code_sessions` (with a note), and Bots' messages, replies and asks work as in any other session.

Optional hardening: to make every session go through Rubi, turn the mode off in the managed settings,
inside `"permissions"`:

```json
"disableBypassPermissionsMode": "disable"
```

Then a session can't start in, or switch to, `bypassPermissions`.

## Bots and sessions

Each Bot (a "sister") can bind to one Claude Code session, usually the main session of its project, and
then message it. Nothing here is specific to one setup: projects are git remotes, and sessions come from
the Claude desktop app's session list and Claude Code's transcripts on that computer (Rubi Home reads
them, it doesn't run Claude).

1. The Bot calls `claude_code_sessions` and picks its session (project, main or sub-session, state).
2. `claude_code_bind` (the Bot passes its name as `rubi_agent` and the `agent_code` of its latest Rubi
   webhook as `rubi_agent_code`; Rubi checks them and tells the plugin the Bot's registered name, so a
   Bot can't bind as another) asks you once, with your passkey. A session talks to one Bot; binding again
   replaces the Bot's binding. Desktop sessions are followed by the app's id, so a binding survives the
   app restarting the session.
3. `claude_code_send` (at most 4000 characters, 30 an hour) queues a message. The session's hooks hand it
   to Claude at its next prompt, or when it stops (at most 5 batches in a row, so it can't be kept busy
   forever). Claude's answer in that turn comes back to the Bot as a `claude_reply` event.
4. Claude asks the Bot with a ` ```rubi-ask kind=research``` ` block in an answer; it arrives as a
   `claude_ask` event, also from the project's sub-sessions. The Bot answers with `claude_code_send` and
   `reply_to_ask`.

5. `claude_code_status` shows how the bound session stands (busy or idle, messages waiting, when a
   message to it would be read). Each message also reports where it stands as a `claude_message` event
   `{id, session_id, state, at}`, sent to the Bot that sent it: `delivered` (Claude has it), `answered`
   (the answer went back as `claude_reply`), or `expired` (24 hours unread). `queued` is the `claude_code_send` result itself (`message_id`), so it isn't repeated as an
   event. Every event may wake the Bot's agent, so there are only these few.

### Waking an idle session

Hooks fire only when Claude Code runs a turn, so a session waiting for you would read a message only
when you next prompt it. The optional waiter hook fixes that: a second `Stop` hook,
`rubi-home claude-hook --wait` with `asyncRewake: true` and `timeout: 3600`, runs in the background while
the session is idle and stays connected to Rubi Home. When a message arrives it writes it to stderr and
exits 2, which makes Claude Code wake the session with the message as a system reminder; Claude answers
and the answer goes back to the Bot as usual. Typing a prompt, ending the session, a newer waiter for the
same session or the hook's time limit (it gives up 30 seconds before the timeout) end the waiter without
delivering anything, so nothing is delivered twice. It never blocks Claude Code: it runs in the
background, prints nothing on stdout and every failure is exit 0. Rubi Home saves queued messages to
`claude-queue.json` in its folder, so a restart keeps them (24 hours at most).

The hook is in [`examples/managed-settings.json`](examples/managed-settings.json). The managed settings
file is owned by root, so adding it needs an admin (`sudo`), and without it (or with an older Rubi Home)
everything still works, only an idle session waits for your next prompt. `claude_code_send` says whether a
waiter is attached (`waiter`) and what to expect (`delivery`).

A Bot can't approve commands, and messages never grant permissions. You can unbind in the plugin's page.
Messages are injected only through hooks; Rubi never resumes a session that is open in the app.

The Claude side's instructions are in [`kit/skills/rubi-sisters`](kit/skills/rubi-sisters/SKILL.md):
copy it to `~/.claude/skills/rubi-sisters/` on the Mac.

## Set up on a Mac

You need Rubi v0.12.0 or later with this plugin installed, and Claude Code v2.1.295 or later (for
`onFailure`).

1. **Install Rubi Home** (skip if you have it):

   ```sh
   curl -fsSL https://rubi-panel.com/install-home.sh | sh
   ```

   It installs `~/.rubi-home/bin/rubi-home`, starts it at login and prints a pairing code.

2. **Put the hook's binary where Claude can't replace it** (owned by root). Rubi Home installs itself
   as `~/.rubi-home/bin/rubi-home` and updates itself, but Claude Code must run a copy no process of yours
   can swap, so this one is installed by you, with an administrator prompt:

   ```sh
   ~/.rubi-home/bin/rubi-home install-hook
   ```

   It shows the binary's sha256 and the exact script, then asks macOS for an administrator password. As
   root the script copies the file once, checks that copy against the shown hash and only then moves it to
   `/usr/local/bin/rubi-home` (root-owned, mode 0755); it refuses a target whose directories anyone but
   root can write, and afterwards the command re-checks the file and its `version`. The hash only says
   which file will be installed: if you got Rubi Home from a release, compare it with that release's
   `SHA256SUMS`. `--dry-run` shows the plan without running anything, `--to PATH` picks another target,
   `--sudo` uses `sudo` in a terminal instead of the dialog. Run it again after each Rubi Home update:
   every hook line carries the hook's version (self-reported, so advisory), Rubi Home logs a warning when
   this copy is older, `rubi-home status` shows its version, hash and ownership, `install-home.sh` warns
   after an upgrade, and `claude_code_sessions` reports a problem for that computer ("the Claude Code
   hook binary on ... is v...: run `~/.rubi-home/bin/rubi-home install-hook` there"). A hook that speaks a
   protocol Rubi Home doesn't know is denied (events are ignored) until it is updated; a hook from before
   v0.13 still works but is reported as old.

   Manual fallback, if the dialog is not an option:

   ```sh
   sudo install -o root -g wheel -m 755 ~/.rubi-home/bin/rubi-home /usr/local/bin/rubi-home
   ```

   `claude-hook` only talks to the running helper; it reads no configuration and writes nothing.

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
   - `allowManagedHooksOnly`: hooks from your own, project or local settings don't apply, so neither you
     nor Claude can add one that replaces Rubi's. The example leaves out `allowManagedPermissionRulesOnly`,
     so allow rules in your own or a project's settings still let matching commands run without asking
     Rubi; add it if you want every such command to go through Rubi, at the cost of more approvals.
   - turns off auto mode and leaves bypassPermissions allowed (see
     [Sessions with bypassPermissions](#sessions-with-bypasspermissions) for turning it off too);
   - denies Claude's edits to `~/.claude`, `~/.claude.json`, a project's `.claude/`, the managed settings
     directory, the hook binary and Rubi Home's files;
   - a `ConfigChange` hook that keeps settings edits from applying to a running session;
   - `SessionStart`, `UserPromptSubmit`, `Stop` and `SessionEnd` hooks that bring Bots' messages in and
     the answers out (10-second timeout, never blocking: when Rubi Home doesn't answer they do nothing);
   - a second `Stop` hook, `claude-hook --wait` (`asyncRewake: true`, 3600-second timeout), that wakes an
     idle session when a Bot's message arrives (see [Waking an idle session](#waking-an-idle-session)).
     Add it with `sudo` like the rest, then restart Claude Code.

6. **Try it.** Restart Claude Code and ask it to run `rm -rf /tmp/rubi-test`. The Rubi approval link
   arrives through your Bot; approve it and the command runs. Lock Rubi and try again: it is denied.

Check the waiter by hand (after adding the second `Stop` hook and restarting Claude Code):

1. In the desktop app, let a session go idle (bound to a Bot).
2. From the Bot, send it a message with `claude_code_send`; the result should say `waiter: true`.
3. Within seconds the session should resume with the message as a system reminder and answer; the Bot
   gets `claude_message` `delivered`, then the `claude_reply` and `answered`.
4. Also check that typing a prompt in an idle session ends the waiter: the message is delivered once.

Claude Code's documentation doesn't promise that a `Stop` hook may use `asyncRewake`, or say what happens
to a running background hook when you send a new prompt, so this check is worth doing once.

To turn it off, remove the hooks (or the file) from the managed settings. Without them, Claude Code
asks in its own prompt again.

### Limits

- The boundary is your macOS user account. Another program running as you can talk to Rubi Home's socket
  (it can only ask) or change Rubi Home's files; it can't answer for you.
- Read and Edit deny rules cover Claude's file tools and the file commands Claude Code recognizes in Bash,
  not every program a command starts. That is why every Bash command needs your approval.
- A binding is made for the Bot Rubi verified (`rubi_agent` with the `agent_code` from its own webhook;
  Rubi passes the plugin the registered name), not a name the Bot typed. Its code, handed only to that
  Bot, keeps other Bots from sending as it. Replies and asks go to that Bot's webhook only: if it isn't
  connected any more, Rubi drops them (and audits that) instead of waking another Bot.
- `git diff` and `git log` honour the repository's configuration (for example an external diff tool), and
  `cat` follows symlinks; an approval for `run_safe` still shows the exact command and directory.

## Development

```sh
go build -o claude-code . && go test -race ./...
e2e/run.sh   # Linux, needs `unshare -rn`: a real Rubi, Rubi Home and this plugin, offline
```

The plugin builds on the Rubi v0.11.0 SDK (`Host.WaitApproval`) and needs a v0.12.0 core at run time
(Rubi Home's `claude-sessions` capability, strict delivery of addressed events and `rubi_verified_agent`).
The e2e builds Rubi and Rubi Home from a core checkout, `../rubi` by default or `RUBI_REPO`; it needs a
v0.12.0 core (the `citri/claude-m2` branch until v0.12.0 is tagged). `PublisherKey` is the Rubi-Project plugin key (public half in
`publisher-key.pub.pem`); only the end-to-end test overrides it, with a throwaway key.

The end-to-end test builds everything with `-race`, runs it in a network namespace with only loopback,
installs the plugin from a signed local store, pairs Rubi Home through the panel API and checks six
endings through the real `rubi-home claude-hook`: approve → allow, deny → deny with the reason, no answer
→ deny, a passkey tap on a safe command → allow, a tap on any other command → refused (it stays pending),
and Rubi locked → deny.

## License

[MIT](LICENSE)
