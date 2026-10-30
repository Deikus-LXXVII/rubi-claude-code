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

### Trust a project until 04:00

(There is also a version [without an end time](#trust-a-project-until-i-revoke-it).)

A `run` approval can have a third button, **Allow and trust this project until Sat 31 Oct 2026 04:00 CET**
(the label names the exact time and date). One approval then trusts the whole project instead of one session:
until the next 04:00 (at most 24 hours; the approval states the time zone) Rubi allows plain, listed commands
in **every** Claude Code session on that computer whose directory is inside the project's root: the session
that asked, its sub-sessions and worktrees, other sessions, and sessions started later (also by a Bot). The
root is the project's top directory as Rubi Home reports it (`project_root` in `claude_code_sessions`; for a
folder that is not a git repository it is the folder itself). The button is offered only when Rubi Home
reports a root, and never for a home directory or anything higher up (fewer than three path parts), a disk, a
folder of documents, a credential path, or a folder with no git remote (`local:` key; the plugin cannot tell it
from a plain folder) with fewer than four path parts. Where Rubi Home reports it (`real_cwd`), the session's
real directory with symlinks resolved must also be inside the root; symlinks inside the tree are still followed
by the commands that use them. Branch patterns that match `main`, `master`, `trunk`, `develop` and the like (or
are `*`) are refused. At most 2000 commands; each allow is audited with the trust's id (`pt_…`).

It uses the same command check as the 2-hour trust (everything above still asks), plus a **branch rule**:
a command that switches to or creates a git branch (`git switch X`, `switch -c X`, `checkout X`,
`checkout -b/-B X`, `branch X`, `branch -m/-c/-d`, `worktree add -b X`, `stash branch X`, `rebase UPSTREAM X`)
is allowed only when `X` matches the trust's branch pattern (`path.Match` syntax, default `citri/*`);
otherwise it asks. Pushes and every remote git command, `--force`, `git tag` (so releases), sudo, the network
and installs, writes outside the root or into `.git` and credential paths ask as before. Commits, merges and rebases go
to whatever branch the session is on, which may be `main`: the rule is about switching and creating, not about
where the session started. A detached switch (`git switch --detach X`) names a commit and asks unless it matches.
`git rebase` asks unless it says `--no-update-refs` (`--update-refs`, or a `rebase.updateRefs` setting Rubi
cannot see, moves other local branches); that holds for the 2-hour trust too. While a project trust covers a
directory, a session's 2-hour trust is held to the same branch rule.

**What it gives the Bot.** A Bot bound (with its own approval) to a session inside the project may, until the
trust ends, `claude_code_start` a session in a directory inside the root and `claude_code_bind` to another
session inside it without a new approval (the new session is bound as usual; the input checks, the rate limits
of 5 starts an hour and Rubi Home's own checks of the folder still apply). Each is audited with the trust's
id. **That means the Bot can open sessions in that project with a task of its own until the trust ends, up to 20 binds and 5 starts an hour.** The bound session must be live and inside the root, and a session Rubi Home starts outside it (a symlink) unbinds the Bot. If
those sessions run with `bypassPermissions` (a desktop app setting), Claude runs any command there without
asking and no trust or approval matters; a trust only covers sessions that ask.
`claude_code_send` and the wake-up never needed an approval.

**Asking for it.** A Bot can ask for the trust with `claude_code_trust_project {bind_code, branch_pattern?}`
for the project of the session it is bound to: a strong, locked approval (a tap isn't enough) that shows the
same text. The trust is never granted by the tool itself. Only one trust is live for a computer and project
root: a new one replaces the old (both audited). A 2-hour trust and a project trust can both exist; either may
allow a command, and revoking one leaves the other.

**Time zone.** Rubi Home doesn't report its computer's time zone, so 04:00 is in the zone of the machine Rubi
runs on, and the approval says which. The end is computed once, when the approval is asked, and is what is
granted; an approval answered after it grants nothing. 04:00 is found with calendar arithmetic in the zone, so
the trust is also capped at 24 hours from the grant, so on a day of 25 hours it can end up to an hour before 04:00 on the clock.

**Revoke and persistence.** The plugin's page in the panel has a "Trusted projects" section (root, computer,
branches, commands used, when it was granted, end or "UNTIL REVOKED") with Revoke and Revoke all; `claude_code_mandates` lists both kinds and revokes
`pt_…`, `md_…` or `all`. The trust is part of the plugin's saved state in Rubi (like 2-hour trusts and
bindings): it survives a restart of Rubi Home, of the plugin and of Rubi until it ends or is revoked; ended
ones are dropped. Nothing in it works around Rubi being locked: the allow is an answer sent through Rubi, so
while Rubi is locked the helper denies as always.

### Trust a project until I revoke it

A fourth button on `run` approvals, **Allow and trust the project /path/to/project until I revoke it**, gives the
same project trust **without an end time**. The 04:00 button stays the default and the first choice; nothing
chooses the unlimited one for you. The Bot can ask for it too: `claude_code_trust_project {bind_code,
branch_pattern?, until?}` with `until` `"0400"` (the default) or `"revoked"`; the approval is strong and locked
as before, carries only the one option for the mode asked, and says **UNTIL REVOKED — no end time** in capitals.

- **How long.** Until you revoke it in the panel or with `claude_code_mandates`, or Rubi is locked. It stays
  on across restarts of Rubi Home, of the plugin and of Rubi, and across days, weeks and months. While Rubi is
  locked nothing is allowed (the allow is an answer sent through Rubi, and the helper denies when Rubi isn't
  polling), and the trust is there again when you unlock. It is never dropped by the plugin's clean-up; the
  list of 20 trusts evicts the oldest *timed* one when full and refuses a new grant when all 20 are unlimited.
- **No count limit.** A 04:00 trust ends after 2000 commands. An unlimited one has no cap, because a cap would
  end it by surprise; every allow is still counted and audited with the trust's `pt_…` id, so the audit log is the
  control. The panel and `claude_code_mandates` show the count and **when it was granted** (`granted_ago`, for
  example "3 d 4 h ago").
- **Everything else is the same.** The same command check, the branch rule, the same always-ask list (push and
  every remote git command, `--force`, sudo, network commands and installs, `git tag`, writes outside the root or
  into `.git`, credential paths, branches outside the pattern, `git rebase` without `--no-update-refs`), the
  same root rules, and the same rate limits for the Bot (20 binds, 5 starts, 5 trust requests an hour).
- **Replacement.** There is one live `pt_…` per computer and root; a new grant, of either mode, replaces the old
  one (both audited with their modes). Choosing "until 04:00" later replaces an unlimited trust with a timed one.
- **The risk, plainly.** Nothing ends it by itself, so it can outlive what you remember about it. While it
  stands, every Claude Code session in the project may run plain, listed commands without asking (builds and
  tests run the project's own code with your rights, which Claude may have just written), the Bot bound to a
  session of the project may open and bind sessions in it without asking, and those sessions run with the
  Claude desktop app's permission settings: if those skip permission prompts (`bypassPermissions`), their
  commands never ask and no trust matters. Look at the plugin's page now and then and revoke what you no longer
  need.

### Sessions with bypassPermissions

The example managed settings leave `bypassPermissions` allowed (a mode the Claude desktop app can set per
session). Such a session never asks before a command, so the `PermissionRequest` hook never runs there:
**neither Rubi approvals nor trusts (2-hour or project) apply to it**, and Claude runs every command without you.
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

### Starting a session when none exists

If your project has no Claude Code session open, the Bot can ask for one with `claude_code_start`
(`rubi_agent`, `rubi_agent_code`, `device`, `cwd`, `task`). It is a strong approval with your passkey, and
the approval says what it does: it starts a NEW Claude Code session on that computer in that directory. The
approval shows the Bot's `task` word for word (at most 2000 characters and 40 lines) and, below it, the
header Rubi adds before it, so you see the whole first message. The session receives it framed as a message
from the sister, not as your own words. The task is rejected, not cleaned, if it contains invisible
characters (zero-width, bidirectional, tag, private-use, control, C1) or more than two blank lines in a row;
Rubi Home checks the same, so what you approved is what is launched.

- **Capability.** The plugin declares the separate Rubi Home capability `claude-start`, which the install
  screen words as starting a new session with a first message (and, where permission prompts are skipped,
  Claude running any command). Plugins without it can't start sessions.
- **Permissions.** The session runs with the Claude desktop app's permission settings. If those skip permission
  prompts (`bypassPermissions`, which desktop sessions may use), Claude can run any command there without
  asking, and Rubi approvals and 2-hour trusts don't apply to it. Approve only if you trust the Bot's task
  with that. The result repeats this when the session reports `bypassPermissions`.
- **Where.** Rubi Home starts sessions only in a directory where Claude Code already has a session (a project
  you have used) or inside a folder you list as `claude_start_dirs` in Rubi Home's `config.json`
  (absolute paths, none by default). The path must be the real one: a path that goes through a symbolic link
  is refused, so the directory you approve is the directory the session runs in. Never `~/.claude`, `~/.ssh`,
  `~/Library`, `~/.local`, `~/.npm`, `~/.oh-my-zsh`, `~/.zsh*`, your home folder itself, `/var`, `/opt`,
  `/Applications`, `/Volumes` itself, system folders. At most 3 starts an hour per computer, and in this plugin
  5 requests an hour per Bot and 10 in all.
- **How.** Rubi Home opens the desktop app's `claude://code/new?folder=...&q=...` link with `/usr/bin/open`
  (a Mac with the Claude desktop app is needed) and waits up to 45 seconds for the new session's SessionStart
  hook (a fresh `startup`, not a resume, in that folder; the first message carries a random reference code that
  is checked when the transcript shows it). The hooks must be set up as for any other session. A headless
  `claude -p` is not used: it needs the command-line tool signed in and leaves no live session behind.
- **After it starts.** The Bot is bound to the new session in the same step, as with `claude_code_bind`: it
  gets `claude_bound` with its `bind_code` (the code is never in the approval's result) and can use
  `claude_code_send`. If the session doesn't show up in time (the app may wait for you to confirm, or the
  hooks are missing), the result says it was launched but not seen yet; once `claude_code_sessions` lists it,
  the Bot binds with `claude_code_bind` (a new approval). If Rubi Home doesn't answer after the request was
  sent, the error says the session may have been started: check the desktop app before trying again.
- **Needs a newer Rubi.** `claude-start` is a new capability; the plugin's `MinRubi` has to be raised to the core
  release that has it when that is tagged.

Manual check on the Mac (not done yet): put a scratch folder in `claude_start_dirs`, have a Bot call
`claude_code_start` with a harmless task, approve, and see that the app opens a session in that folder with
the framed message, that the Bot gets `claude_bound`, that the session keeps running, and which permission
mode it has. Also try a task with spaces, quotes, `&`, `#` and non-ASCII text.

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

### The sister tools inside Claude Code

Claude Code gets four real tools from the `rubi-sisters` plugin (marketplace `rubi`, embedded in the
`rubi-home` binary, with a skill that tells Claude how to use them). Claude calls them as
`mcp__plugin_rubi-sisters_rubi__<tool>`:

| Tool | What it does |
| :- | :- |
| `rubi_sisters {}` | the Bot(s) bound to this session (name, since) and who sent it messages in the last 24 hours |
| `rubi_ask {text, kind?}` | queues an ask for the sister, exactly like a ```` ```rubi-ask ```` block (kind `research`, `audit` or `lookup`, at most 2000 characters, at most 3 a minute); returns the ask's id. It arrives at the Bot as `claude_ask` |
| `rubi_reply {message_id, text}` | answers one message that was delivered to this session in the last 24 hours, now. It arrives at the Bot as `claude_reply` with `in_reply_to` set, and the message's state becomes `answered`. It is Claude's whole answer to that message: the turn's final answer is not sent again for it (messages not replied to still get the final answer) |
| `rubi_inbox_status {}` | messages waiting, replies still owed, whether a waiter is attached, recent states (queued, delivered, answered) |

The text-block convention keeps working (the skill names it as the fallback), and the plugin needs no change
to route these: asks and replies reach the Bot through the same `claude-sessions.next` entries. When you bind
a Bot, unbind it or the binding follows a restarted session, the plugin tells Rubi Home with
`claude-sessions.bound`, which is how `rubi_sisters` names her. An older Rubi Home doesn't know that
operation: the plugin logs it once and carries on, and the tools there say so.

**They add no trust.** Nothing a tool returns approves a command or changes a permission, Claude can't
approve anything with them, and a tool call is a separate line on Rubi Home's socket that is never treated as
an approval or a hook event. A call acts for the session it comes from; an ask from a session that isn't
bound may still go to the Bot of its project (the same route as a text block). Consent: the managed
settings allow only the two read-only tools (`rubi_sisters`, `rubi_inbox_status`) without a prompt;
`rubi_ask` and `rubi_reply` send something out, so Claude Code asks you for each call as it does for any MCP
tool. The allow rule is name-based (plugin `rubi-sisters`, server `rubi`): another marketplace's plugin of the
same name would match it too, so lock marketplaces with the managed `strictKnownMarketplaces` setting
([docs](https://code.claude.com/docs/en/settings-reference.md#strictknownmarketplaces)) if that matters to you.

How the tools know which session calls: not from anything in the request (a process of yours could write any
session id into it), but from the kernel. Rubi Home reads the pid of the process on the other end of its socket
(macOS `LOCAL_PEERPID`, Linux `SO_PEERCRED`) right after accepting the connection, and finds that process's
`claude` ancestor (the first process named `claude` within 6 levels above it, else its direct parent; never a
shell, terminal or the desktop app above it). The first hook line of a session claims that `claude` process
for the session; while that session keeps sending hooks another session's line from the same process is ignored.
A claim ends with the session's SessionEnd (only when it comes from the claiming process), when the pid is
reused, after 24 hours without a hook, or moves when the session has been silent for 10 minutes and another
session's hook arrives from the same process. A tool call is attributed to the session that holds its caller's
`claude` process, or refused ("this session isn't known to Rubi Home yet; try again after its next prompt"),
also before a new `claude` has sent its first hook, even when an earlier one that crashed ran under the same
shell. The CLI process must be named `claude`; otherwise the tools are refused (fail closed). Where the peer
can't be identified the tools are refused too.

What that does and doesn't guarantee: tool identity is the `claude` process tree as the kernel reports it, plus
the hook lines, which are trusted as before. Any process inside session A's tree acts as A: it can use A's tools,
end A's claim and claim the process for another session id (that is what `/clear` does). A process of yours
outside every `claude` tree is refused unless it first claims a process of its own by sending hook lines (you
could always forge those); it can then act as a session id no `claude` has claimed yet, but cannot take a
process an active session holds. The tools give no approval power in any case.

Install (needs the managed settings and the root-owned hook binary below):

```sh
~/.rubi-home/bin/rubi-home install-hook --with-claude-plugin
```

It copies the plugin's files to `/Library/Application Support/Rubi Home/claude-plugin` in the same
administrator step as the binary. The file contents travel inside the script (root reads nothing you can
write), root decodes them into a temporary folder next to the target, checks every file's sha256, makes the
tree root-owned and renames it into place (the old folder is kept until the rename worked). `--dry-run`
lists the files with their hashes. Then the managed settings register the marketplace (`extraKnownMarketplaces`,
a `directory` source) and enable the plugin (`enabledPlugins`); they do not use `managed-mcp.json`, which
would take exclusive control of your MCP servers. Restart Claude Code afterwards. The MCP server runs
`/usr/local/bin/rubi-home claude-mcp`, so that root-owned copy must be new enough: with an older one the
server fails to start (`/mcp` shows it as failed) until you run `install-hook` again. The plugin folder is
root-owned; the Claude Code docs say a marketplace added from a local directory with a relative `source` is
read in place, but they don't say so for managed `extraKnownMarketplaces`, so if Claude Code copies the plugin
into `~/.claude/plugins` that copy is writable by you and only the source is protected. That is why
`strictKnownMarketplaces` and the root-owned command path matter more than the folder itself.

Manual check: start a Claude Code session in a project, ask "which sister do you have? use rubi_sisters"
(it lists the tools and names her once she is bound), then have the Bot send a message and ask Claude to
`rubi_reply` to it (approve the prompt); the Bot should receive `claude_reply` with `in_reply_to`. `/mcp` shows the `rubi`
server of the `rubi-sisters` plugin as connected.

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
   `--sudo` uses `sudo` in a terminal instead of the dialog, `--with-claude-plugin` also installs the
   sister tools' plugin (see above). Run it again after each Rubi Home update:
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
     Add it with `sudo` like the rest, then restart Claude Code;
   - `extraKnownMarketplaces` (marketplace `rubi`, a `directory` source at
     `/Library/Application Support/Rubi Home/claude-plugin`), `enabledPlugins` (`rubi-sisters@rubi`) and one
     allow rules for the two read-only tools (`rubi_sisters`, `rubi_inbox_status`; `rubi_ask` and
     `rubi_reply` still prompt), for the
     [sister tools](#the-sister-tools-inside-claude-code); run
     `rubi-home install-hook --with-claude-plugin` first so the folder exists.

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
