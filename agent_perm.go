package main

// Permissions on the agent path. Rubi Home hands every tool call of the runner (claude-agent.next, item
// perm.ask) and every git credential request (cred.ask) to the plugin, which answers with claude-agent.decide.
// Order of decision:
//
//  1. AskUserQuestion: shown to the user as an approval with the question's options.
//  2. The always-ask list, in every mode: git push and other remote git commands, --force, sudo, the network
//     outside the allow-list (curl/wget/WebFetch to other hosts), paths outside /work, anything under .rubi,
//     edits under .claude, tags and releases. A strong approval; nothing a trust says changes that.
//  3. bypassPermissions: allow.
//  4. A stricter mode (plan, default, acceptEdits): a live 2-hour or project trust (mandate.go, projecttrust.go)
//     allows the plain commands it covers; a read-only command from the short list (classify.go) is a tap; the
//     rest is a normal run approval.
//
// Anything else, or a failure, is a deny: Rubi Home denies by itself after 280 seconds or while Rubi is locked.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const kindAgentQuestion = "claude-code.agent_question"

// agentHosts are the hosts a command may reach without asking: what Rubi Home's proxy lets every project reach
// (the project's git hosts are Rubi Home's own list, and git itself is a remote command that asks).
var agentHosts = map[string]bool{"api.anthropic.com": true, "registry.npmjs.org": true, "registry.yarnpkg.com": true,
	"pypi.org": true, "files.pythonhosted.org": true}

var (
	readTools = map[string]bool{"Read": true, "Glob": true, "Grep": true, "LS": true, "NotebookRead": true, "TodoWrite": true,
		"WebSearch": true, "Task": true, "Agent": true, "BashOutput": true, "KillShell": true, "KillBash": true, "TaskOutput": true,
		"TaskStop": true, "Skill": true, "SlashCommand": true, "ToolSearch": true}
	editTools = map[string]bool{"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true}
)

func toolPaths(tool string, in map[string]any) []string {
	var out []string
	for _, k := range []string{"file_path", "notebook_path", "path"} {
		if v, ok := in[k].(string); ok && v != "" {
			out = append(out, v)
		}
	}
	if v, ok := in["pattern"].(string); ok && tool == "Glob" && (strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.Contains(v, "..")) {
		out = append(out, v)
	}
	return out
}

func segs(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '=' })
}

func hasSeg(p string, names ...string) bool {
	for _, s := range segs(p) {
		for _, n := range names {
			if s == n {
				return true
			}
		}
	}
	return false
}

// agentAlwaysAsk returns why a tool call must have a strong approval whatever the mode, or "".
func agentAlwaysAsk(tool string, raw json.RawMessage, cwd string) string {
	if cwd != "" && !within(agentRoot, cwd) {
		return "the working directory " + cwd + " is outside " + agentRoot
	}
	if cwd == "" {
		cwd = agentRoot
	}
	var in map[string]any
	_ = json.Unmarshal(raw, &in)
	switch {
	case tool == "Bash":
		cmd, _ := in["command"].(string)
		return bashAlwaysAsk(cmd, cwd)
	case tool == "WebFetch":
		u, _ := in["url"].(string)
		if h := fetchHost(u); h == "" || !agentHosts[h] {
			return "WebFetch to " + oneLine(firstNonEmpty(h, u), 80) + ", a host outside the allow-list"
		}
		return ""
	case readTools[tool] || editTools[tool]:
		for _, p := range toolPaths(tool, in) {
			r := p
			if !strings.HasPrefix(p, "~") && !path.IsAbs(p) {
				r = path.Join(cwd, p)
			}
			r = path.Clean(r)
			switch {
			case strings.HasPrefix(p, "~") || !within(agentRoot, r):
				return tool + " of " + oneLine(p, 120) + ", outside " + agentRoot
			case hasSeg(r, ".rubi"):
				return tool + " of " + oneLine(p, 120) + ", under .rubi (Rubi's own files, the Claude login among them)"
			case editTools[tool] && hasSeg(r, ".claude"):
				return "edit of " + oneLine(p, 120) + ", under .claude (it changes how Claude is set up)"
			}
		}
	}
	return ""
}

// bashSegments splits a command line leniently into commands and words: quotes and backslashes are dropped (so
// g”it reads git), command separators and substitutions start a new command, redirections are plain spaces.
// It is a net for the always-ask list, not a parser: whatever it can't read it still reads as words.
func bashSegments(cmd string) [][]string {
	var b strings.Builder
	rs := []rune(cmd)
	for i := 0; i < len(rs); i++ {
		switch r := rs[i]; r {
		case '\n', ';', '&', '|', '(', ')', '`', '{', '}':
			b.WriteRune(0)
		case '$':
			if i+1 < len(rs) && rs[i+1] == '(' {
				b.WriteRune(0)
				i++
			} else {
				b.WriteRune(r)
			}
		case '"', '\'', '\\':
		case '<', '>', '\t', '\r':
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	var out [][]string
	for _, part := range strings.Split(b.String(), "\x00") {
		if f := strings.Fields(part); len(f) > 0 {
			out = append(out, f)
		}
	}
	return out
}

var (
	rootProgs = map[string]bool{"sudo": true, "doas": true, "su": true, "pkexec": true}
	netProgs  = map[string]bool{"ssh": true, "scp": true, "sftp": true, "rsync": true, "nc": true, "ncat": true, "netcat": true, "telnet": true,
		"ftp": true, "tftp": true, "socat": true, "nmap": true, "ping": true, "traceroute": true, "dig": true, "nslookup": true, "mosh": true}
	remoteGit = map[string]bool{"push": true, "fetch": true, "pull": true, "clone": true, "remote": true, "ls-remote": true,
		"submodule": true, "request-pull": true, "send-email": true, "svn": true, "lfs": true}
)

func bashAlwaysAsk(cmd, cwd string) string {
	for _, seg := range bashSegments(cmd) {
		if r := segAlwaysAsk(seg, cwd); r != "" {
			return r
		}
	}
	return ""
}

func segAlwaysAsk(seg []string, cwd string) string {
	base := func(i int) string { return path.Base(seg[i]) }
	for i := range seg {
		if rootProgs[base(i)] {
			return "sudo or another way to become root (" + base(i) + ")"
		}
	}
	for i := range seg {
		switch base(i) {
		case "git":
			sub, rest := gitSub(seg[i+1:])
			switch {
			case remoteGit[sub]:
				return "git " + sub + ": a remote git operation"
			case sub == "tag" && !onlyListing(rest):
				return "git tag: tags are releases"
			}
			for _, t := range rest {
				if t == "-f" || strings.HasPrefix(t, "--force") {
					return "git with " + t + ": it can throw work away"
				}
			}
		case "gh", "hub", "glab":
			return base(i) + ": it works on the remote repository (pushes, pull requests, releases)"
		case "npm", "pnpm", "yarn", "bun", "cargo", "gem", "docker", "twine", "vsce":
			for _, t := range seg[i+1:] {
				if t == "publish" || t == "upload" || t == "push" || t == "adduser" || t == "login" {
					return base(i) + " " + t + ": a release or a login"
				}
			}
		}
	}
	for i := range seg {
		b := base(i)
		if netProgs[b] {
			return b + ": the network outside the allow-list"
		}
		if b == "curl" || b == "wget" {
			hosts := cmdHosts(seg[i+1:])
			if len(hosts) == 0 {
				return b + " with no host Rubi can check"
			}
			for _, h := range hosts {
				if !agentHosts[h] {
					return b + " to " + oneLine(h, 80) + ", a host outside the allow-list"
				}
			}
		}
	}
	for _, t := range seg {
		if strings.HasPrefix(t, "--force") && !strings.HasPrefix(t, "--force-") || t == "--force" {
			return t + ": it overrides a safety check"
		}
	}
	for _, t := range seg {
		if p := outsidePath(t, cwd); p != "" {
			return "the path " + oneLine(p, 120) + " is outside " + agentRoot
		}
	}
	for _, t := range seg {
		if hasSeg(t, ".rubi", ".claude") {
			return oneLine(t, 120) + " is under .rubi or .claude (how Claude is set up, and the Claude login)"
		}
	}
	return ""
}

// gitSub finds the git subcommand among the words after "git" and returns it with the words after it.
func gitSub(w []string) (string, []string) {
	for i := 0; i < len(w); i++ {
		t := w[i]
		if strings.HasPrefix(t, "-") {
			if t == "-C" || t == "-c" || t == "--git-dir" || t == "--work-tree" || t == "--namespace" || t == "--exec-path" {
				i++
			}
			continue
		}
		return t, w[i+1:]
	}
	return "", nil
}

func onlyListing(w []string) bool {
	for _, t := range w {
		if t != "-l" && t != "--list" && t != "-n" {
			return false
		}
	}
	return true
}

// cmdHosts lists the hosts a curl or wget command line names (a word with a scheme, or one that looks like a host).
func cmdHosts(w []string) []string {
	var out []string
	for _, t := range w {
		if i := strings.IndexByte(t, '='); strings.HasPrefix(t, "-") && i > 0 {
			t = t[i+1:]
		} else if strings.HasPrefix(t, "-") {
			continue
		}
		switch {
		case strings.Contains(t, "://"):
			u, err := url.Parse(t)
			if err != nil || u.Hostname() == "" {
				out = append(out, "?")
			} else {
				out = append(out, strings.ToLower(u.Hostname()))
			}
		case strings.ContainsAny(t, ".:") && !strings.HasPrefix(t, "/") && !strings.HasPrefix(t, "."):
			if u, err := url.Parse("//" + t); err == nil && u.Hostname() != "" {
				out = append(out, strings.ToLower(u.Hostname()))
			} else {
				out = append(out, "?")
			}
		}
	}
	return out
}

func fetchHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// outsidePath returns the word (or its value after =) when it names a place outside /work.
func outsidePath(tok, cwd string) string {
	cands := []string{tok}
	if i := strings.IndexByte(tok, '='); i > 0 {
		cands = append(cands, tok[i+1:])
	}
	for _, c := range cands {
		switch {
		case c == "":
		case strings.HasPrefix(c, "~"), strings.HasPrefix(c, "$HOME"), strings.HasPrefix(c, "${HOME"):
			return c
		case strings.HasPrefix(c, "/"):
			if devNull(c) || c == "/dev/stdin" || c == "/dev/tty" || within(agentRoot, path.Clean(c)) {
				continue
			}
			return c
		case !strings.Contains(c, "://") && hasSeg(strings.ReplaceAll(c, "=", "/"), ".."):
			if !within(agentRoot, resolve(cwd, c)) {
				return c
			}
		}
	}
	return ""
}

// ---- handling a question ----

// agentDecision is claude-agent.decide's input.
type agentDecision struct {
	AskID        string `json:"ask_id"`
	Behavior     string `json:"behavior"`
	Message      string `json:"message,omitempty"`
	UpdatedInput any    `json:"updated_input,omitempty"`
}

func (w *watcher) agentDecide(ctx context.Context, d rubiplugin.HomeDevice, id, behavior, msg string) {
	if err := w.h.HomeCall(ctx, d.ID, opAgentDecide, agentDecision{AskID: id, Behavior: behavior, Message: msg}, nil); err != nil && ctx.Err() == nil {
		w.h.Logf("%s: answering %s: %v", d.Name, id, err)
	}
}

func toolDetail(tool string, raw json.RawMessage) string {
	var in map[string]any
	_ = json.Unmarshal(raw, &in)
	switch {
	case tool == "Bash":
		if c, _ := in["command"].(string); c != "" {
			return c
		}
	case tool == "WebFetch":
		if c, _ := in["url"].(string); c != "" {
			return c
		}
	case readTools[tool] || editTools[tool]:
		if p := toolPaths(tool, in); len(p) > 0 {
			return strings.Join(p, " ")
		}
	}
	return oneLine(string(raw), 300)
}

// handleAsk decides one perm.ask or cred.ask item (see the order at the top of the file).
func (w *watcher) handleAsk(ctx context.Context, d rubiplugin.HomeDevice, it agentItem) {
	if it.AskID == "" {
		w.h.Logf("%s: a question without an id was dropped", d.Name)
		return
	}
	deny := func(msg string) { w.agentDecide(ctx, d, it.AskID, "deny", msg) }
	allow := func() { w.agentDecide(ctx, d, it.AskID, "allow", "") }
	cwd := firstNonEmpty(it.Cwd, agentRoot)
	tool := it.Tool
	if it.Type == "cred.ask" {
		tool = "git credential"
	}
	if tool == "AskUserQuestion" {
		w.askQuestion(ctx, d, it, deny)
		return
	}
	reason := ""
	switch {
	case it.Type == "cred.ask":
		reason = "git credentials for a push or another remote operation"
	default:
		reason = agentAlwaysAsk(tool, it.Input, cwd)
	}
	if reason != "" {
		w.agentApprove(ctx, d, it, kindRun, cwd, tool, reason, true, deny)
		return
	}
	if it.Mode == "bypassPermissions" || strings.HasPrefix(tool, "mcp__rubi__") {
		allow()
		return
	}
	// A stricter mode (an unknown mode counts as the strictest that asks).
	var in map[string]any
	_ = json.Unmarshal(it.Input, &in)
	detail := toolDetail(tool, it.Input)
	covered := func() (bool, string) { // a trust that covers the session or project and allows the command
		command := detail
		if tool != "Bash" {
			command = "pwd" // an edit inside /work is judged like a plain command in it: a live trust that covers the session allows it
		}
		r := request{ID: it.AskID, SessionID: it.SessionID, Project: it.Project, ToolName: tool, Command: command, Cwd: cwd}
		m, why := w.s.st.use(d.ID, r, w.s.now())
		if m != nil {
			fields := map[string]any{"mandate": m.ID, "device": d.ID, "session": it.SessionID, "project": it.Project, "request": it.AskID,
				"command": oneLine(detail, 300), "directory": cwd, "uses": m.Uses, "tool": tool}
			w.h.Audit(auditMandateAll, fields)
			return true, ""
		}
		return false, why
	}
	secret := false
	for _, p := range toolPaths(tool, in) {
		secret = secret || secretPath(p) != ""
	}
	switch {
	case tool == "Bash":
		if ok, _ := covered(); ok {
			allow()
			return
		}
		if safe, _ := classify(detail); safe {
			w.agentApprove(ctx, d, it, kindSafe, cwd, tool, "a read-only command", false, deny)
			return
		}
	case readTools[tool] && !secret:
		allow()
		return
	case editTools[tool] && it.Mode == "plan":
		deny("plan mode: Claude may not edit files; ask the user to leave plan mode")
		return
	case editTools[tool] && it.Mode == "acceptEdits" && !secret:
		allow()
		return
	case tool == "WebFetch":
		allow()
		return
	case editTools[tool] && !secret:
		if ok, _ := covered(); ok {
			allow()
			return
		}
	}
	w.agentApprove(ctx, d, it, kindRun, cwd, tool, "this mode asks before "+tool, false, deny)
}

// agentApprove asks the user (kindRun: a strong approval; kindSafe: a tap) and answers Rubi Home when the
// approval ends in anything but a run. An approval that runs answers in execute (allow), so only an approval
// the user gave lets the call through.
func (w *watcher) agentApprove(ctx context.Context, d rubiplugin.HomeDevice, it agentItem, kind, cwd, tool, why string, always bool, deny func(string)) {
	detail := toolDetail(tool, it.Input)
	sum := sha256.Sum256(it.Input)
	preview := map[string]any{"command": detail, "directory": cwd, "computer": d.Name, "tool": tool, "session": it.SessionID,
		"project": it.Project, "mode": it.Mode, "why_this_approval": why}
	if always {
		preview["always_asks"] = "This asks in every mode, bypassPermissions included, and no trust covers it: " + why
	}
	if it.AgentType != "" {
		preview["subagent"] = it.AgentType
	}
	t := ticket{Device: d.ID, DeviceName: d.Name, AskID: it.AskID, AgentProject: it.Project, SessionID: it.SessionID, Cwd: agentRoot, Digest: hex.EncodeToString(sum[:])}
	req := rubiplugin.Request{Kind: kind, Summary: "Claude (" + tool + "): " + oneLine(detail, 100), Preview: preview, Payload: t}
	switch {
	case always:
		req.Options = []rubiplugin.Option{{Key: optionAllow, Label: "Allow", Meaning: "Claude runs this once"}}
	case kind == kindRun:
		req.Options = manifestRunOptions()
	}
	w.submitAgent(ctx, d, it, req, detail, deny)
}

// submitAgent submits the approval, tells the Bot about it and follows it while Rubi Home still waits.
func (w *watcher) submitAgent(ctx context.Context, d rubiplugin.HomeDevice, it agentItem, req rubiplugin.Request, detail string, deny func(string)) {
	life := it.ExpiresAt
	if life.IsZero() {
		life = w.s.now().Add(askLife)
	}
	out, err := w.h.Submit(ctx, req)
	if err != nil {
		w.h.Logf("%s: asking about %s: %v", d.Name, it.AskID, err)
		deny("Rubi couldn't ask you (" + oneLine(err.Error(), 200) + "), so this was denied.")
		return
	}
	id, _ := out["approval_id"].(string)
	if out["status"] != "awaiting_approval" || id == "" {
		return // no approval needed (the level was lowered): execute already answered
	}
	ev := map[string]any{"approval_id": id, "level": out["level"], "command": oneLine(detail, 300), "directory": agentRoot,
		"computer": d.Name, "expires_at": life, "project": it.Project}
	for _, k := range []string{"approval_url", "buttons", "after_sending_the_link"} {
		if v, ok := out[k]; ok {
			ev[k] = v
		}
	}
	if _, err := w.h.Emit(eventNeeded, ev); err != nil {
		w.h.Logf("%s: telling the agent about %s: %v", d.Name, id, err)
	}
	w.follow(ctx, request{ExpiresAt: life}, id, deny)
}

// ---- AskUserQuestion ----

type questionTicket struct {
	Device    string          `json:"device"`
	AskID     string          `json:"ask_id"`
	Question  string          `json:"question"`
	Labels    []string        `json:"labels"`
	Questions json.RawMessage `json:"questions"`
}

// askQuestion shows Claude's question and its options to the user as an approval; the chosen option is the answer.
// One single-choice question at a time is supported; anything else is sent back to Claude to ask again.
func (w *watcher) askQuestion(ctx context.Context, d rubiplugin.HomeDevice, it agentItem, deny func(string)) {
	var in struct {
		Questions json.RawMessage `json:"questions"`
	}
	var qs []struct {
		Question    string `json:"question"`
		Header      string `json:"header"`
		MultiSelect bool   `json:"multiSelect"`
		Options     []struct {
			Label       string `json:"label"`
			Description string `json:"description"`
		} `json:"options"`
	}
	if json.Unmarshal(it.Input, &in) != nil || json.Unmarshal(in.Questions, &qs) != nil || len(qs) != 1 || qs[0].MultiSelect ||
		len(qs[0].Options) < 2 || len(qs[0].Options) > 4 || qs[0].Question == "" {
		deny("Rubi can show one single-choice question with 2 to 4 options at a time; ask again that way")
		return
	}
	q := qs[0]
	t := questionTicket{Device: d.ID, AskID: it.AskID, Question: q.Question, Questions: in.Questions}
	var opts []rubiplugin.Option
	for i, o := range q.Options {
		if o.Label == "" {
			deny("a question option has no label")
			return
		}
		t.Labels = append(t.Labels, o.Label)
		opts = append(opts, rubiplugin.Option{Key: fmt.Sprintf("opt%d", i), Label: oneLine(o.Label, 60), Meaning: oneLine(o.Description, 200)})
	}
	preview := map[string]any{"question": q.Question, "header": q.Header, "computer": d.Name, "session": it.SessionID, "project": it.Project,
		"what_it_does": "Answers Claude's question with the option you choose. Denying tells Claude you declined to answer. It approves nothing else."}
	req := rubiplugin.Request{Kind: kindAgentQuestion, Summary: "Claude asks: " + oneLine(q.Question, 100), Preview: preview, Options: opts, Payload: t}
	w.submitAgent(ctx, d, it, req, q.Question, deny)
}

// answerQuestion runs when the user chose an option: it answers Claude's question with it.
func answerQuestion(ctx context.Context, h homeCaller, option string, payload json.RawMessage) (any, error) {
	var t questionTicket
	if err := json.Unmarshal(payload, &t); err != nil || t.AskID == "" || t.Device == "" {
		return nil, errors.New("bad payload")
	}
	var i int
	if _, err := fmt.Sscanf(option, "opt%d", &i); err != nil || i < 0 || i >= len(t.Labels) {
		return nil, errors.New("unknown option")
	}
	upd := map[string]any{"questions": t.Questions, "answers": map[string]string{t.Question: t.Labels[i]}}
	if err := h.HomeCall(ctx, t.Device, opAgentDecide, agentDecision{AskID: t.AskID, Behavior: "allow", UpdatedInput: upd}, nil); err != nil {
		return nil, fmt.Errorf("Claude is no longer waiting for this answer (%v)", err)
	}
	return map[string]any{"answered": t.Labels[i]}, nil
}
