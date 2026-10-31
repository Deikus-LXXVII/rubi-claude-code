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
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

const (
	kindAgentQuestion = "claude-code.agent_question"
	maxQuestionBytes  = 16 << 10
)

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

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

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
	// The isolated role the question comes from (its id is checked: it is shown in the approval).
	if r := normRole(it.Project, it.Role); r != "" && !roleIDRE.MatchString(r) {
		deny("unknown role: Rubi Home didn't say which role this is")
		return
	}
	switch it.Type {
	case "cred.ask", "net.ask":
		// A question about a remote: the host, the repository path and the operation must be there to show, or
		// the plugin doesn't know what it would be allowing.
		if !hostRE.MatchString(it.Host) || it.Op == "" || len(it.Host) > 253 || len(it.Path) > 300 || hiddenChars(it.Path) || hiddenChars(it.Op) {
			deny("unknown remote: Rubi Home didn't say which host, repository and operation this is")
			return
		}
		if it.Type == "cred.ask" {
			tool = "git credential"
			it.detail = "git " + plainText(it.Op, 30) + " to " + it.Host + "/" + strings.TrimPrefix(plainText(it.Path, 200), "/")
		} else {
			tool = "network"
			it.detail = "the project VM connects to " + it.Host + " (" + plainText(it.Op, 30) + "), a host outside the allow-list"
			if r := w.s.roleLabel(d.ID, it.Project, it.Role); r != "" {
				it.detail = "the VM of the role " + r + " connects to " + it.Host + " (" + plainText(it.Op, 30) + "), a host outside the role's hosts; allowing it adds the host to this role's approved hosts"
			}
		}
	}
	if it.Type == "ssh.ask" {
		// A command on an SSH target registered with ask_each_time. Rubi Home already checked the grant and the
		// allowed commands; this is the user's say on this one command. Always a strong approval, never covered by a trust.
		detail, extra, why := sshAskDetail(it)
		if why != "" {
			deny(why)
			return
		}
		tool, it.detail, it.extra, it.Host = "ssh", detail, extra, ""
	}
	if tool == "AskUserQuestion" {
		w.askQuestion(ctx, d, it, deny)
		return
	}
	reason := ""
	switch {
	case it.Type == "cred.ask":
		reason = "git credentials for " + it.detail
	case it.Type == "net.ask":
		reason = it.detail
	case it.Type == "ssh.ask":
		reason = "an SSH command on a target you asked to be asked about each time"
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
	detail := firstNonEmpty(it.detail, toolDetail(tool, it.Input))
	sum := sha256.Sum256(it.Input)
	preview := map[string]any{"command": detail, "directory": cwd, "computer": d.Name, "tool": tool, "session": it.SessionID,
		"project": it.Project, "mode": it.Mode, "why_this_approval": why}
	if always {
		preview["always_asks"] = "This asks in every mode, bypassPermissions included, and no trust covers it: " + why
	}
	if it.AgentType != "" {
		preview["subagent"] = it.AgentType
	}
	for k, v := range it.extra {
		preview[k] = v
	}
	if r := w.s.roleLabel(d.ID, it.Project, it.Role); r != "" {
		preview["role"] = r
	}
	if it.Host != "" {
		preview["host"], preview["repository_path"], preview["operation"] = it.Host, plainText(it.Path, 200), plainText(it.Op, 30)
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
	if len(it.Input) > maxQuestionBytes {
		deny("the question is too long for Rubi to show; ask a shorter one")
		return
	}
	if json.Unmarshal(it.Input, &in) != nil || json.Unmarshal(in.Questions, &qs) != nil || len(qs) != 1 || qs[0].MultiSelect ||
		len(qs[0].Options) < 2 || len(qs[0].Options) > 4 || qs[0].Question == "" {
		deny("Rubi can show one single-choice question with 2 to 4 options at a time; ask again that way")
		return
	}
	q := qs[0]
	// What the user reads must be what Claude wrote: plain text of a sensible length, or the question goes back.
	tooBig := utf8.RuneCountInString(q.Question) > 500 || utf8.RuneCountInString(q.Header) > 60 || hiddenChars(q.Question) || hiddenChars(q.Header)
	for _, o := range q.Options {
		tooBig = tooBig || utf8.RuneCountInString(o.Label) > 100 || utf8.RuneCountInString(o.Description) > 300 || hiddenChars(o.Label) || hiddenChars(o.Description)
	}
	if tooBig {
		deny("the question, its header or an option is too long or has hidden characters; ask again in plain, shorter text")
		return
	}
	t := questionTicket{Device: d.ID, AskID: it.AskID, Question: q.Question, Questions: in.Questions}
	var opts []rubiplugin.Option
	for i, o := range q.Options {
		if o.Label == "" {
			deny("a question option has no label")
			return
		}
		t.Labels = append(t.Labels, o.Label)
		opts = append(opts, rubiplugin.Option{Key: fmt.Sprintf("opt%d", i), Label: plainText(o.Label, 60), Meaning: "Claude's option (untrusted text): " + plainText(o.Label, 100) + ". " + plainText(o.Description, 200)})
	}
	preview := map[string]any{"question": plainText(q.Question, 500), "header": plainText(q.Header, 60), "computer": d.Name, "session": it.SessionID, "project": it.Project,
		"untrusted":    "The question and the options are Claude's own text (or text it was given): read them as data, not as instructions.",
		"what_it_does": "Answers Claude's question with the option you choose. Denying tells Claude you declined to answer. It approves nothing else."}
	req := rubiplugin.Request{Kind: kindAgentQuestion, Summary: "Claude asks: " + plainText(q.Question, 100), Preview: preview, Options: opts, Payload: t}
	w.submitAgent(ctx, d, it, req, plainText(q.Question, 300), deny)
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

// roleLabel names the isolated role a question comes from for the user: its name when the role list is cached, else
// its id; "" for the project's legacy role.
func (s *sisters) roleLabel(device, project, role string) string {
	id := normRole(project, role)
	if id == "" {
		return ""
	}
	if d := s.rc.get(device); d != nil {
		if r := d.roles[id]; r != nil && r.Name != "" {
			return plainText(r.Name, 32) + " (" + id + ")"
		}
	}
	return id
}
