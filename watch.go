package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

// request is a Claude Code permission request as the helper hands it out (home.ClaudeRequest).
type request struct {
	ID          string    `json:"id"`
	SessionID   string    `json:"session_id"`
	ToolName    string    `json:"tool_name"`
	ToolInput   string    `json:"tool_input"`
	Digest      string    `json:"digest"`
	Command     string    `json:"command"`
	Description string    `json:"description"`
	Cwd         string    `json:"cwd"`
	ExpiresAt   time.Time `json:"expires_at"`
	// Project is set for a request from a Rubi Home agent project (claude-agent); never by the hook helper.
	Project string `json:"project,omitempty"`
}

// answer is claude.decide's input; the helper checks it against the request it handed out.
type answer struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Digest    string `json:"digest"`
	Behavior  string `json:"behavior"`
	Message   string `json:"message,omitempty"`
}

// ticket is the approval's payload: which request on which computer the approval answers.
type ticket struct {
	Device     string `json:"device"`
	DeviceName string `json:"device_name,omitempty"`
	ID         string `json:"id"`
	SessionID  string `json:"session_id"`
	Digest     string `json:"digest"`
	Cwd        string `json:"cwd,omitempty"` // the scope of a mandate given with this approval
	// AskID and AgentProject are set for a permission question of a Rubi Home agent project
	// (claude-agent.next): the answer goes to claude-agent.decide by AskID.
	AskID        string `json:"ask_id,omitempty"`
	AgentProject string `json:"agent_project,omitempty"`
	// Project is the project trust offered with this approval (the trust_project option); nil when none was.
	Project *trustOffer `json:"project,omitempty"`
	// Forever is the same trust until revoked (the trust_project_until_revoked option); nil when none was offered.
	Forever *trustOffer `json:"project_until_revoked,omitempty"`
}

type homeCaller interface {
	HomeCall(ctx context.Context, device, op string, args, out any) error
}

// host is what the watcher uses of *rubiplugin.Host (a fake in tests).
type host interface {
	sisterHost
	WaitApproval(ctx context.Context, id string, wait time.Duration) (rubiplugin.ApprovalState, error)
	Emit(typ string, data map[string]any) (string, error)
}

const (
	pollWait     = 25 * time.Second // the longest claude.next and claude-sessions.next wait
	refreshEvery = 30 * time.Second // how often the list of computers is read again
	maxBackoff   = time.Minute
)

// Denial reasons Claude is told (the helper puts "Rubi: " in front).
const (
	msgDenied    = "you denied this command in Rubi."
	msgCancelled = "the approval was cancelled in Rubi (or Rubi was locked)."
	msgExpired   = "the approval expired in Rubi."
	msgMalformed = "the request didn't check out, so the command was denied."
)

type watcher struct {
	h       host
	s       *sisters // mandates, bindings and routing (nil: none)
	backoff func(n int) time.Duration
	mu      sync.Mutex
	polling map[string]bool
	wg      sync.WaitGroup
}

func newWatcher(h host, s *sisters) *watcher {
	return &watcher{h: h, s: s, polling: map[string]bool{}, backoff: func(n int) time.Duration {
		return min(time.Duration(1<<min(n, 6))*time.Second, maxBackoff)
	}}
}

// run polls every Rubi Home computer until ctx ends, then waits for the requests in hand.
func (w *watcher) run(ctx context.Context) {
	defer w.wg.Wait()
	for {
		w.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(refreshEvery):
		}
	}
}

// refresh starts a poller for each computer that has none.
func (w *watcher) refresh(ctx context.Context) {
	devs, err := w.h.HomeDevices()
	if err != nil {
		w.h.Logf("listing Rubi Home computers: %v", err)
		return
	}
	// A computer whose Rubi Home reports the claude-agent capability is also polled for the agent's questions
	// and events (agent.go); the probe is cached and happens outside the lock.
	agent := map[string]bool{}
	if w.s != nil {
		for _, d := range devs {
			agent[d.ID] = w.s.agentCapable(ctx, w.h, d.ID)
		}
	}
	if w.s != nil {
		var ids []string
		for _, d := range devs {
			if agent[d.ID] {
				ids = append(ids, d.ID)
			}
		}
		if len(ids) > 0 {
			w.wg.Go(func() { w.s.libraryTick(ctx, w.h, ids) })
			w.wg.Go(func() { w.s.sshAuditTick(ctx, w.h, ids) })
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	ops := []string{opNext}
	if w.s != nil {
		ops = append(ops, opSessionsNext)
	}
	for _, d := range devs {
		if agent[d.ID] && !w.polling[d.ID+"|"+opAgentNext] {
			key := d.ID + "|" + opAgentNext
			w.polling[key] = true
			w.wg.Go(func() {
				w.pollAgent(ctx, d)
				w.mu.Lock()
				delete(w.polling, key)
				w.mu.Unlock()
			})
		}
		for _, op := range ops {
			key := d.ID + "|" + op
			if w.polling[key] {
				continue
			}
			w.polling[key] = true
			w.wg.Go(func() {
				w.poll(ctx, d, op)
				w.mu.Lock()
				delete(w.polling, key)
				w.mu.Unlock()
			})
		}
	}
}

// The two polls: permission requests (capability "claude") and what sessions say (capability
// "claude-sessions").
const (
	opNext         = "claude.next"
	opSessionsNext = "claude-sessions.next"
)

// poll asks one computer for permission requests (opNext) or session messages (opSessionsNext) until ctx
// ends or the computer is no longer paired. While Rubi polls opNext, the helper counts it as present;
// when that stops, the helper denies what is waiting.
func (w *watcher) poll(ctx context.Context, d rubiplugin.HomeDevice, op string) {
	failures := 0
	if op == opSessionsNext && w.s != nil {
		go w.s.syncBound(ctx, w.h, d.ID) // off the poll: it must not delay messages
	}
	for ctx.Err() == nil {
		var out struct {
			Request *request `json:"request"`
			Out     *outMsg  `json:"out"`
		}
		err := w.h.HomeCall(ctx, d.ID, op, map[string]any{"wait_seconds": int(pollWait / time.Second)}, &out)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if rubiplugin.ErrorCode(err) == rubiplugin.CodeHomeNotPaired {
				w.h.Logf("%s: %v", d.Name, err)
				return
			}
			failures++
			if failures == 1 || failures%10 == 0 {
				w.h.Logf("%s: %v", d.Name, err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(w.backoff(failures)):
			}
			continue
		}
		failures = 0
		if r := out.Request; r != nil && op == opNext {
			w.wg.Go(func() { w.handle(ctx, d, *r) })
		}
		if o := out.Out; o != nil && op == opSessionsNext && w.s != nil {
			w.wg.Go(func() { w.s.route(ctx, w.h, d, *o) })
		}
	}
}

// handle asks you about one request and answers the helper. Allowing happens in execute (allow), so
// only an approval you gave lets the command run; everything else here denies.
func (w *watcher) handle(ctx context.Context, d rubiplugin.HomeDevice, r request) {
	deny := func(msg string) {
		err := w.h.HomeCall(ctx, d.ID, "claude.decide", answer{ID: r.ID, SessionID: r.SessionID, Digest: r.Digest, Behavior: "deny", Message: msg}, nil)
		if err != nil && ctx.Err() == nil {
			w.h.Logf("%s: denying %s: %v", d.Name, r.ID, err)
		}
	}
	if err := check(r); err != nil {
		w.h.Logf("%s: request %s: %v", d.Name, r.ID, err)
		deny(msgMalformed)
		return
	}
	mandateNote := ""
	if w.s != nil {
		m, why := w.s.st.use(d.ID, r, w.s.now())
		if m != nil {
			err := w.h.HomeCall(ctx, d.ID, "claude.decide", answer{ID: r.ID, SessionID: r.SessionID, Digest: r.Digest, Behavior: "allow"}, nil)
			fields := map[string]any{"mandate": m.ID, "device": d.ID, "session": r.SessionID, "request": r.ID,
				"command": oneLine(r.Command, 300), "directory": r.Cwd, "uses": m.Uses}
			if m.Project {
				fields["project"] = m.Root
			}
			if err != nil {
				fields["error"] = oneLine(err.Error(), 200)
			}
			w.h.Audit(auditMandateAll, fields)
			return
		}
		mandateNote = why
	}
	safe, why := classify(r.Command)
	kind := kindRun
	if safe {
		kind = kindSafe
	}
	preview := map[string]any{"command": r.Command, "directory": r.Cwd, "computer": d.Name, "tool": r.ToolName,
		"session": r.SessionID, "why_this_approval": why}
	if mandateNote != "" {
		preview["mandate"] = mandateNote
	}
	if r.Description != "" {
		preview["claude_says"] = r.Description
	}
	t := ticket{Device: d.ID, DeviceName: d.Name, ID: r.ID, SessionID: r.SessionID, Digest: r.Digest, Cwd: r.Cwd}
	req := rubiplugin.Request{Kind: kind, Summary: "Claude Code: " + oneLine(r.Command, 100), Preview: preview}
	if w.s != nil && kind == kindRun {
		// The third option trusts the whole project; it is offered when Rubi Home says what the project is.
		offer, why := w.s.projectOffer(ctx, w.h, d, r)
		if offer != nil {
			t.Project = offer
			f := offer.forever()
			t.Forever = &f
			preview["project_trust"] = "Option \"" + w.s.trustLabel(*offer) + "\": " + w.s.trustMeaning(*offer, false)
			preview["project_trust_until_revoked"] = "Option \"" + w.s.trustLabel(f) + "\": " + w.s.trustMeaning(f, false)
			req.Options = w.s.runOptions(offer)
		} else {
			preview["project_trust"] = "not offered: " + why
			req.Options = w.s.runOptions(nil)
		}
	}
	req.Payload = t
	out, err := w.h.Submit(ctx, req)
	if err != nil {
		w.h.Logf("%s: asking about %s: %v", d.Name, r.ID, err)
		deny("Rubi couldn't ask you (" + oneLine(err.Error(), 200) + "), so the command was denied.")
		return
	}
	id, _ := out["approval_id"].(string)
	if out["status"] != "awaiting_approval" || id == "" {
		return // no approval needed (you lowered the level): execute already answered
	}
	ev := map[string]any{"approval_id": id, "level": out["level"], "command": oneLine(r.Command, 300), "directory": r.Cwd,
		"computer": d.Name, "expires_at": r.ExpiresAt}
	for _, k := range []string{"approval_url", "buttons", "after_sending_the_link"} {
		if v, ok := out[k]; ok {
			ev[k] = v
		}
	}
	if r.Description != "" {
		ev["claude_says"] = oneLine(r.Description, 300)
	}
	if _, err := w.h.Emit(eventNeeded, ev); err != nil {
		w.h.Logf("%s: telling the agent about %s: %v", d.Name, id, err)
	}
	w.follow(ctx, r, id, deny)
}

// follow waits for your decision while Claude Code still waits for the answer.
func (w *watcher) follow(ctx context.Context, r request, id string, deny func(string)) {
	for ctx.Err() == nil {
		left := time.Until(r.ExpiresAt)
		if left <= 0 {
			return // Claude Code stopped waiting; the helper denied it
		}
		st, err := w.h.WaitApproval(ctx, id, min(left, pollWait))
		if err != nil {
			if ctx.Err() == nil {
				w.h.Logf("approval %s: %v", id, err)
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
				}
			}
			continue
		}
		switch st.State {
		case "pending", "executing":
			continue
		case "executed", "failed": // execute answered the helper (or found it no longer waiting)
		case "denied":
			deny(msgDenied)
		case "cancelled":
			deny(msgCancelled)
		case "expired":
			deny(msgExpired)
		default:
			deny("the approval ended as " + oneLine(st.State, 40) + ", so the command was denied.")
		}
		return
	}
}

// check makes sure the request is what it says: a Bash command whose tool input matches the digest the
// helper will hold the answer to.
func check(r request) error {
	if r.ID == "" || r.ToolName != "Bash" {
		return errors.New("not a Bash request")
	}
	sum := sha256.Sum256([]byte(r.ToolInput))
	if hex.EncodeToString(sum[:]) != strings.ToLower(r.Digest) {
		return errors.New("tool input doesn't match its digest")
	}
	var in struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal([]byte(r.ToolInput), &in); err != nil || in.Command == "" || in.Command != r.Command {
		return errors.New("command doesn't match the tool input")
	}
	return nil
}

// oneLine shortens s to n runes on one line, for summaries.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
