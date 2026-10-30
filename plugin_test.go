package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

// fakeHost stands in for Rubi: Submit and WaitApproval give scripted approval results; HomeCall plays
// the helper.
type fakeHost struct {
	mu        sync.Mutex
	devices   []rubiplugin.HomeDevice
	next      func(ctx context.Context, device string) (*request, error)
	submit    func(r rubiplugin.Request) (map[string]any, error)
	states    []string // WaitApproval answers in turn; the last one repeats
	submits   []rubiplugin.Request
	decided   []decided
	events    []map[string]any
	decideFn  func(device string, a answer) error
	sessions  []session       // claude-sessions.list answers
	listHang  bool            // claude-sessions.list never answers (until ctx ends)
	hangOn    map[string]bool // claude-sessions.list never answers on these computers
	sendExtra map[string]any  // merged into the claude-sessions.send answer (newer Rubi Home fields)
	outs      []outMsg        // claude-sessions.next answers, one per call
	ops       []string        // every op called
	sent      []map[string]any
	audits    []string
	auditLog  []map[string]any
	state     json.RawMessage
	emitToErr error // EmitTo fails (no Bot of that name with a webhook)
}

type decided struct {
	device string
	answer
}

func (f *fakeHost) HomeDevices() ([]rubiplugin.HomeDevice, error) { return f.devices, nil }

func (f *fakeHost) HomeCall(ctx context.Context, device, op string, args, out any) error {
	f.mu.Lock()
	f.ops = append(f.ops, op)
	f.mu.Unlock()
	switch op {
	case "claude.next":
		r, err := f.next(ctx, device)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(map[string]any{"request": r})
		return json.Unmarshal(b, out)
	case "claude.decide":
		a := args.(answer)
		f.mu.Lock()
		f.decided = append(f.decided, decided{device, a})
		fn := f.decideFn
		f.mu.Unlock()
		if fn != nil {
			return fn(device, a)
		}
		return nil
	case "claude-sessions.next": // what a session said, else wait a little like the helper's long poll
		f.mu.Lock()
		if len(f.outs) > 0 {
			o := f.outs[0]
			f.outs = f.outs[1:]
			f.mu.Unlock()
			b, _ := json.Marshal(map[string]any{"out": o})
			return json.Unmarshal(b, out)
		}
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
		return json.Unmarshal([]byte(`{"out":null}`), out)
	case "claude-sessions.list":
		if f.listHang || f.hangOn[device] {
			<-ctx.Done()
			return errors.New("Rubi Home didn't answer")
		}
		f.mu.Lock()
		b, _ := json.Marshal(map[string]any{"sessions": f.sessions})
		f.mu.Unlock()
		return json.Unmarshal(b, out)
	case "claude-sessions.send":
		m := args.(map[string]any)
		f.mu.Lock()
		f.sent = append(f.sent, m)
		f.mu.Unlock()
		f.mu.Lock()
		ans := map[string]any{"queued": true, "id": "msg_1", "waiting": 1}
		for k, v := range f.sendExtra {
			ans[k] = v
		}
		f.mu.Unlock()
		b, _ := json.Marshal(ans)
		return json.Unmarshal(b, out)
	}
	return errors.New("unexpected op " + op)
}

func (f *fakeHost) EmitTo(agent, typ string, data map[string]any) (string, error) {
	f.mu.Lock()
	err := f.emitToErr
	f.mu.Unlock()
	if agent != "" && err != nil {
		return "", err
	}
	data["_agent"] = agent
	return f.Emit(typ, data)
}

func (f *fakeHost) Audit(event string, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audits = append(f.audits, event)
	f.auditLog = append(f.auditLog, fields)
}

func (f *fakeHost) LoadState(v any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.state) == 0 {
		return nil
	}
	return json.Unmarshal(f.state, v)
}

func (f *fakeHost) SaveState(v any) error {
	b, err := json.Marshal(v)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = b
	return err
}

func (f *fakeHost) Submit(_ context.Context, r rubiplugin.Request) (map[string]any, error) {
	f.mu.Lock()
	f.submits = append(f.submits, r)
	f.mu.Unlock()
	if f.submit != nil {
		return f.submit(r)
	}
	return map[string]any{"status": "awaiting_approval", "approval_id": "apr_1", "level": "strong",
		"approval_url": "https://rubi-panel.com/#a=apr_1"}, nil
}

func (f *fakeHost) WaitApproval(_ context.Context, id string, _ time.Duration) (rubiplugin.ApprovalState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return rubiplugin.ApprovalState{ID: id, State: st}, nil
}

func (f *fakeHost) Emit(typ string, data map[string]any) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data["_type"] = typ
	f.events = append(f.events, data)
	return "ev_1", nil
}

func (f *fakeHost) Logf(string, ...any) {}

func newRequest(command string) request {
	in, _ := json.Marshal(map[string]any{"command": command, "description": "List files"})
	sum := sha256.Sum256(in)
	return request{ID: "cc_1", SessionID: "sess-1", ToolName: "Bash", ToolInput: string(in), Digest: hex.EncodeToString(sum[:]),
		Command: command, Description: "List files", Cwd: "/Users/v/project", ExpiresAt: time.Now().Add(time.Minute)}
}

var mac = rubiplugin.HomeDevice{ID: "dev_mac", Name: "Mac"}

func TestApprovedCommandIsAllowedOnlyByExecute(t *testing.T) {
	f := &fakeHost{states: []string{"pending", "executing", "executed"}}
	r := newRequest("rm -rf build")
	newWatcher(f, nil).handle(context.Background(), mac, r)

	if len(f.submits) != 1 {
		t.Fatalf("submits: %v", f.submits)
	}
	s := f.submits[0]
	p := s.Preview.(map[string]any)
	if s.Kind != kindRun || p["command"] != "rm -rf build" || p["directory"] != r.Cwd || p["computer"] != "Mac" ||
		p["session"] != "sess-1" || p["tool"] != "Bash" || !strings.Contains(s.Summary, "rm -rf build") {
		t.Fatalf("submit: %+v", s)
	}
	if len(f.decided) != 0 {
		t.Fatalf("the watcher answered by itself: %v", f.decided)
	}
	if len(f.events) != 1 || f.events[0]["_type"] != eventNeeded || f.events[0]["approval_url"] != "https://rubi-panel.com/#a=apr_1" ||
		f.events[0]["command"] != "rm -rf build" {
		t.Fatalf("events: %v", f.events)
	}

	// Rubi runs execute with the payload it was given: that alone allows, bound to this request.
	payload, _ := json.Marshal(s.Payload)
	if _, err := allow(context.Background(), f, payload); err != nil {
		t.Fatal(err)
	}
	want := decided{"dev_mac", answer{ID: r.ID, SessionID: r.SessionID, Digest: r.Digest, Behavior: "allow"}}
	if len(f.decided) != 1 || f.decided[0] != want {
		t.Fatalf("decided: %+v", f.decided)
	}
}

func TestEndingsDeny(t *testing.T) {
	for state, msg := range map[string]string{"denied": msgDenied, "cancelled": msgCancelled, "expired": msgExpired, "weird": "weird"} {
		f := &fakeHost{states: []string{"pending", state}}
		r := newRequest("curl https://example.com")
		newWatcher(f, nil).handle(context.Background(), mac, r)
		if len(f.decided) != 1 {
			t.Fatalf("%s: decided %v", state, f.decided)
		}
		d := f.decided[0]
		if d.Behavior != "deny" || !strings.Contains(d.Message, msg) || d.ID != r.ID || d.SessionID != r.SessionID ||
			d.Digest != r.Digest || d.device != "dev_mac" {
			t.Fatalf("%s: %+v", state, d)
		}
	}
}

func TestSafeCommandsUseTheQuickAction(t *testing.T) {
	f := &fakeHost{states: []string{"executed"}}
	newWatcher(f, nil).handle(context.Background(), mac, newRequest("git status"))
	if f.submits[0].Kind != kindSafe {
		t.Fatalf("kind %s", f.submits[0].Kind)
	}
}

func TestSubmitFailureDeniesWithTheReason(t *testing.T) {
	f := &fakeHost{submit: func(rubiplugin.Request) (map[string]any, error) {
		return nil, errors.New("hourly limit for approved actions reached")
	}}
	newWatcher(f, nil).handle(context.Background(), mac, newRequest("make test"))
	if len(f.decided) != 1 || f.decided[0].Behavior != "deny" || !strings.Contains(f.decided[0].Message, "hourly limit") {
		t.Fatalf("decided: %+v", f.decided)
	}
}

func TestNoApprovalNeeded(t *testing.T) {
	// At level none Rubi has already called execute (which allowed); the watcher adds nothing.
	f := &fakeHost{submit: func(rubiplugin.Request) (map[string]any, error) { return map[string]any{"allowed": true}, nil }}
	newWatcher(f, nil).handle(context.Background(), mac, newRequest("ls"))
	if len(f.decided) != 0 || len(f.events) != 0 {
		t.Fatalf("decided %v events %v", f.decided, f.events)
	}
}

func TestRequestThatDoesntCheckOutIsDenied(t *testing.T) {
	bad := map[string]func(*request){
		"digest":  func(r *request) { r.Digest = strings.Repeat("0", 64) },
		"command": func(r *request) { r.Command = "ls" },
		"tool":    func(r *request) { r.ToolName = "Write" },
		"not json": func(r *request) {
			r.ToolInput = "x"
			s := sha256.Sum256([]byte("x"))
			r.Digest = hex.EncodeToString(s[:])
		},
		"empty id":     func(r *request) { r.ID = "" },
		"tool swapped": func(r *request) { r.ToolInput = `{"command":"rm -rf /"}` },
	}
	for name, mutate := range bad {
		f := &fakeHost{}
		r := newRequest("cat x")
		mutate(&r)
		newWatcher(f, nil).handle(context.Background(), mac, r)
		if len(f.submits) != 0 {
			t.Errorf("%s: asked about it", name)
		}
		if len(f.decided) != 1 || f.decided[0].Behavior != "deny" || f.decided[0].Message != msgMalformed {
			t.Errorf("%s: decided %+v", name, f.decided)
		}
	}
}

func TestExecuteFailsWhenClaudeStoppedWaiting(t *testing.T) {
	f := &fakeHost{decideFn: func(string, answer) error { return errors.New("unknown or expired request") }}
	payload, _ := json.Marshal(ticket{Device: "dev_mac", ID: "cc_1", SessionID: "s", Digest: "d"})
	if _, err := allow(context.Background(), f, payload); err == nil || !strings.Contains(err.Error(), "no longer waiting") {
		t.Fatalf("err %v", err)
	}
	if _, err := allow(context.Background(), f, json.RawMessage(`{}`)); err == nil {
		t.Fatal("empty payload accepted")
	}
}

func TestExpiredRequestIsLeftToTheHelper(t *testing.T) {
	f := &fakeHost{states: []string{"pending"}}
	r := newRequest("make")
	r.ExpiresAt = time.Now().Add(-time.Second)
	newWatcher(f, nil).handle(context.Background(), mac, r)
	if len(f.decided) != 0 {
		t.Fatalf("decided %v", f.decided)
	}
}

// TestPollsEveryComputerAndStops: each paired computer is polled, its requests handled, and everything
// ends when the plugin stops. A computer that is no longer paired isn't polled again.
func TestPollsEveryComputerAndStops(t *testing.T) {
	gone := rubiplugin.HomeDevice{ID: "dev_old", Name: "Old Mac"}
	var mu sync.Mutex
	served, goneCalls := 0, 0
	f := &fakeHost{devices: []rubiplugin.HomeDevice{mac, gone}, states: []string{"denied"}}
	f.next = func(ctx context.Context, device string) (*request, error) {
		mu.Lock()
		defer mu.Unlock()
		if device == "dev_old" {
			goneCalls++
			return nil, &rubiplugin.Error{Code: rubiplugin.CodeHomeNotPaired, Message: "not paired"}
		}
		if served == 0 {
			served++
			r := newRequest("rm x")
			return &r, nil
		}
		mu.Unlock()
		<-ctx.Done()
		mu.Lock()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	w := newWatcher(f, nil)
	go func() { defer close(done); w.run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.decided)
		f.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the request was never answered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher didn't stop")
	}
	mu.Lock()
	defer mu.Unlock()
	if goneCalls != 1 {
		t.Fatalf("polled an unpaired computer %d times", goneCalls)
	}
	if f.decided[0].device != "dev_mac" || f.decided[0].Message != msgDenied {
		t.Fatalf("decided %+v", f.decided)
	}
}

func TestManifest(t *testing.T) {
	m := manifest()
	if m.ID != "claude-code" || len(m.Egress) != 0 || len(m.Secrets) != 0 || len(m.Home) != 2 || m.Home[0] != "claude" || m.Home[1] != "claude-sessions" || m.Hooks {
		t.Fatalf("permissions: %+v", m)
	}
	run, _ := m.Action(kindRun)
	safe, _ := m.Action(kindSafe)
	if run.DefaultLevel != rubiplugin.Strong || !run.Locked || safe.DefaultLevel != rubiplugin.Tap || safe.Locked {
		t.Fatalf("levels: %+v %+v", run, safe)
	}
	ev, ok := m.Event(eventNeeded)
	if !ok || len(ev.Untrusted) == 0 {
		t.Fatalf("event: %+v", ev)
	}
	// Rubi refuses an event the manifest doesn't declare.
	for _, typ := range []string{eventBound, eventReply, eventAsk, eventMessage} {
		if _, ok := m.Event(typ); !ok {
			t.Errorf("event %s isn't declared in the manifest", typ)
		}
	}
}

// TestTrustOptionIsHonest: the 2-hour trust says builds and tests run the project's own code, and
// makes no promise the command-line check can't keep (no network or writes outside at all).
func TestTrustOptionIsHonest(t *testing.T) {
	m := manifest()
	run, _ := m.Action(kindRun)
	var meaning string
	for _, o := range run.Options {
		if o.Key == optionTrust {
			meaning = o.Meaning
		}
	}
	for _, want := range []string{"builds and tests", "project's own code", "still ask", ".git", "Revoke"} {
		if !strings.Contains(meaning, want) {
			t.Errorf("trust meaning lacks %q: %s", want, meaning)
		}
	}
	if strings.Contains(meaning, "never push, --force, sudo, network") {
		t.Errorf("trust meaning still promises no network at all: %s", meaning)
	}
}
