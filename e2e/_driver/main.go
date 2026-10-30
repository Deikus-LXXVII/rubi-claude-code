// Command e2e drives the Claude Code approvals end to end on one machine, with nothing real involved: a
// throwaway Rubi daemon and Rubi Home helper in temp directories, an in-process relay, a local signed
// catalog with this plugin, and Claude Code played by `rubi-home claude-hook` fed with hook JSON.
//
// It imports rubi/internal/..., so run.sh compiles it into the rubi module with `go build -overlay`
// (nothing is written into that checkout), and runs it inside `unshare -rn` (no network).
//
//	e2e keys <dir>              make the publisher and release keys; print the publisher key (base64 SPKI)
//	e2e run <dir> <rubi> <rubi-home> <plugin>
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Deikus-LXXVII/rubi/internal/home"
	"github.com/Deikus-LXXVII/rubi/internal/panelclient"
	"github.com/Deikus-LXXVII/rubi/internal/paths"
	"github.com/Deikus-LXXVII/rubi/internal/relay/relaytest"
	"github.com/Deikus-LXXVII/rubi/internal/vault"
	"github.com/Deikus-LXXVII/rubi/internal/webauthn"
)

const pw = "e2e claude-code correct horse battery"

func main() {
	var err error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "keys":
		err = keys(os.Args[2])
	case len(os.Args) == 6 && os.Args[1] == "run":
		err = run(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	default:
		err = errors.New("usage: e2e keys <dir> | e2e run <dir> <rubi> <rubi-home> <plugin>")
	}
	if err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func step(format string, a ...any) { fmt.Printf("  ok: "+format+"\n", a...) }

// ---- keys and the signed catalog ----

func keys(dir string) error {
	for _, name := range []string{"publisher", "release"} {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		if err := os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return err
		}
		pub, _ := x509.MarshalPKIXPublicKey(priv.Public())
		if err := os.WriteFile(filepath.Join(dir, name+".pub.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o600); err != nil {
			return err
		}
		if name == "publisher" {
			fmt.Println(base64.StdEncoding.EncodeToString(pub))
		}
	}
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM in " + path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return k.(ed25519.PrivateKey), nil
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// registry serves a signed catalog listing claude-code and its signed release, like the real marketplace.
func registry(dir, plugin string) (string, error) {
	pub, err := loadKey(filepath.Join(dir, "publisher.key"))
	if err != nil {
		return "", err
	}
	rel, err := loadKey(filepath.Join(dir, "release.key"))
	if err != nil {
		return "", err
	}
	manifest, err := exec.Command(plugin, "--manifest").Output()
	if err != nil {
		return "", fmt.Errorf("plugin --manifest: %w", err)
	}
	var m struct {
		Version   string `json:"version"`
		Publisher struct {
			Key string `json:"key"`
		} `json:"publisher"`
	}
	_ = json.Unmarshal(manifest, &m)
	exe, err := os.ReadFile(plugin)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "claude-code", Mode: 0o755, Size: int64(len(exe)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(exe)
	_ = tw.Close()
	_ = gz.Close()
	archive := fmt.Sprintf("claude-code-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	sums := fmt.Sprintf("%s  rubi-plugin.json\n%s  %s\n", hexSum(manifest), hexSum(buf.Bytes()), archive)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	base := "http://" + ln.Addr().String()
	cat, _ := json.Marshal(map[string]any{"schema": 1, "updated_at": time.Now().UTC(), "plugins": []any{map[string]any{
		"id": "claude-code", "name": "Claude Code", "summary": "Approve Claude Code's commands.",
		"publisher": map[string]string{"name": "Rubi-Project", "key": m.Publisher.Key}, "source": base + "/claude-code",
		"versions": []any{map[string]string{"version": m.Version, "sums_sha256": hexSum([]byte(sums))}}}}})
	ver := "/claude-code/" + m.Version + "/"
	files := map[string][]byte{
		"/marketplace/catalog.json": cat, "/marketplace/catalog.json.sig": ed25519.Sign(rel, cat),
		ver + "rubi-plugin.json": manifest, ver + archive: buf.Bytes(),
		ver + "SHA256SUMS": []byte(sums), ver + "SHA256SUMS.sig": ed25519.Sign(pub, []byte(sums)),
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.Replace(r.URL.Path, "/claude-code/latest/", ver, 1)
		if b, ok := files[p]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	return base, nil
}

// ---- the agent (MCP over the daemon's socket) and the panel ----

type agent struct{ ss *mcp.ClientSession }

func (a agent) call(name string, args map[string]any) (map[string]any, error) {
	res, err := a.ss.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if res.IsError {
		var msg []string
		for _, c := range res.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				msg = append(msg, t.Text)
			}
		}
		return nil, fmt.Errorf("%s: tool error: %s", name, strings.Join(msg, " "))
	}
	var out map[string]any
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	return out, nil
}

// softKey is a software passkey (P-256), registered as an approver at pairing. Like a security key asked
// for userVerification "discouraged", it can sign with user presence only (UP=1, UV=0): a tap.
type softKey struct {
	key   *ecdsa.PrivateKey
	count uint32
}

func (k *softKey) approver() vault.Approver {
	spki, _ := x509.MarshalPKIXPublicKey(&k.key.PublicKey)
	return vault.Approver{CredentialID: "e2e-key", PublicKey: spki, Alg: webauthn.AlgES256, Label: "e2e security key"}
}

// sign returns a signer for origin (the panel's) with the given authenticator flags: 0x01 = present only
// (a tap), 0x05 = present and verified (Face ID).
func (k *softKey) sign(origin string, flags byte) func([]byte) webauthn.Assertion {
	b64 := base64.RawURLEncoding
	return func(challenge []byte) webauthn.Assertion {
		k.count++
		u, _ := url.Parse(origin)
		rp := sha256.Sum256([]byte(u.Hostname()))
		auth := binary.BigEndian.AppendUint32(append(rp[:], flags), k.count)
		cd, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": b64.EncodeToString(challenge), "origin": origin})
		h := sha256.Sum256(cd)
		d := sha256.Sum256(append(append([]byte{}, auth...), h[:]...))
		sig, _ := ecdsa.SignASN1(rand.Reader, k.key, d[:])
		return webauthn.Assertion{CredentialID: "e2e-key", ClientDataJSON: b64.EncodeToString(cd),
			AuthenticatorData: b64.EncodeToString(auth), Signature: b64.EncodeToString(sig)}
	}
}

// panelOrigin is the origin of a panel link (https://rubi-panel.com unless the daemon says otherwise).
func panelOrigin(link string) string {
	if i := strings.Index(link, "/#"); i > 0 {
		return link[:i]
	}
	return link
}

func panel(link string) (*panelclient.Client, error) {
	l, err := panelclient.ParseLink(link)
	if err != nil {
		return nil, err
	}
	return panelclient.New(l)
}

// approveChange approves a settings change a panel operation returned.
func approveChange(base *panelclient.Client, res map[string]any) error {
	pc := *base
	pc.Link.Ticket, _ = res["ticket"].(string)
	id, _ := res["approval_id"].(string)
	info, err := pc.ApprovalInfo(id)
	if err != nil {
		return err
	}
	out, err := pc.ApproveWithPassword(id, info.Approval.Options[0].Key, pw)
	if err != nil {
		return err
	}
	if out["state"] != "executed" {
		return fmt.Errorf("change %s: %v", id, out)
	}
	return nil
}

// webhook is the Bot's routine webhook: it keeps the latest agent code and every body.
type webhook struct {
	mu     sync.Mutex
	code   string
	agent  string
	bodies []map[string]any
}

func (h *webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, _ := m["agent_code"].(string); c != "" {
		h.code = c
	}
	if a, _ := m["agent"].(string); a != "" {
		h.agent = a
	}
	h.bodies = append(h.bodies, m)
}

func waitFor(what string, d time.Duration, cond func() (bool, error)) error {
	deadline := time.Now().Add(d)
	for {
		ok, err := cond()
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ---- Claude Code's side ----

type hookResult struct {
	Behavior, Message string
	Took              time.Duration
	Raw               string
}

// hook runs `rubi-home claude-hook` the way Claude Code does for a Bash permission request.
func hook(bin, helperDir, command string) <-chan hookResult {
	out := make(chan hookResult, 1)
	in, _ := json.Marshal(map[string]any{"session_id": "e2e-session", "transcript_path": "/tmp/none.jsonl",
		"cwd": "/Users/e2e/project", "permission_mode": "default", "hook_event_name": "PermissionRequest",
		"tool_name": "Bash", "tool_input": map[string]any{"command": command, "description": "e2e: " + command}})
	go func() {
		start := time.Now()
		cmd := exec.Command(bin, "claude-hook")
		cmd.Env = append(os.Environ(), "RUBI_HOME_DIR="+helperDir)
		cmd.Stdin = bytes.NewReader(in)
		b, err := cmd.Output()
		var v struct {
			HookSpecificOutput struct {
				HookEventName string `json:"hookEventName"`
				Decision      struct {
					Behavior string `json:"behavior"`
					Message  string `json:"message"`
				} `json:"decision"`
			} `json:"hookSpecificOutput"`
		}
		_ = json.Unmarshal(b, &v)
		r := hookResult{Behavior: v.HookSpecificOutput.Decision.Behavior, Message: v.HookSpecificOutput.Decision.Message,
			Took: time.Since(start).Round(100 * time.Millisecond), Raw: strings.TrimSpace(string(b))}
		if err != nil || v.HookSpecificOutput.HookEventName != "PermissionRequest" {
			r.Behavior = "error"
			r.Message = fmt.Sprintf("%v: %s", err, b)
		}
		out <- r
	}()
	return out
}

// hookEvent runs `rubi-home claude-hook` for another hook event (SessionStart, Stop …) and returns what
// it printed.
func hookEvent(bin, helperDir string, in map[string]any) (string, error) {
	b, _ := json.Marshal(in)
	cmd := exec.Command(bin, "claude-hook")
	cmd.Env = append(os.Environ(), "RUBI_HOME_DIR="+helperDir)
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

type waitResult struct {
	Code           int
	Stdout, Stderr string
	Took           time.Duration
}

// waiter runs `rubi-home claude-hook --wait` the way Claude Code runs an asyncRewake Stop hook: in the
// background, with the Stop input on stdin. Exit 2 with the message on stderr wakes the session.
func waiter(bin, helperDir string, in map[string]any) <-chan waitResult {
	out := make(chan waitResult, 1)
	b, _ := json.Marshal(in)
	go func() {
		start := time.Now()
		cmd := exec.Command(bin, "claude-hook", "--wait")
		cmd.Env = append(os.Environ(), "RUBI_HOME_DIR="+helperDir)
		cmd.Stdin = bytes.NewReader(b)
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		out <- waitResult{code, so.String(), se.String(), time.Since(start)}
	}()
	return out
}

func run(dir, rubiBin, homeBin, plugin string) (err error) {
	for _, d := range []string{dir} {
		if !strings.HasPrefix(filepath.Clean(d), os.TempDir()) {
			return fmt.Errorf("refusing: %s is not under %s", d, os.TempDir())
		}
	}
	rubiHome, helperDir := filepath.Join(dir, "rubi-data"), filepath.Join(dir, "helper-data")
	real, _ := os.UserHomeDir()
	if strings.HasPrefix(rubiHome, filepath.Join(real, ".rubi")) {
		return errors.New("refusing the real RUBI_HOME")
	}
	// Every child (rubi, rubi-home run/pair/claude-hook) inherits these, so none of them can
	// fall back to the real home directory's Rubi or Rubi Home state.
	fakeHome := filepath.Join(dir, "home")
	if err := os.MkdirAll(fakeHome, 0o700); err != nil {
		return err
	}
	for k, v := range map[string]string{"HOME": fakeHome, "XDG_CONFIG_HOME": filepath.Join(fakeHome, ".config"),
		"RUBI_HOME": rubiHome, "RUBI_HOME_DIR": helperDir} {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	if c, err := net.DialTimeout("tcp", "1.1.1.1:443", time.Second); err == nil {
		c.Close()
		return errors.New("refusing: this process has network access (run it inside unshare -rn)")
	}
	var procs []*exec.Cmd
	defer func() {
		for _, p := range procs {
			_ = p.Process.Signal(os.Interrupt)
		}
		for _, p := range procs {
			_ = p.Wait()
		}
		for _, log := range []string{"daemon.log", "rubi-home.log", "rubi-home-restarted.log"} {
			b, _ := os.ReadFile(filepath.Join(dir, log))
			if bytes.Contains(b, []byte("DATA RACE")) || bytes.Contains(b, []byte("panic:")) {
				fmt.Printf("%s:\n%s\n", log, b)
				if err == nil {
					err = fmt.Errorf("%s has a panic or data race", log)
				}
			}
		}
	}()
	start := func(name string, env []string, bin string, args ...string) error {
		f, err := os.Create(filepath.Join(dir, name+".log"))
		if err != nil {
			return err
		}
		cmd := exec.Command(bin, args...)
		cmd.Env, cmd.Stdout, cmd.Stderr = append(os.Environ(), env...), f, f
		if err := cmd.Start(); err != nil {
			return err
		}
		procs = append(procs, cmd)
		return nil
	}

	// 1. The relay, the marketplace, the Bot's webhook.
	rl := relaytest.New()
	defer rl.Close()
	reg, err := registry(dir, plugin)
	if err != nil {
		return err
	}
	wh := &webhook{}
	whLn, _ := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(whLn, wh)
	step("relay %s, marketplace %s, webhook %s", rl.URL(), reg, whLn.Addr())

	// 2. Rubi Home, answering Claude Code within 20 s (instead of 280) to keep the timeout case short.
	h, err := home.Open(helperDir)
	if err != nil {
		return err
	}
	if err := h.Update(func(c *home.Config) { c.Relays, c.ClaudeWaitSeconds = []string{rl.URL()}, 20 }); err != nil {
		return err
	}
	if err := start("rubi-home", []string{"RUBI_HOME_DIR=" + helperDir}, homeBin, "run"); err != nil {
		return err
	}
	homeProc := procs[len(procs)-1]
	if err := waitFor("the helper's socket", 10*time.Second, func() (bool, error) {
		_, err := os.Stat(home.ClaudeSocketPath(helperDir))
		return err == nil, nil
	}); err != nil {
		return err
	}
	r := <-hook(homeBin, helperDir, "ls")
	if r.Behavior != "deny" || !strings.Contains(r.Message, "isn't connected") {
		return fmt.Errorf("before Rubi is set up the hook should deny: %+v", r)
	}
	step("before Rubi is set up: deny in %s (%q)", r.Took, r.Message)

	// 3. Rubi.
	if err := os.MkdirAll(rubiHome, 0o700); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(rubiHome, "transport.json"), []byte(`{"transport":"tailscale"}`), 0o600)
	port := "18790"
	if err := start("daemon", []string{"RUBI_HOME=" + rubiHome, "RUBI_DEV=1",
		"RUBI_PUBLIC_URL=http://127.0.0.1:" + port, "RUBI_PANEL_API_PORT=" + port, "RUBI_PANEL_ORIGIN=http://127.0.0.1:18080",
		"RUBI_MARKETPLACE_URL=" + reg + "/marketplace/catalog.json",
		"RUBI_TEST_RELEASE_KEY_FILE=" + filepath.Join(dir, "release.pub.pem")}, rubiBin, "daemon"); err != nil {
		return err
	}
	os.Setenv("RUBI_HOME", rubiHome)
	layout, _ := paths.Default()
	if err := waitFor("the daemon's socket", 10*time.Second, func() (bool, error) {
		_, err := os.Stat(layout.Socket())
		return err == nil, nil
	}); err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", layout.Socket(), 5*time.Second)
	if err != nil {
		return err
	}
	ss, err := mcp.NewClient(&mcp.Implementation{Name: "e2e-bot", Version: "0"}, nil).
		Connect(context.Background(), &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		return err
	}
	defer ss.Close()
	ag := agent{ss}
	st, err := ag.call("rubi_status", nil)
	if err != nil {
		return err
	}
	pc, err := panel(fmt.Sprint(st["link"]))
	if err != nil {
		return err
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	passkey := &softKey{key: ek}
	if _, err := pc.PairWithPassword(pw, passkey.approver()); err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	origin := panelOrigin(fmt.Sprint(st["link"]))
	step("Rubi paired with a password and a software passkey (panel origin %s)", origin)

	settings := func() (*panelclient.Client, error) {
		out, err := ag.call("rubi_link", map[string]any{"purpose": "settings"})
		if err != nil {
			return nil, err
		}
		return panel(fmt.Sprint(out["url"]))
	}
	sc, err := settings()
	if err != nil {
		return err
	}
	var res map[string]any
	if err := sc.Call("webhook.set", map[string]any{"url": "http://" + whLn.Addr().String(), "key": "crsr_e2e"}, &res); err != nil {
		return fmt.Errorf("webhook.set: %w", err)
	}
	if err := approveChange(sc, res); err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	step("Bot webhook set")

	out, err := ag.call("rubi_plugin_install", map[string]any{"plugin": "claude-code"})
	if err != nil {
		return err
	}
	if out["status"] != "awaiting_approval" {
		return fmt.Errorf("install: %v", out)
	}
	ipc, err := panel(fmt.Sprint(out["approval_url"]))
	if err != nil {
		return err
	}
	info, err := ipc.ApprovalInfo(fmt.Sprint(out["approval_id"]))
	if err != nil {
		return err
	}
	preview, _ := json.Marshal(info.Approval)
	if !strings.Contains(string(preview), "Claude Code's permission requests") || !strings.Contains(string(preview), "listing the Claude Code sessions") {
		return fmt.Errorf("the install screen doesn't say what the plugin may do: %s", preview)
	}
	if res, err := ipc.ApproveWithPassword(fmt.Sprint(out["approval_id"]), info.Approval.Options[0].Key, pw); err != nil || res["state"] != "executed" {
		return fmt.Errorf("install: %v %v", res, err)
	}
	step("claude-code installed from the signed local catalog (install screen names the claude and claude-sessions capabilities)")

	pairOut, err := exec.Command(homeBin, "pair").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rubi-home pair: %v: %s", err, pairOut)
	}
	lines := strings.Fields(strings.TrimSpace(string(pairOut)))
	code := lines[len(lines)-1]
	if sc, err = settings(); err != nil {
		return err
	}
	if err := sc.Call("device.pair", map[string]any{"code": code}, &res); err != nil {
		return fmt.Errorf("device.pair: %w", err)
	}
	if err := approveChange(sc, res); err != nil {
		return fmt.Errorf("device.pair: %w", err)
	}
	step("Rubi Home paired")

	// The approval link reaches the Bot as an event; it reads events with the code from its webhook.
	approvalFor := func(command string) (id, url string, err error) {
		err = waitFor("the approval_needed event for "+command, 30*time.Second, func() (bool, error) {
			wh.mu.Lock()
			code, name := wh.code, wh.agent
			wh.mu.Unlock()
			if name == "" {
				name = "Main" // webhook.set (the single-webhook panel setting) manages the agent named "Main"
			}
			if code == "" {
				_, err := ag.call("rubi_verify", map[string]any{"agent": name})
				return false, err
			}
			evs, err := ag.call("rubi_events", map[string]any{"agent": name, "code": code})
			if err != nil {
				return false, err
			}
			if evs["needs_code"] == true {
				wh.mu.Lock()
				wh.code = ""
				wh.mu.Unlock()
				return false, nil
			}
			list, _ := evs["events"].([]any)
			for _, e := range list {
				m, _ := e.(map[string]any)
				d, _ := m["data"].(map[string]any)
				if strings.HasSuffix(fmt.Sprint(m["type"]), "approval_needed") && d["command"] == command {
					id, url = fmt.Sprint(d["approval_id"]), fmt.Sprint(d["approval_url"])
					return true, nil
				}
			}
			return false, nil
		})
		return id, url, err
	}
	// Ask, retrying while the plugin hasn't started polling the helper yet.
	ask := func(command string) (<-chan hookResult, error) {
		for i := 0; i < 60; i++ {
			ch := hook(homeBin, helperDir, command)
			select {
			case r := <-ch:
				if r.Behavior == "deny" && strings.Contains(r.Message, "isn't connected") {
					time.Sleep(500 * time.Millisecond)
					continue
				}
				return nil, fmt.Errorf("answered before anyone decided: %+v", r)
			case <-time.After(3 * time.Second):
				return ch, nil
			}
		}
		return nil, errors.New("the plugin never started polling Rubi Home")
	}

	var results []string
	report := func(name string, r hookResult) {
		results = append(results, fmt.Sprintf("%-8s -> %s in %s: %s", name, r.Behavior, r.Took, r.Raw))
	}

	// Case 1: approve -> allow.
	ch, err := ask("rm -rf build")
	if err != nil {
		return err
	}
	id, url, err := approvalFor("rm -rf build")
	if err != nil {
		return err
	}
	// No Bot follows claude-code here, so Rubi itself tells the administrator, with a fresh link, and the
	// request waits in the panel's list (Rubi with approval.list; an older one skips this).
	var list map[string]any
	if sc, err = settings(); err != nil {
		return err
	}
	if err := sc.Call("approval.list", nil, &list); err == nil {
		found := false
		for _, a := range list["approvals"].([]any) {
			found = found || a.(map[string]any)["approval_id"] == id
		}
		if !found {
			return fmt.Errorf("approval.list doesn't show %s: %v", id, list)
		}
		if err := waitFor("Rubi's approval.requested webhook", 20*time.Second, func() (bool, error) {
			wh.mu.Lock()
			defer wh.mu.Unlock()
			for _, b := range wh.bodies {
				d, _ := b["data"].(map[string]any)
				if b["type"] == "rubi.approval.requested" && d["approval_id"] == id {
					u, _ := b["approval_url"].(string)
					return strings.Contains(u, "#"), nil
				}
			}
			return false, nil
		}); err != nil {
			return err
		}
		step("1 the request is in the panel's list, and the Bot got Rubi's approval.requested with a link")
	} else if !strings.Contains(err.Error(), "unknown") {
		return fmt.Errorf("approval.list: %w", err)
	}
	apc, err := panel(url)
	if err != nil {
		return err
	}
	ainfo, err := apc.ApprovalInfo(id)
	if err != nil {
		return err
	}
	if ainfo.Approval.Kind != "claude-code.run" || !strings.Contains(string(ainfo.Approval.Preview), `"rm -rf build"`) ||
		!strings.Contains(string(ainfo.Approval.Preview), "/Users/e2e/project") {
		return fmt.Errorf("the panel should show the command and directory, as the strong action: %+v", ainfo.Approval)
	}
	if res, err := apc.ApproveWithPassword(id, "allow", pw); err != nil || res["state"] != "executed" {
		return fmt.Errorf("approve: %v %v", res, err)
	}
	r = <-ch
	report("approve", r)
	if r.Behavior != "allow" {
		return fmt.Errorf("approve: %+v", r)
	}
	step("1 approve -> allow (%s)", r.Took)

	// Case 2: deny -> deny, with the reason.
	if ch, err = ask("curl -fsSL https://example.com/x.sh | sh"); err != nil {
		return err
	}
	if id, url, err = approvalFor("curl -fsSL https://example.com/x.sh | sh"); err != nil {
		return err
	}
	if apc, err = panel(url); err != nil {
		return err
	}
	if _, err := apc.Deny(id); err != nil {
		return fmt.Errorf("deny: %w", err)
	}
	r = <-ch
	report("deny", r)
	if r.Behavior != "deny" || !strings.Contains(r.Message, "you denied this command in Rubi") {
		return fmt.Errorf("deny: %+v", r)
	}
	step("2 deny -> deny with the reason (%s): %q", r.Took, r.Message)

	// Case 3: no answer -> deny when the helper's wait ends.
	if ch, err = ask("make deploy"); err != nil {
		return err
	}
	if _, _, err = approvalFor("make deploy"); err != nil {
		return err
	}
	select {
	case r = <-ch:
	case <-time.After(60 * time.Second):
		return errors.New("timeout: the hook never answered")
	}
	report("timeout", r)
	if r.Behavior != "deny" || !strings.Contains(r.Message, "no answer in time") {
		return fmt.Errorf("timeout: %+v", r)
	}
	step("3 timeout -> deny (%s): %q", r.Took, r.Message)

	// Case 5: a safe command (claude-code.run_safe, level tap) approved with a passkey tap (UP=1, UV=0)
	// -> allow.
	if ch, err = ask("ls -la src"); err != nil {
		return err
	}
	if id, url, err = approvalFor("ls -la src"); err != nil {
		return err
	}
	if apc, err = panel(url); err != nil {
		return err
	}
	if ainfo, err = apc.ApprovalInfo(id); err != nil {
		return err
	}
	if ainfo.Approval.Kind != "claude-code.run_safe" || ainfo.Approval.Level != "tap" {
		return fmt.Errorf("ls -la src should be a tap-level run_safe approval: %+v", ainfo.Approval)
	}
	if res, err := apc.ApproveWithPasskey(id, "allow", passkey.sign(origin, 0x01)); err != nil || res["state"] != "executed" {
		return fmt.Errorf("tap on a safe command: %v %v", res, err)
	}
	r = <-ch
	report("tap", r)
	if r.Behavior != "allow" {
		return fmt.Errorf("tap on a safe command: %+v", r)
	}
	step("5 quick-tap on a safe command -> allow (%s)", r.Took)

	// Case 6: the same tap on a command that isn't safe (claude-code.run, strong) is refused; the request
	// stays open, and nothing is allowed. The user then denies it.
	if ch, err = ask("rm -rf dist"); err != nil {
		return err
	}
	if id, url, err = approvalFor("rm -rf dist"); err != nil {
		return err
	}
	if apc, err = panel(url); err != nil {
		return err
	}
	if ainfo, err = apc.ApprovalInfo(id); err != nil {
		return err
	}
	if ainfo.Approval.Kind != "claude-code.run" || ainfo.Approval.Level != "strong" {
		return fmt.Errorf("rm -rf dist should be a strong run approval: %+v", ainfo.Approval)
	}
	res6, err6 := apc.ApproveWithPasskey(id, "allow", passkey.sign(origin, 0x01))
	if err6 == nil || !strings.Contains(err6.Error(), "verification") {
		return fmt.Errorf("a tap approved a strong command: %v %v", res6, err6)
	}
	select {
	case r = <-ch:
		return fmt.Errorf("the hook answered after a refused tap: %+v", r)
	case <-time.After(2 * time.Second):
	}
	if ainfo, err = apc.ApprovalInfo(id); err != nil || ainfo.Approval.State != "pending" {
		return fmt.Errorf("after a refused tap the request should still be pending: %+v %v", ainfo.Approval, err)
	}
	if _, err := apc.Deny(id); err != nil {
		return fmt.Errorf("deny after tap: %w", err)
	}
	r = <-ch
	report("tap!run", r)
	if r.Behavior != "deny" {
		return fmt.Errorf("tap on a strong command, then deny: %+v", r)
	}
	step("6 quick-tap on a non-safe command -> rejected (%q), request stayed pending, then deny", err6.Error())

	// The Bot reads its events with the code from its webhook.
	evWait := 30 * time.Second
	eventFor := func(what, typ string, match func(d map[string]any) bool) (map[string]any, error) {
		var found map[string]any
		err := waitFor(what, evWait, func() (bool, error) {
			wh.mu.Lock()
			code, name := wh.code, wh.agent
			wh.mu.Unlock()
			if name == "" {
				name = "Main"
			}
			if code == "" {
				_, err := ag.call("rubi_verify", map[string]any{"agent": name})
				return false, err
			}
			evs, err := ag.call("rubi_events", map[string]any{"agent": name, "code": code})
			if err != nil {
				return false, err
			}
			if evs["needs_code"] == true {
				wh.mu.Lock()
				wh.code = ""
				wh.mu.Unlock()
				return false, nil
			}
			list, _ := evs["events"].([]any)
			for _, e := range list {
				m, _ := e.(map[string]any)
				d, _ := m["data"].(map[string]any)
				if strings.HasSuffix(fmt.Sprint(m["type"]), typ) && match(d) {
					found = d
					return true, nil
				}
			}
			return false, nil
		})
		return found, err
	}

	// Case 7: a Bot finds its project's session (the desktop app's store), binds to it with one strong
	// approval, sends it a message, the Stop hook hands the message to Claude, and Claude's answer (and
	// its rubi-ask) come back to that Bot.
	proj := filepath.Join(dir, "proj")
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o700); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(proj, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600)
	_ = os.WriteFile(filepath.Join(proj, ".git", "config"), []byte("[remote \"origin\"]\n\turl = git@github.com:e2e/proj.git\n"), 0o600)
	store := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "Claude", "claude-code-sessions", "acct", "org")
	if err := os.MkdirAll(store, 0o700); err != nil {
		return err
	}
	desk, _ := json.Marshal(map[string]any{"sessionId": "local_e2e", "cliSessionId": "cli-e2e", "cwd": proj, "originCwd": proj,
		"title": "E2E main session", "permissionMode": "default", "createdAt": time.Now().UnixMilli(), "lastActivityAt": time.Now().UnixMilli()})
	if err := os.WriteFile(filepath.Join(store, "local_e2e.json"), desk, 0o600); err != nil {
		return err
	}
	sl, err := ag.call("claude_code_sessions", map[string]any{"repo": "e2e/proj"})
	if err != nil {
		return err
	}
	ss7, _ := sl["sessions"].([]any)
	if len(ss7) != 1 {
		return fmt.Errorf("claude_code_sessions: %v", sl)
	}
	s7 := ss7[0].(map[string]any)
	if s7["session_id"] != "cli-e2e" || s7["repo_key"] != "github.com/e2e/proj" || s7["role"] != "main" || s7["source"] != "desktop" {
		return fmt.Errorf("the desktop session: %v", s7)
	}
	step("7 claude_code_sessions finds the desktop app's session (%s, %s)", s7["repo_key"], s7["role"])
	sister := "Main"
	// A name the Bot types proves nothing: binding needs the agent code from the Bot's own webhook, and
	// Rubi passes the plugin the registered name.
	if _, err := ag.call("claude_code_bind", map[string]any{"sister": sister, "rubi_agent": sister, "rubi_verified_agent": sister, "session_id": "local_e2e"}); err == nil {
		return errors.New("a bind without a proof (and a forged rubi_verified_agent) went through")
	}
	if _, err := ag.call("claude_code_bind", map[string]any{"rubi_agent": sister, "rubi_agent_code": "wrong", "session_id": "local_e2e"}); err == nil {
		return errors.New("a bind with a wrong agent code went through")
	}
	var agentCode string
	if err := waitFor("Main's agent code", 15*time.Second, func() (bool, error) {
		wh.mu.Lock()
		agentCode = wh.code
		wh.mu.Unlock()
		if agentCode == "" {
			_, err := ag.call("rubi_verify", map[string]any{"agent": sister})
			return false, err
		}
		return true, nil
	}); err != nil {
		return err
	}
	bo, err := ag.call("claude_code_bind", map[string]any{"rubi_agent": "main", "rubi_agent_code": agentCode, "session_id": "local_e2e"})
	if err != nil {
		return err
	}
	if bo["status"] != "awaiting_approval" {
		return fmt.Errorf("bind should ask: %v", bo)
	}
	bpc, err := panel(fmt.Sprint(bo["approval_url"]))
	if err != nil {
		return err
	}
	binfo, err := bpc.ApprovalInfo(fmt.Sprint(bo["approval_id"]))
	if err != nil {
		return err
	}
	if binfo.Approval.Kind != "claude-code.bind" || binfo.Approval.Level != "strong" || !strings.Contains(string(binfo.Approval.Preview), `"bot":"Main"`) {
		return fmt.Errorf("bind should be a strong approval for the registered name Main: %+v", binfo.Approval)
	}
	if _, err := bpc.ApproveWithPasskey(fmt.Sprint(bo["approval_id"]), "bind", passkey.sign(origin, 0x01)); err == nil {
		return errors.New("a tap approved a binding")
	}
	if res, err := bpc.ApproveWithPassword(fmt.Sprint(bo["approval_id"]), "bind", pw); err != nil || res["state"] != "executed" {
		return fmt.Errorf("bind: %v %v", res, err)
	} else if raw, _ := json.Marshal(res); strings.Contains(string(raw), "bc_") {
		return errors.New("the bind approval's result carries the bind code (it must only reach the Bot in claude_bound)")
	}
	bound, err := eventFor("the claude_bound event", "claude_bound", func(d map[string]any) bool { return d["session_id"] == "cli-e2e" })
	if err != nil {
		return err
	}
	bindCode := fmt.Sprint(bound["bind_code"])
	step("7 bound for the verified Bot (no proof or a wrong code refused) with one strong approval (a tap is refused); the Bot got claude_bound")
	if _, err := ag.call("claude_code_send", map[string]any{"sister": sister, "bind_code": "bc_wrong", "text": "x"}); err == nil {
		return errors.New("send with a wrong bind code went through")
	}
	if _, err := ag.call("claude_code_send", map[string]any{"sister": sister, "bind_code": bindCode, "text": "e2e: audit found 2 issues in x.go"}); err != nil {
		return err
	}
	stop := map[string]any{"session_id": "cli-e2e", "transcript_path": filepath.Join(dir, "none.jsonl"), "cwd": proj,
		"permission_mode": "default", "hook_event_name": "Stop", "stop_hook_active": false}
	o1, err := hookEvent(homeBin, helperDir, stop)
	if err != nil {
		return fmt.Errorf("Stop hook: %w", err)
	}
	var blk struct{ Decision, Reason string }
	if json.Unmarshal([]byte(o1), &blk); blk.Decision != "block" || !strings.Contains(blk.Reason, "e2e: audit found 2 issues") {
		return fmt.Errorf("Stop should block with the message: %q", o1)
	}
	step("7 Stop hook hands the message to Claude (decision block)")
	stop["stop_hook_active"] = true
	stop["last_assistant_message"] = "Fixed both in x.go.\n```rubi-ask kind=research\nIs there a newer x release?\n```"
	o2, err := hookEvent(homeBin, helperDir, stop)
	if err != nil || strings.Contains(o2, "block") {
		return fmt.Errorf("second Stop should let Claude stop: %q %v", o2, err)
	}
	rep, err := eventFor("the claude_reply event", "claude_reply", func(d map[string]any) bool { return strings.Contains(fmt.Sprint(d["text"]), "Fixed both") })
	if err != nil {
		return err
	}
	ask7, err := eventFor("the claude_ask event", "claude_ask", func(d map[string]any) bool { return d["text"] == "Is there a newer x release?" })
	if err != nil {
		return err
	}
	if rep["session_id"] != "cli-e2e" || ask7["kind"] != "research" {
		return fmt.Errorf("reply %v, ask %v", rep, ask7)
	}
	step("7 Claude's answer came back as claude_reply, its rubi-ask as claude_ask")
	// The same session switched to bypassPermissions: its session hooks still bring messages in and the
	// answer out (only PermissionRequest stops firing in that mode).
	if _, err := ag.call("claude_code_send", map[string]any{"sister": sister, "bind_code": bindCode, "text": "e2e: bypass check"}); err != nil {
		return err
	}
	ups := map[string]any{"session_id": "cli-e2e", "transcript_path": filepath.Join(dir, "none.jsonl"), "cwd": proj,
		"permission_mode": "bypassPermissions", "hook_event_name": "UserPromptSubmit", "prompt": "carry on"}
	o3, err := hookEvent(homeBin, helperDir, ups)
	if err != nil || !strings.Contains(o3, "additionalContext") || !strings.Contains(o3, "e2e: bypass check") {
		return fmt.Errorf("UserPromptSubmit in a bypassPermissions session: %q %v", o3, err)
	}
	stop["permission_mode"], stop["stop_hook_active"] = "bypassPermissions", false
	stop["last_assistant_message"] = "bypass ok"
	if o4, err := hookEvent(homeBin, helperDir, stop); err != nil || strings.Contains(o4, "block") {
		return fmt.Errorf("Stop in a bypassPermissions session: %q %v", o4, err)
	}
	if _, err := eventFor("the claude_reply from the bypass session", "claude_reply", func(d map[string]any) bool { return d["text"] == "bypass ok" }); err != nil {
		return err
	}
	step("7 in bypassPermissions too, UserPromptSubmit brings the message in and Stop sends the answer back")

	// Case 7b: the session is idle (its last Stop is played) and a waiter hook is attached, as Claude
	// Code's background Stop hook would be. A message wakes it within seconds, the Bot is told it was
	// delivered, and the answer at the next Stop comes back with "answered".
	stop["permission_mode"], stop["stop_hook_active"] = "default", false
	delete(stop, "last_assistant_message")
	wch := waiter(homeBin, helperDir, stop)
	time.Sleep(1500 * time.Millisecond) // let the waiter connect
	sres, err := ag.call("claude_code_send", map[string]any{"sister": sister, "bind_code": bindCode, "text": "e2e: wake up, audit x.go"})
	if err != nil {
		return err
	}
	if sres["waiter"] != true || sres["session_state"] != "idle" || !strings.Contains(fmt.Sprint(sres["delivery"]), "within seconds") {
		return fmt.Errorf("send to an idle session with a waiter: %v", sres)
	}
	wakeID := fmt.Sprint(sres["message_id"])
	select {
	case w := <-wch:
		if w.Code != 2 || !strings.Contains(w.Stderr, "e2e: wake up, audit x.go") || strings.TrimSpace(w.Stdout) != "" {
			return fmt.Errorf("the waiter should exit 2 with the message on stderr: %+v", w)
		}
		step("7b an idle session's waiter woke in %s: exit 2, the message on stderr", w.Took.Round(100*time.Millisecond))
	case <-time.After(10 * time.Second):
		return errors.New("the waiter wasn't woken by a message to an idle session")
	}
	stateOf := func(id, state string) error {
		_, err := eventFor("claude_message "+state+" for "+id, "claude_message", func(d map[string]any) bool { return d["id"] == id && d["state"] == state })
		return err
	}
	for _, st := range []string{"delivered"} {
		if err := stateOf(wakeID, st); err != nil {
			return err
		}
	}
	stat, err := ag.call("claude_code_status", map[string]any{"sister": sister, "bind_code": bindCode})
	if err != nil || stat["session_id"] != "cli-e2e" || stat["eta"] == nil || stat["waiter"] == nil {
		return fmt.Errorf("claude_code_status: %v %v", stat, err)
	}
	if _, err := ag.call("claude_code_status", map[string]any{"sister": sister, "bind_code": "bc_wrong"}); err == nil {
		return errors.New("claude_code_status with a wrong bind code went through")
	}
	stop["last_assistant_message"] = "Woken: audit of x.go done, all clean."
	if o, err := hookEvent(homeBin, helperDir, stop); err != nil || strings.Contains(o, "block") {
		return fmt.Errorf("Stop after the wake: %q %v", o, err)
	}
	if _, err := eventFor("the claude_reply to the woken session", "claude_reply", func(d map[string]any) bool { return strings.Contains(fmt.Sprint(d["text"]), "Woken: audit") }); err != nil {
		return err
	}
	if err := stateOf(wakeID, "answered"); err != nil {
		return err
	}
	step("7b the Bot got claude_message delivered and answered, and the reply; claude_code_status works")

	// Case 7c: a message queued for a session with no waiter survives a restart of Rubi Home, and the next
	// prompt delivers it.
	delete(stop, "last_assistant_message")
	sres, err = ag.call("claude_code_send", map[string]any{"sister": sister, "bind_code": bindCode, "text": "e2e: survive the restart"})
	if err != nil {
		return err
	}
	if sres["waiter"] != false {
		return fmt.Errorf("no waiter is attached, yet: %v", sres)
	}
	keepID := fmt.Sprint(sres["message_id"])
	_ = homeProc.Process.Signal(os.Interrupt)
	_ = homeProc.Wait()
	procs = slices.DeleteFunc(procs, func(c *exec.Cmd) bool { return c == homeProc })
	if fi, err := os.Stat(filepath.Join(helperDir, "claude-queue.json")); err != nil || fi.Mode().Perm() != 0o600 {
		return fmt.Errorf("the queue wasn't saved on stop: %v %v", fi, err)
	}
	if err := start("rubi-home-restarted", []string{"RUBI_HOME_DIR=" + helperDir}, homeBin, "run"); err != nil {
		return err
	}
	ups = map[string]any{"session_id": "cli-e2e", "transcript_path": filepath.Join(dir, "none.jsonl"), "cwd": proj,
		"permission_mode": "default", "hook_event_name": "UserPromptSubmit", "prompt": "back again"}
	if err := waitFor("the queued message after the restart", 20*time.Second, func() (bool, error) {
		o, err := hookEvent(homeBin, helperDir, ups)
		return err == nil && strings.Contains(o, "e2e: survive the restart"), nil
	}); err != nil {
		return err
	}
	// The plugin's poll of the restarted helper recovers with its own backoff: allow for it.
	evWait = 120 * time.Second
	restartAt := time.Now()
	stop["last_assistant_message"] = "Restart survived."
	if o, err := hookEvent(homeBin, helperDir, stop); err != nil || strings.Contains(o, "block") {
		return fmt.Errorf("Stop after the restart: %q %v", o, err)
	}
	if _, err := eventFor("the claude_reply after the restart", "claude_reply", func(d map[string]any) bool { return d["text"] == "Restart survived." }); err != nil {
		return err
	}
	for _, st := range []string{"delivered", "answered"} {
		if err := stateOf(keepID, st); err != nil {
			return err
		}
	}
	evWait = 30 * time.Second
	fmt.Printf("  (the Bot heard back %s after the stop)\n", time.Since(restartAt).Round(time.Second))
	step("7c a message queued before a Rubi Home restart was delivered at the next prompt, answered, and the Bot told")

	// Case 8: "trust this session for 2 hours": the next plain commands are allowed without asking;
	// a push still asks.
	if ch, err = ask("go test ./..."); err != nil {
		return err
	}
	if id, url, err = approvalFor("go test ./..."); err != nil {
		return err
	}
	if apc, err = panel(url); err != nil {
		return err
	}
	if res, err := apc.ApproveWithPassword(id, "trust_2h", pw); err != nil || res["state"] != "executed" {
		return fmt.Errorf("trust: %v %v", res, err)
	}
	if r = <-ch; r.Behavior != "allow" {
		return fmt.Errorf("trust: %+v", r)
	}
	select {
	case r = <-hook(homeBin, helperDir, "go vet ./... && go test -race ./internal/..."):
	case <-time.After(20 * time.Second):
		return errors.New("a command under the trust wasn't allowed by itself")
	}
	report("mandate", r)
	if r.Behavior != "allow" {
		return fmt.Errorf("mandate: %+v", r)
	}
	step("8 trusted for 2 hours, then go vet && go test allowed without asking (%s)", r.Took)
	if ch, err = ask("git status && git push origin main"); err != nil {
		return fmt.Errorf("push under a trust: %w", err)
	}
	if id, url, err = approvalFor("git status && git push origin main"); err != nil {
		return err
	}
	if apc, err = panel(url); err != nil {
		return err
	}
	if ainfo, err = apc.ApprovalInfo(id); err != nil || !strings.Contains(string(ainfo.Approval.Preview), "push") {
		return fmt.Errorf("push approval: %+v %v", ainfo.Approval, err)
	}
	if _, err := apc.Deny(id); err != nil {
		return err
	}
	if r = <-ch; r.Behavior != "deny" {
		return fmt.Errorf("push under a trust: %+v", r)
	}
	report("push", r)
	step("8 git push under the trust still asked, and was denied")
	mo, err := ag.call("claude_code_mandates", map[string]any{"revoke": "all"})
	if err != nil || fmt.Sprint(mo["revoked"]) != "1" {
		return fmt.Errorf("revoke: %v %v", mo, err)
	}
	if ch, err = ask("go vet ./..."); err != nil {
		return fmt.Errorf("after revoking: %w", err)
	}
	if id, url, err = approvalFor("go vet ./..."); err != nil {
		return err
	}
	if apc, err = panel(url); err != nil {
		return err
	}
	if _, err := apc.Deny(id); err != nil {
		return err
	}
	<-ch
	step("8 revoked: the next command asks again")

	// Case 4: Rubi locked -> deny.
	if _, err := ag.call("rubi_lock", nil); err != nil {
		return err
	}
	ch = hook(homeBin, helperDir, "git push --force")
	select {
	case r = <-ch:
	case <-time.After(90 * time.Second):
		return errors.New("locked: the hook never answered")
	}
	report("locked", r)
	if r.Behavior != "deny" {
		return fmt.Errorf("locked: %+v", r)
	}
	step("4 locked -> deny (%s): %q", r.Took, r.Message)
	r = <-hook(homeBin, helperDir, "git push --force")
	report("locked+", r)
	if r.Behavior != "deny" || !strings.Contains(r.Message, "isn't connected") {
		return fmt.Errorf("locked, later: %+v", r)
	}
	step("4b still locked -> deny at once (%s)", r.Took)

	fmt.Println("\nHook outputs:")
	for _, l := range results {
		fmt.Println("  " + l)
	}
	fmt.Println("E2E PASS")
	return nil
}
