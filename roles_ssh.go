package main

// SSH targets (docs/design/agent-roles.md section 9, and agent-runner.md "SSH relay (R11)"). Rubi Home holds the
// target registry, the private keys and the pinned host keys, and does the network work; the VM never sees a key or
// a host. This plugin is the user's side of it: the panel page that lists, adds and removes targets, the strong
// approval `claude-code.ssh_target` that carries the host key fingerprint the user confirmed, the role grants
// (tier 1 for a registered target), the ssh.ask questions of targets registered with ask_each_time, and the plugin
// side of the audit. A Bot can't register a target: registration is panel-only. It may grant a restricted one (tier 1); granting one that allows any command is tier 2.

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

// Home operations (capability claude-agent).
const (
	opSSHScan     = "claude-agent.ssh.scan"
	opSSHRegister = "claude-agent.ssh.register"
	opSSHList     = "claude-agent.ssh.list"
	opSSHRemove   = "claude-agent.ssh.remove"
	opSSHAudit    = "claude-agent.ssh.audit"
)

const (
	kindSSHTarget = "claude-code.ssh_target" // registering a target (strong, locked)

	pageSSH      = "ssh"
	pageSSHAudit = "ssh_audit"

	auditSSHRegistered = "ssh.target_registered"
	auditSSHRemoved    = "ssh.target_removed"
	auditSSHStream     = "ssh.stream"
	auditSSHCopy       = "ssh.audit_copied"

	maxSSHDrafts   = 8
	maxAllowedCmds = 8
	maxAllowedLen  = 200
	sshDraftLife   = time.Hour
	sshAuditEvery  = 5 * time.Minute
	sshAuditLimit  = 50
	maxSSHItems    = 100
	maxSSHAskCmd   = 1000 // an ssh.ask command longer than this is refused, never cut
)

var (
	sshNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	sshUserRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	sshFPRE   = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

type sshRoleRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Project string `json:"project"`
}

// sshTarget is one row of ssh.list.
type sshTarget struct {
	Name            string       `json:"name"`
	Host            string       `json:"host"`
	Port            int          `json:"port"`
	User            string       `json:"user"`
	Fingerprint     string       `json:"fingerprint"`
	KeyType         string       `json:"key_type"`
	AllowedCommands []string     `json:"allowed_commands"`
	AskEachTime     bool         `json:"ask_each_time"`
	CreatedAt       string       `json:"created_at"`
	HostKeyChanged  bool         `json:"host_key_changed"`
	Roles           []sshRoleRef `json:"roles"`
}

// ---- the registry as the plugin last saw it ----

// registeredSSH says which targets of a computer are registered (the tier engine's Registered).
func (s *sisters) registeredSSH(device string) map[string]bool {
	if s.rc.ssh != nil {
		return s.rc.ssh(device)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sshNames[device]
}

func (s *sisters) setSSHNames(device string, targets []sshTarget) {
	names := map[string]bool{}
	open := map[string]sshTarget{}
	for _, t := range targets {
		names[t.Name] = true
		if t.unrestricted() {
			open[t.Name] = t
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sshNames == nil {
		s.sshNames = map[string]map[string]bool{}
	}
	if s.sshOpen == nil {
		s.sshOpen = map[string]map[string]sshTarget{}
	}
	s.sshNames[device] = names
	s.sshOpen[device] = open
}

// openSSH says which registered targets of a computer let a role run any command (the tier engine's Unrestricted).
func (s *sisters) openSSH(device string) map[string]sshTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sshOpen[device]
}

// unrestricted: the target has no allowed-commands list that limits it and doesn't ask for each command. A pattern
// that is only * or that ends in ** passes any command (or any options), so it limits nothing.
func (t sshTarget) unrestricted() bool {
	if t.AskEachTime {
		return false
	}
	if len(t.AllowedCommands) == 0 {
		return true
	}
	for _, c := range t.AllowedCommands {
		c = strings.TrimSpace(c)
		if c == "*" || strings.HasSuffix(c, "**") {
			return true
		}
	}
	return false
}

// listSSH reads the registry of a computer and remembers the names. A failure forgets them: with no registry an SSH
// grant is not registered, so it needs the user.
func (s *sisters) listSSH(ctx context.Context, h sisterHost, device string) ([]sshTarget, error) {
	var out struct {
		Targets []sshTarget `json:"targets"`
	}
	lctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(lctx, device, opSSHList, map[string]any{}, &out); err != nil {
		s.setSSHNames(device, nil)
		if isUnknownOp(err) {
			return nil, errors.New("this computer's Rubi Home doesn't do SSH targets yet; the user updates it")
		}
		return nil, fmt.Errorf("couldn't list the SSH targets: %s", oneLine(err.Error(), 160))
	}
	s.setSSHNames(device, out.Targets)
	return out.Targets, nil
}

// refreshSSH is listSSH before a decision that depends on which targets exist (a no-op when a test fixed the registry).
func (s *sisters) refreshSSH(ctx context.Context, h sisterHost, device string) error {
	if s.rc.ssh != nil {
		return nil
	}
	_, err := s.listSSH(ctx, h, device)
	return err
}

// ---- drafts of a target the user is adding ----

type sshDraft struct {
	Device  string
	Name    string
	Host    string
	Port    int
	User    string
	Allowed []string
	Ask     bool
	Reuse   bool
	At      time.Time
}

func draftKey(device, name string) string { return device + "|" + name }

// parseSSHAdd reads "name host user [port]".
func parseSSHAdd(text string) (name, host, user string, port int, err error) {
	f := strings.Fields(text)
	if len(f) < 3 || len(f) > 4 {
		return "", "", "", 0, errors.New("type: name host user [port], for example: web-1 web.example.com deploy 22")
	}
	name, host, user, port = f[0], strings.ToLower(f[1]), f[2], 22
	if len(f) == 4 {
		var perr error
		if port, perr = strconv.Atoi(f[3]); perr != nil {
			return "", "", "", 0, errors.New("the port must be a number")
		}
	}
	switch {
	case !sshNameRE.MatchString(name):
		err = errors.New("the name is 1 to 32 characters of a-z, 0-9 and -")
	case !hostnameOK(host) || hiddenChars(host):
		err = errors.New("the host must be a host name or an IP address")
	case !sshUserRE.MatchString(user):
		err = errors.New("the user is 1 to 32 letters, digits, dots, hyphens or underscores")
	case port < 1 || port > 65535:
		err = errors.New("the port must be between 1 and 65535")
	}
	return
}

func (s *sisters) putDraft(d sshDraft) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sshDrafts == nil {
		s.sshDrafts = map[string]*sshDraft{}
	}
	now := s.now()
	for k, x := range s.sshDrafts {
		if now.Sub(x.At) > sshDraftLife {
			delete(s.sshDrafts, k)
		}
	}
	d.At = now
	for len(s.sshDrafts) >= maxSSHDrafts {
		oldest, key := now, ""
		for k, x := range s.sshDrafts {
			if key == "" || x.At.Before(oldest) {
				oldest, key = x.At, k
			}
		}
		delete(s.sshDrafts, key)
	}
	s.sshDrafts[draftKey(d.Device, d.Name)] = &d
}

// draftEdit changes a copy of a draft under the lock; it reports whether the draft still exists.
func (s *sisters) draftEdit(device, name string, edit func(d *sshDraft) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.sshDrafts[draftKey(device, name)]
	if d == nil || s.now().Sub(d.At) > sshDraftLife {
		delete(s.sshDrafts, draftKey(device, name))
		return errors.New("that target isn't being added any more (it was discarded or too old); start again")
	}
	if err := edit(d); err != nil {
		return err
	}
	d.At = s.now()
	return nil
}

func (s *sisters) draftsOf(device string) []sshDraft {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sshDraft
	for k, d := range s.sshDrafts {
		if d.Device != device {
			continue
		}
		if s.now().Sub(d.At) > sshDraftLife {
			delete(s.sshDrafts, k)
			continue
		}
		c := *d
		c.Allowed = slices.Clone(d.Allowed)
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b sshDraft) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// checkAllowedCmd checks one allowed-command entry: plain text of one line. Home decides what a prefix may contain.
func checkAllowedCmd(c string) (string, error) {
	c = strings.TrimSpace(c)
	if c == "" {
		return "", errors.New("type a command, or a prefix ending in * such as tail -n * (or ** to allow options too)")
	}
	if r := approvalText("the command", c, maxAllowedLen); r != "" {
		return "", errors.New(r)
	}
	if strings.ContainsAny(c, "\r\n\t") {
		return "", errors.New("a command is one line")
	}
	// As Rubi Home reads them: a pattern is a command, or a prefix and a final `*` (word boundary, no options in what
	// the role adds) or `**` (any arguments, options included).
	if strings.Contains(c, "*") {
		var prefix string
		switch {
		case strings.HasSuffix(c, " **"):
			prefix = strings.TrimSuffix(c, " **")
		case strings.HasSuffix(c, " *"):
			prefix = strings.TrimSuffix(c, " *")
		default:
			return "", errors.New("a * goes last, after a space, such as tail -n * (use ** to allow options as well)")
		}
		if strings.TrimSpace(prefix) == "" {
			return "", errors.New("a pattern needs a command before the *; to allow any command use Allow any command")
		}
		if strings.Contains(prefix, "*") {
			return "", errors.New("only one * at the end of a pattern")
		}
	}
	return c, nil
}

// anyOptionsPattern says the pattern is a `prefix **` one.
func anyOptionsPattern(c string) bool { return strings.HasSuffix(strings.TrimSpace(c), " **") }

// anyOptionsWarning is shown wherever a `**` pattern is listed or approved.
const anyOptionsWarning = "lets the role pass any options, including ones that run other programs"

// anyOptionsOf lists the `**` patterns among cmds.
func anyOptionsOf(cmds []string) []string {
	var out []string
	for _, c := range cmds {
		if anyOptionsPattern(c) {
			out = append(out, c)
		}
	}
	return out
}

// ---- panel: the SSH targets page ----

func (s *sisters) sshPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	var sections []map[string]any
	devs := s.agentDevices(ctx, h)
	for _, d := range devs {
		if p.Device != "" && d.ID != p.Device {
			continue
		}
		prefix := ifElse(len(devs) > 1, d.Name+": ", "")
		targets, err := s.listSSH(ctx, h, d.ID)
		if err != nil {
			sections = append(sections, map[string]any{"title": prefix + "SSH targets", "empty": oneLine(err.Error(), 200)})
			continue
		}
		var items []map[string]any
		for _, t := range clipList(targets, maxSSHItems) {
			items = append(items, s.sshRow(d.ID, t))
		}
		sections = append(sections, map[string]any{"title": prefix + "SSH targets", "note": panelSSHDoc, "empty": "No targets registered.", "items": items,
			"actions": []map[string]any{{"label": "Add a target", "op": "ssh_add", "args": panelPage{Device: d.ID}.args(),
				"prompt": map[string]any{"arg": "text", "label": "Name, host, user and optionally port, separated by spaces (for example: prod db.example.com deploy 22)", "value": ""}}}})
		if keys := s.sshKeysOf(d.ID, targets); len(keys) > 0 {
			sections = append(sections, map[string]any{"title": prefix + "Install the public key", "note": "Add this line to ~/.ssh/authorized_keys of the user on the server. It is a public key (safe to copy); the private key stays in Rubi Home on your computer. It is shown until Rubi's plugin restarts.", "empty": "", "items": keys})
		}
		if drafts := s.draftsOf(d.ID); len(drafts) > 0 {
			var di []map[string]any
			for _, dr := range drafts {
				di = append(di, sshDraftRow(dr))
			}
			sections = append(sections, map[string]any{"title": prefix + "Targets being added", "note": "Nothing is registered until you confirm the host key in a strong approval. Choose the allowed commands and whether each command asks you, then press Check the host key.", "empty": "", "items": di})
		}
	}
	if len(sections) == 0 {
		sections = []map[string]any{{"title": "SSH targets", "empty": "No computer reports the claude-agent capability."}}
	}
	return map[string]any{"title": "SSH targets", "refresh": 20,
		"up":       map[string]any{"label": "Projects", "open": panelPage{Page: pageAgent}.open()},
		"sections": sections}, nil
}

const panelSSHDoc = "A target is a server a role may run commands on, from your computer: Rubi Home connects, so the project VM never sees a key or a host. Only you register a target (a Bot can't). A role gets a target only when it is granted: you grant it on the role's page, and a Bot with a project trust may grant a target with restricted commands or ask-each-time to its roles. A target that allows any command needs your approval for each grant. The target's allowed commands apply. Names, hosts and commands are shown as text."

func (s *sisters) sshRow(device string, t sshTarget) map[string]any {
	allowed := "any command"
	if len(t.AllowedCommands) > 0 {
		var cs []string
		for _, c := range t.AllowedCommands {
			cs = append(cs, clipOne(c, 60))
		}
		allowed = "only " + strings.Join(clipList(cs, 6), "; ")
	}
	var roles []string
	for _, r := range t.Roles {
		roles = append(roles, clipOne(r.Name, 32))
	}
	rolesText := "no role has it"
	if len(roles) > 0 {
		rolesText = "granted to " + strings.Join(clipList(roles, 6), ", ")
	}
	detail := fmt.Sprintf("%s@%s:%d · host key %s (%s) · %s · %s · %s", clipOne(t.User, 32), clipOne(t.Host, 80), t.Port, clipOne(t.Fingerprint, 60), clipOne(t.KeyType, 20), allowed,
		ifElse(t.AskEachTime, "asks you for each command", "runs without asking"), rolesText)
	it := map[string]any{"title": clipOne(t.Name, 40), "detail": oneLine(detail, 580),
		"actions": []map[string]any{
			{"label": "Audit", "open": panelPage{Page: pageSSHAudit, Device: device, Target: t.Name}.open()},
			{"label": "Remove", "op": "ssh_remove", "args": panelPage{Device: device}.argsWith("item", t.Name), "danger": true,
				"confirm": "Remove this target? Its key is deleted, streams open to it are cut and roles lose the grant. You would have to remove the key from the server yourself."},
		}}
	if w := anyOptionsOf(t.AllowedCommands); len(w) > 0 {
		it["warn"] = true
		it["detail"] = oneLine("WARNING: "+strings.Join(clipList(w, 3), "; ")+" "+anyOptionsWarning+" · "+detail, 580)
	}
	if t.HostKeyChanged {
		it["warn"] = true
		it["detail"] = oneLine("HOST KEY CHANGED: the server presented another host key than the one pinned, so Rubi Home refuses to connect. This can be a reinstalled server or someone in between; check, then remove and add the target again. · "+detail, 580)
	}
	return it
}

func (p panelPage) argsWith(kv ...any) map[string]any {
	m := p.args()
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func sshDraftRow(d sshDraft) map[string]any {
	allowed := "any command"
	if len(d.Allowed) > 0 {
		var cs []string
		for _, c := range d.Allowed {
			cs = append(cs, clipOne(c, 60))
		}
		allowed = "only " + strings.Join(cs, "; ")
	}
	detail := fmt.Sprintf("%s@%s:%d · %s · %s%s", d.User, clipOne(d.Host, 80), d.Port, allowed, ifElse(d.Ask, "asks you for each command", "runs without asking"),
		ifElse(d.Reuse, " · reuses the name of a removed target (roles that still list it get this one)", ""))
	args := panelPage{Device: d.Device}.argsWith("item", d.Name)
	warn := false
	if w := anyOptionsOf(d.Allowed); len(w) > 0 {
		detail = "WARNING: " + strings.Join(clipList(w, 3), "; ") + " " + anyOptionsWarning + " · " + detail
		warn = true
	}
	return map[string]any{"title": clipOne(d.Name, 40), "detail": oneLine(detail, 580), "warn": warn, "actions": []map[string]any{
		{"label": "Check the host key", "op": "ssh_confirm", "args": args,
			"prompt": map[string]any{"arg": "text", "label": "Host key fingerprint you expect (SHA256:...). Leave empty to compare it in the approval instead", "value": ""}},
		{"label": "Allow a command", "op": "ssh_draft_cmd", "args": args,
			"prompt": map[string]any{"arg": "text", "label": "A command, or a prefix ending in * (more arguments, no options) or ** (any arguments, options too: it lets the role pass options that run other programs), such as tail -n * (up to 200 characters)", "value": ""}},
		{"label": "Allow any command", "op": "ssh_draft_anycmd", "args": args},
		{"label": ifElse(d.Ask, "Don't ask for each command", "Ask for each command"), "op": "ssh_draft_ask", "args": panelPage{Device: d.Device}.argsWith("item", d.Name, "on", !d.Ask)},
		{"label": ifElse(d.Reuse, "Don't reuse a removed name", "Reuse a removed name"), "op": "ssh_draft_reuse", "args": panelPage{Device: d.Device}.argsWith("item", d.Name, "on", !d.Reuse)},
		{"label": "Discard", "op": "ssh_draft_discard", "args": args, "danger": true},
	}}
}

// sshKeysOf lists the public key lines kept from registrations that are still registered.
func (s *sisters) sshKeysOf(device string, targets []sshTarget) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, t := range targets {
		if line := s.sshKeys[draftKey(device, t.Name)]; line != "" {
			// info carries the line for a panel that draws a copy button; detail has it as text for the others.
			out = append(out, map[string]any{"title": "authorized_keys line for " + clipOne(t.Name, 40), "detail": clipRunes(line, 580), "info": line, "warn": true})
		}
	}
	return out
}

func (s *sisters) setSSHKey(device, name, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sshKeys == nil || len(s.sshKeys) > 64 {
		s.sshKeys = map[string]string{}
	}
	s.sshKeys[draftKey(device, name)] = line
}

// ---- panel: the actions ----

// panelSSH runs the SSH buttons of the page. Every one is the user's own request; registering ends in the strong
// approval, which is the only thing that makes Home register.
func (s *sisters) panelSSH(ctx context.Context, h sisterHost, op, device, item string, on *bool, text *string) (any, error) {
	d, err := s.roleDeviceFor(ctx, h, device)
	if err != nil {
		return nil, err
	}
	switch op {
	case "ssh_add":
		if text == nil {
			return nil, errors.New("this Rubi's panel can't ask for text; update Rubi")
		}
		name, host, user, port, err := parseSSHAdd(*text)
		if err != nil {
			return nil, err
		}
		s.putDraft(sshDraft{Device: d.ID, Name: name, Host: host, Port: port, User: user, Ask: true})
		return map[string]any{"added": name, "next": "Choose the allowed commands, then press Check the host key. Nothing is registered yet."}, nil
	case "ssh_remove":
		return s.panelSSHRemove(ctx, h, d, item)
	}
	if !sshNameRE.MatchString(item) {
		return nil, errors.New("no such target")
	}
	switch op {
	case "ssh_draft_discard":
		s.mu.Lock()
		delete(s.sshDrafts, draftKey(d.ID, item))
		s.mu.Unlock()
		return map[string]any{"discarded": true}, nil
	case "ssh_draft_anycmd":
		return map[string]any{"allowed": "any command"}, s.draftEdit(d.ID, item, func(x *sshDraft) error { x.Allowed = nil; return nil })
	case "ssh_draft_cmd":
		if text == nil {
			return nil, errors.New("this Rubi's panel can't ask for text; update Rubi")
		}
		c, err := checkAllowedCmd(*text)
		if err != nil {
			return nil, err
		}
		return map[string]any{"allowed": c}, s.draftEdit(d.ID, item, func(x *sshDraft) error {
			if len(x.Allowed) >= maxAllowedCmds {
				return fmt.Errorf("at most %d allowed commands", maxAllowedCmds)
			}
			if !slices.Contains(x.Allowed, c) {
				x.Allowed = append(x.Allowed, c)
			}
			return nil
		})
	case "ssh_draft_ask", "ssh_draft_reuse":
		if on == nil {
			return nil, errors.New("say on or off")
		}
		return map[string]any{"set": *on}, s.draftEdit(d.ID, item, func(x *sshDraft) error {
			if op == "ssh_draft_ask" {
				x.Ask = *on
			} else {
				x.Reuse = *on
			}
			return nil
		})
	case "ssh_confirm":
		return s.askSSHRegister(ctx, h, d, item, text)
	}
	return nil, fmt.Errorf("unknown op %q", op)
}

// sshTicket is the payload of the strong approval: exactly what the user confirmed, fingerprint included.
type sshTicket struct {
	Device      string   `json:"device"`
	DeviceName  string   `json:"device_name,omitempty"`
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	User        string   `json:"user"`
	Fingerprint string   `json:"fingerprint"`
	KeyType     string   `json:"key_type,omitempty"`
	Allowed     []string `json:"allowed_commands,omitempty"`
	AskEachTime bool     `json:"ask_each_time"`
	Reuse       bool     `json:"reuse,omitempty"`
}

// askSSHRegister reads the server's host key (Rubi Home dials from the computer, no login), compares it with the one
// the user typed if they did, and asks for the strong approval that carries the fingerprint.
func (s *sisters) askSSHRegister(ctx context.Context, h sisterHost, dev rubiplugin.HomeDevice, name string, expect *string) (any, error) {
	var dr *sshDraft
	if err := s.draftEdit(dev.ID, name, func(x *sshDraft) error { c := *x; c.Allowed = slices.Clone(x.Allowed); dr = &c; return nil }); err != nil {
		return nil, err
	}
	var scan struct {
		Fingerprint string `json:"fingerprint"`
		KeyType     string `json:"key_type"`
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := h.HomeCall(sctx, dev.ID, opSSHScan, map[string]any{"host": dr.Host, "port": dr.Port}, &scan); err != nil {
		if isUnknownOp(err) {
			return nil, errors.New("this computer's Rubi Home doesn't do SSH targets yet; update it")
		}
		return nil, fmt.Errorf("couldn't read the server's host key: %s", oneLine(err.Error(), 160))
	}
	if !sshFPRE.MatchString(scan.Fingerprint) || hiddenChars(scan.KeyType) || len(scan.KeyType) > 40 {
		return nil, errors.New("Rubi Home answered with a host key fingerprint that doesn't look right")
	}
	if expect != nil && strings.TrimSpace(*expect) != "" && strings.TrimSpace(*expect) != scan.Fingerprint {
		return nil, fmt.Errorf("the server's host key is %s, not the %s you typed; nothing was registered", scan.Fingerprint, clipOne(*expect, 60))
	}
	t := sshTicket{Device: dev.ID, DeviceName: dev.Name, Name: dr.Name, Host: dr.Host, Port: dr.Port, User: dr.User, Fingerprint: scan.Fingerprint,
		KeyType: scan.KeyType, Allowed: dr.Allowed, AskEachTime: dr.Ask, Reuse: dr.Reuse}
	allowed := any("any command")
	if len(t.Allowed) > 0 {
		allowed = t.Allowed
	}
	preview := map[string]any{"computer": dev.Name, "name": t.Name, "host": t.Host, "port": t.Port, "user": t.User, "host_key_fingerprint": t.Fingerprint, "host_key_type": t.KeyType,
		"allowed_commands": allowed, "ask_each_time": t.AskEachTime, "reuses_the_name_of_a_removed_target": t.Reuse,
		"compare_the_fingerprint": "Compare the fingerprint with the one the server itself shows (on the server: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) before you approve. Rubi Home pins this key and refuses the target if the server ever presents another.",
		"what_it_does":            "Registers the target on that computer. Rubi Home makes a new key pair there (the private key never leaves it) and shows you the public key line to put on the server. A role can use the target only after it is granted: Bots with a project trust may grant a target with restricted commands or ask-each-time to their roles, and a target that allows any command needs your approval per grant. The project VM never gets the key or the host. Commands run as " + t.User + " on the server."}
	if w := anyOptionsOf(t.Allowed); len(w) > 0 {
		preview["warning"] = strings.Join(w, "; ") + " " + anyOptionsWarning
	}
	if expect != nil && strings.TrimSpace(*expect) != "" {
		preview["matches_the_fingerprint_you_typed"] = true
	}
	return h.Submit(ctx, rubiplugin.Request{Kind: kindSSHTarget,
		Summary: "Register the SSH target " + t.Name + " (" + t.User + "@" + t.Host + ":" + strconv.Itoa(t.Port) + "), host key " + t.Fingerprint,
		Preview: preview, Payload: t})
}

// executeSSHRegister runs once the user approved. Rubi Home refuses when the server's key is no longer the one
// confirmed.
func (s *sisters) executeSSHRegister(ctx context.Context, h sisterHost, t sshTicket) (any, error) {
	if t.Device == "" || !sshNameRE.MatchString(t.Name) || !hostnameOK(t.Host) || !sshUserRE.MatchString(t.User) || t.Port < 1 || t.Port > 65535 ||
		!sshFPRE.MatchString(t.Fingerprint) || len(t.Allowed) > maxAllowedCmds {
		return nil, errors.New("bad payload")
	}
	for _, c := range t.Allowed {
		if _, err := checkAllowedCmd(c); err != nil {
			return nil, errors.New("bad payload")
		}
	}
	args := map[string]any{"name": t.Name, "host": t.Host, "port": t.Port, "user": t.User, "fingerprint": t.Fingerprint, "ask_each_time": t.AskEachTime}
	if len(t.Allowed) > 0 {
		args["allowed_commands"] = t.Allowed
	}
	if t.Reuse {
		args["reuse"] = true // the user saw this in the strong approval
	}
	var res struct {
		PublicKeyLine string `json:"public_key_line"`
	}
	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := h.HomeCall(rctx, t.Device, opSSHRegister, args, &res); err != nil {
		msg := oneLine(err.Error(), 200)
		if strings.Contains(strings.ToLower(msg), "reuse") {
			return nil, errors.New("not registered: the name " + t.Name + " belonged to a target that was removed, and roles that still list it would get this one. Add it again with Reuse a removed name turned on if that is what you want (" + msg + ")")
		}
		return nil, errors.New("not registered: " + msg)
	}
	line := strings.TrimSpace(res.PublicKeyLine)
	if line == "" || len(line) > 2000 || strings.ContainsAny(line, "\r\n") || hiddenChars(line) {
		return nil, errors.New("registered, but Rubi Home's public key line doesn't look right; remove the target and add it again")
	}
	s.setSSHKey(t.Device, t.Name, line)
	s.mu.Lock()
	delete(s.sshDrafts, draftKey(t.Device, t.Name))
	s.mu.Unlock()
	_, _ = s.listSSH(ctx, h, t.Device)
	h.Audit(auditSSHRegistered, map[string]any{"device": t.Device, "target": t.Name, "host": t.Host, "port": t.Port, "user": t.User, "fingerprint": t.Fingerprint,
		"allowed_commands": len(t.Allowed), "ask_each_time": t.AskEachTime, "reuse": t.Reuse, "by": "user"})
	return map[string]any{"registered": t.Name, "public_key_line": line, "info": line,
		"next": "Add the public key line to ~/.ssh/authorized_keys of " + t.User + " on the server (the SSH targets page shows it too), then grant the target to a role."}, nil
}

// panelSSHRemove deletes a target and takes the grants away from the roles that name it, as the user's own changes
// (Home doesn't edit role records, and a later target with the same name must not inherit a grant).
func (s *sisters) panelSSHRemove(ctx context.Context, h sisterHost, dev rubiplugin.HomeDevice, name string) (any, error) {
	if !sshNameRE.MatchString(name) {
		return nil, errors.New("no such target")
	}
	var res struct {
		OK            bool `json:"ok"`
		ClosedStreams int  `json:"closed_streams"`
	}
	rctx, cancel := context.WithTimeout(ctx, roleCallTimeout)
	defer cancel()
	if err := h.HomeCall(rctx, dev.ID, opSSHRemove, map[string]any{"name": name}, &res); err != nil {
		return nil, fmt.Errorf("not removed: %s", oneLine(err.Error(), 200))
	}
	s.mu.Lock()
	delete(s.sshKeys, draftKey(dev.ID, name))
	s.mu.Unlock()
	_, _ = s.listSSH(ctx, h, dev.ID)
	revoked, failed := 0, 0
	if rd, err := s.refreshRoles(ctx, h, dev.ID, true); err == nil {
		for _, r := range rd.roles {
			if !slices.Contains(r.SSH, name) {
				continue
			}
			next := r.clone()
			next.SSH = slices.DeleteFunc(next.SSH, func(x string) bool { return x == name })
			if _, err := s.panelChange(ctx, h, roleChangeReq{Bot: panelUser, ByUser: true, Dev: dev, Op: "role.ssh.target_removed", Cur: r, Next: next, Lim: roleLimitsOf(h)}); err != nil {
				failed++
				h.Logf("taking the SSH grant %s from role %s: %v", name, r.ID, err)
				continue
			}
			revoked++
		}
	} else {
		failed++
	}
	h.Audit(auditSSHRemoved, map[string]any{"device": dev.ID, "target": name, "closed_streams": res.ClosedStreams, "grants_removed": revoked, "grants_failed": failed, "by": "user"})
	out := map[string]any{"removed": name, "closed_streams": res.ClosedStreams, "grants_removed": revoked}
	if failed > 0 {
		out["note"] = "The target is gone, but some role grants couldn't be removed; they do nothing while no target has the name, but remove them on the roles' pages before you register that name again."
	}
	return out, nil
}

// ---- panel: the audit of one target ----

type sshAuditEntry struct {
	Seq      int64  `json:"seq"`
	Stream   string `json:"stream"`
	Role     string `json:"role"`
	Project  string `json:"project"`
	Bot      string `json:"bot"`
	Target   string `json:"target"`
	Command  string `json:"command"`
	Start    string `json:"start"`
	End      string `json:"end"`
	Exit     *int   `json:"exit"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Result   string `json:"result"`
	Reason   string `json:"reason"`
}

func (s *sisters) readSSHAudit(ctx context.Context, h sisterHost, device, target string, limit int) ([]sshAuditEntry, error) {
	out, err := s.readSSHAuditAfter(ctx, h, device, target, limit, 0)
	return out.Entries, err
}

// sshAuditReply is ssh.audit's answer: the entries and, when Home counts them, its counters of refusals by reason.
type sshAuditReply struct {
	Entries  []sshAuditEntry  `json:"entries"`
	Refusals map[string]int64 `json:"refusals"`
}

// readSSHAuditAfter asks for the entries after a sequence number (0: the newest limit).
func (s *sisters) readSSHAuditAfter(ctx context.Context, h sisterHost, device, target string, limit int, after int64) (sshAuditReply, error) {
	var out sshAuditReply
	args := map[string]any{"limit": limit}
	if target != "" {
		args["target"] = target
	}
	if after > 0 {
		args["after_seq"] = after
	}
	actx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(actx, device, opSSHAudit, args, &out); err != nil {
		return sshAuditReply{}, fmt.Errorf("couldn't read the SSH audit: %s", oneLine(err.Error(), 160))
	}
	return out, nil
}

func (s *sisters) sshAuditPage(ctx context.Context, h sisterHost, p panelPage) (any, error) {
	if !sshNameRE.MatchString(p.Target) {
		return nil, errors.New("no such target")
	}
	d, err := s.roleDeviceFor(ctx, h, p.Device)
	if err != nil {
		return nil, err
	}
	entries, err := s.readSSHAudit(ctx, h, d.ID, p.Target, sshAuditLimit)
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	for _, e := range entries {
		exit := ""
		if e.Exit != nil {
			exit = fmt.Sprintf(" · exit %d", *e.Exit)
		}
		who := s.roleLabel(d.ID, e.Project, e.Role)
		detail := fmt.Sprintf("role %s · by %s%s · %d bytes in, %d out · command: %s", clipOne(firstNonEmpty(who, "default"), 60), clipOne(firstNonEmpty(e.Bot, "unknown"), 40), exit, e.BytesIn, e.BytesOut, plainText(e.Command, 200))
		if e.Reason != "" {
			detail += " · " + plainText(e.Reason, 100)
		}
		it := map[string]any{"title": clipOne(firstNonEmpty(e.Start, "unknown time"), 40) + " · " + clipOne(firstNonEmpty(e.Result, "ok"), 30), "detail": oneLine(detail, 580)}
		if e.Result != "" && e.Result != "ok" {
			it["warn"] = true
		}
		items = append(items, it)
	}
	return map[string]any{"title": "Audit of " + clipOne(p.Target, 40), "refresh": 20,
		"up":       map[string]any{"label": "SSH targets", "open": panelPage{Page: pageSSH, Device: d.ID}.open()},
		"sections": []map[string]any{{"title": "Newest first", "note": "Every stream a role opened to this target, and every refusal (an ungranted role, a command that isn't allowed, a changed host key). Commands are the Bots' own text, shown clipped; no output and no key is ever recorded.", "empty": "Nothing yet.", "items": clipList(items, maxSSHItems)}}}, nil
}

// sshAuditTick copies Home's SSH audit entries into Rubi's audit log (the plugin's side of section 9.7): at most
// every sshAuditEvery. Home numbers its entries (seq): the plugin asks for those after the last seq it copied, which
// it keeps in its state per computer, so nothing is copied twice or missed after a restart. A Home that sends no seq
// gets the old way: the newest sshAuditLimit entries, each once while the plugin runs. A per-computer summary
// (entries copied, refusals, Home's refusal counters) is audited too.
func (s *sisters) sshAuditTick(ctx context.Context, h sisterHost, devices []string) {
	s.mu.Lock()
	if !s.sshAuditAt.IsZero() && s.now().Sub(s.sshAuditAt) < sshAuditEvery {
		s.mu.Unlock()
		return
	}
	s.sshAuditAt = s.now()
	s.mu.Unlock()
	for _, dev := range devices {
		last := s.st.sshAuditSeq(dev)
		copied, refused := 0, 0
		var counters map[string]int64
		for page := 0; page < 10; page++ {
			rep, err := s.readSSHAuditAfter(ctx, h, dev, "", sshAuditLimit, last)
			if err != nil {
				break
			}
			counters = rep.Refusals
			entries := rep.Entries
			numbered := slices.ContainsFunc(entries, func(e sshAuditEntry) bool { return e.Seq > 0 })
			if numbered {
				slices.SortStableFunc(entries, func(a, b sshAuditEntry) int { return cmp.Compare(a.Seq, b.Seq) })
			} else {
				slices.Reverse(entries) // oldest first
			}
			next := last
			for _, e := range entries {
				if numbered && e.Seq <= last {
					continue
				}
				if !numbered && s.sshSeenBefore(dev, e) {
					continue
				}
				h.Audit(auditSSHStream, sshAuditFields(dev, e))
				copied++
				if e.Result != "" && e.Result != "ok" {
					refused++
				}
				next = max(next, e.Seq)
			}
			if next > last {
				_ = s.st.setSSHAuditSeq(dev, next)
			}
			if !numbered || next == last || len(entries) < sshAuditLimit {
				break
			}
			last = next
		}
		if copied > 0 || len(counters) > 0 {
			f := map[string]any{"device": dev, "copied": copied, "refused": refused}
			if len(counters) > 0 {
				f["refusals"] = counters
			}
			h.Audit(auditSSHCopy, f)
		}
	}
}

func (s *sisters) sshSeenBefore(dev string, e sshAuditEntry) bool {
	key := dev + "|" + e.Stream + "|" + e.Start + "|" + e.Target + "|" + e.Role + "|" + e.Result
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sshSeen == nil || len(s.sshSeen) > 2000 {
		s.sshSeen = map[string]bool{}
	}
	seen := s.sshSeen[key]
	s.sshSeen[key] = true
	return seen
}

func sshAuditFields(dev string, e sshAuditEntry) map[string]any {
	f := map[string]any{"device": dev, "role": e.Role, "project": e.Project, "bot": e.Bot, "target": e.Target, "command": plainText(e.Command, 200),
		"start": e.Start, "end": e.End, "bytes_in": e.BytesIn, "bytes_out": e.BytesOut, "result": e.Result}
	if e.Seq > 0 {
		f["seq"] = e.Seq
	}
	if e.Exit != nil {
		f["exit"] = *e.Exit
	}
	if e.Reason != "" {
		f["reason"] = plainText(e.Reason, 100)
	}
	return f
}

// ---- role grants on the role page ----

// sshGrantItems lists the registered targets (Grant or Revoke) and the granted names that are not registered any
// more (Revoke).
func (s *sisters) sshGrantItems(ctx context.Context, h sisterHost, device string, r *role, args func(extra ...any) map[string]any) ([]map[string]any, string) {
	targets, err := s.listSSH(ctx, h, device)
	var items []map[string]any
	note := "A target is registered on the SSH targets page, by you only. Granting a registered target is immediate; the role can then run the target's allowed commands from its VM."
	if err != nil {
		note += " Couldn't read the targets: " + oneLine(err.Error(), 120)
	}
	known := map[string]bool{}
	for _, t := range targets {
		known[t.Name] = true
		granted := slices.Contains(r.SSH, t.Name)
		act := map[string]any{"label": "Grant", "op": "role_ssh_grant", "args": args("item", t.Name)}
		if granted {
			act = map[string]any{"label": "Revoke", "op": "role_ssh_revoke", "args": args("item", t.Name), "danger": true}
		}
		detail := fmt.Sprintf("%s@%s:%d · %s", clipOne(t.User, 32), clipOne(t.Host, 80), t.Port, ifElse(granted, "this role may use it", "not granted"))
		it := map[string]any{"title": clipOne(t.Name, 40), "detail": oneLine(detail, 300), "actions": []map[string]any{act}}
		if t.HostKeyChanged {
			it["warn"] = true
			it["detail"] = "HOST KEY CHANGED, connections are refused · " + oneLine(detail, 280)
		}
		items = append(items, it)
	}
	for _, name := range r.SSH {
		if !known[name] {
			items = append(items, map[string]any{"title": clipOne(name, 40), "detail": "granted, but no target has this name (not registered, or not listed)", "warn": true,
				"actions": []map[string]any{{"label": "Revoke", "op": "role_ssh_revoke", "args": args("item", name), "danger": true}}})
		}
	}
	return clipList(items, maxRoleItems), note
}

// ---- ssh.ask: a command on a target registered with ask_each_time ----

// sshAskInput is the item's input.
type sshAskInput struct {
	Target  string `json:"target"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Command string `json:"command"`
}

// sshAskDetail checks an ssh.ask and builds what the user reads. The command is the Bot's own text: it is shown exactly
// (line ends marked, so a second line can't pass for part of the first) or the question is refused.
func sshAskDetail(it agentItem) (detail string, extra map[string]any, why string) {
	var in sshAskInput
	if err := json.Unmarshal(it.Input, &in); err != nil {
		return "", nil, "unknown SSH request: Rubi Home's question isn't readable"
	}
	host := firstNonEmpty(in.Host, it.Host)
	switch {
	case !sshNameRE.MatchString(in.Target) || !hostnameOK(host) || hiddenChars(host) || !sshUserRE.MatchString(in.User) || in.Port < 1 || in.Port > 65535:
		return "", nil, "unknown SSH request: Rubi Home didn't say which target, host and user this is"
	case strings.TrimSpace(in.Command) == "" || len(in.Command) > maxSSHAskCmd:
		return "", nil, "unknown SSH request: the command is empty or too long for Rubi to show whole, so it was refused"
	case strings.ContainsAny(in.Command, "⏎⇥"):
		return "", nil, "the SSH command has the characters Rubi uses to mark line ends, so Rubi can't show exactly what it does"
	case hiddenChars(strings.NewReplacer("\n", "", "\r", "", "\t", "").Replace(in.Command)):
		return "", nil, "the SSH command has hidden or control characters, so Rubi can't show what it does"
	}
	// Exactly the command, spaces and all. Only line ends and tabs get a visible mark (a command that has the marks
	// itself is refused), so a second line can't pass for part of the first.
	cmd := strings.NewReplacer("\r\n", "⏎", "\n", "⏎", "\r", "⏎", "\t", "⇥").Replace(in.Command)
	detail = "ssh " + in.Target + " (" + in.User + "@" + strings.ToLower(host) + ":" + strconv.Itoa(in.Port) + "): " + cmd
	extra = map[string]any{"ssh_target": in.Target, "ssh_host": strings.ToLower(host), "ssh_port": in.Port, "ssh_user": in.User, "ssh_command": cmd,
		"what_it_does": "Runs this command as " + in.User + " on the server " + strings.ToLower(host) + " from your computer, once. You are asked each time because the target was registered that way. The command is shown exactly as the agent wrote it (line ends and tabs are marked)."}
	return detail, extra, ""
}
