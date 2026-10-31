package main

import (
	"fmt"
	"strings"
	"sync"
)

// fakeSSH plays Rubi Home's SSH registry (claude-agent.ssh.*): scan reads the live host key, register pins the one the
// user confirmed (and refuses a changed key, a taken name and, after a removal, a name without reuse), list shows each
// target with the roles that have it, audit returns the stream entries.
type fakeSSH struct {
	mu        sync.Mutex
	live      string // the fingerprint the server presents now
	targets   map[string]*sshTarget
	removed   map[string]bool // names used by a removed target (the tombstone)
	calls     []fakeCall
	audit     []sshAuditEntry
	numbered  bool           // the audit entries carry seq and after_seq works
	refusals  map[string]int // Home's refusal counters
	scanErr   error
	registers []map[string]any
}

const (
	fpGood  = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	fpOther = "SHA256:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
)

func newFakeSSH() *fakeSSH {
	return &fakeSSH{live: fpGood, targets: map[string]*sshTarget{}, removed: map[string]bool{}}
}

func (f *fakeSSH) registeredNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for n := range f.targets {
		out = append(out, n)
	}
	return out
}

func (f *fakeSSH) called(op string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, c := range f.calls {
		if c.op == op {
			out = append(out, c.args)
		}
	}
	return out
}

func (f *fakeSSH) call(op string, m map[string]any, roles *fakeRoles) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{op, m})
	switch op {
	case opSSHScan:
		if f.scanErr != nil {
			return nil, f.scanErr
		}
		return map[string]any{"fingerprint": f.live, "key_type": "ssh-ed25519"}, nil
	case opSSHRegister:
		f.registers = append(f.registers, m)
		name, _ := m["name"].(string)
		if _, ok := f.targets[name]; ok {
			return nil, homeRefusal("the target %s exists", name)
		}
		if f.removed[name] && m["reuse"] != true {
			return nil, homeRefusal("the name %s belonged to a removed target; pass reuse:true to take it again", name)
		}
		if fp, _ := m["fingerprint"].(string); fp != f.live {
			return nil, homeRefusal("the server's host key is %s, not the fingerprint you confirmed", f.live)
		}
		t := &sshTarget{Name: name, Host: fmt.Sprint(m["host"]), User: fmt.Sprint(m["user"]), Fingerprint: f.live, KeyType: "ssh-ed25519", AskEachTime: m["ask_each_time"] == true}
		t.Port = int(m["port"].(float64))
		if cs, ok := m["allowed_commands"].([]any); ok {
			for _, c := range cs {
				t.AllowedCommands = append(t.AllowedCommands, fmt.Sprint(c))
			}
		}
		f.targets[name] = t
		delete(f.removed, name)
		prefix := "restrict"
		if len(t.AllowedCommands) == 1 && !strings.HasSuffix(t.AllowedCommands[0], "*") {
			prefix += `,command="` + t.AllowedCommands[0] + `"`
		}
		return map[string]any{"public_key_line": prefix + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey rubi-" + name}, nil
	case opSSHList:
		var rows []sshTarget
		for _, t := range f.targets {
			c := *t
			c.Roles = nil
			if roles != nil {
				for id, vs := range roles.roles {
					r := vs[len(vs)-1]
					for _, g := range r.SSH {
						if g == t.Name {
							c.Roles = append(c.Roles, sshRoleRef{ID: id, Name: r.Name, Project: r.Project})
						}
					}
				}
			}
			rows = append(rows, c)
		}
		return map[string]any{"targets": rows}, nil
	case opSSHRemove:
		name, _ := m["name"].(string)
		if _, ok := f.targets[name]; !ok {
			return nil, homeRefusal("no target %s", name)
		}
		delete(f.targets, name)
		f.removed[name] = true
		return map[string]any{"ok": true, "closed_streams": 1}, nil
	case opSSHAudit:
		target, _ := m["target"].(string)
		var out []sshAuditEntry
		after, _ := m["after_seq"].(int64)
		for i := len(f.audit) - 1; i >= 0; i-- {
			if f.numbered {
				f.audit[i].Seq = int64(i + 1)
			}
			if (target == "" || f.audit[i].Target == target) && f.audit[i].Seq > after || (!f.numbered && (target == "" || f.audit[i].Target == target)) {
				out = append(out, f.audit[i])
			}
		}
		return map[string]any{"entries": out, "refusals": f.refusals}, nil
	}
	return nil, fmt.Errorf(`Rubi Home doesn't do "%s"`, op)
}
