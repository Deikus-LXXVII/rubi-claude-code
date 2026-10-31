package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

// fakeRoles plays Rubi Home's role store (claude-agent.role.*): versions, base_version conflicts, the checks that
// matter to the plugin (approval ids on MCP servers and plugins, blobs, modes) and a toy skill scan: text with
// mcpServers, allowed-tools or "curl -d" is flagged (held until accepted), text with "AKIA" is rejected.
type fakeRoles struct {
	mu     sync.Mutex
	roles  map[string][]*role // id -> versions
	blobs  map[string]string
	n      int
	puts   []map[string]any
	legacy []string
}

func newFakeRoles() *fakeRoles {
	return &fakeRoles{roles: map[string][]*role{}, blobs: map[string]string{}, legacy: []string{"p1"}}
}

func homeRefusal(format string, args ...any) error {
	return &rubiplugin.Error{Code: rubiplugin.CodeHomeFailed, Message: fmt.Sprintf(format, args...)}
}

var fakeNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func (f *fakeRoles) cur(id string) *role {
	v := f.roles[id]
	if len(v) == 0 {
		return nil
	}
	return v[len(v)-1]
}

func (f *fakeRoles) call(op string, m map[string]any) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := json.Marshal(m)
	switch op {
	case opRoleList:
		rows := []roleRow{}
		for _, p := range f.legacy {
			rows = append(rows, roleRow{ID: p, Project: p, Name: "default", Status: "active", Legacy: true})
		}
		for id := range f.roles {
			r := f.cur(id)
			rows = append(rows, roleRow{ID: id, Project: r.Project, Name: r.Name, Description: r.Description, Status: r.Status, Version: r.Version, ChangedBy: r.ChangedBy})
		}
		return map[string]any{"roles": rows}, nil
	case opRoleGet:
		var a struct {
			ID      string `json:"id"`
			Version int    `json:"version"`
		}
		_ = json.Unmarshal(raw, &a)
		vs := f.roles[a.ID]
		if len(vs) == 0 {
			return nil, homeRefusal("no role %q", a.ID)
		}
		if a.Version == 0 {
			a.Version = len(vs)
		}
		if a.Version < 1 || a.Version > len(vs) {
			return nil, homeRefusal("no version %d", a.Version)
		}
		return vs[a.Version-1], nil
	case opRoleHistory:
		var a struct {
			ID    string `json:"id"`
			Limit int    `json:"limit"`
		}
		_ = json.Unmarshal(raw, &a)
		vs := f.roles[a.ID]
		if len(vs) == 0 {
			return nil, homeRefusal("no role %q", a.ID)
		}
		var out []map[string]any
		for i := len(vs) - 1; i >= 0; i-- {
			r := vs[i]
			out = append(out, map[string]any{"version": r.Version, "parent": r.Parent, "changed_by": r.ChangedBy, "changed_at": r.ChangedAt, "name": r.Name, "status": r.Status, "change": r.Change})
		}
		return map[string]any{"id": a.ID, "current": len(vs), "versions": out}, nil
	case opRoleDiff:
		var a struct {
			ID       string `json:"id"`
			From, To int
		}
		_ = json.Unmarshal(raw, &a)
		vs := f.roles[a.ID]
		if a.From < 1 || a.To < 1 || a.From > len(vs) || a.To > len(vs) {
			return nil, homeRefusal("no such version")
		}
		x, y := vs[a.From-1], vs[a.To-1]
		changes := []map[string]any{}
		for _, fld := range fieldDiffers(x, y) {
			changes = append(changes, map[string]any{"field": fld, "kind": "changed", "from": json.RawMessage(x.fieldValue(fld)), "to": json.RawMessage(y.fieldValue(fld))})
		}
		texts := []map[string]any{}
		for _, k := range y.Skills {
			if f.blobs[k.SHA256] != "" {
				texts = append(texts, map[string]any{"name": k.Name, "diff": "+" + f.blobs[k.SHA256]})
			}
		}
		return map[string]any{"id": a.ID, "from": a.From, "to": a.To, "changes": changes, "skill_text": texts}, nil
	case opRolePut:
		f.puts = append(f.puts, m)
		return f.put(raw)
	}
	return nil, fmt.Errorf(`Rubi Home doesn't do "%s"`, op)
}

func (f *fakeRoles) put(raw []byte) (any, error) {
	var a struct {
		ID     string            `json:"id"`
		Base   int               `json:"base_version"`
		Spec   *role             `json:"spec"`
		Blobs  map[string]string `json:"blobs"`
		By     string            `json:"by"`
		Change *roleChangeInfo   `json:"change"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || a.Spec == nil {
		return nil, homeRefusal("bad arguments")
	}
	var old *role
	if a.ID != "" {
		if old = f.cur(a.ID); old == nil {
			return nil, homeRefusal("no role %q", a.ID)
		}
		if old.Version != a.Base {
			return nil, homeRefusal("the role changed: base_version %d, current version %d", a.Base, old.Version)
		}
	} else if a.Base != 0 {
		return nil, homeRefusal("a new role has base_version 0")
	}
	r := a.Spec.clone()
	var why []string
	switch {
	case !fakeNameRE.MatchString(r.Name) || r.Name == "default":
		why = append(why, "name: bad")
	}
	for id, vs := range f.roles {
		o := vs[len(vs)-1]
		if id != a.ID && o.Project == r.Project && o.Name == r.Name && o.Status == "active" && r.Status == "active" {
			why = append(why, "name: already used on this project")
		}
	}
	if _, ok := roleModeRank[r.DefaultMode]; !ok {
		why = append(why, "default_mode: bad")
	}
	for _, t := range r.Tools {
		if !slices.Contains(knownRoleTools, t) {
			why = append(why, "tools: unknown "+t)
		}
	}
	for _, m := range r.MCP {
		if m.Approval == "" {
			why = append(why, "mcp "+m.Name+": it needs an approval id")
		}
	}
	for _, p := range r.Plugins {
		if p.Approval == "" {
			why = append(why, "plugin "+p.Name+": it needs an approval id")
		}
	}
	newBlobs := map[string]string{}
	for sha, text := range a.Blobs {
		if shaOf(text) != sha {
			why = append(why, "blobs: not the sha256 of its content")
		}
		newBlobs[sha] = text
	}
	for i := range r.Skills {
		k := &r.Skills[i]
		text, ok := newBlobs[k.SHA256]
		if !ok {
			text, ok = f.blobs[k.SHA256]
		}
		if !ok {
			why = append(why, "skill "+k.Name+": no text")
			continue
		}
		verdict, rules := "pass", []map[string]any{}
		switch {
		case strings.Contains(text, "AKIA"):
			why = append(why, "skill "+k.Name+": sec.aws line 1")
			continue
		case strings.Contains(text, "mcpServers") || strings.Contains(text, "allowed-tools") || strings.Contains(text, "curl -d"):
			verdict, rules = "flag", []map[string]any{{"id": "wid.claim", "line": 1, "excerpt": "mentions a grant"}}
		}
		sc, _ := json.Marshal(map[string]any{"verdict": verdict, "rules": rules})
		k.Scan = sc
		k.State = "active"
		if verdict == "flag" && !slices.Contains(k.Accepted, "wid.claim") {
			k.State = "held"
		}
	}
	if len(why) > 0 {
		return nil, homeRefusal("role refused: %s", strings.Join(why, "; "))
	}
	for sha, text := range newBlobs {
		f.blobs[sha] = text
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if old == nil {
		f.n++
		r.ID = fmt.Sprintf("r_%08d", f.n)
		r.CreatedBy, r.CreatedAt = a.By, now
		r.Version, r.Parent = 1, 0
	} else {
		r.ID, r.CreatedBy, r.CreatedAt = old.ID, old.CreatedBy, old.CreatedAt
		r.Version, r.Parent = old.Version+1, old.Version
	}
	r.ChangedBy, r.ChangedAt, r.Change = a.By, now, a.Change
	f.roles[r.ID] = append(f.roles[r.ID], r)
	res := map[string]any{"id": r.ID, "version": r.Version}
	var sk []map[string]any
	for _, k := range r.Skills {
		var sc scanView
		_ = json.Unmarshal(k.Scan, &sc)
		sk = append(sk, map[string]any{"name": k.Name, "state": k.State, "verdict": sc.Verdict})
	}
	res["skills"] = sk
	return res, nil
}

// current is the stored current version of a role.
func (f *fakeRoles) current(id string) *role {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur(id)
}

func (f *fakeRoles) putCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.puts)
}
