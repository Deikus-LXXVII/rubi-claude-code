package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProjectFilesChangedIsShownAndUnknownKindsAreIgnored(t *testing.T) {
	f, s, _ := agentFixture(t)
	ctx := context.Background()
	var it agentItem
	raw := `{"type":"event","project":"p1","role":"r1","role_name":"builder","event":{"kind":"project_files_changed","files":[".mcp.json",".git/config"],"role_name":"builder","message":"x"}}`
	if err := json.Unmarshal([]byte(raw), &it); err != nil || it.Kind != "project_files_changed" || len(it.Files) != 2 {
		t.Fatalf("%v %+v", err, it)
	}
	n := len(f.events)
	s.routeAgent(ctx, f, mac, it)
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "something_new_later", Project: "p1", Files: []string{"x"}})
	s.routeAgent(ctx, f, mac, agentItem{Type: "event", Kind: "project_files_changed", Project: "p1"}) // no files: nothing to show
	if len(f.events) != n {
		t.Fatalf("nothing goes to a Bot: %+v", f.events[n:])
	}
	items := s.fileNoteItems(mac.ID, "p1")
	if len(items) != 1 || items[0]["warn"] != true || !strings.Contains(items[0]["title"].(string), ".mcp.json, .git/config") ||
		!strings.Contains(items[0]["detail"].(string), "builder") {
		t.Fatalf("%+v", items)
	}
	if len(s.fileNoteItems(mac.ID, "p2")) != 0 {
		t.Fatal("another project")
	}
	// Only the latest few are kept, and old ones expire.
	for range 5 {
		s.routeAgent(ctx, f, mac, it)
	}
	if got := len(s.fileNoteItems(mac.ID, "p1")); got != maxFileNotes {
		t.Fatalf("%d", got)
	}
	now := time.Now().Add(fileNoteMaxAge + time.Hour)
	s.now = func() time.Time { return now }
	if got := s.fileNoteItems(mac.ID, "p1"); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}
