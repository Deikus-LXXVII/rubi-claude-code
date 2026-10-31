package main

import (
	"strings"
	"time"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

// A role session that changed a file another session or the host's tools load (.mcp.json, .git/config) is reported by
// Rubi Home as a project_files_changed event. The plugin audits it and keeps the latest few per project to show as a
// warning in the panel's projects view; nothing is blocked (Rubi Home detects, the user reviews).
const (
	maxFileNotes   = 3
	maxNoteFiles   = 6
	fileNoteMaxAge = 7 * 24 * time.Hour
)

type fileNote struct {
	role  string
	files []string
	at    time.Time
}

func fileNoteKey(device, project string) string { return device + "|" + project }

// noteFilesChanged records one project_files_changed event. File names come from the session's folder, so they are
// untrusted text and are shortened and stripped of line breaks.
func (s *sisters) noteFilesChanged(h sisterHost, d rubiplugin.HomeDevice, it agentItem) {
	if it.Project == "" || len(it.Files) == 0 {
		return
	}
	files := make([]string, 0, min(len(it.Files), maxNoteFiles))
	for _, f := range it.Files {
		if len(files) == maxNoteFiles {
			break
		}
		files = append(files, oneLine(f, 120))
	}
	role := oneLine(firstNonEmpty(it.RoleName, it.Role), 40)
	h.Audit("project_files_changed", map[string]any{"computer": d.Name, "project": it.Project, "role": role, "files": strings.Join(files, ", ")})
	h.Logf("%s: a role session (%s) changed %s in project %s", d.Name, role, strings.Join(files, ", "), it.Project)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fileNotes == nil {
		s.fileNotes = map[string][]fileNote{}
	}
	k := fileNoteKey(d.ID, it.Project)
	s.fileNotes[k] = append(s.fileNotes[k], fileNote{role: role, files: files, at: s.now()})
	if n := len(s.fileNotes[k]); n > maxFileNotes {
		s.fileNotes[k] = s.fileNotes[k][n-maxFileNotes:]
	}
}

// fileNoteItems are the panel items for a project's recent notes (newest last, old ones dropped).
func (s *sisters) fileNoteItems(device, project string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := fileNoteKey(device, project)
	var items []map[string]any
	var keep []fileNote
	for _, n := range s.fileNotes[k] {
		if s.now().Sub(n.at) > fileNoteMaxAge {
			continue
		}
		keep = append(keep, n)
		items = append(items, map[string]any{"title": "A role session changed " + strings.Join(n.files, ", "),
			"detail": "Role " + n.role + " · " + n.at.Local().Format("2006-01-02 15:04") + " · review before another session or your editor loads it", "warn": true})
	}
	if len(keep) == 0 {
		delete(s.fileNotes, k)
	} else if s.fileNotes != nil {
		s.fileNotes[k] = keep
	}
	return items
}
