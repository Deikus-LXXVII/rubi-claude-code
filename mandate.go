package main

// Mandates: you approve one command with "Allow and trust this session for 2 hours", and for that time
// the plugin allows the session's commands by itself, as long as each one is plain and on the mandate's
// list. Every such allow is audited. A mandate is bound to one computer, one Claude Code session and its
// directory, ends after two hours or maxUses commands, and can be revoked in the panel (the plugin's
// page) or with the claude_code_mandates tool. Locking Rubi stops it too: the helper denies everything
// while Rubi doesn't poll.
//
// Some things always ask, whatever the mandate: pushing or any git command not on the list, --force,
// sudo and other ways to run a command as someone else or through a shell (eval, sh -c, xargs,
// substitutions, backticks), options that name another program to run (git grep -O, go -exec, make
// --eval), the network (curl, ssh, installs, publishing), writing or deleting outside the session's
// directory or into git's own files (a hook there runs at the next commit), and paths that hold
// credentials. Every option of a listed program must be on that program's list (mandate_programs.go,
// mandate_git.go); an unknown option asks. The check reads only the command line:
// a build, test or script it runs (make, go test, npm run) can do anything you can, so a mandate trusts
// the project's own code. The check reads no files either: a symlink that already exists in the project
// and points outside is followed by the commands that use it (a link the command line itself makes is
// resolved from the link's directory and must stay inside). A cd NAME can still land elsewhere when the
// user's own zsh configuration sets cdablevars or CDPATH; the check can't see that.

import (
	"path"
	"strings"
	"time"
	"unicode"
)

const (
	mandateTTL      = 2 * time.Hour
	mandateMaxUses  = 300
	maxMandates     = 10
	optionAllow     = "allow"
	optionTrust     = "trust_2h"
	auditMandateAll = "mandate_allow"
)

type mandate struct {
	ID         string    `json:"id"`
	Device     string    `json:"device"`
	DeviceName string    `json:"device_name,omitempty"`
	SessionID  string    `json:"session_id"`
	Cwd        string    `json:"cwd"`
	Issued     time.Time `json:"issued"`
	Expires    time.Time `json:"expires"`
	MaxUses    int       `json:"max_uses"`
	Uses       int       `json:"uses"`
	Approval   string    `json:"approval,omitempty"`
	// Project is the Rubi Home agent project (claude-agent) the mandate is for; "" for a Claude Code session
	// seen through the hook. A mandate of one never covers the other.
	Project string `json:"project,omitempty"`
}

func (m mandate) live(now time.Time) bool { return now.Before(m.Expires) && m.Uses < m.MaxUses }

// covers says whether a request falls in the mandate's scope (computer, session, directory).
func (m mandate) covers(device string, r request) bool {
	return m.Device == device && m.Project == r.Project && m.SessionID == r.SessionID && within(m.Cwd, r.Cwd)
}

// within: dir is root or under it (both absolute, cleaned).
func within(root, dir string) bool {
	if root == "" || dir == "" || !path.IsAbs(root) || !path.IsAbs(dir) {
		return false
	}
	root, dir = path.Clean(root), path.Clean(dir)
	return dir == root || strings.HasPrefix(dir, strings.TrimSuffix(root, "/")+"/")
}

// ---- the command check ----

type word struct {
	text string
	glob bool // has an unquoted * ? or [
}

type redirect struct {
	op     string // ">", ">>" or "<"
	target word
}

type segment struct {
	words  []word
	redirs []redirect
	next   string // the operator that joins it to the next command: && || ; | &; "" for the last
}

// splitShell splits a command line the way a POSIX shell would for the plain subset the mandate
// accepts: words with quotes, the operators && || ; | & and newlines between commands, and simple
// redirections. Anything else (substitutions, variables, backticks, escapes, subshells, braces, here
// documents, comments, unterminated quotes) is refused with a reason.
func splitShell(s string) ([]segment, string) {
	var segs []segment
	cur := segment{}
	var w strings.Builder
	inWord, glob := false, false
	pendingRedir := ""
	dup := false // after >& or <&: a descriptor number or - duplicates a descriptor, any other word is a file
	bad := ""
	lastOp := "" // the operator before the current command; && || | need one after them
	empty := func() bool { return !inWord && len(cur.words) == 0 && len(cur.redirs) == 0 && pendingRedir == "" }
	endWord := func() string {
		if !inWord {
			return ""
		}
		wd := word{w.String(), glob}
		w.Reset()
		inWord, glob = false, false
		if pendingRedir != "" {
			isDup := dup && (isDigits(wd.text) || wd.text == "-")
			if dup && !isDup && wd.text != "" && wd.text[0] >= '0' && wd.text[0] <= '9' {
				bad = "an ambiguous descriptor redirection"
			}
			if !isDup {
				cur.redirs = append(cur.redirs, redirect{pendingRedir, wd})
			}
			pendingRedir, dup = "", false
			return ""
		}
		cur.words = append(cur.words, wd)
		return ""
	}
	endSeg := func() string {
		endWord()
		if pendingRedir != "" {
			return "a redirection without a target"
		}
		if len(cur.words) == 0 && len(cur.redirs) == 0 {
			return "an empty command"
		}
		segs = append(segs, cur)
		cur = segment{}
		return ""
	}
	r := []rune(s)
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == '\'':
			j := i + 1
			for j < len(r) && r[j] != '\'' {
				j++
			}
			if j >= len(r) {
				return nil, "an unterminated quote"
			}
			w.WriteString(string(r[i+1 : j]))
			inWord = true
			i = j
		case c == '"':
			j := i + 1
			for j < len(r) && r[j] != '"' {
				if r[j] == '$' || r[j] == '`' || r[j] == '\\' {
					return nil, "a substitution or escape inside double quotes"
				}
				j++
			}
			if j >= len(r) {
				return nil, "an unterminated quote"
			}
			w.WriteString(string(r[i+1 : j]))
			inWord = true
			i = j
		case c == ' ' || c == '\t':
			endWord()
		case c == '\n' || c == ';':
			if empty() && (lastOp == "" || lastOp == ";") && c == '\n' {
				continue // blank lines
			}
			if why := endSeg(); why != "" {
				return nil, why
			}
			lastOp = ";"
			segs[len(segs)-1].next = ";"
		case c == '&' || c == '|':
			// "2>&1" and ">&2" duplicate a descriptor: no file.
			if c == '&' && (pendingRedir == ">" || pendingRedir == "<") && !inWord && i > 0 && (r[i-1] == '>' || r[i-1] == '<') {
				dup = true
				continue
			}
			lastOp = string(c)
			if i+1 < len(r) && r[i+1] == c {
				i++
				lastOp += string(c)
			}
			if why := endSeg(); why != "" {
				return nil, why
			}
			segs[len(segs)-1].next = lastOp
		case c == '>' || c == '<':
			if inWord && isDigits(w.String()) { // a descriptor number: 2>
				w.Reset()
				inWord = false
			}
			endWord()
			if pendingRedir != "" {
				return nil, "a redirection without a target"
			}
			op := string(c)
			if i+1 < len(r) && r[i+1] == c {
				if c == '<' {
					return nil, "a here document"
				}
				op += string(c)
				i++
			}
			if i+1 < len(r) && (r[i+1] == '(' || r[i+1] == '|') {
				return nil, "a process substitution"
			}
			pendingRedir = op
		case c == '$' || c == '`':
			return nil, "a substitution or variable"
		case c == '\\':
			return nil, "a backslash escape"
		case strings.ContainsRune("(){}", c):
			return nil, "a subshell or brace group"
		case c == '#' && !inWord:
			return nil, "a comment"
		case c == '*' || c == '?' || c == '[':
			w.WriteRune(c)
			inWord, glob = true, true
		case c < ' ' || c == 0x7f:
			return nil, "a control character"
		default:
			w.WriteRune(c)
			inWord = true
		}
	}
	if why := endSeg(); why != "" {
		if why != "an empty command" || len(segs) == 0 || lastOp != ";" && lastOp != "&" {
			if why == "an empty command" && len(segs) > 0 {
				return nil, "a command ending in " + lastOp
			}
			return nil, why
		}
	}
	if bad != "" {
		return nil, bad
	}
	return segs, ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// mandateAllows says whether a mandate for root lets command run in cwd without asking, and if not why.
func mandateAllows(command, root, cwd string) (bool, string) {
	return mandateAllowsBranch(command, root, cwd, "")
}

// mandateAllowsBranch is mandateAllows for a project trust: when branchPattern isn't empty, a command that
// switches to or creates a git branch is allowed only for a name that matches the pattern (branchRule).
func mandateAllowsBranch(command, root, cwd, branchPattern string) (bool, string) {
	if strings.TrimSpace(command) == "" {
		return false, "empty command"
	}
	if !within(root, cwd) {
		return false, "runs outside the trusted directory"
	}
	segs, why := splitShell(command)
	if why != "" {
		return false, "uses " + why
	}
	// dirs are the places the next command may run in. A cd joined by && moves them; after any other
	// operator the next command may also run where an earlier command ran (a cd that was skipped or failed).
	dirs := []string{path.Clean(cwd)}
	seen := dirs
	for _, sg := range segs {
		var next []string
		isCd := false
		for _, d := range dirs {
			nd, cd, why := checkSegment(sg, root, d, branchPattern)
			if why != "" {
				return false, why
			}
			isCd = cd
			next = addDir(next, nd)
		}
		if isCd && sg.next != "" && sg.next != "&&" {
			return false, "cd joined to the next command by " + sg.next + " (only && keeps the directory)"
		}
		for _, d := range next {
			seen = addDir(seen, d)
		}
		if sg.next == "&&" {
			dirs = next
		} else {
			dirs = seen
		}
		if len(dirs) > 8 {
			return false, "too many working directories"
		}
	}
	return true, "inside the mandate"
}

func addDir(ds []string, d string) []string {
	for _, x := range ds {
		if x == d {
			return ds
		}
	}
	return append(append([]string(nil), ds...), d)
}

// harmlessEnv are the variables a command may set in front of itself (CI=1 go test): names only, matched
// without regard to case; anything else (PATH, CC, GOCACHE, CDPATH, XDG_*, proxies ...) asks.
var harmlessEnv = map[string]bool{"CI": true, "NO_COLOR": true, "FORCE_COLOR": true, "CLICOLOR": true, "CLICOLOR_FORCE": true,
	"TERM": true, "COLUMNS": true, "LINES": true, "LANG": true, "TZ": true, "GOOS": true, "GOARCH": true, "GOARM": true, "GOAMD64": true,
	"GOMAXPROCS": true, "GOGC": true, "GOTRACEBACK": true, "CGO_ENABLED": true, "RUST_BACKTRACE": true, "RUST_LOG": true,
	"NODE_ENV": true, "PYTHONDONTWRITEBYTECODE": true, "PYTHONUNBUFFERED": true, "DEBUG": true, "VERBOSE": true}

func harmlessName(n string) bool {
	u := strings.ToUpper(n)
	return harmlessEnv[u] || strings.HasPrefix(u, "LC_")
}

// checkSegment checks one command and returns the working directory after it (cd) and whether it was a cd.
func checkSegment(sg segment, root, dir, branchPattern string) (string, bool, string) {
	ws := sg.words
	for _, w := range ws {
		if bad := secretIn(w.text); bad != "" {
			return dir, false, "touches a credential path (" + bad + ")"
		}
		if hasURL(w.text) {
			return dir, false, "names a network address (" + oneLine(w.text, 60) + ")"
		}
		if w.glob {
			if why := globCheck(root, dir, w); why != "" {
				return dir, false, why
			}
		}
	}
	for _, rd := range sg.redirs {
		if bad := secretIn(rd.target.text); bad != "" {
			return dir, false, "touches a credential path (" + bad + ")"
		}
		if hasURL(rd.target.text) {
			return dir, false, "names a network address (" + oneLine(rd.target.text, 60) + ")"
		}
		if rd.target.glob {
			if why := globCheck(root, dir, rd.target); why != "" {
				return dir, false, why
			}
		}
		if rd.op != "<" && !devNull(rd.target.text) {
			if why := writeCheck(root, dir, rd.target); why != "" {
				return dir, false, why
			}
		}
	}
	// NAME=value in front of a command.
	for len(ws) > 0 {
		name, _, ok := strings.Cut(ws[0].text, "=")
		if !ok || name == "" || strings.ContainsAny(name, "/.-") {
			break
		}
		if !harmlessName(name) {
			return dir, false, "sets " + name
		}
		if why := envValueCheck(root, dir, ws[0]); why != "" {
			return dir, false, why
		}
		ws = ws[1:]
	}
	if len(ws) == 0 {
		return dir, false, "only sets variables"
	}
	// Wrappers that just run the next word. time and command keep the shell's own builtins; nice, nohup
	// and timeout start an external program, so a cd behind them changes nothing in the shell.
	wrapped := false
	for len(ws) > 1 {
		switch ws[0].text {
		case "time", "command":
			ws = ws[1:]
			continue
		case "nohup":
			wrapped = true
			ws = ws[1:]
			continue
		case "nice", "timeout":
			wrapped = true
			ws = ws[1:]
			for len(ws) > 1 && (strings.HasPrefix(ws[0].text, "-") || isDuration(ws[0].text)) {
				ws = ws[1:]
			}
			continue
		}
		break
	}
	prog := ws[0]
	if prog.glob || strings.Contains(prog.text, "/") {
		return dir, false, "runs a program by path (" + oneLine(prog.text, 60) + ")"
	}
	args := ws[1:]
	name := prog.text
	if why, ok := alwaysAsk[name]; ok {
		return dir, false, name + " always asks (" + why + ")"
	}
	spec, ok := programs[name]
	if !ok {
		return dir, false, name + " isn't on the mandate's list"
	}
	if name == "cd" && wrapped {
		return dir, true, "cd behind a wrapper runs as a program and changes nothing"
	}
	if why := checkArgs(name, spec, args, root, dir, branchPattern); why != "" {
		return dir, name == "cd", why
	}
	if name == "cd" {
		if len(args) == 0 || args[len(args)-1].text == "-" {
			return dir, true, "cd out of the trusted directory"
		}
		return resolve(dir, args[len(args)-1].text), true, ""
	}
	return dir, false, ""
}

// envValueCheck: the value of a NAME=value in front of a command names no place outside the directory,
// no address and no credential.
func envValueCheck(root, dir string, w word) string {
	name, val, _ := strings.Cut(w.text, "=")
	if w.glob {
		return "sets " + name + " to a wildcard"
	}
	if bad := secretIn(val); bad != "" {
		return "sets " + name + " to a credential path (" + bad + ")"
	}
	if hasURL(val) {
		return "sets " + name + " to a network address"
	}
	for _, piece := range strings.FieldsFunc(val, func(c rune) bool { return c == '=' || c == ':' || c == ',' || c == ' ' || c == '\t' }) {
		for _, p := range pathCandidates(piece) {
			if pathish(p) {
				if why := writeCheck(root, dir, word{text: p}); why != "" {
					return "sets " + name + " to a path: " + why
				}
			}
		}
	}
	return ""
}

func isDuration(s string) bool {
	return s != "" && strings.Trim(s, "0123456789.smhd") == "" && s[0] >= '0' && s[0] <= '9'
}

var alwaysAsk = map[string]string{
	"sudo": "runs as another user", "su": "runs as another user", "doas": "runs as another user", "pkexec": "runs as another user",
	"sh": "runs a shell", "bash": "runs a shell", "zsh": "runs a shell", "dash": "runs a shell", "fish": "runs a shell", "ksh": "runs a shell",
	"eval": "runs text as a command", "exec": "replaces the shell", "source": "runs a script in the shell", ".": "runs a script in the shell",
	"env": "runs a command with a changed environment", "xargs": "runs commands from its input",
	"curl": "network", "wget": "network", "ssh": "network", "rubi-ssh": "network", "scp": "network", "sftp": "network", "rsync": "network",
	"nc": "network", "ncat": "network", "netcat": "network", "telnet": "network", "ftp": "network", "socat": "network",
	"gh": "network", "hub": "network", "docker": "containers and registries", "podman": "containers and registries",
	"brew": "installs software", "pip": "installs software", "pip3": "installs software", "gem": "installs software",
	"osascript": "controls other apps", "open": "opens apps and addresses", "launchctl": "system services", "crontab": "scheduled jobs",
	"defaults": "system settings", "security": "the keychain", "dd": "raw disk writes", "shred": "destroys files",
	"diskutil": "disks", "mkfs": "disks", "rubi-home": "Rubi's own helper", "claude": "starts another Claude",
	"awk": "can run commands", "perl": "runs code", "python": "runs code", "python3": "runs code", "ruby": "runs code",
	"node": "runs code", "deno": "runs code", "php": "runs code", "npx": "downloads and runs packages",
}

// writeCheck says why a write to the path w names is refused: outside the directory, or into git's own
// files (a hook or config written there runs at the next git command).
func writeCheck(root, dir string, w word) string {
	if !inside(root, dir, w) {
		return "writes outside the trusted directory (" + w.text + ")"
	}
	if inGitDir(dir, w) {
		return "writes into git's own files (" + w.text + ")"
	}
	return ""
}

func inGitDir(dir string, w word) bool {
	for _, part := range strings.Split(resolve(dir, globPrefix(w)), "/") {
		if strings.EqualFold(part, ".git") {
			return true
		}
	}
	// a wildcard part that starts with a dot or a bracket can match .git (.g*, .gi?/hooks, [.]git)
	if w.glob {
		for _, part := range strings.Split(w.text, "/") {
			i := strings.IndexAny(part, "*?[")
			if i < 0 || part[0] != '.' && part[0] != '[' {
				continue
			}
			if m, err := path.Match(strings.ToLower(part), ".git"); m || err != nil && strings.HasPrefix(".git", strings.ToLower(part[:i])) {
				return true
			}
		}
	}
	return false
}

// inside: the path a word names (relative to dir) is in root. A word starting with ~ is the home
// directory (outside); a glob counts by the part before its first wildcard.
func inside(root, dir string, w word) bool {
	t := globPrefix(w)
	if strings.HasPrefix(t, "~") || strings.HasPrefix(w.text, "~") {
		return false
	}
	// a ".." after the first wildcard (a*/../../x) leaves the prefix the check resolved
	if i := strings.IndexAny(w.text, "*?["); w.glob && i >= 0 {
		for _, part := range strings.Split(w.text[i:], "/") {
			if part == ".." {
				return false
			}
		}
	}
	return within(root, resolve(dir, t))
}

func globPrefix(w word) string {
	i := strings.IndexAny(w.text, "*?[")
	if !w.glob || i < 0 {
		return w.text
	}
	p := w.text[:i]
	if p == "" {
		return "."
	}
	if !strings.HasSuffix(p, "/") {
		p = path.Dir(p)
	}
	return p
}

func resolve(dir, p string) string {
	if path.IsAbs(p) {
		return path.Clean(p)
	}
	return path.Join(dir, p)
}

func devNull(p string) bool { return p == "/dev/null" || p == "/dev/stdout" || p == "/dev/stderr" }

func hasURL(s string) bool {
	l := strings.ToLower(s)
	for _, p := range []string{"http://", "https://", "ssh://", "git://", "ftp://", "file://", "git@"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// secretIn is secretPath for a word that may carry a path after = : or , (--ignore-file=.env, a,b) or
// glued to a short option (-f.env).
func secretIn(s string) string {
	if bad := secretPath(s); bad != "" {
		return bad
	}
	for _, piece := range strings.FieldsFunc(s, func(c rune) bool { return c == '=' || c == ':' || c == ',' || unicode.IsSpace(c) }) {
		if bad := secretPath(piece); bad != "" {
			return bad
		}
		if len(piece) > 2 && piece[0] == '-' && piece[1] != '-' {
			if bad := secretPath(piece[2:]); bad != "" {
				return bad
			}
		}
	}
	return ""
}

// secretNames are path components that hold credentials, settings with tokens or things that run at login.
var secretNames = []string{".ssh", ".aws", ".gnupg", ".kube", ".docker", ".claude", ".claude.json", ".rubi-home", "rubi home", "keychains",
	".git-credentials", ".netrc", ".npmrc", ".pypirc", ".zsh_history", ".bash_history", "launchagents",
	// shell startup files (a line there runs in every new terminal) and per-user settings with tokens
	".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".bashrc", ".bash_profile", ".bash_login", ".profile",
	".gitconfig", ".config", ".vault-token", ".pgpass", ".my.cnf", ".azure", ".gcloud", ".terraform.d",
	".dockercfg", ".s3cfg", ".boto", ".oci", ".mysql_history", ".psql_history", ".python_history", ".node_repl_history", ".m2",
	".codex", ".openai", ".cursor", ".mozilla", "environ",
	// browser sessions: Safari, Chrome, Firefox cookies and Chrome's saved passwords
	"cookies", "cookies.binarycookies", "cookies.sqlite", "login data"}

var (
	secretPrefixes = []string{".env", "id_rsa", "id_ed25519", "id_ecdsa"}
	secretSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".keychain", ".keychain-db"}
	secretInfixes  = []string{"secret", "credential", "password"}
)

func secretName(part string) bool {
	for _, n := range secretNames {
		if part == n {
			return true
		}
	}
	for _, p := range secretPrefixes {
		if strings.HasPrefix(part, p) {
			return true
		}
	}
	for _, suf := range secretSuffixes {
		if strings.HasSuffix(part, suf) {
			return true
		}
	}
	for _, sub := range secretInfixes {
		if strings.Contains(part, sub) {
			return true
		}
	}
	return false
}

// secretPath returns the part of s that names a credential or settings location, or "".
func secretPath(s string) string {
	for _, part := range strings.Split(strings.ToLower(s), "/") {
		part = strings.TrimSpace(part)
		if secretName(part) {
			return part
		}
	}
	return ""
}

// secretCandidates are names a wildcard component is tried against.
func secretCandidates() []string {
	c := append([]string(nil), secretNames...)
	c = append(c, secretPrefixes...)
	c = append(c, ".env.local", "server.pem", "server.key", "login.keychain-db")
	for _, i := range secretInfixes {
		c = append(c, i, i+"s", "my"+i+"s.txt")
	}
	return c
}

// secretGlob returns the credential name a wildcard in s can match (.s?h, id_*, [.]env), or "". A pattern
// needs two literal characters, and one that starts with a wildcard doesn't match a name that starts with a dot.
func secretGlob(s string) string {
	for _, piece := range strings.FieldsFunc(strings.ToLower(s), func(c rune) bool { return c == '=' || c == ':' || c == ',' || unicode.IsSpace(c) }) {
		cands := []string{piece}
		if len(piece) > 2 && piece[0] == '-' && piece[1] != '-' {
			cands = append(cands, piece[2:])
		}
		for _, cand := range cands {
			for _, part := range strings.Split(cand, "/") {
				i := strings.IndexAny(part, "*?[")
				if i < 0 || len(strings.Trim(part, "*?[]")) < 2 {
					continue
				}
				for _, name := range secretCandidates() {
					if name[0] == '.' && part[0] != '.' && part[0] != '[' {
						continue
					}
					if m, _ := path.Match(strings.ReplaceAll(part, "[!", "[^"), name); m {
						return part
					}
				}
			}
		}
	}
	return ""
}

// globCheck: an unquoted wildcard word must be provably inside the directory (not at ~, not absolute outside,
// not a relative path that leaves it: ../../.*/*), and may not match a credential name.
func globCheck(root, dir string, w word) string {
	if !strings.HasPrefix(w.text, "-") && !inside(root, dir, w) {
		return "a wildcard path outside the trusted directory (" + oneLine(w.text, 60) + ")"
	}
	for _, piece := range strings.FieldsFunc(w.text, func(c rune) bool { return c == '=' || c == ':' || c == ',' || unicode.IsSpace(c) }) {
		for _, p := range pathCandidates(piece) {
			if strings.ContainsAny(p, "*?[") && !inside(root, dir, word{text: p, glob: true}) || strings.HasPrefix(p, "~") {
				return "a wildcard path outside the trusted directory (" + oneLine(w.text, 60) + ")"
			}
		}
	}
	if bad := secretGlob(w.text); bad != "" {
		return "a wildcard that can match a credential path (" + bad + ")"
	}
	return ""
}
