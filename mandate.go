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
// credentials. The check reads only the command line:
// a build, test or script it runs (make, go test, npm run) can do anything you can, so a mandate trusts
// the project's own code.

import (
	"path"
	"strings"
	"time"
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
}

func (m mandate) live(now time.Time) bool { return now.Before(m.Expires) && m.Uses < m.MaxUses }

// covers says whether a request falls in the mandate's scope (computer, session, directory).
func (m mandate) covers(device string, r request) bool {
	return m.Device == device && m.SessionID == r.SessionID && within(m.Cwd, r.Cwd)
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
			cur.redirs = append(cur.redirs, redirect{pendingRedir, wd})
			pendingRedir = ""
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
		case c == '&' || c == '|':
			// "2>&1" and ">&2" duplicate a descriptor: no file.
			if c == '&' && pendingRedir == ">" && !inWord && i+1 < len(r) && r[i+1] >= '0' && r[i+1] <= '9' {
				pendingRedir = ""
				i++
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
	dir := path.Clean(cwd)
	for _, sg := range segs {
		next, why := checkSegment(sg, root, dir)
		if why != "" {
			return false, why
		}
		dir = next
	}
	return true, "inside the mandate"
}

var riskyEnv = []string{"PATH", "LD_", "DYLD_", "GIT_", "BASH_ENV", "ENV", "PROMPT_COMMAND", "NODE_OPTIONS", "PYTHON", "PERL5", "RUBYOPT", "HOME", "SHELL", "EDITOR", "VISUAL", "PAGER"}

// checkSegment checks one command and returns the working directory after it (cd).
func checkSegment(sg segment, root, dir string) (string, string) {
	ws := sg.words
	for _, w := range ws {
		if bad := secretPath(w.text); bad != "" {
			return dir, "touches a credential path (" + bad + ")"
		}
		if hasURL(w.text) {
			return dir, "names a network address (" + oneLine(w.text, 60) + ")"
		}
	}
	for _, rd := range sg.redirs {
		if bad := secretPath(rd.target.text); bad != "" {
			return dir, "touches a credential path (" + bad + ")"
		}
		if rd.op != "<" && !devNull(rd.target.text) {
			if why := writeCheck(root, dir, rd.target); why != "" {
				return dir, why
			}
		}
	}
	// NAME=value in front of a command.
	for len(ws) > 0 {
		name, _, ok := strings.Cut(ws[0].text, "=")
		if !ok || name == "" || strings.ContainsAny(name, "/.-") {
			break
		}
		for _, p := range riskyEnv {
			if name == p || strings.HasPrefix(name, p) {
				return dir, "sets " + name
			}
		}
		ws = ws[1:]
	}
	if len(ws) == 0 {
		return dir, "only sets variables"
	}
	// Wrappers that just run the next word.
	for len(ws) > 1 {
		switch ws[0].text {
		case "time", "nohup", "command":
			ws = ws[1:]
			continue
		case "nice", "timeout":
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
		return dir, "runs a program by path (" + oneLine(prog.text, 60) + ")"
	}
	args := ws[1:]
	name := prog.text
	if why, ok := alwaysAsk[name]; ok {
		return dir, name + " always asks (" + why + ")"
	}
	rule, ok := programs[name]
	if !ok {
		return dir, name + " isn't on the mandate's list"
	}
	if why := rule(args, root, dir); why != "" {
		return dir, why
	}
	if name == "cd" {
		if len(args) == 0 || args[len(args)-1].text == "-" {
			return dir, "cd out of the trusted directory"
		}
		return resolve(dir, args[len(args)-1].text), ""
	}
	return dir, ""
}

func isDuration(s string) bool {
	return s != "" && strings.Trim(s, "0123456789.smhd") == "" && s[0] >= '0' && s[0] <= '9'
}

var alwaysAsk = map[string]string{
	"sudo": "runs as another user", "su": "runs as another user", "doas": "runs as another user", "pkexec": "runs as another user",
	"sh": "runs a shell", "bash": "runs a shell", "zsh": "runs a shell", "dash": "runs a shell", "fish": "runs a shell", "ksh": "runs a shell",
	"eval": "runs text as a command", "exec": "replaces the shell", "source": "runs a script in the shell", ".": "runs a script in the shell",
	"env": "runs a command with a changed environment", "xargs": "runs commands from its input",
	"curl": "network", "wget": "network", "ssh": "network", "scp": "network", "sftp": "network", "rsync": "network",
	"nc": "network", "ncat": "network", "netcat": "network", "telnet": "network", "ftp": "network", "socat": "network",
	"gh": "network", "hub": "network", "docker": "containers and registries", "podman": "containers and registries",
	"brew": "installs software", "pip": "installs software", "pip3": "installs software", "gem": "installs software",
	"osascript": "controls other apps", "open": "opens apps and addresses", "launchctl": "system services", "crontab": "scheduled jobs",
	"defaults": "system settings", "security": "the keychain", "dd": "raw disk writes", "shred": "destroys files",
	"diskutil": "disks", "mkfs": "disks", "rubi-home": "Rubi's own helper", "claude": "starts another Claude",
	"awk": "can run commands", "perl": "runs code", "python": "runs code", "python3": "runs code", "ruby": "runs code",
	"node": "runs code", "deno": "runs code", "php": "runs code", "npx": "downloads and runs packages",
}

type argRule func(args []word, root, dir string) string

// programs on the mandate's list, with what each may do.
var programs = map[string]argRule{
	// read-only and harmless
	"ls": noRule, "cat": noRule, "head": noRule, "tail": noRule, "wc": noRule, "grep": noRule,
	"diff": noRule, "cmp": noRule, "jq": noRule, "echo": noRule, "printf": noRule, "pwd": noRule,
	"which": noRule, "file": noRule, "stat": noRule, "du": noRule, "date": noRule, "true": noRule, "false": noRule,
	"test": noRule, "basename": noRule, "dirname": noRule, "realpath": noRule, "readlink": noRule, "tr": noRule,
	"cut": noRule, "shasum": noRule, "sha256sum": noRule, "md5": noRule,
	// read, but an option or operand names a file they write
	"sort": sortRule, "uniq": outputOperand("-f", "-s", "-w"), "xxd": outputOperand("-c", "-cols", "-g", "-groupsize", "-l", "-len", "-o", "-offset", "-s", "-seek", "-n", "-name"),
	"tree": treeRule,
	"rg":   forbidOpts("--pre", "--pre-glob", "--hostname-bin"),
	"find": forbidOpts("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"),
	// writing: every path inside the directory
	"mkdir": pathsInside, "touch": pathsInside, "cp": pathsInside, "mv": pathsInside, "ln": pathsInside,
	"chmod": pathsInside, "tee": pathsInside, "rm": removeInside, "rmdir": removeInside,
	"cd": cdRule,
	// builds and tests: they run the project's own code, but every path on the command line stays inside
	// the directory (outside git's own files) and no option names another program to run
	"go":            noOutside(goRule(noDownloads(subcommands("build", "test", "vet", "fmt", "run", "list", "env", "version", "mod", "work", "doc", "generate", "tool", "clean")))),
	"gofmt":         pathsInside,
	"make":          noOutside(makeRule),
	"cargo":         noOutside(forbidThen([]string{"--config", "-Z"}, noPublish(subcommands("build", "test", "check", "fmt", "clippy", "run", "doc", "bench", "tree", "metadata", "clean")))),
	"npm":           noOutside(forbidThen(npmExec, noPublish(subcommands("test", "run", "ls", "outdated", "version")))),
	"pnpm":          noOutside(forbidThen(npmExec, noPublish(subcommands("test", "run", "ls", "outdated")))),
	"yarn":          noOutside(forbidThen(npmExec, noPublish(subcommands("test", "run")))),
	"swift":         noOutside(subcommands("build", "test", "run")),
	"pytest":        noOutside(noRule),
	"git":           gitRule,
	"golangci-lint": noOutside(noRule), "staticcheck": noOutside(noRule),
}

func noRule([]word, string, string) string { return "" }

// forbidOpts refuses the named options, alone or as -opt=value (a two-letter one also glued, -Zx).
func forbidOpts(opts ...string) argRule { return forbidThen(opts, noRule) }

// forbidThen refuses opts, then applies r.
func forbidThen(opts []string, r argRule) argRule {
	return func(args []word, root, dir string) string {
		for _, a := range args {
			for _, o := range opts {
				if a.text == o || strings.HasPrefix(a.text, o+"=") || len(o) == 2 && o[1] != '-' && strings.HasPrefix(a.text, o) {
					return "option " + o + " runs or changes things"
				}
			}
		}
		return r(args, root, dir)
	}
}

// npmExec are npm, pnpm and yarn options that name a program or code to run.
var npmExec = []string{"--script-shell", "--node-options"}

func subcommands(allowed ...string) argRule {
	return func(args []word, root, dir string) string {
		for i := 0; i < len(args); i++ {
			a := args[i].text
			if a == "-C" && i+1 < len(args) { // go -C dir, make -C dir
				if !inside(root, dir, args[i+1]) {
					return "works outside the trusted directory (" + args[i+1].text + ")"
				}
				i++
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			for _, s := range allowed {
				if a == s {
					return ""
				}
			}
			return "subcommand " + a + " isn't on the mandate's list"
		}
		return "no subcommand"
	}
}

// noPublish refuses script and target names that look like publishing (npm run deploy).
func noPublish(r argRule) argRule {
	return func(args []word, root, dir string) string {
		for _, a := range args {
			if publishing(a.text) {
				return a.text + " looks like publishing"
			}
		}
		return r(args, root, dir)
	}
}

func publishing(s string) bool {
	l := strings.ToLower(s)
	for _, p := range []string{"push", "publish", "release", "deploy", "upload"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// noDownloads refuses module@version arguments (go run x@latest fetches code).
func noDownloads(r argRule) argRule {
	return func(args []word, root, dir string) string {
		for _, a := range args {
			if strings.Contains(a.text, "@") {
				return "downloads a module (" + a.text + ")"
			}
		}
		return r(args, root, dir)
	}
}

func makeRule(args []word, root, dir string) string {
	for i := 0; i < len(args); i++ {
		a := args[i].text
		switch {
		case a == "--eval" || strings.HasPrefix(a, "--eval=") || strings.HasPrefix(a, "-E"):
			return "make --eval runs the text it is given"
		case !strings.HasPrefix(a, "-") && strings.Contains(a, "="):
			// VAR=value overrides a variable the Makefile may run (CC, SHELL): a plain value only.
			name, val, _ := strings.Cut(a, "=")
			if n := strings.ToUpper(strings.TrimSuffix(strings.TrimSuffix(name, ":"), "+")); n == "SHELL" || n == ".SHELLFLAGS" || n == "MAKEFLAGS" || n == "MFLAGS" || n == "MAKESHELL" {
				return "make " + name + "= changes how recipes run"
			}
			if strings.ContainsAny(val, " \t;|&<>()$`'\"\\") {
				return "make " + name + "= with a command-like value"
			}
		case a == "-C" || a == "-f" || a == "--directory" || a == "--file" || a == "--makefile":
			if i+1 >= len(args) || !inside(root, dir, args[i+1]) {
				return "make outside the trusted directory"
			}
			i++
		case publishing(a):
			return "make target " + a + " looks like publishing"
		}
	}
	return ""
}

func pathsInside(args []word, root, dir string) string {
	for _, a := range args {
		if strings.HasPrefix(a.text, "-") {
			// --target-directory=DIR, -tDIR: a path glued to an option.
			if v := optionValue(a.text); v != "" && pathish(v) {
				if why := writeCheck(root, dir, word{text: v}); why != "" {
					return why
				}
			}
			continue
		}
		if why := writeCheck(root, dir, a); why != "" {
			return why
		}
	}
	return ""
}

// cdRule: cd stays in the directory.
func cdRule(args []word, root, dir string) string {
	for _, a := range args {
		if !strings.HasPrefix(a.text, "-") && !inside(root, dir, a) {
			return "goes outside the trusted directory (" + a.text + ")"
		}
	}
	return ""
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
		if part == ".git" {
			return true
		}
	}
	return false
}

// optionValue is the value glued to an option: after = (--out=x), or after the letter (-ox).
func optionValue(a string) string {
	if _, v, ok := strings.Cut(a, "="); ok {
		return v
	}
	if len(a) > 2 && a[0] == '-' && a[1] != '-' {
		return a[2:]
	}
	return ""
}

// pathish: s may name a place outside the working directory.
func pathish(s string) bool {
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return true
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." || part == ".git" {
			return true
		}
	}
	return false
}

// noOutside wraps a build or test tool's rule: no word on its command line, nor a value inside one
// (-o=/x, cache_dir=/x, html:/x, a,b), names a place outside the directory or in git's own files. These
// tools write outputs, caches and reports wherever they are told to.
func noOutside(r argRule) argRule {
	return func(args []word, root, dir string) string {
		for _, a := range args {
			for _, piece := range strings.FieldsFunc(a.text, func(c rune) bool { return c == '=' || c == ':' || c == ',' }) {
				p := strings.TrimLeft(piece, "-")
				if len(piece) > 2 && piece[0] == '-' && piece[1] != '-' && !pathish(p) {
					p = piece[2:] // -o/x
				}
				if pathish(p) {
					if why := writeCheck(root, dir, word{text: p, glob: a.glob}); why != "" {
						return why
					}
				}
			}
		}
		return r(args, root, dir)
	}
}

// goRule refuses go options that run another program (-exec, -toolexec), go env -w/-u (writes Go's own
// settings file) and go clean of the shared caches.
func goRule(r argRule) argRule {
	return func(args []word, root, dir string) string {
		sub := ""
		for _, a := range args {
			t := a.text
			name, _, _ := strings.Cut(strings.TrimLeft(t, "-"), "=")
			if strings.HasPrefix(t, "-") {
				switch name {
				case "exec", "toolexec":
					return "go -" + name + " runs another program"
				case "w", "u":
					if sub == "env" {
						return "go env -" + name + " changes Go's settings"
					}
				case "cache", "modcache", "fuzzcache":
					if sub == "clean" {
						return "go clean -" + name + " deletes outside the trusted directory"
					}
				}
				continue
			}
			if sub == "" {
				sub = t
			}
		}
		return r(args, root, dir)
	}
}

// sortRule: sort reads anything, but -o/--output and -T/--temporary-directory write, and
// --compress-program runs a program.
func sortRule(args []word, root, dir string) string {
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if strings.HasPrefix(t, "--compress-program") {
			return "sort --compress-program runs another program"
		}
		var target string
		has := false
		switch {
		case t == "--output" || t == "--temporary-directory":
			has = true
			if i+1 < len(args) {
				target = args[i+1].text
				i++
			}
		case strings.HasPrefix(t, "--output=") || strings.HasPrefix(t, "--temporary-directory="):
			has, target = true, t[strings.Index(t, "=")+1:]
		case len(t) > 1 && t[0] == '-' && t[1] != '-':
			// a short cluster: -o FILE, -oFILE, -uo FILE (o or T takes the rest or the next word)
			if j := strings.IndexAny(t[1:], "oT"); j >= 0 {
				has = true
				if rest := t[j+2:]; rest != "" {
					target = rest
				} else if i+1 < len(args) {
					target = args[i+1].text
					i++
				}
			}
		}
		if has {
			if target == "" {
				return "sort output without a file"
			}
			if why := writeCheck(root, dir, word{text: target}); why != "" {
				return why
			}
		}
	}
	return ""
}

// outputOperand is for uniq and xxd: [INPUT [OUTPUT]], where the second operand is written. valued are
// the options that take a separate value.
func outputOperand(valued ...string) argRule {
	return func(args []word, root, dir string) string {
		n := 0
		for i := 0; i < len(args); i++ {
			t := args[i].text
			if strings.HasPrefix(t, "-") && t != "-" {
				for _, v := range valued {
					if t == v {
						i++
					}
				}
				continue
			}
			n++
			if n >= 2 {
				if why := writeCheck(root, dir, args[i]); why != "" {
					return why
				}
			}
		}
		return ""
	}
}

// treeRule: tree -o FILE writes FILE.
func treeRule(args []word, root, dir string) string {
	for i := 0; i < len(args); i++ {
		t := args[i].text
		target, has := "", false
		switch {
		case t == "-o":
			has = true
			if i+1 < len(args) {
				target = args[i+1].text
				i++
			}
		case strings.HasPrefix(t, "-o"):
			has, target = true, t[2:]
		}
		if has {
			if target == "" {
				return "tree -o without a file"
			}
			if why := writeCheck(root, dir, word{text: target}); why != "" {
				return why
			}
		}
	}
	return ""
}

func removeInside(args []word, root, dir string) string {
	if why := pathsInside(args, root, dir); why != "" {
		return strings.Replace(why, "writes", "removes", 1)
	}
	for _, a := range args {
		if strings.HasPrefix(a.text, "-") {
			continue
		}
		p := resolve(dir, globPrefix(a))
		if p == path.Clean(root) {
			return "removes the whole trusted directory"
		}
		for _, part := range strings.Split(p, "/") {
			if part == ".git" {
				return "removes git's own files"
			}
		}
	}
	return ""
}

// git subcommands a mandate allows; everything else (push, fetch, pull, clone, remote, config,
// submodule, filter-branch, reset, clean, aliases …) asks.
var gitAllowed = map[string]bool{"status": true, "diff": true, "log": true, "show": true, "add": true, "commit": true,
	"switch": true, "checkout": true, "restore": true, "branch": true, "stash": true, "merge": true, "rebase": true,
	"cherry-pick": true, "revert": true, "mv": true, "rm": true, "blame": true, "grep": true, "rev-parse": true,
	"ls-files": true, "describe": true, "shortlog": true, "show-ref": true, "cat-file": true, "worktree": true}

var gitForbidden = []string{"--force", "-f", "--force-with-lease", "--exec", "-x", "--exec-path", "--upload-pack",
	"--receive-pack", "--ext-diff", "--textconv", "--output", "-o", "--hard", "--merge", "--keep", "-D", "--delete",
	"--discard-changes", "--git-dir", "--work-tree", "-c", "--config-env",
	"-O", "--open-files-in-pager"} // git grep -O<program> runs it on the matches

// gitForbiddenShort are one-letter git options that force, delete or run things (also inside -xyz).
const gitForbiddenShort = "fDxocO"

func gitRule(args []word, root, dir string) string {
	i := 0
	for ; i < len(args); i++ {
		a := args[i].text
		if a == "-C" {
			if i+1 >= len(args) || !inside(root, dir, args[i+1]) {
				return "git outside the trusted directory"
			}
			i++
			continue
		}
		if a == "--no-pager" || a == "-P" || a == "--no-optional-locks" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			return "git option " + a + " isn't on the mandate's list"
		}
		break
	}
	if i >= len(args) {
		return "git without a command"
	}
	sub := args[i].text
	if sub == "push" {
		return "git push always asks"
	}
	if !gitAllowed[sub] {
		return "git " + sub + " isn't on the mandate's list"
	}
	rest := args[i+1:]
	for _, a := range rest {
		for _, f := range gitForbidden {
			if a.text == f || strings.HasPrefix(a.text, f+"=") {
				return "git option " + f + " always asks"
			}
		}
		if t := a.text; len(t) > 2 && t[0] == '-' && t[1] != '-' && strings.ContainsAny(t[1:], gitForbiddenShort) {
			return "git option " + t + " always asks"
		}
	}
	switch sub {
	case "checkout", "restore":
		for _, a := range rest {
			if a.text == "." || a.text == "--" && sub == "checkout" {
				return "git " + sub + " that discards changes always asks"
			}
		}
	case "worktree":
		if len(rest) > 0 && (rest[0].text == "remove" || rest[0].text == "prune") {
			return "git worktree " + rest[0].text + " always asks"
		}
		if len(rest) > 0 && (rest[0].text == "add" || rest[0].text == "move") {
			// every operand (the new worktree's path, a branch, a commit) as a path: a branch name is a
			// relative path inside, so only real places outside are refused
			for j := 1; j < len(rest); j++ {
				t := rest[j].text
				if t == "-b" || t == "-B" || t == "--reason" {
					j++
					continue
				}
				if strings.HasPrefix(t, "-") {
					continue
				}
				if why := writeCheck(root, dir, rest[j]); why != "" {
					return "git worktree " + rest[0].text + " " + why
				}
			}
		}
	case "stash":
		if len(rest) > 0 && (rest[0].text == "drop" || rest[0].text == "clear") {
			return "git stash " + rest[0].text + " always asks"
		}
	case "mv", "rm":
		return pathsInside(rest, root, dir)
	}
	return ""
}

// inside: the path a word names (relative to dir) is in root. A word starting with ~ is the home
// directory (outside); a glob counts by the part before its first wildcard.
func inside(root, dir string, w word) bool {
	t := globPrefix(w)
	if strings.HasPrefix(t, "~") {
		return false
	}
	return within(root, resolve(dir, t))
}

func globPrefix(w word) string {
	if !w.glob {
		return w.text
	}
	i := strings.IndexAny(w.text, "*?[")
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

// secretPath returns the part of s that names a credential or settings location, or "".
func secretPath(s string) string {
	for _, part := range strings.Split(strings.ToLower(s), "/") {
		part = strings.TrimSpace(part)
		switch part {
		case ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".claude", ".claude.json", ".rubi-home", "rubi home", "keychains",
			".git-credentials", ".netrc", ".npmrc", ".pypirc", ".zsh_history", ".bash_history", "launchagents",
			// shell startup files (a line there runs in every new terminal) and per-user settings with tokens
			".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".bashrc", ".bash_profile", ".bash_login", ".profile",
			".gitconfig", ".config", ".vault-token", ".pgpass", ".my.cnf", ".azure", ".gcloud", ".terraform.d",
			// browser sessions: Safari, Chrome, Firefox cookies and Chrome's saved passwords
			"cookies", "cookies.binarycookies", "cookies.sqlite", "login data":
			return part
		}
		if strings.HasPrefix(part, ".env") || strings.HasPrefix(part, "id_rsa") || strings.HasPrefix(part, "id_ed25519") ||
			strings.HasPrefix(part, "id_ecdsa") {
			return part
		}
		for _, suf := range []string{".pem", ".key", ".p12", ".pfx", ".keychain", ".keychain-db"} {
			if strings.HasSuffix(part, suf) {
				return part
			}
		}
		for _, sub := range []string{"secret", "credential", "password"} {
			if strings.Contains(part, sub) {
				return part
			}
		}
	}
	return ""
}
