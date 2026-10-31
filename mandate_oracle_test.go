package main

// The generator and the oracle behind FuzzMandate. The oracle is independent of the production code: it
// has its own tokenizer (simple and conservative: anything it does not understand makes it treat every
// word as a possible write path and every program as a writing one), its own credential and .git checks
// and its own rules, and it never reads the spec table.

import (
	"path"
	"strings"
	"testing"
)

var fuzzProgs = []string{"ls", "cat", "head", "tail", "wc", "grep", "rg", "diff", "cmp", "jq", "echo", "printf", "pwd", "which", "file",
	"stat", "du", "date", "true", "false", "test", "basename", "dirname", "realpath", "readlink", "tr", "cut", "shasum", "sha256sum", "md5",
	"sort", "uniq", "xxd", "tree", "find", "mkdir", "touch", "cp", "mv", "ln", "chmod", "tee", "rm", "rmdir", "cd", "cd", "cd", "go", "gofmt", "make",
	"cargo", "npm", "pnpm", "yarn", "swift", "pytest", "git", "golangci-lint", "staticcheck",
	"sudo", "curl", "sh", "env", "xargs", "python3", "awk", "open", "foo", "bar"}

var fuzzSubs = []string{"build", "test", "vet", "run", "list", "env", "mod", "clean", "get", "install", "tidy", "status", "diff", "log",
	"show", "add", "commit", "push", "checkout", "restore", "switch", "branch", "stash", "worktree", "rebase", "merge", "grep", "drop",
	"clear", "remove", "prune", "publish", "deploy", "move", "check", "fmt", "clippy", "doc", "ls", "outdated", "version", "cover", "pop",
	"generate", "download", "-b", "-B", "--staged", "-S", "-W", "-s", "--source=HEAD", "--worktree", "-p"}

var fuzzOpts = []string{"-v", "-n", "-r", "-f", "-l", "-a", "-p", "-o", "-t", "-c", "-C", "-x", "-i", "-e", "-s", "-m", "-b", "-d", "-w",
	"-u", "-j", "-k", "-q", "-R", "-L", "-O", "-E", "-Z", "-I", "-T", "-S", "-X", "-D", "-F", "-G", "-P", "-M", "-U3", "-20", "-A", "-B",
	"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fls", "--pre", "--pre-glob", "--hostname-bin",
	"--open-files-in-pager", "--open-files-in-pager=vim", "-Ovim", "-exec=echo", "-toolexec", "-toolexec=x", "-vettool", "--eval",
	"--eval=x", "--config", "--config=x", "-Zx", "--script-shell", "--script-shell=sh", "--node-options", "--node-options=x",
	"--compress-program", "--compress-program=gzip", "--output", "--output=out.txt", "--output=/tmp/x", "--target-dir", "--prefix",
	"--basetemp", "--basetemp=/tmp/x", "-tx", "-t/tmp", "-race", "-count=1", "-run", "--release", "--all", "--force", "--hard", "--frob",
	"-zq", "--color", "--color=never", "--stat", "--oneline", "--cached", "--no-edit", "--amend", "--continue", "--abort", "--include",
	"--exclude", "--files-from", "--target-directory", "--target-directory=/tmp", "--", "-", "-o/tmp/x", "-coverprofile=/tmp/c",
	"-C..", "--cwd=..", "--manifest-path", "--junitxml=/tmp/x", "-c", "--ext-diff", "--textconv", "--exec", "--edit", "--interactive",
	"-gcflags='-o /Users/alice/x'", "-ldflags='-o /Users/alice/x'", "-ldflags='-s -w'", "-gcflags='all=-N -l'", "-ldflags='-extar sh'", "-o addopts='--junitxml /tmp/x'",
	"-o log_cli=true", "-f -", "-f-", "--file=-", "-s", "--symbolic", "-t", "--staged", "-S", "--worktree", "-W", "--source=HEAD", "-gcflags=-cpuprofile=/tmp/x"}

var fuzzOperands = []string{"a.txt", "sub/b.go", "./", "src/main.go", "/Users/alice/project/out", "/Users/alice/project/x/../y.txt", "/tmp/x",
	"../x", "~/x", ".git/hooks/x", ".git", "/Users/alice/.zshrc", "/Users/alice/.ssh/id_rsa", ".env", "https://example.com/x", "git@host:r/p.git",
	"HEAD", "main", "755", "+x", "k=v", "CC=gcc", "SHELL=sh", "release", "build", "*.go", "sub/*", "/tmp/*", "~", "..", ".", "-n5",
	"/Users/alice/project/.git/config", "/Users/alice/project/sub/../.git/x", "/Users/alice/project/../x", "x:/tmp/y", "a,/tmp/b", "html:/tmp/c",
	"/Users/alice/Documents/secrets/x", "./.git/x", "sub/.git", "-",
	".GIT/hooks/x", ".Git", "sub/.GiT/x", ".GIT", "'a b/../../x'", "'-o /Users/alice/x'", "'a b'", "../..", "../", "sub", "nosuch", "l", "../Documents",
	"~/.s?h/i*", "./.s?h/i*", "~/.s[s]h/id_*", "./.e*", "*", "i*", ".s[s]h", "'$(id)'", "'$(shell touch /tmp/pwned)'", "'x=$(shell id)'",
	"CC=./cc", "V=1", "X=a/b", "GOFLAGS=-toolexec=sh", "/etc/*", "1/../../pwned", "2foo", "link"}

var fuzzEnvs = []string{"", "", "", "", "", "FOO=1 ", "CI=1 ", "CC=sh ", "CC='sh -c id' ", "GOCACHE=/Users/alice/x ", "CDPATH=/ ", "XDG_CONFIG_HOME=evil ", "path=/x ",
	"IFS=x ", "TMPDIR=/Users/alice/x ", "GOOS=linux ", "TZ=UTC ", "NO_COLOR=1 ", "MAKEFILES=/x ", "GNUMAKEFLAGS=--eval=x ", "CI=../x ", "CI=.GIT/x ", "time ", "nice -n 5 ", "timeout 5 ", "command "}

var fuzzSeps = []string{" ; ", " && ", " | ", "\n", " || ", " & ", " && ", " && "}

var fuzzRedirs = []string{" > ", " >> ", " < ", " >& ", " >&", " 2>&", " &> ", " >| "}

var fuzzRedirTargets = []string{"out.txt", "/dev/null", "/tmp/x", "../x", "~/x", ".git/hooks/x", "/Users/alice/project/y", "/Users/alice/.zshrc", "sub/z",
	"/Users/alice/project/.git/x", "./.git/config", ".GIT/hooks/x", "1/../../pwned", "2foo", "1", "2", "-", "l/pwn", "3x"}

type byteSrc struct {
	b []byte
	i int
}

func (s *byteSrc) next() int {
	if s.i >= len(s.b) {
		return 0
	}
	s.i++
	return int(s.b[s.i-1])
}

func pick(s *byteSrc, from []string) string { return from[s.next()%len(from)] }

// fuzzCommand builds a command line from the bytes, or uses them as the command if they start with 0xff
// (the seeds are whole commands).
func fuzzCommand(data []byte) string {
	if len(data) > 0 && data[0] == 0xff {
		return string(data[1:])
	}
	s := &byteSrc{b: data}
	var sb strings.Builder
	for n := 1 + s.next()%3; n > 0; n-- {
		sb.WriteString(pick(s, fuzzEnvs))
		sb.WriteString(pick(s, fuzzProgs))
		for k := s.next() % 8; k > 0; k-- {
			c := s.next()
			switch {
			case c < 100:
				sb.WriteString(" " + pick(s, fuzzOpts))
			case c < 180:
				sb.WriteString(" " + pick(s, fuzzOperands))
			case c < 215:
				sb.WriteString(" " + pick(s, fuzzSubs))
			case c < 235:
				sb.WriteString(" " + pick(s, fuzzOpts) + "=" + pick(s, fuzzOperands))
			default: // a value glued to the option: -ox, --out=x
				o := pick(s, fuzzOpts)
				if len(o) > 2 && !strings.Contains(o, "=") {
					o += "="
				}
				sb.WriteString(" " + o + pick(s, fuzzOperands))
			}
		}
		if r := s.next() % 12; r < len(fuzzRedirs) {
			sb.WriteString(fuzzRedirs[r] + pick(s, fuzzRedirTargets))
		}
		if n > 1 {
			sb.WriteString(pick(s, fuzzSeps))
		}
	}
	return sb.String()
}

// ---- the oracle's own tokenizer ----

type otok struct {
	text string
	glob bool
}

type oredir struct {
	op     string // > >> < >& <& &> >|
	target string
	glob   bool
}

type oseg struct {
	words  []otok
	redirs []oredir
	sep    string // && || ; | & or "" after the last
}

// oTokenize splits a command line into segments. unknown says it met something it does not model
// (a substitution, an escape, a subshell, a comment, a here document); then the oracle is maximally strict.
func oTokenize(cmd string) (segs []oseg, unknown bool) {
	var cur oseg
	var w strings.Builder
	inWord, glob := false, false
	pending := ""
	flush := func() {
		if !inWord {
			return
		}
		t := w.String()
		if pending != "" {
			cur.redirs = append(cur.redirs, oredir{pending, t, glob})
			pending = ""
		} else {
			cur.words = append(cur.words, otok{t, glob})
		}
		w.Reset()
		inWord, glob = false, false
	}
	endSeg := func(sep string) {
		flush()
		if len(cur.words) > 0 || len(cur.redirs) > 0 {
			cur.sep = sep
			segs = append(segs, cur)
		}
		cur = oseg{}
	}
	r := []rune(cmd)
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == '\'':
			j := i + 1
			for j < len(r) && r[j] != '\'' {
				j++
			}
			if j >= len(r) {
				return segs, true
			}
			w.WriteString(string(r[i+1 : j]))
			inWord = true
			i = j
		case c == '"':
			j := i + 1
			for j < len(r) && r[j] != '"' {
				if r[j] == '$' || r[j] == '`' || r[j] == '\\' {
					unknown = true
				}
				j++
			}
			if j >= len(r) {
				return segs, true
			}
			w.WriteString(string(r[i+1 : j]))
			inWord = true
			i = j
		case c == ' ' || c == '\t':
			flush()
		case c == '\n' || c == ';':
			endSeg(";")
		case c == '&' && i+1 < len(r) && r[i+1] == '&':
			endSeg("&&")
			i++
		case c == '|' && i+1 < len(r) && r[i+1] == '|':
			endSeg("||")
			i++
		case c == '|':
			endSeg("|")
		case c == '&' && i+1 < len(r) && r[i+1] == '>':
			flush()
			pending = "&>"
			i++
		case c == '&':
			endSeg("&")
		case c == '>' || c == '<':
			if inWord && isDigitsOnly(w.String()) { // a descriptor number in front
				w.Reset()
				inWord = false
			}
			flush()
			op := string(c)
			for i+1 < len(r) && strings.ContainsRune(">&|", r[i+1]) && len(op) < 3 {
				op += string(r[i+1])
				i++
			}
			pending = op
		case strings.ContainsRune("$`\\(){}", c) || c == '#' && !inWord:
			unknown = true
			w.WriteRune(c)
			inWord = true
		default:
			if c == '*' || c == '?' || c == '[' {
				glob = true
			}
			w.WriteRune(c)
			inWord = true
		}
	}
	endSeg("")
	return segs, unknown
}

func isDigitsOnly(s string) bool {
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

// ---- the oracle's own rules ----

var oracleWriters = map[string]bool{"mkdir": true, "touch": true, "cp": true, "mv": true, "chmod": true, "tee": true, "rm": true,
	"rmdir": true, "go": true, "gofmt": true, "make": true, "cargo": true, "npm": true, "pnpm": true, "yarn": true, "swift": true,
	"pytest": true, "golangci-lint": true, "staticcheck": true}

// oracleExec are, per program, the options that run another program (matched as the word, word=value, or
// for two-letter ones glued).
var oracleExec = map[string][]string{
	"find": {"-exec", "-execdir", "-ok", "-okdir", "-delete"}, "rg": {"--pre", "--pre-glob", "--hostname-bin"},
	"git": {"-O", "--open-files-in-pager"}, "go": {"-exec", "-toolexec"}, "make": {"--eval", "-E"}, "cargo": {"--config", "-Z"},
	"npm": {"--script-shell", "--node-options"}, "pnpm": {"--script-shell", "--node-options"}, "yarn": {"--script-shell", "--node-options"},
	"sort": {"--compress-program"},
}

var oracleSecretNames = []string{".ssh", ".aws", ".zshrc", ".bashrc", ".gnupg", ".netrc", ".npmrc", ".git-credentials", "cookies", ".kube",
	".dockercfg", ".s3cfg", ".boto", ".oci", ".mysql_history", ".psql_history", ".m2", ".codex", ".openai", ".cursor", ".mozilla", "environ"}

// oracleHarmlessEnv are the only variables an allowed command may set in front of itself.
var oracleHarmlessEnv = map[string]bool{"CI": true, "NO_COLOR": true, "FORCE_COLOR": true, "TERM": true, "TZ": true, "GOOS": true, "GOARCH": true,
	"CGO_ENABLED": true, "RUST_BACKTRACE": true, "RUST_LOG": true, "NODE_ENV": true, "DEBUG": true, "VERBOSE": true, "LANG": true, "COLUMNS": true,
	"GOMAXPROCS": true, "GOGC": true, "LINES": true}

var oracleMakeTools = []string{"CC", "CXX", "CPP", "LD", "AR", "AS", "SHELL", "MAKE", "MAKEFILES", "MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS"}

func oLowerSplit(w string) []string {
	return strings.FieldsFunc(strings.ToLower(w), func(c rune) bool { return c == '=' || c == ':' || c == ',' || strings.ContainsRune(" \t\n\r\v\f", c) })
}

// oracleSecret says a word names a credential: one of its path components (also after = : , or a glued
// short option) is a known name, starts with .env or id_rsa, or has secret or credential in it; or a
// wildcard component can match such a name.
func oracleSecret(w string, glob bool) bool {
	for _, piece := range oLowerSplit(w) {
		cands := []string{piece}
		if len(piece) > 2 && piece[0] == '-' && piece[1] != '-' {
			cands = append(cands, piece[2:])
		}
		for _, cand := range cands {
			for _, part := range strings.Split(cand, "/") {
				if strings.HasPrefix(part, ".env") || strings.HasPrefix(part, "id_rsa") || strings.HasPrefix(part, "id_ed25519") ||
					strings.Contains(part, "secret") || strings.Contains(part, "credential") {
					return true
				}
				for _, n := range oracleSecretNames {
					if part == n {
						return true
					}
				}
				if glob && strings.ContainsAny(part, "*?[") && len(strings.Trim(part, "*?[]")) >= 2 {
					for _, n := range append([]string{".env", "id_rsa", "secret", "credentials"}, oracleSecretNames...) {
						if n[0] == '.' && part[0] != '.' && part[0] != '[' {
							continue
						}
						if m, _ := path.Match(part, n); m {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// oracleInside says the path p (relative to dir) is inside root and not under .git (any case). A glob
// counts by the directory before its first wildcard; a wildcard part that can match .git, or a .. after
// it, is outside.
func oracleInside(dir, p string, glob bool) bool {
	if strings.HasPrefix(p, "~") {
		return false
	}
	if i := strings.IndexAny(p, "*?["); glob && i >= 0 {
		for _, part := range strings.Split(p[i:], "/") {
			if part == ".." {
				return false
			}
		}
		for _, part := range strings.Split(p, "/") {
			if strings.ContainsAny(part, "*?[") {
				if m, _ := path.Match(strings.ToLower(part), ".git"); m && !strings.HasPrefix(part, "*") && !strings.HasPrefix(part, "?") {
					return false
				}
			}
		}
		p = p[:strings.LastIndex(p[:i], "/")+1]
	}
	if !strings.HasPrefix(p, "/") {
		p = dir + "/" + p
	}
	p = path.Clean(p)
	if p != root && !strings.HasPrefix(p, root+"/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if strings.EqualFold(part, ".git") {
			return false
		}
	}
	return true
}

func pathLike(s string) bool {
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return true
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." || strings.EqualFold(part, ".git") {
			return true
		}
	}
	return false
}

// oPieces are the places a word may name a path: itself and its pieces split at = : , and white space,
// each also without leading dashes and without a glued short option letter.
func oPieces(w string) []string {
	var out []string
	for _, piece := range strings.FieldsFunc(w, func(c rune) bool { return c == '=' || c == ':' || c == ',' || strings.ContainsRune(" \t\n\r\v\f", c) }) {
		out = append(out, strings.TrimLeft(piece, "-"))
		if len(piece) > 2 && piece[0] == '-' && piece[1] != '-' {
			out = append(out, piece[2:])
		}
	}
	return out
}

func oracleURL(l string) bool {
	for _, p := range []string{"http://", "https://", "ssh://", "git://", "ftp://", "ftps://", "file://", "git@"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func oracleGitSub(args []string) string {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-C":
			i++
		case strings.HasPrefix(args[i], "-"):
		default:
			return args[i]
		}
	}
	return ""
}

func oracleExecHit(prog string, args []string) string {
	if prog == "git" && oracleGitSub(args) != "grep" {
		return ""
	}
	for _, w := range args {
		for _, n := range oracleExec[prog] {
			base, _, _ := strings.Cut(w, "=")
			if prog == "go" && strings.HasPrefix(w, "-") {
				base = "-" + strings.TrimLeft(base, "-")
			}
			if base == n || len(n) == 2 && strings.HasPrefix(w, n) {
				return w
			}
		}
	}
	return ""
}

func nonDash(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func has(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n || strings.HasPrefix(a, n+"=") {
				return true
			}
		}
	}
	return false
}

// checkOracle runs the command through mandateAllows and, if it is allowed, checks what an allowed command
// must never have. It reports through t.
func checkOracle(t *testing.T, cmd string) {
	t.Helper()
	if ok, _ := mandateAllows(cmd, root, root); !ok {
		return
	}
	fail := func(format string, a ...any) {
		t.Helper()
		t.Fatalf("allowed: "+format+": %q", append(a, cmd)...)
	}
	segs, unknown := oTokenize(cmd)
	dirs := []string{root}
	seen := dirs
	for _, sg := range segs {
		anyGlob := unknown // a quoted wildcard is a plain character
		for _, w := range sg.words {
			anyGlob = anyGlob || w.glob
		}
		for _, rd := range sg.redirs {
			anyGlob = anyGlob || rd.glob
		}
		inAllG := func(p string, glob bool) bool {
			for _, d := range dirs {
				if !oracleInside(d, p, glob) {
					return false
				}
			}
			return true
		}
		inAll := func(p string) bool { return inAllG(p, anyGlob) }
		for _, rd := range sg.redirs {
			fd := (rd.op == ">&" || rd.op == "<&") && (isDigitsOnly(rd.target) || rd.target == "-")
			writes := strings.Contains(rd.op, ">")
			if writes && !fd && rd.target != "/dev/null" && !inAllG(rd.target, rd.glob || unknown) {
				fail("redirection %s writes %q", rd.op, rd.target)
			}
		}
		ws := append([]otok(nil), sg.words...)
		for _, rd := range sg.redirs {
			ws = append(ws, otok{rd.target, rd.glob})
		}
		for _, w := range sg.words {
			if w.glob && (strings.HasPrefix(w.text, "~") || strings.HasPrefix(w.text, "/") && !inAll(w.text)) {
				fail("wildcard word %q reaches outside", w.text)
			}
		}
		for _, w := range ws {
			if oracleURL(strings.ToLower(w.text)) {
				fail("address %q", w.text)
			}
			if oracleSecret(w.text, w.glob || unknown) {
				fail("credential path %q", w.text)
			}
		}
		// NAME=value in front of the program, then wrappers.
		words := wordsText(sg.words)
		for len(words) > 0 && strings.Contains(words[0], "=") && !strings.HasPrefix(words[0], "-") && !strings.ContainsAny(strings.SplitN(words[0], "=", 2)[0], "/.") {
			name, val, _ := strings.Cut(words[0], "=")
			if !oracleHarmlessEnv[strings.ToUpper(name)] && !strings.HasPrefix(strings.ToUpper(name), "LC_") {
				fail("sets %s", name)
			}
			for _, p := range oPieces(val) {
				if pathLike(p) && !inAll(p) {
					fail("%s names %q", name, p)
				}
			}
			words = words[1:]
		}
		prog, args := oracleProgram(words)
		if hit := oracleExecHit(prog, args); hit != "" {
			fail("%s with exec option %q", prog, hit)
		}
		writer := oracleWriters[prog] || unknown
		if writer {
			for _, a := range args {
				for _, p := range oPieces(a) {
					if (pathLike(p) || unknown && strings.Contains(p, "/")) && !inAll(p) {
						fail("%s names %q", prog, a)
					}
				}
			}
		}
		oracleRules(prog, args, inAll, fail)
		// the directory the next command runs in
		var next []string
		for _, d := range dirs {
			nd := d
			if prog == "cd" && len(args) > 0 {
				p := args[len(args)-1]
				if !strings.HasPrefix(p, "/") {
					p = d + "/" + p
				}
				nd = path.Clean(p)
			}
			next = oAddDir(next, nd)
		}
		if prog == "cd" && sg.sep != "" && sg.sep != "&&" {
			fail("cd joined by %s", sg.sep)
		}
		for _, d := range next {
			seen = oAddDir(seen, d)
		}
		if sg.sep == "&&" {
			dirs = next
		} else {
			dirs = seen
		}
	}
}

// oracleRules are the per-program rules an allowed command must satisfy.
func oracleRules(prog string, args []string, inAll func(string) bool, fail func(string, ...any)) {
	sub := ""
	if nd := nonDash(args); len(nd) > 0 {
		sub = nd[0]
	}
	switch prog {
	case "cd":
		ops := args
		if len(args) > 0 && args[0] == "--" {
			ops = args[1:]
		}
		if len(ops) != 1 || strings.HasPrefix(ops[0], "-") && len(args) == len(ops) && ops[0] != "-" {
			fail("cd with %d words", len(args))
		}
	case "go":
		if sub == "generate" || sub == "mod" && len(nonDash(args)) > 1 && nonDash(args)[1] == "download" {
			fail("go %s", sub)
		}
	case "npm", "pnpm":
		if sub == "outdated" {
			fail("%s outdated", prog)
		}
	case "pytest":
		for i, a := range args {
			if (a == "-o" || a == "--override-ini") && i+1 < len(args) && strings.HasPrefix(args[i+1], "addopts") || strings.HasPrefix(a, "-oaddopts") {
				fail("pytest sets addopts")
			}
		}
	case "make":
		for i, a := range args {
			if strings.ContainsAny(a, "$`") {
				fail("make expands %q", a)
			}
			if (a == "-f" || a == "--file" || a == "--makefile") && i+1 < len(args) && args[i+1] == "-" || a == "-f-" || a == "--file=-" || a == "--makefile=-" {
				fail("make reads standard input")
			}
			name, _, ok := strings.Cut(a, "=")
			for _, tool := range oracleMakeTools {
				if ok && strings.EqualFold(name, tool) {
					fail("make sets %s", name)
				}
			}
		}
	case "jq":
		for _, a := range args {
			if strings.Contains(a, "$ENV") || strings.Contains(a, "input_filename") || strings.Contains(a, "__loc__") {
				fail("jq reads the environment")
			}
		}
	case "git":
		g := oracleGitSub(args)
		nd := nonDash(args)
		switch g {
		case "restore":
			pre := args
			for i, a := range args {
				if a == "--" {
					pre = args[:i]
					break
				}
			}
			letters := ""
			for _, a := range pre {
				if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
					letters += a[1:]
				}
			}
			if !(has(pre, "--staged") || strings.Contains(letters, "S")) || has(pre, "--worktree", "--source", "--patch") || strings.ContainsAny(letters, "Wsp") {
				fail("git restore touching working files")
			}
		case "checkout":
			n := 0
			for i, a := range nd {
				if i > 0 {
					n++
				}
				if strings.ContainsAny(a, "*?[") || a == "." {
					fail("git checkout of a path")
				}
			}
			for _, a := range args {
				if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && (strings.HasSuffix(a, "b") || strings.HasSuffix(a, "B")) { // each takes a branch name
					n--
				}
			}
			if has(args, "--") || n > 1 {
				fail("git checkout of a path")
			}
		}
	case "ln":
		oracleLn(args, inAll, fail)
	}
}

// oracleLn: the link is written inside; a symbolic link's target is resolved from the link's directory.
func oracleLn(args []string, inAll func(string) bool, fail func(string, ...any)) {
	var ops []string
	link := ""
	symbolic := false
	ended := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case ended:
			ops = append(ops, a)
		case a == "--":
			ended = true
		case strings.HasPrefix(a, "--target-directory="):
			link = a[len("--target-directory="):]
		case a == "--target-directory" && i+1 < len(args):
			link = args[i+1]
			i++
		case a == "--symbolic":
			symbolic = true
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && a != "-":
			for j := 1; j < len(a); j++ {
				if a[j] == 's' {
					symbolic = true
				}
				if a[j] == 't' {
					if a[j+1:] != "" {
						link = a[j+1:]
					} else if i+1 < len(args) {
						link = args[i+1]
						i++
					}
					break
				}
			}
		case strings.HasPrefix(a, "-") && a != "-":
		default:
			ops = append(ops, a)
		}
	}
	targets := ops
	if link == "" && len(ops) >= 2 {
		link, targets = ops[len(ops)-1], ops[:len(ops)-1]
	} else if link == "" && len(ops) == 1 {
		link = path.Base(ops[0])
	}
	if link != "" && !inAll(link) {
		fail("ln links at %q", link)
	}
	for _, tg := range targets {
		if !symbolic {
			if !inAll(tg) {
				fail("ln targets %q", tg)
			}
			continue
		}
		// from the link's directory: only the directory part of the link matters, and the link itself
		// (a wildcard in the link counts by the directory before it)
		lk := link
		if i := strings.IndexAny(lk, "*?["); i >= 0 {
			lk = lk[:strings.LastIndex(lk[:i], "/")+1]
			if lk == "" {
				lk = "."
			}
		}
		for _, base := range []string{path.Dir(lk), lk} {
			if !strings.HasPrefix(base, "/") {
				base = "./" + base
			}
			if strings.HasPrefix(tg, "/") || strings.HasPrefix(tg, "~") {
				if !inAll(tg) {
					fail("ln -s target %q", tg)
				}
				continue
			}
			if !inAll(base + "/" + tg) {
				fail("ln -s target %q from %q", tg, base)
			}
		}
	}
}

// oracleProgram skips NAME=value words and the wrappers and returns the program and its arguments.
func oracleProgram(ws []string) (string, []string) {
	for len(ws) > 1 {
		switch ws[0] {
		case "time", "nohup", "command":
			ws = ws[1:]
			continue
		case "nice", "timeout":
			ws = ws[1:]
			for len(ws) > 1 && (strings.HasPrefix(ws[0], "-") || ws[0][0] >= '0' && ws[0][0] <= '9') {
				ws = ws[1:]
			}
			continue
		}
		break
	}
	if len(ws) == 0 {
		return "", nil
	}
	return ws[0], ws[1:]
}

func wordsText(ws []otok) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.text
	}
	return out
}

func oAddDir(ds []string, d string) []string {
	for _, x := range ds {
		if x == d {
			return ds
		}
	}
	return append(append([]string(nil), ds...), d)
}
