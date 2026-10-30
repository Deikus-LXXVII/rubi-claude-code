package main

// The per-program spec the mandate checks a command against. Every option of a listed program is named
// here with what it takes; an option that isn't named asks (deny by default). The table itself is in
// mandate_programs.go.

import (
	"path"
	"strings"
	"unicode"
)

type argKind int

const (
	kFlag   argKind = iota + 1 // no value (a flag may carry an optional =value that names no file)
	kValue                     // one value that names no file
	kValue2                    // two values that name no file (jq --arg name value)
	kRead                      // a path that is read: anywhere except credential paths
	kWrite                     // a path that is written: inside the directory and not under .git
	kDir                       // a directory the command works in: inside the directory
	kGlued                     // an optional value glued to the option (-M50, -uall), never the next word
	kNum                       // an optional number, glued or as the next word (make -j 4)
	kRest                      // everything after it is an operand (go test -args)
	kExec                      // names a program or code to run: always asks
	kDeny                      // always asks (deletes, or changes settings outside the project)
)

type cmdSpec struct {
	opts          map[string]argKind
	operands      []argKind // the kind of operand 1, 2, ...; the last repeats; none means read
	subs          map[string]*cmdSpec
	subOptional   bool // the command may run without a subcommand (git stash)
	single        bool // long options with one dash (go -race, find -name): matched whole, no clusters
	anyOpt        bool // options are irrelevant: every word is an operand (echo, test, tr)
	numeric       bool // -20 means a count (head -20, git log -20)
	stopAtOperand bool // the first operand ends the options (go run . -flag)
	deny          string
	publish       bool // operands that look like publishing ask (npm run deploy)
	build         bool // extra layer for builds and writing programs: no word on the line names a place outside the directory
	check         func(c *call) string
}

// call is one command being checked.
type call struct {
	root, dir string
	name      string // the program and the subcommands so far: "git worktree add"
	args      []word
	operands  []word
	ended     bool // after -- or -args
	exec      []string
	seen      map[string]bool     // the options given, by name
	vals      map[string][]string // the values each option took
}

// opts builds an option table: an argKind sets the kind of the names (space separated strings) after it;
// a map is merged in.
func opts(spec ...any) map[string]argKind {
	m := map[string]argKind{}
	var k argKind
	for _, s := range spec {
		switch v := s.(type) {
		case argKind:
			k = v
		case map[string]argKind:
			for n, kk := range v {
				m[n] = kk
			}
		case string:
			for _, n := range strings.Fields(v) {
				m[n] = k
			}
		}
	}
	return m
}

// checkArgs checks the words after a listed program against its spec and returns why they ask, or "".
func checkArgs(name string, top *cmdSpec, args []word, root, dir string) string {
	c := &call{root: root, dir: dir, name: name, args: args, seen: map[string]bool{}, vals: map[string][]string{}}
	c.exec = execNames(top, nil)
	cur := top
	chain := []*cmdSpec{top}
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if !c.ended && t == "--" {
			c.ended = true
			continue
		}
		if !c.ended && cur.isOption(t) {
			n, why := c.option(cur, i)
			if why != "" {
				return why
			}
			i += n
			continue
		}
		if cur.subs != nil {
			sub, ok := cur.subs[t]
			if c.ended || !ok {
				return c.name + " " + t + " isn't on the mandate's list"
			}
			if sub.deny != "" {
				return c.name + " " + t + " always asks (" + sub.deny + ")"
			}
			c.name += " " + t
			cur = sub
			chain = append(chain, sub)
			continue
		}
		if strings.HasPrefix(t, "-") && execLike(c.exec, t) {
			return "option " + t + " runs another program"
		}
		c.operands = append(c.operands, args[i])
		if why := c.operand(cur.operandKind(len(c.operands)-1), args[i]); why != "" {
			return why
		}
		if cur.stopAtOperand {
			c.ended = true
		}
	}
	if cur.subs != nil && !cur.subOptional {
		return name + " without a command"
	}
	for _, s := range chain {
		if s.check != nil {
			if why := s.check(c); why != "" {
				return why
			}
		}
		if s.publish {
			for _, o := range c.operands {
				if publishing(o.text) {
					return o.text + " looks like publishing"
				}
			}
		}
	}
	if top.build {
		return noOutside(c.root, c.dir, args)
	}
	return ""
}

func (s *cmdSpec) isOption(t string) bool {
	return !s.anyOpt && len(t) > 1 && t[0] == '-'
}

func (s *cmdSpec) operandKind(n int) argKind {
	if len(s.operands) == 0 {
		return kRead
	}
	if n >= len(s.operands) {
		n = len(s.operands) - 1
	}
	return s.operands[n]
}

// operand applies an operand's kind: write and dir operands stay inside the directory.
func (c *call) operand(k argKind, w word) string {
	if w.text == "-" {
		return ""
	}
	return c.use(k, w)
}

func (c *call) use(k argKind, w word) string {
	switch k {
	case kWrite:
		return writeCheck(c.root, c.dir, w)
	case kDir:
		if !inside(c.root, c.dir, w) {
			return "works outside the trusted directory (" + w.text + ")"
		}
	}
	return ""
}

// option checks the option at args[i] and returns how many following words it took as values.
func (c *call) option(s *cmdSpec, i int) (int, string) {
	t := c.args[i].text
	if s.numeric && isDigits(t[1:]) {
		return 0, ""
	}
	if s.single || strings.HasPrefix(t, "--") {
		name, val, has := strings.Cut(t, "=")
		if s.single {
			name = "-" + strings.TrimLeft(name, "-")
		}
		return c.take(s, i, name, val, has)
	}
	for j := 1; j < len(t); j++ { // a cluster: every letter but the last is a flag
		name := "-" + t[j:j+1]
		if k, ok := s.opts[name]; ok && k == kFlag {
			c.seen[name] = true
			continue
		}
		rest := t[j+1:]
		return c.take(s, i, name, rest, rest != "")
	}
	return 0, ""
}

// take handles one named option: has says its value was glued (--out=x, -ox) and is val.
func (c *call) take(s *cmdSpec, i int, name, val string, has bool) (int, string) {
	k, ok := s.opts[name]
	if !ok {
		return 0, "option " + c.args[i].text + " isn't on the mandate's list for " + c.name
	}
	c.seen[name] = true
	switch k {
	case kExec:
		return 0, "option " + name + " runs another program"
	case kDeny:
		return 0, "option " + name + " always asks (it deletes, or changes settings outside the project)"
	case kFlag, kGlued:
		return 0, ""
	case kRest:
		c.ended = true
		return 0, ""
	case kNum:
		if !has && i+1 < len(c.args) && isDigits(c.args[i+1].text) {
			return 1, ""
		}
		return 0, ""
	}
	var vals []word
	if has {
		vals = append(vals, word{val, c.args[i].glob && strings.ContainsAny(val, "*?[")})
	}
	want := 1
	if k == kValue2 {
		want = 2
	}
	taken := 0
	for len(vals) < want {
		if i+1+taken >= len(c.args) {
			return 0, "option " + name + " without a value"
		}
		v := c.args[i+1+taken]
		if execLike(c.exec, v.text) {
			return 0, "option " + name + " is followed by " + v.text + ", an option that runs another program"
		}
		vals = append(vals, v)
		taken++
	}
	if k == kWrite || k == kDir {
		if why := c.use(k, vals[0]); why != "" {
			return 0, why
		}
	}
	for _, v := range vals {
		c.vals[name] = append(c.vals[name], v.text)
	}
	return taken, ""
}

// execNames collects the names of the exec and deny options of a spec and all its subcommands.
func execNames(s *cmdSpec, names []string) []string {
	for n, k := range s.opts {
		if k == kExec || k == kDeny {
			names = append(names, n)
		}
	}
	for _, sub := range s.subs {
		names = execNames(sub, names)
	}
	return names
}

// execLike: w is, or is glued to, one of the exec options. It is used on words that are not parsed as
// options (a value, or an operand after --), so an exec option can't hide as someone's value.
func execLike(names []string, w string) bool {
	if !strings.HasPrefix(w, "-") {
		return false
	}
	base, _, _ := strings.Cut(w, "=")
	alt := "-" + strings.TrimLeft(base, "-")
	for _, n := range names {
		if base == n || alt == n || len(n) == 2 && strings.HasPrefix(w, n) {
			return true
		}
	}
	return false
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

// noOutside is the extra layer for build and test tools: no word on their command line, nor a value
// inside one (-o=/x, cache_dir=/x, html:/x, a,b), names a place outside the directory or in git's own
// files. These tools write outputs, caches and reports wherever they are told to.
func noOutside(root, dir string, args []word) string {
	for _, a := range args {
		for _, piece := range strings.FieldsFunc(a.text, func(c rune) bool { return c == '=' || c == ':' || c == ',' || unicode.IsSpace(c) }) {
			cands := pathCandidates(piece)
			for _, p := range cands {
				if pathish(p) {
					if why := writeCheck(root, dir, word{text: p, glob: a.glob && strings.ContainsAny(p, "*?[")}); why != "" {
						return why
					}
				}
			}
		}
	}
	return ""
}

// pathCandidates are the paths a piece of a word may name: without leading dashes, and without a short
// option letter glued in front (-o/x).
func pathCandidates(piece string) []string {
	c := []string{strings.TrimLeft(piece, "-")}
	if len(piece) > 2 && piece[0] == '-' && piece[1] != '-' {
		c = append(c, piece[2:])
	}
	return c
}

// pathish: s may name a place outside the working directory.
func pathish(s string) bool {
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

// ---- semantic checks a table can't say ----

// removeCheck: rm and rmdir never remove the whole trusted directory.
func removeCheck(c *call) string {
	for _, o := range c.operands {
		if resolve(c.dir, globPrefix(o)) == path.Clean(c.root) {
			return "removes the whole trusted directory"
		}
	}
	return ""
}

// goCheck: no module@version (go run x@latest downloads code), no linker or compiler flag that names
// another program (-ldflags=-extld=x, -toolexec), and compiler and linker flags only from a short known
// list (a flag such as -o or -cpuprofile in them writes a file).
func goCheck(c *call) string {
	for _, a := range c.args {
		if strings.Contains(a.text, "@") {
			return "downloads a module (" + a.text + ")"
		}
		if strings.Contains(a.text, "extld") || strings.Contains(a.text, "toolexec") {
			return "go " + a.text + " runs another program"
		}
	}
	for _, name := range []string{"-ldflags", "-gcflags", "-asmflags", "-gccgoflags"} {
		for _, v := range c.vals[name] {
			if !safeGoFlags(name, v) {
				return "go " + name + " " + oneLine(v, 60) + " isn't on the mandate's list"
			}
		}
	}
	return ""
}

// safeGoFlags: -ldflags takes -s -w -X pkg.name=value -buildid=x; -gcflags takes -N -l -m -m=N -B -e, with
// an optional leading pattern= (all=-N -l); -asmflags and -gccgoflags take nothing.
func safeGoFlags(name, v string) bool {
	toks := strings.Fields(v)
	if name == "-gcflags" && len(toks) > 0 {
		if i := strings.Index(toks[0], "="); i > 0 && toks[0][0] != '-' && !pathish(toks[0][:i]) {
			toks[0] = toks[0][i+1:]
		}
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch name {
		case "-ldflags":
			switch {
			case t == "-s" || t == "-w" || strings.HasPrefix(t, "-buildid="):
			case t == "-X" && i+1 < len(toks):
				i++
				if !strings.Contains(toks[i], "=") {
					return false
				}
			default:
				return false
			}
		case "-gcflags":
			if t != "-N" && t != "-l" && t != "-m" && t != "-B" && t != "-e" && !(strings.HasPrefix(t, "-m=") && isDigits(t[3:])) {
				return false
			}
		default:
			return false
		}
		if pathish(strings.TrimLeft(t, "-")) {
			return false
		}
	}
	return true
}

// makeToolVars are variables a Makefile runs as programs or reads as settings: a command line may not set them.
var makeToolVars = map[string]bool{"CC": true, "CXX": true, "CPP": true, "LD": true, "AR": true, "AS": true, "FC": true, "F77": true,
	"RANLIB": true, "STRIP": true, "NM": true, "OBJCOPY": true, "OBJDUMP": true, "LEX": true, "YACC": true, "SHELL": true, "MAKE": true,
	"MAKEFILES": true, "MAKEFLAGS": true, "GNUMAKEFLAGS": true, "MFLAGS": true, ".SHELLFLAGS": true, "MAKESHELL": true, "VPATH": true,
	"GO": true, "CARGO": true, "NPM": true, "PYTHON": true, "SH": true, "PATH": true}

func makeTool(name string) bool {
	n := strings.ToUpper(strings.TrimSpace(name))
	if makeToolVars[n] {
		return true
	}
	for _, p := range []string{"GNUMAKE", "GO", "CGO_", "RUST", "CARGO", "NPM_", "PNPM_", "YARN_"} { // settings that name tools or flags
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// makeCheck: no makefile from standard input, no $ or backtick (make expands $(shell ...) even from quotes),
// and VAR=value only with a plain value for a variable that isn't a tool.
func makeCheck(c *call) string {
	for _, n := range []string{"-f", "--file", "--makefile"} {
		for _, v := range c.vals[n] {
			if v == "-" || v == "" {
				return "make reads a makefile from standard input"
			}
		}
	}
	for i, a := range c.args {
		if a.text == "-f-" || a.text == "--file=-" || a.text == "--makefile=-" ||
			(a.text == "-f" || a.text == "--file" || a.text == "--makefile") && i+1 < len(c.args) && c.args[i+1].text == "-" {
			return "make reads a makefile from standard input"
		}
		if strings.ContainsAny(a.text, "$`") {
			return "make expands $ and backticks in " + oneLine(a.text, 60)
		}
		if name, _, ok := strings.Cut(a.text, "="); ok && !strings.HasPrefix(name, "-") {
			name = strings.TrimSpace(name)
			if strings.HasSuffix(name, "!") {
				return "make " + name + "= runs a shell command"
			}
			if i := strings.IndexAny(name, ":+?!"); i >= 0 {
				name = name[:i]
			}
			if makeTool(name) {
				return "make " + name + "= changes how recipes run"
			}
		}
	}
	for _, o := range c.operands {
		name, val, ok := strings.Cut(o.text, "=")
		if !ok {
			continue
		}
		if strings.ContainsAny(val, " \t;|&<>()$`'\"\\/") || strings.HasPrefix(val, ".") || strings.HasPrefix(val, "~") {
			return "make " + name + "= with a path or command-like value"
		}
		if l := strings.ToLower(val); strings.Contains(l, "exec") || strings.Contains(l, "extld") || strings.Contains(l, "shell") {
			return "make " + name + "= with a value that names a program"
		}
	}
	return ""
}

// pytestCheck: -o sets ini keys, and addopts or plugins among them would pass any option; only a short list of keys.
var pytestKeys = map[string]bool{"log_cli": true, "log_cli_level": true, "log_level": true, "console_output_style": true, "junit_family": true,
	"asyncio_mode": true, "python_files": true, "python_classes": true, "python_functions": true, "testpaths": true, "minversion": true,
	"norecursedirs": true, "cache_dir": true, "xfail_strict": true, "log_format": true, "log_date_format": true}

func pytestCheck(c *call) string {
	for _, v := range c.vals["-o"] {
		if key, _, _ := strings.Cut(v, "="); !pytestKeys[key] {
			return "pytest -o " + key + " isn't on the mandate's list"
		}
	}
	return ""
}

// lnCheck: the link is written, so it stays inside. A symbolic link's target is read from the link's own
// directory, so it is resolved there (and from the link itself, in case the link names an existing
// directory) and must be inside and not in .git; a hard link's target is a path from here.
func lnCheck(c *call) string {
	ops := c.operands
	link := word{}
	targets := ops
	if v := c.vals["-t"]; len(v) > 0 {
		link = word{text: v[0]}
	} else if v := c.vals["--target-directory"]; len(v) > 0 {
		link = word{text: v[0]}
	} else if len(ops) >= 2 {
		link = ops[len(ops)-1]
		targets = ops[:len(ops)-1]
	} else if len(ops) == 1 {
		link = word{text: path.Base(ops[0].text)}
	}
	if why := writeCheck(c.root, c.dir, link); why != "" {
		return why
	}
	symbolic := c.seen["-s"] || c.seen["--symbolic"]
	linkPath := resolve(c.dir, globPrefix(link))
	for _, t := range targets {
		bases := []string{c.dir}
		if symbolic {
			bases = []string{path.Dir(linkPath), linkPath}
		}
		for _, base := range bases {
			if why := writeCheck(c.root, base, t); why != "" {
				return "ln target " + t.text + " leads out of the trusted directory: " + why
			}
		}
	}
	return ""
}

// cdCheck: cd takes exactly one directory, no wildcard.
func cdCheck(c *call) string {
	n := len(c.args)
	if len(c.operands) == 1 {
		if t := c.operands[0].text; t != "" && t != "-" && strings.ContainsRune("+-=", rune(t[0])) {
			return "cd " + t + " (a directory stack or command lookup in zsh)"
		}
	}
	if len(c.operands) != 1 || c.operands[0].glob || n != 1 && !(n == 2 && c.args[0].text == "--") {
		return "cd takes exactly one plain directory"
	}
	return ""
}

// restoreCheck: git restore only unstages (--staged); it never touches the working files.
func restoreCheck(c *call) string {
	if !c.seen["--staged"] && !c.seen["-S"] || c.seen["--worktree"] || c.seen["-W"] || c.seen["--source"] || c.seen["-s"] || c.seen["-p"] || c.seen["--patch"] {
		return c.name + " that changes working files always asks (only --staged is allowed)"
	}
	return ""
}

// checkoutCheck: git checkout only switches or creates a branch: one branch (or -), or -b/-B name [start].
// A path (two operands, or anything after --) would overwrite working files.
func checkoutCheck(c *call) string {
	for _, a := range c.args {
		if a.glob || strings.ContainsAny(a.text, "*?[") || a.text == "." { // git expands quoted pathspecs too
			return c.name + " of a path that discards changes always asks"
		}
	}
	for _, a := range c.args {
		t := a.text
		if t == "--" || t == ".." || strings.HasPrefix(t, ":") || strings.HasPrefix(t, "./") || strings.HasPrefix(t, "../") || strings.HasSuffix(t, "/") && t != "-" {
			return c.name + " of a path that discards changes always asks"
		}
	}
	if len(c.operands) > 1 {
		return c.name + " of a path that discards changes always asks"
	}
	return ""
}

// jqCheck: a hint, not a barrier (jq can build the word env in other ways): a filter that reads the
// environment or the input file name asks.
func jqCheck(c *call) string {
	for _, a := range c.args {
		t := a.text
		if strings.Contains(t, "$ENV") || strings.Contains(t, "input_filename") || strings.Contains(t, "__prog") || strings.Contains(t, "__loc__") {
			return "jq reads the environment or the input file name"
		}
	}
	if len(c.operands) > 0 && bareWord(c.operands[0].text, "env") { // the filter
		return "jq reads the environment"
	}
	return ""
}

// bareWord: w is in s as a name of its own (not a .field, not part of a longer name).
func bareWord(s, w string) bool {
	for i := 0; i+len(w) <= len(s); i++ {
		if s[i:i+len(w)] != w {
			continue
		}
		before := i == 0 || !identChar(s[i-1]) && s[i-1] != '.'
		after := i+len(w) == len(s) || !identChar(s[i+len(w)])
		if before && after {
			return true
		}
	}
	return false
}

func identChar(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
