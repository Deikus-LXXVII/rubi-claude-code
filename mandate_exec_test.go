package main

// TestMandateAgainstRealShell runs commands the mandate allows in a real zsh, with recorder stubs in place
// of every external program, and checks what actually happened: no file outside the directory changed
// (this catches redirections the shell performs itself), and no stub was called with a path outside the
// directory (writing and building programs), with a credential path, or from a directory outside it. The
// fuzz oracle shares its author's idea of how the shell behaves; this test asks the shell. It runs on the
// developer's Mac and in CI wherever zsh is installed, and is skipped without zsh or in -short mode.

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// zshBuiltins run for real in the shell, so they get no stub.
var zshBuiltins = map[string]bool{"cd": true, "echo": true, "printf": true, "pwd": true, "true": true, "false": true, "test": true,
	"which": true, "time": true, "command": true, "eval": true, "exec": true, "source": true, ".": true}

var execSecretParts = []string{".ssh", ".aws", ".zshrc", ".gnupg", ".config", "credentials", "id_x"}

type stubCall struct {
	name, cwd, env string
	args           []string
}

type shellTree struct {
	tmp, home, root, bin, log string
}

func newShellTree(t *testing.T) shellTree {
	t.Helper()
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := shellTree{tmp: tmp, home: filepath.Join(tmp, "home"), bin: filepath.Join(tmp, "bin"), log: filepath.Join(tmp, "stub.log")}
	st.root = filepath.Join(st.home, "proj")
	for _, d := range []string{".ssh", ".aws", "Documents", "victim", ".config", "Library/Application Support/x",
		"proj/sub", "proj/a/b", "proj/internal", "proj/build", "proj/tmp", "proj/cmd", "proj/src", "proj/out", "proj/wt", "proj/.git/hooks", "bin"} {
		if d != "bin" {
			d = "home/" + d
		}
		if err := os.MkdirAll(filepath.Join(tmp, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := []string{"home/.ssh/id_x", "home/.aws/credentials", "home/Documents/x", "home/.zshrc", "home/.config/y", "home/victim/f",
		"proj/a.txt", "proj/b.go", "proj/go.mod", "proj/notes.txt", "proj/README.md", "proj/sub/x", "proj/a/b/c", "proj/internal/i.go",
		"proj/.git/config", "proj/.git/hooks/pre-commit.sample", "proj/.hidden", "proj/Makefile"}
	for _, f := range files {
		if strings.HasPrefix(f, "proj/") {
			f = "home/" + f
		}
		if err := os.WriteFile(filepath.Join(tmp, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(st.log, nil, 0o644)
	// one write per call, so stubs in a pipeline don't interleave their records; the environment goes along
	stub := "#!/bin/sh\nd=$(pwd -P)\ne=$(/usr/bin/env -0 | /usr/bin/tr '\\0' '\\001')\nprintf '%s\\0' \"${0##*/}\" \"$d\" \"$e\" \"$@\" \"$(printf '\\036')\" >> \"$STUBLOG\"\n"
	if err := os.WriteFile(filepath.Join(st.bin, "stub"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	names := []string{"nice", "nohup", "timeout"}
	for n := range programs {
		names = append(names, n)
	}
	for n := range alwaysAsk {
		names = append(names, n)
	}
	for _, n := range names {
		if zshBuiltins[n] || strings.Contains(n, "/") {
			continue
		}
		_ = os.Symlink("stub", filepath.Join(st.bin, n))
	}
	return st
}

// outside lists everything under the tmp tree except the project directory, with size and time.
func (st shellTree) outside() string {
	var sb strings.Builder
	_ = filepath.WalkDir(st.tmp, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == st.log {
			return nil
		}
		if p == st.root {
			return filepath.SkipDir
		}
		if fi, err := d.Info(); err == nil {
			fmt.Fprintf(&sb, "%s %v %d %d\n", p, fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		}
		return nil
	})
	return sb.String()
}

func (st shellTree) run(cmd string, extraEnv ...string) ([]stubCall, error) {
	_ = os.WriteFile(st.log, nil, 0o644)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "zsh", "-f", "-c", cmd)
	c.Dir = st.root
	c.Env = append([]string{"PATH=" + st.bin, "HOME=" + st.home, "STUBLOG=" + st.log, "LANG=C"}, extraEnv...)
	_ = c.Run()
	data, err := os.ReadFile(st.log)
	if err != nil {
		return nil, err
	}
	var calls []stubCall
	for _, rec := range bytes.Split(data, []byte{0x1e, 0}) {
		f := strings.Split(strings.TrimSuffix(string(rec), "\x00"), "\x00")
		if len(f) < 3 {
			continue
		}
		calls = append(calls, stubCall{f[0], f[1], f[2], f[3:]})
	}
	return calls, nil
}

func insideDir(rootDir, p string) bool {
	p = filepath.Clean(p)
	if p != rootDir && !strings.HasPrefix(p, rootDir+"/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if strings.EqualFold(part, ".git") {
			return false
		}
	}
	return true
}

func hasSecretPart(p string) bool {
	for _, part := range strings.Split(strings.ToLower(p), "/") {
		for _, s := range execSecretParts {
			if part == s {
				return true
			}
		}
	}
	return false
}

// execReaders only read: for them a path anywhere is fine unless it is a credential.
var execReaders = map[string]bool{"cat": true, "ls": true, "head": true, "tail": true, "wc": true, "grep": true, "rg": true, "diff": true,
	"cmp": true, "jq": true, "file": true, "stat": true, "du": true, "shasum": true, "sha256sum": true, "md5": true, "readlink": true,
	"realpath": true, "basename": true, "dirname": true, "which": true, "tr": true, "cut": true, "date": true, "printf": true, "echo": true, "test": true, "true": true, "false": true, "pwd": true}

// execEnvOK are the variables a call may see: what the test sets, what zsh sets, and the mandate's harmless
// ones (written out here again, on purpose).
var execEnvOK = map[string]bool{"PATH": true, "HOME": true, "STUBLOG": true, "LANG": true, "PWD": true, "OLDPWD": true, "SHLVL": true, "_": true, "LOGNAME": true, "USER": true,
	"CI": true, "NO_COLOR": true, "FORCE_COLOR": true, "TERM": true, "TZ": true, "GOOS": true, "GOARCH": true, "CGO_ENABLED": true,
	"RUST_BACKTRACE": true, "RUST_LOG": true, "NODE_ENV": true, "DEBUG": true, "VERBOSE": true, "COLUMNS": true, "LINES": true,
	"GOMAXPROCS": true, "GOGC": true}

// effective looks through nice, nohup and timeout to the program they would run.
func effective(name string, args []string) (string, []string) {
	for name == "nice" || name == "nohup" || name == "timeout" {
		i := 0
		for i < len(args) && args[i] != "" && (args[i][0] == '-' || args[i][0] >= '0' && args[i][0] <= '9') {
			i++
		}
		if i >= len(args) {
			return name, nil
		}
		name, args = args[i], args[i+1:]
	}
	return name, args
}

// writeArgs are the arguments a program that mostly reads is given to write to.
func writeArgs(name string, args []string) []string {
	var out []string
	next := func(i int) {
		if i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	switch name {
	case "sort":
		for i, a := range args {
			switch {
			case a == "-o" || a == "-T" || a == "--output" || a == "--temporary-directory":
				next(i)
			case strings.HasPrefix(a, "--output="):
				out = append(out, a[len("--output="):])
			case strings.HasPrefix(a, "--temporary-directory="):
				out = append(out, a[len("--temporary-directory="):])
			case len(a) > 1 && a[0] == '-' && a[1] != '-':
				for j := 1; j < len(a); j++ {
					if a[j] == 'o' || a[j] == 'T' {
						if a[j+1:] != "" {
							out = append(out, a[j+1:])
						} else {
							next(i)
						}
						break
					}
					if !strings.ContainsRune("unrfbdghiMRsVzcCm", rune(a[j])) {
						break
					}
				}
			}
		}
	case "uniq", "xxd":
		valued := map[string]bool{"-f": true, "-s": true, "-w": true, "-c": true, "-g": true, "-l": true, "-o": true, "-n": true, "-cols": true,
			"-groupsize": true, "-len": true, "-offset": true, "-seek": true, "-name": true, "-R": true}
		var ops []string
		for i := 0; i < len(args); i++ {
			if strings.HasPrefix(args[i], "-") && args[i] != "-" {
				if valued[args[i]] {
					i++
				}
				continue
			}
			ops = append(ops, args[i])
		}
		if len(ops) >= 2 {
			out = append(out, ops[1])
		}
	case "tree":
		for i, a := range args {
			if a == "-o" {
				next(i)
			} else if strings.HasPrefix(a, "-o") {
				out = append(out, a[2:])
			}
		}
	case "find":
		for i, a := range args {
			if a == "-fprint" || a == "-fprint0" || a == "-fls" {
				next(i)
			}
		}
	case "git":
		for i, a := range args {
			if a == "--output" {
				next(i)
			} else if strings.HasPrefix(a, "--output=") {
				out = append(out, a[len("--output="):])
			}
		}
	}
	return out
}

func (st shellTree) resolveArg(cwd, p string) string {
	if strings.HasPrefix(p, "/") {
		return filepath.Clean(p)
	}
	return filepath.Join(cwd, p)
}

// callProblem returns what is wrong with one recorded call, or "".
func (st shellTree) callProblem(c stubCall) string {
	if _, ok := programs[c.name]; !ok && c.name != "nice" && c.name != "nohup" && c.name != "timeout" {
		return "ran " + c.name + ", which is not on the list"
	}
	if _, ask := alwaysAsk[c.name]; ask {
		return "ran " + c.name + ", which always asks"
	}
	if c.cwd != st.root && !strings.HasPrefix(c.cwd, st.root+"/") {
		return fmt.Sprintf("%s ran in %s, outside the directory", c.name, c.cwd)
	}
	for _, kv := range strings.Split(c.env, "\x01") {
		if kv == "" {
			continue
		}
		name, val, _ := strings.Cut(kv, "=")
		if !execEnvOK[strings.ToUpper(name)] && !strings.HasPrefix(strings.ToUpper(name), "LC_") {
			return fmt.Sprintf("%s ran with %s set", c.name, name)
		}
		switch name {
		case "PATH":
			if val != st.bin {
				return fmt.Sprintf("%s ran with PATH=%s", c.name, val)
			}
		case "HOME":
			if val != st.home {
				return fmt.Sprintf("%s ran with HOME=%s", c.name, val)
			}
		case "STUBLOG", "LANG", "PWD", "OLDPWD", "SHLVL", "_":
		default:
			for _, piece := range strings.FieldsFunc(val, func(r rune) bool { return r == ':' || r == ',' || r == '=' || r == ' ' }) {
				if (strings.HasPrefix(piece, "/") || strings.HasPrefix(piece, "~") || strings.Contains(piece, "..")) && !insideDir(st.root, st.resolveArg(c.cwd, piece)) {
					return fmt.Sprintf("%s ran with %s=%s", c.name, name, val)
				}
			}
		}
	}
	name, args := effective(c.name, c.args)
	for _, a := range writeArgs(name, args) {
		if p := st.resolveArg(c.cwd, a); !insideDir(st.root, p) || hasSecretPart(p) {
			return fmt.Sprintf("%s was told to write %q, which resolves to %s", name, a, p)
		}
	}
	for i, a := range args {
		for _, piece := range strings.FieldsFunc(a, func(r rune) bool { return r == '=' || r == ':' || r == ',' || strings.ContainsRune(" \t\n", r) }) {
			cands := []string{strings.TrimLeft(piece, "-")}
			if len(piece) > 2 && piece[0] == '-' && piece[1] != '-' {
				cands = append(cands, piece[2:])
			}
			for _, cand := range cands {
				if cand == "" {
					continue
				}
				base := c.cwd
				if name == "ln" && i < len(args)-1 { // a symbolic link's target is read from the link's directory
					base = filepath.Dir(st.resolveArg(c.cwd, args[len(args)-1]))
				}
				p := st.resolveArg(base, cand)
				if hasSecretPart(p) {
					return fmt.Sprintf("%s was given the credential path %q", name, a)
				}
				judged := !execReaders[name] && !readsAnywhere[name]
				if judged && !insideDir(st.root, p) {
					return fmt.Sprintf("%s was given %q, which resolves to %s", name, a, p)
				}
			}
		}
	}
	return ""
}

// readsAnywhere are programs that read operands anywhere (their writes are judged by writeArgs).
var readsAnywhere = map[string]bool{"sort": true, "uniq": true, "xxd": true, "tree": true, "find": true, "git": true, "cd": true}

// execCases collects every command the tests know, with the fixed test paths turned into the real tree's.
func (st shellTree) execCases() (cases, mustAllow []string) {
	fix := func(c string) string {
		return strings.ReplaceAll(strings.ReplaceAll(c, "/Users/v/project", st.root), "/Users/v/", st.home+"/")
	}
	for _, l := range [][]string{mandateAllowedCases, writesAllowedCases, tableAllowed, reviewAllowed} {
		for _, c := range l {
			mustAllow = append(mustAllow, fix(c))
		}
	}
	for _, l := range [][]string{escapeProbes, tableRefused, reviewRefused} {
		for _, c := range l {
			cases = append(cases, fix(c))
		}
	}
	rng := rand.New(rand.NewSource(77))
	for i := 0; i < 5000; i++ {
		data := make([]byte, 8+rng.Intn(100))
		rng.Read(data)
		cases = append(cases, fix(fuzzCommand(data)))
	}
	cases = append(cases, st.focused()...)
	return append(mustAllow, cases...), mustAllow
}

// focused builds commands around cd, wrappers, wildcards, redirections and environment prefixes.
func (st shellTree) focused() []string {
	cds := []string{"cd sub", "cd a", "cd nosuch", "cd ..", "cd ../..", "cd -P sub", "cd sub b", "nice cd sub", "nohup cd sub", "timeout 5 cd sub",
		"command cd sub", "time cd sub", "CDPATH=/ cd tmp", "CDPATH=" + st.home + " cd Documents", "cd internal", "cd a/b", "cd -- sub", "cd ."}
	cmds := []string{"rm -rf ../victim", "rm -rf ../../victim", "touch ../x", "touch x", "ls ../../.ssh", "cat ../.ssh/id_x", "cat ../../.*/*",
		"cat ../.*/*", "cat ../*/*", "ls ../.??*", "cat ~/.ssh/id_x", "cat ../victim/*", "ls *", "cat .*", "ls .[!.]*", "echo hi > pwn", "echo hi > ../pwn",
		"echo hi >&1/../../pwned", "echo hi >&2/x", "echo hi >&2", "echo hi 2>&1", "echo hi > .GIT/x", "ln -s ../ ../l", "ln -s ../ l", "ln -s a l2", "ln -sr ../.. l3",
		"tee ../x", "tee x", "cp a.txt ../b", "cp a.txt c.txt", "mv a.txt ../victim/a", "go build -o ../x", "go build -o x", "go build -gcflags='-o ../x'",
		"make -f -", "make", "make CC=x", "git checkout ./", "git checkout main", "git restore a.txt", "cat a.txt", "ls -la", "pwd", "chmod +x a.txt",
		"chmod +x ../victim/f", "mkdir -p out/x", "mkdir ../m", "rm -rf build", "rm -rf ..", "cat ../../Library/*/*", "head -3 ../victim/f", "sort -o ../s a.txt",
		"sort -o s.txt a.txt", "cat $(id)", "echo $HOME", "ls ..", "cat ../.zshrc", "cat ../.aws/credentials", "ls -d .*", "rm -f ../victim/*"}
	ok := []string{"ls -la", "cat a.txt", "go test ./...", "go build -o bin/app ./cmd/x", "git status", "git diff --stat", "rg foo", "grep -rn x .", "head -3 README.md",
		"sort -o s.txt a.txt", "uniq a.txt u.txt", "xxd a.txt x.hex", "tree -o t.txt", "find . -name '*.go' -fprint f.txt", "mkdir -p out/y", "touch out/z", "cp a.txt out/a2", "mv out/a2 out/a3",
		"rm -f out/a3", "chmod +x a.txt", "ln -s a.txt lnk", "ln -s ../a.txt sub/lnk", "tee out/t.txt", "make test", "npm test", "cargo build", "pytest -q", "gofmt -l .", "jq . a.txt",
		"diff a.txt b.go", "wc -l a.txt", "tail -n 2 a.txt", "echo ok > out/e.txt", "echo ok >> out/e.txt", "echo ok 2>&1", "pwd", "git log --oneline -3", "git add -A", "git commit -m x",
		"sort /etc/hosts", "cat /etc/hosts", "ls ~", "du -sh .", "date", "which go", "stat a.txt", "git diff --output=out/d.txt", "go tool cover -o out/c.html"}
	seps := []string{" && ", " && ", " ; ", " || ", " | ", " & ", "\n"}
	envs := []string{"", "", "", "", "CI=1 ", "CDPATH=/ ", "PATH=/tmp ", "path=/x ", "GOCACHE=" + st.home + "/x ", "TMPDIR=" + st.home + "/x ", "IFS=x ", "nice ", "nohup ", "timeout 5 "}
	rng := rand.New(rand.NewSource(11))
	var out []string
	for i := 0; i < 2500; i++ {
		var sb strings.Builder
		for n := 1 + rng.Intn(3); n > 0; n-- {
			sb.WriteString(envs[rng.Intn(len(envs))])
			switch r := rng.Intn(8); {
			case r < 3:
				sb.WriteString(ok[rng.Intn(len(ok))])
			case r < 5:
				sb.WriteString(cds[rng.Intn(len(cds))])
			default:
				sb.WriteString(cmds[rng.Intn(len(cmds))])
			}
			if n > 1 {
				sb.WriteString(seps[rng.Intn(len(seps))])
			}
		}
		out = append(out, sb.String())
	}
	return out
}

func TestMandateAgainstRealShell(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if _, err := exec.LookPath("zsh"); err != nil {
		t.Skip("zsh is not installed")
	}
	st := newShellTree(t)
	cases, mustAllow := st.execCases()
	must := map[string]bool{}
	for _, c := range mustAllow {
		must[c] = true
	}
	seen := map[string]bool{}
	focused := map[string]bool{}
	for _, c := range st.focused() {
		focused[c] = true
	}
	ran, ranFocused, limit := 0, 0, 3000
	for _, cmd := range cases {
		if seen[cmd] || ran >= limit {
			continue
		}
		seen[cmd] = true
		if ok, why := mandateAllows(cmd, st.root, st.root); !ok {
			if must[cmd] {
				t.Errorf("%q: refused (%s), want allowed", cmd, why)
			}
			continue
		}
		ran++
		if focused[cmd] {
			ranFocused++
		}
		before := st.outside()
		calls, err := st.run(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if after := st.outside(); after != before {
			t.Fatalf("%q: allowed, and the shell changed files outside the directory:\n%s", cmd, diffLines(before, after))
		}
		for _, c := range calls {
			if p := st.callProblem(c); p != "" {
				t.Fatalf("%q: allowed, but %s (cwd %s, args %q)", cmd, p, strings.TrimPrefix(c.cwd, st.root), c.args)
			}
		}
	}
	t.Logf("%d allowed commands ran in zsh (%d from the generated cd/wrapper/glob/redirect/env set)", ran, ranFocused)
}

func diffLines(a, b string) string {
	as, bs := map[string]bool{}, map[string]bool{}
	for _, l := range strings.Split(a, "\n") {
		as[l] = true
	}
	var out []string
	for _, l := range strings.Split(b, "\n") {
		bs[l] = true
		if !as[l] {
			out = append(out, "+ "+l)
		}
	}
	for l := range as {
		if !bs[l] {
			out = append(out, "- "+l)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// TestMandateGitAgainstRealGit runs the git commands that could discard work (checkout, restore, switch)
// with a real git in a repo that has one modified tracked file, and checks the file is untouched and nothing
// outside the directory changed. Without a real git it is skipped. (A single-name `git checkout a.txt` is
// indistinguishable from a branch name and is a documented residual, so it is not in the cases.)
func TestMandateGitAgainstRealGit(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	if _, err := exec.LookPath("zsh"); err != nil {
		t.Skip("zsh is not installed")
	}
	st := newShellTree(t)
	_ = os.Remove(filepath.Join(st.bin, "git"))
	if err := os.Symlink(realGit, filepath.Join(st.bin, "git")); err != nil {
		t.Fatal(err)
	}
	env := []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t"}
	_ = os.RemoveAll(filepath.Join(st.root, ".git"))
	for _, c := range []string{"git init -q", "git checkout -q -b main", "git add a.txt", "git commit -q -m init", "git branch other"} {
		if _, err := st.run(c, env...); err != nil {
			t.Fatal(err)
		}
	}
	changed := filepath.Join(st.root, "a.txt")
	reset := func() {
		if err := os.WriteFile(changed, []byte("changed"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var cases []string
	for _, l := range [][]string{mandateAllowedCases, writesAllowedCases, tableAllowed, reviewAllowed, tableRefused, reviewRefused, escapeProbes} {
		for _, c := range l {
			if strings.HasPrefix(c, "git checkout") || strings.HasPrefix(c, "git restore") || strings.HasPrefix(c, "git switch") {
				cases = append(cases, c)
			}
		}
	}
	cases = append(cases, "git checkout other", "git checkout main", "git switch other", "git switch main", "git checkout -b n1", "git checkout -", "git switch -c n2",
		"git checkout HEAD a.txt", "git checkout -- a.txt", "git checkout .", "git checkout ./", "git checkout ../", "git checkout :/", "git checkout ':(top)a.txt'",
		"git checkout 'a.*'", "git checkout main -- a.txt", "git restore a.txt", "git restore .", "git restore -s HEAD a.txt", "git restore --worktree a.txt",
		"git restore --staged a.txt", "git restore -S .", "git restore --staged --worktree a.txt", "git switch --discard-changes main", "git checkout -f main",
		"git checkout -B main", "git checkout --detach", "git checkout -p", "git restore -p a.txt")
	ran := 0
	for _, cmd := range cases {
		cmd = strings.ReplaceAll(strings.ReplaceAll(cmd, "/Users/v/project", st.root), "/Users/v/", st.home+"/")
		if ok, _ := mandateAllows(cmd, st.root, st.root); !ok {
			continue
		}
		reset()
		before := st.outside()
		if _, err := st.run(cmd, env...); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(changed)
		if string(got) != "changed" {
			t.Fatalf("%q: allowed, and real git changed the modified file to %q", cmd, got)
		}
		if after := st.outside(); after != before {
			t.Fatalf("%q: allowed, and changed files outside the directory:\n%s", cmd, diffLines(before, after))
		}
		ran++
	}
	t.Logf("%d allowed git commands ran against a real repo", ran)
}
