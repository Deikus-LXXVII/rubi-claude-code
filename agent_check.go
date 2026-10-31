package main

// The always-ask classifier of the agent path. It fails closed: a Bash command is read with the strict shell
// splitter of the mandate check (splitShell), and anything that splitter refuses (expansions, substitutions,
// escapes and line continuations, here documents, subshells, comments) asks, because Rubi can't know what such
// a line would run. A command it can read is then checked word by word. Over-asking is the intended error;
// the check can't see what a program does inside (make, npm scripts, python x.py), which the VM's borders cover.

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

// protected path parts (lower case): .rubi holds Rubi's files and the Claude login (any access asks); the others
// change how Claude, git or an MCP server runs and ask when written.
var (
	protectedAccess = []string{".rubi"}
	protectedWrite  = []string{".rubi", ".claude", ".git", ".gitmodules", ".mcp.json"}
)

func toolPaths(tool string, in map[string]any) []string {
	var out []string
	for _, k := range []string{"file_path", "notebook_path", "path", "glob"} {
		if v, ok := in[k].(string); ok && v != "" {
			out = append(out, v)
		}
	}
	if v, ok := in["pattern"].(string); ok && tool == "Glob" && v != "" {
		out = append(out, v)
	}
	return out
}

// pathProblem says why a path (or glob) in a tool call or a word of a command needs an approval: it is outside
// /work (also ~ and a .. that leaves it), or it can name a protected part. dir is where relative paths start.
func pathProblem(p, dir string, glob, write bool) string {
	if p == "" || strings.Contains(p, "://") {
		return ""
	}
	if strings.HasPrefix(p, "~") {
		return "the path " + oneLine(p, 100) + " is in the home directory, outside " + agentRoot
	}
	w := word{text: p, glob: glob || strings.ContainsAny(p, "*?[")}
	if devNull(p) || p == "/dev/stdin" || p == "/dev/tty" {
		return ""
	}
	if !inside(agentRoot, dir, w) {
		return "the path " + oneLine(p, 100) + " is outside " + agentRoot
	}
	names := protectedAccess
	if write {
		names = protectedWrite
	}
	for _, seg := range strings.Split(path.Clean(resolve(dir, p)), "/") {
		low := strings.ToLower(seg)
		for _, n := range names {
			if low == n {
				return "the path " + oneLine(p, 100) + " is under " + n + protectedWhy(n)
			}
			// A wildcard part that starts with a dot can match it (.r*, .ru[b]i); one that doesn't can't match a dotfile.
			if strings.ContainsAny(low, "*?[") && strings.HasPrefix(low, ".") {
				if ok, _ := path.Match(low, n); ok {
					return "the wildcard " + oneLine(p, 100) + " can match " + n + protectedWhy(n)
				}
			}
		}
	}
	return ""
}

func protectedWhy(n string) string {
	switch n {
	case ".rubi":
		return " (Rubi's own files, the Claude login among them)"
	case ".claude":
		return " (it changes how Claude is set up)"
	case ".git", ".gitmodules":
		return " (git hooks and config run programs)"
	case ".mcp.json":
		return " (it sets up programs Claude starts)"
	}
	return ""
}

// agentAlwaysAsk returns why a tool call must have a strong approval whatever the mode, or "".
func agentAlwaysAsk(tool string, raw json.RawMessage, cwd string) string {
	if cwd != "" && !within(agentRoot, cwd) {
		return "the working directory " + cwd + " is outside " + agentRoot
	}
	if cwd == "" {
		cwd = agentRoot
	}
	cwd = path.Clean(cwd)
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		return "the " + tool + " input isn't readable, so Rubi can't check it"
	}
	switch {
	case tool == "Bash":
		cmd, ok := in["command"].(string)
		if !ok {
			return "the Bash input has no command Rubi can read"
		}
		return bashAlwaysAsk(cmd, cwd)
	case tool == "WebFetch":
		u, _ := in["url"].(string)
		if !allowedURL(u) {
			return "WebFetch to " + oneLine(u, 100) + ", not a plain URL on the allow-list"
		}
		return ""
	case readTools[tool] || editTools[tool]:
		write := editTools[tool]
		found := false
		for _, k := range []string{"file_path", "notebook_path", "path", "glob", "pattern"} {
			v, present := in[k]
			if !present {
				continue
			}
			s, isStr := v.(string)
			if !isStr {
				return tool + " has a " + k + " that isn't text"
			}
			if k == "pattern" && tool != "Glob" {
				continue // a search pattern, not a path
			}
			if k == "file_path" || k == "notebook_path" || k == "path" {
				found = found || s != ""
			}
			if why := pathProblem(s, cwd, k == "glob" || k == "pattern", write); why != "" {
				return tool + ": " + why
			}
		}
		if write && !found {
			return tool + " names no file Rubi can read"
		}
	case tool == "WebSearch" || tool == "AskUserQuestion" || tool == "Task" || tool == "Agent" || tool == "TodoWrite":
	default:
		// Any other tool (an MCP tool ...): text that names a place outside /work asks.
		for _, s := range stringsIn(in) {
			if (strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, "../")) && !strings.ContainsAny(s, " \n") {
				if why := pathProblem(s, cwd, false, true); why != "" {
					return tool + ": " + why
				}
			}
		}
	}
	return ""
}

func stringsIn(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, stringsIn(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, e := range x {
			out = append(out, stringsIn(e)...)
		}
		return out
	}
	return nil
}

// urlRE is the only shape of URL taken as plain: a lower-case ASCII host, an optional port, a path without
// spaces, backslashes, @ or #. Anything else (user info, look-alike characters, escapes) asks.
var urlRE = regexp.MustCompile(`^(https?://)?([a-z0-9][a-z0-9.-]*[a-z0-9])(:[0-9]{1,5})?(/[^\s\\@#]*)?$`)

// allowedURL says whether s is a plain URL (or bare host) on the allow-list.
func allowedURL(s string) bool {
	m := urlRE.FindStringSubmatch(s)
	if m == nil || strings.Contains(s, "..") && !strings.Contains(s, "/") {
		return false
	}
	if u, err := url.Parse("https://" + strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")); err != nil || u.Hostname() != m[2] {
		return false
	}
	return agentHosts[m[2]]
}

var (
	rootProgs = map[string]bool{"sudo": true, "doas": true, "su": true, "pkexec": true, "run0": true}
	// Programs that run another program or shell, change the shell's state or hide what runs.
	wrapperProgs = setOf("sh bash zsh dash ksh csh tcsh fish ash busybox eval exec env xargs source . command builtin nohup timeout nice ionice time setsid stdbuf watch chroot unshare nsenter script flock parallel pushd popd trap alias shopt set setopt unset export declare typeset local readonly at batch crontab systemd-run screen tmux ssh-agent")
	netProgs     = setOf("ssh scp sftp rsync nc ncat netcat telnet ftp tftp lftp socat nmap ping ping6 traceroute dig nslookup host mosh openssl gnutls-cli aria2c http https httpie websocat wscat smbclient psql mysql mariadb redis-cli mongosh mongo sqlcmd telnetd ftpd tcpdump tshark ngrok cloudflared")
	interpreters = setOf("python python2 python3 node nodejs deno bun ruby perl php lua luajit rscript osascript tclsh pwsh powershell julia ghc runghc swift")
	publishProgs = setOf("npm pnpm yarn bun cargo gem docker twine vsce poetry flit hatch uv pip pip3")
	linkProgs    = setOf("ln link mount")
	// Git subcommands that only work on the local repository. Anything else (remote operations, config, archive,
	// bundle, an alias this check can't see ...) asks.
	localGit = setOf("status diff log show add commit branch checkout switch restore stash merge rebase cherry-pick revert mv rm blame grep rev-parse ls-files describe shortlog show-ref cat-file worktree reset clean init apply bisect reflog diff-tree ls-tree rev-list whatchanged fsck gc notes format-patch am name-rev merge-base symbolic-ref update-index hash-object write-tree commit-tree for-each-ref show-branch count-objects verify-commit help version tag stage")
	// Substrings of a git word that mean a remote operation, a program run or a config change.
	gitRemoteBits = []string{"push", "fetch", "pull", "clone", "remote", "send-pack", "receive-pack", "upload-pack", "http-push", "http-fetch",
		"archive", "bundle", "submodule", "lfs", "svn", "request-pull", "send-email", "imap-send", "daemon", "instaweb", "credential", "config", "exec", "ssh"}
	// Options that point curl or wget somewhere else, read a config or upload.
	netOptBits = []string{"--proxy", "-x", "--resolve", "--connect-to", "--config", "-K", "--socks", "--interface", "--upload", "-T", "--post-file", "--form", "-F", "--oauth", "--netrc", "--cacert", "--capath", "--output-dir"}
)

func setOf(s string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(s) {
		m[f] = true
	}
	return m
}

func baseName(s string) string { return strings.ToLower(path.Base(s)) }

func bashAlwaysAsk(cmd, cwd string) string {
	segs, bad := splitShell(cmd)
	if bad != "" {
		return "the command uses " + bad + ", which Rubi can't check"
	}
	dir := cwd
	for _, sg := range segs {
		if why := segAlwaysAsk(sg, &dir); why != "" {
			return why
		}
	}
	return ""
}

// wordCandidates are the paths a word may carry: itself, the value glued to a short option (-C/tmp), and what
// follows an = in it, split at : and ,.
func wordCandidates(t string) []string {
	if strings.Contains(t, "://") {
		return nil
	}
	cands := []string{t}
	if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && len(t) > 2 {
		cands = append(cands, t[2:])
	}
	for _, c := range cands {
		if i := strings.IndexByte(c, '='); i > 0 {
			cands = append(cands, c[i+1:])
		}
	}
	for _, c := range cands {
		if strings.ContainsAny(c, ":,") {
			cands = append(cands, strings.FieldsFunc(c, func(r rune) bool { return r == ':' || r == ',' })...)
		}
	}
	return cands
}

func segAlwaysAsk(sg segment, dir *string) string {
	ws := make([]string, len(sg.words))
	for i, w := range sg.words {
		ws[i] = w.text
	}
	for _, r := range sg.redirs {
		if why := pathProblem(r.target.text, *dir, r.target.glob, true); why != "" {
			return "a redirection to " + why
		}
	}
	if len(ws) == 0 {
		return ""
	}
	prog := baseName(ws[0])
	rest := ws[1:]
	if i := strings.IndexByte(ws[0], '='); i > 0 && !strings.HasPrefix(ws[0], "-") && !strings.Contains(ws[0][:i], "/") {
		return "an environment variable set in front of a command (" + oneLine(ws[0], 60) + ")"
	}
	for _, w := range ws {
		if rootProgs[baseName(w)] {
			return "sudo or another way to become root (" + baseName(w) + ")"
		}
	}
	for _, w := range ws {
		if t := strings.TrimLeft(w, "-"); strings.HasPrefix(w, "--force") && !strings.HasPrefix(t, "force-") || w == "--force" {
			return w + ": it overrides a safety check"
		}
	}
	switch {
	case wrapperProgs[prog]:
		return prog + ": it runs another program or shell, or changes the shell, in a way Rubi can't follow"
	case netProgs[prog]:
		return prog + ": the network outside the allow-list"
	case linkProgs[prog]:
		return prog + ": a link can point outside " + agentRoot
	case prog == "find":
		for _, w := range rest {
			if strings.HasPrefix(w, "-exec") || strings.HasPrefix(w, "-ok") || w == "-delete" || w == "-fprint" || strings.HasPrefix(w, "-fprint") || w == "-fls" {
				return "find " + w + ": it runs or writes through find"
			}
		}
	case prog == "awk" || prog == "gawk" || prog == "mawk" || prog == "sed" || prog == "gsed":
		for _, w := range rest {
			if strings.Contains(w, "system") || strings.Contains(w, "getline") || strings.Contains(w, "| ") || prog != "awk" && prog != "gawk" && prog != "mawk" && (strings.HasSuffix(w, "/e") || strings.Contains(w, "/e;")) {
				return prog + " with a program that can run commands"
			}
		}
	case interpreters[prog]:
		if why := interpreterAsk(prog, rest); why != "" {
			return why
		}
	case prog == "curl" || prog == "wget":
		if why := fetchAsk(prog, rest); why != "" {
			return why
		}
	case prog == "git":
		if why := gitAsk(rest); why != "" {
			return why
		}
	case prog == "gh" || prog == "hub" || prog == "glab":
		return prog + ": it works on the remote repository (pushes, pull requests, releases)"
	case publishProgs[prog]:
		for _, w := range rest {
			if w == "publish" || w == "upload" || w == "push" || w == "adduser" || w == "login" || w == "token" {
				return prog + " " + w + ": a release or a login"
			}
		}
	case prog == "cd":
		return cdAsk(rest, dir)
	}
	for _, w := range sg.words {
		for _, c := range wordCandidates(w.text) {
			if strings.HasPrefix(c, "-") && c == w.text {
				continue
			}
			if why := pathProblem(c, *dir, w.glob, true); why != "" {
				return why
			}
		}
	}
	return ""
}

// cdAsk follows cd: the directory it moves to must stay inside /work (a bare cd goes home).
func cdAsk(args []string, dir *string) string {
	var target string
	n := 0
	for _, a := range args {
		if a == "-L" || a == "-P" || a == "--" || a == "-e" {
			continue
		}
		target = a
		n++
	}
	switch {
	case n == 0:
		return "cd with no directory goes to the home directory, outside " + agentRoot
	case n > 1 || target == "-" || strings.HasPrefix(target, "~") || strings.ContainsAny(target, "*?["):
		return "cd " + oneLine(target, 80) + ": Rubi can't tell where it goes"
	}
	next := resolve(*dir, target)
	if !within(agentRoot, next) {
		return "cd " + oneLine(target, 80) + " leaves " + agentRoot
	}
	if why := pathProblem(target, *dir, false, true); why != "" {
		return "cd into " + why
	}
	*dir = next
	return ""
}

// interpreterAsk: an interpreter given its program on the command line (-c, -e ...) or on stdin runs code Rubi
// can't read.
func interpreterAsk(prog string, rest []string) string {
	script := false
	for _, w := range rest {
		switch {
		case strings.HasPrefix(w, "--eval") || strings.HasPrefix(w, "--print") || strings.HasPrefix(w, "--command") || strings.HasPrefix(w, "--exec") || strings.HasPrefix(w, "--run"):
			return prog + " " + w + ": code on the command line"
		case strings.HasPrefix(w, "--"):
		case strings.HasPrefix(w, "-") && len(w) > 1 && strings.ContainsAny(w[1:], "cepErxCRX"):
			return prog + " " + w + ": code on the command line"
		case w == "-" || !strings.HasPrefix(w, "-"):
			script = script || w != "-"
		}
	}
	if !script {
		return prog + " with no script file: it would run code from the command line or stdin"
	}
	return ""
}

// fetchAsk: every non-option word of curl or wget must be a plain allow-listed URL or host, apart from the
// values of the few options that take one; options that redirect, proxy or upload ask.
func fetchAsk(prog string, rest []string) string {
	takesValue := setOf("-H --header -A --user-agent -X --request -m --max-time -w --write-out -o --output --retry --connect-timeout -d --data --data-raw --data-binary -O -P -T --timeout --tries -U --directory-prefix -t -e --referer")
	hosts := 0
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if strings.HasPrefix(w, "-") {
			opt := w
			if j := strings.IndexByte(w, '='); j > 0 && strings.HasPrefix(w, "--") {
				opt = w[:j]
			}
			for _, bit := range netOptBits {
				if opt == bit || strings.HasPrefix(bit, "--") && strings.HasPrefix(opt, bit) {
					return prog + " " + w + ": it redirects, proxies or uploads"
				}
			}
			if prog == "curl" && !strings.HasPrefix(w, "--") && strings.ContainsAny(w[1:], "xKTF") {
				return prog + " " + w + ": it redirects, proxies or uploads"
			}
			if takesValue[opt] && !strings.Contains(w, "=") && i+1 < len(rest) {
				i++
			}
			continue
		}
		if !allowedURL(w) {
			return prog + " to " + oneLine(w, 80) + ", not a plain URL on the allow-list"
		}
		hosts++
	}
	if hosts == 0 {
		return prog + " with no URL Rubi can check"
	}
	return ""
}

// gitAsk: a git command that isn't a plain local one asks (remote operations, config, aliases, programs run).
func gitAsk(rest []string) string {
	sub := ""
	var after []string
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		low := strings.ToLower(w)
		switch {
		case w == "-C":
			i++
		case w == "-c" || strings.HasPrefix(w, "--config-env") || strings.HasPrefix(w, "--git-dir") || strings.HasPrefix(w, "--work-tree") ||
			strings.HasPrefix(w, "--exec-path") || strings.HasPrefix(w, "--namespace") || strings.HasPrefix(w, "--super-prefix"):
			return "git " + w + ": it changes git's configuration or location"
		case strings.HasPrefix(w, "-"):
			// An odd option in front of the command (-ppush ...) is read for a remote operation hiding in it.
			for _, bit := range gitRemoteBits {
				if strings.Contains(low, bit) {
					return "git " + oneLine(w, 40) + ": it hides a remote operation or a program run"
				}
			}
		default:
			sub, after = w, rest[i+1:]
			i = len(rest)
		}
	}
	switch {
	case sub == "":
		return ""
	case !localGit[sub]:
		return "git " + oneLine(sub, 40) + ": not a plain local git command (it may be an alias or reach a remote)"
	}
	for _, w := range after {
		switch {
		case w == "-f" || strings.HasPrefix(w, "--force"):
			return "git with " + w + ": it can throw work away"
		case w == "-x" || strings.HasPrefix(w, "--exec") || sub == "bisect" && w == "run":
			return "git " + sub + " " + w + ": it runs a program"
		case sub == "tag" && w != "-l" && w != "--list" && w != "-n":
			return "git tag: tags are releases"
		}
	}
	return ""
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// plainText drops format and control characters, so what the user reads is what Claude wrote.
func plainText(s string, n int) string {
	return oneLine(strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Co, r) {
			return ' '
		}
		return r
	}, s), n)
}

// hiddenChars says whether s has a format, control or private-use character.
func hiddenChars(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Co, r) {
			return true
		}
	}
	return false
}
