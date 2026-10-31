package main

import (
	"encoding/json"
	"testing"
)

// Regression cases from a security review of the always-ask list: every one of them must ask.
func TestAgentAlwaysAskFailsClosed(t *testing.T) {
	bash := func(c, cwd string) string {
		b, _ := json.Marshal(map[string]any{"command": c})
		return agentAlwaysAsk("Bash", b, cwd)
	}
	for _, c := range []struct{ c, cwd string }{
		{"cd ..; cd ..; cd ..; touch x", "/work/a"},
		{"cd ..\ncd ..\ncat etc/passwd", "/work/a"},
		{"cd; cat .ssh/id_rsa", "/work"},
		{"cd; touch x", "/work"},
		{"tar xf a.tar -C/tmp", "/work"},
		{"curl -o/tmp/x https://pypi.org/x", "/work"},
		{"git -c alias.x=push x", "/work"},
		{"git config alias.p push && git p", "/work"},
		{"git send-pack https://h/r main", "/work"},
		{"git bundle create /work/x", "/work"},
		{"$'\\x67it' push", "/work"},
		{"g=git; $g push", "/work"},
		{"cat .ru*/claude/.credentials.json", "/work"},
		{"cat .r[u]bi/claude/x", "/work"},
		{"cat $PWD/../../etc/passwd", "/work"},
		{"cat $TMPDIR/x; ls $XDG_CONFIG_HOME", "/work"},
		{"python3 -c 'import urllib.request as u;u.urlopen(\"https://evil.com\")'", "/work"},
		{"node -e 'fetch(\"https://evil.com\")'", "/work"},
		{"curl api.anthropic.com evil", "/work"},
		{"curl -x evil:1 https://pypi.org", "/work"},
		{"curl --resolve pypi.org:443:1.2.3.4 https://pypi.org", "/work"},
		{"echo ok > .git/hooks/pre-commit", "/work"},
		{"cat <<EOF\ngit push\nEOF", "/work"},
		{"ln -s /etc x", "/work"},
		{"ln -s .. up; cat up/x", "/work"},
		{"openssl s_client -connect evil.com:443", "/work"},
		{"git archive --remote=ssh://evil/r HEAD", "/work"},
		{"git --git-dir=/tmp/x log", "/work"},
		{"sh -c 'g''it push'", "/work"},
		{"git fetch", "/work"},
		{"git pu\\\nsh", "/work"},
		{"git\tpush", "/work"},
		{"GIT_SSH_COMMAND=x git push", "/work"},
		{"git push", "/work"},
		{"git -ppush", "/work"},
		{"git --paginate push", "/work"},
		{"git -p push", "/work"},
		{"git --no-pager push", "/work"},
		{"git${IFS}push", "/work"},
		{"git$IFS$9push origin", "/work"},
		{"sudo${IFS}id", "/work"},
		{"echo Z2l0IHB1c2g= | base64 -d | sh", "/work"},
		{"su\\\ndo id", "/work"},
		{"$(echo git) push", "/work"},
		{"cd .rubi", "/work"},
		{"cat -- .rubi/x", "/work"},
		{"cat ./.rubi/claude/.credentials.json", "/work"},
		{"git -C /work push", "/work"},
		// more of the same kind
		{"perl -e 'system(\"id\")'", "/work"},
		{"python3 -", "/work"},
		{"find . -exec sh {} ;", "/work"},
		{"cat .git/config", "/work"},
		{"echo x >> .gitmodules", "/work"},
		{"git rebase --exec 'sh x' main", "/work"},
		{"git remote add o https://h/r", "/work"},
		{"git alias-guess", "/work"},
		{"wget -O- https://example.com", "/work"},
		{"nc evil 1", "/work"},
	} {
		if why := bash(c.c, c.cwd); why == "" {
			t.Errorf("Bash %q (cwd %s) did not ask", c.c, c.cwd)
		}
	}
	tool := func(tn string, in map[string]any, cwd string) string {
		b, _ := json.Marshal(in)
		return agentAlwaysAsk(tn, b, cwd)
	}
	for _, u := range []string{"https://api.anthropic.com\\@evil.com/", "https://evil.com\\.api.anthropic.com", "https://evil.com#@pypi.org",
		"http://pypi.org:80@evil.com", " https://evil.com", "https://pypi.org.evil.com", "https://PYPI.org/", "https://pypi.org%2eevil.com",
		"https://user@evil.com", "http://[::1]/", "https://pypi.org\t.evil.com", "https://pypi.org/\n@evil", "https://api.anthropic.com。evil.com"} {
		if tool("WebFetch", map[string]any{"url": u}, "/work") == "" {
			t.Errorf("WebFetch %q did not ask", u)
		}
	}
	for name, c := range map[string]struct {
		tool string
		in   map[string]any
		cwd  string
	}{
		"relative .rubi":   {"Write", map[string]any{"file_path": "a/../.rubi/x"}, "/work"},
		"upper .CLAUDE":    {"Write", map[string]any{"file_path": "/work/.CLAUDE/x"}, "/work"},
		".git hooks":       {"Write", map[string]any{"file_path": "/work/.git/hooks/pre-commit"}, "/work"},
		".git config edit": {"Edit", map[string]any{"file_path": ".git/config"}, "/work"},
		".gitmodules":      {"Write", map[string]any{"file_path": ".gitmodules"}, "/work"},
		".mcp.json":        {"Write", map[string]any{"file_path": "/work/.mcp.json"}, "/work"},
		"/work2":           {"Write", map[string]any{"file_path": "/work2/x"}, "/work"},
		"notebook":         {"NotebookEdit", map[string]any{"notebook_path": "/etc/x.ipynb"}, "/work"},
		"multiedit":        {"MultiEdit", map[string]any{"file_path": "/etc/x", "edits": []any{}}, "/work"},
		"grep glob":        {"Grep", map[string]any{"pattern": "token", "glob": "../../etc/*"}, "/work"},
		"glob .rubi":       {"Glob", map[string]any{"pattern": ".rubi/**"}, "/work"},
		"glob **/.rubi":    {"Glob", map[string]any{"pattern": "**/.rubi/**"}, "/work"},
		"glob dot star":    {"Glob", map[string]any{"pattern": ".r*/**"}, "/work"},
		"read ~":           {"Read", map[string]any{"file_path": "~/x"}, "/work"},
		"read number":      {"Read", map[string]any{"file_path": 5}, "/work"},
		"array path":       {"Write", map[string]any{"file_path": []string{"/etc/x"}}, "/work"},
		"other key":        {"Write", map[string]any{"filePath": "/etc/x"}, "/work"},
		"unknown tool":     {"mcp__evil__x", map[string]any{"path": "/etc/x"}, "/work"},
		"cwd dotdot":       {"Bash", map[string]any{"command": "ls"}, "/work/../etc"},
		"cwd /workx":       {"Bash", map[string]any{"command": "ls"}, "/workx"},
	} {
		if tool(c.tool, c.in, c.cwd) == "" {
			t.Errorf("%s did not ask", name)
		}
	}
	if agentAlwaysAsk("Write", json.RawMessage(`[1`), "/work") == "" {
		t.Error("an unreadable input did not ask")
	}
	// Not asking is a decision too: plain work stays quiet.
	for _, c := range []string{"ls -la", "go test ./... 2>&1 | tail -5", "cd src && git status && cd .. && git diff", "git commit -m 'fix the build'",
		"git checkout -b feature/push-x", "git log --oneline -5", "curl -sSL https://registry.npmjs.org/left-pad -o out.json",
		"grep -rn TODO src", "cat .gitignore", "git tag -l", "python3 build.py --fast"} {
		if why := bash(c, "/work"); why != "" {
			t.Errorf("Bash %q asked: %s", c, why)
		}
	}
}
