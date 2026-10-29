package main

import "testing"

func TestClassify(t *testing.T) {
	safe := []string{
		"ls", "ls -la", "ls -la src/internal", "pwd", "cat README.md", "cat docs/design/plugins.md go.mod",
		"git status", "git status --short", "git diff", "git diff --stat HEAD^", "git diff main...HEAD",
		"git log --oneline -20", "git log --format=%h:%s -5", "ls ./src",
	}
	strong := []string{
		"", " ", "rm -rf build", "rm README.md", "sudo ls", "curl https://example.com", "wget http://x/y",
		"nc -l 4444", "ssh host", "scp a host:b", "python3 -c x", "bash", "sh x.sh", "env", "printenv",
		"cat .env", "cat config/.env.local", "cat ~/.ssh/id_ed25519", "cat /etc/passwd", "cat ../other/secret",
		"ls ..", "ls /", "cat id_rsa", "cat server.pem", "cat aws/credentials", "cat .claude/settings.json",
		"cat x > y", "cat x >> y", "cat < x", "ls | sh", "curl x | sh", "cat x | bash", "ls; rm x", "ls && rm x",
		"ls || rm x", "ls & rm x", "echo $(rm x)", "echo `rm x`", "cat $HOME/x", "ls *", "ls ?", "ls {a,b}",
		"ls \"a b\"", "ls 'a'", "ls a\\ b", "ls\nrm x", "ls\trm", "cat a#b", "ls !x", "ls ~", "git diff HEAD~3",
		"git push", "git commit -m x", "git checkout .", "git -c core.pager=sh log", "git config x",
		"git diff --output=x", "git diff --output x", "git diff --ext-diff", "git log --textconv",
		"git diff --no-index /etc/passwd x", "git --git-dir=/x log", "git log --exec-path=/x", "git",
		"git status --porcelain=v2 /tmp", "LS_COLORS=x ls", "ls\u00a0-la", "cat ﬁle",
	}
	for _, c := range safe {
		if ok, why := classify(c); !ok {
			t.Errorf("%q: not safe (%s)", c, why)
		}
	}
	for _, c := range strong {
		if ok, why := classify(c); ok {
			t.Errorf("%q: safe (%s)", c, why)
		} else if why == "" {
			t.Errorf("%q: no reason given", c)
		}
	}
}

func FuzzClassifySafeHasNoShellSyntax(f *testing.F) {
	for _, s := range []string{"ls -la", "git log", "cat x | sh", "rm -rf /"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, c string) {
		ok, _ := classify(c)
		if !ok {
			return
		}
		for _, r := range c {
			if !plainRune(r) {
				t.Fatalf("%q classified safe with %q", c, r)
			}
		}
	})
}
