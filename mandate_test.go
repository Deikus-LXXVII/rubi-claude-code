package main

import (
	"strings"
	"testing"
	"time"
)

const root = "/Users/v/project"

func TestMandateAllows(t *testing.T) {
	allowed := []string{
		"ls -la",
		"go test ./...",
		"go vet ./... && go test -race ./internal/...",
		"git status; git diff --stat | head -50",
		"git add -A && git commit -m 'fix: bug'",
		"git log --oneline -20",
		"cat go.mod > out.txt",
		"rg -n foo internal",
		"rm -rf build",
		"mkdir -p tmp/x && touch tmp/x/a",
		"cd internal && go test ./...",
		"make test",
		"npm test",
		"go build ./... 2>&1 | tail -5",
		"FOO=1 go test ./...",
		"cat /etc/hosts",
	}
	for _, c := range allowed {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("%q: refused (%s), want allowed", c, why)
		}
	}
	refused := []string{
		"git push",
		"git push origin main",
		"git -C . push",
		"git --no-pager push",
		"command git push",
		"timeout 5 git push",
		"g''it pu''sh",
		"\"git\" \"push\"",
		"ls && git push",
		"ls; git push --force",
		"ls | git push",
		"ls & git push",
		"ls\ngit push",
		"git commit --amend --no-edit && git push -f",
		"git branch -Df main",
		"git reset --hard HEAD~1",
		"git checkout -- .",
		"git clean -fdx",
		"git config user.email x",
		"git remote add o https://x",
		"git -c core.sshCommand=x fetch",
		"sudo ls",
		"eval ls",
		"sh -c 'ls'",
		"bash script.sh",
		"echo $(git push)",
		"echo `git push`",
		"ls $HOME",
		"ls ${X}",
		"echo \\\"",
		"(git push)",
		"{ git push; }",
		"cat <<EOF\nx\nEOF",
		"cat <(ls)",
		"ls # comment",
		"xargs git push",
		"env git push",
		"curl https://example.com",
		"wget x",
		"ssh host",
		"scp a b:",
		"npm install left-pad",
		"npm publish",
		"npm run deploy",
		"make release",
		"go run example.com/tool@latest",
		"go get example.com/x",
		"rm -rf /",
		"rm -rf ..",
		"rm -rf ../other",
		"rm -rf " + root,
		"rm -rf .git",
		"rm ~/x",
		"echo x > /etc/passwd",
		"echo x > ../out",
		"cat ~/.ssh/id_ed25519",
		"cat .env",
		"cat secrets/token.json",
		"cd .. && rm -rf project",
		"cd - && rm -rf x",
		"cd /tmp && rm -rf x",
		"/usr/bin/git push",
		"./script.sh",
		"python3 -c 'print(1)'",
		"node x.js",
		"PATH=/tmp ls",
		"GIT_SSH_COMMAND=x git fetch",
		"LD_PRELOAD=x ls",
		"open https://x",
		"osascript -e x",
		"docker run x",
		"gh pr create",
		"rubi-home claude-hook",
		"claude -p hi",
		"awk 'BEGIN{system(\"ls\")}'",
		"find . -exec rm {} ;",
		"find . -delete",
		"rg --pre ./x foo",
		"ls 'unterminated",
		"ls &&",
		"",
	}
	for _, c := range refused {
		if ok, _ := mandateAllows(c, root, root); ok {
			t.Errorf("%q: allowed, want refused", c)
		}
	}
}

func TestMandateScope(t *testing.T) {
	now := time.Now()
	m := mandate{ID: "md_1", Device: "dev_mac", SessionID: "s1", Cwd: root, Expires: now.Add(time.Hour), MaxUses: 2}
	r := request{SessionID: "s1", Cwd: root + "/internal"}
	if !m.covers("dev_mac", r) {
		t.Fatal("subdirectory not covered")
	}
	for _, bad := range []request{{SessionID: "s2", Cwd: root}, {SessionID: "s1", Cwd: "/Users/v/project2"}, {SessionID: "s1", Cwd: "/Users/v"}} {
		if m.covers("dev_mac", bad) {
			t.Errorf("%+v covered", bad)
		}
	}
	if m.covers("dev_other", r) {
		t.Error("other computer covered")
	}
	m.Uses = 2
	if m.live(now) {
		t.Error("used up mandate is live")
	}
	m.Uses = 0
	if m.live(now.Add(2 * time.Hour)) {
		t.Error("expired mandate is live")
	}
}

// pushes are ways to say git push in the plain shell subset the mandate parses.
var pushes = []string{"git push", "git  push  origin  HEAD", "g''it pu''sh", "'git' 'push'", "\"gi\"t p\"us\"h",
	"git -C . push", "git --no-pager push", "command git push", "nice git push", "nohup git push", "timeout 9 git push",
	"FOO=1 git push", "git push --force", "git push -f", "git -c x=y push", "git --git-dir=.git push",
	"git push --mirror", "git push origin :main", "git send-pack", "git subtree push", "git lfs push"}

var seps = []string{" && ", " || ", "; ", " | ", " & ", "\n", ";", "&&", "|"}

var benign = []string{"ls", "go test ./...", "git status", "echo ok", "cat README.md", "true", "rg foo"}

func FuzzMandateNeverAllowsPush(f *testing.F) {
	for i := range pushes {
		f.Add(uint8(i), uint8(0), uint8(0), uint8(0), "")
	}
	f.Add(uint8(0), uint8(3), uint8(2), uint8(1), "-v")
	f.Fuzz(func(t *testing.T, p, sep, before, after uint8, extra string) {
		push := pushes[int(p)%len(pushes)]
		if extra != "" && !strings.ContainsAny(extra, "\x00") {
			push += " " + extra
		}
		s := seps[int(sep)%len(seps)]
		var cmd string
		switch before % 3 {
		case 0:
			cmd = push
		case 1:
			cmd = benign[int(after)%len(benign)] + s + push
		default:
			cmd = benign[int(after)%len(benign)] + s + push + s + benign[int(before)%len(benign)]
		}
		if ok, _ := mandateAllows(cmd, root, root); ok {
			t.Fatalf("push allowed: %q", cmd)
		}
	})
}

// TestMandateNeverAllowsPushRandom also runs the push shapes without the fuzzer, so go test covers them.
func TestMandateNeverAllowsPushRandom(t *testing.T) {
	for _, p := range pushes {
		for _, s := range seps {
			for _, b := range benign {
				for _, cmd := range []string{p, b + s + p, p + s + b, b + s + p + s + b} {
					if ok, _ := mandateAllows(cmd, root, root); ok {
						t.Errorf("push allowed: %q", cmd)
					}
				}
			}
		}
	}
}
