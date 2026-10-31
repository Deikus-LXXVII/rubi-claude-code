package main

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

const root = "/Users/alice/project"

var mandateAllowedCases = []string{
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
	"CI=1 go test ./...",
	"cat /etc/hosts",
}

func TestMandateAllows(t *testing.T) {
	for _, c := range mandateAllowedCases {
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
		"rubi-ssh web-1 ls",
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
	for _, bad := range []request{{SessionID: "s2", Cwd: root}, {SessionID: "s1", Cwd: "/Users/alice/project2"}, {SessionID: "s1", Cwd: "/Users/alice"}} {
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

// TestMandateWritesAndRunsOnlyInside: the escapes the 2026-10-30 audit found (each was allowed by
// v0.2.1) now ask, and the everyday in-project form of the same commands is still allowed.
var writesAllowedCases = []string{
	"sort -u notes.txt",
	"sort -o sorted.txt notes.txt",
	"sort -k2 -t, data.csv > sorted.csv",
	"uniq -c words.txt",
	"uniq words.txt out/uniq.txt",
	"xxd bin.dat | head",
	"xxd -r dump.hex out.bin",
	"tree -L 2",
	"tree -o tree.txt",
	"go build -o bin/app ./cmd/app",
	"go test -coverprofile=cover.out ./...",
	"go test -run 'TestA/sub' -count=1 ./...",
	"go env GOPATH",
	"go clean -testcache",
	"find . -name '*.go' -print0",
	"git worktree add wt/feat -b feat",
	"git grep -n foo",
	"make test V=1",
	"make -C sub build",
	"cargo build",
	"cargo test --target-dir target/ci",
	"npm run build",
	"pytest -q tests --basetemp=tmp/pytest",
	"cp -t build a.txt b.txt",
	"echo x >> notes.md",
	"cat .git/config",
	"cd internal && go test ./...",
}

func TestMandateWritesAndRunsOnlyInside(t *testing.T) {
	for _, c := range writesAllowedCases {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("%q: refused (%s), want allowed", c, why)
		}
	}
	for _, c := range escapeProbes {
		if ok, _ := mandateAllows(c, root, root); ok {
			t.Errorf("%q: allowed, want refused", c)
		}
	}
}

// escapeProbes are the escapes the 2026-10-30 audit found; each must ask. They seed FuzzMandate.
var escapeProbes = []string{
	// writes outside the directory
	"sort -o /Users/alice/.zshrc notes.txt",
	"sort --output=/tmp/x notes.txt",
	"sort -uo /tmp/x notes.txt",
	"sort -T /tmp notes.txt",
	"uniq notes.txt /Users/alice/.zprofile",
	"uniq -f 1 notes.txt /tmp/out",
	"xxd -r dump.hex /Users/alice/bin/tool",
	"xxd in.bin ../out.hex",
	"tree -o /tmp/out.txt",
	"go build -o /usr/local/bin/rubi-home ./cmd/x",
	"go build -o=../bin/x .",
	"go test -coverprofile=/tmp/c.out ./...",
	"go test -cpuprofile /tmp/cpu.out ./...",
	"find . -fprint0 /Users/alice/x",
	"git worktree add /tmp/elsewhere",
	"git worktree add ../sibling -b x",
	"git worktree move wt /tmp/wt",
	"cargo build --target-dir /tmp/t",
	"npm run build --prefix ../other",
	"pytest --basetemp=/Users/alice/Documents",
	"pytest --cov-report=html:/tmp/cov",
	"pytest -o cache_dir=/tmp/c",
	"cp --target-directory=/tmp a.txt",
	"cp -t/tmp a.txt",
	"go clean -modcache",
	"go env -w GOFLAGS=-mod=mod",
	// git's own files: a hook or config there runs at the next git command
	"tee .git/hooks/pre-commit",
	"chmod 755 .git/hooks/pre-commit",
	"echo x > .git/hooks/pre-commit",
	"cp evil .git/hooks/post-checkout",
	"echo '[core]' >> .git/config",
	"go build -o .git/hooks/pre-commit ./cmd/x",
	// options that run another program or text
	"git grep --open-files-in-pager=vim foo",
	"git grep -Ovim foo",
	"git grep -O foo",
	"go test -exec=echo ./...",
	"go run -toolexec=strace .",
	"cargo build --config 'target.x.runner=zsh'",
	"cargo build -Zunstable-options",
	"npm test --script-shell=zsh",
	"make --eval='all: ; ls'",
	"make -E 'all: ; ls'",
	"make CC='cc; ls'",
	"make SHELL=zsh",
	"sort --compress-program=gzip notes.txt",
	"rg --hostname-bin=x foo",
}

// TestMandateSecretPaths: shell startup files, per-user settings with tokens and browser cookies ask,
// wherever they are named (an argument, an option value, a redirection); project files don't.
func TestMandateSecretPaths(t *testing.T) {
	for _, c := range []string{
		"cat /Users/alice/.zshrc",
		"cat ~/.zprofile",
		"cp /Users/alice/.bash_profile notes.txt",
		"head -5 /Users/alice/.profile",
		"cat /Users/alice/.gitconfig",
		"cat /Users/alice/.config/gh/hosts.yml",
		"cat /Users/alice/.vault-token",
		"cat /Users/alice/.pgpass",
		"cat /Users/alice/Library/Cookies/Cookies.binarycookies",
		"cat '/Users/alice/Library/Application Support/Google/Chrome/Default/Cookies'",
		"cat '/Users/alice/Library/Application Support/Google/Chrome/Default/Login Data'",
		"xxd /Users/alice/Library/Application Support/Firefox/Profiles/x/cookies.sqlite",
		"rg --files-from=/Users/alice/.zshrc foo",
		"wc -l < /Users/alice/.bashrc",
	} {
		if ok, _ := mandateAllows(c, root, root); ok {
			t.Errorf("%q: allowed, want refused", c)
		}
	}
	for _, c := range []string{"cat config/app.yaml", "cat README.md", "ls internal", "cat profile.go", "grep -rn cookie internal"} {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("%q: refused (%s), want allowed", c, why)
		}
	}
}

// FuzzMandate builds commands from a vocabulary (programs, options including unknown, exec and write
// ones, paths inside, outside, in .git and secret, separators, redirections) and checks with an oracle
// that does not use the spec table that an allowed command has no write outside the directory or in
// .git, no exec option, no credential path and no address. A first byte 0xff makes the rest a whole command.
func FuzzMandate(f *testing.F) {
	for _, c := range escapeProbes {
		f.Add(append([]byte{0xff}, c...))
	}
	for _, c := range reviewRefused {
		f.Add(append([]byte{0xff}, c...))
	}
	f.Add([]byte{0, 3, 40, 3, 50, 120, 130})
	f.Fuzz(func(t *testing.T, data []byte) { checkOracle(t, fuzzCommand(data)) })
}

// TestMandateOracleSample runs the fuzz body over a fixed random sample, so go test covers it.
func TestMandateOracleSample(t *testing.T) {
	rng := rand.New(rand.NewSource(77))
	allowed := 0
	for i := 0; i < 5000; i++ {
		data := make([]byte, 8+rng.Intn(100))
		rng.Read(data)
		cmd := fuzzCommand(data)
		if ok, _ := mandateAllows(cmd, root, root); ok {
			allowed++
		}
		checkOracle(t, cmd)
	}
	for _, c := range append(append([]string(nil), escapeProbes...), reviewRefused...) {
		checkOracle(t, c)
	}
	t.Logf("%d of 5000 sampled commands were allowed", allowed)
}
