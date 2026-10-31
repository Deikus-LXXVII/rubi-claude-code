package main

import "testing"

// reviewRefused are the bypasses the 2026-10-30 reviews confirmed (each wrote or ran outside, or read
// credentials, in a real shell); every one must ask.
var reviewRefused = []string{
	// cd: one operand, no options, and only && keeps the directory
	"cd nosuch ; rm -rf ../victim", "cd nosuch || rm -rf ../victim", "cd sub | rm -rf ../victim", "cd sub & rm -rf ../victim",
	"cd a b", "CDPATH=/ cd tmp && printf x > owned", "cd -P link && ls", "cd -L sub && ls", "cd sub\nrm -rf ../victim", "cd * && ls",
	"false && cd sub && ls ; rm -rf ../victim", "cd sub && ls || rm -rf ../victim",
	// >&word is a file unless it is a descriptor number or -
	"echo hi >&1/../../pwned", "echo hi >&2/x", "echo hi >&2foo", "echo hi >&../x", "echo hi >& ../x", "echo hi >&/tmp/x", "cat <&/etc/hosts >&2x",
	// symbolic links are resolved from the link's directory
	"cd a && ln -s ../ ../l", "ln -s ../Documents ../l", "cd a && ln -s ../.. ../l", "ln -s /tmp l", "ln -s .. l", "ln -s .git/hooks l",
	// .git in any case
	"echo hi > .GIT/hooks/x", "touch .GIT/hooks/pre-commit", "go build -o .GiT/hooks/pre-commit", "git diff --output=.GIT/hooks/x",
	"rm -rf .GIT", "chmod +x .GIT/hooks/pre-commit", "echo hi > .Git/x", "tee .G*/hooks/x", "cp a [.]GIT/hooks/x",
	// wildcards that spell credentials
	"cat ~/.s?h/i*", "cat ~/.s[s]h/id_*", "ls ~/.a?s", "cat ./.s?h/i*", "cat /Users/alice/.s?h/id_rsa", "cat /etc/*", "cat ./.ENV*", "cat ./.e[n]v",
	// environment prefixes
	"CC='sh -c id' go build ./...", "CC=./ccwrap go test ./...", "GOCACHE=/Users/alice/x go build ./...", "GOMODCACHE=/tmp/gm go build ./...",
	"TMPDIR=/Users/alice/x sort a", "RIPGREP_CONFIG_PATH=rg.conf rg foo", "path=/x ls", "GNUMAKEFLAGS=--eval=x make", "MAKEFILES=/x make",
	"XDG_CONFIG_HOME=evil git add f", "ALL_PROXY=socks5://h go build ./...", "CDPATH=/ cd tmp", "IFS=x ls", "FOO=1 ls", "CI=/tmp/x ls",
	"CI=../x ls", "CI=https://x ls", "CI=.env ls", "TZ=* ls", "PATH=/tmp ls",
	// values with spaces
	"go build -gcflags='-o /Users/alice/x' ./...", "go build -ldflags='-o /Users/alice/x' ./...", "go build -gcflags='-cpuprofile /Users/alice/x' ./...",
	"pytest -o addopts='--junitxml /Users/alice/x'", "go build -ldflags='-extar sh -buildmode=c-archive'", "go build -ldflags '-extld  sh'",
	"go build -ldflags='-linkmode=external'", "go build -asmflags=-x ./...", "go build -gcflags='all=-o /tmp/x'", "pytest -o 'cache_dir=a b/../../x'",
	"pytest -o plugins=x", "pytest -o python_files='a /tmp/x'", "make 'X=-o /tmp/x'",
	// make
	"make -f -", "make -f-", "make --file=-", "make CC=./ccwrap foo.o", "make '$(shell touch /tmp/pwned)'", "make 'x=$(shell id)'",
	"make CC=gcc", "make SHELL=sh", "make GOFLAGS=-toolexec=sh", "make X=./a", "make X=a/b", "make X='a b'", "make MAKEFLAGS=x", "make GNUMAKEFLAGS=x",
	// network and programs
	"go mod download", "go list -m -versions golang.org/x/text", "npm outdated", "pnpm outdated", "go generate ./...", "go list -u -m all",
	// git discards
	"git restore -- file.go", "git restore *", "git checkout HEAD file.go", "git checkout HEAD *", "git restore -s HEAD~1 a.go", "git restore a.go",
	"git restore --staged --worktree a.go", "git restore -S -W a.go", "git restore --staged --source=HEAD a.go", "git restore -p", "git checkout -b x main extra",
	"git checkout -- file.go", "git checkout main -- file.go", "git checkout -p", "git checkout .", "git checkout -f main",
	// second review: wrappers run cd as a program
	"nice cd sub && rm -rf ../victim", "nohup cd sub && rm -rf ../victim", "timeout 5 cd sub && rm -rf ../victim", "nice -n 5 cd sub && ls",
	// relative globs that reach credentials
	"cat ../../.*/*", "ls ../../.??*", "cat ../../.??*/*", "cat ../../.?*/*", "cat ../../.[!.]*/*", "grep -r x ../../.*", "cat ../../*/*", "cat /,0*",
	"cat ../../Library/*/*", "cat ../.*/id_*", "cat ../../.[^.]*/*", "ls ../../.[a-z]*", "cat ./.s[!x]h/id_*", "grep --include=../*.go x .",
	// checkout of a path
	"git checkout ./", "git checkout '*'", "git checkout '*.go'", "git checkout ../", "git checkout :/", "git checkout ':(top)a'", "git checkout ./a", "git checkout ..", "git checkout a/",
	"git checkout -b x ./a",
	// ln -r, make variable operators, go -mod
	"ln -sr ../.. sub/l", "ln -s -r ../.. sub/l", "ln -s --relative a b", "make CC::=true", "make X!=id", "make SHELL::=sh", "make CC?=x",
	"make 'CC!=x'", "make SHELL!=sh", "make CC:=x", "make CC+=x", ".SHELLFLAGS::=-c", "make .SHELLFLAGS::=-c", "make cc=x", "make 'CXX\t=x'",
	"go build -mod=mod ./...", "go test -mod=mod ./...", "go build -mod mod", "go fmt -mod=mod", "go clean -mod=mod",
	// third review: cd with +, - or = operands; make variables that name tools or flags
	"cd +1", "cd -1", "cd =ls", "cd +1 && ls", "make GOFLAGS=-mod=mod", "make CGO_CFLAGS=-O2", "make RUSTFLAGS=-Cx", "make CARGO_HOME=x", "make NPM_CONFIG_PREFIX=x",
	"make npm_config_prefix=x", "make GOCACHE=x", "make GOPROXY=off",
	// credentials and jq
	"jq -n env", "jq '$ENV' a.json", "jq -n 'input_filename'", "jq -n '$__loc__'", "jq -n '. | env | .HOME'", "jq --rawfile a ~/.ssh/id_rsa .",
	"cat ~/.dockercfg", "cat ~/.s3cfg", "cat ~/.mysql_history", "cat ~/.m2/settings.xml", "cat ~/.codex/auth.json", "cat /proc/self/environ",
	"cat ~/.openai/x", "cat ~/.cursor/x", "cat ~/.mozilla/x", "cat ~/.boto", "cat ~/.oci/config",
}

// reviewAllowed are everyday forms next to those bypasses; they stay allowed.
var reviewAllowed = []string{
	"cd sub && ls", "cd sub && go test ./... && cd .. && ls", "cd sub", "ls ; cd sub", "cd -- sub && ls", "cd sub && ls | head", "cd internal && go test ./... 2>&1 | tail -5",
	"echo hi >&2", "echo hi 2>&1", "go test ./... 2>&1 | tail", "echo hi >&- ", "echo hi > out.txt 2>&1", "cat < a.txt",
	"ln -s a b", "ln -s ../a sub/l", "ln -s a sub/l", "ln -sf a b", "ln a b", "ln -s sub/a l", "cd sub && ln -s ../a l",
	"CI=1 go test ./...", "CGO_ENABLED=0 GOOS=linux go build -o bin/app ./cmd/app", "NO_COLOR=1 go vet ./...", "TZ=America/New_York date", "LC_ALL=C sort a", "RUST_BACKTRACE=1 cargo test",
	"go build -ldflags '-s -w -X main.version=1.2.3' ./...", "go build -ldflags=-s -gcflags='all=-N -l' ./...", "go build -gcflags='-m' ./...", "go test -gcflags=-l ./...",
	"pytest -o log_cli=true -o cache_dir=.cache", "make V=1 test", "make CFLAGS=-O2", "make -f build.mk all", "make -j 4",
	"cat ./*.go", "ls *", "ls i*", "rm -f sub/*.o", "cat sub/*.md", "ls .*", "ls *.pem.bak",
	"git restore --staged a.go", "git restore -S .", "git checkout main", "git checkout -b x", "git checkout -b x main", "git checkout -", "git checkout feature/x",
	"git checkout -b feature/x origin/main", "command cd sub && ls", "time cd sub && ls", "cat .*", "make CFLAGS=-O2 test",
	"jq '.a.env.b' a.json", "jq -r '.name' env.json", "jq -n '1+1'",
	"go list -m all", "go mod tidy", "git stash", "git stash -u",
}

func TestMandateReviewRefused(t *testing.T) {
	for _, c := range reviewRefused {
		if ok, _ := mandateAllows(c, root, root); ok {
			t.Errorf("%q: allowed, want refused", c)
		}
	}
}

func TestMandateReviewAllowed(t *testing.T) {
	for _, c := range reviewAllowed {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("%q: refused (%s), want allowed", c, why)
		}
	}
}
