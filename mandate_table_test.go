package main

import "testing"

// everyday forms the mandate allows, per program.
var tableAllowed = []string{
	// go
	"go test -v -race -count=3 -run TestX -bench . -benchmem -timeout 60s -short -cover -coverprofile=cover.out -tags integration -failfast -json -p 4 -cpu 2 -shuffle on ./...",
	"go test -fuzz FuzzX -fuzztime 10s ./pkg",
	"go test -count 1 -run 'TestA|TestB' -args -flag=1 ./...",
	"go build -o bin/app -v -race -trimpath -ldflags '-s -w -X main.version=1.2' -tags netgo ./cmd/app",
	"go build ./...", "go vet ./...", "go vet -printf=false ./...",
	"go mod tidy", "go mod verify", "go list -f '{{.Dir}}' ./...", "go list -m all",
	"go doc fmt.Println", "go fmt ./...", "go version", "go env GOPATH GOOS",
	"go run . --port 8080", "go run -race ./cmd/x -v", "go clean -testcache", "go tool cover -html=cover.out -o cover.html",
	"gofmt -l -w .", "gofmt -d main.go", "golangci-lint run ./... --fix", "golangci-lint run --timeout 5m -E gosec ./...", "staticcheck ./...",
	// git
	"git status -s -sb --porcelain --short --branch",
	"git diff --stat --cached --staged --name-only --name-status -U3 --color=never --word-diff",
	"git diff HEAD~1 -- main.go", "git diff main...feature --stat",
	"git log --oneline -n 5 -5 --graph --decorate --all --format=%h --pretty=oneline --since=2.weeks --author=me --grep fix -p --stat --follow main.go",
	"git show --stat HEAD:mandate.go", "git show HEAD~2",
	"git add -A", "git add -p", "git add -u .", "git add -N file.go",
	"git commit -m msg", "git commit -am msg", "git commit --amend --no-edit -q --allow-empty", "git commit -F msg.txt", "git commit -F /tmp/msg.txt",
	"git switch -c feature", "git checkout -b feature", "git checkout main", "git branch -a -v --list", "git branch -m old new", "git branch -d merged",
	"git stash push -m wip", "git stash list", "git stash show -p", "git stash pop", "git stash apply", "git stash", "git stash -u",
	"git merge --no-ff feature", "git merge --ff-only main", "git merge --abort", "git merge --continue",
	"git rebase --no-update-refs main", "git rebase --continue", "git rebase --abort", "git cherry-pick abc123", "git cherry-pick -x abc", "git revert --no-edit HEAD",
	"git rev-parse --show-toplevel", "git rev-parse --abbrev-ref HEAD", "git ls-files", "git blame -L 10,20 main.go",
	"git grep -n -i -w -e foo", "git grep -l foo -- '*.go'", "git grep -c TODO",
	"git worktree add wt/x -b x", "git worktree list", "git worktree move wt/x wt/y",
	"git -C . status", "git --no-pager log -3", "git mv a.go b.go", "git rm --cached a.go", "git restore --staged a.go", "git restore -S .", "git checkout -b x main", "git checkout -B x", "git checkout -",
	"git describe --tags --always", "git shortlog -sn", "git diff -O orderfile",
	// search and read
	"rg -n -i -S -w -l -c -g '*.go' -t go -A 2 -B 2 -C 3 --hidden --no-ignore -F -e foo --json foo internal",
	"rg --files", "rg --files-from=list.txt foo", "rg --color never foo",
	"grep -r -R -n -i -l -c -v -w -E -F -e foo -A 2 -B 2 -C 2 --include '*.go' --exclude '*_test.go' -o -h -H -s -q --color=auto foo .",
	"grep -rn --exclude-dir=.git foo .",
	"ls -la", "ls -lh -R -1 -t -r -S -d -a -A internal", "cat -n go.mod", "head -n 5 go.mod", "head -5 go.mod", "head -c 10 go.mod", "tail -n 5 go.mod", "tail -f -n 20 log.txt", "tail -c 10 go.mod",
	"wc -l -w -c -m go.mod", "diff -u -r -N -q --color a b", "diff -u a.txt b.txt",
	"jq -r -c -e -s . data.json", "jq --arg x y '.a' data.json", "jq --argjson n 3 '.a' data.json", "jq -r '.a[]' data.json",
	"sort -u -n -r -k2 -t, data.csv", "uniq -c words.txt", "xxd bin.dat", "tree -L 2 -a", "tree -o tree.txt",
	"find . -name '*.go' -iname x -path './a/*' -type f -maxdepth 2 -mindepth 1 -newer go.mod -mtime -2 -size +1k -print -print0",
	"find . -not -name x -o -name y", "find . ! -name x -a -type d", "find . -path ./vendor -prune -o -name '*.go' -print",
	// writing
	"cp -r -R -p -a -f -v -n -i a b", "cp -t build a b", "mv -f -v -n -i a b", "mv -t build a b",
	"rm -r -R -f -rf -v -i -d build", "rm -rf build/ dist", "mkdir -p -v -m 755 out/x", "touch -c a.txt", "ln -s -f -n -v a b", "chmod -R 755 scripts", "chmod +x run.sh", "chmod -x run.sh",
	"echo hi | tee -a log.txt", "rmdir -p a/b",
	// build tools
	"make -j 4 -k -s -n -B -C sub -f Makefile VAR=value build test", "make -j4", "make", "make -f build.mk all",
	"cargo build --release --all-targets --workspace -p pkg --features x --all-features --no-default-features --target-dir target/x --lib --bins --tests -q -v -j 4",
	"cargo test -- --nocapture", "cargo test name -- --test-threads=1", "cargo check", "cargo fmt -- --check", "cargo clippy --all-targets -- -D warnings",
	"cargo run --release -- arg", "cargo doc --no-deps", "cargo bench", "cargo tree", "cargo metadata --format-version 1", "cargo clean",
	"npm test", "npm run build", "npm run test -- --watch=false", "npm ls", "npm version", "npm run lint --silent",
	"pnpm test", "pnpm run build", "pnpm ls", "pnpm run --filter web build", "yarn test", "yarn run build",
	"swift build", "swift build -c release", "swift test --filter MyTests", "swift run", "swift run -c release tool arg",
	"pytest -q -x -k expr -v -s --maxfail=3 -m slow --basetemp=tmp/pt --cov=pkg --cov-report=term-missing -o log_cli=true -p no:cacheprovider tests/test_a.py::test_x",
	"pytest --cov-report=html:htmlcov --junitxml=out/junit.xml",
	// small tools
	"echo -n hi", "echo --version", "printf '%s\\n' -x", "pwd", "which go", "file go.mod", "stat go.mod", "stat -f %z go.mod", "du -sh .", "date", "date +%s", "date -u",
	"true", "false", "test -f go.mod", "test -z x", "basename a/b.go .go", "dirname a/b.go", "realpath .", "readlink -f .", "tr -d '\\n'", "tr -cd a-z", "tr a-z A-Z",
	"cut -d , -f 1", "cut -d, -f1", "cut -c 1-3", "shasum -a 256 go.mod", "sha256sum go.mod", "md5 go.mod", "cmp a b",
	"cd internal && ls",
}

// forms the mandate refuses, per program: an unknown option, an option that runs something, a write
// outside the directory or into .git.
var tableRefused = []string{
	// unknown options ask
	"ls --frob", "ls -Z", "cat -zq go.mod", "head --frob go.mod", "grep --frob foo", "rg --frob foo", "rg -zq foo", "find . -frob", "sort --frob a",
	"cp --frob a b", "rm --frob a", "mkdir --frob a", "touch --frob a", "go build -frob", "go test -zq ./...", "git log --frob", "git status --frob", "git diff -zq",
	"make --frob", "cargo build --frob", "npm test --frob", "pytest --frob", "jq --frob .", "diff --frob a b", "wc --frob a", "tree --frob", "du --frob", "xxd -zq a",
	"golangci-lint run --frob", "staticcheck -frob ./...", "gofmt -frob .", "swift build --frob", "pnpm test --frob", "yarn test --frob", "cut -Z a", "chmod --frob a b", "ln --frob a b", "mv --frob a b", "tee --frob a",
	"uniq --frob a", "stat --frob a", "date --frob", "git commit --frob", "git add --frob", "git switch --frob", "git merge --frob", "git grep --frob x",
	// exec options ask
	"find . -exec rm x", "find . -execdir x", "find . -ok x", "find . -okdir x", "find . -delete", "find . -fprintf /tmp/x %p", "find . -name x -exec echo",
	"rg --pre cat foo", "rg --pre-glob '*.x' foo", "rg --hostname-bin=x foo", "git grep -O vim foo", "git grep --open-files-in-pager=vim foo",
	"git rebase -i HEAD~3", "git rebase main", "git rebase --update-refs --onto main a", "git rebase --update-refs main", "git rebase --no-update-refs --update-refs main", "git rebase --exec 'make test' main", "git rebase -x ls main", "git commit -e", "git add -i", "git diff --ext-diff", "git diff --textconv", "git cat-file --textconv HEAD:a", "git merge --edit",
	"go test -exec=echo ./...", "go test -exec echo ./...", "go run -toolexec=strace .", "go vet -vettool=./x ./...", "go build -ldflags '-extld=sh' .",
	"make --eval='all: ; ls'", "make -E x", "make -kE x", "cargo build --config x=y", "cargo build -Zx", "cargo test -Z unstable-options",
	"npm test --script-shell=zsh", "npm run x --node-options=--require=./a.js", "pnpm test --script-shell zsh", "yarn run x --node-options x",
	"sort --compress-program=gzip a", "sort --compress-program gzip a",
	"git -c core.pager=x log", "git -c x=y status", "git --exec-path=/tmp status",
	// values that look like exec options
	"find . -name -exec", "rg -e --pre foo", "git log --grep --open-files-in-pager", "make -f -E", "cargo build -p -Zfoo", "go test -run -exec ./...",
	"cargo run -- -Zfoo", "make -- -E x",
	// writes outside or into .git
	"cp a /tmp/b", "cp -t /tmp a", "cp --target-directory=/tmp a", "mv a ../b", "mv -t ../x a", "ln -s a /tmp/l", "ln -s /etc/hosts l", "mkdir /tmp/x", "mkdir -p ../x", "touch ../x", "touch -r /etc/hosts a",
	"chmod 755 /tmp/x", "chmod -R 777 ..", "tee /tmp/x", "tee -a ~/x", "rm /tmp/x", "rm -rf ~/x", "rm -rf .", "rm -rf ./", "rmdir ..",
	"sort -o /tmp/x a", "uniq a /tmp/x", "xxd -r a /tmp/x", "tree -o /tmp/x", "find . -fprint /tmp/x", "find . -fls ../x",
	"go build -o /tmp/x .", "go test -coverprofile=/tmp/c ./...", "go test -cpuprofile /tmp/c ./...", "go -C .. build", "go build -overlay /tmp/o.json", "go mod vendor -o /tmp/v", "go clean -cache",
	"go env -w GOFLAGS=x", "go env -u GOFLAGS", "go get x", "go install ./...", "go mod edit -replace a=../b", "go tool cover -o /tmp/x",
	"gofmt -w /tmp/x", "gofmt -w ../x",
	"make -C .. x", "make -C /tmp", "make -f /tmp/Makefile", "make --directory=/tmp",
	"cargo build --target-dir /tmp/t", "cargo build --manifest-path /tmp/Cargo.toml", "cargo build --manifest-path ../x/Cargo.toml",
	"npm run x --prefix ../y", "npm test --prefix /tmp", "yarn run x --cwd ../y", "pnpm run x -C /tmp",
	"pytest --basetemp=/tmp/x", "pytest --junitxml=/tmp/x.xml", "pytest --rootdir=/tmp", "pytest -c /tmp/pytest.ini",
	"swift build --build-path /tmp/b", "swift build --package-path ..",
	"golangci-lint run -c /tmp/x.yml", "golangci-lint run --output.json.path /tmp/x",
	"git mv a .git/hooks/x", "git rm .git/x", "git worktree add /tmp/w", "git worktree add ../w", "git worktree move a /tmp/w", "git -C .. status", "git -C /tmp log",
	"git diff --output=/tmp/x", "git diff --output=.git/hooks/pre-commit",
	"tee .git/hooks/pre-commit", "rm -rf .git", "rm .git/index", "touch .git/hooks/x", "cp a .git/hooks/x", "chmod +x .git/hooks/pre-commit", "ln -s a .git/hooks/x", "sort -o .git/x a", "go build -o .git/x .", "mkdir .git/x",
	"echo x > .git/hooks/x", "echo x >> .git/config", "echo x > /tmp/x", "echo x > ../x", "cat a > ~/x",
	// found by FuzzMandate: a path glued to a short option, a credential after =, an address as a target, ~ with a glob
	"pytest -p/Users/alice/project/../x", "make -o/tmp/x", "cat --ignore-file=.env", "cat -f.env", "echo x > git@host", "cp ~* b",
	// git things that always ask
	"git push", "git checkout .", "git checkout -- a.go", "git restore .", "git restore -s HEAD~1 a.go", "git stash drop", "git stash clear", "git worktree remove wt", "git worktree prune",
	"git branch -D x", "git branch --delete x", "git reset --hard", "git clean -fd", "git switch --discard-changes x", "git checkout -f x", "git add -f x", "git commit -S", "git switch -f x",
	// make details
	"make SHELL=zsh", "make CC='cc; ls'", "make release", "make deploy",
	// npm publishing and others
	"npm publish", "npm run deploy", "pnpm run release", "yarn run publish", "cargo run -- publish",
	// credentials, addresses
	"cat ~/.ssh/id_rsa", "cat /Users/alice/.zshrc", "rg foo /Users/alice/.aws/credentials", "jq . .env", "cp .env b", "curl x", "cat https://x",
}

func TestMandateTableAllowed(t *testing.T) {
	for _, c := range tableAllowed {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("%q: refused (%s), want allowed", c, why)
		}
	}
}

func TestMandateTableRefused(t *testing.T) {
	for _, c := range tableRefused {
		if ok, _ := mandateAllows(c, root, root); ok {
			t.Errorf("%q: allowed, want refused", c)
		}
	}
}

// TestMandateRefusalReasons: an exec option and an unknown option say which, so the approval is clear.
func TestMandateRefusalReasons(t *testing.T) {
	for c, want := range map[string]string{
		"find . -exec rm x":        "option -exec runs another program",
		"make -E x":                "option -E runs another program",
		"go test -exec=echo ./...": "option -exec runs another program",
		"ls --frob":                "option --frob isn't on the mandate's list for ls",
		"git log --frob":           "option --frob isn't on the mandate's list for git log",
		"git stash drop":           "git stash drop always asks",
		"go build -o /tmp/x .":     "writes outside the trusted directory",
	} {
		_, why := mandateAllows(c, root, root)
		if len(why) < len(want) || why[:len(want)] != want {
			t.Errorf("%q: reason %q, want it to start with %q", c, why, want)
		}
	}
}

// TestMandateOptionParsing: the shapes of option values.
func TestMandateOptionParsing(t *testing.T) {
	allowed := []string{
		"sort -ko2 a", "sort -uo out.txt a", "sort --output out.txt a", "sort --output=out.txt a", "cp -rt build a", "cp -rpt build a",
		"head -n5 a", "ls -- -weird", "cat -- -n", "rm -- -rf", "grep -e -v file", "git commit -am 'x y'", "git log -n5", "git diff -U10",
		"git grep -nie foo", "rg -A2 foo", "make -j", "make -j4 test", "make -j test",
	}
	for _, c := range allowed {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("%q: refused (%s), want allowed", c, why)
		}
	}
	refused := []string{"sort -o", "sort -uo", "sort --output", "cp -t", "head -n", "cp -rt /tmp a", "rm -- ../x", "touch -- /tmp/x"}
	for _, c := range refused {
		if ok, _ := mandateAllows(c, root, root); ok {
			t.Errorf("%q: allowed, want refused", c)
		}
	}
}

// TestMandateGlobPiece: a glob word whose pieces (split at = : ,) hold no wildcard is not a crash.
func TestMandateGlobPiece(t *testing.T) {
	if ok, _ := mandateAllows("npm run ..,0*", root, root); ok {
		t.Error("allowed, want refused")
	}
	if ok, why := mandateAllows("make a,b*", root, root); !ok {
		t.Errorf("refused (%s), want allowed", why)
	}
}

// TestMandateGlobEscapes: a wildcard can name .git or lead out of the directory.
func TestMandateGlobEscapes(t *testing.T) {
	for _, c := range []string{"echo x > .git*", "tee .gi*/hooks/pre-commit", "touch .g?t/hooks/x", "cp a [.]git/hooks/x", "rm -rf a*/../../x", "touch s*/../../../x"} {
		if ok, _ := mandateAllows(c, root, root); ok {
			t.Errorf("%q: allowed, want refused", c)
		}
	}
	for _, c := range []string{"cp a.txt build/*", "touch *.go", "rm -f sub/*.o", "tee sub*/log.txt"} {
		if ok, why := mandateAllows(c, root, root); !ok {
			t.Errorf("%q: refused (%s), want allowed", c, why)
		}
	}
}
