package main

import (
	"path"
	"strings"
)

// git for the mandate: the subcommands it allows and every option of each. Everything else (push, fetch,
// pull, clone, remote, config, submodule, filter-branch, reset, clean, aliases ...) asks, and so do
// -f/--force, --hard, -D, --delete, -c and the options that run an editor, a pager or another program.

var gitDiffOpts = opts(kFlag, "--stat --cached --staged --name-only --name-status --color --no-color --word-diff --color-words --check --shortstat --numstat --summary --patch -p -u --no-patch -s --raw --minimal --patience --histogram --ignore-space-change -b -w --ignore-all-space --ignore-space-at-eol --ignore-blank-lines --ignore-cr-at-eol -B -R -a --text -W --function-context --exit-code --quiet --no-ext-diff --no-textconv --no-renames --find-renames --find-copies --find-copies-harder --full-index --binary --abbrev --compact-summary --dirstat --relative --submodule --no-index --merge-base --irreversible-delete -z --ita-invisible-in-index --no-prefix --default-prefix --diff-algorithm --indent-heuristic --no-indent-heuristic --unified --color-moved --stat-width --stat-graph-width --stat-count --stat-name-width --inter-hunk-context --word-diff-regex --ws-error-highlight",
	kGlued, "-M -C -l", kValue, "-U -S -G --src-prefix --dst-prefix --diff-filter -I --ignore-matching-lines --pickaxe-regex",
	kRead, "-O --orderfile --rotate-to --skip-to", kWrite, "--output", kExec, "--ext-diff --textconv")

var gitLogOpts = opts(gitDiffOpts, kFlag, "--oneline --graph --decorate --no-decorate --all --branches --tags --remotes --follow --reverse --merges --no-merges --first-parent --abbrev-commit --no-abbrev-commit --relative-date --source --left-right --cherry-pick --cherry-mark --cherry --boundary --topo-order --date-order --author-date-order --simplify-by-decoration --simplify-merges --full-history --sparse --dense --ancestry-path --regexp-ignore-case -i -E --extended-regexp -F --fixed-strings --all-match --invert-grep --notes --no-notes --no-walk --use-mailmap --mailmap --no-mailmap -m -c --cc --children --parents --format --pretty --date --diff-merges --glob --not -g --walk-reflogs --count -q",
	kValue, "-n --max-count --skip --since --until --after --before --author --committer --grep --grep-reflog -L --min-parents --max-parents --exclude --since-as-filter")

var gitSpec = &cmdSpec{
	opts: opts(kFlag, "--no-pager -P --no-optional-locks --no-replace-objects", kDir, "-C", kExec, "-c --exec-path --config-env", kDeny, "--git-dir --work-tree --namespace"),
	subs: map[string]*cmdSpec{
		"status": {numeric: true, opts: opts(kFlag, "-s -b --short --branch --porcelain --long -v --verbose --ignored --untracked-files -z --show-stash --ahead-behind --no-ahead-behind --renames --no-renames --column --no-column", kGlued, "-u")},
		"diff":   {numeric: true, opts: gitDiffOpts},
		"log":    {numeric: true, opts: gitLogOpts},
		"show":   {numeric: true, opts: gitLogOpts},
		"add":    {opts: opts(kFlag, "-A --all -u --update -p --patch -N --intent-to-add -v --verbose -n --dry-run --ignore-errors --refresh --renormalize --chmod --sparse --ignore-missing --pathspec-file-nul", kRead, "--pathspec-from-file", kExec, "-e --edit -i --interactive")},
		"commit": {opts: opts(kFlag, "-a --all -q --quiet -v --verbose --amend --no-edit --allow-empty --allow-empty-message -s --signoff -n --no-verify --no-post-rewrite --no-status --status --dry-run --short --porcelain --long -z --only -o --include -i --reset-author --no-gpg-sign --pathspec-file-nul", kGlued, "-u --untracked-files",
			kValue, "-m --message -C --reuse-message --author --date --fixup --squash --cleanup --trailer", kRead, "-F --file -t --template --pathspec-from-file", kExec, "-e --edit")},
		"switch":   {opts: opts(kFlag, "-d --detach -t --track --no-track --guess --no-guess -q --quiet --ignore-other-worktrees --recurse-submodules --no-recurse-submodules", kValue, "-c --create --orphan", kDeny, "--discard-changes")},
		"checkout": {check: checkoutCheck, opts: opts(kFlag, "-d --detach -t --track --no-track -q --quiet --guess --no-guess --recurse-submodules --no-recurse-submodules --ignore-other-worktrees", kValue, "-b -B --orphan", kDeny, "--discard-changes")},
		"restore":  {check: restoreCheck, opts: opts(kFlag, "--staged -S --worktree -W -p --patch -q --quiet --overlay --no-overlay --ignore-unmerged --recurse-submodules --no-recurse-submodules", kValue, "-s --source", kRead, "--pathspec-from-file")},
		"branch": {opts: opts(kFlag, "-a --all -v -vv --verbose -r --remotes -l --list -m --move -c --copy --show-current -t --track --no-track -q --quiet --color --no-color --column -i --ignore-case --abbrev --contains --no-contains --merged --no-merged -d",
			kValue, "--sort --format --points-at", kExec, "--edit-description")},
		"stash": {subOptional: true, opts: opts(kFlag, "-u --include-untracked -a --all -k --keep-index --no-keep-index -p --patch -q --quiet -S --staged", kValue, "-m --message"), subs: map[string]*cmdSpec{
			"push":   {opts: opts(kFlag, "-u --include-untracked -a --all -k --keep-index --no-keep-index -p --patch -q --quiet -S --staged", kValue, "-m --message", kRead, "--pathspec-from-file")},
			"save":   {opts: opts(kFlag, "-u --include-untracked -a --all -k --keep-index --no-keep-index -p --patch -q --quiet -S --staged")},
			"list":   {opts: gitLogOpts},
			"show":   {opts: gitLogOpts},
			"pop":    {opts: opts(kFlag, "--index -q --quiet")},
			"apply":  {opts: opts(kFlag, "--index -q --quiet")},
			"branch": {},
			"drop":   {deny: "it throws a stash away"},
			"clear":  {deny: "it throws every stash away"},
		}},
		"merge": {opts: opts(kFlag, "--no-ff --ff-only --ff --abort --continue --quit --squash --no-squash --no-commit --commit --no-edit -q --quiet -v --verbose --stat -n --no-stat --allow-unrelated-histories --autostash --no-autostash --log --no-log --signoff --no-signoff --no-verify --verify --rerere-autoupdate", kValue, "-m --message -X --strategy-option", kRead, "-F --file", kExec, "-e --edit")},
		"rebase": {check: rebaseCheck, opts: opts(kFlag, "--continue --abort --skip --quit --autostash --no-autostash --autosquash --no-autosquash --keep-base --root --no-ff -q --quiet -v --verbose --stat --no-stat -r --rebase-merges --update-refs --no-update-refs --fork-point --no-fork-point --signoff --committer-date-is-author-date --reapply-cherry-picks --no-reapply-cherry-picks --ignore-date --no-verify --verify", kValue, "--onto --empty -X --strategy-option",
			kExec, "-i --interactive -x --exec --edit-todo")},
		"cherry-pick": {opts: opts(kFlag, "-x -n --no-commit --continue --abort --skip --quit --ff --allow-empty --allow-empty-message --keep-redundant-commits -s --signoff --no-edit --rerere-autoupdate --no-rerere-autoupdate", kValue, "-m --mainline -X --strategy-option", kExec, "-e --edit")},
		"revert":      {opts: opts(kFlag, "--no-edit -n --no-commit --continue --abort --skip --quit -s --signoff --rerere-autoupdate --no-rerere-autoupdate", kValue, "-m --mainline -X --strategy-option", kExec, "-e --edit")},
		"mv":          {operands: []argKind{kWrite}, opts: opts(kFlag, "-v --verbose -n --dry-run -k")},
		"rm":          {operands: []argKind{kWrite}, opts: opts(kFlag, "-r -n --dry-run -q --quiet --cached --ignore-unmatch --sparse")},
		"blame":       {opts: opts(kFlag, "-w -e --show-email -s -p --porcelain --line-porcelain -l -t -f --show-name -n --show-number --root --incremental -b --first-parent --reverse --progress --no-progress --abbrev --score-debug --show-stats", kGlued, "-M -C", kValue, "-L --since --date --ignore-rev", kRead, "--contents -S --ignore-revs-file")},
		"grep": {numeric: true, opts: opts(kFlag, "-n -i -w -l --files-with-matches -L -c -v -E -F -G -P -h -H -I -a -o -q -r --recursive -z --null --heading --break --column --untracked --no-index --cached --text --count --line-number --ignore-case --word-regexp --invert-match --extended-regexp --fixed-strings --perl-regexp --all-match --and --or --not -p --show-function -W --function-context --color --no-color --no-recursive --exclude-standard --full-name --files-without-match --only-matching --quiet --no-line-number --basic-regexp",
			kValue, "-e -A -B -C -m --max-count --max-depth --threads --after-context --before-context --context", kRead, "-f", kExec, "-O --open-files-in-pager")},
		"rev-parse": {opts: opts(kFlag, "--show-toplevel --abbrev-ref --short --git-dir --is-inside-work-tree --is-inside-git-dir --verify -q --quiet --symbolic --symbolic-full-name --absolute-git-dir --show-prefix --show-cdup --git-common-dir --is-bare-repository --is-shallow-repository --all --branches --tags --remotes --sq --revs-only --no-revs --flags --no-flags --show-superproject-working-tree --show-object-format", kValue, "--git-path --default")},
		"ls-files":  {opts: opts(kFlag, "-c --cached -d --deleted -m --modified -o --others -i --ignored -s --stage -u --unmerged -k --killed -z --directory --no-empty-directory --eol --full-name -t -v --exclude-standard --error-unmatch --recurse-submodules --deduplicate --abbrev --sparse", kValue, "-x --exclude --exclude-per-directory --format", kRead, "-X --exclude-from")},
		"describe":  {opts: opts(kFlag, "--tags --all --always --long --abbrev --dirty --broken --contains --exact-match --first-parent", kValue, "--match --exclude --candidates")},
		"shortlog":  {numeric: true, opts: opts(gitLogOpts, kFlag, "-s --summary -n --numbered -e --email --committer", kValue, "-w --group")},
		"show-ref":  {opts: opts(kFlag, "--head --tags --heads -d --dereference -s --hash --verify -q --quiet --abbrev --exists")},
		"cat-file":  {opts: opts(kFlag, "-t -s -e -p --batch --batch-check --batch-all-objects --buffer --follow-symlinks -Z --allow-unknown-type --mailmap --use-mailmap", kExec, "--textconv --filters")},
		"worktree": {subs: map[string]*cmdSpec{
			"add":    {operands: []argKind{kWrite}, opts: opts(kFlag, "-d --detach --checkout --no-checkout --lock -q --quiet --track --no-track --guess-remote --no-guess-remote", kValue, "-b --orphan --reason")},
			"list":   {opts: opts(kFlag, "-v --verbose --porcelain -z", kValue, "--expire")},
			"move":   {operands: []argKind{kWrite}},
			"remove": {deny: "it deletes a worktree"},
			"prune":  {deny: "it deletes worktrees"},
		}},
		"push": {deny: "it publishes your work"},
	},
}

// rebaseCheck: git rebase --update-refs (or the rebase.updateRefs setting, which the command line can't show)
// moves other local branches whose tips are in the replayed range, main included. So a rebase that starts
// must say --no-update-refs; --update-refs asks; --continue, --abort, --skip and --quit go on with or end a
// rebase that was started (and approved) already.
func rebaseCheck(c *call) string {
	if c.seen["--update-refs"] {
		return "git rebase --update-refs moves other branches"
	}
	for _, f := range []string{"--continue", "--abort", "--skip", "--quit"} {
		if c.seen[f] {
			return ""
		}
	}
	if !c.seen["--no-update-refs"] {
		return "git rebase without --no-update-refs (a rebase.updateRefs setting would move other branches)"
	}
	return ""
}

// ---- the branch rule of a project trust ----

// branchListFlags make `git branch` list branches: the operands are patterns, not names to create.
var branchListFlags = []string{"-l", "--list", "-a", "--all", "-r", "--remotes", "--show-current", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at"}

// branchRule is the extra check of a project trust, run on a git command the option tables accepted: a
// command that switches to or creates a branch is allowed only for a name that matches pattern. It reads
// what checkArgs parsed (option values, operands), so every spelling of an option is covered. A name with
// a wildcard, "..", or "-" (the previous branch) never matches. Commands that only list, commit, merge or
// cherry-pick stay on their branch and are not looked at here; `git tag`, `git push` and the rest of what
// the tables refuse never get this far.
func branchRule(c *call, pattern string) string {
	var names []string
	operand := func(i int) {
		if i < len(c.operands) {
			names = append(names, c.operands[i].text)
		}
	}
	switch c.name {
	case "git switch": // a detached switch (--detach X) names X too: it asks unless X is in the pattern
		names = append(append(append(names, c.vals["-c"]...), c.vals["--create"]...), c.vals["--orphan"]...)
		if len(names) == 0 {
			operand(0)
		}
	case "git checkout":
		names = append(append(append(names, c.vals["-b"]...), c.vals["-B"]...), c.vals["--orphan"]...)
		if len(names) == 0 {
			operand(0)
		}
	case "git branch":
		if c.seen["-m"] || c.seen["--move"] || c.seen["-c"] || c.seen["--copy"] || c.seen["-d"] || c.seen["--delete"] {
			for i := range c.operands { // rename, copy, delete: every name is one, whatever else (-r) is given
				operand(i)
			}
			break
		}
		for _, f := range branchListFlags {
			if c.seen[f] {
				return ""
			}
		}
		operand(0) // create: the name, then a start point
	case "git worktree add":
		names = append(append(names, c.vals["-b"]...), c.vals["--orphan"]...)
		if len(names) == 0 && !c.seen["-d"] && !c.seen["--detach"] {
			switch len(c.operands) {
			case 0:
			case 1: // git makes a branch named like the directory
				names = append(names, path.Base(c.operands[0].text))
			default:
				operand(1)
			}
		}
	case "git stash branch":
		operand(0)
	case "git rebase": // rebase UPSTREAM BRANCH switches to BRANCH first
		if c.seen["--root"] {
			operand(0)
		} else {
			operand(1)
		}
	}
	for _, n := range names {
		if !branchMatches(pattern, n) {
			return c.name + " of branch " + oneLine(n, 60) + ", which is outside the project trust's branches (" + pattern + ")"
		}
	}
	return ""
}

// branchMatches: name is a plain branch name that matches the path.Match pattern.
func branchMatches(pattern, name string) bool {
	if name == "" || strings.ContainsAny(name, "*?[\\") || strings.Contains(name, "..") || strings.HasPrefix(name, "-") {
		return false
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}
