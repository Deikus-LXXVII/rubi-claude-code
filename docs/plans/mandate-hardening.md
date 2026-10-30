# B5: Mandate hardening (explicit option tables)

Brief from Цитри's audit (2026-10-30, F2/B5). Branch `citri/mandate-hardening` from `citri/cc-polish`
(A6–A11, A17, A18), not pushed. A4/A5 (the F2 probe cases) are already in mandate.go and
`TestMandateWritesAndRunsOnlyInside`; this task makes the design deny-by-default.

## Goal
A 2-hour mandate allows exactly what its approval text says. Every option of an allowed program is
known and classified; an unknown option asks.

## Design
- Replace the per-program `argRule` grab bag with a table of `cmdSpec`:
  - `opts map[string]argKind` for every option the mandate accepts, long and short spellings.
    Kinds: `flag` (no value), `value` (takes a value that names no file), `read` (a path that is read:
    anywhere except credential paths), `write` (a path that is written: inside root and not under .git),
    `exec` (names a program or code to run: always asks; listed so the reason is specific).
  - Parsing: `--long=v` and `--long v`; short `-o v` and glued `-ov`; short clusters `-abc` where every
    letter is a flag and only the last may take a value; `--` ends options. Program-specific quirks
    (find's single-dash long options, go's single-dash long flags `-race`, `-run=x`) are declared on the
    spec, not special-cased in the parser.
  - `operands argKind` (or per-position kinds, e.g. uniq/xxd: read then write).
  - `subs map[string]*cmdSpec` for git, go, cargo, npm/pnpm/yarn, swift; options before the subcommand
    use the parent's table, after it the subcommand's.
  - `check func(...) string` for semantics a table can't say (git checkout ., rm of root or .git, make
    VAR=value, publishing names, cd tracking, go env -w, worktree remove/prune, stash drop/clear).
- Unknown option of an allowed program → ask ("option X isn't on the mandate's list for P").
- Writes under `.git` (hooks, config, anything) ask; any exec-kind option asks.
- Keep: splitShell, alwaysAsk, secretPath, hasURL, riskyEnv, wrappers, programs by path ask.

## Docs
- main.go trust option Meaning and README "Trust a session for 2 hours": say that options are checked
  against a list and unknown ones ask; keep the honest note that builds/tests run project code.

## Tests
- Table tests per program: allowed everyday forms and refused forms (including every F2 probe).
- `FuzzMandate`: structured fuzzer building commands from a vocabulary (programs, options incl.
  unknown ones, paths inside/outside/.git/secret, separators, redirections); asserts via an independent
  oracle that an allowed command has no write target outside root or in .git, no exec option, no
  secret path, no URL. Seed corpus = F2 probes.
- Acceptance: every F2 probe asks; existing tests pass; `go test -fuzz=FuzzMandate -fuzztime=60s` clean;
  `go vet ./...`, `go test -race ./...`, e2e if it runs locally.

## Status
- [x] implement (spec tables: mandate_spec.go, mandate_programs.go, mandate_git.go)
- [x] tests: table tests, review regressions, FuzzMandate with an independent oracle (60 s clean),
      real-zsh oracle with recorder stubs, real-git checkout/restore test
- [x] review: 3 rounds (reviewer with real-shell probes, grok-reviewer); all Major fixed
- [x] e2e (Linux container) PASS
- Residuals (documented): `git checkout <one name>` can be a path; symlinks already in the project;
  zsh cdablevars/CDPATH from the user's config; project code run by builds.
