package main

import (
	"path"
	"strings"
)

// classify says whether a Bash command is on the short list of read-only commands that may be approved
// the quick way (the claude-code.run_safe action), and if not, why. It is deliberately conservative: a
// command is safe only if it is one plain command (no shell syntax at all: no pipes, redirections,
// substitutions, globs, quotes or variables), the program is ls, cat, pwd or git status/diff/log, and no
// argument names a credential or a path outside the project. Anything else needs the strong approval.
func classify(command string) (safe bool, why string) {
	if command == "" {
		return false, "empty command"
	}
	for _, r := range command {
		if !plainRune(r) {
			return false, "uses shell syntax (" + describe(r) + ")"
		}
	}
	args := strings.Fields(command)
	if len(args) == 0 {
		return false, "empty command"
	}
	switch prog := args[0]; prog {
	case "ls", "cat", "pwd":
		if bad := riskyArg(args[1:]); bad != "" {
			return false, bad
		}
		return true, prog + " only reads"
	case "git":
		if len(args) < 2 {
			return false, "git without a command"
		}
		switch args[1] {
		case "status", "diff", "log":
		default:
			return false, "git " + args[1] + " isn't on the read-only list"
		}
		for _, a := range args[2:] {
			for _, opt := range gitWriteOptions {
				if a == opt || strings.HasPrefix(a, opt+"=") {
					return false, "git option " + opt + " can write files or run programs"
				}
			}
		}
		if bad := riskyArg(args[2:]); bad != "" {
			return false, bad
		}
		return true, "git " + args[1] + " only reads"
	default:
		return false, prog + " isn't on the read-only list"
	}
}

// plainRune: letters, digits and the punctuation of ordinary paths and options. Everything a shell gives
// a meaning to (| & ; < > ( ) $ ` \ " ' * ? [ ] { } ~ ! # and newlines) is left out.
func plainRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune(" ._/-,:=@%+^", r)
}

func describe(r rune) string {
	switch r {
	case '|':
		return "a pipe"
	case '>', '<':
		return "a redirection"
	case ';', '&', '\n':
		return "more than one command"
	case '$', '`':
		return "a substitution or variable"
	case '\t':
		return "a tab"
	}
	if r < ' ' || r == 0x7f {
		return "a control character"
	}
	return "the character " + string(r)
}

// gitWriteOptions make git diff or log write a file or run another program.
var gitWriteOptions = []string{"--output", "-o", "--ext-diff", "--textconv", "--exec-path", "-c", "--config-env",
	"--git-dir", "--work-tree", "--paginate"}

// sensitive are path parts that hold credentials or settings (lower case).
var sensitive = []string{".env", ".ssh", ".aws", ".gnupg", ".netrc", ".npmrc", ".pypirc", ".git-credentials",
	".docker", ".kube", ".config", ".claude", "keychain", "credential", "secret", "token", "password", "passwd",
	"shadow", "id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".key", ".p12", ".pfx", "history"}

// riskyArg returns why one of the arguments makes the command need the strong approval, or "".
func riskyArg(args []string) string {
	for _, a := range args {
		v := a
		if i := strings.IndexByte(a, '='); strings.HasPrefix(a, "-") && i > 0 {
			v = a[i+1:]
		} else if strings.HasPrefix(a, "-") {
			continue
		}
		if strings.HasPrefix(v, "/") || path.Clean(v) == ".." || strings.HasPrefix(path.Clean(v), "../") {
			return "reads outside the project (" + a + ")"
		}
		low := strings.ToLower(v)
		for _, s := range sensitive {
			if strings.Contains(low, s) {
				return "touches a credential or settings path (" + a + ")"
			}
		}
	}
	return ""
}
