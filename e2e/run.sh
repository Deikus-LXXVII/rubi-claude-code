#!/usr/bin/env bash
# End-to-end check of Claude Code approvals on one machine, without network (unshare -rn) and without
# touching any real Rubi: a throwaway daemon and helper in a temp dir, a local signed catalog, an
# in-process relay, and `rubi-home claude-hook` playing Claude Code. Cases: approve -> allow,
# deny -> deny with the reason, no answer -> deny, a passkey tap on a safe command -> allow, a tap on any
# other command -> refused (then deny), Rubi locked -> deny; a Bot binds to a desktop-app session (only
# with its webhook's agent code, strong approval), sends a message, the Stop hook hands it to Claude and
# the answer and a rubi-ask come back to that Bot, also with the session in bypassPermissions; "trust
# this session for 2 hours" auto-allows plain commands, a push still asks, revoke ends it; a Bot starts a
# new session (claude_code_start; the helper is built with -tags rubie2e so its launcher writes the claude://
# link to a file instead of opening the app) and is bound to it; "trust this project until 04:00" lets other
# sessions of the project and the bound Bot (start, bind) run without questions, still asks outside it / for
# push, tags and other branches, holds over a Rubi Home restart, ends on revoke and at its time (the plugin is
# built with -tags rubie2e, whose only additions are files that shorten the trust and move the plugin's clock),
# and does not beat a locked Rubi. "Trust this project until I revoke it" (no end time) holds over a Rubi Home
# restart and 25 hours and 40 days later (the fake clock), still asks for push, tags, other branches, a rebase
# without --no-update-refs and anything outside the root, ends at once on revoke, a Bot can ask for it
# (claude_code_trust_project until=revoked), and a locked Rubi beats it too.
#
#   RUBI_REPO=../rubi e2e/run.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PLUGIN_REPO=$(cd "$HERE/.." && pwd)
RUBI_REPO=$(cd "${RUBI_REPO:-$PLUGIN_REPO/../rubi}" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/rubi-claude-e2e.XXXXXX")
case "$WORK" in /tmp/*|"${TMPDIR:-/tmp}"/*) ;; *) echo "refusing WORK=$WORK"; exit 1;; esac
unshare -rn true 2>/dev/null || { echo "unshare -rn is not permitted here; refusing to run a daemon with network"; exit 1; }
echo "work dir: $WORK"

printf '{"Replace":{"%s/cmd/rubi-claude-e2e/main.go":"%s/_driver/main.go"}}' "$RUBI_REPO" "$HERE" >"$WORK/overlay.json"
(cd "$RUBI_REPO" &&
  go build -race -overlay "$WORK/overlay.json" -o "$WORK/e2e" ./cmd/rubi-claude-e2e &&
  go build -race -o "$WORK/rubi" ./cmd/rubi &&
  go build -race -tags rubie2e -o "$WORK/rubi-home" ./cmd/rubi-home)  # rubie2e: the launcher writes the claude:// link to a file
KEY=$("$WORK/e2e" keys "$WORK")
(cd "$PLUGIN_REPO" && go build -race -tags rubie2e -ldflags "-X main.PublisherKey=$KEY" -o "$WORK/claude-code" .)

rc=0
unshare -rn bash -c 'ip link set lo up && exec "$1/e2e" run "$1" "$1/rubi" "$1/rubi-home" "$1/claude-code"' _ "$WORK" || rc=$?
if [ $rc != 0 ]; then
  echo "--- daemon.log (tail)"; tail -40 "$WORK/daemon.log" 2>/dev/null || true
  echo "--- rubi-home.log (tail)"; tail -40 "$WORK/rubi-home.log" 2>/dev/null || true
  echo "--- rubi-home-restarted.log (tail)"; tail -40 "$WORK/rubi-home-restarted.log" 2>/dev/null || true
  echo "kept $WORK for inspection"
  exit $rc
fi
rm -rf "$WORK"; echo "E2E done"
