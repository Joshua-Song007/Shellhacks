#!/bin/sh
# Benign, on-stage-safe Stage-1 trigger (Phase 9 item 8). Builds
# test_threat.c fresh into a private temp dir (not an Apple-platform
# binary, same reason spike1_eslogger.sh does this) and runs it as a
# child, so its exec event (target = a temp-dir path -> ExecFromTempOrCache)
# rolls up into this script's own lineage -- a shell invoked with a script
# argument is not an "interactive shell" boundary per lineage.rs's own
# rule, so this doesn't need to `exec`-replace itself to stay one lineage.
# Deliberately NOT `exec`: a replaced process has no shell left to run the
# EXIT trap below, which would leak $WORK on every run (caught live during
# this item's own verification). See test_threat.c for the rest of the
# narrative (burst -> tamper-shaped exec).
set -eu

# Guard added after a real live incident: running this script attached to a
# terminal/agent foreground job rolls its whole process tree into the
# invoking shell's own lineage.rs lineage (neither an interactive shell nor
# a `-c`/script-arg shell is a lineage boundary), so when Scout convicts it,
# suspend_all() SIGSTOPs the invoking shell/agent process along with the
# trigger. The real Electron "Run test threat" button is unaffected --
# backend.cjs spawns this with stdio:'ignore', so stdout is never a tty.
if [ -t 1 ] && [ "${TCELL_ALLOW_FOREGROUND:-}" != "1" ]; then
	echo "test_threat.sh: refusing to run attached to a terminal (this would" >&2
	echo "freeze this shell/session if Scout convicts the trigger's lineage)." >&2
	echo "Run it detached instead, e.g.:" >&2
	echo "  nohup \"$0\" \"\$@\" > /tmp/test_threat.log 2>&1 & disown" >&2
	echo "or set TCELL_ALLOW_FOREGROUND=1 to run anyway." >&2
	exit 1
fi

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tcell-demo.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

cc -O0 -o "$WORK/payload" "$SRC_DIR/test_threat.c"
cp "$WORK/payload" "$WORK/tmutil"

"$WORK/payload" burst
