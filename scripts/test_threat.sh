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

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tcell-demo.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

cc -O0 -o "$WORK/payload" "$SRC_DIR/test_threat.c"
cp "$WORK/payload" "$WORK/tmutil"

"$WORK/payload" burst
