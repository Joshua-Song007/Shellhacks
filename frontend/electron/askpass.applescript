#!/usr/bin/osascript
-- SUDO_ASKPASS helper (see backend.cjs's scoutSpawn/spawnScout): sudo execve's
-- this file directly and expects the password alone on stdout. A leading "#"
-- is an AppleScript comment, so the shebang above is both a valid Unix
-- interpreter line (osascript can run a script named directly on argv[0],
-- same as any #!-script) and valid AppleScript, ignored by the compiler.
-- osascript prints a top-level script's final result to stdout automatically
-- -- exactly the protocol sudo -A expects, no extra plumbing needed.
-- Cancelling the dialog makes "display dialog" throw (user canceled), so this
-- script exits nonzero with no stdout -- sudo reads that as "no password
-- given" and fails closed, which is exactly the signal backend.cjs's fallback
-- to --libproc is watching for.
display dialog "T-cell wants administrator access to monitor system-wide file and process activity for full threat detection. Enter your password, or Cancel to run with reduced (no-root) detection instead." with title "T-cell" with icon caution with hidden answer default answer "" buttons {"Cancel", "Allow"} default button "Allow" cancel button "Cancel"
text returned of result
