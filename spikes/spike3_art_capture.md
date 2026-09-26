# SPIKE-3: ART atomic capture -> TES trace

**Result: PASS** (2026-09-26)

## Atomic used

[T1070.004](https://attack.mitre.org/techniques/T1070/004) — Indicator Removal on Host: File
Deletion, **Atomic Test #2: "Delete an entire folder - FreeBSD/Linux/macOS"**
(`auto_generated_guid: a415f17e-ce8d-4ce2-a8b4-83b674e7017e`, from
[atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md)).
Confirmed macOS-supported. Attack command: `rm -rf #{folder_to_delete}`.

Chosen over other macOS-tagged atomics (e.g. T1490's "Disable Time Machine")
because its command only ever touches a folder we create ourselves (no real
data at risk), and its file-deletion pattern maps directly onto our own
`RapidFileModBurst` detector (FR-D-8) — the two other T1490/T1204 candidates
found by scanning the atomic-red-team repo either needed real elevation with
system-wide side effects (`tmutil disable`) or were Windows-only.

## Method (FR-R-8: isolated environment)

1. `mkdir /tmp/tcell-spike3-victim` + 100 dummy files (the atomic's own
   target; not real data).
2. `sudo eslogger exec fork open create rename unlink exit` capturing to
   `spikes/out/spike3_capture.ndjson` (gitignored, matches spike1's
   convention) — same primary source as FR-D-2, needs root + Full Disk
   Access (already granted per SPIKE-1).
3. Ran the atomic under `sandbox-exec` for isolation:
   `sandbox-exec -p '(version 1)(allow default)(deny file-write* (subpath "/Users"))(deny file-write* (subpath "/Library"))(deny file-write* (subpath "/System"))(deny file-write* (subpath "/Applications"))' rm -rf /tmp/tcell-spike3-victim`
   — allow-by-default, deny writes outside `/tmp` to the real home/system
   directories. A stricter deny-by-default profile (only explicitly
   allowing process-exec + file ops under `/tmp`) caused `rm` to abort
   (SIGABRT, likely missing a permission `rm` needs even for its own
   bookkeeping, e.g. mach-lookup) — not pursued further given time, the
   allow-default/deny-outside-tmp profile is adequate containment for this
   atomic's blast radius.
4. Stopped the capture (`sudo kill`).

Root cause of two earlier failed attempts, for the record: backgrounding
`sudo eslogger ...` with `&` immediately (before sudo had a cached
timestamp) meant sudo couldn't get an interactive password prompt at all —
the redirected capture file was never even created. Fixed by running
`sudo -v` alone first (foreground, real password prompt), then the
backgrounded capture command reused the cached credential.

## Result

- 318 raw eslogger lines captured; **0 rejected, 0 adapter_errors** when
  replayed through Scout's real pipeline (`scout --eslogger-file
  spikes/out/spike3_capture.ndjson --dry-run`) — confirms the raw-capture
  -> TES-normalization pipeline works cleanly for a real ART atomic. This
  is SPIKE-3's actual pass/fail bar ("confirm 1 ART atomic captures to a
  TES trace"), and it's clean.
- 101 `unlink` events under `/private/tmp/tcell-spike3-victim/`, all within
  a ~9.7ms window — comfortably past `RapidFileModBurst`'s `BURST_OPS`
  (>=64) and `BURST_WINDOW_NS` (1s) thresholds. Exec events confirm `/bin/rm
  -rf /tmp/tcell-spike3-victim` ran as a child of `/usr/bin/sandbox-exec`,
  itself a child of the shell.
- Scout's pipeline reported `"detections":0` for this trace. Not a bug:
  `RapidFileModBurst` alone is 40 of the 100 points scoring.rs requires
  (all three Stage-1 actions must corroborate — see scoring.rs's own doc
  note), and this single atomic only trips that one signal. Confirms
  scoring.rs's threshold logic is working as designed, not over-triggering
  on a lone weak signal.

## Implication for Phase 7 / AC-3

FR-R-5's "SHOULD be captured from a real ART atomic" is now confirmed
feasible, informing trace-capture/main.rs's design (staged next). For
AC-3's demo ("at least one real ART atomic detected on stage"): this
single atomic alone won't cross Scout's 100pt bar by itself — a live demo
moment would need either a chained sequence of atomics hitting multiple
Stage-1 signals, or AC-3 read as "recognized as a Stage-1 action" rather
than "crosses full conviction." Flagging for whoever choreographs the demo;
not solved here, out of scope for trace-capture itself.
