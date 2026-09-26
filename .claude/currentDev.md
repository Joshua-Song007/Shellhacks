## Status: Staged
Task: Phase 7 (plan.md) — crates/trace-capture/src/main.rs.
SPIKE-3 already run and PASSED this session (see plan.md Phase 0, spikes/spike3_art_capture.md) — real ART atomic T1070.004 Test #2 captured cleanly to TES via eslogger + sandbox-exec. This stage encodes that exact proven recipe as a reusable one-shot CLI tool, deterministically (waits on the atomic's real exit, not fixed sleeps).
User decision 2026-09-26: trace-capture gets a narrow scout dependency, reusing ONLY scout::source_eslogger::map_line (pure parsing fn) — not the live detection pipeline, not reader::spawn/source_eslogger::spawn (those are small enough to reimplement directly here, unlike map_line's much larger ES-schema mapping logic). architecture.md's "trace-capture -> tes" line gets updated to "-> tes, scout (map_line only)".

### Scaffold
- new crate crates/trace-capture; add to root Cargo.toml workspace members (+ default-members)
- Cargo.toml deps: tes (path), scout (path, for source_eslogger::map_line only), serde_json (already used transitively but need direct access for one-off parsing if needed)
- Linux-VM path (FR-R-8's "and/or a free-tier Linux VM (other atomics)") NOT implemented — no non-macOS telemetry source exists anywhere in this codebase (eslogger is macOS-only); scoped to macOS/eslogger only, noted as a deferred gap, no revisit scheduled unless a Linux atomic ever gets prioritized

### crates/trace-capture/src/main.rs (FR-R-5, FR-R-8)
- usage: `sudo trace-capture --output PATH [--profile-file PATH] [--warmup-ms N (default 500)] [--cooldown-ms N (default 1000)] -- <atomic-command...>` — run with sudo directly (matches scout's own `sudo scout` pattern); internally calls `eslogger` as a direct child, no internal sudo escalation needed since the whole process is already root
- default sandbox-exec profile = the SPIKE-3-validated one, embedded as a const string: `(version 1)(allow default)(deny file-write* (subpath "/Users"))(deny file-write* (subpath "/Library"))(deny file-write* (subpath "/System"))(deny file-write* (subpath "/Applications"))`; `--profile-file` overrides it
- flow: spawn `eslogger exec fork exit open create rename unlink` (same fixed kind list as FR-D-2, hardcoded, no need to make configurable) with stdout piped, reading lines directly in a loop (no scout::reader reuse -- this is a one-shot offline tool, not sustaining a live high-throughput stream under NFR-7 pressure, so the decoupled-reader apparatus isn't needed) -> sleep `warmup_ms` (SPIKE-1 noted ~180ms Gatekeeper/XProtect delay on first launch of a fresh binary; warmup absorbs that) -> spawn `sandbox-exec -p <profile> <atomic-command...>` as a foreground CHILD PROCESS and **wait on its actual exit status** (deterministic, not a guessed sleep -- strictly better than the manual SPIKE-3 recipe, which had to background+guess because of the sudo/TTY constraint that doesn't apply here since trace-capture itself is already root) -> sleep `cooldown_ms` to flush trailing events -> kill the eslogger child -> drain remaining buffered lines
- `pub fn normalize(raw_lines: impl Iterator<Item = String>) -> (Vec<String>, RejectStats)` — pure, unit-testable without root/eslogger: maps each raw line via `scout::source_eslogger::map_line`, validates via `tes::validate::Validator`, collects accepted lines as NDJSON strings + counts rejects (mirrors FR-D-5/NFR-7's "never silently drop" discipline)
- `RejectStats { adapter_errors: u32, validation_rejects: u32, seq_gaps: u32 }` — printed to stderr as a summary after writing output, matching NFR-7's observability requirement even for this offline tool
- writes `normalize`'s accepted lines to `--output` as NDJSON (the TES trace), ready to hand to soldier's `--trace`/`--benign-trace` (Phase 3, already built)
- exits non-zero with a clear message if the atomic command exits non-zero itself (capture still gets written -- a failed atomic run is still useful signal, not discarded) or if eslogger never started (root/FDA check, matching scout main.rs's own error message style)

### Tests
- commit a small trimmed excerpt of the real SPIKE-3 capture (spikes/out/spike3_capture.ndjson is gitignored, not a permanent fixture) as `crates/trace-capture/tests/fixtures/spike3_excerpt.ndjson` -- matches scout's own precedent (tests/fixtures/eslogger_trigger.ndjson, committed, validated against the SPIKE-1 capture)
- unit tests for `normalize`: the committed excerpt normalizes with zero adapter_errors/validation_rejects and the expected unlink count; a deliberately malformed injected line increments validation_rejects without dropping silently; empty input produces empty output + zero stats
- no live spawn/eslogger test (needs root, same as scout's own main.rs and ac2_bench.rs precedent of "not yet run live" for the process-spawning glue) -- `normalize` is where the real logic lives and is fully covered

### On apply, also update
- plan.md: check off trace-capture/main.rs w/ notes per above (Linux-VM gap, scout dependency scope, deterministic wait-on-exit vs SPIKE-3's manual sleep-based recipe)
- architecture.md: "trace-capture -> tes, scout (map_line only)" dependency line + a short "Trace-capture internals" section
- branchDep.md: note the new crate's deps (all path-based, no new external crates expected)
