# Architecture

File/module structure and internal component-to-component dependency graph. This describes structural dependencies (what imports/depends on what) — for build order and per-file implementation detail, see `plan.md`.

## Module tree
```
Cargo.toml        workspace (members: tes, scout; ledger-program is a separate Anchor workspace)
crates/
  tes/            schema.rs, validate.rs, schema/tes_v1.schema.json, tests/schema_twin.rs
  scout/          reader.rs, source_eslogger.rs, source_libproc.rs, source_beacon.rs, lineage.rs, scoring.rs, pipeline.rs, main.rs
                  tests/pipeline.rs, tests/fixtures/eslogger_trigger.ndjson
  soldier/        trigger.rs, sandbox.rs, allele_search.rs, replay_target.rs, reenactor.rs, gene_compile.rs, main.rs
  ledger-program/ programs/t_cell/src/{state.rs, poi.rs, lib.rs}
  ledger-client/  client.rs
  mesh/           identity.rs, transport.rs, message.rs, verify.rs, revocation.rs
  trace-capture/  main.rs
dashboard/        App.tsx, TelemetryView.tsx, LedgerFeed.tsx, MyDevices.tsx
spikes/           spike1_eslogger.sh, spike1_trigger.c, spike2_libp2p_pair.rs, spike3_art_capture.md
                  out/ (gitignored raw captures)
```

## Scout internals (A -> B means A calls/uses B)
- main -> source_eslogger::spawn (live), reader::spawn, pipeline; `--libproc` -> source_libproc::{ProcWatcher, FileWatcher}, pipeline (no reader: kqueue + FSEvents are already event-at-a-time); `--beacon` -> source_beacon::BeaconCollector, alongside any source, output kept separate from `detection`/`stats` (own `network_finding` record)
- pipeline -> source_eslogger::map_line, tes::Validator, lineage, scoring
- scoring -> lineage (LineageId only)
- source_libproc -> reader::now_ns, scoring::BURST_WINDOW_NS (attribution window)
- source_beacon -> reader::now_ns, source_libproc::exe_path (own-uid exe resolution only); does not use tes (see Notes)
- bin/ac2_bench -> source_eslogger::{spawn, map_line}, reader::{spawn, now_ns}, scoring::{Action, exec_actions}, tes::Validator; standalone binary, not linked by main.rs
- reader, lineage, source_eslogger -> no other scout module

## Dependency graph (A -> B means A depends on B)
- scout -> tes
- soldier -> tes, scout (wake-signal contract only — `scout::scoring::{WakeSignal, Action}` — not scout internals)
- ledger-program -> (none internal; standalone Anchor program)
- ledger-client -> ledger-program (account layout/IDL)
- mesh -> tes (DATA-3 payload), ledger-client (async chain lookup)
- trace-capture -> tes (offline, isolated; not on hot path of scout/soldier)
- dashboard -> scout (telemetry stream), ledger-client (ledger feed), mesh (My Devices status)
- spikes -> none (throwaway, gate Phase 1+ start)

## Notes
- tes is the only crate every other crate may depend on directly; no other cross-crate deps besides what's listed above (keeps §10 boundary + NFR-5 auditable).
- reenactor.rs (soldier) is MAY-tier; if unimplemented, sandbox.rs operates on trace data only, no live process dependency.
- Scout I/O: stdout = NDJSON `{"type":"detection"|"stats",…}` records (dashboard input); wake signals go to Soldier as one JSON line per connection on the `--wake-socket` Unix stream.
- reader.rs (scout) sits between source_eslogger.rs's stdout and tes::validate; decouples pipe read from parse so a slow parser can't backpressure the OS pipe (FR-D-7a); its drop counter + validate.rs's seq-gap counter are the two observable-loss signals required by NFR-7.
- source_beacon.rs is intentionally outside the tes/Pipeline dependency graph: TES v1 (DATA-1) models a lossless, nanosecond-precision event stream, and an `lsof -i` poll is neither (see plan.md). Its findings are their own `network_finding` stdout record, un-scored and never fed to `Pipeline`; NFR-7's loss counters do not apply to it (it has its own `beacon` stats key instead: snapshots/lsof_errors/new_sightings/findings).
- gene payloads are chunked across multiple tx per CON-9/FR-R-9 whenever they exceed the ~900B post-overhead budget; ledger-client owns the chunking orchestration, ledger-program's commit_gene accepts either a single write or a sequence of appends into the same fixed-size (4096B) Genome Registry PDA.
</content>
