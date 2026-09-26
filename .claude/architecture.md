# Architecture

File/module structure and internal component-to-component dependency graph. This describes structural dependencies (what imports/depends on what) — for build order and per-file implementation detail, see `plan.md`.

## Module tree
```
crates/
  tes/            schema.rs, validate.rs, schema/tes_v1.schema.json
  scout/          source_eslogger.rs, reader.rs, source_libproc.rs, source_beacon.rs, lineage.rs, scoring.rs, main.rs
  soldier/        trigger.rs, sandbox.rs, allele_search.rs, replay_target.rs, reenactor.rs, gene_compile.rs, main.rs
  ledger-program/ programs/t_cell/src/{state.rs, poi.rs, lib.rs}
  ledger-client/  client.rs
  mesh/           identity.rs, transport.rs, message.rs, verify.rs, revocation.rs
  trace-capture/  main.rs
dashboard/        App.tsx, TelemetryView.tsx, LedgerFeed.tsx, MyDevices.tsx
spikes/           spike1_eslogger.sh, spike2_libp2p_pair.rs, spike3_art_capture.md
```

## Dependency graph (A -> B means A depends on B)
- scout -> tes
- soldier -> tes, scout (wake-signal contract only, not scout internals)
- ledger-program -> (none internal; standalone Anchor program)
- ledger-client -> ledger-program (account layout/IDL)
- mesh -> tes (DATA-3 payload), ledger-client (async chain lookup)
- trace-capture -> tes (offline, isolated; not on hot path of scout/soldier)
- dashboard -> scout (telemetry stream), ledger-client (ledger feed), mesh (My Devices status)
- spikes -> none (throwaway, gate Phase 1+ start)

## Notes
- tes is the only crate every other crate may depend on directly; no other cross-crate deps besides what's listed above (keeps §10 boundary + NFR-5 auditable).
- reenactor.rs (soldier) is MAY-tier; if unimplemented, sandbox.rs operates on trace data only, no live process dependency.
- reader.rs (scout) sits between source_eslogger.rs's stdout and tes::validate; decouples pipe read from parse so a slow parser can't backpressure the OS pipe (FR-D-7a); its drop counter + validate.rs's seq-gap counter are the two observable-loss signals required by NFR-7.
- gene payloads are chunked across multiple tx per CON-9/FR-R-9 whenever they exceed the ~900B post-overhead budget; ledger-client owns the chunking orchestration, ledger-program's commit_gene accepts either a single write or a sequence of appends into the same fixed-size (4096B) Genome Registry PDA.
</content>
