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
  ledger-program/ Anchor.toml, keys/ (gitignored, 5 devnet PoI keypairs), programs/t_cell/
                  src/{constants.rs, error.rs, state.rs, poi.rs, instructions.rs, instructions/{submit_threat.rs, commit_gene.rs, suppress_gene.rs}, lib.rs}
                  tests/test_instructions.rs (litesvm, no local-validator/Node dependency)
  ledger-client/  lib.rs, client.rs, examples/devnet_smoke.rs (manual verification, not run in CI), examples/suppress.rs (AC-5 demo kill-switch CLI), tests/integration.rs (#[ignore]'d, needs a local solana-test-validator)
  mesh/           identity.rs, transport.rs, message.rs, verify.rs, revocation.rs
  trace-capture/  main.rs
frontend/         electron/{main,preload,backend}.cjs, src/{data,main,mesh,helix,genome,advisor}.js
advisor-service/  schema.sql (Postgres DDL), server.js (POST /v1/incident: auth -> Spaces -> Postgres -> Gemma; POST /v1/review: auth -> 7-day incident aggregates -> Gemma; POST /v1/explain: auth -> one genome block's derived fields -> Gemma, nothing stored), test.js
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

## Soldier internals (A -> B means A calls/uses B)
- trigger -> scout::scoring::WakeSignal (deserializes the line Scout's send_wake writes); no other scout/tes symbol
- sandbox -> wasmi only; no tes/scout dependency
- allele_search -> scout::scoring::Action (containment_value reuses Action::weight() rather than a second weight table); no tes dependency; defines the ContainmentTarget trait, implemented by replay_target
- replay_target -> scout::scoring::{Action, exec_actions, BURST_WINDOW_NS, BURST_OPS} (pure/stateless helpers only, not Scorer/lineage), tes::schema::{TesEvent, Event}; implements allele_search::ContainmentTarget
- gene_compile -> allele_search::{Allele, ALL} (bitmask encoding), sandbox::{Sandbox, SandboxError} (apply = instantiate); own sha2/wat deps; no tes/scout dependency
- regression -> allele_search::{Allele, ALL, ContainmentTarget} (decodes the `allele_bitmask` global back into a bitmask -> `Vec<Allele>`, inverse of gene_compile's private encoding, same bit order), replay_target::ReplayTarget (as the benign-behavior source via ContainmentTarget::benign_actions()), sandbox::Sandbox (instantiate); no gene_compile dependency (doesn't need to re-derive the encoding, only mirror its documented convention); no tes/scout dependency beyond what allele_search/replay_target already pull in
- lib.rs -> trigger, sandbox, allele_search, replay_target, gene_compile, regression (module declarations only)
- main.rs (binary entrypoint, not part of lib.rs) -> trigger, replay_target, allele_search, gene_compile, ledger_client::LedgerClient (submit_threat, fetch_genome_registry for the FR-L-7 check, commit_gene); lib.rs modules stay ledger-free, only the binary touches the chain

## Ledger program internals (A -> B means A calls/uses B)
- constants.rs -> anchor-lang only (SEED bytes, MAX_REPORTERS/MAX_GENE_BYTES caps); no other module
- state.rs -> constants (SEED/MAX_* for PDA seeds and fixed SPACE consts); defines ThreatRegistry, GenomeRegistry
- poi.rs -> error::TCellError only; hardcoded 5-pubkey POI_COMMITTEE + pure require_poi(&[Pubkey]) (no Signer/Anchor-runtime dependency, unit-testable with plain cargo test)
- instructions/submit_threat.rs -> constants::MAX_REPORTERS, error::TCellError, state::ThreatRegistry; no poi (ungated, corroboration only)
- instructions/commit_gene.rs, instructions/suppress_gene.rs -> poi::require_poi, state::GenomeRegistry, error::TCellError (commit_gene also constants::MAX_GENE_BYTES); both take 5 required (non-Option) Signer accounts, dedup/counted by poi::require_poi
- instructions.rs -> re-exports the 3 instruction files' Accounts structs (module declarations only)
- lib.rs -> declares constants/error/instructions/poi/state; #[program] block is thin wiring to each instructions/*.rs handle_* fn
- tests/test_instructions.rs -> litesvm (loads the built .so directly, no anchor-cli/local-validator/Node needed at test time) + the 5 devnet keypairs under keys/ (gitignored) for PoI-signing scenarios

## Ledger client internals (A -> B means A calls/uses B)
- client.rs -> t_cell::{instruction, accounts, state, ID, THREAT_SEED, GENOME_SEED, MAX_GENE_BYTES} (Anchor-generated types, reused directly rather than hand-encoded); anchor_lang::solana_program::{instruction::Instruction, system_program} (t_cell has no own solana_program re-export, goes through anchor-lang); solana_client::rpc_client::RpcClient (sync/blocking — matches the rest of this project, no async runtime anywhere yet); own MAX_CHUNK_BYTES=400 (independently declared, no dependency edge onto soldier's gene_compile.rs, which has a *different* ~900B constant for a *different* concern — compiled gene size, not tx-chunk size); `recent_signatures`/`all_genomes` (Phase 9 item 7b) add solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config + solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature -- `all_genomes` reuses the existing `AccountDeserialize` import as a filter over `get_program_accounts`' mixed ThreatRegistry/GenomeRegistry results, no new account-layout code
- lib.rs -> client (module declaration + re-export only)
- examples/devnet_smoke.rs, examples/suppress.rs, tests/integration.rs -> client::LedgerClient (public API only); integration.rs also directly constructs its own RpcClient for test-only airdrops (not part of LedgerClient's real surface — production clients don't fund themselves)
- examples/feed.rs (new, Phase 9 item 7b) -> client::LedgerClient::{recent_signatures, all_genomes} in a poll loop; two pure/unit-tested diff helpers (`new_signatures`, `genome_diff`) decide what's actually new since the last tick, matching `frontend -> process/NDJSON`'s "ledger-client `feed` example stdout" note below -- this is that process, now real

## Mesh daemon internals (crates/mesh/src/bin/meshd.rs, A -> B means A calls/uses B)
- composed `#[derive(NetworkBehaviour)] struct MeshBehaviour { ping, rr: request_response::json::Behaviour<WireRequest,WireResponse> }` on the `/tcell/pair/1` protocol -- derive-generated `MeshBehaviourEvent::{Ping,Rr}` confirmed by a scratch probe build, not guessed
- `WireRequest::{Pair{nonce_hex,pubkey}, Hint(mesh::message::CureHint), Status{status}}` / `WireResponse::{Ok{pubkey}, Err(String)}` -- both `Pair` and `Ok` carry the sender's own protobuf-encoded pubkey because a libp2p `PeerId` cannot be reversed into a `PublicKey`; every handler verifies `pubkey.to_peer_id() == observed_peer_id` before trusting a self-attested key
- `handle_inbound_pair`/`handle_pair_response` -> `mesh::identity::{Roster::admit, Roster::add_trusted}`; `handle_inbound_hint` -> `ledger_client::LedgerClient::fetch_genome_registry`, `mesh::verify::{evaluate, confirm_via_chain}`, `soldier::gene_compile::apply`
- `Stage3Adapter` -> `soldier::regression::check` + a `soldier::replay_target::ReplayTarget` loaded once at startup from `--benign-trace` (`ReplayTarget::from_traces(io::empty(), benign_reader)`, since meshd only ever needs `benign_actions()`)
- `MeshState` bundles `Roster`/`RevocationList`/`VerifiedHashCache`/`CorroborationTracker` plus meshd-only bookkeeping (`peer_id_of`/`pubkey_of` maps, per-peer status/heartbeat, single pending pairing code/join, monotonic `next_seq` for `CureHint::sign`); persisted to `--state PATH` as hex-pubkey JSON, 0600
- stdin commands (`#[serde(tag="cmd")]`): `pair_start`/`pair_join`/`broadcast`/`status`/`revoke`; stdout records: `listening`/`pair_code`/`paired`/`pair_error`/`hint`/`peer`/`revoked`

## Frontend backend internals (frontend/electron/backend.cjs, A -> B means A calls/uses B)
- `startBackend(opts)` -> four `spawn`ed children via a shared `spawnLineReader` helper (readline over stdout, NDJSON parse, auto-restart on unexpected exit): `scout` (default `--libproc`, NFR-3 no-root; `TCELL_SCOUT_MODE=eslogger` wraps in best-effort `sudo -n`), `meshd` (stdin kept open for `sendMeshCommand`), ledger-client's `feed` example -- each bridged onto a plain `EventEmitter` (`'scout'|'mesh'|'ledger'`)
- `WakeRelay` -> binds the canonical wake socket itself (the address given to `scout --wake-socket`; Scout is the client, per trigger.rs's own doc); FIFO-queues incoming `WakeSignal`s (`'wake'` event), serially spawns one ephemeral-socket Soldier per queued wake via `_deliverToFreshSoldier` -- readiness detected by matching soldier main.rs's own pre-existing stderr line `"dormant, waiting on"` (unmodified Rust side, no new marker), then connects as a client exactly like Scout's own `send_wake` (one JSON line, drop); captures Soldier's one `cure` stdout line as `'soldier'`, unlinks the ephemeral socket on child exit
- `runTestThreat()` -> `scripts/test_threat.sh` (Phase 9 item 8), fire-and-forget
- `startHostStatsPoller(events, getPids)` (2026-09-26 addendum, fixes a real bug: the System panel's cpu/mem were silently frozen at their sim baseline under a "Live" badge) -> polls real `ps -o pid=,%cpu=,%mem=` every 5000ms (matches scout's own `--stats-every` default) over scout+meshd+feed's real child pids (soldier excluded, short-lived/self-terminating per-wake), emits a new `'hoststats'` event; same lightweight-periodic-poll-off-the-detection-path pattern as source_beacon.rs's lsof lane (FR-D-11)
- wired into main.cjs/preload.cjs now, real (Phase 9 item 10): `main.cjs` calls `startBackend()` in `app.whenReady()`, forwards every backend event over one generic `tcell:event` IPC channel (`{channel,payload}`) to all windows, exposes `ipcMain.handle('tcell:mesh-command'|'tcell:run-test-threat', ...)`; `preload.cjs` exposes `window.tcell.{onEvent,sendMeshCommand,runTestThreat}` (plus the pre-existing `openGenome`) to both windows (shared preload script)

## Frontend live translator (frontend/src/data.js, Phase 9 item 11, A -> B means A calls/uses B)
- `real()` (used only when `window.tcell` exists; a plain browser keeps running the untouched `simulate()`) -> `window.tcell.onEvent` dispatches by `channel` to `onScout`/`onSoldier`/`onMesh`/`onLedger`, each mapping real NDJSON fields onto the SAME `feed`/`state` contract `simulate()` already produces
- `onScout` -> keys live incidents by `root_exe` (the only field both `Progress` and `Detection` records share -- `Detection` carries no lineage-id), reuses `WEIGHT`/`ACT_LABEL` (already defined for the sim path) to build `inc.tree.acts` from real embedded TES events; also tracks real `eps`/`lag` (2026-09-26 fix, see plan.md item 11) -- `eps` from delta(`stats.pipeline.accepted`)/delta(time) between consecutive real stats records, `lag` from the latest progress record's embedded `event.recv_ns - event.ts_ns`; `onHostStats` (new) sets real `cpu`/`mem` from backend.cjs's `'hoststats'` poller
- `onSoldier` -> on `source:'evolved'`, replays the EXISTING local `evaluate()`/`ALLELES` search (same fitness fn as allele_search.rs) seeded by the real detected schema for the step-by-step UI animation, but always finishes on Soldier's real `sequence`/`gene_hash` (a real `--benign-trace` collision this client can't see would otherwise diverge the local replay's own winner -- logged if so); registers `cure.ledger.submit_sig`/`commit_sigs` in a `pendingLedger` map for `onLedger` to resolve later, rather than faking a PoI-signature countdown
- `onLedger` -> `signature` records resolve `pendingLedger` entries (real `cured` transition fires here, not on the cure record itself); an unrecognized signature (feed.rs doesn't decode instruction data) becomes an honest `activity` block kind; `genome` records backfill real `bytes` onto a matching gene or ingest a network-learned one
- `onMesh` -> `pair_code` resolves `startPairing()`'s promise (nonce parsed back out of the real `uri`, since meshd doesn't send it separately); `paired`/`peer`/`revoked` drive real `state.devices` mutations, including cross-device status propagation (`sendMeshCommand({cmd:'status',...})` broadcasts this device's own phase, incoming `peer` records apply a real peer's broadcast status)
- `startPairing`/`cancelPairing`/`revoke` (exported) dispatch on `state.source` to `live*`/`sim*` implementations; `joinByUri` (new export) is live-only

## Dependency graph (A -> B means A depends on B)
- scout -> tes
- soldier -> tes, scout (wake-signal contract plus a handful of scout::scoring's pure, stateless helpers — `WakeSignal`, `Action`, `exec_actions`, `BURST_WINDOW_NS`, `BURST_OPS` — never Scorer/lineage/host-detection internals), ledger-client (main.rs only: FR-L-7 check + stage-4 commit; user-approved 2026-09-26)
- ledger-program -> (none internal; standalone Anchor program)
- ledger-client -> t_cell (path dependency on `crates/ledger-program/programs/t_cell`, `cpi` feature — a concrete cross-workspace dependency, not just an abstract "account layout/IDL" note; reuses t_cell's Anchor-generated instruction/accounts/state types directly rather than hand-encoding Borsh)
- mesh -> ledger-client (async chain lookup, verify.rs::confirm_via_chain -- real now, not just planned). NOT tes: DATA-3's payload (message.rs's CureHint) never needed a tes::schema type, its fields are already plain [u8;32]/u64/Vec<u8> -- the "mesh -> tes" edge in overview.md's dependency sketch never materialized as an actual `use tes::...` anywhere in this crate; if that stays true through revocation.rs (Phase 6 now fully built), architecture.md's dependency line should probably just drop tes, but leaving the note here rather than silently deleting the edge without user sign-off
- trace-capture -> tes, scout (narrow: source_eslogger::map_line only, user-approved 2026-09-26 -- not the live detection pipeline, not reader::spawn) (offline, isolated; not on hot path of scout/soldier)
- frontend -> process/NDJSON only, no Rust linkage (electron/backend.cjs spawns each and parses stdout, real now -- Phase 9 item 9): scout stdout (telemetry stream), soldier stdout (`cure`), meshd stdout (My Devices status), ledger-client `feed` example stdout (ledger feed)
- mesh -> soldier (meshd.rs only, real now: `soldier::regression::check` for Stage-3, `soldier::replay_target::ReplayTarget` to load `--benign-trace`, `soldier::gene_compile::apply` on Accept; user-approved 2026-09-26). lib.rs modules (identity/message/revocation/transport/verify) stay soldier-free, only the binary crosses castes -- same shape as soldier main.rs's own ledger-client edge
- spikes -> none (throwaway, gate Phase 1+ start)

## Notes
- tes is the only crate every other crate may depend on directly; no other cross-crate deps besides what's listed above (keeps §10 boundary + NFR-5 auditable).
- reenactor.rs (soldier) is MAY-tier; if unimplemented, sandbox.rs operates on trace data only, no live process dependency.
- Scout I/O: stdout = NDJSON `{"type":"progress"|"detection"|"stats",…}` records (dashboard input; `progress` = one per Stage-1 action credited to a lineage, pre-conviction); wake signals go as one JSON line per connection on the `--wake-socket` Unix stream: Scout -> frontend/electron/backend.cjs wake relay (FIFO buffer) -> Soldier, one wake per Soldier.
- reader.rs (scout) sits between source_eslogger.rs's stdout and tes::validate; decouples pipe read from parse so a slow parser can't backpressure the OS pipe (FR-D-7a); its drop counter + validate.rs's seq-gap counter are the two observable-loss signals required by NFR-7.
- source_beacon.rs is intentionally outside the tes/Pipeline dependency graph: TES v1 (DATA-1) models a lossless, nanosecond-precision event stream, and an `lsof -i` poll is neither (see plan.md). Its findings are their own `network_finding` stdout record, un-scored and never fed to `Pipeline`; NFR-7's loss counters do not apply to it (it has its own `beacon` stats key instead: snapshots/lsof_errors/new_sightings/findings).
- gene payloads are chunked across multiple tx per CON-9/FR-R-9 whenever they exceed ledger-client's MAX_CHUNK_BYTES=400 budget; ledger-client owns the chunking orchestration, ledger-program's commit_gene accepts either a single write or a sequence of appends into the same fixed-size (4096B) Genome Registry PDA. 400, not overview.md's ~900B guideline: measured empirically during Phase 5 that commit_gene's 8-account/6-signature shape (payer + genome_registry + system_program + 5 required PoI signers) carries a constant 799B of per-transaction overhead regardless of chunk length — a real 1232B-cap rejection from a live validator caught this; overview.md's figure assumed a much cheaper, few-signer instruction shape.
- allele_search.rs's allele->action mapping and cost table are invented (overview.md specifies no allele physics, FR-R-6 real alleles are unimplemented); the search is fitness-based (containment_value - stability_cost, including a benign-action collision penalty), not gated on full containment, so it can legally return the empty sequence — see plan.md's note on that item.
</content>
