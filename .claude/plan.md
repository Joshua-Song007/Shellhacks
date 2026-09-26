# Build Plan

- Checklist, worked top-to-bottom. Each item is exactly one file with a single responsibility — `stage`/`apply` should be able to touch one checklist item without needing to also change any other file. Phases are ordered by dependency (later phases consume earlier ones).

## Phase 0 — Spikes (gate; SPIKE-1/2/3, §12)
- [ ] spikes/spike1_eslogger.sh — confirm `eslogger exec fork` streams w/ available privileges (SPIKE-1); fail -> Scout uses FR-D-3 path
- [ ] spikes/spike2_libp2p_pair.rs — confirm 2 devices pair via libp2p/manual-IP over hotspot (SPIKE-2); fail -> mesh descopes toward FR-M baseline/out
- [ ] spikes/spike3_art_capture.md — confirm 1 ART atomic (macOS variant) captures to TES trace (SPIKE-3); fail -> sandbox uses FR-R-4 hand-authored trace only

## Phase 1 — TES schema (DATA-1; consumed by all downstream crates)
- [x] crates/tes/src/schema.rs — TES v1 struct: v, seq, ts_ns, recv_ns, proc{pid,pidver,ppid,exe,signing_id?,team_id?,platform}, event tagged union (exec/fork/exit/open/create/rename/unlink) (FR-D-4) (pid/ppid typed u32 so negative pids are unparseable; per-kind `data` shapes: exec{target,args}, fork{child_pid,child_pidver}, exit{status}, open{path,write}, create/unlink{path}, rename{from,to} — overview.md leaves kind-specific data unspecified; no revisit scheduled)
- [x] crates/tes/schema/tes_v1.schema.json — JSON Schema twin for out-of-Rust validation (§9) (agreement with Rust boundary enforced by crates/tes/tests/schema_twin.rs)
- [x] crates/tes/src/validate.rs — boundary validator: reject unknown fields, wrong schema version, non-absolute path, pid==0; count rejects, observable not silent (FR-D-5, NFR-7); inbound adapters tolerate unknown fields pre-boundary (FR-D-6) (also counts seq-gap events; one Validator per source stream)

## Phase 2 — Scout (detection; depends on tes)
- [ ] crates/scout/src/source_eslogger.rs — primary source, subscribe exec/fork/exit/open/create/rename/unlink, root+FDA, no ES client entitlement; pidver = audit token `pidversion`, native (FR-D-2, FR-D-7)
- [ ] crates/scout/src/reader.rs — dedicated thread reads raw stdout lines into bounded channel before JSON deserialize/TES normalization, so parsing never backpressures the OS pipe; explicit drop policy, drops counted + surfaced alongside seq-gap drops (FR-D-7a, NFR-7)
- [ ] crates/scout/src/source_libproc.rs — degraded path: libproc proc_listpids/proc_pidinfo + kqueue EVFILT_PROC + FSEvents, event-driven, no lsof; pidver derived via proc_pidinfo(PROC_PIDTBSDINFO)->pbi_start_tvsec, not PROC_PIDTASKINFO (FR-D-3, FR-D-7)
- [ ] crates/scout/src/source_beacon.rs — separate periodic lsof -i/nettop collector -> TES, network lane only, not on eslogger (FR-D-11, CON-5)
- [ ] crates/scout/src/lineage.rs — lineage rollup via fork/exec, identity=(pid,pidver) discriminates recycled PID, survives single PID exit (FR-D-7)
- [ ] crates/scout/src/scoring.rs — Stage-1 weights table (ExecFromTempOrCache=20, RecoverySnapshotTamper=50, RapidFileModBurst=40), threshold>=100 -> SIGSTOP lineage + emit {Threat_ID,pid,schema}; Threat_ID=SHA256(ordered action bytes), deterministic; never suspend own PID/below system floor (FR-D-8/9/10)
- [ ] crates/scout/src/main.rs — Scout daemon: wire sources -> reader -> tes::validate -> lineage -> scoring; no polling shell-out on process/file path (FR-D-1, NFR-1/2)

## Phase 3 — Soldier (response; depends on tes, Scout's wake signal contract)
- [ ] crates/soldier/src/trigger.rs — dormant until wake signal from Scout (FR-R-1)
- [ ] crates/soldier/src/sandbox.rs — wasmi sandbox, zero host imports, test asserts compiled gene has zero imports (FR-R-2, NFR-5)
- [ ] crates/soldier/src/allele_search.rs — combinatorial allele search scored on containment success + target-host stability (FR-R-3)
- [ ] crates/soldier/src/replay_target.rs — search target = replay of TES trace; baseline hand-authored trace imitating ATT&CK atomic (FR-R-4)
- [ ] crates/soldier/src/reenactor.rs — (MAY) real containment alleles act on live benign reenactor re-performing TES trace, reset=relaunch (FR-R-6)
- [ ] crates/soldier/src/gene_compile.rs — compile winning sequence to portable .wasm, strip debug symbols/minimal size, hash to gene_hash; if payload exceeds tx budget submit via chunked append (else single write), apply, self-terminate after (FR-R-7, FR-R-9, CON-9)
- [ ] crates/soldier/src/main.rs — Soldier daemon entrypoint wiring trigger -> sandbox -> allele_search -> gene_compile

## Phase 4 — Ledger program (Anchor; independent of Scout/Soldier internals, consumed by ledger-client)
- [ ] crates/ledger-program/programs/t_cell/src/state.rs — Threat Registry PDA {Threat_ID,Confidence_Score,behavioral_schema_hash}; Genome Registry PDA {Threat_ID,gene_hash,gene_seq,Epigenetic_Status}, gene_seq space fixed generous max e.g. 4096 bytes to avoid AccountStorageFull (FR-L-3/4, DATA-2, FR-R-9)
- [ ] crates/ledger-program/programs/t_cell/src/poi.rs — 3-of-5 PoI multisig check gating commit_gene (FR-L-6)
- [ ] crates/ledger-program/programs/t_cell/src/lib.rs — instructions submit_threat/commit_gene/suppress_gene; commit_gene accepts chunked append calls across multiple tx when gene exceeds ~900B post-overhead budget (single write when it fits); no raw telemetry/payload in instruction data (FR-L-1/2/7/8, FR-R-9, CON-9)

## Phase 5 — Ledger client (depends on ledger-program account layout)
- [ ] crates/ledger-client/src/client.rs — RPC light client, confirmed/finalized reads only, no custom Merkle client/local validator/IPFS; orchestrates chunked gene upload across multiple tx when payload exceeds tx budget (FR-L-5, CON-1/2, FR-R-9, CON-9)

## Phase 6 — Mesh / Lymph network (§6; depends on tes DATA-3, ledger-client for async chain lookup)
- [ ] crates/mesh/src/identity.rs — Ed25519 keypair per device, one-time OOB code/QR pairing <=5min expiry (FR-M-1)
- [ ] crates/mesh/src/transport.rs — libp2p + Noise, ephemeral per-connection session keys, no mDNS dependency, manual IP pairing reliable path (FR-M-3/4)
- [ ] crates/mesh/src/message.rs — signed mesh message {Threat_ID,gene_hash,sender_pubkey,seq,ts,signature} (FR-M-2, DATA-3)
- [ ] crates/mesh/src/verify.rs — apply cure hint only if signature verifies AND content verified via hash-cache+quorum; run local Stage-3 regression + check Epigenetic_Status before apply; async chain lookup w/ rollback (FR-M-5/6)
- [ ] crates/mesh/src/revocation.rs — long-lived identity keys, compromise via revocation not rotation (FR-M-7)

## Phase 7 — Trace capture (offline, off demo path; depends on tes)
- [ ] crates/trace-capture/src/main.rs — runs in sandbox_init/sandbox-exec (macOS) or free-tier Linux VM (other atomics), captures ART atomic -> TES trace, not on demo/evolution-loop path (FR-R-5/8)

## Phase 8 — Dashboard (consumes Scout telemetry, ledger-client feed, Mesh status; last)
- [ ] dashboard/src/App.tsx — Tauri+React+Vite shell, read-only (FR-U-1)
- [ ] dashboard/src/TelemetryView.tsx — live telemetry view (FR-U-1)
- [ ] dashboard/src/LedgerFeed.tsx — ledger feed view (FR-U-1)
- [ ] dashboard/src/MyDevices.tsx — per-device status (clean/watching/isolated/cured) + heartbeat + mesh threat propagation (FR-U-2)
</content>
