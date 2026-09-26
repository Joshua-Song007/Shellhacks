# T-cell — Technical Specification

**Project:** T-cell — Autonomous Bio-Digital Endpoint Defense Mesh
**Target:** ShellHacks (FIU, Miami) — 36 h, 2 engineers
**Build:** clean-room; no code reused from any prior project.

**Requirement priorities (RFC-2119 style):**
**MUST** = committed baseline; the demo fails without it. **SHOULD** = target if the spike passes / time allows. **MAY** = stretch.

Priorities are the current commitment; adjust the balance between mesh (FR-M) and sandbox full-tier (FR-R-5/6) if hours run short — the MUST spine (detection + sandbox baseline + ledger) is fixed.

---

## 1. Glossary

| Term | Definition |
|---|---|
| T-cell agent | The endpoint program installed on a device. Runs two castes. |
| Scout | Detection caste. Observes and scores behavior; never terminates. |
| Soldier | Response caste. A dormant "spore" that wakes on threat, isolates, evolves a cure, applies it, self-terminates ("apoptosis"). |
| Lymph node | A single device running the T-cell agent. |
| Lymph network | The local mesh of paired lymph nodes (FR-M). |
| Gene | A compiled WebAssembly containment payload. Identity = `gene_hash`. |
| Allele | A low-level containment primitive. A gene is an ordered sequence of alleles. |
| TES v1 | T-cell Event Schema v1 — the strict normalized telemetry format (DATA-1). |
| Threat_ID | SHA-256 over the ordered Stage-1 action bytes of a lineage. |
| Confidence_Score | Per-threat corroboration counter in the Threat Registry. |
| Epigenetic_Status | Per-gene kill-switch flag in the Genome Registry. |
| Proof of Immunity (PoI) | App-level 3-of-5 multisig attestation gating `commit_gene`. |

---

## 2. System overview

T-cell is a decentralized, behavior-based endpoint defense system. Detection and response run locally per device; verified cures are published to a shared ledger so other devices inherit immunity without meeting the threat.

**Four-stage cure pipeline.** Every published cure clears: (1) Trajectory scoring crosses 100 pts; (2) local isolation + allele search in a sandbox; (3) Lymph Node regression (cure must not break whitelisted apps); (4) 3-of-5 PoI consensus → devnet commit.

**Three-ledger model on one chain.** State Ledger (Solana itself, RPC light-client reads); Threat Registry (PDA, `Threat_ID` → `Confidence_Score`); Genome Registry (PDA, `Threat_ID` → `gene_hash`, gene bytes in `gene_seq`, `Epigenetic_Status`).

**Two-layer propagation.** L1 = global chain (authoritative, seconds). L2 = lymph network (paired local devices, sub-second, offline-capable).

---

## 3. Functional requirements — Detection (Scout)

- **FR-D-1 [MUST]** The Scout SHALL detect process and file behavior from an event-driven telemetry source. No polling shell-out (`lsof`, `pgrep`) on the process/file detection path.
- **FR-D-2 [MUST]** Primary source SHALL be `eslogger` (macOS 13+), subscribed to `exec`, `fork`, `exit`, `open`, `create`, `rename`, `unlink`. Runs with root + Full Disk Access; SHALL NOT require the ES client entitlement.
- **FR-D-3 [MUST]** Degraded source (when FR-D-2 is unavailable per SPIKE-1) SHALL be `libproc` (`proc_listpids`/`proc_pidinfo`) + `kqueue` `EVFILT_PROC` + FSEvents. This path is event-driven and SHALL NOT use `lsof` for process/file detection.
- **FR-D-4 [MUST]** Every source SHALL be normalized to TES v1 (DATA-1) before rule evaluation. Rules SHALL consume TES only, never raw source output.
- **FR-D-5 [MUST]** The TES boundary SHALL reject any event with unknown fields, wrong schema version, non-absolute path, or `pid == 0`. Rejected lines SHALL be counted, never partially accepted.
- **FR-D-6 [MUST]** The inbound source adapter SHALL tolerate unknown fields in raw source events (strictness is enforced only at the TES boundary).
- **FR-D-7 [MUST]** Scoring SHALL accumulate by process lineage: a child's actions roll up to the lineage root (via `fork`/`exec`); a lineage trajectory SHALL survive any single PID exit; process identity SHALL be `(pid, pidver)`, where `pidver` discriminates a recycled PID.
  - On the eslogger path, `pidver` SHALL be taken directly from the event's audit token (`pidversion`) — provided natively, no derivation needed.
  - On the degraded path (FR-D-3), where the audit token is unavailable, `pidver` SHALL be derived from the process start time via `proc_pidinfo(PROC_PIDTBSDINFO)` → `proc_bsdinfo.pbi_start_tvsec` (not `PROC_PIDTASKINFO`, which carries no start time).
- **FR-D-7a [MUST]** The telemetry reader SHALL decouple pipe reading from parsing: a dedicated thread/task SHALL read raw lines off the source's stdout and hand them to a **bounded** channel *before* any JSON deserialization or TES normalization, so parsing can never backpressure the OS pipe. The channel SHALL have an explicit drop policy; drops SHALL be counted and surfaced (alongside source-side drops inferred from `seq` gaps, DATA-1), never silent. Rationale: under load a lagging reader fills the kernel pipe buffer, producing dropped events or phantom latency; `eslogger` is a NOTIFY client, so it is not killed for slowness — it simply drops.
- **FR-D-8 [MUST]** Stage-1 actions, weights, and detectors SHALL be:

  | Action | Weight | ATT&CK | Detector (TES) |
  |---|---|---|---|
  | `ExecFromTempOrCache` | 20 | T1204 | `exec` target path under `/tmp`, `/private/var/folders`, `/var/tmp`, or `…/Caches/` |
  | `RecoverySnapshotTamper` | 50 | T1490 | `exec` of snapshot/backup deletion (`tmutil deletelocalsnapshots`, APFS snapshot deletion) |
  | `RapidFileModBurst` | 40 | T1486 | high-rate `open(write)`/`create`/`rename`/`unlink` from one lineage |

- **FR-D-9 [MUST]** At cumulative score ≥ 100 the Scout SHALL suspend the lineage (`SIGSTOP`) and emit a wake signal `{Threat_ID, pid, schema}`. `Threat_ID` SHALL be SHA-256 over the ordered action bytes and SHALL be deterministic across nodes.
- **FR-D-10 [MUST]** The Scout SHALL NOT suspend its own PID or PIDs below a system-process floor.
- **FR-D-11 [SHOULD]** An optional outbound-beacon lane (T1046/T1071) SHALL be provided by a **separate** periodic collector using `lsof -i` / `nettop`. Findings SHALL be written to the observation/dashboard output, separate from the TES-fed scoring pipeline: TES v1 (DATA-1) models a lossless, nanosecond-precision event stream, and a `lsof`-sampled interval signal is neither — forcing it into TES would give false seq/ts_ns precision to data that has none. This lane SHALL NOT use `eslogger` (ES exposes no network events — CON-5). Periodic polling is acceptable here because a beacon is interval-based, not a millisecond window. *(Settled: `lsof` is the network collector; findings bypass TES and scoring.)*

---

## 4. Functional requirements — Response & Sandbox (Soldier)

- **FR-R-1 [MUST]** The Soldier SHALL remain dormant until it receives a wake signal (FR-D-9).
- **FR-R-2 [MUST]** The evolved cure SHALL execute in a `wasmi` sandbox compiled with **zero host imports**. A test SHALL assert the compiled gene has zero imports.
- **FR-R-3 [MUST]** The Soldier SHALL run a combinatorial allele search, scoring each candidate on containment success AND target-host stability.
- **FR-R-4 [MUST]** The search target's behavior SHALL be a replay of a TES trace. Baseline: a hand-authored trace imitating a real ATT&CK atomic.
- **FR-R-5 [SHOULD]** The trace SHOULD be captured from a real Atomic Red Team atomic with a confirmed macOS variant (per SPIKE-3), in an isolated environment (FR-R-8).
- **FR-R-6 [MAY]** Real containment alleles (`SIGSTOP`, kill child tree, block sockets, quarantine dropped files, revert touched files) MAY replace synthetic allele physics. If implemented, they SHALL act on a live benign **reenactor** process that re-performs the TES trace — not on trace data — with reset = relaunch the reenactor.
- **FR-R-7 [MUST]** The winning allele sequence SHALL compile to a portable `.wasm`, be hashed to `gene_hash`, be applied, and the Soldier SHALL self-terminate after application.
- **FR-R-8 [MUST]** Trace capture (FR-R-5) SHALL run offline in `sandbox_init`/`sandbox-exec` (macOS atomics) and/or a free-tier Linux VM (other atomics). It SHALL NOT be on the demo or evolution-loop path.
- **FR-R-9 [MUST]** The compiled gene SHALL be size-disciplined to satisfy CON-9: debug symbols stripped, minimal `wasm`, targeting a payload that fits a single Solana transaction (see CON-9). If a gene cannot be kept within one transaction, `commit_gene` SHALL upload it via chunked appends across multiple transactions rather than a single write. The `Genome Registry` PDA SHALL be initialized with a fixed, generous maximum (e.g. 4,096 bytes) to avoid `AccountStorageFull`.

---

## 5. Functional requirements — Ledger & Consensus

- **FR-L-1 [MUST]** An Anchor program SHALL be deployed to Solana devnet with a freshly generated program id.
- **FR-L-2 [MUST]** The program SHALL expose `submit_threat`, `commit_gene`, `suppress_gene`.
- **FR-L-3 [MUST]** The Threat Registry SHALL be a PDA keyed by `Threat_ID`, holding `Confidence_Score` that increments on independent matching reports.
- **FR-L-4 [MUST]** The Genome Registry SHALL be a PDA mapping `Threat_ID` → `gene_hash`, storing gene bytes in `gene_seq` and an `Epigenetic_Status` flag.
- **FR-L-5 [MUST]** Endpoints SHALL be RPC light clients trusting `confirmed`/`finalized` reads. No custom Merkle light-client, no local validator, no IPFS/off-chain blob store.
- **FR-L-6 [MUST]** `commit_gene` SHALL require a valid 3-of-5 PoI multisig.
- **FR-L-7 [MUST]** `suppress_gene` SHALL set `Epigenetic_Status`; every Soldier SHALL check this flag before fetching or running a gene.
- **FR-L-8 [MUST]** No raw host telemetry or malware payload SHALL enter instruction data.

---

## 6. Functional requirements — Lymph Network (mesh)

- **FR-M-1 [SHOULD]** Devices SHALL pair via a one-time out-of-band code/QR (≤ 5 min expiry). Each device SHALL generate its own Ed25519 identity keypair; the household SHALL record every device's public key.
- **FR-M-2 [SHOULD]** Every mesh message SHALL be signed by the sender's identity key.
- **FR-M-3 [SHOULD]** Transport SHALL be encrypted with ephemeral per-connection session keys (forward secrecy) — e.g. Noise via `libp2p`.
- **FR-M-4 [SHOULD]** Transport SHALL NOT depend on mDNS. Manual pairing by IP SHALL be the reliable path; a controlled hotspot is the demo network (CON + venue constraint).
- **FR-M-5 [MUST, if §6 in scope]** A received cure hint SHALL be acted on only if BOTH: (a) its signature verifies against a paired device's public key, AND (b) its content is verified (FR-M-6). Before applying, the receiver SHALL run its own Stage-3 regression and check `Epigenetic_Status`.
- **FR-M-6 [SHOULD]** Content verification SHALL use a verified-hash cache plus local corroboration quorum (K independent signers report the same `gene_hash`); the authoritative chain lookup MAY be asynchronous with rollback on failure.
- **FR-M-7 [SHOULD]** Identity keys SHALL be long-lived. Compromise SHALL be handled by revocation (+ optional re-attestation), not scheduled identity-key rotation.
- **FR-M-8 [MAY]** mDNS discovery MAY be offered for home networks only.
- **FR-M-9 [MAY]** The household roster MAY be anchored on-chain.
- **FR-M-10 [MAY]** Real multi-device 3-of-5 co-signing MAY replace single-process multisig, making PoI genuinely multi-party.

---

## 7. Functional requirements — Dashboard

- **FR-U-1 [MUST]** A read-only dashboard (Tauri + React + Vite) SHALL show live telemetry and the ledger feed.
- **FR-U-2 [SHOULD]** A "My Devices" view SHALL show each paired lymph node with status (`clean` / `watching` / `isolated` / `cured`) and a heartbeat, and SHALL visibly reflect threat propagation across the mesh.

---

## 8. Non-functional requirements

- **NFR-1 [MUST]** Detection latency (malicious action → suspension) SHALL be measured and reported. The event-driven path SHALL detect within the offending action's own lifetime, not bounded by a poll interval.
- **NFR-2 [MUST]** Idle Scout CPU cost SHALL be negligible (event-driven; no busy polling on the hot path).
- **NFR-3 [MUST]** Platform: macOS 13+ (Apple Silicon and Intel). The degraded detection path (FR-D-3) SHALL function without root.
- **NFR-4 [SHOULD]** Private keys SHALL never be transmitted and SHOULD be stored in the macOS Keychain / Secure Enclave.
- **NFR-5 [MUST]** Safety boundary (see CON-7, CON-8, FR-R-2, FR-L-8) SHALL hold: no live malware, no raw telemetry/payload on-chain, cure sandbox provably import-free.
- **NFR-6 [MUST]** `Threat_ID` and `gene_hash` SHALL be deterministic across nodes given identical input.
- **NFR-7 [MUST]** Telemetry ingestion SHALL sustain bursty high-volume event streams without silently dropping or stalling: reading is decoupled from parsing per FR-D-7a, and event loss (reader-side channel drops and source-side `seq` gaps) SHALL be counted and observable. This is a correctness property, not just performance — silent drops = missed detections.

---

## 9. Data formats

**DATA-1 — TES v1 event (NDJSON, one per line).**

| Field | Type | Meaning |
|---|---|---|
| `v` | int | Schema version (pinned = 1). |
| `seq` | int | Source sequence number; gaps indicate source-level drops. |
| `ts_ns` | int | OS event time (epoch ns). |
| `recv_ns` | int | Parse time (epoch ns); `recv_ns − ts_ns` = pipeline lag. |
| `proc` | obj | `{pid, pidver, ppid, exe, signing_id?, team_id?, platform}`. |
| `event` | tagged union | `kind` ∈ `exec`/`fork`/`exit`/`open`/`create`/`rename`/`unlink`, with kind-specific `data`. |

A JSON Schema twin SHALL exist for out-of-Rust validation.

**DATA-2 — On-chain accounts.**
Threat Registry PDA: `{Threat_ID, Confidence_Score, behavioral_schema_hash}`.
Genome Registry PDA: `{Threat_ID, gene_hash, gene_seq (bytes), Epigenetic_Status}`.

**DATA-3 — Mesh message.** `{Threat_ID, gene_hash, sender_pubkey, seq, ts, signature}`.

---

## 10. Constraints & non-goals

- **CON-1** Gene bytes stored on-chain (`gene_seq`); no IPFS / off-chain blob store.
- **CON-2** RPC `confirmed`/`finalized` reads only; no custom Merkle light-client, no local validator. Trust-minimized reads (Merkle inclusion proofs against a block header) are **not** a standard Solana client primitive — they depend on in-progress protocol work (SIMD-0052) and the still-maturing Tinydancer light client, so they are out of scope. Cheap mitigation if RPC trust is a concern: cross-read the same account from ≥2 independent RPC providers. (A Merkle tree used as a *set-commitment* structure — one on-chain root over a set of hashes with off-chain membership proofs — is unrelated and permitted; relevant only to a future surveillance layer.)
- **CON-2a** Devnet SOL / rent cost is not a constraint (hackathon credits cover it). This does **not** relax CON-9, which is a size limit, not a cost.
- **CON-3** No Firecracker/MicroVM (requires Linux+KVM; will not run on macOS) and no AWS Lambda for capture (ephemeral, locked-down, Firecracker-based, no low-level telemetry).
- **CON-4** No kernel extension and no dependency on the ES client entitlement; entitlement-free telemetry only.
- **CON-5** Endpoint Security exposes no general network events (Apple directs network monitoring to NetworkExtension). Network detection therefore uses the separate `lsof`/`nettop` collector (FR-D-11) only.
- **CON-6** Endpoint Security exposes file operations, not file contents; no content-entropy detection. `RapidFileModBurst` keys on operation rate/pattern.
- **CON-7** No live malware at any point. Threats are benign Atomic Red Team atomics; the evolution loop uses replayed/authored traces.
- **CON-8** Clean-room: no reuse of prior-project code.
- **CON-9** A Solana transaction is capped at **1232 bytes total**. A gene therefore cannot be written to `gene_seq` in a single transaction unless its payload fits within that budget (≈ sub-900 bytes after instruction overhead). Genes exceeding this MUST be uploaded via chunked appends (FR-R-9). This is a hard size limit that credits/rent do not address (CON-2a), and it is what makes the on-chain-gene decision (CON-1) valid only for tiny genes: if genes grow beyond one transaction and chunked writes aren't implemented, the on-chain-vs-off-chain tradeoff must be revisited. (Account allocation caps — 10 MiB max, ~10 KB `realloc` growth per instruction — are secondary to the transaction-size wall.)

---

## 11. Acceptance criteria

- **AC-1** Scout ingests a live event stream (eslogger or degraded path), normalizes to TES v1, and scores by lineage.
- **AC-2** A short-window threat behavior is caught that a `lsof`-polling detector misses; catch-rate and median detection latency are measured for both and reported.
- **AC-3** At least one real Atomic Red Team atomic (macOS variant) is detected on stage.
- **AC-4** A cure is evolved against a replayed trace, isolated in the zero-import `wasmi` sandbox, and applied.
- **AC-5** A cure clears the 4-stage pipeline and is committed to devnet; `suppress_gene` demonstrably halts a flagged gene network-wide.
- **AC-6 (if §6 in scope)** Two paired devices exchange a signed, encrypted cure hint over the mesh; the receiver verifies via cache/quorum (no fresh chain lookup) and reflects propagation in the My Devices view, over hotspot/manual-pairing.
- **AC-7** Every boundary in §10 holds; nothing is claimed more real than it is.

---

## 12. Prerequisite spikes (first ~3 hours)

Each spike sets a feature's tier before dependent work begins.

- **SPIKE-1** `sudo eslogger exec fork …` streams on the demo Mac with available privileges. Fail → detection uses FR-D-3.
- **SPIKE-2** Two devices connect via `libp2p`/manual-pairing over the hotspot (not venue wifi). Fail → mesh descopes toward FR-M baseline or out.
- **SPIKE-3** One ART atomic with a macOS variant runs and its behavior captures to a TES trace. Fail → sandbox uses FR-R-4 hand-authored trace only.