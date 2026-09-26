# External Dependencies

## Toolchain (dev machine, arm64 macOS 26.4.1)
- rustc / cargo 1.95.0 — workspace edition 2024, resolver 3
- anchor-cli 1.1.2 (avm 1.1.2)
- solana-cli 3.1.10 (Agave)
- node 25.9.0 / npm 11.12.1

## Crates
| Crate | Dep | Version | Kind | Notes |
|---|---|---|---|---|
| tes | serde | 1.0.229 | normal | `derive` feature |
| tes | serde_json | 1.0.151 | normal | |
| tes | jsonschema | 0.58.0 | dev | `default-features = false` — defaults pull reqwest/tokio/aws-lc for remote `$ref` resolution, not needed |
| scout | tes | path | normal | |
| scout | serde | 1.0.229 | normal | `derive` feature |
| scout | serde_json | 1.0.151 | normal | |
| scout | sha2 | 0.11.0 | normal | Threat_ID |
| scout | libc | 0.2.189 | normal | `kill(SIGSTOP)`; libproc, kqueue, `proc_pid_rusage` (degraded path) |
| soldier | scout | path | normal | WakeSignal, Action + pure scoring helpers (exec_actions, BURST_WINDOW_NS, BURST_OPS) |
| soldier | tes | path | normal | |
| soldier | serde | 1.0.229 | normal | `derive` feature |
| soldier | serde_json | 1.0.151 | normal | |
| soldier | wasmi | 0.32.3 | normal | resolved from `"0.32"`; 2.0.0 is available but not requested — sandbox.rs pins the 0.32 API (Engine/Linker/Module/Store) |
| soldier | wat | 1.259.0 | normal | gene_compile.rs compiles the winning allele sequence's WAT text to wasm at runtime; also still used by sandbox.rs's test fixtures |
| soldier | sha2 | 0.11.0 | normal | gene_compile.rs's gene_hash (own hasher, not scout::scoring's — see architecture.md) |
| soldier | ledger-client | path | normal | main.rs only (FR-L-7 check, submit_threat/commit_gene); pulls the Solana client crates into soldier's build |
| soldier | solana-keypair | 3.1.2 | normal | `read_keypair_file` for --payer / --poi-key; matches ledger-client |
| soldier | solana-commitment-config | "3" | normal | LedgerClient construction; matches ledger-client |
| t_cell | anchor-lang | "1.1.2" -> resolved 1.2.0, `init-if-needed` feature | normal | crates/ledger-program is its own nested Anchor/Cargo workspace, NOT a root-workspace member; its own rust-toolchain.toml pins channel 1.89.0 (older than the root workspace's 1.95.0) — anchor init's own scaffold choice, not adjusted. `edition`/`rust-version` were de-inherited from `.workspace = true` to literal `"2021"`/`"1.89.0"` on 2026-09-26 (Phase 5) — inheriting broke when ledger-client path-depended on t_cell from the ROOT workspace, since Cargo resolves `.workspace = true` against whichever workspace is doing the building, not the crate's own nearest one; literal values sidestep that ambiguity entirely |
| t_cell | litesvm | 0.10.0 | dev | in-process Rust-native test validator for tests/test_instructions.rs; no anchor-cli/local-validator/Node needed at test time, only `anchor build` once first to produce target/deploy/t_cell.so |
| t_cell | solana-keypair/-message/-transaction/-signer | 3.1.2/3.0.1/3.0.2/3.0.0 (scaffold-pinned) | dev | test-only tx construction; solana-keypair's `read_keypair_file` loads the 5 devnet PoI keypairs under keys/ |
| ledger-client | t_cell | path (`../ledger-program/programs/t_cell`), `cpi` feature | normal | cross-workspace path dependency (root workspace -> a crate belonging to ledger-program's separate nested workspace) — works once t_cell's edition/rust-version are literal, see above; reuses t_cell's Anchor-generated instruction/accounts/state types directly instead of hand-encoding Borsh |
| ledger-client | anchor-lang | "1.1.2" -> resolved 1.2.0 | normal | pinned to the same resolved version t_cell uses, for AccountDeserialize/InstructionData/ToAccountMetas trait coherence |
| ledger-client | solana-client | "3" -> resolved 3.1.14 | normal | RpcClient; confirmed/finalized reads only (FR-L-5) |
| ledger-client | solana-commitment-config | "3" -> resolved 3.1.1 | normal | |
| ledger-client | solana-signature | "3" -> resolved 3.6.0 | normal | `Signature` return type for submit_threat/commit_gene/suppress_gene |
| ledger-client | solana-keypair/-signer/-message/-transaction/-pubkey | 3.1.2/3.0.1/3.1.0/3.1.0/3.0.0 | normal | matched to versions already resolved in ledger-program's Cargo.lock where the same crates overlap |
| ledger-client | bincode, solana-hash | 1 / "3" -> resolved 3.1.0 | dev | only the `commit_gene_at_max_chunk_bytes_fits_a_real_transaction` regression test (serializes a real Transaction to measure its byte size) |
| mesh | libp2p | "0.54" -> resolved 0.54.1, features tcp/noise/yamux/tokio/macros/ping | normal | same version SPIKE-2 validated; `ping` is normal (not dev) because src/bin/pairing_probe.rs (a real bin target) needs it and Cargo bin targets never get dev-dependencies — confirmed by a real build failure during Phase 6's apply |
| mesh | tokio | "1" -> resolved 1.53.1, features rt-multi-thread/macros/time/fs | normal | first async runtime in this project (identity.rs/transport.rs are the first mesh-adjacent code; scout/soldier are all sync/std-thread) |
| mesh | rand | "0.8" -> resolved 0.8.8 | normal | PairingCode's one-time nonce (FR-M-1) |
| mesh | futures | "0.3" -> resolved 0.3.34 | normal | same reason as `ping` above — src/bin/pairing_probe.rs needs `StreamExt`, bin targets get no dev-dependencies |
| mesh | tempfile | "3" -> resolved 3.27.0 | dev | test-only identity persistence paths and tests/pairing.rs's temp keypair files |
| mesh | ledger-client | path (`../ledger-client`) | normal | fulfills architecture.md's previously-aspirational "mesh -> ledger-client (async chain lookup)" edge; verify.rs::confirm_via_chain is the first real user |
| mesh | solana-client/-pubkey/-commitment-config/-keypair/-signer | "3"/"3.0.0"/"3"/"3.1.2"/"3.0.1" | dev | tests/chain_lookup.rs only — talks to a local solana-test-validator directly (funding, building a payer/committee), same pattern ledger-client's own local-validator tests use |
| trace-capture | tes, scout | path | normal | no new external crates — scout is a narrow reuse of source_eslogger::map_line only (user-approved 2026-09-26), not the live detection pipeline |

## Mesh (`crates/mesh/`)
- SPIKE-2 (plan.md Phase 0) PASSED 2026-09-26 before this crate was built: two libp2p 0.54.1 peers paired over manual IP with Noise, no mDNS, ~175us ping RTT on loopback (two OS processes, since no second physical device/hotspot was available in this dev environment)
- real finding during Phase 6's apply (identity.rs/transport.rs stage): two libp2p Swarms running in the SAME process hit a multistream-select negotiation failure on the accepting side (`IncomingConnectionError { ... Select(Failed) }`) that does NOT occur across two real OS processes (confirmed by directly running transport.rs's own build_swarm/listen_on/dial via a throwaway two-process probe before writing the permanent test) — likely a libp2p same-process quirk, not a bug in transport.rs itself, since production mesh usage is always one process per device anyway. The permanent regression test (tests/pairing.rs) spawns two real subprocesses of src/bin/pairing_probe.rs rather than two in-process swarms, both to sidestep this and to more faithfully match real deployment shape
- real finding during Phase 6's apply (message/verify/revocation stage): `verify::confirm_via_chain` failed with "can call blocking only when running on the multi-threaded runtime" under the default `#[tokio::test]` (single-threaded) runtime -- `solana-rpc-client` uses `tokio::task::block_in_place` internally, which requires a multi-threaded runtime. Any real caller of `confirm_via_chain` needs one too (`#[tokio::main]`/`#[tokio::test]` with `flavor = "multi_thread"`, or an explicit multi-thread `Runtime`); documented on the function itself, demonstrated by tests/chain_lookup.rs

## Ledger program (nested Anchor workspace, `crates/ledger-program/`)
- toolchain confirmed present: anchor-cli 1.1.2, solana-cli 3.1.10 (see Toolchain above)
- 5 devnet-only PoI committee keypairs generated 2026-09-26 via `solana-keygen new`, stored gitignored under `crates/ledger-program/keys/poi-{1..5}.json`; their pubkeys are hardcoded into `poi.rs`'s `POI_COMMITTEE` const (see plan.md Phase 4 for why hardcoded vs. a runtime config account); original 5 lost from disk, REGENERATED 2026-09-26 (new pubkeys DuUq…/AYGK…/AuoR…/8DPZ…/GTK9… now in poi.rs) — the live devnet program still has the OLD committee compiled in until upgraded
- deployed live to devnet 2026-09-26 (Phase 5, FR-L-1): program id `27v76nMPKQg5akQHBsPHnhPt8K7kSf3s8GZjRzUnvBuq`, upgrade authority = `HeAubH3AUZDwztNC3BCsDSacnGSAXnd2ZpLJ3H68W6b3` (NOT this machine's `~/.config/solana/id.json` = `Apz5x…YN56s`; authority keypair not found on this machine — likely the other engineer's wallet); verified end-to-end via `crates/ledger-client/examples/devnet_smoke.rs` (submit_threat -> commit_gene -> suppress_gene, all confirmed on-chain — AC-5)

## Trace-capture (`crates/trace-capture/`)
- SPIKE-3 (plan.md Phase 0) PASSED 2026-09-26 before this crate was built: a real Atomic Red Team atomic (T1070.004 Test #2, "Delete an entire folder") captured cleanly via eslogger + sandbox-exec isolation, 318 raw lines / 0 rejected when replayed through scout's real pipeline. Full method/findings in spikes/spike3_art_capture.md.
- real finding while running SPIKE-3 manually: backgrounding `sudo eslogger ...` with `&` immediately (no cached sudo timestamp yet) meant sudo couldn't get an interactive password prompt at all — the redirected capture file never even got created, silently. Fixed by running `sudo -v` alone first (foreground, real prompt) before the backgrounded capture command. trace-capture/main.rs itself doesn't hit this: it's meant to be invoked as `sudo trace-capture ...` directly (the whole process already root), matching scout main.rs's own `sudo scout` convention, so there's no internal sudo call to race against a TTY at all.

## Frontend (`frontend/`, npm)
| Dep | Version | Kind | Notes |
|---|---|---|---|
| gsap | ^3.15.0 | normal | all UI motion |
| three | ^0.186.1 | normal | helix renderer (helix.js) |
| qrcode | ^1.5.4 | normal | renders the pairing QR (identity.rs leaves QR rendering to the dashboard); added 2026-09-26 |
| electron | ^44.4.5 | dev | desktop shell |
| vite | ^8.3.1 | dev | dev server / bundler |

## System tools used at runtime
- `eslogger` (macOS 13+, root + Full Disk Access) — Scout primary source; verified on macOS 26.4.1 (SPIKE-1)
- `cc` (Xcode CLT) — builds spikes/spike1_trigger.c
- `lsof` — source_beacon.rs (FR-D-11 `lsof -i`, degraded lane) and bin/ac2_bench.rs (polling baseline, measurement-only, FR-D-1); never on Scout's own eslogger/libproc detection path

## System frameworks linked
- CoreServices (FSEvents), CoreFoundation — scout degraded path; hand-written FFI in source_libproc.rs, no binding crate

## Pending version bumps
- none
