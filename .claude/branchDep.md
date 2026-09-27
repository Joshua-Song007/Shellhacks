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
| ledger-client | serde_json | 1.0.151 | dev | Phase 9 item 7b, `examples/feed.rs` only (NDJSON stdout records) -- examples, unlike bin targets, CAN use dev-dependencies per Cargo's own docs, so this stays out of `[dependencies]` |
| mesh | libp2p | "0.54" -> resolved 0.54.1, features tcp/noise/yamux/tokio/macros/ping/request-response/json | normal | same version SPIKE-2 validated; `ping` is normal (not dev) because src/bin/pairing_probe.rs (a real bin target) needs it and Cargo bin targets never get dev-dependencies — confirmed by a real build failure during Phase 6's apply; `request-response`+`json` added Phase 9 item 6 for meshd.rs's wire protocol, resolves to libp2p-request-response 0.27.0 (confirmed via a scratch probe build, not guessed) |
| mesh | tokio | "1" -> resolved 1.53.1, features rt-multi-thread/macros/time/fs/io-std | normal | first async runtime in this project (identity.rs/transport.rs are the first mesh-adjacent code; scout/soldier are all sync/std-thread); `io-std` added Phase 9 item 6 for meshd.rs's async stdin command loop |
| mesh | rand | "0.8" -> resolved 0.8.8 | normal | PairingCode's one-time nonce (FR-M-1) |
| mesh | futures | "0.3" -> resolved 0.3.34 | normal | same reason as `ping` above — src/bin/pairing_probe.rs needs `StreamExt`, bin targets get no dev-dependencies; meshd.rs's own swarm event loop needs it too |
| mesh | sha2 | "0.11.0" | normal | meshd.rs verifies `sha256(genome.gene_seq) == hint.gene_hash` before trusting an inbound cure hint (Phase 9 item 6) |
| mesh | solana-commitment-config | "3" | normal | meshd.rs (a real bin target, no dev-deps) builds a live `LedgerClient::devnet(CommitmentConfig::confirmed())`, same bin-target-needs-normal-deps rule as soldier's own main.rs; moved out of dev-dependencies (was there for tests/chain_lookup.rs only) since it's needed in both places now |
| mesh | soldier | path (`../soldier`) | normal | meshd.rs only (Stage-3 regression via `soldier::regression::check`, `soldier::replay_target::ReplayTarget` for `--benign-trace`, `soldier::gene_compile::apply` on Accept); lib.rs modules stay soldier-free, same shape as soldier main.rs's own ledger-client edge |
| mesh | tempfile | "3" -> resolved 3.27.0 | dev | test-only identity persistence paths and tests/pairing.rs's/tests/meshd_pairing.rs's temp keypair/state files |
| mesh | ledger-client | path (`../ledger-client`) | normal | fulfills architecture.md's previously-aspirational "mesh -> ledger-client (async chain lookup)" edge; verify.rs::confirm_via_chain is the first real user, meshd.rs's Hint handling the second |
| mesh | solana-client/-pubkey/-keypair/-signer | "3"/"3.0.0"/"3.1.2"/"3.0.1" | dev | tests/chain_lookup.rs only — talks to a local solana-test-validator directly (funding, building a payer/committee), same pattern ledger-client's own local-validator tests use |
| trace-capture | tes, scout | path | normal | no new external crates — scout is a narrow reuse of source_eslogger::map_line only (user-approved 2026-09-26), not the live detection pipeline |

## Mesh (`crates/mesh/`)
- SPIKE-2 (plan.md Phase 0) PASSED 2026-09-26 before this crate was built: two libp2p 0.54.1 peers paired over manual IP with Noise, no mDNS, ~175us ping RTT on loopback (two OS processes, since no second physical device/hotspot was available in this dev environment)
- real finding during Phase 6's apply (identity.rs/transport.rs stage): two libp2p Swarms running in the SAME process hit a multistream-select negotiation failure on the accepting side (`IncomingConnectionError { ... Select(Failed) }`) that does NOT occur across two real OS processes (confirmed by directly running transport.rs's own build_swarm/listen_on/dial via a throwaway two-process probe before writing the permanent test) — likely a libp2p same-process quirk, not a bug in transport.rs itself, since production mesh usage is always one process per device anyway. The permanent regression test (tests/pairing.rs) spawns two real subprocesses of src/bin/pairing_probe.rs rather than two in-process swarms, both to sidestep this and to more faithfully match real deployment shape
- real finding during Phase 6's apply (message/verify/revocation stage): `verify::confirm_via_chain` failed with "can call blocking only when running on the multi-threaded runtime" under the default `#[tokio::test]` (single-threaded) runtime -- `solana-rpc-client` uses `tokio::task::block_in_place` internally, which requires a multi-threaded runtime. Any real caller of `confirm_via_chain` needs one too (`#[tokio::main]`/`#[tokio::test]` with `flavor = "multi_thread"`, or an explicit multi-thread `Runtime`); documented on the function itself, demonstrated by tests/chain_lookup.rs
- real finding during Phase 9 item 6's apply (meshd.rs): a `PeerId` cannot be reversed into a `PublicKey` -- `Event::Message{peer: PeerId, ...}` only ever authenticates *which connection* a message came from, not the peer's actual public key. Fixed by having both pairing directions self-attest their pubkey in-band and having the verifier check `pubkey.to_peer_id() == observed_peer_id`; this refinement isn't in overview.md/plan.md's original mesh sketch, added during this apply
- meshd.rs's supervisor-visible "listening" stdout marker was added specifically to close a spawn-vs-async-bind race a test/supervisor would otherwise hit (issuing `pair_start` before the swarm has actually bound a listen address) -- same reason src/bin/pairing_probe.rs prints a bare "LISTENING" line

## Ledger program (nested Anchor workspace, `crates/ledger-program/`)
- toolchain confirmed present: anchor-cli 1.1.2, solana-cli 3.1.10 (see Toolchain above)
- 5 devnet-only PoI committee keypairs generated 2026-09-26 via `solana-keygen new`, stored gitignored under `crates/ledger-program/keys/poi-{1..5}.json`; their pubkeys are hardcoded into `poi.rs`'s `POI_COMMITTEE` const (see plan.md Phase 4 for why hardcoded vs. a runtime config account); original 5 lost from disk, REGENERATED 2026-09-26 (new pubkeys DuUq…/AYGK…/AuoR…/8DPZ…/GTK9… now in poi.rs)
- REDEPLOYED 2026-09-26 (program id change, not an upgrade): the original devnet deploy at `27v76nMPKQg5akQHBsPHnhPt8K7kSf3s8GZjRzUnvBuq` had upgrade authority `HeAubH3AUZDwztNC3BCsDSacnGSAXnd2ZpLJ3H68W6b3` — not this machine's wallet, and not recoverable (other engineer's key, not shared) — so once the committee keypairs above were lost/regenerated, that program could never be upgraded to recognize the new committee from this machine. Fixed by redeploying to a brand-new program id instead of waiting on the old authority: `declare_id!` + both `Anchor.toml` program entries changed to `5zYHmq4nRceYcxtyyhRCW3RRAYf6j7cN6V7e6dz9DJPy` (the keypair Anchor had already generated locally at `target/deploy/t_cell-keypair.json`, previously unused), rebuilt, `anchor deploy --provider.cluster devnet` using `~/.config/solana/id.json` (`Apz5x…YN56s`) as both payer and new upgrade authority. This machine's wallet is now the sole upgrade authority going forward — back it up, losing it permanently freezes the program. The old program id's on-chain data (one real committed gene) is abandoned; harmless, it's synthetic devnet-only data (CON-7)
- verified end-to-end via `crates/ledger-client/examples/devnet_smoke.rs` against the NEW program id (submit_threat -> commit_gene -> suppress_gene, all confirmed on-chain — AC-5); this is the first time the CURRENT (regenerated) committee has actually been exercised live, since the old deployment never got upgraded to recognize it
- build gotcha hit during the redeploy: `anchor build`/`cargo build-sbf` failed with `` error: no such command: `+1.89.0-sbpf-solana-v1.52` `` — `/opt/homebrew/bin/cargo` (a plain Homebrew cargo, not rustup's proxy) was shadowing `~/.cargo/bin/cargo` in PATH, and only rustup's cargo understands `+toolchain` directives. Worked around per-command with `PATH="$HOME/.cargo/bin:$PATH"` rather than reordering the user's global PATH; not fixed at the shell-profile level, will recur unless that's addressed

## Ledger client (`crates/ledger-client/`)
- Phase 9 item 7b: `client.rs` gained `recent_signatures` (wraps `RpcClient::get_signatures_for_address_with_config`, `commitment: None` so it inherits this client's own configured commitment) and `all_genomes` (`get_program_accounts` returns every PDA the program owns -- ThreatRegistry and GenomeRegistry mixed -- so `GenomeRegistry::try_deserialize` is used as the filter: a ThreatRegistry account's discriminator fails it cleanly, silently skipped, not an error)
- `examples/feed.rs` (new) is a long-running poll loop, not a one-shot like `devnet_smoke.rs` -- it's the process architecture.md already names as what `frontend/electron/backend.cjs` (Phase 9 item 9, unbuilt) will eventually spawn+parse for the dashboard's ledger feed. Only emits NDJSON for what's NEW/CHANGED since the last poll (two pure, unit-tested diff helpers: `new_signatures`, `genome_diff`), and the very first poll only baselines silently -- same "first snapshot never raises findings" convention as `crates/scout/src/source_beacon.rs`, since a long-lived devnet program can already hold a large backlog that isn't new activity. Not run against live devnet in this apply (would need real chain activity to produce non-empty diffs); verified via 8 unit tests on the pure diff logic instead, matching this project's established "network glue untested-but-documented, pure logic real-tested" split (e.g. meshd.rs's own precedent)

## Frontend backend (`frontend/electron/backend.cjs`, Phase 9 item 9)
- no new npm dependencies -- plain Node `child_process`/`net`/`readline`/`fs`/`path`/`os`/`events` only
- real finding during this apply's own live verification (item 8): `test_threat.sh`'s first draft used `exec "$WORK/payload" burst` to replace the shell process (so the lineage's first exec event would already be the temp-dir target) -- but a replaced process image has no shell left to run the `trap ... EXIT` cleanup, leaking the temp working dir on every run. Fixed by running the compiled binary as a plain child instead (a shell invoked WITH a script argument is not an "interactive shell" boundary per `lineage.rs`'s own rule, so the child's exec still rolls up into the same lineage without self-replacement)
- real finding while building the wake relay: soldier main.rs already emits an unmodified stderr line (`"soldier: dormant, waiting on <path>"`) right after `Trigger::bind` succeeds and right before it blocks on `wait()` -- reused directly as the real bind-readiness signal for `WakeRelay._deliverToFreshSoldier`, the same problem meshd.rs's `"listening"` stdout marker solved on the Rust side (Phase 9 item 6), but solved here without touching soldier at all, keeping this a backend.cjs-only change
- verified live 2026-09-26 via a real manual smoke run (no JS test framework exists in this project yet, so none was added): scout(--libproc)+meshd+ledger-feed all real-spawned and bridged; a real `pair_start` round-tripped through the meshd stdin bridge to a real `pair_code`; a hand-fed synthetic `WakeSignal` round-tripped through the relay into a freshly spawned real Soldier, which really evolved+applied a gene and really committed `submit_threat`/`commit_gene` to devnet, picked up moments later by the real ledger feed; a second run against the same synthetic threat_id correctly took the `Inherit` path (FR-L-7 genuinely exercised against live chain state) -- zero errors, ephemeral socket cleaned up after use

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

- no new npm dependencies added for Phase 9 items 10-12; `node_modules`/`dist` weren't present in this checkout at all until this apply (`npm install` had never been run here) -- now installed, gitignored, needed before `npm run dev`/`build`/`web`
- real finding verifying items 10-12 together 2026-09-26: no Chrome/Playwright browser binary is available in this sandboxed dev environment (`browser_navigate` failed with "chrome executable not found"), and `osascript`/System Events has no assistive-access permission here either (no screenshot path). Verification instead used: (a) a real `npm run build` (Vite production build, 53 modules transformed, clean); (b) a real `npm run dev` run -- a genuine Electron window actually launched on this machine, `backend.cjs`'s `startBackend()` really spawned a real `scout --libproc` process (its own real stderr line reached the terminal via Vite's console-forwarding), zero console errors/uncaught exceptions over ~23s of live runtime, and `before-quit` was confirmed real (the wake-relay socket file was actually removed on process exit); (c) a standalone Node script faking `window.tcell` and dynamically importing `data.js` as a real ES module, feeding it a realistic sequence of scout/soldier/ledger/mesh records (soldier's `cure` record shape taken verbatim from this session's own earlier live smoke test) -- 25/25 assertions passed. A live two-Electron-instance pairing exchange (one issuing a code, one joining by pasted URI) was NOT performed -- needs two running instances, out of scope for this single-machine pass; the real wire protocol underneath is already proven by `crates/mesh/tests/meshd_pairing.rs` (Phase 9 item 6)

## System tools used at runtime
- `eslogger` (macOS 13+, root + Full Disk Access) — Scout primary source; verified on macOS 26.4.1 (SPIKE-1)
- `cc` (Xcode CLT) — builds spikes/spike1_trigger.c
- `lsof` — source_beacon.rs (FR-D-11 `lsof -i`, degraded lane) and bin/ac2_bench.rs (polling baseline, measurement-only, FR-D-1); never on Scout's own eslogger/libproc detection path

## System frameworks linked
- CoreServices (FSEvents), CoreFoundation — scout degraded path; hand-written FFI in source_libproc.rs, no binding crate

## Pending version bumps
- none
