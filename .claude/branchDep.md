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
| soldier | scout | path | normal | wake-signal contract only (WakeSignal, Action) |
| soldier | tes | path | normal | |
| soldier | serde | 1.0.229 | normal | `derive` feature |
| soldier | serde_json | 1.0.151 | normal | |
| soldier | wasmi | 0.32.3 | normal | resolved from `"0.32"`; 2.0.0 is available but not requested — sandbox.rs pins the 0.32 API (Engine/Linker/Module/Store) |
| soldier | wat | 1.259.0 | normal | gene_compile.rs compiles the winning allele sequence's WAT text to wasm at runtime; also still used by sandbox.rs's test fixtures |
| soldier | sha2 | 0.11.0 | normal | gene_compile.rs's gene_hash (own hasher, not scout::scoring's — see architecture.md) |

## System tools used at runtime
- `eslogger` (macOS 13+, root + Full Disk Access) — Scout primary source; verified on macOS 26.4.1 (SPIKE-1)
- `cc` (Xcode CLT) — builds spikes/spike1_trigger.c
- `lsof` — source_beacon.rs (FR-D-11 `lsof -i`, degraded lane) and bin/ac2_bench.rs (polling baseline, measurement-only, FR-D-1); never on Scout's own eslogger/libproc detection path

## System frameworks linked
- CoreServices (FSEvents), CoreFoundation — scout degraded path; hand-written FFI in source_libproc.rs, no binding crate

## Pending version bumps
- none
