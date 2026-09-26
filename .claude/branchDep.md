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

## Pending version bumps
- none
