## Status: Staged
Task: Phase 4 (plan.md) — ledger-program (state.rs, poi.rs, lib.rs), new Anchor workspace.
Also bundled: fix branchDep.md staleness (soldier's `wat` is now [dependencies] not dev-only; `sha2` missing from soldier's row) — should have landed with the Phase 3 apply, missed it.

### Scaffold (not a checklist item, but required plumbing, same as Cargo.toml edits in earlier phases)
- toolchain confirmed present: anchor-cli 1.1.2, solana-cli 3.1.10 (branchDep.md)
- `cd crates && anchor init t_cell --no-git && mv t_cell ledger-program` -> gives exactly `crates/ledger-program/{Anchor.toml,Cargo.toml,programs/t_cell/{Cargo.toml,src/lib.rs},tests/t_cell.ts,...}`, matching plan.md's path with one rename, no inner package-name surgery
- Anchor.toml: cluster = devnet (FR-L-1); program id = whatever `anchor init` auto-generates in target/deploy/t_cell-keypair.json + declare_id!() (freshly generated, per FR-L-1)
- root Cargo.toml `[workspace] members` stays untouched (tes/scout/soldier only) — ledger-program is its own nested Anchor/Cargo workspace, confirmed no auto-discovery conflict
- generate 5 devnet PoI committee keypairs: `solana-keygen new --no-bip39-passphrase -o crates/ledger-program/keys/poi-{1..5}.json`; add `crates/ledger-program/keys/` to .gitignore (ephemeral demo keys, not secrets worth committing but shouldn't be tracked either)
- enable anchor-lang `init-if-needed` feature in programs/t_cell/Cargo.toml (needed by both submit_threat and commit_gene below)

### programs/t_cell/src/state.rs (FR-L-3/4, DATA-2, FR-R-9)
- `pub const MAX_GENE_BYTES: usize = 4096;` `pub const MAX_REPORTERS: usize = 32;` (invented cap — no spec number; bounds ThreatRegistry's fixed init space, note as simplification)
- `#[account] ThreatRegistry { threat_id: [u8;32], confidence_score: u32, behavioral_schema_hash: [u8;32], reporters: Vec<Pubkey> }` — `reporters` is the "independent report" dedup set (FR-L-3): "independent" = distinct signer pubkey, invented interpretation (no mesh/device-identity system wired yet — Phase 6 unbuilt)
  - `SEED_PREFIX = b"threat"`, PDA seeds = [SEED_PREFIX, threat_id.as_ref()]
  - `SPACE = 8 + 32 + 4 + 32 + 4 + 32*MAX_REPORTERS`
- `#[account] GenomeRegistry { threat_id: [u8;32], gene_hash: [u8;32], gene_seq: Vec<u8>, epigenetic_status: bool }`
  - `SEED_PREFIX = b"genome"`, PDA seeds = [SEED_PREFIX, threat_id.as_ref()]
  - `SPACE = 8 + 32 + 32 + 4 + MAX_GENE_BYTES + 1` — fixed at init regardless of current gene_seq length (CON-9/FR-R-9, avoids AccountStorageFull)
  - nothing ever resets epigenetic_status false — no "un-suppress" instruction exists (matches FR-L-2's exact 3-instruction list); note as accepted spec gap, no revisit scheduled

### programs/t_cell/src/poi.rs (FR-L-6)
- `pub const POI_THRESHOLD: usize = 3;` `pub const POI_COMMITTEE: [Pubkey; 5] = [...]` — hardcoded compile-time consts from the 5 generated devnet keypairs above (NOT a runtime-configurable on-chain config account: FR-L-2 names exactly 3 instructions, a 4th init-config instruction would be added scope beyond spec; genuine dynamic multi-party membership is FR-M-10, MAY/stretch. Note as simplification, revisit only if FR-M-10 gets picked up.)
- `#[error_code] PoiError::InsufficientSignatures`
- `pub fn require_poi(candidates: &[Option<Pubkey>]) -> Result<()>` — pure function: dedups the up-to-5 provided pubkeys, counts how many are in POI_COMMITTEE, requires >= POI_THRESHOLD. Takes plain `Option<Pubkey>` (not `Signer`) so it's unit-testable with zero Solana runtime (no local validator needed, consistent w/ CON-2) — "is this a real signer" is Anchor's `Signer<'info>` type's job in lib.rs's Accounts struct, kept separate from "is it enough of the committee"
- tests (plain `#[test]`, no anchor/runtime): exactly-3-distinct-committee-members passes; 2-of-5 fails; duplicates of the same committee pubkey across slots don't count twice; non-committee pubkeys don't count; all 5 slots None fails

### programs/t_cell/src/lib.rs (FR-L-1/2/7/8, FR-R-9, CON-9)
- `declare_id!(...)` (auto from scaffold)
- `submit_threat(ctx, threat_id: [u8;32], behavioral_schema_hash: [u8;32])` — `init_if_needed` ThreatRegistry (payer = reporter signer); first call sets threat_id/behavioral_schema_hash; every call requires stored schema hash matches (mismatch = error, prevents hash-collision confusion); if `reporter` pubkey not already in `reporters` (and under MAX_REPORTERS), push + increment confidence_score. No PoI gate (FR-L-6 only names commit_gene) — anyone can report, that's the point of corroboration. FR-L-8: only pre-hashed threat_id/schema_hash ever enters instruction data, never raw telemetry.
- `commit_gene(ctx, threat_id: [u8;32], gene_hash: [u8;32], chunk: Vec<u8>, is_final_chunk: bool)` — requires PoI (poi::require_poi over the 5 optional Signer slots' `.key()`s); `init_if_needed` GenomeRegistry (space=GenomeRegistry::SPACE fixed regardless of chunk count); require `gene_seq.len() + chunk.len() <= MAX_GENE_BYTES` (else GeneTooLarge error); append chunk; on `is_final_chunk`, set gene_hash. Single-write callers just pass the whole gene as one chunk with is_final_chunk=true — same code path, no separate "single vs chunked" instruction (matches plan.md: "single write when it fits" is just the 1-chunk case)
- `suppress_gene(ctx, threat_id: [u8;32])` — requires PoI (same 5-slot check, same committee) per user decision 2026-09-26 (FR-L-6 only names commit_gene; gating suppress_gene too is a deliberate scope addition — an ungated kill-switch is a griefing vector); sets `genome_registry.epigenetic_status = true`
- `CommitGene`/`SuppressGene` Accounts structs: `genome_registry: Account<GenomeRegistry>` (mut, seeds=[...], bump) + `signer_a..signer_e: Option<Signer<'info>>` (exactly 5 named optional slots, not `remaining_accounts` — simpler to reason about, matches poi.rs's fixed-5 committee)
- `#[error_code] TCellError { SchemaMismatch, TooManyReporters, GeneTooLarge }`
- FR-L-5 (light-client reads only) is a ledger-CLIENT concern (Phase 5, unbuilt) — nothing to implement here, program-side has no RPC trust model of its own

### Test strategy
- poi.rs: plain `cargo test` unit tests (listed above), no runtime needed
- lib.rs instruction-level behavior: `anchor test` (spins up Anchor's local test validator + deploys + runs the default TS/Mocha scaffold under tests/) — this is dev-time test tooling, not a production RPC client, so it does NOT conflict with CON-2's "no local validator" (that constraint is about ledger-client's production read path, Phase 5)
- state.rs: no behavior of its own beyond consts/structs; no dedicated tests planned

### On apply, also update
- branchDep.md: fix soldier's `wat` row (dev -> normal), add soldier `sha2` row; add ledger-program's new toolchain-adjacent deps (anchor-lang version, whatever `anchor init` pins) once scaffolded
- architecture.md: add a "Ledger program internals" section (state.rs/poi.rs/lib.rs edges) and update the existing "ledger-program -> (none internal...)" dependency-graph line if it's no longer accurate post-scaffold
- plan.md: check off all three Phase 4 lines w/ notes per above (MAX_REPORTERS/committee-hardcoding/no-unsuppress simplifications)
- .gitignore: add `crates/ledger-program/keys/`
