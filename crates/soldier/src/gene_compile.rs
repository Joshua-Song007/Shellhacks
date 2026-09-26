//! FR-R-7, FR-R-9, CON-9: compiles the winning allele sequence into a
//! portable, zero-import `.wasm` gene, hashes it to `gene_hash`, and
//! applies it in the sandbox. FR-R-6 (real host-side containment alleles)
//! is unimplemented/MAY, so "apply" here means successful sandbox
//! instantiation, not any live host action -- there is no host action to
//! take yet. Tx-chunking (CON-9) is limited to *deciding* whether the gene
//! fits a single Solana transaction; actually submitting it is
//! ledger-client's job (Phase 5, unbuilt) -- architecture.md's dependency
//! graph has no soldier -> ledger-client edge.

use sha2::{Digest, Sha256};

use crate::allele_search::{ALL, Allele};
use crate::sandbox::{Sandbox, SandboxError};

/// CON-9: a Solana transaction is capped at 1232 bytes total; budget the
/// gene payload to ~900 bytes to leave room for instruction overhead.
pub const MAX_SINGLE_TX_BYTES: usize = 900;

/// FR-R-9: whether the compiled gene fits one transaction or must be
/// uploaded via chunked appends. Carries the chunk bytes either way so the
/// caller never has to re-slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadPlan {
    Single(Vec<u8>),
    Chunked(Vec<Vec<u8>>),
}

/// Bit `i` of the mask is set iff `allele_search::ALL[i]` is present in
/// `sequence`. Matches `search`'s own mask enumeration order, so a mask
/// round-trips through `compile` deterministically for a given sequence.
fn bitmask(sequence: &[Allele]) -> i32 {
    let mut mask = 0i32;
    for (i, allele) in ALL.iter().enumerate() {
        if sequence.contains(allele) {
            mask |= 1 << i;
        }
    }
    mask
}

/// FR-R-7: compiles `sequence` to a portable `.wasm` gene. The module
/// exports the winning allele bitmask as a single global and declares zero
/// imports by construction, satisfying FR-R-2's sandbox boundary for the
/// actual gene, not just test fixtures. `wat::parse_str` emits no
/// debug/name section, so "debug symbols stripped" holds without an extra
/// step.
pub fn compile(sequence: &[Allele]) -> Vec<u8> {
    let wat = format!(
        r#"(module (global $allele_bitmask i32 (i32.const {})) (export "allele_bitmask" (global $allele_bitmask)))"#,
        bitmask(sequence)
    );
    wat::parse_str(&wat).expect("generated WAT is always well-formed")
}

/// `gene_hash`: SHA-256 of the compiled wasm bytes, hex-encoded. Uses its
/// own hasher rather than scout::scoring's `Threat_ID` one -- architecture.md
/// pins soldier's scout surface to WakeSignal/Action/exec_actions/
/// BURST_WINDOW_NS/BURST_OPS only.
pub fn hash(wasm_bytes: &[u8]) -> String {
    let digest = Sha256::digest(wasm_bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// FR-R-9/CON-9: decides whether `wasm_bytes` needs chunked upload. Pure
/// sizing decision -- actual transaction submission belongs to
/// ledger-client (Phase 5, unbuilt).
pub fn chunk_plan(wasm_bytes: &[u8]) -> UploadPlan {
    if wasm_bytes.len() <= MAX_SINGLE_TX_BYTES {
        UploadPlan::Single(wasm_bytes.to_vec())
    } else {
        UploadPlan::Chunked(wasm_bytes.chunks(MAX_SINGLE_TX_BYTES).map(<[u8]>::to_vec).collect())
    }
}

/// FR-R-7: applies the compiled gene. FR-R-6 real containment alleles are
/// unimplemented/MAY, so there is no live host action to take yet --
/// successful instantiation in the zero-import sandbox stands in for "the
/// cure was accepted." The caller self-terminates after this returns.
pub fn apply(wasm_bytes: &[u8]) -> Result<(), SandboxError> {
    Sandbox::new().instantiate(wasm_bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_of_the_empty_sequence_instantiates() {
        let wasm = compile(&[]);
        assert!(apply(&wasm).is_ok(), "zero-import module always instantiates");
    }

    #[test]
    fn compile_round_trips_a_partial_sequence_deterministically() {
        let seq = [Allele::QuarantineDroppedFiles, Allele::KillChildTree];
        let a = compile(&seq);
        let b = compile(&seq);
        assert_eq!(a, b, "same sequence compiles to identical bytes");
    }

    #[test]
    fn compile_of_the_full_sequence_still_has_zero_imports() {
        assert!(apply(&compile(&ALL)).is_ok());
    }

    #[test]
    fn different_sequences_hash_differently() {
        let empty_hash = hash(&compile(&[]));
        let full_hash = hash(&compile(&ALL));
        assert_ne!(empty_hash, full_hash);
        assert_eq!(empty_hash.len(), 64, "sha-256 hex digest is 64 chars");
    }

    #[test]
    fn hash_is_deterministic() {
        let wasm = compile(&[Allele::SigStop]);
        assert_eq!(hash(&wasm), hash(&wasm));
    }

    #[test]
    fn a_gene_under_budget_gets_a_single_upload_plan() {
        let wasm = compile(&[Allele::SigStop]);
        assert!(wasm.len() <= MAX_SINGLE_TX_BYTES, "generated genes are tiny");
        assert_eq!(chunk_plan(&wasm), UploadPlan::Single(wasm));
    }

    #[test]
    fn chunk_plan_splits_a_payload_over_budget() {
        let oversized = vec![0u8; MAX_SINGLE_TX_BYTES + 10];
        let UploadPlan::Chunked(chunks) = chunk_plan(&oversized) else { panic!("expected Chunked") };
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), MAX_SINGLE_TX_BYTES);
        assert_eq!(chunks[1].len(), 10);
    }
}
