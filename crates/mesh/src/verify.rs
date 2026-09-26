//! FR-M-5 (MUST, since §6 is in scope) / FR-M-6 (SHOULD): the gate a
//! received cure hint must clear before being applied. `evaluate` is the
//! synchronous fast path (signature -> paired&non-revoked -> corroboration
//! quorum/cache -> suppression -> Stage-3 regression); `confirm_via_chain`
//! is the async authoritative check FR-M-6 allows to run separately,
//! updating the cache for future decisions rather than blocking this one.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ledger_client::{LedgerClient, LedgerError};
use libp2p::identity::PublicKey;

use crate::identity::Roster;
use crate::message::CureHint;
use crate::revocation::RevocationList;

/// FR-M-6: "K independent signers report the same gene_hash" -- invented,
/// no spec number given. Revisit only if a real value gets specified.
pub const QUORUM_K: usize = 2;

/// FR-M-6: a local cache of gene_hashes already confirmed via the
/// authoritative chain lookup. `rollback` implements FR-M-6's "rollback on
/// failure" -- a hash provisionally trusted (e.g. via quorum) that the
/// chain later fails to confirm gets un-cached.
#[derive(Default)]
pub struct VerifiedHashCache {
    verified: HashSet<[u8; 32]>,
}

impl VerifiedHashCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_verified(&self, gene_hash: [u8; 32]) -> bool {
        self.verified.contains(&gene_hash)
    }

    pub fn mark_verified(&mut self, gene_hash: [u8; 32]) {
        self.verified.insert(gene_hash);
    }

    pub fn rollback(&mut self, gene_hash: [u8; 32]) {
        self.verified.remove(&gene_hash);
    }
}

type ThreatGenePair = ([u8; 32], [u8; 32]);

/// FR-M-6: tracks distinct signers reporting the same (threat_id,
/// gene_hash) pair. Keyed on the pair, not just gene_hash, so a stale
/// report from an old, now-superseded threat can't contribute quorum to a
/// gene minted for a different threat.
#[derive(Default)]
pub struct CorroborationTracker {
    reports: HashMap<ThreatGenePair, HashSet<Vec<u8>>>,
}

impl CorroborationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `hint`'s sender as having reported this (threat_id,
    /// gene_hash). A HashSet keyed by raw sender_pubkey bytes means a
    /// retransmission from the same sender never inflates the count.
    pub fn record(&mut self, hint: &CureHint) {
        self.reports.entry((hint.threat_id, hint.gene_hash)).or_default().insert(hint.sender_pubkey.clone());
    }

    pub fn has_quorum(&self, threat_id: [u8; 32], gene_hash: [u8; 32]) -> bool {
        self.reports.get(&(threat_id, gene_hash)).is_some_and(|s| s.len() >= QUORUM_K)
    }
}

/// FR-M-5's third gate: "run its own Stage-3 regression" before applying.
/// Injected, not implemented here -- no file in this codebase currently
/// exposes "replay an arbitrary received gene against my whitelisted-app
/// behavior" as a reusable function (soldier's allele_search/sandbox
/// operate on allele sequences during the evolution *search*, a different
/// abstraction, and mesh has no dependency edge onto soldier per
/// architecture.md). Left as a required trait, not a default/stub that
/// silently passes, so this MUST-tier gate can't be accidentally bypassed
/// by omission -- a real caller has to supply a real implementation.
pub trait Stage3Regression {
    fn check(&self, gene_bytes: &[u8]) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    RejectBadSignature,
    RejectUnpairedOrRevoked,
    RejectNoQuorum,
    RejectSuppressed,
    RejectRegressionFailed,
}

/// FR-M-5: the full gate, in the order the requirement lists it. Pure and
/// synchronous -- `epigenetic_status` is a plain bool the caller already
/// resolved (via `confirm_via_chain` below, or a cache), so this stays
/// unit-testable without any network or async runtime.
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    hint: &CureHint,
    roster: &Roster,
    revocations: &RevocationList,
    corroboration: &mut CorroborationTracker,
    cache: &VerifiedHashCache,
    gene_bytes: &[u8],
    regression: &impl Stage3Regression,
    epigenetic_status: bool,
) -> Decision {
    if !hint.signature_valid() {
        return Decision::RejectBadSignature;
    }
    let Some(sender) = hint.sender_public_key() else { return Decision::RejectBadSignature };
    if !is_paired_and_not_revoked(&sender, roster, revocations) {
        return Decision::RejectUnpairedOrRevoked;
    }

    corroboration.record(hint);
    if !cache.is_verified(hint.gene_hash) && !corroboration.has_quorum(hint.threat_id, hint.gene_hash) {
        return Decision::RejectNoQuorum;
    }

    if epigenetic_status {
        return Decision::RejectSuppressed;
    }
    if !regression.check(gene_bytes) {
        return Decision::RejectRegressionFailed;
    }

    Decision::Accept
}

fn is_paired_and_not_revoked(key: &PublicKey, roster: &Roster, revocations: &RevocationList) -> bool {
    roster.paired().contains(key) && !revocations.is_revoked(key)
}

/// FR-M-6: "the authoritative chain lookup MAY be asynchronous" -- wraps
/// ledger-client's synchronous RpcClient in `spawn_blocking` so it never
/// blocks the fast cache+quorum path in `evaluate`, per the plan Phase 5
/// already flagged for this. Returns whether the chain's committed
/// gene_hash for `threat_id` matches `gene_hash`; the caller decides
/// whether to `VerifiedHashCache::mark_verified`/`rollback` based on the
/// result -- this function doesn't touch the cache itself.
///
/// Requires a multi-threaded tokio runtime: `solana-rpc-client` uses
/// `tokio::task::block_in_place` internally, which panics ("can call
/// blocking only when running on the multi-threaded runtime") on a
/// current-thread runtime -- confirmed by a real test failure before this
/// was documented (tests/chain_lookup.rs uses `#[tokio::test(flavor =
/// "multi_thread")]` for exactly this reason).
pub async fn confirm_via_chain(
    client: Arc<LedgerClient>,
    threat_id: [u8; 32],
    gene_hash: [u8; 32],
) -> Result<bool, LedgerError> {
    let genome = tokio::task::spawn_blocking(move || client.fetch_genome_registry(threat_id))
        .await
        .expect("blocking task panicked")?;
    Ok(genome.is_some_and(|g| g.gene_hash == gene_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Identity, PairingCode};

    struct AlwaysPass;
    impl Stage3Regression for AlwaysPass {
        fn check(&self, _gene_bytes: &[u8]) -> bool {
            true
        }
    }

    struct AlwaysFail;
    impl Stage3Regression for AlwaysFail {
        fn check(&self, _gene_bytes: &[u8]) -> bool {
            false
        }
    }

    fn temp_identity() -> Identity {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let identity = Identity::load_or_generate(&path).unwrap();
        std::mem::forget(dir);
        identity
    }

    /// A roster containing exactly `sender`, via the normal pairing path
    /// (identity.rs's PairingCode/Roster::redeem), not a shortcut.
    fn paired_roster(sender: &Identity) -> Roster {
        let code = PairingCode::generate(sender);
        let mut roster = Roster::new();
        roster.redeem(&code, &code.nonce()).unwrap();
        roster
    }

    fn quorum_of(threat_id: [u8; 32], gene_hash: [u8; 32], senders: &[&Identity]) -> CorroborationTracker {
        let mut tracker = CorroborationTracker::new();
        for (i, sender) in senders.iter().enumerate() {
            tracker.record(&CureHint::sign(sender, threat_id, gene_hash, i as u64));
        }
        tracker
    }

    #[test]
    fn a_bad_signature_is_rejected_before_anything_else() {
        let sender = temp_identity();
        let mut hint = CureHint::sign(&sender, [1u8; 32], [2u8; 32], 0);
        hint.signature[0] ^= 0xFF;
        let roster = paired_roster(&sender);
        let decision = evaluate(
            &hint,
            &roster,
            &RevocationList::new(),
            &mut CorroborationTracker::new(),
            &VerifiedHashCache::new(),
            b"gene",
            &AlwaysPass,
            false,
        );
        assert_eq!(decision, Decision::RejectBadSignature);
    }

    #[test]
    fn an_unpaired_sender_is_rejected() {
        let sender = temp_identity();
        let hint = CureHint::sign(&sender, [1u8; 32], [2u8; 32], 0);
        let decision = evaluate(
            &hint,
            &Roster::new(), // sender never paired
            &RevocationList::new(),
            &mut CorroborationTracker::new(),
            &VerifiedHashCache::new(),
            b"gene",
            &AlwaysPass,
            false,
        );
        assert_eq!(decision, Decision::RejectUnpairedOrRevoked);
    }

    #[test]
    fn a_revoked_sender_is_rejected_even_if_paired() {
        let sender = temp_identity();
        let hint = CureHint::sign(&sender, [1u8; 32], [2u8; 32], 0);
        let roster = paired_roster(&sender);
        let mut revocations = RevocationList::new();
        revocations.revoke(sender.public());
        let decision = evaluate(
            &hint,
            &roster,
            &revocations,
            &mut CorroborationTracker::new(),
            &VerifiedHashCache::new(),
            b"gene",
            &AlwaysPass,
            false,
        );
        assert_eq!(decision, Decision::RejectUnpairedOrRevoked);
    }

    #[test]
    fn below_quorum_and_uncached_is_rejected() {
        let sender = temp_identity();
        let hint = CureHint::sign(&sender, [1u8; 32], [2u8; 32], 0);
        let roster = paired_roster(&sender);
        let decision = evaluate(
            &hint,
            &roster,
            &RevocationList::new(),
            &mut CorroborationTracker::new(), // no prior reports
            &VerifiedHashCache::new(),
            b"gene",
            &AlwaysPass,
            false,
        );
        assert_eq!(decision, Decision::RejectNoQuorum);
    }

    #[test]
    fn reaching_quorum_across_distinct_signers_passes_that_gate() {
        let sender = temp_identity();
        let other = temp_identity();
        let threat_id = [1u8; 32];
        let gene_hash = [2u8; 32];
        let hint = CureHint::sign(&sender, threat_id, gene_hash, 0);
        let roster = paired_roster(&sender);
        let mut corroboration = quorum_of(threat_id, gene_hash, &[&sender, &other]);
        let decision = evaluate(
            &hint,
            &roster,
            &RevocationList::new(),
            &mut corroboration,
            &VerifiedHashCache::new(),
            b"gene",
            &AlwaysPass,
            false,
        );
        assert_eq!(decision, Decision::Accept);
    }

    #[test]
    fn a_cached_hash_skips_the_quorum_requirement() {
        let sender = temp_identity();
        let hint = CureHint::sign(&sender, [1u8; 32], [2u8; 32], 0);
        let roster = paired_roster(&sender);
        let mut cache = VerifiedHashCache::new();
        cache.mark_verified([2u8; 32]);
        let decision =
            evaluate(&hint, &roster, &RevocationList::new(), &mut CorroborationTracker::new(), &cache, b"gene", &AlwaysPass, false);
        assert_eq!(decision, Decision::Accept);
    }

    #[test]
    fn a_suppressed_gene_is_rejected_even_with_quorum() {
        let sender = temp_identity();
        let hint = CureHint::sign(&sender, [1u8; 32], [2u8; 32], 0);
        let roster = paired_roster(&sender);
        let mut cache = VerifiedHashCache::new();
        cache.mark_verified([2u8; 32]);
        let decision = evaluate(
            &hint,
            &roster,
            &RevocationList::new(),
            &mut CorroborationTracker::new(),
            &cache,
            b"gene",
            &AlwaysPass,
            true, // epigenetic_status
        );
        assert_eq!(decision, Decision::RejectSuppressed);
    }

    #[test]
    fn a_failed_regression_is_rejected() {
        let sender = temp_identity();
        let hint = CureHint::sign(&sender, [1u8; 32], [2u8; 32], 0);
        let roster = paired_roster(&sender);
        let mut cache = VerifiedHashCache::new();
        cache.mark_verified([2u8; 32]);
        let decision =
            evaluate(&hint, &roster, &RevocationList::new(), &mut CorroborationTracker::new(), &cache, b"gene", &AlwaysFail, false);
        assert_eq!(decision, Decision::RejectRegressionFailed);
    }

    #[test]
    fn rollback_removes_a_cached_hash() {
        let mut cache = VerifiedHashCache::new();
        cache.mark_verified([9u8; 32]);
        assert!(cache.is_verified([9u8; 32]));
        cache.rollback([9u8; 32]);
        assert!(!cache.is_verified([9u8; 32]));
    }
}
