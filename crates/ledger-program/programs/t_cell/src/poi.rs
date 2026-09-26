use anchor_lang::prelude::*;

use crate::error::TCellError;

/// FR-L-6: 3-of-5 PoI multisig. Hardcoded compile-time committee rather
/// than a runtime-configurable on-chain config account: FR-L-2 names
/// exactly 3 instructions (submit_threat/commit_gene/suppress_gene), and a
/// 4th init-config instruction would be scope beyond spec. Genuine dynamic
/// multi-party membership is FR-M-10 (MAY/stretch) -- revisit only if that
/// gets picked up. These are the 5 devnet-only demo keypairs generated
/// under crates/ledger-program/keys/ (gitignored, not committed).
pub const POI_THRESHOLD: usize = 3;

pub const POI_COMMITTEE: [Pubkey; 5] = [
    pubkey!("DuUqFL3imPUxFESsaB7gKKKR9n65NWbWvDKmRdFUkPMX"),
    pubkey!("AYGKu1ypUQBjtPevHUS5PztNz57Qm2wZsGtiAhVk17ek"),
    pubkey!("AuoRudix57E3V1ZcvnqcC2tmQUTxLc4BpqjY1oeEnKU7"),
    pubkey!("8DPZvDNCkh9kgjxdMXghqkUKJ6bgqatyv144V3YfRDTA"),
    pubkey!("GTK9bPW447GNRYwpqrWppX37v22JQY8PcEwpqHPFeTfz"),
];

/// Pure: counts distinct POI_COMMITTEE members among the 5 candidate
/// pubkeys and requires at least POI_THRESHOLD. Takes plain `Pubkey`s
/// rather than `Signer`s so it's unit-testable with zero Solana runtime --
/// "did this account actually sign the transaction" is Anchor's
/// `Signer<'info>` type's job, enforced as a required (non-`Option`) field
/// in each instruction's Accounts struct; this only checks *who* signed
/// against the fixed committee. All 5 slots are required signers even when
/// fewer than 5 real committee members are available -- a caller short on
/// committee members just repeats one they do have (or the payer) in the
/// unused slots; duplicates and non-committee pubkeys simply don't count
/// toward the threshold. Chosen over `Option<Signer<'info>>` slots because
/// Anchor's optional-account resolution has version-specific encoding
/// quirks not worth chasing at hackathon scale -- every Solana transaction
/// already lists concrete signer accounts, so "optional" isn't a native
/// concept here anyway.
pub fn require_poi(candidates: &[Pubkey]) -> Result<()> {
    let mut seen: Vec<Pubkey> = Vec::with_capacity(POI_COMMITTEE.len());
    for key in candidates {
        if POI_COMMITTEE.contains(key) && !seen.contains(key) {
            seen.push(*key);
        }
    }
    require!(seen.len() >= POI_THRESHOLD, TCellError::InsufficientSignatures);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee(i: usize) -> Pubkey {
        POI_COMMITTEE[i]
    }

    fn outsider() -> Pubkey {
        Pubkey::new_unique()
    }

    #[test]
    fn exactly_three_distinct_committee_members_passes() {
        // unused slots repeat a committee member, as a real caller short on
        // distinct signers would -- must not inflate the count above 3.
        let candidates = [committee(0), committee(1), committee(2), committee(0), committee(0)];
        assert!(require_poi(&candidates).is_ok());
    }

    #[test]
    fn two_of_five_fails() {
        let candidates = [committee(0), committee(1), committee(0), committee(1), committee(0)];
        assert!(require_poi(&candidates).is_err(), "only 2 distinct committee members even though all 5 slots are committee pubkeys");
    }

    #[test]
    fn duplicate_committee_pubkey_across_slots_does_not_count_twice() {
        let candidates = [committee(0), committee(0), committee(1), outsider(), outsider()];
        assert!(require_poi(&candidates).is_err(), "only 2 distinct committee members -- duplicate shouldn't inflate the count");
    }

    #[test]
    fn non_committee_pubkeys_do_not_count() {
        let candidates = [committee(0), committee(1), outsider(), outsider(), outsider()];
        assert!(require_poi(&candidates).is_err());
    }

    #[test]
    fn all_outsiders_fails() {
        let candidates = [outsider(), outsider(), outsider(), outsider(), outsider()];
        assert!(require_poi(&candidates).is_err());
    }

    #[test]
    fn all_five_committee_members_passes() {
        let candidates = [committee(0), committee(1), committee(2), committee(3), committee(4)];
        assert!(require_poi(&candidates).is_ok());
    }
}
