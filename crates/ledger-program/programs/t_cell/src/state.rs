use anchor_lang::prelude::*;

use crate::constants::{GENOME_SEED, MAX_GENE_BYTES, MAX_REPORTERS, THREAT_SEED};

/// FR-L-3/DATA-2: Threat Registry PDA. `reporters` dedups "independent"
/// corroboration by signer pubkey -- no mesh/device-identity system exists
/// yet (Phase 6 unbuilt), so a distinct on-chain signer is the interim
/// definition of "independent report". `threat_id == [0; 32]` marks an
/// account not yet initialized by a first submit_threat call (a real
/// SHA-256 Threat_ID is never all-zero in practice).
#[account]
pub struct ThreatRegistry {
    pub threat_id: [u8; 32],
    pub confidence_score: u32,
    pub behavioral_schema_hash: [u8; 32],
    pub reporters: Vec<Pubkey>,
}

impl ThreatRegistry {
    pub const SEED: &'static [u8] = THREAT_SEED;
    /// discriminator + threat_id + confidence_score + schema_hash + Vec len
    /// prefix + MAX_REPORTERS pubkeys. Fixed at init regardless of current
    /// reporter count (same discipline as GenomeRegistry::SPACE below).
    pub const SPACE: usize = 8 + 32 + 4 + 32 + 4 + 32 * MAX_REPORTERS;
}

/// FR-L-4/CON-9/FR-R-9: Genome Registry PDA. `gene_seq`'s space is fixed at
/// MAX_GENE_BYTES regardless of how much is currently written, so chunked
/// appends never trigger AccountStorageFull. `epigenetic_status` only ever
/// gets set true (suppress_gene) -- no un-suppress instruction exists,
/// matching FR-L-2's exact 3-instruction list; accepted spec gap, no
/// revisit scheduled.
#[account]
pub struct GenomeRegistry {
    pub threat_id: [u8; 32],
    pub gene_hash: [u8; 32],
    pub gene_seq: Vec<u8>,
    pub epigenetic_status: bool,
}

impl GenomeRegistry {
    pub const SEED: &'static [u8] = GENOME_SEED;
    pub const SPACE: usize = 8 + 32 + 32 + 4 + MAX_GENE_BYTES + 1;
}
