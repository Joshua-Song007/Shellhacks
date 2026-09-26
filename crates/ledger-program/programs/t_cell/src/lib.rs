pub mod constants;
pub mod error;
pub mod instructions;
pub mod poi;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
pub use instructions::*;
pub use state::*;

declare_id!("27v76nMPKQg5akQHBsPHnhPt8K7kSf3s8GZjRzUnvBuq");

#[program]
pub mod t_cell {
    use super::*;

    /// FR-L-2/L-3: report a threat, corroborating it if already known.
    pub fn submit_threat(
        ctx: Context<SubmitThreat>,
        threat_id: [u8; 32],
        behavioral_schema_hash: [u8; 32],
    ) -> Result<()> {
        crate::instructions::submit_threat::handle_submit_threat(ctx, threat_id, behavioral_schema_hash)
    }

    /// FR-L-2/L-4/L-6/R-9: commit (or append a chunk of) the cure gene, PoI-gated.
    pub fn commit_gene(
        ctx: Context<CommitGene>,
        threat_id: [u8; 32],
        gene_hash: [u8; 32],
        chunk: Vec<u8>,
        is_final_chunk: bool,
    ) -> Result<()> {
        crate::instructions::commit_gene::handle_commit_gene(ctx, threat_id, gene_hash, chunk, is_final_chunk)
    }

    /// FR-L-2/L-7: network-wide kill-switch for a flagged gene, PoI-gated.
    pub fn suppress_gene(ctx: Context<SuppressGene>, threat_id: [u8; 32]) -> Result<()> {
        crate::instructions::suppress_gene::handle_suppress_gene(ctx, threat_id)
    }
}
