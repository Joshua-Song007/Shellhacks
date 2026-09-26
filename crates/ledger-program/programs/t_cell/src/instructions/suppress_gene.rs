use anchor_lang::prelude::*;

use crate::poi;
use crate::state::GenomeRegistry;

/// FR-L-7: flips Epigenetic_Status so every Soldier halts on this gene
/// before fetching/running it. Also PoI-gated (same 3-of-5 committee as
/// commit_gene) per user decision 2026-09-26: FR-L-6 only names
/// commit_gene, but leaving this network-wide kill-switch ungated is a
/// griefing vector -- a deliberate scope addition beyond spec's literal
/// wording, not something FR-L-6 requires.
#[derive(Accounts)]
#[instruction(threat_id: [u8; 32])]
pub struct SuppressGene<'info> {
    #[account(mut, seeds = [GenomeRegistry::SEED, threat_id.as_ref()], bump)]
    pub genome_registry: Account<'info, GenomeRegistry>,
    pub signer_a: Signer<'info>,
    pub signer_b: Signer<'info>,
    pub signer_c: Signer<'info>,
    pub signer_d: Signer<'info>,
    pub signer_e: Signer<'info>,
}

pub fn handle_suppress_gene(ctx: Context<SuppressGene>, _threat_id: [u8; 32]) -> Result<()> {
    poi::require_poi(&[
        ctx.accounts.signer_a.key(),
        ctx.accounts.signer_b.key(),
        ctx.accounts.signer_c.key(),
        ctx.accounts.signer_d.key(),
        ctx.accounts.signer_e.key(),
    ])?;
    ctx.accounts.genome_registry.epigenetic_status = true;
    Ok(())
}
