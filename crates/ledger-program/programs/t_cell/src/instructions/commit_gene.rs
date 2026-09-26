use anchor_lang::prelude::*;

use crate::constants::MAX_GENE_BYTES;
use crate::error::TCellError;
use crate::poi;
use crate::state::GenomeRegistry;

/// FR-L-4/L-6/R-9/CON-9: writes (or appends a chunk of) the gene, gated by
/// the 3-of-5 PoI multisig on every call -- not just the final chunk -- so
/// a partial gene can't be seeded by a minority. A single-write caller just
/// passes the whole gene as one chunk with `is_final_chunk = true`; that's
/// the same code path as a multi-chunk upload, no separate instruction.
/// `signer_a..signer_e` are all required (not `Option<Signer>`) -- a
/// caller with fewer than 5 distinct committee members on hand just
/// repeats one they do have; `poi::require_poi` dedups, so repeats can't
/// inflate the count. See poi.rs's doc comment for why over `Option`.
#[derive(Accounts)]
#[instruction(threat_id: [u8; 32])]
pub struct CommitGene<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        space = GenomeRegistry::SPACE,
        seeds = [GenomeRegistry::SEED, threat_id.as_ref()],
        bump
    )]
    pub genome_registry: Account<'info, GenomeRegistry>,
    pub system_program: Program<'info, System>,
    pub signer_a: Signer<'info>,
    pub signer_b: Signer<'info>,
    pub signer_c: Signer<'info>,
    pub signer_d: Signer<'info>,
    pub signer_e: Signer<'info>,
}

pub fn handle_commit_gene(
    ctx: Context<CommitGene>,
    threat_id: [u8; 32],
    gene_hash: [u8; 32],
    chunk: Vec<u8>,
    is_final_chunk: bool,
) -> Result<()> {
    poi::require_poi(&[
        ctx.accounts.signer_a.key(),
        ctx.accounts.signer_b.key(),
        ctx.accounts.signer_c.key(),
        ctx.accounts.signer_d.key(),
        ctx.accounts.signer_e.key(),
    ])?;

    let genome = &mut ctx.accounts.genome_registry;
    // gene_seq is append-only: once a final chunk has set gene_hash, a second
    // commit for the same (deterministic) threat_id would append a duplicate
    // copy and corrupt the stored gene.
    require!(genome.gene_hash == [0u8; 32], TCellError::GeneAlreadyCommitted);
    require!(genome.gene_seq.len() + chunk.len() <= MAX_GENE_BYTES, TCellError::GeneTooLarge);

    if genome.threat_id == [0u8; 32] {
        genome.threat_id = threat_id;
    }
    genome.gene_seq.extend_from_slice(&chunk);
    if is_final_chunk {
        genome.gene_hash = gene_hash;
    }
    Ok(())
}
