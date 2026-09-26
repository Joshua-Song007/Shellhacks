use anchor_lang::prelude::*;

use crate::constants::MAX_REPORTERS;
use crate::error::TCellError;
use crate::state::ThreatRegistry;

/// FR-L-2/L-3/L-8: creates the Threat Registry PDA on first report, then
/// increments confidence_score on each subsequent *independent* report
/// (deduped by reporter pubkey -- see state.rs's doc comment). Only the
/// already-hashed threat_id/schema_hash ever enters instruction data, never
/// raw telemetry (FR-L-8). No PoI gate: FR-L-6 only names commit_gene --
/// corroboration is meant to be freely reportable by any device.
#[derive(Accounts)]
#[instruction(threat_id: [u8; 32])]
pub struct SubmitThreat<'info> {
    #[account(mut)]
    pub reporter: Signer<'info>,
    #[account(
        init_if_needed,
        payer = reporter,
        space = ThreatRegistry::SPACE,
        seeds = [ThreatRegistry::SEED, threat_id.as_ref()],
        bump
    )]
    pub threat_registry: Account<'info, ThreatRegistry>,
    pub system_program: Program<'info, System>,
}

pub fn handle_submit_threat(
    ctx: Context<SubmitThreat>,
    threat_id: [u8; 32],
    behavioral_schema_hash: [u8; 32],
) -> Result<()> {
    let registry = &mut ctx.accounts.threat_registry;
    let reporter = ctx.accounts.reporter.key();

    if registry.threat_id == [0u8; 32] {
        registry.threat_id = threat_id;
        registry.behavioral_schema_hash = behavioral_schema_hash;
    }
    require!(registry.behavioral_schema_hash == behavioral_schema_hash, TCellError::SchemaMismatch);

    if !registry.reporters.contains(&reporter) {
        require!(registry.reporters.len() < MAX_REPORTERS, TCellError::TooManyReporters);
        registry.reporters.push(reporter);
        registry.confidence_score = registry.confidence_score.saturating_add(1);
    }
    Ok(())
}
