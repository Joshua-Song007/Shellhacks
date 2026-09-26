use anchor_lang::prelude::*;

#[error_code]
pub enum TCellError {
    #[msg("commit_gene/suppress_gene require at least 3 of the 5 registered PoI committee members to sign")]
    InsufficientSignatures,
    #[msg("this threat_id's behavioral_schema_hash does not match the one already recorded")]
    SchemaMismatch,
    #[msg("ThreatRegistry has reached its fixed reporter cap")]
    TooManyReporters,
    #[msg("gene_seq chunk would exceed the fixed Genome Registry space")]
    GeneTooLarge,
}
