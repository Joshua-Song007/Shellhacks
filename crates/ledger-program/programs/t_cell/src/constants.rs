use anchor_lang::prelude::*;

#[constant]
pub const THREAT_SEED: &[u8] = b"threat";
#[constant]
pub const GENOME_SEED: &[u8] = b"genome";

/// FR-L-3: invented cap (no spec number) bounding ThreatRegistry's fixed
/// init space -- how many distinct reporters can corroborate one threat_id.
pub const MAX_REPORTERS: usize = 32;

/// CON-9/FR-R-9: fixed generous max for gene_seq so chunked appends never
/// need `realloc`/trigger `AccountStorageFull`.
pub const MAX_GENE_BYTES: usize = 4096;
