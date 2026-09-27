//! FR-L-5, CON-1/2, FR-R-9, CON-9: RPC light client. Trusts `confirmed`/
//! `finalized` reads only -- no custom Merkle light-client, no local
//! validator, no IPFS/off-chain blob store (CON-1/2). Owns the chunked
//! gene-upload orchestration (FR-R-9): a gene under the per-tx budget is a
//! single `commit_gene` call, one over it becomes several calls into the
//! same fixed-size Genome Registry PDA -- same on-chain code path either
//! way, decided here.
//!
//! Reuses `t_cell`'s own Anchor-generated instruction/accounts/state types
//! directly (via a path dependency with the `cpi` feature) rather than
//! hand-encoding Borsh -- the same pattern Phase 4's litesvm tests proved
//! out, just swapping `litesvm` for a real `RpcClient`.

use std::fmt;

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use solana_client::client_error::ClientError;
use solana_client::rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient};
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::system_program;
use solana_signature::Signature;

/// CON-9: a Solana transaction is capped at 1232 bytes total. commit_gene's
/// account overhead is unusually high -- 8 accounts (payer, genome_registry,
/// system_program, 5 PoI signers) means 6 required signatures (64B each) on
/// every call, measured empirically (see `probe_tx_size_matches_measured_overhead`
/// below) at a constant 799 bytes regardless of chunk length. That leaves
/// 1232-799=433 bytes for the chunk itself; 400 keeps a safety margin.
/// overview.md's own "~900B post-overhead" figure assumed a much cheaper,
/// few-signer instruction shape -- it doesn't hold once an instruction
/// needs 5 extra required signers, as commit_gene does (a consequence of
/// Phase 4's Option<Signer> -> required-Signer simplification). This is a
/// transaction-construction concern independent of `t_cell::MAX_GENE_BYTES`
/// (that's the *account's* total fixed space). Duplicated from soldier's
/// gene_compile.rs rather than reused -- ledger-client has no dependency
/// edge onto soldier per architecture.md.
pub const MAX_CHUNK_BYTES: usize = 400;

#[derive(Debug)]
pub enum LedgerError {
    Rpc(ClientError),
    Deserialize(anchor_lang::error::Error),
    GeneTooLarge(usize),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Rpc(e) => write!(f, "rpc: {e}"),
            LedgerError::Deserialize(e) => write!(f, "deserialize: {e}"),
            LedgerError::GeneTooLarge(n) => write!(f, "gene is {n} bytes, exceeds t_cell::MAX_GENE_BYTES"),
        }
    }
}

impl std::error::Error for LedgerError {}

pub struct LedgerClient {
    rpc: RpcClient,
    program_id: Pubkey,
}

impl LedgerClient {
    pub fn new(rpc_url: &str, commitment: CommitmentConfig) -> Self {
        Self { rpc: RpcClient::new_with_commitment(rpc_url.to_string(), commitment), program_id: t_cell::ID }
    }

    /// FR-L-1: convenience constructor for the devnet deployment.
    pub fn devnet(commitment: CommitmentConfig) -> Self {
        Self::new("https://api.devnet.solana.com", commitment)
    }

    fn threat_registry_pda(&self, threat_id: [u8; 32]) -> Pubkey {
        Pubkey::find_program_address(&[t_cell::THREAT_SEED, threat_id.as_ref()], &self.program_id).0
    }

    fn genome_registry_pda(&self, threat_id: [u8; 32]) -> Pubkey {
        Pubkey::find_program_address(&[t_cell::GENOME_SEED, threat_id.as_ref()], &self.program_id).0
    }

    /// FR-L-2/L-3: report a threat (or corroborate one already known).
    pub fn submit_threat(
        &self,
        reporter: &Keypair,
        threat_id: [u8; 32],
        behavioral_schema_hash: [u8; 32],
    ) -> Result<Signature, LedgerError> {
        let threat_registry = self.threat_registry_pda(threat_id);
        let ix = Instruction::new_with_bytes(
            self.program_id,
            &t_cell::instruction::SubmitThreat { threat_id, behavioral_schema_hash }.data(),
            t_cell::accounts::SubmitThreat {
                reporter: reporter.pubkey(),
                threat_registry,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        );
        self.send(&[ix], reporter, &[reporter])
    }

    /// FR-L-4/L-6/R-9/CON-9: commits the gene, splitting into `MAX_CHUNK_BYTES`
    /// slices when it exceeds that per-tx budget -- one `commit_gene` call
    /// per chunk, `is_final_chunk` on the last. `committee` (1-5 keypairs)
    /// is padded to 5 slots by repeating the last entry when fewer than 5
    /// are given, matching t_cell::poi::require_poi's tolerance for repeats.
    pub fn commit_gene(
        &self,
        payer: &Keypair,
        committee: &[&Keypair],
        threat_id: [u8; 32],
        gene_hash: [u8; 32],
        gene_bytes: &[u8],
    ) -> Result<Vec<Signature>, LedgerError> {
        if gene_bytes.len() > t_cell::MAX_GENE_BYTES {
            return Err(LedgerError::GeneTooLarge(gene_bytes.len()));
        }
        let five = pad_committee(committee);
        let genome_registry = self.genome_registry_pda(threat_id);
        let chunks = plan_chunks(gene_bytes);

        let mut signatures = Vec::with_capacity(chunks.len());
        for (i, chunk) in chunks.iter().enumerate() {
            let is_final_chunk = i == chunks.len() - 1;
            let ix = Instruction::new_with_bytes(
                self.program_id,
                &t_cell::instruction::CommitGene { threat_id, gene_hash, chunk: chunk.to_vec(), is_final_chunk }
                    .data(),
                t_cell::accounts::CommitGene {
                    payer: payer.pubkey(),
                    genome_registry,
                    system_program: system_program::ID,
                    signer_a: five[0].pubkey(),
                    signer_b: five[1].pubkey(),
                    signer_c: five[2].pubkey(),
                    signer_d: five[3].pubkey(),
                    signer_e: five[4].pubkey(),
                }
                .to_account_metas(None),
            );
            let mut signers: Vec<&Keypair> = vec![payer];
            signers.extend(five.iter());
            signatures.push(self.send(&[ix], payer, &signers)?);
        }
        Ok(signatures)
    }

    /// FR-L-7: network-wide kill-switch. Same committee-padding as `commit_gene`.
    pub fn suppress_gene(
        &self,
        payer: &Keypair,
        committee: &[&Keypair],
        threat_id: [u8; 32],
    ) -> Result<Signature, LedgerError> {
        let five = pad_committee(committee);
        let genome_registry = self.genome_registry_pda(threat_id);
        let ix = Instruction::new_with_bytes(
            self.program_id,
            &t_cell::instruction::SuppressGene { threat_id }.data(),
            t_cell::accounts::SuppressGene {
                genome_registry,
                signer_a: five[0].pubkey(),
                signer_b: five[1].pubkey(),
                signer_c: five[2].pubkey(),
                signer_d: five[3].pubkey(),
                signer_e: five[4].pubkey(),
            }
            .to_account_metas(None),
        );
        let mut signers: Vec<&Keypair> = vec![payer];
        signers.extend(five.iter());
        self.send(&[ix], payer, &signers)
    }

    /// FR-L-3/L-5: RPC light-client read at this client's configured
    /// commitment. An account that doesn't exist yet (nobody has reported
    /// this threat) is `Ok(None)`, not an error.
    pub fn fetch_threat_registry(&self, threat_id: [u8; 32]) -> Result<Option<t_cell::ThreatRegistry>, LedgerError> {
        self.fetch(self.threat_registry_pda(threat_id))
    }

    /// FR-L-4/L-5/L-7: RPC light-client read. Every Soldier SHALL check
    /// `epigenetic_status` here before fetching/running a gene -- this is
    /// the read path that check would use; wiring it into soldier itself
    /// is not part of this crate (soldier has no dependency edge onto
    /// ledger-client per architecture.md), noted not solved here.
    pub fn fetch_genome_registry(&self, threat_id: [u8; 32]) -> Result<Option<t_cell::GenomeRegistry>, LedgerError> {
        self.fetch(self.genome_registry_pda(threat_id))
    }

    /// FR-L-5: light-client read of this program's recent transaction
    /// signatures (submit_threat/commit_gene/suppress_gene calls), newest
    /// first -- raw material for a ledger activity feed. One RPC page only
    /// (no cursor), matching this client's existing sync, no-pagination
    /// style; `commitment: None` falls back to this client's own configured
    /// commitment rather than overriding it.
    pub fn recent_signatures(
        &self,
        limit: usize,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>, LedgerError> {
        let config = GetConfirmedSignaturesForAddress2Config {
            before: None,
            until: None,
            limit: Some(limit),
            commitment: None,
        };
        self.rpc.get_signatures_for_address_with_config(&self.program_id, config).map_err(LedgerError::Rpc)
    }

    /// FR-L-4/L-5: enumerates every Genome Registry account this program
    /// owns. `get_program_accounts` returns every PDA the program owns
    /// (ThreatRegistry and GenomeRegistry mixed, since both live under the
    /// same program id) -- a ThreatRegistry account's discriminator makes
    /// `GenomeRegistry::try_deserialize` fail cleanly, so it's silently
    /// skipped rather than treated as an error.
    pub fn all_genomes(&self) -> Result<Vec<t_cell::GenomeRegistry>, LedgerError> {
        let accounts = self.rpc.get_program_accounts(&self.program_id).map_err(LedgerError::Rpc)?;
        Ok(accounts
            .into_iter()
            .filter_map(|(_, account)| t_cell::GenomeRegistry::try_deserialize(&mut account.data.as_slice()).ok())
            .collect())
    }

    /// Every Threat Registry account this program owns; same mixed-account
    /// filter as `all_genomes`, from the other side.
    pub fn all_threats(&self) -> Result<Vec<t_cell::ThreatRegistry>, LedgerError> {
        let accounts = self.rpc.get_program_accounts(&self.program_id).map_err(LedgerError::Rpc)?;
        Ok(accounts
            .into_iter()
            .filter_map(|(_, account)| t_cell::ThreatRegistry::try_deserialize(&mut account.data.as_slice()).ok())
            .collect())
    }

    fn fetch<T: AccountDeserialize>(&self, pda: Pubkey) -> Result<Option<T>, LedgerError> {
        match self.rpc.get_account_data(&pda) {
            Ok(data) => T::try_deserialize(&mut data.as_slice()).map(Some).map_err(LedgerError::Deserialize),
            Err(e) if e.to_string().contains("AccountNotFound") => Ok(None),
            Err(e) => Err(LedgerError::Rpc(e)),
        }
    }

    fn send(
        &self,
        instructions: &[Instruction],
        payer: &Keypair,
        signers: &[&Keypair],
    ) -> Result<Signature, LedgerError> {
        let blockhash = self.rpc.get_latest_blockhash().map_err(LedgerError::Rpc)?;
        let message = Message::new(instructions, Some(&payer.pubkey()));
        let tx = Transaction::new(signers, message, blockhash);
        self.rpc.send_and_confirm_transaction(&tx).map_err(LedgerError::Rpc)
    }
}

/// FR-R-9/CON-9: pure -- splits `bytes` into `MAX_CHUNK_BYTES` slices. An
/// empty gene still produces exactly one (empty) chunk, so `commit_gene`
/// always sends at least one call.
fn plan_chunks(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        vec![bytes]
    } else {
        bytes.chunks(MAX_CHUNK_BYTES).collect()
    }
}

/// Pads `committee` (1-5 keypairs) to exactly 5 slots by repeating the last
/// entry -- matches t_cell::poi::require_poi's tolerance for repeats (they
/// simply don't inflate the distinct-signer count).
fn pad_committee<'a>(committee: &[&'a Keypair]) -> [&'a Keypair; 5] {
    assert!(!committee.is_empty() && committee.len() <= 5, "commit_gene/suppress_gene need 1-5 committee signers");
    let mut out = [committee[committee.len() - 1]; 5];
    out[..committee.len()].copy_from_slice(committee);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for the CON-9 budget above: a commit_gene call at
    /// exactly MAX_CHUNK_BYTES must still fit in a real 1232-byte
    /// transaction. Caught a real bug during Phase 5's apply -- the
    /// original 900B guess (borrowed from a generic few-signer assumption)
    /// produced a 1699-byte transaction and was rejected by a live
    /// validator; this test would have caught it without needing the
    /// network.
    #[test]
    fn commit_gene_at_max_chunk_bytes_fits_a_real_transaction() {
        let payer = Keypair::new();
        let five: [Keypair; 5] = std::array::from_fn(|_| Keypair::new());
        let ix = Instruction::new_with_bytes(
            t_cell::ID,
            &t_cell::instruction::CommitGene {
                threat_id: [0u8; 32],
                gene_hash: [0u8; 32],
                chunk: vec![0u8; MAX_CHUNK_BYTES],
                is_final_chunk: true,
            }
            .data(),
            t_cell::accounts::CommitGene {
                payer: payer.pubkey(),
                genome_registry: Pubkey::new_unique(),
                system_program: system_program::ID,
                signer_a: five[0].pubkey(),
                signer_b: five[1].pubkey(),
                signer_c: five[2].pubkey(),
                signer_d: five[3].pubkey(),
                signer_e: five[4].pubkey(),
            }
            .to_account_metas(None),
        );
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let mut signers: Vec<&Keypair> = vec![&payer];
        signers.extend(five.iter());
        let tx = Transaction::new(&signers, message, solana_hash::Hash::default());
        let size = bincode::serialize(&tx).unwrap().len();
        assert!(size <= 1232, "commit_gene at MAX_CHUNK_BYTES serializes to {size} bytes, over the 1232B tx cap");
    }

    #[test]
    fn plan_chunks_of_empty_bytes_is_one_empty_chunk() {
        assert_eq!(plan_chunks(&[]), vec![&[] as &[u8]]);
    }

    #[test]
    fn plan_chunks_under_budget_is_a_single_chunk() {
        let bytes = vec![0u8; MAX_CHUNK_BYTES];
        assert_eq!(plan_chunks(&bytes).len(), 1);
    }

    #[test]
    fn plan_chunks_one_byte_over_budget_splits_into_two() {
        let bytes = vec![0u8; MAX_CHUNK_BYTES + 1];
        let chunks = plan_chunks(&bytes);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), MAX_CHUNK_BYTES);
        assert_eq!(chunks[1].len(), 1);
    }

    #[test]
    fn plan_chunks_several_multiples_over_splits_evenly() {
        let bytes = vec![0u8; MAX_CHUNK_BYTES * 3];
        assert_eq!(plan_chunks(&bytes).len(), 3);
    }

    fn kp(seed: u8) -> Keypair {
        Keypair::new_from_array([seed; 32])
    }

    #[test]
    fn pad_committee_of_one_repeats_it_five_times() {
        let a = kp(1);
        let padded = pad_committee(&[&a]);
        assert!(padded.iter().all(|k| k.pubkey() == a.pubkey()));
    }

    #[test]
    fn pad_committee_of_three_pads_with_the_last() {
        let a = kp(1);
        let b = kp(2);
        let c = kp(3);
        let padded = pad_committee(&[&a, &b, &c]);
        assert_eq!(padded[0].pubkey(), a.pubkey());
        assert_eq!(padded[1].pubkey(), b.pubkey());
        assert_eq!(padded[2].pubkey(), c.pubkey());
        assert_eq!(padded[3].pubkey(), c.pubkey());
        assert_eq!(padded[4].pubkey(), c.pubkey());
    }

    #[test]
    fn pad_committee_of_five_is_unchanged() {
        let keys: Vec<Keypair> = (1..=5).map(kp).collect();
        let refs: Vec<&Keypair> = keys.iter().collect();
        let padded = pad_committee(&refs);
        for i in 0..5 {
            assert_eq!(padded[i].pubkey(), keys[i].pubkey());
        }
    }
}
