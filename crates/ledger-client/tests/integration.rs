//! Integration tests against a real `RpcClient`, run through a local
//! `solana-test-validator` -- dev-time infra (CON-2 forbids a local
//! validator only for the *production* client's own read path, not for
//! testing it). `#[ignore]` by default; run with `cargo test -p
//! ledger-client -- --ignored` after:
//!   1. `solana-test-validator --reset --quiet &`
//!   2. `solana program deploy ../ledger-program/target/deploy/t_cell.so
//!      --program-id ../ledger-program/target/deploy/t_cell-keypair.json
//!      --url localhost`
//!
//! These deliberately force a multi-chunk gene upload (a synthetic gene
//! sized past MAX_CHUNK_BYTES) -- Phase 4's litesvm tests never exercised
//! that path since real compiled genes are tiny.

use ledger_client::LedgerClient;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_signer::Signer;

const LOCALNET: &str = "http://127.0.0.1:8899";

fn client() -> LedgerClient {
    LedgerClient::new(LOCALNET, CommitmentConfig::confirmed())
}

/// Loads one of the 5 real PoI committee keypairs (t_cell::poi::POI_COMMITTEE
/// hardcodes their pubkeys) generated during Phase 4, under
/// crates/ledger-program/keys/ (gitignored). Only a transaction's fee payer
/// needs SOL -- co-signers don't, so these are never airdropped to.
fn poi_keypair(n: u8) -> Keypair {
    let path = match n {
        1 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-1.json"),
        2 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-2.json"),
        3 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-3.json"),
        4 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-4.json"),
        5 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-5.json"),
        _ => panic!("only 5 PoI keypairs exist"),
    };
    read_keypair_file(path).expect("poi keypair file present (crates/ledger-program/keys/, gitignored)")
}

fn poi_committee() -> Vec<Keypair> {
    (1..=3).map(poi_keypair).collect() // 3-of-5 is sufficient
}

/// A fresh threat_id per call, derived from wall-clock nanos. The local
/// validator persists state across separate `cargo test` invocations
/// (only `--reset` on startup clears it), so a hardcoded threat_id would
/// accumulate confidence_score/gene_seq from every prior run instead of
/// starting clean.
fn fresh_threat_id() -> [u8; 32] {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let mut id = [0u8; 32];
    id[..16].copy_from_slice(&nanos.to_le_bytes());
    id
}

/// Test-only: airdropping isn't part of LedgerClient's real API surface
/// (production clients don't fund themselves) -- this talks to the local
/// validator directly, just to set up test fixtures.
fn funded(n: usize) -> Vec<Keypair> {
    let rpc = RpcClient::new_with_commitment(LOCALNET.to_string(), CommitmentConfig::confirmed());
    (0..n)
        .map(|_| {
            let kp = Keypair::new();
            let sig = rpc.request_airdrop(&kp.pubkey(), 1_000_000_000).expect("airdrop (is solana-test-validator running?)");
            // `confirm_transaction` reports a snapshot, it does not block
            // until true -- poll until the airdrop has actually landed.
            for _ in 0..50 {
                if rpc.confirm_transaction(&sig).unwrap_or(false) {
                    return kp;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("airdrop for {} never confirmed", kp.pubkey());
        })
        .collect()
}

#[test]
#[ignore]
fn submit_threat_creates_registry_and_dedupes_by_reporter() {
    let client = client();
    let reporters = funded(2);
    let threat_id = fresh_threat_id();
    let schema_hash = [22u8; 32];

    client.submit_threat(&reporters[0], threat_id, schema_hash).unwrap();
    assert_eq!(client.fetch_threat_registry(threat_id).unwrap().unwrap().confidence_score, 1);

    client.submit_threat(&reporters[1], threat_id, schema_hash).unwrap();
    assert_eq!(client.fetch_threat_registry(threat_id).unwrap().unwrap().confidence_score, 2);

    client.submit_threat(&reporters[0], threat_id, schema_hash).unwrap();
    assert_eq!(
        client.fetch_threat_registry(threat_id).unwrap().unwrap().confidence_score,
        2,
        "a repeat report from the same reporter must not double-count"
    );
}

#[test]
#[ignore]
fn fetch_threat_registry_of_an_unreported_threat_is_none() {
    let client = client();
    assert!(client.fetch_threat_registry([99u8; 32]).unwrap().is_none());
    assert!(client.fetch_genome_registry([99u8; 32]).unwrap().is_none());
}

#[test]
#[ignore]
fn commit_gene_forces_a_real_multi_chunk_upload() {
    let client = client();
    let payer = &funded(1)[0];
    let committee_keys = poi_committee();
    let committee: Vec<&Keypair> = committee_keys.iter().collect();

    let threat_id = [23u8; 32];
    let gene_hash = [24u8; 32];
    // Deliberately over ledger_client::client::MAX_CHUNK_BYTES so this must
    // take >1 commit_gene call -- litesvm's tests never hit this path.
    let gene_bytes: Vec<u8> = (0..2100u32).map(|i| (i % 256) as u8).collect();

    let signatures = client.commit_gene(payer, &committee, threat_id, gene_hash, &gene_bytes).unwrap();
    assert!(signatures.len() >= 5, "2100 bytes at 400/chunk must take at least 5 transactions");

    let genome = client.fetch_genome_registry(threat_id).unwrap().unwrap();
    assert_eq!(genome.gene_seq, gene_bytes);
    assert_eq!(genome.gene_hash, gene_hash);
    assert!(!genome.epigenetic_status);
}

#[test]
#[ignore]
fn suppress_gene_requires_poi_and_sets_epigenetic_status() {
    let client = client();
    let payer = &funded(1)[0];
    let committee_keys = poi_committee();
    let committee: Vec<&Keypair> = committee_keys.iter().collect();

    let threat_id = [25u8; 32];
    client.commit_gene(payer, &committee, threat_id, [26u8; 32], &[1, 2, 3]).unwrap();
    assert!(!client.fetch_genome_registry(threat_id).unwrap().unwrap().epigenetic_status);

    client.suppress_gene(payer, &committee, threat_id).unwrap();
    assert!(client.fetch_genome_registry(threat_id).unwrap().unwrap().epigenetic_status);
}
