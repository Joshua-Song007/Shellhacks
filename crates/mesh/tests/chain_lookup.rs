//! Integration test for verify::confirm_via_chain against a real
//! `RpcClient`, through a local `solana-test-validator` -- same
//! dev-time-infra precedent as ledger-client's own local-validator tests
//! (Phase 5). `#[ignore]` by default; run with `cargo test -p mesh --test
//! chain_lookup -- --ignored` after:
//!   1. `solana-test-validator --reset --quiet &`
//!   2. `solana program deploy ../ledger-program/target/deploy/t_cell.so
//!      --program-id ../ledger-program/target/deploy/t_cell-keypair.json
//!      --url localhost`

use std::sync::Arc;

use ledger_client::LedgerClient;
use mesh::verify::confirm_via_chain;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_signer::Signer;

const LOCALNET: &str = "http://127.0.0.1:8899";

fn poi_keypair(n: u8) -> Keypair {
    let path = match n {
        1 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-1.json"),
        2 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-2.json"),
        3 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-3.json"),
        _ => unreachable!(),
    };
    read_keypair_file(path).expect("poi keypair file present (crates/ledger-program/keys/, gitignored)")
}

fn fund(rpc: &solana_client::rpc_client::RpcClient, pubkey: &solana_pubkey::Pubkey) {
    let sig = rpc.request_airdrop(pubkey, 1_000_000_000).expect("airdrop (is solana-test-validator running?)");
    for _ in 0..50 {
        if rpc.confirm_transaction(&sig).unwrap_or(false) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    panic!("airdrop never confirmed");
}

// solana-rpc-client uses `tokio::task::block_in_place` internally, which
// panics ("can call blocking only when running on the multi-threaded
// runtime") on the default single-threaded #[tokio::test] runtime --
// confirmed by a real failure here before this flavor was set.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn confirm_via_chain_matches_the_committed_gene_hash() {
    let client = Arc::new(LedgerClient::new(LOCALNET, CommitmentConfig::confirmed()));
    let raw_rpc = solana_client::rpc_client::RpcClient::new_with_commitment(LOCALNET.to_string(), CommitmentConfig::confirmed());

    let payer = Keypair::new();
    fund(&raw_rpc, &payer.pubkey());
    let committee = [poi_keypair(1), poi_keypair(2), poi_keypair(3)];
    let committee_refs: Vec<&Keypair> = committee.iter().collect();

    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let mut threat_id = [0u8; 32];
    threat_id[..16].copy_from_slice(&nanos.to_le_bytes());
    let gene_hash = [7u8; 32];

    client.commit_gene(&payer, &committee_refs, threat_id, gene_hash, b"chain-lookup-test").expect("commit_gene");

    assert!(confirm_via_chain(client.clone(), threat_id, gene_hash).await.unwrap(), "must confirm the hash that was actually committed");
    assert!(
        !confirm_via_chain(client.clone(), threat_id, [8u8; 32]).await.unwrap(),
        "must not confirm a hash that was never committed"
    );

    let unreported_threat_id = {
        let mut id = threat_id;
        id[31] ^= 0xFF;
        id
    };
    assert!(
        !confirm_via_chain(client, unreported_threat_id, gene_hash).await.unwrap(),
        "must not confirm a threat_id with no genome registry at all"
    );
}
