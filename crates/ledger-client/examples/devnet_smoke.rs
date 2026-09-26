//! Manual end-to-end verification against the real devnet deployment
//! (FR-L-1, AC-5). Not run in CI or by `cargo test` -- it costs real
//! (free, devnet) SOL and hits the public network. Run with:
//!   `cargo run -p ledger-client --example devnet_smoke`
//!
//! Uses the local `solana` CLI's configured wallet (~/.config/solana/id.json)
//! as payer, since devnet airdrops are rate-limited and this wallet is
//! already funded; and 3 of the 5 real PoI committee keypairs generated
//! during Phase 4 (crates/ledger-program/keys/, gitignored).

use ledger_client::LedgerClient;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_signer::Signer;

fn poi_keypair(n: u8) -> Keypair {
    let path = match n {
        1 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-1.json"),
        2 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-2.json"),
        3 => concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys/poi-3.json"),
        _ => unreachable!(),
    };
    read_keypair_file(path).expect("poi keypair file present (crates/ledger-program/keys/, gitignored)")
}

fn main() {
    let payer = read_keypair_file(shellexpand_home("~/.config/solana/id.json"))
        .expect("local solana CLI wallet at ~/.config/solana/id.json");
    println!("payer: {}", payer.pubkey());

    let client = LedgerClient::devnet(CommitmentConfig::confirmed());

    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let mut threat_id = [0u8; 32];
    threat_id[..16].copy_from_slice(&nanos.to_le_bytes());
    let schema_hash = [7u8; 32];
    let gene_hash = [9u8; 32];
    let gene_bytes = b"tcell-devnet-smoke-test".to_vec();

    println!("threat_id: {}", bs58_like(&threat_id));

    let sig = client.submit_threat(&payer, threat_id, schema_hash).expect("submit_threat");
    println!("submit_threat: https://explorer.solana.com/tx/{sig}?cluster=devnet");

    let registry = client.fetch_threat_registry(threat_id).unwrap().expect("just submitted");
    println!("confidence_score = {}", registry.confidence_score);
    assert_eq!(registry.confidence_score, 1);

    let committee = [poi_keypair(1), poi_keypair(2), poi_keypair(3)];
    let committee_refs: Vec<&Keypair> = committee.iter().collect();

    let signatures =
        client.commit_gene(&payer, &committee_refs, threat_id, gene_hash, &gene_bytes).expect("commit_gene");
    for sig in &signatures {
        println!("commit_gene: https://explorer.solana.com/tx/{sig}?cluster=devnet");
    }

    let genome = client.fetch_genome_registry(threat_id).unwrap().expect("just committed");
    assert_eq!(genome.gene_seq, gene_bytes);
    assert_eq!(genome.gene_hash, gene_hash);
    assert!(!genome.epigenetic_status);
    println!("gene committed, {} bytes, epigenetic_status=false", genome.gene_seq.len());

    let sig = client.suppress_gene(&payer, &committee_refs, threat_id).expect("suppress_gene");
    println!("suppress_gene: https://explorer.solana.com/tx/{sig}?cluster=devnet");

    let genome = client.fetch_genome_registry(threat_id).unwrap().expect("still exists");
    assert!(genome.epigenetic_status);
    println!("AC-5 confirmed live on devnet: cure committed, suppress_gene halted it.");
}

fn shellexpand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{rest}", std::env::var("HOME").expect("HOME set"))
    } else {
        path.to_string()
    }
}

fn bs58_like(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
