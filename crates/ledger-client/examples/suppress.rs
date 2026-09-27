//! AC-5 demo helper: flips `epigenetic_status` for one threat so every
//! Soldier refuses its gene (FR-L-7). Run with:
//!   `cargo run -p ledger-client --example suppress -- <threat_id hex> [rpc url]`
//! Payer = ~/.config/solana/id.json; committee = the first 3 PoI keypairs
//! under crates/ledger-program/keys/ (gitignored).

use ledger_client::LedgerClient;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{Keypair, read_keypair_file};

fn main() {
    let mut args = std::env::args().skip(1);
    let hex = args.next().expect("usage: suppress <threat_id hex> [rpc url]");
    let rpc = args.next().unwrap_or_else(|| "https://api.devnet.solana.com".into());
    assert_eq!(hex.len(), 64, "threat_id must be 32 bytes of hex");
    let mut threat_id = [0u8; 32];
    for (i, b) in threat_id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
    }

    let home = std::env::var("HOME").expect("HOME set");
    let payer = read_keypair_file(format!("{home}/.config/solana/id.json")).expect("payer wallet");
    let keys = concat!(env!("CARGO_MANIFEST_DIR"), "/../ledger-program/keys");
    let committee: Vec<Keypair> =
        (1..=3).map(|n| read_keypair_file(format!("{keys}/poi-{n}.json")).expect("poi keypair")).collect();
    let committee: Vec<&Keypair> = committee.iter().collect();

    let client = LedgerClient::new(&rpc, CommitmentConfig::confirmed());
    match client.suppress_gene(&payer, &committee, threat_id) {
        Ok(sig) => println!("{}", serde_json::json!({"type": "suppressed", "threat_id": hex, "signature": sig.to_string()})),
        Err(e) => {
            println!("{}", serde_json::json!({"type": "error", "message": e.to_string()}));
            std::process::exit(1);
        }
    }
}
