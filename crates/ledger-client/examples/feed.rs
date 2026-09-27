//! Long-running ledger activity feed (Phase 9 item 7b) -- unlike
//! devnet_smoke.rs's one-shot verification, this polls forever. It's the
//! process architecture.md already documents backend.cjs (Phase 9 item 9,
//! unbuilt) as eventually spawning and parsing stdout NDJSON from, same
//! stdout-record shape as scout/soldier/meshd's own contracts.
//!
//! Run with: `cargo run -p ledger-client --example feed -- [--rpc URL] [--interval-secs N]`
//!
//! The first poll only baselines (records what already exists without
//! emitting it) -- same "first snapshot never raises findings" convention
//! as crates/scout/src/source_beacon.rs, since a long-lived devnet program
//! can already hold a large backlog of past signatures/genomes that aren't
//! new activity.

use std::collections::HashMap;
use std::time::Duration;

use ledger_client::LedgerClient;
use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
use solana_commitment_config::CommitmentConfig;

struct Args {
    rpc: Option<String>,
    interval_secs: u64,
}

fn parse_args() -> Args {
    let mut rpc = None;
    let mut interval_secs = 5;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rpc" => rpc = Some(args.next().expect("--rpc needs a URL")),
            "--interval-secs" => {
                interval_secs = args.next().expect("--interval-secs needs a number").parse().expect("valid u64");
            }
            other => panic!("unknown arg: {other}"),
        }
    }
    Args { rpc, interval_secs }
}

fn main() {
    let args = parse_args();
    let client = match &args.rpc {
        Some(url) => LedgerClient::new(url, CommitmentConfig::confirmed()),
        None => LedgerClient::devnet(CommitmentConfig::confirmed()),
    };

    let mut last_seen_signature: Option<String> = None;
    let mut seen_genomes: HashMap<[u8; 32], ([u8; 32], bool)> = HashMap::new();
    let mut first_tick = true;

    loop {
        match client.recent_signatures(50) {
            Ok(fresh) => {
                if first_tick {
                    if let Some(newest) = fresh.first() {
                        last_seen_signature = Some(newest.signature.clone());
                    }
                } else {
                    for sig in new_signatures(&fresh, last_seen_signature.as_deref()) {
                        emit(serde_json::json!({
                            "type": "signature",
                            "signature": sig.signature,
                            "slot": sig.slot,
                            "err": sig.err.is_some(),
                            "block_time": sig.block_time,
                        }));
                    }
                    if let Some(newest) = fresh.first() {
                        last_seen_signature = Some(newest.signature.clone());
                    }
                }
            }
            Err(e) => emit(serde_json::json!({"type": "error", "source": "recent_signatures", "message": e.to_string()})),
        }

        match client.all_genomes() {
            Ok(genomes) => {
                let changes = genome_diff(&genomes, &mut seen_genomes);
                // Genomes are emitted on the first tick too: they're the chain's
                // standing immune memory, so the dashboard loads what's already
                // committed (and keeps it across restarts). Signatures still baseline.
                for g in changes {
                    emit(serde_json::json!({
                        "type": "genome",
                        "threat_id": hex_encode(&g.threat_id),
                        "gene_hash": hex_encode(&g.gene_hash),
                        "bytes": g.bytes,
                        "epigenetic_status": g.epigenetic_status,
                    }));
                }
            }
            Err(e) => emit(serde_json::json!({"type": "error", "source": "all_genomes", "message": e.to_string()})),
        }

        first_tick = false;
        std::thread::sleep(Duration::from_secs(args.interval_secs));
    }
}

fn emit(record: serde_json::Value) {
    println!("{record}");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Pure: `fresh` is newest-first (RPC order, as `recent_signatures`
/// returns it). Returns the ones strictly newer than `last_seen`, in
/// oldest-to-newest emission order. `last_seen: None`, or a signature not
/// found in this page (more than `limit` new signatures landed between
/// polls -- a page-boundary gap, accepted, no revisit scheduled), returns
/// everything in `fresh`.
fn new_signatures<'a>(
    fresh: &'a [RpcConfirmedTransactionStatusWithSignature],
    last_seen: Option<&str>,
) -> Vec<&'a RpcConfirmedTransactionStatusWithSignature> {
    let cutoff = last_seen.and_then(|s| fresh.iter().position(|f| f.signature == s));
    let newer = match cutoff {
        Some(i) => &fresh[..i],
        None => fresh,
    };
    newer.iter().rev().collect()
}

struct GenomeChange {
    threat_id: [u8; 32],
    gene_hash: [u8; 32],
    bytes: usize,
    epigenetic_status: bool,
}

/// Pure: returns genomes whose `(gene_hash, epigenetic_status)` differs
/// from what `seen` last recorded (including first sight), updating `seen`
/// in place as it goes.
fn genome_diff(current: &[t_cell::GenomeRegistry], seen: &mut HashMap<[u8; 32], ([u8; 32], bool)>) -> Vec<GenomeChange> {
    let mut changes = Vec::new();
    for g in current {
        let key = (g.gene_hash, g.epigenetic_status);
        if seen.get(&g.threat_id) != Some(&key) {
            changes.push(GenomeChange {
                threat_id: g.threat_id,
                gene_hash: g.gene_hash,
                bytes: g.gene_seq.len(),
                epigenetic_status: g.epigenetic_status,
            });
            seen.insert(g.threat_id, key);
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(s: &str, slot: u64) -> RpcConfirmedTransactionStatusWithSignature {
        RpcConfirmedTransactionStatusWithSignature {
            signature: s.to_string(),
            slot,
            err: None,
            memo: None,
            block_time: None,
            confirmation_status: None,
        }
    }

    #[test]
    fn new_signatures_with_no_last_seen_returns_everything_oldest_first() {
        let fresh = vec![sig("c", 3), sig("b", 2), sig("a", 1)];
        let out = new_signatures(&fresh, None);
        assert_eq!(out.iter().map(|s| s.signature.as_str()).collect::<Vec<_>>(), vec!["a", "b", "c"]);
    }

    #[test]
    fn new_signatures_returns_only_what_is_newer_than_last_seen() {
        let fresh = vec![sig("d", 4), sig("c", 3), sig("b", 2), sig("a", 1)];
        let out = new_signatures(&fresh, Some("b"));
        assert_eq!(out.iter().map(|s| s.signature.as_str()).collect::<Vec<_>>(), vec!["c", "d"]);
    }

    #[test]
    fn new_signatures_with_nothing_newer_is_empty() {
        let fresh = vec![sig("a", 1)];
        let out = new_signatures(&fresh, Some("a"));
        assert!(out.is_empty());
    }

    #[test]
    fn new_signatures_with_last_seen_off_the_page_returns_everything() {
        let fresh = vec![sig("c", 3), sig("b", 2)];
        let out = new_signatures(&fresh, Some("long-since-scrolled-off"));
        assert_eq!(out.len(), 2);
    }

    fn genome(threat_id: u8, gene_hash: u8, bytes: usize, suppressed: bool) -> t_cell::GenomeRegistry {
        t_cell::GenomeRegistry {
            threat_id: [threat_id; 32],
            gene_hash: [gene_hash; 32],
            gene_seq: vec![0u8; bytes],
            epigenetic_status: suppressed,
        }
    }

    #[test]
    fn genome_diff_reports_every_genome_on_first_sight() {
        let mut seen = HashMap::new();
        let current = vec![genome(1, 10, 5, false), genome(2, 20, 7, false)];
        let changes = genome_diff(&current, &mut seen);
        assert_eq!(changes.len(), 2);
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn genome_diff_is_silent_when_nothing_changed() {
        let mut seen = HashMap::new();
        let current = vec![genome(1, 10, 5, false)];
        genome_diff(&current, &mut seen);
        let changes = genome_diff(&current, &mut seen);
        assert!(changes.is_empty());
    }

    #[test]
    fn genome_diff_reports_a_suppression_flip() {
        let mut seen = HashMap::new();
        genome_diff(&[genome(1, 10, 5, false)], &mut seen);
        let changes = genome_diff(&[genome(1, 10, 5, true)], &mut seen);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].epigenetic_status);
    }

    #[test]
    fn genome_diff_reports_a_gene_hash_change() {
        let mut seen = HashMap::new();
        genome_diff(&[genome(1, 10, 5, false)], &mut seen);
        let changes = genome_diff(&[genome(1, 99, 5, false)], &mut seen);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].gene_hash, [99; 32]);
    }
}
