//! Soldier daemon entrypoint (FR-R-1, FR-R-7): dormant on the wake socket
//! until Scout delivers a WakeSignal, then runs exactly one
//! search -> compile -> apply cycle against the configured trace file(s)
//! and self-terminates ("apoptosis") when `main` returns -- no loop, no
//! respawn. Relaunch is handled by an external supervisor
//! (frontend/electron/backend.cjs), which respawns a fresh Soldier after
//! each exit. Wake signals are buffered by the supervisor, so a wake
//! arriving during the respawn gap is delivered to the next Soldier, not
//! lost.
//!
//! FR-L-7 / AC-5 stage 4: on wake, the threat is reported (`submit_threat`,
//! corroboration) and the Genome Registry is read before any gene runs. A
//! suppressed gene (`epigenetic_status`) is refused; a finalized gene
//! already on chain is inherited (hash-checked) instead of evolved; a
//! freshly evolved gene is committed under the 3-of-5 PoI committee keys
//! this process holds (single-process multisig -- FR-M-10 unimplemented).
//! Ledger failures never block local containment: a failed read falls back
//! to evolving locally without committing.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ledger_client::LedgerClient;
use scout::scoring::Action;
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{Keypair, read_keypair_file};
use soldier::replay_target::ReplayTarget;
use soldier::trigger::Trigger;
use soldier::{allele_search, gene_compile};

const USAGE: &str = "usage: soldier --wake-socket PATH --trace PATH [--benign-trace PATH] \
                     --poi-key PATH [--poi-key PATH ...] [--payer PATH] [--rpc URL]";

struct Args {
    wake_socket: PathBuf,
    trace: PathBuf,
    benign_trace: Option<PathBuf>,
    poi_keys: Vec<PathBuf>,
    payer: Option<PathBuf>,
    rpc: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut wake_socket = None;
    let mut trace = None;
    let mut benign_trace = None;
    let mut poi_keys = Vec::new();
    let mut payer = None;
    let mut rpc = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--wake-socket" => wake_socket = Some(PathBuf::from(value()?)),
            "--trace" => trace = Some(PathBuf::from(value()?)),
            "--benign-trace" => benign_trace = Some(PathBuf::from(value()?)),
            "--poi-key" => poi_keys.push(PathBuf::from(value()?)),
            "--payer" => payer = Some(PathBuf::from(value()?)),
            "--rpc" => rpc = Some(value()?),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if poi_keys.is_empty() {
        return Err("at least one --poi-key is required".into());
    }
    Ok(Args {
        wake_socket: wake_socket.ok_or("--wake-socket is required")?,
        trace: trace.ok_or("--trace is required")?,
        benign_trace,
        poi_keys,
        payer,
        rpc,
    })
}

fn load_keypair(path: &Path) -> io::Result<Keypair> {
    read_keypair_file(path).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))
}

/// Wake signals and gene_compile carry hex; ledger-client takes raw bytes.
fn unhex(s: &str) -> io::Result<[u8; 32]> {
    let bad = || io::Error::other(format!("not a 32-byte hex digest: {s:?}"));
    if s.len() != 64 || !s.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// `behavioral_schema_hash` (DATA-2): sha256 of the ordered action names,
/// comma-joined. Not specified by overview.md; it only has to be
/// byte-identical across nodes or submit_threat fails with SchemaMismatch.
fn schema_hash(schema: &[Action]) -> [u8; 32] {
    let names: Vec<String> = schema.iter().map(|a| format!("{a:?}")).collect();
    Sha256::digest(names.join(",").as_bytes()).into()
}

#[derive(Debug, PartialEq)]
enum Decision {
    /// FR-L-7: gene flagged network-wide; run nothing.
    Suppressed,
    /// A finalized, hash-verified gene is already on chain.
    Inherit(Vec<u8>),
    /// Evolve locally. `commit` is false when the chain already holds an
    /// unfinalized/unverifiable upload for this threat (appending would
    /// corrupt it) or the chain couldn't be read.
    Evolve { commit: bool },
}

/// Pure: `genome` is the Genome Registry's (epigenetic_status, gene_hash,
/// gene_seq), or None if nobody has committed for this threat yet.
fn decide(genome: Option<(bool, [u8; 32], &[u8])>) -> Decision {
    match genome {
        None => Decision::Evolve { commit: true },
        Some((true, _, _)) => Decision::Suppressed,
        Some((false, hash, _)) if hash == [0u8; 32] => Decision::Evolve { commit: false },
        Some((false, hash, seq)) if Sha256::digest(seq)[..] == hash => Decision::Inherit(seq.to_vec()),
        Some(_) => Decision::Evolve { commit: false },
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("soldier: {e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("soldier: {e}");
            ExitCode::FAILURE
        }
    }
}

/// FR-R-1: blocks on `Trigger::wait` until Scout wakes this Soldier, then
/// runs one cure cycle. Returning from here (and so from `main`) is the
/// self-terminate step -- there is no loop.
fn run(args: &Args) -> io::Result<()> {
    // trigger.rs: `bind` fails on a stale socket from a prior run; this is
    // the caller-side cleanup that recovery requires.
    let _ = std::fs::remove_file(&args.wake_socket);
    // Keys load before going dormant so a bad path fails now, not mid-cure.
    let payer_path = match &args.payer {
        Some(p) => p.clone(),
        None => PathBuf::from(std::env::var("HOME").map_err(io::Error::other)?).join(".config/solana/id.json"),
    };
    let payer = load_keypair(&payer_path)?;
    let committee = args.poi_keys.iter().map(|p| load_keypair(p)).collect::<io::Result<Vec<_>>>()?;
    let committee: Vec<&Keypair> = committee.iter().collect();
    let ledger = match &args.rpc {
        Some(url) => LedgerClient::new(url, CommitmentConfig::confirmed()),
        None => LedgerClient::devnet(CommitmentConfig::confirmed()),
    };

    let trigger = Trigger::bind(&args.wake_socket)?;
    eprintln!("soldier: dormant, waiting on {}", args.wake_socket.display());
    let wake = trigger.wait()?;
    eprintln!("soldier: woke for threat {} (pid {})", wake.threat_id, wake.pid);
    let threat_id = unhex(&wake.threat_id)?;

    let mut ledger_errors: Vec<String> = Vec::new();
    let submit_sig = match ledger.submit_threat(&payer, threat_id, schema_hash(&wake.schema)) {
        Ok(sig) => Some(sig.to_string()),
        Err(e) => {
            ledger_errors.push(format!("submit_threat: {e}"));
            None
        }
    };
    let decision = match ledger.fetch_genome_registry(threat_id) {
        Ok(g) => decide(g.as_ref().map(|g| (g.epigenetic_status, g.gene_hash, g.gene_seq.as_slice()))),
        Err(e) => {
            // fail-open: local containment never waits on the ledger
            ledger_errors.push(format!("fetch_genome_registry: {e}"));
            Decision::Evolve { commit: false }
        }
    };

    let mut cure = json!({ "type": "cure", "threat_id": wake.threat_id });
    cure["schema"] = json!(wake.schema.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>());
    let mut commit_sigs: Vec<String> = Vec::new();
    let suppressed = decision == Decision::Suppressed;
    let applied = match decision {
        Decision::Suppressed => {
            eprintln!("soldier: gene for {} is suppressed (Epigenetic_Status), refusing", wake.threat_id);
            cure["source"] = json!("suppressed");
            false
        }
        Decision::Inherit(wasm) => {
            cure["source"] = json!("inherited");
            cure["gene_hash"] = json!(gene_compile::hash(&wasm));
            gene_compile::apply(&wasm).is_ok()
        }
        Decision::Evolve { commit } => {
            let malicious = BufReader::new(File::open(&args.trace)?);
            let target = match &args.benign_trace {
                Some(p) => ReplayTarget::from_traces(malicious, BufReader::new(File::open(p)?))?,
                None => ReplayTarget::from_malicious_only(malicious)?,
            };

            let result = allele_search::search(&target);
            let wasm = gene_compile::compile(&result.sequence);
            let gene_hash = gene_compile::hash(&wasm);
            let applied = gene_compile::apply(&wasm).is_ok();

            if applied && commit {
                match ledger.commit_gene(&payer, &committee, threat_id, unhex(&gene_hash)?, &wasm) {
                    Ok(sigs) => commit_sigs = sigs.iter().map(ToString::to_string).collect(),
                    Err(e) => ledger_errors.push(format!("commit_gene: {e}")),
                }
            }
            cure["source"] = json!("evolved");
            cure["gene_hash"] = json!(gene_hash);
            cure["sequence"] = json!(result.sequence.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>());
            cure["fitness"] = json!(result.evaluation.fitness);
            cure["containment_value"] = json!(result.evaluation.containment_value);
            cure["stability_cost"] = json!(result.evaluation.stability_cost);
            applied
        }
    };
    cure["applied"] = json!(applied);
    cure["ledger"] = json!({ "submit_sig": submit_sig, "commit_sigs": commit_sigs, "errors": ledger_errors });
    println!("{cure}");

    if !applied && !suppressed {
        return Err(io::Error::other("gene failed sandbox instantiation"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_on_chain_evolves_and_commits() {
        assert_eq!(decide(None), Decision::Evolve { commit: true });
    }

    #[test]
    fn suppressed_wins_over_a_valid_gene() {
        let gene = gene_compile::compile(&[]);
        let hash: [u8; 32] = Sha256::digest(&gene).into();
        assert_eq!(decide(Some((true, hash, &gene))), Decision::Suppressed);
    }

    #[test]
    fn a_finalized_matching_gene_is_inherited() {
        let gene = gene_compile::compile(&[]);
        let hash: [u8; 32] = Sha256::digest(&gene).into();
        assert_eq!(decide(Some((false, hash, &gene))), Decision::Inherit(gene.clone()));
    }

    #[test]
    fn an_unfinalized_upload_evolves_without_committing() {
        assert_eq!(decide(Some((false, [0u8; 32], &[1, 2, 3]))), Decision::Evolve { commit: false });
    }

    #[test]
    fn a_hash_mismatch_is_not_inherited() {
        assert_eq!(decide(Some((false, [7u8; 32], &[1, 2, 3]))), Decision::Evolve { commit: false });
    }

    #[test]
    fn unhex_round_trips_gene_compile_hash() {
        let wasm = gene_compile::compile(&[]);
        let bytes = unhex(&gene_compile::hash(&wasm)).unwrap();
        assert_eq!(bytes, <[u8; 32]>::from(Sha256::digest(&wasm)));
        assert!(unhex("abc").is_err());
        assert!(unhex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn schema_hash_is_order_sensitive() {
        use Action::*;
        assert_ne!(
            schema_hash(&[ExecFromTempOrCache, RapidFileModBurst]),
            schema_hash(&[RapidFileModBurst, ExecFromTempOrCache])
        );
    }

    #[test]
    fn cure_schema_stringifies_each_action_in_order() {
        use Action::*;
        let wake_schema = vec![ExecFromTempOrCache, RapidFileModBurst, RecoverySnapshotTamper];
        let mut cure = json!({ "type": "cure", "threat_id": "deadbeef" });
        cure["schema"] = json!(wake_schema.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>());
        assert_eq!(cure["schema"], json!(["ExecFromTempOrCache", "RapidFileModBurst", "RecoverySnapshotTamper"]));
    }
}
