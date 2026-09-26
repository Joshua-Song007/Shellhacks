//! Soldier daemon entrypoint (FR-R-1, FR-R-7): dormant on the wake socket
//! until Scout delivers a WakeSignal, then runs exactly one
//! search -> compile -> apply cycle against the configured trace file(s)
//! and self-terminates ("apoptosis") when `main` returns -- no loop, no
//! respawn. A supervisor relaunching Soldier for the next threat is out of
//! scope.
//!
//! FR-L-7 (check Epigenetic_Status before running a gene) is not
//! implemented here: it needs ledger-client (Phase 4/5), which does not
//! exist yet. Deferred, no revisit scheduled until ledger-client lands.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;
use soldier::replay_target::ReplayTarget;
use soldier::trigger::Trigger;
use soldier::{allele_search, gene_compile};

const USAGE: &str = "usage: soldier --wake-socket PATH --trace PATH [--benign-trace PATH]";

struct Args {
    wake_socket: PathBuf,
    trace: PathBuf,
    benign_trace: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut wake_socket = None;
    let mut trace = None;
    let mut benign_trace = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--wake-socket" => wake_socket = Some(PathBuf::from(value()?)),
            "--trace" => trace = Some(PathBuf::from(value()?)),
            "--benign-trace" => benign_trace = Some(PathBuf::from(value()?)),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(Args {
        wake_socket: wake_socket.ok_or("--wake-socket is required")?,
        trace: trace.ok_or("--trace is required")?,
        benign_trace,
    })
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
    let trigger = Trigger::bind(&args.wake_socket)?;
    eprintln!("soldier: dormant, waiting on {}", args.wake_socket.display());
    let wake = trigger.wait()?;
    eprintln!("soldier: woke for threat {} (pid {})", wake.threat_id, wake.pid);

    let malicious = BufReader::new(File::open(&args.trace)?);
    let target = match &args.benign_trace {
        Some(p) => ReplayTarget::from_traces(malicious, BufReader::new(File::open(p)?))?,
        None => ReplayTarget::from_malicious_only(malicious)?,
    };

    let result = allele_search::search(&target);
    let wasm = gene_compile::compile(&result.sequence);
    let gene_hash = gene_compile::hash(&wasm);
    let applied = gene_compile::apply(&wasm).is_ok();

    println!(
        "{}",
        json!({
            "type": "cure",
            "threat_id": wake.threat_id,
            "gene_hash": gene_hash,
            "sequence": result.sequence.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>(),
            "fitness": result.evaluation.fitness,
            "containment_value": result.evaluation.containment_value,
            "stability_cost": result.evaluation.stability_cost,
            "applied": applied,
        })
    );

    if !applied {
        return Err(io::Error::other("gene failed sandbox instantiation"));
    }
    Ok(())
}
