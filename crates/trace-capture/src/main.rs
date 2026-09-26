//! FR-R-5, FR-R-8: captures a real ART atomic's behavior into a TES v1
//! trace, running the atomic under `sandbox-exec` isolation while
//! `eslogger` observes it. Not on the demo/evolution-loop path -- this is
//! an offline, one-shot operator tool; the trace it produces gets handed
//! to soldier's `--trace`/`--benign-trace` (Phase 3) separately.
//!
//! Encodes the exact recipe SPIKE-3 (plan.md Phase 0) validated by hand,
//! but deterministically: it waits on the atomic subprocess's real exit
//! rather than SPIKE-3's fixed sleeps, which only existed because that
//! manual recipe had to background `sudo eslogger` around an interactive
//! password prompt -- a constraint that doesn't apply here since this
//! whole process is already root (run as `sudo trace-capture ...`).
//!
//! FR-R-8's "and/or a free-tier Linux VM (other atomics)" path is NOT
//! implemented: no non-macOS telemetry source exists anywhere in this
//! codebase (eslogger is macOS-only). Scoped to macOS/eslogger only.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use scout::source_eslogger;

/// The exact sandbox-exec profile SPIKE-3 validated: allow-by-default,
/// deny writes to the real home/system directories. A stricter
/// deny-by-default profile made `rm` abort (SIGABRT) in SPIKE-3's testing
/// -- not pursued further, this is adequate containment for an atomic
/// whose blast radius is limited to files the operator creates under /tmp.
const DEFAULT_SANDBOX_PROFILE: &str = r#"(version 1)
(allow default)
(deny file-write* (subpath "/Users"))
(deny file-write* (subpath "/Library"))
(deny file-write* (subpath "/System"))
(deny file-write* (subpath "/Applications"))
"#;

/// FR-D-2's fixed event-kind list; same as scout's own eslogger invocation.
const ESLOGGER_KINDS: &[&str] = &["exec", "fork", "exit", "open", "create", "rename", "unlink"];

const USAGE: &str =
    "usage: sudo trace-capture --output PATH [--profile-file PATH] [--warmup-ms N] [--cooldown-ms N] -- <atomic-command...>";

struct Args {
    output: PathBuf,
    profile_file: Option<PathBuf>,
    warmup: Duration,
    cooldown: Duration,
    atomic_command: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut output = None;
    let mut profile_file = None;
    let mut warmup_ms: u64 = 500;
    let mut cooldown_ms: u64 = 1000;
    let mut atomic_command = Vec::new();

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--output" => output = Some(PathBuf::from(value()?)),
            "--profile-file" => profile_file = Some(PathBuf::from(value()?)),
            "--warmup-ms" => warmup_ms = value()?.parse().map_err(|_| "--warmup-ms needs an integer".to_string())?,
            "--cooldown-ms" => cooldown_ms = value()?.parse().map_err(|_| "--cooldown-ms needs an integer".to_string())?,
            "--" => {
                atomic_command = it.collect();
                break;
            }
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    Ok(Args {
        output: output.ok_or("--output is required")?,
        profile_file,
        warmup: Duration::from_millis(warmup_ms),
        cooldown: Duration::from_millis(cooldown_ms),
        atomic_command: {
            if atomic_command.is_empty() {
                return Err("no atomic command given after --".to_string());
            }
            atomic_command
        },
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("trace-capture: {e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("trace-capture: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let profile = match &args.profile_file {
        Some(path) => std::fs::read_to_string(path).map_err(|e| format!("reading profile file: {e}"))?,
        None => DEFAULT_SANDBOX_PROFILE.to_string(),
    };

    let mut eslogger_cmd = Command::new("eslogger");
    eslogger_cmd.args(ESLOGGER_KINDS).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut eslogger = eslogger_cmd
        .spawn()
        .map_err(|e| format!("spawning eslogger: {e} (needs root + Full Disk Access, run as `sudo trace-capture ...`)"))?;
    let stdout = eslogger.stdout.take().expect("eslogger stdout is piped");
    let reader_thread = std::thread::spawn(move || {
        BufReader::new(stdout).lines().collect::<Result<Vec<String>, _>>().unwrap_or_default()
    });

    std::thread::sleep(args.warmup); // SPIKE-1: fresh-binary Gatekeeper/XProtect delay ~180ms

    eprintln!("trace-capture: running atomic: {}", args.atomic_command.join(" "));
    let atomic_status = Command::new("sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .args(&args.atomic_command)
        .status()
        .map_err(|e| format!("spawning sandbox-exec: {e}"))?;
    if !atomic_status.success() {
        eprintln!("trace-capture: atomic command exited with {atomic_status} (capture still written -- a failed run is still signal)");
    }

    std::thread::sleep(args.cooldown); // let trailing events (e.g. exit) flush through eslogger

    // eslogger is a NOTIFY client; it won't be killed by SIGTERM misbehaving,
    // but we still own its lifecycle here since we spawned it.
    let _ = eslogger.kill();
    let _ = eslogger.wait();
    let raw_lines = reader_thread.join().map_err(|_| "eslogger reader thread panicked".to_string())?;

    let recv_ns = now_ns();
    let (trace_lines, reject_stats, validator_stats) = normalize(raw_lines.into_iter(), recv_ns);

    let mut out = std::fs::File::create(&args.output).map_err(|e| format!("creating {}: {e}", args.output.display()))?;
    for line in &trace_lines {
        writeln!(out, "{line}").map_err(|e| format!("writing {}: {e}", args.output.display()))?;
    }

    eprintln!(
        "trace-capture: wrote {} TES lines to {} (adapter_errors={} validation_rejects={} seq_gap_events={})",
        trace_lines.len(),
        args.output.display(),
        reject_stats.adapter_errors,
        validator_stats.rejected(),
        validator_stats.seq_gap_events,
    );
    Ok(())
}

/// FR-D-5/NFR-7: how many raw lines `source_eslogger::map_line` itself
/// rejected as malformed (distinct from `tes::validate::Validator`'s own
/// boundary rejects, tracked separately in its `Stats`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RejectStats {
    pub adapter_errors: u64,
}

/// Pure: maps each raw eslogger line through `map_line`, then through
/// `tes::validate::Validator`, returning the accepted lines as NDJSON
/// strings ready to write out as a trace. `recv_ns` is a single snapshot
/// applied to the whole batch -- this is offline batch normalization, not
/// a live per-event latency measurement (soldier's replay_target.rs only
/// ever reads `ts_ns`, never `recv_ns`, so this has no effect on replay
/// correctness).
pub fn normalize(
    raw_lines: impl Iterator<Item = String>,
    recv_ns: u64,
) -> (Vec<String>, RejectStats, tes::validate::Stats) {
    let mut validator = tes::validate::Validator::new();
    let mut accepted = Vec::new();
    let mut reject_stats = RejectStats::default();

    for raw in raw_lines {
        match source_eslogger::map_line(&raw, recv_ns) {
            Ok(Some(ev)) => {
                if let Ok(valid_ev) = validator.check_event(ev) {
                    accepted.push(valid_ev.to_line());
                }
            }
            Ok(None) => {} // unmodeled kind, not an error (matches scout's own convention)
            Err(_) => reject_stats.adapter_errors += 1,
        }
    }

    (accepted, reject_stats, validator.stats().clone())
}

fn now_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_lines() -> Vec<String> {
        let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/spike3_excerpt.ndjson"))
            .expect("fixture present");
        raw.lines().map(String::from).collect()
    }

    #[test]
    fn the_spike3_excerpt_normalizes_with_zero_rejects() {
        let (trace, reject_stats, validator_stats) = normalize(fixture_lines().into_iter(), 0);
        assert_eq!(reject_stats.adapter_errors, 0);
        assert_eq!(validator_stats.rejected(), 0);
        assert!(!trace.is_empty());
    }

    #[test]
    fn the_spike3_excerpt_yields_the_expected_unlink_count() {
        let (trace, _, _) = normalize(fixture_lines().into_iter(), 0);
        let unlink_count = trace.iter().filter(|l| l.contains(r#""kind":"unlink""#)).count();
        assert_eq!(unlink_count, 36, "fixture was trimmed to exactly 36 unlink events");
    }

    #[test]
    fn a_malformed_line_increments_adapter_errors_without_dropping_silently() {
        let mut lines = fixture_lines();
        lines.push("not valid json".to_string());
        let (_, reject_stats, _) = normalize(lines.into_iter(), 0);
        assert_eq!(reject_stats.adapter_errors, 1);
    }

    #[test]
    fn empty_input_produces_empty_output_and_zero_stats() {
        let (trace, reject_stats, validator_stats) = normalize(std::iter::empty(), 0);
        assert!(trace.is_empty());
        assert_eq!(reject_stats.adapter_errors, 0);
        assert_eq!(validator_stats.accepted, 0);
    }
}
