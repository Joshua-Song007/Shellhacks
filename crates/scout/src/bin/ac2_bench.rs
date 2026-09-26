//! AC-2: measures catch-rate and detection latency of Scout's event-driven
//! eslogger path against an `lsof`-polling baseline, against the same
//! stream of short-window benign executions. `lsof` lives only in this
//! binary — never on Scout's own detection path (FR-D-1); this is a
//! measurement harness, not a source.
//!
//! Needs root (eslogger requires root + Full Disk Access, SPIKE-1).

use std::collections::HashMap;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::{io, path::Path};

use scout::reader::{self, now_ns};
use scout::scoring::{exec_actions, Action};
use scout::source_eslogger;
use serde_json::json;
use tes::Validator;

#[derive(Debug, Clone, Copy)]
struct Args {
    trials: usize,
    poll_ms: u64,
    lifetime_ms: u64,
    gap_ms: u64,
}

fn parse_args() -> Args {
    let mut a = Args { trials: 50, poll_ms: 1_000, lifetime_ms: 50, gap_ms: 300 };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || -> u64 { it.next().expect("missing value").parse().expect("bad number") };
        match flag.as_str() {
            "--trials" => a.trials = value() as usize,
            "--poll-ms" => a.poll_ms = value(),
            "--lifetime-ms" => a.lifetime_ms = value(),
            "--gap-ms" => a.gap_ms = value(),
            other => panic!("unknown argument {other}"),
        }
    }
    a
}

fn main() -> ExitCode {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("ac2_bench: needs root (eslogger requires root + Full Disk Access)");
        return ExitCode::from(2);
    }
    let args = parse_args();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ac2_bench: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Shared pending-trial map: pid -> spawn time, drained by whichever
/// detector matches the pid first.
type Pending = Arc<Mutex<HashMap<u32, u64>>>;

fn run(args: Args) -> io::Result<()> {
    let Args { trials, poll_ms, lifetime_ms, gap_ms } = args;

    let dir = std::env::temp_dir().join(format!("tcell-ac2-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let probe = dir.join("probe");
    std::fs::copy("/bin/sleep", &probe)?;
    let probe_str = probe.to_str().expect("probe path is valid UTF-8").to_string();

    let mut eslogger = source_eslogger::spawn()?;
    let stdout = eslogger.stdout.take().expect("eslogger stdout is piped");
    let rdr = reader::spawn(stdout, reader::DEFAULT_CAPACITY);

    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let es_hits: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let lsof_hits: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let lsof_run_ms: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));

    let (es_stop_tx, es_stop_rx) = mpsc::channel::<()>();
    let (poll_stop_tx, poll_stop_rx) = mpsc::channel::<()>();

    let es_thread = {
        let pending = Arc::clone(&pending);
        let hits = Arc::clone(&es_hits);
        thread::spawn(move || es_detector_loop(rdr, &pending, &hits, &es_stop_rx))
    };
    let poll_thread = {
        let pending = Arc::clone(&pending);
        let hits = Arc::clone(&lsof_hits);
        let run_ms = Arc::clone(&lsof_run_ms);
        let probe_str = probe_str.clone();
        thread::spawn(move || poll_detector_loop(&probe_str, Duration::from_millis(poll_ms), &pending, &hits, &run_ms, &poll_stop_rx))
    };

    // Warm-up: absorb the ~180ms first-launch Gatekeeper/XProtect scan
    // (SPIKE-1) on this freshly copied binary so it doesn't skew trial 0.
    run_probe(&probe, lifetime_ms)?.wait()?;
    thread::sleep(Duration::from_millis(poll_ms.max(gap_ms) + 200));

    for i in 0..trials {
        let jitter_ms = lcg_jitter(std::process::id().wrapping_add(i as u32), poll_ms);
        let t0 = now_ns();
        let mut child = run_probe(&probe, lifetime_ms)?;
        let pid = child.id();
        pending.lock().expect("pending map poisoned").insert(pid, t0);
        child.wait()?;
        thread::sleep(Duration::from_millis(gap_ms + jitter_ms));
    }

    // Let stragglers land on both detectors before tearing down.
    thread::sleep(Duration::from_millis(poll_ms * 2));
    let _ = es_stop_tx.send(());
    let _ = poll_stop_tx.send(());
    let (es_seq_gaps, reader_stats) = es_thread.join().expect("eslogger detector thread panicked");
    poll_thread.join().expect("poll detector thread panicked");

    let _ = eslogger.kill();
    let _ = eslogger.wait();
    let _ = std::fs::remove_dir_all(&dir);

    let es_lat: Vec<f64> = es_hits.lock().unwrap().iter().map(|&n| n as f64 / 1e6).collect();
    let po_lat: Vec<f64> = lsof_hits.lock().unwrap().iter().map(|&n| n as f64 / 1e6).collect();
    let run_ms: Vec<f64> = lsof_run_ms.lock().unwrap().iter().map(|&n| n as f64).collect();
    let (es_med, es_p95) = median_p95(es_lat.clone());
    let (po_med, po_p95) = median_p95(po_lat.clone());
    let (run_med, _) = median_p95(run_ms);

    let report = json!({
        "trials": trials,
        "poll_ms": poll_ms,
        "lifetime_ms": lifetime_ms,
        "eslogger": {
            "caught": es_lat.len(),
            "catch_rate": es_lat.len() as f64 / trials as f64,
            "median_ms": es_med,
            "p95_ms": es_p95,
        },
        "lsof": {
            "caught": po_lat.len(),
            "catch_rate": po_lat.len() as f64 / trials as f64,
            "median_ms": po_med,
            "p95_ms": po_p95,
            "median_run_ms": run_med,
        },
        "eslogger_seq_gaps": es_seq_gaps,
        "reader_drops": reader_stats.dropped,
    });
    println!("{report}");
    Ok(())
}

fn run_probe(probe: &Path, lifetime_ms: u64) -> io::Result<Child> {
    Command::new(probe)
        .arg(format!("{:.3}", lifetime_ms.max(1) as f64 / 1000.0))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// A tiny LCG seeded from `seed`, used only to avoid phase-locking the trial
/// cadence with the poll interval; not cryptographic.
fn lcg_jitter(seed: u32, bound_ms: u64) -> u64 {
    if bound_ms == 0 {
        return 0;
    }
    let x = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    u64::from(x) % bound_ms
}

fn median_p95(mut xs: Vec<f64>) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = xs.len();
    let median = if n.is_multiple_of(2) { (xs[n / 2 - 1] + xs[n / 2]) / 2.0 } else { xs[n / 2] };
    let p95_idx = (((n - 1) as f64) * 0.95).round() as usize;
    (median, xs[p95_idx])
}

/// Event-driven detector: watches eslogger's stdout for `ExecFromTempOrCache`
/// on a pending pid, exactly the rule Scout itself uses (`scoring::exec_actions`).
fn es_detector_loop(
    rdr: reader::Reader,
    pending: &Pending,
    hits: &Mutex<Vec<u64>>,
    stop_rx: &mpsc::Receiver<()>,
) -> (u64, reader::ReaderStats) {
    let mut validator = Validator::new();
    loop {
        match rdr.lines.recv_timeout(Duration::from_millis(200)) {
            Ok(raw) => {
                if let Ok(Some(ev)) = source_eslogger::map_line(&raw.line, raw.recv_ns)
                    && let Ok(ev) = validator.check_event(ev)
                    && exec_actions(&ev).contains(&Action::ExecFromTempOrCache)
                    && let Some(t0) = pending.lock().expect("pending map poisoned").remove(&ev.proc.pid)
                {
                    hits.lock().expect("hits vec poisoned").push(ev.recv_ns.saturating_sub(t0));
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if stop_rx.try_recv().is_ok() {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    (validator.stats().seq_gap_events, rdr.counters.snapshot())
}

/// Polling baseline (measurement-only, FR-D-1): every `period`,
/// start-to-start, runs `lsof -d txt` and matches its output against the
/// pending trial map by the probe's path.
fn poll_detector_loop(
    probe_path: &str,
    period: Duration,
    pending: &Pending,
    hits: &Mutex<Vec<u64>>,
    run_ms: &Mutex<Vec<u64>>,
    stop_rx: &mpsc::Receiver<()>,
) {
    loop {
        let t0 = Instant::now();
        let now = now_ns();
        if let Ok(out) = Command::new("lsof").args(["-n", "-P", "-w", "-d", "txt", "-Fpn"]).output() {
            let entries = parse_lsof_txt(&String::from_utf8_lossy(&out.stdout));
            let matched: Vec<u32> = entries.iter().filter(|(_, path)| path == probe_path).map(|(pid, _)| *pid).collect();
            let mut p = pending.lock().expect("pending map poisoned");
            for pid in matched {
                if let Some(t0_spawn) = p.remove(&pid) {
                    hits.lock().expect("hits vec poisoned").push(now.saturating_sub(t0_spawn));
                }
            }
        }
        run_ms.lock().expect("run_ms vec poisoned").push(t0.elapsed().as_millis() as u64);
        let sleep_for = period.saturating_sub(t0.elapsed());
        match stop_rx.recv_timeout(sleep_for) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

/// Parses `lsof -d txt -Fpn` output: a `p<pid>` line followed by one or more
/// `n<path>` lines (a process's text segment plus shared libraries on macOS).
fn parse_lsof_txt(out: &str) -> Vec<(u32, String)> {
    let mut result = Vec::new();
    let mut pid: Option<u32> = None;
    for line in out.lines() {
        let mut chars = line.chars();
        let Some(field) = chars.next() else { continue };
        let value = chars.as_str();
        match field {
            'p' => pid = value.parse().ok(),
            'n' => {
                if let Some(p) = pid {
                    result.push((p, value.to_string()));
                }
            }
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsof_txt_fixture() {
        let out = "p111\nn/private/tmp/tcell-ac2-1/probe\np222\nn/usr/lib/dyld\nn/private/tmp/tcell-ac2-1/probe\n";
        let entries = parse_lsof_txt(out);
        assert_eq!(
            entries,
            [
                (111, "/private/tmp/tcell-ac2-1/probe".to_string()),
                (222, "/usr/lib/dyld".to_string()),
                (222, "/private/tmp/tcell-ac2-1/probe".to_string()),
            ]
        );
    }

    #[test]
    fn median_and_p95_of_a_sample() {
        let xs: Vec<f64> = (1..=20).map(f64::from).collect();
        let (median, p95) = median_p95(xs);
        assert_eq!(median, 10.5);
        assert_eq!(p95, 19.0);
        assert_eq!(median_p95(vec![]), (0.0, 0.0));
        assert_eq!(median_p95(vec![5.0]), (5.0, 5.0));
    }

    #[test]
    fn matches_pending_pid_by_probe_path() {
        let entries = [(111, "/other/bin".to_string()), (222, "/probe/path".to_string())];
        let matched: Vec<u32> = entries.iter().filter(|(_, p)| p == "/probe/path").map(|(pid, _)| *pid).collect();
        assert_eq!(matched, [222]);
    }

    #[test]
    fn jitter_stays_within_bound_and_zero_bound_is_zero() {
        assert_eq!(lcg_jitter(1, 0), 0);
        for seed in 0..1000u32 {
            assert!(lcg_jitter(seed, 300) < 300);
        }
    }
}
