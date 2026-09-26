//! FR-D-11, CON-5: optional outbound-beacon lane. A separate periodic
//! `lsof -i` collector, entirely outside TES and the scoring pipeline (see
//! architecture.md): TES v1 models a lossless, nanosecond-precision event
//! stream and this lane is neither — a 5-second poll cannot say when inside
//! that window a connection opened, and a connection that opens and closes
//! between two polls is invisible. Findings are written as their own
//! records for the dashboard and never reach `Pipeline` (no score, no
//! Threat_ID, never SIGSTOP).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::reader::now_ns;
use crate::source_libproc::exe_path;

/// Default interval between `lsof -i` snapshots (`--beacon` with no value).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);
/// Same (pid, remote) must reappear as a new connection instance this many
/// times before it is even considered for the beacon check.
const BEACON_MIN_COUNT: usize = 3;
/// Inter-arrival spread `(max - min) / mean`, as a percentage, at or below
/// which a repeating connection is called regular enough to be a beacon.
const BEACON_SPREAD_PCT: f64 = 20.0;
/// New distinct remotes from one pid in a single snapshot to call it a scan.
const SCAN_MIN_REMOTES: usize = 20;
/// Timestamps kept per (pid, remote); bounds memory, not detection quality
/// (only the last `BEACON_MIN_COUNT` matter for the regularity check).
const HISTORY_CAP: usize = 20;

/// One connection `lsof -i` reported with a remote peer (listening sockets,
/// which have no `->` in `lsof`'s `n` field, are not sightings).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Sighting {
    pid: u32,
    cmd: String,
    proto: String,
    local: String,
    remote: String,
}

/// Parses `lsof -i -n -P -FpcnP` output: repeated `p`/`c` per process, then
/// a `P`/`n` pair per open socket. A socket line with no `->` (listening, or
/// a UDP socket with no peer) is skipped.
fn parse_lsof_i(out: &str) -> Vec<Sighting> {
    let mut sightings = Vec::new();
    let (mut pid, mut cmd, mut proto): (Option<u32>, Option<String>, Option<String>) = (None, None, None);
    for line in out.lines() {
        let mut chars = line.chars();
        let Some(field) = chars.next() else { continue };
        let value = chars.as_str();
        match field {
            'p' => {
                pid = value.parse().ok();
                cmd = None;
            }
            'c' => cmd = Some(value.to_string()),
            'P' => proto = Some(value.to_string()),
            'n' => {
                if let (Some(p), Some(c), Some(pr)) = (pid, &cmd, &proto)
                    && let Some((local, remote)) = value.split_once("->")
                {
                    sightings.push(Sighting {
                        pid: p,
                        cmd: c.clone(),
                        proto: pr.clone(),
                        local: local.to_string(),
                        remote: remote.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    sightings
}

fn run_lsof() -> io::Result<Vec<Sighting>> {
    // `-n`/`-P` skip hostname/service-name lookups (interval collector, not
    // worth the latency); a non-zero exit with no matches is not an error.
    let out = Command::new("lsof").args(["-i", "-n", "-P", "-FpcnP"]).output()?;
    Ok(parse_lsof_i(&String::from_utf8_lossy(&out.stdout)))
}

/// A beacon (T1071) or scan (T1046) finding, written verbatim for the
/// dashboard. Never scored, never fed to `Pipeline`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum Finding {
    Beacon {
        attack_id: &'static str,
        pid: u32,
        exe: String,
        remote: String,
        count: usize,
        interval_ms: u64,
        window_ns: [u64; 2],
    },
    Scan {
        attack_id: &'static str,
        pid: u32,
        exe: String,
        remotes: usize,
        window_ns: [u64; 2],
    },
}

/// Tracks connection history across snapshots to raise beacon/scan findings.
#[derive(Debug, Default)]
struct BeaconState {
    prev: HashSet<Sighting>,
    /// (pid, remote) -> snapshot times a *new* connection instance to that
    /// remote was seen (a new local port each time is expected of a beacon).
    history: HashMap<(u32, String), VecDeque<u64>>,
    flagged: HashSet<(u32, String)>,
    /// The first snapshot has no prior state, so every connection looks
    /// "new"; treating it as a scan/beacon signal would flag whatever was
    /// already open when Scout started, not new behavior.
    bootstrapped: bool,
}

impl BeaconState {
    /// Returns findings raised by this snapshot and how many sightings were
    /// new (for `BeaconStats::new_sightings`).
    fn observe(&mut self, current: Vec<Sighting>, window: [u64; 2]) -> (Vec<Finding>, usize) {
        let current_set: HashSet<Sighting> = current.into_iter().collect();
        let mut findings = Vec::new();
        let new_count;
        if self.bootstrapped {
            let new: Vec<&Sighting> = current_set.difference(&self.prev).collect();
            new_count = new.len();

            let mut by_pid: HashMap<u32, HashSet<&str>> = HashMap::new();
            for s in &new {
                by_pid.entry(s.pid).or_default().insert(s.remote.as_str());
            }
            for (pid, remotes) in &by_pid {
                if remotes.len() >= SCAN_MIN_REMOTES {
                    findings.push(Finding::Scan {
                        attack_id: "T1046",
                        pid: *pid,
                        exe: exe_path(*pid).unwrap_or_default(),
                        remotes: remotes.len(),
                        window_ns: window,
                    });
                }
            }

            for s in &new {
                let key = (s.pid, s.remote.clone());
                let times = self.history.entry(key.clone()).or_default();
                times.push_back(window[1]);
                while times.len() > HISTORY_CAP {
                    times.pop_front();
                }
                if times.len() < BEACON_MIN_COUNT || self.flagged.contains(&key) {
                    continue;
                }
                let intervals: Vec<u64> =
                    times.iter().copied().collect::<Vec<_>>().windows(2).map(|w| w[1] - w[0]).collect();
                let mean = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
                let (min, max) = (*intervals.iter().min().unwrap(), *intervals.iter().max().unwrap());
                let spread_pct = if mean > 0.0 { (max - min) as f64 / mean * 100.0 } else { 0.0 };
                if spread_pct <= BEACON_SPREAD_PCT {
                    self.flagged.insert(key.clone());
                    findings.push(Finding::Beacon {
                        attack_id: "T1071",
                        pid: key.0,
                        exe: exe_path(key.0).unwrap_or_default(),
                        remote: key.1,
                        count: times.len(),
                        interval_ms: (mean / 1e6) as u64,
                        window_ns: window,
                    });
                }
            }
        } else {
            self.bootstrapped = true;
            new_count = current_set.len();
        }
        self.prev = current_set;
        (findings, new_count)
    }
}

/// Degraded-lane counters, surfaced in Scout's stats records under
/// `"beacon"` — separate from `PipelineStats` (NFR-7 covers the scoring
/// path; this lane never reaches it).
#[derive(Debug, Default)]
pub struct BeaconCounters {
    pub snapshots: AtomicU64,
    pub lsof_errors: AtomicU64,
    pub lsof_run_ms_last: AtomicU64,
    pub new_sightings: AtomicU64,
    pub findings: AtomicU64,
}

impl BeaconCounters {
    pub fn snapshot(&self) -> BeaconStats {
        BeaconStats {
            snapshots: self.snapshots.load(Ordering::Relaxed),
            lsof_errors: self.lsof_errors.load(Ordering::Relaxed),
            lsof_run_ms_last: self.lsof_run_ms_last.load(Ordering::Relaxed),
            new_sightings: self.new_sightings.load(Ordering::Relaxed),
            findings: self.findings.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BeaconStats {
    pub snapshots: u64,
    pub lsof_errors: u64,
    pub lsof_run_ms_last: u64,
    pub new_sightings: u64,
    pub findings: u64,
}

/// Runs the collector on its own thread until dropped.
pub struct BeaconCollector {
    pub findings: Receiver<Finding>,
    pub counters: Arc<BeaconCounters>,
    stop: mpsc::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl BeaconCollector {
    /// `interval` paces `lsof -i` snapshots; the first snapshot only
    /// establishes a baseline (see `BeaconState::bootstrapped`).
    pub fn start(interval: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel();
        let counters = Arc::new(BeaconCounters::default());
        let thread_counters = Arc::clone(&counters);
        let handle = thread::Builder::new()
            .name("tcell-beacon".into())
            .spawn(move || run(interval, &stop_rx, &tx, &thread_counters))
            .expect("spawn beacon thread");
        Self { findings: rx, counters, stop: stop_tx, handle: Some(handle) }
    }
}

impl Drop for BeaconCollector {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn run(interval: Duration, stop_rx: &Receiver<()>, tx: &mpsc::Sender<Finding>, counters: &BeaconCounters) {
    let mut state = BeaconState::default();
    let mut window_start = now_ns();
    loop {
        match stop_rx.recv_timeout(interval) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {}
        }
        let t0 = Instant::now();
        let result = run_lsof();
        counters.lsof_run_ms_last.store(t0.elapsed().as_millis() as u64, Ordering::Relaxed);
        counters.snapshots.fetch_add(1, Ordering::Relaxed);
        let window_end = now_ns();
        let sightings = match result {
            Ok(s) => s,
            Err(_) => {
                counters.lsof_errors.fetch_add(1, Ordering::Relaxed);
                window_start = window_end;
                continue;
            }
        };
        let (findings, new_count) = state.observe(sightings, [window_start, window_end]);
        counters.new_sightings.fetch_add(new_count as u64, Ordering::Relaxed);
        for f in findings {
            counters.findings.fetch_add(1, Ordering::Relaxed);
            if tx.send(f).is_err() {
                return;
            }
        }
        window_start = window_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sighting(pid: u32, remote: &str) -> Sighting {
        sighting_from(pid, "10.0.0.1:1", remote)
    }

    /// A beacon reconnects with a new local (ephemeral) port each time, so
    /// each instance is a distinct `Sighting` even though pid/remote match.
    fn sighting_from(pid: u32, local: &str, remote: &str) -> Sighting {
        Sighting { pid, cmd: "x".into(), proto: "TCP".into(), local: local.into(), remote: remote.into() }
    }

    #[test]
    fn parses_lsof_i_fixture_and_skips_listeners() {
        let out = "p1234\ncchrome\nPTCP\nn192.168.1.5:54321->172.217.14.110:443\nPTCP\nn192.168.1.5:54322->172.217.14.110:443\np999\ncsshd\nPTCP\nn*:22\n";
        let s = parse_lsof_i(out);
        assert_eq!(
            s,
            [
                Sighting {
                    pid: 1234,
                    cmd: "chrome".into(),
                    proto: "TCP".into(),
                    local: "192.168.1.5:54321".into(),
                    remote: "172.217.14.110:443".into()
                },
                Sighting {
                    pid: 1234,
                    cmd: "chrome".into(),
                    proto: "TCP".into(),
                    local: "192.168.1.5:54322".into(),
                    remote: "172.217.14.110:443".into()
                },
            ],
            "the sshd listener (no ->) is not a sighting"
        );
    }

    #[test]
    fn bootstrap_snapshot_raises_no_findings() {
        let mut state = BeaconState::default();
        let (findings, new_count) = state.observe(vec![sighting(1, "1.1.1.1:443")], [0, 1]);
        assert!(findings.is_empty());
        assert_eq!(new_count, 1, "still counted as a sighting for stats");
        assert!(state.bootstrapped);
    }

    #[test]
    fn regular_repeated_connections_are_flagged_as_a_beacon() {
        let mut state = BeaconState::default();
        state.observe(vec![], [0, 0]);
        let mut ns = 0u64;
        // BEACON_MIN_COUNT = 3: the first two new instances only build
        // history; the third has enough of a series to judge regularity and
        // is the one that fires (once flagged, a key does not re-fire). A
        // fresh local port each time is what makes it a *new* instance.
        for port in 0..BEACON_MIN_COUNT - 1 {
            ns += 5_000_000_000; // 5s cadence, exactly regular
            let s = sighting_from(1, &format!("10.0.0.1:{port}"), "9.9.9.9:443");
            let (findings, _) = state.observe(vec![s], [ns - 5_000_000_000, ns]);
            assert!(findings.is_empty(), "needs {BEACON_MIN_COUNT} instances first");
        }
        ns += 5_000_000_000;
        let s = sighting_from(1, &format!("10.0.0.1:{BEACON_MIN_COUNT}"), "9.9.9.9:443");
        let (findings, _) = state.observe(vec![s], [ns - 5_000_000_000, ns]);
        assert_eq!(findings.len(), 1);
        assert!(matches!(&findings[0], Finding::Beacon { attack_id, pid: 1, remote, count, .. }
            if *attack_id == "T1071" && remote == "9.9.9.9:443" && *count == BEACON_MIN_COUNT));
    }

    #[test]
    fn irregular_repeated_connections_are_not_a_beacon() {
        let mut state = BeaconState::default();
        state.observe(vec![], [0, 0]);
        let mut ns = 0u64;
        let mut all_findings = Vec::new();
        for (port, gap) in [1_000_000_000, 9_000_000_000, 2_000_000_000].into_iter().enumerate() {
            ns += gap;
            let s = sighting_from(1, &format!("10.0.0.1:{port}"), "9.9.9.9:443");
            let (findings, _) = state.observe(vec![s], [ns - gap, ns]);
            all_findings.extend(findings);
        }
        assert!(all_findings.is_empty(), "spread far exceeds {BEACON_SPREAD_PCT}%");
    }

    #[test]
    fn many_new_remotes_in_one_snapshot_is_a_scan() {
        let mut state = BeaconState::default();
        state.observe(vec![], [0, 0]);
        let few: Vec<Sighting> = (0..19).map(|i| sighting(7, &format!("10.0.0.{i}:80"))).collect();
        let (findings, _) = state.observe(few, [0, 1]);
        assert!(findings.is_empty(), "19 new remotes must not trip the {SCAN_MIN_REMOTES} threshold");

        let many: Vec<Sighting> = (100..120).map(|i| sighting(7, &format!("10.0.0.{i}:80"))).collect();
        let (findings, _) = state.observe(many, [1, 2]);
        assert_eq!(findings.len(), 1);
        assert!(matches!(&findings[0], Finding::Scan { attack_id, pid: 7, remotes: 20, .. } if *attack_id == "T1046"));
    }
}
