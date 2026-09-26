//! FR-D-8/9/10: Stage-1 detectors, per-lineage trajectory scoring, and
//! lineage suspension.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tes::schema::{Event, TesEvent};

use crate::lineage::LineageId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    ExecFromTempOrCache,
    RecoverySnapshotTamper,
    RapidFileModBurst,
}

impl Action {
    pub const fn weight(self) -> u32 {
        match self {
            Action::ExecFromTempOrCache => 20,
            Action::RecoverySnapshotTamper => 50,
            Action::RapidFileModBurst => 40,
        }
    }

    /// Byte hashed into `Threat_ID`. Part of the cross-node contract
    /// (NFR-6): never renumber.
    pub const fn code(self) -> u8 {
        match self {
            Action::ExecFromTempOrCache => 1,
            Action::RecoverySnapshotTamper => 2,
            Action::RapidFileModBurst => 3,
        }
    }

    pub const fn attack_id(self) -> &'static str {
        match self {
            Action::ExecFromTempOrCache => "T1204",
            Action::RecoverySnapshotTamper => "T1490",
            Action::RapidFileModBurst => "T1486",
        }
    }
}

/// How an event reached the scorer. `Inferred` events come from the
/// degraded path, where FSEvents reports a change without its process and
/// Scout credits it to the process that did most of the writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "evidence", rename_all = "snake_case")]
pub enum Evidence {
    Observed,
    /// `candidates` = processes that wrote during the batch.
    Inferred { candidates: usize },
}

/// An action whose evidence was inferred rather than observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct InferredAction {
    pub action: Action,
    pub candidates: usize,
}

pub const THRESHOLD: u32 = 100;
pub const BURST_WINDOW_NS: u64 = 1_000_000_000;
pub const BURST_OPS: usize = 64;

const TEMP_PREFIXES: &[&str] = &[
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/var/folders/",
    "/private/var/folders/",
];

/// Stage-1 actions implied by a single exec event.
pub fn exec_actions(ev: &TesEvent) -> Vec<Action> {
    let Event::Exec(d) = &ev.event else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if TEMP_PREFIXES.iter().any(|p| d.target.starts_with(p)) || d.target.contains("/Caches/") {
        found.push(Action::ExecFromTempOrCache);
    }
    if is_snapshot_tamper(&d.target, &d.args) {
        found.push(Action::RecoverySnapshotTamper);
    }
    found
}

fn is_snapshot_tamper(target: &str, args: &[String]) -> bool {
    let name = target.rsplit('/').next().unwrap_or(target);
    let has = |verbs: &[&str]| args.iter().skip(1).any(|a| verbs.iter().any(|v| a.eq_ignore_ascii_case(v)));
    match name {
        "tmutil" => has(&["deletelocalsnapshots", "delete", "thinlocalsnapshots", "deleteinprogress"]),
        "diskutil" => has(&["apfs"]) && has(&["deleteSnapshot"]),
        _ => false,
    }
}

fn is_mutation(ev: &TesEvent) -> bool {
    match &ev.event {
        Event::Open(o) => o.write,
        Event::Create(_) | Event::Rename(_) | Event::Unlink(_) => true,
        Event::Exec(_) | Event::Fork(_) | Event::Exit(_) => false,
    }
}

pub fn threat_id(actions: &[Action]) -> [u8; 32] {
    let codes: Vec<u8> = actions.iter().map(|a| a.code()).collect();
    Sha256::digest(&codes).into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Default)]
struct Trajectory {
    /// Distinct actions in first-occurrence order; each counts once.
    actions: Vec<Action>,
    inferred: Vec<InferredAction>,
    burst: VecDeque<(u64, Evidence)>,
    convicted: bool,
}

impl Trajectory {
    fn score(&self) -> u32 {
        self.actions.iter().map(|a| a.weight()).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub lineage: LineageId,
    pub threat_id: [u8; 32],
    pub actions: Vec<Action>,
    pub score: u32,
    pub trigger_pid: u32,
    pub trigger_ts_ns: u64,
    pub inferred: Vec<InferredAction>,
}

#[derive(Debug, Default)]
pub struct Scorer {
    trajectories: HashMap<LineageId, Trajectory>,
}

impl Scorer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a verdict the first time a lineage's score reaches `THRESHOLD`.
    pub fn observe(&mut self, lineage: LineageId, ev: &TesEvent) -> Option<Verdict> {
        self.observe_with(lineage, ev, Evidence::Observed)
    }

    /// As `observe`; a burst is inferred if any op inside its window was.
    pub fn observe_with(&mut self, lineage: LineageId, ev: &TesEvent, evidence: Evidence) -> Option<Verdict> {
        let mut found: Vec<(Action, Evidence)> = exec_actions(ev).into_iter().map(|a| (a, evidence)).collect();
        if is_mutation(ev) {
            let t = self.trajectories.entry(lineage).or_default();
            if !t.actions.contains(&Action::RapidFileModBurst) {
                t.burst.push_back((ev.ts_ns, evidence));
                while t.burst.front().is_some_and(|&(first, _)| ev.ts_ns.saturating_sub(first) > BURST_WINDOW_NS) {
                    t.burst.pop_front();
                }
                if t.burst.len() >= BURST_OPS {
                    let burst_evidence = t
                        .burst
                        .iter()
                        .filter_map(|&(_, e)| match e {
                            Evidence::Inferred { candidates } => Some(candidates),
                            Evidence::Observed => None,
                        })
                        .max()
                        .map_or(Evidence::Observed, |candidates| Evidence::Inferred { candidates });
                    t.burst = VecDeque::new();
                    found.push((Action::RapidFileModBurst, burst_evidence));
                }
            }
        }
        if found.is_empty() {
            return None;
        }
        let t = self.trajectories.entry(lineage).or_default();
        for (a, e) in found {
            if !t.actions.contains(&a) {
                t.actions.push(a);
                if let Evidence::Inferred { candidates } = e {
                    t.inferred.push(InferredAction { action: a, candidates });
                }
            }
        }
        let score = t.score();
        if t.convicted || score < THRESHOLD {
            return None;
        }
        t.convicted = true;
        Some(Verdict {
            lineage,
            threat_id: threat_id(&t.actions),
            actions: t.actions.clone(),
            score,
            trigger_pid: ev.proc.pid,
            trigger_ts_ns: ev.ts_ns,
            inferred: t.inferred.clone(),
        })
    }

    pub fn score(&self, lineage: LineageId) -> u32 {
        self.trajectories.get(&lineage).map_or(0, Trajectory::score)
    }

    pub fn forget(&mut self, lineage: LineageId) {
        self.trajectories.remove(&lineage);
    }

    pub fn len(&self) -> usize {
        self.trajectories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.trajectories.is_empty()
    }
}

/// FR-D-9 wake signal handed to the Soldier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeSignal {
    pub threat_id: String,
    pub pid: u32,
    pub schema: Vec<Action>,
}

pub trait Suspender {
    fn suspend(&mut self, pid: u32) -> io::Result<()>;
}

pub struct SigStop;

impl Suspender for SigStop {
    fn suspend(&mut self, pid: u32) -> io::Result<()> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: kill(2) has no memory-safety preconditions.
        if unsafe { libc::kill(pid, libc::SIGSTOP) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Records instead of signalling; for `--dry-run` and tests.
#[derive(Debug, Default)]
pub struct DryRun {
    pub suspended: Vec<u32>,
}

impl Suspender for DryRun {
    fn suspend(&mut self, pid: u32) -> io::Result<()> {
        self.suspended.push(pid);
        Ok(())
    }
}

/// launchd and early-boot daemons live below this PID on macOS.
pub const SYSTEM_PID_FLOOR: u32 = 100;

#[derive(Debug, Clone)]
pub struct SuspendPolicy {
    pub own_pid: u32,
    pub protected: HashSet<u32>,
    pub floor: u32,
}

impl SuspendPolicy {
    pub fn new(own_pid: u32) -> Self {
        Self { own_pid, protected: HashSet::new(), floor: SYSTEM_PID_FLOOR }
    }

    pub fn protect(&mut self, pid: u32) {
        self.protected.insert(pid);
    }

    pub fn allows(&self, pid: u32) -> bool {
        pid >= self.floor && pid != self.own_pid && !self.protected.contains(&pid)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct SuspendReport {
    pub suspended: Vec<u32>,
    pub skipped: Vec<u32>,
    pub failed: Vec<(u32, String)>,
}

pub fn suspend_all(pids: &[u32], policy: &SuspendPolicy, suspender: &mut impl Suspender) -> SuspendReport {
    let mut report = SuspendReport::default();
    for &pid in pids {
        if !policy.allows(pid) {
            report.skipped.push(pid);
            continue;
        }
        match suspender.suspend(pid) {
            Ok(()) => report.suspended.push(pid),
            Err(e) => report.failed.push((pid, e.to_string())),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use tes::schema::{ExecData, OpenData, PathData, Proc};

    fn ev(ts_ns: u64, event: Event) -> TesEvent {
        TesEvent {
            v: 1,
            seq: 0,
            ts_ns,
            recv_ns: ts_ns,
            proc: Proc { pid: 500, pidver: 1, ppid: 1, exe: "/tmp/p".into(), signing_id: None, team_id: None, platform: false },
            event,
        }
    }
    fn exec(target: &str, args: &[&str]) -> TesEvent {
        let args = args.iter().map(|s| s.to_string()).collect();
        ev(0, Event::Exec(ExecData { target: target.into(), args, new_pidver: 2 }))
    }
    fn create(ts_ns: u64) -> TesEvent {
        ev(ts_ns, Event::Create(PathData { path: "/Users/u/doc".into() }))
    }

    #[test]
    fn exec_from_temp_and_caches() {
        for t in [
            "/tmp/x",
            "/private/tmp/x",
            "/var/tmp/x",
            "/private/var/folders/ab/T/x",
            "/Users/u/Library/Caches/com.x/y",
        ] {
            assert_eq!(exec_actions(&exec(t, &[t])), [Action::ExecFromTempOrCache], "{t}");
        }
        assert!(exec_actions(&exec("/usr/bin/ls", &["ls"])).is_empty());
        assert!(exec_actions(&exec("/tmpfoo/x", &["x"])).is_empty());
    }

    #[test]
    fn snapshot_tamper() {
        let tmutil = "/usr/bin/tmutil";
        assert_eq!(exec_actions(&exec(tmutil, &["tmutil", "deletelocalsnapshots", "/"])), [Action::RecoverySnapshotTamper]);
        assert!(exec_actions(&exec(tmutil, &["tmutil", "listlocalsnapshots", "/"])).is_empty());
        let diskutil = "/usr/sbin/diskutil";
        assert_eq!(
            exec_actions(&exec(diskutil, &["diskutil", "apfs", "deletesnapshot", "disk3s1", "-name", "x"])),
            [Action::RecoverySnapshotTamper]
        );
        assert!(exec_actions(&exec(diskutil, &["diskutil", "list"])).is_empty());
        assert_eq!(
            exec_actions(&exec("/tmp/tmutil", &["tmutil", "delete", "/b"])),
            [Action::ExecFromTempOrCache, Action::RecoverySnapshotTamper]
        );
    }

    #[test]
    fn burst_needs_enough_ops_inside_the_window() {
        let mut s = Scorer::new();
        for i in 0..(BURST_OPS as u64 - 1) {
            assert_eq!(s.observe(1, &create(i * 1_000_000)), None);
        }
        assert_eq!(s.score(1), 0);
        s.observe(1, &create(63 * 1_000_000));
        assert_eq!(s.score(1), 40);

        let mut slow = Scorer::new();
        for i in 0..(BURST_OPS as u64 * 4) {
            slow.observe(2, &create(i * 20_000_000));
        }
        assert_eq!(slow.score(2), 0, "~50 ops/s never packs 64 into one second");
    }

    #[test]
    fn reads_do_not_count_toward_a_burst() {
        let mut s = Scorer::new();
        for i in 0..200 {
            s.observe(1, &ev(i, Event::Open(OpenData { path: "/a".into(), write: false })));
        }
        assert_eq!(s.score(1), 0);
    }

    #[test]
    fn each_action_counts_once_and_verdict_fires_once() {
        let mut s = Scorer::new();
        for _ in 0..10 {
            assert_eq!(s.observe(7, &exec("/tmp/p", &["p"])), None);
        }
        assert_eq!(s.score(7), 20, "repeated temp execs must not reach the threshold alone");
        for i in 0..BURST_OPS as u64 {
            assert_eq!(s.observe(7, &create(i)), None);
        }
        assert_eq!(s.score(7), 60);
        let v = s.observe(7, &exec("/usr/bin/tmutil", &["tmutil", "deletelocalsnapshots", "/"])).unwrap();
        assert_eq!(v.score, 110);
        assert_eq!(
            v.actions,
            [Action::ExecFromTempOrCache, Action::RapidFileModBurst, Action::RecoverySnapshotTamper]
        );
        assert_eq!(v.threat_id, threat_id(&v.actions));
        assert_eq!((v.lineage, v.trigger_pid), (7, 500));
        assert_eq!(s.observe(7, &exec("/usr/bin/tmutil", &["tmutil", "delete", "/"])), None);
    }

    #[test]
    fn inferred_burst_is_marked_and_threat_id_is_unchanged() {
        let mut s = Scorer::new();
        s.observe(7, &exec("/tmp/p", &["p"]));
        for i in 0..BURST_OPS as u64 {
            let evidence = if i == 10 { Evidence::Inferred { candidates: 3 } } else { Evidence::Observed };
            s.observe_with(7, &create(i), evidence);
        }
        let v = s.observe(7, &exec("/usr/bin/tmutil", &["tmutil", "deletelocalsnapshots", "/"])).unwrap();
        assert_eq!(v.inferred, [InferredAction { action: Action::RapidFileModBurst, candidates: 3 }]);
        assert_eq!(v.threat_id, threat_id(&v.actions), "evidence does not enter Threat_ID (NFR-6)");

        let mut observed = Scorer::new();
        for i in 0..BURST_OPS as u64 {
            observed.observe(8, &create(i));
        }
        assert!(observed.trajectories[&8].inferred.is_empty());
    }

    #[test]
    fn threat_id_is_pinned_sha256_of_ordered_codes() {
        let order = [Action::ExecFromTempOrCache, Action::RecoverySnapshotTamper, Action::RapidFileModBurst];
        // `printf '\x01\x02\x03' | shasum -a 256`
        assert_eq!(hex(&threat_id(&order)), "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81");
        let other = [Action::RapidFileModBurst, Action::ExecFromTempOrCache, Action::RecoverySnapshotTamper];
        assert_ne!(threat_id(&order), threat_id(&other), "order is part of the identity");
    }

    #[test]
    fn suspension_policy_protects_self_system_and_listed_pids() {
        let mut policy = SuspendPolicy::new(4000);
        policy.protect(4001);
        let mut dry = DryRun::default();
        let report = suspend_all(&[1, 99, 100, 4000, 4001, 5000], &policy, &mut dry);
        assert_eq!(dry.suspended, [100, 5000]);
        assert_eq!(report.suspended, [100, 5000]);
        assert_eq!(report.skipped, [1, 99, 4000, 4001]);
    }

    #[test]
    fn suspension_failures_are_reported() {
        struct Failing;
        impl Suspender for Failing {
            fn suspend(&mut self, _: u32) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::ESRCH))
            }
        }
        let report = suspend_all(&[5000], &SuspendPolicy::new(1), &mut Failing);
        assert_eq!(report.failed.len(), 1);
        assert!(report.suspended.is_empty());
    }

    #[test]
    fn wake_signal_json_shape() {
        let w = WakeSignal { threat_id: "ab".into(), pid: 9, schema: vec![Action::RapidFileModBurst] };
        assert_eq!(serde_json::to_string(&w).unwrap(), r#"{"threat_id":"ab","pid":9,"schema":["RapidFileModBurst"]}"#);
    }
}
