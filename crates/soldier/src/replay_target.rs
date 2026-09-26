//! FR-R-4: the search target's behavior is a replay of a TES trace. The
//! baseline is a hand-authored trace file imitating a real ATT&CK atomic.
//!
//! This deliberately does not reuse `scout::scoring::Scorer`: `Scorer`
//! only exposes the actions it has accumulated via a `Verdict`, returned
//! once, at the moment a lineage crosses the 100pt conviction threshold.
//! A benign/whitelisted trace should never be expected to convict, so that
//! contract doesn't fit here. Reimplementing Stage-1 detection from
//! scratch would risk drifting from scout's real detectors, so instead
//! this replays a trace using scout::scoring's already-public, stateless
//! helpers (`exec_actions`, `BURST_WINDOW_NS`, `BURST_OPS`) and does its
//! own light bookkeeping on top -- no scout file needed a new export for
//! this. It does not do full lineage rollup (fork/exec identity tracking)
//! either: a burst is tracked per raw `(pid, pidver)` actor, which is
//! enough for a single-actor hand-authored trace and still sound (just
//! more conservative) for a multi-actor one.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufRead};

use scout::scoring::{Action, BURST_OPS, BURST_WINDOW_NS, exec_actions};
use tes::schema::{Event, TesEvent};

use crate::allele_search::ContainmentTarget;

#[derive(Debug)]
pub struct ReplayTarget {
    threat_actions: Vec<Action>,
    benign_actions: Vec<Action>,
}

impl ContainmentTarget for ReplayTarget {
    fn threat_actions(&self) -> &[Action] {
        &self.threat_actions
    }

    fn benign_actions(&self) -> &[Action] {
        &self.benign_actions
    }
}

impl ReplayTarget {
    /// `malicious` is the FR-R-4 attack trace; `benign` is whatever
    /// whitelisted behavior the cure must not break. Neither trace is
    /// required to cross any scoring threshold -- the target is simply
    /// whichever Stage-1 actions each trace exhibits.
    pub fn from_traces(malicious: impl BufRead, benign: impl BufRead) -> io::Result<Self> {
        Ok(Self { threat_actions: replay(malicious)?, benign_actions: replay(benign)? })
    }

    /// Convenience for when no benign trace exists yet: `benign_actions()`
    /// is empty, so `allele_search`'s collision penalty never fires.
    pub fn from_malicious_only(malicious: impl BufRead) -> io::Result<Self> {
        Self::from_traces(malicious, io::empty())
    }
}

fn replay(trace: impl BufRead) -> io::Result<Vec<Action>> {
    let mut seen: HashSet<Action> = HashSet::new();
    let mut windows: HashMap<(u32, u64), VecDeque<u64>> = HashMap::new();
    for line in trace.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let ev: TesEvent = serde_json::from_str(&line).map_err(io::Error::other)?;
        seen.extend(exec_actions(&ev));
        if is_mutation(&ev) {
            let window = windows.entry((ev.proc.pid, ev.proc.pidver)).or_default();
            window.push_back(ev.ts_ns);
            while window.front().is_some_and(|&t| ev.ts_ns.saturating_sub(t) > BURST_WINDOW_NS) {
                window.pop_front();
            }
            if window.len() >= BURST_OPS {
                seen.insert(Action::RapidFileModBurst);
            }
        }
    }
    let mut actions: Vec<Action> = seen.into_iter().collect();
    actions.sort_by_key(|a| a.code());
    Ok(actions)
}

/// Matches scout::scoring's private classification of the same name.
/// Duplicated rather than exported because it's tied to TES event kinds
/// (stable) rather than any detection policy (which stays scout-only).
fn is_mutation(ev: &TesEvent) -> bool {
    match &ev.event {
        Event::Open(o) => o.write,
        Event::Create(_) | Event::Rename(_) | Event::Unlink(_) => true,
        Event::Exec(_) | Event::Fork(_) | Event::Exit(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tes::schema::{ExecData, PathData, Proc};

    use super::*;
    use crate::allele_search::{self, Allele};

    fn ev(ts_ns: u64, pid: u32, event: Event) -> TesEvent {
        TesEvent {
            v: 1,
            seq: 0,
            ts_ns,
            recv_ns: ts_ns,
            proc: Proc { pid, pidver: 1, ppid: 1, exe: "/tmp/p".into(), signing_id: None, team_id: None, platform: false },
            event,
        }
    }

    fn exec(ts_ns: u64, pid: u32, target: &str) -> TesEvent {
        ev(ts_ns, pid, Event::Exec(ExecData { target: target.into(), args: vec![target.into()], new_pidver: 2 }))
    }

    fn tamper(ts_ns: u64, pid: u32) -> TesEvent {
        ev(
            ts_ns,
            pid,
            Event::Exec(ExecData {
                target: "/usr/bin/tmutil".into(),
                args: vec!["tmutil".into(), "deletelocalsnapshots".into(), "/".into()],
                new_pidver: 2,
            }),
        )
    }

    fn create(ts_ns: u64, pid: u32) -> TesEvent {
        ev(ts_ns, pid, Event::Create(PathData { path: "/Users/u/doc".into() }))
    }

    fn lines(events: &[TesEvent]) -> Cursor<Vec<u8>> {
        let mut s = String::new();
        for e in events {
            s.push_str(&e.to_line());
            s.push('\n');
        }
        Cursor::new(s.into_bytes())
    }

    fn full_attack_trace() -> Vec<TesEvent> {
        let mut events = vec![exec(0, 500, "/tmp/p"), tamper(1, 500)];
        for i in 0..BURST_OPS as u64 {
            events.push(create(2_000_000 + i * 1_000_000, 500));
        }
        events
    }

    #[test]
    fn a_malicious_trace_yields_every_stage1_action_it_exhibits() {
        let target = ReplayTarget::from_malicious_only(lines(&full_attack_trace())).unwrap();
        assert_eq!(
            target.threat_actions(),
            [Action::ExecFromTempOrCache, Action::RecoverySnapshotTamper, Action::RapidFileModBurst]
        );
    }

    #[test]
    fn a_benign_trace_with_ordinary_behavior_yields_no_actions() {
        let benign = vec![exec(0, 600, "/usr/bin/ls"), create(1_000_000_000, 600), create(3_000_000_000, 600)];
        let target = ReplayTarget::from_traces(lines(&full_attack_trace()), lines(&benign)).unwrap();
        assert!(target.benign_actions().is_empty());
    }

    #[test]
    fn a_blank_line_is_skipped_not_an_error() {
        let mut s = full_attack_trace()[0].to_line();
        s.push_str("\n\n");
        let target = ReplayTarget::from_malicious_only(Cursor::new(s.into_bytes())).unwrap();
        assert_eq!(target.threat_actions(), [Action::ExecFromTempOrCache]);
    }

    #[test]
    fn a_malformed_line_is_an_error() {
        let err = ReplayTarget::from_malicious_only(Cursor::new(b"not json".to_vec())).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn search_settles_for_partial_containment_when_full_containment_would_collide() {
        let benign = vec![exec(0, 700, "/tmp/legit-helper")];
        let target = ReplayTarget::from_traces(lines(&full_attack_trace()), lines(&benign)).unwrap();
        assert_eq!(target.benign_actions(), [Action::ExecFromTempOrCache]);

        let result = allele_search::search(&target);
        assert_eq!(result.sequence, [Allele::RevertTouchedFiles], "every allele covering Exec also breaks the legit helper");
        assert_eq!(result.evaluation.fitness, 45);
    }
}
