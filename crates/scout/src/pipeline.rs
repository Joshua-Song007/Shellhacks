//! Scout's per-event pipeline: TES boundary -> lineage -> scoring ->
//! suspension. Source-agnostic so it can be driven by live eslogger, a
//! captured eslogger file, a TES trace, or in-process adapters.

use serde::Serialize;
use tes::schema::{Event, TesEvent};
use tes::{Stats, Validator};

use crate::lineage::Lineages;
use crate::reader::{RawLine, now_ns};
use crate::scoring::{
    Evidence, InferredAction, Scorer, SuspendPolicy, SuspendReport, Suspender, Verdict, WakeSignal, hex,
    suspend_all,
};
use crate::source_eslogger;

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub wake: WakeSignal,
    pub root_exe: String,
    pub score: u32,
    pub attack_ids: Vec<&'static str>,
    /// Actions credited by inference (degraded path), not direct observation.
    pub inferred: Vec<InferredAction>,
    pub suspend: SuspendReport,
    pub trigger_ts_ns: u64,
    pub trigger_recv_ns: u64,
    pub suspended_ns: u64,
    /// NFR-1: suspension time minus the OS time of the tipping action.
    pub latency_ns: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PipelineStats {
    pub accepted: u64,
    pub rejected: u64,
    pub seq_gap_events: u64,
    pub adapter_errors: u64,
    pub unmodeled_kinds: u64,
    pub inferred_events: u64,
    pub lineages: usize,
    pub trajectories: usize,
    pub detections: u64,
}

pub struct Pipeline<S: Suspender> {
    validator: Validator,
    lineages: Lineages,
    scorer: Scorer,
    policy: SuspendPolicy,
    suspender: S,
    adapter_errors: u64,
    unmodeled_kinds: u64,
    inferred_events: u64,
    detections: u64,
}

impl<S: Suspender> Pipeline<S> {
    pub fn new(policy: SuspendPolicy, suspender: S) -> Self {
        Self {
            validator: Validator::new(),
            lineages: Lineages::new(),
            scorer: Scorer::new(),
            policy,
            suspender,
            adapter_errors: 0,
            unmodeled_kinds: 0,
            inferred_events: 0,
            detections: 0,
        }
    }

    pub fn feed_eslogger_line(&mut self, raw: &RawLine) -> Option<Detection> {
        match source_eslogger::map_line(&raw.line, raw.recv_ns) {
            Ok(Some(ev)) => self.feed_tes_event(ev),
            Ok(None) => {
                self.unmodeled_kinds += 1;
                None
            }
            Err(_) => {
                self.adapter_errors += 1;
                None
            }
        }
    }

    pub fn feed_tes_line(&mut self, line: &str) -> Option<Detection> {
        let ev = self.validator.check_line(line).ok()?;
        self.process(ev)
    }

    pub fn feed_tes_event(&mut self, ev: TesEvent) -> Option<Detection> {
        let ev = self.validator.check_event(ev).ok()?;
        self.process(ev)
    }

    /// A TES event whose process was inferred, not reported by the source.
    pub fn feed_inferred_event(&mut self, ev: TesEvent, candidates: usize) -> Option<Detection> {
        let ev = self.validator.check_event(ev).ok()?;
        self.inferred_events += 1;
        self.process_with(ev, Evidence::Inferred { candidates })
    }

    fn process(&mut self, ev: TesEvent) -> Option<Detection> {
        self.process_with(ev, Evidence::Observed)
    }

    fn process_with(&mut self, ev: TesEvent, evidence: Evidence) -> Option<Detection> {
        let lineage = self.lineages.observe(&ev);
        let detection = self.scorer.observe_with(lineage, &ev, evidence).map(|v| self.convict(v, &ev));
        if matches!(ev.event, Event::Exit(_)) && self.lineages.retire_if_empty(lineage) {
            self.scorer.forget(lineage);
        }
        detection
    }

    fn convict(&mut self, verdict: Verdict, ev: &TesEvent) -> Detection {
        let pids = self.lineages.live_pids(verdict.lineage);
        let suspend = suspend_all(&pids, &self.policy, &mut self.suspender);
        let suspended_ns = now_ns();
        self.detections += 1;
        let root_exe = self.lineages.get(verdict.lineage).map(|l| l.root_exe.clone()).unwrap_or_default();
        Detection {
            wake: WakeSignal {
                threat_id: hex(&verdict.threat_id),
                pid: verdict.trigger_pid,
                schema: verdict.actions.clone(),
            },
            root_exe,
            score: verdict.score,
            attack_ids: verdict.actions.iter().map(|a| a.attack_id()).collect(),
            inferred: verdict.inferred.clone(),
            suspend,
            trigger_ts_ns: verdict.trigger_ts_ns,
            trigger_recv_ns: ev.recv_ns,
            suspended_ns,
            latency_ns: suspended_ns.saturating_sub(verdict.trigger_ts_ns),
        }
    }

    pub fn suspender(&self) -> &S {
        &self.suspender
    }

    pub fn validator_stats(&self) -> &Stats {
        self.validator.stats()
    }

    pub fn stats(&self) -> PipelineStats {
        let v = self.validator.stats();
        PipelineStats {
            accepted: v.accepted,
            rejected: v.rejected(),
            seq_gap_events: v.seq_gap_events,
            adapter_errors: self.adapter_errors,
            unmodeled_kinds: self.unmodeled_kinds,
            inferred_events: self.inferred_events,
            lineages: self.lineages.len(),
            trajectories: self.scorer.len(),
            detections: self.detections,
        }
    }
}
