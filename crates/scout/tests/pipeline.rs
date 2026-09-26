use std::process::Command;

use scout::pipeline::{Detection, Pipeline};
use scout::reader::RawLine;
use scout::scoring::{Action, BURST_OPS, DryRun, InferredAction, SuspendPolicy};
use tes::schema::{Event, ExecData, ForkData, PathData, Proc, RenameData, TesEvent};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/eslogger_trigger.ndjson");
const SCOUT_PID: u32 = 4_242;
/// `printf '\x01\x02\x03' | shasum -a 256`
const THREAT_ID_EXEC_TAMPER_BURST: &str = "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81";

fn pipeline() -> Pipeline<DryRun> {
    Pipeline::new(SuspendPolicy::new(SCOUT_PID), DryRun::default())
}

#[test]
fn real_eslogger_capture_maps_validates_and_retires() {
    let lines: Vec<String> = std::fs::read_to_string(FIXTURE).unwrap().lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 8);
    let mut p = pipeline();
    for (i, line) in lines.iter().enumerate() {
        let d = p.feed_eslogger_line(&RawLine { line: line.clone(), recv_ns: 0 });
        assert!(d.is_none(), "a benign spike trigger must not be convicted");
        if i == 5 {
            assert_eq!(p.stats().trajectories, 1, "exec from /private/tmp scored ExecFromTempOrCache");
        }
    }
    let s = p.stats();
    assert_eq!((s.accepted, s.rejected, s.adapter_errors, s.unmodeled_kinds), (8, 0, 0, 0));
    assert_eq!(s.seq_gap_events, 7_179, "sampled fixture: gaps between kept global_seq_nums are counted");
    assert_eq!((s.lineages, s.trajectories), (0, 0), "both processes exited, lineage retired");
}

struct Trace {
    events: Vec<TesEvent>,
    seq: u64,
    ts_ns: u64,
}

impl Trace {
    fn new() -> Self {
        Self { events: Vec::new(), seq: 0, ts_ns: 1_758_000_000_000_000_000 }
    }

    fn push(&mut self, pid: u32, pidver: u64, exe: &str, event: Event) {
        self.seq += 1;
        self.ts_ns += 1_000_000;
        self.events.push(TesEvent {
            v: 1,
            seq: self.seq,
            ts_ns: self.ts_ns,
            recv_ns: self.ts_ns + 50_000,
            proc: Proc { pid, pidver, ppid: 1, exe: exe.into(), signing_id: None, team_id: None, platform: false },
            event,
        });
    }

    fn fork(&mut self, pid: u32, ver: u64, exe: &str, child: u32) {
        self.push(pid, ver, exe, Event::Fork(ForkData { child_pid: child, child_pidver: 1 }));
    }

    fn exec(&mut self, pid: u32, exe: &str, target: &str, args: &[&str]) {
        let args = args.iter().map(|s| s.to_string()).collect();
        self.push(pid, 1, exe, Event::Exec(ExecData { target: target.into(), args, new_pidver: 2 }));
    }

    fn to_ndjson(&self) -> String {
        self.events.iter().map(|e| e.to_line() + "\n").collect()
    }
}

/// Hand-authored ransomware-shaped trajectory (FR-R-4 baseline style):
/// payload run from /private/tmp, snapshot deletion via a shell, then a
/// rename burst. Launched from an interactive zsh that must not be touched.
fn attack_trace() -> Trace {
    let mut t = Trace::new();
    t.fork(700, 1, "/bin/zsh", 701);
    t.exec(701, "/bin/zsh", "/private/tmp/payload", &["/private/tmp/payload"]);
    t.fork(701, 2, "/private/tmp/payload", 702);
    t.exec(702, "/private/tmp/payload", "/bin/sh", &["sh", "-c", "tmutil deletelocalsnapshots /"]);
    t.fork(702, 2, "/bin/sh", 703);
    t.exec(703, "/bin/sh", "/usr/bin/tmutil", &["tmutil", "deletelocalsnapshots", "/"]);
    for i in 0..BURST_OPS {
        let from = format!("/Users/demo/Documents/file{i}.txt");
        let to = format!("{from}.locked");
        t.push(701, 2, "/private/tmp/payload", Event::Rename(RenameData { from, to }));
    }
    t
}

fn assert_attack_detection(d: &Detection) {
    assert_eq!(d.wake.threat_id, THREAT_ID_EXEC_TAMPER_BURST);
    assert_eq!(d.wake.pid, 701);
    assert_eq!(
        d.wake.schema,
        [Action::ExecFromTempOrCache, Action::RecoverySnapshotTamper, Action::RapidFileModBurst]
    );
    assert_eq!(d.score, 110);
    assert_eq!(d.attack_ids, ["T1204", "T1490", "T1486"]);
    assert_eq!(d.root_exe, "/private/tmp/payload");
    assert_eq!(d.suspend.suspended, [701, 702, 703], "whole lineage, not the launching shell");
}

#[test]
fn attack_chain_is_detected_once_and_whole_lineage_suspended() {
    let trace = attack_trace();
    let mut p = pipeline();
    let mut detections = Vec::new();
    for line in trace.to_ndjson().lines() {
        detections.extend(p.feed_tes_line(line));
    }
    assert_eq!(detections.len(), 1);
    let d = &detections[0];
    assert_attack_detection(d);
    assert_eq!(d.trigger_ts_ns, trace.events.last().unwrap().ts_ns, "tipping action is the 64th rename");
    assert_eq!(p.suspender().suspended, [701, 702, 703]);
    assert_eq!(p.stats().rejected, 0);
}

#[test]
fn scout_never_suspends_itself_even_inside_a_convicted_lineage() {
    let mut trace = attack_trace();
    trace.events.insert(2, {
        let mut e = trace.events[0].clone();
        e.proc.pid = 701;
        e.proc.pidver = 2;
        e.proc.exe = "/private/tmp/payload".into();
        e.event = Event::Fork(ForkData { child_pid: SCOUT_PID, child_pidver: 1 });
        e
    });
    let mut p = pipeline();
    let d: Vec<Detection> = trace.events.into_iter().filter_map(|e| p.feed_tes_event(e)).collect();
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].suspend.skipped, [SCOUT_PID]);
    assert!(!p.suspender().suspended.contains(&SCOUT_PID));
}

#[test]
fn inferred_burst_convicts_and_is_marked_inferred() {
    let trace = attack_trace();
    let mut p = pipeline();
    let mut detections = Vec::new();
    for e in trace.events {
        // Degraded path: file ops come from FSEvents with an inferred process.
        detections.extend(if matches!(e.event, Event::Rename(_)) {
            p.feed_inferred_event(e, 2)
        } else {
            p.feed_tes_event(e)
        });
    }
    assert_eq!(detections.len(), 1);
    let d = &detections[0];
    assert_attack_detection(d);
    assert_eq!(d.inferred, [InferredAction { action: Action::RapidFileModBurst, candidates: 2 }]);
    assert_eq!(p.stats().inferred_events, BURST_OPS as u64);
    let json = serde_json::to_value(d).unwrap();
    assert_eq!(json["inferred"], serde_json::json!([{ "action": "RapidFileModBurst", "candidates": 2 }]));
}

#[test]
fn observed_attack_has_no_inferred_actions() {
    let mut p = pipeline();
    let d: Vec<Detection> = attack_trace().events.into_iter().filter_map(|e| p.feed_tes_event(e)).collect();
    assert!(d[0].inferred.is_empty());
}

#[test]
fn heavy_benign_file_churn_is_not_convicted() {
    let mut t = Trace::new();
    t.fork(800, 1, "/bin/zsh", 801);
    t.exec(801, "/bin/zsh", "/opt/homebrew/bin/node", &["node", "npm-cli.js", "install"]);
    for i in 0..5_000 {
        t.push(801, 2, "/opt/homebrew/bin/node", Event::Create(PathData { path: format!("/Users/demo/app/node_modules/f{i}") }));
    }
    let mut p = pipeline();
    assert!(t.events.into_iter().all(|e| p.feed_tes_event(e).is_none()));
    assert!(p.suspender().suspended.is_empty());
}

#[test]
fn scout_binary_replays_eslogger_capture_and_tes_trace() {
    let bin = env!("CARGO_BIN_EXE_scout");

    let out = Command::new(bin).args(["--eslogger-file", FIXTURE, "--dry-run"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stats: serde_json::Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert_eq!(stats["type"], "stats");
    assert_eq!(stats["final"], true);
    assert_eq!(stats["reader"]["read"], 8);
    assert_eq!(stats["pipeline"]["accepted"], 8);

    let trace_path = std::env::temp_dir().join(format!("tcell-attack-{}.ndjson", std::process::id()));
    std::fs::write(&trace_path, attack_trace().to_ndjson()).unwrap();
    let out = Command::new(bin).args(["--tes-file", trace_path.to_str().unwrap(), "--dry-run"]).output().unwrap();
    std::fs::remove_file(&trace_path).unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let detection: serde_json::Value = stdout
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|v| v["type"] == "detection")
        .expect("detection line on stdout");
    assert_eq!(detection["detection"]["wake"]["threat_id"], THREAT_ID_EXEC_TAMPER_BURST);
    assert_eq!(detection["detection"]["suspend"]["suspended"], serde_json::json!([701, 702, 703]));
}

#[test]
fn each_credited_action_emits_one_progress_record_in_order() {
    let mut p = pipeline();
    let mut detections = 0;
    for e in attack_trace().events {
        detections += p.feed_tes_event(e).is_some() as usize;
    }
    let progress = p.drain_progress();
    let got: Vec<(Action, u32)> = progress.iter().map(|g| (g.action, g.score)).collect();
    assert_eq!(
        got,
        [
            (Action::ExecFromTempOrCache, 20),
            (Action::RecoverySnapshotTamper, 70),
            (Action::RapidFileModBurst, 110)
        ]
    );
    assert_eq!(detections, 1);
    assert!(progress.iter().all(|g| g.root_exe == "/private/tmp/payload"));
    assert_eq!(progress[1].attack_id, "T1490");
    assert!(p.drain_progress().is_empty(), "drain empties the buffer");
}

#[test]
fn one_exec_crediting_two_actions_emits_both() {
    let mut t = Trace::new();
    t.exec(900, "/bin/sh", "/tmp/tmutil", &["tmutil", "deletelocalsnapshots", "/"]);
    let mut p = pipeline();
    p.feed_tes_event(t.events.remove(0));
    let got: Vec<(Action, u32)> = p.drain_progress().iter().map(|g| (g.action, g.score)).collect();
    assert_eq!(got, [(Action::ExecFromTempOrCache, 20), (Action::RecoverySnapshotTamper, 70)]);
}
