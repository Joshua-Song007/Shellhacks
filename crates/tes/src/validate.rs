use serde_json::Value;

use crate::schema::{SCHEMA_VERSION, TesEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    Malformed,
    /// Unknown field anywhere in the record, or an unknown event `kind`.
    Unknown,
    WrongVersion,
    NonAbsolutePath,
    ZeroPid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    pub reason: RejectReason,
    pub detail: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub accepted: u64,
    pub malformed: u64,
    pub unknown: u64,
    pub wrong_version: u64,
    pub non_absolute_path: u64,
    pub zero_pid: u64,
    /// Events the source numbered but never delivered, inferred from `seq` gaps.
    pub seq_gap_events: u64,
}

impl Stats {
    pub fn rejected(&self) -> u64 {
        self.malformed + self.unknown + self.wrong_version + self.non_absolute_path + self.zero_pid
    }
}

/// Strict TES boundary. Use one instance per source stream: `seq` gap
/// accounting assumes a single monotonically numbered source.
#[derive(Debug, Default)]
pub struct Validator {
    stats: Stats,
    last_seq: Option<u64>,
}

impl Validator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn check_line(&mut self, line: &str) -> Result<TesEvent, Reject> {
        match serde_json::from_str::<TesEvent>(line) {
            Ok(ev) => self.check_event(ev),
            Err(err) => {
                let detail = err.to_string();
                let value = serde_json::from_str::<Value>(line).ok();
                if let Some(seq) = value.as_ref().and_then(|v| v.get("seq")).and_then(Value::as_u64) {
                    self.observe_seq(seq);
                }
                let reason = match &value {
                    None => RejectReason::Malformed,
                    Some(v) if v.get("v").and_then(Value::as_u64) != Some(SCHEMA_VERSION as u64) => {
                        RejectReason::WrongVersion
                    }
                    Some(_) if detail.contains("unknown field") || detail.contains("unknown variant") => {
                        RejectReason::Unknown
                    }
                    Some(_) => RejectReason::Malformed,
                };
                Err(self.reject(reason, detail))
            }
        }
    }

    /// For in-process adapters that build `TesEvent` directly rather than
    /// emitting NDJSON; applies every boundary rule that a struct can violate.
    pub fn check_event(&mut self, ev: TesEvent) -> Result<TesEvent, Reject> {
        self.observe_seq(ev.seq);
        if ev.v != SCHEMA_VERSION {
            return Err(self.reject(RejectReason::WrongVersion, format!("v = {}", ev.v)));
        }
        if ev.proc.pid == 0 {
            return Err(self.reject(RejectReason::ZeroPid, "pid = 0".into()));
        }
        if let Some(bad) = std::iter::once(ev.proc.exe.as_str())
            .chain(ev.event.paths())
            .find(|p| !p.starts_with('/'))
        {
            let detail = format!("non-absolute path {bad:?}");
            return Err(self.reject(RejectReason::NonAbsolutePath, detail));
        }
        self.stats.accepted += 1;
        Ok(ev)
    }

    fn reject(&mut self, reason: RejectReason, detail: String) -> Reject {
        let counter = match reason {
            RejectReason::Malformed => &mut self.stats.malformed,
            RejectReason::Unknown => &mut self.stats.unknown,
            RejectReason::WrongVersion => &mut self.stats.wrong_version,
            RejectReason::NonAbsolutePath => &mut self.stats.non_absolute_path,
            RejectReason::ZeroPid => &mut self.stats.zero_pid,
        };
        *counter += 1;
        Reject { reason, detail }
    }

    fn observe_seq(&mut self, seq: u64) {
        if let Some(last) = self.last_seq {
            if seq <= last {
                return;
            }
            self.stats.seq_gap_events += seq - last - 1;
        }
        self.last_seq = Some(seq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(seq: u64, pid: u32, exe: &str, event: &str) -> String {
        format!(
            r#"{{"v":1,"seq":{seq},"ts_ns":1,"recv_ns":2,"proc":{{"pid":{pid},"pidver":7,"ppid":1,"exe":"{exe}","platform":false}},"event":{event}}}"#
        )
    }

    const EXIT: &str = r#"{"kind":"exit","data":{"status":0}}"#;

    #[test]
    fn accepts_valid_event_and_round_trips() {
        let mut v = Validator::new();
        let ev = v.check_line(&line(1, 42, "/bin/sh", EXIT)).unwrap();
        assert_eq!(ev.proc.pid, 42);
        assert_eq!(v.check_line(&ev.to_line()).unwrap(), ev);
        assert_eq!(v.stats().accepted, 2);
    }

    #[test]
    fn accepts_every_event_kind() {
        let kinds = [
            r#"{"kind":"exec","data":{"target":"/tmp/x","args":["/tmp/x","-v"]}}"#,
            r#"{"kind":"fork","data":{"child_pid":43,"child_pidver":1}}"#,
            EXIT,
            r#"{"kind":"open","data":{"path":"/a","write":true}}"#,
            r#"{"kind":"create","data":{"path":"/a"}}"#,
            r#"{"kind":"rename","data":{"from":"/a","to":"/b"}}"#,
            r#"{"kind":"unlink","data":{"path":"/b"}}"#,
        ];
        let mut v = Validator::new();
        for (i, k) in kinds.iter().enumerate() {
            v.check_line(&line(i as u64, 42, "/bin/sh", k)).unwrap();
        }
        assert_eq!(v.stats().accepted, kinds.len() as u64);
    }

    #[test]
    fn rejects_unknown_fields_at_every_level() {
        let mut v = Validator::new();
        let top = line(1, 42, "/bin/sh", EXIT).replacen("{", r#"{"extra":1,"#, 1);
        let in_proc = line(2, 42, "/bin/sh", EXIT).replace(r#""platform":false"#, r#""platform":false,"x":1"#);
        let in_data = line(3, 42, "/bin/sh", r#"{"kind":"exit","data":{"status":0,"x":1}}"#);
        let bad_kind = line(4, 42, "/bin/sh", r#"{"kind":"mmap","data":{}}"#);
        for l in [top, in_proc, in_data, bad_kind] {
            assert_eq!(v.check_line(&l).unwrap_err().reason, RejectReason::Unknown, "{l}");
        }
        assert_eq!(v.stats().unknown, 4);
        assert_eq!(v.stats().accepted, 0);
    }

    #[test]
    fn rejects_wrong_or_missing_version() {
        let mut v = Validator::new();
        let v2 = line(1, 42, "/bin/sh", EXIT).replacen(r#""v":1"#, r#""v":2"#, 1);
        let missing = line(2, 42, "/bin/sh", EXIT).replacen(r#""v":1,"#, "", 1);
        let v2_with_new_field = v2.replacen("{", r#"{"future":true,"#, 1);
        for l in [v2, missing, v2_with_new_field] {
            assert_eq!(v.check_line(&l).unwrap_err().reason, RejectReason::WrongVersion, "{l}");
        }
    }

    #[test]
    fn rejects_non_absolute_paths_in_exe_and_event() {
        let mut v = Validator::new();
        let rel_exe = line(1, 42, "bin/sh", EXIT);
        let rel_target = line(2, 42, "/bin/sh", r#"{"kind":"rename","data":{"from":"/a","to":"b"}}"#);
        for l in [rel_exe, rel_target] {
            assert_eq!(v.check_line(&l).unwrap_err().reason, RejectReason::NonAbsolutePath);
        }
    }

    #[test]
    fn rejects_zero_pid_and_garbage() {
        let mut v = Validator::new();
        assert_eq!(v.check_line(&line(1, 0, "/bin/sh", EXIT)).unwrap_err().reason, RejectReason::ZeroPid);
        assert_eq!(v.check_line("not json").unwrap_err().reason, RejectReason::Malformed);
        let missing_proc_field = line(3, 42, "/bin/sh", EXIT).replace(r#""ppid":1,"#, "");
        assert_eq!(v.check_line(&missing_proc_field).unwrap_err().reason, RejectReason::Malformed);
        assert_eq!(v.stats().rejected(), 3);
    }

    #[test]
    fn counts_seq_gaps_including_across_rejected_lines() {
        let mut v = Validator::new();
        v.check_line(&line(10, 42, "/bin/sh", EXIT)).unwrap();
        v.check_line(&line(11, 0, "/bin/sh", EXIT)).unwrap_err();
        v.check_line(&line(12, 42, "/bin/sh", EXIT)).unwrap();
        assert_eq!(v.stats().seq_gap_events, 0, "a rejected line is counted as a reject, not a gap");
        v.check_line(&line(20, 42, "/bin/sh", EXIT)).unwrap();
        assert_eq!(v.stats().seq_gap_events, 7);
        v.check_line(&line(15, 42, "/bin/sh", EXIT)).unwrap();
        assert_eq!(v.stats().seq_gap_events, 7, "late arrivals do not rewind the cursor");
    }
}
