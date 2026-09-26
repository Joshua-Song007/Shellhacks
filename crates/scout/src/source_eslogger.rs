//! FR-D-2 primary source: `eslogger` JSON -> TES v1. Raw structs here are
//! deliberately lenient (unknown fields ignored, FR-D-6); strictness lives at
//! the TES boundary (`tes::Validator`).

use std::io;
use std::process::{Child, Command, Stdio};

use serde::Deserialize;
use tes::schema::{
    Event, ExecData, ExitData, ForkData, OpenData, PathData, Proc, RenameData, SCHEMA_VERSION,
    TesEvent,
};

pub const SUBSCRIBED: [&str; 7] = ["exec", "fork", "exit", "open", "create", "rename", "unlink"];

/// `FWRITE` from <sys/fcntl.h>; ES reports kernel-style fflags, not O_* flags.
const FWRITE: u64 = 0x0002;

/// Requires root + Full Disk Access (SPIKE-1). Read its stdout with
/// `reader::spawn`, never directly on the parsing thread (FR-D-7a).
pub fn spawn() -> io::Result<Child> {
    Command::new("eslogger")
        .args(SUBSCRIBED)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapError {
    Json(String),
    BadTime(String),
}

/// `Ok(None)` means the message is an event kind TES does not model.
pub fn map_line(raw: &str, recv_ns: u64) -> Result<Option<TesEvent>, MapError> {
    let msg: EsMessage = serde_json::from_str(raw).map_err(|e| MapError::Json(e.to_string()))?;
    let ts_ns = parse_rfc3339_utc_ns(&msg.time).ok_or_else(|| MapError::BadTime(msg.time.clone()))?;
    let Some(event) = map_event(msg.event) else {
        return Ok(None);
    };
    let p = msg.process;
    Ok(Some(TesEvent {
        v: SCHEMA_VERSION,
        seq: msg.global_seq_num,
        ts_ns,
        recv_ns,
        proc: Proc {
            pid: p.audit_token.pid,
            pidver: p.audit_token.pidversion,
            ppid: p.ppid,
            exe: p.executable.path,
            signing_id: p.signing_id,
            team_id: p.team_id,
            platform: p.is_platform_binary,
        },
        event,
    }))
}

fn map_event(ev: EsEvent) -> Option<Event> {
    if let Some(e) = ev.exec {
        return Some(Event::Exec(ExecData {
            target: e.target.executable.path,
            args: e.args,
            new_pidver: e.target.audit_token.pidversion,
        }));
    }
    if let Some(e) = ev.fork {
        return Some(Event::Fork(ForkData {
            child_pid: e.child.audit_token.pid,
            child_pidver: e.child.audit_token.pidversion,
        }));
    }
    if let Some(e) = ev.exit {
        return Some(Event::Exit(ExitData { status: e.stat }));
    }
    if let Some(e) = ev.open {
        return Some(Event::Open(OpenData { path: e.file.path, write: e.fflag & FWRITE != 0 }));
    }
    if let Some(e) = ev.create {
        return Some(Event::Create(PathData { path: e.destination.into_path()? }));
    }
    if let Some(e) = ev.rename {
        return Some(Event::Rename(RenameData { from: e.source.path, to: e.destination.into_path()? }));
    }
    if let Some(e) = ev.unlink {
        return Some(Event::Unlink(PathData { path: e.target.path }));
    }
    None
}

#[derive(Deserialize)]
struct EsMessage {
    global_seq_num: u64,
    time: String,
    process: EsProcess,
    event: EsEvent,
}

#[derive(Deserialize)]
struct EsProcess {
    audit_token: AuditToken,
    ppid: u32,
    executable: EsFile,
    #[serde(default)]
    signing_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    is_platform_binary: bool,
}

#[derive(Deserialize)]
struct AuditToken {
    pid: u32,
    pidversion: u64,
}

#[derive(Deserialize)]
struct EsFile {
    path: String,
}

#[derive(Deserialize)]
struct EsEvent {
    exec: Option<EsExec>,
    fork: Option<EsFork>,
    exit: Option<EsExit>,
    open: Option<EsOpen>,
    create: Option<EsCreate>,
    rename: Option<EsRename>,
    unlink: Option<EsUnlink>,
}

#[derive(Deserialize)]
struct EsExec {
    target: EsTarget,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Deserialize)]
struct EsTarget {
    audit_token: AuditToken,
    executable: EsFile,
}

#[derive(Deserialize)]
struct EsFork {
    child: EsChild,
}

#[derive(Deserialize)]
struct EsChild {
    audit_token: AuditToken,
}

#[derive(Deserialize)]
struct EsExit {
    stat: i32,
}

#[derive(Deserialize)]
struct EsOpen {
    fflag: u64,
    file: EsFile,
}

#[derive(Deserialize)]
struct EsCreate {
    destination: EsDestination,
}

#[derive(Deserialize)]
struct EsRename {
    source: EsFile,
    destination: EsDestination,
}

#[derive(Deserialize)]
struct EsUnlink {
    target: EsFile,
}

/// ES reports a create/rename destination either as an existing file or as
/// a directory plus a new filename.
#[derive(Deserialize)]
struct EsDestination {
    existing_file: Option<EsFile>,
    new_path: Option<EsNewPath>,
}

#[derive(Deserialize)]
struct EsNewPath {
    dir: EsFile,
    filename: String,
}

impl EsDestination {
    fn into_path(self) -> Option<String> {
        if let Some(f) = self.existing_file {
            return Some(f.path);
        }
        let np = self.new_path?;
        let dir = np.dir.path.trim_end_matches('/');
        Some(format!("{dir}/{}", np.filename))
    }
}

/// Parses eslogger's `YYYY-MM-DDTHH:MM:SS[.fraction]Z` into epoch nanoseconds.
pub fn parse_rfc3339_utc_ns(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[b.len() - 1] != b'Z'
    {
        return None;
    }
    let field = |from: usize, to: usize| -> Option<i64> {
        let part = s.get(from..to)?;
        part.bytes().all(|c| c.is_ascii_digit()).then(|| part.parse().ok())?
    };
    let (year, month, day) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (hour, minute, second) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let frac = &s[19..s.len() - 1];
    let nanos = match frac.strip_prefix('.') {
        None if frac.is_empty() => 0,
        None => return None,
        Some(d) if d.is_empty() || d.len() > 9 || !d.bytes().all(|c| c.is_ascii_digit()) => return None,
        Some(d) => d.parse::<u64>().ok()? * 10u64.pow(9 - d.len() as u32),
    };
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(secs).ok()?.checked_mul(1_000_000_000)?.checked_add(nanos)
}

/// Howard Hinnant's days-from-civil (proleptic Gregorian, 1970-01-01 = 0).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(event: &str) -> String {
        format!(
            r#"{{"global_seq_num":7,"time":"1970-01-01T00:00:01.5Z","unknown_top":1,"process":{{"audit_token":{{"pid":10,"pidversion":3,"asid":1}},"ppid":1,"executable":{{"path":"\/tmp\/x","stat":{{}}}},"signing_id":"x","team_id":null,"is_platform_binary":false,"tty":null}},"event":{event}}}"#
        )
    }

    fn map(event: &str) -> Event {
        map_line(&msg(event), 99).unwrap().unwrap().event
    }

    #[test]
    fn maps_process_and_envelope() {
        let ev = map_line(&msg(r#"{"exit":{"stat":0}}"#), 99).unwrap().unwrap();
        assert_eq!((ev.v, ev.seq, ev.ts_ns, ev.recv_ns), (1, 7, 1_500_000_000, 99));
        assert_eq!((ev.proc.pid, ev.proc.pidver, ev.proc.ppid), (10, 3, 1));
        assert_eq!(ev.proc.exe, "/tmp/x", "JSON-escaped slashes must be decoded");
        assert_eq!(ev.proc.signing_id.as_deref(), Some("x"));
        assert_eq!(ev.proc.team_id, None);
    }

    #[test]
    fn exec_carries_post_exec_pidversion() {
        let e = map(r#"{"exec":{"target":{"audit_token":{"pid":10,"pidversion":4},"executable":{"path":"/bin/ls"}},"args":["ls","-l"],"env":["A=1"]}}"#);
        assert_eq!(
            e,
            Event::Exec(ExecData { target: "/bin/ls".into(), args: vec!["ls".into(), "-l".into()], new_pidver: 4 })
        );
    }

    #[test]
    fn fork_and_exit() {
        assert_eq!(
            map(r#"{"fork":{"child":{"audit_token":{"pid":11,"pidversion":5}}}}"#),
            Event::Fork(ForkData { child_pid: 11, child_pidver: 5 })
        );
        assert_eq!(map(r#"{"exit":{"stat":256}}"#), Event::Exit(ExitData { status: 256 }));
    }

    #[test]
    fn open_write_flag_uses_fwrite_bit() {
        let read = map(r#"{"open":{"fflag":1,"file":{"path":"/a"}}}"#);
        let write = map(r#"{"open":{"fflag":3,"file":{"path":"/a"}}}"#);
        assert_eq!(read, Event::Open(OpenData { path: "/a".into(), write: false }));
        assert_eq!(write, Event::Open(OpenData { path: "/a".into(), write: true }));
    }

    #[test]
    fn create_and_rename_destinations_both_shapes() {
        let existing = map(r#"{"create":{"destination_type":0,"destination":{"existing_file":{"path":"/d/f1"}}}}"#);
        let new_path = map(r#"{"create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"/d/"},"filename":"f1","mode":420}}}}"#);
        assert_eq!(existing, Event::Create(PathData { path: "/d/f1".into() }));
        assert_eq!(new_path, Event::Create(PathData { path: "/d/f1".into() }));
        let rename = map(r#"{"rename":{"source":{"path":"/d/f1"},"destination_type":1,"destination":{"new_path":{"dir":{"path":"/d"},"filename":"f2"}}}}"#);
        assert_eq!(rename, Event::Rename(RenameData { from: "/d/f1".into(), to: "/d/f2".into() }));
        assert_eq!(map(r#"{"unlink":{"parent_dir":{"path":"/d"},"target":{"path":"/d/f2"}}}"#), Event::Unlink(PathData { path: "/d/f2".into() }));
    }

    #[test]
    fn unmodeled_kind_is_skipped_not_an_error() {
        assert_eq!(map_line(&msg(r#"{"close":{"modified":true}}"#), 0), Ok(None));
    }

    #[test]
    fn malformed_input_is_an_error() {
        assert!(matches!(map_line("{", 0), Err(MapError::Json(_))));
        let bad_time = msg(r#"{"exit":{"stat":0}}"#).replace("1970-01-01T00:00:01.5Z", "yesterday");
        assert!(matches!(map_line(&bad_time, 0), Err(MapError::BadTime(_))));
    }

    #[test]
    fn rfc3339_parser() {
        assert_eq!(parse_rfc3339_utc_ns("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_utc_ns("1970-01-01T00:00:01.000000001Z"), Some(1_000_000_001));
        assert_eq!(parse_rfc3339_utc_ns("1970-01-01T00:00:00.123Z"), Some(123_000_000));
        assert_eq!(parse_rfc3339_utc_ns("2000-02-29T12:34:56.5Z"), Some(951_827_696_500_000_000));
        for bad in ["", "2000-02-29T12:34:56", "2000-13-01T00:00:00Z", "2000-02-29T12:34:56.Z", "2000-02-29T12:34:56.1234567890Z", "+000-01-01T00:00:00Z"] {
            assert_eq!(parse_rfc3339_utc_ns(bad), None, "{bad}");
        }
    }
}
