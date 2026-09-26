use std::fs::File;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use scout::pipeline::{Detection, Pipeline};
use scout::reader;
use scout::scoring::{DryRun, SigStop, SuspendPolicy, Suspender, WakeSignal};
use scout::source_beacon::{self, BeaconCollector, BeaconCounters, Finding};
use scout::source_eslogger;
use scout::source_libproc::{FileWatcher, ProcWatcher};
use serde::Serialize;
use serde_json::json;

const USAGE: &str = "usage: scout [--eslogger | --eslogger-file PATH | --tes-file PATH | --libproc [--watch DIR]...] \
[--beacon [SECS]] [--dry-run] [--wake-socket PATH] [--stats-every SECS]";

/// FSEvents coalescing latency and batch queue depth for `--libproc`.
const FS_LATENCY: Duration = Duration::from_millis(50);
const FS_CAPACITY: usize = 4_096;

enum Source {
    Eslogger,
    EsloggerFile(PathBuf),
    TesFile(PathBuf),
    /// FR-D-3 degraded path; watches these directories for file changes.
    Libproc(Vec<PathBuf>),
}

impl Source {
    fn label(&self) -> &'static str {
        match self {
            Source::Eslogger => "eslogger",
            Source::EsloggerFile(_) => "eslogger-file",
            Source::TesFile(_) => "tes-file",
            Source::Libproc(_) => "libproc",
        }
    }
}

struct Args {
    source: Source,
    beacon: Option<Duration>,
    dry_run: bool,
    wake_socket: Option<PathBuf>,
    stats_every: Duration,
}

fn parse_args() -> Result<Args, String> {
    let mut args =
        Args { source: Source::Eslogger, beacon: None, dry_run: false, wake_socket: None, stats_every: Duration::from_secs(5) };
    let mut it = std::env::args().skip(1).peekable();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--eslogger" => args.source = Source::Eslogger,
            "--eslogger-file" => args.source = Source::EsloggerFile(value()?.into()),
            "--tes-file" => args.source = Source::TesFile(value()?.into()),
            "--libproc" => args.source = Source::Libproc(Vec::new()),
            "--watch" => {
                let dir = PathBuf::from(value()?);
                match &mut args.source {
                    Source::Libproc(roots) => roots.push(dir),
                    _ => return Err("--watch needs --libproc before it".into()),
                }
            }
            // FR-D-11: optional lane, independent of `source`; `[SECS]` is
            // an optional trailing value, so a following flag is not eaten.
            "--beacon" => {
                let looks_numeric = |s: &String| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.');
                let interval = if it.peek().is_some_and(looks_numeric) {
                    let s = it.next().expect("peeked Some");
                    Duration::from_secs_f64(s.parse().map_err(|_| "--beacon needs seconds".to_string())?)
                } else {
                    source_beacon::DEFAULT_INTERVAL
                };
                args.beacon = Some(interval);
            }
            "--dry-run" => args.dry_run = true,
            "--wake-socket" => args.wake_socket = Some(value()?.into()),
            "--stats-every" => {
                let secs: f64 = value()?.parse().map_err(|_| "--stats-every needs seconds".to_string())?;
                if !(secs > 0.0 && secs.is_finite()) {
                    return Err("--stats-every must be positive".into());
                }
                args.stats_every = Duration::from_secs_f64(secs);
            }
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if let Source::Libproc(roots) = &mut args.source
        && roots.is_empty()
    {
        let home = std::env::var_os("HOME").ok_or("--libproc without --watch needs $HOME")?;
        roots.push(home.into());
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("scout: {e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = if args.dry_run { run(&args, DryRun::default()) } else { run(&args, SigStop) };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scout: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run<S: Suspender>(args: &Args, suspender: S) -> io::Result<()> {
    if let Source::Libproc(roots) = &args.source {
        return run_libproc(args, roots, suspender);
    }
    let mut policy = SuspendPolicy::new(std::process::id());
    let mut child = None;
    let (reader, tes_lines) = match &args.source {
        Source::Eslogger => {
            let mut c = source_eslogger::spawn()?;
            policy.protect(c.id());
            let stdout = c.stdout.take().expect("eslogger stdout is piped");
            child = Some(c);
            (reader::spawn(stdout, reader::DEFAULT_CAPACITY), false)
        }
        Source::EsloggerFile(p) => (reader::spawn(File::open(p)?, reader::DEFAULT_CAPACITY), false),
        Source::TesFile(p) => (reader::spawn(File::open(p)?, reader::DEFAULT_CAPACITY), true),
        Source::Libproc(_) => unreachable!("handled above"),
    };
    eprintln!("scout: source={} dry_run={} pid={}", args.source.label(), args.dry_run, std::process::id());

    let beacon = args.beacon.map(BeaconCollector::start);
    let mut pipeline = Pipeline::new(policy, suspender);
    let mut out = io::stdout().lock();
    let mut last_stats = Instant::now();
    loop {
        match reader.lines.recv_timeout(args.stats_every) {
            Ok(raw) => {
                let detection =
                    if tes_lines { pipeline.feed_tes_line(&raw.line) } else { pipeline.feed_eslogger_line(&raw) };
                if let Some(d) = detection {
                    report_detection(&mut out, args, &d)?;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        drain_beacon(&mut out, &beacon)?;
        if last_stats.elapsed() >= args.stats_every {
            emit_stats(&mut out, &pipeline, "reader", reader.counters.snapshot(), beacon_counters(&beacon), false)?;
            last_stats = Instant::now();
        }
    }
    emit_stats(&mut out, &pipeline, "reader", reader.counters.snapshot(), beacon_counters(&beacon), true)?;

    if let Some(mut c) = child {
        let status = c.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!("eslogger exited with {status} (needs root + Full Disk Access)")));
        }
    }
    Ok(())
}

/// FR-D-3: kqueue process events plus FSEvents file batches, both on this
/// thread. The FSEvents callback wakes the kqueue wait, so nothing polls;
/// the timeout only paces stats records. Runs until killed.
fn run_libproc<S: Suspender>(args: &Args, roots: &[PathBuf], suspender: S) -> io::Result<()> {
    let mut procs = ProcWatcher::new()?;
    let watched = procs.watch_all();
    let roots: Vec<String> = roots
        .iter()
        .map(|r| r.canonicalize().map(|p| p.to_string_lossy().into_owned()))
        .collect::<io::Result<_>>()?;
    let root_refs: Vec<&str> = roots.iter().map(String::as_str).collect();
    let (files, batches) = FileWatcher::start(&root_refs, FS_LATENCY, FS_CAPACITY, Some(procs.waker()))?;
    eprintln!(
        "scout: source=libproc dry_run={} pid={} watching {watched} processes, files under {roots:?}",
        args.dry_run,
        std::process::id()
    );

    let beacon = args.beacon.map(BeaconCollector::start);
    let mut pipeline = Pipeline::new(SuspendPolicy::new(std::process::id()), suspender);
    let mut out = io::stdout().lock();
    let mut last_stats = Instant::now();
    loop {
        for ev in procs.next_events(Some(args.stats_every))? {
            if let Some(d) = pipeline.feed_tes_event(ev) {
                report_detection(&mut out, args, &d)?;
            }
        }
        for batch in batches.try_iter() {
            let attributed = procs.attribute(&batch);
            for ev in attributed.events {
                if let Some(d) = pipeline.feed_inferred_event(ev, attributed.candidates) {
                    report_detection(&mut out, args, &d)?;
                }
            }
        }
        drain_beacon(&mut out, &beacon)?;
        if last_stats.elapsed() >= args.stats_every {
            let source = json!({ "fs_dropped_batches": files.dropped_batches(), "attribution": procs.stats() });
            emit_stats(&mut out, &pipeline, "libproc", source, beacon_counters(&beacon), false)?;
            last_stats = Instant::now();
        }
    }
}

fn beacon_counters(beacon: &Option<BeaconCollector>) -> Option<&BeaconCounters> {
    beacon.as_ref().map(|b| b.counters.as_ref())
}

/// Drains whatever beacon findings arrived since the last check; the
/// collector runs on its own thread and interval, so this never blocks.
fn drain_beacon(out: &mut impl Write, beacon: &Option<BeaconCollector>) -> io::Result<()> {
    let Some(beacon) = beacon else { return Ok(()) };
    for finding in beacon.findings.try_iter() {
        report_finding(out, &finding)?;
    }
    Ok(())
}

/// FR-D-11: written outside the `detection`/`stats` records above — a
/// beacon/scan finding is never scored and never triggers a wake signal.
fn report_finding(out: &mut impl Write, finding: &Finding) -> io::Result<()> {
    let mut record = serde_json::to_value(finding)?;
    record["type"] = json!("network_finding");
    writeln!(out, "{record}")?;
    out.flush()
}

fn report_detection(out: &mut impl Write, args: &Args, d: &Detection) -> io::Result<()> {
    eprintln!(
        "scout: DETECTED threat {} score {} root {} suspended {:?} skipped {:?} failed {:?} latency {:.2} ms",
        d.wake.threat_id,
        d.score,
        d.root_exe,
        d.suspend.suspended,
        d.suspend.skipped,
        d.suspend.failed,
        d.latency_ns as f64 / 1e6,
    );
    writeln!(out, "{}", json!({ "type": "detection", "source": args.source.label(), "detection": d }))?;
    out.flush()?;
    if let Some(path) = &args.wake_socket
        && let Err(e) = send_wake(path, &d.wake)
    {
        eprintln!("scout: wake signal not delivered to {}: {e}", path.display());
    }
    Ok(())
}

fn send_wake(path: &Path, wake: &WakeSignal) -> io::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    serde_json::to_writer(&mut stream, wake)?;
    stream.write_all(b"\n")
}

/// `source_key` names the source-side loss counters: "reader" (FR-D-7a) or
/// "libproc" (FSEvents drops and attribution outcomes). `beacon`, when the
/// lane is running, adds its own counters — separate from `pipeline.stats()`
/// since findings never pass through the pipeline (FR-D-11).
fn emit_stats<S: Suspender>(
    out: &mut impl Write,
    pipeline: &Pipeline<S>,
    source_key: &str,
    source: impl Serialize,
    beacon: Option<&BeaconCounters>,
    last: bool,
) -> io::Result<()> {
    let mut record = json!({ "type": "stats", "final": last, "pipeline": pipeline.stats() });
    record[source_key] = serde_json::to_value(source)?;
    if let Some(b) = beacon {
        record["beacon"] = serde_json::to_value(b.snapshot())?;
    }
    writeln!(out, "{record}")?;
    out.flush()
}
