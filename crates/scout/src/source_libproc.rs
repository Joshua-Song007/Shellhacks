//! FR-D-3 degraded source (no root): kqueue EVFILT_PROC for process events,
//! FSEvents for file events, libproc for process identity.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, c_char, c_void};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::Duration;

use serde::Serialize;
use tes::schema::{
    Event, ExecData, ExitData, ForkData, OpenData, PathData, Proc, RenameData, SCHEMA_VERSION, TesEvent,
};

use crate::reader::now_ns;

const PROC_NOTES: u32 = libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT | libc::NOTE_EXITSTATUS;
/// EVFILT_USER ident the FSEvents callback triggers to wake `next_events`.
const WAKE_IDENT: libc::uintptr_t = 1;

#[derive(Debug, Clone)]
struct Known {
    pidver: u64,
    ppid: u32,
    exe: String,
    /// `ri_logical_writes` at the last attribution; `None` when rusage is
    /// unreadable (another user's process without root).
    writes: Option<u64>,
}

/// Wakes a `ProcWatcher` blocked in `next_events` from another thread.
#[derive(Clone)]
pub struct Waker {
    kq: Arc<OwnedFd>,
}

impl Waker {
    pub fn wake(&self) {
        let change = user_kevent(libc::NOTE_TRIGGER, 0);
        // SAFETY: one valid change record and no output buffer; the kqueue fd
        // is kept open by the shared Arc.
        unsafe { libc::kevent(self.kq.as_raw_fd(), &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    }
}

fn user_kevent(fflags: u32, flags: u16) -> libc::kevent {
    libc::kevent {
        ident: WAKE_IDENT,
        filter: libc::EVFILT_USER,
        flags,
        fflags,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

/// Event-driven process watcher (FR-D-3): one EVFILT_PROC knote per visible
/// process. macOS has no NOTE_TRACK, so on NOTE_FORK the new child is found
/// with `proc_listchildpids` and watched from then on. A child that forks or
/// execs before it is registered has that step missed.
pub struct ProcWatcher {
    kq: Arc<OwnedFd>,
    ids: Identities,
    known: HashMap<u32, Known>,
    seq: u64,
    stats: LibprocStats,
    /// Per-batch write deltas inside the attribution window.
    recent: VecDeque<(u64, Vec<(u32, u64)>)>,
}

impl ProcWatcher {
    pub fn new() -> io::Result<Self> {
        // SAFETY: kqueue has no preconditions.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a freshly created descriptor that nothing else owns.
        let kq = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
        let change = user_kevent(0, libc::EV_ADD | libc::EV_CLEAR);
        // SAFETY: one valid change record and no output buffer.
        if unsafe { libc::kevent(kq.as_raw_fd(), &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            kq,
            ids: Identities::default(),
            known: HashMap::new(),
            seq: 0,
            stats: LibprocStats::default(),
            recent: VecDeque::new(),
        })
    }

    pub fn waker(&self) -> Waker {
        Waker { kq: Arc::clone(&self.kq) }
    }

    pub fn stats(&self) -> &LibprocStats {
        &self.stats
    }

    /// Registers every visible process; returns how many were registered.
    pub fn watch_all(&mut self) -> usize {
        all_pids().into_iter().filter(|&pid| pid != 0 && self.watch(pid, None)).count()
    }

    pub fn watch(&mut self, pid: u32, parent: Option<u32>) -> bool {
        let change = libc::kevent {
            ident: pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD,
            fflags: PROC_NOTES,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: one valid change record and no output buffer.
        let rc = unsafe { libc::kevent(self.kq.as_raw_fd(), &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if rc != 0 {
            return false;
        }
        let ppid = parent.or_else(|| bsdinfo(pid).map(|b| b.pbi_ppid)).unwrap_or(0);
        let exe = exe_path(pid).unwrap_or_default();
        let pidver = self.ids.pidver(pid);
        // Baseline now, so writes made before Scout saw the process are never
        // credited to a later batch.
        let writes = logical_writes(pid);
        self.known.insert(pid, Known { pidver, ppid, exe, writes });
        true
    }

    pub fn watched(&self) -> usize {
        self.known.len()
    }

    /// Blocks up to `timeout` (forever if `None`) and returns the TES events
    /// implied by whatever process notes arrived. Also returns (possibly with
    /// no events) when a `Waker` fires.
    pub fn next_events(&mut self, timeout: Option<Duration>) -> io::Result<Vec<TesEvent>> {
        // SAFETY: kevent is plain old data; all-zero is a valid value.
        let mut buf: [libc::kevent; 64] = unsafe { std::mem::zeroed() };
        let ts = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });
        let ts_ptr = ts.as_ref().map_or(std::ptr::null(), |t| t as *const libc::timespec);
        // SAFETY: buf is valid for writes of buf.len() events; ts_ptr is null or valid.
        let n = unsafe {
            libc::kevent(self.kq.as_raw_fd(), std::ptr::null(), 0, buf.as_mut_ptr(), buf.len() as i32, ts_ptr)
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::Interrupted { Ok(Vec::new()) } else { Err(err) };
        }
        let now = now_ns();
        let mut out = Vec::new();
        for kev in buf[..n as usize].iter().filter(|k| k.filter == libc::EVFILT_PROC) {
            let pid = kev.ident as u32;
            if kev.fflags & libc::NOTE_FORK != 0 {
                self.on_fork(pid, now, &mut out);
            }
            if kev.fflags & libc::NOTE_EXEC != 0 {
                self.on_exec(pid, now, &mut out);
            }
            if kev.fflags & libc::NOTE_EXIT != 0 {
                self.on_exit(pid, kev.data as i32, now, &mut out);
            }
        }
        Ok(out)
    }

    fn on_fork(&mut self, parent: u32, now: u64, out: &mut Vec<TesEvent>) {
        for child in child_pids(parent) {
            if self.known.contains_key(&child) || !self.watch(child, Some(parent)) {
                continue;
            }
            let child_pidver = self.known[&child].pidver;
            self.emit(parent, now, Event::Fork(ForkData { child_pid: child, child_pidver }), out);
        }
    }

    /// Start time survives exec, so `new_pidver` equals the current pidver.
    fn on_exec(&mut self, pid: u32, now: u64, out: &mut Vec<TesEvent>) {
        let Some(target) = exe_path(pid) else {
            return;
        };
        let Some(new_pidver) = self.known.get(&pid).map(|k| k.pidver) else {
            return;
        };
        let args = args(pid).unwrap_or_else(|| vec![target.clone()]);
        self.emit(pid, now, Event::Exec(ExecData { target: target.clone(), args, new_pidver }), out);
        if let Some(k) = self.known.get_mut(&pid) {
            k.exe = target;
        }
    }

    fn on_exit(&mut self, pid: u32, status: i32, now: u64, out: &mut Vec<TesEvent>) {
        self.emit(pid, now, Event::Exit(ExitData { status }), out);
        self.known.remove(&pid);
        self.ids.forget(pid);
    }

    /// Attributes one FSEvents batch (FR-D-3). Reads the `ri_logical_writes`
    /// delta of every watched process whose rusage is readable and sums them
    /// over the last `ATTRIBUTION_WINDOW_NS`; if one process made at least
    /// `DOMINANCE_PCT` of that total, the batch's changes are emitted as TES
    /// events of that process. Otherwise nothing is emitted and the batch is
    /// counted. The window exists because FSEvents delivers after the writes:
    /// a fast writer's bytes are all read on the first batch, and the batches
    /// that follow would otherwise see no writer. The emitted process is an
    /// inference, never an observation.
    pub fn attribute(&mut self, batch: &FsBatch) -> Attributed {
        self.stats.batches += 1;
        self.stats.changes += batch.changes.len() as u64;
        if batch.source_dropped {
            self.stats.source_dropped_batches += 1;
        }
        let mut deltas = Vec::new();
        for (&pid, k) in self.known.iter_mut() {
            let Some(now) = logical_writes(pid) else {
                continue;
            };
            let prev = k.writes.replace(now).unwrap_or(now);
            if now > prev {
                deltas.push((pid, now - prev));
            }
        }
        self.recent.push_back((batch.recv_ns, deltas));
        while self.recent.front().is_some_and(|(t, _)| batch.recv_ns.saturating_sub(*t) > ATTRIBUTION_WINDOW_NS) {
            self.recent.pop_front();
        }
        let mut totals: HashMap<u32, u64> = HashMap::new();
        for (pid, d) in self.recent.iter().flat_map(|(_, ds)| ds) {
            *totals.entry(*pid).or_default() += d;
        }
        let totals: Vec<(u32, u64)> = totals.into_iter().collect();
        let mut out = Attributed { events: Vec::new(), candidates: 0 };
        let pid = match dominance(&totals) {
            Dominance::Dominant { pid, .. } if !self.known.contains_key(&pid) => {
                self.stats.unattributed_writer_exited += 1;
                return out;
            }
            Dominance::Dominant { pid, candidates } => {
                self.stats.attributed_batches += 1;
                out.candidates = candidates;
                pid
            }
            Dominance::Split { .. } => {
                self.stats.unattributed_split += 1;
                return out;
            }
            Dominance::NoWriters => {
                self.stats.unattributed_no_writers += 1;
                return out;
            }
        };
        let (mapped, unpaired) = map_changes(&batch.changes, |p| std::path::Path::new(p).exists());
        self.stats.unpaired_renames += unpaired;
        let recv_ns = now_ns();
        for event in mapped {
            self.emit_at(pid, batch.recv_ns, recv_ns, event, &mut out.events);
        }
        self.stats.inferred_events += out.events.len() as u64;
        out
    }

    /// kqueue carries no event timestamp, so `ts_ns` is the delivery time.
    fn emit(&mut self, pid: u32, now: u64, event: Event, out: &mut Vec<TesEvent>) {
        self.emit_at(pid, now, now, event, out);
    }

    fn emit_at(&mut self, pid: u32, ts_ns: u64, recv_ns: u64, event: Event, out: &mut Vec<TesEvent>) {
        let Some(k) = self.known.get(&pid) else {
            return;
        };
        self.seq += 1;
        out.push(TesEvent {
            v: SCHEMA_VERSION,
            seq: self.seq,
            ts_ns,
            recv_ns,
            proc: Proc {
                pid,
                pidver: k.pidver,
                ppid: k.ppid,
                exe: k.exe.clone(),
                signing_id: None,
                team_id: None,
                platform: false,
            },
            event,
        });
    }
}

/// Share of a batch's written bytes one process must hold to be credited.
pub const DOMINANCE_PCT: u64 = 80;
/// Trailing window of write deltas a batch is judged against; the same
/// length as the burst window, so one burst is judged as a whole.
pub const ATTRIBUTION_WINDOW_NS: u64 = crate::scoring::BURST_WINDOW_NS;

/// TES events of one attributed batch; `candidates` = processes that wrote.
#[derive(Debug, Default)]
pub struct Attributed {
    pub events: Vec<TesEvent>,
    pub candidates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dominance {
    Dominant { pid: u32, candidates: usize },
    Split { candidates: usize },
    NoWriters,
}

/// Picks the process holding at least `DOMINANCE_PCT` of the written bytes.
pub fn dominance(deltas: &[(u32, u64)]) -> Dominance {
    let writers: Vec<&(u32, u64)> = deltas.iter().filter(|(_, d)| *d > 0).collect();
    let total: u128 = writers.iter().map(|(_, d)| u128::from(*d)).sum();
    let Some(&&(pid, top)) = writers.iter().max_by_key(|(_, d)| *d) else {
        return Dominance::NoWriters;
    };
    let candidates = writers.len();
    if u128::from(top) * 100 >= total * u128::from(DOMINANCE_PCT) {
        Dominance::Dominant { pid, candidates }
    } else {
        Dominance::Split { candidates }
    }
}

/// One TES event per FSEvents entry, since coalesced flags cannot say how
/// many operations happened: removed -> unlink, else created -> create, else
/// modified -> open(write). Renamed-only entries become a rename when two
/// consecutive ones pair up as (gone, present); the rest are counted.
pub fn map_changes(changes: &[FileChange], exists: impl Fn(&str) -> bool) -> (Vec<Event>, u64) {
    let mut out = Vec::new();
    let mut unpaired = 0;
    let mut pending_from: Option<&str> = None;
    for c in changes {
        let path = c.path.clone();
        let event = if c.removed() {
            Some(Event::Unlink(PathData { path }))
        } else if c.created() {
            Some(Event::Create(PathData { path }))
        } else if c.modified() {
            Some(Event::Open(OpenData { path, write: true }))
        } else {
            None
        };
        if let Some(e) = event {
            out.push(e);
            continue;
        }
        if !c.renamed() {
            continue;
        }
        let present = exists(&c.path);
        match (pending_from.take(), present) {
            (Some(from), true) => out.push(Event::Rename(RenameData { from: from.into(), to: c.path.clone() })),
            (Some(_), false) => {
                unpaired += 1;
                pending_from = Some(&c.path);
            }
            (None, false) => pending_from = Some(&c.path),
            (None, true) => unpaired += 1,
        }
    }
    unpaired += u64::from(pending_from.is_some());
    (out, unpaired)
}

/// Degraded-source counters, surfaced in Scout's stats records (NFR-7).
#[derive(Debug, Clone, Default, Serialize)]
pub struct LibprocStats {
    pub batches: u64,
    pub changes: u64,
    /// FSEvents reported its own drops or coalescing in these batches.
    pub source_dropped_batches: u64,
    pub attributed_batches: u64,
    /// Several processes wrote and none held `DOMINANCE_PCT`.
    pub unattributed_split: u64,
    /// No readable process wrote (another user's process, a process that
    /// already exited, or rename/unlink only, which rusage does not count).
    pub unattributed_no_writers: u64,
    /// The dominant writer exited before its batch arrived.
    pub unattributed_writer_exited: u64,
    pub unpaired_renames: u64,
    pub inferred_events: u64,
}

/// One path reported by FSEvents with its (possibly coalesced) flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: String,
    pub flags: u32,
}

impl FileChange {
    pub fn created(&self) -> bool {
        self.flags & fsevents::ITEM_CREATED != 0
    }
    pub fn removed(&self) -> bool {
        self.flags & fsevents::ITEM_REMOVED != 0
    }
    pub fn renamed(&self) -> bool {
        self.flags & fsevents::ITEM_RENAMED != 0
    }
    pub fn modified(&self) -> bool {
        self.flags & fsevents::ITEM_MODIFIED != 0
    }
    pub fn is_file(&self) -> bool {
        self.flags & fsevents::ITEM_IS_FILE != 0
    }
}

/// One FSEvents callback. FSEvents never says which process made a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsBatch {
    pub changes: Vec<FileChange>,
    pub recv_ns: u64,
    /// FSEvents itself reported dropped or coalesced-away events.
    pub source_dropped: bool,
}

struct StreamContext {
    tx: SyncSender<FsBatch>,
    dropped: AtomicU64,
    waker: Option<Waker>,
}

/// FSEvents stream over `roots`, delivered on a private serial dispatch
/// queue into a bounded channel; a full channel drops the batch and counts
/// it (same policy as `reader.rs`).
pub struct FileWatcher {
    stream: fsevents::StreamRef,
    queue: fsevents::DispatchQueue,
    ctx: *mut StreamContext,
}

impl FileWatcher {
    /// `waker`, if given, fires after every delivered batch so a thread
    /// blocked in `ProcWatcher::next_events` can drain the channel.
    pub fn start(
        roots: &[&str],
        latency: Duration,
        capacity: usize,
        waker: Option<Waker>,
    ) -> io::Result<(Self, Receiver<FsBatch>)> {
        let (tx, rx) = mpsc::sync_channel(capacity);
        let ctx = Box::into_raw(Box::new(StreamContext { tx, dropped: AtomicU64::new(0), waker }));
        // SAFETY: every CF object created here is released before returning;
        // `ctx` outlives the stream because Drop invalidates the stream first.
        unsafe {
            let strings: Vec<fsevents::CFRef> = roots
                .iter()
                .map(|r| {
                    fsevents::CFStringCreateWithBytes(
                        std::ptr::null(),
                        r.as_ptr(),
                        r.len() as isize,
                        fsevents::UTF8,
                        0,
                    )
                })
                .collect();
            let paths = fsevents::CFArrayCreate(
                std::ptr::null(),
                strings.as_ptr(),
                strings.len() as isize,
                (&raw const fsevents::kCFTypeArrayCallBacks).cast(),
            );
            for s in &strings {
                fsevents::CFRelease(*s);
            }
            let context = fsevents::Context {
                version: 0,
                info: ctx.cast(),
                retain: std::ptr::null(),
                release: std::ptr::null(),
                copy_description: std::ptr::null(),
            };
            let stream = fsevents::FSEventStreamCreate(
                std::ptr::null(),
                on_fs_events,
                &context,
                paths,
                fsevents::SINCE_NOW,
                latency.as_secs_f64(),
                fsevents::CREATE_FILE_EVENTS | fsevents::CREATE_NO_DEFER,
            );
            fsevents::CFRelease(paths);
            if stream.is_null() {
                drop(Box::from_raw(ctx));
                return Err(io::Error::other("FSEventStreamCreate failed"));
            }
            let queue = fsevents::dispatch_queue_create(c"tcell.scout.fsevents".as_ptr(), std::ptr::null());
            fsevents::FSEventStreamSetDispatchQueue(stream, queue);
            if fsevents::FSEventStreamStart(stream) == 0 {
                fsevents::FSEventStreamInvalidate(stream);
                fsevents::FSEventStreamRelease(stream);
                fsevents::dispatch_release(queue);
                drop(Box::from_raw(ctx));
                return Err(io::Error::other("FSEventStreamStart failed"));
            }
            Ok((Self { stream, queue, ctx }, rx))
        }
    }

    /// Batches dropped because the consumer fell behind.
    pub fn dropped_batches(&self) -> u64 {
        // SAFETY: ctx stays valid until Drop.
        unsafe { (*self.ctx).dropped.load(Ordering::Relaxed) }
    }
}

impl Drop for FileWatcher {
    fn drop(&mut self) {
        // SAFETY: stop + invalidate guarantee no callback runs afterwards, so
        // freeing the context and queue is then sound.
        unsafe {
            fsevents::FSEventStreamStop(self.stream);
            fsevents::FSEventStreamInvalidate(self.stream);
            fsevents::FSEventStreamRelease(self.stream);
            fsevents::dispatch_release(self.queue);
            drop(Box::from_raw(self.ctx));
        }
    }
}

extern "C" fn on_fs_events(
    _stream: fsevents::StreamRef,
    info: *mut c_void,
    count: usize,
    paths: *mut c_void,
    flags: *const u32,
    _ids: *const u64,
) {
    let recv_ns = now_ns();
    // SAFETY: `info` is the StreamContext passed at creation and alive until
    // the stream is invalidated. Without kFSEventStreamCreateFlagUseCFTypes,
    // `paths` is a C array of `count` NUL-terminated strings and `flags` has
    // `count` entries.
    let (ctx, paths, flags) = unsafe {
        (
            &*(info as *const StreamContext),
            std::slice::from_raw_parts(paths as *const *const c_char, count),
            std::slice::from_raw_parts(flags, count),
        )
    };
    let mut batch = FsBatch { changes: Vec::with_capacity(count), recv_ns, source_dropped: false };
    for (&path, &flags) in paths.iter().zip(flags) {
        if flags & fsevents::DROPPED_FLAGS != 0 {
            batch.source_dropped = true;
        }
        // SAFETY: see above; each entry is a valid C string.
        let path = unsafe { CStr::from_ptr(path) }.to_string_lossy().into_owned();
        batch.changes.push(FileChange { path, flags });
    }
    if let Err(TrySendError::Full(_)) = ctx.tx.try_send(batch) {
        ctx.dropped.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(w) = &ctx.waker {
        w.wake();
    }
}

/// Minimal CoreServices/CoreFoundation/libdispatch surface for FSEvents.
#[allow(non_upper_case_globals, non_snake_case)]
mod fsevents {
    use std::ffi::{c_char, c_void};

    pub type CFRef = *const c_void;
    pub type StreamRef = *mut c_void;
    pub type DispatchQueue = *mut c_void;
    pub type Callback = extern "C" fn(StreamRef, *mut c_void, usize, *mut c_void, *const u32, *const u64);

    #[repr(C)]
    pub struct Context {
        pub version: isize,
        pub info: *mut c_void,
        pub retain: *const c_void,
        pub release: *const c_void,
        pub copy_description: *const c_void,
    }

    pub const UTF8: u32 = 0x0800_0100;
    pub const SINCE_NOW: u64 = u64::MAX;
    pub const CREATE_NO_DEFER: u32 = 0x02;
    pub const CREATE_FILE_EVENTS: u32 = 0x10;

    pub const MUST_SCAN_SUBDIRS: u32 = 0x01;
    pub const USER_DROPPED: u32 = 0x02;
    pub const KERNEL_DROPPED: u32 = 0x04;
    pub const DROPPED_FLAGS: u32 = MUST_SCAN_SUBDIRS | USER_DROPPED | KERNEL_DROPPED;
    pub const ITEM_CREATED: u32 = 0x100;
    pub const ITEM_REMOVED: u32 = 0x200;
    pub const ITEM_RENAMED: u32 = 0x800;
    pub const ITEM_MODIFIED: u32 = 0x1000;
    pub const ITEM_IS_FILE: u32 = 0x1_0000;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        /// `CFArrayCallBacks`: version + four function pointers.
        pub static kCFTypeArrayCallBacks: [usize; 5];
        pub fn CFStringCreateWithBytes(alloc: CFRef, bytes: *const u8, len: isize, encoding: u32, external: u8) -> CFRef;
        pub fn CFArrayCreate(alloc: CFRef, values: *const CFRef, count: isize, callbacks: *const c_void) -> CFRef;
        pub fn CFRelease(cf: CFRef);
    }

    #[link(name = "CoreServices", kind = "framework")]
    unsafe extern "C" {
        pub fn FSEventStreamCreate(
            alloc: CFRef,
            callback: Callback,
            context: *const Context,
            paths: CFRef,
            since_when: u64,
            latency: f64,
            flags: u32,
        ) -> StreamRef;
        pub fn FSEventStreamSetDispatchQueue(stream: StreamRef, queue: DispatchQueue);
        pub fn FSEventStreamStart(stream: StreamRef) -> u8;
        pub fn FSEventStreamStop(stream: StreamRef);
        pub fn FSEventStreamInvalidate(stream: StreamRef);
        pub fn FSEventStreamRelease(stream: StreamRef);
    }

    unsafe extern "C" {
        pub fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueue;
        pub fn dispatch_release(object: *mut c_void);
    }
}

fn all_pids() -> Vec<u32> {
    // SAFETY: a null buffer asks for the current pid count.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0i32; n as usize + 64];
    let bytes = (pids.len() * std::mem::size_of::<i32>()) as i32;
    // SAFETY: pids is valid for writes of `bytes` bytes.
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(n.max(0) as usize);
    pids.into_iter().map(|p| p as u32).collect()
}

fn child_pids(ppid: u32) -> Vec<u32> {
    let mut pids = vec![0i32; 1024];
    let bytes = (pids.len() * std::mem::size_of::<i32>()) as i32;
    // SAFETY: pids is valid for writes of `bytes` bytes.
    let n = unsafe { libc::proc_listchildpids(ppid as i32, pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(n.max(0) as usize);
    pids.into_iter().map(|p| p as u32).collect()
}

fn bsdinfo(pid: u32) -> Option<libc::proc_bsdinfo> {
    // SAFETY: proc_bsdinfo is plain old data; all-zero is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: info is valid for writes of `size` bytes.
    let n = unsafe {
        libc::proc_pidinfo(pid as i32, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
    };
    (n == size).then_some(info)
}

pub fn exe_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buf is valid for writes of buf.len() bytes.
    let n = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// Cumulative bytes the process has written (`ri_logical_writes`). Grows on
/// create and write, not on rename or unlink. Own-uid processes only without
/// root.
pub fn logical_writes(pid: u32) -> Option<u64> {
    // SAFETY: rusage_info_v4 is plain old data; all-zero is a valid value.
    let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    // SAFETY: info is valid for writes of a whole rusage_info_v4, the flavor asked for.
    let rc = unsafe { libc::proc_pid_rusage(pid as i32, libc::RUSAGE_INFO_V4, (&raw mut info).cast()) };
    (rc == 0).then_some(info.ri_logical_writes)
}

/// Process start time in microseconds, via `PROC_PIDTBSDINFO` (FR-D-7).
/// Readable only for the caller's own processes without root.
pub fn start_time_us(pid: u32) -> Option<u64> {
    bsdinfo(pid).map(|info| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

/// argv via `KERN_PROCARGS2`: `int argc`, exec path, NUL padding, then argc
/// NUL-terminated strings. Readable only for the caller's own processes.
pub fn args(pid: u32) -> Option<Vec<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as i32];
    let mut size: libc::size_t = 0;
    // SAFETY: a null buffer asks sysctl for the required size.
    let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) };
    if rc != 0 || size < 4 {
        return None;
    }
    let mut buf = vec![0u8; size];
    // SAFETY: buf is valid for writes of `size` bytes.
    let rc = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0)
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(size);
    parse_procargs2(&buf)
}

fn parse_procargs2(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok()?;
    let rest = buf.get(4..)?;
    let exec_end = rest.iter().position(|&b| b == 0)?;
    let mut pos = exec_end;
    while rest.get(pos) == Some(&0) {
        pos += 1;
    }
    let mut out = Vec::with_capacity(argc);
    for _ in 0..argc {
        let len = rest.get(pos..)?.iter().position(|&b| b == 0)?;
        out.push(String::from_utf8_lossy(&rest[pos..pos + len]).into_owned());
        pos += len + 1;
    }
    Some(out)
}

/// Assigns `pidver` (FR-D-7): start time for readable processes, else a
/// Scout-assigned counter held for the process's lifetime. Counters start at
/// 1 and start times are ~1.7e15 µs, so the two ranges cannot collide.
#[derive(Debug, Default)]
pub struct Identities {
    assigned: HashMap<u32, u64>,
    next_counter: u64,
}

impl Identities {
    pub fn pidver(&mut self, pid: u32) -> u64 {
        if let Some(start) = start_time_us(pid) {
            self.assigned.insert(pid, start);
            return start;
        }
        if let Some(&v) = self.assigned.get(&pid) {
            return v;
        }
        self.next_counter += 1;
        self.assigned.insert(pid, self.next_counter);
        self.next_counter
    }

    pub fn forget(&mut self, pid: u32) {
        self.assigned.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_pid() -> u32 {
        std::process::id()
    }

    #[test]
    fn own_process_identity_is_readable() {
        let exe = exe_path(own_pid()).unwrap();
        assert_eq!(std::path::Path::new(&exe), std::env::current_exe().unwrap().canonicalize().unwrap());
        let start = start_time_us(own_pid()).unwrap();
        assert!(start > 1_600_000_000_000_000, "start time in µs since epoch");
        assert_eq!(start_time_us(own_pid()), Some(start));
        let argv = args(own_pid()).unwrap();
        let expected: Vec<String> = std::env::args().collect();
        assert_eq!(argv, expected);
    }

    #[test]
    fn missing_process_yields_none() {
        let gone = 99_999_999;
        assert_eq!(exe_path(gone), None);
        assert_eq!(start_time_us(gone), None);
        assert_eq!(args(gone), None);
    }

    #[test]
    fn procargs2_parsing() {
        let mut buf = 2i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/bin/sh\0\0\0\0sh\0-c\0ENV=1\0");
        assert_eq!(parse_procargs2(&buf), Some(vec!["sh".into(), "-c".into()]));
        assert_eq!(parse_procargs2(&buf[..3]), None);
        let mut truncated = 3i32.to_ne_bytes().to_vec();
        truncated.extend_from_slice(b"/x\0a\0");
        assert_eq!(parse_procargs2(&truncated), None);
    }

    #[test]
    fn pidver_uses_start_time_or_a_stable_lifetime_counter() {
        let mut ids = Identities::default();
        assert_eq!(ids.pidver(own_pid()), start_time_us(own_pid()).unwrap());

        let unreadable = 99_999_999;
        let first = ids.pidver(unreadable);
        assert_eq!(ids.pidver(unreadable), first, "stable while the process lives");
        ids.forget(unreadable);
        assert_ne!(ids.pidver(unreadable), first, "a recycled pid gets a new identity");
        assert!(first < 1_000_000);
    }

    #[test]
    fn watcher_reports_fork_exec_exit_of_a_spawned_child() {
        use std::process::Command;
        use std::time::Instant;

        let mut w = ProcWatcher::new().unwrap();
        assert!(w.watch(own_pid(), None));
        let mut child = Command::new("/bin/sh").args(["-c", "sleep 0.3; exec /bin/sleep 0.2"]).spawn().unwrap();
        let cpid = child.id();

        let exited = |events: &[TesEvent]| events.iter().any(|e| e.proc.pid == cpid && matches!(e.event, Event::Exit(_)));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut events = Vec::new();
        while !exited(&events) && Instant::now() < deadline {
            events.extend(w.next_events(Some(Duration::from_millis(200))).unwrap());
        }
        child.wait().unwrap();

        let (parent, child_pidver) = events
            .iter()
            .find_map(|e| match &e.event {
                Event::Fork(f) if f.child_pid == cpid => Some((e.proc.pid, f.child_pidver)),
                _ => None,
            })
            .expect("fork of the spawned child");
        assert_eq!(parent, own_pid());
        assert!(child_pidver > 1_600_000_000_000_000, "own-uid child keyed by start time");

        // macOS /bin/sh is a launcher that execs /bin/bash, so the chain is
        // sh -> bash -> sleep; each exec reports the image it replaced.
        let execs: Vec<(String, ExecData)> = events
            .iter()
            .filter_map(|e| match &e.event {
                Event::Exec(x) if e.proc.pid == cpid => Some((e.proc.exe.clone(), x.clone())),
                _ => None,
            })
            .collect();
        let chain: Vec<(&str, &str)> = execs.iter().map(|(from, x)| (from.as_str(), x.target.as_str())).collect();
        assert_eq!(chain, [("/bin/sh", "/bin/bash"), ("/bin/bash", "/bin/sleep")]);
        let (_, sleep) = &execs[1];
        assert_eq!(sleep.args, ["/bin/sleep", "0.2"]);
        assert!(execs.iter().all(|(_, x)| x.new_pidver == child_pidver), "start time survives exec");

        let status = events
            .iter()
            .find_map(|e| match &e.event {
                Event::Exit(x) if e.proc.pid == cpid => Some(x.status),
                _ => None,
            })
            .expect("exit of the child");
        assert_eq!(status, 0);

        // Includes the grandchild bash forks for `sleep 0.3`; filtering it out
        // would leave seq gaps.
        let mut validator = tes::Validator::new();
        for e in events {
            validator.check_event(e).expect("watcher output passes the TES boundary");
        }
        assert_eq!(validator.stats().seq_gap_events, 0);
    }

    #[test]
    fn file_watcher_reports_create_rename_modify_remove() {
        use std::collections::HashMap;
        use std::time::Instant;

        let dir = std::env::temp_dir().join(format!("tcell-fsevents-{}", own_pid()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.canonicalize().unwrap();
        let root_str = root.to_str().unwrap();
        let (watcher, rx) = FileWatcher::start(&[root_str], Duration::from_millis(20), 64, None).unwrap();
        std::thread::sleep(Duration::from_millis(200));

        let a = root.join("a.txt");
        let b = root.join("b.txt");
        std::fs::write(&a, b"x").unwrap();
        std::fs::rename(&a, &b).unwrap();
        std::fs::write(&b, b"yy").unwrap();
        std::fs::remove_file(&b).unwrap();

        let mut flags: HashMap<String, u32> = HashMap::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let b_str = b.to_str().unwrap().to_owned();
        while Instant::now() < deadline && flags.get(&b_str).is_none_or(|f| f & fsevents::ITEM_REMOVED == 0) {
            if let Ok(batch) = rx.recv_timeout(Duration::from_millis(100)) {
                assert!(batch.recv_ns > 0);
                for c in batch.changes {
                    *flags.entry(c.path).or_default() |= c.flags;
                }
            }
        }
        drop(watcher);
        std::fs::remove_dir_all(&dir).unwrap();

        let get = |p: &std::path::Path| FileChange { path: p.to_str().unwrap().into(), flags: flags[p.to_str().unwrap()] };
        let (a, b) = (get(&a), get(&b));
        assert!(a.created() && a.renamed() && a.is_file(), "{a:?}");
        assert!(b.renamed() && b.modified() && b.removed(), "{b:?}");
    }

    #[test]
    fn file_watcher_drops_and_counts_when_the_consumer_stalls() {
        let dir = std::env::temp_dir().join(format!("tcell-fsevents-stall-{}", own_pid()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.canonicalize().unwrap();
        let (watcher, rx) = FileWatcher::start(&[root.to_str().unwrap()], Duration::ZERO, 1, None).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        for i in 0..200 {
            std::fs::write(root.join(format!("f{i}")), b"x").unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        std::thread::sleep(Duration::from_millis(300));
        let delivered = rx.try_iter().count();
        let dropped = watcher.dropped_batches();
        drop(watcher);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(delivered, 1, "capacity-1 channel holds one batch while nobody reads");
        assert!(dropped > 0, "later batches are counted, not blocked on");
    }

    #[test]
    fn watch_all_registers_every_visible_process() {
        let mut w = ProcWatcher::new().unwrap();
        let n = w.watch_all();
        assert!(n > 50, "registered {n}");
        assert_eq!(w.watched(), n);
    }

    #[test]
    fn dominance_needs_eighty_percent_of_the_written_bytes() {
        assert_eq!(dominance(&[(1, 800), (2, 200), (3, 0)]), Dominance::Dominant { pid: 1, candidates: 2 });
        assert_eq!(dominance(&[(1, 790), (2, 210)]), Dominance::Split { candidates: 2 });
        assert_eq!(dominance(&[(5, 1)]), Dominance::Dominant { pid: 5, candidates: 1 });
        assert_eq!(dominance(&[(1, 0), (2, 0)]), Dominance::NoWriters);
        assert_eq!(dominance(&[]), Dominance::NoWriters);
        assert_eq!(dominance(&[(1, u64::MAX), (2, u64::MAX / 10)]), Dominance::Dominant { pid: 1, candidates: 2 });
    }

    #[test]
    fn changes_map_to_one_tes_event_each() {
        use fsevents::{ITEM_CREATED, ITEM_IS_FILE, ITEM_MODIFIED, ITEM_REMOVED, ITEM_RENAMED};
        let c = |path: &str, flags: u32| FileChange { path: path.into(), flags: flags | ITEM_IS_FILE };
        let changes = [
            c("/h/new", ITEM_CREATED | ITEM_MODIFIED),
            c("/h/gone", ITEM_CREATED | ITEM_REMOVED),
            c("/h/edit", ITEM_MODIFIED),
            c("/h/a", ITEM_RENAMED),
            c("/h/a.locked", ITEM_RENAMED),
            c("/h/orphan", ITEM_RENAMED),
            c("/h/meta", 0),
        ];
        let present = ["/h/new", "/h/edit", "/h/a.locked"];
        let (events, unpaired) = map_changes(&changes, |p| present.contains(&p));
        assert_eq!(
            events,
            [
                Event::Create(PathData { path: "/h/new".into() }),
                Event::Unlink(PathData { path: "/h/gone".into() }),
                Event::Open(OpenData { path: "/h/edit".into(), write: true }),
                Event::Rename(RenameData { from: "/h/a".into(), to: "/h/a.locked".into() }),
            ]
        );
        assert_eq!(unpaired, 1, "a rename with no partner is counted, not guessed");
    }

    #[test]
    fn waker_interrupts_a_blocked_wait() {
        use std::time::Instant;
        let mut w = ProcWatcher::new().unwrap();
        let waker = w.waker();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            waker.wake();
        });
        let start = Instant::now();
        assert!(w.next_events(Some(Duration::from_secs(10))).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(5));
        t.join().unwrap();
    }

    #[test]
    fn file_burst_is_attributed_to_the_writing_child() {
        use std::process::Command;
        use std::time::Instant;

        let dir = std::env::temp_dir().join(format!("tcell-attr-{}", own_pid()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.canonicalize().unwrap();
        let mut w = ProcWatcher::new().unwrap();
        assert!(w.watch(own_pid(), None));
        let (fw, rx) = FileWatcher::start(&[root.to_str().unwrap()], Duration::from_millis(20), 256, Some(w.waker())).unwrap();
        std::thread::sleep(Duration::from_millis(200));

        // Writes 100 files of 4 KiB from the shell itself (printf is a
        // builtin), then stays alive so its batches are attributed while it
        // runs. 4 KiB each keeps it dominant over other tests in this process.
        let script = "s=$(printf '%4096s' x); i=0; while [ $i -lt 100 ]; do printf '%s' \"$s\" > f$i; i=$((i+1)); done; sleep 1";
        let mut child = Command::new("/bin/sh").args(["-c", script]).current_dir(&root).spawn().unwrap();
        let cpid = child.id();

        let mut all = Vec::new();
        let mut inferred = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        let exited = |all: &[TesEvent]| all.iter().any(|e| e.proc.pid == cpid && matches!(e.event, Event::Exit(_)));
        while !exited(&all) && Instant::now() < deadline {
            all.extend(w.next_events(Some(Duration::from_millis(500))).unwrap());
            for batch in rx.try_iter() {
                let a = w.attribute(&batch);
                inferred.extend(a.events.iter().map(|e| (e.clone(), a.candidates)));
                all.extend(a.events);
            }
        }
        child.wait().unwrap();
        drop(fw);
        std::fs::remove_dir_all(&dir).unwrap();

        let creates = inferred
            .iter()
            .filter(|(e, _)| e.proc.pid == cpid && matches!(e.event, Event::Create(_)))
            .count();
        assert!(creates >= crate::scoring::BURST_OPS, "{creates} creates credited to the child; {:?}", w.stats());
        assert!(inferred.iter().all(|(_, c)| *c >= 1));
        assert!(w.stats().attributed_batches >= 1);

        let mut validator = tes::Validator::new();
        for e in all {
            validator.check_event(e).expect("inferred events pass the TES boundary");
        }
        assert_eq!(validator.stats().seq_gap_events, 0, "process and file events share one seq");
    }
}
