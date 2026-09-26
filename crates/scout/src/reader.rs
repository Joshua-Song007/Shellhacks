use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_CAPACITY: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLine {
    pub line: String,
    pub recv_ns: u64,
}

/// Drop policy: when the channel is full the incoming (newest) line is
/// dropped and counted, so the reader never blocks on the parser.
#[derive(Debug, Default)]
pub struct ReaderCounters {
    pub read: AtomicU64,
    pub dropped: AtomicU64,
    pub io_errors: AtomicU64,
}

impl ReaderCounters {
    pub fn snapshot(&self) -> ReaderStats {
        ReaderStats {
            read: self.read.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            io_errors: self.io_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ReaderStats {
    pub read: u64,
    pub dropped: u64,
    pub io_errors: u64,
}

pub struct Reader {
    pub lines: Receiver<RawLine>,
    pub counters: Arc<ReaderCounters>,
    pub handle: JoinHandle<()>,
}

pub fn spawn<R: Read + Send + 'static>(source: R, capacity: usize) -> Reader {
    let (tx, rx) = mpsc::sync_channel(capacity);
    let counters = Arc::new(ReaderCounters::default());
    let thread_counters = Arc::clone(&counters);
    let handle = thread::Builder::new()
        .name("tes-reader".into())
        .spawn(move || pump(source, tx, &thread_counters))
        .expect("spawn reader thread");
    Reader { lines: rx, counters, handle }
}

fn pump<R: Read>(source: R, tx: SyncSender<RawLine>, counters: &ReaderCounters) {
    let mut reader = BufReader::with_capacity(1 << 20, source);
    let mut buf = Vec::with_capacity(4096);
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                counters.io_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        let recv_ns = now_ns();
        counters.read.fetch_add(1, Ordering::Relaxed);
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        let line = String::from_utf8_lossy(&buf).into_owned();
        match tx.try_send(RawLine { line, recv_ns }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => return,
        }
    }
}

pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn delivers_lines_in_order_without_newlines() {
        let r = spawn(Cursor::new(b"a\nb\r\nc".to_vec()), 16);
        r.handle.join().unwrap();
        let got: Vec<String> = r.lines.try_iter().map(|l| l.line).collect();
        assert_eq!(got, ["a", "b", "c"]);
        assert_eq!(r.counters.snapshot(), ReaderStats { read: 3, dropped: 0, io_errors: 0 });
    }

    #[test]
    fn full_channel_drops_newest_and_counts_instead_of_blocking() {
        let input: String = (0..100).map(|i| format!("{i}\n")).collect();
        let r = spawn(Cursor::new(input.into_bytes()), 2);
        r.handle.join().expect("reader must finish without a consumer");
        let got: Vec<String> = r.lines.try_iter().map(|l| l.line).collect();
        assert_eq!(got, ["0", "1"]);
        let s = r.counters.snapshot();
        assert_eq!((s.read, s.dropped), (100, 98));
    }

    #[test]
    fn stamps_arrival_time() {
        let before = now_ns();
        let r = spawn(Cursor::new(b"x\n".to_vec()), 1);
        r.handle.join().unwrap();
        let l = r.lines.recv().unwrap();
        assert!(l.recv_ns >= before && l.recv_ns <= now_ns());
    }
}
