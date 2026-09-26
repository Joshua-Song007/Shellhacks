//! FR-R-1: the Soldier stays dormant until it receives a wake signal from
//! Scout. Scout is the client here (see scout::main::send_wake): it
//! connects to the socket, writes one `WakeSignal` JSON line, and drops the
//! connection. The Soldier is therefore the server -- it binds the socket
//! and blocks on `accept` until a line arrives.

use std::io::{self, BufRead, BufReader};
use std::os::unix::net::UnixListener;
use std::path::Path;

use scout::scoring::WakeSignal;

pub struct Trigger {
    listener: UnixListener,
}

impl Trigger {
    /// Binds the wake socket. Fails if `path` already exists (a stale
    /// socket from a prior run); the caller is responsible for removing it
    /// first if that's the intended recovery.
    pub fn bind(path: &Path) -> io::Result<Self> {
        Ok(Self { listener: UnixListener::bind(path)? })
    }

    /// Blocks until a connection delivers a valid `WakeSignal` line, then
    /// returns it. A connection that closes without writing anything, or
    /// writes a line that doesn't parse, is treated as noise: it does not
    /// wake the Soldier -- FR-R-1 requires dormancy until an actual signal,
    /// not "wake on garbage".
    pub fn wait(&self) -> io::Result<WakeSignal> {
        loop {
            let (stream, _) = self.listener.accept()?;
            let mut line = String::new();
            if BufReader::new(stream).read_line(&mut line)? == 0 {
                continue;
            }
            if let Ok(wake) = serde_json::from_str::<WakeSignal>(line.trim_end()) {
                return Ok(wake);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::thread;

    use scout::scoring::Action;

    use super::*;

    fn socket_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tcell-trigger-test-{name}-{}", std::process::id()))
    }

    #[test]
    fn wait_returns_the_wake_signal_scout_sends() {
        let path = socket_path("basic");
        let _ = std::fs::remove_file(&path);
        let trigger = Trigger::bind(&path).unwrap();
        let wake = WakeSignal { threat_id: "abc123".into(), pid: 42, schema: vec![Action::RapidFileModBurst] };
        let wake_clone = wake.clone();
        let path_clone = path.clone();
        thread::spawn(move || {
            let mut stream = UnixStream::connect(&path_clone).unwrap();
            serde_json::to_writer(&mut stream, &wake_clone).unwrap();
            stream.write_all(b"\n").unwrap();
        });
        assert_eq!(trigger.wait().unwrap(), wake);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_malformed_line_does_not_wake_the_soldier() {
        let path = socket_path("malformed");
        let _ = std::fs::remove_file(&path);
        let trigger = Trigger::bind(&path).unwrap();
        let good = WakeSignal { threat_id: "def456".into(), pid: 7, schema: vec![Action::ExecFromTempOrCache] };
        let good_clone = good.clone();
        let path_clone = path.clone();
        thread::spawn(move || {
            let mut bad = UnixStream::connect(&path_clone).unwrap();
            bad.write_all(b"not json\n").unwrap();
            drop(bad);
            let mut ok = UnixStream::connect(&path_clone).unwrap();
            serde_json::to_writer(&mut ok, &good_clone).unwrap();
            ok.write_all(b"\n").unwrap();
        });
        assert_eq!(trigger.wait().unwrap(), good);
        let _ = std::fs::remove_file(&path);
    }
}
