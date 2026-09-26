//! FR-D-7 lineage rollup. A child joins its parent's lineage unless the parent
//! is a *boundary* (launchd, a login/session host, or an interactive shell),
//! in which case the child starts a new lineage. Without boundaries every
//! command typed in a terminal would accumulate into one trajectory.

use std::collections::{HashMap, HashSet};

use tes::schema::{Event, TesEvent};

/// Process identity `(pid, pidver)`; `pidver` discriminates a recycled PID.
pub type ProcKey = (u32, u64);
pub type LineageId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lineage {
    pub id: LineageId,
    pub root: ProcKey,
    pub root_exe: String,
    pub members: HashSet<ProcKey>,
}

#[derive(Debug, Clone, Copy)]
struct Node {
    lineage: LineageId,
    boundary: bool,
}

#[derive(Debug, Default)]
pub struct Lineages {
    nodes: HashMap<ProcKey, Node>,
    lineages: HashMap<LineageId, Lineage>,
    next_id: LineageId,
}

impl Lineages {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attributes `ev` to its actor's lineage (returned) and applies the
    /// fork/exec/exit bookkeeping it implies.
    pub fn observe(&mut self, ev: &TesEvent) -> LineageId {
        let key = (ev.proc.pid, ev.proc.pidver);
        let node = self.ensure(key, &ev.proc.exe);
        match &ev.event {
            Event::Fork(d) => {
                let child = (d.child_pid, d.child_pidver);
                let lineage = if node.boundary {
                    self.new_lineage(child, ev.proc.exe.clone())
                } else {
                    self.lineage_mut(node.lineage).members.insert(child);
                    node.lineage
                };
                self.nodes.insert(child, Node { lineage, boundary: false });
            }
            Event::Exec(d) => {
                let new_key = (ev.proc.pid, d.new_pidver);
                self.nodes.remove(&key);
                let l = self.lineage_mut(node.lineage);
                l.members.remove(&key);
                l.members.insert(new_key);
                if l.root == key {
                    l.root = new_key;
                    l.root_exe = d.target.clone();
                }
                let boundary = is_boundary(&d.target, Some(&d.args));
                self.nodes.insert(new_key, Node { lineage: node.lineage, boundary });
            }
            Event::Exit(_) => {
                self.nodes.remove(&key);
                self.lineage_mut(node.lineage).members.remove(&key);
            }
            _ => {}
        }
        node.lineage
    }

    pub fn get(&self, id: LineageId) -> Option<&Lineage> {
        self.lineages.get(&id)
    }

    pub fn live_pids(&self, id: LineageId) -> Vec<u32> {
        let mut pids: Vec<u32> = self
            .lineages
            .get(&id)
            .map(|l| l.members.iter().map(|&(pid, _)| pid).collect())
            .unwrap_or_default();
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    /// Drops a lineage with no live members. The caller decides whether its
    /// trajectory is still worth keeping before calling this.
    pub fn retire_if_empty(&mut self, id: LineageId) -> bool {
        let empty = self.lineages.get(&id).is_some_and(|l| l.members.is_empty());
        if empty {
            self.lineages.remove(&id);
        }
        empty
    }

    pub fn len(&self) -> usize {
        self.lineages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lineages.is_empty()
    }

    fn ensure(&mut self, key: ProcKey, exe: &str) -> Node {
        if let Some(node) = self.nodes.get(&key) {
            return *node;
        }
        let lineage = self.new_lineage(key, exe.to_owned());
        let node = Node { lineage, boundary: is_boundary(exe, None) };
        self.nodes.insert(key, node);
        node
    }

    fn new_lineage(&mut self, root: ProcKey, root_exe: String) -> LineageId {
        let id = self.next_id;
        self.next_id += 1;
        let members = HashSet::from([root]);
        self.lineages.insert(id, Lineage { id, root, root_exe, members });
        id
    }

    fn lineage_mut(&mut self, id: LineageId) -> &mut Lineage {
        self.lineages.get_mut(&id).expect("every node points at a live lineage")
    }
}

const SESSION_HOSTS: &[&str] = &[
    "/sbin/launchd",
    "/usr/bin/login",
    "/usr/sbin/sshd",
    "/usr/libexec/sshd-session",
    "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
    "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
    "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock",
    "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
    "/Applications/iTerm.app/Contents/MacOS/iTerm2",
];

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish"];

/// `args == None` means the process was first seen mid-life (no exec
/// observed); a shell seen that way is assumed interactive.
pub fn is_boundary(exe: &str, args: Option<&[String]>) -> bool {
    if SESSION_HOSTS.contains(&exe) {
        return true;
    }
    let name = exe.rsplit('/').next().unwrap_or(exe);
    if !SHELLS.contains(&name) {
        return false;
    }
    args.is_none_or(interactive_shell_args)
}

/// Interactive iff every argument after argv[0] is an option and none of
/// them runs a command string (`-c`) or reads a script from stdin (`-s`).
fn interactive_shell_args(args: &[String]) -> bool {
    args.iter().skip(1).all(|a| {
        if let Some(long) = a.strip_prefix("--") {
            !long.is_empty()
        } else if let Some(short) = a.strip_prefix('-') {
            !short.is_empty() && !short.contains(['c', 's'])
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tes::schema::{ExecData, ExitData, ForkData, OpenData, Proc};

    fn ev(pid: u32, pidver: u64, exe: &str, event: Event) -> TesEvent {
        TesEvent {
            v: 1,
            seq: 0,
            ts_ns: 0,
            recv_ns: 0,
            proc: Proc { pid, pidver, ppid: 1, exe: exe.into(), signing_id: None, team_id: None, platform: false },
            event,
        }
    }
    fn fork(pid: u32, ver: u64, exe: &str, child: u32, child_ver: u64) -> TesEvent {
        ev(pid, ver, exe, Event::Fork(ForkData { child_pid: child, child_pidver: child_ver }))
    }
    fn exec(pid: u32, ver: u64, exe: &str, target: &str, args: &[&str], new_ver: u64) -> TesEvent {
        let args = args.iter().map(|s| s.to_string()).collect();
        ev(pid, ver, exe, Event::Exec(ExecData { target: target.into(), args, new_pidver: new_ver }))
    }
    fn exit(pid: u32, ver: u64, exe: &str) -> TesEvent {
        ev(pid, ver, exe, Event::Exit(ExitData { status: 0 }))
    }
    fn write(pid: u32, ver: u64, exe: &str) -> TesEvent {
        ev(pid, ver, exe, Event::Open(OpenData { path: "/f".into(), write: true }))
    }

    #[test]
    fn children_of_non_boundary_roll_up_across_generations() {
        let mut l = Lineages::new();
        let root = l.observe(&fork(100, 1, "/tmp/evil", 101, 1));
        assert_eq!(l.observe(&fork(101, 1, "/tmp/evil", 102, 1)), root);
        assert_eq!(l.observe(&write(102, 1, "/tmp/evil")), root);
        assert_eq!(l.live_pids(root), [100, 101, 102]);
    }

    #[test]
    fn exec_rekeys_by_new_pidver_and_keeps_lineage() {
        let mut l = Lineages::new();
        let id = l.observe(&fork(100, 1, "/tmp/evil", 101, 5));
        assert_eq!(l.observe(&exec(101, 5, "/tmp/evil", "/bin/sh", &["sh", "-c", "x"], 6)), id);
        assert_eq!(l.observe(&write(101, 6, "/bin/sh")), id, "post-exec identity must resolve");
        assert!(!l.get(id).unwrap().members.contains(&(101, 5)));
    }

    #[test]
    fn root_exec_moves_the_root() {
        let mut l = Lineages::new();
        let id = l.observe(&exec(100, 1, "/bin/zsh", "/tmp/evil", &["/tmp/evil"], 2));
        let lin = l.get(id).unwrap();
        assert_eq!((lin.root, lin.root_exe.as_str()), ((100, 2), "/tmp/evil"));
    }

    #[test]
    fn trajectory_survives_root_exit() {
        let mut l = Lineages::new();
        let id = l.observe(&fork(100, 1, "/tmp/evil", 101, 1));
        l.observe(&exit(100, 1, "/tmp/evil"));
        assert_eq!(l.observe(&write(101, 1, "/tmp/evil")), id);
        assert_eq!(l.live_pids(id), [101]);
        assert!(!l.retire_if_empty(id));
        l.observe(&exit(101, 1, "/tmp/evil"));
        assert!(l.retire_if_empty(id));
        assert!(l.get(id).is_none());
    }

    #[test]
    fn interactive_shell_isolates_typed_commands_but_scripts_roll_up() {
        let mut l = Lineages::new();
        let shell = l.observe(&exec(50, 1, "/usr/bin/login", "/bin/zsh", &["-zsh"], 2));
        let a = l.observe(&fork(50, 2, "/bin/zsh", 60, 1));
        let b = l.observe(&fork(50, 2, "/bin/zsh", 61, 1));
        assert_eq!(a, shell, "the fork itself is the shell's own action");
        assert_eq!(b, shell);
        let first_cmd = l.observe(&write(60, 1, "/bin/zsh"));
        let second_cmd = l.observe(&write(61, 1, "/bin/zsh"));
        assert_ne!(first_cmd, shell);
        assert_ne!(first_cmd, second_cmd, "each typed command is its own lineage");

        l.observe(&exec(61, 1, "/bin/zsh", "/bin/bash", &["bash", "/tmp/evil.sh"], 2));
        l.observe(&fork(61, 2, "/bin/bash", 62, 1));
        assert_eq!(l.observe(&write(62, 1, "/usr/bin/openssl")), second_cmd, "children of a script-running shell roll up");
    }

    #[test]
    fn launchd_children_are_separate_lineages() {
        let mut l = Lineages::new();
        l.observe(&fork(1, 1, "/sbin/launchd", 200, 1));
        l.observe(&fork(1, 1, "/sbin/launchd", 201, 1));
        assert_ne!(l.observe(&write(200, 1, "/sbin/launchd")), l.observe(&write(201, 1, "/sbin/launchd")));
    }

    #[test]
    fn recycled_pid_with_new_pidver_is_a_different_process() {
        let mut l = Lineages::new();
        let first = l.observe(&write(300, 1, "/tmp/a"));
        l.observe(&exit(300, 1, "/tmp/a"));
        assert_ne!(l.observe(&write(300, 9, "/tmp/b")), first);
    }

    #[test]
    fn boundary_rules() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_boundary("/bin/zsh", None));
        assert!(is_boundary("/bin/zsh", Some(&a(&["-zsh"]))));
        assert!(is_boundary("/bin/bash", Some(&a(&["bash", "-l", "--noprofile"]))));
        assert!(!is_boundary("/bin/bash", Some(&a(&["bash", "/tmp/x.sh"]))));
        assert!(!is_boundary("/bin/sh", Some(&a(&["sh", "-c", "ls"]))));
        assert!(!is_boundary("/bin/bash", Some(&a(&["bash", "-lc", "ls"]))));
        assert!(!is_boundary("/bin/bash", Some(&a(&["bash", "-s"]))));
        assert!(!is_boundary("/bin/bash", Some(&a(&["bash", "--", "x"]))));
        assert!(is_boundary("/sbin/launchd", Some(&a(&["launchd"]))));
        assert!(!is_boundary("/usr/bin/python3", None));
    }
}
