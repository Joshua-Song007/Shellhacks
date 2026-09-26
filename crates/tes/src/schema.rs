use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TesEvent {
    pub v: u32,
    pub seq: u64,
    pub ts_ns: u64,
    pub recv_ns: u64,
    pub proc: Proc,
    pub event: Event,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proc {
    pub pid: u32,
    pub pidver: u64,
    pub ppid: u32,
    pub exe: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    pub platform: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "lowercase",
    deny_unknown_fields
)]
pub enum Event {
    Exec(ExecData),
    Fork(ForkData),
    Exit(ExitData),
    Open(OpenData),
    Create(PathData),
    Rename(RenameData),
    Unlink(PathData),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecData {
    pub target: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkData {
    pub child_pid: u32,
    pub child_pidver: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitData {
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenData {
    pub path: String,
    pub write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathData {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameData {
    pub from: String,
    pub to: String,
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Event::Exec(_) => "exec",
            Event::Fork(_) => "fork",
            Event::Exit(_) => "exit",
            Event::Open(_) => "open",
            Event::Create(_) => "create",
            Event::Rename(_) => "rename",
            Event::Unlink(_) => "unlink",
        }
    }

    pub fn paths(&self) -> Vec<&str> {
        match self {
            Event::Exec(d) => vec![&d.target],
            Event::Open(d) => vec![&d.path],
            Event::Create(d) | Event::Unlink(d) => vec![&d.path],
            Event::Rename(d) => vec![&d.from, &d.to],
            Event::Fork(_) | Event::Exit(_) => vec![],
        }
    }
}

impl TesEvent {
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("TES event serialization is infallible")
    }
}
