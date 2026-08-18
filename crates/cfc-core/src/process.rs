//! Process: the local actor that owns a Connection.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub ppid: Option<u32>,
    /// `None` means the process could not be attributed (e.g. it exited
    /// before /proc was read). It is deliberately not 0: fabricating uid 0
    /// would make uid-scoped rules for root match unattributed traffic.
    pub uid: Option<u32>,
    /// See `uid`: `None` means unknown, never a fabricated gid.
    pub gid: Option<u32>,
    pub exe: PathBuf,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub sha256: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Process {
    pub fn unknown(pid: u32) -> Self {
        Self {
            pid,
            ppid: None,
            uid: None,
            gid: None,
            exe: PathBuf::from("<unknown>"),
            cmdline: Vec::new(),
            cwd: None,
            sha256: None,
            started_at: None,
        }
    }

    pub fn display_name(&self) -> String {
        self.exe
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("pid:{}", self.pid))
    }
}
