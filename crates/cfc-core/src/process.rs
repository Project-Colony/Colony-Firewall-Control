//! Process: the local actor that owns a Connection.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
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
            uid: 0,
            gid: 0,
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
