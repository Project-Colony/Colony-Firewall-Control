//! Process: the local actor that owns a Connection.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Package provenance of a process's executable: "does this binary still
/// match what the distribution installed?"
///
/// This is the Linux answer to Windows Firewall Control's
/// `Signed: Yes (Canon Inc.)` line. Instead of a code signature we lean on
/// the system package manager, which already records a cryptographic digest
/// for every file it installed.
///
/// The comparison is deliberately asymmetric: the digest we compare comes
/// from the *running* binary (hashed through `/proc/<pid>/exe`, i.e. the
/// bytes the kernel actually mapped) while the recorded digest describes the
/// package's file at that path. [`Provenance::Modified`] therefore means
/// "the thing that is running is not the thing the package shipped" - a
/// patched, replaced or trojaned binary - which is exactly the signal worth
/// raising.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Provenance {
    /// Not checked, no package database on this host, the lookup failed, or
    /// the owning package is known but records no digest we can verify
    /// against (see [`Process::package`] - it is `Some` in that last case).
    #[default]
    Unknown,
    /// No installed package owns this path. The interesting case: a binary
    /// running out of /tmp, /home or a downloaded tarball.
    Unpackaged,
    /// A package owns this path and the running binary's sha256 matches the
    /// digest the package recorded.
    Verified,
    /// A package owns this path but the running binary's sha256 differs from
    /// the recorded one. Security-relevant; surface it loudly.
    Modified,
}

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
    /// Package that owns `exe`, as `"<name> <version>"`
    /// (e.g. `"curl 8.21.0-1"`). `None` when no package owns the path, when
    /// there is no package database, or when the lookup was skipped.
    ///
    /// `#[serde(default)]`: rules and events serialized by builds predating
    /// provenance must keep deserializing.
    #[serde(default)]
    pub package: Option<String>,
    /// Whether the running binary still matches the package record. See
    /// [`Provenance`].
    #[serde(default)]
    pub provenance: Provenance,
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
            package: None,
            provenance: Provenance::Unknown,
        }
    }

    pub fn display_name(&self) -> String {
        self.exe
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("pid:{}", self.pid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_process_claims_no_provenance() {
        let p = Process::unknown(7);
        assert_eq!(p.package, None);
        assert_eq!(p.provenance, Provenance::Unknown);
    }

    #[test]
    fn old_serialized_processes_still_deserialize() {
        // A record written before provenance existed: the two new fields
        // are absent and must default rather than fail the whole load.
        let json = r#"{
            "pid": 42, "ppid": 1, "uid": 1000, "gid": 1000,
            "exe": "/usr/bin/curl", "cmdline": ["curl"], "cwd": "/home/u",
            "sha256": "abc", "started_at": null
        }"#;
        let p: Process = serde_json::from_str(json).unwrap();
        assert_eq!(p.pid, 42);
        assert_eq!(p.package, None);
        assert_eq!(p.provenance, Provenance::Unknown);
    }

    #[test]
    fn provenance_round_trips_through_json() {
        for v in [
            Provenance::Unknown,
            Provenance::Unpackaged,
            Provenance::Verified,
            Provenance::Modified,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            assert_eq!(serde_json::from_str::<Provenance>(&s).unwrap(), v);
        }
    }
}
