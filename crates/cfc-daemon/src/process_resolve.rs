//! Process resolution: given a (pid, socket inode) pair from netlink, build
//! a Process record by reading /proc.
//!
//! TOCTOU note: between the packet arriving and us reading /proc/{pid}/exe,
//! the process may have died. We return Process::unknown(pid) in that case
//! and the decision engine treats it as low-confidence.
//!
//! Phase 4 will replace most of this with an eBPF capture-on-exec table.

use anyhow::Context;
use cfc_core::Process;
use procfs::process::Process as ProcFsProcess;
use std::path::PathBuf;

pub fn resolve(pid: u32) -> Process {
    match resolve_inner(pid) {
        Ok(p) => p,
        Err(_) => Process::unknown(pid),
    }
}

fn resolve_inner(pid: u32) -> anyhow::Result<Process> {
    let p = ProcFsProcess::new(pid as i32).context("opening /proc/{pid}")?;
    let stat = p.stat().context("reading stat")?;
    let status = p.status().context("reading status")?;
    let exe = p.exe().unwrap_or_else(|_| PathBuf::from("<deleted>"));
    let cmdline = p.cmdline().unwrap_or_default();
    let cwd = p.cwd().ok();

    Ok(Process {
        pid,
        ppid: Some(stat.ppid as u32),
        uid: status.ruid,
        gid: status.rgid,
        exe,
        cmdline,
        cwd,
        sha256: None,
        started_at: None,
    })
}

/// Locate the pid that owns a given socket inode.
///
/// Walks /proc/*/fd/* looking for a symlink target like `socket:[12345]`.
/// O(N) over all open fds in the system - cache aggressively in Phase 4.
pub fn pid_for_socket_inode(_inode: u64) -> Option<u32> {
    // TODO: implement /proc walk. Stub for the scaffold.
    None
}
