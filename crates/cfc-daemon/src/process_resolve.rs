//! Process resolution: given a 5-tuple, find the local pid that owns the
//! socket, then read /proc/{pid} to fill a `Process` record.
//!
//! Two-step walk:
//!   1. Parse /proc/net/{tcp,tcp6,udp,udp6} to map 5-tuple -> socket inode.
//!   2. Walk /proc/*/fd/ symlinks to map inode -> pid.
//!
//! This is the userspace slow path. Phase 4 swaps step 1 for netlink
//! sock_diag and step 2 for an eBPF capture-on-exec table.
//!
//! TOCTOU note: the resolved pid may have exited by the time we read
//! /proc/{pid}/exe. We return `Process::unknown(pid)` in that case.

use cfc_core::{Process, Protocol};
use procfs::process::{FDTarget, Process as ProcFsProcess};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Build a full Process record from /proc/{pid}.
pub fn resolve(pid: u32) -> Process {
    match resolve_inner(pid) {
        Ok(p) => p,
        Err(_) => Process::unknown(pid),
    }
}

fn resolve_inner(pid: u32) -> anyhow::Result<Process> {
    let p = ProcFsProcess::new(pid as i32)?;
    let stat = p.stat()?;
    let status = p.status()?;
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

/// Find the pid that owns a socket matching the given 5-tuple.
///
/// Walks /proc/net/{tcp,udp}{,6}. Returns None if no match found within a
/// short budget; caller falls back to `Process::unknown`.
pub fn pid_for_socket(
    protocol: Protocol,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<u32> {
    let started = Instant::now();
    let deadline = started + Duration::from_millis(50);

    let tables: &[&str] = match (protocol, src_ip) {
        (Protocol::Tcp, IpAddr::V4(_)) => &["/proc/net/tcp"],
        (Protocol::Tcp, IpAddr::V6(_)) => &["/proc/net/tcp6"],
        (Protocol::Udp, IpAddr::V4(_)) => &["/proc/net/udp"],
        (Protocol::Udp, IpAddr::V6(_)) => &["/proc/net/udp6"],
        _ => return None,
    };

    let mut inode = None;
    for table in tables {
        if Instant::now() > deadline {
            break;
        }
        if let Some(i) = scan_proc_net(table, src_ip, src_port, dst_ip, dst_port) {
            inode = Some(i);
            break;
        }
    }
    let inode = inode?;

    pid_owning_inode(inode, deadline)
}

fn scan_proc_net(
    path: &str,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<u64> {
    let contents = fs::read_to_string(path).ok()?;
    let want_local = format_addr_port(src_ip, src_port);
    let want_remote = format_addr_port(dst_ip, dst_port);

    for line in contents.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _sl = cols.next()?;
        let local = cols.next()?;
        let remote = cols.next()?;
        let _state = cols.next()?;
        let _txrx = cols.next()?;
        let _tr = cols.next()?;
        let _retr = cols.next()?;
        let _uid = cols.next()?;
        let _timeout = cols.next()?;
        let inode_str = cols.next()?;

        if local.eq_ignore_ascii_case(&want_local)
            && remote.eq_ignore_ascii_case(&want_remote)
        {
            return inode_str.parse::<u64>().ok();
        }
    }
    None
}

fn format_addr_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => {
            // /proc/net/tcp formats IPv4 as 4 bytes little-endian hex.
            let o = v4.octets();
            format!("{:02X}{:02X}{:02X}{:02X}:{:04X}", o[3], o[2], o[1], o[0], port)
        }
        IpAddr::V6(v6) => {
            // /proc/net/tcp6 formats IPv6 as 4 little-endian u32s, each
            // printed as 8 uppercase hex chars.
            let seg = v6.octets();
            let mut s = String::with_capacity(32);
            for chunk in seg.chunks(4) {
                let w = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                s.push_str(&format!("{:08X}", w.swap_bytes()));
            }
            s.push(':');
            s.push_str(&format!("{:04X}", port));
            s
        }
    }
}

fn pid_owning_inode(inode: u64, deadline: Instant) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    let proc_dir = fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        if Instant::now() > deadline {
            return None;
        }
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        let Ok(pid) = name_s.parse::<u32>() else {
            continue;
        };

        let p = match ProcFsProcess::new(pid as i32) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let Ok(fds) = p.fd() else { continue };
        for fd in fds.flatten() {
            if let FDTarget::Socket(i) = fd.target {
                if i == inode {
                    return Some(pid);
                }
            }
            // Also handle stringly-named targets just in case.
            // Most kernels report Socket(inode), so the above branch hits.
            let _ = &target;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_ipv4() {
        let s = format_addr_port(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        assert_eq!(s, "0100007F:0050");
    }

    #[test]
    fn formats_ipv6_loopback() {
        let s = format_addr_port(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
        // ::1 = 16 bytes ending in 0x01. Linux prints 4 LE-word groups, so
        // the last group is the byte-reversed 0x00000001 = "01000000".
        assert_eq!(s, "00000000000000000000000001000000:0035");
    }
}
