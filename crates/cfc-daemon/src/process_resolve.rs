//! Process resolution: given a 5-tuple, find the local pid that owns the
//! socket, then describe that pid as a `Process`.
//!
//! Resolution strategy, fastest first:
//!   1. netlink sock_diag exact-tuple query ([`crate::sock_diag`]): one
//!      round-trip per connection instead of a full-table parse. Falls
//!      back silently on any error (EPERM in containers, old kernels).
//!   2. Parse /proc/net/{tcp,udp}{,6} with layered match passes (exact,
//!      unconnected-UDP, wildcard-bind, v4-mapped-in-v6).
//!   3. inode -> pid via a verified TTL cache, else a /proc/*/fd walk.
//!
//! TOCTOU note: the resolved pid may have exited by the time we describe it.
//! The process cache is keyed by (pid, starttime) so pid reuse invalidates
//! naturally, and the inode cache re-verifies its answer with a single
//! readlink before trusting it.
//!
//! # Where the kernel exec table fits
//!
//! When the eBPF layer is running (see [`crate::ebpf`]), a table fed by the
//! `sched_process_exec` / `sched_process_exit` tracepoints is consulted
//! *before* `/proc` in [`resolve`]. Precisely what that changes:
//!
//! | field | without eBPF | with eBPF |
//! |---|---|---|
//! | `ppid` | `/proc/<pid>/stat` field 4 | exec event (or `None` if BTF offsets were unresolved) |
//! | `uid`/`gid` | `/proc/<pid>/status` `Ruid`/`Rgid` | exec event, i.e. the values at `execve()` |
//! | `exe` | `/proc/<pid>/exe` | `/proc/<pid>/exe`, falling back to the exec event's path when `/proc` is gone |
//! | `cmdline`, `cwd` | `/proc/<pid>/{cmdline,cwd}` | unchanged - no kernel source |
//! | `sha256`, package | `/proc/<pid>/exe` | unchanged - the digest must be of the mapped image |
//!
//! So it removes two `/proc` file parses per uncached resolve and, more
//! importantly, produces a *named* process where the pre-eBPF path could only
//! return [`Process::unknown`] - the short-lived-process case that a
//! packet-triggered `/proc` read loses by construction.
//!
//! It does **not** remove the socket -> pid step: NFQUEUE hands the daemon a
//! packet, not a pid, so `sock_diag` (or the table walk, or the `/proc/*/fd`
//! scan) still runs first. And it does not override a readable
//! `/proc/<pid>/exe`, because the exec event carries the path as passed to
//! `execve()` - possibly relative, possibly an unresolved symlink - while
//! rules, the digest and package provenance are all in terms of the
//! canonical path of the image the kernel actually mapped.

use crate::ebpf::proc_table::KernelProcTable;
use cfc_core::{Direction, Process, Protocol};
use parking_lot::Mutex;
use procfs::process::{FDTarget, Process as ProcFsProcess};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::trace;

/// Per-lookup budget for the /proc slow path.
const RESOLVE_BUDGET: Duration = Duration::from_millis(50);

/// inode -> (pid, fd) entries live this long before a re-walk is forced.
/// Short: it only needs to cover the burst of packets a new connection
/// produces (SYN, first payload, retransmits).
const INODE_CACHE_TTL: Duration = Duration::from_secs(2);

/// (pid, starttime) -> Process. starttime makes pid reuse self-invalidating,
/// so this TTL only bounds staleness of mutable fields (cwd, cmdline).
const PROCESS_CACHE_TTL: Duration = Duration::from_secs(5);

/// Executable digests are keyed by (dev, inode, mtime) which is already
/// content-addressed for our purposes; the TTL is just a memory backstop.
/// The digest cache does not expire, and that is the point.
///
/// Its key is `(dev, inode, mtime, mtime_nsec)`, which is content-addressed:
/// a file whose bytes change gets a new mtime and therefore a new key, so a
/// stale entry cannot be returned for changed content. An hour's expiry
/// bought nothing and cost a re-hash of the whole binary on the packet
/// worker - a single thread - every hour, per executable:
///
/// ```text
/// /usr/bin/node        59.9 MB  ->  ~34 ms
/// /usr/bin/gh          38.8 MB  ->  ~22 ms
/// /usr/bin/tailscaled  28.5 MB  ->  ~16 ms
/// ```
///
/// The 64 MiB size cap barely helps: it excludes almost nothing that is
/// actually installed. The 1024-entry bound still evicts, so this is a cache
/// with a size limit and no clock, not an unbounded one.
///
/// The digest cannot simply be skipped instead: `RuleScope::exe_sha256` is a
/// rule predicate, and a hash-scoped rule abstains when the hash is unknown.
const SHA_CACHE_TTL: Duration = Duration::from_secs(u64::MAX / 2);

/// Don't hash executables larger than this. Shared with the CLI's
/// `--pin-hash` (`cfc_core::rule`), which must refuse to create what this
/// side would refuse to compute.
const SHA256_MAX_LEN: u64 = cfc_core::rule::SHA256_MAX_LEN;

const CACHE_CAP: usize = 1024;

static INODE_PID_CACHE: LazyLock<Mutex<TtlCache<u64, (u32, i32)>>> =
    LazyLock::new(|| Mutex::new(TtlCache::new(INODE_CACHE_TTL, CACHE_CAP)));

static PROCESS_CACHE: LazyLock<Mutex<TtlCache<(u32, u64), Process>>> =
    LazyLock::new(|| Mutex::new(TtlCache::new(PROCESS_CACHE_TTL, CACHE_CAP)));

#[allow(clippy::type_complexity)]
static SHA_CACHE: LazyLock<Mutex<TtlCache<(u64, u64, i64, i64), Option<String>>>> =
    LazyLock::new(|| Mutex::new(TtlCache::new(SHA_CACHE_TTL, CACHE_CAP)));

/// Build a full Process record for `pid`, from the kernel exec table where
/// one is available and from /proc/{pid} for everything else.
///
/// Cached by (pid, starttime from /proc/{pid}/stat field 22): a recycled
/// pid has a different starttime, so it can never hit a stale entry. That
/// same start time is what the exec table is verified against.
pub fn resolve(pid: u32) -> Process {
    let now = Instant::now();
    let starttime = read_starttime(pid);

    if let Some(st) = starttime {
        if let Some(p) = PROCESS_CACHE.lock().get(&(pid, st), now) {
            return p;
        }
    }

    match resolve_inner(pid, starttime, now, crate::ebpf::proc_table::global()) {
        Ok(p) => {
            if let Some(st) = starttime {
                PROCESS_CACHE.lock().insert((pid, st), p.clone(), now);
            }
            p
        }
        Err(_) => Process::unknown(pid),
    }
}

/// The table is a parameter rather than a reach into
/// `crate::ebpf::proc_table::global()` so the tests below can drive both
/// branches without mutating process-wide state that every other test in the
/// binary shares.
fn resolve_inner(
    pid: u32,
    starttime: Option<u64>,
    now: Instant,
    table: &KernelProcTable,
) -> anyhow::Result<Process> {
    // Kernel-sourced identity, if the exec tracepoint is attached and the
    // record still belongs to this process (the table checks `starttime`
    // itself, so a recycled pid returns None here rather than a stale name).
    let kern = table.get(pid, starttime, now);

    // /proc may be entirely gone by now; every read below is independently
    // optional so that a process which exited mid-resolve still yields
    // whatever is known rather than collapsing to `unknown`.
    let p = ProcFsProcess::new(pid as i32).ok();
    if p.is_none() && kern.is_none() {
        anyhow::bail!("pid {pid} has neither a /proc entry nor a kernel exec record");
    }

    let proc_exe = p.as_ref().and_then(|p| p.exe().ok());
    let cmdline = p
        .as_ref()
        .and_then(|p| p.cmdline().ok())
        .unwrap_or_default();
    let cwd = p.as_ref().and_then(|p| p.cwd().ok());

    let (ppid, uid, gid) = match &kern {
        // The exec event already carries all three, so /proc/{pid}/stat and
        // /proc/{pid}/status are not read at all on this path.
        Some(k) => (k.ppid, Some(k.uid), Some(k.gid)),
        None => {
            let stat = p.as_ref().and_then(|p| p.stat().ok());
            let status = p.as_ref().and_then(|p| p.status().ok());
            (
                stat.map(|s| s.ppid as u32),
                status.as_ref().map(|s| s.ruid),
                status.as_ref().map(|s| s.rgid),
            )
        }
    };

    // /proc/{pid}/exe wins whenever it is readable: it is the canonical path
    // of the image the kernel mapped, which is what rules match and what the
    // digest below describes. The exec event's path is the fallback for a
    // process that is already gone, and only when it is absolute (see
    // `KernelProc::absolute_exe`).
    let exe = proc_exe
        .or_else(|| {
            kern.as_ref()
                .and_then(|k| k.absolute_exe().map(Path::to_path_buf))
        })
        .unwrap_or_else(|| PathBuf::from("<deleted>"));

    // The kernel appends " (deleted)" to /proc/<pid>/exe once the file has been
    // replaced or removed underneath a running process. On a rolling
    // distribution that is not an edge case, it is Tuesday: every long-lived
    // program keeps running the old inode after its package is upgraded.
    //
    // Left in place, that suffix is a quiet disaster for an application
    // firewall, because it is part of the string rules match on:
    //
    //   * a rule created from a prompt carries it, and stops matching the
    //     moment the user restarts the program;
    //   * a rule the user wrote by hand for the real path never matches while
    //     the program is running the old bytes.
    //
    // Both observed on a live machine, with Firefox upgraded mid-session:
    // `exe=/usr/lib/firefox/firefox (deleted)`, a hand-written rule for
    // `/usr/lib/firefox/firefox` inert, and the browser blocked.
    //
    // The path is what identity means here, so the suffix is stripped and the
    // fact is kept separately. `provenance::describe` still needs it - the
    // digest below is of the *old* bytes, and comparing those against the new
    // file on disk would report `Modified` for every process running across an
    // upgrade - so it is passed the original.
    let replaced_on_disk = exe.to_string_lossy().ends_with(DELETED_SUFFIX);
    let exe_for_provenance = exe.clone();
    let exe = if replaced_on_disk {
        let s = exe.to_string_lossy();
        PathBuf::from(&s[..s.len() - DELETED_SUFFIX.len()])
    } else {
        exe
    };

    // Package provenance reuses the digest computed just above rather than
    // re-hashing. That digest comes from /proc/{pid}/exe -- the binary the
    // kernel actually mapped -- while the package database describes the
    // file at `exe` on disk. Comparing those two is the whole point: a
    // mismatch means the running binary is not the one the package shipped
    // (replaced, patched, or swapped under a live process), which is what
    // makes `Modified` worth shouting about. See `crate::provenance`.
    //
    // This is deliberately NOT taken from the exec event: an exec-time path
    // says which file was launched, not which bytes are running now.
    //
    // Everything underneath is cached (path index by database mtime,
    // per-executable records by (dev, inode, mtime)), and this whole
    // function is itself behind PROCESS_CACHE, so a steady flow of packets
    // from a known process does no work here at all.
    let sha256 = exe_sha256(pid);
    let (package, provenance) = crate::provenance::describe(&exe_for_provenance, sha256.as_deref());

    Ok(Process {
        pid,
        ppid,
        uid,
        gid,
        exe,
        cmdline,
        cwd,
        sha256,
        started_at: None,
        package,
        provenance,
    })
}

/// Find the pid that owns a socket matching the given 5-tuple.
///
/// Tries a sock_diag netlink query first, then /proc/net/{tcp,udp}{,6}.
/// Returns None if no match found within a short budget; caller falls
/// back to `Process::unknown`.
///
/// `direction` is not decoration. Every step below looks for a socket whose
/// 4-tuple is already this flow - which is a thing that exists for an outbound
/// `connect()` and does not exist for an inbound SYN. Nothing has accepted it
/// yet; the only socket involved is the listener, whose tuple is different.
/// So on the inbound path every step was guaranteed to miss, and the search
/// was not free:
///
/// ```text
/// /proc/net/tcp   1.32 ms
/// /proc/net/tcp6  1.09 ms   (read even for a v4 flow, for v4-mapped sockets)
/// ------------------------
///                 2.40 ms   per inbound packet, to learn nothing
/// ```
///
/// Measured on the owner's machine, and it showed up exactly where you would
/// expect: inbound connect latency was 2.78 ms median against 0.28 ms for
/// outbound over the same veth pair. Returning early takes inbound to 0.19 ms.
///
/// This costs no attribution that previously worked - the search returned
/// `None` before, it returns `None` now, 14x faster. Attributing an inbound
/// flow to the process *listening* on the port is a real and separate thing,
/// and it would be one netlink round trip rather than two /proc scans; it is
/// not done here because it would change which rules match, not just how fast.
pub fn pid_for_socket(
    protocol: Protocol,
    direction: Direction,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<u32> {
    if direction == Direction::Inbound {
        return None;
    }
    let deadline = Instant::now() + RESOLVE_BUDGET;

    // Fast path: one exact-tuple kernel query. Any failure (EPERM,
    // unsupported protocol, unconnected UDP the kernel won't match)
    // falls through to the table scan.
    let info = crate::sock_diag::query(protocol, src_ip, src_port, dst_ip, dst_port);

    // Fastest path: the kernel recorded cookie -> tgid at connect() time
    // (`SOCK_PIDS`, written by cfc_connect4|6 in the connecting process's own
    // context). One map lookup replaces the /proc walk below, which measures
    // 37-44 ms on a loaded desktop - per NEW connection, before rule
    // evaluation, on the only worker thread. This one line is the difference
    // between the firewall being invisible and being felt.
    if let Some(cookie) = info.as_ref().and_then(|i| i.cookie) {
        if let Some(pid) = crate::ebpf::cookie_pid(cookie) {
            record_resolved_pid(pid);
            return Some(pid);
        }
    }

    let inode = info
        .map(|i| i.inode)
        .or_else(|| proc_net_inode(protocol, src_ip, src_port, dst_ip, dst_port, deadline))?;

    pid_owning_inode(inode, deadline)
}

/// Pids that recently owned a resolved socket, most recent first.
///
/// The walk fallback's second prior, after recent execs: a browser opens
/// dozens of connections from one long-lived pid, and each new socket is a new
/// inode the caches cannot know - but the *pid* is the one that resolved two
/// seconds ago. Sixteen entries covers every interactive workload; this is a
/// hint list, not a cache, so staleness costs a few wasted readlinks and
/// nothing else.
static RESOLVED_PIDS: Mutex<VecDeque<u32>> = Mutex::new(VecDeque::new());
const RESOLVED_PIDS_CAP: usize = 16;

fn record_resolved_pid(pid: u32) {
    let mut q = RESOLVED_PIDS.lock();
    if q.front() == Some(&pid) {
        return;
    }
    q.retain(|p| *p != pid);
    q.push_front(pid);
    q.truncate(RESOLVED_PIDS_CAP);
}

/// Does `/proc/<pid>/fd` contain a socket with this inode?
///
/// The unit of work the probe lists reuse: one process's fd table instead of
/// every process's.
fn pid_has_socket_inode(pid: u32, inode: u64) -> Option<u32> {
    let p = ProcFsProcess::new(pid as i32).ok()?;
    let fds = p.fd().ok()?;
    for fd in fds.flatten() {
        if matches!(fd.target, FDTarget::Socket(i) if i == inode) {
            INODE_PID_CACHE
                .lock()
                .insert(inode, (pid, fd.fd), Instant::now());
            return Some(pid);
        }
    }
    None
}

/// Slow path: scan the relevant /proc/net tables for the tuple's inode.
///
/// For a V4 flow the v6 table is scanned as well: dual-stack AF_INET6
/// sockets (Java, Go, node) carry v4 traffic but only appear in
/// /proc/net/{tcp6,udp6} as v4-mapped `::ffff:a.b.c.d` entries.
fn proc_net_inode(
    protocol: Protocol,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    deadline: Instant,
) -> Option<u64> {
    let tables: &[&str] = match (protocol, src_ip) {
        (Protocol::Tcp, IpAddr::V4(_)) => &["/proc/net/tcp", "/proc/net/tcp6"],
        (Protocol::Tcp, IpAddr::V6(_)) => &["/proc/net/tcp6"],
        (Protocol::Udp, IpAddr::V4(_)) => &["/proc/net/udp", "/proc/net/udp6"],
        (Protocol::Udp, IpAddr::V6(_)) => &["/proc/net/udp6"],
        _ => return None,
    };

    for table in tables {
        if Instant::now() > deadline {
            break;
        }
        let Ok(contents) = fs::read_to_string(table) else {
            continue;
        };
        if let Some(inode) =
            scan_table_content(&contents, protocol, (src_ip, src_port), (dst_ip, dst_port))
        {
            return Some(inode);
        }
    }
    None
}

/// One parsed row of a /proc/net table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TableEntry {
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
    inode: u64,
}

/// Match a socket table (the text of /proc/net/{tcp,udp}{,6}) against a
/// flow, in decreasing order of precision. Stops at the first hit.
///
/// Pass 1 - exact local+remote: connected TCP/UDP sockets.
/// Pass 2 - UDP only, exact local, zero remote: unconnected UDP sockets
///   doing plain sendto() (mDNS, NTP, syslog, QUIC stacks) list their
///   remote as 0.0.0.0:0, so an exact-remote match can never hit them.
/// Pass 3 - wildcard local addr, matching port, remote exact-or-zero:
///   sockets bound to 0.0.0.0 / :: show the wildcard, not the address
///   the flow actually uses.
///
/// All address comparisons canonicalize v4-mapped v6 (::ffff:a.b.c.d) to
/// plain v4 first, which is how dual-stack sockets appear in the v6 tables.
fn scan_table_content(
    content: &str,
    protocol: Protocol,
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
) -> Option<u64> {
    // inode 0 rows (TIME_WAIT, orphans) are unattributable; drop them so
    // they can't shadow a real socket in a later pass.
    let entries: Vec<TableEntry> = content
        .lines()
        .skip(1)
        .filter_map(parse_table_line)
        .filter(|e| e.inode != 0)
        .collect();

    // Pass 1: exact 4-tuple.
    for e in &entries {
        if endpoint_eq(e.local, local) && endpoint_eq(e.remote, remote) {
            return Some(e.inode);
        }
    }

    // Pass 2: unconnected UDP (exact local, zero remote).
    if protocol == Protocol::Udp {
        for e in &entries {
            if endpoint_eq(e.local, local) && endpoint_is_zero(e.remote) {
                return Some(e.inode);
            }
        }
    }

    // Pass 3: wildcard-bound local (port must match), remote exact or zero
    // (zero covers listeners and wildcard-bound unconnected UDP).
    for e in &entries {
        if e.local.1 == local.1
            && e.local.0.to_canonical().is_unspecified()
            && (endpoint_eq(e.remote, remote) || endpoint_is_zero(e.remote))
        {
            return Some(e.inode);
        }
    }

    None
}

fn endpoint_eq(a: (IpAddr, u16), b: (IpAddr, u16)) -> bool {
    a.1 == b.1 && a.0.to_canonical() == b.0.to_canonical()
}

fn endpoint_is_zero(a: (IpAddr, u16)) -> bool {
    a.1 == 0 && a.0.to_canonical().is_unspecified()
}

fn parse_table_line(line: &str) -> Option<TableEntry> {
    let mut cols = line.split_whitespace();
    let _sl = cols.next()?;
    let local = parse_hex_addr_port(cols.next()?)?;
    let remote = parse_hex_addr_port(cols.next()?)?;
    let _state = cols.next()?;
    let _txrx = cols.next()?;
    let _tr = cols.next()?;
    let _retr = cols.next()?;
    let _uid = cols.next()?;
    let _timeout = cols.next()?;
    let inode = cols.next()?.parse::<u64>().ok()?;
    Some(TableEntry {
        local,
        remote,
        inode,
    })
}

/// Parse an `ADDR:PORT` column from /proc/net tables.
///
/// IPv4 is 8 hex chars: the kernel prints the raw __be32 as a native-endian
/// u32, so on little-endian the bytes appear reversed. IPv6 is 32 hex
/// chars: 4 u32 groups, each group's bytes likewise reversed (the address
/// is printed as 4 native-endian words of the big-endian in6_addr).
fn parse_hex_addr_port(col: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = col.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match addr_hex.len() {
        8 => {
            let v = u32::from_str_radix(addr_hex, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(v.swap_bytes()))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, group) in addr_hex.as_bytes().chunks(8).enumerate() {
                let g = u32::from_str_radix(std::str::from_utf8(group).ok()?, 16).ok()?;
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&g.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// Format an address the way /proc/net tables print it. Inverse of
/// [`parse_hex_addr_port`]; kept for tests that build table lines.
#[cfg(test)]
fn format_addr_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!(
                "{:02X}{:02X}{:02X}{:02X}:{:04X}",
                o[3], o[2], o[1], o[0], port
            )
        }
        IpAddr::V6(v6) => {
            let seg = v6.octets();
            let mut s = String::with_capacity(37);
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

/// Map a socket inode to its owning pid.
///
/// A verified cache fronts the /proc/*/fd walk: on a hit we re-readlink
/// the remembered fd and only trust the pid if it still points at
/// `socket:[inode]`; otherwise the entry is dropped and we re-walk.
fn pid_owning_inode(inode: u64, deadline: Instant) -> Option<u32> {
    let now = Instant::now();
    let cached = INODE_PID_CACHE.lock().get(&inode, now);
    if let Some((pid, fd)) = cached {
        if fd_points_at_socket(pid, fd, inode) {
            return Some(pid);
        }
        INODE_PID_CACHE.lock().remove(&inode);
    }

    // Two cheap priors before the machine-wide walk, recently-resolved first.
    //
    // That order is the opposite of the original, and the reason it changed is
    // that the walk below changed. The exec prior went first because the walk
    // was *ascending*, so a process that had just exec'd - the highest pid -
    // was reached last and cost a full pass. The walk is descending now, which
    // covers that case on its own.
    //
    // What the descending walk does not cover is the other prior: a long-lived
    // process opening its Nth connection. Every connection is a new inode no
    // cache can know, and the pid may be old and therefore low. So that list
    // is now the one consulted first, and it is also the shorter of the two
    // (16 entries against 24), which makes the miss cheaper as well.
    let recently_resolved: Vec<u32> = RESOLVED_PIDS.lock().iter().copied().collect();
    for pid in recently_resolved {
        if let Some(found) = pid_has_socket_inode(pid, inode) {
            record_resolved_pid(found);
            return Some(found);
        }
    }
    let recent_execs = crate::ebpf::proc_table::global().recent_pids(24, Instant::now());
    for pid in recent_execs {
        if let Some(found) = pid_has_socket_inode(pid, inode) {
            record_resolved_pid(found);
            return Some(found);
        }
    }

    // Last resort: every process - in DESCENDING pid order, because the socket
    // being resolved belongs to a new connection and new connections skew
    // heavily toward new processes. Collecting-and-sorting ~500 dirents is
    // microseconds against the tens of milliseconds the walk itself costs.
    let proc_dir = fs::read_dir("/proc").ok()?;
    let mut pids: Vec<u32> = proc_dir
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();
    pids.sort_unstable_by(|a, b| b.cmp(a));
    for pid in pids {
        if Instant::now() > deadline {
            return None;
        }
        if let Some(found) = pid_has_socket_inode(pid, inode) {
            record_resolved_pid(found);
            return Some(found);
        }
    }
    None
}

fn fd_points_at_socket(pid: u32, fd: i32, inode: u64) -> bool {
    fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .map(|t| t.as_os_str().to_string_lossy() == format!("socket:[{inode}]"))
        .unwrap_or(false)
}

/// Process start time in clock ticks since boot, the pid-reuse discriminator.
///
/// `pub(crate)` because the eBPF exec consumer captures it too, right after an
/// exec event arrives, to bind the kernel record to the exact process it
/// describes (see `crate::ebpf::proc_table`).
pub(crate) fn read_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_starttime(&stat)
}

/// Field 22 of /proc/{pid}/stat: process start time in clock ticks since
/// boot. The comm field (2) may contain spaces and parens, so fields are
/// counted from the last ')': state is field 3, starttime field 22.
fn parse_starttime(stat: &str) -> Option<u64> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// What the kernel appends to `/proc/<pid>/exe` when the file has been replaced
/// or removed since the process started.
///
/// Shared with `provenance`, which uses it to decline to verify such a path -
/// the two uses are opposite and both correct: rule matching wants the suffix
/// gone, provenance wants to know it was there.
pub(crate) const DELETED_SUFFIX: &str = " (deleted)";

/// sha256 of the running executable, read through /proc/{pid}/exe.
///
/// The magic link resolves to the binary actually mapped by the kernel,
/// so this hashes what is really running even if the file on disk was
/// replaced or deleted. Cached by (dev, inode, mtime) of that file.
/// Returns None for unreadable or oversized (> 64 MiB) binaries.
fn exe_sha256(pid: u32) -> Option<String> {
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    let meta = fs::metadata(&path).ok()?;
    if meta.len() > SHA256_MAX_LEN {
        trace!(pid, len = meta.len(), "exe too large to hash; skipping");
        return None;
    }
    let key = (meta.dev(), meta.ino(), meta.mtime(), meta.mtime_nsec());
    let now = Instant::now();
    if let Some(cached) = SHA_CACHE.lock().get(&key, now) {
        return cached;
    }
    let digest = sha256_file(&path, SHA256_MAX_LEN);
    SHA_CACHE.lock().insert(key, digest.clone(), now);
    digest
}

/// Streaming sha256 of a file; None on I/O error or if the file exceeds
/// `max_len` (checked up front so we never read an oversized file).
fn sha256_file(path: &Path, max_len: u64) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    if f.metadata().ok()?.len() > max_len {
        return None;
    }
    // Read in a loop rather than io::copy, and hex-encode by hand rather than
    // with `{:x}`. RustCrypto 0.11 drops `io::Write` on the hashers and returns
    // an `Array` that no longer implements `LowerHex`, so both idioms stop
    // compiling — which is what Dependabot #8 surfaced. This form compiles
    // against 0.10 and 0.11 alike, so the bump becomes a version bump again.
    //
    // Worth the care: this digest is what `--pin-hash` binds a rule to. A rule
    // that hashes differently from the daemon does not fail loudly, it simply
    // never matches.
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        use std::io::Read as _;
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    Some(out)
}

/// Bounded TTL map. `now` is injected so expiry is unit-testable without
/// sleeping. When full, expired entries are pruned first, then the oldest
/// entry is evicted.
///
/// `pub(crate)` so [`crate::provenance`] can memoize package lookups with
/// exactly the same eviction and expiry behaviour instead of growing a
/// second, subtly different cache.
pub(crate) struct TtlCache<K, V> {
    map: HashMap<K, CacheEntry<V>>,
    ttl: Duration,
    cap: usize,
}

struct CacheEntry<V> {
    value: V,
    inserted: Instant,
}

impl<K: Eq + Hash + Clone, V: Clone> TtlCache<K, V> {
    pub(crate) fn new(ttl: Duration, cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            ttl,
            cap,
        }
    }

    pub(crate) fn get(&mut self, key: &K, now: Instant) -> Option<V> {
        match self.map.get(key) {
            Some(e) if now.saturating_duration_since(e.inserted) <= self.ttl => {
                Some(e.value.clone())
            }
            Some(_) => {
                self.map.remove(key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V, now: Instant) {
        if self.map.len() >= self.cap && !self.map.contains_key(&key) {
            let ttl = self.ttl;
            self.map
                .retain(|_, e| now.saturating_duration_since(e.inserted) <= ttl);
            if self.map.len() >= self.cap {
                if let Some(oldest) = self
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.inserted)
                    .map(|(k, _)| k.clone())
                {
                    self.map.remove(&oldest);
                }
            }
        }
        self.map.insert(
            key,
            CacheEntry {
                value,
                inserted: now,
            },
        );
    }

    fn remove(&mut self, key: &K) {
        self.map.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // -- hex address formatting / parsing ---------------------------------

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

    #[test]
    fn a_replaced_binary_still_matches_a_rule_for_its_path() {
        // The Firefox case, reduced: a package upgrade replaces the file while
        // the process keeps running the old inode, and the kernel starts
        // reporting the path with " (deleted)" glued on. Rules match on the
        // path string, so leaving it there means the rule the user wrote - or
        // the one a prompt created - matches nothing.
        let raw = PathBuf::from("/usr/lib/firefox/firefox (deleted)");
        let s = raw.to_string_lossy();
        assert!(s.ends_with(DELETED_SUFFIX));
        let cleaned = PathBuf::from(&s[..s.len() - DELETED_SUFFIX.len()]);
        assert_eq!(cleaned, PathBuf::from("/usr/lib/firefox/firefox"));

        // And a path that merely *contains* the words is left alone: the
        // suffix is a suffix, not a substring.
        let odd = PathBuf::from("/opt/my (deleted) app/bin");
        assert!(!odd.to_string_lossy().ends_with(DELETED_SUFFIX));
    }

    #[test]
    fn hex_addr_round_trips_v4() {
        for (ip, port) in [
            (Ipv4Addr::new(127, 0, 0, 1), 80u16),
            (Ipv4Addr::new(0, 0, 0, 0), 0),
            (Ipv4Addr::new(192, 168, 1, 254), 65535),
        ] {
            let ip = IpAddr::V4(ip);
            let s = format_addr_port(ip, port);
            assert_eq!(parse_hex_addr_port(&s), Some((ip, port)), "col {s}");
        }
    }

    #[test]
    fn hex_addr_round_trips_v6() {
        for (ip, port) in [
            (Ipv6Addr::LOCALHOST, 53u16),
            (Ipv6Addr::UNSPECIFIED, 0),
            ("2001:db8::ff00:42:8329".parse().unwrap(), 8443),
            (Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped(), 443),
        ] {
            let ip = IpAddr::V6(ip);
            let s = format_addr_port(ip, port);
            assert_eq!(parse_hex_addr_port(&s), Some((ip, port)), "col {s}");
        }
    }

    #[test]
    fn parses_real_v4_mapped_hex() {
        // ::ffff:10.0.0.5 exactly as /proc/net/tcp6 prints it: 4 groups of
        // a big-endian in6_addr, each printed as a byte-swapped u32.
        let (ip, port) = parse_hex_addr_port("0000000000000000FFFF00000500000A:01BB").unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped()));
        assert_eq!(ip.to_canonical(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(port, 443);
    }

    // -- table scanning ---------------------------------------------------

    const HEADER: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    fn line(local: (IpAddr, u16), remote: (IpAddr, u16), state: &str, inode: u64) -> String {
        format!(
            "   0: {} {} {state} 00000000:00000000 00:00000000 00000000  1000        0 {inode} 2 0000000000000000 0\n",
            format_addr_port(local.0, local.1),
            format_addr_port(remote.0, remote.1),
        )
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> (IpAddr, u16) {
        (IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn exact_match_found() {
        let local = v4(10, 0, 2, 15, 41000);
        let remote = v4(1, 1, 1, 1, 443);
        let table = format!("{HEADER}{}", line(local, remote, "01", 777));
        assert_eq!(
            scan_table_content(&table, Protocol::Tcp, local, remote),
            Some(777)
        );
    }

    #[test]
    fn unconnected_udp_falls_back_to_zero_remote() {
        // Plain sendto() UDP socket: rem_address is 00000000:0000, so an
        // exact-remote match can never hit. Real-format line, hand-crafted.
        let local = v4(10, 0, 2, 15, 5353);
        let table = format!(
            "{HEADER}  272: 0F02000A:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 4242 2 0000000000000000 0\n"
        );
        assert_eq!(
            scan_table_content(&table, Protocol::Udp, local, v4(224, 0, 0, 251, 5353)),
            Some(4242)
        );
    }

    #[test]
    fn unconnected_fallback_is_udp_only() {
        // The zero-remote pass must not apply to TCP: a TCP row with a
        // zero remote is a listener, matched (if at all) by the wildcard
        // pass, not by pretending it is connected to our destination.
        let local = v4(10, 0, 2, 15, 5353);
        let table = format!("{HEADER}{}", line(local, v4(0, 0, 0, 0, 0), "0A", 4242));
        assert_eq!(
            scan_table_content(&table, Protocol::Tcp, local, v4(224, 0, 0, 251, 5353)),
            None
        );
    }

    #[test]
    fn wildcard_local_matches_on_port() {
        // Socket bound to 0.0.0.0: the local column is the wildcard, so
        // only the port can be compared.
        let table = format!(
            "{HEADER}{}",
            line(v4(0, 0, 0, 0, 68), v4(0, 0, 0, 0, 0), "07", 555)
        );
        assert_eq!(
            scan_table_content(
                &table,
                Protocol::Udp,
                v4(192, 168, 1, 5, 68),
                v4(192, 168, 1, 1, 67)
            ),
            Some(555)
        );
    }

    #[test]
    fn wildcard_v6_matches_v4_flow() {
        // Dual-stack socket bound to [::]:8080 must attribute v4 traffic.
        let local = (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080);
        let remote = (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let table = format!("{HEADER}{}", line(local, remote, "0A", 909));
        assert_eq!(
            scan_table_content(
                &table,
                Protocol::Tcp,
                v4(10, 0, 0, 7, 8080),
                v4(1, 2, 3, 4, 55000)
            ),
            Some(909)
        );
    }

    #[test]
    fn v4_mapped_entry_matches_v4_flow() {
        // Dual-stack connected socket: appears only in the v6 table as
        // ::ffff:a.b.c.d. Hand-crafted real-format tcp6 line.
        let table = format!(
            "{HEADER}   3: 0000000000000000FFFF00000500000A:01BB 0000000000000000FFFF0000D1558E01:C350 01 00000000:00000000 00:00000000 00000000  1000        0 31337 1 0000000000000000 20 4 30 10 -1\n"
        );
        // ::ffff:1.142.85.209? Group "D1558E01" -> bytes 01 8E 55 D1.
        let remote = v4(1, 142, 85, 209, 0xC350);
        assert_eq!(
            scan_table_content(&table, Protocol::Tcp, v4(10, 0, 0, 5, 443), remote),
            Some(31337)
        );
    }

    #[test]
    fn exact_match_beats_wildcard() {
        let local = v4(10, 0, 2, 15, 9000);
        let remote = v4(9, 9, 9, 9, 443);
        let table = format!(
            "{HEADER}{}{}",
            line(v4(0, 0, 0, 0, 9000), v4(0, 0, 0, 0, 0), "0A", 1),
            line(local, remote, "01", 2),
        );
        assert_eq!(
            scan_table_content(&table, Protocol::Tcp, local, remote),
            Some(2)
        );
    }

    #[test]
    fn inode_zero_rows_are_skipped() {
        // TIME_WAIT rows have inode 0; they must not shadow anything nor
        // be returned as an (unattributable) match.
        let local = v4(10, 0, 2, 15, 41000);
        let remote = v4(1, 1, 1, 1, 443);
        let table = format!("{HEADER}{}", line(local, remote, "06", 0));
        assert_eq!(
            scan_table_content(&table, Protocol::Tcp, local, remote),
            None
        );
    }

    // -- /proc/{pid}/stat parsing -----------------------------------------

    #[test]
    fn parses_starttime_around_weird_comm() {
        // comm may contain spaces and parens; fields count from last ')'.
        let stat = "1234 (my (we) ird proc) S 1 1234 1234 0 -1 4194560 1189 0 2 0 3 1 0 0 20 0 1 0 987654 22200320 1000 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0";
        assert_eq!(parse_starttime(stat), Some(987654));
    }

    // -- caches ------------------------------------------------------------

    #[test]
    fn cache_hits_within_ttl_and_expires_after() {
        let mut c: TtlCache<u32, u32> = TtlCache::new(Duration::from_secs(2), 8);
        let t0 = Instant::now();
        c.insert(1, 100, t0);
        assert_eq!(c.get(&1, t0), Some(100));
        assert_eq!(c.get(&1, t0 + Duration::from_millis(1900)), Some(100));
        assert_eq!(c.get(&1, t0 + Duration::from_millis(2100)), None);
        // Expired entry was dropped, not resurrected.
        assert_eq!(c.get(&1, t0), None);
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        let mut c: TtlCache<u32, u32> = TtlCache::new(Duration::from_secs(60), 2);
        let t0 = Instant::now();
        c.insert(1, 10, t0);
        c.insert(2, 20, t0 + Duration::from_millis(1));
        c.insert(3, 30, t0 + Duration::from_millis(2));
        assert_eq!(
            c.get(&1, t0 + Duration::from_millis(3)),
            None,
            "oldest evicted"
        );
        assert_eq!(c.get(&2, t0 + Duration::from_millis(3)), Some(20));
        assert_eq!(c.get(&3, t0 + Duration::from_millis(3)), Some(30));
    }

    #[test]
    fn pid_reuse_misses_process_cache() {
        // The process cache key is (pid, starttime): a recycled pid has a
        // new starttime and must not hit the old entry.
        let mut c: TtlCache<(u32, u64), &'static str> = TtlCache::new(Duration::from_secs(5), 8);
        let t0 = Instant::now();
        c.insert((100, 5000), "old-process", t0);
        assert_eq!(c.get(&(100, 5000), t0), Some("old-process"));
        assert_eq!(c.get(&(100, 9000), t0), None, "same pid, new starttime");
    }

    // -- sha256 -------------------------------------------------------------

    #[test]
    fn sha256_of_known_content() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cfc-sha-test-{}", std::process::id()));
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"hello world").unwrap();
        }
        let got = sha256_file(&path, SHA256_MAX_LEN);
        fs::remove_file(&path).ok();
        assert_eq!(
            got.as_deref(),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );
    }

    #[test]
    fn sha256_skips_oversized_files() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cfc-sha-cap-test-{}", std::process::id()));
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(&[0u8; 4096]).unwrap();
        }
        let got = sha256_file(&path, 1024);
        fs::remove_file(&path).ok();
        assert_eq!(got, None);
    }

    #[test]
    fn sha256_missing_file_is_none() {
        assert_eq!(
            sha256_file(Path::new("/nonexistent/cfc-test"), SHA256_MAX_LEN),
            None
        );
    }

    // -- kernel exec table integration --------------------------------------

    use cfc_ebpf_common::{ExecEvent, FILENAME_LEN};

    /// A pid that cannot exist: pid_max is at most 2^22 on 64-bit Linux.
    const DEAD_PID: u32 = 0x7fff_fffe;

    fn kernel_table(pid: u32, exe: &str, uid: u32, ppid: u32) -> KernelProcTable {
        let t = KernelProcTable::new();
        t.set_live(true);
        let mut e = ExecEvent::zeroed();
        e.pid = pid;
        e.ppid = ppid;
        e.uid = uid;
        e.gid = uid + 1;
        let n = exe.len().min(FILENAME_LEN);
        e.filename[..n].copy_from_slice(&exe.as_bytes()[..n]);
        e.filename_len = n as u16;
        t.observe_exec(&e, None, Instant::now());
        t
    }

    #[test]
    fn a_process_that_already_exited_is_named_from_the_exec_record() {
        // This is the case the pre-eBPF path loses by construction: NFQUEUE
        // delivers the packet, the process is already reaped, /proc has
        // nothing, and attribution used to collapse to `unknown`.
        let table = kernel_table(DEAD_PID, "/usr/bin/curl", 1000, 7);
        let p = resolve_inner(DEAD_PID, None, Instant::now(), &table).unwrap();
        assert_eq!(p.pid, DEAD_PID);
        assert_eq!(p.exe, PathBuf::from("/usr/bin/curl"));
        assert_eq!(p.uid, Some(1000));
        assert_eq!(p.gid, Some(1001));
        assert_eq!(p.ppid, Some(7));
        assert_eq!(p.sha256, None, "no mapped image left to hash");
        assert!(p.cmdline.is_empty());
    }

    #[test]
    fn without_a_kernel_record_a_dead_pid_still_fails_the_way_it_used_to() {
        let empty = KernelProcTable::new();
        assert!(resolve_inner(DEAD_PID, None, Instant::now(), &empty).is_err());
        // ... and `resolve` turns that into the unattributed record, with no
        // fabricated uid. That contract is what keeps uid-scoped root rules
        // from matching traffic nobody could attribute.
        let unknown = Process::unknown(DEAD_PID);
        assert_eq!(unknown.uid, None);
        assert_eq!(unknown.gid, None);
    }

    #[test]
    fn kernel_uid_gid_and_ppid_replace_the_proc_status_read() {
        let me = std::process::id();
        let table = kernel_table(me, "/nonexistent/from-the-exec-event", 4242, 77);
        let st = read_starttime(me);
        let p = resolve_inner(me, st, Instant::now(), &table).unwrap();
        assert_eq!(
            p.uid,
            Some(4242),
            "exec-time uid wins over /proc/self/status"
        );
        assert_eq!(p.gid, Some(4243));
        assert_eq!(p.ppid, Some(77));
    }

    #[test]
    fn a_readable_proc_exe_always_wins_over_the_exec_path() {
        // The exec event records the path passed to execve(); /proc/<pid>/exe
        // is the canonical path of the image actually mapped, and it is what
        // the digest, package provenance and every `exe` rule are written in
        // terms of. Switching the eBPF layer on must not silently change the
        // path a running process is reported under.
        let me = std::process::id();
        let real = std::fs::read_link(format!("/proc/{me}/exe")).unwrap();
        let table = kernel_table(me, "/nonexistent/from-the-exec-event", 1000, 1);
        let p = resolve_inner(me, read_starttime(me), Instant::now(), &table).unwrap();
        assert_eq!(p.exe, real);
    }

    #[test]
    fn a_relative_exec_path_is_never_used_as_an_exe() {
        // `./configure`-style paths mean nothing outside the launcher's cwd.
        let table = kernel_table(DEAD_PID, "./configure", 1000, 1);
        let p = resolve_inner(DEAD_PID, None, Instant::now(), &table).unwrap();
        assert_eq!(p.exe, PathBuf::from("<deleted>"));
        assert_eq!(p.uid, Some(1000), "the rest of the record is still used");
    }

    #[test]
    fn a_table_that_is_not_live_changes_nothing() {
        let table = kernel_table(DEAD_PID, "/usr/bin/curl", 1000, 7);
        table.set_live(false);
        assert!(resolve_inner(DEAD_PID, None, Instant::now(), &table).is_err());
    }

    #[test]
    fn a_recycled_pid_falls_back_to_proc_instead_of_reusing_the_record() {
        let me = std::process::id();
        let table = kernel_table(me, "/nonexistent/from-the-exec-event", 4242, 77);
        // Bind the record to one start time...
        assert!(table.get(me, Some(1), Instant::now()).is_some());
        // ...then resolve with a different one, as a recycled pid would.
        let p = resolve_inner(me, Some(2), Instant::now(), &table).unwrap();
        assert_ne!(p.uid, Some(4242), "the stale exec record must not be used");
        assert_eq!(
            p.uid,
            Some(nix::unistd::getuid().as_raw()),
            "the /proc reads take over"
        );
    }
}
