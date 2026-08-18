//! Process resolution: given a 5-tuple, find the local pid that owns the
//! socket, then read /proc/{pid} to fill a `Process` record.
//!
//! Resolution strategy, fastest first:
//!   1. netlink sock_diag exact-tuple query ([`crate::sock_diag`]): one
//!      round-trip per connection instead of a full-table parse. Falls
//!      back silently on any error (EPERM in containers, old kernels).
//!   2. Parse /proc/net/{tcp,udp}{,6} with layered match passes (exact,
//!      unconnected-UDP, wildcard-bind, v4-mapped-in-v6).
//!   3. inode -> pid via a verified TTL cache, else a /proc/*/fd walk.
//!
//! TOCTOU note: the resolved pid may have exited by the time we read
//! /proc/{pid}/exe. We return `Process::unknown(pid)` in that case. The
//! process cache is keyed by (pid, starttime) so pid reuse invalidates
//! naturally, and the inode cache re-verifies its answer with a single
//! readlink before trusting it.

use cfc_core::{Process, Protocol};
use parking_lot::Mutex;
use procfs::process::{FDTarget, Process as ProcFsProcess};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
const SHA_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Don't hash executables larger than this.
const SHA256_MAX_LEN: u64 = 64 * 1024 * 1024;

const CACHE_CAP: usize = 1024;

static INODE_PID_CACHE: LazyLock<Mutex<TtlCache<u64, (u32, i32)>>> =
    LazyLock::new(|| Mutex::new(TtlCache::new(INODE_CACHE_TTL, CACHE_CAP)));

static PROCESS_CACHE: LazyLock<Mutex<TtlCache<(u32, u64), Process>>> =
    LazyLock::new(|| Mutex::new(TtlCache::new(PROCESS_CACHE_TTL, CACHE_CAP)));

#[allow(clippy::type_complexity)]
static SHA_CACHE: LazyLock<Mutex<TtlCache<(u64, u64, i64, i64), Option<String>>>> =
    LazyLock::new(|| Mutex::new(TtlCache::new(SHA_CACHE_TTL, CACHE_CAP)));

/// Build a full Process record from /proc/{pid}.
///
/// Cached by (pid, starttime from /proc/{pid}/stat field 22): a recycled
/// pid has a different starttime, so it can never hit a stale entry.
pub fn resolve(pid: u32) -> Process {
    let now = Instant::now();
    let starttime = read_starttime(pid);

    if let Some(st) = starttime {
        if let Some(p) = PROCESS_CACHE.lock().get(&(pid, st), now) {
            return p;
        }
    }

    match resolve_inner(pid) {
        Ok(p) => {
            if let Some(st) = starttime {
                PROCESS_CACHE.lock().insert((pid, st), p.clone(), now);
            }
            p
        }
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

    // Package provenance reuses the digest computed just above rather than
    // re-hashing. That digest comes from /proc/{pid}/exe -- the binary the
    // kernel actually mapped -- while the package database describes the
    // file at `exe` on disk. Comparing those two is the whole point: a
    // mismatch means the running binary is not the one the package shipped
    // (replaced, patched, or swapped under a live process), which is what
    // makes `Modified` worth shouting about. See `crate::provenance`.
    //
    // Everything underneath is cached (path index by database mtime,
    // per-executable records by (dev, inode, mtime)), and this whole
    // function is itself behind PROCESS_CACHE, so a steady flow of packets
    // from a known process does no work here at all.
    let sha256 = exe_sha256(pid);
    let (package, provenance) = crate::provenance::describe(&exe, sha256.as_deref());

    Ok(Process {
        pid,
        ppid: Some(stat.ppid as u32),
        uid: Some(status.ruid),
        gid: Some(status.rgid),
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
pub fn pid_for_socket(
    protocol: Protocol,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<u32> {
    let deadline = Instant::now() + RESOLVE_BUDGET;

    // Fast path: one exact-tuple kernel query. Any failure (EPERM,
    // unsupported protocol, unconnected UDP the kernel won't match)
    // falls through to the table scan.
    let inode = crate::sock_diag::query(protocol, src_ip, src_port, dst_ip, dst_port)
        .map(|info| info.inode)
        .or_else(|| proc_net_inode(protocol, src_ip, src_port, dst_ip, dst_port, deadline))?;

    pid_owning_inode(inode, deadline)
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

    let proc_dir = fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        if Instant::now() > deadline {
            return None;
        }
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(p) = ProcFsProcess::new(pid as i32) else {
            continue;
        };
        let Ok(fds) = p.fd() else { continue };
        for fd in fds.flatten() {
            if matches!(fd.target, FDTarget::Socket(i) if i == inode) {
                INODE_PID_CACHE
                    .lock()
                    .insert(inode, (pid, fd.fd), Instant::now());
                return Some(pid);
            }
        }
    }
    None
}

fn fd_points_at_socket(pid: u32, fd: i32, inode: u64) -> bool {
    fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .map(|t| t.as_os_str().to_string_lossy() == format!("socket:[{inode}]"))
        .unwrap_or(false)
}

fn read_starttime(pid: u32) -> Option<u64> {
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
    let mut hasher = Sha256::new();
    std::io::copy(&mut f, &mut hasher).ok()?;
    Some(format!("{:x}", hasher.finalize()))
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
}
