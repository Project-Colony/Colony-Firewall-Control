//! Types and pure parsers shared between the Colony Firewall Control eBPF
//! programs (`cfc-ebpf`, compiled for `bpfel-unknown-none`) and the userspace
//! daemon.
//!
//! Everything in this crate must compile in `#![no_std]` *and* on the host:
//!
//! * the `#[repr(C)]` event structs are the exact wire format of the BPF ring
//!   buffers and hash maps, so kernel and userspace must agree byte-for-byte;
//! * the parsers in [`dns`] and [`net`] are the *arithmetic* half of the BPF
//!   programs. Living here means they can be unit-tested on the host, which is
//!   the only practical way to test verifier-constrained code.
//!
//! # Layout rules
//!
//! Every struct is `#[repr(C)]`, POD (no pointers, no `Drop`, no niches) and
//! carries **explicit** padding fields so that:
//!
//! * `size_of` is stable across compilers and architectures (asserted in the
//!   tests below);
//! * the kernel never copies uninitialised padding bytes into the ring buffer.
//!
//! # `aya::Pod`
//!
//! These structs are deliberately *not* wired to `aya::Pod` here: doing so
//! would force `aya` into the default dependency graph of the stable workspace
//! (and into `Cargo.lock` / `cargo deny`) purely for a marker trait. The
//! userspace consumer should instead write, next to its map handles:
//!
//! ```ignore
//! unsafe impl aya::Pod for cfc_ebpf_common::ExecEvent {}
//! unsafe impl aya::Pod for cfc_ebpf_common::ExitEvent {}
//! unsafe impl aya::Pod for cfc_ebpf_common::DnsPacket {}
//! ```
//!
//! which is sound precisely because of the layout rules above.

#![cfg_attr(not(feature = "std"), no_std)]
// `deny` rather than `forbid`: the crate proper contains no `unsafe`, but the
// layout tests need a raw byte view of their own POD to prove padding is zero.
#![deny(unsafe_code)]

pub mod dns;
pub mod net;

pub use dns::{DnsCursor, DnsHeader, MAX_ANSWERS, MAX_LABEL_JUMPS, MAX_NAME_LEN};
pub use net::UdpPayload;

/// Name of the symbol the kernel object exports to declare its event layout.
///
/// The object is shipped as a separate file and loaded from a path, so a stale
/// one *will* eventually meet a newer daemon: a package that installed the
/// object but not the binary, a hand-copied file, an interrupted upgrade.
/// Nothing about that is loud. `decode<T>` accepts any record at least
/// `size_of::<T>()` long and reads the prefix, so a layout change turns into
/// plausible-looking garbage in `exe`, `uid`, `gid` and `ppid` - fields the
/// daemon *prefers over `/proc`* when deciding who a connection belongs to.
///
/// The loader therefore requires this exact symbol to be present before it
/// attaches anything (`override_global(.., must_exist = true)`, so a missing
/// one fails the load rather than being silently skipped). The version is in
/// the *name*, so an object built against a different layout does not merely
/// carry a different value - it fails to match at all.
///
/// **Bump both this and [`ABI_VERSION`] whenever an event struct's layout
/// changes.** The `const` assertions below exist to make forgetting a build
/// error rather than a field of garbage.
pub const ABI_SYMBOL: &str = "CFC_EBPF_ABI_V3";

/// Value stored at [`ABI_SYMBOL`]. Present so the two sides disagree loudly if
/// the name is ever reused without changing the layout.
///
/// **v2** added the `cgroup/connect4|6` programs, `ConnectDeny` and the maps
/// they use. **v3** added `SOCK_PIDS` (socket cookie -> tgid, written at
/// `connect()` for O(1) attribution) and the `_basic` program variants for
/// kernels without `bpf_get_socket_cookie` on sock_addr programs.
///
/// The version is also the bpffs pin path, so bumping it is what makes a
/// daemon detach the previous version's in-kernel enforcement instead of
/// inheriting programs whose behaviour it no longer matches - here, v2 pins
/// would enforce fine but never write a cookie, which would silently cost
/// every connection the 40 ms walk the map exists to remove.
pub const ABI_VERSION: u32 = 3;

// The guard behind ABI_SYMBOL. If any of these fires, an event layout moved:
// bump ABI_VERSION *and* the version suffix in ABI_SYMBOL, and update the
// matching `static` in crates/cfc-ebpf/src/main.rs to the new name.
const _: () = {
    assert!(core::mem::size_of::<ExecEvent>() == 292);
    assert!(core::mem::size_of::<ExitEvent>() == 4);
    assert!(core::mem::size_of::<DnsPacket>() == 514);
    assert!(core::mem::size_of::<DnsAnswer>() == 276);
    assert!(core::mem::size_of::<ConnectDeny>() == 24);
};

// ---------------------------------------------------------------------------
// In-kernel enforcement
// ---------------------------------------------------------------------------

/// Values the daemon writes into the `VERDICTS` map, keyed by tgid, for the
/// `cgroup/connect4|6` programs to read.
///
/// **Absence is not a verdict.** A pid with no entry is allowed to proceed
/// through `connect()` and meets NFQUEUE instead, which is where the
/// interactive prompt lives. This is the one place in CFC where the default is
/// not Deny, and it is deliberate: the map only ever holds processes the daemon
/// has seen `exec`, so a default deny here would blackhole every process that
/// started before the daemon did - including the ones that bring the network
/// up. The fail-closed guarantee stays where it already was, in the nftables
/// ruleset (`ct state new queue num 0`, no `bypass`).
///
/// The point of this layer is the *opposite* direction: a deny written here
/// keeps being enforced after the daemon is gone, because the link is pinned.
pub mod verdict {
    /// Let `connect()` proceed. Written when a rule allows this executable
    /// unconditionally, so NFQUEUE would only reach the same answer slower.
    pub const ALLOW: u32 = 1;

    /// Refuse `connect()` in-kernel; the syscall returns `EPERM` before a
    /// packet exists. Written when a rule denies this executable
    /// unconditionally.
    pub const DENY: u32 = 2;
}

/// One `connect()` refused in the kernel.
///
/// Exists so an in-kernel deny is not a *silent* deny. Every other deny CFC
/// makes passes through NFQUEUE, which logs it, counts the rule hit and streams
/// an event to the UI. A `connect()` refused before a packet exists never
/// reaches any of that, and a firewall that blocks things without saying so is
/// a firewall people stop trusting.
///
/// The address is the one the process asked for, taken from `bpf_sock_addr`
/// before the kernel does anything with it - so this is exactly the destination
/// NFQUEUE would have reported, minus the DNS name, which userspace resolves
/// from its own cache anyway.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectDeny {
    /// Thread-group id, matching the key in `VERDICTS` and `PROCS`.
    pub pid: u32,
    /// Destination address, network byte order. IPv4 occupies the first four
    /// bytes and the rest is zero; `family` says which to read.
    pub addr: [u8; 16],
    /// Destination port, **network byte order** - `bpf_sock_addr::user_port`
    /// is stored that way and this passes it through untouched rather than
    /// swapping it twice.
    pub port: u16,
    /// 4 or 6. Not `AF_INET`/`AF_INET6`: those differ per architecture in the
    /// UAPI headers this struct is decoded next to, and 4/6 cannot be
    /// misread.
    pub family: u8,
    /// Explicit, so the 24-byte size is not an alignment accident.
    pub _pad: u8,
}

impl ConnectDeny {
    /// All zeroes, for a scratch slot.
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            addr: [0; 16],
            port: 0,
            family: 0,
            _pad: 0,
        }
    }
}

/// Slots in the `ENFORCE_STATS` per-CPU array.
///
/// Counters, not events: the connect path must not allocate, and a ring buffer
/// record per `connect()` would be a lot of records. The daemon sums these
/// across CPUs for `cfc status`, which is also how the live tests prove the
/// hook is firing at all.
pub mod enforce_stat {
    /// `connect()` allowed because the map said so.
    pub const ALLOWED: u32 = 0;
    /// `connect()` refused in-kernel.
    pub const DENIED: u32 = 1;
    /// No entry for this pid; fell through to NFQUEUE.
    pub const UNKNOWN: u32 = 2;
    /// Number of slots, and the array's `max_entries`.
    pub const SLOTS: u32 = 3;
}

/// Length of the kernel's `task_struct::comm` field, including the NUL.
/// FNV-1a of an executable path, used as the key of the kernel's rule table.
///
/// Lives here because **both sides must agree exactly**. The kernel hashes the
/// path `execve` was handed; userspace hashes the path a rule names. A private
/// copy on either side that drifted by one constant would not fail loudly - it
/// would simply stop matching, and the in-kernel refusals would quietly never
/// fire again. One function, compiled into both.
///
/// FNV rather than something stronger because the kernel side has to pass the
/// verifier: a bounded loop, one load and two arithmetic ops per byte, no
/// tables and no branches on data.
///
/// A collision can only cause a *refusal* for the wrong program, never an
/// allow, because only denials are ever written. That is the closed direction.
pub fn hash_exe_path(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0usize;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

pub const COMM_LEN: usize = 16;

/// Maximum executable path captured from the `sched_process_exec` tracepoint.
///
/// Longer paths are truncated; `ExecEvent::filename_len` always reflects the
/// number of bytes actually stored.
pub const FILENAME_LEN: usize = 256;

/// Size of the DNS payload prefix the kernel program copies out of a packet.
///
/// 512 is the RFC 1035 §4.2.1 limit on an unextended UDP DNS message, so this
/// captures a whole classic response. It costs the verifier almost nothing:
/// the kernel only ever *copies* into this buffer with constant-length
/// `bpf_skb_load_bytes` calls and never indexes it, because the parsing now
/// happens in userspace (see [`DnsPacket`]).
///
/// EDNS(0) responses may be larger; those are truncated to this prefix, which
/// is safe. [`dns::for_each_answer`] stops at the first record it cannot read
/// in full, and any address it therefore misses is still named by the PTR
/// path.
pub const DNS_BUF_LEN: usize = 512;

// ---------------------------------------------------------------------------
// ExecEvent
// ---------------------------------------------------------------------------

/// One `execve()` observed by the `sched/sched_process_exec` tracepoint.
///
/// Layout (`size_of` = 292, `align_of` = 4):
///
/// ```text
///   0..4    pid
///   4..8    ppid
///   8..12   uid
///  12..16   gid
///  16..32   comm
///  32..288  filename
/// 288..290  filename_len
/// 290..292  _pad
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    /// Thread-group id (what userspace calls "the pid").
    pub pid: u32,
    /// Thread-group id of the parent, or `0` for "unknown".
    ///
    /// Rust/aya has no CO-RE field relocation, so the kernel side can only fill
    /// this in when the loader supplies `task_struct` offsets resolved from
    /// BTF. Treat `0` as "resolve it from `/proc` if you care".
    pub ppid: u32,
    /// Real uid of the calling task.
    pub uid: u32,
    /// Real gid of the calling task.
    pub gid: u32,
    /// `task_struct::comm`, NUL-padded.
    pub comm: [u8; COMM_LEN],
    /// Executable path as passed to `execve()`, possibly truncated.
    ///
    /// Only the first [`Self::filename_len`] bytes are meaningful; the kernel
    /// writes a NUL after them but does **not** clear the rest of the buffer
    /// (a 256-byte `memset` is not lowerable on the BPF target). Always read it
    /// through [`Self::filename_bytes`] / [`Self::filename_str`], which clamp
    /// on both the length and the NUL.
    pub filename: [u8; FILENAME_LEN],
    /// Number of valid bytes in [`Self::filename`] (<= [`FILENAME_LEN`]).
    pub filename_len: u16,
    /// Explicit tail padding. Always zero; never read it.
    pub _pad: [u8; 2],
}

impl ExecEvent {
    /// An all-zero event. `const` so the BPF side can use it as a map
    /// initialiser without a runtime `memset` the verifier has to reason about.
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0; COMM_LEN],
            filename: [0; FILENAME_LEN],
            filename_len: 0,
            _pad: [0; 2],
        }
    }
}

impl Default for ExecEvent {
    fn default() -> Self {
        Self::zeroed()
    }
}

// ---------------------------------------------------------------------------
// ExitEvent
// ---------------------------------------------------------------------------

/// A process (thread-group leader) that has exited.
///
/// Userspace uses this to evict `pid` from its cache, so a recycled pid can
/// never be attributed to the process that previously owned it.
///
/// Layout (`size_of` = 4, `align_of` = 4).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExitEvent {
    /// Thread-group id that just died.
    pub pid: u32,
}

// ---------------------------------------------------------------------------
// DnsAnswer
// ---------------------------------------------------------------------------

/// One `A` or `AAAA` answer record lifted out of a DNS response.
///
/// Layout (`size_of` = 276, `align_of` = 4):
///
/// ```text
///   0..16   ip          (IPv4 in the first 4 bytes, rest zero)
///  16..17   is_v6
///  17..270  name
/// 270..271  name_len
/// 271..272  _pad
/// 272..276  ttl
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsAnswer {
    /// Answer address. IPv4 occupies bytes `0..4` with `4..16` zeroed.
    pub ip: [u8; 16],
    /// `1` when [`Self::ip`] is an IPv6 address, `0` for IPv4.
    pub is_v6: u8,
    /// Owner name of the record, dot-separated, without a trailing dot.
    ///
    /// Only the first [`Self::name_len`] bytes are meaningful; a NUL follows
    /// them, but the rest of the buffer is *not* cleared (same BPF `memset`
    /// constraint as [`ExecEvent::filename`]). Always read it through
    /// [`Self::name_bytes`] / [`Self::name_str`].
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in [`Self::name`] (<= [`MAX_NAME_LEN`] = 253).
    pub name_len: u8,
    /// Explicit padding. Always zero; never read it.
    pub _pad: [u8; 1],
    /// Record TTL in seconds, host byte order.
    pub ttl: u32,
}

impl DnsAnswer {
    /// An all-zero answer.
    pub const fn zeroed() -> Self {
        Self {
            ip: [0; 16],
            is_v6: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            _pad: [0; 1],
            ttl: 0,
        }
    }
}

impl Default for DnsAnswer {
    fn default() -> Self {
        Self::zeroed()
    }
}

// ---------------------------------------------------------------------------
// DnsPacket
// ---------------------------------------------------------------------------

/// A prefix of one DNS response payload, copied verbatim off the wire.
///
/// This is what the `cgroup_skb/ingress` program actually publishes. The kernel
/// does not parse DNS at all: it confirms the datagram is UDP from source port
/// 53, checks the QR bit, and copies the payload here. Userspace then runs
/// [`dns::for_each_answer`] over [`Self::payload`] and turns the result into
/// [`DnsAnswer`]s.
///
/// The reason is the verifier's 1,000,000-instruction complexity budget: the
/// nested answer x label x byte loops of in-kernel name parsing blew past it
/// (see `crates/cfc-ebpf/README.md`). A constant-length copy does not.
///
/// Layout (`size_of` = 514, `align_of` = 2):
///
/// ```text
///   0..2    len
///   2..514  data
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsPacket {
    /// Number of valid bytes in [`Self::data`] (<= [`DNS_BUF_LEN`]).
    pub len: u16,
    /// The DNS message, starting at its 12-byte header.
    ///
    /// Only the first [`Self::len`] bytes are meaningful. The kernel writes
    /// exactly that many and leaves the tail as whatever the ring-buffer slot
    /// held before (there is no 512-byte `memset` the BPF backend would
    /// lower). Always read it through [`Self::payload`], which clamps.
    pub data: [u8; DNS_BUF_LEN],
}

impl DnsPacket {
    /// An all-zero packet.
    pub const fn zeroed() -> Self {
        Self {
            len: 0,
            data: [0; DNS_BUF_LEN],
        }
    }

    /// The valid bytes: `len`, clamped to the buffer.
    ///
    /// Unlike the string fields there is no NUL to stop at -- DNS payloads are
    /// binary -- so `len` is the only bound, and it is clamped here rather than
    /// trusted.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let n = self.len as usize;
        let n = if n < DNS_BUF_LEN { n } else { DNS_BUF_LEN };
        match self.data.get(..n) {
            Some(s) => s,
            None => &[],
        }
    }
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self::zeroed()
    }
}

// ---------------------------------------------------------------------------
// no_std-safe accessors (available everywhere)
// ---------------------------------------------------------------------------

/// Returns the leading NUL-terminated prefix of `buf`, capped at `max`.
///
/// Bounded, allocation-free and panic-free, so it is usable from BPF too.
#[inline(always)]
pub fn nul_terminated(buf: &[u8], max: usize) -> &[u8] {
    let cap = if max < buf.len() { max } else { buf.len() };
    let mut n = 0;
    while n < cap {
        match buf.get(n) {
            Some(0) | None => break,
            Some(_) => n += 1,
        }
    }
    // `n <= cap <= buf.len()`, so this cannot panic.
    match buf.get(..n) {
        Some(s) => s,
        None => &[],
    }
}

impl ExecEvent {
    /// `comm` as raw bytes, stopping at the first NUL.
    #[inline]
    pub fn comm_bytes(&self) -> &[u8] {
        nul_terminated(&self.comm, COMM_LEN)
    }

    /// `filename` as raw bytes: `filename_len` bytes, additionally truncated at
    /// the first NUL so a bogus length can never expose stale buffer contents.
    #[inline]
    pub fn filename_bytes(&self) -> &[u8] {
        nul_terminated(&self.filename, self.filename_len as usize)
    }
}

impl DnsAnswer {
    /// `name` as raw bytes: `name_len` bytes, truncated at the first NUL.
    #[inline]
    pub fn name_bytes(&self) -> &[u8] {
        nul_terminated(&self.name, self.name_len as usize)
    }

    /// True when this record carries an IPv6 address.
    #[inline]
    pub fn is_ipv6(&self) -> bool {
        self.is_v6 != 0
    }
}

// ---------------------------------------------------------------------------
// std-only conveniences
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
mod std_impls {
    use super::{ConnectDeny, DnsAnswer, DnsPacket, ExecEvent};
    use std::borrow::Cow;
    use std::fmt;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    impl ExecEvent {
        /// `comm` as a string. Never panics: invalid UTF-8 is replaced.
        pub fn comm_str(&self) -> Cow<'_, str> {
            String::from_utf8_lossy(self.comm_bytes())
        }

        /// `filename` as a string. Never panics: invalid UTF-8 is replaced.
        pub fn filename_str(&self) -> Cow<'_, str> {
            String::from_utf8_lossy(self.filename_bytes())
        }
    }

    impl ConnectDeny {
        /// The address the process asked for.
        ///
        /// `family` decides the width, so a v4 record never reads the 12 zero
        /// bytes after it. An unrecognised family reads as the unspecified v4
        /// address rather than panicking: this decodes bytes that crossed a
        /// kernel boundary, and the only correct response to a record we do not
        /// understand is a duller log line.
        pub fn ip_addr(&self) -> IpAddr {
            if self.family == 6 {
                IpAddr::V6(Ipv6Addr::from(self.addr))
            } else {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&self.addr[..4]);
                IpAddr::V4(Ipv4Addr::from(v4))
            }
        }

        /// `addr:port`, with the port brought back into host order.
        pub fn destination(&self) -> SocketAddr {
            SocketAddr::new(self.ip_addr(), u16::from_be(self.port))
        }
    }

    impl DnsAnswer {
        /// Owner name as a string. Never panics: invalid UTF-8 is replaced.
        pub fn name_str(&self) -> Cow<'_, str> {
            String::from_utf8_lossy(self.name_bytes())
        }

        /// The answer address.
        pub fn ip_addr(&self) -> IpAddr {
            if self.is_v6 != 0 {
                IpAddr::V6(Ipv6Addr::from(self.ip))
            } else {
                IpAddr::V4(Ipv4Addr::new(
                    self.ip[0], self.ip[1], self.ip[2], self.ip[3],
                ))
            }
        }

        /// Store an [`IpAddr`], zero-extending IPv4 into the 16-byte field.
        pub fn set_ip(&mut self, addr: IpAddr) {
            match addr {
                IpAddr::V4(v4) => {
                    self.ip = [0; 16];
                    self.ip[..4].copy_from_slice(&v4.octets());
                    self.is_v6 = 0;
                }
                IpAddr::V6(v6) => {
                    self.ip = v6.octets();
                    self.is_v6 = 1;
                }
            }
        }
    }

    // Hand-written so a 256-byte array does not turn every log line into a
    // wall of integers.
    impl fmt::Debug for ExecEvent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ExecEvent")
                .field("pid", &self.pid)
                .field("ppid", &self.ppid)
                .field("uid", &self.uid)
                .field("gid", &self.gid)
                .field("comm", &self.comm_str())
                .field("filename", &self.filename_str())
                .finish()
        }
    }

    impl fmt::Debug for DnsAnswer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("DnsAnswer")
                .field("name", &self.name_str())
                .field("ip", &self.ip_addr())
                .field("ttl", &self.ttl)
                .finish()
        }
    }

    // Same reasoning: 512 raw payload bytes are not something to print by
    // accident. The length is the only part worth logging.
    impl fmt::Debug for DnsPacket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("DnsPacket")
                .field("len", &self.len)
                .finish_non_exhaustive()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // -- layout ------------------------------------------------------------

    #[test]
    fn exec_event_layout_is_frozen() {
        assert_eq!(size_of::<ExecEvent>(), 292);
        assert_eq!(align_of::<ExecEvent>(), 4);
        // 4 * u32 + comm + filename + u16 + pad == size, i.e. no hidden holes.
        assert_eq!(
            16 + COMM_LEN + FILENAME_LEN + 2 + 2,
            size_of::<ExecEvent>(),
            "ExecEvent gained implicit padding"
        );
    }

    #[test]
    fn dns_answer_layout_is_frozen() {
        assert_eq!(size_of::<DnsAnswer>(), 276);
        assert_eq!(align_of::<DnsAnswer>(), 4);
        assert_eq!(
            16 + 1 + MAX_NAME_LEN + 1 + 1 + 4,
            size_of::<DnsAnswer>(),
            "DnsAnswer gained implicit padding"
        );
    }

    #[test]
    fn exit_event_layout_is_frozen() {
        assert_eq!(size_of::<ExitEvent>(), 4);
        assert_eq!(align_of::<ExitEvent>(), 4);
    }

    #[test]
    fn dns_packet_layout_is_frozen() {
        assert_eq!(size_of::<DnsPacket>(), 514);
        assert_eq!(align_of::<DnsPacket>(), 2);
        assert_eq!(
            2 + DNS_BUF_LEN,
            size_of::<DnsPacket>(),
            "DnsPacket gained implicit padding"
        );
    }

    #[test]
    fn zeroed_constructors_are_all_zero() {
        let e = ExecEvent::zeroed();
        let bytes: &[u8] = unsafe_transmute_exec(&e);
        assert!(bytes.iter().all(|b| *b == 0));

        let a = DnsAnswer::zeroed();
        let bytes: &[u8] = unsafe_transmute_dns(&a);
        assert!(bytes.iter().all(|b| *b == 0));

        let p = DnsPacket::zeroed();
        assert_eq!(p.len, 0);
        assert!(p.data.iter().all(|b| *b == 0));
    }

    // -- DnsPacket ---------------------------------------------------------

    #[test]
    fn dns_packet_payload_respects_len() {
        let mut p = DnsPacket::zeroed();
        p.data[..4].copy_from_slice(b"\xab\xcd\x81\x80");
        p.len = 4;
        assert_eq!(p.payload(), b"\xab\xcd\x81\x80");
    }

    #[test]
    fn dns_packet_payload_clamps_a_lying_len() {
        let mut p = DnsPacket::zeroed();
        // The kernel can only ever write DNS_BUF_LEN bytes, but a truncated or
        // corrupted ring record must not turn into an out-of-bounds read.
        p.len = u16::MAX;
        assert_eq!(p.payload().len(), DNS_BUF_LEN);
    }

    #[test]
    fn dns_packet_payload_is_empty_when_len_is_zero() {
        assert!(DnsPacket::zeroed().payload().is_empty());
    }

    #[test]
    fn dns_packet_debug_does_not_dump_the_buffer() {
        let mut p = DnsPacket::zeroed();
        p.len = 7;
        let s = format!("{p:?}");
        assert!(s.contains("len: 7"), "{s}");
        // 512 bytes of payload in a log line would be unreadable at best and a
        // way to leak query contents into the journal at worst.
        assert!(s.len() < 64, "Debug printed the payload: {s}");
    }

    // Small local helpers keep `#![forbid(unsafe_code)]` intact for the crate
    // proper: the test module opts out explicitly and only reads its own POD.
    #[allow(unsafe_code)]
    fn unsafe_transmute_exec(e: &ExecEvent) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((e as *const ExecEvent).cast::<u8>(), size_of::<ExecEvent>())
        }
    }

    #[allow(unsafe_code)]
    fn unsafe_transmute_dns(a: &DnsAnswer) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((a as *const DnsAnswer).cast::<u8>(), size_of::<DnsAnswer>())
        }
    }

    // -- string helpers ----------------------------------------------------

    fn exec_with(comm: &[u8], filename: &[u8], filename_len: u16) -> ExecEvent {
        let mut e = ExecEvent::zeroed();
        e.comm[..comm.len()].copy_from_slice(comm);
        e.filename[..filename.len()].copy_from_slice(filename);
        e.filename_len = filename_len;
        e
    }

    #[test]
    fn comm_str_stops_at_nul() {
        let e = exec_with(b"curl\0garbage", b"", 0);
        assert_eq!(e.comm_str(), "curl");
    }

    #[test]
    fn comm_str_handles_unterminated_buffer() {
        // All 16 bytes used, no NUL anywhere.
        let e = exec_with(b"0123456789abcdef", b"", 0);
        assert_eq!(e.comm_bytes().len(), COMM_LEN);
        assert_eq!(e.comm_str(), "0123456789abcdef");
    }

    #[test]
    fn comm_str_is_lossy_on_invalid_utf8() {
        let e = exec_with(&[0xff, 0xfe, b'a', 0x00], b"", 0);
        let s = e.comm_str();
        assert!(
            s.contains('\u{fffd}'),
            "expected replacement chars, got {s:?}"
        );
        assert!(s.ends_with('a'));
    }

    #[test]
    fn filename_str_respects_len() {
        let e = exec_with(b"", b"/usr/bin/curl", 13);
        assert_eq!(e.filename_str(), "/usr/bin/curl");
    }

    #[test]
    fn filename_str_truncates_at_nul_even_if_len_lies() {
        // A hostile / buggy producer claims 200 bytes but only wrote 5.
        let e = exec_with(b"", b"/bin\0stale-bytes-from-a-previous-exec", 200);
        assert_eq!(e.filename_str(), "/bin");
    }

    #[test]
    fn filename_str_clamps_len_beyond_buffer() {
        let mut e = exec_with(b"", &[b'x'; FILENAME_LEN], FILENAME_LEN as u16);
        e.filename_len = u16::MAX; // nonsense length
        assert_eq!(e.filename_bytes().len(), FILENAME_LEN);
    }

    #[test]
    fn filename_str_is_lossy_on_invalid_utf8() {
        let e = exec_with(b"", &[b'/', 0xc3, 0x28, b'x'], 4);
        let s = e.filename_str();
        assert!(
            s.contains('\u{fffd}'),
            "expected replacement chars, got {s:?}"
        );
    }

    // -- DnsAnswer helpers -------------------------------------------------

    #[test]
    fn dns_name_str_and_len() {
        let mut a = DnsAnswer::zeroed();
        a.name[..11].copy_from_slice(b"example.com");
        a.name_len = 11;
        assert_eq!(a.name_str(), "example.com");
    }

    #[test]
    fn dns_name_str_is_lossy_and_bounded() {
        let mut a = DnsAnswer::zeroed();
        a.name[..3].copy_from_slice(&[0xff, 0xff, b'z']);
        a.name_len = 255; // > MAX_NAME_LEN and > written bytes
        let s = a.name_str();
        assert!(s.contains('\u{fffd}'));
        assert_eq!(a.name_bytes().len(), 3, "must stop at the NUL");
    }

    #[test]
    fn dns_name_str_unterminated_full_buffer() {
        let mut a = DnsAnswer::zeroed();
        a.name = [b'a'; MAX_NAME_LEN];
        a.name_len = MAX_NAME_LEN as u8;
        assert_eq!(a.name_bytes().len(), MAX_NAME_LEN);
        assert_eq!(a.name_str().len(), MAX_NAME_LEN);
    }

    #[test]
    fn ip_addr_v4() {
        let mut a = DnsAnswer::zeroed();
        a.ip[..4].copy_from_slice(&[93, 184, 216, 34]);
        assert_eq!(a.ip_addr(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert!(!a.is_ipv6());
    }

    #[test]
    fn ip_addr_v6() {
        let mut a = DnsAnswer::zeroed();
        a.is_v6 = 1;
        a.ip = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946).octets();
        assert_eq!(
            a.ip_addr(),
            IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946
            ))
        );
        assert!(a.is_ipv6());
    }

    #[test]
    fn set_ip_round_trips() {
        let mut a = DnsAnswer::zeroed();
        a.set_ip(IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap()));
        assert_eq!(a.ip_addr().to_string(), "::1");
        a.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(a.ip_addr().to_string(), "127.0.0.1");
        assert_eq!(&a.ip[4..], &[0u8; 12], "v4 must zero-extend");
    }

    #[test]
    fn nul_terminated_edge_cases() {
        assert_eq!(nul_terminated(b"", 0), b"");
        assert_eq!(nul_terminated(b"\0abc", 4), b"");
        assert_eq!(nul_terminated(b"abc", 0), b"");
        assert_eq!(nul_terminated(b"abcdef", 3), b"abc");
        assert_eq!(nul_terminated(b"abc", 99), b"abc");
    }
}
