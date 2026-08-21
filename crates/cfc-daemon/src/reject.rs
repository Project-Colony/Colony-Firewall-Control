//! Honest `Action::Reject`: an immediate, protocol-appropriate refusal.
//!
//! `Deny` and `Reject` differ only in what the *application* experiences.
//! Both stop the packet, but a plain drop leaves the app retransmitting
//! into a black hole until its own timeout expires (SYN retries alone are
//! ~130s on Linux). `Reject` promises the opposite - fail fast, like a
//! closed port would - and the UI, CLI and proto have advertised that
//! promise since day one. Until this module existed, `Reject` was silently
//! a drop: an advertised security semantic that did nothing.
//!
//! So for a rejected flow we impersonate the peer the app tried to reach
//! and send the refusal it would have sent:
//!
//! - TCP -> a RST (RFC 9293 s3.5.2, née RFC 793 s3.4) -> `ECONNREFUSED`.
//! - UDP -> ICMP(v6) port unreachable (RFC 792 / RFC 4443) -> `ECONNREFUSED`
//!   on the app's next send/recv for connected sockets.
//! - anything else (ICMP, ESP, ...) -> no meaningful refusal exists, so the
//!   flow is dropped exactly like `Deny` and the fact is trace-logged.
//!
//! # Why we build every header ourselves
//!
//! The whole point is to *spoof* the source address: the response has to
//! look like it came from the peer, or the app's TCP stack discards it as
//! out-of-connection. A kernel-built IP header would source the packet
//! from a locally chosen address (the destination is local, so the route
//! is loopback and the kernel would pick the app's own address), producing
//! a RST the stack ignores. Hence `IP_HDRINCL` for v4 and `IPV6_HDRINCL`
//! (Linux >= 4.5) for v6, with every checksum computed here. That also
//! makes packet construction a set of pure functions unit-testable without
//! root; only [`send_raw`] touches a socket.
//!
//! # Why this does not feed back into our own queue
//!
//! The injected packet leaves through `NF_INET_LOCAL_OUT`, the same hook
//! the shipped nft snippet queues from - but that rule matches
//! `ct state new`, and neither response qualifies: conntrack classifies an
//! unsolicited RST as INVALID (`tcp_conntracks[sNONE][rst] == sIV`) and an
//! ICMP error whose inner tuple has no conntrack entry as untracked. A
//! deployment that queues *all* outbound packets instead would see the
//! response come back around; it would then be unattributable rather than
//! looping, since the sending socket is a raw socket and never appears in
//! /proc/net/tcp.
//!
//! # Degradation
//!
//! Raw sockets need `CAP_NET_RAW` (the unit grants it; containers and the
//! test runner typically do not). Socket creation failures are reported
//! once at startup and then the rejecter is inert for the process
//! lifetime: `Reject` behaves exactly like `Deny`. It never panics and
//! never logs per packet above trace level.

use cfc_core::{Connection, Protocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, trace, warn};

/// IANA protocol numbers we emit.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_ICMPV6: u8 = 58;

/// IPv6 extension headers, mirrored from [`crate::packet`] so the L4
/// offset can be recovered from the queued packet.
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;
/// Same bound as the parser: crafted chains must not make us loop.
const MAX_EXT_HEADERS: usize = 8;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
/// ICMP / ICMPv6 fixed header: type, code, checksum, 4 unused bytes.
const ICMP_HEADER_LEN: usize = 8;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_CODE_PORT_UNREACH: u8 = 3;
const ICMPV6_DEST_UNREACH: u8 = 1;
const ICMPV6_CODE_PORT_UNREACH: u8 = 4;

/// RFC 792: the ICMPv4 error quotes the offending IP header plus the first
/// 64 bits of its payload - enough for the ports, which is all the
/// receiving stack needs to match the error to a socket.
const ICMPV4_QUOTE_L4_BYTES: usize = 8;
/// RFC 4443 s3.1: an ICMPv6 error carries as much of the invoking packet
/// as fits without exceeding the minimum IPv6 MTU.
const IPV6_MIN_MTU: usize = 1280;

/// TTL / hop limit for injected responses. 64 is the Linux default, so the
/// response is indistinguishable from one a local peer would emit.
const DEFAULT_TTL: u8 = 64;

/// What happened to a reject attempt. Returned (rather than logged and
/// swallowed) so the worker can trace it and tests can assert on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectOutcome {
    /// An error response was handed to the kernel.
    Sent,
    /// No raw socket for this family: the daemon lacks CAP_NET_RAW, or the
    /// kernel refused the HDRINCL option. Flow is drop-only.
    Unavailable,
    /// No refusal is defined for this protocol, or the queued packet was
    /// too malformed to answer. Flow is drop-only.
    Unsupported,
    /// The socket existed but the kernel refused the send.
    SendFailed,
}

/// Raw sockets used to inject refusals, opened once at daemon start.
///
/// Each is `None` when its creation failed; the whole struct being inert
/// is the normal state in an unprivileged environment.
pub struct Rejecter {
    /// AF_INET / IPPROTO_TCP with `IP_HDRINCL` - TCP RSTs.
    v4: Option<OwnedFd>,
    /// AF_INET6 / IPPROTO_TCP with `IPV6_HDRINCL` - TCP RSTs.
    v6: Option<OwnedFd>,
    /// AF_INET / IPPROTO_ICMP with `IP_HDRINCL` - port unreachable.
    icmp4: Option<OwnedFd>,
    /// AF_INET6 / IPPROTO_ICMPV6 with `IPV6_HDRINCL` - port unreachable.
    icmp6: Option<OwnedFd>,
    /// Latches after the first send failure so a persistently unroutable
    /// destination logs once at WARN and then only at DEBUG.
    warned_send_failure: AtomicBool,
}

impl Rejecter {
    /// Opens the injection sockets. Never fails: whatever could not be
    /// opened is reported in a single startup WARN and that family
    /// degrades to drop-only.
    pub fn open() -> Self {
        let mut missing: Vec<String> = Vec::new();
        let mut track = |what: &str, result: std::io::Result<OwnedFd>| match result {
            Ok(fd) => Some(fd),
            Err(e) => {
                missing.push(format!("{what}: {e}"));
                None
            }
        };

        let v4 = track("ipv4 tcp", open_raw_v4(libc::IPPROTO_TCP));
        let v6 = track("ipv6 tcp", open_raw_v6(libc::IPPROTO_TCP));
        let icmp4 = track("ipv4 icmp", open_raw_v4(libc::IPPROTO_ICMP));
        let icmp6 = track("ipv6 icmpv6", open_raw_v6(libc::IPPROTO_ICMPV6));

        if missing.is_empty() {
            debug!("reject injection ready (TCP RST + ICMP port-unreachable, v4 + v6)");
        } else {
            // One line, once. Reject still filters correctly (the packet is
            // dropped either way); the app just waits for its own timeout.
            warn!(
                "raw socket setup failed ({}); Reject rules will behave like Deny \
                 for those families. CAP_NET_RAW is required - the bundled \
                 colony-firewalld.service grants it.",
                missing.join("; ")
            );
        }

        Self {
            v4,
            v6,
            icmp4,
            icmp6,
            warned_send_failure: AtomicBool::new(false),
        }
    }

    /// Inert rejecter, as if every socket failed to open. Used by tests to
    /// exercise the degraded path without dropping privileges.
    #[cfg(test)]
    fn disabled() -> Self {
        Self {
            v4: None,
            v6: None,
            icmp4: None,
            icmp6: None,
            warned_send_failure: AtomicBool::new(false),
        }
    }

    /// Sends the refusal for a rejected flow.
    ///
    /// `conn` supplies the 5-tuple (already parsed by the worker) and
    /// `original` is the exact packet NFQUEUE handed us, needed for the
    /// TCP sequence arithmetic and the ICMP quotation.
    pub fn reject(&self, conn: &Connection, original: &[u8]) -> RejectOutcome {
        match conn.protocol {
            Protocol::Tcp => self.reject_tcp(conn, original),
            Protocol::Udp => self.reject_udp(conn, original),
            other => {
                trace!(protocol = ?other, "no reject response defined; dropping only");
                RejectOutcome::Unsupported
            }
        }
    }

    fn reject_tcp(&self, conn: &Connection, original: &[u8]) -> RejectOutcome {
        let Some(offset) = l4_offset(original) else {
            trace!("reject: cannot locate TCP header; dropping only");
            return RejectOutcome::Unsupported;
        };
        let Some(fields) = rst_fields(&original[offset..]) else {
            trace!("reject: truncated TCP header; dropping only");
            return RejectOutcome::Unsupported;
        };
        // Source = the peer the app dialed, destination = the app.
        let Some(packet) = build_tcp_rst(
            conn.dst_ip,
            conn.dst_port,
            conn.src_ip,
            conn.src_port,
            fields,
        ) else {
            trace!("reject: mixed address families; dropping only");
            return RejectOutcome::Unsupported;
        };
        let socket = match conn.src_ip {
            IpAddr::V4(_) => &self.v4,
            IpAddr::V6(_) => &self.v6,
        };
        self.emit(socket, conn.src_ip, &packet)
    }

    fn reject_udp(&self, conn: &Connection, original: &[u8]) -> RejectOutcome {
        let Some(packet) = build_icmp_port_unreachable(conn.dst_ip, conn.src_ip, original) else {
            trace!("reject: cannot quote the offending datagram; dropping only");
            return RejectOutcome::Unsupported;
        };
        let socket = match conn.src_ip {
            IpAddr::V4(_) => &self.icmp4,
            IpAddr::V6(_) => &self.icmp6,
        };
        self.emit(socket, conn.src_ip, &packet)
    }

    fn emit(&self, socket: &Option<OwnedFd>, dst: IpAddr, bytes: &[u8]) -> RejectOutcome {
        let Some(fd) = socket.as_ref() else {
            return RejectOutcome::Unavailable;
        };
        match send_raw(fd, dst, bytes) {
            Ok(()) => {
                trace!(%dst, len = bytes.len(), "reject response injected");
                RejectOutcome::Sent
            }
            Err(e) => {
                // This sits on the per-packet path: an unroutable
                // destination (or an IPv6 link-local one, which would need
                // a scope id we do not carry) must not flood the log.
                if self.warned_send_failure.swap(true, Ordering::Relaxed) {
                    debug!(%dst, "sending reject response failed: {e}");
                } else {
                    warn!(
                        %dst,
                        "sending reject response failed: {e} \
                         (further failures logged at debug)"
                    );
                }
                RejectOutcome::SendFailed
            }
        }
    }
}

// ---------------------------------------------------------------------
// Pure packet construction. No syscalls below this line except in the
// clearly marked socket layer at the bottom.
// ---------------------------------------------------------------------

/// Sequence numbers and ACK flag of the RST answering an offending
/// segment, per RFC 9293 s3.5.2 ("Reset Generation").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RstFields {
    pub seq: u32,
    pub ack: u32,
    /// Whether the RST carries the ACK flag (and a meaningful `ack`).
    pub ack_flag: bool,
}

/// Derives the RST fields from the offending TCP segment, or `None` when
/// no RST may be sent.
///
/// Two cases, straight from the RFC: a segment carrying ACK is answered
/// with `SEQ = SEG.ACK` and no ACK flag; otherwise (the common case - a
/// SYN opening the connection) the RST uses sequence zero and acknowledges
/// `SEG.SEQ + SEG.LEN`, where SYN and FIN each count as one octet. Getting
/// this wrong means the app's stack silently discards the RST and the
/// reject degrades to a slow drop.
pub fn rst_fields(tcp: &[u8]) -> Option<RstFields> {
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    let seq = u32::from_be_bytes(tcp[4..8].try_into().ok()?);
    let ack = u32::from_be_bytes(tcp[8..12].try_into().ok()?);
    let flags = tcp[13];

    // "A TCP endpoint MUST NOT send a RST in response to a segment
    // containing RST" (RFC 9293 s3.5.2) - answering one would risk a
    // reset war. The shipped nft rule never queues such a segment
    // (conntrack calls a bare RST INVALID, not NEW), but a deployment
    // that queues everything might.
    if flags & TCP_FLAG_RST != 0 {
        return None;
    }

    if flags & TCP_FLAG_ACK != 0 {
        return Some(RstFields {
            seq: ack,
            ack: 0,
            ack_flag: false,
        });
    }

    let data_offset = ((tcp[12] >> 4) as usize * 4).clamp(TCP_HEADER_LEN, tcp.len());
    let mut seg_len = (tcp.len() - data_offset) as u32;
    if flags & TCP_FLAG_SYN != 0 {
        seg_len += 1;
    }
    if flags & TCP_FLAG_FIN != 0 {
        seg_len += 1;
    }
    Some(RstFields {
        seq: 0,
        ack: seq.wrapping_add(seg_len),
        ack_flag: true,
    })
}

/// Builds a complete IP packet carrying a TCP RST from `src`:`src_port` to
/// `dst`:`dst_port`. Returns `None` if the two addresses are not the same
/// family (impossible for a parsed flow, but the type system allows it).
pub fn build_tcp_rst(
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    fields: RstFields,
) -> Option<Vec<u8>> {
    let mut tcp = tcp_rst_segment(src_port, dst_port, fields);
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let sum = checksum16(&[&v4_pseudo_header(src, dst, IPPROTO_TCP, tcp.len()), &tcp]);
            tcp[16..18].copy_from_slice(&sum.to_be_bytes());
            let mut packet = ipv4_header(src, dst, IPPROTO_TCP, tcp.len());
            packet.extend_from_slice(&tcp);
            Some(packet)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let sum = checksum16(&[&v6_pseudo_header(src, dst, IPPROTO_TCP, tcp.len()), &tcp]);
            tcp[16..18].copy_from_slice(&sum.to_be_bytes());
            let mut packet = ipv6_header(src, dst, IPPROTO_TCP, tcp.len());
            packet.extend_from_slice(&tcp);
            Some(packet)
        }
        _ => None,
    }
}

/// Builds a complete IP packet carrying an ICMP(v6) port-unreachable error
/// from `src` to `dst`, quoting `original` (the offending datagram as it
/// arrived from NFQUEUE). Returns `None` if the families disagree or the
/// quotation cannot be taken.
pub fn build_icmp_port_unreachable(src: IpAddr, dst: IpAddr, original: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            // RFC 792: IP header + 8 bytes of the datagram. The L4 offset
            // is the header length, so this is exactly `offset + 8`.
            let quote_len = l4_offset(original)?.checked_add(ICMPV4_QUOTE_L4_BYTES)?;
            if original.len() < quote_len {
                return None;
            }
            let mut icmp = icmp_error_header(ICMP_DEST_UNREACH, ICMP_CODE_PORT_UNREACH);
            icmp.extend_from_slice(&original[..quote_len]);
            // ICMPv4 has no pseudo-header: the checksum covers the
            // message only (RFC 792).
            let sum = checksum16(&[&icmp]);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());

            let mut packet = ipv4_header(src, dst, IPPROTO_ICMP, icmp.len());
            packet.extend_from_slice(&icmp);
            Some(packet)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            // RFC 4443 s3.1: quote as much as fits under the minimum MTU.
            let max_quote = IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMP_HEADER_LEN;
            let quote_len = original.len().min(max_quote);
            let mut icmp = icmp_error_header(ICMPV6_DEST_UNREACH, ICMPV6_CODE_PORT_UNREACH);
            icmp.extend_from_slice(&original[..quote_len]);
            // ICMPv6, unlike ICMPv4, checksums over the IPv6 pseudo-header
            // (RFC 4443 s2.3) - a v4-style checksum here would be dropped.
            let sum = checksum16(&[
                &v6_pseudo_header(src, dst, IPPROTO_ICMPV6, icmp.len()),
                &icmp,
            ]);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());

            let mut packet = ipv6_header(src, dst, IPPROTO_ICMPV6, icmp.len());
            packet.extend_from_slice(&icmp);
            Some(packet)
        }
        _ => None,
    }
}

/// 20-byte RST segment with a zero checksum placeholder at [16..18].
fn tcp_rst_segment(src_port: u16, dst_port: u16, fields: RstFields) -> Vec<u8> {
    let mut tcp = vec![0u8; TCP_HEADER_LEN];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&fields.seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&fields.ack.to_be_bytes());
    tcp[12] = 5 << 4; // data offset: 5 words, no options
    tcp[13] = TCP_FLAG_RST | if fields.ack_flag { TCP_FLAG_ACK } else { 0 };
    // Window 0 (a RST closes the connection), checksum filled by caller,
    // urgent pointer 0.
    tcp
}

/// ICMP / ICMPv6 error header: type, code, zero checksum, 4 unused bytes.
fn icmp_error_header(icmp_type: u8, code: u8) -> Vec<u8> {
    let mut icmp = vec![0u8; ICMP_HEADER_LEN];
    icmp[0] = icmp_type;
    icmp[1] = code;
    icmp
}

/// 20-byte IPv4 header with a correct header checksum.
///
/// The kernel overwrites total length and header checksum on an
/// `IP_HDRINCL` socket (raw(7)) and fills the identification when it is
/// zero, but we compute them anyway so the buffer is self-consistent and
/// assertable in tests.
fn ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: usize) -> Vec<u8> {
    let mut ip = vec![0u8; IPV4_HEADER_LEN];
    ip[0] = 0x45; // version 4, IHL 5 words
    let total = (IPV4_HEADER_LEN + payload_len) as u16;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    // Identification 0: the kernel assigns one on send.
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    ip[8] = DEFAULT_TTL;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let sum = checksum16(&[&ip]);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip
}

/// 40-byte IPv6 header. There is no header checksum in IPv6.
fn ipv6_header(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload_len: usize) -> Vec<u8> {
    let mut ip = vec![0u8; IPV6_HEADER_LEN];
    ip[0] = 0x60; // version 6, traffic class 0, flow label 0
    ip[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    ip[6] = next_header;
    ip[7] = DEFAULT_TTL;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip
}

/// TCP/UDP pseudo-header for IPv4 (RFC 793): src, dst, zero, protocol,
/// upper-layer length.
fn v4_pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, l4_len: usize) -> [u8; 12] {
    let mut ph = [0u8; 12];
    ph[0..4].copy_from_slice(&src.octets());
    ph[4..8].copy_from_slice(&dst.octets());
    ph[9] = protocol;
    ph[10..12].copy_from_slice(&(l4_len as u16).to_be_bytes());
    ph
}

/// Upper-layer pseudo-header for IPv6 (RFC 8200 s8.1): src, dst, 32-bit
/// upper-layer length, three zero bytes, next header.
fn v6_pseudo_header(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, l4_len: usize) -> [u8; 40] {
    let mut ph = [0u8; 40];
    ph[0..16].copy_from_slice(&src.octets());
    ph[16..32].copy_from_slice(&dst.octets());
    ph[32..36].copy_from_slice(&(l4_len as u32).to_be_bytes());
    ph[39] = next_header;
    ph
}

/// RFC 1071 one's-complement checksum over the concatenation of `parts`.
///
/// Taking a slice of slices avoids materializing pseudo-header + payload
/// into one buffer per packet; a byte left over at the end of one part is
/// carried into the next so the result matches the concatenated input
/// regardless of how it is split.
fn checksum16(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut pending: Option<u8> = None;

    for part in parts {
        let mut bytes: &[u8] = part;
        if let Some(high) = pending.take() {
            match bytes.split_first() {
                Some((&low, rest)) => {
                    sum += u32::from(u16::from_be_bytes([high, low]));
                    bytes = rest;
                }
                None => {
                    pending = Some(high);
                    continue;
                }
            }
        }
        let (words, remainder) = bytes.as_chunks::<2>();
        for word in words {
            sum += u32::from(u16::from_be_bytes(*word));
        }
        if let [last] = remainder {
            pending = Some(*last);
        }
    }
    if let Some(high) = pending {
        // Odd total length: pad with a zero byte.
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Offset of the upper-layer header inside a queued IP packet.
///
/// The worker's [`crate::packet`] parser reports the 5-tuple but not where
/// L4 starts, and we need that both for the TCP sequence arithmetic and
/// for the ICMPv4 quotation length. Mirrors the parser's IPv6
/// extension-header walk (same bound) so the two agree on what "the L4
/// header" means.
fn l4_offset(packet: &[u8]) -> Option<usize> {
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < IPV4_HEADER_LEN {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < IPV4_HEADER_LEN || packet.len() < ihl {
                return None;
            }
            Some(ihl)
        }
        6 => {
            if packet.len() < IPV6_HEADER_LEN {
                return None;
            }
            let mut next_header = packet[6];
            let mut offset = IPV6_HEADER_LEN;
            for _ in 0..=MAX_EXT_HEADERS {
                let len = match next_header {
                    IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                        (*packet.get(offset + 1)? as usize + 1) * 8
                    }
                    IPPROTO_AH => (*packet.get(offset + 1)? as usize + 2) * 4,
                    IPPROTO_FRAGMENT => 8,
                    _ => return Some(offset),
                };
                next_header = *packet.get(offset)?;
                offset = offset.checked_add(len)?;
                if packet.len() < offset {
                    return None;
                }
            }
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Socket layer: the only code here that talks to the kernel.
// ---------------------------------------------------------------------

/// AF_INET raw socket with `IP_HDRINCL`, so the source address we write is
/// the one that goes on the wire.
fn open_raw_v4(protocol: libc::c_int) -> std::io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the return value is checked before use and
    // ownership is transferred to OwnedFd exactly once.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a freshly created, valid descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_flag(&fd, libc::IPPROTO_IP, libc::IP_HDRINCL)?;
    Ok(fd)
}

/// AF_INET6 raw socket with `IPV6_HDRINCL` (Linux >= 4.5). Without it the
/// kernel would build the IPv6 header and pick the source address by
/// routing, defeating the impersonation the refusal depends on; on an
/// older kernel the setsockopt fails and this family degrades to
/// drop-only, which is the honest outcome.
fn open_raw_v6(protocol: libc::c_int) -> std::io::Result<OwnedFd> {
    // SAFETY: plain socket(2); see open_raw_v4.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a freshly created, valid descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_flag(&fd, libc::IPPROTO_IPV6, libc::IPV6_HDRINCL)?;
    Ok(fd)
}

fn set_flag(fd: &OwnedFd, level: libc::c_int, name: libc::c_int) -> std::io::Result<()> {
    let enable: libc::c_int = 1;
    // SAFETY: fd is valid and owned; the option value points at a properly
    // sized c_int that outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&enable as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Hands a fully built IP packet to the kernel for routing. `dst` only
/// selects the route - the addresses that go on the wire are the ones
/// inside `bytes`.
fn send_raw(fd: &OwnedFd, dst: IpAddr, bytes: &[u8]) -> std::io::Result<()> {
    let sent = match dst {
        IpAddr::V4(v4) => {
            // SAFETY: an all-zero sockaddr_in is valid; every field we
            // care about is set below.
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            // s_addr is __be32 and octets() is already network order.
            addr.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            // SAFETY: bytes is a valid initialized buffer of the stated
            // length and addr outlives the call.
            unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    0,
                    (&addr as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        IpAddr::V6(v6) => {
            // SAFETY: an all-zero sockaddr_in6 is valid; see above.
            let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_addr = libc::in6_addr {
                s6_addr: v6.octets(),
            };
            // sin6_scope_id stays 0: a link-local destination would need
            // the ingress ifindex, which the queue metadata does not carry
            // through to here. Such sends fail with EINVAL and are logged
            // once, rather than being silently mis-routed.
            // SAFETY: bytes is a valid initialized buffer of the stated
            // length and addr outlives the call.
            unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    0,
                    (&addr as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfc_core::Direction;

    const APP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
    const PEER: Ipv4Addr = Ipv4Addr::new(5, 6, 7, 8);
    const APP6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const PEER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const APP_PORT: u16 = 5555;
    const PEER_PORT: u16 = 80;

    /// Deliberately naive, independent one's-complement checksum used to
    /// cross-check [`checksum16`]. Written from RFC 1071 directly rather
    /// than shared with the implementation, so a bug in one shows up as a
    /// mismatch instead of cancelling out.
    fn naive_checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            sum += ((bytes[i] as u32) << 8) | bytes[i + 1] as u32;
            i += 2;
        }
        if i < bytes.len() {
            sum += (bytes[i] as u32) << 8;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// A checksummed buffer sums (including the checksum field) to zero -
    /// the classic RFC 1071 verification property.
    fn sums_to_zero(parts: &[&[u8]]) -> bool {
        checksum16(parts) == 0
    }

    /// Minimal IPv4 packet: `PEER`/`APP` with an L4 blob appended.
    fn ipv4_packet(protocol: u8, l4: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; IPV4_HEADER_LEN];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&((IPV4_HEADER_LEN + l4.len()) as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = protocol;
        pkt[12..16].copy_from_slice(&APP.octets());
        pkt[16..20].copy_from_slice(&PEER.octets());
        pkt.extend_from_slice(l4);
        pkt
    }

    fn ipv6_packet(next_header: u8, l4: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; IPV6_HEADER_LEN];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
        pkt[6] = next_header;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&APP6.octets());
        pkt[24..40].copy_from_slice(&PEER6.octets());
        pkt.extend_from_slice(l4);
        pkt
    }

    /// TCP header with the given sequence, ack and flags.
    fn tcp_header(seq: u32, ack: u32, flags: u8) -> Vec<u8> {
        let mut tcp = vec![0u8; TCP_HEADER_LEN];
        tcp[0..2].copy_from_slice(&APP_PORT.to_be_bytes());
        tcp[2..4].copy_from_slice(&PEER_PORT.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp
    }

    fn udp_header(payload_len: usize) -> Vec<u8> {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&APP_PORT.to_be_bytes());
        udp[2..4].copy_from_slice(&PEER_PORT.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        udp
    }

    fn conn(protocol: Protocol, src: IpAddr, dst: IpAddr) -> Connection {
        Connection::new(protocol, Direction::Outbound, src, APP_PORT, dst, PEER_PORT)
    }

    // ---- checksum helper ----

    #[test]
    fn checksum_matches_independent_implementation() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0xff],
            vec![0x45, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x40, 0x00],
            (0u8..=200).collect(),
            vec![0xff; 77],
        ];
        for case in cases {
            assert_eq!(
                checksum16(&[&case]),
                naive_checksum(&case),
                "mismatch for {case:?}"
            );
        }
    }

    #[test]
    fn checksum_is_split_invariant() {
        // Same bytes, split at an odd boundary: the carried byte must not
        // change the result, or every pseudo-header sum would be wrong.
        let all: Vec<u8> = (0u8..=99).collect();
        let whole = checksum16(&[&all]);
        assert_eq!(checksum16(&[&all[..7], &all[7..]]), whole);
        assert_eq!(checksum16(&[&all[..1], &all[1..50], &all[50..]]), whole);
        assert_eq!(checksum16(&[&[], &all, &[]]), whole);
    }

    // ---- RFC 9293 reset generation ----

    #[test]
    fn rst_fields_for_syn_acknowledges_seq_plus_one() {
        let syn = tcp_header(0x1000_0000, 0, TCP_FLAG_SYN);
        assert_eq!(
            rst_fields(&syn).unwrap(),
            RstFields {
                seq: 0,
                ack: 0x1000_0001,
                ack_flag: true,
            }
        );
    }

    #[test]
    fn rst_fields_for_acking_segment_uses_the_ack_field() {
        let seg = tcp_header(0x1000_0000, 0xdead_beef, TCP_FLAG_ACK);
        assert_eq!(
            rst_fields(&seg).unwrap(),
            RstFields {
                seq: 0xdead_beef,
                ack: 0,
                ack_flag: false,
            }
        );
    }

    #[test]
    fn rst_fields_count_payload_fin_and_wrap() {
        // Data-carrying segment without ACK: SEG.LEN is the payload.
        let mut seg = tcp_header(100, 0, 0);
        seg.extend_from_slice(&[0xaa; 12]);
        assert_eq!(rst_fields(&seg).unwrap().ack, 112);

        // FIN counts as one octet on top of the payload.
        let mut fin = tcp_header(100, 0, TCP_FLAG_FIN);
        fin.extend_from_slice(&[0xaa; 12]);
        assert_eq!(rst_fields(&fin).unwrap().ack, 113);

        // Sequence space wraps modulo 2^32.
        let syn = tcp_header(u32::MAX, 0, TCP_FLAG_SYN);
        assert_eq!(rst_fields(&syn).unwrap().ack, 0);

        // Truncated header: no fields, caller falls back to a plain drop.
        assert!(rst_fields(&[0u8; 12]).is_none());
    }

    #[test]
    fn rst_is_never_sent_in_response_to_a_rst() {
        // RFC 9293 s3.5.2: answering a RST with a RST invites a reset war.
        assert!(rst_fields(&tcp_header(1, 0, TCP_FLAG_RST)).is_none());
        assert!(rst_fields(&tcp_header(1, 9, TCP_FLAG_RST | TCP_FLAG_ACK)).is_none());

        // ...and the worker sees that as "nothing to inject", not as a
        // missing socket.
        let rejecter = Rejecter::disabled();
        assert_eq!(
            rejecter.reject(
                &conn(Protocol::Tcp, IpAddr::V4(APP), IpAddr::V4(PEER)),
                &ipv4_packet(6, &tcp_header(1, 0, TCP_FLAG_RST))
            ),
            RejectOutcome::Unsupported
        );
    }

    // ---- TCP RST construction ----

    #[test]
    fn build_tcp_rst_v4_byte_layout() {
        let fields = RstFields {
            seq: 0,
            ack: 0x1000_0001,
            ack_flag: true,
        };
        let pkt = build_tcp_rst(
            IpAddr::V4(PEER),
            PEER_PORT,
            IpAddr::V4(APP),
            APP_PORT,
            fields,
        )
        .unwrap();

        assert_eq!(pkt.len(), IPV4_HEADER_LEN + TCP_HEADER_LEN);
        let (ip, tcp) = pkt.split_at(IPV4_HEADER_LEN);

        // IPv4 header, byte for byte (checksum checked separately).
        assert_eq!(ip[0], 0x45);
        assert_eq!(ip[1], 0x00);
        assert_eq!(&ip[2..4], &40u16.to_be_bytes()); // total length
        assert_eq!(&ip[4..6], &[0, 0]); // id: filled in by the kernel
        assert_eq!(&ip[6..8], &[0x40, 0x00]); // DF, fragment offset 0
        assert_eq!(ip[8], 64); // TTL
        assert_eq!(ip[9], IPPROTO_TCP);
        assert_eq!(&ip[12..16], &PEER.octets()); // impersonated peer
        assert_eq!(&ip[16..20], &APP.octets()); // back to the app

        // TCP header, byte for byte.
        assert_eq!(&tcp[0..2], &PEER_PORT.to_be_bytes());
        assert_eq!(&tcp[2..4], &APP_PORT.to_be_bytes());
        assert_eq!(&tcp[4..8], &0u32.to_be_bytes()); // seq
        assert_eq!(&tcp[8..12], &0x1000_0001u32.to_be_bytes()); // ack
        assert_eq!(tcp[12], 0x50); // data offset 5, no options
        assert_eq!(tcp[13], TCP_FLAG_RST | TCP_FLAG_ACK);
        assert_eq!(&tcp[14..16], &[0, 0]); // window
        assert_eq!(&tcp[18..20], &[0, 0]); // urgent pointer

        // Checksums against the independent implementation, plus the
        // "sums to zero" property of a correctly checksummed buffer.
        let mut ip_zeroed = ip.to_vec();
        ip_zeroed[10..12].copy_from_slice(&[0, 0]);
        assert_eq!(
            u16::from_be_bytes([ip[10], ip[11]]),
            naive_checksum(&ip_zeroed)
        );
        assert!(sums_to_zero(&[ip]));

        let pseudo = v4_pseudo_header(PEER, APP, IPPROTO_TCP, TCP_HEADER_LEN);
        assert_eq!(&pseudo[..4], &PEER.octets());
        assert_eq!(&pseudo[4..8], &APP.octets());
        assert_eq!(&pseudo[8..12], &[0, IPPROTO_TCP, 0, 20]);
        let mut tcp_zeroed = tcp.to_vec();
        tcp_zeroed[16..18].copy_from_slice(&[0, 0]);
        assert_eq!(
            u16::from_be_bytes([tcp[16], tcp[17]]),
            naive_checksum(&[pseudo.as_slice(), tcp_zeroed.as_slice()].concat())
        );
        assert!(sums_to_zero(&[&pseudo, tcp]));
    }

    #[test]
    fn build_tcp_rst_v4_without_ack_flag() {
        let fields = RstFields {
            seq: 0xdead_beef,
            ack: 0,
            ack_flag: false,
        };
        let pkt = build_tcp_rst(
            IpAddr::V4(PEER),
            PEER_PORT,
            IpAddr::V4(APP),
            APP_PORT,
            fields,
        )
        .unwrap();
        let tcp = &pkt[IPV4_HEADER_LEN..];
        assert_eq!(tcp[13], TCP_FLAG_RST);
        assert_eq!(&tcp[4..8], &0xdead_beefu32.to_be_bytes());
        assert!(sums_to_zero(&[
            &v4_pseudo_header(PEER, APP, IPPROTO_TCP, TCP_HEADER_LEN),
            tcp
        ]));
    }

    #[test]
    fn build_tcp_rst_v6_byte_layout() {
        let fields = RstFields {
            seq: 0,
            ack: 42,
            ack_flag: true,
        };
        let pkt = build_tcp_rst(
            IpAddr::V6(PEER6),
            PEER_PORT,
            IpAddr::V6(APP6),
            APP_PORT,
            fields,
        )
        .unwrap();

        assert_eq!(pkt.len(), IPV6_HEADER_LEN + TCP_HEADER_LEN);
        let (ip, tcp) = pkt.split_at(IPV6_HEADER_LEN);
        assert_eq!(ip[0], 0x60);
        assert_eq!(&ip[1..4], &[0, 0, 0]); // traffic class / flow label
        assert_eq!(&ip[4..6], &(TCP_HEADER_LEN as u16).to_be_bytes());
        assert_eq!(ip[6], IPPROTO_TCP);
        assert_eq!(ip[7], 64); // hop limit
        assert_eq!(&ip[8..24], &PEER6.octets());
        assert_eq!(&ip[24..40], &APP6.octets());
        assert_eq!(tcp[13], TCP_FLAG_RST | TCP_FLAG_ACK);

        // IPv6 TCP checksums over the 40-byte pseudo-header.
        let pseudo = v6_pseudo_header(PEER6, APP6, IPPROTO_TCP, TCP_HEADER_LEN);
        assert_eq!(&pseudo[32..36], &(TCP_HEADER_LEN as u32).to_be_bytes());
        assert_eq!(pseudo[39], IPPROTO_TCP);
        assert!(sums_to_zero(&[&pseudo, tcp]));
    }

    #[test]
    fn build_tcp_rst_rejects_mixed_families() {
        let fields = RstFields {
            seq: 0,
            ack: 1,
            ack_flag: true,
        };
        assert!(build_tcp_rst(
            IpAddr::V4(PEER),
            PEER_PORT,
            IpAddr::V6(APP6),
            APP_PORT,
            fields
        )
        .is_none());
    }

    // ---- ICMP port unreachable ----

    #[test]
    fn icmpv4_port_unreachable_structure() {
        let original = ipv4_packet(17, &[udp_header(4), vec![1, 2, 3, 4]].concat());
        let pkt =
            build_icmp_port_unreachable(IpAddr::V4(PEER), IpAddr::V4(APP), &original).unwrap();

        // IPv4 header + 8-byte ICMP header + 28-byte quotation.
        assert_eq!(pkt.len(), IPV4_HEADER_LEN + ICMP_HEADER_LEN + 28);
        let (ip, icmp) = pkt.split_at(IPV4_HEADER_LEN);
        assert_eq!(ip[9], IPPROTO_ICMP);
        assert_eq!(&ip[2..4], &(pkt.len() as u16).to_be_bytes());
        assert_eq!(&ip[12..16], &PEER.octets());
        assert_eq!(&ip[16..20], &APP.octets());
        assert!(sums_to_zero(&[ip]));

        assert_eq!(icmp[0], 3); // destination unreachable
        assert_eq!(icmp[1], 3); // port unreachable
        assert_eq!(&icmp[4..8], &[0, 0, 0, 0]); // unused

        // Quotation: the offending IP header plus exactly 8 bytes of the
        // datagram, i.e. the UDP header - the payload is not quoted.
        let quote = &icmp[ICMP_HEADER_LEN..];
        assert_eq!(quote.len(), IPV4_HEADER_LEN + 8);
        assert_eq!(quote, &original[..IPV4_HEADER_LEN + 8]);
        assert_eq!(&quote[IPV4_HEADER_LEN..][..2], &APP_PORT.to_be_bytes());
        assert_eq!(&quote[IPV4_HEADER_LEN..][2..4], &PEER_PORT.to_be_bytes());

        // ICMPv4 has no pseudo-header in its checksum.
        let mut zeroed = icmp.to_vec();
        zeroed[2..4].copy_from_slice(&[0, 0]);
        assert_eq!(
            u16::from_be_bytes([icmp[2], icmp[3]]),
            naive_checksum(&zeroed)
        );
        assert!(sums_to_zero(&[icmp]));
    }

    #[test]
    fn icmpv4_needs_a_full_quotation() {
        // Header present but fewer than 8 bytes of datagram: nothing
        // RFC-conformant to send, so the flow is drop-only.
        let short = ipv4_packet(17, &[0u8; 4]);
        assert!(build_icmp_port_unreachable(IpAddr::V4(PEER), IpAddr::V4(APP), &short).is_none());
        assert!(build_icmp_port_unreachable(IpAddr::V4(PEER), IpAddr::V4(APP), &[]).is_none());
    }

    #[test]
    fn icmpv6_port_unreachable_structure() {
        let original = ipv6_packet(17, &[udp_header(4), vec![1, 2, 3, 4]].concat());
        let pkt =
            build_icmp_port_unreachable(IpAddr::V6(PEER6), IpAddr::V6(APP6), &original).unwrap();

        // IPv6 quotes the whole invoking packet when it fits.
        assert_eq!(
            pkt.len(),
            IPV6_HEADER_LEN + ICMP_HEADER_LEN + original.len()
        );
        let (ip, icmp) = pkt.split_at(IPV6_HEADER_LEN);
        assert_eq!(ip[0], 0x60);
        assert_eq!(ip[6], IPPROTO_ICMPV6);
        assert_eq!(&ip[4..6], &(icmp.len() as u16).to_be_bytes());
        assert_eq!(&ip[8..24], &PEER6.octets());
        assert_eq!(&ip[24..40], &APP6.octets());

        assert_eq!(icmp[0], 1); // destination unreachable
        assert_eq!(icmp[1], 4); // port unreachable
        assert_eq!(&icmp[4..8], &[0, 0, 0, 0]);
        assert_eq!(&icmp[ICMP_HEADER_LEN..], &original[..]);

        // ICMPv6 checksums over the IPv6 pseudo-header (RFC 4443 s2.3).
        let pseudo = v6_pseudo_header(PEER6, APP6, IPPROTO_ICMPV6, icmp.len());
        let mut zeroed = icmp.to_vec();
        zeroed[2..4].copy_from_slice(&[0, 0]);
        assert_eq!(
            u16::from_be_bytes([icmp[2], icmp[3]]),
            naive_checksum(&[pseudo.as_slice(), zeroed.as_slice()].concat())
        );
        assert!(sums_to_zero(&[&pseudo, icmp]));
        // A v4-style (pseudo-header-less) checksum would differ; make sure
        // we did not accidentally compute that one.
        assert_ne!(
            u16::from_be_bytes([icmp[2], icmp[3]]),
            naive_checksum(&zeroed)
        );
    }

    #[test]
    fn icmpv6_quotation_is_capped_at_the_minimum_mtu() {
        let original = ipv6_packet(17, &vec![0xab; 4000]);
        let pkt =
            build_icmp_port_unreachable(IpAddr::V6(PEER6), IpAddr::V6(APP6), &original).unwrap();
        assert_eq!(pkt.len(), IPV6_MIN_MTU);
        let quote = &pkt[IPV6_HEADER_LEN + ICMP_HEADER_LEN..];
        assert_eq!(
            quote.len(),
            IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMP_HEADER_LEN
        );
        assert_eq!(quote, &original[..quote.len()]);
    }

    // ---- L4 offset recovery ----

    #[test]
    fn l4_offset_handles_options_and_extension_headers() {
        assert_eq!(l4_offset(&ipv4_packet(6, &tcp_header(1, 0, 0))), Some(20));

        // IPv4 with 8 bytes of options (IHL 7).
        let mut with_options = ipv4_packet(6, &tcp_header(1, 0, 0));
        with_options[0] = 0x47;
        assert_eq!(l4_offset(&with_options), Some(28));

        // Plain IPv6.
        assert_eq!(l4_offset(&ipv6_packet(6, &tcp_header(1, 0, 0))), Some(40));

        // IPv6 behind a hop-by-hop header.
        let mut hbh = ipv6_packet(IPPROTO_HOPOPTS, &[]);
        hbh.extend_from_slice(&[IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        hbh.extend_from_slice(&tcp_header(1, 0, 0));
        assert_eq!(l4_offset(&hbh), Some(48));

        // Garbage and truncation never panic and never lie.
        assert_eq!(l4_offset(&[]), None);
        assert_eq!(l4_offset(&[0x90, 0, 0, 0]), None);
        assert_eq!(l4_offset(&[0x40, 0, 0]), None);
        let mut bad_ihl = ipv4_packet(6, &tcp_header(1, 0, 0));
        bad_ihl[0] = 0x44; // IHL 16 bytes, below the 20-byte minimum
        assert_eq!(l4_offset(&bad_ihl), None);
    }

    // ---- Rejecter behaviour ----

    #[test]
    fn disabled_rejecter_is_a_no_op() {
        let rejecter = Rejecter::disabled();
        let tcp = ipv4_packet(6, &tcp_header(7, 0, TCP_FLAG_SYN));
        assert_eq!(
            rejecter.reject(
                &conn(Protocol::Tcp, IpAddr::V4(APP), IpAddr::V4(PEER)),
                &tcp
            ),
            RejectOutcome::Unavailable
        );

        let udp = ipv4_packet(17, &udp_header(0));
        assert_eq!(
            rejecter.reject(
                &conn(Protocol::Udp, IpAddr::V4(APP), IpAddr::V4(PEER)),
                &udp
            ),
            RejectOutcome::Unavailable
        );

        let tcp6 = ipv6_packet(6, &tcp_header(7, 0, TCP_FLAG_SYN));
        assert_eq!(
            rejecter.reject(
                &conn(Protocol::Tcp, IpAddr::V6(APP6), IpAddr::V6(PEER6)),
                &tcp6
            ),
            RejectOutcome::Unavailable
        );
    }

    #[test]
    fn protocols_without_a_refusal_report_unsupported() {
        let rejecter = Rejecter::disabled();
        // ICMP and friends: no "connection refused" concept exists, so the
        // flow is dropped and nothing is injected - reported before the
        // socket is even consulted.
        for protocol in [Protocol::Icmp, Protocol::Other(50), Protocol::Other(132)] {
            assert_eq!(
                rejecter.reject(
                    &conn(protocol, IpAddr::V4(APP), IpAddr::V4(PEER)),
                    &ipv4_packet(1, &[0u8; 8])
                ),
                RejectOutcome::Unsupported,
                "{protocol:?}"
            );
        }
    }

    #[test]
    fn malformed_packets_report_unsupported_not_unavailable() {
        let rejecter = Rejecter::disabled();
        // Claims TCP but the header is truncated: we cannot derive RFC-
        // conformant sequence numbers, so no RST is attempted.
        let truncated = ipv4_packet(6, &[0u8; 8]);
        assert_eq!(
            rejecter.reject(
                &conn(Protocol::Tcp, IpAddr::V4(APP), IpAddr::V4(PEER)),
                &truncated
            ),
            RejectOutcome::Unsupported
        );
        assert_eq!(
            rejecter.reject(&conn(Protocol::Tcp, IpAddr::V4(APP), IpAddr::V4(PEER)), &[]),
            RejectOutcome::Unsupported
        );
    }

    #[test]
    fn open_never_panics_without_privileges() {
        // Runs unprivileged in CI (all sockets fail, single WARN) and as
        // root locally (sockets open); neither may panic.
        let rejecter = Rejecter::open();
        let outcome = rejecter.reject(
            &conn(Protocol::Other(89), IpAddr::V4(APP), IpAddr::V4(PEER)),
            &ipv4_packet(89, &[0u8; 8]),
        );
        assert_eq!(outcome, RejectOutcome::Unsupported);
    }
}
