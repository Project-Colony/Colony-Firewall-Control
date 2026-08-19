//! Minimal NETLINK_SOCK_DIAG client: one INET_DIAG_REQ_V2 exact-tuple
//! query per new connection instead of parsing entire /proc/net tables.
//!
//! Deliberately tiny: raw libc socket, hand-serialized request, fixed-part
//! response parse. On ANY failure (EPERM in containers, unsupported
//! protocol, kernel without the diag module) the caller falls back to the
//! /proc scan, so every error path here just returns None with a trace log.
//!
//! Byte-order note: nlmsghdr and inet_diag fields are host-endian, but the
//! sockid ports/addresses are big-endian (network order), matching the
//! kernel's __be16/__be32 declarations.

use cfc_core::Protocol;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tracing::trace;

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_HDR_LEN: usize = 16;
const INET_DIAG_REQ_V2_LEN: usize = 56;
const REQ_LEN: usize = NLMSG_HDR_LEN + INET_DIAG_REQ_V2_LEN;
/// Fixed part of struct inet_diag_msg (before any attributes).
const INET_DIAG_MSG_LEN: usize = 72;

/// Answer to an exact-tuple query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockInfo {
    pub inode: u64,
    /// `sk_cookie`, the kernel's stable per-socket id. The same value the
    /// `cfc_connect4|6` programs key `SOCK_PIDS` on: both sides go through
    /// `sock_gen_cookie`, which assigns it lazily to whoever asks first.
    /// `None` when the kernel reported the unassigned sentinel.
    pub cookie: Option<u64>,
    #[allow(dead_code)]
    pub uid: u32,
}

/// Look up the socket for a flow by exact 4-tuple.
///
/// `src` is the local endpoint, `dst` the remote one. Returns None on any
/// error or miss; the caller is expected to fall back to /proc/net.
pub fn query(
    protocol: Protocol,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<SockInfo> {
    let proto_num = match protocol {
        Protocol::Tcp => libc::IPPROTO_TCP as u8,
        Protocol::Udp => libc::IPPROTO_UDP as u8,
        _ => return None,
    };
    let family = match src_ip {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    };

    let sock = match DiagSocket::open() {
        Ok(s) => s,
        Err(e) => {
            trace!("sock_diag socket unavailable ({e}); falling back to /proc");
            return None;
        }
    };

    let req = build_request(family, proto_num, (src_ip, src_port), (dst_ip, dst_port));
    if let Some(info) = sock.round_trip(&req) {
        return Some(info);
    }

    // udp_diag's exact lookup historically interprets the sockid with
    // src/dst swapped relative to tcp_diag (it feeds the request straight
    // into the incoming-packet lookup). Retry swapped before giving up;
    // for unconnected sockets the kernel may still miss, in which case
    // the /proc scan's zero-remote pass takes over.
    if protocol == Protocol::Udp {
        let req = build_request(family, proto_num, (dst_ip, dst_port), (src_ip, src_port));
        return sock.round_trip(&req);
    }
    None
}

/// Serialize nlmsghdr + inet_diag_req_v2 for an exact (non-dump) query.
fn build_request(
    family: u8,
    protocol: u8,
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
) -> [u8; REQ_LEN] {
    let mut buf = [0u8; REQ_LEN];

    // struct nlmsghdr: len, type, flags, seq, pid (all host-endian).
    buf[0..4].copy_from_slice(&(REQ_LEN as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    buf[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_ne_bytes());
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
                                                     // nlmsg_pid stays 0 (kernel).

    // struct inet_diag_req_v2.
    buf[16] = family;
    buf[17] = protocol;
    // idiag_ext = 0, pad = 0.
    buf[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // idiag_states: all

    // struct inet_diag_sockid: sport, dport (big-endian), src, dst,
    // interface, cookie.
    buf[24..26].copy_from_slice(&local.1.to_be_bytes());
    buf[26..28].copy_from_slice(&remote.1.to_be_bytes());
    write_addr(&mut buf[28..44], local.0);
    write_addr(&mut buf[44..60], remote.0);
    // idiag_if = 0 (any).
    buf[64..72].copy_from_slice(&[0xFF; 8]); // INET_DIAG_NOCOOKIE x2

    buf
}

fn write_addr(dst: &mut [u8], ip: IpAddr) {
    match ip {
        // AF_INET uses only idiag_src[0] / idiag_dst[0].
        IpAddr::V4(v4) => dst[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => dst[..16].copy_from_slice(&v6.octets()),
    }
}

/// Parse the first netlink message of a reply. Exact (non-dump) queries
/// answer with a single SOCK_DIAG_BY_FAMILY message or an NLMSG_ERROR.
fn parse_response(buf: &[u8]) -> Option<SockInfo> {
    if buf.len() < NLMSG_HDR_LEN {
        return None;
    }
    let msg_len = u32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize;
    let msg_type = u16::from_ne_bytes(buf[4..6].try_into().ok()?);
    if msg_type != SOCK_DIAG_BY_FAMILY || msg_len > buf.len() {
        // NLMSG_ERROR (no such socket, EPERM, ...) or truncated reply.
        return None;
    }
    let payload = &buf[NLMSG_HDR_LEN..msg_len];
    if payload.len() < INET_DIAG_MSG_LEN {
        return None;
    }
    // struct inet_diag_msg: id.idiag_cookie sits at payload offset 44
    // (family/state/timer/retrans = 4, sport+dport = 4, src = 16, dst = 16,
    // if = 4), then expires, rqueue, wqueue, uid at 64, inode at 68. The
    // kernel splits `sk_cookie` into two native-endian u32s, which on the
    // architectures this daemon targets reads back as one ne u64.
    let cookie_raw = u64::from_ne_bytes(payload[44..52].try_into().ok()?);
    let cookie = (cookie_raw != 0 && cookie_raw != u64::MAX).then_some(cookie_raw);
    let uid = u32::from_ne_bytes(payload[64..68].try_into().ok()?);
    let inode = u32::from_ne_bytes(payload[68..72].try_into().ok()?) as u64;
    if inode == 0 {
        return None;
    }
    Some(SockInfo { inode, uid, cookie })
}

/// Owned NETLINK_SOCK_DIAG socket with a short receive timeout.
struct DiagSocket(OwnedFd);

impl DiagSocket {
    fn open() -> std::io::Result<Self> {
        // SAFETY: plain socket(2); the return value is checked before use
        // and ownership is transferred to OwnedFd exactly once.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is a freshly created, valid descriptor we own.
        let sock = Self(unsafe { OwnedFd::from_raw_fd(fd) });

        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        // SAFETY: fd is valid; the option value points at a properly sized
        // timeval that outlives the call. Best-effort: failure only means
        // a blocking recv, which the kernel answers promptly anyway.
        unsafe {
            libc::setsockopt(
                sock.0.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        Ok(sock)
    }

    fn round_trip(&self, req: &[u8]) -> Option<SockInfo> {
        let fd = self.0.as_raw_fd();

        // SAFETY: zeroed sockaddr_nl is a valid "to the kernel" address.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;

        // SAFETY: req is a valid, initialized buffer of the stated length;
        // the address struct outlives the call.
        let sent = unsafe {
            libc::sendto(
                fd,
                req.as_ptr().cast(),
                req.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent != req.len() as isize {
            trace!(
                "sock_diag send failed ({}); falling back to /proc",
                std::io::Error::last_os_error()
            );
            return None;
        }

        let mut buf = [0u8; 8192];
        // SAFETY: buf is a valid writable buffer of the stated length.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            trace!(
                "sock_diag recv failed ({}); falling back to /proc",
                std::io::Error::last_os_error()
            );
            return None;
        }
        parse_response(&buf[..n as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    #[test]
    fn request_serialization_layout() {
        let local = (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote = (IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let req = build_request(libc::AF_INET as u8, libc::IPPROTO_TCP as u8, local, remote);

        // nlmsghdr.
        assert_eq!(u32::from_ne_bytes(req[0..4].try_into().unwrap()), 72);
        assert_eq!(u16::from_ne_bytes(req[4..6].try_into().unwrap()), 20); // SOCK_DIAG_BY_FAMILY
        assert_eq!(
            u16::from_ne_bytes(req[6..8].try_into().unwrap()),
            libc::NLM_F_REQUEST as u16
        );
        assert_eq!(u32::from_ne_bytes(req[8..12].try_into().unwrap()), 1); // seq
        assert_eq!(&req[12..16], &[0; 4]); // pid

        // inet_diag_req_v2.
        assert_eq!(req[16], libc::AF_INET as u8);
        assert_eq!(req[17], libc::IPPROTO_TCP as u8);
        assert_eq!(&req[18..20], &[0, 0]); // ext + pad
        assert_eq!(&req[20..24], &[0xFF; 4]); // states = all

        // sockid: ports big-endian, addresses network order.
        assert_eq!(&req[24..26], &[0x1F, 0x90]); // 8080
        assert_eq!(&req[26..28], &[0x01, 0xBB]); // 443
        assert_eq!(&req[28..32], &[127, 0, 0, 1]);
        assert_eq!(&req[32..44], &[0; 12]); // rest of idiag_src
        assert_eq!(&req[44..48], &[93, 184, 216, 34]);
        assert_eq!(&req[48..60], &[0; 12]); // rest of idiag_dst
        assert_eq!(&req[60..64], &[0; 4]); // idiag_if
        assert_eq!(&req[64..72], &[0xFF; 8]); // INET_DIAG_NOCOOKIE
    }

    #[test]
    fn request_serialization_v6_addresses() {
        let local = (IpAddr::V6("2001:db8::1".parse().unwrap()), 1);
        let remote = (IpAddr::V6("::1".parse().unwrap()), 2);
        let req = build_request(libc::AF_INET6 as u8, libc::IPPROTO_UDP as u8, local, remote);
        assert_eq!(
            &req[28..44],
            &[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            &req[44..60],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn parses_inet_diag_reply() {
        let mut buf = vec![0u8; NLMSG_HDR_LEN + INET_DIAG_MSG_LEN];
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        buf[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        // uid at payload offset 64, inode at 68.
        buf[NLMSG_HDR_LEN + 64..NLMSG_HDR_LEN + 68].copy_from_slice(&1000u32.to_ne_bytes());
        buf[NLMSG_HDR_LEN + 68..NLMSG_HDR_LEN + 72].copy_from_slice(&31337u32.to_ne_bytes());
        assert_eq!(
            parse_response(&buf),
            Some(SockInfo {
                inode: 31337,
                cookie: None,
                uid: 1000
            })
        );
    }

    #[test]
    fn error_reply_is_none() {
        // NLMSG_ERROR (type 2) reply, as the kernel sends for a miss.
        let mut buf = vec![0u8; NLMSG_HDR_LEN + 4];
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        buf[4..6].copy_from_slice(&2u16.to_ne_bytes());
        buf[NLMSG_HDR_LEN..].copy_from_slice(&(-2i32).to_ne_bytes()); // -ENOENT
        assert_eq!(parse_response(&buf), None);
    }

    #[test]
    fn truncated_reply_is_none() {
        assert_eq!(parse_response(&[0u8; 8]), None);
        let mut buf = vec![0u8; NLMSG_HDR_LEN + 8];
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        buf[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        assert_eq!(parse_response(&buf), None);
    }

    #[test]
    fn unmatched_tuple_degrades_to_none() {
        // Whether or not sock_diag is permitted in this environment, a
        // query for a tuple nobody owns must return None without panicking.
        let got = query(
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            1,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
            1,
        );
        assert_eq!(got, None);
    }

    fn socket_inode(sock: &UdpSocket) -> u64 {
        // SAFETY: zeroed stat is valid out-param storage; fd is open.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(sock.as_raw_fd(), &mut st) };
        assert_eq!(rc, 0, "fstat on test socket");
        st.st_ino
    }

    /// Live query against a socket this test owns. Exercises the real
    /// netlink round-trip; sock_diag is queryable without privileges on
    /// normal kernels (verified on this machine).
    #[test]
    fn live_query_finds_own_udp_socket() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
        sock.connect("127.0.0.1:9").expect("connect test socket");
        let local: SocketAddr = sock.local_addr().unwrap();
        let inode = socket_inode(&sock);

        let got = query(
            Protocol::Udp,
            local.ip(),
            local.port(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9,
        );
        assert_eq!(
            got.map(|i| i.inode),
            Some(inode),
            "sock_diag should find the test's own connected UDP socket"
        );
    }
}
