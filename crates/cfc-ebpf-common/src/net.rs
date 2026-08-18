//! Bounded L3/L4 offset arithmetic.
//!
//! The `cgroup_skb` hooks hand the program an `skb` whose data starts at the
//! **IP header** (there is no Ethernet header at that layer). This module turns
//! those bytes into "where does the UDP payload begin and how long is it",
//! using only [`Option`]-returning reads so no panic path is ever generated.
//!
//! Same rules as [`crate::dns`]: constant loop bounds, no slicing, no
//! allocation, `no_std`.

/// IPv4/IPv6 protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;

/// The DNS service port.
pub const DNS_PORT: u16 = 53;

/// Minimum IPv4 header length in bytes.
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Fixed IPv6 header length in bytes.
pub const IPV6_HEADER_LEN: usize = 40;

/// UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// Location of a UDP datagram's payload inside a buffer that starts at L3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpPayload {
    /// UDP source port, host byte order.
    pub src_port: u16,
    /// UDP destination port, host byte order.
    pub dst_port: u16,
    /// Offset of the first payload byte, relative to the start of the buffer.
    pub offset: usize,
    /// Number of payload bytes actually readable (already clamped to `valid`).
    pub len: usize,
}

#[inline(always)]
fn u8_at(buf: &[u8], valid: usize, off: usize) -> Option<u8> {
    if off >= valid {
        return None;
    }
    buf.get(off).copied()
}

#[inline(always)]
fn u16_at(buf: &[u8], valid: usize, off: usize) -> Option<u16> {
    let hi = u8_at(buf, valid, off)? as u16;
    let lo = u8_at(buf, valid, off + 1)? as u16;
    Some((hi << 8) | lo)
}

/// Locates the UDP payload in a buffer whose byte 0 is the IP header.
///
/// `valid` is how many bytes of `buf` were actually filled from the packet.
///
/// Returns `None` for anything that is not a complete, unfragmented UDP
/// datagram. Specifically **skipped**:
///
/// * IPv4 fragments other than the first (a later fragment has no UDP header);
/// * IPv6 packets with extension headers (next-header != UDP) — parsing the
///   chain would need another unbounded-ish loop for very little gain;
/// * anything whose headers do not fit inside `valid`.
#[inline(always)]
pub fn udp_payload_from_l3(buf: &[u8], valid: usize) -> Option<UdpPayload> {
    let first = u8_at(buf, valid, 0)?;
    let l4_off = match first >> 4 {
        4 => {
            let ihl = (first & 0x0f) as usize * 4;
            if ihl < IPV4_MIN_HEADER_LEN {
                return None;
            }
            if u8_at(buf, valid, 9)? != IPPROTO_UDP {
                return None;
            }
            // Fragment offset must be zero: only the first fragment carries L4.
            let frag = u16_at(buf, valid, 6)?;
            if frag & 0x1fff != 0 {
                return None;
            }
            ihl
        }
        6 => {
            if u8_at(buf, valid, 6)? != IPPROTO_UDP {
                return None;
            }
            IPV6_HEADER_LEN
        }
        _ => return None,
    };

    let src_port = u16_at(buf, valid, l4_off)?;
    let dst_port = u16_at(buf, valid, l4_off + 2)?;
    let udp_len = u16_at(buf, valid, l4_off + 4)? as usize;
    if udp_len < UDP_HEADER_LEN {
        return None;
    }

    let offset = l4_off + UDP_HEADER_LEN;
    if offset > valid {
        return None;
    }
    let declared = udp_len - UDP_HEADER_LEN;
    let available = valid - offset;
    let len = if declared < available {
        declared
    } else {
        available
    };

    Some(UdpPayload {
        src_port,
        dst_port,
        offset,
        len,
    })
}

/// True when this datagram looks like a DNS *response* (source port 53).
#[inline(always)]
pub fn is_dns_response(p: &UdpPayload) -> bool {
    p.src_port == DNS_PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(payload: &[u8], src_port: u16, dst_port: u16, ihl_words: u8, frag: u16) -> Vec<u8> {
        let ihl = ihl_words as usize * 4;
        let mut v = vec![0u8; ihl];
        v[0] = 0x40 | ihl_words;
        let total = (ihl + UDP_HEADER_LEN + payload.len()) as u16;
        v[2..4].copy_from_slice(&total.to_be_bytes());
        v[6..8].copy_from_slice(&frag.to_be_bytes());
        v[9] = IPPROTO_UDP;
        v.extend_from_slice(&src_port.to_be_bytes());
        v.extend_from_slice(&dst_port.to_be_bytes());
        v.extend_from_slice(&((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes());
        v.extend_from_slice(&[0, 0]); // checksum
        v.extend_from_slice(payload);
        v
    }

    fn ipv6_udp(payload: &[u8], src_port: u16, dst_port: u16, next_header: u8) -> Vec<u8> {
        let mut v = vec![0u8; IPV6_HEADER_LEN];
        v[0] = 0x60;
        let plen = (UDP_HEADER_LEN + payload.len()) as u16;
        v[4..6].copy_from_slice(&plen.to_be_bytes());
        v[6] = next_header;
        v.extend_from_slice(&src_port.to_be_bytes());
        v.extend_from_slice(&dst_port.to_be_bytes());
        v.extend_from_slice(&plen.to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn ipv4_no_options() {
        let p = ipv4_udp(b"hello", 53, 40000, 5, 0);
        let u = udp_payload_from_l3(&p, p.len()).unwrap();
        assert_eq!(u.src_port, 53);
        assert_eq!(u.dst_port, 40000);
        assert_eq!(u.offset, 28);
        assert_eq!(u.len, 5);
        assert!(is_dns_response(&u));
        assert_eq!(&p[u.offset..u.offset + u.len], b"hello");
    }

    #[test]
    fn ipv4_with_options() {
        let p = ipv4_udp(b"xy", 53, 1, 8, 0); // 32-byte IPv4 header
        let u = udp_payload_from_l3(&p, p.len()).unwrap();
        assert_eq!(u.offset, 40);
        assert_eq!(u.len, 2);
    }

    #[test]
    fn ipv4_short_ihl_is_rejected() {
        let mut p = ipv4_udp(b"x", 53, 1, 5, 0);
        p[0] = 0x44; // ihl = 4 words = 16 bytes
        assert!(udp_payload_from_l3(&p, p.len()).is_none());
    }

    #[test]
    fn ipv4_later_fragment_is_rejected() {
        let p = ipv4_udp(b"x", 53, 1, 5, 0x0001);
        assert!(udp_payload_from_l3(&p, p.len()).is_none());
    }

    #[test]
    fn ipv4_first_fragment_with_mf_is_accepted() {
        // MF bit set (0x2000) but offset 0 -> this fragment does have the UDP
        // header, so we can still read the beginning of the response.
        let p = ipv4_udp(b"x", 53, 1, 5, 0x2000);
        assert!(udp_payload_from_l3(&p, p.len()).is_some());
    }

    #[test]
    fn ipv4_non_udp_is_rejected() {
        let mut p = ipv4_udp(b"x", 53, 1, 5, 0);
        p[9] = 6; // TCP
        assert!(udp_payload_from_l3(&p, p.len()).is_none());
    }

    #[test]
    fn ipv6_plain() {
        let p = ipv6_udp(b"abcd", 53, 9999, IPPROTO_UDP);
        let u = udp_payload_from_l3(&p, p.len()).unwrap();
        assert_eq!(u.offset, 48);
        assert_eq!(u.len, 4);
        assert_eq!(u.src_port, 53);
    }

    #[test]
    fn ipv6_extension_headers_are_skipped() {
        let p = ipv6_udp(b"abcd", 53, 9999, 44); // fragment header
        assert!(udp_payload_from_l3(&p, p.len()).is_none());
    }

    #[test]
    fn payload_len_is_clamped_to_captured_bytes() {
        let p = ipv4_udp(&[0u8; 200], 53, 1, 5, 0);
        // Pretend only 100 bytes were copied out of the skb.
        let u = udp_payload_from_l3(&p, 100).unwrap();
        assert_eq!(u.offset, 28);
        assert_eq!(u.len, 72, "declared 200, only 72 readable");
    }

    #[test]
    fn undersized_udp_len_is_rejected() {
        let mut p = ipv4_udp(b"x", 53, 1, 5, 0);
        p[24..26].copy_from_slice(&4u16.to_be_bytes()); // udp len < 8
        assert!(udp_payload_from_l3(&p, p.len()).is_none());
    }

    #[test]
    fn truncated_inputs_never_panic() {
        let p = ipv4_udp(b"hello world", 53, 1, 5, 0);
        for n in 0..=p.len() {
            let _ = udp_payload_from_l3(&p, n);
        }
        let p6 = ipv6_udp(b"hello world", 53, 1, IPPROTO_UDP);
        for n in 0..=p6.len() {
            let _ = udp_payload_from_l3(&p6, n);
        }
        assert!(udp_payload_from_l3(&[], 0).is_none());
    }

    #[test]
    fn non_ip_version_is_rejected() {
        let p = [0x00u8; 64];
        assert!(udp_payload_from_l3(&p, p.len()).is_none());
        let p = [0x50u8; 64];
        assert!(udp_payload_from_l3(&p, p.len()).is_none());
    }
}
