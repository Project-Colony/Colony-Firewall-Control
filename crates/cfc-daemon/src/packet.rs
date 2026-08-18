//! Minimal IP/TCP/UDP/ICMP parser for NFQUEUE payloads.
//!
//! We only need enough to extract the 5-tuple and the L4 protocol. No
//! options, no fragment reassembly, no checksum verification - the kernel
//! has already done all of that before handing us the packet.

use cfc_core::{Connection, Direction, Protocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("packet too short for {0}")]
    Truncated(&'static str),
    #[error("unsupported IP version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid ipv4 header length {0}")]
    BadIhl(usize),
    #[error("too many ipv6 extension headers")]
    TooManyExtensions,
}

/// IANA protocol numbers we recognize.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

/// IPv6 extension-header numbers (RFC 8200 / RFC 4302).
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;

/// Upper bound on the IPv6 extension-header chain we are willing to walk.
/// Real traffic rarely carries more than two or three; anything longer is
/// almost certainly crafted, and bounding the walk keeps parsing O(1).
const MAX_EXT_HEADERS: usize = 8;

pub fn parse(payload: &[u8], direction: Direction) -> Result<Connection, ParseError> {
    if payload.is_empty() {
        return Err(ParseError::Truncated("ip version byte"));
    }
    let version = payload[0] >> 4;
    match version {
        4 => parse_ipv4(payload, direction),
        6 => parse_ipv6(payload, direction),
        v => Err(ParseError::UnsupportedVersion(v)),
    }
}

fn parse_ipv4(buf: &[u8], direction: Direction) -> Result<Connection, ParseError> {
    // The version nibble was already validated by `parse` before dispatch.
    if buf.len() < 20 {
        return Err(ParseError::Truncated("ipv4 header"));
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    // IHL must cover at least the fixed 20-byte header (RFC 791). Without
    // this check a crafted IHL < 5 would make us read the L4 ports out of
    // the IPv4 header itself, yielding a bogus 5-tuple for rule matching.
    if ihl < 20 {
        return Err(ParseError::BadIhl(ihl));
    }
    if buf.len() < ihl {
        return Err(ParseError::Truncated("ipv4 header (ihl)"));
    }
    let proto_num = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let payload = &buf[ihl..];
    finalize(
        IpAddr::V4(src),
        IpAddr::V4(dst),
        proto_num,
        payload,
        direction,
    )
}

fn parse_ipv6(buf: &[u8], direction: Direction) -> Result<Connection, ParseError> {
    if buf.len() < 40 {
        return Err(ParseError::Truncated("ipv6 header"));
    }
    let src_bytes: [u8; 16] = buf[8..24].try_into().unwrap();
    let dst_bytes: [u8; 16] = buf[24..40].try_into().unwrap();
    let src = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_bytes));

    // Walk the extension-header chain (RFC 8200) until we reach the upper
    // layer. Skipping this walk would let TCP/UDP hidden behind e.g. a
    // Hop-by-Hop header be misclassified as Protocol::Other with zero
    // ports, evading port/protocol-scoped rules. The walk is bounded to
    // MAX_EXT_HEADERS so crafted chains cannot make us loop.
    let mut next_header = buf[6];
    let mut offset = 40usize;
    for _ in 0..=MAX_EXT_HEADERS {
        match next_header {
            // Hop-by-Hop, Routing, and Destination Options share the common
            // format: next-header at +0, length at +1 in 8-octet units, not
            // counting the first 8 octets.
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                let hdr = buf
                    .get(offset..offset + 2)
                    .ok_or(ParseError::Truncated("ipv6 extension header"))?;
                let len = (hdr[1] as usize + 1) * 8;
                if buf.len() < offset + len {
                    return Err(ParseError::Truncated("ipv6 extension header"));
                }
                next_header = hdr[0];
                offset += len;
            }
            // Authentication Header (RFC 4302) uses a different length
            // encoding: 4-octet units, not counting the first 8 octets, i.e.
            // (len + 2) * 4 total. AH authenticates but does not encrypt, so
            // the real L4 header follows and we keep walking. (ESP, by
            // contrast, encrypts its payload; it falls through to `finalize`
            // below and is classified Protocol::Other(50).)
            IPPROTO_AH => {
                let hdr = buf
                    .get(offset..offset + 2)
                    .ok_or(ParseError::Truncated("ipv6 auth header"))?;
                let len = (hdr[1] as usize + 2) * 4;
                if buf.len() < offset + len {
                    return Err(ParseError::Truncated("ipv6 auth header"));
                }
                next_header = hdr[0];
                offset += len;
            }
            // Fragment header (RFC 8200 s4.5): fixed 8 bytes. Only the
            // first fragment (offset 0) carries the L4 header; for any
            // other fragment the ports are unknowable, so we classify it
            // gracefully as Protocol::Other(44) with zero ports rather
            // than erroring (the packet itself is well-formed).
            IPPROTO_FRAGMENT => {
                let hdr = buf
                    .get(offset..offset + 8)
                    .ok_or(ParseError::Truncated("ipv6 fragment header"))?;
                let frag_offset = u16::from_be_bytes([hdr[2], hdr[3]]) >> 3;
                if frag_offset != 0 {
                    return Ok(Connection::new(
                        Protocol::Other(IPPROTO_FRAGMENT),
                        direction,
                        src,
                        0,
                        dst,
                        0,
                    ));
                }
                next_header = hdr[0];
                offset += 8;
            }
            // Anything else is an upper-layer protocol (TCP/UDP/ICMPv6/
            // ESP/No-Next-Header/...) and terminates the chain.
            _ => return finalize(src, dst, next_header, &buf[offset..], direction),
        }
    }
    Err(ParseError::TooManyExtensions)
}

fn finalize(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto_num: u8,
    l4_payload: &[u8],
    direction: Direction,
) -> Result<Connection, ParseError> {
    let (protocol, src_port, dst_port) = match proto_num {
        IPPROTO_TCP => {
            if l4_payload.len() < 4 {
                return Err(ParseError::Truncated("tcp ports"));
            }
            (
                Protocol::Tcp,
                u16::from_be_bytes([l4_payload[0], l4_payload[1]]),
                u16::from_be_bytes([l4_payload[2], l4_payload[3]]),
            )
        }
        IPPROTO_UDP => {
            if l4_payload.len() < 4 {
                return Err(ParseError::Truncated("udp ports"));
            }
            (
                Protocol::Udp,
                u16::from_be_bytes([l4_payload[0], l4_payload[1]]),
                u16::from_be_bytes([l4_payload[2], l4_payload[3]]),
            )
        }
        IPPROTO_ICMP | IPPROTO_ICMPV6 => (Protocol::Icmp, 0, 0),
        other => (Protocol::Other(other), 0, 0),
    };

    Ok(Connection::new(
        protocol, direction, src_ip, src_port, dst_ip, dst_port,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_ipv4_tcp() {
        // version=4, ihl=5 (20 bytes), tot_len=40, proto=6 (TCP), src=1.2.3.4,
        // dst=5.6.7.8, tcp src=1234, dst=80
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = IPPROTO_TCP;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[20..22].copy_from_slice(&1234u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());

        let conn = parse(&pkt, Direction::Outbound).unwrap();
        assert_eq!(conn.src_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(conn.dst_ip, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(conn.src_port, 1234);
        assert_eq!(conn.dst_port, 80);
        assert_eq!(conn.protocol, Protocol::Tcp);
    }

    #[test]
    fn parses_minimal_ipv6_udp() {
        let mut pkt = [0u8; 48];
        pkt[0] = 0x60; // version 6
        pkt[6] = IPPROTO_UDP;
        pkt[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[40..42].copy_from_slice(&5353u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&53u16.to_be_bytes());

        let conn = parse(&pkt, Direction::Outbound).unwrap();
        assert_eq!(conn.src_port, 5353);
        assert_eq!(conn.dst_port, 53);
        assert_eq!(conn.protocol, Protocol::Udp);
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse(&[0x45, 0, 0], Direction::Outbound).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        assert!(parse(&[0x90, 0, 0, 0], Direction::Outbound).is_err());
    }

    /// IHL nibbles 0..=4 encode header lengths 0/4/8/12/16 bytes - all below
    /// the 20-byte minimum - and must be rejected even when the buffer is
    /// long enough, otherwise the "ports" are read out of the IPv4 header.
    #[test]
    fn rejects_ipv4_short_ihl() {
        for nibble in 0u8..=4 {
            let mut pkt = [0u8; 40];
            pkt[0] = 0x40 | nibble;
            pkt[9] = IPPROTO_TCP;
            let err = parse(&pkt, Direction::Outbound).unwrap_err();
            assert!(
                matches!(err, ParseError::BadIhl(_)),
                "ihl nibble {nibble} gave {err:?}"
            );
        }
    }

    #[test]
    fn rejects_ipv4_ihl_beyond_buffer() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x46; // ihl = 24 bytes, buffer only 20
        assert!(parse(&pkt, Direction::Outbound).is_err());
    }

    // ---- IPv6 extension-header handling ----

    const SRC6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const DST6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    fn ipv6_header(first_next_header: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[6] = first_next_header;
        pkt[8..24].copy_from_slice(&SRC6);
        pkt[24..40].copy_from_slice(&DST6);
        pkt
    }

    fn tcp_ports(sport: u16, dport: u16) -> Vec<u8> {
        let mut l4 = Vec::new();
        l4.extend_from_slice(&sport.to_be_bytes());
        l4.extend_from_slice(&dport.to_be_bytes());
        l4
    }

    #[test]
    fn parses_ipv6_hop_by_hop_then_tcp() {
        let mut pkt = ipv6_header(IPPROTO_HOPOPTS);
        pkt.extend_from_slice(&[IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0]); // 8-byte HBH
        pkt.extend_from_slice(&tcp_ports(443, 8080));

        let conn = parse(&pkt, Direction::Inbound).unwrap();
        assert_eq!(conn.protocol, Protocol::Tcp);
        assert_eq!(conn.src_port, 443);
        assert_eq!(conn.dst_port, 8080);
        assert_eq!(conn.src_ip, IpAddr::V6(Ipv6Addr::from(SRC6)));
        assert_eq!(conn.dst_ip, IpAddr::V6(Ipv6Addr::from(DST6)));
    }

    #[test]
    fn parses_ipv6_first_fragment_then_tcp() {
        let mut pkt = ipv6_header(IPPROTO_FRAGMENT);
        // Fragment header: next=TCP, reserved, offset=0 + M=1, ident.
        pkt.extend_from_slice(&[IPPROTO_TCP, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef]);
        pkt.extend_from_slice(&tcp_ports(1234, 80));

        let conn = parse(&pkt, Direction::Outbound).unwrap();
        assert_eq!(conn.protocol, Protocol::Tcp);
        assert_eq!(conn.src_port, 1234);
        assert_eq!(conn.dst_port, 80);
    }

    #[test]
    fn ipv6_non_first_fragment_is_other_with_zero_ports() {
        let mut pkt = ipv6_header(IPPROTO_FRAGMENT);
        let offset_field = (185u16 << 3).to_be_bytes(); // fragment offset 185
        pkt.extend_from_slice(&[
            IPPROTO_TCP,
            0,
            offset_field[0],
            offset_field[1],
            0xde,
            0xad,
            0xbe,
            0xef,
        ]);
        pkt.extend_from_slice(&[0u8; 8]); // fragment payload, not a TCP header

        let conn = parse(&pkt, Direction::Inbound).unwrap();
        assert_eq!(conn.protocol, Protocol::Other(IPPROTO_FRAGMENT));
        assert_eq!(conn.src_port, 0);
        assert_eq!(conn.dst_port, 0);
    }

    #[test]
    fn parses_ipv6_auth_header_then_udp() {
        let mut pkt = ipv6_header(IPPROTO_AH);
        // AH: next=UDP, payload-len=4 -> (4 + 2) * 4 = 24 bytes total.
        let mut ah = vec![0u8; 24];
        ah[0] = IPPROTO_UDP;
        ah[1] = 4;
        pkt.extend_from_slice(&ah);
        pkt.extend_from_slice(&tcp_ports(5353, 53));

        let conn = parse(&pkt, Direction::Outbound).unwrap();
        assert_eq!(conn.protocol, Protocol::Udp);
        assert_eq!(conn.src_port, 5353);
        assert_eq!(conn.dst_port, 53);
    }

    #[test]
    fn rejects_truncated_ipv6_extension_header() {
        // Claims a Hop-by-Hop header but the buffer ends inside it.
        let mut pkt = ipv6_header(IPPROTO_HOPOPTS);
        pkt.push(IPPROTO_TCP); // only 1 of the minimum 8 bytes present
        assert!(parse(&pkt, Direction::Inbound).is_err());

        // Length field promises more octets than the buffer holds.
        let mut pkt = ipv6_header(IPPROTO_HOPOPTS);
        pkt.extend_from_slice(&[IPPROTO_TCP, 10, 0, 0, 0, 0, 0, 0]); // 88 bytes claimed
        assert!(parse(&pkt, Direction::Inbound).is_err());
    }

    #[test]
    fn rejects_ipv6_extension_chain_longer_than_bound() {
        let mut pkt = ipv6_header(IPPROTO_DSTOPTS);
        for _ in 0..8 {
            pkt.extend_from_slice(&[IPPROTO_DSTOPTS, 0, 0, 0, 0, 0, 0, 0]);
        }
        // 9th extension header, then TCP - one past the bound.
        pkt.extend_from_slice(&[IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&tcp_ports(1, 2));
        let err = parse(&pkt, Direction::Inbound).unwrap_err();
        assert!(matches!(err, ParseError::TooManyExtensions), "{err:?}");
    }

    #[test]
    fn parses_ipv6_extension_chain_at_bound() {
        let mut pkt = ipv6_header(IPPROTO_DSTOPTS);
        for _ in 0..7 {
            pkt.extend_from_slice(&[IPPROTO_DSTOPTS, 0, 0, 0, 0, 0, 0, 0]);
        }
        // 8th extension header, then TCP - exactly at the bound.
        pkt.extend_from_slice(&[IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&tcp_ports(1, 2));
        let conn = parse(&pkt, Direction::Inbound).unwrap();
        assert_eq!(conn.protocol, Protocol::Tcp);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn build_ipv4(
        ihl_words: u8, // 5..=15
        proto: u8,
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
    ) -> Vec<u8> {
        let ihl = ihl_words as usize * 4;
        let mut pkt = vec![0u8; ihl];
        pkt[0] = 0x40 | ihl_words;
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt.extend_from_slice(&sport.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt
    }

    /// Build an IPv6 packet whose header chain is `exts` (extension-header
    /// protocol numbers) followed by `l4_proto` and its ports.
    fn build_ipv6(
        exts: &[u8],
        l4_proto: u8,
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[6] = *exts.first().unwrap_or(&l4_proto);
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        for (i, &kind) in exts.iter().enumerate() {
            let next = *exts.get(i + 1).unwrap_or(&l4_proto);
            match kind {
                IPPROTO_FRAGMENT => {
                    // First fragment: offset 0, M=1.
                    pkt.extend_from_slice(&[next, 0, 0, 1, 0, 0, 0, 42]);
                }
                IPPROTO_AH => {
                    // payload-len=1 -> (1 + 2) * 4 = 12 bytes.
                    let mut ah = vec![0u8; 12];
                    ah[0] = next;
                    ah[1] = 1;
                    pkt.extend_from_slice(&ah);
                }
                _ => {
                    // Common format, minimum 8-byte header.
                    let mut ext = vec![0u8; 8];
                    ext[0] = next;
                    pkt.extend_from_slice(&ext);
                }
            }
        }
        pkt.extend_from_slice(&sport.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt
    }

    fn ext_kind() -> impl Strategy<Value = u8> {
        prop_oneof![
            Just(IPPROTO_HOPOPTS),
            Just(IPPROTO_ROUTING),
            Just(IPPROTO_DSTOPTS),
            Just(IPPROTO_FRAGMENT),
            Just(IPPROTO_AH),
        ]
    }

    fn l4_proto() -> impl Strategy<Value = u8> {
        prop_oneof![Just(IPPROTO_TCP), Just(IPPROTO_UDP)]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Round-trip: a well-formed IPv4 TCP/UDP packet parses back to
        /// exactly the tuple it was built from.
        #[test]
        fn roundtrip_ipv4(
            ihl_words in 5u8..=15,
            proto in l4_proto(),
            src: [u8; 4],
            dst: [u8; 4],
            sport: u16,
            dport: u16,
        ) {
            let pkt = build_ipv4(ihl_words, proto, src, dst, sport, dport);
            let conn = parse(&pkt, Direction::Outbound).unwrap();
            prop_assert_eq!(conn.src_ip, IpAddr::V4(Ipv4Addr::from(src)));
            prop_assert_eq!(conn.dst_ip, IpAddr::V4(Ipv4Addr::from(dst)));
            prop_assert_eq!(conn.src_port, sport);
            prop_assert_eq!(conn.dst_port, dport);
            let expected = if proto == IPPROTO_TCP { Protocol::Tcp } else { Protocol::Udp };
            prop_assert_eq!(conn.protocol, expected);
        }

        /// Round-trip: a well-formed IPv6 TCP/UDP packet - optionally behind
        /// a chain of 0-3 extension headers - parses back to exactly the
        /// tuple it was built from.
        #[test]
        fn roundtrip_ipv6(
            exts in proptest::collection::vec(ext_kind(), 0..=3),
            proto in l4_proto(),
            src: [u8; 16],
            dst: [u8; 16],
            sport: u16,
            dport: u16,
        ) {
            let pkt = build_ipv6(&exts, proto, src, dst, sport, dport);
            let conn = parse(&pkt, Direction::Inbound).unwrap();
            prop_assert_eq!(conn.src_ip, IpAddr::V6(Ipv6Addr::from(src)));
            prop_assert_eq!(conn.dst_ip, IpAddr::V6(Ipv6Addr::from(dst)));
            prop_assert_eq!(conn.src_port, sport);
            prop_assert_eq!(conn.dst_port, dport);
            let expected = if proto == IPPROTO_TCP { Protocol::Tcp } else { Protocol::Udp };
            prop_assert_eq!(conn.protocol, expected);
        }

        /// Robustness: arbitrary bytes never panic the parser, and whenever
        /// it claims TCP/UDP on IPv4 the header length was actually valid
        /// and the buffer really contained the port bytes past the header.
        #[test]
        fn arbitrary_bytes_never_panic(
            buf in proptest::collection::vec(any::<u8>(), 0..=128),
        ) {
            if let Ok(conn) = parse(&buf, Direction::Inbound) {
                if matches!(conn.protocol, Protocol::Tcp | Protocol::Udp) && buf[0] >> 4 == 4 {
                    let ihl = (buf[0] & 0x0f) as usize * 4;
                    prop_assert!(ihl >= 20);
                    prop_assert!(buf.len() >= ihl + 4);
                }
            }
        }
    }
}
