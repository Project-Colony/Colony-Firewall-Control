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
    #[error("unsupported next-header {0:#x}")]
    UnsupportedNextHeader(u8),
}

/// IANA protocol numbers we recognize.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

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
    if buf.len() < 20 {
        return Err(ParseError::Truncated("ipv4 header"));
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
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
    let next_header = buf[6];
    let src_bytes: [u8; 16] = buf[8..24].try_into().unwrap();
    let dst_bytes: [u8; 16] = buf[24..40].try_into().unwrap();
    let src = Ipv6Addr::from(src_bytes);
    let dst = Ipv6Addr::from(dst_bytes);
    let payload = &buf[40..];
    finalize(
        IpAddr::V6(src),
        IpAddr::V6(dst),
        next_header,
        payload,
        direction,
    )
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
}
