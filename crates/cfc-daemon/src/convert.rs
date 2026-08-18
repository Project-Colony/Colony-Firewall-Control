//! Conversions between `cfc_core` types and the gRPC schema in `cfc_proto`.

use cfc_core::{Action, Connection, Direction, Process, Protocol, Rule, RuleScope, Verdict};
use cfc_proto::v1 as pb;
use std::str::FromStr;

pub fn action_to_pb(a: Action) -> pb::Action {
    match a {
        Action::Allow => pb::Action::Allow,
        Action::Deny => pb::Action::Deny,
        Action::Reject => pb::Action::Reject,
    }
}

pub fn action_from_pb(a: i32) -> Action {
    match pb::Action::try_from(a).unwrap_or(pb::Action::Unspecified) {
        pb::Action::Allow | pb::Action::Unspecified => Action::Allow,
        pb::Action::Deny => Action::Deny,
        pb::Action::Reject => Action::Reject,
    }
}

pub fn protocol_to_pb(p: Protocol) -> pb::Protocol {
    match p {
        Protocol::Tcp => pb::Protocol::Tcp,
        Protocol::Udp => pb::Protocol::Udp,
        Protocol::Icmp => pb::Protocol::Icmp,
        Protocol::Other(_) => pb::Protocol::Other,
    }
}

pub fn protocol_from_pb(p: i32) -> Protocol {
    match pb::Protocol::try_from(p).unwrap_or(pb::Protocol::Unspecified) {
        pb::Protocol::Tcp => Protocol::Tcp,
        pb::Protocol::Udp => Protocol::Udp,
        pb::Protocol::Icmp => Protocol::Icmp,
        _ => Protocol::Other(0),
    }
}

pub fn direction_to_pb(d: Direction) -> pb::Direction {
    match d {
        Direction::Outbound => pb::Direction::Outbound,
        Direction::Inbound => pb::Direction::Inbound,
    }
}

pub fn duration_to_pb(d: cfc_core::Duration) -> pb::Duration {
    use cfc_core::Duration as D;
    match d {
        D::Once => pb::Duration::Once,
        D::UntilRestart => pb::Duration::UntilRestart,
        D::Always | D::Seconds(_) => pb::Duration::Always,
    }
}

pub fn duration_from_pb(d: i32) -> cfc_core::Duration {
    use cfc_core::Duration as D;
    match pb::Duration::try_from(d).unwrap_or(pb::Duration::Unspecified) {
        pb::Duration::Once => D::Once,
        pb::Duration::UntilRestart => D::UntilRestart,
        _ => D::Always,
    }
}

pub fn connection_to_pb(c: &Connection) -> pb::ConnectionInfo {
    pb::ConnectionInfo {
        id: c.id.to_string(),
        timestamp_unix_ms: c.timestamp.timestamp_millis(),
        protocol: protocol_to_pb(c.protocol) as i32,
        direction: direction_to_pb(c.direction) as i32,
        src_ip: c.src_ip.to_string(),
        src_port: c.src_port as u32,
        dst_ip: c.dst_ip.to_string(),
        dst_port: c.dst_port as u32,
        dst_host: c.dst_host.clone().unwrap_or_default(),
    }
}

pub fn process_to_pb(p: &Process) -> pb::ProcessInfo {
    pb::ProcessInfo {
        pid: p.pid,
        ppid: p.ppid.unwrap_or(0),
        // TODO(wave3): proto optional uid. The pb ProcessInfo uid/gid are
        // plain u32, so an unattributed process (None) flattens to 0 on the
        // wire. This direction is display-only; rule matching never sees it.
        uid: p.uid.unwrap_or(0),
        gid: p.gid.unwrap_or(0),
        exe: p.exe.to_string_lossy().into_owned(),
        cmdline: p.cmdline.clone(),
        cwd: p
            .cwd
            .as_ref()
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default(),
        sha256: p.sha256.clone().unwrap_or_default(),
    }
}

pub fn scope_to_pb(s: &RuleScope) -> pb::RuleScope {
    pb::RuleScope {
        exe_path: s
            .exe_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        exe_sha256: s.exe_sha256.clone().unwrap_or_default(),
        parent_exe: s
            .parent_exe
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        uid: s.uid.unwrap_or(0),
        has_uid: s.uid.is_some(),
        dst_host: s.dst_host.clone().unwrap_or_default(),
        dst_net: s.dst_net.map(|n| n.to_string()).unwrap_or_default(),
        dst_port: s.dst_port.map(|p| p as u32).unwrap_or(0),
        has_dst_port: s.dst_port.is_some(),
        protocol: s.protocol.map(|p| protocol_to_pb(p) as i32).unwrap_or(0),
        has_protocol: s.protocol.is_some(),
    }
}

pub fn scope_from_pb(s: &pb::RuleScope) -> RuleScope {
    RuleScope {
        exe_path: empty_to_none(&s.exe_path).map(Into::into),
        exe_sha256: empty_to_none(&s.exe_sha256),
        parent_exe: empty_to_none(&s.parent_exe).map(Into::into),
        uid: s.has_uid.then_some(s.uid),
        dst_host: empty_to_none(&s.dst_host),
        dst_net: empty_to_none(&s.dst_net).and_then(|n| ipnet::IpNet::from_str(&n).ok()),
        dst_port: s.has_dst_port.then_some(s.dst_port as u16),
        protocol: s.has_protocol.then(|| protocol_from_pb(s.protocol)),
    }
}

pub fn rule_to_pb(r: &Rule) -> pb::RuleInfo {
    pb::RuleInfo {
        id: r.id.to_string(),
        name: r.name.clone(),
        enabled: r.enabled,
        action: action_to_pb(r.action) as i32,
        duration: duration_to_pb(r.duration) as i32,
        scope: Some(scope_to_pb(&r.scope)),
        created_at_unix_ms: r.created_at.timestamp_millis(),
        hit_count: r.hit_count,
    }
}

pub fn rule_from_pb(r: &pb::RuleInfo) -> Result<Rule, String> {
    let id = if r.id.is_empty() {
        uuid::Uuid::new_v4()
    } else {
        uuid::Uuid::parse_str(&r.id).map_err(|e| format!("bad id: {e}"))?
    };
    let scope = r
        .scope
        .as_ref()
        .map(scope_from_pb)
        .unwrap_or(RuleScope::any());
    let created_at = if r.created_at_unix_ms == 0 {
        chrono::Utc::now()
    } else {
        chrono::DateTime::from_timestamp_millis(r.created_at_unix_ms)
            .unwrap_or_else(chrono::Utc::now)
    };
    Ok(Rule {
        id,
        name: r.name.clone(),
        enabled: r.enabled,
        action: action_from_pb(r.action),
        duration: duration_from_pb(r.duration),
        scope,
        created_at,
        hit_count: r.hit_count,
    })
}

pub fn verdict_to_pb_action(v: &Verdict) -> pb::Action {
    action_to_pb(v.action)
}

fn empty_to_none(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfc_core::{Direction, Duration, Rule, RuleScope};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    #[test]
    fn action_roundtrip() {
        for a in [Action::Allow, Action::Deny, Action::Reject] {
            let pb = action_to_pb(a) as i32;
            assert_eq!(action_from_pb(pb), a);
        }
    }

    #[test]
    fn action_unspecified_maps_to_allow() {
        // Defensive: an out-of-range / unspecified value should be the
        // permissive default.
        assert_eq!(action_from_pb(0), Action::Allow);
        assert_eq!(action_from_pb(99), Action::Allow);
    }

    #[test]
    fn protocol_roundtrip() {
        for p in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
            let pb = protocol_to_pb(p) as i32;
            assert_eq!(protocol_from_pb(pb), p);
        }
    }

    #[test]
    fn duration_roundtrip_common_cases() {
        assert_eq!(
            duration_from_pb(duration_to_pb(Duration::Once) as i32),
            Duration::Once
        );
        assert_eq!(
            duration_from_pb(duration_to_pb(Duration::UntilRestart) as i32),
            Duration::UntilRestart
        );
        assert_eq!(
            duration_from_pb(duration_to_pb(Duration::Always) as i32),
            Duration::Always
        );
    }

    #[test]
    fn duration_seconds_collapses_to_always() {
        // We don't carry the Seconds variant on the wire; it round-trips
        // through "Always" by design.
        assert_eq!(
            duration_from_pb(duration_to_pb(Duration::Seconds(60)) as i32),
            Duration::Always
        );
    }

    #[test]
    fn scope_roundtrip_full() {
        let scope = RuleScope {
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
            exe_sha256: Some("abc123".into()),
            parent_exe: Some(PathBuf::from("/bin/bash")),
            uid: Some(1000),
            dst_host: Some("example.com".into()),
            dst_net: Some("10.0.0.0/8".parse().unwrap()),
            dst_port: Some(443),
            protocol: Some(Protocol::Tcp),
        };
        let pb = scope_to_pb(&scope);
        let back = scope_from_pb(&pb);
        assert_eq!(back, scope);
    }

    #[test]
    fn scope_roundtrip_empty() {
        let scope = RuleScope::any();
        let pb = scope_to_pb(&scope);
        let back = scope_from_pb(&pb);
        assert_eq!(back, scope);
    }

    #[test]
    fn rule_roundtrip() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        scope.dst_port = Some(443);
        let rule = Rule::new("curl-https", Action::Allow, scope);

        let pb = rule_to_pb(&rule);
        let back = convert::rule_from_pb_helper(&pb);
        assert_eq!(back.id, rule.id);
        assert_eq!(back.name, rule.name);
        assert_eq!(back.action, rule.action);
        assert_eq!(back.duration, rule.duration);
        assert_eq!(back.scope, rule.scope);
    }

    #[test]
    fn rule_from_pb_invalid_id() {
        let pb = cfc_proto::v1::RuleInfo {
            id: "not-a-uuid".into(),
            name: "x".into(),
            enabled: true,
            action: cfc_proto::v1::Action::Allow as i32,
            duration: cfc_proto::v1::Duration::Always as i32,
            scope: Some(cfc_proto::v1::RuleScope::default()),
            created_at_unix_ms: 0,
            hit_count: 0,
        };
        assert!(rule_from_pb(&pb).is_err());
    }

    #[test]
    fn connection_to_pb_carries_5tuple() {
        let conn = cfc_core::Connection::new(
            Protocol::Tcp,
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            5555,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        );
        let pb = connection_to_pb(&conn);
        assert_eq!(pb.src_ip, "1.2.3.4");
        assert_eq!(pb.dst_ip, "8.8.8.8");
        assert_eq!(pb.src_port, 5555);
        assert_eq!(pb.dst_port, 443);
        assert_eq!(pb.protocol, cfc_proto::v1::Protocol::Tcp as i32);
    }

    // Helper that does an empty-id rule_from_pb (skips uuid parsing).
    mod convert {
        use super::*;
        pub fn rule_from_pb_helper(pb: &cfc_proto::v1::RuleInfo) -> Rule {
            super::rule_from_pb(pb).expect("test rule should be valid")
        }
    }
}
