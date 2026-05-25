//! Conversions between `cfc_core` types and the gRPC schema in `cfc_proto`.

use cfc_core::{
    Action, Connection, Direction, Process, Protocol, Rule, RuleScope, Verdict,
};
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
        uid: p.uid,
        gid: p.gid,
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
        protocol: s
            .protocol
            .map(|p| protocol_to_pb(p) as i32)
            .unwrap_or(0),
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
