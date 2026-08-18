//! Conversions between `cfc_core` types and the gRPC schema in `cfc_proto`.
//!
//! Inbound conversions (`*_from_pb`) fail closed. A field the daemon does
//! not recognise - an unset enum from a default-initialized client, or an
//! integer from a newer/older schema - is an error, never a silently
//! manufactured `Allow`. Callers map the `String` error to
//! `Status::invalid_argument`.

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

/// Fail-closed: `ACTION_UNSPECIFIED` and any out-of-range integer are
/// rejected rather than defaulted to `Allow`.
pub fn action_from_pb(a: i32) -> Result<Action, String> {
    match pb::Action::try_from(a) {
        Ok(pb::Action::Allow) => Ok(Action::Allow),
        Ok(pb::Action::Deny) => Ok(Action::Deny),
        Ok(pb::Action::Reject) => Ok(Action::Reject),
        Ok(pb::Action::Unspecified) | Err(_) => Err(format!("action unspecified/unknown: {a}")),
    }
}

/// String form of an action as persisted in the `events` table and matched
/// by [`crate::storage::EventFilter::action`]. Kept next to the enum so the
/// writer and the query filter can never drift apart.
pub fn action_db_str(a: Action) -> &'static str {
    match a {
        Action::Allow => "Allow",
        Action::Deny => "Deny",
        Action::Reject => "Reject",
    }
}

/// Provenance label persisted alongside each event.
pub fn verdict_source_db_str(s: &cfc_core::VerdictSource) -> &'static str {
    match s {
        cfc_core::VerdictSource::Rule(_) => "rule",
        cfc_core::VerdictSource::UserPrompt => "user",
        cfc_core::VerdictSource::DefaultPolicy => "default",
        cfc_core::VerdictSource::Timeout => "timeout",
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

/// Fail-closed: `DURATION_UNSPECIFIED` and out-of-range integers are
/// rejected rather than defaulted to the longest-lived `Always`.
pub fn duration_from_pb(d: i32) -> Result<cfc_core::Duration, String> {
    use cfc_core::Duration as D;
    match pb::Duration::try_from(d) {
        Ok(pb::Duration::Once) => Ok(D::Once),
        Ok(pb::Duration::UntilRestart) => Ok(D::UntilRestart),
        Ok(pb::Duration::Always) => Ok(D::Always),
        Ok(pb::Duration::Unspecified) | Err(_) => Err(format!("duration unspecified/unknown: {d}")),
    }
}

/// `Once` is a one-shot answer to a single prompt, applied by the router as
/// the packet's verdict. A persisted `Once` rule is meaningless: rule lookup
/// treats it as never-expiring and storage purges it at the next start, so
/// it silently becomes either "forever" or "gone". Reject it at the API
/// boundary instead of persisting a lie.
pub fn reject_unpersistable_duration(d: cfc_core::Duration) -> Result<(), String> {
    if d == cfc_core::Duration::Once {
        return Err("Once rules cannot be persisted".to_string());
    }
    Ok(())
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
        // Explicit presence on the wire: an unattributed process stays
        // absent rather than collapsing into "uid 0" (i.e. root).
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
        action: action_from_pb(r.action)?,
        duration: duration_from_pb(r.duration)?,
        scope,
        created_at,
        hit_count: r.hit_count,
    })
}

pub fn verdict_to_pb_action(v: &Verdict) -> pb::Action {
    action_to_pb(v.action)
}

/// Flattens a decided flow into the row shape persisted by
/// [`crate::storage::RuleStore::insert_events`].
pub fn event_row_from_observed(
    conn: &Connection,
    proc: &Process,
    verdict: &Verdict,
) -> crate::storage::EventRow {
    crate::storage::EventRow {
        id: 0,
        ts_unix_ms: conn.timestamp.timestamp_millis(),
        proto: Some(protocol_db_str(conn.protocol).to_string()),
        src_ip: Some(conn.src_ip.to_string()),
        src_port: Some(conn.src_port),
        dst_ip: Some(conn.dst_ip.to_string()),
        dst_port: Some(conn.dst_port),
        dst_host: conn.dst_host.clone(),
        exe: Some(proc.exe.to_string_lossy().into_owned()).filter(|e| !e.is_empty()),
        pid: Some(proc.pid),
        uid: proc.uid,
        action: action_db_str(verdict.action).to_string(),
        source: verdict_source_db_str(&verdict.source).to_string(),
        rule_id: match verdict.source {
            cfc_core::VerdictSource::Rule(id) => Some(id.to_string()),
            _ => None,
        },
    }
}

/// Renders a persisted event back onto the wire.
pub fn event_row_to_pb(row: &crate::storage::EventRow) -> pb::Event {
    pb::Event {
        ts_unix_ms: row.ts_unix_ms,
        proto: row.proto.clone().unwrap_or_default(),
        src_ip: row.src_ip.clone().unwrap_or_default(),
        src_port: row.src_port.unwrap_or(0) as u32,
        dst_ip: row.dst_ip.clone().unwrap_or_default(),
        dst_port: row.dst_port.unwrap_or(0) as u32,
        dst_host: row.dst_host.clone().unwrap_or_default(),
        exe: row.exe.clone().unwrap_or_default(),
        pid: row.pid.unwrap_or(0),
        uid: row.uid,
        // Rows written by older builds (or hand-edited ones) may carry an
        // action string this build does not know; surface it as
        // unspecified rather than dropping the row.
        action: action_db_from_str(&row.action)
            .map(|a| action_to_pb(a) as i32)
            .unwrap_or(pb::Action::Unspecified as i32),
        source: row.source.clone(),
        rule_id: row.rule_id.clone().unwrap_or_default(),
    }
}

fn protocol_db_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::Other(_) => "other",
    }
}

fn action_db_from_str(s: &str) -> Option<Action> {
    match s {
        "Allow" => Some(Action::Allow),
        "Deny" => Some(Action::Deny),
        "Reject" => Some(Action::Reject),
        _ => None,
    }
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
            assert_eq!(action_from_pb(pb).unwrap(), a);
        }
    }

    #[test]
    fn action_unspecified_and_unknown_are_rejected() {
        // Inverted from the old behaviour on purpose: mapping an unset or
        // version-skewed enum onto Allow let a default-initialized client
        // manufacture ALLOW verdicts and rules. Both now fail closed.
        let unspecified = action_from_pb(0).unwrap_err();
        assert!(unspecified.contains('0'), "{unspecified}");
        let unknown = action_from_pb(99).unwrap_err();
        assert!(unknown.contains("99"), "{unknown}");
        assert!(action_from_pb(-1).is_err());
    }

    #[test]
    fn duration_unspecified_and_unknown_are_rejected() {
        assert!(duration_from_pb(0).is_err());
        assert!(duration_from_pb(99).is_err());
        assert!(duration_from_pb(-1).is_err());
    }

    #[test]
    fn once_duration_is_not_persistable() {
        assert!(reject_unpersistable_duration(Duration::Once).is_err());
        for d in [
            Duration::UntilRestart,
            Duration::Always,
            Duration::Seconds(60),
        ] {
            assert!(reject_unpersistable_duration(d).is_ok());
        }
    }

    #[test]
    fn rule_from_pb_rejects_unspecified_action_and_duration() {
        let mut pb = cfc_proto::v1::RuleInfo {
            id: String::new(),
            name: "x".into(),
            enabled: true,
            action: cfc_proto::v1::Action::Unspecified as i32,
            duration: cfc_proto::v1::Duration::Always as i32,
            scope: Some(cfc_proto::v1::RuleScope::default()),
            created_at_unix_ms: 0,
            hit_count: 0,
        };
        assert!(rule_from_pb(&pb).is_err());

        pb.action = cfc_proto::v1::Action::Deny as i32;
        pb.duration = cfc_proto::v1::Duration::Unspecified as i32;
        assert!(rule_from_pb(&pb).is_err());

        pb.duration = cfc_proto::v1::Duration::Always as i32;
        assert!(rule_from_pb(&pb).is_ok());
    }

    #[test]
    fn process_uid_absence_survives_the_wire() {
        let mut p = cfc_core::Process::unknown(42);
        assert_eq!(p.uid, None);
        // Unattributed: absent, NOT uid 0.
        assert_eq!(process_to_pb(&p).uid, None);
        assert_eq!(process_to_pb(&p).gid, None);

        p.uid = Some(0);
        assert_eq!(process_to_pb(&p).uid, Some(0));
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
        for d in [Duration::Once, Duration::UntilRestart, Duration::Always] {
            assert_eq!(duration_from_pb(duration_to_pb(d) as i32).unwrap(), d);
        }
    }

    #[test]
    fn duration_seconds_collapses_to_always() {
        // We don't carry the Seconds variant on the wire; it round-trips
        // through "Always" by design.
        assert_eq!(
            duration_from_pb(duration_to_pb(Duration::Seconds(60)) as i32).unwrap(),
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

    #[test]
    fn event_row_roundtrips_through_the_wire_shape() {
        let mut conn = cfc_core::Connection::new(
            Protocol::Udp,
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5353,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
        );
        conn.dst_host = Some("one.one.one.one".into());
        let mut proc = cfc_core::Process::unknown(4242);
        proc.exe = PathBuf::from("/usr/bin/dig");
        proc.uid = Some(1000);
        let rule_id = uuid::Uuid::new_v4();
        let verdict = cfc_core::Verdict::deny_from_rule(rule_id);

        let row = event_row_from_observed(&conn, &proc, &verdict);
        assert_eq!(row.action, "Deny");
        assert_eq!(row.source, "rule");
        assert_eq!(row.rule_id.as_deref(), Some(rule_id.to_string().as_str()));
        assert_eq!(row.proto.as_deref(), Some("udp"));
        assert_eq!(row.uid, Some(1000));

        let ev = event_row_to_pb(&row);
        assert_eq!(ev.dst_port, 53);
        assert_eq!(ev.dst_host, "one.one.one.one");
        assert_eq!(ev.exe, "/usr/bin/dig");
        assert_eq!(ev.pid, 4242);
        assert_eq!(ev.uid, Some(1000));
        assert_eq!(ev.action, cfc_proto::v1::Action::Deny as i32);
    }

    #[test]
    fn event_row_keeps_unattributed_uid_absent() {
        let conn = cfc_core::Connection::new(
            Protocol::Tcp,
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            2,
        );
        let proc = cfc_core::Process::unknown(7);
        let row = event_row_from_observed(&conn, &proc, &cfc_core::Verdict::default_allow());
        assert_eq!(row.uid, None);
        assert_eq!(row.source, "default");
        assert_eq!(row.rule_id, None);
        assert_eq!(event_row_to_pb(&row).uid, None);
    }

    #[test]
    fn event_row_to_pb_tolerates_unknown_action_strings() {
        let row = crate::storage::EventRow {
            action: "Something-Else".into(),
            ..Default::default()
        };
        assert_eq!(
            event_row_to_pb(&row).action,
            cfc_proto::v1::Action::Unspecified as i32
        );
    }

    #[test]
    fn action_db_str_matches_the_filter_vocabulary() {
        for a in [Action::Allow, Action::Deny, Action::Reject] {
            assert_eq!(action_db_from_str(action_db_str(a)), Some(a));
        }
    }

    // Helper that does an empty-id rule_from_pb (skips uuid parsing).
    mod convert {
        use super::*;
        pub fn rule_from_pb_helper(pb: &cfc_proto::v1::RuleInfo) -> Rule {
            super::rule_from_pb(pb).expect("test rule should be valid")
        }
    }
}
