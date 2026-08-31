//! Conversions between `cfc_core` types and the gRPC schema in `cfc_proto`.
//!
//! Inbound conversions (`*_from_pb`) fail closed. A field the daemon does
//! not recognise - an unset enum from a default-initialized client, or an
//! integer from a newer/older schema - is an error, never a silently
//! manufactured `Allow`. Callers map the `String` error to
//! `Status::invalid_argument`.

use cfc_core::{
    Action, Connection, Direction, Process, Protocol, Provenance, Rule, RuleScope, Verdict,
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

/// Fails closed, like [`action_from_pb`] and [`duration_from_pb`].
///
/// The previous `_ => Protocol::Other(0)` was worse than a wrong answer: a
/// scope carrying `has_protocol = true` with an unspecified or unrecognised
/// value became a predicate that **can never match any parsed packet** - the
/// datapath only ever produces `Other(n)` for a real IP protocol number, and 0
/// is IPv6 hop-by-hop, which is an extension header and never a transport. The
/// rule was therefore inert while still counting toward `specificity()`, so it
/// also outranked the rules that would have matched.
pub fn protocol_from_pb(p: i32) -> Result<Protocol, String> {
    match pb::Protocol::try_from(p) {
        Ok(pb::Protocol::Tcp) => Ok(Protocol::Tcp),
        Ok(pb::Protocol::Udp) => Ok(Protocol::Udp),
        Ok(pb::Protocol::Icmp) => Ok(Protocol::Icmp),
        // `Other` has no number on the wire to carry, so a scope cannot express
        // "protocol 47" and must not pretend to.
        Ok(pb::Protocol::Other) => Err(
            "protocol `other` cannot be used in a rule scope: the wire format \
             carries no protocol number for it"
                .to_string(),
        ),
        Ok(pb::Protocol::Unspecified) | Err(_) => Err(format!("protocol unspecified/unknown: {p}")),
    }
}

pub fn provenance_to_pb(p: Provenance) -> pb::Provenance {
    match p {
        Provenance::Unknown => pb::Provenance::Unspecified,
        Provenance::Unpackaged => pb::Provenance::Unpackaged,
        Provenance::Verified => pb::Provenance::Verified,
        Provenance::Modified => pb::Provenance::Modified,
    }
}

/// Unlike `action_from_pb` this does not fail closed, because there is
/// nothing to fail closed *to*: provenance is advisory metadata, never a
/// verdict input. An unset field (an older client) and an integer from a
/// newer schema both mean the same thing operationally - "this build cannot
/// say" - which is exactly [`Provenance::Unknown`].
pub fn provenance_from_pb(p: i32) -> Provenance {
    match pb::Provenance::try_from(p).unwrap_or(pb::Provenance::Unspecified) {
        pb::Provenance::Unpackaged => Provenance::Unpackaged,
        pb::Provenance::Verified => Provenance::Verified,
        pb::Provenance::Modified => Provenance::Modified,
        pb::Provenance::Unspecified => Provenance::Unknown,
    }
}

pub fn direction_to_pb(d: Direction) -> pb::Direction {
    match d {
        Direction::Outbound => pb::Direction::Outbound,
        Direction::Inbound => pb::Direction::Inbound,
    }
}

/// Fails closed, like every other enum crossing this boundary.
///
/// `has_direction = true` with an unspecified value is a client that meant to
/// say something and did not; guessing "outbound" would silently make an
/// inbound rule fire on the wrong traffic entirely.
pub fn direction_from_pb(d: i32) -> Result<Direction, String> {
    match pb::Direction::try_from(d) {
        Ok(pb::Direction::Outbound) => Ok(Direction::Outbound),
        Ok(pb::Direction::Inbound) => Ok(Direction::Inbound),
        Ok(pb::Direction::Unspecified) | Err(_) => {
            Err(format!("direction unspecified/unknown: {d}"))
        }
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
        // Empty means "no package owns this" or "we did not / could not
        // check"; `provenance` is what tells those apart.
        package: p.package.clone().unwrap_or_default(),
        provenance: provenance_to_pb(p.provenance) as i32,
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
        direction: s.direction.map(|d| direction_to_pb(d) as i32).unwrap_or(0),
        has_direction: s.direction.is_some(),
        src_net: s.src_net.map(|n| n.to_string()).unwrap_or_default(),
        src_port: s.src_port.map(|p| p as u32).unwrap_or(0),
        has_src_port: s.src_port.is_some(),
        protocol: s.protocol.map(|p| protocol_to_pb(p) as i32).unwrap_or(0),
        has_protocol: s.protocol.is_some(),
    }
}

/// Converts a scope from the wire, **rejecting** anything it cannot represent.
///
/// This is the trust boundary, and it used to be the one place in the product
/// where a malformed field silently widened a rule. `dst_net` was
/// `.and_then(|n| IpNet::from_str(&n).ok())`, so a typo'd CIDR became `None` -
/// turning an Allow scoped `exe + 10.0.0.0/8` into an Allow scoped `exe`, i.e.
/// "this program may reach anywhere". A client's own validation is not a
/// substitute: `UpsertRule` accepts whatever any group member sends.
///
/// Three fields can fail: `dst_net`, `protocol` and `dst_port`. The last is the
/// least obvious and was missed on the first pass - the wire type is `uint32`
/// and the scope holds a `u16`, so `as u16` silently *wrapped*: a client asking
/// for port 65979 got a rule scoped to 443. Same class as the `dst_net` bug, on
/// the same boundary, so it fails the same way.
///
/// The remaining fields are total by construction: a string is a string, and
/// the `has_*` flags carry presence explicitly.
pub fn scope_from_pb(s: &pb::RuleScope) -> Result<RuleScope, String> {
    let dst_net = match empty_to_none(&s.dst_net) {
        Some(n) => Some(ipnet::IpNet::from_str(&n).map_err(|e| format!("bad dst_net `{n}`: {e}"))?),
        None => None,
    };
    let protocol = match s.has_protocol {
        true => Some(protocol_from_pb(s.protocol)?),
        false => None,
    };
    let dst_port =
        match s.has_dst_port {
            true => Some(u16::try_from(s.dst_port).map_err(|_| {
                format!("dst_port {} is out of range; a port is 0-65535", s.dst_port)
            })?),
            false => None,
        };
    let direction = match s.has_direction {
        true => Some(direction_from_pb(s.direction)?),
        false => None,
    };
    let src_net = match empty_to_none(&s.src_net) {
        Some(n) => Some(ipnet::IpNet::from_str(&n).map_err(|e| format!("bad src_net `{n}`: {e}"))?),
        None => None,
    };
    let src_port =
        match s.has_src_port {
            true => Some(u16::try_from(s.src_port).map_err(|_| {
                format!("src_port {} is out of range; a port is 0-65535", s.src_port)
            })?),
            false => None,
        };
    Ok(RuleScope {
        direction,
        src_net,
        src_port,
        exe_path: empty_to_none(&s.exe_path).map(Into::into),
        // Canonicalised at the wire, not merely stored: digests are matched by
        // exact string equality against the daemon's lowercase hex, so an
        // uppercase or truncated one arriving here would produce a rule that
        // lists, ranks, and never fires.
        exe_sha256: empty_to_none(&s.exe_sha256)
            .map(|h| cfc_core::rule::canonical_exe_sha256(&h))
            .transpose()?,
        parent_exe: empty_to_none(&s.parent_exe).map(Into::into),
        uid: s.has_uid.then_some(s.uid),
        dst_host: empty_to_none(&s.dst_host),
        dst_net,
        dst_port,
        protocol,
    })
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

/// Refuses a scope that constrains nothing.
///
/// Such a rule matches every process and every destination, so an Allow one is
/// "switch the firewall off" and a Deny one is "take the network down" - and it
/// arrives as an *empty message*, exactly what a default-initialised or
/// truncated client sends. Every first-party client already blocks it before
/// sending (the tray's own comment reads "a RuleScope with an empty exe_path
/// matches EVERYTHING"), which is the strongest argument for enforcing it here:
/// three clients independently decided it was dangerous, and the one boundary
/// they all pass through did not check.
pub fn reject_unscoped(scope: &RuleScope) -> Result<(), String> {
    if scope.specificity() == 0 {
        return Err(
            "rule scope constrains nothing, so it would match every process and \
             every destination; scope it to at least one of exe_path, uid, \
             dst_host, dst_net, dst_port or protocol"
                .to_string(),
        );
    }
    Ok(())
}

pub fn rule_from_pb(r: &pb::RuleInfo) -> Result<Rule, String> {
    let id = if r.id.is_empty() {
        uuid::Uuid::new_v4()
    } else {
        uuid::Uuid::parse_str(&r.id).map_err(|e| format!("bad id: {e}"))?
    };
    let scope = match r.scope.as_ref() {
        Some(s) => scope_from_pb(s)?,
        None => RuleScope::any(),
    };
    reject_unscoped(&scope)?;
    scope.reject_unmatchable_exe()?;
    scope.reject_unmatchable_parent()?;
    scope.reject_inbound_destination_scope()?;
    scope.reject_unattributable_inbound_scope()?;
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
            // Scoped, so this test measures the action/duration gate and not
            // the unscoped-rule gate below it.
            scope: Some(cfc_proto::v1::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                ..Default::default()
            }),
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
    fn a_rule_that_constrains_nothing_is_refused() {
        // An empty scope matches every process and every destination, so an
        // Allow one switches the firewall off. It also happens to be what a
        // default-initialised or truncated client sends, which is why the
        // boundary has to catch it rather than trusting three clients to.
        let mut pb = cfc_proto::v1::RuleInfo {
            id: String::new(),
            name: "everything".into(),
            enabled: true,
            action: cfc_proto::v1::Action::Allow as i32,
            duration: cfc_proto::v1::Duration::Always as i32,
            scope: Some(cfc_proto::v1::RuleScope::default()),
            created_at_unix_ms: 0,
            hit_count: 0,
        };
        let e = rule_from_pb(&pb).expect_err("an unscoped rule must be refused");
        assert!(e.contains("constrains nothing"), "{e}");

        // A missing scope message is the same thing arriving a different way.
        pb.scope = None;
        assert!(rule_from_pb(&pb).is_err());

        // Any single predicate is enough to make it a rule about something.
        pb.scope = Some(cfc_proto::v1::RuleScope {
            has_uid: true,
            uid: 1000,
            ..Default::default()
        });
        assert!(rule_from_pb(&pb).is_ok());
    }

    #[test]
    fn an_out_of_range_port_is_refused_rather_than_wrapped() {
        // `as u16` wrapped: a scope asking for 65979 became a rule scoped to
        // 443. The wire type is uint32 and the scope holds a u16, so the
        // conversion has to be checked like any other narrowing at a trust
        // boundary.
        let mut scope = cfc_proto::v1::RuleScope {
            exe_path: "/usr/bin/curl".into(),
            has_dst_port: true,
            dst_port: 65_979,
            ..Default::default()
        };
        let e = scope_from_pb(&scope).expect_err("65979 is not a port");
        assert!(e.contains("out of range"), "{e}");
        assert!(e.contains("65979"), "the message must quote the value: {e}");

        // 65535 is the largest real port and must still work.
        scope.dst_port = 65_535;
        assert_eq!(scope_from_pb(&scope).unwrap().dst_port, Some(65_535));

        // And an absent port is still absent, whatever junk rides along.
        scope.has_dst_port = false;
        scope.dst_port = 999_999;
        assert_eq!(scope_from_pb(&scope).unwrap().dst_port, None);
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
    fn provenance_roundtrip() {
        for p in [
            Provenance::Unknown,
            Provenance::Unpackaged,
            Provenance::Verified,
            Provenance::Modified,
        ] {
            assert_eq!(provenance_from_pb(provenance_to_pb(p) as i32), p);
        }
    }

    #[test]
    fn provenance_unknown_absorbs_unset_and_version_skew() {
        // Advisory metadata, so an unrecognized value degrades to "cannot
        // say" instead of erroring a whole prompt off the wire.
        assert_eq!(provenance_from_pb(0), Provenance::Unknown);
        assert_eq!(provenance_from_pb(99), Provenance::Unknown);
        assert_eq!(provenance_from_pb(-1), Provenance::Unknown);
    }

    #[test]
    fn process_carries_package_and_provenance_onto_the_wire() {
        let mut p = cfc_core::Process::unknown(42);
        // Default: nothing claimed.
        assert_eq!(process_to_pb(&p).package, "");
        assert_eq!(
            process_to_pb(&p).provenance,
            cfc_proto::v1::Provenance::Unspecified as i32
        );

        p.package = Some("curl 8.21.0-1".into());
        p.provenance = Provenance::Modified;
        let pb = process_to_pb(&p);
        assert_eq!(pb.package, "curl 8.21.0-1");
        assert_eq!(pb.provenance, cfc_proto::v1::Provenance::Modified as i32);
        assert_eq!(provenance_from_pb(pb.provenance), Provenance::Modified);

        // "Owned but unverifiable" (dpkg): a package name alongside
        // UNSPECIFIED must survive the wire as exactly that pair.
        p.provenance = Provenance::Unknown;
        let pb = process_to_pb(&p);
        assert_eq!(pb.package, "curl 8.21.0-1");
        assert_eq!(pb.provenance, cfc_proto::v1::Provenance::Unspecified as i32);
    }

    #[test]
    fn protocol_roundtrip() {
        for p in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
            let pb = protocol_to_pb(p) as i32;
            assert_eq!(protocol_from_pb(pb).unwrap(), p);
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
            direction: None,
            src_net: None,
            src_port: None,
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
            // A real-shaped digest: the wire now refuses anything but 64
            // lowercase hex, and this test's job is the roundtrip, not the
            // validator.
            exe_sha256: Some("a".repeat(64)),
            parent_exe: Some(PathBuf::from("/bin/bash")),
            uid: Some(1000),
            dst_host: Some("example.com".into()),
            dst_net: Some("10.0.0.0/8".parse().unwrap()),
            dst_port: Some(443),
            protocol: Some(Protocol::Tcp),
        };
        let pb = scope_to_pb(&scope);
        let back = scope_from_pb(&pb).expect("a scope we produced must convert back");
        assert_eq!(back, scope);
    }

    #[test]
    fn scope_roundtrip_empty() {
        let scope = RuleScope::any();
        let pb = scope_to_pb(&scope);
        let back = scope_from_pb(&pb).expect("a scope we produced must convert back");
        assert_eq!(back, scope);
    }

    #[test]
    fn a_malformed_dst_net_is_refused_not_dropped() {
        // The whole point. Dropping it to None turned "this program may reach
        // 10.0.0.0/8" into "this program may reach anywhere" - a silent
        // widening of policy on the path any group member can reach.
        let mut pb = scope_to_pb(&RuleScope::any());
        pb.exe_path = "/usr/bin/curl".into();
        pb.dst_net = "10.0.0.0/33".into();
        let e = scope_from_pb(&pb).expect_err("a bad CIDR must not be silently ignored");
        assert!(
            e.contains("dst_net"),
            "the message must name the field: {e}"
        );
        assert!(e.contains("10.0.0.0/33"), "and quote the value: {e}");

        // A rule carrying it is refused whole, rather than persisted narrower
        // than it reads.
        let mut r = rule_to_pb(&Rule::new("x", Action::Allow, RuleScope::any()));
        r.scope = Some(pb);
        assert!(rule_from_pb(&r).is_err());
    }

    #[test]
    fn an_unspecified_protocol_is_refused_rather_than_made_unmatchable() {
        // has_protocol = true with UNSPECIFIED used to become Other(0), a
        // predicate no parsed packet can ever satisfy - so the rule was inert
        // *and* outranked the rules that would have matched, because an unset
        // predicate and an unmatchable one score the same specificity.
        let mut pb = scope_to_pb(&RuleScope::any());
        pb.has_protocol = true;
        pb.protocol = cfc_proto::v1::Protocol::Unspecified as i32;
        assert!(scope_from_pb(&pb).is_err());

        // Same for a value from a newer client this build does not know.
        pb.protocol = 9999;
        assert!(scope_from_pb(&pb).is_err());

        // And for `other`, which carries no protocol number on the wire, so a
        // scope cannot express it even in principle.
        pb.protocol = cfc_proto::v1::Protocol::Other as i32;
        assert!(scope_from_pb(&pb).is_err());
    }

    #[test]
    fn an_absent_protocol_is_still_absent_not_an_error() {
        // has_protocol = false is the ordinary "this rule says nothing about
        // protocol" case and must stay total.
        let mut pb = scope_to_pb(&RuleScope::any());
        pb.has_protocol = false;
        pb.protocol = 9999;
        assert_eq!(scope_from_pb(&pb).unwrap().protocol, None);
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
