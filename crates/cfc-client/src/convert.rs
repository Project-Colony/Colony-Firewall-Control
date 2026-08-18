//! Small helpers for rendering proto types in a UI/CLI-friendly form.

use cfc_proto::v1 as pb;

pub fn action_label(a: i32) -> &'static str {
    match pb::Action::try_from(a).unwrap_or(pb::Action::Unspecified) {
        pb::Action::Allow => "allow",
        pb::Action::Deny => "deny",
        pb::Action::Reject => "reject",
        pb::Action::Unspecified => "?",
    }
}

pub fn protocol_label(p: i32) -> &'static str {
    match pb::Protocol::try_from(p).unwrap_or(pb::Protocol::Unspecified) {
        pb::Protocol::Tcp => "tcp",
        pb::Protocol::Udp => "udp",
        pb::Protocol::Icmp => "icmp",
        pb::Protocol::Other => "other",
        pb::Protocol::Unspecified => "?",
    }
}

pub fn direction_label(d: i32) -> &'static str {
    match pb::Direction::try_from(d).unwrap_or(pb::Direction::Unspecified) {
        pb::Direction::Outbound => "out",
        pb::Direction::Inbound => "in",
        pb::Direction::Unspecified => "?",
    }
}

pub fn duration_label(d: i32) -> &'static str {
    match pb::Duration::try_from(d).unwrap_or(pb::Duration::Unspecified) {
        pb::Duration::Once => "once",
        pb::Duration::UntilRestart => "until-restart",
        pb::Duration::Always => "always",
        pb::Duration::Unspecified => "?",
    }
}

/// One-word provenance token, for JSON output and log lines.
pub fn provenance_token(p: i32) -> &'static str {
    match pb::Provenance::try_from(p).unwrap_or(pb::Provenance::Unspecified) {
        pb::Provenance::Unpackaged => "unpackaged",
        pb::Provenance::Verified => "verified",
        pb::Provenance::Modified => "modified",
        pb::Provenance::Unspecified => "unknown",
    }
}

/// The one-line answer to "does this binary still match what the
/// distribution installed?", short enough for a table cell.
///
/// Five shapes, because `package` and `provenance` are read together:
///
/// - `"curl 8.21.0-1 (verified)"`  - owned, and the running bytes match.
/// - `"curl 8.21.0-1 — MODIFIED since install"` - owned, bytes differ.
/// - `"curl 8.21.0-1 (unverified)"` - owned, but the package database
///   records no digest we can check (dpkg). Says who shipped it and
///   pointedly does not vouch for it.
/// - `"not from a package"` - nobody owns this path.
/// - `"unknown"` - not checked, or no package database on this host.
pub fn provenance_label(p: &pb::ProcessInfo) -> String {
    let pkg = p.package.trim();
    match pb::Provenance::try_from(p.provenance).unwrap_or(pb::Provenance::Unspecified) {
        pb::Provenance::Modified if pkg.is_empty() => "MODIFIED since install".to_string(),
        pb::Provenance::Modified => format!("{pkg} — MODIFIED since install"),
        pb::Provenance::Verified if pkg.is_empty() => "verified".to_string(),
        pb::Provenance::Verified => format!("{pkg} (verified)"),
        pb::Provenance::Unpackaged => "not from a package".to_string(),
        pb::Provenance::Unspecified if pkg.is_empty() => "unknown".to_string(),
        pb::Provenance::Unspecified => format!("{pkg} (unverified)"),
    }
}

/// Whether [`provenance_label`] would say anything worth a line of screen.
/// False on a host with no package database, where every process would
/// otherwise carry a useless "unknown".
pub fn has_provenance(p: &pb::ProcessInfo) -> bool {
    !p.package.trim().is_empty()
        || pb::Provenance::try_from(p.provenance).unwrap_or(pb::Provenance::Unspecified)
            != pb::Provenance::Unspecified
}

/// Renders a process uid for display.
///
/// `None` means the daemon could not attribute the flow to a process. The
/// proto carries explicit presence precisely so that case does not render
/// as uid 0, i.e. as root.
pub fn uid_label(uid: Option<u32>) -> String {
    match uid {
        Some(u) => u.to_string(),
        None => "unknown".to_string(),
    }
}

pub fn process_display(p: &pb::ProcessInfo) -> String {
    if p.exe.is_empty() {
        format!("pid:{}", p.pid)
    } else {
        match std::path::Path::new(&p.exe).file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => p.exe.clone(),
        }
    }
}

pub fn rule_summary(r: &pb::RuleInfo) -> String {
    let scope = r.scope.as_ref();
    let target = scope
        .and_then(|s| {
            if !s.dst_host.is_empty() {
                Some(s.dst_host.clone())
            } else if !s.dst_net.is_empty() {
                Some(s.dst_net.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "*".into());
    let port = scope
        .and_then(|s| s.has_dst_port.then_some(s.dst_port))
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    let exe = scope
        .and_then(|s| {
            if s.exe_path.is_empty() {
                None
            } else {
                Some(s.exe_path.clone())
            }
        })
        .unwrap_or_else(|| "*".into());
    format!(
        "{:<7} {} -> {}{}",
        action_label(r.action),
        exe,
        target,
        port
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(package: &str, provenance: pb::Provenance) -> pb::ProcessInfo {
        pb::ProcessInfo {
            package: package.into(),
            provenance: provenance as i32,
            ..Default::default()
        }
    }

    #[test]
    fn provenance_labels() {
        assert_eq!(
            provenance_label(&proc("curl 8.21.0-1", pb::Provenance::Verified)),
            "curl 8.21.0-1 (verified)"
        );
        assert_eq!(
            provenance_label(&proc("curl 8.21.0-1", pb::Provenance::Modified)),
            "curl 8.21.0-1 — MODIFIED since install"
        );
        assert_eq!(
            provenance_label(&proc("", pb::Provenance::Unpackaged)),
            "not from a package"
        );
        assert_eq!(
            provenance_label(&proc("", pb::Provenance::Unspecified)),
            "unknown"
        );
        // dpkg: package known, bytes not vouched for.
        assert_eq!(
            provenance_label(&proc("curl", pb::Provenance::Unspecified)),
            "curl (unverified)"
        );
    }

    #[test]
    fn provenance_label_never_swallows_a_modified_verdict() {
        // Even with no package name, MODIFIED must still shout.
        let s = provenance_label(&proc("", pb::Provenance::Modified));
        assert!(s.contains("MODIFIED"), "{s}");
        // An unpackaged binary that somehow carries a name: the "no package
        // owns this" fact wins, because that is what the enum asserts.
        assert_eq!(
            provenance_label(&proc("stale", pb::Provenance::Unpackaged)),
            "not from a package"
        );
    }

    #[test]
    fn provenance_label_survives_version_skew() {
        let mut p = proc("curl 8.21.0-1", pb::Provenance::Verified);
        p.provenance = 99;
        assert_eq!(provenance_label(&p), "curl 8.21.0-1 (unverified)");
        assert_eq!(provenance_token(99), "unknown");
    }

    #[test]
    fn provenance_is_worth_showing_only_when_something_is_known() {
        assert!(!has_provenance(&proc("", pb::Provenance::Unspecified)));
        assert!(has_provenance(&proc("", pb::Provenance::Unpackaged)));
        assert!(has_provenance(&proc("curl", pb::Provenance::Unspecified)));
        assert!(has_provenance(&proc(
            "curl 8.21.0-1",
            pb::Provenance::Verified
        )));
    }

    #[test]
    fn provenance_tokens() {
        assert_eq!(
            provenance_token(pb::Provenance::Verified as i32),
            "verified"
        );
        assert_eq!(
            provenance_token(pb::Provenance::Modified as i32),
            "modified"
        );
        assert_eq!(
            provenance_token(pb::Provenance::Unpackaged as i32),
            "unpackaged"
        );
        assert_eq!(
            provenance_token(pb::Provenance::Unspecified as i32),
            "unknown"
        );
    }
}
