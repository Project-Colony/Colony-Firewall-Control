//! Small helpers for rendering proto types in a UI/CLI-friendly form.

use cfc_proto::v1 as pb;

/// Renders an untrusted value (a path, a command line, a DNS name) as one
/// line that cannot rearrange what is around it.
///
/// Control characters (newlines included) and the bidi embedding, override
/// and isolate characters are written as escapes. Process strings are
/// chosen by the program being judged, or by whoever named its file, and DNS
/// names by whoever answers the query: a U+202E in a directory name reverses
/// the rest of a Path row, and an embedded newline adds a fake line to a
/// prompt. Only for display; rules and copies keep the raw value.
pub fn display_safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control()
                || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

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
        pb::Duration::Seconds => "seconds",
        pb::Duration::Unspecified => "?",
    }
}

/// Human-readable duration including a timed rule's exact lifetime.
pub fn rule_duration_label(rule: &pb::RuleInfo) -> String {
    if rule.duration == pb::Duration::Seconds as i32 {
        format!("{}s", rule.duration_seconds)
    } else {
        duration_label(rule.duration).to_string()
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

/// Re-exported so a UI can name the placeholder without depending on the core
/// crate for one string.
pub use cfc_core::UNKNOWN_EXE;

/// Whether `exe` can be the basis of a program-scoped rule.
///
/// Three ways a prompt's executable string fails to be one, and all three
/// produce a rule that is wider than it reads:
///
/// * empty - `exe_path: ""` matches every program on the machine;
/// * [`cfc_core::UNKNOWN_EXE`] - what is shown when the process could not be
///   identified. A rule carrying it matches every unattributable flow, and
///   inbound flows are always unattributable. One such rule, answered once in
///   a bubble, admitted every inbound connection on a real machine;
/// * not absolute - rules match absolute paths, so it could never fire.
///
/// The daemon refuses all three, but a UI that offers the choice and then
/// reports a failure is a worse answer than not offering it.
pub fn exe_is_rule_scopable(exe: &str) -> bool {
    !exe.is_empty() && exe != cfc_core::UNKNOWN_EXE && std::path::Path::new(exe).is_absolute()
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

/// The program's basename for display, made [`display_safe`].
pub fn process_display(p: &pb::ProcessInfo) -> String {
    if p.exe.is_empty() {
        format!("pid:{}", p.pid)
    } else {
        display_safe(&match std::path::Path::new(&p.exe).file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => p.exe.clone(),
        })
    }
}

/// One line per rule, for `rules list` and the GUI's rule rows.
///
/// Direction and the source predicates are part of the line, not only of
/// `--json`: without them the inbound bundle's LAN-scoped SSH rule rendered as
/// `allow * -> *:22` - byte-identical to an unrestricted outbound allow - so
/// the one listing an operator audits hid both the inbound direction and the
/// 192.168.0.0/16 that makes the rule safe.
pub fn rule_summary(r: &pb::RuleInfo) -> String {
    let scope = r.scope.as_ref();
    let target = scope
        .and_then(|s| {
            if !s.dst_host.is_empty() {
                Some(format!(
                    "{} [legacy hostname; uncertain]",
                    display_safe(&s.dst_host)
                ))
            } else if !s.dst_net.is_empty() {
                Some(s.dst_net.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "*".into());
    // Protocol, uid and a pinned digest narrow the rule too; left out, a
    // `deny uid 1000 udp/53` read as DNS blocked for everyone.
    let port = scope.map_or_else(String::new, |s| {
        let mut port = if s.has_dst_port {
            format!(":{}", s.dst_port)
        } else {
            String::new()
        };
        if s.has_protocol {
            port.push(' ');
            port.push_str(protocol_label(s.protocol));
        }
        if s.has_uid {
            port.push_str(&format!(" uid={}", s.uid));
        }
        if !s.exe_sha256.is_empty() {
            port.push_str(" [pinned]");
        }
        port
    });
    let exe = scope
        .and_then(|s| {
            if s.exe_path.is_empty() {
                None
            } else {
                Some(display_safe(&s.exe_path))
            }
        })
        .unwrap_or_else(|| "*".into());
    // src_net and src_port collapse into one "peer" column, mirroring how
    // target and dst_port do.
    let src = scope.and_then(|s| {
        let net = (!s.src_net.is_empty()).then(|| s.src_net.clone());
        let sport = s.has_src_port.then(|| format!(":{}", s.src_port));
        match (net, sport) {
            (None, None) => None,
            (net, sport) => Some(format!(
                "{}{}",
                net.unwrap_or_else(|| "*".into()),
                sport.unwrap_or_default()
            )),
        }
    });
    let inbound =
        scope.is_some_and(|s| s.has_direction && s.direction == pb::Direction::Inbound as i32);
    if inbound {
        // Inbound reads peer -> our port. The exe slot is dropped: inbound
        // flows are never attributed to a program, and the boundary refuses
        // program-scoped inbound rules outright.
        format!(
            "{:<7} in {} -> {}{}",
            action_label(r.action),
            src.unwrap_or_else(|| "*".into()),
            target,
            port
        )
    } else if let Some(src) = src {
        // An outbound rule constraining its source is unusual but
        // expressible; hiding the predicate would make the rule read wider
        // than it matches.
        format!(
            "{:<7} {} from {} -> {}{}",
            action_label(r.action),
            exe,
            src,
            target,
            port
        )
    } else {
        format!(
            "{:<7} {} -> {}{}",
            action_label(r.action),
            exe,
            target,
            port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_safe_escapes_controls_and_bidi_only() {
        assert_eq!(display_safe("line\nnext\tcell"), "line\\nnext\\tcell");
        assert!(display_safe("\u{202e}\u{2066}").is_ascii());
        assert_eq!(display_safe("/usr/bin/caf\u{e9}"), "/usr/bin/caf\u{e9}");
        let p = pb::ProcessInfo {
            exe: "/tmp/\u{202e}gpj.sh".into(),
            ..Default::default()
        };
        assert!(process_display(&p).is_ascii());
    }

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

    fn rule(scope: pb::RuleScope) -> pb::RuleInfo {
        pb::RuleInfo {
            action: pb::Action::Allow as i32,
            scope: Some(scope),
            ..Default::default()
        }
    }

    #[test]
    fn an_outbound_summary_keeps_its_shape() {
        // The overwhelming case; the direction/source additions must not
        // reformat every ordinary row.
        let s = rule_summary(&rule(pb::RuleScope {
            exe_path: "/usr/bin/curl".into(),
            dst_host: "example.com".into(),
            dst_port: 443,
            has_dst_port: true,
            ..Default::default()
        }));
        assert_eq!(
            s,
            "allow   /usr/bin/curl -> example.com [legacy hostname; uncertain]:443"
        );
    }

    #[test]
    fn an_inbound_summary_shows_direction_and_peer() {
        // The inbound bundle's LAN-scoped SSH rule used to render as
        // `allow * -> *:22` - indistinguishable from an unrestricted
        // outbound allow. The direction and the source restriction are the
        // two facts that make the rule safe, so the summary must carry both.
        let s = rule_summary(&rule(pb::RuleScope {
            direction: pb::Direction::Inbound as i32,
            has_direction: true,
            src_net: "192.168.0.0/16".into(),
            dst_port: 22,
            has_dst_port: true,
            ..Default::default()
        }));
        assert!(s.contains("in "), "{s}");
        assert!(s.contains("192.168.0.0/16"), "{s}");
        assert!(s.contains(":22"), "{s}");
    }

    #[test]
    fn protocol_uid_and_pinned_digest_are_not_hidden() {
        let s = rule_summary(&rule(pb::RuleScope {
            exe_sha256: "ab".repeat(32),
            uid: 1000,
            has_uid: true,
            protocol: pb::Protocol::Udp as i32,
            has_protocol: true,
            dst_port: 53,
            has_dst_port: true,
            ..Default::default()
        }));
        assert_eq!(s, "allow   * -> *:53 udp uid=1000 [pinned]");
    }

    #[test]
    fn an_outbound_source_restriction_is_not_hidden() {
        let s = rule_summary(&rule(pb::RuleScope {
            exe_path: "/usr/bin/curl".into(),
            src_port: 5000,
            has_src_port: true,
            ..Default::default()
        }));
        assert!(s.contains("from *:5000"), "{s}");
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
