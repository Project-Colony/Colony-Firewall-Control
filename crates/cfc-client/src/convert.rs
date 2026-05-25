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
