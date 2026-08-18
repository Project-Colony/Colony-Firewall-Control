//! The live feed: everything the daemon decided, newest first.
//!
//! Filterable, freezable (rows shifting under the cursor made the old feed
//! unclickable), and every row can seed a rule.

use cfc_client::{convert, proto};
use iced::widget::{
    button, column, container, pick_list, row, scrollable, text, text_input, Space,
};
use iced::{Element, Length};
use std::collections::VecDeque;

use crate::{format, LiveEntry, Message};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum VerdictFilter {
    #[default]
    All,
    Allowed,
    Denied,
}

impl VerdictFilter {
    pub const ALL: [VerdictFilter; 3] = [
        VerdictFilter::All,
        VerdictFilter::Allowed,
        VerdictFilter::Denied,
    ];

    /// Reject counts as denied: both stop the flow.
    fn accepts(self, verdict: i32) -> bool {
        let action = proto::Action::try_from(verdict).unwrap_or(proto::Action::Unspecified);
        match self {
            VerdictFilter::All => true,
            VerdictFilter::Allowed => action == proto::Action::Allow,
            VerdictFilter::Denied => {
                matches!(action, proto::Action::Deny | proto::Action::Reject)
            }
        }
    }
}

impl std::fmt::Display for VerdictFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VerdictFilter::All => "All verdicts",
            VerdictFilter::Allowed => "Allowed",
            VerdictFilter::Denied => "Denied",
        })
    }
}

pub struct ListArgs<'a> {
    pub live: &'a VecDeque<LiveEntry>,
    /// Snapshot rendered instead of `live` while the feed is paused.
    pub frozen: Option<&'a [LiveEntry]>,
    pub filter: &'a str,
    pub verdict: VerdictFilter,
    pub new_while_paused: usize,
}

/// Free-text match over process name, executable path, hostname and
/// address, plus the verdict filter. Case-insensitive.
pub fn matches(ev: &proto::ConnectionEvent, needle: &str, verdict: VerdictFilter) -> bool {
    if !verdict.accepts(ev.verdict) {
        return false;
    }
    let needle = needle.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    if let Some(p) = ev.process.as_ref() {
        if p.exe.to_ascii_lowercase().contains(&needle) {
            return true;
        }
        if convert::process_display(p)
            .to_ascii_lowercase()
            .contains(&needle)
        {
            return true;
        }
    }
    if let Some(c) = ev.connection.as_ref() {
        if c.dst_host.to_ascii_lowercase().contains(&needle) {
            return true;
        }
        if c.dst_ip.to_ascii_lowercase().contains(&needle) {
            return true;
        }
        if c.dst_port.to_string().contains(&needle) {
            return true;
        }
    }
    false
}

pub fn view(args: ListArgs<'_>) -> Element<'_, Message> {
    let ListArgs {
        live,
        frozen,
        filter,
        verdict,
        new_while_paused,
    } = args;

    let paused = frozen.is_some();
    let source: Box<dyn Iterator<Item = &LiveEntry>> = match frozen {
        Some(f) => Box::new(f.iter()),
        None => Box::new(live.iter()),
    };
    let shown: Vec<&LiveEntry> = source
        .filter(|e| matches(&e.event, filter, verdict))
        .collect();
    let total = frozen.map(<[LiveEntry]>::len).unwrap_or(live.len());

    let pause_label = if paused {
        if new_while_paused > 0 {
            format!("Resume ({new_while_paused} new)")
        } else {
            "Resume".to_string()
        }
    } else {
        "Pause".to_string()
    };

    let toolbar = row![
        text_input("Filter by process / host / ip / port", filter)
            .on_input(Message::LiveFilterChanged)
            .padding(4)
            .size(12)
            .width(Length::Fixed(280.0)),
        pick_list(
            VerdictFilter::ALL,
            Some(verdict),
            Message::LiveVerdictFilter
        )
        .text_size(12)
        .padding([2, 6]),
        button(text(pause_label).size(12))
            .padding([4, 12])
            .on_press(Message::ToggleLivePause)
            .style(if paused {
                iced::widget::button::primary
            } else {
                iced::widget::button::secondary
            }),
        Space::new().width(Length::Fill),
        text(format!("{}/{total} rows", shown.len())).size(11),
    ]
    .spacing(8)
    .padding(6)
    .align_y(iced::Alignment::Center);

    let header = row![
        text("time").size(11).width(Length::Fixed(70.0)),
        text("proto").size(11).width(Length::Fixed(44.0)),
        text("process").size(11).width(Length::Fixed(150.0)),
        text("dest").size(11).width(Length::Fill),
        text("verdict").size(11).width(Length::Fixed(64.0)),
        text("").width(Length::Fixed(90.0)),
    ]
    .spacing(6)
    .padding(6);

    if shown.is_empty() {
        let msg = if total == 0 {
            "(no traffic observed yet)".to_string()
        } else {
            "(no rows match the current filter)".to_string()
        };
        return container(
            column![toolbar, header, container(text(msg).size(12)).padding(12)].spacing(4),
        )
        .padding(8)
        .into();
    }

    let rows: Vec<Element<'_, Message>> = shown.into_iter().map(live_row).collect();

    container(
        column![
            toolbar,
            header,
            scrollable(column(rows).spacing(1).padding([0, 6])).height(Length::Fill),
        ]
        .spacing(4),
    )
    .padding(8)
    .into()
}

fn live_row(e: &LiveEntry) -> Element<'_, Message> {
    let ev = &e.event;
    let conn = ev.connection.as_ref();
    let proc = ev.process.as_ref();

    let t = conn
        .map(|c| format::format_clock_ms(c.timestamp_unix_ms))
        .unwrap_or_else(|| "?".into());
    let proto_label = conn
        .map(|c| convert::protocol_label(c.protocol).to_string())
        .unwrap_or_default();
    let process_label = proc
        .map(|p| format!("{} ({})", convert::process_display(p), p.pid))
        .unwrap_or_else(|| "unknown".into());
    let dest = conn
        .map(|c| format::dest_display(&c.dst_host, &c.dst_ip, c.dst_port))
        .unwrap_or_else(|| "?".into());

    let action = proto::Action::try_from(ev.verdict).unwrap_or(proto::Action::Unspecified);
    let denied = matches!(action, proto::Action::Deny | proto::Action::Reject);
    let verdict_badge = container(text(convert::action_label(ev.verdict)).size(10))
        .padding([1, 6])
        .style(if action == proto::Action::Allow {
            crate::theme::badge_ok
        } else if denied {
            crate::theme::badge_err
        } else {
            crate::theme::badge_warn
        });

    let copy: Element<'_, Message> = match conn {
        Some(c) => button(text("⧉").size(10))
            .padding([0, 4])
            .on_press(Message::CopyText(format::dest_display(
                &c.dst_host,
                &c.dst_ip,
                c.dst_port,
            )))
            .style(crate::theme::subtle_icon)
            .into(),
        None => Space::new().into(),
    };

    // Seeds the rule editor from this exact flow - the shortcut people
    // reach for most in opensnitch.
    let make_rule: Element<'_, Message> = match conn {
        Some(c) => button(text("make rule").size(10))
            .padding([1, 6])
            .on_press(Message::MakeRuleFromEvent {
                exe: proc.map(|p| p.exe.clone()).unwrap_or_default(),
                dst_host: c.dst_host.clone(),
                dst_ip: c.dst_ip.clone(),
                dst_port: c.dst_port,
                protocol: c.protocol,
            })
            .style(crate::theme::subtle_icon)
            .into(),
        None => Space::new().into(),
    };

    let inner = row![
        text(t).size(11).width(Length::Fixed(70.0)),
        text(proto_label).size(11).width(Length::Fixed(44.0)),
        text(process_label).size(11).width(Length::Fixed(150.0)),
        row![text(dest).size(11), copy]
            .spacing(4)
            .width(Length::Fill)
            .align_y(iced::Alignment::Center),
        container(verdict_badge).width(Length::Fixed(64.0)),
        container(make_rule).width(Length::Fixed(90.0)),
    ]
    .spacing(6)
    .padding(2)
    .align_y(iced::Alignment::Center);

    if denied {
        container(inner).style(crate::theme::row_denied).into()
    } else {
        inner.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        exe: &str,
        host: &str,
        ip: &str,
        port: u32,
        verdict: proto::Action,
    ) -> proto::ConnectionEvent {
        proto::ConnectionEvent {
            connection: Some(proto::ConnectionInfo {
                id: String::new(),
                timestamp_unix_ms: 0,
                protocol: proto::Protocol::Tcp as i32,
                direction: proto::Direction::Outbound as i32,
                src_ip: "10.0.0.2".into(),
                src_port: 5000,
                dst_ip: ip.into(),
                dst_port: port,
                dst_host: host.into(),
            }),
            process: Some(proto::ProcessInfo {
                pid: 42,
                ppid: 1,
                uid: None,
                gid: None,
                exe: exe.into(),
                cmdline: vec![],
                cwd: String::new(),
                sha256: String::new(),
            }),
            verdict: verdict as i32,
            rule_id: String::new(),
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        let e = ev(
            "/usr/bin/curl",
            "example.com",
            "1.2.3.4",
            443,
            proto::Action::Allow,
        );
        assert!(matches(&e, "", VerdictFilter::All));
        assert!(matches(&e, "   ", VerdictFilter::All));
    }

    #[test]
    fn filter_hits_exe_basename_host_ip_and_port() {
        let e = ev(
            "/usr/bin/curl",
            "example.com",
            "93.184.216.34",
            443,
            proto::Action::Allow,
        );
        assert!(matches(&e, "curl", VerdictFilter::All));
        assert!(matches(&e, "/usr/bin", VerdictFilter::All));
        assert!(
            matches(&e, "EXAMPLE", VerdictFilter::All),
            "case-insensitive"
        );
        assert!(matches(&e, "93.184", VerdictFilter::All));
        assert!(matches(&e, "443", VerdictFilter::All));
        assert!(!matches(&e, "firefox", VerdictFilter::All));
    }

    #[test]
    fn verdict_filter_groups_reject_with_deny() {
        let allowed = ev("/bin/a", "", "1.1.1.1", 80, proto::Action::Allow);
        let denied = ev("/bin/a", "", "1.1.1.1", 80, proto::Action::Deny);
        let rejected = ev("/bin/a", "", "1.1.1.1", 80, proto::Action::Reject);

        assert!(matches(&allowed, "", VerdictFilter::Allowed));
        assert!(!matches(&denied, "", VerdictFilter::Allowed));

        assert!(matches(&denied, "", VerdictFilter::Denied));
        assert!(matches(&rejected, "", VerdictFilter::Denied));
        assert!(!matches(&allowed, "", VerdictFilter::Denied));

        for e in [&allowed, &denied, &rejected] {
            assert!(matches(e, "", VerdictFilter::All));
        }
    }

    #[test]
    fn text_and_verdict_filters_are_conjunctive() {
        let e = ev(
            "/usr/bin/curl",
            "example.com",
            "1.2.3.4",
            443,
            proto::Action::Allow,
        );
        assert!(matches(&e, "curl", VerdictFilter::Allowed));
        assert!(!matches(&e, "curl", VerdictFilter::Denied));
        assert!(!matches(&e, "wget", VerdictFilter::Allowed));
    }

    #[test]
    fn events_without_process_or_connection_do_not_panic() {
        let mut e = ev("/bin/a", "h", "1.1.1.1", 80, proto::Action::Allow);
        e.process = None;
        e.connection = None;
        assert!(matches(&e, "", VerdictFilter::All));
        assert!(!matches(&e, "anything", VerdictFilter::All));
    }
}
