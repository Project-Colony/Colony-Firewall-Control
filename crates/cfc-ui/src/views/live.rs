//! The live feed: everything the daemon decided, newest first.
//!
//! Filterable, freezable (rows shifting under the cursor made the old feed
//! unclickable), and every row can seed a rule.

use cfc_client::{convert, proto};
use iced::widget::{button, column, container, pick_list, row, scrollable, text_input, Space};
use iced::{Element, Length};
use std::collections::VecDeque;

use crate::app::Message;
use crate::format;
use crate::i18n::{t, t_fmt};
use crate::theme::{self, sz, ui_text};

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
            VerdictFilter::All => t("live_all"),
            VerdictFilter::Allowed => t("live_allowed"),
            VerdictFilter::Denied => t("live_denied"),
        })
    }
}

pub struct ListArgs<'a> {
    pub live: &'a VecDeque<proto::ConnectionEvent>,
    /// Snapshot rendered instead of `live` while the feed is paused.
    pub frozen: Option<&'a [proto::ConnectionEvent]>,
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
    let source: Box<dyn Iterator<Item = &proto::ConnectionEvent>> = match frozen {
        Some(f) => Box::new(f.iter()),
        None => Box::new(live.iter()),
    };
    let shown: Vec<&proto::ConnectionEvent> =
        source.filter(|e| matches(e, filter, verdict)).collect();
    let total = frozen
        .map(<[proto::ConnectionEvent]>::len)
        .unwrap_or(live.len());

    let pause_label = if paused {
        if new_while_paused > 0 {
            t_fmt(
                "live_resume_new",
                &[("count", &new_while_paused.to_string())],
            )
        } else {
            t("button_resume").to_string()
        }
    } else {
        t("button_pause").to_string()
    };

    let toolbar = row![
        text_input(t("live_filter"), filter)
            .font(colony_ui::ui_font())
            .on_input(Message::LiveFilterChanged)
            .padding(4)
            .size(sz(12))
            .width(theme::scaled(280.0)),
        pick_list(
            VerdictFilter::ALL,
            Some(verdict),
            Message::LiveVerdictFilter
        )
        .font(colony_ui::ui_font())
        .text_size(sz(12))
        .padding([2, 6]),
        button(ui_text(pause_label).size(sz(12)))
            .padding([4, 12])
            .on_press(Message::ToggleLivePause)
            .style(if paused {
                iced::widget::button::primary
            } else {
                iced::widget::button::secondary
            }),
        Space::new().width(Length::Fill),
        ui_text(t_fmt(
            "live_rows",
            &[
                ("shown", &shown.len().to_string()),
                ("total", &total.to_string()),
            ],
        ))
        .size(sz(11)),
    ]
    .spacing(8)
    .padding(6)
    .align_y(iced::Alignment::Center);

    let header = row![
        ui_text(t("live_col_time"))
            .size(sz(11))
            .width(theme::scaled(70.0)),
        ui_text(t("live_col_proto"))
            .size(sz(11))
            .width(theme::scaled(44.0)),
        ui_text(t("live_col_process"))
            .size(sz(11))
            .width(theme::scaled(150.0)),
        ui_text(t("live_col_dest")).size(sz(11)).width(Length::Fill),
        ui_text(t("live_col_verdict"))
            .size(sz(11))
            .width(theme::scaled(64.0)),
        ui_text("").width(theme::scaled(90.0)),
    ]
    .spacing(6)
    .padding(6);

    if shown.is_empty() {
        let msg = t(if total == 0 {
            "live_no_traffic"
        } else {
            "live_no_match"
        });
        return container(
            column![
                toolbar,
                header,
                container(ui_text(msg).size(sz(12))).padding(12)
            ]
            .spacing(4),
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

fn live_row(ev: &proto::ConnectionEvent) -> Element<'_, Message> {
    let conn = ev.connection.as_ref();
    let proc = ev.process.as_ref();

    let time = conn
        .map(|c| format::format_clock_ms(c.timestamp_unix_ms))
        .unwrap_or_else(|| "?".into());
    let proto_label = conn
        .map(|c| convert::protocol_label(c.protocol).to_string())
        .unwrap_or_default();
    let process_label = proc
        .map(|p| format!("{} ({})", convert::process_display(p), p.pid))
        .unwrap_or_else(|| t("unknown").into());
    let dest = conn
        .map(|c| format::dest_display(&c.dst_host, &c.dst_ip, c.dst_port))
        .unwrap_or_else(|| "?".into());

    let action = proto::Action::try_from(ev.verdict).unwrap_or(proto::Action::Unspecified);
    let denied = matches!(action, proto::Action::Deny | proto::Action::Reject);
    let verdict_badge = container(ui_text(format::action_label(ev.verdict)).size(sz(10)))
        .padding([1, 6])
        .style(if action == proto::Action::Allow {
            theme::badge_ok
        } else if denied {
            theme::badge_err
        } else {
            theme::badge_warn
        });

    let copy: Element<'_, Message> = match conn {
        Some(c) => button(ui_text("⧉").size(sz(10)))
            .padding([0, 4])
            .on_press(Message::CopyText(format::dest_display(
                &c.dst_host,
                &c.dst_ip,
                c.dst_port,
            )))
            .style(theme::subtle_icon)
            .into(),
        None => Space::new().into(),
    };

    // Seeds the rule editor from this exact flow - the shortcut people
    // reach for most in opensnitch.
    let make_rule: Element<'_, Message> = match conn {
        Some(c) => button(ui_text(t("live_make_rule")).size(sz(10)))
            .padding([1, 6])
            .on_press(Message::MakeRuleFromEvent {
                exe: proc.map(|p| p.exe.clone()).unwrap_or_default(),
                src_ip: c.src_ip.clone(),
                dst_ip: c.dst_ip.clone(),
                dst_port: c.dst_port,
                protocol: c.protocol,
                direction: c.direction,
            })
            .style(theme::subtle_icon)
            .into(),
        None => Space::new().into(),
    };

    let inner = row![
        ui_text(time).size(sz(11)).width(theme::scaled(70.0)),
        ui_text(proto_label).size(sz(11)).width(theme::scaled(44.0)),
        ui_text(process_label)
            .size(sz(11))
            .width(theme::scaled(150.0)),
        row![ui_text(dest).size(sz(11)), copy]
            .spacing(4)
            .width(Length::Fill)
            .align_y(iced::Alignment::Center),
        container(verdict_badge).width(theme::scaled(64.0)),
        container(make_rule).width(theme::scaled(90.0)),
    ]
    .spacing(6)
    .padding(2)
    .align_y(iced::Alignment::Center);

    if denied {
        container(inner).style(theme::row_denied).into()
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
                dst_host_verified: false,
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
                package: String::new(),
                provenance: 0,
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
