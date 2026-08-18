//! Daemon counters, the health signals that come with them, and two
//! breakdowns computed from the live feed this session.

use cfc_client::{convert, proto};
use iced::widget::{column, container, row, scrollable, text, Space};
use iced::{Element, Length};

use crate::session_stats::{Counts, SessionStats};
use crate::{format, Message};

const TOP_N: usize = 10;

pub fn view<'a>(
    status: Option<&'a proto::StatusResponse>,
    session: &'a SessionStats,
    now_ms: i64,
) -> Element<'a, Message> {
    let Some(s) = status else {
        return container(text("Waiting for daemon status...").size(13))
            .padding(16)
            .into();
    };

    let mut blocks: Vec<Element<'a, Message>> = Vec::new();

    // A running daemon that never sees a packet is the failure mode that
    // looks exactly like everything being fine.
    if !s.enforcing {
        blocks.push(banner(
            crate::theme::banner_err,
            "⚠ not enforcing",
            "No packets seen - is the nftables/iptables NFQUEUE rule loaded? (Also expected under --dry-run.)",
        ));
    }
    if s.skipped_rules > 0 {
        blocks.push(banner(
            crate::theme::banner_warn,
            "⚠ rules skipped",
            &format!(
                "{} rule row(s) on disk could not be loaded and are NOT being enforced.",
                s.skipped_rules
            ),
        ));
    }
    if s.paused {
        blocks.push(banner(
            crate::theme::banner_warn,
            "⚠ paused",
            &format!(
                "Everything is being accepted without consulting rules - {}.",
                format::format_resume_in(s.resume_at_unix_ms, now_ms)
            ),
        ));
    }

    blocks.push(
        row![
            stat_card("daemon version", s.version.clone()),
            stat_card("uptime", humanize_seconds(s.uptime_seconds)),
            stat_card("rules", s.rules_count.to_string()),
            stat_card("pending prompts", s.prompts_pending.to_string()),
            Space::new().width(Length::Fill),
        ]
        .spacing(10)
        .into(),
    );
    blocks.push(
        row![
            stat_card("connections seen", s.connections_today.to_string()),
            stat_card("allowed", s.connections_allowed.to_string()),
            stat_card("denied", s.connections_denied.to_string()),
            Space::new().width(Length::Fill),
        ]
        .spacing(10)
        .into(),
    );

    // The live policy, i.e. what happens when nobody answers.
    blocks.push(
        row![
            stat_small("prompt timeout", format!("{}s", s.prompt_timeout_secs)),
            stat_small(
                "on timeout",
                convert::action_label(s.timeout_action).to_string()
            ),
            stat_small(
                "with no UI",
                convert::action_label(s.no_ui_action).to_string()
            ),
            Space::new().width(Length::Fill),
        ]
        .spacing(10)
        .into(),
    );

    blocks.push(
        text(format!(
            "Breakdowns below cover this UI session only ({} events observed since the window opened).",
            session.events()
        ))
        .size(10)
        .into(),
    );
    blocks.push(
        row![
            top_table("Top apps (session)", session.top_apps(TOP_N), true),
            top_table(
                "Top destinations (session)",
                session.top_dests(TOP_N),
                false
            ),
        ]
        .spacing(10)
        .into(),
    );

    container(scrollable(column(blocks).spacing(12).padding(4)))
        .padding(16)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn banner<'a>(
    style: fn(&iced::Theme) -> iced::widget::container::Style,
    title: &'a str,
    body: &str,
) -> Element<'a, Message> {
    container(column![text(title).size(14), text(body.to_string()).size(11)].spacing(3))
        .padding(10)
        .width(Length::Fill)
        .style(style)
        .into()
}

fn stat_card<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    container(column![text(label).size(11), text(value).size(22)].spacing(4))
        .padding(12)
        .width(Length::Fixed(170.0))
        .style(crate::theme::panel)
        .into()
}

fn stat_small<'a>(label: &'a str, value: String) -> Element<'a, Message> {
    container(column![text(label).size(10), text(value).size(14)].spacing(2))
        .padding(8)
        .width(Length::Fixed(150.0))
        .style(crate::theme::panel)
        .into()
}

/// `shorten_path` trims executables to their basename; destinations are
/// already short enough to show whole.
fn top_table<'a>(
    title: &'a str,
    rows: Vec<(&'a str, Counts)>,
    shorten_path: bool,
) -> Element<'a, Message> {
    let mut body: Vec<Element<'a, Message>> = vec![row![
        text(title).size(13),
        Space::new().width(Length::Fill),
        text("conn / allow / deny").size(9),
    ]
    .align_y(iced::Alignment::Center)
    .into()];

    if rows.is_empty() {
        body.push(text("(nothing observed yet)").size(11).into());
    }

    for (key, counts) in rows {
        let label = if shorten_path { basename(key) } else { key };
        body.push(
            row![
                text(label.to_string()).size(11).width(Length::Fill),
                text(format!(
                    "{} / {} / {}",
                    counts.total, counts.allowed, counts.denied
                ))
                .size(11),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center)
            .into(),
        );
    }

    container(column(body).spacing(3))
        .padding(10)
        .width(Length::Fill)
        .style(crate::theme::panel)
        .into()
}

fn basename(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name,
        _ => path,
    }
}

fn humanize_seconds(s: u64) -> String {
    let d = s / 86400;
    let h = (s % 86400) / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {sec}s")
    } else {
        format!("{sec}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_picks_the_coarsest_useful_unit() {
        assert_eq!(humanize_seconds(0), "0s");
        assert_eq!(humanize_seconds(45), "45s");
        assert_eq!(humanize_seconds(3 * 60 + 7), "3m 7s");
        assert_eq!(humanize_seconds(2 * 3600 + 5 * 60), "2h 5m");
        assert_eq!(humanize_seconds(3 * 86400 + 4 * 3600), "3d 4h");
    }

    #[test]
    fn basename_handles_bare_and_trailing_slash_names() {
        assert_eq!(basename("/usr/bin/curl"), "curl");
        assert_eq!(basename("curl"), "curl");
        assert_eq!(basename("/usr/bin/"), "/usr/bin/");
        assert_eq!(basename("unknown"), "unknown");
    }
}
