use cfc_client::proto;
use iced::widget::{column, container, row, text, Space};
use iced::{Element, Length};

use crate::Message;

pub fn view<'a>(status: Option<&'a proto::StatusResponse>) -> Element<'a, Message> {
    let Some(s) = status else {
        return container(text("Waiting for daemon status...").size(13))
            .padding(16)
            .into();
    };

    let uptime = humanize_seconds(s.uptime_seconds);

    let card = |label: &'a str, value: String| -> Element<'a, Message> {
        container(column![text(label).size(11), text(value).size(22),].spacing(4))
            .padding(12)
            .width(Length::Fixed(170.0))
            .into()
    };

    container(
        column![
            row![
                card("daemon version", s.version.clone()),
                card("uptime", uptime),
                card("rules", s.rules_count.to_string()),
                card("pending prompts", s.prompts_pending.to_string()),
                Space::new().width(Length::Fill),
            ]
            .spacing(10),
            row![
                card("connections seen", s.connections_today.to_string()),
                card("allowed", s.connections_allowed.to_string()),
                card("denied", s.connections_denied.to_string()),
                Space::new().width(Length::Fill),
            ]
            .spacing(10),
        ]
        .spacing(10),
    )
    .padding(16)
    .width(Length::Fill)
    .into()
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
