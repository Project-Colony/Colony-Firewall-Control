use cfc_client::{convert, proto};
use iced::widget::{column, container, row, scrollable, text};
use iced::{Element, Length};
use std::collections::VecDeque;

use crate::{LiveEntry, Message};

pub fn view<'a>(entries: &'a VecDeque<LiveEntry>) -> Element<'a, Message> {
    let header = row![
        text("time").size(11).width(Length::Fixed(80.0)),
        text("proto").size(11).width(Length::Fixed(50.0)),
        text("process").size(11).width(Length::Fixed(160.0)),
        text("dest").size(11).width(Length::Fill),
        text("verdict").size(11).width(Length::Fixed(70.0)),
    ]
    .spacing(6)
    .padding(6);

    if entries.is_empty() {
        return container(
            column![
                header,
                container(text("(no traffic observed yet)").size(12)).padding(12),
            ]
            .spacing(4),
        )
        .padding(8)
        .into();
    }

    let rows: Vec<Element<'a, Message>> = entries.iter().map(live_row).collect();

    container(
        column![
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
        .map(|c| {
            chrono::DateTime::from_timestamp_millis(c.timestamp_unix_ms)
                .map(|d| d.format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "?".into())
        })
        .unwrap_or_else(|| "?".into());
    let proto_label = conn
        .map(|c| convert::protocol_label(c.protocol).to_string())
        .unwrap_or_default();
    let process_label = proc
        .map(|p| format!("{} ({})", convert::process_display(p), p.pid))
        .unwrap_or_else(|| "unknown".into());
    let dest = conn
        .map(|c| {
            if c.dst_host.is_empty() {
                format!("{}:{}", c.dst_ip, c.dst_port)
            } else {
                format!("{} ({}:{})", c.dst_host, c.dst_ip, c.dst_port)
            }
        })
        .unwrap_or_else(|| "?".into());

    let _ = proto::Action::Unspecified;

    row![
        text(t).size(11).width(Length::Fixed(80.0)),
        text(proto_label).size(11).width(Length::Fixed(50.0)),
        text(process_label).size(11).width(Length::Fixed(160.0)),
        text(dest).size(11).width(Length::Fill),
        text(convert::action_label(ev.verdict))
            .size(11)
            .width(Length::Fixed(70.0)),
    ]
    .spacing(6)
    .padding(2)
    .into()
}
