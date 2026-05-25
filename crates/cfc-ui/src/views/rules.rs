use cfc_client::{convert, proto};
use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Element, Length};

use crate::Message;

pub fn view<'a>(rules: &'a [proto::RuleInfo]) -> Element<'a, Message> {
    if rules.is_empty() {
        return container(
            column![
                text("No rules yet").size(18),
                text("Rules are created when you answer a prompt with \"Allow/Deny this app\".")
                    .size(12),
            ]
            .spacing(8),
        )
        .padding(16)
        .into();
    }

    let header = row![
        text("action").size(11).width(Length::Fixed(60.0)),
        text("duration").size(11).width(Length::Fixed(90.0)),
        text("summary").size(11).width(Length::Fill),
        text("hits").size(11).width(Length::Fixed(60.0)),
        text("").width(Length::Fixed(80.0)),
    ]
    .spacing(6)
    .padding(6);

    let rows: Vec<Element<'a, Message>> = rules.iter().map(rule_row).collect();

    container(
        column![
            header,
            scrollable(column(rows).spacing(2).padding([0, 6])).height(Length::Fill),
        ]
        .spacing(4),
    )
    .padding(8)
    .into()
}

fn rule_row(r: &proto::RuleInfo) -> Element<'_, Message> {
    let id = r.id.clone();
    row![
        text(convert::action_label(r.action))
            .size(12)
            .width(Length::Fixed(60.0)),
        text(convert::duration_label(r.duration))
            .size(12)
            .width(Length::Fixed(90.0)),
        text(convert::rule_summary(r)).size(12).width(Length::Fill),
        text(r.hit_count.to_string())
            .size(12)
            .width(Length::Fixed(60.0)),
        button(text("Delete").size(11))
            .padding([2, 8])
            .on_press(Message::DeleteRule(id))
            .style(iced::widget::button::danger),
        Space::new(),
    ]
    .spacing(6)
    .padding(4)
    .align_y(iced::Alignment::Center)
    .into()
}
