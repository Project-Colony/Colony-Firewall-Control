//! The navigation sidebar: the app name, one entry per tab and the
//! keyboard shortcuts.

use iced::widget::{button, column, container, row, text, Space};
use iced::{Element, Length};

use crate::app::{Message, Tab};
use crate::theme;

/// `pending_prompts` is shown as a badge on the Prompts entry.
pub fn view<'a>(tab: Tab, pending_prompts: usize) -> Element<'a, Message> {
    let title_block = column![text("Colony").size(20), text("Firewall Control").size(14),]
        .spacing(2)
        .padding([18, 16]);

    let nav = column![
        nav_item("Prompts", Tab::Prompts, tab, pending_prompts),
        nav_item("Rules", Tab::Rules, tab, 0),
        nav_item("Live", Tab::Live, tab, 0),
        nav_item("Stats", Tab::Stats, tab, 0),
    ]
    .spacing(0);

    let hints = column![
        text("1-4  switch tab").size(9),
        text("Keys answer the top prompt:").size(9),
        text("A  allow once").size(9),
        text("D  block for now").size(9),
        text("Shift+A  always allow program").size(9),
        text("Shift+D  always block program").size(9),
    ]
    .spacing(1)
    .padding([6, 16]);

    let inner = column![
        title_block,
        divider(),
        nav,
        Space::new().height(Length::Fill),
        hints,
        container(text(format!("v{}", env!("CARGO_PKG_VERSION"))).size(10)).padding([6, 16]),
    ]
    .height(Length::Fill);

    container(inner)
        .width(Length::Fixed(190.0))
        .height(Length::Fill)
        .style(theme::sidebar_bg)
        .into()
}

fn nav_item<'a>(label: &'a str, this: Tab, current: Tab, badge: usize) -> Element<'a, Message> {
    let is_active = this == current;
    let label_text = text(label).size(14);
    let row_content: Element<'_, Message> = if badge > 0 {
        row![
            label_text,
            Space::new().width(Length::Fill),
            container(text(badge.to_string()).size(11))
                .padding([1, 7])
                .style(theme::badge_err),
        ]
        .align_y(iced::Alignment::Center)
        .into()
    } else {
        row![label_text].into()
    };

    let btn = button(row_content)
        .on_press(Message::TabSelected(this))
        .padding([10, 18])
        .width(Length::Fill);

    if is_active {
        btn.style(theme::nav_item_active).into()
    } else {
        btn.style(theme::nav_item_inactive).into()
    }
}

fn divider<'a>() -> Element<'a, Message> {
    container(Space::new().height(Length::Fixed(1.0)))
        .width(Length::Fill)
        .style(|_| iced::widget::container::Style {
            background: Some(iced::Background::Color(theme::HAIRLINE)),
            ..Default::default()
        })
        .into()
}
