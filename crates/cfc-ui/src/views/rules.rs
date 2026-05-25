use iced::widget::{column, container, text};
use iced::{Element, Length};

use crate::Message;

pub fn view<'a>() -> Element<'a, Message> {
    container(
        column![
            text("Rules").size(18),
            text("Persistent rules will appear here. Phase 1 wires this to ListRules on the daemon.").size(13),
        ]
        .spacing(10),
    )
    .padding(16)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}
