use iced::widget::{column, container, text};
use iced::{Element, Length};

use crate::Message;

pub fn view<'a>() -> Element<'a, Message> {
    container(
        column![
            text("Stats").size(18),
            text("Counts: connections today, allowed, denied, rule hits. Phase 2 graphs.").size(13),
        ]
        .spacing(10),
    )
    .padding(16)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}
