use iced::widget::{column, container, text};
use iced::{Element, Length};

use crate::Message;

pub fn view<'a>() -> Element<'a, Message> {
    container(
        column![
            text("Live connections").size(18),
            text("A scrolling feed of allowed/denied outbound flows will appear here.").size(13),
        ]
        .spacing(10),
    )
    .padding(16)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}
