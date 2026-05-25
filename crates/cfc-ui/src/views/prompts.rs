use iced::widget::{column, container, text};
use iced::{Element, Length};

use crate::Message;

pub fn view<'a>() -> Element<'a, Message> {
    container(
        column![
            text("Pending prompts").size(18),
            text("No daemon connection - prompts will appear here once cfc-daemon is reachable on /run/colony-firewall/cfc.sock.").size(13),
        ]
        .spacing(10),
    )
    .padding(16)
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}
