//! The navigation sidebar: the app name, one entry per tab and the
//! keyboard shortcuts, in the Colony order (design/navigation.md).

use colony_ui::{widgets, Typography};
use iced::widget::{button, column, container, row, Space};
use iced::{Alignment, Element, Length};

use crate::app::{Message, Tab};
use crate::i18n::t;
use crate::theme::{self, ui_text, ui_text_bold};

/// The sidebar's width at a text scale of 1.0; it grows with the scale so the
/// longest hint still fits on one line.
const SIDEBAR_WIDTH: f32 = 220.0;

/// `pending_prompts` is shown as a badge on the Prompts entry.
pub fn view<'a>(tab: Tab, pending_prompts: usize) -> Element<'a, Message> {
    let typo = Typography::current();
    let title_block = column![
        ui_text_bold("Colony").size(typo.sz(20)),
        ui_text("Firewall Control").size(typo.sz(14)),
    ]
    .spacing(2)
    .padding([18, 16]);

    let nav = column![
        nav_entry(&typo, t("tab_prompts"), Tab::Prompts, tab, pending_prompts),
        nav_entry(&typo, t("tab_rules"), Tab::Rules, tab, 0),
        nav_entry(&typo, t("tab_live"), Tab::Live, tab, 0),
        nav_entry(&typo, t("tab_stats"), Tab::Stats, tab, 0),
    ]
    .spacing(2);

    let hints = column![
        widgets::nav_hint(&typo, t("hint_switch_tab")),
        widgets::nav_hint(&typo, t("hint_keys_title")),
        widgets::nav_hint(&typo, t("hint_allow_once")),
        widgets::nav_hint(&typo, t("hint_block_once")),
        widgets::nav_hint(&typo, t("hint_allow_program")),
        widgets::nav_hint(&typo, t("hint_block_program")),
        widgets::nav_hint(&typo, &format!("v{}", env!("CARGO_PKG_VERSION"))),
    ]
    .spacing(1);

    let inner = column![
        title_block,
        container(Space::new().height(Length::Fixed(1.0)))
            .width(Length::Fill)
            .style(theme::divider),
        column![widgets::nav_label(&typo, t("nav_views")), nav]
            .spacing(6)
            .padding([12, 8]),
        Space::new().height(Length::Fill),
        container(hints).padding([8, 16]),
    ]
    .height(Length::Fill);

    container(inner)
        .width(Length::Fixed(SIDEBAR_WIDTH * typo.scale))
        .height(Length::Fill)
        .style(theme::sidebar_bg)
        .into()
}

/// One tab entry: the kit's `nav_item`, plus the pending-prompt count when
/// there is one, styled the same way.
fn nav_entry<'a>(
    typo: &Typography,
    name: &'a str,
    this: Tab,
    current: Tab,
    badge: usize,
) -> Element<'a, Message> {
    let selected = this == current;
    if badge == 0 {
        return widgets::nav_item(typo, name, selected, Message::TabSelected(this));
    }
    button(
        row![
            ui_text(name).size(typo.sz(13)),
            Space::new().width(Length::Fill),
            container(ui_text(badge.to_string()).size(typo.sz(11)))
                .padding([1, 7])
                .style(theme::badge_err),
        ]
        .align_y(Alignment::Center),
    )
    .on_press(Message::TabSelected(this))
    .padding([8, 14])
    .width(Length::Fill)
    .style(widgets::selection_style(selected))
    .into()
}
