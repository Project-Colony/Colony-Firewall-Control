//! The navigation sidebar: the app name, which opens Preferences, one entry
//! per tab and the keyboard shortcuts, in the Colony order
//! (design/navigation.md).

use colony_ui::{widgets, Typography};
use iced::widget::{button, column, container, row, Space};
use iced::{Alignment, Element, Length};

use crate::app::{Message, Tab};
use crate::i18n::t;
use crate::theme::{self, ui_text};

/// The sidebar's width at a text scale of 1.0; it grows with the scale so the
/// app name and the longest hint still fit on one line.
const SIDEBAR_WIDTH: f32 = 250.0;

/// The name in the identity button, as the desktop entry and the tray say it.
const APP_NAME: &str = "Colony Firewall";

/// `pending_prompts` is shown as a badge on the Prompts entry. While
/// Preferences are open no tab is marked, and the app name is.
pub fn view<'a>(tab: Tab, pending_prompts: usize, prefs_open: bool) -> Element<'a, Message> {
    let typo = Typography::current();
    let title_block = container(widgets::identity_button(
        &typo,
        APP_NAME,
        20,
        prefs_open,
        Message::TogglePreferences,
    ))
    .padding([16, 8]);
    // No tab reads as current while Preferences cover them.
    let tab = (!prefs_open).then_some(tab);

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
    current: Option<Tab>,
    badge: usize,
) -> Element<'a, Message> {
    let selected = current == Some(this);
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
