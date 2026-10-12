//! The Preferences page: the kit's General, Appearance and Accessibility,
//! then Prompts and Notifications, then About (design/settings-page.md).
//! It replaces the content area; the sidebar stays.

use cfc_client::proto;
use colony_ui::widgets::{self, PreferencesView, ABOUT_CATEGORY, STANDARD_CATEGORIES};
use colony_ui::{Palette, Typography};
use iced::widget::{column, Space};
use iced::Element;
use std::collections::HashSet;
use std::path::Path;

use crate::app::Message;
use crate::format;
use crate::i18n::{t, t_fmt};
use crate::preferences::{Config, Language};
use crate::theme::ui_text;

/// This app's categories, between the three standard ones and About.
const OWN_CATEGORIES: [&str; 2] = ["preferences_cat_prompts", "preferences_cat_notifications"];

/// How many categories the list shows.
pub const CATEGORY_COUNT: usize = STANDARD_CATEGORIES.len() + OWN_CATEGORIES.len() + 1;

pub struct Args<'a> {
    pub config: &'a Config,
    pub category: usize,
    pub expanded: &'a HashSet<String>,
    pub status: Option<&'a proto::StatusResponse>,
    /// Sealed, and the installed `/usr/bin/colony-firewall`.
    pub official: bool,
    pub socket: &'a Path,
}

pub fn view(args: Args<'_>) -> Element<'_, Message> {
    let typo = Typography::current();
    let kit = PreferencesView::new(
        typo,
        &args.config.standard,
        args.expanded,
        Message::Preference,
        Message::ToggleSection,
    );
    let content: Element<'_, Message> = match args.category {
        0 => kit.general().push(language_section(&typo, &args)).into(),
        1 => kit.appearance().into(),
        2 => kit.accessibility().into(),
        3 => prompts(&typo, &args),
        4 => notifications(&typo, &args),
        _ => about(&typo, &args),
    };
    let labels = STANDARD_CATEGORIES
        .iter()
        .chain(&OWN_CATEGORIES)
        .chain([&ABOUT_CATEGORY])
        .map(|key| t(key));
    widgets::preferences_page(
        &typo,
        widgets::category_list(&typo, labels, args.category, Message::PreferencesCategory),
        content,
        Message::TogglePreferences,
    )
}

/// A collapsible section: its description first, then its rows.
fn section<'a>(
    typo: &Typography,
    args: &Args<'_>,
    key: &'static str,
    title: &str,
    description: &str,
    rows: Vec<Element<'a, Message>>,
) -> Element<'a, Message> {
    widgets::collapsible_section(
        typo,
        title,
        args.expanded.contains(key),
        Message::ToggleSection(key),
        column![widgets::section_description(typo, description)]
            .extend(rows)
            .into(),
    )
}

fn language_section<'a>(typo: &Typography, args: &Args<'_>) -> Element<'a, Message> {
    let label = |language| {
        t(match language {
            Language::System => "preferences_language_system",
            Language::En => "preferences_language_en",
            Language::Fr => "preferences_language_fr",
        })
        .to_string()
    };
    let picker = widgets::dropdown(
        typo,
        Language::ALL.map(|language| (language, label(language))),
        &args.config.language,
        Message::SetLanguage,
    );
    section(
        typo,
        args,
        "language",
        t("preferences_section_language"),
        t("preferences_language_desc"),
        vec![widgets::setting_row(
            typo,
            t("preferences_language"),
            t("preferences_language_row_desc"),
            picker,
        )],
    )
}

fn prompts<'a>(typo: &Typography, args: &Args<'_>) -> Element<'a, Message> {
    let arrival = section(
        typo,
        args,
        "arrival",
        t("preferences_section_arrival"),
        t("preferences_arrival_desc"),
        vec![widgets::functional_toggle(
            typo,
            t("preferences_raise_on_prompt"),
            t("preferences_raise_on_prompt_desc"),
            args.config.raise_on_prompt,
            Message::ToggleRaiseOnPrompt,
        )],
    );

    // The daemon's policy, shown rather than edited: it lives in a file only
    // root may change.
    let (timeout, no_ui) = match args.status {
        Some(s) => (
            t_fmt(
                "preferences_timeout_value",
                &[
                    ("verdict", format::fallback_past(s.timeout_action)),
                    ("secs", &s.prompt_timeout_secs.to_string()),
                ],
            ),
            format::fallback_past(s.no_ui_action).to_string(),
        ),
        None => (
            t("preferences_not_connected").to_string(),
            t("preferences_not_connected").to_string(),
        ),
    };
    let unanswered = section(
        typo,
        args,
        "timeout",
        t("preferences_section_timeout"),
        t("preferences_timeout_desc"),
        vec![
            widgets::setting_row(
                typo,
                t("preferences_timeout"),
                t("preferences_timeout_row_desc"),
                value(typo, timeout),
            ),
            widgets::setting_row(
                typo,
                t("preferences_no_ui"),
                t("preferences_no_ui_row_desc"),
                value(typo, no_ui),
            ),
        ],
    );

    widgets::category_heading(
        typo,
        t("preferences_cat_prompts"),
        t("preferences_prompts_desc"),
    )
    .push(arrival)
    .push(unanswered)
    .into()
}

fn notifications<'a>(typo: &Typography, args: &Args<'_>) -> Element<'a, Message> {
    widgets::category_heading(
        typo,
        t("preferences_cat_notifications"),
        t("preferences_notifications_desc"),
    )
    .push(section(
        typo,
        args,
        "tray",
        t("preferences_section_tray"),
        t("preferences_tray_desc"),
        vec![widgets::functional_toggle(
            typo,
            t("preferences_tray_notifications"),
            t("preferences_tray_notifications_desc"),
            args.config.tray_notifications,
            Message::ToggleTrayNotifications,
        )],
    ))
    .into()
}

fn about<'a>(typo: &Typography, args: &Args<'_>) -> Element<'a, Message> {
    let daemon = match args.status {
        Some(s) => t_fmt("preferences_about_daemon_value", &[("version", &s.version)]),
        None => t("preferences_not_connected").to_string(),
    };
    let (changes, changes_desc) = if args.official {
        (
            "preferences_about_official",
            "preferences_about_official_desc",
        )
    } else {
        (
            "preferences_about_read_only",
            "preferences_about_read_only_desc",
        )
    };
    let file = Config::locate()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|e| e.to_string());
    let socket = args.socket.display().to_string();

    widgets::category_heading(typo, t(ABOUT_CATEGORY), t("preferences_about_desc"))
        .push(widgets::setting_row(
            typo,
            t("preferences_about_version"),
            t("preferences_about_version_desc"),
            value(typo, env!("CARGO_PKG_VERSION").to_string()),
        ))
        .push(widgets::setting_row(
            typo,
            t("preferences_about_daemon"),
            t("preferences_about_daemon_desc"),
            value(typo, daemon),
        ))
        .push(widgets::setting_row(
            typo,
            t("preferences_about_changes"),
            t(changes_desc),
            value(typo, t(changes).to_string()),
        ))
        .push(widgets::setting_row(
            typo,
            t("preferences_about_file"),
            &file,
            Space::new(),
        ))
        .push(widgets::setting_row(
            typo,
            t("preferences_about_socket"),
            &socket,
            Space::new(),
        ))
        .into()
}

/// A read-only value on the right of a row.
fn value<'a>(typo: &Typography, text: String) -> Element<'a, Message> {
    ui_text(text)
        .size(typo.sz(12))
        .color(Palette::TEXT_SECONDARY())
        .into()
}
