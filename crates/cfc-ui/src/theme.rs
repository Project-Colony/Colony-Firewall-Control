//! Typography and the container/button styles, all read from the active
//! Colony palette and text scale.
//!
//! Nothing here holds a colour or a size of its own: colours come from
//! [`colony_ui::Palette`] (the user's theme, accent and high contrast) and
//! sizes from [`colony_ui::sz`] (both text-size preferences), so a theme or
//! scale change redraws everything with no restart.

use colony_ui::{contrast_on, Palette};
use iced::widget::{button, container, progress_bar, text, Text};
use iced::{Background, Border, Color, Length, Shadow, Theme, Vector};

// --- Typography --------------------------------------------------------------

/// Text in the interface font at `sz(base)`. Every text in the window goes
/// through this (or [`ui_text_bold`]), so the dyslexia font and both text-size
/// preferences reach all of it.
pub fn ui_text<'a>(content: impl text::IntoFragment<'a>) -> Text<'a> {
    text(content).font(colony_ui::ui_font())
}

/// [`ui_text`] in the bold weight.
pub fn ui_text_bold<'a>(content: impl text::IntoFragment<'a>) -> Text<'a> {
    text(content).font(colony_ui::ui_font_bold())
}

/// The scaled size for a base size: shorthand for [`colony_ui::sz`].
pub fn sz(base: u16) -> f32 {
    colony_ui::sz(base)
}

/// A fixed width laid out at a text scale of 1.0, grown with the scale so the
/// text it holds still fits.
pub fn scaled(base: f32) -> Length {
    Length::Fixed(base * colony_ui::font_scale())
}

/// The iced theme for the active palette, so the widgets this app does not
/// style itself (text inputs, pick lists, scrollbars) follow it too.
pub fn iced_theme() -> Theme {
    Theme::custom(
        "Colony".to_string(),
        iced::theme::Palette {
            background: Palette::BG_PRIMARY(),
            text: Palette::TEXT_PRIMARY(),
            primary: Palette::ACCENT(),
            success: Palette::SUCCESS(),
            warning: Palette::WARNING(),
            danger: Palette::ERROR(),
        },
    )
}

/// A colour at `alpha`, for tints laid over the page.
fn tint(color: Color, alpha: f32) -> Color {
    Color { a: alpha, ..color }
}

// --- Container styles --------------------------------------------------------

/// Sidebar background - slightly darker than the page.
pub fn sidebar_bg(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Palette::BG_SIDEBAR())),
        text_color: Some(Palette::TEXT_PRIMARY()),
        ..Default::default()
    }
}

/// Main content card - bordered box on the page.
pub fn card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Palette::BG_PRIMARY())),
        border: Border {
            color: Palette::BORDER_SUBTLE(),
            width: 1.0,
            radius: 6.0.into(),
        },
        text_color: Some(Palette::TEXT_PRIMARY()),
        shadow: Shadow {
            color: tint(Palette::TEXT_PRIMARY(), 0.05),
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        snap: false,
    }
}

/// Header strip across the top of the main panel.
pub fn header_bar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Palette::BG_SIDEBAR())),
        text_color: Some(Palette::TEXT_PRIMARY()),
        ..Default::default()
    }
}

/// Footer strip with the status log.
pub fn footer_bar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Palette::BG_CARD_PRESSED())),
        text_color: Some(Palette::TEXT_SECONDARY()),
        ..Default::default()
    }
}

/// A pill filled with `fill`, its text in whichever ink reads on it.
fn badge(fill: Color) -> container::Style {
    container::Style {
        background: Some(Background::Color(fill)),
        border: Border {
            color: fill,
            width: 0.0,
            radius: 10.0.into(),
        },
        text_color: Some(contrast_on(fill)),
        ..Default::default()
    }
}

/// Status badge backgrounds.
pub fn badge_ok(_theme: &Theme) -> container::Style {
    badge(Palette::SUCCESS())
}

pub fn badge_warn(_theme: &Theme) -> container::Style {
    badge(Palette::WARNING())
}

pub fn badge_err(_theme: &Theme) -> container::Style {
    badge(Palette::ERROR())
}

/// Sub-panel inside the body card (top-N tables, prompt cards).
pub fn panel(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Palette::BG_CARD())),
        border: Border {
            color: Palette::BORDER_SUBTLE(),
            width: 1.0,
            radius: 5.0.into(),
        },
        text_color: Some(Palette::TEXT_PRIMARY()),
        ..Default::default()
    }
}

/// A full-width strip tinted with `color`.
fn banner(color: Color, alpha: f32) -> container::Style {
    container::Style {
        background: Some(Background::Color(tint(color, alpha))),
        border: Border {
            color,
            width: 1.0,
            radius: 5.0.into(),
        },
        text_color: Some(Palette::TEXT_PRIMARY()),
        ..Default::default()
    }
}

/// Full-width warning strip - "the daemon is running but not enforcing".
pub fn banner_warn(_theme: &Theme) -> container::Style {
    banner(Palette::WARNING(), 0.18)
}

/// Full-width danger strip - enforcement is silently not happening.
pub fn banner_err(_theme: &Theme) -> container::Style {
    banner(Palette::ERROR(), 0.14)
}

/// Live-feed row tint for a blocked flow, so denies read at a glance.
pub fn row_denied(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(tint(Palette::ERROR(), 0.07))),
        text_color: Some(Palette::TEXT_PRIMARY()),
        ..Default::default()
    }
}

/// A one-pixel rule between sections.
pub fn divider(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Palette::DIVIDER())),
        ..Default::default()
    }
}

/// Prompt countdown - an accent bar draining over the progress track.
pub fn countdown_bar(_theme: &Theme) -> progress_bar::Style {
    progress_bar::Style {
        background: Background::Color(Palette::BG_PROGRESS()),
        bar: Background::Color(Palette::ACCENT_PROGRESS()),
        border: Border {
            color: Palette::BORDER_SUBTLE(),
            width: 1.0,
            radius: 3.0.into(),
        },
    }
}

/// Same bar in the warning colour, for the last few seconds before the
/// daemon decides.
pub fn countdown_bar_urgent(_theme: &Theme) -> progress_bar::Style {
    progress_bar::Style {
        background: Background::Color(Palette::BG_PROGRESS()),
        bar: Background::Color(Palette::WARNING()),
        border: Border {
            color: Palette::WARNING(),
            width: 1.0,
            radius: 3.0.into(),
        },
    }
}

// --- Button styles -----------------------------------------------------------

/// A borderless button: no background until hovered, `ink` text.
fn flat(status: button::Status, ink: Color) -> button::Style {
    button::Style {
        background: match status {
            button::Status::Hovered => Some(Background::Color(Palette::BG_CARD_HOVER())),
            _ => None,
        },
        text_color: ink,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 3.0.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Clickable column header. Reads as a label until hovered.
pub fn column_header(_theme: &Theme, status: button::Status) -> button::Style {
    flat(status, Palette::TEXT_PRIMARY())
}

/// Borderless icon button (copy affordance, log dismiss).
pub fn subtle_icon(_theme: &Theme, status: button::Status) -> button::Style {
    flat(status, Palette::TEXT_MUTED())
}

/// Inline link ("Customize this rule before creating it"). Accent text on
/// no background, so it reads as a way out of the three big buttons rather
/// than as a fourth one.
pub fn link_button(_theme: &Theme, status: button::Status) -> button::Style {
    flat(status, Palette::ACCENT())
}

/// Subordinate action row ("Allow once"). Outlined rather than filled, so it
/// never competes with the three decisions above it.
pub fn action_secondary(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: match status {
            button::Status::Hovered => Some(Background::Color(Palette::BG_CARD_HOVER())),
            button::Status::Disabled => None,
            _ => Some(Background::Color(Palette::BG_PRIMARY())),
        },
        text_color: match status {
            button::Status::Disabled => Palette::TEXT_MUTED(),
            _ => Palette::TEXT_PRIMARY(),
        },
        border: Border {
            color: Palette::BORDER_SUBTLE(),
            width: 1.0,
            radius: 4.0.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The active theme is process-wide, and tests run in parallel.
    fn theme_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every style follows the active theme: none of them keeps a colour of
    /// its own, so switching the theme changes what each one draws.
    #[test]
    fn styles_follow_the_active_theme() {
        let _lock = theme_lock();
        let theme = Theme::Light;
        let draw = || {
            let c = |s: container::Style| {
                (
                    s.background.map(|b| format!("{b:?}")),
                    s.text_color,
                    s.border.color,
                )
            };
            let b = |s: button::Style| (s.background.map(|b| format!("{b:?}")), s.text_color);
            let p =
                |s: progress_bar::Style| (format!("{:?}", s.background), format!("{:?}", s.bar));
            (
                [
                    c(sidebar_bg(&theme)),
                    c(card(&theme)),
                    c(header_bar(&theme)),
                    c(footer_bar(&theme)),
                    c(badge_ok(&theme)),
                    c(badge_warn(&theme)),
                    c(badge_err(&theme)),
                    c(panel(&theme)),
                    c(banner_warn(&theme)),
                    c(banner_err(&theme)),
                    c(row_denied(&theme)),
                    c(divider(&theme)),
                ],
                [
                    b(column_header(&theme, button::Status::Hovered)),
                    b(subtle_icon(&theme, button::Status::Hovered)),
                    b(link_button(&theme, button::Status::Hovered)),
                    b(action_secondary(&theme, button::Status::Active)),
                ],
                [p(countdown_bar(&theme)), p(countdown_bar_urgent(&theme))],
            )
        };
        colony_ui::set_active_theme("parchment", "light");
        let parchment = draw();
        colony_ui::set_active_theme("gruvbox", "dark");
        let gruvbox = draw();
        colony_ui::set_active_theme("parchment", "light");

        for (i, (a, b)) in parchment.0.iter().zip(&gruvbox.0).enumerate() {
            assert_ne!(a, b, "container style #{i} ignores the theme");
        }
        for (i, (a, b)) in parchment.1.iter().zip(&gruvbox.1).enumerate() {
            assert_ne!(a, b, "button style #{i} ignores the theme");
        }
        for (i, (a, b)) in parchment.2.iter().zip(&gruvbox.2).enumerate() {
            assert_ne!(a, b, "progress style #{i} ignores the theme");
        }
    }

    /// Badge text is picked for its fill, not fixed to white: white on a
    /// light theme's amber is unreadable.
    #[test]
    fn badge_text_reads_on_its_fill() {
        let _lock = theme_lock();
        let theme = Theme::Light;
        for family in colony_ui::THEME_FAMILIES {
            for variant in family.variants {
                colony_ui::set_active_theme(family.key, variant.key);
                for style in [badge_ok(&theme), badge_warn(&theme), badge_err(&theme)] {
                    let Some(Background::Color(fill)) = style.background else {
                        panic!("a badge has a solid fill");
                    };
                    let ink = style.text_color.expect("a badge sets its text colour");
                    assert_eq!(ink, contrast_on(fill), "{}/{}", family.key, variant.key);
                }
            }
        }
        colony_ui::set_active_theme("parchment", "light");
    }
}
