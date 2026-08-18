//! Colony parchment theme + reusable container/button styles.
//!
//! Parchment background + burgundy accents, matching the Colony app
//! aesthetic (DNS-345 Colony Edition, Grape, SAM).

use iced::widget::{button, container, progress_bar};
use iced::{theme::Palette, Background, Border, Color, Shadow, Theme, Vector};

pub const PARCHMENT_BG: Color = Color::from_rgb(
    0xf2 as f32 / 255.0,
    0xe9 as f32 / 255.0,
    0xd0 as f32 / 255.0,
);
pub const PARCHMENT_DARK: Color = Color::from_rgb(
    0xe6 as f32 / 255.0,
    0xd9 as f32 / 255.0,
    0xb6 as f32 / 255.0,
);
pub const PARCHMENT_DARKER: Color = Color::from_rgb(
    0xd9 as f32 / 255.0,
    0xc6 as f32 / 255.0,
    0x9a as f32 / 255.0,
);
pub const PARCHMENT_TEXT: Color = Color::from_rgb(
    0x2b as f32 / 255.0,
    0x1d as f32 / 255.0,
    0x0e as f32 / 255.0,
);
pub const PARCHMENT_MUTED: Color = Color::from_rgb(
    0x6e as f32 / 255.0,
    0x5a as f32 / 255.0,
    0x3e as f32 / 255.0,
);
pub const BURGUNDY: Color = Color::from_rgb(
    0x80 as f32 / 255.0,
    0x1f as f32 / 255.0,
    0x2c as f32 / 255.0,
);
pub const BURGUNDY_DARK: Color = Color::from_rgb(
    0x5a as f32 / 255.0,
    0x12 as f32 / 255.0,
    0x1c as f32 / 255.0,
);
pub const INK_GREEN: Color = Color::from_rgb(
    0x3c as f32 / 255.0,
    0x5a as f32 / 255.0,
    0x3b as f32 / 255.0,
);
pub const AMBER: Color = Color::from_rgb(
    0xb8 as f32 / 255.0,
    0x73 as f32 / 255.0,
    0x33 as f32 / 255.0,
);
#[allow(dead_code)]
pub const FADED: Color = Color::from_rgb(
    0xb8 as f32 / 255.0,
    0x99 as f32 / 255.0,
    0x6a as f32 / 255.0,
);
pub const HAIRLINE: Color = Color::from_rgb(
    0xc2 as f32 / 255.0,
    0xaa as f32 / 255.0,
    0x7a as f32 / 255.0,
);

pub fn parchment() -> Theme {
    Theme::custom(
        "Colony Parchment".to_string(),
        Palette {
            background: PARCHMENT_BG,
            text: PARCHMENT_TEXT,
            primary: BURGUNDY,
            success: INK_GREEN,
            warning: AMBER,
            danger: BURGUNDY,
        },
    )
}

// --- Container styles --------------------------------------------------------

/// Sidebar background - slightly darker than the page.
pub fn sidebar_bg(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(PARCHMENT_DARK)),
        border: Border {
            color: HAIRLINE,
            width: 0.0,
            radius: 0.0.into(),
        },
        text_color: Some(PARCHMENT_TEXT),
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Main content card - bordered box on parchment.
pub fn card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(PARCHMENT_BG)),
        border: Border {
            color: HAIRLINE,
            width: 1.0,
            radius: 6.0.into(),
        },
        text_color: Some(PARCHMENT_TEXT),
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.05),
            offset: Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
        snap: false,
    }
}

/// Header strip across the top of the main panel.
pub fn header_bar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(PARCHMENT_DARK)),
        border: Border {
            color: HAIRLINE,
            width: 0.0,
            radius: 0.0.into(),
        },
        text_color: Some(PARCHMENT_TEXT),
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Footer strip with the last error.
pub fn footer_bar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(PARCHMENT_DARKER)),
        border: Border {
            color: HAIRLINE,
            width: 0.0,
            radius: 0.0.into(),
        },
        text_color: Some(BURGUNDY_DARK),
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Status badge backgrounds.
pub fn badge_ok(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(INK_GREEN)),
        border: Border {
            color: INK_GREEN,
            width: 0.0,
            radius: 10.0.into(),
        },
        text_color: Some(Color::WHITE),
        shadow: Shadow::default(),
        snap: false,
    }
}

pub fn badge_warn(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(AMBER)),
        border: Border {
            color: AMBER,
            width: 0.0,
            radius: 10.0.into(),
        },
        text_color: Some(Color::WHITE),
        shadow: Shadow::default(),
        snap: false,
    }
}

pub fn badge_err(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BURGUNDY)),
        border: Border {
            color: BURGUNDY,
            width: 0.0,
            radius: 10.0.into(),
        },
        text_color: Some(Color::WHITE),
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Sub-panel inside the body card (top-N tables, prompt cards).
pub fn panel(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(PARCHMENT_DARK)),
        border: Border {
            color: HAIRLINE,
            width: 1.0,
            radius: 5.0.into(),
        },
        text_color: Some(PARCHMENT_TEXT),
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Full-width warning strip - "the daemon is running but not enforcing".
pub fn banner_warn(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(
            0xb8 as f32 / 255.0,
            0x73 as f32 / 255.0,
            0x33 as f32 / 255.0,
            0.18,
        ))),
        border: Border {
            color: AMBER,
            width: 1.0,
            radius: 5.0.into(),
        },
        text_color: Some(PARCHMENT_TEXT),
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Full-width danger strip - enforcement is silently not happening.
pub fn banner_err(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(
            0x80 as f32 / 255.0,
            0x1f as f32 / 255.0,
            0x2c as f32 / 255.0,
            0.14,
        ))),
        border: Border {
            color: BURGUNDY,
            width: 1.0,
            radius: 5.0.into(),
        },
        text_color: Some(BURGUNDY_DARK),
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Live-feed row tint for a blocked flow, so denies read at a glance.
pub fn row_denied(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(
            0x80 as f32 / 255.0,
            0x1f as f32 / 255.0,
            0x2c as f32 / 255.0,
            0.07,
        ))),
        border: Border::default(),
        text_color: Some(PARCHMENT_TEXT),
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Prompt countdown - burgundy bar draining over parchment.
pub fn countdown_bar(_theme: &Theme) -> progress_bar::Style {
    progress_bar::Style {
        background: Background::Color(PARCHMENT_DARKER),
        bar: Background::Color(BURGUNDY),
        border: Border {
            color: HAIRLINE,
            width: 1.0,
            radius: 3.0.into(),
        },
    }
}

/// Same bar, amber, for the last few seconds before the daemon decides.
pub fn countdown_bar_urgent(_theme: &Theme) -> progress_bar::Style {
    progress_bar::Style {
        background: Background::Color(PARCHMENT_DARKER),
        bar: Background::Color(AMBER),
        border: Border {
            color: AMBER,
            width: 1.0,
            radius: 3.0.into(),
        },
    }
}

// --- Button styles -----------------------------------------------------------

/// Clickable column header. Reads as a label until hovered.
pub fn column_header(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: match status {
            button::Status::Hovered => Some(Background::Color(PARCHMENT_DARKER)),
            _ => None,
        },
        text_color: PARCHMENT_TEXT,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 3.0.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Borderless icon button (copy affordance, log dismiss).
pub fn subtle_icon(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: match status {
            button::Status::Hovered => Some(Background::Color(PARCHMENT_DARKER)),
            _ => None,
        },
        text_color: PARCHMENT_MUTED,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 3.0.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Inline link ("Customize this rule before creating it"). Burgundy text on
/// no background, so it reads as a way out of the three big buttons rather
/// than as a fourth one.
pub fn link_button(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: match status {
            button::Status::Hovered => Some(Background::Color(PARCHMENT_DARKER)),
            _ => None,
        },
        text_color: BURGUNDY,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 3.0.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Subordinate action row ("Allow once"). Outlined rather than filled, so it
/// never competes with the three decisions above it.
pub fn action_secondary(_theme: &Theme, status: button::Status) -> button::Style {
    button::Style {
        background: match status {
            button::Status::Hovered => Some(Background::Color(PARCHMENT_DARKER)),
            button::Status::Disabled => None,
            _ => Some(Background::Color(PARCHMENT_BG)),
        },
        text_color: match status {
            button::Status::Disabled => PARCHMENT_MUTED,
            _ => PARCHMENT_TEXT,
        },
        border: Border {
            color: HAIRLINE,
            width: 1.0,
            radius: 4.0.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Sidebar nav item, inactive. Hover lightens. No border, no bg by default.
pub fn nav_item_inactive(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Some(Background::Color(PARCHMENT_DARKER)),
        _ => None,
    };
    button::Style {
        background: bg,
        text_color: PARCHMENT_TEXT,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 0.0.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

/// Sidebar nav item, active. Burgundy left accent + slightly darker bg.
pub fn nav_item_active(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(Background::Color(PARCHMENT_DARKER)),
        text_color: BURGUNDY,
        border: Border {
            color: BURGUNDY,
            width: 0.0,
            radius: 0.0.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}
