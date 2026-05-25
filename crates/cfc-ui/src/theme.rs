//! Colony parchment theme.
//!
//! Parchment background + burgundy accents, matching the Colony app
//! aesthetic (DNS-345 Colony Edition, Grape, SAM).

use iced::{theme::Palette, Color, Theme};

const PARCHMENT_BG: Color = Color::from_rgb(
    0xf2 as f32 / 255.0,
    0xe9 as f32 / 255.0,
    0xd0 as f32 / 255.0,
);
const PARCHMENT_TEXT: Color = Color::from_rgb(
    0x2b as f32 / 255.0,
    0x1d as f32 / 255.0,
    0x0e as f32 / 255.0,
);
const BURGUNDY: Color = Color::from_rgb(
    0x80 as f32 / 255.0,
    0x1f as f32 / 255.0,
    0x2c as f32 / 255.0,
);
const INK_GREEN: Color = Color::from_rgb(
    0x3c as f32 / 255.0,
    0x5a as f32 / 255.0,
    0x3b as f32 / 255.0,
);
const AMBER: Color = Color::from_rgb(
    0xb8 as f32 / 255.0,
    0x73 as f32 / 255.0,
    0x33 as f32 / 255.0,
);
const FADED: Color = Color::from_rgb(
    0xb8 as f32 / 255.0,
    0x99 as f32 / 255.0,
    0x6a as f32 / 255.0,
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

#[allow(dead_code)]
pub const ACCENT_FADED: Color = FADED;
