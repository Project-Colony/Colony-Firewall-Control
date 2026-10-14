//! What the user chose in Preferences: the shared Colony settings (theme,
//! accent, sizes, accessibility) and this app's own, in one JSON file under
//! `Colony/Colony Firewall Control/`.
//!
//! Saved whole, atomically, on every change: there is no Save button.
//! Read leniently: a value that is missing, unknown or of the wrong type
//! falls back to its default and the rest of the file is kept.

use colony_ui::i18n::{set_locale, Locale};
use colony_ui::preferences::StandardPreferences;
use serde::{Deserialize as _, Serialize};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};

use crate::i18n;

/// The directory the file lives in, under `Colony/`. The tray reads the same
/// file through `cfc_client::preferences_file`.
pub const PROGRAM: &str = cfc_client::PREFERENCES_PROGRAM;
const FILE: &str = "preferences.json";

/// Parchment is this app's identity, and stays the theme until the user picks
/// another.
const THEME: (&str, &str) = ("parchment", "light");

/// The interface language. `System` follows `LC_ALL`, `LC_MESSAGES`, `LANG`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    System,
    En,
    Fr,
}

impl Language {
    pub const ALL: [Language; 3] = [Language::System, Language::En, Language::Fr];

    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("en") => Language::En,
            Some("fr") => Language::Fr,
            _ => Language::System,
        }
    }

    /// Switches the interface to this language. Views read their strings on
    /// every frame, so the whole window follows on the next one.
    pub fn apply(self) {
        match self {
            Language::System => i18n::init_from_env(),
            Language::En => set_locale(Locale::En),
            Language::Fr => set_locale(Locale::Fr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Config {
    #[serde(flatten)]
    pub standard: StandardPreferences,
    pub language: Language,
    /// Show the Prompts tab and raise the window for the first prompt of a
    /// burst. Off, only the sidebar badge counts it.
    pub raise_on_prompt: bool,
    /// Whether the tray shows prompts as notifications it can answer. The
    /// tray reads it when it starts.
    pub tray_notifications: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            standard: StandardPreferences {
                selected_theme: THEME.0.into(),
                selected_variant: THEME.1.into(),
                ..StandardPreferences::default()
            },
            language: Language::System,
            raise_on_prompt: true,
            tray_notifications: true,
        }
    }
}

impl Config {
    /// Parses a saved file. Never fails: see the module comment.
    pub fn from_json(text: &str) -> Self {
        let defaults = Self::default();
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            return defaults;
        };
        let mut standard =
            StandardPreferences::deserialize(&value).unwrap_or_else(|_| defaults.standard.clone());
        // colony-ui keeps any theme name; one this build does not ship (or a
        // missing one) is this app's default, not colony-ui's.
        let shipped = colony_ui::theme::family(&standard.selected_theme)
            .and_then(|family| family.variant(&standard.selected_variant))
            .is_some();
        if !shipped || value.get("selected_theme").is_none() {
            standard.selected_theme = defaults.standard.selected_theme.clone();
            standard.selected_variant = defaults.standard.selected_variant.clone();
        }
        let flag =
            |key: &str, default: bool| value.get(key).and_then(Value::as_bool).unwrap_or(default);
        Self {
            standard,
            language: Language::parse(value.get("language").and_then(Value::as_str)),
            raise_on_prompt: flag("raise_on_prompt", defaults.raise_on_prompt),
            tray_notifications: flag("tray_notifications", defaults.tray_notifications),
        }
    }

    /// Where the file is, without creating anything: for display.
    pub fn locate() -> io::Result<PathBuf> {
        Ok(colony_ui::paths::locate::config_dir(PROGRAM)?.join(FILE))
    }

    /// The saved preferences, or the defaults when there are none yet.
    pub fn load() -> Self {
        let read = Self::locate().and_then(std::fs::read_to_string);
        match read {
            Ok(text) => Self::from_json(&text),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                tracing::warn!("reading the preferences: {e}; using the defaults");
                Self::default()
            }
        }
    }

    /// Puts every preference into effect: theme, accent, sizes, fonts, motion
    /// and the language.
    pub fn apply(&self) {
        self.standard.apply();
        self.language.apply();
    }

    /// Saves to `path` (normally [`Config::locate`]), creating its directory.
    pub fn save_to(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_atomically(path, &serde_json::to_vec_pretty(self)?)
    }
}

/// Writes `bytes` to a sibling temporary file, then renames it over `path`,
/// so a crash mid-write leaves the old file whole rather than half of a new
/// one.
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use colony_ui::{FontSize, TextSize};

    #[test]
    fn a_saved_config_reads_back_the_same() {
        let mut config = Config::default();
        config.standard.selected_theme = "gruvbox".into();
        config.standard.selected_variant = "dark".into();
        config.standard.selected_accent = Some("violet".into());
        config.standard.font_size = FontSize::Large;
        config.standard.text_size_a11y = TextSize::XLarge;
        config.standard.reduce_motion = true;
        config.language = Language::Fr;
        config.raise_on_prompt = false;
        config.tray_notifications = false;

        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(Config::from_json(&json), config);
        // Flat, under the field names every Colony program writes.
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["selected_theme"], "gruvbox");
        assert_eq!(value["language"], "fr");
    }

    #[test]
    fn a_broken_file_falls_back_without_losing_the_rest() {
        assert_eq!(Config::from_json("not json {"), Config::default());
        assert_eq!(Config::from_json("{}"), Config::default());

        let config = Config::from_json(
            r#"{"selected_theme": "no-such-theme", "selected_variant": "dark",
                "high_contrast": true, "language": 42,
                "raise_on_prompt": "yes", "tray_notifications": false}"#,
        );
        let defaults = Config::default();
        assert_eq!(config.standard.selected_theme, "parchment");
        assert_eq!(config.standard.selected_variant, "light");
        assert!(config.standard.high_contrast, "the valid value is kept");
        assert_eq!(config.language, Language::System);
        assert_eq!(config.raise_on_prompt, defaults.raise_on_prompt);
        assert!(!config.tray_notifications);
    }

    #[test]
    fn the_file_lives_under_colony_and_where_the_tray_reads_it() {
        let path = Config::locate().unwrap();
        assert!(
            path.ends_with("Colony/Colony Firewall Control/preferences.json"),
            "{path:?}"
        );
        assert_eq!(cfc_client::preferences_file(), Some(path));
    }

    #[test]
    fn saving_creates_the_directory_and_replaces_the_file_whole() {
        let dir = std::env::temp_dir().join(format!("cfc-ui-prefs-{}", std::process::id()));
        let path = dir.join("Colony").join(FILE);
        let config = Config {
            language: Language::En,
            ..Config::default()
        };
        config.save_to(&path).unwrap();
        std::fs::write(&path, b"old").unwrap();
        config.save_to(&path).unwrap();

        assert_eq!(
            Config::from_json(&std::fs::read_to_string(&path).unwrap()),
            config
        );
        assert!(
            !path.with_extension("json.tmp").exists(),
            "no temporary file is left"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
