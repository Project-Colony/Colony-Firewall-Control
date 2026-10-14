//! The two preferences the tray follows, read from the app's file when the
//! tray starts (`cfc_client::preferences_file`): the language, and whether it
//! shows prompts as notifications. The app writes them; the tray never does.

use serde_json::Value;
use tracing::warn;

use crate::i18n::{self, Locale};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrayPreferences {
    /// `None` follows the environment, like the app's "System language".
    pub locale: Option<Locale>,
    /// Off, the tray neither shows prompt bubbles nor subscribes to prompts,
    /// so with no app window open the daemon applies its policy at once.
    pub prompt_notifications: bool,
}

impl Default for TrayPreferences {
    fn default() -> Self {
        Self {
            locale: None,
            prompt_notifications: true,
        }
    }
}

impl TrayPreferences {
    /// Leniently, like the app: a value that is missing, unknown or of the
    /// wrong type keeps its default.
    pub fn from_json(text: &str) -> Self {
        let value = serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
        Self {
            locale: match value.get("language").and_then(Value::as_str) {
                Some("en") => Some(Locale::En),
                Some("fr") => Some(Locale::Fr),
                _ => None,
            },
            prompt_notifications: value
                .get("tray_notifications")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }
    }

    /// The saved preferences, or the defaults when the app never saved any.
    pub fn load() -> Self {
        let Some(path) = cfc_client::preferences_file() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::from_json(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                warn!("reading {}: {e}; using the defaults", path.display());
                Self::default()
            }
        }
    }

    pub fn apply_language(&self) {
        match self.locale {
            Some(locale) => i18n::set_locale(locale),
            None => i18n::init_from_env(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_app_file_is_read_leniently() {
        assert_eq!(TrayPreferences::from_json(""), TrayPreferences::default());
        assert_eq!(TrayPreferences::from_json("{}"), TrayPreferences::default());
        assert_eq!(
            TrayPreferences::from_json(
                r#"{"selected_theme": "gruvbox", "language": "fr", "tray_notifications": false}"#
            ),
            TrayPreferences {
                locale: Some(Locale::Fr),
                prompt_notifications: false,
            }
        );
        // "system", or anything unknown, follows the environment.
        let odd = TrayPreferences::from_json(r#"{"language": "system", "tray_notifications": 1}"#);
        assert_eq!(odd, TrayPreferences::default());
    }
}
