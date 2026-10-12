//! The tray's strings, in English and French.
//!
//! English is canonical: a key is named after what its English string says,
//! and a new string is written in `en.rs` first. Both tables carry the same
//! keys, which `fr_and_en_have_identical_key_sets` enforces.
//!
//! The tray keeps its own locale instead of colony-ui's: colony-ui pulls in
//! iced, and a tray icon has no business linking a GUI toolkit. It reads the
//! same environment the app does, so both speak the same language.

mod en;
mod fr;

use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    En,
    Fr,
}

impl Locale {
    /// `fr`, `fr-FR`, `fr_FR.UTF-8` and the like are French; anything else
    /// is English. Same reading as colony-ui's `Locale::from_tag`.
    pub fn from_tag(tag: &str) -> Self {
        if tag
            .split(['-', '_', '.'])
            .next()
            .is_some_and(|l| l.eq_ignore_ascii_case("fr"))
        {
            Locale::Fr
        } else {
            Locale::En
        }
    }
}

/// The active locale. Process-wide in the tray; tests get one per thread, so
/// a test reading the French menu cannot flip an English assertion running
/// beside it.
#[cfg(not(test))]
static FRENCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
thread_local! {
    static FRENCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn set_locale(locale: Locale) {
    let french = locale == Locale::Fr;
    #[cfg(not(test))]
    FRENCH.store(french, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    FRENCH.with(|f| f.set(french));
}

pub fn locale() -> Locale {
    #[cfg(not(test))]
    let french = FRENCH.load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    let french = FRENCH.with(std::cell::Cell::get);
    if french {
        Locale::Fr
    } else {
        Locale::En
    }
}

/// Sets the tray's language from the environment (`LC_ALL`, then
/// `LC_MESSAGES`, then `LANG`, as POSIX orders them).
pub fn init_from_env() {
    let tag = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
        .unwrap_or_default();
    set_locale(Locale::from_tag(&tag));
}

type Table = HashMap<&'static str, &'static str>;

static EN: LazyLock<Table> = LazyLock::new(|| en::STRINGS.iter().copied().collect());
static FR: LazyLock<Table> = LazyLock::new(|| fr::STRINGS.iter().copied().collect());

/// The string for `key` in the active locale.
pub fn t(key: &'static str) -> &'static str {
    let table: &Table = match locale() {
        Locale::Fr => &FR,
        Locale::En => &EN,
    };
    table
        .get(key)
        .or_else(|| EN.get(key))
        .copied()
        .unwrap_or(key)
}

/// [`t`] with each `{name}` replaced by its value.
pub fn t_fmt(key: &'static str, vars: &[(&str, &str)]) -> String {
    fill(t(key), vars)
}

/// Replaces each `{name}` of `template` in one pass, so a value is never
/// expanded again: a program named `{reason}` must show as itself.
fn fill(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let value = after.find('}').and_then(|close| {
            vars.iter()
                .find(|(name, _)| *name == &after[..close])
                .map(|(_, value)| (close, value))
        });
        match value {
            Some((close, value)) => {
                out.push_str(value);
                rest = &after[close + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn keys(table: &[(&'static str, &'static str)]) -> BTreeSet<&'static str> {
        table.iter().map(|(k, _)| *k).collect()
    }

    #[test]
    fn fr_and_en_have_identical_key_sets() {
        let (en, fr) = (keys(en::STRINGS), keys(fr::STRINGS));
        assert_eq!(
            en.difference(&fr).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "missing in fr.rs"
        );
        assert_eq!(
            fr.difference(&en).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "missing in en.rs"
        );
        assert_eq!(en.len(), en::STRINGS.len(), "duplicate key in en.rs");
        assert_eq!(fr.len(), fr::STRINGS.len(), "duplicate key in fr.rs");
    }

    #[test]
    fn every_string_is_written_and_takes_the_same_values() {
        let names = |s: &str| -> BTreeSet<String> {
            s.split('{')
                .skip(1)
                .filter_map(|p| p.split_once('}').map(|(n, _)| n.to_string()))
                .collect()
        };
        for (key, value) in en::STRINGS.iter().chain(fr::STRINGS) {
            assert!(!value.trim().is_empty(), "{key} is empty");
            assert!(
                !value.contains(['\u{2013}', '\u{2014}']),
                "{key} has a dash"
            );
            // ksni reads an underscore in a menu label as an access key.
            assert!(!value.contains('_'), "{key} has an underscore");
        }
        for (key, en) in en::STRINGS {
            assert_eq!(names(en), names(FR[key]), "{key}: other values in French");
        }
    }

    /// Every key the source names exists. `t` falls back to the key itself,
    /// so a typo would otherwise ship as `tray_quti` in the menu. Keys picked
    /// in a `match` count too: this reads every snake_case string literal
    /// whose first word starts a known key.
    #[test]
    fn every_key_named_in_the_source_exists() {
        let is_key = |s: &str| {
            s.contains('_')
                && s.starts_with(|c: char| c.is_ascii_lowercase())
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        };
        let first_word = |s: &str| s.split('_').next().unwrap_or_default().to_string();
        let prefixes: BTreeSet<String> = EN.keys().map(|k| first_word(k)).collect();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut checked = 0;
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let file = std::fs::read_to_string(path).unwrap();
            for literal in file.split('"').skip(1).step_by(2) {
                if is_key(literal) && prefixes.contains(&first_word(literal)) {
                    assert!(EN.contains_key(literal), "\"{literal}\" has no string");
                    checked += 1;
                }
            }
        }
        assert!(checked > 30, "the scan found only {checked} keys");
    }

    #[test]
    fn the_locale_follows_the_tag() {
        for tag in ["fr", "fr_FR.UTF-8", "fr-CA", "FR"] {
            assert_eq!(Locale::from_tag(tag), Locale::Fr, "{tag}");
        }
        for tag in ["", "en_US.UTF-8", "C", "french"] {
            assert_eq!(Locale::from_tag(tag), Locale::En, "{tag}");
        }
        set_locale(Locale::Fr);
        assert_eq!(t("menu_quit"), "Quitter l'icône");
        assert_eq!(t("no_such_key"), "no_such_key");
        set_locale(Locale::En);
        assert_eq!(t("menu_quit"), "Quit tray");
    }

    #[test]
    fn fill_substitutes_once() {
        assert_eq!(
            fill("{name}: {reason}", &[("name", "{reason}"), ("reason", "x")]),
            "{reason}: x"
        );
    }
}
