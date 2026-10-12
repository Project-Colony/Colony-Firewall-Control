//! The interface strings, in English and French.
//!
//! English is canonical: a key is named after what its English string says,
//! and a new string is written in `en.rs` first. Both tables carry the same
//! keys, which `fr_and_en_have_identical_key_sets` enforces.
//!
//! The active locale is colony-ui's, so the shared Preferences labels (themes,
//! accents, categories) and this app's own strings always switch together.
//! Keys this app does not define fall through to that shared table.

mod en;
mod fr;

use colony_ui::i18n::{self as shared, Locale};
use std::collections::HashMap;
use std::sync::LazyLock;

type Table = HashMap<&'static str, &'static str>;

static EN: LazyLock<Table> = LazyLock::new(|| en::STRINGS.iter().copied().collect());
static FR: LazyLock<Table> = LazyLock::new(|| fr::STRINGS.iter().copied().collect());

/// Sets the interface language from the environment (`LC_ALL`, then
/// `LC_MESSAGES`, then `LANG`, as POSIX orders them). French when that names
/// French, English otherwise.
pub fn init_from_env() {
    shared::set_locale(Locale::from_tag(&env_language()));
}

fn env_language() -> String {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
        .unwrap_or_default()
}

/// The string for `key` in the active locale.
pub fn t(key: &str) -> &'static str {
    t_in(shared::locale(), key)
}

/// The string for `key` in `locale`: this app's table, then English, then
/// colony-ui's shared labels, then the key itself.
pub fn t_in(locale: Locale, key: &str) -> &'static str {
    let table: &Table = match locale {
        Locale::Fr => &FR,
        _ => &EN,
    };
    table
        .get(key)
        .or_else(|| EN.get(key))
        .copied()
        .unwrap_or_else(|| shared::t_in(locale, key))
}

/// [`t`] with each `{name}` replaced by its value.
pub fn t_fmt(key: &str, vars: &[(&str, &str)]) -> String {
    fill(t(key), vars)
}

/// Replaces each `{name}` of `template` in one pass, so a value is never
/// expanded again: a program named `{time}` must show as itself, not as the
/// countdown.
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
        // A key listed twice would silently shadow its first string.
        assert_eq!(en.len(), en::STRINGS.len(), "duplicate key in en.rs");
        assert_eq!(fr.len(), fr::STRINGS.len(), "duplicate key in fr.rs");
    }

    #[test]
    fn every_string_is_written() {
        for (key, value) in en::STRINGS.iter().chain(fr::STRINGS) {
            assert!(!value.trim().is_empty(), "{key} is empty");
            assert!(
                !value.contains(['\u{2013}', '\u{2014}']),
                "{key} has a dash"
            );
        }
    }

    #[test]
    fn placeholders_match_between_locales() {
        let names = |s: &str| -> BTreeSet<String> {
            s.split('{')
                .skip(1)
                .filter_map(|p| p.split_once('}').map(|(n, _)| n.to_string()))
                .collect()
        };
        for (key, en) in en::STRINGS {
            assert_eq!(
                names(en),
                names(t_in(Locale::Fr, key)),
                "{key}: the French string takes other values"
            );
        }
    }

    /// Every key the source names exists. `t` falls back to the key itself,
    /// so a typo would otherwise ship as `prompt_alow_once` on screen.
    ///
    /// Keys are often picked in a `match` and looked up later, so this reads
    /// every snake_case string literal whose first word starts a known key
    /// (`prompt_`, `rules_`, ...), not only the ones written inside `t(..)`.
    #[test]
    fn every_key_named_in_the_source_exists() {
        fn sources(dir: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if !path.ends_with("i18n") {
                        sources(&path, out);
                    }
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(std::fs::read_to_string(path).unwrap());
                }
            }
        }
        let is_key = |s: &str| {
            s.contains('_')
                && s.starts_with(|c: char| c.is_ascii_lowercase())
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        };
        let first_word = |s: &str| s.split('_').next().unwrap_or_default().to_string();
        let prefixes: BTreeSet<String> = EN
            .keys()
            .filter(|k| is_key(k))
            .map(|k| first_word(k))
            .collect();
        let mut files = Vec::new();
        sources(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        let mut checked = 0;
        for file in &files {
            for literal in file.split('"').skip(1).step_by(2) {
                if !is_key(literal) || !prefixes.contains(&first_word(literal)) {
                    continue;
                }
                assert!(
                    EN.contains_key(literal) || shared::t_in(Locale::En, literal) != literal,
                    "\"{literal}\" has no string"
                );
                checked += 1;
            }
        }
        assert!(checked > 150, "the scan found only {checked} keys");
    }

    #[test]
    fn french_is_french_and_unknown_keys_render_as_themselves() {
        assert_eq!(t_in(Locale::Fr, "tab_rules"), "Règles");
        assert_eq!(t_in(Locale::En, "tab_rules"), "Rules");
        // The shared labels resolve through the same call.
        assert_eq!(t_in(Locale::Fr, "settings_title"), "Préférences");
        assert_eq!(t_in(Locale::En, "no_such_key"), "no_such_key");
    }

    #[test]
    fn fill_substitutes_once_and_keeps_unknown_braces() {
        assert_eq!(fill("{a} then {b}", &[("a", "1"), ("b", "2")]), "1 then 2");
        // A value is never expanded again.
        assert_eq!(
            fill(
                "{program} in {time}",
                &[("program", "{time}"), ("time", "5s")]
            ),
            "{time} in 5s"
        );
        assert_eq!(fill("{missing} {", &[]), "{missing} {");
    }
}
