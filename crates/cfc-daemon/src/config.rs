//! Daemon configuration loaded from `/etc/colony-firewall/daemon.toml`.
//!
//! Resolution model: the on-disk TOML is parsed into [`ConfigToml`], where
//! every `[default_policy]` field is an `Option` so "explicitly written" is
//! distinguishable from "absent". It is then resolved into [`Config`]:
//!
//! - `profile` (if set and recognized) provides the base policy; otherwise
//!   the built-in "balanced" defaults are the base.
//! - Any field explicitly present under `[default_policy]` overrides that
//!   single field of the base.
//! - Absent fields fall back to the base.
//!
//! This replaces the old heuristic that ignored the profile whenever the
//! `[default_policy]` block deviated from the literal struct defaults — a
//! user who wrote balanced-looking values plus `profile = "strict"` used to
//! silently get strict; now their explicit values win, field by field.

use anyhow::Context;
use cfc_core::Action;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Fully-resolved daemon configuration (profile already folded in).
#[derive(Debug, Clone)]
pub struct Config {
    /// Named preset that was requested, verbatim ("relaxed" | "balanced" |
    /// "strict"), kept for display/status purposes. Already applied to
    /// `default_policy` during resolution.
    // TODO(wave3): read by status reporting; remove the allow once wired.
    #[allow(dead_code)]
    pub profile: Option<String>,

    pub default_policy: DefaultPolicy,
    pub nfqueue: NfqConfig,
    pub storage: StorageConfig,
    // TODO(wave2/3): consumed by the pause and event-persistence wiring;
    // remove the allows once wired.
    #[allow(dead_code)]
    pub pause: PauseConfig,
    #[allow(dead_code)]
    pub events: EventsConfig,
}

impl Default for Config {
    fn default() -> Self {
        ConfigToml::default().resolve()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DefaultPolicy {
    /// What to do when no rule matches and no UI is connected.
    pub no_ui_action: Action,
    /// What to do if a prompt expires.
    pub timeout_action: Action,
    /// Prompt timeout, seconds.
    pub prompt_timeout_secs: u32,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Profile::Balanced.policy()
    }
}

/// TOML-facing shape of `[default_policy]`: per-field `Option` so an
/// explicitly-written field is distinguishable from an absent one.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DefaultPolicyToml {
    pub no_ui_action: Option<Action>,
    pub timeout_action: Option<Action>,
    pub prompt_timeout_secs: Option<u32>,
}

impl DefaultPolicyToml {
    /// Overlays the explicitly-present fields onto `base` (the profile's
    /// policy, or the built-in balanced defaults).
    fn resolve(self, base: DefaultPolicy) -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: self.no_ui_action.unwrap_or(base.no_ui_action),
            timeout_action: self.timeout_action.unwrap_or(base.timeout_action),
            prompt_timeout_secs: self.prompt_timeout_secs.unwrap_or(base.prompt_timeout_secs),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Permissive: allow when no UI and on timeout, long timeout.
    Relaxed,
    /// Default: allow on timeout (fail-open) but with a short window.
    Balanced,
    /// Lock down: deny when no UI and on timeout (fail-closed), short window.
    Strict,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "relaxed" => Some(Profile::Relaxed),
            "balanced" => Some(Profile::Balanced),
            "strict" => Some(Profile::Strict),
            _ => None,
        }
    }

    pub fn policy(self) -> DefaultPolicy {
        match self {
            Profile::Relaxed => DefaultPolicy {
                no_ui_action: Action::Allow,
                timeout_action: Action::Allow,
                prompt_timeout_secs: 60,
            },
            Profile::Balanced => DefaultPolicy {
                no_ui_action: Action::Allow,
                timeout_action: Action::Allow,
                prompt_timeout_secs: 15,
            },
            Profile::Strict => DefaultPolicy {
                no_ui_action: Action::Deny,
                timeout_action: Action::Deny,
                prompt_timeout_secs: 10,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NfqConfig {
    /// NFQUEUE number; must match the nftables/iptables rule.
    pub queue_num: u16,
    /// Kernel queue length before packets overflow.
    pub queue_max_len: u32,
    /// What happens to packets when the queue overflows or the daemon cannot
    /// keep up: `false` drops them (fail-closed), `true` lets them through.
    pub fail_open: bool,
}

impl Default for NfqConfig {
    fn default() -> Self {
        Self {
            queue_num: 0,
            queue_max_len: 4096,
            fail_open: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/colony-firewall/rules.db"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default)]
pub struct PauseConfig {
    /// Default duration for `cfc pause` when no explicit duration is given,
    /// in seconds. (A hard cap is enforced by the pause implementation.)
    pub default_secs: u64,
}

impl Default for PauseConfig {
    fn default() -> Self {
        Self { default_secs: 600 }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsConfig {
    /// Maximum number of verdict events retained in the database; the oldest
    /// beyond this cap are pruned.
    pub max_rows: u32,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self { max_rows: 100_000 }
    }
}

/// Raw on-disk shape. Only `[default_policy]` needs Option-per-field (it
/// interacts with `profile`); the other sections carry their own defaults.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct ConfigToml {
    profile: Option<String>,
    default_policy: DefaultPolicyToml,
    nfqueue: NfqConfig,
    storage: StorageConfig,
    pause: PauseConfig,
    events: EventsConfig,
}

impl ConfigToml {
    fn resolve(self) -> Config {
        let base = match self.profile.as_deref() {
            Some(s) => match Profile::parse(s) {
                Some(p) => p.policy(),
                None => {
                    tracing::warn!(
                        profile = s,
                        "unrecognized profile, falling back to \"balanced\" base"
                    );
                    Profile::Balanced.policy()
                }
            },
            None => Profile::Balanced.policy(),
        };
        Config {
            default_policy: self.default_policy.resolve(base),
            profile: self.profile,
            nfqueue: self.nfqueue,
            storage: self.storage,
            pause: self.pause,
            events: self.events,
        }
    }
}

impl Config {
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(txt) => {
                Self::from_toml_str(&txt).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Parses and resolves a TOML document (see the module docs for the
    /// profile / `[default_policy]` precedence rules).
    pub fn from_toml_str(txt: &str) -> anyhow::Result<Self> {
        let raw: ConfigToml = toml::from_str(txt)?;
        Ok(raw.resolve())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_yields_balanced_defaults() {
        let cfg = Config::from_toml_str("").unwrap();
        assert_eq!(cfg.default_policy.no_ui_action, Action::Allow);
        assert_eq!(cfg.default_policy.timeout_action, Action::Allow);
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 15);
        assert_eq!(cfg.nfqueue.queue_num, 0);
        assert_eq!(cfg.nfqueue.queue_max_len, 4096);
        assert!(!cfg.nfqueue.fail_open);
        assert_eq!(cfg.pause.default_secs, 600);
        assert_eq!(cfg.events.max_rows, 100_000);
        assert_eq!(
            cfg.storage.path,
            PathBuf::from("/var/lib/colony-firewall/rules.db")
        );
    }

    #[test]
    fn missing_file_yields_defaults() {
        let cfg = Config::load_or_default(Path::new("/nonexistent/cfc/daemon.toml")).unwrap();
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 15);
        assert_eq!(cfg.pause.default_secs, 600);
    }

    #[test]
    fn profile_only_applies_profile_policy() {
        let cfg = Config::from_toml_str(r#"profile = "strict""#).unwrap();
        assert_eq!(cfg.default_policy.no_ui_action, Action::Deny);
        assert_eq!(cfg.default_policy.timeout_action, Action::Deny);
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 10);
        assert_eq!(cfg.profile.as_deref(), Some("strict"));
    }

    #[test]
    fn profile_plus_partial_override_mixes_per_field() {
        let cfg = Config::from_toml_str(
            r#"
            profile = "strict"

            [default_policy]
            prompt_timeout_secs = 30
            "#,
        )
        .unwrap();
        // Explicit field wins; absent fields come from the profile.
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 30);
        assert_eq!(cfg.default_policy.no_ui_action, Action::Deny);
        assert_eq!(cfg.default_policy.timeout_action, Action::Deny);
    }

    #[test]
    fn explicit_block_without_profile_uses_explicit_values() {
        let cfg = Config::from_toml_str(
            r#"
            [default_policy]
            no_ui_action = "Deny"
            timeout_action = "Reject"
            prompt_timeout_secs = 42
            "#,
        )
        .unwrap();
        assert_eq!(cfg.default_policy.no_ui_action, Action::Deny);
        assert_eq!(cfg.default_policy.timeout_action, Action::Reject);
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 42);
    }

    #[test]
    fn explicit_balanced_values_beat_strict_profile() {
        // The old heuristic couldn't tell "explicitly written balanced
        // values" from "absent" and silently applied the strict profile.
        // Explicit fields must win.
        let cfg = Config::from_toml_str(
            r#"
            profile = "strict"

            [default_policy]
            no_ui_action = "Allow"
            timeout_action = "Allow"
            prompt_timeout_secs = 15
            "#,
        )
        .unwrap();
        assert_eq!(cfg.default_policy.no_ui_action, Action::Allow);
        assert_eq!(cfg.default_policy.timeout_action, Action::Allow);
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 15);
    }

    #[test]
    fn unrecognized_profile_falls_back_to_balanced_base() {
        let cfg = Config::from_toml_str(r#"profile = "paranoid""#).unwrap();
        assert_eq!(cfg.default_policy.no_ui_action, Action::Allow);
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 15);
    }

    #[test]
    fn new_sections_parse_and_default() {
        let cfg = Config::from_toml_str(
            r#"
            [nfqueue]
            queue_num = 3
            queue_max_len = 8192
            fail_open = true

            [pause]
            default_secs = 120

            [events]
            max_rows = 5000
            "#,
        )
        .unwrap();
        assert_eq!(cfg.nfqueue.queue_num, 3);
        assert_eq!(cfg.nfqueue.queue_max_len, 8192);
        assert!(cfg.nfqueue.fail_open);
        assert_eq!(cfg.pause.default_secs, 120);
        assert_eq!(cfg.events.max_rows, 5000);

        // Partial sections keep per-field defaults.
        let cfg = Config::from_toml_str("[nfqueue]\nqueue_num = 7\n").unwrap();
        assert_eq!(cfg.nfqueue.queue_num, 7);
        assert_eq!(cfg.nfqueue.queue_max_len, 4096);
        assert!(!cfg.nfqueue.fail_open);
    }

    #[test]
    fn sample_config_file_parses() {
        // Permanently parse-checks the shipped sample.
        let sample = include_str!("../../../systemd/daemon.toml.sample");
        let cfg = Config::from_toml_str(sample).unwrap();
        assert_eq!(cfg.profile.as_deref(), Some("balanced"));
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 15);
        assert_eq!(cfg.nfqueue.queue_num, 0);
        assert_eq!(cfg.nfqueue.queue_max_len, 4096);
        assert!(!cfg.nfqueue.fail_open);
        assert_eq!(cfg.pause.default_secs, 600);
        assert_eq!(cfg.events.max_rows, 100_000);
        assert_eq!(
            cfg.storage.path,
            PathBuf::from("/var/lib/colony-firewall/rules.db")
        );
    }
}
