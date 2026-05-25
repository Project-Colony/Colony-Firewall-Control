//! Daemon configuration loaded from `/etc/colony-firewall/daemon.toml`.

use anyhow::Context;
use cfc_core::Action;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Named preset to apply on top of explicit defaults.
    ///
    /// Recognized values: "relaxed" | "balanced" | "strict". Falls back to
    /// "balanced" when omitted. Explicit `default_policy` fields override
    /// preset values.
    #[serde(default)]
    pub profile: Option<String>,

    #[serde(default)]
    pub default_policy: DefaultPolicy,

    #[serde(default)]
    pub nfqueue: NfqConfig,

    #[serde(default)]
    pub storage: StorageConfig,
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
        Self {
            no_ui_action: Action::Allow,
            timeout_action: Action::Allow,
            prompt_timeout_secs: 15,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NfqConfig {
    pub queue_num: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Config {
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        let mut cfg: Self = match std::fs::read_to_string(path) {
            Ok(txt) => {
                toml::from_str(&txt).with_context(|| format!("parsing {}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };

        // Apply profile if specified, but let explicit default_policy fields
        // override profile values when both are present. We can't tell here
        // which fields were explicit vs serde-defaulted - design choice: the
        // [profile] key sets the baseline, [default_policy] overrides
        // wholesale when present. So if both exist, treat default_policy as
        // authoritative; if only profile exists, derive policy from it.
        if let Some(p) = cfg.profile.as_ref().and_then(|s| Profile::parse(s)) {
            // Heuristic: if default_policy is at literal struct default, the
            // user only set the profile - so apply it. If they wrote a
            // default_policy block (deviating from defaults), respect that.
            let dp = cfg.default_policy;
            let is_default = matches!(dp.no_ui_action, Action::Allow)
                && matches!(dp.timeout_action, Action::Allow)
                && dp.prompt_timeout_secs == 15;
            if is_default {
                cfg.default_policy = p.policy();
            }
        }

        Ok(cfg)
    }
}
