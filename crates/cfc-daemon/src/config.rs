//! Daemon configuration loaded from `/etc/colony-firewall/daemon.toml`.

use anyhow::Context;
use cfc_core::Action;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
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
        match std::fs::read_to_string(path) {
            Ok(txt) => toml::from_str(&txt).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}
