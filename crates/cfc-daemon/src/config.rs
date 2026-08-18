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
    pub profile: Option<String>,

    pub default_policy: DefaultPolicy,
    pub nfqueue: NfqConfig,
    pub storage: StorageConfig,
    pub pause: PauseConfig,
    pub events: EventsConfig,
    pub ipc: IpcConfig,
    pub provenance: ProvenanceConfig,
    pub ebpf: EbpfConfig,
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
    /// Permissive: allow when there is no UI to ask, and wait a full
    /// minute before denying an unanswered prompt.
    Relaxed,
    /// Default: allow when there is no UI to ask (so a machine still boots
    /// and updates), deny an unanswered prompt after 30s.
    Balanced,
    /// Lock down: deny when there is no UI to ask, and deny an unanswered
    /// prompt after 15s. Needs rules for every always-on service.
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

    /// Every profile denies on timeout.
    ///
    /// A timeout means the question *was* put to the user and went
    /// unanswered — walking away from a prompt must not be a way to grant
    /// access, or an attacker's best move is simply to connect while
    /// nobody is at the keyboard. What the profiles actually differ on is
    /// how long to wait, and what to do when there is nobody to ask at
    /// all (`no_ui_action`): a desktop that boots before its session
    /// starts should keep working, a locked-down box should not.
    pub fn policy(self) -> DefaultPolicy {
        match self {
            Profile::Relaxed => DefaultPolicy {
                no_ui_action: Action::Allow,
                timeout_action: Action::Deny,
                prompt_timeout_secs: 60,
            },
            Profile::Balanced => DefaultPolicy {
                no_ui_action: Action::Allow,
                timeout_action: Action::Deny,
                prompt_timeout_secs: 30,
            },
            Profile::Strict => DefaultPolicy {
                no_ui_action: Action::Deny,
                timeout_action: Action::Deny,
                prompt_timeout_secs: 15,
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

/// Access control for the gRPC control socket. See the module comment in
/// `ipc.rs` for the full trust model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IpcConfig {
    /// Unix group granted access to the control socket. After bind the
    /// daemon chowns the socket to `root:<group>` and chmods it 0660, so
    /// group membership *is* the access check.
    pub group: String,
    /// Require the socket to be group-gated before a non-root peer may
    /// call a mutating RPC. When the group cannot be resolved the socket
    /// stays root-only and non-root mutations are refused. Setting this to
    /// false lets any peer that manages to connect mutate rules — only do
    /// that if you gate the socket some other way (e.g. filesystem ACLs).
    pub require_group: bool,
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            group: "colony-firewall".to_string(),
            require_group: true,
        }
    }
}

/// Binary package provenance (see `crate::provenance`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default)]
pub struct ProvenanceConfig {
    /// Look every prompted/observed executable up in the system package
    /// database and report whether it still matches what was installed.
    pub enabled: bool,
}

impl Default for ProvenanceConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// The eBPF enrichment layer (see `crate::ebpf`).
///
/// Needs a **restart**: programs are loaded and attached once, at startup.
/// SIGHUP deliberately does not touch this - re-attaching a verifier-checked
/// program set while packets are flowing is not something a config reload
/// should be able to do by accident.
///
/// Unlike every other section here, the defaults are `Default`-derived rather
/// than hand-written: "off, no path" is exactly what `bool`/`Option` already
/// mean, and spelling it out invites the two from drifting apart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EbpfConfig {
    /// Load and attach the kernel-side programs. Off by default: this is new,
    /// it needs an installed BPF object and two extra capabilities, and
    /// everything it provides is an improvement on an answer the daemon can
    /// already produce without it.
    pub enabled: bool,
    /// Where the BPF object built by `cargo xtask build-ebpf` was installed.
    /// `None` means `crate::ebpf::DEFAULT_OBJECT_PATH`.
    pub object_path: Option<PathBuf>,
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
    ipc: IpcConfig,
    provenance: ProvenanceConfig,
    ebpf: EbpfConfig,
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
            ipc: self.ipc,
            provenance: self.provenance,
            ebpf: self.ebpf,
        }
    }
}

impl Config {
    /// Loads the config file, or the built-in defaults when it is absent.
    ///
    /// Also publishes the process-wide switches that are not carried by a
    /// value anyone threads through the call graph — currently just
    /// `[provenance] enabled`, consumed deep inside process resolution.
    /// Doing it here rather than in `main` is what makes those switches
    /// hot-reload: SIGHUP re-enters this function (see `reload_policy` in
    /// `main.rs`), so re-applying on every load is both the startup path
    /// and the reload path.
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        let cfg = match std::fs::read_to_string(path) {
            Ok(txt) => {
                Self::from_toml_str(&txt).with_context(|| format!("parsing {}", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        cfg.apply_runtime_switches();
        Ok(cfg)
    }

    /// Pushes config values that live in process-wide state into it. Kept
    /// separate from parsing so `from_toml_str` stays a pure function.
    pub fn apply_runtime_switches(&self) {
        crate::provenance::set_enabled(self.provenance.enabled);
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
        assert_eq!(cfg.default_policy.timeout_action, Action::Deny);
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 30);
        assert_eq!(cfg.nfqueue.queue_num, 0);
        assert_eq!(cfg.nfqueue.queue_max_len, 4096);
        assert!(!cfg.nfqueue.fail_open);
        assert_eq!(cfg.pause.default_secs, 600);
        assert_eq!(cfg.events.max_rows, 100_000);
        assert_eq!(cfg.ipc.group, "colony-firewall");
        assert!(cfg.ipc.require_group);
        assert!(cfg.provenance.enabled);
        assert!(!cfg.ebpf.enabled);
        assert_eq!(cfg.ebpf.object_path, None);
        assert_eq!(
            cfg.storage.path,
            PathBuf::from("/var/lib/colony-firewall/rules.db")
        );
    }

    #[test]
    fn ebpf_is_off_by_default_and_opt_in_only() {
        // This is a security-relevant default, not a style choice: turning it
        // on means loading kernel code and granting CAP_BPF/CAP_PERFMON.
        assert!(!Config::from_toml_str("").unwrap().ebpf.enabled);
        assert!(
            !Config::from_toml_str("[ebpf]\n").unwrap().ebpf.enabled,
            "an empty section keeps the default"
        );

        let cfg = Config::from_toml_str(
            r#"
            [ebpf]
            enabled = true
            object_path = "/opt/cfc/cfc-ebpf.o"
            "#,
        )
        .unwrap();
        assert!(cfg.ebpf.enabled);
        assert_eq!(
            cfg.ebpf.object_path,
            Some(PathBuf::from("/opt/cfc/cfc-ebpf.o"))
        );

        // Enabling without naming a path falls back to the packaged location.
        let cfg = Config::from_toml_str("[ebpf]\nenabled = true\n").unwrap();
        assert!(cfg.ebpf.enabled);
        assert_eq!(cfg.ebpf.object_path, None);
    }

    #[test]
    fn provenance_is_on_by_default_and_can_be_switched_off() {
        assert!(Config::from_toml_str("").unwrap().provenance.enabled);
        assert!(
            Config::from_toml_str("[provenance]\n")
                .unwrap()
                .provenance
                .enabled,
            "an empty section keeps the default"
        );
        assert!(
            !Config::from_toml_str("[provenance]\nenabled = false\n")
                .unwrap()
                .provenance
                .enabled
        );
    }

    #[test]
    fn missing_file_yields_defaults() {
        let cfg = Config::load_or_default(Path::new("/nonexistent/cfc/daemon.toml")).unwrap();
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 30);
        assert_eq!(cfg.pause.default_secs, 600);
    }

    #[test]
    fn profile_only_applies_profile_policy() {
        let cfg = Config::from_toml_str(r#"profile = "strict""#).unwrap();
        assert_eq!(cfg.default_policy.no_ui_action, Action::Deny);
        assert_eq!(cfg.default_policy.timeout_action, Action::Deny);
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 15);
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
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 30);
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

            [ipc]
            group = "wheel"
            require_group = false
            "#,
        )
        .unwrap();
        assert_eq!(cfg.nfqueue.queue_num, 3);
        assert_eq!(cfg.nfqueue.queue_max_len, 8192);
        assert!(cfg.nfqueue.fail_open);
        assert_eq!(cfg.pause.default_secs, 120);
        assert_eq!(cfg.events.max_rows, 5000);
        assert_eq!(cfg.ipc.group, "wheel");
        assert!(!cfg.ipc.require_group);

        // A partial [ipc] section keeps per-field defaults.
        let cfg = Config::from_toml_str("[ipc]\ngroup = \"wheel\"\n").unwrap();
        assert_eq!(cfg.ipc.group, "wheel");
        assert!(cfg.ipc.require_group);

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
        assert_eq!(cfg.default_policy.prompt_timeout_secs, 30);
        assert_eq!(cfg.nfqueue.queue_num, 0);
        assert_eq!(cfg.nfqueue.queue_max_len, 4096);
        assert!(!cfg.nfqueue.fail_open);
        assert_eq!(cfg.pause.default_secs, 600);
        assert_eq!(cfg.events.max_rows, 100_000);
        assert_eq!(cfg.ipc.group, "colony-firewall");
        assert!(cfg.ipc.require_group);
        assert!(cfg.provenance.enabled);
        assert!(!cfg.ebpf.enabled, "the sample must ship eBPF switched off");
        assert_eq!(
            cfg.storage.path,
            PathBuf::from("/var/lib/colony-firewall/rules.db")
        );
    }

    #[test]
    fn loading_publishes_the_provenance_switch() {
        // The sample documents [provenance] as reloading on SIGHUP, which
        // is only true because load_or_default (the function SIGHUP
        // re-enters via reload_policy) re-applies it every time. Assert the
        // wiring rather than trusting the comment.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.toml");

        std::fs::write(&path, "[provenance]\nenabled = false\n").unwrap();
        Config::load_or_default(&path).unwrap();
        assert!(!crate::provenance::enabled());

        std::fs::write(&path, "[provenance]\nenabled = true\n").unwrap();
        Config::load_or_default(&path).unwrap();
        assert!(crate::provenance::enabled());
    }
}
