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
    /// What an inbound flow gets when no rule matches.
    ///
    /// Never `Allow`, and `resolve` refuses to make it one: the inbound chain
    /// exists so that nothing enters without having been authorised, and
    /// authorising is what a rule is. An allow-by-default inbound firewall is
    /// an accept-everything chain with extra steps.
    pub inbound_action: Action,
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
    pub inbound_action: Option<Action>,
    pub prompt_timeout_secs: Option<u32>,
}

impl DefaultPolicyToml {
    /// Overlays the explicitly-present fields onto `base` (the profile's
    /// policy, or the built-in balanced defaults).
    fn resolve(self, base: DefaultPolicy) -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: self.no_ui_action.unwrap_or(base.no_ui_action),
            timeout_action: self.timeout_action.unwrap_or(base.timeout_action),
            // Allow is not on the menu. A config that asks for it gets Deny and
            // a warning rather than a parse error, for the same reason the
            // whole of this file is forgiving: a rejected config exits before
            // READY=1, and against a fail-closed ruleset that is a machine with
            // no network. Refusing the *value* while keeping the daemon up is
            // the only shape that is safe in both directions.
            inbound_action: match self.inbound_action.unwrap_or(base.inbound_action) {
                Action::Allow => {
                    tracing::warn!(
                        "[default_policy] inbound_action = \"Allow\" is not \
                         supported: inbound is default-deny by design, and \
                         allowing by default would make the input chain \
                         decorative. Using Deny; write rules to authorise what \
                         should get in."
                    );
                    Action::Deny
                }
                other => other,
            },
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

    /// **No profile ever produces an Allow by itself.** Not on timeout, not
    /// when there is nobody to ask. Only a rule, or a person answering a
    /// prompt, can permit a connection.
    ///
    /// A timeout means the question *was* put to the user and went
    /// unanswered — walking away from a prompt must not be a way to grant
    /// access, or an attacker's best move is simply to connect while nobody
    /// is at the keyboard.
    ///
    /// `no_ui_action` is the other half of the same principle, and it used to
    /// break it: Relaxed and Balanced answered Allow when no client was
    /// connected, on the theory that a desktop booting before its session
    /// starts should keep working. That theory quietly gave away the whole
    /// product on any machine where a session never starts at all. A headless
    /// server, a VM, anything administered over SSH — `cfc-ui` and the tray
    /// never run there, so "there is nobody to ask" is not a window during
    /// boot, it is the permanent condition, and Allow meant those hosts had no
    /// outbound firewall whatsoever. Denying is the only answer consistent
    /// with what this program is for.
    ///
    /// What the profiles still differ on is how long to wait for an answer.
    ///
    /// The outbound table cannot lock an operator out of a remote machine: it
    /// hooks `output` on `ct state new` only, so an inbound SSH session's
    /// replies are `ct state established` and are never queued, and loopback is
    /// accepted outright. Rules can still be added with `cfc-cli` from that
    /// session. What it *does* mean on a fresh headless install is that
    /// outbound traffic — package updates, NTP, backups — is denied until
    /// rules exist for it.
    ///
    /// The *inbound* table can, which is why it is a separate opt-in unit with
    /// an `ExecStartPre` lockout guard rather than something an upgrade turns
    /// on. Once it is loaded, `inbound_action` below applies to every new
    /// inbound flow that no rule admits — including the next SSH connection.
    /// See `systemd/nftables-inbound.conf`.
    pub fn policy(self) -> DefaultPolicy {
        match self {
            // `Reject` on the relaxed profile: on a LAN an immediate refusal
            // is kinder than a timeout, and a desktop that is not trying to
            // hide answers faster. Still a refusal - the profile changes the
            // *manner*, never the answer.
            Profile::Relaxed => DefaultPolicy {
                no_ui_action: Action::Deny,
                timeout_action: Action::Deny,
                inbound_action: Action::Reject,
                prompt_timeout_secs: 60,
            },
            Profile::Balanced => DefaultPolicy {
                no_ui_action: Action::Deny,
                timeout_action: Action::Deny,
                inbound_action: Action::Deny,
                prompt_timeout_secs: 30,
            },
            // Strict drops rather than rejects: a refusal tells a scanner the
            // host is there.
            Profile::Strict => DefaultPolicy {
                no_ui_action: Action::Deny,
                timeout_action: Action::Deny,
                inbound_action: Action::Deny,
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
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EbpfConfig {
    /// Whether to bring the ring-0 layer up. See [`EbpfMode`].
    pub enabled: EbpfMode,
    /// Where the BPF object built by `cargo xtask build-ebpf` was installed.
    /// `None` means `crate::ebpf::DEFAULT_OBJECT_PATH`.
    pub object_path: Option<PathBuf>,
    /// Let a process-wide allow skip the queue.
    ///
    /// Off by default, and opt-in on purpose. What it buys: a process whose
    /// connections a rule allows outright, for the life of the rule, stops
    /// paying the NFQUEUE round trip - the kernel marks its sockets at
    /// `connect()`, nftables accepts the mark ahead of the queue, and no
    /// packet of that process reaches the daemon. What it costs: those
    /// decisions move off the one path every other guarantee here is built
    /// on. The mark is a value drawn at random at each start and matched
    /// exactly, so a process holding CAP_NET_RAW - enough for `SO_MARK`
    /// since 5.17 - cannot forge it without first learning it; and the flows
    /// it lets through are reported back over a ring buffer rather than seen
    /// on the packet path, so the counters and the live feed for them are only
    /// as timely as that consumer.
    ///
    /// Inert unless all of: enforcement pinned or inherited, exit tracking up
    /// and exact, the exec/exit links actually pinned, the cookie connect
    /// variants and *both* sendmsg hooks verified, the ring consumers started,
    /// and the nftables set declared by the snippet and holding this daemon's
    /// mark.
    ///
    /// The last two are the ones that fail in the field and the ones this list
    /// used to omit: 5.10 verifies `bpf_setsockopt` on connect hooks and
    /// refuses it on sendmsg ones, and the nft unit starts *after* the daemon,
    /// so a fresh boot reports "waiting for the nftables table" until it does.
    /// `cfc status` and the startup log line name whichever it was.
    pub fast_allow: bool,
    /// The `SO_MARK` value the fast path uses, when the machine needs a
    /// specific one.
    ///
    /// `None` - the default - draws one at random at each start, which is what
    /// keeps it from being a forgeable token. Set it only to resolve a
    /// collision: the mark space is shared with the whole machine, and a
    /// consumer that selects on a *mask* will match a random value with a
    /// probability its mask decides. See `ebpf::loader::pick_mark` for the
    /// selectors CFC already avoids, and `docs/TROUBLESHOOTING.md` for how to
    /// find the one it does not know about.
    ///
    /// Zero is refused: it is the mark of every socket nothing has marked.
    pub fast_allow_mark: Option<u32>,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enabled: EbpfMode::Auto,
            object_path: None,
            fast_allow: false,
            fast_allow_mark: None,
        }
    }
}

/// Whether the eBPF layer comes up, and how loudly it complains if it cannot.
///
/// Three states rather than two because "yes" and "try" want different
/// reporting from the same code path. An operator who wrote `enabled = true`
/// asked for ring 0 and should hear about every reason they did not get it; a
/// machine that is merely *capable* of ring 0 should bring it up and say so
/// once, without turning "this kernel cannot" into a warning on every boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EbpfMode {
    /// Bring it up if this machine can, and degrade quietly if not. The
    /// default, and the reason the layer is worth shipping: nothing about a
    /// capable host should require the operator to discover a config switch.
    #[default]
    Auto,
    /// Bring it up, and treat every shortfall as an error worth reporting.
    On,
    /// Do not attempt it at all.
    Off,
}

impl EbpfMode {
    /// Whether to try loading at all.
    pub fn wants_load(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Whether a human explicitly asked for this, as opposed to the daemon
    /// deciding for itself.
    pub fn is_forced(self) -> bool {
        matches!(self, Self::On)
    }
}

impl<'de> Deserialize<'de> for EbpfMode {
    /// Accepts `true` / `false` byte-for-byte as before, plus the strings.
    ///
    /// **An unrecognised string is not an error.** It warns and falls back to
    /// `Auto`, matching how `profile` already treats an unknown value, and for
    /// a reason specific to this daemon: a config parse error propagates out of
    /// `Config::load` and the process exits *before* `READY=1`. The nftables
    /// ruleset is `ct state new queue num 0` with no `bypass`, so a loaded
    /// table with no daemon behind it blackholes every new outbound connection
    /// on the machine. A typo in an enrichment layer's switch must not cost
    /// someone their network.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = EbpfMode;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(r#"true, false, or one of "auto", "on", "off""#)
            }

            fn visit_bool<E>(self, v: bool) -> Result<EbpfMode, E> {
                // Byte-for-byte backward compatible: an existing config saying
                // `enabled = true` keeps meaning "definitely, and tell me if
                // it did not work".
                Ok(if v { EbpfMode::On } else { EbpfMode::Off })
            }

            fn visit_str<E>(self, v: &str) -> Result<EbpfMode, E> {
                Ok(match v.trim().to_ascii_lowercase().as_str() {
                    "auto" => EbpfMode::Auto,
                    "on" | "true" | "yes" | "enabled" => EbpfMode::On,
                    "off" | "false" | "no" | "disabled" => EbpfMode::Off,
                    other => {
                        tracing::warn!(
                            value = other,
                            r#"unrecognised [ebpf] enabled; expected true, false, "auto", "on" or "off". Using "auto"."#
                        );
                        EbpfMode::Auto
                    }
                })
            }
        }
        d.deserialize_any(V)
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
        // Neither half of "we could not ask" may grant access: not a prompt
        // that expired, and not the absence of anyone to prompt. A shipped
        // default that allows is the whole product handed away on any host
        // without a graphical session.
        assert_eq!(cfg.default_policy.no_ui_action, Action::Deny);
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
        assert_eq!(cfg.ebpf.enabled, EbpfMode::Auto);
        assert_eq!(cfg.ebpf.object_path, None);
        assert_eq!(
            cfg.storage.path,
            PathBuf::from("/var/lib/colony-firewall/rules.db")
        );
    }

    /// The tri-state, including the compatibility the booleans still have.
    /// `Allow` is refused as a *value* but must not be refused as a *config*.
    /// Aborting startup would leave the fail-closed ruleset with nothing
    /// answering the queue - a machine with no network - so the daemon warns
    /// and uses Deny instead.
    #[test]
    fn inbound_action_allow_is_coerced_to_deny_without_failing_the_parse() {
        let cfg = Config::from_toml_str("[default_policy]\ninbound_action = \"Allow\"\n")
            .expect("a bad inbound_action must not abort startup");
        assert_eq!(cfg.default_policy.inbound_action, Action::Deny);
    }

    #[test]
    fn inbound_action_deny_and_reject_are_both_honoured() {
        let action = |v: &str| {
            Config::from_toml_str(&format!("[default_policy]\ninbound_action = \"{v}\"\n"))
                .unwrap()
                .default_policy
                .inbound_action
        };
        assert_eq!(action("Deny"), Action::Deny);
        assert_eq!(action("Reject"), Action::Reject);
    }

    /// No profile may ship an inbound default that admits traffic - the whole
    /// premise is that nothing enters unless a rule says so.
    #[test]
    fn no_profile_allows_inbound_by_default() {
        for p in [Profile::Relaxed, Profile::Balanced, Profile::Strict] {
            assert_ne!(
                p.policy().inbound_action,
                Action::Allow,
                "{p:?} would admit unauthorised inbound traffic"
            );
        }
    }

    #[test]
    fn ebpf_enabled_is_a_tri_state_defaulting_to_auto() {
        let mode = |toml: &str| Config::from_toml_str(toml).unwrap().ebpf.enabled;

        assert_eq!(mode(""), EbpfMode::Auto, "absent means auto");
        assert_eq!(
            mode("[ebpf]\n"),
            EbpfMode::Auto,
            "an empty section keeps the default"
        );
        assert_eq!(
            mode(
                r#"[ebpf]
enabled = "auto""#
            ),
            EbpfMode::Auto
        );

        // Existing configs keep working byte-for-byte. `true` means "I asked
        // for this", which is louder than auto, not merely equal to it.
        assert_eq!(mode("[ebpf]\nenabled = true\n"), EbpfMode::On);
        assert_eq!(mode("[ebpf]\nenabled = false\n"), EbpfMode::Off);
        assert_eq!(
            mode(
                r#"[ebpf]
enabled = "on""#
            ),
            EbpfMode::On
        );
        assert_eq!(
            mode(
                r#"[ebpf]
enabled = "off""#
            ),
            EbpfMode::Off
        );
        // Case and stray whitespace are a typo, not a different intent.
        assert_eq!(
            mode(
                r#"[ebpf]
enabled = " Auto ""#
            ),
            EbpfMode::Auto
        );

        let cfg = Config::from_toml_str(
            r#"
            [ebpf]
            enabled = true
            object_path = "/opt/cfc/cfc-ebpf.o"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.ebpf.enabled, EbpfMode::On);
        assert_eq!(
            cfg.ebpf.object_path,
            Some(PathBuf::from("/opt/cfc/cfc-ebpf.o"))
        );
    }

    /// A typo must not be able to take the machine's network away.
    ///
    /// A config parse error propagates out of `Config::load` and the daemon
    /// exits *before* `READY=1`. `systemd/nftables-snippet.conf` is
    /// `ct state new queue num 0` with **no** `bypass`, so a loaded table with
    /// no daemon behind it drops every new outbound connection. Refusing to
    /// start over a misspelled enrichment-layer switch would turn a one-letter
    /// mistake into an outage, so an unknown value warns and falls back -
    /// exactly as `profile` already does.
    #[test]
    fn an_unrecognised_ebpf_mode_falls_back_instead_of_failing_to_start() {
        let cfg = Config::from_toml_str("[ebpf]\nenabled = \"maybe\"\n")
            .expect("an unknown value must parse, not abort startup");
        assert_eq!(cfg.ebpf.enabled, EbpfMode::Auto);

        // Same for a value of an entirely wrong shape.
        let cfg = Config::from_toml_str("[ebpf]\nenabled = \"\"\n")
            .expect("an empty value must parse too");
        assert_eq!(cfg.ebpf.enabled, EbpfMode::Auto);
    }

    /// `daemon.toml.sample` documents the mark in hex, so hex has to parse.
    /// A sample that shows a spelling the parser rejects is worse than no
    /// sample: the operator only finds out when the daemon refuses to start.
    #[test]
    fn the_fast_allow_mark_parses_in_the_spelling_the_sample_documents() {
        let mark = |toml: &str| Config::from_toml_str(toml).unwrap().ebpf.fast_allow_mark;
        assert_eq!(mark(""), None, "absent means draw one");
        assert_eq!(
            mark("[ebpf]\nfast_allow_mark = 0x00033331\n"),
            Some(0x0003_3331)
        );
        assert_eq!(mark("[ebpf]\nfast_allow_mark = 209713\n"), Some(209_713));
        // The whole word must fit: the mark is a u32, and the top bit is as
        // legitimate a mark bit as any other.
        assert_eq!(
            mark("[ebpf]\nfast_allow_mark = 0xffffffff\n"),
            Some(u32::MAX)
        );
    }

    /// The fast path is opt-in: nothing short of `fast_allow = true` turns it
    /// on, and the layer's own eligibility checks still get the last word.
    #[test]
    fn ebpf_fast_allow_is_off_unless_asked_for() {
        let fast_allow = |toml: &str| Config::from_toml_str(toml).unwrap().ebpf.fast_allow;

        assert!(!fast_allow(""), "absent means off");
        assert!(
            !fast_allow("[ebpf]\n"),
            "an empty section keeps the default"
        );
        assert!(!fast_allow("[ebpf]\nfast_allow = false\n"));
        assert!(fast_allow("[ebpf]\nfast_allow = true\n"));
        // Parsed independently of `enabled`: the switch says what was asked
        // for, and the layer decides whether it can honour it.
        assert!(fast_allow("[ebpf]\nenabled = false\nfast_allow = true\n"));
    }

    #[test]
    fn ebpf_mode_helpers_match_their_names() {
        assert!(EbpfMode::Auto.wants_load() && !EbpfMode::Auto.is_forced());
        assert!(EbpfMode::On.wants_load() && EbpfMode::On.is_forced());
        assert!(!EbpfMode::Off.wants_load() && !EbpfMode::Off.is_forced());
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

    /// The invariant the whole product rests on, asserted over every profile
    /// rather than over the one that happens to be the default.
    ///
    /// A profile decides how *long* to wait for an answer. It must never
    /// decide to permit a connection on its own: only a stored rule or a
    /// person answering a prompt may do that. An explicit
    /// `[default_policy] no_ui_action = "Allow"` in an operator's config is a
    /// different matter and is still honoured - see
    /// `explicit_balanced_values_beat_strict_profile`.
    #[test]
    fn no_profile_ever_permits_by_itself() {
        for profile in [Profile::Relaxed, Profile::Balanced, Profile::Strict] {
            let p = profile.policy();
            assert_ne!(
                p.no_ui_action,
                Action::Allow,
                "{profile:?} would allow when no client is connected -- on a \
                 headless or SSH-only host that is the permanent state, not a \
                 boot-time window, so this is 'no outbound firewall at all'"
            );
            assert_ne!(
                p.timeout_action,
                Action::Allow,
                "{profile:?} would allow an unanswered prompt, making 'connect \
                 while nobody is at the keyboard' a winning move"
            );
        }
    }

    #[test]
    fn unrecognized_profile_falls_back_to_balanced_base() {
        let cfg = Config::from_toml_str(r#"profile = "paranoid""#).unwrap();
        assert_eq!(cfg.default_policy.no_ui_action, Action::Deny);
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
        assert_eq!(
            cfg.ebpf.enabled,
            EbpfMode::Auto,
            "the sample must leave the [ebpf] block commented out, so a shipped \
             config resolves to the automatic default"
        );
        assert!(
            !cfg.ebpf.fast_allow,
            "a shipped config must not take allows off the packet path"
        );
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
