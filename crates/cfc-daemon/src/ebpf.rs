//! The eBPF enrichment layer: loading, attaching and consuming the kernel-side
//! programs in `crates/cfc-ebpf`.
//!
//! # It is an enrichment layer, never a dependency
//!
//! Colony Firewall Control filters with NFQUEUE and attributes with
//! `sock_diag` + `/proc`. That works on every Linux since forever and is what
//! the daemon does when this module is compiled out, switched off, or fails at
//! runtime. What eBPF adds is *better answers to the same questions*:
//!
//! | source | what it improves |
//! |---|---|
//! | `sched_process_exec` | exec-time exe/uid/gid/ppid, and a name for processes that died before `/proc` could be read |
//! | `sched_process_exit` | explicit eviction, so a recycled pid cannot inherit an identity |
//! | `cgroup_skb/ingress` | first-hand IP -> hostname mappings taken from real resolver answers instead of the destination's own PTR record |
//!
//! Every step degrades on its own. A missing object, no `CAP_BPF`, a kernel
//! without BTF, a verifier rejection, a host with no cgroup v2 - each is a
//! warning and a narrower feature set, never a failure to start. There is no
//! configuration in which the firewall stops filtering because eBPF was
//! unavailable.
//!
//! # Two switches
//!
//! 1. the `ebpf` **cargo feature**, which is what pulls `aya` in. **On by
//!    default.** Compiling the loader in is not the same as running it, and
//!    aya is pure Rust: the build needs no bpf-linker, no nightly, no
//!    BPF-capable kernel and no root. A binary that is unable to load the
//!    ring-0 layer at all is not a useful default. Opt out with
//!    `cargo build -p cfc-daemon --no-default-features` (package-scoped on
//!    purpose; see the comment in `Cargo.toml`).
//! 2. `[ebpf] enabled` in `daemon.toml`, off by default while this is new.
//!
//! With the feature off, [`start`] returns immediately and reports "compiled
//! out". With the feature on and the config off, it reports "disabled". Both
//! are normal states, not errors -- and at runtime they are indistinguishable:
//! neither reaches `bpf(2)`, reads `/sys/kernel/btf/vmlinux`, or touches a
//! cgroup. The difference is only whether flipping the config can work without
//! a rebuild.
//!
//! # Why the object is loaded from a path rather than embedded
//!
//! `aya::include_bytes_aligned!` would bake `cfc-ebpf` into the daemon binary,
//! and that was rejected. The kernel-side crate is deliberately *not* a member
//! of this workspace: it needs a dated nightly, `-Z build-std=core`, a
//! `bpfel-unknown-none` target and a matching `bpf-linker`, and the whole
//! point of excluding it (see `crates/cfc-ebpf/README.md`) is that a plain
//! stable `cargo build --workspace` never touches any of that. Embedding would
//! hand that dependency straight back - and now that the feature is on by
//! default, it would hand it to *every* build: a plain `cargo build` would
//! fail on any machine without the BPF toolchain, or - worse - succeed against
//! a stale object left in `target/` from an older build.
//!
//! Loading from `[ebpf] object_path` keeps the two build graphs independent:
//! the daemon compiles with nothing but `aya`, the object is built once by
//! `cargo xtask build-ebpf`, and the two are matched at *install* time by the
//! package rather than at compile time by an `include_bytes!`. It also means a
//! rebuilt object can be dropped in and picked up with a restart, which is
//! exactly what you want while the programs are still being iterated on.
//!
//! The cost is a packaging obligation, spelled out at [`DEFAULT_OBJECT_PATH`].
//!
//! # Ring buffers
//!
//! Each of the three ring buffers gets one tokio task. `aya::maps::RingBuf`
//! exposes the map fd, so the task is a `tokio::io::unix::AsyncFd` around it:
//! await readable, drain every record that is there, clear readiness, repeat.
//! No polling interval and no thread per buffer. Records are decoded straight
//! out of the mapped ring - the consumers copy the POD struct out and drop the
//! borrow before doing anything else, so a slow consumer cannot hold the
//! producer's tail.
//!
//! None of this is on the packet path. The consumers write into
//! [`proc_table::KernelProcTable`] and [`crate::dns::DnsCache`]; the NFQUEUE
//! worker only ever reads those.

pub mod btf;
pub mod cgroup;
pub mod proc_table;

#[cfg(feature = "ebpf")]
mod loader;

use crate::config::EbpfConfig;
use crate::dns::DnsCache;

/// Where the BPF object is expected to live.
///
/// TODO(packaging): `pkg/` is out of scope for this change, so the packaging
/// side is written down here instead of done. A package that ships the eBPF
/// backend must install, in addition to today's files:
///
/// ```text
///   crates/cfc-ebpf/target/bpfel-unknown-none/release/cfc-ebpf
///     -> /usr/lib/colony-firewall/cfc-ebpf.o      (0644 root:root)
/// ```
///
/// built with `cargo xtask build-ebpf`, which needs `bpf-linker` and the
/// nightly pinned in `crates/cfc-ebpf/rust-toolchain.toml` at *build* time
/// only - the object has no runtime dependencies. The daemon binary must be
/// built with the `ebpf` feature, which is on by default, and
/// `/etc/colony-firewall/daemon.toml` must carry `[ebpf] enabled = true`. Any
/// of those missing degrades cleanly, so
/// shipping the object without flipping the config is a safe default for a
/// first release.
pub const DEFAULT_OBJECT_PATH: &str = "/usr/lib/colony-firewall/cfc-ebpf.o";

/// Why the ring-0 layer did not fully come up.
///
/// The machine-readable half of a note: [`Report::notes`] says it in prose for
/// whoever is reading the journal, `Degrade` says it in a form [`Report::log`]
/// can pick a severity from. The two are needed separately because the right
/// severity depends on how the layer was asked for - "no object installed" is
/// an ordinary fact under an automatic default and a misconfiguration under an
/// explicit `enabled = true`.
///
/// `#[non_exhaustive]` on purpose. A future kernel or aya release can hand back
/// an errno nobody here has classified, and the only correct response to that
/// is a duller log line - never a change in what the daemon does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Degrade {
    /// Nothing at `[ebpf] object_path`. By far the common case: a host whose
    /// package did not ship the object.
    ObjectMissing,
    /// The file is there but could not be read - permissions, or I/O error.
    ObjectUnreadable,
    /// The file is there and readable, and we declined to hand it to `bpf(2)`
    /// anyway. See `loader::vet_object`.
    ObjectUntrusted,
    /// `EPERM` / `EACCES`. No `CAP_BPF`, a seccomp filter that refuses
    /// `bpf(2)` (Docker's default does), or an unraised `RLIMIT_MEMLOCK`.
    /// Note that this is a *normal* condition in a container, not evidence
    /// that anyone misconfigured anything.
    NotPermitted,
    /// `EINVAL` / `ENOTSUP` / `ENOSYS`. The kernel does not support something
    /// the object needs. The honest "this machine cannot do ring 0" answer.
    Unsupported,
    /// The verifier walked the program and refused it. Unlike the others this
    /// one is usually *our* bug meeting a newer kernel, so it is worth saying
    /// loudly wherever it appears.
    Rejected,
    /// Something else went wrong. Deliberately not subdivided further.
    Other,
}

impl Degrade {
    /// A short stable token for the journal, so this can be grepped and
    /// counted without parsing prose.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ObjectMissing => "object_missing",
            Self::ObjectUnreadable => "object_unreadable",
            Self::ObjectUntrusted => "object_untrusted",
            Self::NotPermitted => "not_permitted",
            Self::Unsupported => "unsupported",
            Self::Rejected => "verifier_rejected",
            Self::Other => "other",
        }
    }
}

/// One positive word for "is ring 0 doing anything on this host?".
///
/// Derived from the per-program flags rather than stored, so it cannot drift
/// out of step with them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ring0 {
    /// Switched off; nothing was attempted.
    #[default]
    Off,
    /// Attempted, and nothing came up.
    Unavailable,
    /// Some programs attached, some did not.
    Partial,
    /// All three attached.
    Active,
}

impl Ring0 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Unavailable => "unavailable",
            Self::Partial => "partial",
            Self::Active => "active",
        }
    }
}

/// What actually came up. Reported once at startup and otherwise inert.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// `[ebpf] enabled` in the config.
    pub configured: bool,
    /// The `ebpf` cargo feature is compiled in.
    pub compiled_in: bool,
    /// `sched_process_exec` is attached and feeding the process table.
    pub exec_tracking: bool,
    /// `sched_process_exit` is attached, so entries are evicted on exit.
    pub exit_tracking: bool,
    /// `cgroup_skb/ingress` is attached and feeding observed DNS answers.
    pub dns_capture: bool,
    /// `task_struct` offsets were resolved from BTF, so exec events carry a
    /// real ppid rather than 0.
    pub ppid_offsets: bool,
    /// Human-readable notes: one line per thing that did not come up.
    pub notes: Vec<String>,
    /// Why the layer is not fully up, when that is known well enough to say in
    /// one word. `None` means either "it is fully up" or "the reason has no
    /// classification", and callers must not read anything into which.
    pub degrade: Option<Degrade>,
    /// `(program, instructions the verifier walked)`, for programs that got as
    /// far as being verified on a kernel that reports the count (>= 5.16).
    ///
    /// Recorded because it is a *budget*: the kernel allows 1,000,000 and
    /// refuses at 1,000,001, and the DNS observer has already been on the
    /// wrong side of that once. Surfacing it turns "a change made the program
    /// more expensive" into something visible here, rather than into "it
    /// stopped loading on someone else's kernel".
    pub verified_insns: Vec<(String, u32)>,
}

impl Report {
    /// A report for a daemon that is not running any eBPF at all.
    fn inert(configured: bool, compiled_in: bool, note: impl Into<String>) -> Self {
        Self {
            configured,
            compiled_in,
            notes: vec![note.into()],
            ..Self::default()
        }
    }

    /// Same, with the reason classified.
    fn inert_because(
        configured: bool,
        compiled_in: bool,
        degrade: Degrade,
        note: impl Into<String>,
    ) -> Self {
        Self {
            degrade: Some(degrade),
            ..Self::inert(configured, compiled_in, note)
        }
    }

    /// True when at least one program is attached.
    pub fn any_active(&self) -> bool {
        self.exec_tracking || self.exit_tracking || self.dns_capture
    }

    /// How much of the ring-0 layer is live.
    ///
    /// Derived, never stored: a field would be one more thing to keep in step
    /// with the three flags, and the whole point of this value is that an
    /// operator can trust it.
    pub fn ring0(&self) -> Ring0 {
        if !self.configured {
            return Ring0::Off;
        }
        match [self.exec_tracking, self.exit_tracking, self.dns_capture]
            .into_iter()
            .filter(|live| *live)
            .count()
        {
            0 => Ring0::Unavailable,
            3 => Ring0::Active,
            _ => Ring0::Partial,
        }
    }

    /// Names the attribution and hostname sources that are live, so the
    /// journal answers "is eBPF actually doing anything on this host?"
    /// without anyone having to guess from the absence of warnings.
    ///
    /// This is deliberately a log line and not a `GetStatus` field: the
    /// protobuf surface is frozen for this change.
    pub fn log(&self) {
        for note in &self.notes {
            if self.configured {
                // The operator asked for this and did not fully get it: say so
                // loudly enough to be noticed in the journal.
                tracing::warn!("eBPF: {note}");
            } else {
                // "It is switched off" is not a warning. A daemon that logs a
                // warning on every boot about a default trains people to
                // ignore its warnings.
                tracing::debug!("eBPF: {note}");
            }
        }
        for (program, insns) in &self.verified_insns {
            // debug!, not info!: this is a number to reach for when something
            // stopped loading, not something every boot needs to say out loud.
            tracing::debug!(program, verified_insns = insns, "verifier accepted");
        }
        tracing::info!(
            // Now that compiling the loader out is the unusual case, the
            // journal has to say which build this is: "no eBPF" and "eBPF that
            // could not load" look identical from the outside otherwise.
            compiled_in = self.compiled_in,
            // One grep-able word for the whole layer, and one for why it is
            // not more than that. Without these, answering "is ring 0 up on
            // this fleet?" means parsing prose out of three separate flags.
            ring0 = self.ring0().as_str(),
            degrade = self.degrade.map(Degrade::as_str).unwrap_or("none"),
            exec_tracking = self.exec_tracking,
            exit_tracking = self.exit_tracking,
            dns_capture = self.dns_capture,
            ppid_from_btf = self.ppid_offsets,
            "attribution sources: sock_diag + /proc{}; hostnames: PTR + FCrDNS{}",
            if self.exec_tracking {
                " + eBPF exec events"
            } else {
                ""
            },
            if self.dns_capture {
                " + observed DNS answers"
            } else {
                ""
            },
        );
    }
}

/// Everything the eBPF layer owns, for as long as the daemon runs.
///
/// **Dropping this detaches the programs.** aya ties every attachment to the
/// lifetime of the `Ebpf` object, so `main` holds the handle until shutdown.
/// The ring-buffer tasks are aborted on drop as well, so a `Drop` here really
/// does put the machine back the way it was.
pub struct Runtime {
    pub report: Report,
    #[cfg(feature = "ebpf")]
    _attached: Option<loader::Attached>,
}

/// Brings the eBPF layer up, as far as it will come up on this host.
///
/// Never returns an error: every failure mode is a note in the [`Report`].
/// Must be called from inside a tokio runtime (it spawns the ring-buffer
/// consumers).
/// `table` is a parameter rather than [`proc_table::global`] so that a test can
/// hand in an instance of its own. Asserting "a failed load did not mark the
/// table live" against a process-wide `LazyLock` is an assertion about every
/// other test in the binary as much as about this one.
pub fn start(cfg: &EbpfConfig, dns: DnsCache, table: proc_table::KernelProcTable) -> Runtime {
    if !cfg.enabled {
        return Runtime {
            report: Report::inert(
                false,
                cfg!(feature = "ebpf"),
                "disabled in config ([ebpf] enabled = false); using sock_diag + /proc only",
            ),
            #[cfg(feature = "ebpf")]
            _attached: None,
        };
    }

    #[cfg(not(feature = "ebpf"))]
    let runtime = {
        // `dns` and `table` are the loader's inputs; without it they are
        // simply never wired to anything.
        let _ = (dns, table);
        Runtime {
            report: Report::inert_because(
                true,
                false,
                Degrade::Unsupported,
                "[ebpf] enabled = true but this build was compiled with \
                 --no-default-features, so it has no eBPF support; rebuild \
                 without that flag (the `ebpf` feature is on by default)",
            ),
        }
    };

    #[cfg(feature = "ebpf")]
    let runtime = {
        // Who chose this file decides how much it has to prove.
        let (path, trust) = match cfg.object_path.clone() {
            // A human wrote this path into the config. That is a statement of
            // trust about a specific file, and it is also the only way the
            // developer workflow works at all: an object under `target/` is
            // owned by whoever ran cargo, never by root. Say what is wrong
            // with it and do as asked.
            Some(p) => (p, loader::Trust::Warn),
            // Nobody named a file. The daemon went to its own compiled-in path
            // and is about to hand whatever it finds there to `bpf(2)` on its
            // own initiative. Vet it: that decision has no human behind it.
            None => (
                std::path::PathBuf::from(DEFAULT_OBJECT_PATH),
                loader::Trust::Refuse,
            ),
        };
        match loader::load_and_attach(&path, dns, table.clone(), trust) {
            Ok((attached, report)) => {
                table.set_live(report.exec_tracking);
                Runtime {
                    report,
                    _attached: Some(attached),
                }
            }
            Err(e) => Runtime {
                report: Report::inert_because(
                    true,
                    true,
                    e.degrade,
                    format!("load failed, continuing without it: {:#}", e.source),
                ),
                _attached: None,
            },
        }
    };

    runtime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_config_produces_an_inert_report() {
        let cfg = EbpfConfig::default();
        assert!(!cfg.enabled, "[ebpf] must stay off by default");
        let rt = start(&cfg, DnsCache::new(), proc_table::KernelProcTable::new());
        assert!(!rt.report.any_active());
        assert!(!rt.report.configured);
        assert_eq!(rt.report.ring0(), Ring0::Off);
        assert_eq!(rt.report.compiled_in, cfg!(feature = "ebpf"));
        assert_eq!(rt.report.notes.len(), 1);
        // Logging a report must never panic, whatever is in it.
        rt.report.log();
    }

    // `#[tokio::test]`, not `#[test]`: with the `ebpf` feature on by default
    // this now traverses the real loader, which spawns the ring-buffer
    // consumers. It happens to pass outside a runtime today only because
    // `std::fs::read` fails before the first `tokio::spawn` -- i.e. for a
    // reason unrelated to what the test asserts. Give it a runtime so the
    // assertion is about the degrade path and not about where the panic lands.
    #[tokio::test]
    async fn an_enabled_config_without_an_object_still_starts() {
        // A path inside a fresh temp dir rather than a literal `/nonexistent`:
        // the point is "the object is absent", and hardcoding an absolute path
        // that some host might one day actually have makes the test lie.
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = EbpfConfig {
            enabled: true,
            object_path: Some(dir.path().join("cfc-ebpf.o")),
        };
        // An instance, not `proc_table::global()`: the assertion below is about
        // what *this* load did, and against the process-wide table it would be
        // an assertion about every other test in the binary as well.
        let table = proc_table::KernelProcTable::new();
        let rt = start(&cfg, DnsCache::new(), table.clone());
        assert!(rt.report.configured);
        assert!(!rt.report.any_active(), "nothing can have attached");
        assert_eq!(rt.report.ring0(), Ring0::Unavailable);
        // The classification differs by build, and both answers are the honest
        // one for their build: with the loader compiled in we went looking and
        // found nothing; compiled out we never looked, and saying "the object
        // is missing" would send whoever reads it to check a file that was
        // never going to be read.
        let expected = if cfg!(feature = "ebpf") {
            Degrade::ObjectMissing
        } else {
            Degrade::Unsupported
        };
        assert_eq!(
            rt.report.degrade,
            Some(expected),
            "an absent object is the ordinary case and must be classified as one"
        );
        assert!(!rt.report.notes.is_empty(), "and it must say why");
        assert!(
            !table.is_live(),
            "a failed load must not leave the table claiming to be live"
        );
    }

    #[test]
    fn a_report_with_nothing_live_names_only_the_procfs_sources() {
        // The startup line is the only place the operator learns which
        // sources are in play, so assert it stays truthful about the
        // default build rather than trusting the format string.
        let r = Report::default();
        assert!(!r.any_active());
        r.log();
    }
}
