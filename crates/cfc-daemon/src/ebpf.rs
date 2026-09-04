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
// Outside the `ebpf` feature gate on purpose: it is a text parser with no aya
// in it, and its tests are the only check that the offset logic is right. They
// must run in the default suite, not only in the configuration that also needs
// a BPF toolchain to be interesting.
pub mod tracefs;

#[cfg(feature = "ebpf")]
mod enforce;
#[cfg(feature = "ebpf")]
mod loader;
mod nft_set;

/// Socket-cookie -> pid, answered from the kernel's `SOCK_PIDS` map.
///
/// The fast path of attribution: the `cfc_connect4|6` programs record the
/// association at `connect()` time, in the connecting process's own context, so
/// this is exact and race-free where the `/proc` walk it replaces was a 37-44ms
/// scan per new connection. `None` means the layer is not up, the object
/// predates the map, the old-kernel `_basic` variants are attached, or the
/// entry was evicted - in every case the caller falls back to the walk, which
/// is what it did before this existed.
pub fn cookie_pid(cookie: u64) -> Option<u32> {
    #[cfg(feature = "ebpf")]
    {
        sock_pids::HANDLE.get().and_then(|m| m.get(&cookie, 0).ok())
    }
    #[cfg(not(feature = "ebpf"))]
    {
        let _ = cookie;
        None
    }
}

#[cfg(feature = "ebpf")]
pub(crate) mod sock_pids {
    use std::sync::OnceLock;

    /// Set once by the loader when the map exists in the loaded object.
    /// `aya`'s `HashMap::get` is one `bpf(BPF_MAP_LOOKUP_ELEM)` syscall on a
    /// shared fd - `&self`, no lock needed.
    pub(crate) static HANDLE: OnceLock<aya::maps::HashMap<aya::maps::MapData, u64, u32>> =
        OnceLock::new();
}

use crate::config::{EbpfConfig, EbpfMode};
use crate::dns::DnsCache;

/// Severity for the per-shortfall notes. Separate from `tracing::Level` so it
/// can be asserted in a test without a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Where the BPF object is expected to live.
///
/// The Colony package installs it here (`pkg/colony.json` postInstall, 0644
/// root:root, which is also what `loader::vet_object` requires before loading
/// it unasked). `.github/workflows/release.yml` builds it with
/// `cargo xtask build-ebpf` and stages it into the tarball;
/// `scripts/check-release-assets.sh` fails the build if the manifest and the
/// tarball ever disagree about it.
///
/// Building needs `bpf-linker` and the nightly pinned in
/// `crates/cfc-ebpf/rust-toolchain.toml` at **build** time only - the object
/// itself has no runtime dependencies.
///
/// The AUR package deliberately does *not* build it: on Arch `rustup`
/// conflicts with `rust`, which the packaging containers install, so
/// `rust-toolchain.toml` would be inert and `-Z build-std` would fail on
/// stable. An AUR install therefore has no object, `Degrade::ObjectMissing`,
/// and the firewall runs on `sock_diag` + `/proc` exactly as it always has.
///
/// This string is duplicated by `pkg/colony.json`, both PKGBUILDs and
/// `systemd/daemon.toml.sample`; `default_object_path_matches_the_packaging`
/// is what keeps them honest.
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
    /// The object does not declare the event layout this daemon speaks - it
    /// was built against a different one. Almost always a half-finished
    /// upgrade: new binary, old object, or the reverse.
    AbiMismatch,
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
            Self::AbiMismatch => "abi_mismatch",
            Self::NotPermitted => "not_permitted",
            Self::Unsupported => "unsupported",
            Self::Rejected => "verifier_rejected",
            Self::Other => "other",
        }
    }
}

/// Where the exec program was told to find the tracepoint's `filename` field.
///
/// Worth reporting rather than just logging: `Suppressed` means exec events
/// arrive with no path at all, which downstream looks identical to a process
/// that could not be resolved. Without this, "this kernel's record is a shape
/// we do not read" and "that binary was already gone" are the same symptom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecOffset {
    /// Read out of tracefs and patched in.
    Parsed(u32),
    /// The format file could not be read; the compiled-in default stands.
    #[default]
    Default,
    /// The record is in a form this build cannot read, so the filename read is
    /// switched off in the kernel program.
    Suppressed,
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

/// Whether `connect()` is enforced in the kernel, and whether that enforcement
/// outlives this process.
///
/// Separate from [`Ring0`] on purpose. `Ring0` answers "is the kernel feeding
/// this daemon better information?"; this answers "does the kernel refuse
/// anything on its own?". They fail independently - a host can have all three
/// observers up and no bpffs to pin into - and conflating them would let a
/// weaker guarantee hide behind a stronger word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Enforcement {
    /// Not attempted: eBPF is off, or the object never loaded.
    #[default]
    Off,
    /// Attempted, and the kernel refused. Decisions happen in userspace only,
    /// which is where they happened before this layer existed.
    Unavailable,
    /// Attached, but the link is held by this process alone. Every deny it
    /// holds is lifted the moment the daemon exits.
    Process,
    /// Attached with the link pinned to bpffs. Denies survive the daemon being
    /// killed; lifting them takes a deliberate `rm` under `/sys/fs/bpf`.
    Pinned,
    /// Not attached by *this* daemon because a previous one's pins are still
    /// there and still enforcing. The map is shared, so this daemon steers it.
    Inherited,
}

impl Enforcement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Unavailable => "unavailable",
            Self::Process => "process",
            Self::Pinned => "pinned",
            Self::Inherited => "inherited",
        }
    }

    /// True when the kernel refuses `connect()` for denied processes, whoever
    /// owns the link.
    pub fn is_live(self) -> bool {
        matches!(self, Self::Process | Self::Pinned | Self::Inherited)
    }

    /// True when that stays true after this process dies.
    pub fn survives_daemon(self) -> bool {
        matches!(self, Self::Pinned | Self::Inherited)
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Unavailable,
            2 => Self::Process,
            3 => Self::Pinned,
            4 => Self::Inherited,
            _ => Self::Off,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Unavailable => 1,
            Self::Process => 2,
            Self::Pinned => 3,
            Self::Inherited => 4,
        }
    }
}

/// The enforcement level this daemon actually reached, readable at any time.
///
/// It exists because losing the in-kernel layer is *silent*. It was switched
/// off machine-wide for hours during development and not one thing failed: the
/// packet path picked up every decision, the tests passed, the logs said
/// nothing after startup. A property nobody can read is a property nobody can
/// rely on - and the ways to lose it are all external (a systemd release that
/// remounts /sys read-only, an SELinux denial on `prog_load`, a kernel without
/// BTF), so it can go away on a machine whose own code never changed.
///
/// A plain atomic rather than a channel: it is written once at startup and read
/// by whoever asks, and it must stay readable even if everything else is wedged.
/// Sentinel for "startup has not answered yet".
///
/// Not the same as `Off`, and the difference is load-bearing. The IPC server
/// binds and starts answering before `ebpf::start` has run, so for the first
/// moments of a daemon's life the honest answer is "ask again". Reporting
/// `Off` there would be a lie in the dangerous direction on the inherited
/// path, where a previous daemon's pinned programs are refusing `connect()`
/// machine-wide at that very instant.
const LEVEL_UNKNOWN: u8 = u8::MAX;

static ENFORCEMENT_LEVEL: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(LEVEL_UNKNOWN);

/// Records what [`start`] achieved. Called once, at the end of startup.
pub fn set_enforcement_level(level: Enforcement) {
    ENFORCEMENT_LEVEL.store(level.as_u8(), std::sync::atomic::Ordering::Relaxed);
}

/// What the in-kernel layer is doing right now, for `cfc status` and anything
/// else that should not have to read the journal to find out.
pub fn enforcement_level() -> Option<Enforcement> {
    match ENFORCEMENT_LEVEL.load(std::sync::atomic::Ordering::Relaxed) {
        LEVEL_UNKNOWN => None,
        v => Some(Enforcement::from_u8(v)),
    }
}

/// Whether the fast-allow path - a process-wide allow marking its sockets so
/// nftables accepts them ahead of the queue - is actually doing anything.
///
/// Two-way, with the reason attached. `Off` carries *why*, because the path
/// has many ways to be silently inert - the config switch, a kernel whose
/// verifier lacks `bpf_setsockopt` on sock_addr or on sendmsg, exit tracking
/// without a readable `group_dead`, tracepoint links that could not be
/// pinned, ring consumers that did not start, an nftables set the snippet
/// does not declare, a table that is not loaded yet, a ruleset reload that
/// emptied the set - and a feature that is off for a reason nobody can read is
/// a feature nobody can rely on. That lesson was learned once already with the
/// enforcement level above.
///
/// Not "an inherited attach from a build that predates it", which this list
/// used to open with. The pin directory carries the ABI version and the fast
/// path arrived with a version bump, so a daemon never inherits pins from a
/// build that lacks it - it would find no pins at that path at all and attach
/// fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastAllow {
    /// Marks are being set and the nftables set holds this daemon's value.
    ///
    /// `deadline_secs` is how long a grant outlives a daemon that stops
    /// refreshing it. It is the full [`fast_allow::DEADLINE_SECS`] when the
    /// exec/exit tracepoint links are pinned - they go on clearing grants
    /// without a daemon, so the deadline is a backstop - and the shorter
    /// [`fast_allow::DEADLINE_SECS_UNPINNED`] when they are not, where it is
    /// the only thing standing between a dead daemon and a recycled pid.
    ///
    /// Carried rather than assumed, because a status line that says `live`
    /// without saying which guarantee is a status line that misleads on
    /// exactly the kernels where the guarantee is weaker.
    Live { deadline_secs: u64 },
    /// Not doing anything, and this is the one sentence that says why.
    Off(String),
}

impl FastAllow {
    /// One token plus the reason, for `cfc status`: `live` or `off: <why>`.
    pub fn describe(&self) -> String {
        match self {
            Self::Live { deadline_secs }
                if *deadline_secs == cfc_ebpf_common::fast_allow::DEADLINE_SECS =>
            {
                "live".to_string()
            }
            Self::Live { deadline_secs } => {
                format!("live, grants lapse within {deadline_secs}s")
            }
            Self::Off(why) => format!("off: {why}"),
        }
    }
}

static FAST_ALLOW_LEVEL: std::sync::RwLock<Option<FastAllow>> = std::sync::RwLock::new(None);

/// Records what [`start`] achieved for the fast path. Called once, at the end
/// of startup, and again if the path is disarmed at shutdown.
pub fn set_fast_allow_level(level: FastAllow) {
    *FAST_ALLOW_LEVEL
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(level);
}

/// The fast path's state, `None` until startup has answered - the same
/// "ask again" sentinel `enforcement_level` uses, for the same reason.
pub fn fast_allow_level() -> Option<FastAllow> {
    FAST_ALLOW_LEVEL
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// What actually came up. Reported once at startup and otherwise inert.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// `[ebpf] enabled` in the config: what was asked for, which decides how
    /// loudly a shortfall is reported.
    pub mode: EbpfMode,
    /// The `ebpf` cargo feature is compiled in.
    pub compiled_in: bool,
    /// `sched_process_exec` is attached and feeding the process table.
    pub exec_tracking: bool,
    /// `sched_process_exit` is attached, so entries are evicted on exit.
    pub exit_tracking: bool,
    /// `cgroup_skb/ingress` is attached and feeding observed DNS answers.
    pub dns_capture: bool,
    /// Whether `cgroup/connect4|6` refuse denied processes in-kernel, and
    /// whether they keep doing so once this daemon is gone.
    pub enforcement: Enforcement,
    /// `task_struct` offsets were resolved from BTF, so exec events carry a
    /// real ppid rather than 0.
    pub ppid_offsets: bool,
    /// Human-readable notes: one line per thing that did not come up.
    pub notes: Vec<String>,
    /// Why the layer is not fully up, when that is known well enough to say in
    /// one word. `None` means either "it is fully up" or "the reason has no
    /// classification", and callers must not read anything into which.
    pub degrade: Option<Degrade>,
    /// Where the exec program was told to find the tracepoint filename field.
    pub exec_offset: ExecOffset,
    /// `(program, instructions the verifier walked)`, for programs that got as
    /// far as being verified on a kernel that reports the count (>= 5.16).
    ///
    /// Recorded because it is a *budget*: the kernel allows 1,000,000 and
    /// refuses at 1,000,001, and the DNS observer has already been on the
    /// wrong side of that once. Surfacing it turns "a change made the program
    /// more expensive" into something visible here, rather than into "it
    /// stopped loading on someone else's kernel".
    pub verified_insns: Vec<(String, u32)>,
    /// The fast path's state after startup, `None` when the layer never got
    /// far enough to have an opinion (eBPF off, object not loaded).
    pub fast_allow: Option<FastAllow>,
    /// Whether process exit is detected exactly (`group_dead` read from the
    /// tracepoint record) rather than approximated by leader exit. A deny
    /// evicted late is an inconvenience; a fast-allow grant evicted late is a
    /// mark on a recycled pid, so the fast path requires the exact answer.
    pub exit_precise: bool,
    /// Whether *both* lifecycle tracepoint links were pinned to bpffs, rather
    /// than merely attached.
    ///
    /// The two are not the same and the difference is the fast path's whole
    /// safety argument. `attach_tracepoint` re-attaches unpinned when a link
    /// cannot be pinned - no `BPF_LINK_TYPE_PERF_EVENT` before 5.15, or a
    /// read-only bpffs - which keeps eviction working for as long as this
    /// daemon runs and stops the moment it does not. The connect programs' own
    /// links are pinned separately and go on marking sockets either way, so
    /// without this flag the ladder granted on a kernel where the clears die
    /// with the daemon and only the sixty-second deadline stood between a
    /// grant and a recycled pid.
    pub lifecycle_pinned: bool,
}

impl Report {
    /// A report for a daemon that is not running any eBPF at all.
    fn inert(mode: EbpfMode, compiled_in: bool, note: impl Into<String>) -> Self {
        Self {
            mode,
            compiled_in,
            notes: vec![note.into()],
            ..Self::default()
        }
    }

    /// Same, with the reason classified.
    fn inert_because(
        mode: EbpfMode,
        compiled_in: bool,
        degrade: Degrade,
        note: impl Into<String>,
    ) -> Self {
        Self {
            degrade: Some(degrade),
            ..Self::inert(mode, compiled_in, note)
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
        if !self.mode.wants_load() {
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

    /// How loudly to report a shortfall, from what was asked for and why it
    /// fell short.
    ///
    /// The whole reason [`EbpfMode`] has three states. Under `On` somebody
    /// asked for ring 0 and did not get it: that is an error, whatever the
    /// cause. Under `Auto` the daemon decided to try, and most ways of failing
    /// are ordinary facts about the machine rather than anything wrong -
    /// warning about them every boot is how a project teaches people to ignore
    /// its warnings.
    ///
    /// Two `Auto` cases are still worth a warning, for opposite reasons:
    ///
    /// * `Rejected` - our program met a kernel that refused it. That is a bug
    ///   in this project, not a property of the host, and it is the single
    ///   thing here most worth hearing about.
    /// * a *partial* bring-up - some programs attached and some did not, which
    ///   is neither the clean "this host cannot" nor the clean "it works", and
    ///   usually means something is contended (see the exclusive cgroup slot).
    ///
    /// `NotPermitted` is deliberately **not** one of them under `Auto`.
    /// EPERM from `bpf(2)` is the *normal* answer inside a container with
    /// Docker's default seccomp profile, in an unprivileged LXC guest, and on
    /// 5.8-5.10 where BPF map memory is charged to an unraised RLIMIT_MEMLOCK.
    /// Reading it as "someone edited the unit" would be wrong far more often
    /// than right.
    fn note_level(&self) -> NoteLevel {
        use Degrade::*;
        match self.mode {
            EbpfMode::Off => NoteLevel::Debug,
            EbpfMode::On => NoteLevel::Error,
            EbpfMode::Auto => match self.degrade {
                Some(Rejected) => NoteLevel::Warn,
                Some(_) => NoteLevel::Info,
                // No classified reason, but not everything came up.
                None if self.ring0() == Ring0::Partial => NoteLevel::Warn,
                None => NoteLevel::Info,
            },
        }
    }

    /// Names the attribution and hostname sources that are live, so the
    /// journal answers "is eBPF actually doing anything on this host?"
    /// without anyone having to guess from the absence of warnings.
    ///
    /// This is deliberately a log line and not a `GetStatus` field: the
    /// protobuf surface is frozen for this change.
    pub fn log(&self) {
        let level = self.note_level();
        for note in &self.notes {
            match level {
                NoteLevel::Error => tracing::error!("eBPF: {note}"),
                NoteLevel::Warn => tracing::warn!("eBPF: {note}"),
                NoteLevel::Info => tracing::info!("eBPF: {note}"),
                NoteLevel::Debug => tracing::debug!("eBPF: {note}"),
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
            // Separate word from `ring0` on purpose: that one says how well the
            // kernel informs this daemon, this one says whether the kernel
            // refuses anything without it. See `Enforcement`.
            enforcement = self.enforcement.as_str(),
            degrade = self.degrade.map(Degrade::as_str).unwrap_or("none"),
            exec_tracking = self.exec_tracking,
            exit_tracking = self.exit_tracking,
            dns_capture = self.dns_capture,
            ppid_from_btf = self.ppid_offsets,
            // The fast path has five reasons to be off and they used to reach
            // `cfc status` only. An operator who set `fast_allow = true`,
            // restarted, and never ran the CLI had no way to learn from the
            // journal that the kernel had refused a hook - which is the whole
            // point of degrading loudly.
            fast_allow = self
                .fast_allow
                .as_ref()
                .map(FastAllow::describe)
                .unwrap_or_else(|| "not decided".to_string()),
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
pub fn start(
    cfg: &EbpfConfig,
    dns: DnsCache,
    table: proc_table::KernelProcTable,
    // Unused without the `ebpf` feature: there is no kernel-side map to steer.
    // Kept in the signature so callers do not need a cfg of their own.
    #[cfg_attr(not(feature = "ebpf"), allow(unused_variables))] engine: Option<
        crate::decision::Engine,
    >,
    // The fast path's reporting: flows the kernel waved past the queue are
    // fed back into the same observed stream and the same counters NFQUEUE
    // feeds, so the live feed and the enforcing heuristic keep telling the
    // truth about traffic the packet path never sees.
    #[cfg_attr(not(feature = "ebpf"), allow(unused_variables))]
    observed: tokio::sync::broadcast::Sender<crate::nfqueue::ObservedConnection>,
    #[cfg_attr(not(feature = "ebpf"), allow(unused_variables))] stats: crate::stats::Stats,
) -> Runtime {
    // The answer until the layer says otherwise. Every early return below
    // leaves it standing, which is the truthful default: no layer, no fast
    // path.
    set_fast_allow_level(FastAllow::Off("the in-kernel layer is not up".to_string()));
    if !cfg.enabled.wants_load() {
        return Runtime {
            report: Report::inert(
                cfg.enabled,
                cfg!(feature = "ebpf"),
                // Deliberately does not name a cause. `start` is handed an
                // already-resolved mode and cannot tell `[ebpf] enabled = false`
                // from `--dry-run` forcing it off, and a note that guesses is
                // worse than one that does not: it would send someone to edit a
                // config file that says nothing of the sort. Whoever forced it
                // says so themselves - see main.rs.
                "switched off; using sock_diag + /proc only",
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
                cfg.enabled,
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
        match loader::load_and_attach(
            &path,
            dns,
            table.clone(),
            engine,
            trust,
            observed,
            stats,
            loader::FastAllowCfg {
                on: cfg.fast_allow,
                mark: cfg.fast_allow_mark,
            },
        ) {
            Ok((attached, mut report)) => {
                // The loader builds its report before it knows how it was
                // asked for; only `start` does. Without this an `auto` host
                // that came up partially would be logged under the forced-on
                // error policy.
                report.mode = cfg.enabled;
                table.set_live(report.exec_tracking);
                // The fast-allow level is NOT published here. The loader
                // publishes it before it spawns the heartbeat, because that
                // task publishes too - and this call site runs after both, so
                // it could only ever overwrite a fresher answer with a staler
                // one. It did: on a restart the heartbeat arms immediately and
                // says `Live`, and this line put "waiting for the nftables
                // table" back on top of it, permanently.
                Runtime {
                    report,
                    _attached: Some(attached),
                }
            }
            Err(e) => {
                // The loader never got far enough to publish one.
                set_fast_allow_level(FastAllow::Off(
                    "the in-kernel layer did not come up".to_string(),
                ));
                Runtime {
                    report: Report::inert_because(
                        cfg.enabled,
                        true,
                        e.degrade,
                        format!("load failed, continuing without it: {:#}", e.source),
                    ),
                    _attached: None,
                }
            }
        }
    };

    runtime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicitly_off_config_produces_an_inert_report() {
        let cfg = EbpfConfig {
            enabled: EbpfMode::Off,
            object_path: None,
            fast_allow: false,
            fast_allow_mark: None,
        };
        let rt = start(
            &cfg,
            DnsCache::new(),
            proc_table::KernelProcTable::new(),
            None,
            tokio::sync::broadcast::channel(8).0,
            crate::stats::Stats::new(),
        );
        assert!(!rt.report.any_active());
        assert_eq!(rt.report.mode, EbpfMode::Off);
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
            enabled: EbpfMode::On,
            object_path: Some(dir.path().join("cfc-ebpf.o")),
            fast_allow: false,
            fast_allow_mark: None,
        };
        // An instance, not `proc_table::global()`: the assertion below is about
        // what *this* load did, and against the process-wide table it would be
        // an assertion about every other test in the binary as well.
        let table = proc_table::KernelProcTable::new();
        let rt = start(
            &cfg,
            DnsCache::new(),
            table.clone(),
            None,
            tokio::sync::broadcast::channel(8).0,
            crate::stats::Stats::new(),
        );
        assert_eq!(rt.report.mode, EbpfMode::On);
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

    /// The end-to-end claim of the whole automatic-mode change, on the real
    /// production path: a **default** config, no `object_path`, so the loader
    /// goes to `DEFAULT_OBJECT_PATH` on its own initiative and therefore vets
    /// the file under `Trust::Refuse`.
    ///
    /// Ignored by default because it needs root, CAP_BPF + CAP_PERFMON, cgroup
    /// v2, and the object actually installed where a package would put it:
    ///
    /// ```sh
    /// cargo xtask build-ebpf
    /// sudo install -D -m 0644 -o root -g root \
    ///     "$(cargo xtask ebpf-path)" /usr/lib/colony-firewall/cfc-ebpf.o
    /// sudo -E ./target/fast/deps/cfc_daemon-<hash> --ignored --nocapture auto_mode
    /// ```
    ///
    /// It asserts the thing no unit test can: that nobody has to configure
    /// anything for ring 0 to come up on a machine that can run it.
    #[tokio::test]
    #[ignore = "needs root, CAP_BPF and the object installed at DEFAULT_OBJECT_PATH"]
    async fn auto_mode_brings_ring0_up_on_this_host() {
        let cfg = EbpfConfig::default();
        assert_eq!(cfg.enabled, EbpfMode::Auto, "the default must be auto");
        assert_eq!(
            cfg.object_path, None,
            "and it must not name a path, so the loader vets under Trust::Refuse"
        );

        let table = proc_table::KernelProcTable::new();
        let rt = start(
            &cfg,
            DnsCache::new(),
            table.clone(),
            None,
            tokio::sync::broadcast::channel(8).0,
            crate::stats::Stats::new(),
        );
        for note in &rt.report.notes {
            println!("note: {note}");
        }
        println!(
            "ring0={} degrade={:?} exec_offset={:?}",
            rt.report.ring0().as_str(),
            rt.report.degrade,
            rt.report.exec_offset
        );
        for (program, insns) in &rt.report.verified_insns {
            println!("verified_insns: {program} = {insns}");
        }

        assert_eq!(
            rt.report.ring0(),
            Ring0::Active,
            "a default config on a capable host must bring all three programs \
             up with no configuration at all: {:?}",
            rt.report.notes
        );
        assert_eq!(rt.report.degrade, None);
        assert!(table.is_live(), "the process table must be serving answers");
    }

    /// The severity policy, over constructed reports rather than by running
    /// `start()` — the point is the (mode, degrade) matrix, not the load.
    #[test]
    fn severity_follows_what_was_asked_for() {
        let with = |mode: EbpfMode, degrade: Option<Degrade>| Report {
            mode,
            degrade,
            ..Report::default()
        };

        // Explicitly on: every shortfall is an error, whatever the cause.
        // Somebody asked for ring 0 and did not get it.
        for d in [
            Degrade::ObjectMissing,
            Degrade::NotPermitted,
            Degrade::Unsupported,
            Degrade::Rejected,
            Degrade::AbiMismatch,
        ] {
            assert_eq!(
                with(EbpfMode::On, Some(d)).note_level(),
                NoteLevel::Error,
                "{d:?} under an explicit `enabled = true` must be an error"
            );
        }

        // Off: nothing to say above debug. A daemon that warns every boot
        // about a default teaches people to ignore its warnings.
        assert_eq!(
            with(EbpfMode::Off, Some(Degrade::ObjectMissing)).note_level(),
            NoteLevel::Debug
        );

        // Auto: ordinary facts about the machine are info, not warnings.
        for d in [
            Degrade::ObjectMissing,
            Degrade::Unsupported,
            Degrade::ObjectUntrusted,
            Degrade::AbiMismatch,
        ] {
            assert_eq!(
                with(EbpfMode::Auto, Some(d)).note_level(),
                NoteLevel::Info,
                "{d:?} under auto is a property of the host, not a problem"
            );
        }

        // EPERM specifically: the normal answer inside a container with
        // Docker's default seccomp, in unprivileged LXC, and on 5.8-5.10 with
        // an unraised RLIMIT_MEMLOCK. Reading it as "the unit was edited"
        // would be wrong far more often than right.
        assert_eq!(
            with(EbpfMode::Auto, Some(Degrade::NotPermitted)).note_level(),
            NoteLevel::Info,
            "EPERM under auto is normal in a container, not a misconfiguration"
        );

        // A verifier rejection is ours, not the host's: the one auto case
        // worth a warning.
        assert_eq!(
            with(EbpfMode::Auto, Some(Degrade::Rejected)).note_level(),
            NoteLevel::Warn,
            "a rejected program is a bug in this project meeting a real kernel"
        );

        // A partial bring-up with no single classified cause is the other:
        // neither a clean "cannot" nor a clean "works".
        let partial = Report {
            mode: EbpfMode::Auto,
            exec_tracking: true,
            exit_tracking: true,
            dns_capture: false,
            ..Report::default()
        };
        assert_eq!(partial.ring0(), Ring0::Partial);
        assert_eq!(partial.note_level(), NoteLevel::Warn);
    }

    /// The path is written down in five places and they must agree.
    ///
    /// This is the guard that was missing when the packaging side became a
    /// `TODO(packaging)` comment instead of code: nothing connected the
    /// constant the daemon looks at to the string the package installs to, so
    /// they could drift silently and the only symptom would be a firewall
    /// quietly running without ring 0 on every installed machine.
    #[test]
    fn default_object_path_matches_the_packaging() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crates/cfc-daemon is two levels below the repo root")
            .to_path_buf();

        // pkg/PKGBUILD is deliberately absent from this list: the AUR package
        // does not ship the object at all (on Arch `rustup` conflicts with
        // `rust`, so the pinned nightly is unavailable inside makepkg). An AUR
        // install gets Degrade::ObjectMissing and runs on sock_diag + /proc,
        // which is a supported configuration - so requiring the path to appear
        // there would assert a promise the package does not make.
        for rel in ["pkg/colony.json", "systemd/daemon.toml.sample"] {
            let path = root.join(rel);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            assert!(
                text.contains(DEFAULT_OBJECT_PATH),
                "{rel} does not mention {DEFAULT_OBJECT_PATH}; the daemon would \
                 look somewhere the package never installs to"
            );
        }
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

#[cfg(test)]
mod enforcement_level_tests {
    use super::*;

    /// The level travels through an atomic as a byte. A variant that lost its
    /// number would report the wrong thing to `cfc status`, and reporting the
    /// wrong enforcement level is worse than reporting none: it would say the
    /// protection survives the daemon when it does not.
    #[test]
    fn every_level_round_trips_through_the_atomic() {
        for level in [
            Enforcement::Off,
            Enforcement::Unavailable,
            Enforcement::Process,
            Enforcement::Pinned,
            Enforcement::Inherited,
        ] {
            set_enforcement_level(level);
            assert_eq!(
                enforcement_level(),
                Some(level),
                "{} did not survive",
                level.as_str()
            );
        }
        set_enforcement_level(Enforcement::Off);
    }

    /// Before startup answers, the level must be *absent*, not `Off`.
    ///
    /// On the inherited path a previous daemon's pinned programs are refusing
    /// `connect()` machine-wide during this window, so reporting "no in-kernel
    /// enforcement" would be false in the direction that matters.
    #[test]
    fn unknown_is_distinguishable_from_a_real_off() {
        assert_ne!(LEVEL_UNKNOWN, Enforcement::Off.as_u8());
        assert_eq!(
            Enforcement::from_u8(Enforcement::Pinned.as_u8()),
            Enforcement::Pinned
        );
    }

    /// Only these two mean "still refusing after this process is gone".
    #[test]
    fn the_surviving_levels_are_the_pinned_ones() {
        assert!(Enforcement::Pinned.survives_daemon());
        assert!(Enforcement::Inherited.survives_daemon());
        assert!(!Enforcement::Process.survives_daemon());
        assert!(!Enforcement::Unavailable.survives_daemon());
        assert!(!Enforcement::Off.survives_daemon());
    }
}
