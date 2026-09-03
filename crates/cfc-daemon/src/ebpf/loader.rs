//! The aya half of the eBPF layer: load the object, patch the `.rodata`
//! globals from BTF, attach the three programs, and spawn one ring-buffer
//! consumer per event stream.
//!
//! Compiled only with the `ebpf` cargo feature; everything aya-shaped lives
//! here so the rest of the daemon never sees it. See the parent module for the
//! design rationale.

use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::FastAllow;
use anyhow::{anyhow, Context as _};
use aya::maps::{HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::links::FdLink;
use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, ProgramError, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use cfc_core::Process;
use cfc_ebpf_common::dns::{self, DnsCursor, DNS_HEADER_LEN};
use cfc_ebpf_common::{ConnectReport, DnsAnswer, DnsPacket, ExecEvent, ExitEvent};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::{
    btf, cgroup, enforce, proc_table::KernelProcTable, tracefs, Degrade, Enforcement, ExecOffset,
    Report,
};
use crate::dns::DnsCache;

/// A load that did not happen, with the reason in a form [`Report::log`] can
/// pick a severity from.
#[derive(Debug)]
pub(super) struct LoadError {
    pub degrade: Degrade,
    pub source: anyhow::Error,
}

impl LoadError {
    fn new(degrade: Degrade, source: anyhow::Error) -> Self {
        Self { degrade, source }
    }
}

/// What to do about an object that fails [`vet_object`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Trust {
    /// Say so and load it anyway. Correct when a human explicitly pointed the
    /// daemon at this file: that is a statement of trust, and it is also the
    /// only way the developer workflow works at all (an object under
    /// `target/` is owned by whoever ran cargo, not by root).
    Warn,
    /// Refuse. Correct when nobody asked for this particular file - the daemon
    /// found it at the default path and decided by itself to load it.
    Refuse,
}

// The (uid, mode) policy lives in cfc-core (`exe_path::{dir,file}_is_sealed`)
// because rule hash-binding asks the identical question about executables:
// "can a non-root user swap the bytes behind this path". One authority; the
// exhaustive tests below stay here, where the policy was first earned.
use cfc_core::exe_path::{dir_is_sealed as dir_is_safe, file_is_sealed as file_is_safe};

/// Decides whether a file is one we are willing to hand to `bpf(2)`.
///
/// Not paranoia about `object_path` being attacker-*supplied* - it comes from a
/// root-owned config file. It is about the file it points at being
/// attacker-*replaceable*. A BPF object is kernel code: it is loaded with
/// CAP_BPF, it runs on every exec and every ingress packet on the machine, and
/// the process table it feeds is *preferred over `/proc`* when the daemon
/// decides who a connection belongs to. A world-writable object, or one under a
/// directory some ordinary user can rename, is a short path from "unprivileged
/// local account" to "decides what the firewall believes".
///
/// Returns the offending path so the note can name it. Symlinks are resolved
/// first: vetting the link and loading the target would check the wrong file.
fn vet_object(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let real =
        std::fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?;
    let meta = std::fs::metadata(&real).with_context(|| format!("stat {}", real.display()))?;
    if !meta.is_file() {
        return Err(anyhow!("{} is not a regular file", real.display()));
    }
    if !file_is_safe(meta.uid(), meta.mode()) {
        return Err(anyhow!(
            "{} is uid {} mode {:o}; a BPF object must be root-owned and \
             writable only by root",
            real.display(),
            meta.uid(),
            meta.mode() & 0o7777,
        ));
    }
    // Walk every ancestor: a safe file under a directory someone else can
    // rename is not a safe file.
    for dir in real.ancestors().skip(1) {
        let m = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
        if !dir_is_safe(m.uid(), m.mode()) {
            return Err(anyhow!(
                "{} lies under {}, which is uid {} mode {:o}; a non-root user \
                 could replace the object",
                real.display(),
                dir.display(),
                m.uid(),
                m.mode() & 0o7777,
            ));
        }
    }
    Ok(())
}

/// Arms the kernel side of the fast path and returns the mark it will set.
///
/// The nftables side is not here: the table is normally not loaded yet when
/// the daemon starts (`colony-firewall-nft.service` waits for the daemon),
/// so the set is written by the heartbeat task, which retries until it can -
/// see `nft_arm_state`. A mark in the map with no element in the set is a
/// wasted `setsockopt`, never a bypass: the ruleset accepts a value only while
/// it is in the set, and the caller flushed the set unconditionally before
/// this ran.
///
/// The deadline does stay zero until the heartbeat's first beat - but because
/// `VerdictSink::arm` zeroes it, not by itself. `FAST_ALLOW_UNTIL` is a pinned
/// map, so after an unclean death it holds whatever the previous daemon last
/// wrote, up to a minute into the future; this comment asserted the zero for
/// two releases before anything wrote it.
///
/// The mark is 32 random bits, never zero (`UNARMED`). Random per start
/// because since kernel 5.17 `SO_MARK` needs only `CAP_NET_RAW`, which docker
/// grants by default: a value anyone could read out of a package would be a
/// bypass token for any such process on the host's network.
fn arm_kernel_side(sink: &enforce::VerdictSink, configured: Option<u32>) -> anyhow::Result<u32> {
    let mark = match configured {
        Some(m) if m == cfc_ebpf_common::fast_allow::UNARMED => {
            return Err(anyhow!(
                "[ebpf] fast_allow_mark = 0 is not a mark: zero is what every socket \
                 nothing has marked carries, and accepting it would accept everything"
            ))
        }
        Some(m) => {
            if let Some(who) = collides_with(m) {
                // Their machine, their call - but not silently.
                warn!(
                    "the configured fast-allow mark 0x{m:08x} is one {who} selects on; \
                     traffic this daemon marks may be routed or dropped by that rule"
                );
            }
            m
        }
        None => pick_mark(|| uuid::Uuid::new_v4().as_u128() as u32).ok_or_else(|| {
            anyhow!(
                "could not draw a fast-allow mark that avoids the fwmark selectors this \
                 host is likely to use; set [ebpf] fast_allow_mark to choose one by hand"
            )
        })?,
    };
    sink.arm(mark)
        .context("writing the fast-allow mark to the kernel")?;
    Ok(mark)
}

/// fwmark selectors this machine is likely to already have, as
/// (mask, value, who) - a candidate `m` collides when `m & mask == value`.
///
/// The mark is one 32-bit word shared by everything on the host, and the
/// dangerous consumers are the ones that select on a *mask*: they do not need
/// to guess our value, only to share a bit with it. A uniformly random word
/// therefore collides at a rate the other rule's mask decides, freshly at every
/// daemon start, which turns this into an intermittent and very hard to
/// attribute network fault - the fast path is off by default, so the operator's
/// first evidence is that turning it on breaks their VPN one boot in N.
///
/// The two kube-proxy entries are why this list is not optional. Their masks
/// are a single bit, so a random word matches one of them **half the time**,
/// and `0x8000/0x8000` is the mark kube-proxy attaches to packets it then
/// DROPs. On such a node the previous code broke every fast-allowed flow on
/// roughly every other daemon start.
///
/// This list is not, and cannot be, complete: nothing enumerates the fwmark
/// users of a Linux host. It is the documented ones, and `[ebpf]
/// fast_allow_mark` is the answer for a machine with a selector it misses.
const KNOWN_SELECTORS: &[(u32, u32, &str)] = &[
    // kube-proxy: masquerade, and drop.
    (0x0000_4000, 0x0000_4000, "kube-proxy (masquerade)"),
    (0x0000_8000, 0x0000_8000, "kube-proxy (drop)"),
    // Tailscale's ip rules: "came from tailscale0", and "bypass tailscale".
    (0x00ff_0000, 0x0008_0000, "Tailscale"),
    (0x00ff_0000, 0x0004_0000, "Tailscale (bypass)"),
    // wg-quick's `ip rule not fwmark <fwmark> lookup <table>`: an exact-word
    // compare, so this one costs a single value out of four billion. Listed
    // because excluding it is free and the failure - the tunnel's own table
    // stops being consulted for our traffic - is silent.
    (0xffff_ffff, 0x0000_ca6c, "wg-quick"),
];

/// The first entry of [`KNOWN_SELECTORS`] that would match `mark`.
fn collides_with(mark: u32) -> Option<&'static str> {
    KNOWN_SELECTORS
        .iter()
        .find(|(mask, value, _)| mark & mask == *value)
        .map(|(_, _, who)| *who)
}

/// Draws a mark that is neither `UNARMED` nor something in
/// [`KNOWN_SELECTORS`].
///
/// Rejection sampling rather than a claimed range, because a range is the
/// thing that must not be predictable: `SO_MARK` needs only CAP_NET_RAW since
/// 5.17, so a value an attacker can enumerate is a bypass token. Roughly a
/// quarter of the word survives the sieve - the two single-bit kube-proxy
/// masks account for almost all of it - which leaves about thirty bits of
/// entropy and takes four draws on average.
fn pick_mark(mut draw: impl FnMut() -> u32) -> Option<u32> {
    // Bounded so a caller whose `draw` is degenerate cannot hang the daemon.
    // About a quarter of the word survives the sieve, so 64 consecutive
    // rejections is not chance - it is a broken source of randomness.
    for _ in 0..64 {
        let candidate = draw();
        if candidate != cfc_ebpf_common::fast_allow::UNARMED && collides_with(candidate).is_none() {
            return Some(candidate);
        }
    }
    // And then nothing, rather than a fallback.
    //
    // The obvious fallback - walk upward from 1 until the sieve passes - was
    // worse than no fast path at all: it does not depend on `draw`, so it is
    // the *same* value on every machine that reaches it. A published constant
    // is precisely the bypass token the random draw exists to avoid, and
    // `SO_MARK` needs only CAP_NET_RAW since 5.17. The path stays off, with
    // the reason in `cfc status`, and every connection keeps taking the queue -
    // which is the behaviour this whole feature degrades to anyway.
    None
}

/// One attempt at the nftables side, at startup, reported as the state it
/// leaves the path in. On a daemon *restart* the table is already loaded and
/// this comes back `Live` at once; on a boot it comes back waiting, and the
/// heartbeat task finishes the job.
fn nft_arm_state(mark: u32) -> FastAllow {
    match super::nft_set::arm(mark) {
        Ok(()) => FastAllow::Live,
        Err(e) => nft_arm_state_from_error(&e),
    }
}

/// The reported state for a failed nftables arm. A missing *table* is the
/// normal boot order (the nft unit starts after this daemon) and reads as
/// waiting; a missing *set* is an operator-visible fact - a snippet that
/// predates the feature - and carries the fix; anything else is quoted.
fn nft_arm_state_from_error(e: &anyhow::Error) -> FastAllow {
    match e.downcast_ref::<super::nft_set::Absent>() {
        Some(super::nft_set::Absent::Table) => FastAllow::Off(
            "waiting for the nftables table (colony-firewall-nft.service starts after the daemon)"
                .to_string(),
        ),
        Some(super::nft_set::Absent::Set) => FastAllow::Off(format!("{e}")),
        None => FastAllow::Off(format!("could not arm nftables: {e:#}")),
    }
}

/// Classifies a failure from `EbpfLoader::load` - parsing the ELF, creating
/// maps, applying relocations.
///
/// `EACCES` here means the kernel refused the *syscall*, not a verifier
/// verdict: no program has been submitted yet at this point.
fn classify_load(err: &anyhow::Error) -> Degrade {
    // A missing ABI symbol is not an errno at all - aya reports it while
    // parsing, before any syscall. Catching it by message is unlovely, but the
    // alternative is filing "your object is from a different release" under
    // `Other` alongside genuine ELF corruption, and those want different
    // advice. The needle is our own symbol name, which we control.
    if err
        .chain()
        .any(|c| c.to_string().contains(cfc_ebpf_common::ABI_SYMBOL))
    {
        return Degrade::AbiMismatch;
    }
    match errno_of(err) {
        Some(libc::EPERM | libc::EACCES) => Degrade::NotPermitted,
        // ENOTSUP and EOPNOTSUPP are the same number on Linux; naming both
        // would be an unreachable pattern.
        Some(libc::EINVAL | libc::ENOTSUP | libc::ENOSYS) => Degrade::Unsupported,
        _ => Degrade::Other,
    }
}

/// Classifies a failure from `prog.load()`, which is where `BPF_PROG_LOAD`
/// actually runs and therefore where the verifier actually speaks.
///
/// The important difference from [`classify_load`]: `BPF_PROG_LOAD` answers
/// **`EACCES` when the verifier rejects the program** and `EPERM` when the
/// caller lacks the capability. Folding those together would file our own bug
/// meeting a newer kernel under "this container has no CAP_BPF" and hide the
/// single most interesting failure this project can have.
fn classify_verify(err: &anyhow::Error) -> Degrade {
    match errno_of(err) {
        Some(libc::EACCES | libc::E2BIG) => Degrade::Rejected,
        Some(libc::EPERM) => Degrade::NotPermitted,
        Some(libc::ENOTSUP | libc::ENOSYS) => Degrade::Unsupported,
        // It reached the verifier, so an unclassified failure here is far more
        // likely to be a rejection than a missing capability.
        _ => Degrade::Rejected,
    }
}

/// Digs the errno out of an error chain.
///
/// aya wraps syscall failures in typed errors whose `Display` has already lost
/// the number, so the chain has to be walked down to the `io::Error`.
fn errno_of(err: &anyhow::Error) -> Option<i32> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
}

/// ELF symbol names of the three programs, as `llvm-readelf --symbols` reports
/// them. aya keys `program_mut` on the symbol, not on the section.
const PROG_EXEC: &str = "cfc_sched_process_exec";
const PROG_EXIT: &str = "cfc_sched_process_exit";
const PROG_DNS: &str = "cfc_dns_ingress";

const MAP_EXEC: &str = "EXEC_EVENTS";
const MAP_EXIT: &str = "EXIT_EVENTS";
const MAP_DNS: &str = "DNS_PACKETS";

/// Everything whose lifetime keeps the programs attached.
///
/// `Ebpf` owns the links; dropping it detaches. The consumer tasks are aborted
/// explicitly rather than left to notice their `RingBuf` went away, because
/// they are parked in `AsyncFd::readable_mut()` and would otherwise sit there
/// holding a dead fd until the runtime shuts down.
pub(super) struct Attached {
    _bpf: Ebpf,
    tasks: Vec<JoinHandle<()>>,
    /// The only strong reference to the verdict sink. The engine's rule-change
    /// callback holds a `Weak`, so this field is what decides how long resync
    /// keeps working - and dropping this whole struct is exactly when it should
    /// stop.
    _sink: Option<std::sync::Arc<enforce::VerdictSink>>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        // A clean stop disarms now rather than letting the deadline lapse:
        // zero deadline and unarmed mark in the kernel, the set flushed in
        // nftables. Best effort - a daemon on its way out has only the log.
        if let Some(sink) = &self._sink {
            sink.disarm();
            if let Err(e) = super::nft_set::disarm_for_shutdown() {
                tracing::warn!(
                    "could not flush the fast-allow mark from nftables on shutdown: {e:#}"
                );
            }
            super::set_fast_allow_level(FastAllow::Off("the daemon stopped".to_string()));
        }
    }
}

/// Loads `object_path`, attaches what it can, and starts the consumers.
///
/// Returns `Err` only when the object itself could not be loaded at all - a
/// missing file, a malformed ELF, a kernel that refuses the whole program set.
/// Individual attach failures are recorded in the [`Report`] and leave the
/// rest running.
// Eight injected dependencies, each a different thing the layer may read or
// feed and none of which it should own; a bag struct to satisfy the lint
/// The `[ebpf]` fast-path settings one load should honour.
///
/// Two fields rather than two parameters: the argument list is already at the
/// lint's limit, and these two are one decision - whether the fast path runs,
/// and with which mark - taken from one config section.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct FastAllowCfg {
    /// `[ebpf] fast_allow`.
    pub on: bool,
    /// `[ebpf] fast_allow_mark`, when the operator pinned one. `None` draws.
    pub mark: Option<u32>,
}

// would name nothing that the parameter list does not already name.
#[allow(clippy::too_many_arguments)]
pub(super) fn load_and_attach(
    object_path: &Path,
    dns: DnsCache,
    table: KernelProcTable,
    engine: Option<crate::decision::Engine>,
    trust: Trust,
    observed: tokio::sync::broadcast::Sender<crate::nfqueue::ObservedConnection>,
    stats: crate::stats::Stats,
    fast_allow: FastAllowCfg,
) -> Result<(Attached, Report), LoadError> {
    let mut report = Report {
        mode: crate::config::EbpfMode::On,
        compiled_in: true,
        ..Report::default()
    };

    // Whatever a previous daemon left accepted in the nftables set, drop it -
    // first, before anything can return.
    //
    // This lived further down for a while, next to the code that arms, and
    // that was wrong twice over. It ran only when this daemon was *eligible*
    // and armed; and even after being made unconditional it still sat behind
    // every early return in this function - a missing object (which is the
    // single most common outcome on a default install), an untrusted one, a
    // failed load. So a daemon that crashed while armed and came back to any
    // of those left its predecessor's mark sitting in the set: accepted by the
    // ruleset, refreshed by nobody, removed by nothing short of the table
    // going away. That is a standing bypass token rather than a stale entry -
    // every process that was ever fast-allowed can read the value back off its
    // own socket with `getsockopt(SO_MARK)`, and setting it again needs only
    // CAP_NET_RAW.
    //
    // Flushing before knowing whether this daemon will arm is the right order:
    // an empty set accepts nothing, which is the safe state to pass through.
    if let Err(e) = super::nft_set::disarm() {
        report.notes.push(format!(
            "could not flush a previous fast-allow mark from nftables: {e:#}"
        ));
    }

    // Vet before read, so a file we would refuse is never even pulled into
    // memory, and so the "not there at all" case is distinguishable from the
    // "there but not ours" one.
    if let Err(e) = vet_object(object_path) {
        // `NotFound` from canonicalize is the ordinary "no object installed"
        // case, not a trust failure, and it must stay that way: under an
        // automatic default it is the single most common outcome on earth and
        // logging it as a security event would be noise.
        let missing = errno_of(&e) == Some(libc::ENOENT);
        if missing {
            return Err(LoadError::new(
                Degrade::ObjectMissing,
                e.context(format!(
                    "no BPF object at {} (build it with `cargo xtask build-ebpf` \
                     and install it there, or set [ebpf] object_path)",
                    object_path.display()
                )),
            ));
        }
        match trust {
            Trust::Refuse => {
                return Err(LoadError::new(Degrade::ObjectUntrusted, e));
            }
            // Somebody pointed the daemon at this file on purpose. Say what is
            // wrong with it and do as asked.
            Trust::Warn => {
                warn!("loading an unvetted BPF object because it was configured explicitly: {e:#}");
                report
                    .notes
                    .push(format!("BPF object failed its ownership check: {e:#}"));
            }
        }
    }

    let object = std::fs::read(object_path).map_err(|e| {
        let degrade = if e.kind() == std::io::ErrorKind::NotFound {
            Degrade::ObjectMissing
        } else {
            Degrade::ObjectUnreadable
        };
        LoadError::new(
            degrade,
            anyhow::Error::new(e).context(format!(
                "reading BPF object {} (build it with `cargo xtask build-ebpf` and \
                 install it there, or set [ebpf] object_path)",
                object_path.display()
            )),
        )
    })?;

    // Resolve the task_struct offsets before load: they are `.rodata`
    // constants, so they can only be set while the object is still bytes.
    // Failure is not fatal - the kernel side reads 0 as "unresolved" and
    // reports ppid 0, which process resolution already treats as unknown.
    let offsets = match btf::task_struct_offsets() {
        Ok(o) if o.is_resolved() => Some(o),
        Ok(o) => {
            report.notes.push(format!(
                "kernel BTF has no usable task_struct offsets ({o:?}); exec events will report ppid 0"
            ));
            None
        }
        Err(e) => {
            report.notes.push(format!(
                "could not resolve task_struct offsets from {}: {e:#}; \
                 exec events will report ppid 0",
                btf::VMLINUX_BTF
            ));
            None
        }
    };
    report.ppid_offsets = offsets.is_some();

    // Where the enforcement pins live, if they can. A failure here is not fatal
    // and not even a degrade: the connect programs still attach, they just do
    // not outlive this process. `prepare` also unpins any older event ABI,
    // which has to happen before the attach below or that attach meets EEXIST.
    let pin_dir = match enforce::prepare() {
        Ok(dir) => Some(dir),
        Err(e) => {
            report.notes.push(format!(
                "in-kernel enforcement cannot be pinned: {e:#}; \
                 it will stop when this daemon does"
            ));
            None
        }
    };
    // If a previous daemon left its pins behind, its programs are still
    // attached and still enforcing. Do not attach a second copy on top - reuse
    // the pinned maps and steer what is already there.
    let inherited = pin_dir.as_deref().is_some_and(enforce::already_attached);

    // Bound outside the loader so the borrows `map_pin_path` takes outlive it.
    let pinned_map_paths: Vec<(&str, PathBuf)> = pin_dir
        .as_deref()
        .map(|dir| {
            vec![
                (enforce::MAP_VERDICTS, dir.join(enforce::MAP_VERDICTS)),
                (enforce::MAP_STATS, dir.join(enforce::MAP_STATS)),
                (enforce::MAP_DENY_EVENTS, dir.join(enforce::MAP_DENY_EVENTS)),
                // The rule table and its gate: an adopted exec program has to
                // read the same ones the daemon writes.
                (enforce::MAP_EXE_RULES, dir.join(enforce::MAP_EXE_RULES)),
                (
                    enforce::MAP_EXE_RULES_ON,
                    dir.join(enforce::MAP_EXE_RULES_ON),
                ),
                // Attribution rather than enforcement, but the same restart
                // split applies; see the SOCK_PIDS paragraph below.
                (enforce::MAP_SOCK_PIDS, dir.join(enforce::MAP_SOCK_PIDS)),
                // The fast path's four. Pinned for the same restart reason
                // as everything above, and it is the pinning that makes the
                // deadline load-bearing: the programs keep these alive after
                // the daemon dies, so only `FAST_ALLOW_UNTIL` running out
                // stops the marks.
                (enforce::MAP_FAST_ALLOW, dir.join(enforce::MAP_FAST_ALLOW)),
                (
                    enforce::MAP_FAST_ALLOW_UNTIL,
                    dir.join(enforce::MAP_FAST_ALLOW_UNTIL),
                ),
                (
                    enforce::MAP_FAST_ALLOW_MARK,
                    dir.join(enforce::MAP_FAST_ALLOW_MARK),
                ),
                (
                    enforce::MAP_ALLOW_EVENTS,
                    dir.join(enforce::MAP_ALLOW_EVENTS),
                ),
            ]
        })
        .unwrap_or_default();

    // Read before `load`, which creates any pin that is missing: on the
    // inherited path "the pin was already there" is the difference between
    // opening the map the still-attached programs write and creating a fresh
    // one they cannot see.
    let sock_pids_was_pinned = pin_dir
        .as_deref()
        .is_some_and(|d| d.join(enforce::MAP_SOCK_PIDS).exists());

    let mut loader = EbpfLoader::new();
    // Pin the enforcement maps by name, so they are the *same* kernel objects
    // across a daemon restart. Without this the pinned programs would go on
    // consulting the map the dead daemon created while the new one wrote to a
    // fresh one nobody reads - enforcement frozen at whatever it held when the
    // daemon died, which is a far worse failure than not pinning at all.
    //
    // aya's `create_pinned_by_name` opens an existing pin when there is one and
    // creates it otherwise, so this is both the first-run and the restart path.
    // `DENY_EVENTS` is pinned for a reason worth spelling out, because the
    // first instinct is not to: a ring buffer nobody is draining fills up. It
    // does, and that costs a log line and nothing else - the refusal already
    // happened when the record could not be written. What pinning buys is the
    // opposite of a leak. On the inherited path this daemon does not re-attach,
    // so the *previously* pinned programs are the ones still writing; an
    // unpinned ring would leave them writing into a map this process cannot
    // see, and every in-kernel refusal after a restart would be silent. Draining
    // the backlog on startup is then a bonus: it says what was refused while
    // nothing was listening.
    //
    // `SOCK_PIDS` is the same split seen from the attribution side, and it
    // was missing from this list long enough to reproduce it: on the
    // inherited path the previous daemon's still-attached connect programs
    // write cookie -> tgid into the map *they* captured at their own load, so
    // an unpinned SOCK_PIDS handed this daemon a fresh map nothing writes.
    // Every cookie_pid() lookup missed for the life of the process, and every
    // new connection paid the 37-44 ms /proc walk the map exists to remove -
    // silently, with nothing in the report to say so. That is byte-for-byte
    // the v2 failure the ABI v3 bump documents, rebuilt inside v3 by an
    // ordinary restart. Unlike `VERDICTS` there is no startup sweep to do
    // here: the key is the kernel's socket cookie, a counter that is never
    // reused, so a stale entry from a previous run can never be looked up by
    // a new socket - it costs an LRU slot until eviction, not a wrong answer.
    //
    // `PROCS` and the other three ring buffers stay unpinned. They are rebuilt
    // from scratch every start, and pinning them really would leak the previous
    // run's backlog into this one.
    for (name, path) in &pinned_map_paths {
        loader.map_pin_path(name, path.as_path());
    }
    // Where `group_dead` sits in the sched_process_exit record.
    //
    // It is what tells the exit program that the *process* is gone rather than
    // one of its threads, and getting it wrong is not symmetric: reading a
    // wrong byte as "gone" evicts the verdict of a process that is still
    // running. So an offset that cannot be confirmed is not guessed - the
    // global keeps its "absent" default and the kernel side falls back to the
    // leader-only check it used before.
    let group_dead_off: u32 = match tracefs::exit_group_dead_offset() {
        Ok(Some(off)) if off > cfc_ebpf_common::TRACEPOINT_FIELD_OFFSET_MAX => {
            // The program bounds this read with the same constant and falls
            // back to the leader-only check without a word - it has nowhere
            // to say one. Patching the value through used to leave the debug
            // line below claiming `group_dead` is carried while the kernel
            // side never read it; report the fallback instead, as the `None`
            // arm does, and send the sentinel the program acts on.
            report.notes.push(format!(
                "sched_process_exit puts `group_dead` at offset {off}, past \
                 the {}-byte bound the program enforces; process exit is \
                 approximated by thread-group leader exit",
                cfc_ebpf_common::TRACEPOINT_FIELD_OFFSET_MAX
            ));
            u32::MAX
        }
        Ok(Some(off)) => {
            debug!(offset = off, "sched_process_exit carries group_dead");
            report.exit_precise = true;
            off
        }
        Ok(None) => {
            report.notes.push(
                "this kernel's sched_process_exit has no readable `group_dead`; \
                 process exit is approximated by thread-group leader exit"
                    .to_string(),
            );
            u32::MAX
        }
        Err(e) => {
            debug!(
                "could not read the sched_process_exit format file ({e}); \
                    keeping the leader-only check"
            );
            u32::MAX
        }
    };
    loader.override_global("EXIT_GROUP_DEAD_OFF", &group_dead_off, false);

    // The ABI gate, before anything else the loader does.
    //
    // `must_exist = true` is the whole mechanism: if the object does not
    // export this symbol, `load()` fails and nothing attaches. The object
    // ships as a separate file loaded from a path, so a stale one *will*
    // eventually meet a newer daemon - a package that updated the binary but
    // not the object, a hand-copied file, an interrupted upgrade - and nothing
    // about that is loud on its own. `decode<T>` accepts any record at least
    // `size_of::<T>()` long and reads the prefix, so a layout change becomes
    // plausible-looking garbage in `exe`, `uid`, `gid` and `ppid`: exactly the
    // fields `process_resolve` prefers over `/proc`. A firewall that
    // confidently attributes a connection to the wrong program is worse than
    // one that admits it does not know.
    //
    // Verified both ways against a live kernel: with the symbol present the
    // object loads; with a name the object does not export, aya answers
    // "symbol with name ... not found in the symbols table" and the load
    // stops there.
    loader.override_global(
        cfc_ebpf_common::ABI_SYMBOL,
        &cfc_ebpf_common::ABI_VERSION,
        true,
    );
    // The kernel's own BTF, used by aya to sanitize the object's BTF against
    // what this kernel supports. Optional: a kernel without it still loads
    // programs, it just gives worse verifier diagnostics.
    let kernel_btf = match Btf::from_sys_fs() {
        Ok(btf) => Some(btf),
        Err(e) => {
            // Was `.ok()`, which threw this away. It is not fatal - programs
            // still load - but it is exactly the fact you want in the journal
            // when a verifier rejection arrives with unhelpful diagnostics.
            report.notes.push(format!(
                "kernel BTF unavailable ({e}); verifier diagnostics will be poorer"
            ));
            None
        }
    };
    loader.btf(kernel_btf.as_ref());
    // Bound outside the `if` so the borrows outlive the loader.
    let (real_parent, tgid) = offsets.map(|o| (o.real_parent, o.tgid)).unwrap_or((0, 0));
    if offsets.is_some() {
        // `must_exist = false`: an object built before these globals existed
        // should still load and simply report ppid 0.
        loader.override_global("TASK_REAL_PARENT_OFFSET", &real_parent, false);
        loader.override_global("TASK_TGID_OFFSET", &tgid, false);
        debug!(
            real_parent,
            tgid, "patched task_struct offsets into .rodata"
        );
    }

    // Where `filename` sits in the sched_process_exec record. Bound outside
    // the match so the borrow outlives the loader.
    let exec_off: u32;
    // Never `?`: a record offset has nothing to do with whether exec, exit and
    // DNS can attach, and failing the whole load over it would trade three
    // working programs for one unread field.
    match tracefs::exec_filename_offset() {
        Ok(tracefs::Resolution::Parsed(off))
            if off > cfc_ebpf_common::TRACEPOINT_FIELD_OFFSET_MAX =>
        {
            // The program bounds its read with the same constant and treats
            // anything past it as "read nothing" - silently, because a BPF
            // program has nowhere to say so. This arm used to not exist, and
            // its absence was a lie in waiting: the loader patched the value
            // in, warned "patched it in", and reported `Parsed` while every
            // exec event arrived with no filename - `Suppressed` behaviour
            // wearing a `Parsed` label. Send the sentinel the program acts
            // on, and report what will actually happen.
            exec_off = 0;
            loader.override_global("EXEC_FILENAME_DATA_LOC", &exec_off, false);
            warn!(
                offset = off,
                "sched_process_exec puts `filename` past the {}-byte bound \
                 the program enforces; exec events will carry no filename",
                cfc_ebpf_common::TRACEPOINT_FIELD_OFFSET_MAX
            );
            report.notes.push(format!(
                "sched_process_exec filename offset {off} is past the \
                 program's {}-byte bound; exec events will carry no path, \
                 and attribution falls back to /proc",
                cfc_ebpf_common::TRACEPOINT_FIELD_OFFSET_MAX
            ));
            report.exec_offset = ExecOffset::Suppressed;
        }
        Ok(tracefs::Resolution::Parsed(off)) => {
            exec_off = off;
            // Unconditionally, not "only when it differs from the built-in 8".
            // Patching only the surprising case means the common case is never
            // exercised, so the day it stops being 8 is the day this code path
            // runs for the first time.
            loader.override_global("EXEC_FILENAME_DATA_LOC", &exec_off, false);
            if off != 8 {
                // On every kernel seen so far this is 8. A different value is
                // the single most interesting thing this parser can report.
                warn!(
                    offset = off,
                    "sched_process_exec puts `filename` somewhere new; \
                     patched it in"
                );
                report.notes.push(format!(
                    "sched_process_exec filename offset is {off}, not the usual 8"
                ));
            }
            report.exec_offset = ExecOffset::Parsed(off);
        }
        Ok(tracefs::Resolution::Unsupported) => {
            // This must reach the *kernel*. Noticing in userspace and leaving
            // the program to read offset 8 anyway would be byte-for-byte the
            // silent failure this change exists to remove.
            exec_off = 0;
            loader.override_global("EXEC_FILENAME_DATA_LOC", &exec_off, false);
            warn!(
                "this kernel's sched_process_exec record is not one we can read \
                 (__rel_loc, or an unexpected field width); exec events will \
                 carry no filename"
            );
            report.notes.push(
                "sched_process_exec filename field is in a form this build cannot \
                 read; exec events will carry no path, and attribution falls back \
                 to /proc"
                    .to_string(),
            );
            report.exec_offset = ExecOffset::Suppressed;
        }
        Err(e) => {
            // The compiled-in 8 stands. `debug!` and no note: notes are
            // escalated to warnings when the layer was asked for, and this
            // changes nothing on any kernel that exists - aya could not have
            // attached the tracepoint at all without reading a sibling of the
            // file we just failed to read.
            debug!("could not read the sched_process_exec format file ({e}); keeping the built-in offset");
            report.exec_offset = ExecOffset::Default;
        }
    }

    let mut bpf = loader
        .load(&object)
        .with_context(|| {
            format!(
                "loading {} (needs CAP_BPF + CAP_PERFMON; on kernels < 5.8, CAP_SYS_ADMIN)",
                object_path.display()
            )
        })
        .map_err(|e| LoadError::new(classify_load(&e), e))?;

    // --- attach, each independently ------------------------------------

    let exec_pin = pin_dir.as_deref().map(|d| d.join(enforce::LINK_EXEC));
    if let Some(p) = exec_pin.as_deref() {
        drop_stale_link_pin(p);
    }
    let mut exec_pinned = false;
    let r = attach_tracepoint(
        &mut bpf,
        PROG_EXEC,
        "sched",
        "sched_process_exec",
        exec_pin.as_deref(),
        &mut exec_pinned,
    );
    report.exec_tracking = record_attach(&mut report, PROG_EXEC, "sched_process_exec", r);

    // Both tracepoints are pinned, for different reasons: exec so a process
    // that starts without a daemon still gets a verdict, exit so the map it
    // writes cannot rot. Both are replaced rather than inherited on restart.
    let exit_pin = pin_dir.as_deref().map(|d| d.join(enforce::LINK_EXIT));
    if let Some(p) = exit_pin.as_deref() {
        drop_stale_link_pin(p);
    }
    let mut exit_pinned = false;
    let r = attach_tracepoint(
        &mut bpf,
        PROG_EXIT,
        "sched",
        "sched_process_exit",
        exit_pin.as_deref(),
        &mut exit_pinned,
    );
    report.exit_tracking = record_attach(&mut report, PROG_EXIT, "sched_process_exit", r);
    // Both clears have to survive this daemon for a grant to be safe past its
    // death, so this is one flag, not two.
    report.lifecycle_pinned = exec_pinned && exit_pinned;
    let r = attach_dns(&mut bpf);
    report.dns_capture = record_attach(&mut report, PROG_DNS, "cgroup_skb/ingress", r);

    // --- enforcement ----------------------------------------------------

    // Whether the kernel side of the fast path is in place: the cookie
    // connect variants plus both sendmsg programs. On the inherited path the
    // pin names do not say which connect variant is running, and the sendmsg
    // pins - made only after the cookie variants attached - are the evidence.
    let mut fast_path = enforce::FastPathCapability::BasicConnect;
    report.enforcement = if inherited {
        // Inherited pins do not say which connect variant is running; the
        // sendmsg pins, made only after the cookie variants attached, are the
        // evidence, and their absence could be either reason. So say neither:
        // this used to report `BasicConnect`, whose reason names a cause -
        // "no bpf_get_socket_cookie on sock_addr programs" - that nothing on
        // this path established.
        fast_path = if pin_dir.as_deref().is_some_and(enforce::fast_path_attached) {
            enforce::FastPathCapability::Ready
        } else {
            enforce::FastPathCapability::Inconclusive
        };
        report.notes.push(format!(
            "in-kernel enforcement was already attached and pinned at {}; \
             steering it rather than replacing it",
            pin_dir.as_deref().unwrap_or(Path::new("?")).display()
        ));
        Enforcement::Inherited
    } else {
        match enforce::attach(&mut bpf, pin_dir.as_deref()) {
            Ok(attached) => {
                fast_path = attached.fast_path;
                for (name, insns) in attached.programs {
                    if let Some(n) = insns {
                        report.verified_insns.push((name, n));
                    }
                }
                if pin_dir.is_some() {
                    Enforcement::Pinned
                } else {
                    Enforcement::Process
                }
            }
            Err(e) => {
                report
                    .notes
                    .push(format!("cgroup/connect4|6 not attached: {e:#}"));
                report.degrade.get_or_insert(classify_verify(&e));
                Enforcement::Unavailable
            }
        }
    };

    // The socket-cookie -> pid map, for O(1) attribution - the pinned one
    // when there is a pin directory, which is what lets an inherited connect
    // program's writes land somewhere this daemon can read. Taken whenever it
    // exists: with the `_basic` fallback attached nothing writes it and every
    // lookup simply misses, which costs one syscall before the walk the caller
    // was going to do anyway. A OnceLock because attribution is called from
    // the NFQUEUE worker thread, far from anything that could carry a handle.
    if report.enforcement.is_live() {
        if let Some(map) = bpf.take_map(enforce::MAP_SOCK_PIDS) {
            match aya::maps::HashMap::<_, u64, u32>::try_from(map) {
                Ok(m) => {
                    let _ = super::sock_pids::HANDLE.set(m);
                }
                Err(e) => report
                    .notes
                    .push(format!("{} unusable: {e}", enforce::MAP_SOCK_PIDS)),
            }
        }
        // The one restart the pin cannot rescue: pins made before SOCK_PIDS
        // joined `pinned_map_paths` hold everything *except* it, so the
        // inherited programs go on writing the anonymous map they captured at
        // their own load, which no fd in this process can reach. Detected and
        // said out loud rather than repaired - replacing the inherited attach
        // to fix attribution would open an enforcement gap, which is the
        // wrong trade - and bpffs does not survive a reboot, so the state
        // heals itself.
        if inherited && !sock_pids_was_pinned {
            report.notes.push(
                "the inherited enforcement predates the SOCK_PIDS pin: its \
                 cookie->pid writes land in a map this daemon cannot open, so \
                 attribution falls back to the /proc walk until the pins are \
                 remade (a reboot, or remove /sys/fs/bpf/colony-firewall and \
                 restart the daemon)"
                    .to_string(),
            );
        }
    }

    // Counters are non-zero at startup only when a previous daemon's pinned
    // programs kept working while this one was not running - which is the whole
    // claim this layer makes, so it is worth stating rather than leaving to be
    // inferred from a quiet log.
    if report.enforcement.is_live() {
        match bpf
            .map(enforce::MAP_STATS)
            .ok_or_else(|| anyhow!("no map named `{}`", enforce::MAP_STATS))
            .and_then(|m| aya::maps::PerCpuArray::<_, u64>::try_from(m).map_err(Into::into))
            .and_then(|m| enforce::stats(&m))
        {
            // Every counter, in the guard and in the message. Two of them
            // used to be read and then left out of both, so the one state an
            // operator most wants named - a foreign mark keeping the fast path
            // permanently disengaged for some program - could not be reached
            // from the note at all.
            Ok(s)
                if s.denied > 0
                    || s.allowed > 0
                    || s.unknown > 0
                    || s.stale > 0
                    || s.foreign_mark > 0
                    || s.report_dropped > 0 =>
            {
                report.notes.push(format!(
                    "in-kernel enforcement carried over: {} connect() refused, \
                     {} fast-allowed, {} passed to the packet path, {} grants \
                     ignored as stale, {} sockets left alone for carrying \
                     another marker's mark, {} decisions the report ring could \
                     not hold, since the pins were made",
                    s.denied, s.allowed, s.unknown, s.stale, s.foreign_mark, s.report_dropped
                ))
            }
            Ok(_) => {}
            Err(e) => report
                .notes
                .push(format!("enforcement counters unreadable: {e:#}")),
        }
    }

    // Evict verdicts for pids that no longer exist. This has to run before the
    // daemon writes anything: while it was down nothing evicted, so a recycled
    // pid would otherwise inherit the previous holder's answer. See
    // `enforce::sweep`.
    if report.enforcement.is_live() {
        match bpf.map_mut(enforce::MAP_VERDICTS) {
            Some(map) => match BpfHashMap::<_, u32, u32>::try_from(map) {
                Ok(mut verdicts) => {
                    let n = enforce::sweep(&mut verdicts);
                    if n > 0 {
                        debug!("evicted {n} verdicts for pids that no longer exist");
                    }
                }
                Err(e) => report
                    .notes
                    .push(format!("{} is not a hash map: {e}", enforce::MAP_VERDICTS)),
            },
            None => report.notes.push(format!(
                "no map named `{}` in the object",
                enforce::MAP_VERDICTS
            )),
        }
    }

    // The handle the exec consumer writes verdicts through. Absent when
    // enforcement did not come up, or when the caller has no rule engine to
    // consult (the live tests); in both cases the map simply stays empty and
    // every connect falls through to the packet path.
    // The mark the kernel side was armed with, when it was: the heartbeat
    // task below needs it to finish the nftables half of arming.
    let mut armed_mark: Option<u32> = None;
    let sink = match (report.enforcement.is_live(), engine) {
        (true, Some(engine)) => {
            match enforce::VerdictSink::new(&mut bpf, engine.clone(), table.clone()) {
                Ok(mut sink) => {
                    // Whatever the previous daemon granted, it granted under
                    // its rules. The map is pinned, so those grants are still
                    // here; nothing below writes a grant until this is done.
                    let dropped = sink.flush_fast_allow();
                    if dropped > 0 {
                        debug!(
                            "dropped {dropped} fast-allow grants inherited from a previous daemon"
                        );
                    }

                    // Every reason the fast path stays off, in the order a
                    // reader can act on. Each is the one sentence `cfc status`
                    // will show.
                    let off = if !fast_allow.on {
                        Some("[ebpf] fast_allow is not set")
                    } else if !sink.has_fast_path() {
                        // Not reachable by an *old* object: the loader
                        // requires the v4 ABI symbol with must_exist, and the
                        // fast path arrived with that bump. What is left is an
                        // object built from a tree with the maps taken out, so
                        // the reason names the maps rather than a version.
                        Some("the loaded object has no fast-allow maps")
                    } else if !matches!(
                        report.enforcement,
                        Enforcement::Pinned | Enforcement::Inherited
                    ) {
                        // A Process-mode link dies with the daemon and takes
                        // the exit eviction with it; a stale grant would then
                        // have nothing but the deadline standing between it
                        // and a recycled pid.
                        Some("enforcement is not pinned to bpffs")
                    } else if !report.exit_tracking {
                        Some("process exit is not tracked on this kernel")
                    } else if !report.exit_precise {
                        // Leader-only exit detection leaks in the fail-closed
                        // direction for denies and the fail-open one for
                        // grants.
                        //
                        // Split from the condition above, which it used to
                        // share: one reason string served two different facts,
                        // so an exit tracepoint that simply failed to attach
                        // was reported to the operator as a kernel that has no
                        // readable `group_dead` - sending them to look at their
                        // kernel version for a problem that was in the notes.
                        Some("process exit is not detected exactly on this kernel (no readable group_dead)")
                    } else if !report.lifecycle_pinned {
                        // Attached is not pinned. The connect programs' links
                        // are pinned and go on marking sockets after this
                        // daemon dies; if the exec and exit links are not, the
                        // clears that make a grant safe die with it, and the
                        // deadline is all that is left.
                        Some("the exec/exit tracepoint links could not be pinned to bpffs, so their clears would not survive this daemon")
                    } else {
                        fast_path.off_reason()
                    };

                    let (state, mark_opt) = match off {
                        Some(why) => {
                            sink.withdraw_fast_path();
                            (FastAllow::Off(why.to_string()), None)
                        }
                        None => match arm_kernel_side(&sink, fast_allow.mark) {
                            Ok(mark) => (nft_arm_state(mark), Some(mark)),
                            Err(e) => {
                                sink.withdraw_fast_path();
                                (FastAllow::Off(format!("could not arm: {e:#}")), None)
                            }
                        },
                    };
                    report.fast_allow = Some(state);
                    armed_mark = mark_opt;

                    let sink = std::sync::Arc::new(sink);
                    // resync rather than compile_rules alone: on the inherited
                    // path the pinned map holds the previous daemon's
                    // verdicts, made under the previous daemon's rules, and
                    // this is the reconciliation that makes them this
                    // daemon's.
                    //
                    // Which of its parts does that work is worth being exact
                    // about, because a comment here once claimed the orphan
                    // sweep did all of it and that was only half true. The
                    // proc table is empty at this point - `set_live` has not
                    // run yet - so the live loop no-ops, and the orphan sweep
                    // reconciles the *denials* the previous daemon left in
                    // `VERDICTS`. It cannot reconcile grants: `flush_fast_allow`
                    // above has just emptied the map the sweep would walk, on
                    // purpose. Re-seeding the grants is `sweep_fast_allow`'s
                    // job, at the end of `resync`, and it walks /proc rather
                    // than any map - which is the only way to reach a process
                    // that was already running when this daemon started.
                    sink.resync();
                    let weak = std::sync::Arc::downgrade(&sink);
                    engine.set_on_change(Box::new(move || {
                        if let Some(sink) = weak.upgrade() {
                            sink.resync();
                        }
                    }));
                    Some(sink)
                }
                Err(e) => {
                    report
                        .notes
                        .push(format!("in-kernel verdicts will not be written: {e:#}"));
                    None
                }
            }
        }
        _ => None,
    };
    if report.fast_allow.is_none() {
        report.fast_allow = Some(FastAllow::Off(
            if report.enforcement.is_live() {
                "no decision engine was handed to the layer"
            } else {
                "in-kernel enforcement is not live"
            }
            .to_string(),
        ));
    }

    // Published here, and only here, because after this point the heartbeat
    // task below is running and publishing states of its own.
    //
    // `start` used to do it, once `load_and_attach` returned - which is *after*
    // that task exists. On a daemon restart the table is already loaded, so the
    // very first thing the heartbeat does is arm and publish `Live`; `start`
    // then overwrote it with the state decided here, "waiting for the nftables
    // table". And nothing ever corrected it: the heartbeat only publishes while
    // it is not armed. `cfc status` said the fast path was waiting for a table
    // that had been there all along, for the life of the daemon, while the path
    // was in fact live.
    if let Some(state) = report.fast_allow.clone() {
        super::set_fast_allow_level(state);
    }

    // Exec without exit tracking would let entries age out on the TTL alone,
    // which is a materially weaker pid-reuse story. Refuse the combination
    // rather than quietly serving it.
    if report.exec_tracking && !report.exit_tracking {
        report.notes.push(
            "exit tracking is unavailable, so exec records could outlive their processes; \
             disabling kernel-sourced process identity"
                .to_string(),
        );
        report.exec_tracking = false;
    }

    // --- consumers -----------------------------------------------------
    //
    // Maps are taken *after* attaching, so a failed attach never leaves a
    // consumer reading a buffer nothing writes to.

    let mut tasks = Vec::new();
    if report.exec_tracking {
        let t = table.clone();
        let sink_exec = sink.clone();
        match spawn_ring(&mut bpf, MAP_EXEC, move |bytes| {
            if let Some(event) = decode::<ExecEvent>(bytes) {
                // Bind the record to /proc/<pid>/stat's start time while the
                // process is (almost certainly) still alive. That single small
                // read is what makes pid reuse detectable later; see
                // `proc_table`. It runs on this task, never on the packet path.
                let starttime = crate::process_resolve::read_starttime(event.pid);
                t.observe_exec(&event, starttime, Instant::now());
                // Precompute the in-kernel answer for this pid, if the rules
                // have one that does not depend on a destination. Runs here,
                // on the exec task, and never on the packet path.
                if let Some(sink) = &sink_exec {
                    sink.on_exec(event.pid, &exec_process(&event));
                }
            }
        }) {
            Ok(task) => tasks.push(task),
            Err(e) => {
                report
                    .notes
                    .push(format!("{MAP_EXEC} consumer not started: {e:#}"));
                report.exec_tracking = false;
            }
        }
    }

    if report.exec_tracking && report.exit_tracking {
        let t = table.clone();
        let sink_exit = sink.clone();
        match spawn_ring(&mut bpf, MAP_EXIT, move |bytes| {
            if let Some(event) = decode::<ExitEvent>(bytes) {
                t.observe_exit(event.pid);
                // The verdict map is pinned, so an entry the daemon forgets
                // outlives the daemon. Evicting here is what stops a recycled
                // pid inheriting a dead process's answer.
                if let Some(sink) = &sink_exit {
                    sink.on_exit(event.pid);
                }
            }
        }) {
            Ok(task) => tasks.push(task),
            Err(e) => {
                // Same reasoning as above: no eviction stream, no kernel
                // identity.
                report
                    .notes
                    .push(format!("{MAP_EXIT} consumer not started: {e:#}"));
                report.exec_tracking = false;
                report.exit_tracking = false;
            }
        }
    }

    // The eligibility ladder ran before any of the consumers above existed,
    // and two of them can retract what it assumed: a ring consumer that fails
    // to start turns `exec_tracking` off, and the exit one turns both off. So
    // the fast path could be armed, reported `live`, and marking sockets while
    // `on_exec` - its only per-execve writer - could never run, and while
    // nothing on the daemon side evicted a grant.
    //
    // Correct it here rather than moving the decision, because the decision
    // needs the sink and the sink is what these consumers borrow. Flush what
    // was granted, empty the set so the ruleset accepts nothing, and leave
    // `armed_mark` unset so the heartbeat task below is never spawned - with
    // no heartbeat the kernel stops honouring grants within one deadline, and
    // with no element in the set it stops mattering immediately.
    if armed_mark.is_some() && !(report.exec_tracking && report.exit_tracking) {
        let why = "the exec/exit ring consumers did not start, so nothing would grant or evict";
        warn!("fast-allow withdrawn after arming: {why}");
        if let Err(e) = super::nft_set::disarm() {
            report
                .notes
                .push(format!("could not flush the fast-allow set: {e:#}"));
        }
        if let Some(sink) = sink.as_ref() {
            sink.flush_fast_allow();
        }
        armed_mark = None;
        report.fast_allow = Some(FastAllow::Off(why.to_string()));
        super::set_fast_allow_level(FastAllow::Off(why.to_string()));
    }

    // Denials refused in the kernel never reach NFQUEUE, so this consumer is
    // the only thing standing between "CFC blocked it" and "the connection just
    // failed". It is a log line rather than a prompt on purpose: the user
    // already answered for this executable, and asking again is the behaviour
    // `72964b5` removed.
    if report.enforcement.is_live() {
        let t = table.clone();
        match spawn_ring(&mut bpf, enforce::MAP_DENY_EVENTS, move |bytes| {
            let Some(ev) = decode::<ConnectReport>(bytes) else {
                return;
            };
            let who = t
                .get(ev.pid, None, Instant::now())
                .map(|p| p.comm)
                .unwrap_or_else(|| "?".to_string());
            tracing::info!(
                pid = ev.pid,
                exe = %who,
                dst = %ev.destination(),
                "deny (kernel): connect() refused before a packet existed"
            );
        }) {
            Ok(task) => tasks.push(task),
            Err(e) => report.notes.push(format!(
                "{} consumer not started: {e:#}; in-kernel denials will be \
                 enforced but not reported",
                enforce::MAP_DENY_EVENTS
            )),
        }
    }

    // The fast path's two tasks, only while it is live: the heartbeat that
    // keeps the kernel honouring grants, and the consumer that keeps the
    // rest of the daemon honest about flows the packet path never sees.
    if let (Some(mark), Some(sink)) = (armed_mark, sink.as_ref()) {
        // Heartbeat, and the nftables side of arming. The two are one task on
        // purpose: `colony-firewall-nft.service` is After= this daemon and
        // waits for it to be active, so at daemon start the table is not
        // loaded yet and the set cannot be written - on every boot, not as
        // an edge case. The kernel side is armed (mark written) but the
        // deadline stays zero, so nothing is honoured, until the element is
        // in the set; then every tick refreshes the deadline. If this task
        // ever stops - abort on shutdown, a wedged runtime, the daemon dying
        // - the kernel stops honouring grants within one deadline. That is
        // the design, not a failure mode.
        let beat = sink.clone();
        let mut armed = matches!(report.fast_allow, Some(FastAllow::Live));
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                cfc_ebpf_common::fast_allow::HEARTBEAT_SECS,
            ));
            let mut last_reason: Option<String> = None;
            // Ticks between two checks that the set still holds the mark.
            const CHECKS_EVERY: u8 = 6;
            let mut since_check: u8 = 0;
            loop {
                tick.tick().await;
                if !armed {
                    // Off the async threads: this execs nft and waits on it.
                    let attempt = tokio::task::spawn_blocking(move || super::nft_set::arm(mark))
                        .await
                        .unwrap_or_else(|e| Err(anyhow!("arming task failed: {e}")));
                    let state = match attempt {
                        Ok(()) => {
                            armed = true;
                            tracing::info!(
                                "fast-allow armed: the nftables set now holds this daemon's mark"
                            );
                            FastAllow::Live
                        }
                        Err(e) => nft_arm_state_from_error(&e),
                    };
                    // Say each reason once, not every ten seconds.
                    let reason = state.describe();
                    if last_reason.as_deref() != Some(reason.as_str()) {
                        if !armed {
                            tracing::info!("fast-allow {reason}");
                        }
                        last_reason = Some(reason);
                    }
                    super::set_fast_allow_level(state);
                    if !armed {
                        continue;
                    }
                }
                if let Err(e) = beat.beat() {
                    tracing::warn!(
                        "fast-allow heartbeat failed: {e:#}; grants lapse within a minute"
                    );
                }

                // Armed is not a fact that stays true, and this loop used to
                // treat it as one: once the element went in, the only thing it
                // ever did again was refresh the deadline. `systemctl restart
                // nftables`, or any `nft -f` that reloads the machine's
                // ruleset, recreates `table inet colony_firewall` with an
                // empty set - and the daemon went on marking sockets, went on
                // crediting rule hits from ALLOW_EVENTS, and went on telling
                // `cfc status` that the fast path was live, while every one of
                // those flows was in fact taking the queue and being counted
                // a second time by the packet path.
                //
                // Checked every sixth tick rather than every tick: this is a
                // fork and exec, the window it leaves is a minute of an
                // over-optimistic status line, and nothing unsafe happens in
                // it - the failure is the set accepting *less* than the daemon
                // thinks, never more.
                since_check += 1;
                if since_check >= CHECKS_EVERY {
                    since_check = 0;
                    match tokio::task::spawn_blocking(move || super::nft_set::holds(mark)).await {
                        Ok(Ok(true)) => {}
                        Ok(Ok(false)) => {
                            armed = false;
                            last_reason = None;
                            tracing::warn!(
                                "the fast-allow mark is no longer in the nftables set (the \
                                 ruleset was reloaded); re-arming"
                            );
                            super::set_fast_allow_level(FastAllow::Off(
                                "the nftables set no longer holds this daemon's mark; re-arming"
                                    .to_string(),
                            ));
                        }
                        // Could not ask. Say nothing and keep the current
                        // state: a failed probe is not evidence either way,
                        // and disarming on it would take the path down on a
                        // transient.
                        Ok(Err(e)) => tracing::debug!("could not check the fast-allow set: {e:#}"),
                        Err(e) => tracing::debug!("fast-allow set check did not run: {e}"),
                    }
                }
            }
        }));

        // ALLOW_EVENTS: one record per flow the kernel waved past the queue.
        // Credited to the rule that granted, counted where NFQUEUE counts,
        // and fed to the same observed stream - so the busiest allow rule
        // does not read as dead and the enforcing heuristic does not flip
        // to "not enforcing" while the firewall is doing its job.
        let credit = sink.clone();
        let engine_hits = sink.engine().clone();
        let observed_tx = observed.clone();
        let stats_tx = stats.clone();
        // The same reverse-DNS seam the packet path uses. Without it a
        // fast-allowed flow is the one kind of connection whose destination
        // never gets a name: the packet path attaches whatever is cached and
        // enqueues a lookup for next time, and this consumer - which exists
        // precisely because these flows never reach that path - did neither.
        // So `cfc log` and the live feed showed bare addresses for exactly the
        // programs a user had trusted enough to allow outright, and the cache
        // was never warmed for their destinations either, so the *next* flow
        // to the same host had no name to attach.
        let dns_hosts = dns.clone();
        match spawn_ring(&mut bpf, enforce::MAP_ALLOW_EVENTS, move |bytes| {
            let Some(ev) = decode::<ConnectReport>(bytes) else {
                return;
            };
            stats_tx.record_allow();
            let verdict = match credit.granted_by(ev.pid) {
                Some(rule) => {
                    engine_hits.record_hit(rule);
                    cfc_core::Verdict::from_rule(cfc_core::Action::Allow, rule)
                }
                // A grant this daemon did not make (a previous one's, in the
                // window before the startup flush). Reported, credited to no
                // rule rather than to the wrong one.
                None => cfc_core::Verdict::from_policy(cfc_core::Action::Allow),
            };
            let protocol = match ev.protocol {
                6 => cfc_core::Protocol::Tcp,
                17 => cfc_core::Protocol::Udp,
                other => cfc_core::Protocol::Other(other),
            };
            let unspecified = if ev.family == 4 {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            };
            let dst = ev.destination();
            let mut connection = cfc_core::Connection::new(
                protocol,
                cfc_core::Direction::Outbound,
                unspecified,
                0,
                dst.ip(),
                dst.port(),
            );
            if let Some(host) = dns_hosts.lookup_cached(dst.ip()) {
                connection = connection.with_host(host);
            }
            dns_hosts.enqueue_lookup(dst.ip());
            let process = crate::process_resolve::resolve(ev.pid);
            let _ = observed_tx.send(crate::nfqueue::ObservedConnection {
                connection,
                process,
                verdict,
            });
        }) {
            Ok(task) => tasks.push(task),
            Err(e) => report.notes.push(format!(
                "{} consumer not started: {e:#}; fast-allowed flows will be \
                 unreported and their rules uncredited",
                enforce::MAP_ALLOW_EVENTS
            )),
        }
    }

    if report.dns_capture {
        let cache = dns.clone();
        // One scratch answer for the life of the consumer. `for_each_answer`
        // rewrites every field it reports, and the 276-byte buffer is the only
        // thing the parser needs, so there is no per-record allocation here.
        let mut scratch = DnsAnswer::zeroed();
        match spawn_ring(&mut bpf, MAP_DNS, move |bytes| {
            let Some(packet) = decode::<DnsPacket>(bytes) else {
                return;
            };
            let payload = packet.payload();
            if payload.len() < DNS_HEADER_LEN {
                // The kernel gates on this too; a record this short means a
                // truncated write, not a short DNS message.
                debug!(len = payload.len(), "DNS record too short to parse");
                return;
            }
            // The whole DNS parse happens here, in userspace, because it could
            // not happen in the kernel: see `crates/cfc-ebpf/README.md`. It is
            // bounded by construction - `MAX_ANSWERS` records, `MAX_LABELS`
            // labels each, `MAX_LABEL_JUMPS` backwards-only compression jumps -
            // so a hostile packet costs a fixed, small amount of work on this
            // task and nothing at all on the packet path.
            let mut observed = 0u32;
            let emitted = dns::for_each_answer(&DnsCursor::new(payload), &mut scratch, |answer| {
                let name = answer.name_str();
                if name.is_empty() {
                    return;
                }
                observed += 1;
                cache.observe_answer(answer.ip_addr(), &name, answer.ttl);
            });
            debug!(
                bytes = payload.len(),
                emitted, observed, "parsed observed DNS response"
            );
        }) {
            Ok(task) => tasks.push(task),
            Err(e) => {
                report
                    .notes
                    .push(format!("{MAP_DNS} consumer not started: {e:#}"));
                report.dns_capture = false;
            }
        }
    }

    Ok((
        Attached {
            _bpf: bpf,
            tasks,
            _sink: sink,
        },
        report,
    ))
}

/// Folds one attach outcome into the report and says whether it is live.
///
/// The first classified failure wins `report.degrade` and later ones do not
/// overwrite it: when three attaches fail it is almost always for one reason,
/// and the first is the one that explains the rest.
fn record_attach(
    report: &mut Report,
    program: &str,
    what: &str,
    result: anyhow::Result<Option<u32>>,
) -> bool {
    match result {
        Ok(insns) => {
            if let Some(n) = insns {
                report.verified_insns.push((program.to_string(), n));
            }
            true
        }
        Err(e) => {
            let degrade = classify_verify(&e);
            report.notes.push(format!("{what} not attached: {e:#}"));
            report.degrade.get_or_insert(degrade);
            false
        }
    }
}

/// Returns the instruction count the verifier walked, when the kernel reports
/// it (>= 5.16).
fn attach_tracepoint(
    bpf: &mut Ebpf,
    name: &str,
    category: &str,
    event: &str,
    pin: Option<&Path>,
    pinned_out: &mut bool,
) -> anyhow::Result<Option<u32>> {
    let prog: &mut TracePoint = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("no program named `{name}` in the object"))?
        .try_into()
        .with_context(|| format!("`{name}` is not a tracepoint program"))?;
    // This, not `EbpfLoader::load`, is where BPF_PROG_LOAD runs and where the
    // verifier speaks. Classification of the error belongs to the caller.
    prog.load().context("verifier rejected the program")?;
    let insns = verifier_cost(name, prog.info());
    let id = prog
        .attach(category, event)
        .with_context(|| format!("attaching to {category}:{event}"))?;

    let Some(pin) = pin else {
        *pinned_out = false;
        return Ok(insns);
    };

    // Pinning is best-effort, and making that true takes work, because the
    // obvious spelling of it is a trap.
    //
    // `take_link` hands ownership out of aya's registry, and *both* failure
    // paths below then consume what they were given: aya's `TryFrom<_> for
    // FdLink` does `value.into_inner()` and drops the value on the non-fd
    // branch, and `FdLink::pin` takes `self` by value. So a link that cannot be
    // pinned - an older kernel without `BPF_LINK_TYPE_PERF_EVENT`, or a
    // read-only /sys/fs/bpf, which is exactly the systemd behaviour this
    // project has already been bitten by - is not merely left unpinned. It is
    // closed, and the tracepoint is detached.
    //
    // That would be strictly worse than not pinning at all: nothing would evict
    // `VERDICTS` or `PROCS` *while the daemon runs*, which is the rot this
    // whole change exists to prevent, and it would happen on the failure path
    // that was supposed to be harmless.
    //
    // So a failed pin re-attaches. Losing the pin then costs only the "keeps
    // evicting after the daemon dies" property, which is what best-effort was
    // meant to mean.
    //
    // `pinned_out` carries that outcome to the caller, because one feature does
    // depend on it. The fast path's eligibility ladder asks for `Pinned`
    // enforcement and exit tracking, on the reasoning that a grant is always
    // cleared even if the daemon dies - and that reasoning is the *pin's*, not
    // the attach's. On a kernel with no BPF_LINK_TYPE_PERF_EVENT the connect
    // programs stay pinned and go on marking sockets while the exec and exit
    // clears die with the daemon, which the ladder could not see because this
    // function used to return the same `Ok` either way.
    let pinned = prog
        .take_link(id)
        .map_err(anyhow::Error::new)
        .and_then(|link| {
            let fd_link: FdLink = link
                .try_into()
                .map_err(anyhow::Error::new)
                .context("link is not fd-based (needs a kernel with bpf_link perf support)")?;
            fd_link
                .pin(pin)
                .map_err(anyhow::Error::new)
                .with_context(|| format!("pinning to {}", pin.display()))
        });
    *pinned_out = pinned.is_ok();
    match pinned {
        Ok(_) => debug!(program = name, path = %pin.display(), "tracepoint link pinned"),
        Err(e) => {
            // The link is gone; put the program back on the tracepoint.
            prog.attach(category, event).with_context(|| {
                format!(
                    "could not pin the tracepoint link ({e}), and re-attaching                      after it failed too"
                )
            })?;
            warn!(
                program = name,
                "could not pin the tracepoint link ({e}); re-attached unpinned, \
                 so eviction works normally while this daemon runs and stops \
                 when it exits - a machine left on a dead daemon can then \
                 accumulate stale denials on recycled pids"
            );
        }
    }
    Ok(insns)
}

/// Removes a stale tracepoint pin, detaching whatever it still holds.
///
/// See [`enforce::LINK_EXIT`]: the pin exists to cover the gap between two
/// daemons, not to be inherited across it. The program behind it references the
/// previous run's `PROCS` and `EXIT_EVENTS`, both rebuilt on every start, so
/// adopting it would leave the new daemon's tables uncleaned.
fn drop_stale_link_pin(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => debug!(path = %path.display(), "removed a previous run's tracepoint pin"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            path = %path.display(),
            "could not remove the previous tracepoint pin ({e}); the old program \
             stays attached alongside the new one"
        ),
    }
}

/// Logs how many instructions the verifier walked to accept a program.
///
/// Worth a line because that number is a *budget*: the kernel gives a program
/// 1,000,000 and rejects it at 1,000,001, and the DNS observer used to be on
/// the wrong side of that (see `crates/cfc-ebpf/README.md`). Logging it turns
/// "a change made the program more expensive" into something visible before it
/// becomes "the program stopped loading on someone else's kernel".
pub(super) fn verifier_cost(
    name: &str,
    info: Result<aya::programs::ProgramInfo, ProgramError>,
) -> Option<u32> {
    match info {
        // `None` on kernels before 5.16, which do not report the count.
        Ok(info) => info.verified_instruction_count(),
        Err(e) => {
            debug!(
                program = name,
                "verified instruction count unavailable: {e}"
            );
            None
        }
    }
}

/// Attaches the DNS observer to the cgroup v2 root, which is what makes it
/// system-wide: every task is in some descendant of it.
fn attach_dns(bpf: &mut Ebpf) -> anyhow::Result<Option<u32>> {
    let root = cgroup::v2_root()
        .ok_or_else(|| anyhow!("no cgroup2 mount in /proc/mounts (unified hierarchy required)"))?;
    // Read-only is enough: the kernel wants the cgroup's fd as an attach
    // target, not write access to the directory. That matters because the
    // shipped unit sets ProtectControlGroups=true, which makes cgroupfs
    // read-only for the daemon.
    let dir = std::fs::File::open(&root)
        .with_context(|| format!("opening cgroup v2 root {}", root.display()))?;
    let prog: &mut CgroupSkb = bpf
        .program_mut(PROG_DNS)
        .ok_or_else(|| anyhow!("no program named `{PROG_DNS}` in the object"))?
        .try_into()
        .with_context(|| format!("`{PROG_DNS}` is not a cgroup_skb program"))?;
    prog.load().context("verifier rejected the program")?;
    let insns = verifier_cost(PROG_DNS, prog.info());
    prog.attach(
        dir.as_fd(),
        CgroupSkbAttachType::Ingress,
        // `Single` rather than `AllowMultiple`: this is the root cgroup, and
        // silently stacking a second copy of the observer on a restart that
        // failed to clean up would double every answer.
        CgroupAttachMode::Single,
    )
    .map_err(|e| {
        // `Single` on an already-claimed slot answers EEXIST. Left to the
        // generic context below it reads as "no cgroup2", which sends whoever
        // is debugging it to look at mounts instead of at the program that
        // actually holds the slot.
        let taken = anyhow::Error::new(e);
        if errno_of(&taken) == Some(libc::EEXIST) {
            taken.context(format!(
                "another program already holds the exclusive cgroup_skb/ingress \
                 slot on {}; observed DNS answers are unavailable while it does",
                root.display()
            ))
        } else {
            taken.context(format!(
                "attaching cgroup_skb/ingress to {}",
                root.display()
            ))
        }
    })?;
    Ok(insns)
}

/// The exec-time view of a process, for rule matching only.
///
/// Deliberately thin. `sha256`, `cmdline`, `cwd` and provenance all cost a file
/// read or a package-database lookup, and this runs on every `execve` on the
/// machine; the packet path builds the full [`Process`] when it actually needs
/// one. `RuleScope::undecidable_for` is what keeps the missing hash from
/// turning into a wrong answer rather than an absent one.
fn exec_process(event: &ExecEvent) -> Process {
    Process {
        pid: event.pid,
        // The kernel side reports 0 for "unresolved", never for a real parent.
        ppid: (event.ppid != 0).then_some(event.ppid),
        uid: Some(event.uid),
        gid: Some(event.gid),
        exe: PathBuf::from(event.filename_str().into_owned()),
        ..Process::unknown(event.pid)
    }
}

/// Takes a ring-buffer map out of the object and starts a task that drains it.
///
/// `AsyncFd` is the pattern aya's own docs point at: `RingBuf` implements
/// `AsRawFd`, and the kernel makes the map fd readable when a record is
/// committed. Draining fully before clearing readiness is required - the fd is
/// edge-triggered, so a record left in the ring after `clear_ready` would not
/// wake us again until the *next* one arrived.
fn spawn_ring<F>(bpf: &mut Ebpf, name: &str, mut on_record: F) -> anyhow::Result<JoinHandle<()>>
where
    F: FnMut(&[u8]) + Send + 'static,
{
    let map = bpf
        .take_map(name)
        .ok_or_else(|| anyhow!("no map named `{name}` in the object"))?;
    let ring: RingBuf<MapData> = RingBuf::try_from(map)
        .with_context(|| format!("`{name}` is not a ring buffer (BPF_MAP_TYPE_RINGBUF)"))?;
    let mut fd = AsyncFd::new(ring).with_context(|| format!("registering `{name}` with tokio"))?;
    let name = name.to_string();

    Ok(tokio::spawn(async move {
        loop {
            let mut guard = match fd.readable_mut().await {
                Ok(g) => g,
                Err(e) => {
                    warn!("ring buffer `{name}` became unreadable, consumer stopping: {e}");
                    return;
                }
            };
            {
                let ring = guard.get_inner_mut();
                while let Some(record) = ring.next() {
                    on_record(&record);
                }
            }
            guard.clear_ready();
        }
    }))
}

/// Copies a POD event out of a ring-buffer record.
///
/// The types come from `cfc-ebpf-common`, which is compiled into both halves,
/// so the layout is the same by construction (and asserted by that crate's
/// tests). A record shorter than the struct is a truncated write and is
/// dropped rather than read past.
fn decode<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        debug!(
            got = bytes.len(),
            want = size_of::<T>(),
            "short ring-buffer record dropped"
        );
        return None;
    }
    // SAFETY: `T` is one of the `#[repr(C)]`, pointer-free, niche-free POD
    // event structs from `cfc-ebpf-common`; `bytes` is at least `size_of::<T>()`
    // bytes of initialised ring-buffer memory written by the kernel side from
    // the same type definition. `read_unaligned` makes no alignment
    // assumption about the ring, and the value is copied out before the
    // record's borrow ends.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::PermissionsExt as _;

    // --- the object-trust policy ----------------------------------------
    //
    // Exercised as pure functions rather than through the filesystem: the
    // interesting cases (root-owned, setgid, sticky) cannot all be created by
    // a test running as an ordinary user, and a policy that is only checked on
    // the machine that happens to be running the suite is not checked.

    #[test]
    fn only_root_owned_unwritable_files_are_trusted() {
        assert!(
            file_is_safe(0, 0o100644),
            "root:root 0644 is the target case"
        );
        assert!(file_is_safe(0, 0o100600));
        assert!(
            !file_is_safe(1000, 0o100644),
            "a user-owned object is not ours"
        );
        assert!(
            !file_is_safe(0, 0o100664),
            "group-writable lets the group swap it"
        );
        assert!(
            !file_is_safe(0, 0o100666),
            "world-writable lets anyone swap it"
        );
        // The sticky bit means nothing on a regular file and must not be
        // mistaken for the directory exemption below.
        assert!(!file_is_safe(0, 0o101666));
    }

    #[test]
    fn sticky_root_directories_are_trusted_but_plain_writable_ones_are_not() {
        assert!(dir_is_safe(0, 0o040755));
        assert!(
            dir_is_safe(0, 0o041777),
            "/tmp: world-writable but sticky, so a non-root user still cannot \
             rename root's files"
        );
        assert!(
            !dir_is_safe(0, 0o040777),
            "world-writable without sticky is a rename away from a swapped object"
        );
        assert!(
            !dir_is_safe(1000, 0o040755),
            "a user-owned parent is enough"
        );
        assert!(!dir_is_safe(0, 0o040775), "group-writable counts too");
    }

    /// The regression this sieve exists for: kube-proxy selects on
    /// `0x8000/0x8000` and DROPs what matches. A uniformly random word has
    /// that bit set half the time, so on a Kubernetes node the previous
    /// draw broke every fast-allowed flow on roughly every other start.
    #[test]
    fn a_mark_sharing_a_bit_with_a_known_selector_is_refused() {
        assert_eq!(collides_with(0x0000_8000), Some("kube-proxy (drop)"));
        assert_eq!(collides_with(0xdead_8000), Some("kube-proxy (drop)"));
        assert_eq!(collides_with(0x0000_4000), Some("kube-proxy (masquerade)"));
        assert_eq!(collides_with(0x0008_0000), Some("Tailscale"));
        assert_eq!(collides_with(0x1208_0000), Some("Tailscale"));
        assert_eq!(collides_with(0x0004_0000), Some("Tailscale (bypass)"));
        // wg-quick's value is caught, though by kube-proxy's masquerade bit
        // rather than by its own entry: 0xca6c has bit 14 set. Its entry is
        // kept anyway - it documents the selector, and it is what would catch
        // the value if the kube-proxy masks ever moved.
        assert!(collides_with(0x0000_ca6c).is_some());

        // And values no selector here claims.
        assert_eq!(collides_with(0x0000_0a6c), None);
        assert_eq!(collides_with(0x0003_3331), None);
    }

    #[test]
    fn a_drawn_mark_is_never_unarmed_and_never_collides() {
        // A deterministic walk over the space rather than a real rng: the
        // property is about the sieve, and a test that draws randomly would
        // pass or fail randomly.
        let mut seed = 0x1234_5678u32;
        let mut draw = || {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            seed
        };
        for _ in 0..2000 {
            let mark = pick_mark(&mut draw).expect("a healthy source always yields one");
            assert_ne!(mark, cfc_ebpf_common::fast_allow::UNARMED);
            assert_eq!(
                collides_with(mark),
                None,
                "drew a colliding mark 0x{mark:08x}"
            );
        }
    }

    /// A source that only ever offers unusable values must not hang the
    /// daemon - and must not be answered with a *constant* either, which is
    /// what an earlier fallback did: a value that does not depend on the draw
    /// is the same on every machine that reaches it, which is the published
    /// bypass token the random draw exists to avoid. Refusing leaves the fast
    /// path off, which is where it degrades to anyway.
    #[test]
    fn a_degenerate_draw_arms_nothing_rather_than_a_constant() {
        assert_eq!(pick_mark(|| 0x0000_8000), None);
        assert_eq!(pick_mark(|| cfc_ebpf_common::fast_allow::UNARMED), None);
    }

    #[test]
    fn a_world_writable_object_is_refused_but_only_under_refuse() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cfc-ebpf.o");
        std::fs::write(&path, b"not an ELF").expect("write");
        // 0666 rather than relying on ownership: this test has to give the
        // same answer whether the suite is run as root or as a user.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");

        let refused = load_and_attach(
            &path,
            DnsCache::new(),
            KernelProcTable::new(),
            None,
            Trust::Refuse,
            tokio::sync::broadcast::channel(8).0,
            crate::stats::Stats::new(),
            Default::default(),
        )
        .err()
        .expect("a world-writable object must not be loaded");
        assert_eq!(refused.degrade, Degrade::ObjectUntrusted);

        // Under `Warn` the same file gets past the check and fails later, on
        // its own merits -- it is not an ELF. The point is that the trust
        // check is what changed, and nothing else.
        let warned = load_and_attach(
            &path,
            DnsCache::new(),
            KernelProcTable::new(),
            None,
            Trust::Warn,
            tokio::sync::broadcast::channel(8).0,
            crate::stats::Stats::new(),
            Default::default(),
        )
        .err()
        .expect("`not an ELF` cannot load either way");
        assert_ne!(
            warned.degrade,
            Degrade::ObjectUntrusted,
            "Trust::Warn must have let it past the ownership check"
        );
    }

    #[test]
    fn an_absent_object_is_missing_not_untrusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Even under `Refuse`: "nobody installed the object" is the ordinary
        // outcome on most hosts, and filing it as a trust failure would turn
        // the commonest case on earth into a security-looking log line.
        let e = load_and_attach(
            &dir.path().join("absent.o"),
            DnsCache::new(),
            KernelProcTable::new(),
            None,
            Trust::Refuse,
            tokio::sync::broadcast::channel(8).0,
            crate::stats::Stats::new(),
            Default::default(),
        )
        .err()
        .expect("there is no object there");
        assert_eq!(e.degrade, Degrade::ObjectMissing);
    }

    #[test]
    fn decode_rejects_short_records() {
        assert!(decode::<ExecEvent>(&[0u8; 8]).is_none());
        assert!(decode::<ExitEvent>(&[0u8; 3]).is_none());
        assert!(decode::<DnsAnswer>(&[]).is_none());
        assert!(decode::<DnsPacket>(&[0u8; 16]).is_none());
    }

    /// The consumer's own arithmetic, without a kernel: a `DnsPacket` as the
    /// BPF program would write it, decoded and parsed the way the ring-buffer
    /// task does it.
    #[test]
    fn a_dns_packet_record_decodes_and_parses() {
        let wire = synthetic_dns_response("cache.example", Ipv4Addr::new(198, 51, 100, 7), 120);
        let mut packet = DnsPacket::zeroed();
        packet.data[..wire.len()].copy_from_slice(&wire);
        packet.len = wire.len() as u16;

        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&packet).cast::<u8>(),
                std::mem::size_of::<DnsPacket>(),
            )
        };
        let got: DnsPacket = decode(bytes).expect("record decodes");
        assert_eq!(got.payload(), &wire[..]);

        let mut scratch = DnsAnswer::zeroed();
        let mut seen = Vec::new();
        dns::for_each_answer(&DnsCursor::new(got.payload()), &mut scratch, |a| {
            seen.push((a.name_str().into_owned(), a.ip_addr(), a.ttl));
        });
        assert_eq!(
            seen,
            vec![(
                "cache.example".to_string(),
                std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                120
            )]
        );
    }

    /// A minimal NOERROR response: one question, one compressed `A` answer.
    ///
    /// Shared by the unit test above and by the live loopback capture in
    /// `loads_and_attaches_on_this_kernel`, so both exercise the same bytes.
    fn synthetic_dns_response(name: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&0xbeefu16.to_be_bytes()); // id
        p.extend_from_slice(&0x8180u16.to_be_bytes()); // QR | RD | RA, NOERROR
        p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        p.extend_from_slice(&1u16.to_be_bytes()); // ancount
        p.extend_from_slice(&0u16.to_be_bytes()); // nscount
        p.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&1u16.to_be_bytes()); // QTYPE  A
        p.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
                                                  // Answer: owner name as a compression pointer to the question, which is
                                                  // what every real resolver emits.
        p.extend_from_slice(&0xc00cu16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes()); // TYPE  A
        p.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        p.extend_from_slice(&ttl.to_be_bytes());
        p.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        p.extend_from_slice(&ip.octets());
        p
    }

    #[test]
    fn decode_round_trips_a_pod_event() {
        let mut e = ExecEvent::zeroed();
        e.pid = 4242;
        e.uid = 1000;
        e.filename[..4].copy_from_slice(b"/bin");
        e.filename_len = 4;
        // Same byte view the kernel would write into the ring.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&e).cast::<u8>(),
                std::mem::size_of::<ExecEvent>(),
            )
        };
        let got: ExecEvent = decode(bytes).unwrap();
        assert_eq!(got.pid, 4242);
        assert_eq!(got.uid, 1000);
        assert_eq!(got.filename_str(), "/bin");
    }

    #[test]
    fn decode_tolerates_a_longer_record() {
        // A future kernel-side struct that grew a tail must still decode its
        // known prefix rather than being dropped.
        let mut bytes = vec![0u8; std::mem::size_of::<ExitEvent>() + 16];
        bytes[..4].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(decode::<ExitEvent>(&bytes).unwrap().pid, 7);
    }

    /// The ceilings, compiled in rather than read from disk.
    ///
    /// `include_str!` and not `std::fs::read`: the qemu matrix runs this very
    /// binary inside a guest that has no source tree, so a runtime path would
    /// turn the check into a skip on exactly the kernels it exists to watch.
    const VERIFIER_BUDGET: &str = include_str!("../../../cfc-ebpf/verifier-budget.toml");

    /// Fails if any program cost more than its ceiling.
    ///
    /// The budget is 1,000,000 and `cfc_dns_ingress` has been over it before -
    /// it simply stopped loading, with no warning first. These ceilings are
    /// tripwires so that happens in the commit that caused it rather than on
    /// someone else's kernel.
    ///
    /// A program with no entry is a hard failure, not a pass: adding a program
    /// and forgetting its ceiling would silently leave the new one unwatched.
    fn assert_within_verifier_budget(measured: &[(String, u32)]) {
        // A three-line parse rather than a toml dependency: cfc-daemon has no
        // toml crate in its non-dev graph, and this file's shape is fixed.
        let mut section = String::new();
        let mut ceilings: Vec<(String, u32)> = Vec::new();
        for line in VERIFIER_BUDGET.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.to_string();
            } else if let Some(v) = line.strip_prefix("max") {
                let v = v.trim_start_matches([' ', '=']).trim();
                if let Ok(n) = v.parse::<u32>() {
                    ceilings.push((section.clone(), n));
                }
            }
        }
        assert!(
            !ceilings.is_empty(),
            "verifier-budget.toml parsed to nothing; the format changed"
        );

        for (program, insns) in measured {
            let max = ceilings
                .iter()
                .find(|(name, _)| name == program)
                .map(|(_, m)| *m)
                .unwrap_or_else(|| {
                    panic!(
                        "{program} has no ceiling in crates/cfc-ebpf/verifier-budget.toml; \
                         add one rather than leaving a program unwatched"
                    )
                });
            assert!(
                *insns <= max,
                "{program} cost {insns} verified instructions, over its ceiling of {max}. \
                 The kernel's own limit is 1,000,000 and this program has been over it \
                 before. Either the change is more expensive than intended, or the \
                 ceiling in crates/cfc-ebpf/verifier-budget.toml needs raising on purpose."
            );
            println!("budget: {program} = {insns} (max {max})");
        }
    }

    /// Capability bit numbers, from `include/uapi/linux/capability.h`.
    const CAP_DAC_OVERRIDE: u32 = 1;
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_SYS_PTRACE: u32 = 19;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_PERFMON: u32 = 38;
    const CAP_BPF: u32 = 39;

    /// The effective capability set of this process, from `/proc/self/status`.
    fn effective_caps() -> u64 {
        let status =
            std::fs::read_to_string("/proc/self/status").expect("reading /proc/self/status");
        let line = status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .expect("no CapEff line in /proc/self/status");
        u64::from_str_radix(line.trim(), 16).expect("CapEff is hex")
    }

    fn has_cap(set: u64, bit: u32) -> bool {
        set & (1u64 << bit) != 0
    }

    /// Proves what `systemd/colony-firewalld.service` claims: the five
    /// capabilities it grants are **enough**, and `CAP_SYS_ADMIN` is not
    /// needed. Until now that was a comment in a unit file.
    ///
    /// Run it as an ordinary user holding the unit's set:
    ///
    /// ```sh
    /// CAPS='+net_admin,+net_raw,+sys_ptrace,+bpf,+perfmon,+dac_override'
    /// cargo xtask build-ebpf
    /// cargo build -p cfc-daemon --tests --profile fast
    /// sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups \
    ///     --bounding-set "-all,${CAPS}" --inh-caps "$CAPS" --ambient-caps "$CAPS" \
    ///     env CFC_EBPF_OBJECT="$(cargo xtask ebpf-path)" \
    ///     ./target/fast/deps/cfc_daemon-<hash> --ignored --nocapture only_the_units_capabilities
    /// ```
    ///
    /// # Why `dac_override` is in that list and not in the unit
    ///
    /// It is **not** a sixth thing the daemon needs granted. `/sys/kernel/tracing`
    /// is `drwx------ root`, so reading the tracepoint `id` and `format` files
    /// is a *discretionary access* question, not a capability one, and the
    /// daemon answers it by being uid 0 - the unit sets no `User=`, and root
    /// bypasses DAC implicitly. This test deliberately drops to a non-root uid
    /// so that capabilities are the only privilege in play, which means it has
    /// to ask for that bypass explicitly. Substituting for root's DAC bypass is
    /// exactly what `CAP_DAC_OVERRIDE` is.
    ///
    /// Verified by removing it: without `dac_override` the cgroup program still
    /// loads and attaches, and both tracepoints fail with "tracefs not found".
    /// That is the shape of a DAC refusal, not a missing capability - and it is
    /// worth knowing, because it means running this daemon as a non-root user
    /// would silently cost it process tracking while leaving DNS capture
    /// working.
    ///
    /// It refuses to pass by accident: running it as root, or with
    /// `CAP_SYS_ADMIN` in the effective set, fails before it loads anything.
    /// A test that silently proves nothing when misrun is worse than no test.
    ///
    /// Deliberately narrower than `loads_and_attaches_on_this_kernel`: it
    /// stops at "all three attached". The end-to-end DNS probe there binds
    /// `127.0.0.1:53`, and a port below 1024 needs `CAP_NET_BIND_SERVICE`,
    /// which the unit does **not** grant and the daemon never needs - only the
    /// test harness does, to impersonate a resolver. Requiring it here would
    /// quietly turn this into "six capabilities are enough".
    #[tokio::test]
    #[ignore = "run under setpriv with the unit's capability set; see the doc comment"]
    async fn attaches_with_only_the_units_capabilities() {
        let uid = unsafe { libc::geteuid() };
        assert_ne!(
            uid, 0,
            "running as root proves nothing about which capabilities are needed; \
             re-run under setpriv (see this test's doc comment)"
        );

        let caps = effective_caps();
        println!("euid={uid} CapEff={caps:#018x}");
        assert!(
            !has_cap(caps, CAP_SYS_ADMIN),
            "CAP_SYS_ADMIN is in the effective set, so a pass here would not \
             show that the unit's narrower grant is sufficient"
        );
        // And the ones the unit does grant really are present, or the test is
        // measuring a differently-broken environment.
        for (bit, name) in [
            (CAP_BPF, "CAP_BPF"),
            (CAP_PERFMON, "CAP_PERFMON"),
            (CAP_NET_ADMIN, "CAP_NET_ADMIN"),
            (CAP_SYS_PTRACE, "CAP_SYS_PTRACE"),
        ] {
            assert!(
                has_cap(caps, bit),
                "{name} is missing from the effective set"
            );
        }
        // Standing in for root's implicit DAC bypass, so that capabilities are
        // the only privilege being measured. See the doc comment.
        assert!(
            has_cap(caps, CAP_DAC_OVERRIDE),
            "CAP_DAC_OVERRIDE is missing; /sys/kernel/tracing is 0700 root, so \
             without it the tracepoints fail on file permissions and this test \
             would be measuring DAC rather than capabilities"
        );

        let path = std::env::var("CFC_EBPF_OBJECT").unwrap_or_else(|_| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../cfc-ebpf/target/bpfel-unknown-none/release/cfc-ebpf.o"
            )
            .to_string()
        });
        let (attached, report) = load_and_attach(
            Path::new(&path),
            DnsCache::new(),
            KernelProcTable::new(),
            None,
            Trust::Warn,
            tokio::sync::broadcast::channel(8).0,
            crate::stats::Stats::new(),
            Default::default(),
        )
        .expect("the unit's capability set must be enough to load the object");

        for note in &report.notes {
            println!("note: {note}");
        }
        for (program, insns) in &report.verified_insns {
            println!("verified_insns: {program} = {insns}");
        }
        assert!(report.exec_tracking, "exec: {:?}", report.notes);
        assert!(report.exit_tracking, "exit: {:?}", report.notes);
        assert!(report.dns_capture, "cgroup_skb/ingress: {:?}", report.notes);
        // The enforcement layer is measured here too, and specifically that it
        // *pinned*. `BPF_OBJ_PIN` was a CAP_SYS_ADMIN operation before 5.8, and
        // writing under /sys/fs/bpf is a DAC question on top of that; if either
        // needed more than this set, the unit's claim would be wrong in the one
        // place where being wrong means denials quietly stop surviving a
        // `kill -9`.
        assert_eq!(
            report.enforcement,
            Enforcement::Pinned,
            "cgroup/connect4|6 must load, attach *and* pin with this set: {:?}",
            report.notes
        );
        // The attribution map must be pinned with the rest, and this is the
        // one test that can prove it (the matrix guests have no bpffs). It
        // went unpinned for a while, and the failure was the quiet kind: on
        // the inherited path the previous daemon's programs write the
        // SOCK_PIDS *they* captured, so an unpinned copy split the map across
        // a restart - every cookie lookup missed, and every new connection
        // paid the /proc walk the map exists to remove.
        let sock_pids_pin = enforce::pin_dir().join(enforce::MAP_SOCK_PIDS);
        assert!(
            sock_pids_pin.exists(),
            "{} must be pinned alongside the verdict maps",
            sock_pids_pin.display()
        );
        // The fast path's maps and links. Unpinned, a restart would split
        // them from the programs still attached (the SOCK_PIDS lesson), and
        // an unpinned deadline map would be one no restarted daemon could
        // ever refresh.
        for name in [
            enforce::MAP_FAST_ALLOW,
            enforce::MAP_FAST_ALLOW_UNTIL,
            enforce::MAP_FAST_ALLOW_MARK,
            enforce::MAP_ALLOW_EVENTS,
            enforce::LINK_SENDMSG4,
            enforce::LINK_SENDMSG6,
        ] {
            let pin = enforce::pin_dir().join(name);
            assert!(pin.exists(), "{} must be pinned", pin.display());
        }

        // And the rung the fast path's safety argument stands on: the exec and
        // exit tracepoint links pinned, not merely attached.
        //
        // Only the pin makes their clears outlive the daemon, and the connect
        // programs' links are pinned separately - so on a kernel where these
        // two cannot be, the marking survives a dead daemon while the clearing
        // does not. The loader used to throw the pin outcome away and the
        // ladder could not see the difference; this is the assertion that
        // stops it being thrown away again. Only this test can make it: the
        // matrix guests have no bpffs.
        for name in [enforce::LINK_EXEC, enforce::LINK_EXIT] {
            let pin = enforce::pin_dir().join(name);
            assert!(
                pin.exists(),
                "{} must be pinned, or the fast path's clears die with the daemon",
                pin.display()
            );
        }
        assert!(
            report.lifecycle_pinned,
            "the report must say both lifecycle links pinned when they did: {:?}",
            report.notes
        );
        println!(
            "seven programs attached; connect, sendmsg and lifecycle links plus \
             every fast-path map pinned, without CAP_SYS_ADMIN"
        );

        drop(attached);
        // Pins outlive the process by design, so this test has to take its own
        // away or it leaves in-kernel enforcement attached to the machine.
        let _ =
            std::fs::remove_dir_all(std::path::Path::new("/sys/fs/bpf").join("colony-firewall"));
    }

    /// Actually loads and attaches on this machine. Needs root (or
    /// CAP_BPF+CAP_PERFMON+CAP_NET_ADMIN), a BTF-enabled kernel, cgroup v2,
    /// and the object built by `cargo xtask build-ebpf`.
    ///
    ///     cargo xtask build-ebpf
    ///     cargo build -p cfc-daemon --tests --profile fast
    ///     sudo -E CFC_EBPF_OBJECT=$(cargo xtask ebpf-path) \
    ///       ./target/fast/deps/cfc_daemon-<hash> --ignored --nocapture loads_and_attaches
    ///
    /// (`cargo test` itself is not run as root; build the test binary first
    /// and run that, as above.)
    #[tokio::test]
    #[ignore = "requires root and a built BPF object; see the doc comment"]
    async fn loads_and_attaches_on_this_kernel() {
        // The loader's own `debug!` lines are the point of running this by
        // hand: they carry the per-program verifier instruction counts.
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let path = std::env::var("CFC_EBPF_OBJECT").unwrap_or_else(|_| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../cfc-ebpf/target/bpfel-unknown-none/release/cfc-ebpf.o"
            )
            .to_string()
        });
        let table = KernelProcTable::new();
        let cache = DnsCache::new();
        // `Trust::Warn`: the object under test lives in `target/`, owned by
        // whoever ran cargo, which is exactly the case the ownership check is
        // meant to refuse in production and must not refuse here.
        let (attached, report) = load_and_attach(
            Path::new(&path),
            cache.clone(),
            table.clone(),
            None,
            Trust::Warn,
            tokio::sync::broadcast::channel(8).0,
            crate::stats::Stats::new(),
            Default::default(),
        )
        .expect("load");
        for note in &report.notes {
            println!("note: {note}");
        }
        assert!(report.exec_tracking, "exec tracepoint should attach");
        assert!(report.exit_tracking, "exit tracepoint should attach");
        assert!(report.ppid_offsets, "BTF offsets should resolve");
        // Assert on the *parse outcome*, not on "an override was issued":
        // the override is now unconditional, so asserting it happened would
        // pass on a kernel whose format file could not be read at all.
        println!("exec_offset = {:?}", report.exec_offset);
        assert!(
            matches!(report.exec_offset, ExecOffset::Parsed(_)),
            "the sched_process_exec filename offset should come from tracefs, \
             not from the compiled-in fallback: {:?}",
            report.exec_offset
        );
        // The verifier budget is 1,000,000 instructions and the DNS observer
        // has been over it before. Print the real numbers so a change that
        // makes a program dramatically more expensive is visible in the run
        // that introduced it rather than on someone else's kernel.
        for (program, insns) in &report.verified_insns {
            println!("verified_insns: {program} = {insns}");
        }
        println!("dns_capture = {}", report.dns_capture);
        assert!(
            report.dns_capture,
            "cgroup_skb/ingress should load and attach: {:?}",
            report.notes
        );
        // The one layer that decides rather than observes. `load_and_attach`
        // deliberately degrades on an enforce failure - a note, a `Degrade`,
        // and `Ok` - so nothing else in this test would notice
        // cgroup/connect4|6 being rejected, and for a long time nothing here
        // did either: the kernel matrix was green while asserting only the
        // observers, which is exactly how a verifier change on a new kernel
        // would have shipped with enforcement silently absent. Attachment is
        // asserted, not pinning: the qemu guests mount cgroup2 but no bpffs,
        // so `Process` is the honest outcome there and `Pinned` on a real
        // host. cgroup sock_addr attach has existed since 4.17 and the matrix
        // floor is 5.10, so there is no kernel in the matrix where degrading
        // is acceptable.
        println!("enforcement = {:?}", report.enforcement);
        assert!(
            report.enforcement.is_live(),
            "cgroup/connect4|6 must load and attach on every matrix kernel: {:?}",
            report.notes
        );
        // The fast path's kernel side rides with the cookie connect variants,
        // but not all the way: 5.10 verifies bpf_setsockopt on connect hooks
        // and refuses it on sendmsg ones, so "cookie verified implies sendmsg
        // verified" is false on the matrix floor and is not asserted. What is
        // asserted is consistency: the two sendmsg programs verify together
        // or not at all.
        println!("fast_allow = {:?}", report.fast_allow);
        let measured = |name: &str| report.verified_insns.iter().any(|(p, _)| p == name);
        assert_eq!(
            measured(enforce::PROG_SENDMSG4),
            measured(enforce::PROG_SENDMSG6),
            "the sendmsg pair must verify together or not at all: {:?}",
            report.verified_insns
        );
        // Off, and off for the reason this test's own setup dictates: it
        // hands the layer no decision engine, so there is no sink to grant
        // from. The first version of this assertion expected the config
        // reason and learned on every matrix kernel at once that the test's
        // inputs never reach the config check - an assertion about a state
        // the test does not produce is the class of mistake this file exists
        // to catch in the code, not to commit in the tests.
        match &report.fast_allow {
            Some(FastAllow::Off(why)) => assert!(
                why.contains("no decision engine"),
                "fast-allow is off for a reason this setup does not produce: {why}"
            ),
            other => panic!("fast-allow should be off here (no engine), got {other:?}"),
        }
        // Where the sendmsg pair did not verify, the report must say so in the
        // fast-path terms - the note is the only trace a kernel like 5.10
        // leaves, and it must not be mistaken for the basic-connect fallback.
        if measured(enforce::PROG_CONNECT4) && !measured(enforce::PROG_SENDMSG4) {
            println!("sendmsg hooks refused by this kernel; fast path unavailable here");
        }
        // `bpf_prog_info.verified_insns` exists since kernel 5.16; before
        // that, an empty report is the correct answer, not a recording
        // failure. On a kernel that does report counts, every program that
        // attached above must have one. This used to be a bare
        // `!verified_insns.is_empty()`, which only caught losing every count
        // at once: one program's count going missing (`verifier_cost` logs at
        // debug and returns `None`) left the vec non-empty, and the budget
        // loop below skips unmeasured programs by design - the `_basic` twins
        // carry ceilings with no measurement - so a single unwatched program,
        // including cfc_dns_ingress, the one the budget file exists for, had
        // no signal anywhere.
        let kernel_reports_counts = aya::util::KernelVersion::current()
            .map(|v| v >= aya::util::KernelVersion::new(5, 16, 0))
            .unwrap_or(true);
        if kernel_reports_counts {
            let measured = |name: &str| report.verified_insns.iter().any(|(p, _)| p == name);
            for name in [PROG_EXEC, PROG_EXIT, PROG_DNS] {
                assert!(
                    measured(name),
                    "this kernel reports verified instruction counts and \
                     `{name}` attached, but no count was recorded for it: {:?}",
                    report.verified_insns
                );
            }
            // Whichever connect variant this kernel's verifier accepted is
            // the one that was loaded and must be measured; the two are never
            // attached together. On the inherited path this run loaded
            // neither, so there is nothing the verifier walked.
            if report.enforcement != Enforcement::Inherited {
                for (cookie, basic) in [
                    (enforce::PROG_CONNECT4, enforce::PROG_CONNECT4_BASIC),
                    (enforce::PROG_CONNECT6, enforce::PROG_CONNECT6_BASIC),
                ] {
                    assert!(
                        measured(cookie) || measured(basic),
                        "neither `{cookie}` nor `{basic}` has a verified \
                         instruction count: {:?}",
                        report.verified_insns
                    );
                }
            }
        }
        assert_within_verifier_budget(&report.verified_insns);

        table.set_live(true);

        // --- DNS capture, end to end, without depending on the network ----
        //
        // A real resolution would prove the same thing but only on a host that
        // has a resolver and an uplink, which is precisely the kind of thing
        // that makes a test flaky. So: bind a socket to 127.0.0.1:53, send one
        // handmade response from it to a socket of our own, and require that
        // the answer came out the far end of the kernel program, the ring
        // buffer, and the parser, into the cache.
        //
        // Loopback is enough because `cgroup_skb/ingress` runs at the receiving
        // socket, not at a device, and this test process is inside the root
        // cgroup the program is attached to.
        let observed_ip = Ipv4Addr::new(198, 51, 100, 23); // TEST-NET-2
        let observed_name = "capture-probe.cfc.invalid";
        {
            let server = std::net::UdpSocket::bind("127.0.0.1:53")
                .expect("binding 127.0.0.1:53 (needs root, and nothing else may hold it)");
            let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("binding a client socket");
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("read timeout");
            let wire = synthetic_dns_response(observed_name, observed_ip, 300);
            server
                .send_to(&wire, client.local_addr().unwrap())
                .expect("sending the synthetic response");
            let mut buf = [0u8; 1500];
            let n = client.recv(&mut buf).expect("the response must arrive");
            assert_eq!(
                &buf[..n],
                &wire[..],
                "loopback delivered a different packet"
            );
        }
        // The consumer is a tokio task on the same runtime; give it a turn.
        for _ in 0..20 {
            if cache
                .lookup_cached(std::net::IpAddr::V4(observed_ip))
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            cache
                .lookup_cached(std::net::IpAddr::V4(observed_ip))
                .as_deref(),
            Some(observed_name),
            "the synthetic answer never reached DnsCache"
        );
        assert_eq!(
            cache.cached_trust(std::net::IpAddr::V4(observed_ip)),
            Some(crate::dns::Trust::Observed),
            "an answer off the wire must be stored as first-hand"
        );
        println!("captured (synthetic): {observed_name} -> {observed_ip}");

        // Now a real resolution, for the record. Best effort by design, and
        // *necessarily* so: this observes packets, and a local resolver that
        // answers `example.com` out of its own cache never sends one. (When it
        // does go upstream, the answer is captured off the resolver's socket,
        // not this process's - the program is attached to the cgroup root, so
        // it sees the whole machine.) It prints what it saw and asserts
        // nothing; the hermetic check above is the one that must hold.
        // Two `getent` calls against a possibly-unreachable resolver cost about
        // 40 seconds and assert nothing - the hermetic half above is the one
        // that must hold. "CI sets this" is what this comment used to say
        // while only one job in six did: the qemu guests ran this block on
        // all five kernels, kept fast only by the accident of an empty
        // resolv.conf failing on ECONNREFUSED - one rootfs edit away from 40
        // TCG-emulated seconds per kernel. Both runner-kernel and the guest
        // init export the variable now (.github/workflows/ebpf.yml, both
        // call sites). A human running this by hand wants the output.
        let skip_live = std::env::var_os("CFC_SKIP_LIVE_RESOLUTION").is_some();
        if !skip_live && Path::new("/usr/bin/getent").exists() {
            // `ahostsv4` forces an A query and `ahosts` will take the AAAA, so
            // a run that goes to the wire at all exercises both record types.
            let mut resolved = Vec::new();
            for (mode, host) in [("ahostsv4", "example.com"), ("ahosts", "one.one.one.one")] {
                if let Ok(out) = std::process::Command::new("/usr/bin/getent")
                    .args([mode, host])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    for line in stdout.lines() {
                        if let Some(Ok(ip)) = line
                            .split_whitespace()
                            .next()
                            .map(str::parse::<std::net::IpAddr>)
                        {
                            resolved.push(ip);
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            // `ahosts*` repeats each address once per socket type.
            resolved.sort();
            resolved.dedup();
            for ip in resolved {
                match cache.lookup_cached(ip) {
                    Some(name) => println!("captured (live): {name} -> {ip}"),
                    None => println!(
                        "not captured (live): {ip} - expected when the local \
                         resolver answered from its own cache"
                    ),
                }
            }
        }

        // A child that stays alive long enough to be looked up, so the exec
        // and exit halves can be asserted separately.
        let sleeper = ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect("no sleep(1) on this host");
        let mut child = std::process::Command::new(sleeper)
            .arg("1")
            .spawn()
            .expect("spawning sleep");
        let pid = child.id();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let seen = table.get(
            pid,
            crate::process_resolve::read_starttime(pid),
            Instant::now(),
        );
        println!("exec record for pid {pid}: {seen:?}");
        println!("table holds {} live processes", table.len());
        let seen = seen.expect("no exec event observed for the child");
        assert_eq!(seen.pid, pid);
        assert_eq!(seen.exe, std::path::PathBuf::from(sleeper));
        assert_eq!(
            seen.ppid,
            Some(std::process::id()),
            "ppid must come back resolved, not 0"
        );
        assert_eq!(seen.uid, 0, "run as root, so exec-time uid is 0");

        let _ = child.wait();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            table.get(pid, None, Instant::now()).is_none(),
            "the exit tracepoint must have evicted the record"
        );

        drop(attached);
        // Pins outlive the process by design, so this test takes its own away
        // - the same courtesy `attaches_with_only_the_units_capabilities`
        // extends. Left behind, every run on a bpffs host parks in-kernel
        // enforcement on the machine, and the *next* run inherits it instead
        // of exercising the attach path it exists to prove. A no-op in the
        // qemu guests, which have no bpffs to begin with.
        let _ =
            std::fs::remove_dir_all(std::path::Path::new("/sys/fs/bpf").join("colony-firewall"));
    }
}
