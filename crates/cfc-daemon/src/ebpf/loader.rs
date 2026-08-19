//! The aya half of the eBPF layer: load the object, patch the `.rodata`
//! globals from BTF, attach the three programs, and spawn one ring-buffer
//! consumer per event stream.
//!
//! Compiled only with the `ebpf` cargo feature; everything aya-shaped lives
//! here so the rest of the daemon never sees it. See the parent module for the
//! design rationale.

use std::os::fd::AsFd as _;
use std::path::Path;
use std::time::Instant;

use anyhow::{anyhow, Context as _};
use aya::maps::{MapData, RingBuf};
use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, ProgramError, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use cfc_ebpf_common::dns::{self, DnsCursor, DNS_HEADER_LEN};
use cfc_ebpf_common::{DnsAnswer, DnsPacket, ExecEvent, ExitEvent};
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::{btf, cgroup, proc_table::KernelProcTable, tracefs, Degrade, ExecOffset, Report};
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

/// Whether a *directory* on the way to the object is safe.
///
/// Root-owned and not group/world-writable, or root-owned, world-writable and
/// **sticky** - the `/tmp` shape, where a non-root user still cannot rename or
/// remove root's files. Kept as a pure function so the policy can be tested
/// exhaustively without needing root or a filesystem that can express every
/// case.
fn dir_is_safe(uid: u32, mode: u32) -> bool {
    uid == 0 && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}

/// Whether the object file itself is safe. No sticky exception: the bit means
/// nothing on a regular file.
fn file_is_safe(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

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
}

impl Drop for Attached {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Loads `object_path`, attaches what it can, and starts the consumers.
///
/// Returns `Err` only when the object itself could not be loaded at all - a
/// missing file, a malformed ELF, a kernel that refuses the whole program set.
/// Individual attach failures are recorded in the [`Report`] and leave the
/// rest running.
pub(super) fn load_and_attach(
    object_path: &Path,
    dns: DnsCache,
    table: KernelProcTable,
    trust: Trust,
) -> Result<(Attached, Report), LoadError> {
    let mut report = Report {
        mode: crate::config::EbpfMode::On,
        compiled_in: true,
        ..Report::default()
    };

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

    let mut loader = EbpfLoader::new();
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

    let r = attach_tracepoint(&mut bpf, PROG_EXEC, "sched", "sched_process_exec");
    report.exec_tracking = record_attach(&mut report, PROG_EXEC, "sched_process_exec", r);
    let r = attach_tracepoint(&mut bpf, PROG_EXIT, "sched", "sched_process_exit");
    report.exit_tracking = record_attach(&mut report, PROG_EXIT, "sched_process_exit", r);
    let r = attach_dns(&mut bpf);
    report.dns_capture = record_attach(&mut report, PROG_DNS, "cgroup_skb/ingress", r);

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
        match spawn_ring(&mut bpf, MAP_EXEC, move |bytes| {
            if let Some(event) = decode::<ExecEvent>(bytes) {
                // Bind the record to /proc/<pid>/stat's start time while the
                // process is (almost certainly) still alive. That single small
                // read is what makes pid reuse detectable later; see
                // `proc_table`. It runs on this task, never on the packet path.
                let starttime = crate::process_resolve::read_starttime(event.pid);
                t.observe_exec(&event, starttime, Instant::now());
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
        match spawn_ring(&mut bpf, MAP_EXIT, move |bytes| {
            if let Some(event) = decode::<ExitEvent>(bytes) {
                t.observe_exit(event.pid);
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

    Ok((Attached { _bpf: bpf, tasks }, report))
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
    prog.attach(category, event)
        .with_context(|| format!("attaching to {category}:{event}"))?;
    Ok(insns)
}

/// Logs how many instructions the verifier walked to accept a program.
///
/// Worth a line because that number is a *budget*: the kernel gives a program
/// 1,000,000 and rejects it at 1,000,001, and the DNS observer used to be on
/// the wrong side of that (see `crates/cfc-ebpf/README.md`). Logging it turns
/// "a change made the program more expensive" into something visible before it
/// becomes "the program stopped loading on someone else's kernel".
fn verifier_cost(
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
            Trust::Refuse,
        )
        .err()
        .expect("a world-writable object must not be loaded");
        assert_eq!(refused.degrade, Degrade::ObjectUntrusted);

        // Under `Warn` the same file gets past the check and fails later, on
        // its own merits -- it is not an ELF. The point is that the trust
        // check is what changed, and nothing else.
        let warned = load_and_attach(&path, DnsCache::new(), KernelProcTable::new(), Trust::Warn)
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
            Trust::Refuse,
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
        let (attached, report) =
            load_and_attach(Path::new(&path), cache.clone(), table.clone(), Trust::Warn)
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
        assert!(
            !report.verified_insns.is_empty(),
            "this kernel reports verified instruction counts; they should be recorded"
        );
        println!("dns_capture = {}", report.dns_capture);
        assert!(
            report.dns_capture,
            "cgroup_skb/ingress should load and attach: {:?}",
            report.notes
        );

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
        if Path::new("/usr/bin/getent").exists() {
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
    }
}
