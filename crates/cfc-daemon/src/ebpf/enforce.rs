//! In-kernel `connect()` enforcement, and the bpffs pins that outlive the
//! daemon.
//!
//! Everything else in this crate observes. This module is the one part that
//! *decides* without a userspace round trip, and the reason it exists is a
//! single sentence in `TODO.md`: today any root process lifts the whole
//! guarantee with `nft delete table inet colony_firewall`, and killing the
//! daemon stops every future decision from being made at all.
//!
//! The mechanism is BPF link pinning. A link held only by a process dies with
//! that process; a link pinned into bpffs is held by the filesystem, so the
//! program stays attached and keeps refusing `connect()` after the daemon is
//! gone - killed, crashed, OOM'd or stopped by an attacker who got root. The
//! map it consults is pinned the same way, so the next daemon picks up exactly
//! the state the last one left.
//!
//! What this does not do, and cannot: confine root. Root can `rm` a pin, and
//! nothing running as root can stop that. What changes is the cost. "Stop the
//! daemon" no longer works, and neither does "flush the ruleset"; an attacker
//! has to know CFC specifically and go take the pins out.
//!
//! # Pin layout
//!
//! ```text
//! /sys/fs/bpf/colony-firewall/v2/
//!   connect4        pinned link  - IPv4 enforcement
//!   connect6        pinned link  - IPv6 enforcement
//!   VERDICTS        pinned map   - tgid -> verdict, written by the daemon
//!   ENFORCE_STATS   pinned map   - per-CPU counters
//!   DENY_EVENTS     pinned map   - one record per refusal, drained by the daemon
//! ```
//!
//! `DENY_EVENTS` is pinned for the same reason as the other two, though the
//! first instinct is not to: a ring buffer nobody drains fills up. It does, and
//! that costs a log line - the refusal already happened when the record could
//! not be written. Leaving it unpinned costs much more: on the inherited path
//! the *previous* daemon's programs are the ones still attached and writing, so
//! an unpinned ring would leave every in-kernel refusal after a restart silent.
//! Observed exactly that way on a real machine: 48 refusals counted, none
//! reported.
//!
//! The `v<N>` component is [`cfc_ebpf_common::ABI_VERSION`]. It is in the *path* because an
//! object built against a different event layout is a different program and
//! must not inherit the previous one's pins; putting the version in a file
//! inside a shared directory would mean reading it before knowing whether it
//! can be trusted. Directories for other versions are unpinned on startup,
//! which is what makes an upgrade work: without it the old program would stay
//! attached forever, consulting a map nothing writes to, and the new one would
//! fail to attach with `EEXIST`.
//!
//! Nothing here survives a reboot. bpffs is an in-memory filesystem, so a
//! stale pin from a previous boot is not a case that exists.

use std::io;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context as _};
use aya::maps::{HashMap as BpfHashMap, MapData, PerCpuArray};
use aya::programs::links::FdLink;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf;
use cfc_core::{Action, Process};
use cfc_ebpf_common::{enforce_stat, ABI_VERSION};
use parking_lot::Mutex;
use tracing::{debug, warn};

use super::proc_table::KernelProcTable;
use crate::decision::Engine;

/// Where the kernel expects a bpffs to be mounted. systemd mounts it here on
/// every system this daemon targets; if it is absent, enforcement is skipped
/// rather than pinned somewhere else, because "somewhere else" would be a
/// directory on a real filesystem where `BPF_OBJ_PIN` fails anyway.
const BPFFS: &str = "/sys/fs/bpf";

/// `BPF_FS_MAGIC` from `include/uapi/linux/magic.h`. Checked because
/// `/sys/fs/bpf` existing as a plain directory - which is what it is before
/// anything mounts over it - is indistinguishable from the real thing by
/// `stat`, and pinning into it would silently do nothing useful.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

/// One directory for all of CFC's pins, so an operator can see and remove the
/// whole thing in one step. Documented in the README as *the* way to lift
/// enforcement by hand.
const PIN_NAMESPACE: &str = "colony-firewall";

/// ELF symbol names, as with the other programs.
pub(super) const PROG_CONNECT4: &str = "cfc_connect4";
pub(super) const PROG_CONNECT6: &str = "cfc_connect6";
/// Identical enforcement without `bpf_get_socket_cookie`, for kernels whose
/// verifier does not offer that helper to sock_addr programs. Tried second;
/// only O(1) attribution is lost, never enforcement.
pub(super) const PROG_CONNECT4_BASIC: &str = "cfc_connect4_basic";
pub(super) const PROG_CONNECT6_BASIC: &str = "cfc_connect6_basic";

pub(super) const MAP_SOCK_PIDS: &str = "SOCK_PIDS";

pub(super) const MAP_VERDICTS: &str = "VERDICTS";
pub(super) const MAP_STATS: &str = "ENFORCE_STATS";
pub(super) const MAP_DENY_EVENTS: &str = "DENY_EVENTS";
pub(super) const MAP_EXE_RULES: &str = "EXE_RULES";
pub(super) const MAP_EXE_RULES_ON: &str = "EXE_RULES_ON";

/// The legacy Fast Allow maps. The daemon no longer grants, but the kernel
/// object still carries them (ABI v4) and the connect programs still read
/// them, so they stay pinned: [`disarm_legacy_fast_allow`] has to reach the
/// copies the pinned programs see, not a fresh map nobody reads.
pub(super) const MAP_FAST_ALLOW: &str = "FAST_ALLOW";
pub(super) const MAP_FAST_ALLOW_UNTIL: &str = "FAST_ALLOW_UNTIL";
pub(super) const MAP_FAST_ALLOW_MARK: &str = "FAST_ALLOW_MARK";
pub(super) const MAP_ALLOW_EVENTS: &str = "ALLOW_EVENTS";

/// Pin names a 0.4-0.6 daemon gave its Fast Allow sendmsg links, and the
/// directory it left beside the connect pins. Nothing attaches or reads these
/// any more; [`prepare`] removes them.
pub(super) const LINK_SENDMSG4: &str = "sendmsg4";
pub(super) const LINK_SENDMSG6: &str = "sendmsg6";
const LEGACY_COOKIE_MARKER: &str = "cookie-variants";

/// Pin name for the `sched_process_exit` link.
///
/// Pinned for one reason, and it is not the reason the connect links are.
/// Those are pinned so enforcement *continues* without the daemon; this one is
/// pinned so enforcement does not silently **rot** without it.
///
/// `VERDICTS` outlives the daemon, so an entry written for a pid stays there
/// after that pid is gone. Linux recycles pids. Without a live exit program to
/// evict them, a machine running with a dead daemon accumulates denials
/// attached to nothing, and unrelated programs start losing the network as
/// they inherit recycled pids. It fails closed, so nothing breaks loudly - the
/// protection just decays into noise.
///
/// Deliberately *not* adopted on restart, unlike the connect links. The exit
/// program touches `PROCS` and `EXIT_EVENTS`, both unpinned and both rebuilt
/// every start; a program adopted from the previous run would go on clearing
/// the *old* `PROCS` while the new daemon filled a new one. So startup removes
/// a stale pin - which detaches the old program - and pins a fresh one. The pin
/// is there to cover the gap between two daemons, not to be inherited across it.
pub(super) const LINK_EXIT: &str = "exit";

/// Pin name for the `sched_process_exec` link.
///
/// Pinned for the reason the exit link is not: so a process that execs while
/// no daemon is running still gets a verdict. The exec program reads
/// `EXE_RULES` - the daemon's process-wide rules compiled into the kernel -
/// and writes `VERDICTS` itself, which is the whole of what makes enforcement
/// outlive its control plane.
///
/// That only works if the table it reads is pinned too, hence `EXE_RULES` and
/// `EXE_RULES_ON` alongside it. Not pinning them would leave an adopted
/// program consulting a map the new daemon cannot see - the exact failure the
/// pinned `DENY_EVENTS` exists to avoid.
///
/// Replaced on restart rather than inherited, exactly like [`LINK_EXIT`]: the
/// program also writes `PROCS` and `EXEC_EVENTS`, both rebuilt every start.
pub(super) const LINK_EXEC: &str = "exec";

/// Writes precomputed verdicts into the pinned map.
///
/// Handed to the exec consumer, which is the only place that can populate it:
/// a verdict is per-pid, and `exec` is the moment a pid acquires the identity
/// the rules are written against.
///
/// Cheap to clone (one `Arc`). The mutex is held only for a map update - the
/// exec consumer is a single task, so it is uncontended in practice and exists
/// to satisfy the borrow checker rather than to arbitrate.
#[derive(Clone)]
pub(super) struct VerdictSink {
    map: Arc<Mutex<BpfHashMap<MapData, u32, u32>>>,
    engine: Engine,
    table: KernelProcTable,
    /// The kernel's own rule table, `None` when the object predates it.
    exe_rules: Option<Arc<Mutex<BpfHashMap<MapData, u64, u32>>>>,
    /// The gate the exec program reads before hashing. `None` likewise.
    exe_rules_on: Option<Arc<Mutex<aya::maps::Array<MapData, u32>>>>,
    /// What was last written to the kernel, so an unchanged recompute costs no
    /// syscalls. `None` until the first compile.
    last_compiled: Arc<Mutex<Option<std::collections::HashMap<u64, u32>>>>,
    /// Held for a whole [`Self::resync`]. Each run decides from the rules it
    /// read and writes afterwards, so two overlapping runs could finish in the
    /// wrong order and leave the older rule set's answers in the kernel.
    resync: Arc<Mutex<()>>,
}

impl VerdictSink {
    /// Takes the pinned `VERDICTS` map out of the object.
    pub(super) fn new(
        bpf: &mut Ebpf,
        engine: Engine,
        table: KernelProcTable,
    ) -> anyhow::Result<Self> {
        let map = bpf
            .take_map(MAP_VERDICTS)
            .ok_or_else(|| anyhow!("no map named `{MAP_VERDICTS}` in the object"))?;
        let map = BpfHashMap::<_, u32, u32>::try_from(map)
            .with_context(|| format!("{MAP_VERDICTS} is not a hash map"))?;
        // Both are optional so a daemon can still drive an older object: a
        // missing table means no in-kernel precommit, which is the behaviour
        // before this existed, not a failure.
        let exe_rules = bpf
            .take_map(MAP_EXE_RULES)
            .and_then(|m| BpfHashMap::<_, u64, u32>::try_from(m).ok())
            .map(|m| Arc::new(Mutex::new(m)));
        let exe_rules_on = bpf
            .take_map(MAP_EXE_RULES_ON)
            .and_then(|m| aya::maps::Array::<_, u32>::try_from(m).ok())
            .map(|m| Arc::new(Mutex::new(m)));
        if exe_rules.is_none() || exe_rules_on.is_none() {
            warn!(
                "this object has no in-kernel rule table; processes that exec \
                 while the daemon is down will not get a verdict"
            );
        }

        Ok(Self {
            map: Arc::new(Mutex::new(map)),
            engine,
            table,
            exe_rules,
            exe_rules_on,
            last_compiled: Arc::new(Mutex::new(None)),
            resync: Arc::new(Mutex::new(())),
        })
    }

    /// Recomputes every live process's verdict.
    ///
    /// Called when the rule set changes, which is the only event that can
    /// invalidate an entry without the process doing anything. `on_exec` alone
    /// is not enough and the gap it leaves is the interesting one: a user
    /// clicking "Block always" in a prompt creates a rule for a program that is
    /// *already running*, so without this the block would be enforced by the
    /// packet path and never reach the kernel - and killing the daemon would
    /// lift the block that had just been asked for.
    ///
    /// Observed exactly that way on a real machine before this existed: a deny
    /// rule added for a running process was honoured by NFQUEUE
    /// (`source="rule"`) and the kernel counters never moved.
    ///
    /// Cost, since it is no longer only map operations: a handful of small
    /// /proc reads per process - three for the view and one to re-date it
    /// before the deny write - for every recently-exec'd process and every
    /// orphan. All of it on whichever thread changed the rules - an IPC
    /// handler or startup, never the packet path - and only when a human or
    /// the CLI actually changed something.
    ///
    /// None of those reads happen while a map lock is held. That is a
    /// constraint, not an accident: `on_exec` and `on_exit` block on the
    /// verdict mutex from inside the ring consumers, and a stalled exec ring
    /// is a dropped record, which is a process with no in-kernel verdict at
    /// all. The orphan sweep has said so since it was written; the live loop
    /// inherited the constraint the moment it started reading /proc too.
    pub(super) fn resync(&self) {
        // One run at a time, so the last run to write is the one that read the
        // newest rules. Not the map lock: the ring consumers never wait on this.
        let _run = self.resync.lock();
        // The kernel's table first: it governs processes that do not exist yet,
        // and it is what survives this daemon.
        self.compile_rules();

        // No early return on an empty live list. There used to be one, and it
        // was wrong in exactly the state this function's own orphan comment
        // describes: after a restart the proc table is empty while the pinned
        // map holds every inherited entry, so the first rule deletion arrived
        // here, saw nothing live, and left - and the kernel went on refusing a
        // program no rule denied. When exec tracking is down entirely the
        // table is empty *forever*, which made that permanent. The live loop
        // below no-ops on an empty list by itself; the orphan sweep is the
        // part that must run precisely then.
        let live = self.table.live_processes(Instant::now());
        let mut denied = 0usize;

        // Every /proc read first, and only then the lock.
        //
        // Reading under it would be the mistake the orphan sweep below spells
        // out at length and avoids: `on_exec` and `on_exit` block on this same
        // mutex from inside the ring consumers, and a stalled exec ring is a
        // dropped record, which is a process with no in-kernel verdict at all.
        // This loop used to decide from an in-memory record and could hold the
        // lock across the whole thing for free; the moment it moved to /proc,
        // it inherited that constraint.
        let views: Vec<(u32, Process, Option<u64>)> = live
            .iter()
            .filter_map(|proc| {
                // From /proc, like every other decider - not from the exec
                // record. The record carries the execve *string*, which is
                // neither absolute for `./foo` nor resolved through a
                // symlink, and the uid at exec, which a process that dropped
                // privileges no longer holds; the orphan sweep below reads
                // /proc, and two deciders that disagree about one process is
                // the defect.
                //
                // Gone, or /proc unreadable: no fallback to the exec record,
                // which is the guess this comment exists to refuse. The deny
                // is left to the exit tracepoint, which owns eviction and can
                // tell "exited" from "unreadable".
                proc_view(proc.pid).map(|(view, judged_at)| (proc.pid, view, judged_at))
            })
            .collect();

        // Decide, and re-date, before taking the lock.
        //
        // The re-dating is not decoration. Between the view and this write a
        // pid can be recycled, and `on_exec` - which runs on the exec ring's
        // own task - installs the new owner's verdict as soon as it sees the
        // execve. Writing from the old view then overwrites a fresh DENY with
        // whatever the *previous* holder's binary deserved, and the common
        // shape of that is a `clear`: the refusal the new process had just
        // earned, erased. The orphan sweep below has carried this guard since
        // it was written; the live loop collected the start times and then
        // dropped them on the floor.
        //
        // Both the read and the decision happen out here, so the lock covers
        // map operations and nothing else.
        enum DenyOp {
            Deny,
            Clear,
            Keep,
        }
        let deny_work: Vec<(u32, DenyOp)> = views
            .iter()
            .filter(|(pid, _, judged_at)| {
                // A pid with no start time now, or a different one, is not the
                // process that was judged. `None` on the judged side means the
                // process was already gone when it was read.
                judged_at.is_some() && proc_starttime(*pid) == *judged_at
            })
            .map(|(pid, as_process, _)| {
                // The same three-way answer as the orphan branch below,
                // because these are the same question at different ages. This
                // loop used to collapse it to deny-or-clear, so a hash-scoped
                // rule that made the engine abstain *cleared* a standing
                // kernel deny for a recently-exec'd process while the orphan
                // branch kept it for an old one - identical binary, identical
                // rules, opposite enforcement, selected by exec age.
                let op = match self.engine.process_wide_action(as_process) {
                    Some(Action::Deny | Action::Reject) => DenyOp::Deny,
                    Some(_) => DenyOp::Clear,
                    None if self.engine.deny_still_possible_for(as_process) => DenyOp::Keep,
                    None => DenyOp::Clear,
                };
                (*pid, op)
            })
            .collect();

        let mut map = self.map.lock();
        for (pid, op) in &deny_work {
            let pid = *pid;
            let r = match op {
                DenyOp::Deny => {
                    denied += 1;
                    map.insert(pid, cfc_ebpf_common::verdict::DENY, 0)
                }
                DenyOp::Clear => clear(&mut map, pid),
                DenyOp::Keep => Ok(()),
            };
            if let Err(e) = r {
                warn!(pid, "verdict resync failed: {e}");
            }
        }
        drop(map);

        // And the entries the live list does not cover.
        //
        // `live_processes` only returns pids the proc table has seen exec
        // recently; its entries expire on a TTL and are never refreshed. So a
        // long-running process drops off that list while its verdict stays in
        // a *pinned* map, and deleting the rule that put it there would never
        // lift it - the kernel would go on refusing a program the daemon now
        // allows, which is the one thing this layer must never do.
        //
        // Not "a handful": after a restart the proc table is empty while the
        // pinned map still holds every inherited entry, so the first rule
        // change makes all of them orphans. The lock is therefore dropped
        // before the per-pid work - `on_exec` and `on_exit` block on this same
        // mutex from inside the ring consumers, and a stalled exec ring is a
        // dropped record, which is a process with no in-kernel verdict.
        let known: std::collections::HashSet<u32> = live.iter().map(|p| p.pid).collect();
        let map = self.map.lock();
        let orphans: Vec<u32> = map
            .keys()
            .flatten()
            .filter(|pid| !known.contains(pid))
            .collect();
        drop(map);

        // Each doomed pid carries the start time it was judged at, so the
        // final pass can tell "still the process I judged" from "the kernel
        // recycled this pid while I was reading /proc". The window is real:
        // this loop does per-pid /proc work over a potentially large orphan
        // set, and on_exec plus the pinned exec program keep writing fresh
        // verdicts the whole time. Clearing unconditionally at the end erased
        // a DENY installed for the pid's *new* owner.
        let mut doomed: Vec<(u32, Option<u64>)> = Vec::new();
        for pid in orphans {
            // Evaluate the process as it actually is, not as a stripped-down
            // guess. Reading the uid matters: `process_wide_action` answers
            // about the process it is given, and a uid-less one does not match
            // a uid-scoped allow - so guessing would clear a denial the allow
            // was never meant to lift, which is the fail-open direction.
            let Some((proc, judged_at)) = proc_view(pid) else {
                // Gone. Clear, or a recycled pid inherits its answer.
                doomed.push((pid, None));
                continue;
            };
            // `None` is two opposite answers and they must not be conflated.
            // An abstention that could still resolve to a refusal - a
            // hash-scoped deny the sweep cannot decide - keeps the entry:
            // clearing would lift a refusal nobody replaced. But "no rule
            // matched at all" is the *deleted rule*, and that is the case
            // this sweep exists for - nobody replaces a deny with an explicit
            // allow, they delete it. Reading `None` as "keep" made the sweep
            // fail at its one job whenever a rule was removed; reading every
            // abstention as "keep" then pinned stale denies on the strength
            // of allow rules that could never justify one.
            match self.engine.process_wide_action(&proc) {
                Some(Action::Deny | Action::Reject) => {}
                Some(_) => doomed.push((pid, judged_at)),
                None => {
                    if !self.engine.deny_still_possible_for(&proc) {
                        doomed.push((pid, judged_at));
                    }
                }
            }
        }

        if !doomed.is_empty() {
            // Re-date every doomed pid *before* the lock. Clear only what was
            // judged: a process existing NOW with a different start time - or
            // existing at all where "gone" was judged - is a new owner of a
            // recycled pid, and its verdict was written by its own exec flow.
            // A pid that has no process now still clears: the judged one
            // exiting in the window only strengthens the judgment.
            //
            // These reads used to happen inside the loop below, under the
            // lock. That is the hazard this function documents twice and the
            // commit that moved the live loop's reads out claimed to have
            // removed everywhere - and it had missed this one, which is the
            // pass that runs over the *largest* pid set, every inherited entry
            // at once after a restart.
            let clearable: Vec<u32> = doomed
                .into_iter()
                .filter(|(pid, judged_at)| {
                    let now = proc_starttime(*pid);
                    now.is_none() || now == *judged_at
                })
                .map(|(pid, _)| pid)
                .collect();
            let mut map = self.map.lock();
            for pid in clearable {
                let _ = clear(&mut map, pid);
            }
        }

        debug!(
            processes = live.len(),
            denied, "resynced in-kernel verdicts after a rule change"
        );
    }

    /// Decides whether this newly-exec'd process gets an in-kernel answer.
    ///
    /// Only denials are written, and only when no rule that could apply to this
    /// process depends on a destination. Two things follow from that, both
    /// deliberate:
    ///
    /// * **an allow is never written.** `VERDICTS` holds denials only; an
    ///   allowed process keeps the packet path, which re-checks every flow. A
    ///   stale allow after pid reuse would be a security problem rather than an
    ///   inconvenience, which is why there is none to go stale.
    /// * **a stale entry is always cleared**, even when the answer is "no
    ///   answer". A pid that re-execs into a different binary must not inherit
    ///   the verdict written for the one before it.
    ///
    /// `Reject` counts as a denial. `EPERM` straight out of `connect()` is if
    /// anything closer to what a Reject rule promises - an immediate error
    /// rather than a silent timeout - than the injected RST it replaces.
    pub(super) fn on_exec(&self, pid: u32, proc: &Process) {
        // Decide on the path /proc reports, not the string execve() was
        // handed. The event's path may be a symlink (/usr/bin/python3 ->
        // python3.12) while rules written from prompts carry the resolved
        // target - so deciding on the event string meant a prompt-created
        // "block always" never engaged in-kernel for symlink-invoked
        // programs, and a CLI rule naming the symlink denied a process the
        // packet path would have prompted for. This read also corrects the
        // kernel's own precommit, which can only hash the execve string: by
        // the time this runs, whatever the exec program wrote for a
        // mismatched spelling is overwritten or cleared. The residual window
        // is the exec-to-consumer latency, and the packet path covers it.
        let resolved = proc_exe(pid);
        // The uid here stays the event's, not a fresh read: at the moment of an
        // execve that *is* the process's uid, and a drop of privileges between
        // the kernel's tracepoint and this consumer is both vanishingly narrow
        // and re-decided by the next resync, whose live loop reads /proc for
        // both. Mixing a live path with an event-time uid is worth naming
        // rather than leaving for a reader to find.
        // When /proc is unreadable, retain the unknown executable supplied by
        // the event consumer. The execve argument cannot attest a mapped image,
        // so missing identity leaves packet policy to NFQUEUE; it must not
        // satisfy an executable-scoped rule.
        let corrected = match resolved {
            Some(exe) if exe != proc.exe => Some(Process {
                exe,
                ..proc.clone()
            }),
            _ => None,
        };
        let as_process = corrected.as_ref().unwrap_or(proc);
        let deny = matches!(
            self.engine.process_wide_action(as_process),
            Some(Action::Deny | Action::Reject)
        );
        let mut map = self.map.lock();
        // Two-way, not three-way like resync: an abstention here still
        // clears. The difference is principled, not an oversight - any
        // existing entry for this pid was written for the binary it just
        // exec'd AWAY from, so there is no standing refusal for the current
        // binary to preserve; keeping it would enforce the predecessor's
        // verdict on its successor. The packet path decides the ambiguous
        // case with the real hash in hand.
        let r = if deny {
            map.insert(pid, cfc_ebpf_common::verdict::DENY, 0)
        } else {
            clear(&mut map, pid)
        };
        if let Err(e) = r {
            warn!(pid, deny, "could not update the in-kernel verdict: {e}");
        } else if deny {
            debug!(pid, exe = %as_process.exe.display(), "in-kernel deny installed");
        }
        drop(map);
    }

    /// Compiles the process-wide rules into the kernel's own table.
    ///
    /// After this, a process that execs while no daemon is running still gets
    /// an answer: the exec program hashes the path it was handed, finds it
    /// here, and writes `VERDICTS` itself.
    ///
    /// **The precedence is not reimplemented.** For each executable any rule
    /// mentions, this asks `Engine::process_wide_action` - the same function
    /// the live path uses - and writes an entry only when it says Deny. So the
    /// kernel can never refuse something the daemon would have allowed: a
    /// higher-precedence allow, a destination-scoped rule, an expired or
    /// disabled one all come back through the same code that governs the
    /// packet path.
    ///
    /// The synthetic process carries the exe and nothing else. That is safe
    /// only because `compilable_exe_paths` already excluded every executable a
    /// uid-scoped rule could touch - a uid-less process does *not* match a
    /// uid-scoped allow, so evaluating one here would compile the deny that
    /// allow was meant to outrank (the exact defect fixed in e56429b; the
    /// earlier version of this comment claimed the opposite). Hash-scoped
    /// rules still make `process_wide_action` abstain, which means "no entry",
    /// which means "ask the packet path" - never "allow".
    ///
    /// Full rebuild rather than a diff: the table is one entry per exe-scoped
    /// rule, and a diff would have to reason about which removals are safe.
    pub(super) fn compile_rules(&self) {
        let Some(rules) = self.exe_rules.as_ref() else {
            return;
        };
        let mut table = rules.lock();

        // Every executable any enabled rule names. A path nothing mentions
        // cannot produce a deny, so it need not be asked about.
        // `None` means a uid-scoped rule names no executable and so could apply
        // to any program: nothing can be compiled safely. Empty the table
        // rather than leave a stale one behind.
        let exes = self.engine.compilable_exe_paths().unwrap_or_default();

        let mut wanted: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
        for exe in &exes {
            let proc = Process {
                exe: exe.clone(),
                ..Process::unknown(0)
            };
            if matches!(
                self.engine.process_wide_action(&proc),
                Some(Action::Deny | Action::Reject)
            ) {
                let key = cfc_ebpf_common::hash_exe_path(exe.as_os_str().as_encoded_bytes());
                wanted.insert(key, cfc_ebpf_common::verdict::DENY);
            }
        }

        // Nothing to do when the answer has not moved, and usually it has not:
        // this runs on every rule change, and most of them - a port, a host, an
        // allow, a hit count - do not touch which executables are denied
        // outright. Skipping here is the difference between a rule edit costing
        // a handful of `bpf(2)` syscalls and costing none.
        if self.last_compiled.lock().as_ref() == Some(&wanted) {
            return;
        }

        // Drop what is no longer wanted before adding, so a full table cannot
        // reject the additions.
        let stale: Vec<u64> = table
            .keys()
            .flatten()
            .filter(|k| !wanted.contains_key(k))
            .collect();
        for k in stale {
            let _ = table.remove(&k);
        }
        let mut written = 0usize;
        for (k, v) in &wanted {
            match table.insert(k, v, 0) {
                Ok(()) => written += 1,
                Err(e) => warn!(key = k, "could not write an in-kernel exe rule: {e}"),
            }
        }
        drop(table);

        // Memoised only now, and only when every write landed. Recording it
        // before would mean a failed insert was remembered as done and never
        // retried on a later identical recompute.
        if written == wanted.len() {
            *self.last_compiled.lock() = Some(wanted);
        }

        // The gate the exec program reads before hashing anything.
        if let Some(on) = self.exe_rules_on.as_ref() {
            let value: u32 = u32::from(written > 0);
            if let Err(e) = on.lock().set(0, value, 0) {
                warn!("could not update the in-kernel exe-rule gate: {e}");
            }
        }
        debug!(
            rules = written,
            executables = exes.len(),
            "compiled process-wide rules into the kernel"
        );
    }

    /// Evicts a dead pid.
    ///
    /// Not merely tidiness: this map is *pinned*, so an entry the daemon
    /// forgets outlives the daemon, and the next process to be handed that pid
    /// would inherit its answer.
    pub(super) fn on_exit(&self, pid: u32) {
        if let Err(e) = clear(&mut self.map.lock(), pid) {
            warn!(pid, "could not evict the in-kernel verdict: {e}");
        }
    }
}

/// `/proc/<pid>/exe` as rules match it (`policy_exe_path`). `None` when the
/// process is gone or its image cannot be read.
fn proc_exe(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt as _;
    let link = format!("/proc/{pid}/exe");
    let path = std::fs::read_link(&link).ok()?;
    let unlinked = std::fs::metadata(&link).ok()?.nlink() == 0;
    Some(crate::process_resolve::policy_exe_path(path, unlinked))
}

/// Everything a resync decision needs about one pid, read from /proc, plus the
/// start time the read happened at.
///
/// This is *the* decider for both loops in `resync`. `matches_process` looks at
/// three things - the executable path, its hash, and the uid - so a view built
/// from the resolved path and the live uid is the whole decision surface; the
/// hash stays `None` here on purpose, which is what makes a hash-scoped rule
/// abstain and keeps the tri-state the sweep depends on.
///
/// `None` means the process is gone or its /proc is unreadable, which callers
/// must treat as "no answer" rather than falling back to a guess.
fn proc_view(pid: u32) -> Option<(Process, Option<u64>)> {
    // `proc_exe` strips the kernel's " (deleted)" suffix - a package upgrade
    // under a running program, which process_resolve calls Tuesday on a rolling
    // distribution. Rules match on exact path equality, so the raw suffixed
    // path matched no rule and abstained for none: the sweep then read a
    // standing deny for the *upgraded* binary as a deleted rule and cleared it.
    let exe = proc_exe(pid)?;
    let uid = proc_uid(pid);
    // Read last, so it dates the whole view: a caller comparing it again at
    // write time learns whether anything it read still describes this pid.
    let starttime = proc_starttime(pid);
    Some((
        Process {
            exe,
            uid,
            ..Process::unknown(pid)
        },
        starttime,
    ))
}

/// Real uid of a live process, from `/proc/<pid>/status`.
///
/// `None` when the process is gone or the line is missing, and the caller must
/// treat that as "cannot decide" rather than "no uid": a uid-scoped allow does
/// not match a process with no uid, so guessing turns an exemption into a
/// refusal that stands.
fn proc_uid(pid: u32) -> Option<u32> {
    // Bytes, decoded lossily - not `read_to_string`. The `Name:` line carries
    // the process's comm raw, so a program whose name is not valid UTF-8 (an
    // execve of such a filename, or any `prctl(PR_SET_NAME)`) made this answer
    // `None` for a live process, permanently. U+FFFD cannot introduce a colon
    // or a digit, so the parse below is unchanged.
    let status =
        String::from_utf8_lossy(&std::fs::read(format!("/proc/{pid}/status")).ok()?).into_owned();
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Start time of a live process (clock ticks since boot, field 22 of
/// `/proc/<pid>/stat`), or `None` when the process is gone.
///
/// This is the one property of a pid the kernel never recycles within a boot:
/// two processes may share a pid across time, never a (pid, starttime) pair.
/// The orphan sweep compares it across its judge-then-clear window so a clear
/// aimed at one process cannot land on the pid's next owner.
fn proc_starttime(pid: u32) -> Option<u64> {
    // Same reason as `proc_uid`, and it matters more here: the kernel writes
    // comm unescaped into this file, and every guard built on this function
    // treats `None` as "no process". A program named with non-UTF-8 bytes was
    // therefore - once the deny pass started filtering on the start time -
    // never given an in-kernel deny, which is resync's whole job.
    // Permanently, not transiently.
    let stat =
        String::from_utf8_lossy(&std::fs::read(format!("/proc/{pid}/stat")).ok()?).into_owned();
    // The comm field is parenthesised and may itself contain spaces and
    // parentheses, so counting fields from the LEFT miscounts for a process
    // named, say, ":-) 1 2 3". Everything after the last ')' is fixed-format;
    // starttime is the 20th field from there (22nd overall).
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// Removes `pid`'s entry, treating "there was no entry" as success.
///
/// It nearly always *is* the outcome: only a process with a standing deny ever
/// gets an entry, and every other exec and every exit still comes through here
/// to make sure a recycled pid inherits nothing.
///
/// `MapError::KeyNotFound` looks like the arm to match and is not: aya only
/// returns that from `get`. `remove` hands back the raw `bpf_map_delete_elem`
/// failure, so the absent case has to be read out of the errno. Getting this
/// wrong is not cosmetic - it logged a warning for **every exec on the
/// machine**, which is both a flood and an accusation that the enforcement
/// layer is broken when it is working exactly as intended.
fn clear(map: &mut BpfHashMap<MapData, u32, u32>, pid: u32) -> Result<(), aya::maps::MapError> {
    match map.remove(&pid) {
        Err(e) if is_absent(&e) => Ok(()),
        other => other,
    }
}

/// True when a map error is the kernel saying "no such key".
fn is_absent(err: &aya::maps::MapError) -> bool {
    if matches!(err, aya::maps::MapError::KeyNotFound) {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        if let Some(io) = e.downcast_ref::<io::Error>() {
            return io.raw_os_error() == Some(libc::ENOENT);
        }
        source = e.source();
    }
    false
}

/// Per-CPU counters, summed. See [`enforce_stat`].
///
/// Only the slots the daemon still reports. The kernel also counts the
/// legacy Fast Allow outcomes, and the slot layout stays as it is.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct EnforceStats {
    /// `connect()` calls refused in-kernel, before a packet existed.
    pub denied: u64,
    /// `connect()` calls with no entry, which went on to the packet path.
    pub unknown: u64,
    /// Decisions the kernel made and could not report, because the ring was
    /// full.
    pub report_dropped: u64,
}

/// The directory this build pins into.
pub(super) fn pin_dir() -> PathBuf {
    Path::new(BPFFS)
        .join(PIN_NAMESPACE)
        .join(format!("v{ABI_VERSION}"))
}

/// True when `path` is on a bpffs mount.
fn is_bpffs(path: &Path) -> io::Result<bool> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `buf` is a valid, correctly sized statfs; `c` is NUL-terminated
    // and outlives the call.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut buf) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // `f_type` is already i64 on 64-bit and u32 on 32-bit; the conversion is
    // redundant on the arch clippy is looking at and required on the other.
    #[allow(clippy::useless_conversion)]
    Ok(i64::from(buf.f_type) == BPF_FS_MAGIC)
}

/// Makes sure the pin directory exists on a real bpffs, and removes the pins of
/// any other ABI version.
///
/// Returns `Err` when pinning is not possible at all, which is not fatal to the
/// daemon: the caller records it and attaches without pinning, which still
/// enforces for as long as the process lives.
pub(super) fn prepare() -> anyhow::Result<PathBuf> {
    let root = Path::new(BPFFS);
    if !is_bpffs(root).with_context(|| format!("stat {BPFFS}"))? {
        // States the fact only. The caller in the loader wraps every error
        // from here with the consequence ("cannot be pinned; it will stop
        // when this daemon does") - repeating it here printed the clause
        // twice in one note.
        return Err(anyhow!(
            "{BPFFS} is not a bpffs mount (mount -t bpf bpffs {BPFFS})"
        ));
    }
    let ns = root.join(PIN_NAMESPACE);
    std::fs::create_dir_all(&ns).with_context(|| format!("creating {}", ns.display()))?;
    unpin_other_versions(&ns);
    let dir = pin_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    remove_legacy_pins(&dir);
    Ok(dir)
}

/// Removes pins left by an object with a different event ABI.
///
/// Best effort by design: a directory that cannot be cleaned is logged and
/// skipped, because failing here would refuse to start enforcement over a
/// leftover from a version that is no longer running anyway. The visible
/// consequence of a failure is the `EEXIST` from the subsequent attach, which
/// the caller reports with the same detail.
fn unpin_other_versions(namespace: &Path) {
    let mine = format!("v{ABI_VERSION}");
    let entries = match std::fs::read_dir(namespace) {
        Ok(e) => e,
        Err(e) => {
            debug!("cannot list {}: {e}", namespace.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == mine.as_str() {
            continue;
        }
        let path = entry.path();
        // `remove_dir_all` on bpffs unpins every object inside, which drops the
        // kernel's last reference to those links and detaches them.
        match std::fs::remove_dir_all(&path) {
            Ok(()) => warn!(
                "removed BPF pins from a previous event ABI at {}; \
                 its in-kernel enforcement is now detached",
                path.display()
            ),
            Err(e) => warn!(
                "could not remove stale BPF pins at {}: {e}; \
                 in-kernel enforcement may fail to attach",
                path.display()
            ),
        }
    }
}

/// True when both link pins are present, i.e. a previous daemon left
/// enforcement running and this one should steer it rather than replace it.
///
/// Exactly one pin present is a half-attached leftover - a daemon that died
/// between pinning connect4 and pinning connect6 - and it does not count as
/// attached. [`attach`] removes it before attaching fresh; without that, the
/// lone pin held the cgroup's Single-mode slot, every later start failed with
/// EEXIST, and the stale program went on refusing IPv4 connect() from the
/// shared pinned map with no daemon steering it and nobody consuming its deny
/// events. That state never healed short of `rm` under bpffs or a reboot.
pub(super) fn already_attached(dir: &Path) -> bool {
    dir.join("connect4").exists() && dir.join("connect6").exists()
}

/// Removes what a 0.4-0.6 daemon pinned for Fast Allow and nothing reads any
/// more: the two sendmsg links and the cookie-variant marker directory.
///
/// Removing a link pin drops the kernel's last reference and detaches the
/// program, so this is also what takes an older daemon's inert sendmsg hooks
/// off the cgroup, on the inherited path as much as on a fresh attach. Absent
/// is the ordinary case and says nothing. The legacy *maps* stay pinned: the
/// connect programs still read them, and [`disarm_legacy_fast_allow`] needs
/// to reach the pinned copies.
fn remove_legacy_pins(dir: &Path) {
    for name in [LINK_SENDMSG4, LINK_SENDMSG6] {
        let pin = dir.join(name);
        match std::fs::remove_file(&pin) {
            Ok(()) => debug!("removed the legacy {name} pin at {}", pin.display()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                "could not remove the legacy {name} pin at {}: {e}",
                pin.display()
            ),
        }
    }
    let marker = dir.join(LEGACY_COOKIE_MARKER);
    match std::fs::remove_dir(&marker) {
        Ok(()) => debug!("removed the legacy marker at {}", marker.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            "could not remove the legacy marker at {}: {e}",
            marker.display()
        ),
    }
}

/// Withdraws whatever Fast Allow state the pinned maps still hold: a zero
/// deadline, the unarmed mark, and no grants.
///
/// The daemon no longer grants, but the kernel object still carries the maps
/// (ABI v4) and the connect programs still consult them. They are pinned, so
/// a 0.4-0.6 daemon that died while armed left its mark armed across any
/// number of restarts. The hooks stop setting it once the deadline passes, but
/// they go on stripping that value from every socket carrying it, and a random
/// mark can collide with the fwmark selectors of kube-proxy, Tailscale or
/// wg-quick. With `UNARMED`
/// written, `mark_decision` returns at its first array read. Best effort: a
/// map that is missing or will not take the write is logged and skipped.
pub(super) fn disarm_legacy_fast_allow(bpf: &mut Ebpf) {
    if let Some(m) = bpf.map_mut(MAP_FAST_ALLOW_UNTIL) {
        match aya::maps::Array::<_, u64>::try_from(m) {
            Ok(mut until) => {
                if let Err(e) = until.set(0, 0u64, 0) {
                    warn!("could not zero the legacy {MAP_FAST_ALLOW_UNTIL}: {e}");
                }
            }
            Err(e) => warn!("{MAP_FAST_ALLOW_UNTIL} is not an array: {e}"),
        }
    }
    if let Some(m) = bpf.map_mut(MAP_FAST_ALLOW_MARK) {
        match aya::maps::Array::<_, u32>::try_from(m) {
            Ok(mut mark) => {
                if let Err(e) = mark.set(0, cfc_ebpf_common::fast_allow::UNARMED, 0) {
                    warn!("could not unarm the legacy {MAP_FAST_ALLOW_MARK}: {e}");
                }
            }
            Err(e) => warn!("{MAP_FAST_ALLOW_MARK} is not an array: {e}"),
        }
    }
    if let Some(m) = bpf.map_mut(MAP_FAST_ALLOW) {
        match BpfHashMap::<_, u32, u32>::try_from(m) {
            Ok(mut grants) => {
                let pids: Vec<u32> = grants.keys().flatten().collect();
                for pid in pids {
                    match grants.remove(&pid) {
                        Err(e) if !is_absent(&e) => {
                            warn!(pid, "could not drop a legacy {MAP_FAST_ALLOW} grant: {e}")
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => warn!("{MAP_FAST_ALLOW} is not a hash map: {e}"),
        }
    }
}

/// Unpins any lone connect-link leftovers so a fresh attach starts clean.
///
/// Removing a pinned link drops the kernel's last reference and detaches the
/// program, so the half that was still enforcing IPv4 stops for the moment
/// between this and the attach a few lines later. That brief gap - covered by
/// the packet path like any other unenforced moment - is the price of not
/// being wedged forever.
fn drop_half_attached(dir: &Path) {
    for name in ["connect4", "connect6"] {
        let pin = dir.join(name);
        if !pin.exists() {
            continue;
        }
        match std::fs::remove_file(&pin) {
            Ok(()) => warn!(
                "removed a half-attached {name} pin at {}; a previous daemon \
                 died mid-attach and its leftover held the cgroup slot",
                pin.display()
            ),
            Err(e) => warn!(
                "could not remove the stale {name} pin at {}: {e}; \
                 the attach below will likely fail with EEXIST",
                pin.display()
            ),
        }
    }
}

/// Loads, attaches and pins one `cgroup/connect*` program.
///
/// Returns the verified instruction count when the kernel reports it, matching
/// the other attach helpers.
fn attach_one(
    bpf: &mut Ebpf,
    name: &str,
    cgroup: &std::fs::File,
    pin: Option<&Path>,
) -> anyhow::Result<Option<u32>> {
    let prog: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("no program named `{name}` in the object"))?
        .try_into()
        .with_context(|| format!("`{name}` is not a cgroup_sock_addr program"))?;
    prog.load().context("verifier rejected the program")?;
    let insns = super::loader::verifier_cost(name, prog.info());
    // `Single`, as with the DNS observer: stacking a second copy would double
    // nothing here (the verdicts are idempotent), but it would hide a failed
    // cleanup, and cgroup programs are AND-ed - a leaked copy from an older
    // build would keep voting.
    let id = prog
        .attach(cgroup.as_fd(), CgroupAttachMode::Single)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("attaching {name} to the cgroup v2 root"))?;

    let Some(pin) = pin else {
        return Ok(insns);
    };
    // Taking the link is what stops `Ebpf`'s drop from detaching it. From here
    // the pin owns it: dropping the returned `PinnedLink` closes this process's
    // fd and leaves the kernel reference held by bpffs, which is the entire
    // point of this module.
    let link = prog
        .take_link(id)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("taking the {name} link"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(anyhow::Error::new)
        .with_context(|| format!("{name} link is not fd-based (needs kernel >= 5.7)"))?;
    // On failure this does NOT leave the program attached-but-unpinned:
    // `pin` consumes the link, the error path drops it, and dropping the last
    // fd of a taken link detaches the program - so the Single-mode cgroup
    // slot frees and the caller's `_basic` fallback attaches cleanly. Worth
    // stating because the opposite reading (attached ghost holding the slot,
    // fallback dying on EEXIST) is the natural first guess, and disproving it
    // took a walk through aya's ownership rather than through this file.
    fd_link
        .pin(pin)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("pinning {name} to {}", pin.display()))?;
    Ok(insns)
}

/// Attaches both connect programs, pinning them under `dir` when it is
/// `Some`, and returns every program attached with its verified instruction
/// count.
///
/// `dir` is `None` when [`prepare`] failed: the programs still attach and still
/// enforce, they just stop when this process does. That is strictly better than
/// not attaching, and worse than pinning, so the caller says which happened.
pub(super) fn attach(
    bpf: &mut Ebpf,
    dir: Option<&Path>,
) -> anyhow::Result<Vec<(String, Option<u32>)>> {
    let root = super::cgroup::v2_root()
        .ok_or_else(|| anyhow!("no cgroup2 mount in /proc/mounts (unified hierarchy required)"))?;
    // Read-only, for the same reason as the DNS attach: the kernel wants the
    // cgroup as an attach target, and the unit makes cgroupfs read-only.
    let cgroup = std::fs::File::open(&root)
        .with_context(|| format!("opening cgroup v2 root {}", root.display()))?;

    // This function only runs when already_attached() said no - which
    // includes the half-attached case, where one leftover pin would make
    // every attach below fail with EEXIST forever.
    if let Some(dir) = dir {
        drop_half_attached(dir);
    }

    let mut out = Vec::with_capacity(4);
    let mut pinned: Vec<std::path::PathBuf> = Vec::with_capacity(4);
    for (name, basic, pin_name) in [
        (PROG_CONNECT4, PROG_CONNECT4_BASIC, "connect4"),
        (PROG_CONNECT6, PROG_CONNECT6_BASIC, "connect6"),
    ] {
        let pin = dir.map(|d| d.join(pin_name));
        // The cookie variant first. A verifier rejection here is the expected
        // answer on a kernel without `bpf_get_socket_cookie` for sock_addr
        // programs, not a bug - so it downgrades to the `_basic` twin rather
        // than failing the layer. Any error on the *fallback* is real and
        // propagates - after unwinding whatever this loop already pinned, or
        // the failure itself would manufacture the half-attached state the
        // cleanup above exists to remove.
        let insns = match attach_one(bpf, name, &cgroup, pin.as_deref()) {
            Ok(i) => {
                if let Some(p) = &pin {
                    pinned.push(p.clone());
                }
                out.push((name.to_string(), i));
                continue;
            }
            Err(first) => {
                // Not "did not verify": attach_one can fail past the verifier
                // (the attach itself, taking the link, pinning), and claiming
                // a verifier rejection for an EEXIST sent a reader hunting a
                // program bug where there was a state bug.
                warn!(
                    "{name} could not load or attach ({first:#}); attaching \
                     {basic} - enforcement is unaffected; O(1) attribution is \
                     unavailable"
                );
                match attach_one(bpf, basic, &cgroup, pin.as_deref()) {
                    Ok(i) => i,
                    Err(e) => {
                        for p in &pinned {
                            let _ = std::fs::remove_file(p);
                        }
                        return Err(e);
                    }
                }
            }
        };
        if let Some(p) = &pin {
            pinned.push(p.clone());
        }
        out.push((basic.to_string(), insns));
    }
    Ok(out)
}

/// Removes entries for pids that no longer exist.
///
/// Necessary because the exit tracepoint is *not* pinned: while the daemon is
/// down nothing evicts, so a pid recycled in that window would inherit the
/// previous holder's verdict. Sweeping at startup closes it. A stale deny is
/// merely wrong in the safe direction; a stale allow would not be, which is why
/// this runs before the daemon writes anything new.
pub(super) fn sweep(verdicts: &mut BpfHashMap<&mut MapData, u32, u32>) -> usize {
    let stale: Vec<u32> = verdicts
        .keys()
        .flatten()
        .filter(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        .collect();
    let mut removed = 0;
    for pid in stale {
        if verdicts.remove(&pid).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Sums the per-CPU counters.
pub(super) fn stats(map: &PerCpuArray<&MapData, u64>) -> anyhow::Result<EnforceStats> {
    // A pin from an earlier build of the *same* ABI version can be one slot
    // short. `ENFORCE_STATS` is pinned, the pin directory is keyed on the ABI
    // version, and `REPORT_DROPPED` was added inside v4 rather than across a
    // bump - so a daemon upgraded in place reuses a five-slot pin while this
    // build asks for six. Reading past the end must answer "this counter did
    // not exist", not fail the whole read: every other counter is still true,
    // and losing all of them would take the startup carry-over note and
    // `cfc status` with it. The kernel side is already safe on its own -
    // `get_ptr_mut` bounds-checks and `bump` silently does nothing.
    let read = |slot: u32| -> anyhow::Result<u64> {
        match map.get(&slot, 0) {
            Ok(v) => Ok(v.iter().sum()),
            // The pin is one slot short. `map.len()` cannot see that - it
            // reports the `max_entries` this build's *object* declares, not
            // the pinned map's, so the two disagree exactly when it matters
            // and a guard written on it was inert on the only path it existed
            // for. The kernel answers ENOENT for an index past its own end,
            // which aya reports as `KeyNotFound`; that is the one place the
            // real slot count is observable here. An in-range lookup on a
            // PERCPU_ARRAY can never answer KeyNotFound, so reading it as
            // "this counter did not exist in the build that made this pin" is
            // unambiguous.
            Err(aya::maps::MapError::KeyNotFound) => Ok(0),
            Err(e) => Err(anyhow::Error::new(e).context(format!("reading {MAP_STATS}[{slot}]"))),
        }
    };
    Ok(EnforceStats {
        denied: read(enforce_stat::DENIED)?,
        unknown: read(enforce_stat::UNKNOWN)?,
        report_dropped: read(enforce_stat::REPORT_DROPPED)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of `proc_view` is that it reads the *resolved* path and
    /// the *current* uid, which is what separates it from the exec record the
    /// resync live loop used to decide from.
    #[test]
    fn proc_view_reads_the_resolved_path_and_the_live_uid() {
        let me = std::process::id();
        let (proc, starttime) = proc_view(me).expect("this process has a /proc");

        let real = std::fs::read_link("/proc/self/exe").expect("readable /proc/self/exe");
        assert_eq!(proc.exe, real, "the view must carry the resolved path");
        assert!(
            proc.exe.is_absolute(),
            "a resolved path is absolute even when argv[0] was relative - the \
             property the live loop lacked, which made it skip such a process"
        );

        // SAFETY: getuid(2) cannot fail and touches no memory.
        assert_eq!(proc.uid, Some(unsafe { libc::getuid() }));
        assert_eq!(
            proc.sha256, None,
            "the hash stays unread here on purpose: it is what makes a \
             hash-scoped rule abstain, and the sweep's tri-state depends on it"
        );
        assert!(starttime.is_some(), "a live pid has a start time");
    }

    /// A view that cannot be read must not become a guess: both callers turn
    /// `None` into "no answer", and the fallback to the exec record is exactly
    /// the bug this replaced.
    #[test]
    fn proc_view_of_a_pid_that_cannot_exist_is_none() {
        // Above /proc/sys/kernel/pid_max on every configuration; no process
        // can hold it, so this is "gone", not "unreadable by us".
        assert!(proc_view(u32::MAX).is_none());
    }

    #[test]
    fn the_pin_directory_carries_the_event_abi_version() {
        let dir = pin_dir();
        assert!(
            dir.ends_with(format!("v{ABI_VERSION}")),
            "an object built against a different event layout must not inherit \
             these pins: {}",
            dir.display()
        );
        assert!(dir.starts_with(BPFFS));
    }

    #[test]
    fn a_plain_directory_is_not_mistaken_for_a_bpffs() {
        // /tmp is a tmpfs or a disk filesystem, never a bpffs. This is the case
        // that matters: `/sys/fs/bpf` exists as an ordinary directory when
        // nothing has mounted over it, and pinning into it would appear to work
        // while pinning nothing.
        assert!(!is_bpffs(Path::new("/tmp")).expect("statfs /tmp"));
    }

    #[test]
    fn a_missing_path_is_an_error_not_a_false_positive() {
        let e = is_bpffs(Path::new("/nonexistent-fbc93a2e")).expect_err("should fail");
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
    }

    /// The claim this whole module exists to make, checked end to end with no
    /// daemon in the picture.
    ///
    /// Sequence: load and attach with pinning, then **drop everything** - the
    /// `Ebpf`, the links, every fd this process holds. That is exactly what
    /// `kill -9` on the daemon does. Then reopen the map from its pin, write a
    /// deny for a child's pid, and watch the child's `connect()` come back
    /// `EPERM`. Nothing that could serve that verdict is alive except the
    /// kernel and bpffs.
    ///
    /// Root, and ignored by default like the other live tests:
    ///
    /// ```text
    /// cargo build -p cfc-daemon --tests
    /// sudo ./target/fast/deps/cfc_daemon-<hash> --ignored --nocapture \
    ///     enforces_a_pinned_deny
    /// ```
    #[tokio::test]
    #[ignore = "needs root and a BPF-capable kernel"]
    async fn enforces_a_pinned_deny_with_no_daemon_alive() {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::process::{Command, Stdio};

        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("skipping: not root");
            return;
        }
        let object = std::env::var("CFC_EBPF_OBJECT")
            .unwrap_or_else(|_| super::super::DEFAULT_OBJECT_PATH.to_string());
        if !Path::new(&object).exists() {
            eprintln!("skipping: no object at {object}");
            return;
        }
        if !Path::new("/bin/bash").exists() {
            eprintln!("skipping: needs bash for /dev/tcp");
            return;
        }

        // A listener that will accept, so "connected" and "refused" are not the
        // same observation. Leaked deliberately: the child needs it alive.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();

        // 1. Bring enforcement up, pinned...
        let (attached, report) = super::super::loader::load_and_attach(
            Path::new(&object),
            crate::dns::DnsCache::new(),
            super::super::proc_table::KernelProcTable::new(),
            None,
            super::super::loader::Trust::Warn,
        )
        .expect("load");
        assert_eq!(
            report.enforcement,
            super::super::Enforcement::Pinned,
            "the point of the test is the pin: {:?}",
            report.notes
        );

        // 2. ...and now take the daemon away. Every fd, every link, the whole
        //    aya object. What is left is bpffs and the kernel.
        drop(attached);

        // 3. Reopen the verdict map through its pin alone.
        let pin = pin_dir().join(MAP_VERDICTS);
        let data = MapData::from_pin(&pin).expect("reopen the pinned VERDICTS map");
        let mut verdicts = BpfHashMap::<_, u32, u32>::try_from(aya::maps::Map::HashMap(data))
            .expect("VERDICTS is a hash map");

        // `read` blocks until the test says go, so the pid is known and the
        // verdict is in place before the connect happens. `exec 3<>` connects in
        // this same process rather than a fork, so the pid is the right one.
        let spawn = || {
            Command::new("/bin/bash")
                .arg("-c")
                .arg(format!(
                    "read -r _; \
                     if exec 3<>/dev/tcp/127.0.0.1/{port}; then echo CONNECTED; \
                     else echo REFUSED; fi"
                ))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn bash")
        };
        let go = |child: &mut std::process::Child| -> String {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(b"\n")
                .expect("write");
            let out = child.stdout.take().expect("stdout");
            let line = BufReader::new(out)
                .lines()
                .next()
                .and_then(Result::ok)
                .unwrap_or_default();
            let _ = child.wait();
            line
        };

        // 4. Denied.
        let mut denied = spawn();
        verdicts
            .insert(denied.id(), cfc_ebpf_common::verdict::DENY, 0)
            .expect("insert the deny");
        let refused = go(&mut denied);
        verdicts.remove(&denied.id()).ok();

        // 5. Not denied: same binary, same destination, no entry.
        let mut allowed = spawn();
        let connected = go(&mut allowed);

        assert_eq!(
            refused, "REFUSED",
            "a pid with a pinned deny must not reach {port}, with no daemon running"
        );
        assert_eq!(
            connected, "CONNECTED",
            "a pid with no entry must fall through to the packet path, not be denied"
        );
        println!("pinned deny enforced with no daemon process alive");

        // Leave the machine as we found it. The pins are the durable part, so
        // they have to be removed explicitly - that is the feature.
        drop(listener);
        let _ = std::fs::remove_dir_all(Path::new(BPFFS).join(PIN_NAMESPACE));
    }

    /// The kernel evicts a verdict on process exit, with no daemon alive.
    ///
    /// This is the property that makes a pinned `VERDICTS` map safe to leave
    /// behind. Userspace evicts on exit too, which is enough while the daemon
    /// runs and is exactly nothing when it does not - and "when it does not" is
    /// the only reason the map is pinned at all.
    ///
    /// Without the in-kernel delete *and* a pinned exit link, a machine running
    /// on a dead daemon accumulates denials attached to pids that no longer
    /// exist. Linux recycles pids; unrelated programs then inherit refusals.
    /// It fails closed, so nothing breaks loudly - the protection just rots,
    /// and nothing anywhere says so.
    ///
    /// ```text
    /// sudo -E cargo test -p cfc-daemon --lib -- --ignored --nocapture \
    ///     evicts_a_verdict_on_exit
    /// ```
    #[tokio::test]
    #[ignore = "needs root and a BPF-capable kernel"]
    async fn the_kernel_evicts_a_verdict_on_exit_with_no_daemon_alive() {
        use std::process::{Command, Stdio};

        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("skipping: not root");
            return;
        }
        let object = std::env::var("CFC_EBPF_OBJECT")
            .unwrap_or_else(|_| super::super::DEFAULT_OBJECT_PATH.to_string());
        if !Path::new(&object).exists() || !Path::new("/bin/sleep").exists() {
            eprintln!("skipping: no object at {object}, or no /bin/sleep");
            return;
        }
        let _ = std::fs::remove_dir_all(Path::new(BPFFS).join(PIN_NAMESPACE));

        let (attached, report) = super::super::loader::load_and_attach(
            Path::new(&object),
            crate::dns::DnsCache::new(),
            super::super::proc_table::KernelProcTable::new(),
            None,
            super::super::loader::Trust::Warn,
        )
        .expect("load");
        assert_eq!(
            report.enforcement,
            super::super::Enforcement::Pinned,
            "the point of the test is the pin: {:?}",
            report.notes
        );
        assert!(
            pin_dir().join(LINK_EXIT).exists(),
            "the exit link was not pinned, so nothing will evict once the daemon goes"
        );

        // A process that will sit still until told otherwise, so its pid is
        // stable while the verdict is written.
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        {
            let pin = pin_dir().join(MAP_VERDICTS);
            let data = MapData::from_pin(&pin).expect("reopen the pinned VERDICTS map");
            let mut verdicts = BpfHashMap::<_, u32, u32>::try_from(aya::maps::Map::HashMap(data))
                .expect("VERDICTS is a hash map");
            verdicts
                .insert(pid, cfc_ebpf_common::verdict::DENY, 0)
                .expect("write the verdict");
            assert_eq!(
                verdicts.get(&pid, 0).ok(),
                Some(cfc_ebpf_common::verdict::DENY)
            );
        }

        // Take the daemon away. Every fd, every link this process owns, the
        // whole aya object. What is left is bpffs and the kernel.
        drop(attached);

        child.kill().expect("kill");
        child.wait().expect("reap");
        // The tracepoint fires during exit; give the kernel a moment to run it.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let pin = pin_dir().join(MAP_VERDICTS);
        let data = MapData::from_pin(&pin).expect("reopen the pinned VERDICTS map");
        let verdicts = BpfHashMap::<_, u32, u32>::try_from(aya::maps::Map::HashMap(data))
            .expect("VERDICTS is a hash map");
        assert!(
            verdicts.get(&pid, 0).is_err(),
            "pid {pid} kept its verdict after exiting with no daemon alive; a \
             recycled pid would inherit it"
        );

        let _ = std::fs::remove_dir_all(Path::new(BPFFS).join(PIN_NAMESPACE));
    }

    /// The other half: a *rule* reaching the kernel by itself.
    ///
    /// The previous test wrote into the map by hand. This one writes a Deny
    /// rule into a rule engine, hands that engine to the loader, execs a copy
    /// of bash, and lets the whole chain run - exec tracepoint, ring buffer,
    /// `process_wide_action`, map write, `connect()` refusal - with nothing
    /// stubbed. A control run with no rule proves the refusal came from the
    /// rule and not from the layer simply blocking everything.
    ///
    /// Root, ignored by default:
    ///
    /// ```text
    /// sudo ./target/fast/deps/cfc_daemon-<hash> --ignored --nocapture \
    ///     a_deny_rule_reaches_the_kernel
    /// ```
    // `multi_thread` is load-bearing, not decoration. The exec event reaches
    // the verdict sink through a `tokio::spawn`ed ring-buffer consumer, and the
    // wait below blocks its thread; on the default current-thread runtime the
    // consumer would never get to run and this test would fail claiming the
    // rule did not reach the kernel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs root and a BPF-capable kernel"]
    async fn a_deny_rule_reaches_the_kernel_by_itself() {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::process::{Command, Stdio};

        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("skipping: not root");
            return;
        }
        let object = std::env::var("CFC_EBPF_OBJECT")
            .unwrap_or_else(|_| super::super::DEFAULT_OBJECT_PATH.to_string());
        if !Path::new(&object).exists() || !Path::new("/bin/bash").exists() {
            eprintln!("skipping: no object at {object}, or no bash");
            return;
        }

        // A private copy of bash, so the rule names a path nothing else on the
        // machine runs. Denying /bin/bash itself would deny the test harness's
        // own shells.
        let dir = tempfile::tempdir().expect("tempdir");
        let shell = dir.path().join("cfc-test-shell");
        std::fs::copy("/bin/bash", &shell).expect("copy bash");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let run = |engine: Option<crate::decision::Engine>| -> String {
            let (attached, report) = super::super::loader::load_and_attach(
                Path::new(&object),
                crate::dns::DnsCache::new(),
                super::super::proc_table::KernelProcTable::new(),
                engine,
                super::super::loader::Trust::Warn,
            )
            .expect("load");
            assert!(
                report.exec_tracking,
                "the rule reaches the kernel via the exec tracepoint: {:?}",
                report.notes
            );
            assert!(report.enforcement.is_live(), "{:?}", report.notes);

            let mut child = Command::new(&shell)
                .arg("-c")
                .arg(format!(
                    "read -r _; \
                     if exec 3<>/dev/tcp/127.0.0.1/{port}; then echo CONNECTED; \
                     else echo REFUSED; fi"
                ))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn");
            // The exec event travels through a ring buffer to a tokio task, so
            // the verdict is not installed synchronously with the spawn. `read`
            // is what holds the child at the starting line until it is.
            std::thread::sleep(std::time::Duration::from_millis(300));
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(b"\n")
                .expect("write");
            let out = child.stdout.take().expect("stdout");
            let line = BufReader::new(out)
                .lines()
                .next()
                .and_then(Result::ok)
                .unwrap_or_default();
            let _ = child.wait();
            drop(attached);
            let _ = std::fs::remove_dir_all(Path::new(BPFFS).join(PIN_NAMESPACE));
            line
        };

        // Control: same object, same shell, no rule.
        let without = run(None);

        // And now with a rule that denies exactly this binary, everywhere.
        let mut scope = cfc_core::RuleScope::any();
        scope.exe_path = Some(shell.clone());
        let mut rules = cfc_core::RuleSet::default();
        rules.rules.push(cfc_core::Rule::new(
            "deny-cfc-test-shell",
            Action::Deny,
            scope,
        ));
        let engine = crate::decision::Engine::new(
            rules,
            Arc::new(std::sync::RwLock::new(crate::config::DefaultPolicy {
                // Irrelevant here - `process_wide_action` never consults it -
                // but set to Deny so a bug that did consult it would show up as
                // the control run failing too.
                no_ui_action: Action::Deny,
                timeout_action: Action::Deny,
                inbound_action: Action::Deny,
                prompt_timeout_secs: 10,
            })),
        );
        let with = run(Some(engine));

        assert_eq!(
            without, "CONNECTED",
            "with no rule the connect must reach the packet path untouched"
        );
        assert_eq!(
            with, "REFUSED",
            "a process-wide Deny rule must be refused in the kernel"
        );
        println!("a Deny rule reached the kernel with nothing stubbed");
        drop(listener);
    }

    #[test]
    fn a_missing_key_is_not_an_error_worth_logging() {
        // The shape aya actually produces: `remove` wraps the raw syscall
        // failure rather than returning KeyNotFound. Matching on the variant
        // alone logged a warning for every exec on the machine.
        let enoent = aya::maps::MapError::SyscallError(aya::sys::SyscallError {
            call: "bpf_map_delete_elem",
            io_error: io::Error::from_raw_os_error(libc::ENOENT),
        });
        assert!(is_absent(&enoent));
        assert!(is_absent(&aya::maps::MapError::KeyNotFound));

        let eperm = aya::maps::MapError::SyscallError(aya::sys::SyscallError {
            call: "bpf_map_delete_elem",
            io_error: io::Error::from_raw_os_error(libc::EPERM),
        });
        assert!(
            !is_absent(&eperm),
            "a real permission failure must still be reported"
        );
    }

    #[test]
    fn already_attached_needs_both_families() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!already_attached(dir.path()));
        std::fs::write(dir.path().join("connect4"), b"").expect("write");
        assert!(
            !already_attached(dir.path()),
            "half a pin is not enforcement; IPv6 would be unfiltered"
        );
        std::fs::write(dir.path().join("connect6"), b"").expect("write");
        assert!(already_attached(dir.path()));
    }
}
