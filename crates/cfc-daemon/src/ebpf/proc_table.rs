//! Kernel-sourced process identity, fed by the `sched_process_exec` /
//! `sched_process_exit` tracepoints.
//!
//! This is the userspace mirror of the BPF `PROCS` hash map, kept in sync by
//! the two ring-buffer consumers in [`crate::ebpf`]. Process resolution
//! consults it before reading `/proc/<pid>/{stat,status}`.
//!
//! # What it does and does not buy us
//!
//! It buys three things:
//!
//! * **Identity for processes that are already gone.** NFQUEUE hands the
//!   daemon a packet some microseconds after the socket wrote it; a
//!   short-lived process (`curl`, a shell one-liner, an installer hook) can
//!   easily be reaped before `/proc/<pid>` is opened. Today that resolves to
//!   `Process::unknown`. With an exec record it resolves to a name.
//! * **Exec-time uid/gid/ppid instead of read-time.** `/proc/<pid>/status`
//!   reports whatever the process is *now*; the exec event reports what it was
//!   when it was launched, which is the thing a rule is really about.
//! * **Explicit eviction.** The exit tracepoint fires for the thread-group
//!   leader, so an entry disappears when the process does, rather than ageing
//!   out on a timer.
//!
//! It does **not** remove:
//!
//! * the socket -> pid step. NFQUEUE gives us a socket, not a pid, so
//!   `sock_diag` (or the `/proc/net` table walk, or the `/proc/*/fd` scan)
//!   still runs first, and this table can only help *after* a pid is in hand.
//!   Kernel-side flow attribution would need a different hook entirely.
//! * the `/proc/<pid>/exe` read. The exec event carries the path as passed to
//!   `execve()`, which may be relative, may be a symlink, and is not what the
//!   digest and package provenance describe - those hash the image the kernel
//!   actually mapped. So the exec path is used as a *fallback* when `/proc` is
//!   gone, never as an override of a readable `/proc/<pid>/exe`. See
//!   `crate::process_resolve::resolve_inner`.
//! * `cmdline` and `cwd`, which have no kernel-side source here.
//!
//! # PID reuse
//!
//! An entry is bound to `/proc/<pid>/stat`'s start time (field 22), captured
//! by the exec consumer right after the event arrives. A later lookup that
//! presents a different start time is a recycled pid: the entry is dropped and
//! the caller falls back to `/proc`. That is exact, not heuristic.
//!
//! Two softer cases remain, both handled conservatively:
//!
//! * the consumer lost the race and could not read the start time (the process
//!   was already gone). The entry is then bound to the *first* start time a
//!   lookup presents, which still catches every subsequent reuse.
//! * the exit event was dropped (ring buffer overflow under an exec storm).
//!   The start-time binding catches the reuse anyway; the TTL below is the
//!   backstop for the case where nothing ever looks the pid up again.

use cfc_ebpf_common::ExecEvent;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// How long an entry survives without being refreshed by a new exec.
///
/// This is a memory backstop, not the correctness mechanism - exit events and
/// the start-time binding are. An hour is long enough that a long-lived daemon
/// keeps its kernel-sourced identity across an idle period, and short enough
/// that a table which somehow stopped receiving exit events drains instead of
/// growing without bound.
const ENTRY_TTL: Duration = Duration::from_secs(3600);

/// Hard cap on live entries, matching the kernel map's `max_entries`. When
/// full, expired entries are pruned first and then the oldest is evicted.
const MAX_ENTRIES: usize = 10_240;

/// One process as the kernel described it at `execve()` time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelProc {
    pub pid: u32,
    /// Thread-group id of the parent, or `None` when the loader could not
    /// resolve the `task_struct` offsets from BTF (the kernel side then
    /// reports 0, which means "unknown", never "init").
    pub ppid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    /// Path as passed to `execve()`. May be relative; see the module docs.
    pub exe: PathBuf,
    /// `task_struct::comm`, i.e. the 15-character kernel process name.
    pub comm: String,
}

impl KernelProc {
    /// The exec path, but only when it is absolute.
    ///
    /// `execve()` takes whatever string the caller passed, so a process
    /// launched as `./configure` records a path that means nothing outside the
    /// launcher's cwd - and rules match on absolute paths. Relative records
    /// are kept (they still name the binary in a prompt) but never fed to rule
    /// evaluation as an `exe`.
    pub fn absolute_exe(&self) -> Option<&Path> {
        self.exe.is_absolute().then_some(self.exe.as_path())
    }
}

impl From<&ExecEvent> for KernelProc {
    fn from(e: &ExecEvent) -> Self {
        Self {
            pid: e.pid,
            // 0 is the kernel side's "unresolved", not pid 0.
            ppid: (e.ppid != 0).then_some(e.ppid),
            uid: e.uid,
            gid: e.gid,
            // `filename_len == 0` is the kernel side saying it did not read a
            // path: either the probe read faulted, or the loader switched the
            // read off because this kernel's tracepoint record is a shape it
            // cannot parse. Build an empty path rather than whatever the
            // per-CPU scratch buffer happens to still hold from a previous
            // event -- the buffer is deliberately not memset (a 292-byte
            // memset does not lower on the BPF backend), so its tail is stale
            // by design and only `filename_len` says how much of it is real.
            //
            // `absolute_exe()` already drops an empty path from rule
            // evaluation, so this is belt-and-braces at this layer. It is
            // worth having anyway because a *garbage but absolute* path could
            // not be detected here at all, which is why the real defence is
            // suppressing the read at the source.
            exe: if e.filename_len == 0 {
                PathBuf::new()
            } else {
                PathBuf::from(e.filename_str().into_owned())
            },
            comm: e.comm_str().into_owned(),
        }
    }
}

struct Entry {
    proc: KernelProc,
    seen_at: Instant,
    /// `/proc/<pid>/stat` start time, the pid-reuse discriminator. `None`
    /// until it is known; see the module docs.
    starttime: Option<u64>,
}

#[derive(Default)]
struct Shared {
    map: RwLock<HashMap<u32, Entry>>,
    /// Whether the exec tracepoint is actually attached. Lookups short-circuit
    /// on this, so in the default build - eBPF off, table permanently empty -
    /// the packet path pays one relaxed atomic load and never touches the
    /// lock or the map.
    live: AtomicBool,
}

/// Live process identity as reported by the kernel.
///
/// Cheap to clone (one `Arc`); the daemon uses the process-wide [`global`]
/// instance and tests build their own.
#[derive(Clone, Default)]
pub struct KernelProcTable {
    inner: std::sync::Arc<Shared>,
}

/// The process-wide table.
///
/// A static rather than a value threaded through the call graph, for the same
/// reason `crate::provenance`'s switch is: `process_resolve::resolve` is a
/// free function reached from the packet path through two trait objects, and
/// widening those signatures to carry a handle that is empty in the default
/// build would be all cost and no clarity.
pub fn global() -> &'static KernelProcTable {
    static TABLE: LazyLock<KernelProcTable> = LazyLock::new(KernelProcTable::default);
    &TABLE
}

impl KernelProcTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the table as fed by a live exec tracepoint. Until this is set,
    /// every lookup returns `None` regardless of contents.
    pub fn set_live(&self, live: bool) {
        self.inner.live.store(live, Ordering::Relaxed);
    }

    pub fn is_live(&self) -> bool {
        self.inner.live.load(Ordering::Relaxed)
    }

    /// Number of live entries. Test and diagnostics only.
    pub fn len(&self) -> usize {
        self.inner.map.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Records an exec. A second exec for the same pid replaces the first,
    /// which is exactly right: the pid now runs a different program.
    pub fn observe_exec(&self, event: &ExecEvent, starttime: Option<u64>, now: Instant) {
        let proc = KernelProc::from(event);
        let mut map = self.inner.map.write();
        if map.len() >= MAX_ENTRIES && !map.contains_key(&proc.pid) {
            map.retain(|_, e| now.saturating_duration_since(e.seen_at) <= ENTRY_TTL);
            if map.len() >= MAX_ENTRIES {
                if let Some(oldest) = map.iter().min_by_key(|(_, e)| e.seen_at).map(|(k, _)| *k) {
                    map.remove(&oldest);
                }
            }
        }
        map.insert(
            proc.pid,
            Entry {
                proc,
                seen_at: now,
                starttime,
            },
        );
    }

    /// Every live entry, for a caller that has to act on all of them at once
    /// rather than answer one lookup.
    ///
    /// The one such caller is the in-kernel verdict resync: when a rule
    /// changes, the answer for *already running* processes changes with it, and
    /// there is no event to hang that off - `exec` already happened. Entries
    /// past their TTL are skipped rather than evicted, because this is not a
    /// lookup and should not have side effects on the table.
    ///
    /// Returns empty when the table is not live, exactly as [`Self::get`] does:
    /// without the exec tracepoint these entries are stale by construction.
    pub fn live_processes(&self, now: Instant) -> Vec<KernelProc> {
        if !self.is_live() {
            return Vec::new();
        }
        self.inner
            .map
            .read()
            .values()
            .filter(|e| now.saturating_duration_since(e.seen_at) <= ENTRY_TTL)
            .map(|e| e.proc.clone())
            .collect()
    }

    /// Records an exit. The kernel side only publishes these for thread-group
    /// leaders, so this really is "the process is gone", not "a thread of it
    /// finished".
    pub fn observe_exit(&self, pid: u32) {
        self.inner.map.write().remove(&pid);
    }

    /// Looks a pid up, verifying it against `/proc/<pid>/stat`'s start time.
    ///
    /// `starttime` is what the caller just read for this pid, or `None` when
    /// `/proc/<pid>` could not be read at all - which is the case this table
    /// exists to serve, so it is *not* treated as a verification failure.
    pub fn get(&self, pid: u32, starttime: Option<u64>, now: Instant) -> Option<KernelProc> {
        if !self.is_live() {
            return None;
        }
        // A write lock throughout: a lookup can bind a start time or evict a
        // stale entry, and splitting that into a read pass plus an upgrade
        // would buy nothing here - the only writers are the two ring-buffer
        // consumers, so contention is a non-issue.
        let mut map = self.inner.map.write();
        let entry = map.get_mut(&pid)?;
        if now.saturating_duration_since(entry.seen_at) > ENTRY_TTL {
            map.remove(&pid);
            return None;
        }
        match (entry.starttime, starttime) {
            // Verified against /proc.
            (Some(known), Some(seen)) if known == seen => Some(entry.proc.clone()),
            // Recycled pid: our exec record belongs to a process that is gone.
            (Some(_), Some(_)) => {
                map.remove(&pid);
                None
            }
            // Nothing to verify against: either /proc/<pid> is already gone
            // (the case this table exists for) or we never learned a start
            // time and the caller has none either.
            (_, None) => Some(entry.proc.clone()),
            // First lookup that can supply one: bind it, so every later
            // lookup is verified.
            (None, Some(_)) => {
                entry.starttime = starttime;
                Some(entry.proc.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfc_ebpf_common::{COMM_LEN, FILENAME_LEN};

    fn exec(pid: u32, exe: &str, uid: u32, ppid: u32) -> ExecEvent {
        let mut e = ExecEvent::zeroed();
        e.pid = pid;
        e.ppid = ppid;
        e.uid = uid;
        e.gid = uid;
        let comm = exe.rsplit('/').next().unwrap_or(exe).as_bytes();
        let n = comm.len().min(COMM_LEN - 1);
        e.comm[..n].copy_from_slice(&comm[..n]);
        let path = exe.as_bytes();
        let n = path.len().min(FILENAME_LEN);
        e.filename[..n].copy_from_slice(&path[..n]);
        e.filename_len = n as u16;
        e
    }

    fn live_table() -> (KernelProcTable, Instant) {
        let t = KernelProcTable::new();
        t.set_live(true);
        (t, Instant::now())
    }

    #[test]
    fn a_table_that_is_not_live_never_answers() {
        let t = KernelProcTable::new();
        let now = Instant::now();
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 1), Some(500), now);
        assert_eq!(t.len(), 1, "events are still recorded");
        assert!(
            t.get(42, Some(500), now).is_none(),
            "but nothing is served until the tracepoint is attached"
        );
        t.set_live(true);
        assert!(t.get(42, Some(500), now).is_some());
    }

    #[test]
    fn insert_and_lookup_round_trip() {
        let (t, now) = live_table();
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 7), Some(500), now);
        let p = t.get(42, Some(500), now).unwrap();
        assert_eq!(p.pid, 42);
        assert_eq!(p.uid, 1000);
        assert_eq!(p.gid, 1000);
        assert_eq!(p.ppid, Some(7));
        assert_eq!(p.exe, PathBuf::from("/usr/bin/curl"));
        assert_eq!(p.comm, "curl");
        assert_eq!(p.absolute_exe(), Some(Path::new("/usr/bin/curl")));
    }

    #[test]
    fn ppid_zero_means_unknown_not_pid_zero() {
        let (t, now) = live_table();
        t.observe_exec(&exec(42, "/usr/bin/curl", 0, 0), None, now);
        assert_eq!(t.get(42, None, now).unwrap().ppid, None);
    }

    #[test]
    fn relative_exec_paths_are_kept_but_not_offered_as_absolute() {
        let (t, now) = live_table();
        t.observe_exec(&exec(42, "./configure", 1000, 1), None, now);
        let p = t.get(42, None, now).unwrap();
        assert_eq!(p.exe, PathBuf::from("./configure"));
        assert_eq!(p.absolute_exe(), None);
    }

    /// `filename_len == 0` is the kernel side saying "I did not read a path".
    ///
    /// It happens when the probe read faults, and — deliberately — when the
    /// loader switched the read off because this kernel's tracepoint record is
    /// a shape it cannot parse. The scratch buffer is not memset between
    /// events (a 292-byte memset does not lower on the BPF backend), so its
    /// tail holds the *previous* exec's path. Reading it would attribute a
    /// connection to whatever ran before.
    #[test]
    fn a_zero_length_filename_yields_no_path_not_a_stale_one() {
        let mut e = exec(42, "/usr/bin/curl", 1000, 1);
        // The bytes stay; only the length says they are not real. That is
        // exactly the on-the-wire shape of a suppressed read.
        e.filename_len = 0;

        let p = KernelProc::from(&e);
        assert_eq!(
            p.exe,
            PathBuf::new(),
            "a stale buffer must not become a path"
        );
        assert_eq!(
            p.absolute_exe(),
            None,
            "and must never reach rule evaluation"
        );
        // Everything else about the event is still trustworthy and must survive.
        assert_eq!(p.pid, 42);
        assert_eq!(p.uid, 1000);
    }

    #[test]
    fn exit_evicts() {
        let (t, now) = live_table();
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 1), Some(500), now);
        t.observe_exit(42);
        assert!(t.get(42, Some(500), now).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn exit_of_another_pid_is_harmless() {
        let (t, now) = live_table();
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 1), Some(500), now);
        t.observe_exit(43);
        assert!(t.get(42, Some(500), now).is_some());
    }

    #[test]
    fn a_second_exec_replaces_the_first() {
        let (t, now) = live_table();
        // The shell that exec()s its last command in place: same pid, same
        // start time, different program.
        t.observe_exec(&exec(42, "/bin/sh", 1000, 1), Some(500), now);
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 1), Some(500), now);
        assert_eq!(t.len(), 1);
        assert_eq!(
            t.get(42, Some(500), now).unwrap().exe,
            PathBuf::from("/usr/bin/curl")
        );
    }

    #[test]
    fn pid_reuse_is_rejected_by_start_time() {
        let (t, now) = live_table();
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 1), Some(500), now);
        // Same pid, a process that started later: the exec record is stale.
        assert!(t.get(42, Some(999), now).is_none());
        assert!(t.is_empty(), "the stale entry is evicted, not just skipped");
    }

    #[test]
    fn pid_reuse_is_caught_even_when_the_exec_consumer_lost_the_race() {
        let (t, now) = live_table();
        // No start time captured at exec time (the process was already gone).
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 1), None, now);
        // First lookup binds the entry to the start time it presents...
        assert!(t.get(42, Some(500), now).is_some());
        // ...and every later lookup is verified against it.
        assert!(t.get(42, Some(500), now).is_some());
        assert!(t.get(42, Some(999), now).is_none());
    }

    #[test]
    fn a_dead_process_is_still_named() {
        let (t, now) = live_table();
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 1), Some(500), now);
        // /proc/<pid> is gone, so the caller has no start time to offer. This
        // is the case the table exists for; serve it.
        assert_eq!(
            t.get(42, None, now).unwrap().exe,
            PathBuf::from("/usr/bin/curl")
        );
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let (t, now) = live_table();
        t.observe_exec(&exec(42, "/usr/bin/curl", 1000, 1), Some(500), now);
        assert!(t.get(42, Some(500), now + ENTRY_TTL).is_some());
        assert!(t
            .get(42, Some(500), now + ENTRY_TTL + Duration::from_secs(1))
            .is_none());
        assert!(t.is_empty(), "expiry drops the entry");
    }

    #[test]
    fn the_table_is_bounded_and_evicts_the_oldest() {
        let (t, now) = live_table();
        for pid in 0..MAX_ENTRIES as u32 + 16 {
            t.observe_exec(
                &exec(pid, "/usr/bin/curl", 1000, 1),
                Some(u64::from(pid)),
                now + Duration::from_millis(u64::from(pid)),
            );
        }
        assert!(t.len() <= MAX_ENTRIES, "len {} > cap", t.len());
        let last = MAX_ENTRIES as u32 + 15;
        assert!(
            t.get(last, Some(u64::from(last)), now).is_some(),
            "the newest entry survives"
        );
        assert!(
            t.get(0, Some(0), now).is_none(),
            "the oldest entry was evicted"
        );
    }

    #[test]
    fn truncated_and_untrusted_event_fields_do_not_panic() {
        let (t, now) = live_table();
        let mut e = ExecEvent::zeroed();
        e.pid = 1;
        // A length that lies about how much was written, and invalid UTF-8.
        e.filename[..4].copy_from_slice(&[b'/', 0xff, 0xfe, 0]);
        e.filename_len = u16::MAX;
        e.comm[..2].copy_from_slice(&[0xff, 0]);
        t.observe_exec(&e, None, now);
        let p = t.get(1, None, now).unwrap();
        assert!(p.exe.to_string_lossy().contains('\u{fffd}'));
    }
}
