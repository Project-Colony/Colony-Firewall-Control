//! Colony Firewall Control - kernel-side eBPF programs.
//!
//! Three programs, three jobs (see `README.md` for attach points and
//! capability requirements):
//!
//! | section                            | purpose                                   |
//! |------------------------------------|-------------------------------------------|
//! | `tracepoint/sched/sched_process_exec` | record every `execve` in `PROCS` + `EXEC_EVENTS` |
//! | `tracepoint/sched/sched_process_exit` | evict dead pids from `PROCS` + `EXIT_EVENTS`     |
//! | `cgroup_skb/ingress`                 | lift `A`/`AAAA` answers into `DNS_ANSWERS`       |
//!
//! All the interesting arithmetic lives in `cfc-ebpf-common` so it can be
//! unit-tested on the host; this file is the thin, verifier-shaped shell around
//! it: map declarations, helper calls and bounded copies.

#![no_std]
#![no_main]

use aya_ebpf::bindings::BPF_ANY;
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid,
    bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{cgroup_skb, map, tracepoint};
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{SkBuffContext, TracePointContext};
use aya_ebpf::{EbpfContext as _, Global};
use cfc_ebpf_common::dns::{self, DNS_HEADER_LEN, DnsCursor};
use cfc_ebpf_common::net::{self, IPV4_MIN_HEADER_LEN, UDP_HEADER_LEN};
use cfc_ebpf_common::{DNS_BUF_LEN, DnsAnswer, ExecEvent, ExitEvent};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// Live processes, keyed by tgid. The daemon reads this to answer "who owns
/// this connection" without racing `/proc`.
///
/// 10240 entries at 292 bytes each is ~3 MiB of (preallocated) kernel memory.
#[map]
static PROCS: HashMap<u32, ExecEvent> = HashMap::with_max_entries(10_240, 0);

/// Stream of `execve` events. 256 KiB = 64 pages, a power-of-two multiple of
/// the page size as the kernel requires.
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Stream of process-exit events. Entries are 4 bytes, so this is generous.
#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Stream of `A`/`AAAA` answers observed on the wire.
#[map]
static DNS_ANSWERS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Scratch space for the 292-byte [`ExecEvent`].
///
/// A BPF program gets 512 bytes of stack *in total*, so the event cannot live
/// there next to everything else. A per-CPU array slot is the standard
/// workaround and costs nothing: BPF programs are non-preemptible, so the slot
/// cannot be clobbered mid-program.
#[map]
static EXEC_SCRATCH: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

/// Scratch space for the 276-byte [`DnsAnswer`]. Same reasoning.
#[map]
static ANSWER_SCRATCH: PerCpuArray<DnsAnswer> = PerCpuArray::with_max_entries(1, 0);

/// Scratch space for the copied packet prefix. Same reasoning, more so.
#[map]
static PKT_SCRATCH: PerCpuArray<[u8; DNS_BUF_LEN]> = PerCpuArray::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// Load-time globals
// ---------------------------------------------------------------------------

// Rust/aya has no CO-RE field relocation (LLVM only emits the relocation
// records for `__builtin_preserve_access_index`, which is C-only), so
// hard-coding `task_struct` offsets here would silently break on every kernel
// that reorders the struct.
//
// Instead the *loader* resolves the two offsets it needs from
// `/sys/kernel/btf/vmlinux` -- which aya can parse -- and overrides these
// `.rodata` globals at load time via `EbpfLoader::set_global`. Both default to
// 0, which this program reads as "unknown, skip ppid" so it degrades to
// `ppid = 0` rather than reading garbage.

/// Byte offset of `task_struct::real_parent`. 0 means "unresolved".
#[unsafe(no_mangle)]
static TASK_REAL_PARENT_OFFSET: Global<u32> = Global::new(0);

/// Byte offset of `task_struct::tgid`. 0 means "unresolved".
#[unsafe(no_mangle)]
static TASK_TGID_OFFSET: Global<u32> = Global::new(0);

// ---------------------------------------------------------------------------
// tracepoint/sched/sched_process_exec
// ---------------------------------------------------------------------------

/// Offset of the `__data_loc char[] filename` field inside the tracepoint
/// record, read from
/// `/sys/kernel/tracing/events/sched/sched_process_exec/format`:
///
/// ```text
/// field:unsigned short common_type;    offset:0;  size:2;
/// field:unsigned char common_flags;    offset:2;  size:1;
/// field:unsigned char common_preempt_count; offset:3; size:1;
/// field:int common_pid;                offset:4;  size:4;
/// field:__data_loc char[] filename;    offset:8;  size:4;
/// field:pid_t pid;                     offset:12; size:4;
/// field:pid_t old_pid;                 offset:16; size:4;
/// ```
///
/// This part of the tracepoint layout is stable ABI, so a constant is safe.
const EXEC_FILENAME_DATA_LOC: usize = 8;

#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn cfc_sched_process_exec(ctx: TracePointContext) -> u32 {
    // Never fail the tracepoint: a dropped event is a monitoring gap, an error
    // return is nothing at all (tracepoint return values are ignored anyway).
    let _ = try_exec(&ctx);
    0
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let slot = EXEC_SCRATCH.get_ptr_mut(0).ok_or(-1i64)?;
    // SAFETY: `get_ptr_mut` returned a non-null pointer to this CPU's slot, and
    // BPF programs are not preemptible, so nothing else can touch it while this
    // program runs.
    let event = unsafe { &mut *slot };

    // NOTE: deliberately no `*event = ExecEvent::zeroed()` here. That is a
    // 292-byte memset, and the BPF backend cannot lower a memset that large to
    // inline stores -- it emits a `memset` libcall, which bpf-linker rejects
    // with "A call to built-in function 'memset' is not supported". Every
    // scalar field is therefore assigned unconditionally below, and the only
    // field left partially written is `filename`, whose stale tail is
    // unreachable from userspace (bounded by `filename_len` *and* by the NUL
    // that `bpf_probe_read_kernel_str` writes). The per-CPU slot starts out
    // zeroed by the kernel, so this is never uninitialised memory.
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let tgid = (pid_tgid >> 32) as u32;

    event.pid = tgid;
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;
    event.ppid = current_ppid();
    event._pad = [0; 2];

    // 16 bytes, small enough for the backend to expand inline.
    event.comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => [0; 16],
    };

    read_exec_filename(ctx, event);

    // Insert first, publish second: by the time userspace sees the ring buffer
    // entry, the map lookup is already guaranteed to succeed.
    let _ = PROCS.insert(&tgid, &*event, u64::from(BPF_ANY));
    let _ = EXEC_EVENTS.output::<ExecEvent>(&*event, 0);

    Ok(())
}

/// Resolves the tracepoint's `__data_loc filename` and copies the path in.
///
/// A `__data_loc` field is a `u32` holding `(length << 16) | offset`, where the
/// offset is relative to the start of the tracepoint record. The string itself
/// sits in the variable-length tail of the record.
#[inline(always)]
fn read_exec_filename(ctx: &TracePointContext, event: &mut ExecEvent) {
    // SAFETY: reading 4 bytes at a fixed, in-record offset via
    // `bpf_probe_read_kernel`, which faults gracefully rather than crashing.
    let data_loc = match unsafe { ctx.read_at::<u32>(EXEC_FILENAME_DATA_LOC) } {
        Ok(v) => v,
        Err(_) => return,
    };
    let offset = (data_loc & 0xffff) as usize;
    let declared_len = (data_loc >> 16) as usize;
    if offset == 0 || declared_len == 0 {
        return;
    }

    // SAFETY: `ctx.as_ptr()` is the tracepoint record; `offset` came from the
    // record's own `__data_loc` word. The read still goes through
    // `bpf_probe_read_kernel_str`, so a bogus offset yields -EFAULT instead of
    // an oops.
    let src = unsafe { ctx.as_ptr().cast::<u8>().add(offset) };
    let copied = match unsafe { bpf_probe_read_kernel_str_bytes(src, &mut event.filename) } {
        // `_str_bytes` excludes the trailing NUL, which is exactly the length
        // userspace wants.
        Ok(bytes) => bytes.len(),
        Err(_) => 0,
    };
    event.filename_len = copied as u16;
}

/// Best-effort parent tgid.
///
/// Returns 0 when the loader did not supply `task_struct` offsets, or when
/// either probe read faults. Both are non-fatal: userspace treats `ppid == 0`
/// as "unknown" and can fall back to `/proc`.
#[inline(always)]
fn current_ppid() -> u32 {
    let parent_off = TASK_REAL_PARENT_OFFSET.load();
    let tgid_off = TASK_TGID_OFFSET.load();
    if parent_off == 0 || tgid_off == 0 {
        return 0;
    }

    // SAFETY: helper call, always valid inside a tracing program.
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return 0;
    }

    let parent_slot = task.wrapping_add(u64::from(parent_off)) as *const u64;
    // SAFETY: `bpf_probe_read_kernel` validates the address itself and returns
    // -EFAULT for anything unmapped; no dereference happens in this program.
    let parent = match unsafe { bpf_probe_read_kernel::<u64>(parent_slot) } {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if parent == 0 {
        return 0;
    }

    let tgid_slot = parent.wrapping_add(u64::from(tgid_off)) as *const u32;
    // SAFETY: as above.
    match unsafe { bpf_probe_read_kernel::<u32>(tgid_slot) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// tracepoint/sched/sched_process_exit
// ---------------------------------------------------------------------------

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn cfc_sched_process_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // This tracepoint fires for every *thread*. Only the thread-group leader's
    // exit means the process is gone; evicting on any thread exit would blind
    // us to a still-running multithreaded process.
    //
    // Deliberately read from `bpf_get_current_pid_tgid()` rather than from the
    // tracepoint record: the record layout for `sched_process_exit` could not
    // be verified on the build host (`/sys/kernel/tracing` is root-only), and
    // the helper is layout-independent.
    if tgid != tid {
        return 0;
    }

    let _ = PROCS.remove(&tgid);

    // Publish the eviction so the userspace cache drops the pid too. Without
    // this, a recycled pid would be attributed to the process that died.
    if let Some(mut entry) = EXIT_EVENTS.reserve::<ExitEvent>(0) {
        entry.write(ExitEvent { pid: tgid });
        entry.submit(0);
    }

    0
}

// ---------------------------------------------------------------------------
// cgroup_skb/ingress -- DNS answers
// ---------------------------------------------------------------------------

/// `cgroup_skb` verdict: let the packet through. This program is an observer
/// and must never drop traffic.
const SKB_PASS: i32 = 1;

/// Shortest packet that could possibly contain a DNS response header.
const MIN_DNS_PACKET: usize = IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN;

#[cgroup_skb(ingress)]
pub fn cfc_dns_ingress(ctx: SkBuffContext) -> i32 {
    let _ = try_dns(&ctx);
    SKB_PASS
}

fn try_dns(ctx: &SkBuffContext) -> Result<(), i64> {
    let skb_len = ctx.len() as usize;
    if skb_len < MIN_DNS_PACKET {
        return Ok(());
    }

    let slot = PKT_SCRATCH.get_ptr_mut(0).ok_or(-1i64)?;
    // SAFETY: per-CPU slot, non-preemptible program. See EXEC_SCRATCH.
    let buf = unsafe { &mut *slot };

    let copied = load_prefix(ctx, buf).ok_or(-1i64)?;

    let udp = net::udp_payload_from_l3(buf, copied).ok_or(-1i64)?;
    if !net::is_dns_response(&udp) {
        return Ok(());
    }

    let answer_slot = ANSWER_SCRATCH.get_ptr_mut(0).ok_or(-1i64)?;
    // SAFETY: per-CPU slot, non-preemptible program. See EXEC_SCRATCH.
    let answer = unsafe { &mut *answer_slot };

    // As with `ExecEvent`, no whole-struct zeroing: 276 bytes is past what the
    // BPF backend will expand inline. `parse_answer_at` writes `ip`, `is_v6`,
    // `ttl`, `name_len` and `_pad` on every accepted record and NUL-terminates
    // `name`, so nothing stale is reachable from userspace.

    let cursor = DnsCursor::with_base(buf, udp.offset, udp.len);
    dns::for_each_answer(&cursor, answer, |a| {
        // A full ring buffer just means userspace fell behind; drop and move on.
        let _ = DNS_ANSWERS.output::<DnsAnswer>(a, 0);
    });

    Ok(())
}

/// Copies the head of the packet into the per-CPU scratch buffer.
///
/// `bpf_skb_load_bytes` needs a length the verifier can see as a constant, and
/// it fails outright if that length runs past the end of the skb. Hence the
/// descending ladder of constant-size attempts instead of one variable-length
/// copy: each rung is a separate call site with a literal length, and the first
/// one that fits wins.
///
/// Returns the number of bytes actually copied. A packet longer than the
/// largest rung is simply truncated -- `for_each_answer` stops at the first
/// record it cannot read in full.
#[inline(always)]
fn load_prefix(ctx: &SkBuffContext, buf: &mut [u8; DNS_BUF_LEN]) -> Option<usize> {
    let avail = ctx.len() as usize;

    // Rungs are 64 bytes apart, so at most 63 trailing bytes are dropped.
    if avail >= 512 && load_exact::<512>(ctx, buf) {
        return Some(512);
    }
    if avail >= 448 && load_exact::<448>(ctx, buf) {
        return Some(448);
    }
    if avail >= 384 && load_exact::<384>(ctx, buf) {
        return Some(384);
    }
    if avail >= 320 && load_exact::<320>(ctx, buf) {
        return Some(320);
    }
    if avail >= 256 && load_exact::<256>(ctx, buf) {
        return Some(256);
    }
    if avail >= 192 && load_exact::<192>(ctx, buf) {
        return Some(192);
    }
    if avail >= 128 && load_exact::<128>(ctx, buf) {
        return Some(128);
    }
    if avail >= 64 && load_exact::<64>(ctx, buf) {
        return Some(64);
    }
    if avail >= MIN_DNS_PACKET && load_exact::<{ MIN_DNS_PACKET }>(ctx, buf) {
        return Some(MIN_DNS_PACKET);
    }
    None
}

#[inline(always)]
fn load_exact<const N: usize>(ctx: &SkBuffContext, buf: &mut [u8; DNS_BUF_LEN]) -> bool {
    match buf.get_mut(..N) {
        Some(dst) => ctx.load_bytes(0, dst).is_ok(),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Object metadata
// ---------------------------------------------------------------------------

/// The kernel gates GPL-only helpers on this section. Everything this object
/// uses -- `bpf_probe_read_kernel`, `bpf_ringbuf_*`, `bpf_get_current_task`,
/// `bpf_skb_load_bytes` -- is GPL-only, and the project is GPL-3.0-or-later,
/// so declaring "GPL" here is both required and accurate.
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
pub static LICENSE: [u8; 4] = *b"GPL\0";

/// Unreachable by construction: every fallible operation in this crate and in
/// `cfc-ebpf-common` returns `Option`/`Result`, and there is no indexing that
/// could bounds-check.
///
/// A plain `loop {}` rather than `unreachable_unchecked()` on purpose: if a
/// panic path ever *did* survive optimisation, this makes the verifier reject
/// the program at load time (the daemon then degrades gracefully), whereas
/// `unreachable_unchecked()` would instead let the optimiser delete the check
/// that guarded it and run unsound code in the kernel.
#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
