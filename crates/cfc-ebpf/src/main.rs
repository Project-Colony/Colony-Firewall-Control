//! Colony Firewall Control - kernel-side eBPF programs.
//!
//! Five programs (see `README.md` for attach points and capability
//! requirements):
//!
//! | section                            | purpose                                   |
//! |------------------------------------|-------------------------------------------|
//! | `tracepoint/sched/sched_process_exec` | record every `execve` in `PROCS` + `EXEC_EVENTS` |
//! | `tracepoint/sched/sched_process_exit` | evict dead pids from `PROCS` + `EXIT_EVENTS`     |
//! | `cgroup_skb/ingress`                 | copy DNS response payloads into `DNS_PACKETS`    |
//! | `cgroup/connect4`, `cgroup/connect6` | refuse `connect()` for already-denied pids       |
//!
//! The first three *observe*. The last two **decide**, and are the only part of
//! CFC that enforces without a userspace round trip: their link is pinned to
//! bpffs, so every deny they hold survives the daemon being killed.
//!
//! All the interesting arithmetic lives in `cfc-ebpf-common` so it can be
//! unit-tested on the host; this file is the thin, verifier-shaped shell around
//! it: map declarations, helper calls and bounded copies.
//!
//! The DNS program does **no parsing**. It classifies the packet with the
//! cheap header arithmetic in `cfc_ebpf_common::net`, checks two bytes of the
//! DNS header, and copies the payload out. Parsing it in the kernel cost more
//! than the verifier's 1,000,000-instruction budget; see `README.md`.

#![no_std]
#![no_main]

use aya_ebpf::bindings::BPF_ANY;
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid,
    bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{cgroup_skb, cgroup_sock_addr, map, tracepoint};
use aya_ebpf::maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{SkBuffContext, SockAddrContext, TracePointContext};
use aya_ebpf::{EbpfContext as _, Global};
use cfc_ebpf_common::dns::DNS_HEADER_LEN;
use cfc_ebpf_common::net::{self, IPV4_MIN_HEADER_LEN, UDP_HEADER_LEN};
use cfc_ebpf_common::{ConnectDeny, DNS_BUF_LEN, DnsPacket, ExecEvent, ExitEvent, FILENAME_LEN};

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

/// Live processes, keyed by tgid. The daemon reads this to answer "who owns
/// this connection" without racing `/proc`.
///
/// 10240 entries at 292 bytes each is ~3 MiB of (preallocated) kernel memory.
#[map]
static PROCS: HashMap<u32, ExecEvent> = HashMap::with_max_entries(10_240, 0);

/// Precomputed per-process verdicts, keyed by tgid, read on the `connect()`
/// path by `cfc_connect4` / `cfc_connect6`.
///
/// The daemon writes an entry when it sees an `exec` whose executable matches a
/// rule that needs no packet to evaluate - no destination, no port, no
/// protocol constraint - because such a rule's answer cannot change between
/// here and NFQUEUE. Anything conditional is left absent on purpose so the
/// packet path still decides it.
///
/// Sized to match `PROCS`; an entry here always has one there.
#[map]
static VERDICTS: HashMap<u32, u32> = HashMap::with_max_entries(10_240, 0);

/// Socket cookie -> tgid, written at `connect()` time, read by attribution.
///
/// This is the map that removes the packet path's single biggest cost. The
/// NFQUEUE worker used to answer "which pid owns this socket?" by walking every
/// `/proc/*/fd` on the machine - measured at 37-44 ms per NEW connection on a
/// desktop, paid before rule evaluation, on every connection, because the inode
/// is new each time and a fresh process sits at the end of the walk. The
/// connect hooks already run in the connecting process's context, so the kernel
/// can hand us the association for free: one `bpf_get_socket_cookie` call here,
/// one sock_diag round trip plus one map lookup in userspace. The same cookie
/// is what sock_diag reports as `idiag_cookie`, assigned lazily by the same
/// `sock_gen_cookie` on whichever side asks first.
///
/// LRU on purpose: sockets close without any hook firing here, so a plain hash
/// would fill with dead cookies and reject new inserts - the failure would land
/// exactly on the newest connections, the ones attribution is for. 16,384
/// entries x 12 bytes is ~a megabyte with overhead, and an LRU eviction of a
/// live-but-old entry costs one fallback walk, not a wrong answer.
#[map]
static SOCK_PIDS: LruHashMap<u64, u32> = LruHashMap::with_max_entries(16_384, 0);

/// The daemon's process-wide rules, compiled into a form the kernel can
/// evaluate alone: `hash_exe_path(exe) -> action`.
///
/// This is what lets a process started while no daemon runs still get an
/// answer. `VERDICTS` holds decisions already made *about a pid*; this holds
/// the decision *about a program*, so the exec program can reach one without
/// asking anybody.
///
/// Only rules that constrain nothing but the executable are here - the same
/// set `Engine::process_wide_action` already precommits - because the connect
/// hooks answer before a destination exists.
#[map]
static EXE_RULES: HashMap<u64, u32> = HashMap::with_max_entries(4_096, 0);

/// Whether `EXE_RULES` holds anything, so the hash below can be skipped.
///
/// A map, not a `.rodata` global, because rules change while the daemon runs
/// and a global is fixed at load. One array lookup is tens of nanoseconds; the
/// hash it guards is a 256-iteration loop, on **every execve on the machine**.
/// A host with no exe-scoped deny - the common case - must not pay for a table
/// that is empty.
#[map]
static EXE_RULES_ON: Array<u32> = Array::with_max_entries(1, 0);

/// Counters for the connect path. See `cfc_ebpf_common::enforce_stat`.
#[map]
static ENFORCE_STATS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(cfc_ebpf_common::enforce_stat::SLOTS, 0);

/// Stream of `connect()` calls refused in-kernel.
///
/// 24-byte records, so 64 KiB holds ~2,700. Only *denials* are reported -
/// a stream of every connect on the machine would be a different and much
/// more expensive product. A full ring costs a log line, never a decision:
/// the refusal already happened when the record is written.
#[map]
static DENY_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Stream of `execve` events. 256 KiB = 64 pages, a power-of-two multiple of
/// the page size as the kernel requires.
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Stream of process-exit events. Entries are 4 bytes, so this is generous.
#[map]
static EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Stream of DNS response payloads observed on the wire.
///
/// Records are 514 bytes, so this holds ~500 responses. Userspace parses them;
/// a full ring just means it fell behind and some answers are missed, which
/// costs a hostname, never a packet.
#[map]
static DNS_PACKETS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Scratch space for the 292-byte [`ExecEvent`].
///
/// A BPF program gets 512 bytes of stack *in total*, so the event cannot live
/// there next to everything else. A per-CPU array slot is the standard
/// workaround and costs nothing: BPF programs are non-preemptible, so the slot
/// cannot be clobbered mid-program.
#[map]
static EXEC_SCRATCH: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

/// Bytes copied out of a packet for header classification.
///
/// Only headers are read out of this buffer, so it is sized for the worst-case
/// header stack and nothing more: a 60-byte IPv4 header with full options, an
/// 8-byte UDP header, and the first 12 bytes of the DNS message. The payload
/// itself never passes through here.
const PKT_SCRATCH_LEN: usize = 80;

/// Scratch space for the copied packet prefix. Same reasoning as
/// `EXEC_SCRATCH`, more so.
///
/// Only the L3/L4 headers and one byte of the DNS header are ever *read* out
/// of this. The payload the daemon parses is copied straight from the skb into
/// the ring-buffer record, so this buffer is never indexed by anything the
/// verifier has to reason about in a loop.
#[map]
static PKT_SCRATCH: PerCpuArray<[u8; PKT_SCRATCH_LEN]> = PerCpuArray::with_max_entries(1, 0);

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

/// Declares which event layout this object was built against.
///
/// The name **must** equal `cfc_ebpf_common::ABI_SYMBOL`, and the version in
/// it must match `ABI_VERSION`. The loader requires this exact symbol to exist
/// before it attaches anything, so an object built against a different layout
/// fails to load instead of feeding userspace prefix-decoded garbage. A
/// mismatch between the two names is not silent either: it fails every load,
/// which the root test catches immediately.
///
/// Rust needs a literal for the symbol name, so this cannot be spelled in
/// terms of the constant. The `const` assertions in `cfc-ebpf-common` are what
/// make a layout change that forgets to bump it a build error.
#[unsafe(no_mangle)]
static CFC_EBPF_ABI_V3: Global<u32> = Global::new(cfc_ebpf_common::ABI_VERSION);

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
/// The first four fields are the `common_*` header every tracepoint carries,
/// so 8 is the value on every kernel this has ever been run on. It is still
/// **not** a constant here: `common_*` has grown before, and the failure mode
/// of guessing wrong is silent and ugly - the program would read four bytes of
/// whatever field actually sits at offset 8, treat the result as
/// `(len << 16) | offset`, and copy a plausible-looking path out of the middle
/// of the record. Userspace cannot tell that apart from a real filename.
///
/// So the loader parses the format file at attach time and patches the answer
/// in, exactly as it does for the `task_struct` offsets above.
///
/// **0 means "do not read the filename at all"** - the suppression sentinel the
/// loader sets when the format file says something this program cannot handle
/// (a `__rel_loc` field, or a size other than 4). Refusing in userspace alone
/// would be no refusal: the kernel side would carry on reading offset 8.
#[unsafe(no_mangle)]
static EXEC_FILENAME_DATA_LOC: Global<u32> = Global::new(8);

/// Largest plausible `__data_loc` offset, used to bound the read below.
///
/// The record header is a handful of fields; anything past this is a parse
/// gone wrong, not a kernel that reorganised its tracepoints.
const EXEC_FILENAME_DATA_LOC_MAX: u32 = 64;

/// Byte offset of `group_dead` in `sched_process_exit`'s record, or
/// [`EXIT_GROUP_DEAD_ABSENT`] when this kernel does not carry it.
///
/// `group_dead` is the kernel saying the *process* is gone rather than one of
/// its threads, and nothing else in the record says that. The substitute this
/// code used - "the exiting task is the thread-group leader" - is wrong in both
/// directions, and both of them matter:
///
///   * a leader can exit first, via `pthread_exit()` from `main`, while its
///     workers keep running under the same tgid. Evicting there hands a denied
///     process its network back while it is still running - a fail-open;
///   * a worker can be the last thread out, and then the leader-only check
///     never fires at all, so the entry is never evicted.
///
/// Overridden by the loader from the live format file. Defaulting to "absent"
/// is the safe direction: an object loaded by something that does not set it
/// keeps the old leader-only behaviour rather than reading a byte at a guessed
/// offset and evicting on garbage.
#[unsafe(no_mangle)]
static EXIT_GROUP_DEAD_OFF: Global<u32> = Global::new(EXIT_GROUP_DEAD_ABSENT);

/// Sentinel for "this kernel's record has no readable `group_dead`".
const EXIT_GROUP_DEAD_ABSENT: u32 = u32::MAX;

/// Largest plausible offset for it, bounding the read the same way the exec
/// filename offset is bounded.
const EXIT_GROUP_DEAD_MAX: u32 = 64;

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

    // Answer for this process without asking anybody. This is the half that
    // keeps working when there is no daemon - the case the pinned `VERDICTS`
    // map exists for and could not previously cover, because nothing wrote it.
    precommit_verdict(tgid, event);

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
    let field_off = EXEC_FILENAME_DATA_LOC.load();
    // Two jobs, and both are load-bearing.
    //
    // `== 0` is the loader's suppression sentinel: this kernel's record is not
    // one we know how to read, so read nothing rather than something wrong.
    //
    // `> MAX` is what keeps the verifier happy, and it is not belt-and-braces.
    // While this was a `const`, the offset was a compile-time literal and the
    // verifier knew the exact address. Reading it from a `.rodata` global makes
    // it a runtime value with umax 2^32-1 as far as the verifier is concerned,
    // and it is about to be used in pointer arithmetic on the context. Without
    // a bound it refuses the program outright. A mask would not do: the point
    // is to *reject* an implausible offset, not to fold it into range.
    if field_off == 0 || field_off > EXEC_FILENAME_DATA_LOC_MAX {
        return;
    }

    // SAFETY: reading 4 bytes at an in-record offset via
    // `bpf_probe_read_kernel`, which faults gracefully rather than crashing.
    let data_loc = match unsafe { ctx.read_at::<u32>(field_off as usize) } {
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

/// Precommits a verdict for a freshly exec'd process, from the kernel's own
/// rule table.
///
/// The whole point: no daemon is consulted, so this keeps working when there
/// is none. Writes only denials - an allow would buy nothing, because the
/// absence of an entry already means "ask the packet path".
#[inline(always)]
fn precommit_verdict(tgid: u32, event: &ExecEvent) {
    // Cheap gate first. See `EXE_RULES_ON`.
    match EXE_RULES_ON.get(0) {
        Some(&on) if on != 0 => {}
        _ => return,
    }

    let len = event.filename_len as usize;
    if len == 0 || len > FILENAME_LEN {
        return;
    }
    // The slice bound is what lets the verifier prove every index is in range.
    let key = cfc_ebpf_common::hash_exe_path(&event.filename[..len]);
    let action = match unsafe { EXE_RULES.get(&key) } {
        Some(a) => *a,
        None => return,
    };
    if action == cfc_ebpf_common::verdict::DENY {
        let _ = VERDICTS.insert(&tgid, &cfc_ebpf_common::verdict::DENY, 0);
    }
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

/// Whether this exit is the last one for its thread group.
///
/// Prefers the kernel's own `group_dead`. Falls back to "the exiting task is
/// the thread-group leader" only when the offset was never resolved, which is
/// the pre-existing behaviour and no worse than it was.
#[inline(always)]
fn process_is_gone(ctx: &TracePointContext, tgid: u32, tid: u32) -> bool {
    let off = EXIT_GROUP_DEAD_OFF.load();
    if off == EXIT_GROUP_DEAD_ABSENT || off > EXIT_GROUP_DEAD_MAX {
        return tgid == tid;
    }
    match unsafe { ctx.read_at::<u8>(off as usize) } {
        Ok(v) => v != 0,
        // The read failed on a record we were told the shape of. Treating that
        // as "not gone" leaks an entry; treating it as "gone" evicts a live
        // process's verdict. Leak, and let the daemon's own exit handling and
        // the next resync clean up.
        Err(_) => false,
    }
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn cfc_sched_process_exit(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // This tracepoint fires for every *thread*, and what we want is the
    // *process* being gone. The kernel says so directly - `group_dead` in the
    // record - so ask it when this kernel carries the field, and fall back to
    // the leader-only approximation when it does not.
    //
    // The approximation is wrong in both directions, which is why it is only
    // the fallback: a leader that calls `pthread_exit()` leaves its workers
    // running under the same tgid (evicting there is a fail-open), and a worker
    // that exits last never satisfies it at all (so nothing is ever evicted).
    if !process_is_gone(&ctx, tgid, tid) {
        return 0;
    }

    let _ = PROCS.remove(&tgid);

    // And the verdict, here in the kernel rather than only from userspace.
    //
    // `VERDICTS` is pinned, so an entry outlives the daemon. Userspace evicts
    // on exit too (`enforce::VerdictSink::on_exit`), which is enough while the
    // daemon is alive and is exactly nothing when it is not - and "when it is
    // not" is the whole reason the map is pinned. Without this line: the daemon
    // dies, a refused process exits, its DENY stays, Linux recycles the pid,
    // and an unrelated program silently loses the network. It fails closed, so
    // nothing breaks loudly; the protection just rots.
    //
    // Cheap and idempotent: one map delete, in a program that already does one,
    // and deleting a key that is not there is not an error.
    let _ = VERDICTS.remove(&tgid);

    // Publish the eviction so the userspace cache drops the pid too. Without
    // this, a recycled pid would be attributed to the process that died.
    if let Some(mut entry) = EXIT_EVENTS.reserve::<ExitEvent>(0) {
        entry.write(ExitEvent { pid: tgid });
        entry.submit(0);
    }

    0
}

// ---------------------------------------------------------------------------
// cgroup_skb/ingress -- DNS response payloads
// ---------------------------------------------------------------------------

/// `cgroup_skb` verdict: let the packet through. This program is an observer
/// and must never drop traffic.
const SKB_PASS: i32 = 1;

/// Shortest packet that could possibly contain a DNS response header.
const MIN_DNS_PACKET: usize = IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN;

/// QR bit, in the high byte of the DNS flags word (byte 2 of the header).
const DNS_QR: u8 = 0x80;

#[cgroup_skb(ingress)]
pub fn cfc_dns_ingress(ctx: SkBuffContext) -> i32 {
    let _ = try_dns(&ctx);
    SKB_PASS
}

/// Classify, gate, copy, submit. Nothing else.
///
/// Everything past "these bytes are a UDP datagram from port 53 whose QR bit is
/// set" -- opcode, rcode, counts, questions, answers, names, compression -- is
/// the daemon's job, because that is where a parser is allowed to have loops.
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

    // How much payload there really is. Deliberately NOT `udp.len`: that is
    // clamped to the header prefix copied above, so using it here would cap
    // every capture at ~50 bytes.
    let avail = skb_len.saturating_sub(udp.offset);
    let mut payload_len = if udp.declared_len < avail {
        udp.declared_len
    } else {
        avail
    };
    if payload_len > DNS_BUF_LEN {
        payload_len = DNS_BUF_LEN;
    }
    if payload_len < DNS_HEADER_LEN {
        return Ok(());
    }

    // One byte of sanity, so a stray port-53 datagram (or a query echoed back
    // by something odd) does not cost a 514-byte ring-buffer record. Anything
    // subtler than this -- opcode, rcode, counts -- belongs in userspace.
    //
    // The flags byte has to be inside the *copied prefix*, which is a stricter
    // condition than "inside the payload": `get` bounds the read against the
    // scratch buffer, and this bounds it against the bytes really written.
    if udp.offset + 3 > copied {
        return Ok(());
    }
    let flags_hi = *buf.get(udp.offset + 2).ok_or(-1i64)?;
    if flags_hi & DNS_QR == 0 {
        return Ok(());
    }

    publish_payload(ctx, udp.offset, payload_len)
}

/// Reserves a [`DnsPacket`] and fills it straight from the skb.
///
/// The payload is *not* copied out of `PKT_SCRATCH`: that would be a memcpy
/// from a runtime offset, which the BPF backend turns into a libcall the linker
/// rejects. A second `bpf_skb_load_bytes` -- which takes a runtime offset and
/// only needs a constant *length* -- writes the ring-buffer record directly,
/// so the payload is copied exactly once and never touches the stack.
#[inline(always)]
fn publish_payload(ctx: &SkBuffContext, offset: usize, len: usize) -> Result<(), i64> {
    // A full ring buffer just means userspace fell behind; drop and move on.
    let mut entry = DNS_PACKETS.reserve::<DnsPacket>(0).ok_or(-1i64)?;
    let pkt = entry.as_mut_ptr();
    // SAFETY: `pkt` points at `size_of::<DnsPacket>()` bytes of reserved,
    // writable ring-buffer memory. `&raw mut` computes the field address
    // without ever forming a reference to uninitialised memory.
    let dst = unsafe { &raw mut (*pkt).data }.cast::<u8>();

    match copy_payload(ctx, offset, len, dst) {
        Some(n) => {
            // SAFETY: as above; `len` is the first field of the record.
            unsafe { (&raw mut (*pkt).len).write(n as u16) };
            entry.submit(0);
            Ok(())
        }
        None => {
            // Nothing was written, so publishing it would hand userspace a
            // record of stale ring memory.
            entry.discard(0);
            Err(-1)
        }
    }
}

/// Copies the head of the packet into the per-CPU scratch buffer.
///
/// `bpf_skb_load_bytes` needs a length the verifier can see as a constant, and
/// it fails outright if that length runs past the end of the skb. Hence the
/// descending ladder of constant-size attempts instead of one variable-length
/// copy: each rung is a separate call site with a literal length, and the first
/// one that fits wins.
///
/// Returns the number of bytes actually copied. Rungs are 8 bytes apart because
/// the shortest thing this has to reach is `udp.offset + 3` on a 60-byte IPv6
/// response, and there are only six of them, because the buffer stops at the
/// headers.
#[inline(always)]
fn load_prefix(ctx: &SkBuffContext, buf: &mut [u8; PKT_SCRATCH_LEN]) -> Option<usize> {
    let avail = ctx.len() as usize;
    let dst = buf.as_mut_ptr();

    // Descending literals, top rung == the buffer, so every one of them is
    // in bounds by inspection.
    if avail >= PKT_SCRATCH_LEN && load_at::<{ PKT_SCRATCH_LEN }>(ctx, 0, dst) {
        return Some(PKT_SCRATCH_LEN);
    }
    if avail >= 72 && load_at::<72>(ctx, 0, dst) {
        return Some(72);
    }
    if avail >= 64 && load_at::<64>(ctx, 0, dst) {
        return Some(64);
    }
    if avail >= 56 && load_at::<56>(ctx, 0, dst) {
        return Some(56);
    }
    if avail >= 48 && load_at::<48>(ctx, 0, dst) {
        return Some(48);
    }
    if avail >= MIN_DNS_PACKET && load_at::<{ MIN_DNS_PACKET }>(ctx, 0, dst) {
        return Some(MIN_DNS_PACKET);
    }
    None
}

/// Copies the DNS payload into the reserved ring-buffer record, **exactly**.
///
/// Same constant-length constraint as [`load_prefix`], but here it has to cover
/// 12..=512 bytes, and one ladder fine enough to do that would be sixty-odd
/// rungs. So it is three passes:
///
/// 1. **coarse**, 64-byte steps, 0..=448, at `dst[0..]`;
/// 2. **fine**, 8-byte steps over what is left, appended right behind it;
/// 3. **tail**, a fixed 8-byte read positioned to *end* exactly at the end of
///    the payload, which fills in the last `len % 8` bytes.
///
/// Passes 1 and 2 are single-choice ladders, so this is 8 x 8 x 2 paths for the
/// verifier rather than 2^n, and their destination offsets are constants on
/// every one of them. Pass 3 overlaps whatever pass 2 already wrote -- copying
/// the same bytes twice is free, and it is what makes the result exact.
///
/// Exactness is not a nicety here. Truncating even three bytes truncates the
/// *last answer record*, and the common case is a response with exactly one
/// answer, so a rounded-down copy would have thrown away most of what this
/// program exists to collect.
///
/// The coarse pass stops at 448 rather than 512 so that `coarse + fine <= 504`
/// is something the verifier can see without carrying a relation between them;
/// a payload that fills the buffer takes the whole-buffer fast path above it.
#[inline(always)]
fn copy_payload(ctx: &SkBuffContext, offset: usize, len: usize, dst: *mut u8) -> Option<usize> {
    if len >= DNS_BUF_LEN && load_at::<{ DNS_BUF_LEN }>(ctx, offset, dst) {
        return Some(DNS_BUF_LEN);
    }

    let coarse = if len >= 448 && load_at::<448>(ctx, offset, dst) {
        448
    } else if len >= 384 && load_at::<384>(ctx, offset, dst) {
        384
    } else if len >= 320 && load_at::<320>(ctx, offset, dst) {
        320
    } else if len >= 256 && load_at::<256>(ctx, offset, dst) {
        256
    } else if len >= 192 && load_at::<192>(ctx, offset, dst) {
        192
    } else if len >= 128 && load_at::<128>(ctx, offset, dst) {
        128
    } else if len >= 64 && load_at::<64>(ctx, offset, dst) {
        64
    } else {
        0
    };

    // SAFETY: `coarse <= 448` and the fine rungs below are all <= 56, so every
    // write stays inside the 512-byte `data` field of the reserved record.
    let mid = unsafe { dst.add(coarse) };
    let at = offset + coarse;
    let rest = len - coarse;

    let fine = if rest >= 56 && load_at::<56>(ctx, at, mid) {
        56
    } else if rest >= 48 && load_at::<48>(ctx, at, mid) {
        48
    } else if rest >= 40 && load_at::<40>(ctx, at, mid) {
        40
    } else if rest >= 32 && load_at::<32>(ctx, at, mid) {
        32
    } else if rest >= 24 && load_at::<24>(ctx, at, mid) {
        24
    } else if rest >= 16 && load_at::<16>(ctx, at, mid) {
        16
    } else if rest >= 8 && load_at::<8>(ctx, at, mid) {
        8
    } else {
        0
    };

    let mut total = coarse + fine;

    // Pass 3. `len - 8` is in `4..=504` (the caller guarantees `len >= 12` and
    // clamps it to `DNS_BUF_LEN`), so an 8-byte write there ends at 512 at the
    // very worst -- which is the bound the verifier needs, and the reason the
    // clamp in `try_dns` is written as an assignment it can see.
    if total < len {
        let back = len - 8;
        // SAFETY: `back + 8 == len <= DNS_BUF_LEN`, so this stays inside the
        // record's `data` field.
        if load_at::<8>(ctx, offset + back, unsafe { dst.add(back) }) {
            total = len;
        }
    }

    // A record shorter than a DNS header tells userspace nothing, and the
    // caller has already established that the payload is at least that long,
    // so getting here means the helper refused every rung.
    if total >= DNS_HEADER_LEN {
        Some(total)
    } else {
        None
    }
}

/// Copies exactly `N` bytes from `offset` in the skb to `dst`, or fails.
///
/// This calls `bpf_skb_load_bytes` directly instead of going through
/// `SkBuffContext::load_bytes`, and that is not a style preference: the aya
/// wrapper recomputes the length as `min(skb.len - offset, dst.len())` at
/// runtime, so the verifier sees a *range* rather than the constant. The
/// bottom of that range is zero, and the kernel rejects a zero-sized read:
///
/// ```text
/// 101: (85) call bpf_skb_load_bytes#26
/// R4 invalid zero-sized read: u64=[0,39]
/// ```
///
/// Passing `N` straight through keeps it a literal in the emitted code, which
/// is exactly what the ladders above are built to guarantee. The caller has
/// already checked that the skb holds at least `offset + N` bytes.
#[inline(always)]
fn load_at<const N: usize>(ctx: &SkBuffContext, offset: usize, dst: *mut u8) -> bool {
    // Guards the const parameter against the larger of the two destinations,
    // so a rung wider than any buffer here is a compile-visible `false` and
    // not an overflow. The narrower destination (`PKT_SCRATCH`) is covered by
    // `load_prefix` topping out at exactly `PKT_SCRATCH_LEN`.
    if N == 0 || N > DNS_BUF_LEN {
        return false;
    }
    // SAFETY: `ctx.skb.skb` is the kernel-provided `__sk_buff` for this
    // invocation. `dst` is either the per-CPU `PKT_SCRATCH` slot or a position
    // inside the `data` field of a reserved `DnsPacket` record; both callers
    // establish that `N` bytes fit from there (see their doc comments). The
    // helper bounds-checks the source itself and returns non-zero rather than
    // reading past the packet.
    let ret = unsafe {
        aya_ebpf::helpers::generated::bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            offset as u32,
            dst.cast(),
            N as u32,
        )
    };
    ret == 0
}

// ---------------------------------------------------------------------------
// connect() enforcement
// ---------------------------------------------------------------------------

/// What `cgroup/connect4|6` returns to let the syscall proceed.
const CONNECT_PROCEED: i32 = 1;

/// What it returns to refuse. The kernel turns this into `EPERM` from
/// `connect(2)` itself - no packet is ever built, so nothing reaches nftables,
/// NFQUEUE, or the wire.
const CONNECT_REFUSE: i32 = 0;

/// Bumps one counter in `ENFORCE_STATS`.
///
/// Per-CPU, so this is a plain non-atomic add: BPF programs are
/// non-preemptible, and the daemon sums the per-CPU values when it reads them.
#[inline(always)]
fn bump(slot: u32) {
    if let Some(ptr) = ENFORCE_STATS.get_ptr_mut(slot) {
        // SAFETY: `get_ptr_mut` bounds-checks against `max_entries` and returned
        // a non-null pointer to this CPU's slot. See EXEC_SCRATCH.
        unsafe { *ptr = (*ptr).wrapping_add(1) };
    }
}

/// Reports a refusal so it is not a silent one. See [`ConnectDeny`].
///
/// Best effort: a full ring buffer drops the record and the refusal stands.
/// The alternative - letting the connection through because we could not
/// describe it - is not a trade a firewall gets to make.
#[inline(always)]
fn report_deny(ctx: &SockAddrContext, tgid: u32, family: u8) {
    let Some(mut entry) = DENY_EVENTS.reserve::<ConnectDeny>(0) else {
        return;
    };
    let mut ev = ConnectDeny::zeroed();
    ev.pid = tgid;
    ev.family = family;
    // SAFETY: `sock_addr` is the program's context pointer, non-null for the
    // whole run, and these are context fields the verifier permits a
    // `cgroup_sock_addr` program to read directly.
    unsafe {
        let sa = &*ctx.sock_addr;
        // `user_port` is a u32 holding a network-order u16 in its low half.
        ev.port = (sa.user_port & 0xffff) as u16;
        if family == 4 {
            ev.addr[..4].copy_from_slice(&sa.user_ip4.to_ne_bytes());
        } else {
            let mut i = 0;
            // Fixed trip count, unrolled by the compiler: the verifier walks
            // it as four constant copies rather than a loop.
            while i < 4 {
                let word = sa.user_ip6[i].to_ne_bytes();
                ev.addr[i * 4..i * 4 + 4].copy_from_slice(&word);
                i += 1;
            }
        }
    }
    entry.write(ev);
    entry.submit(0);
}

/// The whole decision, shared by the v4 and v6 entry points.
///
/// One hash lookup on a `u32`. There is deliberately no path matching, hashing
/// or string work here: the daemon does that once at `exec` and leaves the
/// answer in the map, so this program stays small enough that its cost is
/// invisible next to `connect()` itself.
///
/// Note what is *not* consulted: the destination. An entry in `VERDICTS` means
/// the daemon decided this executable's answer does not depend on where it is
/// going. Anything destination-scoped is left absent and falls through.
#[inline(always)]
fn connect_verdict(ctx: &SockAddrContext, family: u8, record_cookie: bool) -> i32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // `record_cookie` is a literal at every call site and this function is
    // `inline(always)`, so the `false` variants compile to programs that never
    // reference the helper - which is the whole point: `bpf_get_socket_cookie`
    // does not exist for sock_addr programs on every kernel this project
    // supports, and a program that names a missing helper fails verification
    // outright. The `_basic` entry points below are what old kernels load.
    if record_cookie {
        // SAFETY: `as_ptr` hands the program's own context to a helper the
        // kernel defines for exactly this program type; the kernel assigns the
        // cookie if the socket does not have one yet.
        let cookie =
            unsafe { aya_ebpf::helpers::generated::bpf_get_socket_cookie(ctx.as_ptr()) };
        if cookie != 0 {
            // Failure means the LRU is momentarily unable to evict; the cost is
            // one fallback walk in userspace, never a wrong answer.
            let _ = SOCK_PIDS.insert(&cookie, &tgid, 0);
        }
    }
    // SAFETY: `get` on a BPF hash map from a program context; the returned
    // reference borrows map memory that stays valid for this program run.
    match unsafe { VERDICTS.get(&tgid) } {
        Some(&v) if v == cfc_ebpf_common::verdict::DENY => {
            bump(cfc_ebpf_common::enforce_stat::DENIED);
            report_deny(ctx, tgid, family);
            CONNECT_REFUSE
        }
        Some(&v) if v == cfc_ebpf_common::verdict::ALLOW => {
            bump(cfc_ebpf_common::enforce_stat::ALLOWED);
            CONNECT_PROCEED
        }
        // Absent, or a value from an ABI this object does not know. Both mean
        // "no answer here"; the packet path decides. Never a deny - see the
        // `verdict` module's docs for why that direction is load-bearing.
        _ => {
            bump(cfc_ebpf_common::enforce_stat::UNKNOWN);
            CONNECT_PROCEED
        }
    }
}

/// Refuses IPv4 `connect()` for processes the daemon has already ruled on.
///
/// Attached to the cgroup v2 root through a **pinned** link, which is the
/// point: the link outlives the daemon, so `kill -9` on the daemon does not
/// lift a single deny. Only something that can write to bpffs can - which is
/// to say root, which CFC has never claimed to confine.
#[cgroup_sock_addr(connect4)]
pub fn cfc_connect4(ctx: SockAddrContext) -> i32 {
    connect_verdict(&ctx, 4, true)
}

/// Same, for IPv6. A separate program because the kernel has separate attach
/// types; the decision is identical and only the address it reports differs.
#[cgroup_sock_addr(connect6)]
pub fn cfc_connect6(ctx: SockAddrContext) -> i32 {
    connect_verdict(&ctx, 6, true)
}

/// The same programs without the cookie recording, for kernels whose verifier
/// does not know `bpf_get_socket_cookie` for sock_addr programs.
///
/// The loader tries the cookie variants first and falls back to these on a
/// verifier rejection; enforcement is identical either way, and only the O(1)
/// attribution is lost - userspace then falls back to its walk, exactly as it
/// did before the cookie map existed. Shipping both costs nothing at runtime:
/// aya loads programs individually, so an unloaded variant is just bytes in
/// the object.
#[cgroup_sock_addr(connect4)]
pub fn cfc_connect4_basic(ctx: SockAddrContext) -> i32 {
    connect_verdict(&ctx, 4, false)
}

/// See [`cfc_connect4_basic`].
#[cgroup_sock_addr(connect6)]
pub fn cfc_connect6_basic(ctx: SockAddrContext) -> i32 {
    connect_verdict(&ctx, 6, false)
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
