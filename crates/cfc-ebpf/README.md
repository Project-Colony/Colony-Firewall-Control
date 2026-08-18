# `cfc-ebpf` — kernel-side eBPF programs

The kernel half of Colony Firewall Control's Phase 4 eBPF backend. It compiles
to a single BPF ELF object containing three programs and seven maps. Nothing
here loads or attaches anything — that is the daemon's job (see
[Loading](#loading-attaching-and-capabilities)).

Its userspace counterpart is [`cfc-ebpf-common`](../cfc-ebpf-common), which owns
the shared `#[repr(C)]` event structs **and** all the DNS/IP parsing arithmetic.
That split is deliberate: verifier-constrained code is close to untestable in
place, so every branch that can be expressed as pure `no_std` arithmetic lives in
`cfc-ebpf-common` and is unit-tested on the host against hand-built packets.

---

## Programs

### 1. `tracepoint/sched/sched_process_exec` → `cfc_sched_process_exec`

Fires on every successful `execve`. For each one it:

* reads `pid`/`tgid` from `bpf_get_current_pid_tgid()` and `uid`/`gid` from
  `bpf_get_current_uid_gid()`;
* copies `comm` via `bpf_get_current_comm()`;
* resolves the executable path from the tracepoint's `__data_loc filename`
  field (see below);
* best-effort resolves `ppid` (see [ppid](#ppid-and-the-absence-of-co-re));
* **inserts** the resulting `ExecEvent` into the `PROCS` hash map keyed by tgid,
  **then** pushes the same event to the `EXEC_EVENTS` ring buffer.

Insert-before-publish is intentional: by the time userspace sees the ring-buffer
record, the corresponding `PROCS` lookup is already guaranteed to succeed.

#### The `__data_loc` dance

`/sys/kernel/tracing/events/sched/sched_process_exec/format` reports:

```text
field:unsigned short common_type;         offset:0;  size:2;
field:unsigned char  common_flags;        offset:2;  size:1;
field:unsigned char  common_preempt_count;offset:3;  size:1;
field:int            common_pid;          offset:4;  size:4;

field:__data_loc char[] filename;         offset:8;  size:4;
field:pid_t          pid;                 offset:12; size:4;
field:pid_t          old_pid;             offset:16; size:4;
```

`filename` is *not* the string. It is a 4-byte word at record offset 8 encoding
`(length << 16) | offset`, where `offset` is relative to the start of the
tracepoint record and points into the record's variable-length tail. So:

```rust
let data_loc: u32 = ctx.read_at::<u32>(8)?;   // bpf_probe_read_kernel
let offset =  (data_loc & 0xffff) as usize;
let len    = ((data_loc >> 16)  ) as usize;
let src    =  ctx.as_ptr().cast::<u8>().add(offset);
bpf_probe_read_kernel_str_bytes(src, &mut event.filename)
```

`bpf_probe_read_kernel_str_bytes` returns the bytes *excluding* the trailing
NUL, which is exactly the `filename_len` userspace wants. Paths longer than 256
bytes are truncated.

### 2. `tracepoint/sched/sched_process_exit` → `cfc_sched_process_exit`

Removes the pid from `PROCS` and pushes an `ExitEvent` to `EXIT_EVENTS`, so the
userspace cache can never serve a stale entry for a **recycled** pid.

Two details:

* This tracepoint fires for every *thread*. The program compares
  `bpf_get_current_pid_tgid()`'s two halves and only acts when `tgid == tid`,
  i.e. when the thread-group leader dies and the process is genuinely gone.
  Evicting on any thread exit would blind the daemon to a still-running
  multithreaded process.
* It reads nothing from the tracepoint record. `/sys/kernel/tracing` is
  root-only on the build host, so the `sched_process_exit` field layout could
  not be verified; the helper is layout-independent and therefore strictly
  safer.

### 3. `cgroup_skb/ingress` → `cfc_dns_ingress`

Matches inbound UDP datagrams with **source port 53**, parses the DNS response,
and pushes one `DnsAnswer` per `A`/`AAAA` record to the `DNS_ANSWERS` ring
buffer. It always returns `1` (pass) — it is an observer and never drops
traffic.

#### Why `cgroup_skb/ingress` and not `socket_filter`

| | `cgroup_skb/ingress` | `socket_filter` |
|---|---|---|
| scope | every socket of every task in the cgroup | one socket you attached to |
| system-wide DNS | attach once to the root cgroup v2 | needs an `AF_PACKET` socket + `CAP_NET_RAW` |
| skb starts at | **L3** (IP header) | L2 (Ethernet), with per-link variation |
| capability | `CAP_NET_ADMIN` (which the daemon needs anyway) | `CAP_NET_RAW` |

`socket_filter` would have forced the program to parse Ethernet/VLAN headers
whose shape varies per interface, for no benefit. `cgroup_skb` hands us the IP
header directly and covers the whole machine from a single attach, using a
capability the firewall daemon already holds. The trade-off is that it only sees
tasks inside the attached cgroup — attaching to `/sys/fs/cgroup` (the v2 root)
covers everything.

#### What the DNS parser supports

* `A` (type 1) and `AAAA` (type 28) records, class `IN`, in the **answer**
  section of a response (`QR=1`) with `RCODE == NOERROR`.
* Name compression pointers (RFC 1035 §4.1.4), which real resolvers use for
  essentially every answer's owner name. At most **4** pointer jumps per name,
  and only **backwards** pointers (`target < current_offset`) — that constraint
  alone makes non-termination impossible, independent of the jump cap, and kills
  the classic compression-bomb.

#### What it deliberately skips

| skipped | why |
|---|---|
| answers past the 8th | verifier loop budget; `MAX_ANSWERS = 8` |
| responses with > 4 questions | the answer offset needs the questions walked; real responses have 1 |
| names longer than 253 bytes | RFC limit, and the `DnsAnswer::name` field size |
| labels > 63 bytes, reserved label types (`0b01`/`0b10`) | malformed |
| everything past 512 captured bytes | scratch buffer size; parsing stops at the first record it cannot read *in full* |
| `CNAME`/`NS`/`SOA`/`MX`/… | skipped by `rdlength`, not reported |
| the authority and additional sections | not needed for IP→name attribution |
| IPv4 fragments after the first | they carry no UDP header |
| IPv6 with extension headers | next-header must be UDP; chain-walking is another unbounded-ish loop for little gain |
| TCP DNS, DoT, DoH, mDNS | out of scope for this hook |

---

## Maps

| name | type | shape | purpose |
|---|---|---|---|
| `PROCS` | `HASH` | `u32 → ExecEvent` (10240) | live processes by tgid |
| `EXEC_EVENTS` | `RINGBUF` | 256 KiB | exec stream |
| `EXIT_EVENTS` | `RINGBUF` | 64 KiB | exit stream |
| `DNS_ANSWERS` | `RINGBUF` | 256 KiB | `A`/`AAAA` answer stream |
| `EXEC_SCRATCH` | `PERCPU_ARRAY` | 1 × `ExecEvent` | see below |
| `ANSWER_SCRATCH` | `PERCPU_ARRAY` | 1 × `DnsAnswer` | see below |
| `PKT_SCRATCH` | `PERCPU_ARRAY` | 1 × `[u8; 512]` | copied packet prefix |

The three scratch maps exist because **a BPF program gets 512 bytes of stack in
total**. `ExecEvent` alone is 292 bytes and `DnsAnswer` is 276; neither can live
on the stack next to everything else. Per-CPU array slots are the standard
workaround and cost nothing at runtime — BPF programs are non-preemptible, so a
slot cannot be clobbered mid-program.

Measured stack usage of the built object:

```text
cgroup_skb/ingress                     831 insns, 232 bytes of stack
tracepoint/sched/sched_process_exec    153 insns,  48 bytes of stack
tracepoint/sched/sched_process_exit     23 insns,   4 bytes of stack
```

---

## Verifier constraints that shaped the code

These are not stylistic preferences; each one is a thing that failed, or would
have failed, and forced a rewrite.

**No panics anywhere.** Every read goes through `Option`-returning accessors
(`slice::get`, never `&buf[a..b]`). A reachable `panic!` in a BPF object either
fails to link (no `core::fmt`) or traps at runtime. The `#[panic_handler]` is a
bare `loop {}` rather than `unreachable_unchecked()` on purpose: if a panic path
ever *did* survive optimisation, `loop {}` makes the verifier reject the program
at load time — which the daemon handles as "degrade gracefully" — whereas
`unreachable_unchecked()` would instead let the optimiser delete the bounds
check that guarded it and run unsound code in the kernel.

**Constant loop bounds only.** Every loop is `while i < CONST` with an early
`break`, never `while i < runtime_value`. The verifier explores all paths, so a
runtime-bounded loop either gets rejected outright or explodes the instruction
budget.

**No large `memset`.** This is the one that bites hardest, and it produces a
link-time error rather than a verifier error:

```text
ERROR llvm: A call to built-in function 'memset' is not supported.
```

Two independent causes, both fixed here:

1. bpf-linker passes `-bpf-expand-memcpy-in-order` to LLVM by default, which
   sets the BPF backend's `MaxStoresPerMemset` and `MaxStoresPerMemcpy` to
   **zero** while only custom-lowering `MEMCPY`. Every `llvm.memset` then
   becomes a libcall — even a 16-byte `[0u8; 16]`. Fixed by
   `-C link-arg=--disable-expand-memcpy-in-order` in
   [`.cargo/config.toml`](.cargo/config.toml).
2. Even with inline expansion restored, a 292-byte `*event = ExecEvent::zeroed()`
   is far past what the backend will expand to stores. So the programs never
   zero a whole event struct. Instead every scalar field is assigned
   unconditionally, and the two large byte arrays (`ExecEvent::filename`,
   `DnsAnswer::name`) are written as "prefix + one NUL terminator". The stale
   tail is unreachable from userspace: `filename_len`/`name_len` bound it and
   `cfc_ebpf_common::nul_terminated` stops at the NUL as well. The per-CPU slots
   start out zeroed by the kernel, so this is never *uninitialised* memory.

   The same rule killed the obvious `for i in written..MAX { out[i] = 0 }` tail
   clear inside `read_name` — LLVM's loop-idiom pass rewrites it straight back
   into a 253-byte `memset`.

**`bpf_skb_load_bytes` needs a constant length**, and fails outright if that
length runs past the end of the skb. There is no "copy up to N bytes". Hence the
descending ladder in `load_prefix`: constant-size attempts at 512, 448, 384,
320, 256, 192, 128, 64 and finally 40 (`MIN_DNS_PACKET` = 20 + 8 + 12), first
fit wins. Rungs are 64 bytes apart, so at most 63 trailing bytes of a packet are
dropped.

**No unchecked pointer arithmetic on packet data.** Every packet byte is read
through the copied `PKT_SCRATCH` buffer, itself filled only by
`ctx.load_bytes()`. The programs never touch `skb->data`/`skb->data_end`
directly. Kernel memory (the `task_struct` walk) goes exclusively through
`bpf_probe_read_kernel`, which faults gracefully instead of oopsing.

### `ppid` and the absence of CO-RE

Rust/aya has **no CO-RE field relocation**: LLVM only emits the relocation
records for C's `__builtin_preserve_access_index`. Hard-coding
`offsetof(task_struct, real_parent)` would silently break on every kernel that
reorders the struct.

So the program does not guess. Two `.rodata` globals —
`TASK_REAL_PARENT_OFFSET` and `TASK_TGID_OFFSET` — default to `0`, meaning
"unresolved", and the program leaves `ppid = 0` in that case. The **loader** is
expected to read both offsets out of `/sys/kernel/btf/vmlinux` (aya can parse
BTF) and override them via `EbpfLoader::set_global` before load. That is real
CO-RE, done at load time by the side that can actually do it.

`ppid == 0` is a defined, non-fatal state: userspace treats it as "unknown" and
may fall back to `/proc/<pid>/stat`.

---

## Building

Requirements:

* `bpf-linker` (`cargo install bpf-linker`) — **0.11.0** here;
* the dated nightly pinned in [`rust-toolchain.toml`](rust-toolchain.toml) with
  the `rust-src` component.

```sh
# from the repository root
cargo xtask build-ebpf                       # release (default)
cargo xtask build-ebpf --debug
cargo xtask ebpf-path                         # print the object path

# or, equivalently, from this directory
cargo build --release
```

The plain `cargo build` form works because this directory carries its own
`rust-toolchain.toml` and `.cargo/config.toml` (target + `-Z build-std=core`).
The fully explicit form is:

```sh
cd crates/cfc-ebpf
cargo +nightly-2026-07-01 build --release \
    --target bpfel-unknown-none -Z build-std=core
```

Output:

```text
crates/cfc-ebpf/target/bpfel-unknown-none/release/cfc-ebpf   (~198 KiB)
```

### The nightly pin is load bearing

`bpfel-unknown-none` sets `obj-is-bitcode = true`, so rustc hands bpf-linker raw
LLVM **bitcode**. rustc's LLVM must therefore not be *newer* than the LLVM
bpf-linker was built against, or the link fails with `ERROR llvm: Invalid
record`.

```text
bpf-linker 0.11.0    -> system LLVM 22.1.8
nightly-2026-07-01   -> rustc 1.98.0-nightly, LLVM 22.1.8   OK
nightly (2026-08-17) -> rustc 1.100.0-nightly, LLVM 23.1.0  breaks
```

Before bumping the pin, check `rustc +<pin> -Vv | grep LLVM` against
`llvm-config --version`.

### Isolation from the stable workspace

This crate is **not** a member of the root workspace: it is listed under
`exclude` *and* declares its own `[workspace]` table, so it gets its own
`Cargo.lock`. Consequences, all intentional:

* `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets` and the MSRV 1.88 check never see
  this crate and are completely unaffected by it;
* `aya-ebpf` never enters the root lockfile, so it never widens the `cargo deny`
  surface of the shipped userspace binaries;
* the nightly pin and the BPF target settings live in *this* directory
  (`rust-toolchain.toml`, `.cargo/config.toml`). rustup and cargo resolve both
  by walking **up from the current working directory**, so a build started at
  the repository root can never pick them up. The root `.cargo/config.toml`
  contains only an `[alias]`, nothing that could affect a stable build.

---

## Loading, attaching, and capabilities

Verifying the object is **not** possible without privileges, and none of the
following has been exercised on the build host — the object was validated
statically only (ELF sections, relocations, instruction counts, stack usage).

| program | attach | required capabilities |
|---|---|---|
| `tracepoint/sched/sched_process_exec` | `TracePoint::attach("sched", "sched_process_exec")` | `CAP_BPF` + `CAP_PERFMON` |
| `tracepoint/sched/sched_process_exit` | `TracePoint::attach("sched", "sched_process_exit")` | `CAP_BPF` + `CAP_PERFMON` |
| `cgroup_skb/ingress` | `CgroupSkb::attach(cgroup_fd, Ingress, …)`, cgroup v2 root at `/sys/fs/cgroup` | `CAP_BPF` + `CAP_NET_ADMIN` |

All programs declare `license = "GPL"` (the object has a `license` section)
because every helper they use — `bpf_probe_read_kernel`, `bpf_ringbuf_*`,
`bpf_get_current_task`, `bpf_skb_load_bytes` — is GPL-only. The project is
GPL-3.0-or-later, so this is both required and accurate.

Kernel requirements:

* **BTF** at `/sys/kernel/btf/vmlinux` (present on the target host, kernel
  7.1.8). Needed for the `.rodata` globals and for the loader's `task_struct`
  offset resolution.
* Ring buffers → kernel ≥ 5.8. `BPF_MAP_TYPE_ARRAY` `.rodata` with
  `BPF_F_MMAPABLE` → ≥ 5.5. Bounded loops → ≥ 5.3. `CAP_BPF` as a distinct
  capability → ≥ 5.8. In practice: **kernel 5.8+**, running unprivileged-BPF-
  disabled as every modern distro does.
* cgroup v2 mounted (unified hierarchy) for the DNS program.

**The daemon must degrade gracefully when any of this is unavailable.** Missing
`CAP_BPF`, a kernel without BTF, a verifier rejection, or a cgroup v2 path that
does not exist are all expected conditions on some machines, not errors: the
eBPF backend is an *enrichment* layer over the existing nfqueue/procfs path, and
Colony Firewall Control must keep working with it switched off. Each of the
three programs should be attachable independently, so losing the cgroup attach
(e.g. no `CAP_NET_ADMIN`) still leaves exec/exit tracking running.

### Consuming the types

`cfc-ebpf-common` deliberately does **not** depend on `aya`, so that the marker
trait does not drag aya into the stable workspace's dependency graph. The
loader should write, next to its map handles:

```rust
unsafe impl aya::Pod for cfc_ebpf_common::ExecEvent {}
unsafe impl aya::Pod for cfc_ebpf_common::ExitEvent {}
unsafe impl aya::Pod for cfc_ebpf_common::DnsAnswer {}
```

which is sound because all three are `#[repr(C)]`, contain no pointers, no
`Drop` and no niches, and carry explicit padding fields that the kernel side
always writes.
