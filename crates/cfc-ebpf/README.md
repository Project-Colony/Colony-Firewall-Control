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

Matches inbound UDP datagrams with **source port 53** and copies the DNS
payload into the `DNS_PACKETS` ring buffer as a `DnsPacket`. It always returns
`1` (pass) — it is an observer and never drops traffic.

It does **not parse DNS**. That is the whole design, and it is not a
simplification for its own sake: in-kernel DNS parsing does not fit in the
verifier's complexity budget. See
[Why the DNS parsing is in userspace](#why-the-dns-parsing-is-in-userspace).

What the kernel half does, in order:

1. `skb->len >= 40` (the shortest possible IPv4 + UDP + DNS header);
2. copy up to 80 bytes — the worst-case header stack — into `PKT_SCRATCH`;
3. `cfc_ebpf_common::net::udp_payload_from_l3` to confirm IPv4/IPv6 + UDP,
   unfragmented, and to locate the payload;
4. source port == 53;
5. payload length >= 12 and the **QR bit** set (`payload[2] & 0x80`) — one byte
   of sanity so a stray port-53 datagram does not cost a 514-byte record;
6. reserve a `DnsPacket`, copy the payload straight from the skb into it, write
   the length, submit.

Everything past that — opcode, rcode, section counts, questions, answers,
names, compression pointers — is the daemon's job.

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

The parser is `cfc_ebpf_common::dns`, running in the **daemon**, over
`DnsPacket::payload()`. It still obeys the panic-free, constant-loop-bound,
no-dynamic-slicing style it was written in — that style is worth keeping for a
parser fed attacker-influenced bytes, and it keeps the option of moving pieces
back into the kernel open — but it no longer answers to the verifier, so the
caps are set for correctness rather than for a budget.

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
| answers past the 8th | `MAX_ANSWERS = 8`; more than that from one response is not worth the work |
| responses with > 4 questions | the answer offset needs the questions walked; real responses have 1 |
| names longer than 253 bytes | RFC limit, and the `DnsAnswer::name` field size |
| labels > 63 bytes, reserved label types (`0b01`/`0b10`) | malformed |
| everything past 512 captured bytes | `DNS_BUF_LEN`, i.e. the RFC 1035 §4.2.1 limit on an unextended UDP message; larger EDNS(0) responses are truncated and parsing stops at the first record it cannot read *in full* |
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
| `DNS_PACKETS` | `RINGBUF` | 256 KiB | DNS response payloads (514-byte records) |
| `EXEC_SCRATCH` | `PERCPU_ARRAY` | 1 × `ExecEvent` | see below |
| `PKT_SCRATCH` | `PERCPU_ARRAY` | 1 × `[u8; 80]` | copied header prefix |

Six maps, not seven: `ANSWER_SCRATCH` (1 × `DnsAnswer`) is gone with the
in-kernel parser that needed it.

The scratch maps exist because **a BPF program gets 512 bytes of stack in
total**, and `ExecEvent` alone is 292 bytes. Per-CPU array slots are the
standard workaround and cost nothing at runtime — BPF programs are
non-preemptible, so a slot cannot be clobbered mid-program.

`PKT_SCRATCH` is 80 bytes rather than 512 because only *headers* are read out
of it now: 60 bytes of worst-case IPv4 header, 8 of UDP, and the first 12 of the
DNS message. The payload never passes through it — `bpf_skb_load_bytes` writes
it directly into the reserved ring-buffer record, so it is copied exactly once
and never touches the stack.

Measured size and stack usage of the built object:

```text
cgroup_skb/ingress                     355 insns, 56 bytes of stack
tracepoint/sched/sched_process_exec    158 insns, 48 bytes of stack
tracepoint/sched/sched_process_exit     25 insns,  4 bytes of stack
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
descending ladders: constant-size attempts, first fit wins.

There are two of them, because they have different jobs:

* `load_prefix` fills `PKT_SCRATCH` for header classification. Rungs at 80, 72,
  64, 56, 48 and 40 (`MIN_DNS_PACKET` = 20 + 8 + 12) — 8 bytes apart, because
  the shortest thing it has to reach is `udp.offset + 3` on a 60-byte IPv6
  response.
* `copy_payload` fills the ring-buffer record, and has to cover 12..=512 bytes.
  One ladder fine enough for that would be sixty-odd rungs, so it is three
  passes: **coarse** in 64-byte steps (0..=448), **fine** in 8-byte steps over
  what is left, and a **tail** — one fixed 8-byte read positioned to *end*
  exactly at the end of the payload, filling in the last `len % 8` bytes. The
  tail overlaps what the fine pass already wrote; copying the same bytes twice
  is free, and it is what makes the result exact.

That exactness is load-bearing, and was found the hard way. A first version
rounded the length down to a multiple of 8 — losing at most 7 bytes, which
sounded harmless. It is not: those 7 bytes are the *end of the last answer
record*, `parse_answer_at` refuses a record it cannot read in full, and the
common case is a response carrying exactly one answer. The rounded version
captured packets perfectly and produced zero answers.

Note also that `copy_payload` is driven by `UdpPayload::declared_len` (the
length in the UDP header) and **not** by `UdpPayload::len`. The latter is
clamped to however much of the packet was copied into `PKT_SCRATCH`, which is
only ever headers — using it would have capped every capture at ~50 bytes.

**No unchecked pointer arithmetic on packet data.** Every packet byte the
program *reads* comes through the copied `PKT_SCRATCH` buffer, and every byte it
*forwards* is written by the kernel's own helper into a reserved ring-buffer
record. The programs never touch `skb->data`/`skb->data_end` directly. Kernel
memory (the `task_struct` walk) goes exclusively through
`bpf_probe_read_kernel`, which faults gracefully instead of oopsing.

### Why the DNS parsing is in userspace

The verifier gives a program **1,000,000 instructions** of state exploration.
Not instructions executed — instructions *walked*, across every path it has to
prove safe. In-kernel DNS name parsing does not fit, and the gap is not close.

The kernel-side parser was written to every rule above: constant loop bounds,
`slice::get` everywhere, no allocation, scratch in a per-CPU map. Three verifier
rejections were diagnosed and fixed in sequence — a zero-sized
`bpf_skb_load_bytes` read (the aya wrapper's `min`, see above), an unprovable
store into the name buffer (fixed with an index mask, because LLVM deletes a
redundant *check* but cannot delete a mask that changes the value), and then
lowered caps. It still died on:

```text
processed 1000001 insns (limit 1000000)
```

at roughly **24,000 states**, on kernel 7.1.8. Lowering the caps further did not
move it — not `MAX_ANSWERS` 8 → 4, not `MAX_LABELS` 32 → 24, not `DNS_BUF_LEN`
512 → 256. That is the tell. The cost is not any single bound but the *product*
of the nested `answer × label × byte` loops, which the verifier must explore
exhaustively; shaving a factor off one term leaves the shape intact.

So the parsing moved out. The kernel now does only what the kernel is uniquely
able to do — see the packet, cheaply, in flight — and the daemon does the part
that needs loops, where there is no verifier and where the parser
(`cfc_ebpf_common::dns`, 63 host tests) already lived.

The result, measured on the same kernel:

| program | verified insns | budget used |
|---|---|---|
| `cfc_dns_ingress` | **17,058** | 1.7% |
| `cfc_sched_process_exec` | 248 | 0.02% |
| `cfc_sched_process_exit` | 25 | 0.003% |

From over budget to 1.7% of it. The loader logs these counts at `debug` on
every load (`verified_insns`), so a change that makes a program dramatically
more expensive is visible before it becomes "the program stopped loading on
someone else's kernel".

The costs of the split, stated plainly: one extra copy of the payload (into the
ring buffer), 514-byte records instead of 276-byte ones, and DNS answers now
arrive after a ring-buffer hop instead of being extracted in place. None of it
is on the packet path — NFQUEUE only ever *reads* the resulting `DnsCache`.

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
trait does not drag aya into the stable workspace's dependency graph.

An earlier version of this section told the loader to write
`unsafe impl aya::Pod for cfc_ebpf_common::ExecEvent {}`. **That does not
compile**, and cannot: `aya::Pod` and `ExecEvent` are both foreign to
`cfc-daemon`, so the impl is refused by the orphan rule (E0117). It is also
unnecessary - `aya::Pod` is needed for *typed map access*
(`aya::maps::HashMap<_, K, V>`, `Array<_, V>`, `EbpfLoader::override_global`),
and the loader touches none of the typed maps: everything userspace needs
arrives through the ring buffers, which hand back `&[u8]`. Records are decoded
with a checked-length `ptr::read_unaligned`, which is sound for exactly the
reasons the marker trait would have asserted: all three types are `#[repr(C)]`,
contain no pointers, no `Drop` and no niches, and carry explicit padding fields
that the kernel side always writes.

`PROCS` is therefore never read from userspace at all. It stays because the
insert-before-publish ordering is what makes an `EXEC_EVENTS` record imply a
live map entry, and because a future in-kernel consumer (a whitelist fast path)
would want it.

### What the loader actually does

Implemented in `crates/cfc-daemon/src/ebpf/`, behind the daemon's `ebpf` cargo
feature (**on** by default) and `[ebpf] enabled` in `daemon.toml` (still off).

1. reads the object from `[ebpf] object_path`, default
   `/usr/lib/colony-firewall/cfc-ebpf.o`. It is **not** embedded with
   `include_bytes_aligned!`: that would make a stable `cargo build --features
   ebpf` depend on this crate's nightly + bpf-linker toolchain, which is
   exactly what excluding this crate from the workspace was for.
2. resolves `TASK_REAL_PARENT_OFFSET` / `TASK_TGID_OFFSET` from
   `/sys/kernel/btf/vmlinux` and patches them in with
   `EbpfLoader::override_global` (`set_global` is deprecated as of aya 0.13.2).
   It parses the BTF blob by hand rather than through `aya::Btf`, because
   aya-obj 0.3 exposes only `Btf::id_by_type_name_kind` publicly and keeps
   `Btf::types()`, `type_by_id`, `BtfMember` and `Struct::members` all
   `pub(crate)` - there is no public "offset of this member" API.
3. attaches each program independently; any failure is a warning.
4. drains each ring buffer from a tokio task built on
   `AsyncFd<RingBuf<MapData>>`.

Programs are addressed by their **ELF symbol** (`cfc_sched_process_exec`,
`cfc_sched_process_exit`, `cfc_dns_ingress`), not by section name.

### Verified on a live kernel

Loaded and attached under root on kernel 7.1.8 (x86_64). **All three programs
load, verify and attach**, and `dns_capture = true`.

* the BTF patch works end to end — a captured exec event reads
  `KernelProc { pid: 1472174, ppid: Some(1472170), uid: 0, gid: 0,
  exe: "/usr/bin/sleep", comm: "sleep" }`, with a **resolved ppid**, which is
  only possible if both `.rodata` offsets reached the program;
* the exit tracepoint evicts the record when the process dies;
* `cgroup_skb/ingress` captures real answers. Observed in one run, off the
  wire, through the ring buffer and the userspace parser and into `DnsCache`:

  ```text
  one.one.one.one -> 1.1.1.1
  one.one.one.one -> 1.0.0.1
  one.one.one.one -> 2606:4700:4700::1111
  one.one.one.one -> 2606:4700:4700::1001
  example.com     -> 104.20.23.154
  example.com     -> 172.66.147.243
  ```

  Note that those were captured off *systemd-resolved's* socket, not the test
  process's: the program is attached to the cgroup v2 root, so it sees the whole
  machine. The corollary is that a name the local resolver answers from its own
  cache produces no packet and therefore no observation — which is why the live
  half of the test prints and asserts nothing.

#### Reproducing it

```sh
cargo xtask build-ebpf
cargo test -p cfc-daemon --profile fast --no-run
sudo -n env CFC_EBPF_OBJECT=$(cargo xtask ebpf-path) \
    ./target/fast/deps/cfc_daemon-<hash> --ignored --nocapture loads_and_attaches
```

`loads_and_attaches_on_this_kernel` asserts both tracepoints attach, that the
BTF offsets resolve, that `dns_capture` is true, and that a DNS answer reaches
`DnsCache`. The last one is hermetic on purpose: it binds `127.0.0.1:53`, sends
one handmade response to a socket of its own, and requires the answer to come
out the far end. Loopback is enough because `cgroup_skb/ingress` runs at the
receiving socket rather than at a device — so the assertion needs no resolver,
no uplink, and no luck.
