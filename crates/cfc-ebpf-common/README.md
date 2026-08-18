# `cfc-ebpf-common`

The types and parsers shared between the kernel-side
[`cfc-ebpf`](../cfc-ebpf) programs and the userspace daemon.

It is dependency-free and compiles both as `#![no_std]` (for
`bpfel-unknown-none`) and with `std` (default, for the host). Same source, same
struct layouts, same parsing code on both sides — which is the point.

## What lives here

**The wire format.** `ExecEvent`, `ExitEvent` and `DnsAnswer` are the exact
byte layout of the BPF ring buffers and hash-map values. All three are
`#[repr(C)]` POD with **explicit** padding fields, so `size_of` is stable and
the kernel never copies uninitialised padding into a ring buffer. The sizes are
frozen by tests:

| type | size | align |
|---|---|---|
| `ExecEvent` | 292 | 4 |
| `DnsAnswer` | 276 | 4 |
| `ExitEvent` | 4 | 4 |

**The parsers.** `dns` and `net` hold the arithmetic half of the
`cgroup_skb/ingress` program: DNS header/question/answer walking with
compression-pointer support, and IPv4/IPv6 → UDP payload offset math.

They are written to the eBPF verifier's rules — no panics (`slice::get`, never
`&buf[a..b]`), no unbounded loops, no dynamic slicing, no allocation, tiny stack
frames — but they are *ordinary Rust functions*, so the host test suite drives
them directly with hand-built packets. That is the whole reason the module is
here rather than in `cfc-ebpf`: a BPF object cannot be unit-tested, but this
can, and it is where all the interesting off-by-one risk lives.

Covered by the tests: plain `A` and `AAAA` records, compressed owner names,
`CNAME`-then-`A` chains, every truncation prefix of a valid packet, lying
`rdlength`, wrong `rdlength` for the record type, non-`IN` classes, forward and
self-referential compression pointers, over-long names, over-long jump chains, a
9-answer response proving the 8-answer cap, parsing at a non-zero base offset
(as the BPF scratch buffer does), and a small random-garbage fuzz loop. Plus
IPv4 options, IPv4 fragments, IPv6 extension headers, and payload-length
clamping on the `net` side.

## Features

* `std` *(default)* — adds `comm_str()`, `filename_str()`, `name_str()`
  (lossy, never panic on invalid UTF-8 or an unterminated buffer), `ip_addr()`,
  `set_ip()` and readable `Debug` impls.

The kernel-side crate depends on this one with `default-features = false`.

## `aya::Pod`

Deliberately not implemented here — see the note at the top of `lib.rs`. Adding
an `aya` feature would put aya into the root `Cargo.lock` and into `cargo deny`'s
view for the sake of a marker trait. The loader writes the three `unsafe impl`
lines itself; the layout guarantees above are what make that sound.
