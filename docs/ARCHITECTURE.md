# Architecture

## Process model

Two long-running processes:

1. **`colony-firewalld`** (root, systemd) - owns the NFQUEUE socket, runs the
   decision engine, persists rules in SQLite, serves a gRPC API on a Unix
   socket at `/run/colony-firewall/cfc.sock`.

2. **`colony-firewall`** (UI, per user session) - connects to the UDS, streams
   pending prompts, posts verdicts. Tray icon + Qt-like main window built
   with [iced](https://iced.rs/).

The CLI tool `cfc` shares the same gRPC client path as the UI for headless
control.

## Packet flow (Phase 1, NFQUEUE only)

```
kernel (nftables OUTPUT hook)
   |
   |  ct state new   queue num 0
   v
NFQUEUE 0
   |
   v
colony-firewalld
   |  parse 5-tuple
   |  lookup pid via /proc + netlink sock_diag
   |  decision::Engine::evaluate(conn, proc)
   |
   +--> Resolved (rule hit)      --> nfq verdict ACCEPT / DROP
   |
   +--> NeedsPrompt              --> push to UI via gRPC stream
                                     | (user clicks Allow / Deny)
                                     v
                                  nfq verdict ACCEPT / DROP
                                  (optionally persist as new rule)
```

## Packet flow (Phase 4, eBPF fast-path)

The expensive parts of the Phase 1 flow are the userspace round-trip and
the `/proc` walk. Phase 4 replaces both:

- **eBPF capture-on-exec**: hooks `sched_process_exec` and `cgroup_socket`
  to build a kernel-side `(pid, exe, sha256)` table. No `/proc` walk needed.
- **eBPF whitelist fast-path**: a BPF_MAP populated by the daemon with
  already-allowed `(pid, dst_ip, dst_port)` tuples. The kernel-side filter
  accepts these without ever reaching NFQUEUE.

Only unknown flows make the userspace round-trip.

## Threading model

`colony-firewalld` runs on a multi-threaded tokio runtime:

- **nfqueue worker** - blocking thread that owns the NFQUEUE recv loop.
  Hands parsed packets to the decision engine via a bounded channel.
- **decision engine** - sync, lock-free hot path (rule lookup under
  parking_lot::RwLock). Returns `Resolved` immediately or `NeedsPrompt`.
- **ipc server** - tonic gRPC server. Streams prompts to UI clients,
  receives verdicts, applies rule changes.
- **storage** - sqlite, behind a mutex. Writes are async-blocking off the
  hot path; reads are cached in the in-memory `RuleSet`.

## Why GPL-3.0?

We are porting opensnitch, which is GPL-3.0. Derivative works inherit the
license. If we later add modules that are clean-room reimplementations
(eBPF programs from scratch, novel UI flows), those can be dual-licensed,
but the workspace stays GPL.
