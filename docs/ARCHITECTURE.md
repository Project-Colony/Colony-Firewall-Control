# Architecture

## Process model

Two long-running processes:

1. **`colony-firewalld`** (root, systemd) - owns the NFQUEUE socket, runs the
   decision engine, persists rules and a verdict log in SQLite, serves a gRPC
   API on a Unix socket at `/run/colony-firewall/cfc.sock`.

2. **`colony-firewall`** (UI, per user session) - connects to the UDS, streams
   pending prompts, posts verdicts. Main window built with
   [iced](https://iced.rs/).

The CLI tool `cfc` shares the same gRPC client path as the UI, and covers
the same surface: it can answer prompts (`cfc prompts`), which is how a
headless machine gets a say.

```
+----------------------------+     +----------------+
|  cfc-ui   (iced, user)     |     |  cfc-cli (tty) |
|   prompts, rules, live     |     |   status, rules|
|   stats                    |     |   prompts, log |
+------------+---------------+     +-------+--------+
             |                             |
             |  tonic gRPC over UDS, 0660 root:colony-firewall
             |  (SO_PEERCRED checked per RPC)
             v                             v
+--------------------------------------------------+
|  colony-firewalld  (systemd, root)                |
|                                                   |
|   nfqueue worker  --+-- decision engine           |
|    (blocking thread)|    (RwLock<RuleSet>)        |
|          |          |                             |
|          |          +-- prompt router --> gRPC    |
|          |                                        |
|          +-- process resolution                   |
|          |     sock_diag -> /proc, TTL caches     |
|          +-- reject injection (raw sockets)       |
|          +-- reverse DNS cache (forward-confirmed)|
|          +-- observed feed --> event writer       |
|                                                   |
|   storage: sqlite (rules + events)                |
|   sd_notify: READY / WATCHDOG / STOPPING          |
+--------------------------------------------------+
```

## Packet flow

```
kernel (nftables OUTPUT hook)
   |
   |  established,related / daemon refusal packets accepted
   |  oifname lo ct state new   queue num 0 bypass  (accepted if no daemon)
   |  ct state new   queue num 0
   |  all other traffic dropped
   v
NFQUEUE 0
   |
   v
colony-firewalld worker thread
   |  parse 5-tuple (IPv4 ihl check, IPv6 ext-header walk)
   |  resolve pid: sock_diag fast path, /proc fallback, TTL caches
   |  kernel-supplied uid/gid (NFQA_UID/NFQA_GID) override /proc
   |  decision::Engine::evaluate(conn, proc)
   |
   +--> Resolved (rule hit)      --> ACCEPT, or DROP (+ reject response)
   |
   +--> NeedsPrompt
          |
          +-- paused?  --> ACCEPT without prompting
          |
          +-- flow already has a prompt outstanding?
          |      --> park this packet on the existing prompt
          |
          +-- new prompt --> park packet, push to subscribers
                              |
                              +-- user answers        -+
                              +-- prompt times out    -+--> verdict
                              +-- no subscriber       -+     applied to
                                                            every parked
                                                            packet
```

Every resolved connection is also published on an internal broadcast feed,
which fans out to `StreamConnections` subscribers and to the event writer.

## The datapath is non-blocking

The original worker answered one packet at a time, so a prompt nobody
answered held the queue until it timed out - a single dialog could stall
every new connection on the machine. It no longer does.

The worker keeps two maps that are created and destroyed together:

- `waiters: HashMap<prompt_id, PendingPrompt>` holds the fallback and each
  parked packet's connection and process snapshot. A prompt answer is
  checked against current policy for every packet; a new refusal takes precedence.
- `pending_flows: HashMap<FlowKey, prompt_id>` - the deduplication index.

Verdicts arrive asynchronously on a separate channel and are applied out of
order, so a slow prompt only delays its own flow.

**The queue socket is non-blocking for the worker's whole life**, and every
idle turn of the loop waits up to `RECV_POLL_INTERVAL` (5 ms) on the verdict
channel. This paragraph used to describe the opposite - a blocking `recv` with
"no polling, no added latency" whenever no prompt was outstanding - which was
true of an earlier design and had not been true for some time. A thread parked
in a blocking `recv` cannot be woken to see a stop flag, and that was ninety
seconds of hang on every daemon stop; `crates/cfc-daemon/src/nfqueue.rs` has
the full argument.

The price is real and is now measured rather than estimated: a queued flow
pays a whole idle beat, about 5 ms, because a client connecting in series
lands just after the worker committed to a fresh wait. `scripts/vm-bench`
attributes it - 4.90 ms of 5.67 at 300 flows, 5.24 ms of 7.61 at 3000, by
building the same daemon with the constant at 200 us and measuring both in one
boot. These are historical measurements, not a current performance guarantee.
Fast Allow was removed, so allowed flows also pay the queue round trip.

**Prompt deduplication** requires the same UID, executable path, image digest,
destination IP, destination port and protocol. Source address and port are
excluded, so equivalent parallel connections may share a prompt. An incomplete
identity never shares authorization. Persistent prompt Allows use the queued
image digest; they never rehash a later image at a reused PID. A retargeted
pathname cannot suppress the required hash binding.

**Exactly-once resolution.** Four paths can resolve a prompt: the user
answers, the timeout fires, there was no subscriber to begin with, or the
last subscriber vanished. They race through one `HashSet` of pending ids -
whoever removes the id first wins and the losers are discarded. Nothing is
resolved twice, and nothing is left unresolved. If the verdict channel
disconnects entirely, every outstanding prompt gets its fallback applied so
no packet is stranded.

**Pause is not a kill switch.** Rules are still evaluated while paused;
only the prompt is skipped, and only for flows that matched no rule. An
explicit Deny or Reject rule keeps blocking. Pause has a deadline: the
daemon clamps the requested duration (24h maximum), reports the real resume
time, and auto-resumes.

**Malformed packets** never reach the rule engine. The parser rejects an
IPv4 header claiming `ihl < 5` (which would otherwise make it read "ports"
from inside the IP header), walks the IPv6 extension-header chain bounded to
8 headers, and classifies non-first fragments as neither TCP nor UDP. A
packet it cannot parse gets the default policy applied silently.

## Process attribution

Given a 5-tuple, the daemon has to name the program behind it, in the few
hundred microseconds before the packet's latency becomes visible.

1. **TCP `sock_diag` fast path.** A netlink `INET_DIAG_REQ_V2` exact-tuple query
   returns the socket inode directly. It works unprivileged and avoids
   reading the whole `/proc/net` table.
2. **`/proc/net/{tcp,udp}{,6}` fallback**, silently, whenever the fast path
   misses. UDP always reads all relevant tables first and requires one unique
   compatible inode: exact or wildcard local address, with exact or zero
   remote address. An unreadable table, an exhausted lookup budget or
   several compatible inodes leave attribution unknown; an absent table
   (`udp6` under `ipv6.disable=1`) counts as empty. The packet's socket UID,
   when present, filters candidates. All comparisons run on canonical form,
   so `::ffff:a.b.c.d`
   rows in the v6 tables match plain IPv4 flows - which is what dual-stack
   Java, Go and node runtimes produce. Rows with inode 0 (TIME_WAIT,
   orphans) are dropped first so they cannot shadow a live socket.
3. **inode -> pid** via the diagnostic cookie when available, otherwise by
   walking `/proc/*/fd` for a `socket:[inode]` link. A shared or passed socket
   descriptor still does not identify which holder sent a packet.

Two bounded caches avoid repeated socket walks and sealed-image hashing:

| Cache          | Key                                         | Lifetime |
|----------------|---------------------------------------------|----------|
| inode -> pid   | socket inode                                | 2s       |
| sealed exe digest | dev, inode, length, mtime and ctime with nanoseconds | key change or eviction |

A complete process record is read on every resolution: exec changes policy
identity without changing pid or start time. A cache hit on the inode cache
is re-verified by reading the `/proc/<pid>/fd` link back before it is trusted.
The socket lookup has a 50ms budget.

The binary's SHA-256 is read through `/proc/<pid>/exe`, so it hashes the
image actually running even if the file on disk was replaced or deleted.
The same opened file supplies metadata and bytes. Content changes during
hashing are rejected; the mapped link, metadata and process start time must
still agree before publishing executable identity. Mutable images are never
served from the digest cache. Files over 64 MiB retain their path but have no
digest. This remains a read-time snapshot: an exec after the final check can
change the process before the queued packet receives its verdict.

The kernel also reports the originating uid and gid with each queued packet
(`NFQA_UID` / `NFQA_GID`). Those are authoritative and override whatever
`/proc` said. When nothing can be attributed, `uid` and `gid` are `None` -
never a fabricated 0, which used to make unattributed traffic match root's
uid-scoped rules.

### With the eBPF layer on

A table fed by the exec/exit tracepoints is consulted *before* `/proc`:

| field | from `/proc` | from the exec table |
|---|---|---|
| `ppid` | `/proc/<pid>/stat` field 4 | exec event |
| `uid`, `gid` | `/proc/<pid>/status` | exec event, i.e. the values at `execve()` |
| `exe` | `/proc/<pid>/exe` | unchanged; raw exec arguments cannot attest the mapped path |
| `cmdline`, `cwd`, digest, package | `/proc` | unchanged |

Two `/proc` file parses disappear per resolve. When the process has already
exited, the record can preserve uid/gid/ppid. Its executable and digest stay
unknown without a readable, consistent mapped image.

It does **not** remove the socket -> pid step - NFQUEUE gives the daemon a
packet, not a pid - and it does not override a readable `/proc/<pid>/exe`,
because the exec event carries the path as passed to `execve()` (possibly
relative, possibly an unresolved symlink) while rules, the digest and package
provenance are all in terms of the canonical path of the mapped image.

Pid reuse is handled exactly, not heuristically: each exec record is bound to
`/proc/<pid>/stat`'s start time, captured by the ring-buffer consumer right
after the event arrives, and a lookup presenting a different start time drops
the record and falls back to `/proc`.

## Rule evaluation

Executable policies name the canonical mapped target explicitly. New CLI,
GUI, native import, OpenSnitch import and daemon writes refuse paths that
resolve through an alias instead of silently saving its current target.
Shipped system-service bundles intentionally select a current fixed target
from their candidate list. They do not track later alias changes.

Missing absolute targets remain valid before installation when their existing
ancestors need no rewriting and no unresolved symlink is present. An alias
installed there later needs operator review. Existing stored paths remain
fixed targets: older rules lost the original alias spelling, so an automatic
migration cannot recover that intent. This is a policy-entry contract; it
does not pin an inode, follow aliases at exec time, or attest future pathname
changes. Legacy alias intent loss is not repaired by this validation.

`RuleSet` is kept sorted so that lookup is a linear scan that returns the
first match, and the order does not depend on what SQLite happened to
return:

1. specificity descending (how many scope predicates are set)
2. Deny, then Reject, then Allow
3. oldest `created_at` first
4. `id`, as a total-order tiebreak

Disabled and expired rules are filtered at lookup, so a `Seconds(n)` rule
stops matching the instant it expires rather than when the reaper next runs.
A 30-second maintenance task flushes hit counts to disk and deletes expired
rows.

## Rejecting, as opposed to dropping

`Deny` and `Reject` hand the kernel the same DROP verdict; they differ in
what the application sees. A dropped packet leaves the program hanging until
its own connect timeout. `Reject` additionally injects a refusal so it fails
immediately:

- **TCP**: an RFC 9293 reset, sourced from the address the program dialed.
  A segment carrying RST is never answered with a RST.
- **UDP**: an ICMP (v4) or ICMPv6 (v6) port-unreachable quoting the
  offending datagram, with the correct pseudo-header checksum.

The raw sockets are opened once at startup, not per packet, so a missing
`CAP_NET_RAW` is reported exactly once. Without it the daemon warns and
Reject degrades to a plain drop - it never fails and never panics. IPv6 uses
`IPV6_HDRINCL` so the header is ours; a kernel-built one would carry a local
source address and the application would discard the reset.

The verdict carries its action verbatim from wherever it came - a matched
rule, an answered prompt, or the default policy - so a persisted `Reject`
rule refuses exactly like an interactive one. Deny and Reject are only
merged at the very last step, when the kernel is told to DROP.

## Event log

Every verdict is persisted off the packet path. The worker verdicts a parsed
refusal first, logs it to the journal, then queues its row straight into the
event writer's bounded queue with `try_send`. Allow rows reach the same queue
through a feeder on the live feed. The writer commits in batches with WAL and
synchronous=FULL.

```
parsed Deny/Reject --> verdict --> journal --> bounded queue --> async writer
                                   \-> live feed
Allow             --> verdict --> live feed --> bounded queue --> async writer
```

Nothing on the worker thread waits for the database. An fsync per refusal
there let a flood of refused packets stall every new flow on the machine, and
a failed or slow commit used to end the worker, which dropped all new
non-loopback traffic until systemd restarted the daemon. Now a full queue,
feeder lag or a failed batch commit (full disk, I/O error) costs rows instead:
they are counted and logged ("events were not persisted", "event log write
failed"), and the journal line still names each refusal. Rows still in the
writer's batch, at most about a second of them, are lost on a crash, a power
cut or a stop. This does not audit malformed packets, nftables drops or
kernel-ring refusals. It is not a lossless audit or protection against root
rewriting the database.
The table is pruned to `[events] max_rows` every 60 seconds. `ListEvents`
queries it with executable-substring, action and since filters; `cfc log` is
the front end.

## IPC and the trust model

The daemon is root and drives the packet filter, so the control socket is
the entire attack surface. Two layers:

1. **File permissions.** After bind, the socket is chowned `root:<group>`
   (default `colony-firewall`) and then chmodded 0660 - in that order, so it
   is never briefly group-readable by the wrong group. If the group does not
   exist the daemon does not refuse to start: it warns with the exact fix and
   leaves the socket 0600, root-only.
2. **Peer credentials.** Every connection carries `SO_PEERCRED`. Mutating
   RPCs (`UpsertRule`, `ApplyRules`, `DeleteRule`, `SetPaused`, `SubmitVerdict`) require
   uid 0 or a socket that is genuinely group-gated. Read-only RPCs
   (`ListRules`, `GetStatus`, `ListEvents`, `StreamConnections`,
   `StreamPrompts`) are open to any peer that got past layer 1.

Group membership *is* the credential - there is no in-band authentication.
Everyone in the group is fully trusted. The one exception is prompt
ownership: the daemon records which subscriber uids actually received each
prompt and refuses a verdict from anyone else, so one desktop session cannot
answer another's. Root is exempt.

Values arriving over the wire are decoded strictly. An unspecified or
out-of-range action or duration is an `InvalidArgument` error, not a silent
fall-through to the zero value - which happened to be Allow.

Every mutating RPC and every Deny/Reject verdict is logged to the journal
with the calling uid and pid. See [HARDENING.md](HARDENING.md).

## Threading model

`colony-firewalld` runs on a multi-threaded tokio runtime:

- **nfqueue worker** - a blocking thread owning the NFQUEUE recv loop, the
  parked-packet maps, and the reject injector. Everything on the packet path
  is synchronous; nothing here awaits.
- **decision engine** - sync, hot path. Rule lookup under a
  `parking_lot::RwLock`; hit counts accumulate in memory and are flushed
  every 30s.
- **prompt router** - bridges the sync worker to async gRPC subscribers.
  Prompts go out on a broadcast channel; verdicts come back on a dedicated
  channel the worker polls.
- **ipc server** - tonic gRPC over the Unix socket.
- **event writer** - batches every verdict into SQLite and prunes on a timer.
  The worker queues refusals into it after their verdict and never waits for
  it; rows it cannot take are counted and logged.
- **storage** - sqlite behind a mutex. Reads are served from the in-memory
  `RuleSet`. Production startup requires WAL with synchronous=FULL. The packet
  path never touches it.

## Lifecycle and systemd integration

The unit is `Type=notify`. `READY=1` is sent only once **both** the NFQUEUE
and the control socket are bound, so "started" means "actually filtering".
A bind failure propagates and the process exits non-zero *before* READY, so
systemd marks the unit failed and `Restart=on-failure` retries - it used to
exit 0, which under the shipped fail-closed nftables rule meant a healthy
looking unit and a blackholed machine.

`WatchdogSec=30` is backed by a real liveness signal rather than a timer
that always fires. The worker stamps a timestamp each iteration, signed to
distinguish "busy" from "parked in a blocking recv" - a parked worker is
healthy indefinitely, an idle machine is not a stall. The main task
heartbeats `WATCHDOG=1` every 10s and withholds it when the worker has been
busy without progress for 60s, which bounds detection of a wedged daemon at
about 90 seconds.

Signals:

- **SIGTERM / SIGINT** - graceful shutdown: `STOPPING=1`, final hit-count
  flush, control socket removed.
- **SIGHUP** - reloads `profile` and `[default_policy]` in place, without
  dropping a packet. The policy lives behind a shared `RwLock` that the
  engine and the prompt router read per decision, so the next prompt uses
  the new timeout. A config file that fails to parse is rejected and the
  running policy is kept. Everything else - the queue number and tuning, the
  database path, the socket path, the event cap, the IPC group - is bound at
  startup and needs a restart.

## The eBPF layer

The kernel-side programs (`crates/cfc-ebpf`, built separately by
`cargo xtask build-ebpf`) and their userspace loader (`cfc-daemon/src/ebpf/`).
The loader is compiled in by default (the `ebpf` cargo feature, which is what
pulls `aya` in); the runtime defaults to automatic loading when the host supports it.
Compiling it in is not the same as running it: while the config switch is off,
`start` returns before any `bpf(2)` call, so a default build is exactly as
inert as one built with `--no-default-features`.

| program | attach | what the daemon does with it |
|---|---|---|
| `tracepoint/sched/sched_process_exec` | `sched:sched_process_exec` | fills a pid -> (exe, comm, uid, gid, ppid) table |
| `tracepoint/sched/sched_process_exit` | `sched:sched_process_exit` | evicts only on confirmed thread-group death |
| `cgroup_skb/ingress` | cgroup v2 root | copies received DNS response payloads for diagnostics, never policy identity |
| `cgroup/connect4`, `cgroup/connect6` | cgroup v2 root, link **pinned** | refuse `connect()` for pids the daemon has denied outright, before a packet exists |

**In-kernel denials.** The connect hooks refuse an executable denied
process-wide with `EPERM`. Pinned denials outlive the daemon. Conditional rules,
prompts and Allow decisions remain on the normal NFQUEUE path.

**Fast Allow was removed.** It marked the sockets of a process a lasting Allow
covered so that nftables accepted them ahead of the queue. A socket mark cannot
prove the current sender's identity, and lifecycle checks do not repair that
property, so it opened bypasses; it was disabled in 0.7.0 and its userspace
side is gone. The `[ebpf] fast_allow` keys still parse and only log a warning.
The kernel object still carries the Fast Allow maps until an ABI bump, so
startup flushes the legacy nft set once, disarms the pinned maps (unarmed mark,
zero deadline, no grants) and removes the old `sendmsg4`/`sendmsg6` link pins,
which detaches those hooks. The nft snippet has no mark-set accept rule, and
package upgrades reload active nft units with one atomic transaction. A failed
flush emits an error and requires operator action before filtering can be
relied upon.

**Compatibility exit handling.** When `sched_process_exit` exposes `group_dead`,
the kernel evicts only on confirmed process death. Without that field, it
preserves identity and deny entries on thread or leader exit. The daemon can
remove a candidate only after `/proc/<pid>/task` is absent. A leader may exit
before its workers, so this conservative fallback can leave stale denials until
exec or reconciliation; it cannot guarantee immediate cleanup after group death.

**Loaded from a path, not embedded.** The kernel-side crate needs a dated
nightly, `-Z build-std=core` and a matching `bpf-linker`, and is deliberately
excluded from this workspace so a plain stable build never touches any of that.
`aya::include_bytes_aligned!` would hand that dependency straight back - so the
object is installed to `[ebpf] object_path` (default
`/usr/lib/colony-firewall/cfc-ebpf.o`) and read at startup instead. The two
build graphs stay independent and are matched at install time.

**BTF, done by the loader.** Rust/aya has no CO-RE field relocation, so the
programs cannot look up `task_struct::real_parent` themselves; they read two
`.rodata` globals that default to 0 ("unresolved", report ppid 0). The loader
parses `/sys/kernel/btf/vmlinux` and patches both offsets in before load. It
parses the blob directly rather than through `aya::Btf`, because aya-obj 0.3
exposes `id_by_type_name_kind` and keeps every route from a type id to a member
offset `pub(crate)`. Side benefit: the parser has no aya dependency and is unit
tested in the default build.

**Ring buffers.** One tokio task per buffer, each a `tokio::io::unix::AsyncFd`
around `aya::maps::RingBuf`: await readable, drain everything present, clear
readiness. Records are copied out of the mapped ring immediately, so a slow
consumer never holds the producer's tail. None of this is on the packet path -
the consumers write into the process table and the DNS cache, and the NFQUEUE
worker only ever reads them.

## Why GPL-3.0?

We are porting opensnitch, which is GPL-3.0. Derivative works inherit the
license. If we later add modules that are clean-room reimplementations
(eBPF programs from scratch, novel UI flows), those can be dual-licensed,
but the workspace stays GPL.
