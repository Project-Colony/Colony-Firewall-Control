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
   |  meta mark @fast_allow accept   (opt-in fast path: a socket the connect
   |                                  hook marked for an already-allowed
   |                                  process skips the queue; the set holds
   |                                  one element while armed, none otherwise)
   |  ct state new   queue num 0
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

- `waiters: HashMap<prompt_id, PendingPrompt>` - each `PendingPrompt` holds
  the connection, the process, the fallback verdict, and **every packet
  parked on it**. When the prompt resolves, all of them get the same
  verdict.
- `pending_flows: HashMap<FlowKey, prompt_id>` - the deduplication index.

Verdicts arrive asynchronously on a separate channel and are applied out of
order, so a slow prompt only delays its own flow.

**Recv mode follows the outstanding count.** With no prompt outstanding the
worker blocks in `recv`, which is both the common case and the cheapest one:
no polling, no added latency. The moment a prompt is outstanding it switches
the queue socket to non-blocking and interleaves `recv` with 5ms waits on the
verdict channel. It switches back once the last prompt resolves.

**Prompt deduplication** is keyed on `(exe-or-pid, dst_ip, dst_port,
protocol)`. Source address and port are deliberately excluded, so a SYN
retransmit or a second parallel connection from the same program to the same
destination joins the existing prompt instead of raising another one. A
process the daemon could not attribute keys on its pid instead of its path.

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

1. **`sock_diag` fast path.** A netlink `INET_DIAG_REQ_V2` exact-tuple query
   returns the socket inode directly. It works unprivileged and avoids
   reading the whole `/proc/net` table. UDP gets one retry with the local and
   remote ends swapped, because `udp_diag` interprets the request that way.
2. **`/proc/net/{tcp,udp}{,6}` fallback**, silently, whenever the fast path
   misses. Three passes over the table, in order: exact local + exact remote;
   then, for UDP only, exact local with a zero remote (an unconnected socket
   doing `sendto` - mDNS, NTP, syslog, QUIC stacks); then a wildcard-bound
   local address. All comparisons run on canonical form, so `::ffff:a.b.c.d`
   rows in the v6 tables match plain IPv4 flows - which is what dual-stack
   Java, Go and node runtimes produce. Rows with inode 0 (TIME_WAIT,
   orphans) are dropped first so they cannot shadow a live socket.
3. **inode -> pid** by walking `/proc/*/fd` for a `socket:[inode]` link.

Three bounded TTL caches keep the walk off the hot path:

| Cache          | Key                          | TTL   |
|----------------|------------------------------|-------|
| inode -> pid   | socket inode                 | 2s    |
| pid -> process | (pid, process start time)    | 5s    |
| exe digest     | (dev, inode, mtime)          | 1h    |

Keying the process cache on start time makes it safe against pid reuse; a
cache hit on the inode cache is re-verified by reading the `/proc/<pid>/fd`
link back before it is trusted. The whole resolution is under a 50ms budget.

The binary's SHA-256 is read through `/proc/<pid>/exe`, so it hashes the
image actually running even if the file on disk was replaced or deleted.
Files over 64 MiB are skipped.

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
| `exe` | `/proc/<pid>/exe` | only as a fallback, when `/proc` is gone |
| `cmdline`, `cwd`, digest, package | `/proc` | unchanged |

Two `/proc` file parses disappear per uncached resolve, but the real win is the
last row of the first column: a process that exited between the packet and the
`/proc` read used to resolve to `unknown`, and now resolves to a name. That is
the common case for exactly the short-lived processes worth prompting about.

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

Every observed connection and its verdict is persisted, off the packet path:

```
worker --> broadcast feed --> feeder --> bounded mpsc (4096) --> writer
                                |                                  |
                                |                                  v
                          journald audit                   events table
                          (Deny/Reject only)         (batched: 256 rows or 1s)
```

The feeder uses `try_send` and counts what it drops. Persistence can never
block a verdict; if the queue fills, rows are lost and the loss is logged.
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
   RPCs (`UpsertRule`, `DeleteRule`, `SetPaused`, `SubmitVerdict`) require
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
- **event writer** - batches rows into SQLite and prunes on a timer.
- **storage** - sqlite behind a mutex. Reads are served from the in-memory
  `RuleSet`; writes are kept off the hot path.

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

Three kernel-side programs (`crates/cfc-ebpf`, built separately by
`cargo xtask build-ebpf`) and their userspace loader (`cfc-daemon/src/ebpf/`).
The loader is compiled in by default (the `ebpf` cargo feature, which is what
pulls `aya` in); the layer stays off at runtime until `[ebpf] enabled` is set.
Compiling it in is not the same as running it: while the config switch is off,
`start` returns before any `bpf(2)` call, so a default build is exactly as
inert as one built with `--no-default-features`.

| program | attach | what the daemon does with it |
|---|---|---|
| `tracepoint/sched/sched_process_exec` | `sched:sched_process_exec` | fills a pid -> (exe, comm, uid, gid, ppid) table |
| `tracepoint/sched/sched_process_exit` | `sched:sched_process_exit` | evicts from that table |
| `cgroup_skb/ingress` | cgroup v2 root | copies received DNS response payloads out; the daemon parses them and lifts the `A`/`AAAA` records |
| `cgroup/connect4`, `cgroup/connect6` | cgroup v2 root, link **pinned** | refuse `connect()` for pids the daemon has denied outright, before a packet exists - and, under `[ebpf] fast_allow`, mark the sockets of pids a lasting rule allows outright |
| `cgroup/sendmsg4`, `cgroup/sendmsg6` | cgroup v2 root, link pinned | the same mark decision for a UDP send that carries a destination; no refusal |

**Two decisions happen in the kernel; everything else is enrichment.** The
connect hooks refuse a denied program's `connect()` with `EPERM` - pinned, so
the refusal outlives the daemon - and, with one opt-in fast path, wave an
allowed one past the queue. Every other verdict comes from NFQUEUE,
with a single exception: under `[ebpf] fast_allow`, the sockets of a process
the daemon has already ruled allowed process-wide are marked in the connect
hook, and the snippet's `meta mark @fast_allow accept` rule takes them ahead
of the queue. That set is the one thing the daemon ever writes to nftables -
one element added when the path is armed, flushed unconditionally at every
start and at shutdown - and it ships empty, so a default install carries no
bypass value.

**Where revocation reaches.** A grant is re-decided at every hook that opens a
flow: `connect()`, and a `sendmsg` that carries a destination. Deleting the
rule, replacing it with a Block, the process exec'ing, the process exiting, and
the daemon going away for more than one deadline all take effect at the next
such hook, which is what makes the mark safe to hand out at all.

**Only a TCP socket is ever marked.** The property that decides this is not
the protocol but whether a socket passes one of our hooks *again* after it is
set up - because the mark lives on the socket and only a hook can take it back.
TCP does: it passes the connect hook for every connection it opens. A UDP
socket that has called `connect()` sends with `send()`, which carries no
destination and so passes neither hook; the mark it holds then is the mark it
keeps until it is closed, past a revocation, past the deadline, and past the
daemon's death - the one case where "a dead daemon fails closed within sixty
seconds" would not hold.

Two narrower rules were tried first and both leaked, which is why this is an
allowlist rather than a list of protocols to exclude. Refusing UDP only at
`connect()` left the sendmsg hooks free to mark a socket that was *already*
connected: `sendto` with an explicit address is legal on a connected UDP
socket, and the hook runs whenever a destination is supplied. And naming UDP at
all covers only what someone thought to name - UDP-Lite, DCCP and SCTP connect
the same way and have no sendmsg hook here either.

Refusing is never a bare early return: a socket that already carries our mark
is still stripped of it. Never set, always strip.

The cost lands where it does least harm. The ruleset queues `ct state new`; a
UDP peer that answers makes the flow conntrack-established after one exchange,
and established traffic is not queued with or without a mark. A marked UDP
socket only kept *gaining* anything while its peer stayed silent - and
unreplied UDP is conntrack-NEW on every datagram, which is exactly the shape in
which an unrevocable mark does the most damage. Benefit and hazard were the
same case. What is given up in practice is the fast path for QUIC, which was
getting its first packet through it and nothing more.

**Two guarantees can be weaker than the full ones, and neither is a refusal.**
The full guarantee is: a grant is cleared by the kernel the moment its process
exits or execs, with or without a daemon, and a dead daemon is honoured for at
most sixty seconds. Two kernel facts can weaken it, and the eligibility
decision - a pure function, `fast_path_decision`, with a test - reduces rather
than refuses in both cases:

- **The exec/exit tracepoint links could not be pinned** (no
  `BPF_LINK_TYPE_PERF_EVENT` before 5.15, a read-only bpffs, or no bpffs at
  all). Those links are what clears grants after the daemon dies; without them
  an unclean death leaves the connect hooks marking while nothing evicts, and
  the deadline is all that is left. So the deadline drops to six seconds,
  refreshed every two.
- **Process exit is detected by thread-group leader only** - the kernel's
  `sched_process_exit` record has no readable `group_dead`, which the matrix
  shows absent on 5.10 and 6.12 and present on 6.18. Then a process whose leader
  exits first and dies later is never evicted by the kernel, *while the daemon
  is alive*, so a shorter deadline alone bounds nothing. The daemon therefore
  sweeps its grants on every heartbeat, dropping any pid whose `/proc` start
  time no longer matches the one recorded when it was granted. What remains is
  a pid recycled and connecting within one two-second beat, without an exec in
  between - an exec clears the grant in the kernel regardless.

`cfc status` names which applies - `live, grants lapse within 6s (exit is
detected by thread-group leader only, ...)` - because two different weaknesses
give the same number and the word `live` alone would hide both.

Both were refusals in the first design. Refusing the first withheld the path
from a bpffs mounted read-only; refusing the second withheld it from every
kernel RHEL ships, for a risk a per-beat sweep bounds. What still refuses is
where nothing could ever mark - the basic connect variants carry no mark
decision - or nothing could ever evict - exit not tracked at all. And
`Enforcement` is no longer an input: Process mode was refused on the reasoning
that a stale grant would have "nothing but the deadline", which was backwards -
there every link and map dies with the daemon, so a stale grant cannot exist
after it.

**The sendmsg hooks are a caveat, not a requirement.** They used to re-decide a
UDP socket's mark per datagram and were load-bearing; with no UDP socket ever
marked, all they can do is strip a mark somebody *forged* onto an unconnected
UDP socket. Where the kernel's verifier refuses them - 5.10 does - the path
runs, and the report says what it runs without. On the inherited path the
previous daemon leaves a directory marker in bpffs once its cookie connect
variants attached, which is what tells its successor that the pinned programs
carry the mark decision at all; the pin names do not say.

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
