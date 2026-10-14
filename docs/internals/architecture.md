# Architecture

## Process model

Two long-running processes, plus an optional third:

1. **`colony-firewalld`** (root, systemd) - owns the NFQUEUE socket, runs the
   decision engine, persists rules and a verdict log in SQLite, serves a gRPC
   API on a Unix socket at `/run/colony-firewall/cfc.sock`.

2. **`colony-firewall`** (UI, per user session) - connects to the UDS, streams
   pending prompts, posts verdicts. Main window built with
   [iced](https://iced.rs/).

3. **`colony-firewall-tray`** (per user session, optional) - a
   StatusNotifierItem with the status, a pending-prompt badge, prompt
   notifications and pause/resume. It opens the GUI on demand.

The CLI tool `cfc` shares the same gRPC client path as the UI, and covers
the same surface: it can answer prompts (`sudo cfc prompts`), which is how a
headless machine gets a say. Run without sudo it is read-only (see
[IPC and the trust model](#ipc-and-the-trust-model)).

```
+----------------------------+     +----------------+
|  cfc-ui   (iced, user)     |     |  cfc (tty)     |
|   prompts, rules, live     |     |   status, rules|
|   stats                    |     |   prompts, log |
+------------+---------------+     +-------+--------+
             |                             |
             |  tonic gRPC over UDS, 0660 root:colony-firewall
             |  (peer process checked per change RPC)
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

## Repository layout

```
crates/
  cfc/              cfc, the command-line tool
  cfc-core/         shared types and rule matching: Rule, Verdict, Connection, Process
  cfc-proto/        gRPC schema between the daemon and its clients (tonic + tonic-prost)
  cfc-client/       UDS gRPC client shared by the app, the tray and cfc
  cfc-daemon/       colony-firewalld, the privileged daemon
  cfc-ui/           colony-firewall, the iced app
  cfc-tray/         colony-firewall-tray, the StatusNotifierItem companion
  cfc-ebpf-proto/   POD event types and pure parsers shared by the eBPF programs and the daemon
  cfc-ebpf/         kernel-side eBPF programs, a workspace of its own
  cfc-xtask/        build automation, run as `cargo xtask` (builds the eBPF object)
assets/icons/       the app icon, also embedded in the tray at compile time
packaging/
  arch/             PKGBUILD (release), PKGBUILD-git and the pacman install scriptlet
  linux/            .desktop launchers, autostart entries and the polkit policy
  systemd/          units, the sysusers fragment, both nftables tables, daemon.toml.sample
  rpm/              RPM spec
  selinux/          SELinux policy module
  tarball-manifest.json   install and remove steps of the release tarball
scripts/            CI checks, the tarball installer generator, test and bench helpers
docs/               the guides (guide/), these internals (internals/) and the roadmap (project/), indexed by docs/README.md
```

Every root workspace member inherits `version`, `edition`, `rust-version`,
`license` and `repository` from `[workspace.package]`, so the whole workspace
carries one version. Every dependency, internal crates included, is declared
once in `[workspace.dependencies]` with its full version, and members inherit
it with `workspace = true`. `crates/cfc-ebpf` is excluded from the root workspace: it
builds for `bpfel-unknown-none` with the nightly pinned in its own
`rust-toolchain.toml`, keeps its own `Cargo.lock`, and only `cargo xtask
build-ebpf` (or a build from inside that directory) compiles it. Stable builds,
clippy and the MSRV check never see it. See [The eBPF layer](#the-ebpf-layer).

`scripts/tarball-installers.sh` turns `packaging/tarball-manifest.json` into
the tarball's `install.sh` and `uninstall.sh`, and
`scripts/check-release-assets.sh` checks that every file the manifest installs
is staged into the tarball. The packaging notes are in
[packaging](packaging.md).

Releases are cut by release-please and built by
`.github/workflows/release.yml` from the tag: the workspace and the eBPF
object, the tarball, the app under the name Colony installs
(`colony-firewall-control-linux`) and the Arch recipe. The shared
sign-and-publish workflow of Project-Colony-Resources then signs every
asset and publishes the release. Details in
[packaging](packaging.md#releases).

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
  checked against current policy for every packet; a new refusal takes
  precedence, and a rule's Allow takes precedence over a timeout or no-UI
  fallback, though not over a user's own answer.
- `pending_flows: HashMap<FlowKey, prompt_id>` - the deduplication index.

Verdicts arrive asynchronously on a separate channel and are applied out of
order, so a slow prompt only delays its own flow.

**The queue socket is non-blocking for the worker's whole life**, and every
idle turn of the loop waits up to `RECV_POLL_INTERVAL` (5 ms) on the verdict
channel. This paragraph used to describe the opposite - a blocking `recv` with
"no polling, no added latency" whenever no prompt was outstanding - which was
true of an earlier design and had not been true for some time. A thread parked
in a blocking `recv` cannot be woken to see a stop flag, and that was ninety
seconds of hang on every daemon stop; `crates/cfc-daemon/src/nfqueue/mod.rs` has
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
excluded, so equivalent parallel connections may share a prompt. An image over
64 MiB has no digest; it shares by its path when that path is root-sealed, the
same identity a path-only Allow for it uses. Any other incomplete identity
never shares authorization. Persistent prompt Allows use the queued
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
only the prompt is skipped, and only for flows that no rule is about. An
explicit Deny or Reject rule keeps blocking, and a flow that a rule may be
about but cannot be decided (see below) is still prompted. Pause has a deadline: the
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
   several compatible inodes leave attribution unknown (with `--debug` the
   journal says which: "table unreadable", "attribution budget expired",
   "udp attribution ambiguous"); an absent table (`udp6` under
   `ipv6.disable=1`) counts as empty. An unknown owner is judged like any
   other incomplete identity: rules that name no program still answer, and
   where a program rule may apply the flow is prompted with the identity
   shown as unknown. The packet's socket UID,
   when present, filters candidates. All comparisons run on canonical form,
   so `::ffff:a.b.c.d`
   rows in the v6 tables match plain IPv4 flows - which is what dual-stack
   Java, Go and node runtimes produce. Rows with inode 0 (TIME_WAIT,
   orphans) are dropped first so they cannot shadow a live socket.
3. **inode -> pid** via the diagnostic cookie when available, otherwise by
   walking `/proc/*/fd` for a `socket:[inode]` link. A shared or passed socket
   descriptor still does not identify which holder sent a packet.

Two bounded caches avoid repeated socket walks and image hashing:

| Cache          | Key                                         | Lifetime |
|----------------|---------------------------------------------|----------|
| inode -> pid   | socket inode                                | 2s       |
| exe digest     | dev, inode, length, mtime and ctime with nanoseconds | key change or eviction |

A complete process record is read on every resolution: exec changes policy
identity without changing pid or start time. A cache hit on the inode cache
is re-verified by reading the `/proc/<pid>/fd` link back before it is trusted.
The socket lookup has a 50ms budget.

The binary's SHA-256 is read through `/proc/<pid>/exe`, so it hashes the
image actually running even if the file on disk was replaced or deleted.
The same opened file supplies metadata and bytes. Content changes during
hashing are rejected; the mapped link, metadata and process start time must
still agree before publishing executable identity. The link is rendered in
the process's own mount namespace, so a path that names a different file in
the daemon's view leaves the executable unknown. A deleted image's
`" (deleted)"` suffix is dropped only for a process in the daemon's user
namespace whose image sits on a mount of its own mount namespace; elsewhere
the former path cannot be checked. A digest is cached only
when the image's ctime was at least 2 seconds old as hashing began. Userspace
cannot set ctime and any write moves it, so a changed image misses the cache;
an unchanged one is never rehashed per packet on the single worker. The
exception is a store through a shared writable mapping, which moves ctime only
when the page is first dirtied; it needs write access to the file. Files over
64 MiB retain their path but have no digest. This remains a read-time snapshot: an exec after the final check can
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

`RuleSet` is kept sorted so that lookup is a linear scan, and the order does
not depend on what SQLite happened to return:

1. specificity descending (how many scope predicates are set; a `/0`
   network is not counted, since it narrows nothing within its address
   family)
2. Deny, then Reject, then Allow
3. oldest `created_at` first
4. `id`, as a total-order tiebreak

One override is applied during the scan rather than in the sort: a Deny or
Reject rule that names a program (`exe_path` or `exe_sha256`) wins over
every Allow rule that names none, whatever their predicate counts. Rules that
name a program keep their specificity order among themselves, so
`allow --exe X --dst-port 443` still beats `deny --exe X`. Everything else
keeps the order above. The scan holds the first matching generic Allow
instead of returning it, and only a lower program rule can still change the
answer: a program Deny or Reject replaces it, and a program Allow answers in
its place with the same action (it is credited with the hit, since it is what
keeps a lower program Deny from winning). The
relation is not a total order (program Allow 3 > program Deny 2 > generic
Allow 5 > generic Deny 4 > program Allow 3), so no sort key could express
it. The in-kernel precompute (`Engine::process_wide_action`) walks the same
way, and every kernel writer (exec, both resync sweeps, the exe table) asks
`Engine::denies_process_wide`, so the connect hooks refuse a process only when
the packet path would refuse every flow of it. When the walk abstains (a rule
the hash-blind kernel side cannot decide), the kernel entry is cleared and
the packet path decides, prompting if the identity stays incomplete.

**Incomplete identity is asked, not refused.** When the process's
executable, uid or digest is unknown (an unattributed socket, a binary over
the hashing cap, a process gone before `/proc` was read), a rule that tests
the missing field can be neither matched nor excluded. The scan walks past
such a rule and remembers whether it was an Allow or a refusal. If the rule
that then answers agrees with every rule passed that way (all allow, or all
refuse), it answers. Otherwise the flow is prompted, the prompt names the
first rule that could not be decided (`PromptEvent.undecided_rule_id`), and
the UIs show the identity as unknown. The user's answer applies to that
connection; an "always" answer for an unknown program is refused as before.
With no answering UI connected the flow takes `no_ui_action`, and the prompt
caps send overflow to the same fallback. Neither pause nor the loopback
allowance lifts such a flow. The recorded event and the live feed carry the
undecided rule's id in `rule_id` with a source other than `rule`. A legacy
hostname rule (`dst_host`) that cannot be decided is still refused, since no
answer can establish the name.

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
2. **Who the peer process is.** Read-only RPCs (`ListRules`, `GetStatus`,
   `ListEvents`, `StreamConnections`, `StreamPrompts`) are open to any peer
   that got past layer 1. Change RPCs (`SubmitVerdict`, `UpsertRule`,
   `DeleteRule`, `ApplyRules`, `SetPaused`) are accepted from root (or the
   daemon's own uid) and from the installed app and tray only. From
   `SO_PEERCRED`'s pid, `official.rs` checks, between two start-time reads,
   that the process runs in the host namespaces, is not traced, runs under
   no seccomp filter (one can fake the prologue's `close_range`), has sealed
   itself (`cfc_client::seal_official_process`: inherited descriptors closed,
   non-dumpable), runs one of the root-sealed `[ipc] official_clients`
   binaries by device and inode, holds this connection's client end itself
   (`UNIX_DIAG` names it) and mapped no executable file from outside sealed
   directories. The check runs on the blocking pool.
3. **polkit.** `SetPaused` (pause and resume), `ApplyRules`, and an
   `UpsertRule` (or a customized prompt answer) storing an enabled Allow that
   names no program, from the app or tray, also need `CheckAuthorization`
   for `org.projectcolony.firewall.pause`,
   `org.projectcolony.firewall.import-rules` or
   `org.projectcolony.firewall.allow-every-program`
   (`polkit.rs`, one system-bus connection per call, 120 s timeout, the
   dialog cancelled on expiry). Root is never asked.

Every other peer is read-only. Its prompt subscription is not counted in the
router's census, so `no_ui_action` still applies when only such peers
listen, and it never enters a prompt's audience. An answering subscription
is checked again before each prompt it is handed; one that fails (an app or
tray whose binary an upgrade replaced) ends with the reason, which drops it
from the census. Prompt ownership comes on
top: the daemon records which answering subscriber uids actually received
each prompt and refuses a verdict from anyone else, so one desktop session
cannot answer another's. Root is exempt.

Values arriving over the wire are decoded strictly. An unspecified or
out-of-range action or duration is an `InvalidArgument` error, not a silent
fall-through to the zero value - which happened to be Allow.

Every change RPC (allowed or refused, with the official image and the polkit
action) and every Deny/Reject verdict is logged to the journal with the
calling uid and pid. See [hardening](../guide/hardening.md).

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
that always fires. The worker stamps the time on every turn of its loop, and
no turn blocks for more than a few milliseconds (the idle wait is
`RECV_POLL_INTERVAL`), so an idle machine keeps the stamp fresh and is never
mistaken for a stall. The main task heartbeats `WATCHDOG=1` every 10s and
withholds it once the stamp is 60s old, which bounds detection of a wedged
daemon at about 90 seconds.

Signals:

- **SIGTERM / SIGINT** - graceful shutdown: `STOPPING=1`, final hit-count
  flush, control socket removed.
- **SIGHUP** - reloads `profile`, `[default_policy]` and `[provenance]`
  in place, without dropping a packet. The policy lives behind a shared
  `RwLock` that the engine and the prompt router read per decision, so the
  next prompt uses the new timeout. A config file that fails to parse is rejected and the
  running policy is kept. Everything else - the queue number and tuning, the
  database path, the socket path, the event cap, the pause default, the IPC
  settings, the eBPF layer - is bound at startup and needs a restart.

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
startup flushes the legacy nft set once and, when the eBPF layer loads,
disarms the pinned maps (unarmed mark, zero deadline, no grants) and removes
the old `sendmsg4`/`sendmsg6` link pins, which detaches those hooks. With the
layer off, without the object or after a failed load, the old pins stay until
reboot; they can strip a socket mark equal to the old random value, but the
snippet accepts no packet on an application-set mark, so they open nothing. The nft snippet has no mark-set accept rule, and
package upgrades reload active nft units with one atomic transaction. A failed
flush emits an error and requires operator action before filtering can be
relied upon.

**Compatibility exit handling.** When `sched_process_exit` exposes `group_dead`,
the kernel evicts only on confirmed process death. Without that field, it
preserves identity and deny entries on thread or leader exit and reports the
leader's exit as a candidate. The daemon evicts a candidate once
`/proc/<pid>/task` is absent or lists only a zombie leader. The event usually
arrives before that, while the leader is still exiting or its workers still
run, so such a candidate is checked again every two seconds until its group is
gone, or dropped once its pid belongs to another process. At most 1024
candidates wait; past that the oldest leaves its entries to exec or the next
reconciliation.

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

### The kernel-side crate

`crates/cfc-ebpf` compiles to a single BPF ELF object holding the programs in
the table above and the maps listed under [Maps](#maps). Nothing in it loads or
attaches anything - that is the daemon's job (see
[Loading](#loading-attaching-and-capabilities)).

Its userspace counterpart is [`cfc-ebpf-proto`](#shared-types-cfc-ebpf-proto),
which owns the shared `#[repr(C)]` event structs **and** all the DNS/IP parsing
arithmetic. That split is deliberate: verifier-constrained code is close to
untestable in place, so every branch that can be expressed as pure `no_std`
arithmetic lives in `cfc-ebpf-proto` and is unit-tested on the host against
hand-built packets.

### Shared types: `cfc-ebpf-proto`

`crates/cfc-ebpf-proto` holds the types and parsers shared between the
kernel-side programs and the userspace daemon.

It is dependency-free and compiles both as `#![no_std]` (for
`bpfel-unknown-none`) and with `std` (default, for the host). Same source, same
struct layouts, same parsing code on both sides - which is the point.

#### What lives here

**The wire format.** `ExecEvent`, `ExitEvent`, `DnsPacket`, `DnsAnswer` and
`ConnectReport` are the exact byte layout of the BPF ring buffers and hash-map
values. All of them are `#[repr(C)]` POD with **explicit** padding fields, so
`size_of` is stable and the kernel never copies uninitialised padding into a
ring buffer. The sizes are frozen by tests:

| type | size |
|---|---|
| `ExecEvent` | 292 |
| `DnsPacket` | 514 |
| `DnsAnswer` | 276 |
| `ConnectReport` | 24 |
| `ExitEvent` | 4 |

**The parsers.** `dns` and `net` hold the arithmetic half of the
`cgroup_skb/ingress` program: DNS header/question/answer walking with
compression-pointer support, and IPv4/IPv6 → UDP payload offset math.

They are written to the eBPF verifier's rules - no panics (`slice::get`, never
`&buf[a..b]`), no unbounded loops, no dynamic slicing, no allocation, tiny stack
frames - but they are *ordinary Rust functions*, so the host test suite drives
them directly with hand-built packets. That is the whole reason the module is
here rather than in the kernel-side crate: a BPF object cannot be unit-tested, but this
can, and it is where all the interesting off-by-one risk lives.

Covered by the tests: plain `A` and `AAAA` records, compressed owner names,
`CNAME`-then-`A` chains, every truncation prefix of a valid packet, lying
`rdlength`, wrong `rdlength` for the record type, non-`IN` classes, forward and
self-referential compression pointers, over-long names, over-long jump chains, a
9-answer response proving the 8-answer cap, parsing at a non-zero base offset
(as the BPF scratch buffer does), and a small random-garbage fuzz loop. Plus
IPv4 options, IPv4 fragments, IPv6 extension headers, and payload-length
clamping on the `net` side.

#### Features

* `std` *(default)* - adds `comm_str()`, `filename_str()`, `name_str()`
  (lossy, never panic on invalid UTF-8 or an unterminated buffer), `ip_addr()`,
  `set_ip()` and readable `Debug` impls.

The kernel-side crate depends on this one with `default-features = false`.

`aya::Pod` is deliberately not implemented here: see
[Consuming the types](#consuming-the-types).

### The exec tracepoint: `cfc_sched_process_exec`

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

`filename` is *not* the string. It is a 4-byte word encoding
`(length << 16) | offset`, where `offset` is relative to the start of the
tracepoint record and points into the record's variable-length tail. So:

```rust
let field_off = EXEC_FILENAME_DATA_LOC.load();          // patched at load time
if field_off == 0 || field_off > 64 { return; }         // sentinel, and bound
let data_loc: u32 = ctx.read_at::<u32>(field_off)?;     // bpf_probe_read_kernel
let offset =  (data_loc & 0xffff) as usize;
let len    = ((data_loc >> 16)  ) as usize;
let src    =  ctx.as_ptr().cast::<u8>().add(offset);
bpf_probe_read_kernel_str_bytes(src, &mut event.filename)
```

`bpf_probe_read_kernel_str_bytes` returns the bytes *excluding* the trailing
NUL, which is exactly the `filename_len` userspace wants. Paths longer than 256
bytes are truncated.

**Where the field is, is not assumed.** `EXEC_FILENAME_DATA_LOC` is a
`.rodata` global, patched by the loader from the format file above
(`cfc-daemon/src/ebpf/tracefs.rs`), exactly as the `task_struct` offsets are
patched from BTF. It has been 8 on every kernel this has run on and the
`common_*` header is about as stable as the tracepoint ABI gets - but the
failure mode of guessing wrong is silent and ugly. Read four bytes of whatever
field actually sits at offset 8, decode them as `(len << 16) | offset`, and the
program copies a plausible-looking path out of the middle of the record.
Nothing downstream can distinguish that from a real filename, so it would
surface as a firewall confidently attributing connections to a program that
does not exist.

Three outcomes, all handled in the loader:

| format file says | loader does | kernel side does |
|---|---|---|
| `__data_loc`, `size:4` | patches the offset in, unconditionally | reads it |
| `__rel_loc`, or another width | patches **0** in | reads nothing |
| unreadable | leaves the built-in 8 | reads offset 8 |

The middle row is the one that matters. Detecting an unreadable layout in
userspace and leaving the kernel program to read offset 8 anyway would be
byte-for-byte the silent failure this exists to prevent, so the refusal has to
reach the kernel. `0` is that signal.

The `> 64` bound is not belt-and-braces either. As a `const` the offset was a
compile-time literal and the verifier knew the exact address; read from a
global it is a runtime value with umax 2^32-1, about to be used in pointer
arithmetic on the context, and the verifier refuses the program without a
bound. A mask would not do - the point is to *reject* an implausible offset,
not fold it into range.

Measured cost of making it patchable: **+9 verified instructions** (248 → 257).

#### Why not `tp_btf`

A BTF-powered raw tracepoint would skip the format file entirely, reading
`bprm->filename` from the kernel's own type information. It was rejected
because it makes BTF **mandatory** for the exec *and* exit programs, where
today BTF is optional and its absence costs only `ppid`. A kernel built without
`CONFIG_DEBUG_INFO_BTF` would go from "process tracking, minus parent pids" to
"no process tracking" - a strange trade for a change whose purpose is to widen
the set of machines that work. Its residual assumption, that `bprm` is
raw-tracepoint argument 2, is also an undocumented internal detail whose
failure mode is the same silent wrong answer.

Reading the format file adds no dependency: aya already reads
`<tracefs>/events/sched/sched_process_exec/id` to attach at all, a sibling of
`format` in the same directory. No readable `format`, no attached program for
the offset to matter to.

### The exit tracepoint: `cfc_sched_process_exit`

Evicts process identity and deny state only when the tracepoint's `group_dead`
field confirms that the final thread has exited. The loader discovers that
field's offset from the live tracefs format.

On kernels without a readable `group_dead`, thread and leader exits preserve
identity and denials. Leader events are candidates for userspace cleanup only
after `/proc/<pid>/task` disappears. A leader can exit while workers remain, so
leader exit cannot justify eviction. This conservative fallback can retain stale
denials until exec or reconciliation; immediate final-thread cleanup is not
guaranteed on those kernels.

### The DNS observer: `cfc_dns_ingress`

Matches inbound UDP datagrams with **source port 53** and copies the DNS
payload into the `DNS_PACKETS` ring buffer as a `DnsPacket`. It always returns
`1` (pass) - it is an observer and never drops traffic.

It does **not parse DNS**. That is the whole design, and it is not a
simplification for its own sake: in-kernel DNS parsing does not fit in the
verifier's complexity budget. See
[Why the DNS parsing is in userspace](#why-the-dns-parsing-is-in-userspace).

What the kernel half does, in order:

1. `skb->len >= 40` (the shortest possible IPv4 + UDP + DNS header);
2. copy up to 80 bytes - the worst-case header stack - into `PKT_SCRATCH`;
3. `cfc_ebpf_proto::net::udp_payload_from_l3` to confirm IPv4/IPv6 + UDP,
   unfragmented, and to locate the payload;
4. source port == 53;
5. payload length >= 12 and the **QR bit** set (`payload[2] & 0x80`) - one byte
   of sanity so a stray port-53 datagram does not cost a 514-byte record;
6. reserve a `DnsPacket`, copy the payload straight from the skb into it, write
   the length, submit.

Everything past that - opcode, rcode, section counts, questions, answers,
names, compression pointers - is the daemon's job.

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
tasks inside the attached cgroup - attaching to `/sys/fs/cgroup` (the v2 root)
covers everything.

#### What the DNS parser supports

The parser is `cfc_ebpf_proto::dns`, running in the **daemon**, over
`DnsPacket::payload()`. It still obeys the panic-free, constant-loop-bound,
no-dynamic-slicing style it was written in - that style is worth keeping for a
parser fed attacker-influenced bytes, and it keeps the option of moving pieces
back into the kernel open - but it no longer answers to the verifier, so the
caps are set for correctness rather than for a budget.

* `A` (type 1) and `AAAA` (type 28) records, class `IN`, in the **answer**
  section of a response (`QR=1`) with `RCODE == NOERROR`.
* Name compression pointers (RFC 1035 §4.1.4), which real resolvers use for
  essentially every answer's owner name. At most **4** pointer jumps per name,
  and only **backwards** pointers (`target < current_offset`) - that constraint
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


### Maps

| name | type | shape | purpose |
|---|---|---|---|
| `PROCS` | `HASH` | `u32 → ExecEvent` (10240) | live processes by tgid |
| `VERDICTS` | `HASH` | `u32 → u32` (10240) | process-wide verdicts by tgid, read by the connect hooks |
| `EXE_RULES` | `HASH` | `u64 → u32` (4096) | process-wide rules by executable path hash, so a process started while no daemon runs still gets an answer |
| `EXE_RULES_ON` | `ARRAY` | 1 × `u32` | whether `EXE_RULES` holds anything, so an empty table costs no hashing on every execve |
| `SOCK_PIDS` | `LRU_HASH` | `u64 → u32` (16384) | socket cookie → tgid, written at `connect()`, read by attribution |
| `ENFORCE_STATS` | `PERCPU_ARRAY` | counters | connect-path counters (`cfc_ebpf_proto::enforce_stat`) |
| `DENY_EVENTS` | `RINGBUF` | 64 KiB | `connect()` calls refused in-kernel (24-byte `ConnectReport`) |
| `EXEC_EVENTS` | `RINGBUF` | 256 KiB | exec stream |
| `EXIT_EVENTS` | `RINGBUF` | 64 KiB | exit stream |
| `DNS_PACKETS` | `RINGBUF` | 256 KiB | DNS response payloads (514-byte records) |
| `EXEC_SCRATCH` | `PERCPU_ARRAY` | 1 × `ExecEvent` | see below |
| `PKT_SCRATCH` | `PERCPU_ARRAY` | 1 × `[u8; 80]` | copied header prefix |
| `FAST_ALLOW`, `FAST_ALLOW_UNTIL`, `FAST_ALLOW_MARK`, `ALLOW_EVENTS` | | | legacy Fast Allow state, kept until an ABI bump and disarmed at startup (see above) |

The scratch maps exist because **a BPF program gets 512 bytes of stack in
total**, and `ExecEvent` alone is 292 bytes. Per-CPU array slots are the
standard workaround and cost nothing at runtime - BPF programs are
non-preemptible, so a slot cannot be clobbered mid-program.

`PKT_SCRATCH` is 80 bytes rather than 512 because only *headers* are read out
of it now: 60 bytes of worst-case IPv4 header, 8 of UDP, and the first 12 of the
DNS message. The payload never passes through it - `bpf_skb_load_bytes` writes
it directly into the reserved ring-buffer record, so it is copied exactly once
and never touches the stack.

Measured size and stack usage of the built object:

```text
cgroup_skb/ingress                     355 insns, 56 bytes of stack
tracepoint/sched/sched_process_exec    158 insns, 48 bytes of stack
tracepoint/sched/sched_process_exit     25 insns,  4 bytes of stack
```


### Verifier constraints that shaped the code

These are not stylistic preferences; each one is a thing that failed, or would
have failed, and forced a rewrite.

**No panics anywhere.** Every read goes through `Option`-returning accessors
(`slice::get`, never `&buf[a..b]`). A reachable `panic!` in a BPF object either
fails to link (no `core::fmt`) or traps at runtime. The `#[panic_handler]` is a
bare `loop {}` rather than `unreachable_unchecked()` on purpose: if a panic path
ever *did* survive optimisation, `loop {}` makes the verifier reject the program
at load time - which the daemon handles as "degrade gracefully" - whereas
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
   becomes a libcall - even a 16-byte `[0u8; 16]`. Fixed by
   `-C link-arg=--disable-expand-memcpy-in-order` in
   [`.cargo/config.toml`](../../crates/cfc-ebpf/.cargo/config.toml).
2. Even with inline expansion restored, a 292-byte `*event = ExecEvent::zeroed()`
   is far past what the backend will expand to stores. So the programs never
   zero a whole event struct. Instead every scalar field is assigned
   unconditionally, and the two large byte arrays (`ExecEvent::filename`,
   `DnsAnswer::name`) are written as "prefix + one NUL terminator". The stale
   tail is unreachable from userspace: `filename_len`/`name_len` bound it and
   `cfc_ebpf_proto::nul_terminated` stops at the NUL as well. The per-CPU slots
   start out zeroed by the kernel, so this is never *uninitialised* memory.

   The same rule killed the obvious `for i in written..MAX { out[i] = 0 }` tail
   clear inside `read_name` - LLVM's loop-idiom pass rewrites it straight back
   into a 253-byte `memset`.

**`bpf_skb_load_bytes` needs a constant length**, and fails outright if that
length runs past the end of the skb. There is no "copy up to N bytes". Hence the
descending ladders: constant-size attempts, first fit wins.

There are two of them, because they have different jobs:

* `load_prefix` fills `PKT_SCRATCH` for header classification. Rungs at 80, 72,
  64, 56, 48 and 40 (`MIN_DNS_PACKET` = 20 + 8 + 12) - 8 bytes apart, because
  the shortest thing it has to reach is `udp.offset + 3` on a 60-byte IPv6
  response.
* `copy_payload` fills the ring-buffer record, and has to cover 12..=512 bytes.
  One ladder fine enough for that would be sixty-odd rungs, so it is three
  passes: **coarse** in 64-byte steps (0..=448), **fine** in 8-byte steps over
  what is left, and a **tail** - one fixed 8-byte read positioned to *end*
  exactly at the end of the payload, filling in the last `len % 8` bytes. The
  tail overlaps what the fine pass already wrote; copying the same bytes twice
  is free, and it is what makes the result exact.

That exactness is load-bearing, and was found the hard way. A first version
rounded the length down to a multiple of 8 - losing at most 7 bytes, which
sounded harmless. It is not: those 7 bytes are the *end of the last answer
record*, `parse_answer_at` refuses a record it cannot read in full, and the
common case is a response carrying exactly one answer. The rounded version
captured packets perfectly and produced zero answers.

Note also that `copy_payload` is driven by `UdpPayload::declared_len` (the
length in the UDP header) and **not** by `UdpPayload::len`. The latter is
clamped to however much of the packet was copied into `PKT_SCRATCH`, which is
only ever headers - using it would have capped every capture at ~50 bytes.

**No unchecked pointer arithmetic on packet data.** Every packet byte the
program *reads* comes through the copied `PKT_SCRATCH` buffer, and every byte it
*forwards* is written by the kernel's own helper into a reserved ring-buffer
record. The programs never touch `skb->data`/`skb->data_end` directly. Kernel
memory (the `task_struct` walk) goes exclusively through
`bpf_probe_read_kernel`, which faults gracefully instead of oopsing.

#### Why the DNS parsing is in userspace

The verifier gives a program **1,000,000 instructions** of state exploration.
Not instructions executed - instructions *walked*, across every path it has to
prove safe. In-kernel DNS name parsing does not fit, and the gap is not close.

The kernel-side parser was written to every rule above: constant loop bounds,
`slice::get` everywhere, no allocation, scratch in a per-CPU map. Three verifier
rejections were diagnosed and fixed in sequence - a zero-sized
`bpf_skb_load_bytes` read (the aya wrapper's `min`, see above), an unprovable
store into the name buffer (fixed with an index mask, because LLVM deletes a
redundant *check* but cannot delete a mask that changes the value), and then
lowered caps. It still died on:

```text
processed 1000001 insns (limit 1000000)
```

at roughly **24,000 states**, on kernel 7.1.8. Lowering the caps further did not
move it - not `MAX_ANSWERS` 8 → 4, not `MAX_LABELS` 32 → 24, not `DNS_BUF_LEN`
512 → 256. That is the tell. The cost is not any single bound but the *product*
of the nested `answer × label × byte` loops, which the verifier must explore
exhaustively; shaving a factor off one term leaves the shape intact.

So the parsing moved out. The kernel now does only what the kernel is uniquely
able to do - see the packet, cheaply, in flight - and the daemon does the part
that needs loops, where there is no verifier and where the parser
(`cfc_ebpf_proto::dns`, 63 host tests) already lived.

The result, measured on the same kernel:

| program | verified insns | budget used |
|---|---|---|
| `cfc_dns_ingress` | **17,058** | 1.7% |
| `cfc_sched_process_exec` | 257 | 0.03% |
| `cfc_sched_process_exit` | 25 | 0.003% |

From over budget to 1.7% of it. The loader records these counts on every load
(`Report::verified_insns`, logged at `debug`), so a change that makes a program
dramatically more expensive is visible before it becomes "the program stopped
loading on someone else's kernel". The root test asserts they are recorded and
prints them.

Re-measured on kernel 7.1.8 after `EXEC_FILENAME_DATA_LOC` became a patchable
global: exec went 248 → 257, the cost of the sentinel check and the bound.

The costs of the split, stated plainly: one extra copy of the payload (into the
ring buffer), 514-byte records instead of 276-byte ones, and DNS answers now
arrive after a ring-buffer hop instead of being extracted in place. None of it
is on the packet path - NFQUEUE only ever *reads* the resulting `DnsCache`.

#### `ppid` and the absence of CO-RE

Rust/aya has **no CO-RE field relocation**: LLVM only emits the relocation
records for C's `__builtin_preserve_access_index`. Hard-coding
`offsetof(task_struct, real_parent)` would silently break on every kernel that
reorders the struct.

So the program does not guess. Two `.rodata` globals -
`TASK_REAL_PARENT_OFFSET` and `TASK_TGID_OFFSET` - default to `0`, meaning
"unresolved", and the program leaves `ppid = 0` in that case. The **loader** is
expected to read both offsets out of `/sys/kernel/btf/vmlinux` (aya can parse
BTF) and override them via `EbpfLoader::set_global` before load. That is real
CO-RE, done at load time by the side that can actually do it.

`ppid == 0` is a defined, non-fatal state: userspace treats it as "unknown" and
may fall back to `/proc/<pid>/stat`.


### Building the object

Requirements:

* `bpf-linker` (`cargo install bpf-linker`) - **0.11.0** here;
* the dated nightly pinned in [`rust-toolchain.toml`](../../crates/cfc-ebpf/rust-toolchain.toml) with
  the `rust-src` component.

```sh
# from the repository root
cargo xtask build-ebpf                       # release (default)
cargo xtask build-ebpf --debug
cargo xtask ebpf-path                         # print the object path

# or, equivalently, from crates/cfc-ebpf
cargo build --release
```

The plain `cargo build` form works because `crates/cfc-ebpf` carries its own
`rust-toolchain.toml` and `.cargo/config.toml` (target + `-Z build-std=core`).
The fully explicit form is:

```sh
cd crates/cfc-ebpf
cargo +nightly-2026-07-01 build --release \
    --target bpfel-unknown-none -Z build-std=core
```

Output:

```text
crates/cfc-ebpf/target/bpfel-unknown-none/release/cfc-ebpf.o (~158 KiB)
```

#### The nightly pin is load bearing

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

#### Isolation from the stable workspace

The kernel-side crate is **not** a member of the root workspace: it is listed under
`exclude` *and* declares its own `[workspace]` table, so it gets its own
`Cargo.lock`. Consequences, all intentional:

* `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets` and the MSRV 1.89 check never see
  the crate and are completely unaffected by it;
* `aya-ebpf` never enters the root lockfile, so it never widens the `cargo deny`
  surface of the shipped userspace binaries;
* the nightly pin and the BPF target settings live in `crates/cfc-ebpf`
  (`rust-toolchain.toml`, `.cargo/config.toml`). rustup and cargo resolve both
  by walking **up from the current working directory**, so a build started at
  the repository root can never pick them up. The root `.cargo/config.toml`
  contains only an `[alias]`, nothing that could affect a stable build.


### Loading, attaching, and capabilities

Loading needs privileges. What each attach asks for:

| program | attach | required capabilities |
|---|---|---|
| `tracepoint/sched/sched_process_exec` | `TracePoint::attach("sched", "sched_process_exec")` | `CAP_BPF` + `CAP_PERFMON` |
| `tracepoint/sched/sched_process_exit` | `TracePoint::attach("sched", "sched_process_exit")` | `CAP_BPF` + `CAP_PERFMON` |
| `cgroup_skb/ingress` | `CgroupSkb::attach(cgroup_fd, Ingress, …)`, cgroup v2 root at `/sys/fs/cgroup` | `CAP_BPF` + `CAP_NET_ADMIN` |
| `cgroup/connect4`, `cgroup/connect6` | `CgroupSockAddr::attach` to the cgroup v2 root, link pinned under `/sys/fs/bpf/colony-firewall` | `CAP_BPF` + `CAP_NET_ADMIN` |

All programs declare `license = "GPL"` (the object has a `license` section)
because every helper they use - `bpf_probe_read_kernel`, `bpf_ringbuf_*`,
`bpf_get_current_task`, `bpf_skb_load_bytes` - is GPL-only. The project is
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
Colony Firewall Control must keep working with it switched off. Each program
attaches independently, so losing a cgroup attach (e.g. no `CAP_NET_ADMIN`)
still leaves exec/exit tracking running.

#### Consuming the types

`cfc-ebpf-proto` deliberately does **not** depend on `aya`, so that the marker
trait does not drag aya into the stable workspace's dependency graph.

An earlier version of this section told the loader to write
`unsafe impl aya::Pod for cfc_ebpf_proto::ExecEvent {}`. **That does not
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

#### What the loader actually does

Implemented in `crates/cfc-daemon/src/ebpf/`, behind the daemon's `ebpf` cargo
feature (**on** by default) and `[ebpf] enabled` in `daemon.toml` (default
`"auto"`: loads wherever the kernel supports it, `false` turns it off).

1. reads the object from `[ebpf] object_path`, default
   `/usr/lib/colony-firewall/cfc-ebpf.o`. It is **not** embedded with
   `include_bytes_aligned!`: that would make a stable `cargo build --features
   ebpf` depend on the kernel-side crate's nightly + bpf-linker toolchain,
   which is exactly what excluding that crate from the workspace was for.
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

#### Verified on a live kernel

Loaded and attached under root on kernel 7.1.8 (x86_64). **The exec, exit and
DNS programs load, verify and attach**, and `dns_capture = true`.

* the BTF patch works end to end - a captured exec event reads
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
  cache produces no packet and therefore no observation - which is why the live
  half of the test prints and asserts nothing.

##### Reproducing it

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
receiving socket rather than at a device - so the assertion needs no resolver,
no uplink, and no luck.

## Why GPL-3.0?

We are porting opensnitch, which is GPL-3.0. Derivative works inherit the
license. If we later add modules that are clean-room reimplementations
(eBPF programs from scratch, novel UI flows), those can be dual-licensed,
but the workspace stays GPL.
