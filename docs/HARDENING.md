# Hardening guide

This page is for users who already have Colony Firewall Control running
and want to move from "ask me about everything" toward an actual security
posture. It is opinionated and reflects what works in practice on a Linux
desktop, not what's theoretically pure.

## TL;DR

1. Start in `profile = "balanced"`, leave the UI running.
2. Click through prompts for a week. Save persistent rules as you go.
3. Run `cfc rules bootstrap-defaults` to install common system rules.
4. Once the prompt rate drops to maybe 1-2 a day, switch to
   `profile = "strict"` if you prefer a shorter prompt timeout.
5. Audit `cfc rules list` monthly. Remove rules for apps you no longer
   use, and check `cfc log --since 30d` for destinations you did not
   expect.

On a headless machine, substitute `cfc prompts` for "leave the UI
running" throughout - it subscribes the same way the GUI does.

## Choosing a profile

| Profile  | No UI    | Timeout  | Window | Use when                                      |
|----------|----------|----------|--------|------------------------------------------------|
| relaxed  | Deny     | Deny     | 60s    | Longer time to answer prompts                  |
| balanced | Deny     | Deny     | 30s    | Daily-driver workstations (default)            |
| strict   | Deny     | Deny     | 15s    | Shorter time to answer prompts                 |

**No profile ever permits a remote connection by itself.** Not on timeout, not
when nothing is subscribed. The presets differ only in how long a prompt
waits for an answer. Under these presets, a stored rule or a prompt answer
permits remote traffic. Unmatched local IPC is allowed without prompting.

A timeout means the question *was* put to you and went unanswered; if
that granted access, the cheapest attack would be to connect while
nobody is at the keyboard.

`no_ui_action` is the other half of the same principle, and it used to
break it. Relaxed and balanced answered *allow* when nothing was
subscribed, reasoning that a desktop booting before its session starts
should keep working. That reasoning does not survive contact with a
machine where a session never starts at all: on a headless server, a VM,
anything administered over SSH, `colony-firewall` and the tray never run,
so "nobody is subscribed" is not a window during boot — it is the
permanent condition. Those hosts had no outbound firewall whatsoever.

`no_ui_action` and `timeout_action` remain genuinely different questions.
"Nobody is subscribed" is a property of the machine's state; "you were
asked and did not answer" is a decision you made by not making one. Both
now answer *deny*, for different reasons.

You can still set either to `"Allow"` explicitly under `[default_policy]`
— see below. The change is that nothing does it on your behalf.

The danger with `strict` is bootstrap: the units are ordered
before the daemon and `network-pre.target`. Enabled enforcement is required
by NetworkManager and systemd-networkd, so an nft load failure blocks their
startup. Initial daemon failure leaves the table loaded and drops new flows.
This does not cover initramfs networking, already configured interfaces, or
other network managers. Once loaded, strict filtering denies unmatched remote
flows, so DHCP, DNS and NTP need standing rules or
the machine cannot even get a lease. Network managers retrying DNS will
look like total network failure. **Only flip to strict after you have
rules for every always-on system service**.

`bootstrap-defaults` is intended to bridge exactly that gap: it seeds
the DHCP clients (dhcpcd / NetworkManager / systemd-networkd), the
resolved stub, NTP, package managers and ssh.

## What to allow first

System services that *must* always work:

- `/usr/lib/systemd/systemd-resolved` to port 53 (DNS stub)
- `/usr/lib/systemd/systemd-timesyncd` or `/usr/bin/chronyd` to port 123 (NTP)
- `/usr/lib/systemd/systemd-networkd` (DHCP if you use it - UDP 67/68)
- Your VPN client if any (WireGuard usually doesn't traverse NFQUEUE,
  but split-DNS resolvers might)

User-side conveniences that hit the network constantly:

- Package manager: `/usr/bin/pacman`, `/usr/bin/paru`, `/usr/bin/makepkg` -> :443
- Web browser: `/usr/lib/firefox/firefox`, `/opt/google/chrome/chrome` -> :443, :80
- IDE / editor: depends, but many phone home for telemetry - decide per app

You can install the system service rules with one command:

```sh
cfc rules bootstrap-defaults
```

This is idempotent: it skips rules already present by name.

## What to *deny* first

Start with executable rules for unwanted telemetry or resolver clients, and
numeric `dst_net` scopes for endpoints whose addresses you manage. An IP scope
matches addresses, not a website: shared hosting and address changes require
an explicit policy review.

### DNS names are diagnostic only

New rules and imports cannot use `dst_host`. Neither observed DNS answers nor
forward-confirmed PTR records establish the hostname an application intended
to contact, or enumerate all names associated with an address.

Legacy hostname rules keep their scope and priority. When their other known
predicates are compatible, their uncertainty refuses the flow before a lower
Allow, pause or prompt can admit it. Replace these rules explicitly with
executable or numeric scopes; a legacy hostname Allow no longer grants access.
The editor requires the old hostname to be removed before saving a replacement.

CLI and GUI destination presets use the observed numeric endpoint, as `/32`
for IPv4 or `/128` for IPv6, and label it as an IP. They do not turn a domain
into a permanent IP rule. DNS enrichment starts only after an Allow; explicit
Deny/Reject decisions start no lookup. Eight permits bound resolver jobs.

#### Observed answers, with `[ebpf] enabled`

The ingress hook copies DNS-shaped UDP responses received from source port 53.
It does not validate a resolver transaction, sender or question. These records
remain untrusted diagnostics in a separate cache. They cannot satisfy a
policy rule. Observations and forward-confirmed PTR diagnostics use separate caches. Diagnostic entries
retain the record TTL, clamped to 60s..1h; the policy cache remains separate.

## Deny or Reject?

Both stop the connection; they differ in what the application sees.

| Action   | Kernel verdict | Application sees                          |
|----------|----------------|-------------------------------------------|
| `Deny`   | DROP           | Nothing. It hangs until its own timeout.  |
| `Reject` | DROP + refusal | Connection refused / port unreachable, immediately. |

`Reject` injects a TCP RST for TCP flows and an ICMP (or ICMPv6)
port-unreachable for UDP. Prefer it for anything interactive: a browser
that gets an instant refusal shows an error, while a dropped connection
spins for 30 seconds and users blame the network. Prefer `Deny` when you
would rather not tell the other end anything at all - though for
*outbound* filtering the "other end" is a local process you already
control, so this matters less than it does on an inbound firewall.

Two caveats, both real:

- **`Reject` needs `CAP_NET_RAW`** to open the raw sockets it injects
  through. The bundled unit grants it. Without it the daemon logs one
  warning at startup and every Reject silently behaves like a Deny:

  ```
  raw socket setup failed (...); Reject rules will behave like Deny for
  those families. CAP_NET_RAW is required - the bundled
  colony-firewalld.service grants it.
  ```

- **Reject applies wherever the action comes from** - a saved rule, a
  prompt you answered, or `no_ui_action`/`timeout_action = "reject"` in
  `daemon.toml`. The verdict carries the action verbatim to the
  datapath, so a stored Reject rule refuses exactly like an interactive
  one.

## Rule design principles

**Prefer narrow scopes.** A rule that only matches `exe + dst_port +
protocol` is much safer than `exe` alone - if a process is later
compromised, the attacker still can't pivot to arbitrary destinations.

**Watch the hit counter.** `cfc rules list` shows `hits` per rule. A rule
with zero hits after weeks of use is probably obsolete or wrong.

**Stable paths matter.** Symlinks like `/usr/bin/python` may point to a
different binary after an interpreter upgrade. When in doubt, target the
real path under `/usr/lib/...` or pin by SHA-256 (`scope.exe_sha256`).

## What this firewall does *not* protect against

Normal mode follows the desktop application firewall model of OpenSnitch and
Windows Firewall Control. It filters new tracked IP flows using socket
attribution. [Explicit application confinement](../README.md#explicit-application-confinement)
is a separate launch mode.

- **Anything from root**: `/usr/bin/colony-firewalld` itself is trusted,
  and so is any other root process. Use this firewall alongside, not
  instead of, traditional access controls.
- **eBPF / unprivileged user namespaces**: a sufficiently privileged user
  can bypass NFQUEUE entirely with `unshare -rn` and a custom net namespace.
- **Local relays and DNS**: while the daemon runs, explicit rules apply to
  new direct loopback flows and unmatched local IPC is allowed without
  prompting. While no daemon listens on the queue, new loopback flows are
  allowed unfiltered (`bypass` on the `lo` rule only): an explicit loopback
  Deny or Reject rule is not enforced in that window, nothing records those
  flows, and a loopback connection opened then keeps its authorization once
  the daemon is back. An authorized local
  resolver or proxy can relay remote traffic, which is attributed to that
  service. CFC cannot establish the originating application's identity from
  remote flows delegated through AF_UNIX or D-Bus brokers. Existing local
  connections retain their authorization. Hostname rules and observed answers
  do not isolate DNS queries.
- **Inherited or passed sockets**: established/related traffic keeps its
  connection-wide authorization. An inherited or passed descriptor is not
  reauthorized for each sending executable. Current descriptor ownership
  and validated eBPF hints reduce false attribution; neither proves which
  process sent a packet.
- **Mount namespaces and same-user code**: a process reports its executable
  path as its own mount namespace sees it. When that path names a different
  file in the daemon's view (a container's or `unshare -rm` user's
  `/usr/bin/curl`), the executable is reported as unknown, so path rules for
  the host's file do not match it. A path the daemon cannot see at all (a
  Flatpak `/app` path, anything under `/home`, hidden by `ProtectHome`) is
  taken as reported: a hand-written path-only rule for such a path can be
  matched from a mount namespace, so pin its hash. Code already running as a
  user can also borrow an allowed program's identity by running it with
  chosen arguments or with `LD_PRELOAD`, which a hash pin does not prevent.
- **Raw and packet sockets**: applications with `CAP_NET_RAW` can use AF_PACKET
  outside the shipped `inet OUTPUT` hook. Raw IP packets can coincide with
  another socket's tuple even when TCP matching is strict. Tuple and inode
  checks do not prove raw packet provenance or provide layer-2 containment.
- **DNS-over-HTTPS embedded in browsers**: the firewall sees the outer HTTPS
  flow. Domain isolation requires an application-aware proxy or separate containment.
- **Container traffic**: Docker / Podman / LXC route through their own
  bridges. You need to enqueue their veth interfaces explicitly in nftables.

## The control socket and who can talk to it

The daemon runs as root and drives the packet filter, so its control
socket (`/run/colony-firewall/cfc.sock`) is the entire attack surface.
Two layers guard it.

**Layer 1 - the socket file.** After bind, the daemon chowns the socket
to `root:colony-firewall` and then chmods it 0660, in that order, so it
is never briefly readable by the wrong group. The kernel refuses
`connect(2)` to anyone outside the group. To run the GUI or `cfc` as your
regular user:

```sh
sudo usermod -aG colony-firewall $USER
```

then log out and back in for the group to take effect.

If the group does not exist the daemon does **not** fail to start. It
warns, leaves the socket root-only (0600), and only a root `cfc` can
connect - the UI will report a permission error. Create the group with
the shipped `sysusers.d` fragment or by hand
(`groupadd -r colony-firewall`), then add yourself and restart.

**Layer 2 - peer credentials.** Every connection carries `SO_PEERCRED`,
and the daemon checks the caller per RPC:

| RPC class | RPCs                        | Requires                    |
|-----------|-----------------------------|-----------------------------|
| Mutating  | `UpsertRule`, `ApplyRules`, `DeleteRule`, `SetPaused`, `SubmitVerdict` | uid 0, **or** a socket that is genuinely group-gated |
| Read-only | `ListRules`, `GetStatus`, `ListEvents`, `StreamConnections`, `StreamPrompts` | Only layer 1 |

`require_group = false` in `[ipc]` turns the mutating check off. Leave it
on unless you are gating the socket some other way (filesystem ACLs);
with it off, any process that manages to connect can rewrite your rules.

**Say it plainly: every member of the group is fully trusted.** There is
no in-band authentication, no per-user identity, and no password. Group
membership grants the ability to allow or deny any traffic on this host,
which is root-equivalent control over the firewall. This is not a
multi-user privilege boundary - add only administrators of the machine.

**The one exception is prompt ownership.** A prompt is about a process,
and that process has an owner uid. Delivery is scoped to it: a
`StreamPrompts` subscription is handed a prompt only when the subscriber's
peer uid matches the owner, and `SubmitVerdict` refuses a caller the prompt
was not handed to. So another logged-in user's session is neither shown the
prompt nor able to answer it - it never even learns the prompt id.

Exactly what that does and does not promise:

| Prompt is about a process owned by | Delivered to           | Answerable by          |
|------------------------------------|------------------------|------------------------|
| uid 1000                           | uid 1000, root         | uid 1000, root         |
| uid 0 (a system daemon)            | root only              | root only              |
| nobody - attribution failed        | every subscriber       | every subscriber that received it |

Two deliberate consequences:

- **Root is exempt on both counts** - it sees and may answer everything,
  because uid 0 already controls the machine and the root CLI is the
  recovery path when no session is up. The flip side is that a prompt for a
  *root-owned* process is not shown to an ordinary user's UI. With no root
  subscriber connected there is no audience for it, so the daemon answers
  it immediately with `no_ui_action` rather than stalling the packet until
  `prompt_timeout_secs` expires. Run the CLI as root if you want to be
  asked about system daemons.
- **Unattributed flows are offered to everyone.** When the process exited
  before `/proc` could be read the daemon has no owner uid to match. It
  prompts every session rather than none: nobody can claim such a flow, and
  restricting it would mean these connections are silently resolved by
  policy in exactly the case where a human should look.

This is prompt-level isolation between sessions, not a privilege boundary:
every group member can still write rules that affect the whole host.

## What hot-reloads and what needs a restart

`systemctl reload` is not wired up; send `SIGHUP` (or
`systemctl kill -s HUP colony-firewalld`). A reload never drops a packet,
and a config file that fails to parse is rejected with the running policy
left in place.

| Setting                                            | On SIGHUP |
|----------------------------------------------------|-----------|
| `profile`                                          | Live      |
| `[default_policy] no_ui_action` / `timeout_action` | Live      |
| `[default_policy] prompt_timeout_secs`             | Live (next prompt) |
| `[nfqueue] queue_num` / `queue_max_len` / `fail_open` | Restart |
| `[storage] path`                                   | Restart   |
| `[events] max_rows`                                | Restart   |
| `[pause] default_secs`                             | Restart   |
| `[ipc] group` / `require_group`                    | Restart   |

Rules are not read from the config file at all - they live in the
database and every change takes effect immediately.

## The audit trail

Three places record what the firewall did:

**1. journald, for anything that changed state.** Every mutating RPC is
logged with the calling uid and pid, the target, and the outcome:

```sh
journalctl -u colony-firewalld -g 'rule upserted|rules applied|rule delete|verdict submitted|paused'
```

so "who deleted the rule blocking that telemetry endpoint" is answerable
after the fact.

**2. journald, for parsed NFQUEUE refusals.** Deny and Reject verdicts
log the action, its source, the executable, pid, uid and destination:

```sh
journalctl -u colony-firewalld -g 'connection blocked'
```

This line is emitted once the verdict is delivered, before the row is queued
for the database.

**3. The events table.** Every verdict is written by an asynchronous writer
that commits in batches; no packet waits for it. Query with `cfc log`:

```sh
cfc log --since 24h --action deny
cfc log --exe firefox --limit 200
cfc log --json --since 1h | jq -r '.[] | .dst_host // .dst_ip' | sort | uniq -c
```

WAL and synchronous=FULL are required at startup. Rows are lost, never
waited for, when the writer's queue is full or a batch commit fails (a full
disk, an I/O error); the loss is counted and logged:

```sh
journalctl -u colony-firewalld -g 'events were not persisted|event log write failed'
```

Up to about a second of rows still waiting for their batch is lost on a crash,
a power cut or a stop. Malformed packets, nftables drops and in-kernel refusals
are not recorded at all.

Both journal sources share journald's per-unit rate limit (by default 10000
messages per 30 seconds). A sustained flood of refused packets can exceed it,
and journald then drops this unit's lines for the rest of that interval,
including the mutating-RPC lines above; it logs how many it suppressed. Raise
`LogRateLimitIntervalSec=`/`LogRateLimitBurst=` in a drop-in for the unit if
that trail matters more than journal volume. The same flood fills the events
table, whose oldest rows the row cap below evicts.

Retention is a row cap, not a time window:
`[events] max_rows` (default 100000), pruned every 60 seconds. Raise it
if you want a longer history, and remember the table lives in
`/var/lib/colony-firewall/rules.db` - back it up or ship it off the host
if the log matters for forensics, because an attacker with root can
rewrite it.

Verdicts that were *not* blocks are also recorded, so the log answers
"what did this app contact?", not just "what did we stop?".

## Daemon sandboxing

The bundled unit is not a bare `ExecStart`. The daemon parses
attacker-controlled packets as root, so the point of these directives is
to shrink what a code-execution bug could reach:

| Directive                          | Why                             |
|------------------------------------|---------------------------------|
| `CapabilityBoundingSet`, `AmbientCapabilities` | Seven capabilities, not full root: `CAP_NET_ADMIN` for NFQUEUE, the nftables table probe and the one-shot flush of the legacy Fast Allow set, `CAP_NET_RAW` for Reject injection, `CAP_SYS_PTRACE` for reading other processes' `/proc`, `CAP_BPF` + `CAP_PERFMON` for the eBPF layer, `CAP_CHOWN` for the control socket's group, and `CAP_DAC_READ_SEARCH` for the `/proc/*/fd` walk attribution falls back to. The count and the list have to agree: this said seven and named five, and the two it left out are exactly the pair the SELinux policy was once missing - with the fail-closed ruleset, a daemon that cannot read `/proc` attributes nothing and the machine loses outbound traffic |
| `NoNewPrivileges`                  | No regaining privileges via setuid binaries |
| `SystemCallFilter=@system-service` | seccomp; the biggest blast-radius reduction available |
| `SystemCallFilter=bpf perf_event_open` | The two syscalls the eBPF layer needs, named individually |
| `SystemCallArchitectures=native`   | Closes the 32-bit-syscall bypass of that filter |
| `MemoryDenyWriteExecute`           | Nothing here JITs; no W+X memory |
| `ProtectSystem=strict`, `ProtectHome`, `ReadWritePaths` | Read-only filesystem apart from the state, runtime and log directories |
| `RestrictAddressFamilies`          | AF_UNIX, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET only |
| `RestrictNamespaces`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID` | Namespace and personality lockdown |
| `ProtectKernelTunables`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` | No writing kernel state |
| `UMask=0077`                       | Closes the window between `bind` and the explicit chmod of the control socket |
| `PrivateTmp`                       | No shared `/tmp`                |

**`ProtectProc=invisible` is deliberately absent.** It would hide other
processes' `/proc` entries from the daemon, and that is precisely how
process attribution works: `/proc/net/{tcp,udp}` gives a socket inode,
and a current descriptor holder is found by walking `/proc/*/fd` for a
matching `socket:[inode]` link. Turning it on makes every connection resolve to an
unknown process, which defeats the entire tool. Same reason
`CAP_SYS_PTRACE` is in the bounding set. If you are hand-editing the
unit, do not "harden" either of these.

### `CAP_BPF`, `CAP_PERFMON` and the seccomp filter

These are granted unconditionally, even though the eBPF layer is off at
runtime by default (`[ebpf] enabled`). The loader is compiled into the
shipped daemon, so the config switch is the only thing between a stock
install and a ring-0 attach — keeping that switch in one place beats
making operators edit a unit file, and a capability nothing exercises is
not an attack surface.

`SystemCallFilter=bpf perf_event_open` is **required** and is not
implied by `@system-service`. Checked with
`systemd-analyze syscall-filter`: `bpf` lives in `@privileged`,
`perf_event_open` in `@debug`, and neither set is part of the service
baseline. There is no `@bpf` set. Without that line every `bpf(2)` call
returns `EPERM` and the daemon silently falls back to `sock_diag` +
`/proc` - the startup log line names which sources are live, and is the
place to check.

The two syscalls are named individually rather than pulling in
`@privileged` or `@debug` wholesale, which would also restore `mount`,
`chroot`, the setuid family, `ptrace` and `process_vm_readv`.
`perf_event_open` is needed because that is how a tracepoint program is
attached; the `cgroup_skb` program goes through `bpf(BPF_LINK_CREATE)`
alone.

**`MemoryDenyWriteExecute` stays on with eBPF enabled.** It restricts
this process's own mappings, and the BPF JIT does not run in this
process: `bpf(2)` hands the kernel an instruction array, and the
verifier and JIT run kernel-side, emitting into kernel memory that a
per-process address-space policy has no bearing on. `LockPersonality`
is likewise untouched by any of this. Both were verified empirically by
running the loader under the full directive set with `systemd-run`.

`ProtectControlGroups=true` also stays: attaching `cgroup_skb` needs a
read-only fd on the cgroup v2 root as an attach target, not write access
to `cgroupfs`.

## Fail-open or fail-closed

The other half of the security posture is the nftables side, not the
daemon: whether the kernel drops or accepts new connections when nobody
is answering the queue. The shipped snippet is fail-closed for everything
except new loopback flows, which are allowed while no daemon listens. That
is the safer default and also the one that can lock you out of a remote box.
The full matrix - daemon up or down, table loaded or not, with and
without `bypass` - is in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#fail-open-vs-fail-closed-matrix).
Read it before enabling enforcement on a machine you only reach over SSH.

`[nfqueue] fail_open` must be `false`; `true` is rejected. Queue overflow
must drop traffic instead of bypassing policy and refusal auditing.
The nftables `bypass` keyword governs missing listeners; the shipped snippet
uses it only on the loopback rule (`oifname "lo"`).

## When something stops working

Order of operations:

1. Switch profile back to `balanced` so the daemon stops actively denying
   things while you debug.
2. `cfc live` and reproduce the failure - the deny verdict will show in
   real time.
3. `cfc rules list | grep <app>` - is the rule too narrow?
4. Re-add a temporary "allow once" rule via the UI prompt.
5. After it works, narrow the rule back down.

## Backups

Before any large rule cleanup:

```sh
cfc rules export --out ~/cfc-rules-$(date +%F).json
```

Restore with:

```sh
cfc rules import --replace ~/cfc-rules-2026-05-25.json
```

`--replace` makes the daemon's rule set match the file: every rule in the file
is written first, and only then are the rules *absent* from it removed. Nothing
is applied at all unless every rule in the file reads cleanly, so a typo cannot
leave you with a partial rule set — and against a fail-closed ruleset, a partial
rule set is a machine with no outbound network. Without `--replace`, import is
additive and removes nothing.

`--replace` with an empty file is refused rather than obeyed: deleting every
rule is not something a restore command should do by accident.
