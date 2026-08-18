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
   `profile = "strict"` for fail-closed behavior.
5. Audit `cfc rules list` monthly. Remove rules for apps you no longer
   use, and check `cfc log --since 30d` for destinations you did not
   expect.

On a headless machine, substitute `cfc prompts` for "leave the UI
running" throughout - it subscribes the same way the GUI does.

## Choosing a profile

| Profile  | No UI    | Timeout  | Window | Use when                                      |
|----------|----------|----------|--------|------------------------------------------------|
| relaxed  | Allow    | Deny     | 60s    | Headless servers / can't always be at the UI   |
| balanced | Allow    | Deny     | 30s    | Daily-driver workstations (default)            |
| strict   | Deny     | Deny     | 15s    | Lockdown posture, UI always present            |

**No profile ever permits a connection by itself.** Not on timeout, not
when nothing is subscribed. The presets differ only in how long a prompt
waits for an answer. Only a stored rule, or a person answering, allows
traffic.

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
`Before=network-pre.target`, so filtering is live before any interface
is configured and long before your UI session exists — under `strict`,
every outbound flow with no matching rule is denied from the first
instant of boot. That ordering is the point (there is no unfiltered
window at boot), but it means DHCP, DNS and NTP need standing rules or
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

A short blocklist that pays off on most workstations:

- Any DNS-over-TLS or DoH client you didn't install on purpose
- Adobe / Microsoft / Google telemetry endpoints (use `dst_host` rules)
- Crashpad processes in browsers that you don't want phoning home

Example with the CLI:

```sh
cfc rules add --action deny --dst-host 'incoming.telemetry.mozilla.org' \
              --name 'block-firefox-telemetry'
```

### A warning about `dst_host`

Hostname matching is based on reverse DNS: the daemon does a PTR lookup
on the destination IP and matches `dst_host` against whatever comes
back. **PTR records are published by whoever controls the destination
IP** - which, for outbound filtering, is exactly the party you may be
trying to keep the user away from. Taken at face value, a hostile server
could name itself `api.github.com` and satisfy an allow rule.

The daemon mitigates this with forward confirmation (FCrDNS): every PTR
answer is resolved back to its A/AAAA set, and the name is kept only if
that set contains the IP we started from. Names that fail confirmation
are discarded, so a rule never matches on one. That makes a hostname as
trustworthy as the *forward* zone of the claimed domain rather than the
reverse zone of an arbitrary IP.

It is a mitigation, not a guarantee. Names are still resolved after the
fact and cached (300s positive, 60s negative), and an attacker who
controls both zones can still name themselves self-consistently. Treat
`dst_host` as best-effort metadata and a convenience for *deny* rules (a
telemetry endpoint has no incentive to hide its own PTR). Do **not**
lean on a hostname *allow* rule as your only boundary. For allow rules,
pin `exe` + `dst_port` (+ `dst_net` where destinations are stable)
instead.

#### Observed answers, with `[ebpf] enabled`

Turning the eBPF layer on adds a second, better source. The
`cgroup_skb/ingress` program copies the DNS *responses* this machine
receives off the wire, and the daemon lifts the `A`/`AAAA` records
straight out of them. Those mappings win over anything the PTR path
produces.

The difference is who is being asked. A PTR answer is the destination
address's owner saying what it would like to be called - second-hand,
after the fact, from the party you may be trying to block. An observed
answer is first-hand: this host asked a resolver for `example.com` and
was told an address, *before* the connection it explains, by the zone
that owns the name. The "hostile server names itself `api.github.com`"
problem does not arise, because the destination no longer gets a vote.

What it does not fix: the program reads packets off the wire, before the
resolving library's transaction-id and source-port checks. Anything
arriving from source port 53 that parses as a response is observed,
including a forgery that the resolver will go on to reject - and that is
the same attacker who could also forge the forward lookup FCrDNS
depends on. Observed answers raise the bar; they do not make a hostname
allow rule a boundary. The advice above is unchanged.

Answers are cached for the record's own TTL, clamped to 60s..1h.

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

- **Anything from root**: `/usr/bin/colony-firewalld` itself is trusted,
  and so is any other root process. Use this firewall alongside, not
  instead of, traditional access controls.
- **eBPF / unprivileged user namespaces**: a sufficiently privileged user
  can bypass NFQUEUE entirely with `unshare -rn` and a custom net namespace.
- **DNS-over-HTTPS embedded in browsers**: if the browser resolves names
  inside its own HTTPS connection, the firewall sees only the outer
  443/tcp flow. Block at the `dst_host` layer or disable DoH per-app.
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
| Mutating  | `UpsertRule`, `DeleteRule`, `SetPaused`, `SubmitVerdict` | uid 0, **or** a socket that is genuinely group-gated |
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
journalctl -u colony-firewalld -g 'rule upserted|rule delete|verdict submitted|paused'
```

so "who deleted the rule blocking that telemetry endpoint" is answerable
after the fact.

**2. journald, for every blocked connection.** Deny and Reject verdicts
log the action, its source, the executable, pid, uid and destination:

```sh
journalctl -u colony-firewalld -g 'connection blocked'
```

This line is emitted whether or not the row makes it to disk.

**3. The events table, for everything.** Every observed connection and
its verdict is persisted in the rules database and queried with `cfc log`:

```sh
cfc log --since 24h --action deny
cfc log --exe firefox --limit 200
cfc log --json --since 1h | jq -r '.[] | .dst_host // .dst_ip' | sort | uniq -c
```

Persistence happens off the packet path through a bounded queue, so a
slow disk can never delay a verdict; if the queue fills, rows are dropped
and the loss is logged. Retention is a row cap, not a time window:
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
| `CapabilityBoundingSet`, `AmbientCapabilities` | Five capabilities, not full root: `CAP_NET_ADMIN` for NFQUEUE, `CAP_NET_RAW` for Reject injection, `CAP_SYS_PTRACE` for reading other processes' `/proc`, `CAP_BPF` + `CAP_PERFMON` for the eBPF layer |
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
and the owning pid is found by walking `/proc/*/fd` for a matching
`socket:[inode]` link. Turning it on makes every connection resolve to an
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
is answering the queue. The shipped snippet is fail-closed, which is the
safer default and also the one that can lock you out of a remote box.
The full matrix - daemon up or down, table loaded or not, with and
without `bypass` - is in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#fail-open-vs-fail-closed-matrix).
Read it before enabling enforcement on a machine you only reach over SSH.

Note that `[nfqueue] fail_open` is a *different* knob: it governs what
the kernel does when the queue overflows while the daemon is running
(default `false`, drop). The `bypass` keyword governs what happens when
no daemon is attached at all.

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

`--replace` deletes everything first; without it, import is additive.
