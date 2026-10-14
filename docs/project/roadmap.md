# Roadmap

Tracking the port from opensnitch (Go daemon + Python Qt UI) to Rust.

Phases 0-3 are done and have since been through a hardening pass
(Phase 3.5). The eBPF backend and the system tray have since landed
too; the whitelist fast path landed and was later removed (see
[The eBPF layer](../internals/architecture.md#the-ebpf-layer)). What is left
is VirusTotal lookups, publishing to the AUR, and the [open work](#open-work)
found by using it.

## Phase 0 - Foundation [done]

- [x] Workspace skeleton
- [x] `cfc-core`: types (Rule, Verdict, Connection, Process)
- [x] `cfc-proto`: gRPC schema
- [x] `cfc-client`: shared UDS gRPC client
- [x] `cfc-daemon`: module skeletons
- [x] `cfc-ui`: iced skeleton with parchment theme + 4 tabs
- [x] `cfc` (CLI crate): clap skeleton
- [x] systemd unit + nft snippet
- [x] CI: cargo fmt + clippy + test + build
- [x] AUR PKGBUILD draft
- [x] Release tarball recipe (`packaging/tarball-manifest.json`; no Colony
      store client reads it, `scripts/tarball-installers.sh` turns it into the tarball's
      `install.sh`)

## Phase 1 - Daemon MVP [done]

- [x] NFQUEUE recv loop via `nfq` crate (spawn_blocking + recv loop)
- [x] IPv4/IPv6 + TCP/UDP/ICMP 5-tuple parse from raw packet
- [x] Process resolution: /proc/net/{tcp,udp}{,6} -> inode -> /proc/*/fd
- [x] Decision engine evaluate path wired
- [x] Rule storage (sqlite via `rusqlite`)
- [x] gRPC server bound on Unix domain socket
- [x] Handlers: ListRules, UpsertRule, DeleteRule, GetStatus, StreamConnections
- [x] Atomic stats counters (uptime, total/allowed/denied, prompts pending)
- [x] PromptRouter: sync NFQUEUE worker <-> async UI subscribers
- [x] StreamPrompts + SubmitVerdict with timeout fallback
- [x] Persist-on-answer (scope from UI becomes a new Rule)
- [x] Smoke test: nftables enqueue + curl => observable DROP/ACCEPT
      - `scripts/armed-e2e.sh`, run by the `e2e` workflow on pushes to
        `main` and on pull requests, loads the shipped nftables snippet in a network
        namespace and runs the daemon on a real NFQUEUE: an allowed flow
        gets HTTP 200, a denied or unmatched one is dropped (curl exit
        28), and new flows stay dropped after the daemon stops on SIGTERM
        or SIGKILL. `scripts/smoke-test.sh` still covers the gRPC/CLI
        surface against a `--dry-run` daemon.

## Phase 2 - UI MVP [done]

- [x] Connect to UDS (tonic + hyper-util TokioIo connector)
- [x] Prompt cards: process info, destination, Allow/Deny + scope buttons
- [x] Rules table with delete
- [x] Live feed scrolling list
- [x] Stats counter cards (read from GetStatus, 2s polling)
- [x] Desktop notifications via notify-rust on new prompts
- [x] Inline rule editor in Rules tab (name, action, duration, exe, host, net, port, protocol)
- [x] System tray icon (ksni): `colony-firewall-tray`: status, pending-prompt badge, pause/resume, opens the GUI

## Phase 3 - CLI [done]

- [x] `cfc status` real
- [x] `cfc rules list/remove`
- [x] `cfc rules add` with full scope flags
- [x] `cfc rules export/import` (JSON)
- [x] `cfc rules import-opensnitch` (parses opensnitch's rule JSON)
- [x] `cfc live` terminal feed
- [x] Color output and follow mode polish (colors respect `NO_COLOR`
      and a non-tty stdout; `--follow` reconnects across daemon restarts)

## Phase 3.5 - hardening & correctness [done]

Not originally on the roadmap. Four waves of work on the things that
were wrong or missing once the happy path worked.

### Rule semantics

- [x] Deterministic precedence (specificity, then Deny > Reject >
      Allow, then created_at, then id; a program-scoped Deny or Reject
      beats any Allow that names no program, and `/0` adds no
      specificity)
- [x] `Duration` enforced at lookup; expired rules reaped periodically
- [x] `Once` / `UntilRestart` purged at startup; persisting `Once` refused
- [x] Forward-compatible rule serialization + frozen v0.1.0 fixtures
- [x] Undeserializable rules counted and surfaced, never silently dropped

### Datapath

- [x] Out-of-order verdicts: one unanswered prompt no longer blocks
      every other flow
- [x] Prompt deduplication by flow (exe-or-pid, destination, protocol)
- [x] Pause evaluates rules, so Deny/Reject rules stay enforced
- [x] NFQUEUE open/bind failure exits non-zero (was: silent exit 0 under
      a fail-closed nft rule)
- [x] Queue tuning: `queue_max_len`, `fail_open`, kernel-reported uid/gid
- [x] Packet parser hardening: IPv4 `ihl >= 20`, IPv6 extension-header
      walk, fragment handling, proptest never-panic coverage

### Process attribution

- [x] netlink `sock_diag` fast path with `/proc` fallback
- [x] Fallbacks for unconnected UDP, wildcard-bound locals, and
      v4-mapped addresses in the IPv6 tables
- [x] TTL caches (inode -> pid, pid -> process, exe -> digest)
- [x] SHA-256 of the running binary

### Daemon lifecycle

- [x] SIGTERM/SIGINT graceful shutdown, SIGHUP policy hot-reload
- [x] sd_notify READY / WATCHDOG / STOPPING; unit is `Type=notify`
- [x] systemd sandboxing: seccomp, MemoryDenyWriteExecute, UMask, ...

### Security

- [x] Control socket `root:colony-firewall` 0660 + `[ipc]` config
- [x] Peer-credential authorization (mutating vs read-only RPCs)
- [x] Prompt ownership: only the session that got a prompt may answer it
- [x] Audit logging for mutating RPCs and blocked connections
- [x] Fallible protobuf conversions (no more unknown enum -> Allow)
- [x] Real `Reject` (TCP RST + ICMP unreachable), degrading to Deny
      without `CAP_NET_RAW`
- [x] `Process` uid/gid optional, so unattributed traffic cannot match
      uid-scoped rules

### Event log

- [x] `events` table with schema versioning and retention cap
- [x] Off-datapath persistence pipeline (bounded, batched, drops rather
      than blocks)
- [x] `ListEvents` RPC + `cfc log`

### CLI & UI

- [x] `cfc prompts` - answer prompts from a terminal (headless machines)
- [x] `cfc log`, `--json` everywhere, documented exit codes
- [x] Actionable connection errors (not running / not in the group /
      stale socket)
- [x] `cfc live` filters, app column, `--follow`
- [x] `cfc rules show/enable/disable`; id-prefix and name resolution
- [x] `cfc pause --for`
- [x] Shell completions + man pages, generated from the binary
- [x] UI: prompt countdown and auto-expiry, hostnames, process details
- [x] UI: daemon-death detection with backoff retry
- [x] UI: sortable rules, delete confirmation, live filters, session
      stats, status log, keyboard shortcuts

### CI & packaging

- [x] cargo-deny, Dependabot, SHA-pinned actions, `--locked`, MSRV gate
- [x] Release workflow + version consistency guard
- [x] AUR-ready PKGBUILD, desktop/autostart/icon, sysusers group
- [x] `colony-firewall-nft.service` with `ExecStop` cleanup

## Phase 4 - eBPF backend [done]

Compiled in by default (the `ebpf` cargo feature), and brought up at
runtime wherever the kernel supports it and the object is installed:
`[ebpf] enabled` defaults to `"auto"`, and `false` turns it off. Verified
end to end on kernel 7.1.8.

- [x] aya project setup, BPF target in workspace (own workspace, own
      pinned nightly, excluded from the stable build; `cargo xtask
      build-ebpf`)
- [x] `sched_process_exec` capture -> kernel pid table, with
      `sched_process_exit` eviction and start-time binding so PID reuse
      cannot serve a stale record. task_struct offsets come from BTF
      parsed by the loader (Rust has no CO-RE relocation)
- [x] DNS sniff -> observed A/AAAA answers outrank PTR-derived names in
      the hostname cache. The kernel gates and copies; the parser runs
      in userspace, because the in-kernel version hit the verifier's
      1,000,000-instruction complexity limit (see
      [Why the DNS parsing is in userspace](../internals/architecture.md#why-the-dns-parsing-is-in-userspace))
- [x] Whitelist fast path for already-allowed flows (`[ebpf]
      fast_allow`): removed. Allowed TCP connects were marked with
      SO_MARK at connect time and accepted ahead of the queue rule, and
      a socket mark does not attest which process sends, so it opened
      bypasses; see [open work](#open-work)

## Phase 5 - Polish

- [ ] VirusTotal lookup integration (optional, opt-in)
- [x] Profile presets: relaxed / balanced / strict
- [x] Import rules from opensnitch JSON
- [x] Colony app store listing (the root `colony.json`; the store installs
      the app alone for the user, never units or tables)
- [x] AUR PKGBUILD draft (now AUR-ready in `packaging/arch/`; not yet published,
      signed release pending)
- [x] Shell completions + man pages
- [x] Persistent verdict log (`cfc log`)
- [ ] Publish to the AUR

## Open work

Found by using it, ordered by what would change the most.

- [ ] **An in-kernel Allow with sender attestation.** Fast Allow marked the
      sockets of a process a lasting Allow covered, and a socket mark does
      not attest the current sender, so it opened bypasses and was removed.
      Bringing an in-kernel Allow back needs a design that verifies current
      socket ownership and revocation. Until then allowed flows use NFQUEUE,
      whose remaining cost still warrants measurement and optimisation with
      the same policy semantics (see [benchmarks](../internals/benchmarks.md)).
- [ ] **In-kernel enforcement for rules that depend on a destination.**
      `process_wide_action` deliberately answers `None` for them, which is
      correct and also means a program with a port-scoped rule gets no
      in-kernel enforcement at all. A destination-keyed map would fix it and
      is a much larger design: the kernel side would need to match addresses,
      and every DNS-name rule would have to be resolved to addresses in
      advance.
- [ ] **Run the SELinux policy on an enforcing host.** It compiles against
      the real `selinux-policy-devel` of Rocky 9 and Fedora, which proves
      every type and interface it names exists there, not that its rules are
      sufficient. The [validation protocol](../internals/selinux.md#validating-the-policy-on-an-enforcing-host)
      is ready for whoever has an enforcing VM.
- [ ] **Build the RPM on Rocky 9 itself.** The `rhel` workflow builds,
      installs and verifies the package in a Fedora container. Rocky 9's own
      path, the `rust-toolset` module (its default repositories stop short of
      the 1.89 MSRV), is untried, so "the deployment target can build this
      package" is still an assumption.
- [ ] **Watch package provenance inside the unit's sandbox.** The rpm
      backend runs `rpm -qa` as a child of the daemon, under its
      `SystemCallFilter`, `ProtectSystem=strict` and
      `MemoryDenyWriteExecute`. It degrades safely (a warning and an empty
      index) but has not been observed working there.
- [ ] **Confirm the tray icon fallback on quickshell/Noctalia.** Without the
      installed theme icon, the tray writes its SVG under
      `$XDG_RUNTIME_DIR/cfc-tray/icons` and exports it through
      `IconThemePath`. That is unit-tested, but nobody has yet watched
      quickshell/Noctalia, the host that showed a placeholder, render it on a
      machine without the package.
- [ ] **Decide how the AUR package gets the eBPF object.** On Arch `rustup`
      conflicts with `rust`, so `-Z build-std` fails inside `makepkg` and an
      AUR install runs on `sock_diag` + `/proc`. The ways out: leave it (the
      release tarball has the object), ship the object as a second `source=()`
      from the release assets (the one shipped component no AUR user builds
      from source), or provision a chroot with rustup and bpf-linker.
