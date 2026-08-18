# Roadmap

Tracking the port from opensnitch (Go daemon + Python Qt UI) to Rust.

Phases 0-3 are done and have since been through a hardening pass
(Phase 3.5). The eBPF backend and the system tray have since landed
too. What is left is the whitelist fast-path map, VirusTotal lookups,
and one end-to-end test that is still manual.

## Phase 0 - Foundation [done]

- [x] Workspace skeleton
- [x] `cfc-core`: types (Rule, Verdict, Connection, Process)
- [x] `cfc-proto`: gRPC schema
- [x] `cfc-client`: shared UDS gRPC client
- [x] `cfc-daemon`: module skeletons
- [x] `cfc-ui`: iced skeleton with parchment theme + 4 tabs
- [x] `cfc-cli`: clap skeleton
- [x] systemd unit + nft snippet
- [x] CI: cargo fmt + clippy + test + build
- [x] AUR PKGBUILD draft
- [x] Colony app store manifest (`pkg/colony.json`)

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
- [ ] Smoke test: nftables enqueue + curl => observable DROP/ACCEPT (manual)
      - `scripts/smoke-test.sh` runs in CI but drives a `--dry-run`
        daemon: it never binds NFQUEUE, so it proves the gRPC/CLI
        surface, not that a packet is actually dropped. Verifying a real
        DROP/ACCEPT still means loading the nftables snippet on a real
        machine by hand.

## Phase 2 - UI MVP [done]

- [x] Connect to UDS (tonic + hyper-util TokioIo connector)
- [x] Prompt cards: process info, destination, Allow/Deny + scope buttons
- [x] Rules table with delete
- [x] Live feed scrolling list
- [x] Stats counter cards (read from GetStatus, 2s polling)
- [x] Desktop notifications via notify-rust on new prompts
- [x] Inline rule editor in Rules tab (name, action, duration, exe, host, net, port, protocol)
- [x] System tray icon (ksni): `colony-firewall-tray` — status, pending-prompt badge, pause/resume, opens the GUI

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
      Allow, then created_at, then id)
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

## Phase 4 - eBPF backend [mostly done]

Off by default: needs `--features ebpf` at build time and `[ebpf]
enabled` in `daemon.toml`. Verified end to end on kernel 7.1.8.

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
      `crates/cfc-ebpf/README.md` for the full write-up)
- [ ] Whitelist fast-path map for already-allowed flows. Note the
      shape of this one is not what it looks like: nftables enqueues
      only `ct state new`, so the per-packet cost is already paid once
      per connection, and the cgroup egress hook runs *after*
      NF_INET_LOCAL_OUT - it cannot short-circuit NFQUEUE. The win
      available here is attribution cost, not packet cost

## Phase 5 - Polish

- [ ] VirusTotal lookup integration (optional, opt-in)
- [x] Profile presets: relaxed / balanced / strict
- [x] Import rules from opensnitch JSON
- [x] Colony app store manifest (`colony.json`)
- [x] AUR PKGBUILD draft (now AUR-ready in `pkg/`; not yet published,
      signed release pending)
- [x] Shell completions + man pages
- [x] Persistent verdict log (`cfc log`)
- [ ] Publish to the AUR
