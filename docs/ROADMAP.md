# Roadmap

Tracking the port from opensnitch (Go daemon + Python Qt UI) to Rust.

## Phase 0 - Foundation [done]

- [x] Workspace skeleton
- [x] `cfc-core`: types (Rule, Verdict, Connection, Process)
- [x] `cfc-proto`: gRPC schema
- [x] `cfc-daemon`: module skeletons
- [x] `cfc-ui`: iced skeleton with parchment theme + 4 tabs
- [x] `cfc-cli`: clap skeleton
- [x] systemd unit + nft snippet
- [ ] CI: cargo check + clippy + fmt on push
- [ ] AUR PKGBUILD draft

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

## Phase 2 - UI MVP [next]

- [ ] Connect to UDS (tonic UDS client)
- [ ] Prompt pop-up: process info, destination, Allow/Deny + scope chips
- [ ] Rules table with edit/delete
- [ ] Live feed scrolling list
- [ ] Stats numbers (read from GetStatus)
- [ ] System tray icon (ksni) with quick toggle
- [ ] Desktop notifications via notify-rust

## Phase 3 - CLI

- [ ] `cfc status` real
- [ ] `cfc rules list/add/remove/export/import`
- [ ] `cfc live` terminal feed (color, follow mode)

## Phase 4 - eBPF backend

- [ ] aya project setup, BPF target in workspace
- [ ] `sched_process_exec` capture -> kernel pid table
- [ ] DNS sniff -> resolve dst_ip back to hostname pre-NFQ
- [ ] Whitelist fast-path map for already-allowed flows

## Phase 5 - Polish

- [ ] VirusTotal lookup integration (optional, opt-in)
- [ ] Profile presets: medium / high / no-filtering
- [ ] Import rules from opensnitch JSON
- [ ] Colony app store manifest (`colony.json`)
- [ ] AUR PKGBUILD + signed release
