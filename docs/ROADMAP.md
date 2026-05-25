# Roadmap

Tracking the port from opensnitch (Go daemon + Python Qt UI) to Rust.

## Phase 0 - Foundation [current]

- [x] Workspace skeleton
- [x] `cfc-core`: types (Rule, Verdict, Connection, Process)
- [x] `cfc-proto`: gRPC schema
- [x] `cfc-daemon`: skeleton modules (nfqueue, decision, storage, ipc)
- [x] `cfc-ui`: iced skeleton with parchment theme + 4 tabs
- [x] `cfc-cli`: clap skeleton
- [x] systemd unit + nft snippet
- [ ] CI: cargo check + clippy + fmt on push
- [ ] AUR PKGBUILD draft

## Phase 1 - Daemon MVP

- [ ] Real NFQUEUE recv loop in `nfqueue.rs`
- [ ] IPv4/IPv6 5-tuple parse from raw packet
- [ ] Process resolution via `procfs` (with TOCTOU guard)
- [ ] Socket-inode -> pid lookup via netlink sock_diag (faster than /proc walk)
- [ ] Rule lookup + verdict back to kernel
- [ ] Persist new rules (UpsertRule wired)
- [ ] gRPC handlers: ListRules, UpsertRule, DeleteRule, GetStatus
- [ ] Prompt round-trip (StreamPrompts + SubmitVerdict) with timeout
- [ ] Smoke test: nftables enqueue + curl => DROP/ACCEPT observable

## Phase 2 - UI MVP

- [ ] Connect to UDS (tonic-with-named-pipe)
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
