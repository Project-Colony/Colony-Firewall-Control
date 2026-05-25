# Colony Firewall Control

Application-aware outbound firewall for Linux, written in Rust.

A Colony-flavored port of [opensnitch](https://github.com/evilsocket/opensnitch)
from Go/Python to Rust, with an [iced](https://iced.rs/) UI matching the
Colony app aesthetic (parchment + burgundy).

## Status

Pre-alpha. Workspace scaffold only. Not usable yet.

## Goals

- **Per-app outbound filtering**: prompt on every new connection (process + destination)
- **eBPF-first**: kernel-side decision for whitelisted flows, NFQUEUE only for unknown
- **Single static binary**: no PyQt5, no protobuf-python, no clang at build time
- **Colony integration**: iced UI, parchment theme, distributable via Colony app store
- **Memory-safe**: Rust top to bottom for a root daemon parsing untrusted packets

## Architecture

```
+----------------------------+
|  cfc-ui  (iced, user)      |
|   pop-up, rules editor     |
+------------+---------------+
             | tonic / gRPC over UDS
+------------v---------------+
|  cfc-daemon  (systemd)     |
|   nfq + aya/eBPF           |
|   decision engine          |
|   sqlite rules store       |
+----------------------------+
```

| Crate | Purpose |
|-------|---------|
| `cfc-core` | Shared types: `Rule`, `Verdict`, `Connection`, `Process` |
| `cfc-proto` | gRPC schema for daemon <-> UI IPC |
| `cfc-daemon` | Root daemon. NFQUEUE intercept, decision engine, rule persistence |
| `cfc-ui` | iced GUI: prompts, rules, live feed |
| `cfc-cli` | CLI control tool (allow/deny/list, no GUI required) |

## Roadmap

### Phase 0 - Foundation (current)
- [x] Workspace scaffold
- [ ] Type definitions in `cfc-core`
- [ ] gRPC schema in `cfc-proto`
- [ ] systemd unit + install scripts

### Phase 1 - Daemon MVP (NFQUEUE only)
- [ ] NFQUEUE packet intercept via `nfq` crate
- [ ] Process resolution via `/proc/{pid}` (TOCTOU aware)
- [ ] Rule storage (sqlite via `rusqlite`)
- [ ] Decision engine: lookup -> verdict
- [ ] gRPC server for UI connection

### Phase 2 - UI MVP
- [ ] iced app skeleton with Colony theme
- [ ] New-connection pop-up
- [ ] Rules list / editor
- [ ] Live connection feed
- [ ] Tray icon via `ksni`

### Phase 3 - CLI
- [ ] `cfc-cli rules list/add/remove/export`
- [ ] `cfc-cli live` (terminal connection feed)
- [ ] `cfc-cli stats`

### Phase 4 - eBPF backend
- [ ] Process-exec capture via `aya`
- [ ] DNS sniff via eBPF (cure NFQUEUE DNS race)
- [ ] Fast-path whitelisting in kernel

### Phase 5 - Polish
- [ ] VirusTotal lookup integration
- [ ] Profiles (medium/high/no filtering)
- [ ] Rule import from opensnitch
- [ ] PKGBUILD for AUR / Colony app manifest

## License

GPL-3.0-or-later. Inherited from [opensnitch](https://github.com/evilsocket/opensnitch)
since this is a derivative port.

## Credits

- [opensnitch](https://github.com/evilsocket/opensnitch) by Simone Margaritelli
  (evilsocket) and Gustavo Iniguez Goia - the project we are porting.
- The Rust [aya](https://github.com/aya-rs/aya) and [iced](https://iced.rs/)
  ecosystems.
