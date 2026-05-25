# Changelog

All notable changes to Colony Firewall Control will be documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Pause toggle in the UI header and a `SetPaused` gRPC RPC. When paused,
  the NFQUEUE worker short-circuits every packet to ACCEPT without
  parsing or consulting the rule engine. Status response now carries the
  `paused` flag.
- Better startup diagnostics when NFQUEUE bind fails: hints for missing
  `CAP_NET_ADMIN`, missing `nfnetlink_queue` module, or queue-number
  collision.
- This `CHANGELOG.md`.

## [0.1.0] - 2026-05-25 (initial alpha)

First end-to-end usable build. Daemon filters real outbound traffic, UI
serves prompts, CLI exercises the full surface.

### Added

#### Daemon (`colony-firewalld`)
- NFQUEUE recv loop with IPv4/IPv6 + TCP/UDP/ICMP 5-tuple parsing
- Process resolution via `/proc/net/{tcp,udp}{,6}` + `/proc/*/fd`
- Decision engine with `RuleSet::lookup` and atomic upserts
- Reverse DNS cache (`dns-lookup`, 300s positive / 60s negative TTL)
- Self-pid skip so the daemon's own reverse-DNS queries don't deadlock
- SQLite rule store via `rusqlite`
- gRPC server over Unix domain socket (tonic 0.14 + hyper-util)
- `PromptRouter` bridging sync NFQUEUE worker to async UI subscribers
- Timeout fallback per `[default_policy]` config block
- Named profiles in config: `relaxed`, `balanced`, `strict`
- Atomic stats counters (uptime, total/allowed/denied, prompts pending)
- `--dry-run` flag that skips NFQUEUE bind for UI/CLI development
- systemd unit with `CAP_NET_ADMIN`, `ProtectSystem=strict`, etc.

#### UI (`colony-firewall`)
- iced 0.14 application with parchment + burgundy Colony theme
- Four tabs: Prompts / Rules / Live / Stats
- Prompt cards with five answer scopes (once, this app, this app + dst,
  deny once, deny app)
- Rules table with: add, edit, delete, enable/disable toggle, search
  by name / exe / host / net
- Live connection feed (subscription, capped at 500 entries)
- Stats counter cards (2s polling)
- Auto-reconnect on UDS errors with backoff
- Desktop notifications via `notify-rust` on every new prompt

#### CLI (`cfc`)
- `cfc status` - daemon counters
- `cfc rules list / add / remove / toggle`
- `cfc rules export [--out FILE]` / `import [--replace]` JSON
- `cfc rules import-opensnitch <path>` - migrates from opensnitch
- `cfc live` - colorized terminal feed (allow green, deny red)

#### Packaging & infra
- `pkg/PKGBUILD` (Arch / AUR)
- `pkg/colony.json` (Colony app store manifest)
- GitHub Actions: fmt + clippy `-D warnings` + tests + fast-profile build
- 29 unit tests across `cfc-core`, `cfc-daemon`

### License

GPL-3.0-or-later (derivative of opensnitch).
