# Colony Firewall Control

Application-aware outbound firewall for Linux, written in Rust.

A Colony-flavored port of [opensnitch](https://github.com/evilsocket/opensnitch)
from Go/Python to Rust, with an [iced](https://iced.rs/) UI matching the
Colony app aesthetic (parchment + burgundy).

## Why

The Linux desktop has no built-in outbound firewall with per-application
prompts. The closest equivalent of [Windows Firewall Control](https://www.malwarebytes.com/windows-firewall-control)
is opensnitch, which works but ships a Go daemon plus a 200 MB PyQt5 GUI.
Colony Firewall Control gives you the same model in a single Rust workspace:
NFQUEUE in the kernel, per-app pop-ups in iced, gRPC IPC over a Unix socket.

## Features

- Per-application outbound filtering with NFQUEUE intercept
- Live pop-ups for unknown connections, persistent rules for known ones
- iced GUI with parchment / burgundy theme, four tabs (Prompts / Rules /
  Live / Stats)
- Desktop notifications for new prompts when the window is hidden
- Headless CLI (`cfc`) for status, rule CRUD, live feed
- JSON export / import for backup and machine-to-machine sync
- opensnitch JSON import for one-shot migration
- Named profiles: relaxed / balanced / strict (in `daemon.toml`)
- Memory-safe Rust top to bottom for a root daemon parsing untrusted packets

## Architecture

```
+----------------------------+
|  cfc-ui   (iced, user)     |     +----------------+
|   pop-ups, rules editor    | --- |  cfc-cli (tty) |
+------------+---------------+     +-------+--------+
             | tonic gRPC over UDS         |
             v                             v
+----------------------------+
|  cfc-daemon  (systemd, root)
|   - NFQUEUE intercept
|   - process resolution (/proc + sock_diag)
|   - decision engine
|   - sqlite rules store
|   - prompt router (sync NFQ <-> async UI)
+----------------------------+
```

Five workspace crates:

| Crate         | Role                                                     |
|---------------|----------------------------------------------------------|
| `cfc-core`    | Shared types: `Rule`, `Verdict`, `Connection`, `Process` |
| `cfc-proto`   | gRPC schema (tonic + tonic-prost)                        |
| `cfc-client`  | Shared UDS gRPC client wrapper                           |
| `cfc-daemon`  | Privileged daemon                                        |
| `cfc-ui`      | iced GUI                                                 |
| `cfc-cli`     | Terminal control tool                                    |

More docs:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - process model, packet
  flow, threading
- [docs/HARDENING.md](docs/HARDENING.md) - moving to a locked-down profile
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - lockout recovery,
  no-network debugging, fail-open vs fail-closed
- [docs/ROADMAP.md](docs/ROADMAP.md) - full phase checklist

## Install

### Arch Linux

Not on the AUR yet. An AUR-ready PKGBUILD ships in `pkg/` for building
locally in the meantime:

```sh
cp pkg/PKGBUILD ./
makepkg -si
```

### Manual

```sh
cargo build --workspace --release

sudo install -Dm755 target/release/colony-firewalld /usr/bin/colony-firewalld
sudo install -Dm755 target/release/colony-firewall  /usr/bin/colony-firewall
sudo install -Dm755 target/release/cfc              /usr/bin/cfc
sudo install -Dm644 systemd/colony-firewalld.service /usr/lib/systemd/system/
sudo install -Dm644 systemd/daemon.toml.sample /etc/colony-firewall/daemon.toml
sudo systemctl daemon-reload
sudo systemctl enable --now colony-firewalld
```

Installing only puts the binaries and daemon in place - no traffic is
filtered until you enable enforcement. See First run below.

## First run

A fresh install has **zero rules**: once enforcement is on, every new
outbound connection prompts (or falls back to the profile default). Do
these three things, in order:

**1. Enable enforcement persistently.** This release adds a companion
unit that loads the nftables ruleset at boot and removes it on stop:

```sh
sudo systemctl enable --now colony-firewall-nft.service
```

Alternatively, apply the snippet by hand - but note this does **not**
survive a reboot; after restarting, the daemon runs while enforcing
nothing:

```sh
sudo nft -f systemd/nftables-snippet.conf
```

**2. Seed the starter rules** so always-on system services keep working
without prompting:

```sh
cfc rules bootstrap-defaults
```

This installs six allow rules - systemd-resolved DNS (:53),
systemd-timesyncd and chronyd NTP (:123/udp), pacman and paru HTTPS
mirrors (:443/tcp), and the SSH client (:22/tcp) - and is idempotent
(already-present rules are skipped by name; `--dry-run` previews).

**3. Launch the GUI** so prompts have somewhere to go:

```sh
colony-firewall
```

> **WARNING - remote / SSH machines:** the shipped nftables snippet is
> fail-closed. If the daemon is down while the rule is loaded, **all new
> outbound connections drop**, and a mistake can lock you out of a box you
> only reach over SSH. Read
> [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - specifically the
> SSH exemption and dead-man's-switch patterns - *before* enabling
> enforcement remotely.

## Quick start

Open the GUI:

```sh
colony-firewall
```

Or drive everything from the CLI:

```sh
# Status
cfc status

# Add a rule from the command line
cfc rules add --action allow --exe /usr/bin/curl --dst-port 443

# Watch traffic decisions in real time (colorized)
cfc live

# Back up rules
cfc rules export --out rules.json

# Migrate from an existing opensnitch install
cfc rules import-opensnitch /etc/opensnitchd/rules
```

## Profiles

`daemon.toml` accepts a `profile` key with three presets:

| Profile  | No UI    | Timeout  | Window |
|----------|----------|----------|--------|
| relaxed  | Allow    | Allow    | 60s    |
| balanced | Allow    | Allow    | 15s    | (default)
| strict   | Deny     | Deny     | 10s    |

Use `strict` only when you always have the UI running, otherwise you lose
network when the daemon starts before the UI does (fail-closed posture).

## Development

Requires Rust stable (>= 1.78) and `protobuf-compiler`. On Debian/Ubuntu:

```sh
sudo apt install protobuf-compiler libnfnetlink-dev libnetfilter-queue-dev
```

```sh
cargo build --workspace --profile fast
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

The daemon needs `CAP_NET_ADMIN` to bind NFQUEUE, so run it as root or via
the bundled systemd unit. The UI and CLI run as your regular user.

For development without root, the daemon accepts `--dry-run` which skips
the NFQUEUE bind and lets you exercise the gRPC server and UI against a
daemon that just reports rules and a stub status feed:

```sh
cargo run -p cfc-daemon -- --debug --dry-run --socket /tmp/cfc.sock
cargo run -p cfc-ui     # in another terminal
```

## Status

| Phase                    | State |
|--------------------------|-------|
| 0  Foundation            | done  |
| 1  Daemon MVP            | done  |
| 2  UI MVP                | done  |
| 3  CLI                   | done  |
| 4  eBPF backend          | TODO  |
| 5a CI                    | done  |
| 5b Packaging             | in progress (AUR-ready PKGBUILD in `pkg/`, not yet published) |
| 5  System tray, VT       | TODO  |

See `docs/ROADMAP.md` for the full checklist.

## License

GPL-3.0-or-later. Inherited from
[opensnitch](https://github.com/evilsocket/opensnitch) since this is a
derivative port.

## Credits

- [opensnitch](https://github.com/evilsocket/opensnitch) by Simone
  Margaritelli (evilsocket) and Gustavo Iniguez Goia - the project we are
  porting.
- The Rust [tonic](https://github.com/hyperium/tonic),
  [aya](https://github.com/aya-rs/aya), [iced](https://iced.rs/), and
  [nfq](https://crates.io/crates/nfq) crates.
