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
  Live / Stats), a countdown on every prompt, and desktop notifications
  when the window is hidden
- **Answer prompts from a terminal** (`cfc prompts`) - headless servers
  and SSH sessions are not second-class citizens
- **Persistent verdict log** (`cfc log`): what did this app contact, and
  what did we do about it
- **`--json` on every command**, NDJSON for the streaming ones, and a
  documented exit-code contract, so `cfc` scripts cleanly
- **Real `Reject`**: a TCP RST or ICMP port-unreachable, so a blocked app
  fails immediately instead of hanging on its own timeout
- **Group-gated control socket** (`root:colony-firewall`, 0660) with
  per-RPC peer-credential checks and an audit trail in the journal
- **Hot policy reload** on `SIGHUP`, and a systemd `Type=notify` unit
  that reports ready only once it is actually filtering
- Headless CLI (`cfc`) for status, rule CRUD, live feed, prompts and log
- System-tray companion (`colony-firewall-tray`): status at a glance,
  pending-prompt badge and notifications, quick pause/resume
- JSON export / import for backup and machine-to-machine sync
- opensnitch JSON import for one-shot migration
- Named profiles: relaxed / balanced / strict (in `daemon.toml`)
- Shell completions and man pages, generated from the binary
- **Optional eBPF backend**: exec tracking and observed DNS answers read
  from inside the kernel, so attribution does not race `/proc` and
  hostnames come from the resolver's own replies rather than the
  destination's PTR record
- Memory-safe Rust top to bottom for a root daemon parsing untrusted packets

## Architecture

```
+----------------------------+     +----------------+
|  cfc-ui   (iced, user)     |     |  cfc-cli (tty) |
|   pop-ups, rules editor    |     |   status, rules|
|   live feed, stats         |     |   prompts, log |
+------------+---------------+     +-------+--------+
             |                             |
             | tonic gRPC over UDS, 0660 root:colony-firewall
             |   (peer credentials checked per RPC)
             v                             v
+--------------------------------------------------+
|  cfc-daemon  (systemd, root)                      |
|   - NFQUEUE intercept, out-of-order verdicts      |
|   - process resolution (sock_diag + /proc, cached)|
|   - decision engine (deterministic precedence)    |
|   - reject injection (TCP RST / ICMP unreachable) |
|   - sqlite: rules + event log                     |
|   - prompt router (sync NFQ <-> async clients)    |
+--------------------------------------------------+
```

Seven workspace crates:

| Crate         | Role                                                     |
|---------------|----------------------------------------------------------|
| `cfc-core`    | Shared types: `Rule`, `Verdict`, `Connection`, `Process` |
| `cfc-proto`   | gRPC schema (tonic + tonic-prost)                        |
| `cfc-client`  | Shared UDS gRPC client wrapper                           |
| `cfc-daemon`  | Privileged daemon                                        |
| `cfc-ui`      | iced GUI                                                 |
| `cfc-cli`     | Terminal control tool                                    |
| `cfc-tray`    | System-tray companion (StatusNotifierItem)               |

More docs:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - process model, packet
  flow, threading
- [docs/HARDENING.md](docs/HARDENING.md) - moving to a locked-down
  profile, the socket trust model, the audit trail
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) - lockout recovery,
  no-network debugging, socket permissions, fail-open vs fail-closed
- [docs/ROADMAP.md](docs/ROADMAP.md) - full phase checklist

## Install

### Arch Linux

Not on the AUR yet. Two recipes ship in `pkg/`; the `-git` one works
today, without a published release:

```sh
mkdir -p /tmp/cfc-build
cp pkg/PKGBUILD-git /tmp/cfc-build/PKGBUILD
cp pkg/colony-firewall-control.install /tmp/cfc-build/
cd /tmp/cfc-build && makepkg -si
```

`pkg/PKGBUILD` is the AUR release recipe instead: it builds from the
`v$pkgver` GitHub tag tarball, so it only resolves once that tag is
pushed, and its checksums have to be filled in with `updpkgsums` first.
See [pkg/README.md](pkg/README.md) for the submission procedure.

Either package installs everything - both units, the sysusers fragment,
the nftables snippet, the desktop entry and icon, completions and man
pages - and prints the first-run steps on install.

### Manual

```sh
cargo build --workspace --release

# Binaries
sudo install -Dm755 target/release/colony-firewalld /usr/bin/colony-firewalld
sudo install -Dm755 target/release/colony-firewall  /usr/bin/colony-firewall
sudo install -Dm755 target/release/cfc              /usr/bin/cfc
sudo install -Dm755 target/release/colony-firewall-tray /usr/bin/colony-firewall-tray

# Both units. colony-firewall-nft.service is what First run step 1
# enables; without it that step fails with "Unit ... not found".
sudo install -Dm644 systemd/colony-firewalld.service \
     /usr/lib/systemd/system/colony-firewalld.service
sudo install -Dm644 systemd/colony-firewall-nft.service \
     /usr/lib/systemd/system/colony-firewall-nft.service

# The ruleset colony-firewall-nft.service loads. The unit hardcodes this
# path, so it is not optional either.
sudo install -Dm644 systemd/nftables-snippet.conf \
     /usr/share/colony-firewall/nftables-snippet.conf

# Config, and the group that gates the control socket
sudo install -Dm644 systemd/daemon.toml.sample /etc/colony-firewall/daemon.toml
sudo install -Dm644 systemd/colony-firewall.sysusers \
     /usr/lib/sysusers.d/colony-firewall.conf
sudo systemd-sysusers

# Desktop integration: launcher, autostart entry (so prompts reach you in
# every session) and icon. Skip on a headless box.
sudo install -Dm644 pkg/colony-firewall.desktop \
     /usr/share/applications/colony-firewall.desktop
sudo install -Dm644 pkg/colony-firewall-autostart.desktop \
     /etc/xdg/autostart/colony-firewall.desktop
sudo install -Dm644 pkg/colony-firewall.svg \
     /usr/share/icons/hicolor/scalable/apps/colony-firewall.svg
sudo install -Dm644 pkg/colony-firewall-tray-autostart.desktop \
     /etc/xdg/autostart/colony-firewall-tray.desktop

sudo systemctl daemon-reload
sudo systemctl enable --now colony-firewalld

# The control socket is root:colony-firewall 0660. Join the group, then
# log out and back in, or the GUI and cfc get "permission denied".
sudo usermod -aG colony-firewall "$USER"
```

Installing only puts the binaries and daemon in place - no traffic is
filtered until you enable enforcement. See First run below.

## First run

A fresh install has **zero rules**: once enforcement is on, every new
outbound connection prompts (or falls back to the profile default). Do
these three things, in order:

**1. Enable enforcement persistently.** A companion unit loads the
nftables ruleset at boot and removes it on stop:

```sh
sudo systemctl enable --now colony-firewall-nft.service
```

Alternatively, apply the snippet by hand - but note this does **not**
survive a reboot; after restarting, the daemon runs while enforcing
nothing:

```sh
sudo nft -f /usr/share/colony-firewall/nftables-snippet.conf   # installed
sudo nft -f systemd/nftables-snippet.conf                      # from a checkout
```

**2. Seed the starter rules** so always-on system services keep working
without prompting:

```sh
sudo cfc rules bootstrap-defaults   # same as: cfc rules bundle add system
```

(`sudo` because group membership from `usermod -aG colony-firewall` only
takes effect in a new login session. After logging out and back in, plain
`cfc` works.)

This installs twelve allow rules - systemd-resolved DNS (:53),
systemd-timesyncd and chronyd NTP (:123/udp), the DHCP clients (dhcpcd,
NetworkManager and systemd-networkd, :67 and :547/udp), pacman and paru
HTTPS mirrors (:443/tcp), and the SSH client (:22/tcp) - and is
idempotent (already-present rules are skipped by name; `--dry-run`
previews). **Do not skip this step.** No profile allows anything on its
own, so on a machine with no rules and no UI connected nothing outbound
gets through - including the DHCP lease. Filtering starts before the
network is configured (see below), and these rules are what let the
machine come up at all.

For everything else, there are bundles:

```sh
cfc rules bundle list                 # what there is, and what applies here
cfc rules bundle add web --dry-run    # preview
sudo cfc rules bundle add web         # installed browsers -> 443 and 80
sudo cfc rules bundle add dev         # git, cargo, npm, pip, docker
sudo cfc rules bundle add updates     # apt, dnf, flatpak, yay
sudo cfc rules bundle remove web      # exactly the rules that bundle owns
```

Two properties worth knowing. **Every rule names an executable** - there
is no way to write "allow tcp/443" here, because a payload phoning home
uses 443 exactly like a browser does and a port-shaped rule cannot tell
them apart. And entries whose program is not installed on this machine
are **skipped and reported**, so "4 added, 10 skipped" is the normal
outcome of `bundle add web` on a box with two browsers.

**3. Give prompts somewhere to go.** On a desktop, launch the GUI:

```sh
colony-firewall
```

On a headless machine, answer them from the terminal instead:

```sh
cfc prompts
```

With no subscriber at all the daemon applies `no_ui_action` to every
unmatched flow without asking anyone. **That is a denial under every
profile.** "Nobody is connected" is a permanent condition on a headless
box, not a passing one, and answering it with an allow would mean those
hosts had no outbound firewall whatsoever. Stored rules are what such a
machine runs on; `cfc prompts` is how you add more without a GUI.

This cannot lock you out of a remote machine: the ruleset hooks `output`
on `ct state new` only, so an inbound SSH session's replies are
`ct state established` and are never queued.

**Boot behaviour.** Both units are ordered `Before=network-pre.target`,
the systemd convention for firewalls: every network-configuration
service (NetworkManager, systemd-networkd, dhcpcd) is
`After=network-pre.target`, so the daemon and its nftables ruleset are
in place before any interface is configured. There is no window at boot
where the network is up but filtering is not - the same guarantee
Windows' built-in firewall provides with its boot-time filters. During
that early phase no UI is connected, so unmatched flows resolve via
`no_ui_action` - a denial - and the bootstrap DHCP/DNS/NTP rules are
what keep the machine bootable.

Then confirm it is really filtering:

```sh
cfc status     # "enforcing yes", and it warns on stderr when it is not
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
# Status: version, uptime, whether it is actually enforcing, policy
cfc status

# Answer prompts from this terminal - no GUI needed.
# a=allow d=deny r=reject s=skip q=quit, then duration and scope.
cfc prompts

# Add a rule from the command line
cfc rules add --action allow --exe /usr/bin/curl --dst-port 443

# Rules take an id, a unique id prefix, or the rule's name
cfc rules show curl-https
cfc rules disable 3f2a

# Watch traffic decisions in real time (colorized), with filters
cfc live --denied
cfc live --exe firefox --follow

# What has this machine been talking to?
cfc log --since 24h
cfc log --exe firefox --action deny

# Pause enforcement for a bounded window (the daemon auto-resumes)
cfc pause --for 30m
cfc resume

# Back up rules
cfc rules export --out rules.json

# Migrate from an existing opensnitch install
cfc rules import-opensnitch /etc/opensnitchd/rules
```

### Scripting

Every command takes `--json` (or `-o json`). One-shot commands print a
single JSON document; the streaming ones (`live`, `prompts`) print NDJSON,
one object per line, flushed as events arrive:

```sh
cfc --json status | jq .enforcing
cfc --json log --since 1h --action deny | jq -r '.[].exe' | sort | uniq -c
cfc --json live --denied | jq -r '"blocked: \(.exe)"'
```

Exit codes are a contract, so failures are distinguishable without
parsing stderr:

| Code | Meaning                                                  |
|------|----------------------------------------------------------|
| 0    | success                                                  |
| 1    | runtime or RPC error                                     |
| 2    | usage error (bad flags or arguments)                     |
| 3    | not found (no rule matches that id, prefix or name)      |
| 4    | daemon unreachable (not running, stale socket, no access)|

Shell completions and man pages are generated by the binary itself, so
they cannot drift from the CLI. The PKGBUILD installs both; building by
hand, generate them with:

```sh
cfc completions bash > /usr/share/bash-completion/completions/cfc
cfc completions zsh  > /usr/share/zsh/site-functions/_cfc
cfc completions fish > /usr/share/fish/vendor_completions.d/cfc.fish
cfc man --dir /usr/share/man/man1
```

## Profiles

`daemon.toml` accepts a `profile` key with three presets:

| Profile  | No UI    | Timeout  | Window |
|----------|----------|----------|--------|
| relaxed  | Allow    | Deny     | 60s    |
| balanced | Allow    | Deny     | 30s    | (default)
| strict   | Deny     | Deny     | 15s    |

Every profile denies on timeout: a prompt you were shown and did not
answer must not become an allow. The profiles differ in how long they
wait, and in what happens when there is nobody subscribed to ask.

Use `strict` only when you always have the UI running (or `cfc prompts`),
otherwise you lose network when the daemon starts before a subscriber
does (fail-closed posture).

A profile is a base, not a lock: any field you set under
`[default_policy]` overrides just that field. All three hot-reload on
`SIGHUP`, so you can retune the policy without dropping a packet.

## Development

Requires Rust stable (MSRV 1.88, gated in CI) and `protobuf-compiler`.
On Debian/Ubuntu:

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

| Phase                        | State |
|------------------------------|-------|
| 0  Foundation                | done  |
| 1  Daemon MVP                | done  |
| 2  UI MVP                    | done  |
| 3  CLI                       | done  |
| 3.5 Hardening & correctness  | done  |
| 4  eBPF backend              | done; compiled in by default, gated by `[ebpf] enabled` |
| 5a CI                        | done  |
| 5b Packaging                 | in progress (AUR-ready PKGBUILD in `pkg/`, not yet published) |
| 5  Polish                    | done, except VirusTotal (opt-in lookup, not started) |

Two honest caveats:

- The Arch package is built end to end on every push (`makepkg` on the
  `-git` recipe), but it has never been published to the AUR, so the
  release recipe's tag tarball and checksums are only exercised at tag
  time.
- The end-to-end test in CI drives a `--dry-run` daemon, so it proves the
  gRPC and CLI surface, not that a packet is really dropped. Verifying a
  live DROP/ACCEPT still means loading the nftables snippet on a real
  machine by hand.

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
