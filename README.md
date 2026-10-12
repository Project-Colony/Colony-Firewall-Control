<div align="center">

# Colony Firewall Control

**An outbound firewall for Linux desktops and servers that asks before a program reaches the network, and remembers the answer.**

</div>

[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Colony app](https://img.shields.io/badge/Colony-security-purple)](https://github.com/Project-Colony/Colony)
[![Platforms](https://img.shields.io/badge/platforms-linux-lightgrey)](#installation)

Linux ships no outbound firewall that works per program: ufw, firewalld and
plain nftables decide by address and port, so a browser and a payload phoning
home on port 443 look the same to them, and opensnitch, the closest
equivalent of Windows Firewall Control, needs a Go daemon plus a 200 MB PyQt5
GUI. Colony Firewall Control is a Rust port of the opensnitch model: the
kernel queues every new connection, a root daemon decides it from rules that
name the program, and an [iced](https://iced.rs/) app, a tray icon or the
terminal asks you about the rest.

> **Status:** the daemon, the app, the tray and the `cfc` CLI cover outbound
> filtering end to end, and opt-in inbound filtering. CI tests real packet
> verdicts on a live NFQUEUE in a network namespace, loads the eBPF layer on
> several kernels and installs the RPM end to end on Fedora; the app and the
> tray are covered by unit tests only. Nothing is published on the AUR yet: use the
> release tarball or build the PKGBUILD each release carries. The copy Colony
> installs is a read-only monitor (see [Via Colony](#via-colony-recommended)).
> Explicit application confinement is experimental. Releases after 0.8.0 are
> signed with the organisation key.

## Why Colony Firewall Control

- **Rules name programs, not just ports.** A rule names the executable that
  connects, checked against the image actually running, so allowing a
  browser on 443 does not allow everything else on 443. An Allow rule that
  names no program takes an administrator password.
- **One Rust workspace instead of Go plus PyQt.** The daemon, the app, the
  tray and `cfc` share one gRPC schema over a Unix socket, and the root
  daemon that parses untrusted packets is memory-safe.
- **Headless machines are first class.** `sudo cfc prompts` answers prompts
  over SSH, and every command takes `--json`.
- **It fails closed, and says so.** With the daemon down, new non-loopback
  connections drop instead of passing, and `cfc status` and the app say when
  nothing is being enforced.

```
+----------------------------+     +----------------+
|  cfc-ui   (iced, user)     |     |  cfc (tty)     |
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

## What it does

- Per-application outbound filtering with NFQUEUE intercept
- Live pop-ups for unknown connections, persistent rules for known ones
- iced GUI with parchment / burgundy theme, four tabs (Prompts / Rules /
  Live / Stats), a countdown on every prompt, and desktop notifications
  when the window is hidden
- **Answer prompts from a terminal** (`sudo cfc prompts`) - headless servers
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
- **Optional eBPF backend**: exec tracking and DNS response diagnostics
  from inside the kernel supplement `/proc` attribution; uncorrelated DNS
  observations never supply policy identity
- Memory-safe Rust top to bottom for a root daemon parsing untrusted packets

## Installation

### Via Colony (recommended)

Search for **Colony Firewall Control** in
[Colony](https://github.com/Project-Colony/Colony) (category Security) and
install it. Colony installs the app for your user and keeps it updated.

A firewall also needs parts that Colony, which runs nothing as root, cannot
install: the daemon, its systemd units, the nftables ruleset, the
`colony-firewall` group and the polkit policy. Install those from the
[release tarball](#direct-binary-download), the
[Arch recipe](#arch-linux-aur) or a [source build](#build-from-source), then
follow [First run](docs/guide/first-run.md#first-run). The copy Colony
installs is a read-only monitor: it shows the status, prompts, rules and
live traffic, but the daemon accepts changes only from the root-owned
`/usr/bin/colony-firewall` and `/usr/bin/colony-firewall-tray` that the
packages install, and the app shows the daemon's reason when it refuses one.

### Arch Linux (AUR)

Not published on the AUR yet. Each release carries the recipe CI built
against its tag, with the real source checksum (`PKGBUILD` and `SRCINFO`);
[packaging/README.md](packaging/README.md#arch-linux-aur) shows how to build
it. From a checkout, the `-git` recipe builds the current source:

```sh
build=$(mktemp -d)
cp packaging/arch/PKGBUILD-git "$build"/PKGBUILD
cp packaging/arch/colony-firewall-control.install "$build"/
cd "$build" && makepkg -si
```

Either package installs everything except the eBPF object - the three
units, the sysusers fragment, both nftables rulesets and the inbound
lockout guard, the polkit policy, the desktop entries and icon,
completions and man pages - and prints the first-run steps on install.
Without the object the daemon runs on `sock_diag` + `/proc`; the release
tarball ships it, see [packaging/README.md](packaging/README.md#release-tarball).

### Direct binary download

Grab the assets from the [latest release](../../releases/latest):

| Asset | What it is |
|---|---|
| `colony-firewall-control-<V>-linux-x86_64.tar.zst` | everything: the daemon, the app, the tray, `cfc`, the units, the eBPF object and an `install.sh` |
| `colony-firewall-control-linux` | the app alone, x86_64; the file Colony installs |
| `PKGBUILD`, `SRCINFO` | the Arch recipe for this release |
| `SHA256SUMS` | sha256 of the tarball and of the app |

Check a download as described under [Code signing policy](#code-signing-policy),
then install the tarball as root:

```sh
tar --zstd -xf colony-firewall-control-<V>-linux-x86_64.tar.zst
cd colony-firewall-control-<V>-linux-x86_64
sudo ./install.sh      # then First run
```

`sudo ./uninstall.sh` from the same directory removes it again. What the
tarball contains and how its scripts are generated:
[packaging/README.md](packaging/README.md#release-tarball).

### Build from source

```sh
git clone https://github.com/Project-Colony/Colony-Firewall-Control
cd Colony-Firewall-Control
cargo build --workspace --release --locked
```

Requires Rust 1.89 or newer and `protobuf-compiler`. Installing the build by
hand (binaries, units, nftables ruleset, group, polkit policy) is in
[docs/guide/first-run.md](docs/guide/first-run.md#manual-install); building
and testing for development is in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Documentation

Full documentation is in [docs/](docs/). Start at
[docs/README.md](docs/README.md): first run, the CLI, profiles, hardening,
troubleshooting and the architecture.

## Code signing policy

Every release asset is signed by the Project Colony organisation in CI, never on
a developer machine. Next to each asset on the release page:

| File | What it is |
|---|---|
| `<asset>.sig` | an ed25519 signature over the asset, made with the organisation's release key |
| `<asset>.meta` | three lines binding the asset to its file name, its sha256 and the release version |
| `<asset>.meta.sig` | an ed25519 signature over the `.meta` |

The private key is an organisation secret, used only by the shared
[sign-and-publish workflow](https://github.com/Project-Colony/Project-Colony-Resources/blob/main/.github/workflows/sign-and-publish.yml)
in a job that builds nothing; the jobs that compile Colony Firewall Control
never see it. Colony checks all three files before it installs or updates
Colony Firewall Control, and refuses a release older than the one installed.
To check a download yourself with OpenSSL 3 (the same commands work for every
asset):

```bash
cat > colony-release.pub <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARNjg3Nn8H6/aBg1unwGjkUTcrdTxERNefVaqU8cFu0s=
-----END PUBLIC KEY-----
EOF
a=colony-firewall-control-linux
openssl pkeyutl -verify -pubin -inkey colony-release.pub -rawin -in "$a" -sigfile "$a.sig"
openssl pkeyutl -verify -pubin -inkey colony-release.pub -rawin -in "$a.meta" -sigfile "$a.meta.sig"
cat "$a.meta"     # version=<tag>, asset=<file name>, sha256=<digest>
sha256sum "$a"    # the digest must equal the sha256 line
```

Releases up to 0.8.0 predate this policy and carry no signatures. The app and
the tarball also carry a build provenance attestation, see
[SECURITY.md](SECURITY.md#verifying-releases).

How releases are built, signed and published:
[design/releases.md](https://github.com/Project-Colony/Project-Colony-Resources/blob/main/design/releases.md#5-signing).

## Privacy

Colony Firewall Control sends no telemetry, no analytics and no crash
reports, checks for no updates and has no server of its own. What it keeps
stays on this machine:

| Data | Stored or sent | Where, and why |
|---|---|---|
| Rules | stored | `/var/lib/colony-firewall/rules.db`, readable by root only: what you allowed or blocked, with program paths, and a hash for rules pinned to a binary |
| Connection log | stored | the same database. For every decided flow: the time, protocol, source and destination address and port, destination host name, program path, pid, uid, verdict and deciding rule. `cfc log` reads it. Capped at `[events] max_rows` rows (100000 by default), oldest first; set it to 0 in `/etc/colony-firewall/daemon.toml` and restart the daemon to keep none |
| System journal | stored | blocked connections (program, pid, uid, destination) and every accepted or refused change (who asked, which program, the polkit answer), through systemd-journald like any service log |
| Host names | sent | the daemon names a destination by a reverse (PTR) lookup, confirmed by a forward lookup, through the system resolver, so your DNS server sees those lookups. With the eBPF layer on, DNS answers this machine receives are also read in the kernel; they stay in the daemon's memory |
| App and tray | stored | no files. The tray writes its icon to `$XDG_RUNTIME_DIR/cfc-tray/icons`, which lives in memory until you log out, only when the icon theme lacks it |
| Rule exports | stored | only where `cfc rules export --out` is told to write |

The app, the tray and `cfc` talk to the daemon only through the local socket
`/run/colony-firewall/cfc.sock` (`root:colony-firewall`, 0660). Colony
Firewall Control connects to no server: the DNS lookups above are the only
network traffic it causes itself.

## License

GPL-3.0-or-later, see [LICENSE](LICENSE). Inherited from
[opensnitch](https://github.com/evilsocket/opensnitch) since this is a
derivative port.

### Credits

- [opensnitch](https://github.com/evilsocket/opensnitch) by Simone
  Margaritelli (evilsocket) and Gustavo Iniguez Goia - the project we are
  porting.
- The Rust [tonic](https://github.com/hyperium/tonic),
  [aya](https://github.com/aya-rs/aya), [iced](https://iced.rs/), and
  [nfq](https://crates.io/crates/nfq) crates.
