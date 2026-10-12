# Development

Requires Rust stable (MSRV 1.89, gated in CI) and `protobuf-compiler`.
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
daemon that just reports rules and a stub status feed. Point its rule
database somewhere writable (the default is under `/var/lib`), and point
the clients at its socket: `cfc` takes `--socket`, the GUI and tray read
`CFC_SOCKET`. A daemon running as your own user accepts changes from
anything else you run, a development build of the GUI included:

```sh
mkdir -p /tmp/cfc-dev
printf '[storage]\npath = "/tmp/cfc-dev/rules.db"\n' > /tmp/cfc-dev/daemon.toml
cargo run -p cfc-daemon -- --debug --dry-run \
    --config /tmp/cfc-dev/daemon.toml --socket /tmp/cfc-dev/cfc.sock
# in another terminal
CFC_SOCKET=/tmp/cfc-dev/cfc.sock cargo run -p cfc-ui
cargo run -p cfc -- --socket /tmp/cfc-dev/cfc.sock status
```

## What CI tests

`check.yml` runs on every push and pull request: rustfmt, clippy, the test
suite with and without the eBPF feature, the release-profile build, the MSRV
build, the version and release-asset consistency scripts, and the packaging
lints plus a full `makepkg` of `PKGBUILD-git`. `ebpf.yml` builds the BPF
object with the pinned nightly and loads it on the runner kernel and on
other kernels in a VM. `rhel.yml` compiles the SELinux module, builds the
source RPM and installs the package end to end on Fedora. `deny.yml` runs
`cargo deny` against the RustSec advisory database.

Real packet verdicts are tested in CI. The `e2e` workflow
(`.github/workflows/e2e.yml`) runs `scripts/armed-e2e.sh` on pushes to
`main` and on pull requests: it loads the shipped nftables snippet in a throwaway network
namespace, runs the daemon (built without the eBPF layer) on a real NFQUEUE
and asserts that an allowed flow gets HTTP 200, while a denied or unmatched
one is silently dropped (curl exit 28). It also checks that new flows drop
before the daemon starts and after it stops on SIGTERM or is killed with
SIGKILL, that rules survive a restart, that the event log names the deciding
rule and that new loopback flows still pass with no daemon. The separate
`smoke` workflow drives a `--dry-run` daemon to cover the gRPC and CLI
surface.

The Arch package is built end to end on every push
(`makepkg` on the `-git` recipe), but it has never been published to the
AUR, so the release recipe's tag tarball and checksums are only exercised
at tag time.

The release workflow and what it publishes are described in
[packaging](packaging.md#releases). The phase checklist
is [roadmap](../project/roadmap.md).
