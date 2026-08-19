#!/usr/bin/env bash
# Print the path of the cfc-daemon lib test binary, building it if needed.
#
# The root-only eBPF tests are `#[ignore]`d, so they are run by invoking the
# compiled test binary directly under sudo/setpriv rather than through
# `cargo test`. Finding that binary by globbing `target/*/deps/cfc_daemon-*`
# is a trap: the glob also matches binaries left over from earlier compiles,
# and running a stale one fails or - worse - passes, against code that is no
# longer in the tree. Ask cargo instead.
#
# Usage: scripts/ebpf-test-binary.sh [--profile <name>]
set -euo pipefail

PROFILE="fast"
while [[ $# -gt 0 ]]; do
    case "$1" in
    --profile)
        PROFILE="$2"
        shift 2
        ;;
    *)
        echo "usage: $0 [--profile <name>]" >&2
        exit 2
        ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# Build first; the JSON pass below is then a cheap no-op re-run that only
# reports where things landed.
cargo test -p cfc-daemon --profile "${PROFILE}" --locked --no-run >&2

BIN="$(cargo test -p cfc-daemon --profile "${PROFILE}" --locked --no-run \
    --message-format=json 2>/dev/null |
    python3 -c '
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    target = msg.get("target", {})
    if (
        msg.get("profile", {}).get("test")
        and target.get("kind") == ["lib"]
        and target.get("name") == "cfc_daemon"
    ):
        print(msg["executable"])
' | tail -1)"

if [[ -z "${BIN}" || ! -x "${BIN}" ]]; then
    echo "error: could not locate the cfc-daemon test binary" >&2
    exit 1
fi

printf '%s\n' "${BIN}"
