#!/usr/bin/env bash
# End-to-end smoke test for Colony Firewall Control.
#
# Spawns colony-firewalld in --dry-run mode (no NFQUEUE bind, no root
# required), then drives it through every cfc-cli subcommand. Tears down
# at the end. Exits non-zero on any failure.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
SOCKET="${TMPDIR}/cfc.sock"
CONFIG="${TMPDIR}/daemon.toml"
DB="${TMPDIR}/rules.db"
LOG="${TMPDIR}/daemon.log"

cleanup() {
    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

say() { printf '\n=== %s ===\n' "$*"; }

say "Building workspace"
cargo build --workspace --profile fast --quiet

DAEMON="${ROOT}/target/fast/colony-firewalld"
CFC="${ROOT}/target/fast/cfc"

cat >"${CONFIG}" <<EOF
profile = "balanced"
[storage]
path = "${DB}"
EOF

say "Starting daemon (--dry-run)"
"${DAEMON}" --debug --dry-run --config "${CONFIG}" --socket "${SOCKET}" \
    >"${LOG}" 2>&1 &
DAEMON_PID=$!

# Wait for the UDS to appear.
for i in $(seq 1 50); do
    if [[ -S "${SOCKET}" ]]; then
        break
    fi
    sleep 0.1
done
if [[ ! -S "${SOCKET}" ]]; then
    echo "daemon never created ${SOCKET}"; tail "${LOG}"; exit 1
fi

say "cfc status"
"${CFC}" --socket "${SOCKET}" status

say "cfc rules list (empty)"
"${CFC}" --socket "${SOCKET}" rules list

say "cfc rules bootstrap-defaults --dry-run"
"${CFC}" --socket "${SOCKET}" rules bootstrap-defaults --dry-run

say "cfc rules bootstrap-defaults (real)"
"${CFC}" --socket "${SOCKET}" rules bootstrap-defaults

say "cfc rules list (post-bootstrap)"
"${CFC}" --socket "${SOCKET}" rules list

say "cfc rules add"
"${CFC}" --socket "${SOCKET}" rules add \
    --action deny --dst-port 25 --protocol tcp --name 'smoke-block-smtp'

say "cfc rules export"
EXPORT="${TMPDIR}/export.json"
"${CFC}" --socket "${SOCKET}" rules export --out "${EXPORT}"
test -s "${EXPORT}" || { echo "export was empty"; exit 1; }

say "cfc rules import --replace"
"${CFC}" --socket "${SOCKET}" rules import --replace "${EXPORT}"

say "cfc rules list (post-roundtrip)"
"${CFC}" --socket "${SOCKET}" rules list

# Pick the first rule id and exercise toggle + remove.
FIRST_ID="$("${CFC}" --socket "${SOCKET}" rules list \
    | awk 'NR>2 && NF>0 {print $1; exit}')"
if [[ -n "${FIRST_ID}" ]]; then
    say "cfc rules toggle ${FIRST_ID}"
    "${CFC}" --socket "${SOCKET}" rules toggle "${FIRST_ID}"
    say "cfc rules toggle ${FIRST_ID} (flip back)"
    "${CFC}" --socket "${SOCKET}" rules toggle "${FIRST_ID}"
    say "cfc rules remove ${FIRST_ID}"
    "${CFC}" --socket "${SOCKET}" rules remove "${FIRST_ID}"
fi

say "Smoke test passed"
