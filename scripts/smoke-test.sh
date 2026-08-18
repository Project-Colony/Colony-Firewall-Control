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

# Runs a command and asserts its exit status. The CLI's exit codes are a
# contract (0 ok, 1 runtime, 2 usage, 3 not found, 4 unreachable), so they
# are tested like any other output.
expect_exit() {
    local want="$1"; shift
    local rc=0
    "$@" >/dev/null 2>&1 || rc=$?
    if [[ "${rc}" -ne "${want}" ]]; then
        echo "expected exit ${want}, got ${rc}, from: $*"
        exit 1
    fi
}

if command -v jq >/dev/null 2>&1; then
    HAVE_JQ=1
else
    HAVE_JQ=0
    echo "note: jq not found; JSON output will only be checked for non-emptiness"
fi

say "Building workspace"
cargo build --workspace --profile fast --locked --quiet

DAEMON="${ROOT}/target/fast/colony-firewalld"
CFC="${ROOT}/target/fast/cfc"

# Offline surface: these must work with no daemon at all (packaging runs
# them against a freshly built binary).
say "cfc completions + man (no daemon required)"
for shell in bash zsh fish; do
    "${CFC}" completions "${shell}" >"${TMPDIR}/comp.${shell}"
    test -s "${TMPDIR}/comp.${shell}" || { echo "empty ${shell} completions"; exit 1; }
done
"${CFC}" man >"${TMPDIR}/cfc.1"
test -s "${TMPDIR}/cfc.1" || { echo "empty man page"; exit 1; }
grep -q '^\.TH cfc 1' "${TMPDIR}/cfc.1" || { echo "man page has no .TH header"; exit 1; }
# The packaging path: one page per subcommand, so the cross references in
# cfc.1 resolve after install.
"${CFC}" man --dir "${TMPDIR}/man"
for page in cfc.1 cfc-rules.1 cfc-rules-show.1 cfc-prompts.1 cfc-log.1; do
    test -s "${TMPDIR}/man/${page}" || { echo "missing man page ${page}"; exit 1; }
done

say "exit code 4 when the daemon is unreachable"
expect_exit 4 "${CFC}" --socket "${TMPDIR}/definitely-not-here.sock" status
say "exit code 2 on a usage error"
expect_exit 2 "${CFC}" --socket "${SOCKET}" rules bogus-subcommand

cat >"${CONFIG}" <<EOF
profile = "balanced"
[storage]
path = "${DB}"
[ipc]
# This test runs unprivileged against a socket in a temp dir, so it can be
# neither root-owned nor gated by the colony-firewall group. Without this
# the daemon (correctly) refuses every mutating RPC and the test can only
# exercise the read-only half of the CLI. Production keeps the default.
require_group = false
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

say "cfc status --json"
STATUS_JSON="$("${CFC}" --socket "${SOCKET}" status --json)"
test -n "${STATUS_JSON}" || { echo "status --json was empty"; exit 1; }
if [[ "${HAVE_JQ}" -eq 1 ]]; then
    echo "${STATUS_JSON}" | jq -e '.version and (.paused == false)' >/dev/null \
        || { echo "status --json missing version/paused"; exit 1; }
    # --dry-run never binds NFQUEUE, so the daemon must admit it is not
    # enforcing and the CLI must carry that through.
    echo "${STATUS_JSON}" | jq -e '.enforcing == false' >/dev/null \
        || { echo "expected enforcing=false under --dry-run"; exit 1; }
    echo "${STATUS_JSON}" | jq -e 'has("skipped_rules") and has("timeout_action")' \
        >/dev/null || { echo "status --json missing wave-3 fields"; exit 1; }
fi

say "cfc rules list (empty)"
"${CFC}" --socket "${SOCKET}" rules list

say "cfc rules bootstrap-defaults --dry-run"
"${CFC}" --socket "${SOCKET}" rules bootstrap-defaults --dry-run

say "cfc rules bootstrap-defaults (real)"
"${CFC}" --socket "${SOCKET}" rules bootstrap-defaults

say "cfc rules list (post-bootstrap)"
"${CFC}" --socket "${SOCKET}" rules list

say "cfc rules list --json"
RULES_JSON="$("${CFC}" --socket "${SOCKET}" rules list --json)"
if [[ "${HAVE_JQ}" -eq 1 ]]; then
    echo "${RULES_JSON}" | jq -e 'type == "array" and length > 0' >/dev/null \
        || { echo "rules list --json is not a non-empty array"; exit 1; }
    echo "${RULES_JSON}" | jq -e '.[0] | has("id") and has("name") and has("scope")' \
        >/dev/null || { echo "rules list --json rows are missing fields"; exit 1; }
fi

say "cfc rules add"
"${CFC}" --socket "${SOCKET}" rules add \
    --action deny --dst-port 25 --protocol tcp --name 'smoke-block-smtp'

say "cfc rules show (by name)"
"${CFC}" --socket "${SOCKET}" rules show smoke-block-smtp
"${CFC}" --socket "${SOCKET}" rules show smoke-block-smtp --json >"${TMPDIR}/show.json"
if [[ "${HAVE_JQ}" -eq 1 ]]; then
    jq -e '.name == "smoke-block-smtp" and .action == "deny" and has("hit_count")' \
        "${TMPDIR}/show.json" >/dev/null \
        || { echo "rules show --json is missing fields"; exit 1; }
fi

say "cfc rules export"
EXPORT="${TMPDIR}/export.json"
"${CFC}" --socket "${SOCKET}" rules export --out "${EXPORT}"
test -s "${EXPORT}" || { echo "export was empty"; exit 1; }

say "cfc rules import --replace"
"${CFC}" --socket "${SOCKET}" rules import --replace "${EXPORT}"

say "cfc rules list (post-roundtrip)"
"${CFC}" --socket "${SOCKET}" rules list

# Pick the first rule id. The list prints a short id in column 1, which
# must be enough to act on: everything below resolves by prefix.
if [[ "${HAVE_JQ}" -eq 1 ]]; then
    FULL_ID="$("${CFC}" --socket "${SOCKET}" rules list --json | jq -r '.[0].id')"
else
    FULL_ID=""
fi
SHORT_ID="$("${CFC}" --socket "${SOCKET}" rules list \
    | awk 'NR>1 && NF>0 {print $1; exit}')"

if [[ -n "${SHORT_ID}" ]]; then
    say "cfc rules show ${SHORT_ID} (id prefix)"
    "${CFC}" --socket "${SOCKET}" rules show "${SHORT_ID}"

    say "cfc rules disable/enable ${SHORT_ID} (idempotent)"
    "${CFC}" --socket "${SOCKET}" rules disable "${SHORT_ID}" | grep -q 'disabled' \
        || { echo "expected disable to report the new state"; exit 1; }
    "${CFC}" --socket "${SOCKET}" rules disable "${SHORT_ID}" | grep -q 'already disabled' \
        || { echo "expected the second disable to be a no-op"; exit 1; }
    "${CFC}" --socket "${SOCKET}" rules enable "${SHORT_ID}" | grep -q 'enabled' \
        || { echo "expected enable to report the new state"; exit 1; }
    "${CFC}" --socket "${SOCKET}" rules enable "${SHORT_ID}" | grep -q 'already enabled' \
        || { echo "expected the second enable to be a no-op"; exit 1; }

    say "cfc rules toggle ${SHORT_ID}"
    "${CFC}" --socket "${SOCKET}" rules toggle "${SHORT_ID}"
    say "cfc rules toggle ${SHORT_ID} (flip back)"
    "${CFC}" --socket "${SOCKET}" rules toggle "${SHORT_ID}"

    if [[ -n "${FULL_ID}" ]]; then
        say "cfc rules remove ${FULL_ID} (full id)"
        "${CFC}" --socket "${SOCKET}" rules remove "${FULL_ID}"
    else
        say "cfc rules remove ${SHORT_ID}"
        "${CFC}" --socket "${SOCKET}" rules remove "${SHORT_ID}"
    fi
fi

say "exit code 3 for an unknown rule"
expect_exit 3 "${CFC}" --socket "${SOCKET}" rules remove 00000000-dead-beef-0000-000000000000
expect_exit 3 "${CFC}" --socket "${SOCKET}" rules show no-such-rule-name
expect_exit 3 "${CFC}" --socket "${SOCKET}" rules enable no-such-rule-name

say "cfc log"
"${CFC}" --socket "${SOCKET}" log --limit 5
"${CFC}" --socket "${SOCKET}" log --limit 5 --since 2h --action deny >/dev/null
LOG_JSON="$("${CFC}" --socket "${SOCKET}" log --limit 5 --json)"
if [[ "${HAVE_JQ}" -eq 1 ]]; then
    echo "${LOG_JSON}" | jq -e 'type == "array"' >/dev/null \
        || { echo "log --json is not an array"; exit 1; }
fi
say "exit code 2 for a bad --since"
expect_exit 2 "${CFC}" --socket "${SOCKET}" log --since banana

say "cfc live (connects, then is interrupted)"
# No traffic flows in --dry-run, so the stream stays open: a timeout kill
# (124) is the success case here, anything else means it fell over.
LIVE_RC=0
timeout 2 "${CFC}" --socket "${SOCKET}" live --json >/dev/null 2>&1 || LIVE_RC=$?
if [[ "${LIVE_RC}" -ne 124 ]]; then
    echo "expected cfc live to keep running until the timeout (got ${LIVE_RC})"
    exit 1
fi

say "cfc pause --for 30s"
"${CFC}" --socket "${SOCKET}" pause --for 30s
"${CFC}" --socket "${SOCKET}" status | grep -E "paused\s+yes \(resumes in" >/dev/null \
    || { echo "expected status to show a pause countdown"; exit 1; }
if [[ "${HAVE_JQ}" -eq 1 ]]; then
    "${CFC}" --socket "${SOCKET}" status --json \
        | jq -e '.paused == true and .resume_in_seconds > 0' >/dev/null \
        || { echo "expected status --json to report a resume countdown"; exit 1; }
fi

say "cfc resume"
"${CFC}" --socket "${SOCKET}" resume
"${CFC}" --socket "${SOCKET}" status | grep -E "paused\s+no" >/dev/null \
    || { echo "expected status to show paused=no after resume"; exit 1; }

say "Smoke test passed"
