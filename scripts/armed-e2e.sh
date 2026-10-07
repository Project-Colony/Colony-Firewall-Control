#!/usr/bin/env bash
# Armed end-to-end test: real NFQUEUE verdicts, not --dry-run.
#
# Everything filtered lives in a throwaway network namespace, so the host's
# own traffic (the CI runner's connection to GitHub, an SSH session) never
# meets the fail-closed table. Two namespaces joined by a veth pair:
#   FW   the shipped nftables snippet, colony-firewalld and curl
#   SRV  three HTTP servers, no filtering
# Needs sudo (passwordless on GitHub runners). Never runs nft outside FW.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DAEMON="${ROOT}/target/debug/colony-firewalld"
CFC="${ROOT}/target/debug/cfc"
FW="cfc-e2e-fw-$$"
SRV="cfc-e2e-srv-$$"
SRV_IP=10.200.0.2
ALLOW_PORT=8080      # allow rule
DENY_PORT=8081       # deny rule
UNMATCHED_PORT=8082  # no rule: balanced profile, nobody subscribed -> Deny
LO_PORT=8083         # 127.0.0.1 inside FW, last step only
W="$(mktemp -d "${RUNNER_TEMP:-/tmp}/cfc-e2e.XXXXXX")"
SOCK="${W}/cfc.sock"

fail() { echo "FAIL: $*" >&2; exit 1; }
say() { printf '\n=== %s ===\n' "$*"; }
in_fw() { sudo ip netns exec "${FW}" "$@"; }
in_srv() { sudo ip netns exec "${SRV}" "$@"; }
cfc() { sudo "${CFC}" --socket "${SOCK}" "$@"; }
table_loaded() { in_fw nft list table inet colony_firewall >/dev/null; }
# Kernel truth, not a log line: is anything bound to NFQUEUE 0 in FW?
queue_bound() {
    in_fw awk '$1 == 0 { b = 1 } END { exit !b }' \
        /proc/net/netfilter/nfnetlink_queue 2>/dev/null
}

# curl from inside FW as the unprivileged runner user. Prints the HTTP code
# and returns curl's exit status.
probe() {
    in_fw setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups \
        curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' \
        --connect-timeout 3 --max-time 6 "http://${SRV_IP}:$1/"
}
expect_200() {
    local code
    code="$(probe "$1")" || fail "port $1: curl failed, expected HTTP 200"
    [[ "${code}" == 200 ]] || fail "port $1: got HTTP ${code}, expected 200"
}
# 28 = connect timeout: the SYN vanished. 7 (refused) would mean an RST came
# back, i.e. something answered instead of dropping.
expect_drop() {
    local rc=0
    probe "$1" >/dev/null 2>&1 || rc=$?
    [[ "${rc}" -eq 28 ]] || fail "port $1: curl exit ${rc}, expected 28 (silently dropped)"
}

start_daemon() {
    # The inner sh writes its own PID and then execs the daemon, so the file
    # names the daemon itself (pkill -x cannot: comm is cut to 15 characters).
    # shellcheck disable=SC2016 # $$, $0 and $@ belong to the inner sh
    in_fw sh -c 'echo $$ >"$0"; exec "$@"' "${W}/daemon.pid" \
        "${DAEMON}" --debug --config "${W}/daemon.toml" --socket "${SOCK}" \
        >"${W}/$1.log" 2>&1 &
    DAEMON_JOB=$!
    for _ in $(seq 1 150); do
        queue_bound && cfc status >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    fail "daemon did not bind NFQUEUE 0 and its socket within 30s"
}
stop_daemon() {
    local pid
    pid="$(sudo cat "${W}/daemon.pid")"
    sudo kill -"$1" "${pid}"
    for _ in $(seq 1 100); do
        sudo kill -0 "${pid}" 2>/dev/null || break
        sleep 0.2
    done
    if sudo kill -0 "${pid}" 2>/dev/null; then fail "daemon survived SIG$1 for 20s"; fi
    wait "${DAEMON_JOB}" 2>/dev/null || true
    sudo rm -f "${W}/daemon.pid"
}

cleanup() {
    local rc=$?
    if sudo test -s "${W}/daemon.pid"; then
        sudo kill -KILL "$(sudo cat "${W}/daemon.pid")" 2>/dev/null || true
    fi
    for ns in "${SRV}" "${FW}"; do
        sudo ip netns pids "${ns}" 2>/dev/null | xargs -r sudo kill 2>/dev/null || true
    done
    sudo ip netns del "${FW}" 2>/dev/null || true
    sudo ip netns del "${SRV}" 2>/dev/null || true
    if [[ "${rc}" -ne 0 ]]; then
        for f in "${W}"/*.log; do
            [[ -e "${f}" ]] || continue
            echo "--- ${f} (last 200 lines)"
            tail -n 200 "${f}"
        done
    fi
    sudo rm -rf "${W}"
}
trap cleanup EXIT

sudo -v
command -v jq >/dev/null || fail "jq is required"

say "Building colony-firewalld (no eBPF) and cfc"
cargo build --locked -p cfc-daemon -p cfc-cli --no-default-features

say "Namespaces, veth pair, HTTP servers"
sudo modprobe -a nfnetlink_queue nft_queue
sudo ip netns add "${FW}"
sudo ip netns add "${SRV}"
sudo ip link add fw0 netns "${FW}" type veth peer name srv0 netns "${SRV}"
in_fw ip addr add 10.200.0.1/24 dev fw0
in_fw ip link set fw0 up
in_srv ip addr add "${SRV_IP}/24" dev srv0
in_srv ip link set srv0 up
# FW's lo stays down on purpose while a daemon runs: no loopback flows (the
# daemon's own reverse DNS to a 127.0.0.53 stub fails fast instead of being
# queued). The last step brings it up, after the final daemon is gone.
mkdir "${W}/www"
for p in "${ALLOW_PORT}" "${DENY_PORT}" "${UNMATCHED_PORT}"; do
    in_srv python3 -m http.server "${p}" --bind "${SRV_IP}" \
        --directory "${W}/www" >"${W}/http-${p}.log" 2>&1 &
done

say "Control: every port answers before the firewall exists"
for p in "${ALLOW_PORT}" "${DENY_PORT}" "${UNMATCHED_PORT}"; do
    for _ in $(seq 1 50); do
        [[ "$(probe "${p}" 2>/dev/null)" == 200 ]] && break
        sleep 0.2
    done
    expect_200 "${p}"
done

say "Load the shipped snippet in FW (as README: nft -f from a checkout)"
in_fw nft -f "${ROOT}/systemd/nftables-snippet.conf"
table_loaded || fail "table inet colony_firewall not loaded in ${FW}"
queue_bound && fail "something is already bound to NFQUEUE 0"

say "Fail-closed before the daemon ever started"
expect_drop "${ALLOW_PORT}"

say "IPv6 neighbour discovery passes the fail-closed chain"
in_fw ip -6 addr add fd00:200::1/64 dev fw0 nodad
in_srv ip -6 addr add fd00:200::2/64 dev srv0 nodad
# SRV's echo request is inbound to FW and FW's reply is established, so only
# FW's Neighbour Advertisement, which conntrack leaves untracked, meets the
# output chain's policy here.
in_srv ping -6 -c 1 -W 3 fd00:200::1 >/dev/null \
    || fail "IPv6 ping into FW failed; its neighbour advertisement was dropped"

cat >"${W}/daemon.toml" <<TOML
profile = "balanced"
[storage]
path = "${W}/rules.db"
TOML

say "Daemon up, rules in"
start_daemon daemon-1
cfc rules add --name e2e-allow --action allow --protocol tcp \
    --dst-net "${SRV_IP}/32" --dst-port "${ALLOW_PORT}"
DENY_ID="$(cfc --json rules add --name e2e-deny --action deny --protocol tcp \
    --dst-net "${SRV_IP}/32" --dst-port "${DENY_PORT}" | jq -r .id)"
[[ -n "${DENY_ID}" && "${DENY_ID}" != null ]] || fail "rules add --json returned no id"

say "Verdicts"
expect_200 "${ALLOW_PORT}"
expect_drop "${DENY_PORT}"
expect_drop "${UNMATCHED_PORT}"

say "Audit trail names the deciding rule"
DENIES="$(cfc --json log --action deny --limit 200)"
echo "${DENIES}" | jq -c --argjson p "${DENY_PORT}" '[.[] | select(.dst_port == $p)][:3][]'
echo "${DENIES}" | jq -e --arg id "${DENY_ID}" --argjson p "${DENY_PORT}" \
    'any(.[]; .dst_port == $p and .rule_id == $id)' >/dev/null \
    || fail "no deny event on port ${DENY_PORT} attributed to rule ${DENY_ID}"
echo "${DENIES}" | jq -e --argjson p "${UNMATCHED_PORT}" \
    'any(.[]; .dst_port == $p and .rule_id == null)' >/dev/null \
    || fail "no default-deny event on port ${UNMATCHED_PORT}"

say "SIGTERM: clean stop keeps the table, new flows drop"
stop_daemon TERM
table_loaded || fail "a clean daemon stop removed the table"
queue_bound && fail "NFQUEUE 0 still bound after the daemon exited"
expect_drop "${ALLOW_PORT}"

say "Restart: rules persisted"
start_daemon daemon-2
expect_200 "${ALLOW_PORT}"
expect_drop "${DENY_PORT}"

say "SIGKILL: crash keeps the table, new flows drop"
stop_daemon KILL
table_loaded || fail "table gone after SIGKILL"
queue_bound && fail "NFQUEUE 0 still bound after SIGKILL"
expect_drop "${ALLOW_PORT}"

say "No daemon: a new loopback flow still passes (bypass on lo only)"
in_fw ip link set lo up
in_fw python3 -m http.server "${LO_PORT}" --bind 127.0.0.1 \
    --directory "${W}/www" >"${W}/http-lo.log" 2>&1 &
for _ in $(seq 1 50); do
    [[ -n "$(in_fw ss -Hltn "sport = :${LO_PORT}")" ]] && break
    sleep 0.2
done
in_fw curl -sS --noproxy '*' -o /dev/null --connect-timeout 3 --max-time 6 \
    "http://127.0.0.1:${LO_PORT}/" \
    || fail "new loopback flow failed with no daemon; the lo bypass rule should accept it"

say "Armed e2e passed"
