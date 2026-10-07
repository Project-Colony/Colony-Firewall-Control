#!/bin/bash
# Why does a queued flow cost what it costs, and does that cost depend on load?
#
# The first full run said 17.8 ms per queued flow at 3000 flows and 5.5 ms at
# 40, with the two rounds 15.0 and 20.7 ms apart - and a state that did
# strictly MORE work came out faster than one that did less. None of that is a
# per-packet constant. Two candidate explanations, and this run separates them:
#
#   1. a fixed cost per flow, dominated by RECV_POLL_INTERVAL (5 ms), the beat
#      the NFQUEUE worker idles on. Testable by changing the constant: the same
#      daemon built with 200 us is in this image as colony-firewalld-alt.
#   2. a cost that grows with how many sockets are around, because attribution
#      falls back to reading /proc/net/tcp, whose length is the socket table.
#      Testable by sweeping the number of flows with everything else fixed.
#
# So: the same state at 100, 300, 1000 and 3000 flows, with a drain between
# every state so each starts from a comparable socket table, and the socket and
# conntrack counts recorded next to each measurement rather than assumed.
set -uo pipefail

SOCK=/run/colony-firewall/cfc.sock
CFG=/etc/colony-firewall/daemon.toml
LOG=/var/log/colony-firewall/daemon.log
SNIPPET=/etc/colony-firewall/nftables-snippet.conf
PIN=/sys/fs/bpf/colony-firewall
DPID=""
PY="$(readlink -f "$(command -v python3)")"

say() { echo "== $*"; }
ctx() { echo "CTX $*"; }
qseq() { awk '$1=="0"{print $8; exit}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null || echo 0; }
sockets() { echo $(( $(wc -l < /proc/net/tcp) - 1 )); }
ctcount() { cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?'; }

# TIME_WAIT is 60 s and nothing shortens it. A state that starts on the
# previous state's leftovers is measuring the previous state too.
drain() {
    local before; before="$(sockets)"
    sleep "${DRAIN_SECS:-70}"
    ctx "drain sockets $before -> $(sockets), conntrack $(ctcount)"
}

write_cfg() {
    cat > "$CFG" <<EOF
[default_policy]
no_ui_action = "Allow"
timeout_action = "Allow"
prompt_timeout_secs = 2
[storage]
path = "/var/lib/colony-firewall/rules.db"
[ipc]
require_group = false
[provenance]
enabled = false
[ebpf]
enabled = "on"
object_path = "/cfc-ebpf.o"
EOF
}

write_rules() {
    cat > /tmp/rules.json <<EOF
[{"id":"22222222-2222-4222-8222-222222222222","name":"bench-lasting","enabled":true,
  "action":"allow","duration":"always","scope":{"exe_path":"$PY"}}]
EOF
}

start_daemon() {  # $1 binary  $2 RUST_LOG
    : > "$LOG"
    RUST_LOG="${2:-}" "$1" --config "$CFG" --socket "$SOCK" >> "$LOG" 2>&1 &
    DPID=$!
    for _ in $(seq 1 150); do [ -S "$SOCK" ] && return 0; sleep 0.1; done
    say "!! socket never appeared for $1"; tail -20 "$LOG"; return 1
}

stop_daemon() {
    [ -n "$DPID" ] && { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }
    DPID=""
    nft delete table inet colony_firewall 2>/dev/null
    rm -rf "$PIN"
}

probe_layer() {
    say "what the in-kernel layer comes up as here"
    write_cfg
    start_daemon /usr/bin/colony-firewalld info || return 1
    nft -f "$SNIPPET"; write_rules
    cfc --socket "$SOCK" rules import --replace /tmp/rules.json >/dev/null 2>&1
    sleep 4
    for k in ring0 enforcement degrade exec_tracking exit_tracking dns_capture ppid_from_btf; do
        v="$(grep -oE "$k=[A-Za-z_-]+" "$LOG" | tail -1)"
        [ -n "$v" ] && ctx "layer $v"
    done
    ctx "layer $(cfc --socket "$SOCK" status --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("status_enforcing=%s" % d["enforcing"])')"
    stop_daemon
}

measure() {  # $1 label  $2 n  $3 mode(none|queue)  $4 binary
    local label="$1" n="$2" mode="$3" bin="${4:-/usr/bin/colony-firewalld}" q0 q1
    say "state: $label  n=$n  mode=$mode  daemon=$(basename "$bin")"
    if [ "$mode" != none ]; then
        [ -x "$bin" ] || { echo "SKIP $label: $bin is not in this image"; return 0; }
        write_cfg
        start_daemon "$bin" || { echo "FAIL $label"; return 1; }
        nft -f "$SNIPPET" || { echo "FAIL $label nft"; stop_daemon; return 1; }
        write_rules
        cfc --socket "$SOCK" rules import --replace /tmp/rules.json >/dev/null 2>&1
        sleep 4
    fi
    ctx "$label before sockets=$(sockets) conntrack=$(ctcount)"
    q0="$(qseq)"
    /bench/bench-latency.sh -n "$n" -w 20 -t 5 -l "$label" --json 2>/dev/null \
        | while read -r line; do echo "RESULT $line"; done
    q1="$(qseq)"
    ctx "$label after sockets=$(sockets) conntrack=$(ctcount) queued_packets=$(( q1 - q0 ))"
    [ "$mode" != none ] && stop_daemon
    return 0
}

say "the binary the rules name: $PY"
say "conntrack max: $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')"
probe_layer

# The sweep: one variable at a time, a drain before each. SWEEP overrides the
# flow counts (a short list is how one checks the harness itself without
# waiting for the real thing).
SWEEP="${SWEEP:-100 300 1000 3000}"
SMALL="${SWEEP%% *}"; LARGE="${SWEEP##* }"

drain; measure "floor-$SMALL"  "$SMALL" none
for n in $SWEEP; do
    drain; measure "queue-$n" "$n" queue /usr/bin/colony-firewalld
done
for n in "$SMALL" "$LARGE"; do
    drain; measure "poll200us-$n" "$n" queue /usr/bin/colony-firewalld-alt
done
[ "$SMALL" != "$LARGE" ] && { drain; measure "floor-$LARGE" "$LARGE" none; }
say "done"
