#!/usr/bin/env bash
# Connect latency through Colony Firewall Control, on a link that has none of
# its own.
#
# What CFC costs a new flow cannot be read off a connection to the Internet:
# the twenty-odd milliseconds to any real host drown the fraction of one the
# queue round trip adds. This bench puts the other end of the connection in a
# network namespace on this machine, one veth pair away (round trip ~0.05 ms),
# so what is left in the numbers is the firewall.
#
# Two directions, because they do not take the same path:
#   out   host -> namespace. Every SYN leaves through the host's output chain,
#         where `inet colony_firewall` queues `ct state new` to the daemon -
#         unless the client is fast-allowed, in which case its mark takes it
#         past the queue. This is the direction the fast path exists for.
#   in    namespace -> host. The SYN arrives on the host's input path, which
#         `inet colony_firewall_inbound` filters only where that opt-in unit
#         is loaded. With it absent, this direction never meets a queue - but
#         it still runs CFC's connect hooks, which are attached to the cgroup
#         and not to a network namespace, so the namespace client pays the
#         eBPF per-connect cost exactly as the host client does. `out - in`
#         therefore isolates the NFQUEUE round trip alone; the eBPF cost is
#         `in` with the daemon running against `in` with it stopped. A host
#         firewall of its own (firewalld, the "simple & safe" nftables.conf)
#         answers the namespace's SYN with ICMP admin-prohibited, which the
#         client sees as EHOSTUNREACH and this bench names: open tcp/47000
#         from 10.199.0.0/24 there, or read `in` as unavailable on that host.
#
# The script never touches nftables, the daemon or its rules. It measures the
# machine as it finds it, prints what `cfc status` says the fast path is, and
# leaves the comparison to whoever runs it more than once: with the client
# covered by a lasting Allow rule (fast path), by a flow-scoped one (queue),
# and with the table absent (nothing). The client CFC attributes is python3,
# so the rule to write is for python3's resolved path (`readlink -f
# "$(command -v python3)"`); the first connect of a run is the one that prompts.
#
# Two lessons from the previous bench, kept here so they are not relearned:
#   - a difference in the numbers is a hypothesis, not a cause. The 5 ms poll
#     interval was once blamed for the residual latency; changing it to 200 us
#     moved the median by 0.08 ms. Test a cause by changing the constant and
#     measuring again, never by the shape of a distribution.
#   - nothing here writes to disk, so the tmpfs trap (fsync is free in /tmp,
#     and a storage bench there measures nothing) does not apply; it did to the
#     SQLite bench, and the next one that writes should remember it.
#
# Needs root - it creates a namespace and a veth pair - plus iproute2 and
# python3. A VM is the right place: the point of measuring is to arm the fast
# path, and arming a firewall on a development host has consequences.
#
#   sudo scripts/bench-latency.sh                          both directions, 200 connects
#   sudo scripts/bench-latency.sh -n 1000 -d out -l "fast path live"
#   sudo scripts/bench-latency.sh --json >> runs.jsonl     one JSON object per direction

set -euo pipefail

NS=cfcbench
HOST_IF=cfcb-host
NS_IF=cfcb-ns
HOST_IP=10.199.0.1
NS_IP=10.199.0.2
COUNT=200
WARMUP=3
TIMEOUT=5
PORT=47000
DIRECTION=both
LABEL=""
JSON=0
KEEP=0

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    cat <<USAGE

Options:
  -n, --count N        connects per direction after warm-up (default ${COUNT})
  -w, --warmup N       connects discarded at the start of each direction (default ${WARMUP})
  -t, --timeout S      per-connect timeout in seconds; a denied flow shows up here (default ${TIMEOUT})
  -d, --direction D    out | in | both (default ${DIRECTION})
  -p, --port P         listener port on both sides (default ${PORT})
  -l, --label TEXT     free text carried into the output, e.g. the CFC state you set up
      --json           one JSON object per direction on stdout, everything else on stderr
      --keep           leave the namespace and veth pair in place afterwards
  -h, --help
USAGE
}

die() { echo "bench-latency: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        # Every value-taking option, checked once: under `set -u` a bare `-d`
        # as the last argument otherwise dies on `$2: unbound variable`.
        -n|--count|-w|--warmup|-t|--timeout|-d|--direction|-p|--port|-l|--label)
            [[ $# -ge 2 ]] || die "$1 needs a value (try --help)" ;;&
        -n|--count)     COUNT="$2"; shift 2 ;;
        -w|--warmup)    WARMUP="$2"; shift 2 ;;
        -t|--timeout)   TIMEOUT="$2"; shift 2 ;;
        -d|--direction) DIRECTION="$2"; shift 2 ;;
        -p|--port)      PORT="$2"; shift 2 ;;
        -l|--label)     LABEL="$2"; shift 2 ;;
        --json)         JSON=1; shift ;;
        --keep)         KEEP=1; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              die "unknown argument: $1 (try --help)" ;;
    esac
done

case "$DIRECTION" in out|in|both) ;; *) die "--direction must be out, in or both" ;; esac
[[ "$COUNT" =~ ^[0-9]+$ && "$COUNT" -gt 0 ]] || die "--count must be a positive integer"
[[ "$WARMUP" =~ ^[0-9]+$ ]] || die "--warmup must be an integer"
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -gt 0 && "$PORT" -lt 65536 ]] || die "--port out of range"
# A timeout of 0 makes the socket non-blocking and every connect an EINPROGRESS.
{ [[ "$TIMEOUT" =~ ^[0-9]*\.?[0-9]+$ ]] && awk "BEGIN { exit !($TIMEOUT > 0) }"; } \
    || die "--timeout must be a positive number of seconds"
[[ $EUID -eq 0 ]] || die "run as root: this creates a network namespace and a veth pair"
for tool in ip ss python3; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# The one side of the connection that is not being measured: accept and close.
read -r -d '' LISTENER <<'PY' || true
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(128)
while True:
    c, _ = s.accept()
    c.close()
PY

# The side being measured: wall clock around connect(), one socket per flow so
# every connect is a new flow to conntrack and therefore a new verdict. A
# connect that runs into the timeout is what a denied or unanswered flow looks
# like from here; it is counted, not measured. If every warm-up connect times
# out the run stops, because two hundred more would only cost time.
read -r -d '' CLIENT <<'PY' || true
import errno, json, socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
count, timeout, warmup = int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
samples = []
fails = {"timeout": 0, "refused": 0, "other": 0}
# The abort probe: if the first `probe` connects all time out, nothing admits
# this flow and the remaining ones would only cost time. Independent of the
# warm-up size, because `-w 0` is allowed and used to disable the only abort.
probe = max(warmup, 3)
# Named, because "other" alone once hid a hundred EHOSTUNREACHes: an ICMP
# admin-prohibited from a host firewall looks nothing like a queue timeout
# and the bench has to say which one it saw.
errnos = {}
for i in range(warmup + count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter_ns()
    try:
        s.connect((host, port))
        dt_ms = (time.perf_counter_ns() - t0) / 1e6
        if i >= warmup:
            samples.append(dt_ms)
    except socket.timeout:
        fails["timeout"] += 1
    except ConnectionRefusedError:
        fails["refused"] += 1
    except OSError as e:
        fails["other"] += 1
        name = errno.errorcode.get(e.errno, str(e.errno))
        errnos[name] = errnos.get(name, 0) + 1
    finally:
        s.close()
    if i + 1 == probe and fails["timeout"] == probe:
        print(json.dumps({"ok": 0, "failed": fails, "errnos": errnos, "ms": None,
                          "aborted": f"the first {probe} connects all timed out: nothing admits this flow"}))
        sys.exit(0)
samples.sort()
def pct(p):
    k = int(round(p / 100 * (len(samples) - 1)))
    return samples[max(0, min(len(samples) - 1, k))]
ms = None
if samples:
    ms = {"p50": pct(50), "p90": pct(90), "p99": pct(99),
          "max": samples[-1], "mean": sum(samples) / len(samples)}
print(json.dumps({"ok": len(samples), "failed": fails, "errnos": errnos, "ms": ms}))
PY

LISTENER_PIDS=()
cleanup() {
    local pid
    for pid in "${LISTENER_PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    # kill is asynchronous. A listener still alive when the namespace is
    # deleted keeps the namespace - and its end of the veth pair - alive until
    # it dies, which left a stray host interface for a moment after a run.
    for pid in "${LISTENER_PIDS[@]:-}"; do
        [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
    done
    if [[ $KEEP -eq 0 ]]; then
        # Either end takes the pair with it; the host end is the one that
        # needs no namespace to still be named.
        ip link del "$HOST_IF" 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
}
trap cleanup EXIT

in_ns() { # in_ns <ns-or-empty> cmd...
    local ns="$1"; shift
    if [[ -n "$ns" ]]; then ip netns exec "$ns" "$@"; else "$@"; fi
}

wait_listening() { # wait_listening <ns-or-empty> <port>
    for _ in $(seq 1 50); do
        if in_ns "$1" ss -Hltn "sport = :$2" 2>/dev/null | grep -q .; then return 0; fi
        sleep 0.1
    done
    die "the listener on port $2 did not come up"
}

# The link. A stale namespace of the same name is ours from a --keep run, or
# from a run that was killed before its trap: replaced, not reused. The host
# end goes first: `ip netns del` only unlinks the name, and a namespace some
# process still holds keeps its end of the pair alive, which made the
# `ip link add` below fail on "File exists" while the name was already gone.
ip link del "$HOST_IF" 2>/dev/null || true
ip netns del "$NS" 2>/dev/null || true
ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip link set "$NS_IF" netns "$NS"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "$NS_IP/24" dev "$NS_IF"
ip netns exec "$NS" ip link set "$NS_IF" up
ip netns exec "$NS" ip link set lo up

# Both listeners up front, so switching direction costs nothing.
ip netns exec "$NS" python3 -c "$LISTENER" "$NS_IP" "$PORT" &
LISTENER_PIDS+=("$!")
python3 -c "$LISTENER" "$HOST_IP" "$PORT" &
LISTENER_PIDS+=("$!")
wait_listening "$NS" "$PORT"
wait_listening "" "$PORT"

# What this machine is, for the record next to the numbers. Read-only, and
# each probe is allowed to fail: the bench is also how one measures a machine
# with no CFC on it at all.
KERNEL="$(uname -r)"
FAST_ALLOW="cfc not installed"
if command -v cfc >/dev/null 2>&1; then
    # cfc exits non-zero when the daemon is down; under pipefail that failed
    # the whole pipeline after python had already printed, and the `|| echo`
    # that used to follow printed the same words a second time.
    FAST_ALLOW="$( (cfc status --json 2>/dev/null || true) | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("fast_allow", "not reported"))
except Exception:
    print("daemon not reachable")
')"
fi
TABLES="nft not installed"
if command -v nft >/dev/null 2>&1; then
    # `|| true` on the whole pipeline: a machine with no colony table makes
    # grep exit 1, and under pipefail that failed assignment ended the script
    # without a word. Same class as the `verified_insns` grep in CI: nothing
    # found is a valid answer, not an error.
    TABLES="$( (nft list tables 2>/dev/null || true) | grep -o 'colony_firewall[a-z_]*' | paste -sd ' ' - || true)"
    TABLES="${TABLES:-none loaded}"
fi
{
    echo "kernel:      $KERNEL"
    echo "fast-allow:  $FAST_ALLOW"
    echo "nft tables:  $TABLES"
    echo "link:        $HOST_IF ($HOST_IP) <-> $NS:$NS_IF ($NS_IP), port $PORT"
    echo "per run:     $COUNT connects after $WARMUP warm-up, ${TIMEOUT}s timeout each"
    [[ -n "$LABEL" ]] && echo "label:       $LABEL"
    echo
} >&2

run_direction() { # run_direction <out|in>
    local dir="$1" ns="" target="$NS_IP" raw
    if [[ "$dir" == in ]]; then ns="$NS"; target="$HOST_IP"; fi
    raw="$(in_ns "$ns" python3 -c "$CLIENT" "$target" "$PORT" "$COUNT" "$TIMEOUT" "$WARMUP")"
    python3 - "$raw" "$dir" "$LABEL" "$KERNEL" "$FAST_ALLOW" "$COUNT" "$JSON" "$PORT" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
port_num = int(sys.argv[8])
r.update(direction=sys.argv[2], label=sys.argv[3], kernel=sys.argv[4],
         fast_allow=sys.argv[5], connects=int(sys.argv[6]))
if sys.argv[7] == "1":
    print(json.dumps(r))
    sys.exit(0)
f = r["failed"]
other = f"{f['other']}"
if r.get("errnos"):
    other += " (" + ", ".join(f"{k} x{v}" for k, v in sorted(r["errnos"].items())) + ")"
unreachable = sum(v for k, v in r.get("errnos", {}).items() if k in ("EHOSTUNREACH", "ENETUNREACH"))
if unreachable:
    print(f"note ({r['direction']}): {unreachable} connect(s) got EHOSTUNREACH/ENETUNREACH - an ICMP "
          "admin-prohibited from a host firewall (firewalld, /etc/nftables.conf), rejected before "
          "any CFC table sees the SYN. Allow tcp/%d from 10.199.0.0/24 there, or read this "
          "direction as not measurable on this host." % port_num, file=sys.stderr)
if r.get("aborted"):
    print(f"{r['direction']:<5} aborted: {r['aborted']}")
elif r["ms"] is None:
    print(f"{r['direction']:<5} no connect succeeded  (timeouts {f['timeout']}, refused {f['refused']}, other {other})")
else:
    m = r["ms"]
    print(f"{r['direction']:<5} {r['ok']:>5}/{r['connects']:<5} "
          f"p50 {m['p50']:7.3f}  p90 {m['p90']:7.3f}  p99 {m['p99']:7.3f}  "
          f"max {m['max']:7.3f}  mean {m['mean']:7.3f} ms"
          f"   timeouts {f['timeout']}  refused {f['refused']}  other {other}")
PY
}

if [[ $JSON -eq 0 ]]; then
    echo "dir     ok/total   latency of connect(), milliseconds"
fi
case "$DIRECTION" in
    out)  run_direction out ;;
    in)   run_direction in ;;
    both) run_direction out; run_direction in ;;
esac
