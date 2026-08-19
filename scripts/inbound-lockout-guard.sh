#!/bin/sh
# Refuse to load the inbound chain if doing so would strand the session that
# enabled it.
#
# The failure this prevents is specific, and permanent when it lands. You
# enable inbound filtering over SSH; the chain loads; your session survives,
# because `ct state established,related accept` covers it. Then the daemon
# restarts, or the box reboots, and the next SSH connection is a NEW inbound
# flow with no rule to admit it. The machine is now unreachable and the fix
# needs the console you do not have.
#
# That deferral is the whole reason for a pre-flight check: "did I just lose my
# shell" cannot detect it.
#
# WHAT THIS CHECKS, AND WHAT IT DOES NOT
#
# Conservative and deliberately dumb: for every established inbound connection
# on a port this host listens on, is there an enabled inbound Allow rule that
# could plausibly admit it - one scoped to that port, or to no port at all?
# It does not evaluate precedence, source networks, or executables. A rule that
# exists but would not actually match still satisfies this check.
#
# So it is a seatbelt, not a proof. It catches "you forgot entirely", which is
# the way people actually get locked out. It will not catch "your rule has the
# wrong source network".
#
# Exits non-zero (blocking ExecStartPre) when it finds nothing that could admit
# a live session. CFC_INBOUND_FORCE=1 overrides.
set -eu

CFC="${CFC_BIN:-/usr/bin/cfc}"

if [ "${CFC_INBOUND_FORCE:-0}" = "1" ]; then
    echo "inbound-lockout-guard: CFC_INBOUND_FORCE=1 set, skipping the check" >&2
    exit 0
fi

# No ss, no check. Failing *open* here is deliberate: this guard is a safety
# net, not a security boundary, and a missing tool must not make the unit
# permanently unstartable on a machine that is sitting in front of its user.
command -v ss >/dev/null 2>&1 || {
    echo "inbound-lockout-guard: ss(8) not found; skipping the lockout check" >&2
    exit 0
}
command -v python3 >/dev/null 2>&1 || {
    echo "inbound-lockout-guard: python3 not found; skipping the lockout check" >&2
    exit 0
}

listening="$(ss -Hltn 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un || true)"
[ -n "$listening" ] || exit 0

established="$(ss -Htn state established 2>/dev/null | awk '{print $3" "$4}' || true)"
[ -n "$established" ] || exit 0

rules_json="$("$CFC" rules list --json 2>/dev/null || echo '[]')"

RULES_JSON="$rules_json" LISTENING="$listening" ESTABLISHED="$established" python3 - <<'PY'
import json, os, sys

rules = json.loads(os.environ.get("RULES_JSON") or "[]")
if isinstance(rules, dict):
    rules = rules.get("rules", [])
listening = {l.strip() for l in os.environ["LISTENING"].split() if l.strip()}

# Ports an enabled inbound Allow rule could admit. `None` means the rule names
# no port, so it could admit any of them.
admitted, any_port = set(), False
for r in rules:
    if not r.get("enabled", True):
        continue
    if str(r.get("action", "")).lower() != "allow":
        continue
    scope = r.get("scope") or {}
    if str(scope.get("direction", "")).lower() not in ("in", "inbound"):
        continue
    port = scope.get("dst_port")
    if port is None:
        any_port = True
    else:
        admitted.add(str(port))

at_risk = []
for line in os.environ["ESTABLISHED"].splitlines():
    parts = line.split()
    if len(parts) != 2:
        continue
    local, peer = parts
    lport = local.rsplit(":", 1)[-1]
    pip = peer.rsplit(":", 1)[0].strip("[]")
    if lport not in listening:
        continue  # an outbound connection's ephemeral local port
    if pip.startswith("127.") or pip == "::1":
        continue  # loopback is accepted unconditionally
    if any_port or lport in admitted:
        continue
    at_risk.append(f"  {pip} -> port {lport}")

if at_risk:
    print("inbound-lockout-guard: REFUSING to load the inbound chain.", file=sys.stderr)
    print("", file=sys.stderr)
    print("These connections are established right now, and no inbound Allow rule", file=sys.stderr)
    print("mentions their port:", file=sys.stderr)
    print("\n".join(sorted(set(at_risk))), file=sys.stderr)
    print("", file=sys.stderr)
    print("They survive today only because the chain accepts established flows.", file=sys.stderr)
    print("They die at the next daemon restart or reboot, and on a remote machine", file=sys.stderr)
    print("you would not get back in.", file=sys.stderr)
    print("", file=sys.stderr)
    print("Authorise them first, for example:", file=sys.stderr)
    print("  cfc rules add --direction in --action allow --protocol tcp \\", file=sys.stderr)
    print("      --dst-port 22 --src-net 192.168.1.0/24 --name ssh-inbound", file=sys.stderr)
    print("", file=sys.stderr)
    print("Or, with console access and on purpose:", file=sys.stderr)
    print("  systemctl set-environment CFC_INBOUND_FORCE=1", file=sys.stderr)
    sys.exit(1)
PY
