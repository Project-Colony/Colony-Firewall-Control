#!/usr/bin/env python3
"""Turn a guest console log into the table the measurement is for.

Reads the `RESULT` lines (one JSON object per state and direction) and the
`CTX` lines (what was true beside each measurement) that `plan.sh` prints.
"""
import collections
import json
import sys


def main(path):
    rows, ctx = [], collections.defaultdict(list)
    for line in open(path, errors="replace"):
        line = line.replace("\r", "").strip()
        if line.startswith("RESULT "):
            try:
                rows.append(json.loads(line[7:]))
            except json.JSONDecodeError:
                pass
        elif line.startswith("CTX "):
            head, _, rest = line[4:].partition(" ")
            if rest:
                ctx[head].append(rest)

    print(f"{'state':<16} {'dir':<4} {'flows':>6} {'p50 ms':>9} {'p90 ms':>9} "
          f"{'p99 ms':>9} {'max ms':>9}")
    print("-" * 72)
    out = {}
    for r in rows:
        if not r.get("ms"):
            print(f"{r['label']:<16} {r['direction']:<4} {r['ok']:>6}   "
                  f"no connect succeeded: {r.get('failed')}")
            continue
        m = r["ms"]
        if r["direction"] == "out":
            out[r["label"]] = m["p50"]
        print(f"{r['label']:<16} {r['direction']:<4} {r['ok']:>6} {m['p50']:>9.4f} "
              f"{m['p90']:>9.4f} {m['p99']:>9.4f} {m['max']:>9.4f}")

    if ctx:
        print("\nwhat was true beside each state")
        for k in sorted(ctx):
            print(f"  {k:<16} " + " | ".join(ctx[k]))

    def pair(a, b, what):
        if a in out and b in out:
            print(f"  {what:<50} {out[a]:>8.4f} vs {out[b]:>8.4f}   "
                  f"{out[a] - out[b]:+8.4f} ms")

    # The flow counts are whatever the run used (SWEEP overrides them), so the
    # comparisons are derived from the labels present rather than named here -
    # a hard-coded "queue-3000" prints nothing at all on a shorter sweep, and
    # silence reads like "no difference" instead of "not measured".
    def counts(prefix):
        return sorted(int(k.rsplit("-", 1)[1]) for k in out
                      if k.rsplit("-", 1)[0] == prefix and k.rsplit("-", 1)[1].isdigit())

    q, f, fl, po = (counts(x) for x in ("queue", "fast", "floor", "poll200us"))
    print("\nreadings (p50 of the `out` direction, the one that meets the queue)")
    if len(q) > 1:
        pair(f"queue-{q[-1]}", f"queue-{q[0]}",
             f"queue: {q[-1]} flows against {q[0]}")
    for n in po:
        pair(f"poll200us-{n}", f"queue-{n}",
             f"{n} flows: a 200us idle beat against the 5ms one")
    for n in f:
        pair(f"fast-{n}", f"queue-{n}", f"{n} flows: the fast path against the queue")
    for n in sorted(set(f) & set(fl)):
        pair(f"fast-{n}", f"floor-{n}", f"{n} flows: what the fast path costs over nothing")
    if len(fl) > 1:
        pair(f"floor-{fl[-1]}", f"floor-{fl[0]}",
             f"the floor itself, {fl[-1]} flows against {fl[0]}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "guest.log")
