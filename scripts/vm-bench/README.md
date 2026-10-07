# Measuring what the firewall costs, on a machine it may arm

`scripts/bench-latency.sh` measures connect latency over a veth pair. It
answers nothing on its own, because the interesting comparison needs CFC
*armed* - the queue rule loaded, the daemon deciding - and arming a fail-closed firewall on a development machine has consequences.

This directory boots a throwaway VM instead. It assembles an initramfs from the
host's own kernel modules, `nftables`, `iproute2`, `python3` and the release
binaries in `target/`, boots it under KVM, and runs the bench there against a
real daemon. Nothing is downloaded; nothing outside `target/vm-bench` is
written; the guest exists for one boot.

```sh
cargo build --release -p cfc-daemon -p cfc-cli
cargo xtask build-ebpf
./scripts/vm-bench/run.sh
```

One `sudo` is needed, once, to read the host's kernel image. `KERNEL`, `OUT`,
`MEM`, `SMP` and `TIMEOUT` override the defaults.

## What it measures, and why each state exists

Every state differs from its neighbour in exactly one thing, so each difference
isolates one cost.

| state | what is running | what the difference against the previous one buys |
|---|---|---|
| `floor` | nothing: no daemon, no table | the veth link and `connect()` itself |
| `queue-N` | the daemon, the table, a lasting Allow | the NFQUEUE round trip, at N flows |
| `poll200us-N` | the same, with a daemon built with a shorter `RECV_POLL_INTERVAL` | how much of that round trip is the worker's idle beat |
| `lo-floor` | nothing; a UDP echo server on `127.0.0.1` inside the guest | the loopback round trip itself |
| `lo-queue` | the daemon and the table, same echo server | what the `oifname "lo" ... queue num 0 bypass` rule costs a new loopback flow |

The two `lo-*` states run after the sweep. The client opens a new socket per
round trip (1000 of them), so every round trip is a new conntrack flow,
and reports mean, p50, p90, p95, p99 and max under direction `lo`.

Both directions run in every veth state and they answer different questions. `out`
leaves through the host's output chain and meets the queue. `in` is generated
inside the network namespace, whose own output chain carries no colony table,
so it never meets a queue - but its client sits in the root cgroup and still
runs the connect hooks, which makes `in` the cost of the eBPF layer alone.

One thing is recorded beside every measurement rather than assumed:
`id_sequence` from `/proc/net/netfilter/nfnetlink_queue` - one increment per
packet the kernel actually handed to userspace. A state whose queue saw no
packets did not measure the queue, and no latency figure says that on its own.

`ALT_DAEMON=/path/to/colony-firewalld` carries a second daemon into the same
image, measured in the same boot under conditions that differ in nothing else.
That is how the `poll200us` row is produced: build one, point at it, and the
constant under test is the only variable.

## What it found

Run on 2026-09-06, Linux 7.2.2, KVM, four vCPUs, 3000 flows unless said.

| state | 300 flows | 3000 flows |
|---|---|---|
| no firewall | 0.0158 ms | 0.0162 ms |
| queue, 200 us idle beat | 0.7703 ms | 2.3646 ms |
| queue, the shipped 5 ms beat | 5.6745 ms | 7.6083 ms |

That run also measured Fast Allow, since removed because a socket mark does
not prove which process sends (see `TODO.md` 1a). Read across, and two things
fall out.

- **A full `RECV_POLL_INTERVAL` is paid per queued flow, not half of one.**
  `crates/cfc-daemon/src/nfqueue.rs` predicts "up to one interval (mean: half
  that)", which is right for random arrivals and wrong for a client that
  connects in series: every connect lands just after the worker committed to a
  fresh idle wait, so it waits the whole beat. Measured by changing the
  constant, not by reading the shape of a distribution: 4.90 ms of the 5.67 at
  300 flows, 5.24 ms of the 7.61 at 3000.
- **What is left grows with the number of live sockets** - 0.77 ms at 300 flows
  against 2.36 ms at 3000, with the beat removed. That growth is in the daemon's
  per-packet work, not the kernel's: the `floor` state moved 0.0003 ms across
  the same range.

The absolute numbers are this VM's, not a bare-metal host's. What transfers is
that every state was measured in the same guest, back to back, with one
variable moving at a time.
