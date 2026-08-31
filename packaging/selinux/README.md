# SELinux policy for Colony Firewall Control

For RHEL, Rocky, AlmaLinux and Fedora, where SELinux is enforcing by default.

The alternative to shipping this file is shipping instructions that say "set it
permissive", which on those distributions is advice to turn off the thing they
are built around. So: a real module.

## Build and install

```sh
make -f /usr/share/selinux/devel/Makefile colony_firewall.pp
sudo semodule -i colony_firewall.pp
sudo restorecon -RvF /usr/bin/colony-firewalld /etc/colony-firewall \
    /var/lib/colony-firewall /var/log/colony-firewall /run/colony-firewall
```

`selinux-policy-devel` provides that Makefile. The `.spec` in `packaging/rpm`
does all of this in `%post`.

Removing it:

```sh
sudo semodule -r colony_firewall
```

## What it grants, and what each denial costs

Grouped that way on purpose: the failure modes are not equivalent, and an AVC
tells you which kind of trouble you are in.

| group | denial costs |
|---|---|
| netlink_netfilter, raw sockets | **everything.** The daemon exits before `READY=1`, and the ruleset is fail-closed, so the machine loses outbound network |
| unix socket under `/run` | the CLI, tray and GUI cannot reach the daemon; filtering continues, unattended |
| `bpf`, `perf_event`, tracefs, cgroup | the ring-0 layer. Attribution falls back to `sock_diag` + `/proc`, hostnames to PTR lookups. Logged once, then filtering continues |
| bpffs (`/sys/fs/bpf`) | in-kernel denials no longer survive the daemon being killed. Silent apart from `enforcement=process` in the startup line |
| `/proc` of other domains | process attribution. Connections resolve to "unknown" |
| `rpm_exec_t`, `rpm_var_lib_t` | provenance. Every binary reports `Unpackaged` |

Only the first two are fatal. Everything else is a narrower feature set and one
log line, which is the same contract the daemon keeps everywhere else.

## What is deliberately not here

**`CAP_SYS_ADMIN`.** The seven capabilities in `colony_firewall.te` are exactly
the seven the systemd unit grants — the five BPF/network ones plus `chown`
(the control socket is chgrped to `colony-firewall` after bind) and
`dac_read_search` (the `/proc/*/fd` walk behind attribution; its absence once
took a real machine's network down, see the capability comment in the `.te`).
That the BPF set is sufficient is a test rather than a claim:
`attaches_with_only_the_units_capabilities` drops to uid 1000, asserts
`CAP_SYS_ADMIN` is absent from its own effective set, and requires all five BPF
programs to load, attach and pin. If an AVC ever asks for `sys_admin`, that is
a regression to find, not a rule to add.

**A domain for the client binaries.** `cfc`, `colony-firewall` and
`colony-firewall-tray` run as the invoking user and do nothing privileged.
Labelling them would confine the user's session rather than the process holding
`CAP_NET_ADMIN`. They get `colony_firewall_stream_connect` and nothing else.

**A transition to `rpm_t`.** The provenance backend runs `rpm -qa` in the
daemon's own domain. Transitioning would hand the child a domain that can
install packages, to run a read-only query.

**`permissive colony_firewalld_t`.** Adding that line would make this file look
like a policy while behaving like `setenforce 0` for one domain.

## Status

The module builds against `selinux-policy-devel` in CI (`.github/workflows/rhel.yml`,
Rocky 9 and Fedora containers), which proves the syntax is right and every type
and interface it names exists on those releases.

It has **not** been exercised against a running enforcing system with the daemon
under load. Expect a round of `audit2allow -w` on first deployment, and please
report what it asks for rather than adding it locally - a missing rule here is a
bug in this file.
