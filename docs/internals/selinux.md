# SELinux policy for Colony Firewall Control

For RHEL, Rocky, AlmaLinux and Fedora, where SELinux is enforcing by default.

The alternative to shipping this file is shipping instructions that say "set it
permissive", which on those distributions is advice to turn off the thing they
are built around. So: a real module.

The policy sources live in
[`packaging/selinux/`](../../packaging/selinux/): `colony_firewall.te`,
`colony_firewall.if` and `colony_firewall.fc`.

## Build and install

From `packaging/selinux/`:

```sh
make -f /usr/share/selinux/devel/Makefile colony_firewall.pp
sudo semodule -i colony_firewall.pp
sudo restorecon -RvF /usr/bin/colony-firewalld /etc/colony-firewall \
    /var/lib/colony-firewall /run/colony-firewall
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
| netlink_netfilter, raw sockets | **everything.** The daemon exits before `READY=1`, and the ruleset is fail-closed (except new loopback flows), so the machine loses non-loopback outbound network |
| unix socket under `/run` | the CLI, tray and GUI cannot reach the daemon; filtering continues, unattended |
| `bpf`, `perf_event`, tracefs, cgroup | the ring-0 layer. Attribution falls back to `sock_diag` + `/proc`, hostnames to PTR lookups. Logged once, then filtering continues |
| bpffs (`/sys/fs/bpf`) | in-kernel denials no longer survive the daemon being killed. Silent apart from `enforcement=process` in the startup line |
| `/proc` of other domains | process attribution. Connections resolve to "unknown" |
| `rpm_exec_t`, `rpm_var_lib_t` | provenance. Every binary reports `Unpackaged` |

Only the first two are fatal. Everything else is a narrower feature set and one
log line, which is the same contract the daemon keeps everywhere else.

## What is deliberately not here

**`CAP_SYS_ADMIN`.** The seven capabilities in `colony_firewall.te` are exactly
the seven the systemd unit grants - the five BPF/network ones plus `chown`
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
bug in `colony_firewall.te`. The protocol below is how to run that check.

## Validating the policy on an enforcing host

CI proves this module *compiles* against the real `selinux-policy-devel` of
Rocky 9 and Fedora, and the `rpm end to end` job proves the package that
carries it builds and installs. Neither proves the rules are **sufficient**,
and nothing that runs in a container can: sufficiency is a property of the
daemon under real load on a kernel with SELinux enforcing. This file is the
protocol for whoever has such a host. Run it once, report what you see, and
the item on the [roadmap](../project/roadmap.md) closes.

### What you need

- A Rocky 9 or Fedora VM with SELinux enforcing (`getenforce` says
  `Enforcing`). A VM, not your workstation: the ruleset is fail-closed
  (except new loopback flows), and a policy gap in the wrong group takes the
  machine's outbound network down.
  For the same reason, have **console access**, not just SSH.
- The audit tooling: `dnf install audit policycoreutils-python-utils`.
  `semanage` and `audit2allow` live in the second package, and on a minimal
  install neither is present. If `auditd` is not running, AVCs go to the
  kernel ring buffer instead and `ausearch` finds nothing - `systemctl
  enable --now auditd` first.
- The package. Either the `rpms-fedora` artifact from the `rhel` workflow
  (Fedora VMs only - they are Fedora RPMs), or a local build on the VM
  itself following [Build from source](../../README.md#build-from-source) in the main README.

### Step 0: make the domain permissive, on purpose, first

```sh
sudo semanage permissive -a colony_firewalld_t
```

One domain, not the machine (`setenforce 0` would also stop *collecting*
useful evidence, since other domains' behaviour changes too). Permissive for
`colony_firewalld_t` means every rule this module is missing shows up as an
AVC in the audit log **without being enforced** - observed, not suffered.

Why that ordering matters here more than for most policies, in the module's
own words: a denied `netlink_netfilter` socket is not a degraded feature, it
is a daemon that exits before `READY=1` - and because the nftables ruleset is
fail-closed for everything except new loopback flows, which are allowed while
no daemon listens, a daemon that does not come up takes the machine's
non-loopback outbound network with it. Running the first pass
permissive converts that outage into a log line.

Dontaudit rules hide denials, and this module carries some
(`init_dontaudit_use_fds`, `userdom_dontaudit_search_user_home_dirs`). For a
validation pass you want to see everything:

```sh
sudo semodule -DB     # rebuild policy with dontaudit disabled
# ... run the tests ...
sudo semodule -B      # put it back when done
```

### Step 1: install

From the RPM (the selinux subpackage's `%post` runs `semodule` and the
relabel for you):

```sh
sudo dnf install ./colony-firewall-control-*.x86_64.rpm \
                 ./colony-firewall-control-selinux-*.noarch.rpm
```

Or by hand, from `packaging/selinux/` in a checkout (the same commands as
[Build and install](#build-and-install) above):

```sh
make -f /usr/share/selinux/devel/Makefile colony_firewall.pp
sudo semodule -i colony_firewall.pp
sudo restorecon -RvF /usr/bin/colony-firewalld /etc/colony-firewall \
    /var/lib/colony-firewall /run/colony-firewall
```

Verify the label took - this is the single most common way a policy "fails"
while being perfectly correct:

```sh
ls -Z /usr/bin/colony-firewalld    # must say colony_firewalld_exec_t
```

If it says `bin_t`, the domain transition never happens, the daemon runs
unconfined, and every test below passes while testing nothing.

### Step 2: start the daemon and turn enforcement on

```sh
sudo systemctl enable --now colony-firewalld
sudo systemctl enable --now colony-firewall-nft.service
sudo cfc rules bootstrap-defaults   # DNS/NTP/DHCP allows, so the VM keeps working
ps -o label= -p "$(systemctl show -p MainPID --value colony-firewalld)"
```

The last line must show `colony_firewalld_t`. `Type=notify` means the unit
reaching `active` already proves the queue and the control socket bound - if
the unit cycles through restarts instead, you have found something: go to
Step 4 now.

### Step 3: exercise every group the .te documents

The `.te` groups its rules by failure mode. Each row below drives one group;
the point is that after this table every rule in the module has had the
chance to be needed.

| group in the .te | how to exercise it | what a denial looks like |
|---|---|---|
| netlink/NFQUEUE filtering | any new outbound connection: `curl https://example.com`, answer the prompt in `sudo cfc prompts` | daemon exits before READY=1; permissive: AVC on `netlink_netfilter_socket` |
| raw sockets | answer one prompt with **r** (Reject - it sends the refusal via a raw socket; Deny does not) | Reject behaves like Deny (silent drop instead of an immediate refusal); AVC on `rawip_socket` |
| sock_diag fallback | exercised by every connection while ring 0 is down - which is the RPM's normal state, see next row | attribution falls to /proc alone; AVC on `netlink_tcpdiag_socket` |
| bpf/perf ring 0 | **degraded by design in the RPM**: no eBPF object ships (see the spec's `%build` comment), so the journal says `ring0=unavailable degrade=object_missing` once at startup and the bpf/perf/bpffs/tracefs rules are never reached. That log line *is* the expected result. To exercise the group for real: build the object (`cargo xtask build-ebpf`, pinned nightly + bpf-linker), drop it at `/usr/lib/colony-firewall/cfc-ebpf.o`, restart, and expect `ring0=active` | with the object installed: `degrade=not_permitted` where `object_missing` was, and AVCs on `bpf`, `perf_event`, `tracefs_t`/`debugfs_t` or `bpf_t` |
| /proc attribution walk | `curl` from a second user account; the prompt must name curl's real path and pid | every prompt says `exe=<unknown> pid=0`; AVCs from `domain_read_all_domains_state` targets. Enforcing, this is the outage mode: no exe rule can ever match |
| rpm provenance | automatic: one `rpm -qa` at startup and after any `dnf install`. Install any small package, wait ~2 minutes, then check a prompt or `cfc log` shows package names | everything reports `Unpackaged` plus one provenance warning in the journal; AVC on `rpm_exec_t` or `rpm_var_lib_t` |
| control socket, unconfined client | `cfc status` and `cfc rules list` as a normal logged-in user in the `colony-firewall` group (not root, not sudo) | connection refused/denied; AVC with the client's domain (`unconfined_t`) and `colony_firewall_runtime_t` |
| official clients | run the installed `colony-firewall` GUI as a group member, then delete a rule from it; then run `cfc rules remove <id>` without sudo, which must be refused with "read-only access" | the GUI's change is refused with a reason naming a stat or "unix_diag"; AVCs with `getattr` on `bin_t`/`lib_t`/`usr_t` or on `netlink_tcpdiag_socket` |
| polkit over D-Bus | press Pause in the GUI: your polkit agent must show "Authentication is required to pause or resume the firewall"; cancel it, then press Pause again and authenticate | "system D-Bus is unreachable" or "polkit check failed" instead of the dialog; AVCs on `system_dbusd_t` (`unix_stream_socket connectto`, `dbus send_msg`) or `policykit_t` |
| sqlite WAL in /var/lib | answer any prompt with a persistent choice (**a**, then `3`=always), then `ls /var/lib/colony-firewall/` - `rules.db-wal` and `rules.db-shm` must exist while the daemon runs | the `map` denial is the quiet one: no error anywhere, just journal-mode SQLite and a 2.5x write regression. An AVC with class `file` permission `map` on `colony_firewall_var_lib_t` is the tell |

Let the daemon run for at least a few minutes of normal use - browse
something, let NTP and DNS happen, `sudo dnf check-update` for the provenance
path. The rules that get missed by policies written away from the platform
are the periodic ones, not the startup ones.

### Step 4: collect the verdict

```sh
sudo ausearch -m AVC,USER_AVC -ts recent
sudo audit2allow -w -a
```

`audit2allow -w` translates each denial into which rule would have allowed
it - that output is the report, not something to apply.

A **clean run** is: no AVC lines referencing `colony_firewalld_t` (as source
or target), across the whole session, with dontaudit disabled. AVCs about
*other* domains are normal background noise on any host; the grep is:

```sh
sudo ausearch -m AVC -ts recent | grep colony
```

### Step 5: the same pass, enforcing

Only after a clean permissive pass:

```sh
sudo semanage permissive -d colony_firewalld_t
sudo systemctl restart colony-firewalld
```

and repeat Step 3. Permissive mode reports only the *first* denial on some
paths (subsequent ones can be short-circuited), so an enforcing pass can
surface a rule the permissive pass hid behind another. If the machine loses
outbound network here, that is the console access earning its place:
`semanage permissive -a colony_firewalld_t` from the console restores it.

### Reporting

Open an issue containing:

- distro and release (`cat /etc/os-release`),
- `colony-firewalld --version`,
- whether the run was permissive or enforcing,
- the full `audit2allow -w -a` output, and the matching raw `ausearch -m AVC`
  lines.

A missing rule is a bug in `colony_firewall.te`, **not something to add
locally**. A local module would fix your machine and nobody else's, and the
next package update would reintroduce the gap for everyone whose machine it
never fixed. The one exception carved out under
[What is deliberately not here](#what-is-deliberately-not-here): if the denial
asks for `sys_admin`, that is a regression in the daemon to find, not a rule
to add anywhere.
