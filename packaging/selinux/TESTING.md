# Validating the policy on an enforcing host

CI proves this module *compiles* against the real `selinux-policy-devel` of
Rocky 9 and Fedora, and the `rpm end to end` job proves the package that
carries it builds and installs. Neither proves the rules are **sufficient**,
and nothing that runs in a container can: sufficiency is a property of the
daemon under real load on a kernel with SELinux enforcing. This file is the
protocol for whoever has such a host. Run it once, report what you see, and
`TODO.md` 2a stops being open.

## What you need

- A Rocky 9 or Fedora VM with SELinux enforcing (`getenforce` says
  `Enforcing`). A VM, not your workstation: the ruleset is fail-closed, and a
  policy gap in the wrong group takes the machine's outbound network down.
  For the same reason, have **console access**, not just SSH.
- The audit tooling: `dnf install audit policycoreutils-python-utils`.
  `semanage` and `audit2allow` live in the second package, and on a minimal
  install neither is present. If `auditd` is not running, AVCs go to the
  kernel ring buffer instead and `ausearch` finds nothing - `systemctl
  enable --now auditd` first.
- The package. Either the `rpms-fedora` artifact from the `rhel` workflow
  (Fedora VMs only - they are Fedora RPMs), or a local build on the VM
  itself following the README's *Building* section.

## Step 0: make the domain permissive, on purpose, first

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
fail-closed (`ct state new queue num 0`, no `bypass`), a daemon that does not
come up takes the machine's outbound network with it. Running the first pass
permissive converts that outage into a log line.

Dontaudit rules hide denials, and this module carries some
(`init_dontaudit_use_fds`, `userdom_dontaudit_search_user_home_dirs`). For a
validation pass you want to see everything:

```sh
sudo semodule -DB     # rebuild policy with dontaudit disabled
# ... run the tests ...
sudo semodule -B      # put it back when done
```

## Step 1: install

From the RPM (the selinux subpackage's `%post` runs `semodule` and the
relabel for you):

```sh
sudo dnf install ./colony-firewall-control-*.x86_64.rpm \
                 ./colony-firewall-control-selinux-*.noarch.rpm
```

Or by hand, from a checkout (these are the same commands as README.md in
this directory):

```sh
make -f /usr/share/selinux/devel/Makefile colony_firewall.pp
sudo semodule -i colony_firewall.pp
sudo restorecon -RvF /usr/bin/colony-firewalld /etc/colony-firewall \
    /var/lib/colony-firewall /var/log/colony-firewall /run/colony-firewall
```

Verify the label took - this is the single most common way a policy "fails"
while being perfectly correct:

```sh
ls -Z /usr/bin/colony-firewalld    # must say colony_firewalld_exec_t
```

If it says `bin_t`, the domain transition never happens, the daemon runs
unconfined, and every test below passes while testing nothing.

## Step 2: start the daemon and turn enforcement on

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

## Step 3: exercise every group the .te documents

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
| nft, the fast-allow set | needs ring 0 up (the object installed as in the bpf/perf row) and `[ebpf] fast_allow = true`, then both units running. Fast-allow armed: `cfc status` shows fast_allow live, `sudo nft list set inet colony_firewall fast_allow` shows one element. Then set `fast_allow = false` and `systemctl restart colony-firewalld`: the set is empty while the table is still loaded, which is the unconditional start-up flush. (Do **not** test this by stopping the daemon - `colony-firewall-nft.service` is `PartOf=` it and tears the whole table down first, so `list set` answers "No such file or directory" and tells you nothing about the flush.) | `cfc status` shows fast_allow off with an nft error as the reason, and the set stays empty; AVC on `iptables_exec_t` (execute) - the `netlink_netfilter_socket` nft needs is the filtering group's, already exercised by the first row |
| control socket, unconfined client | `cfc status` and `cfc rules list` as a normal logged-in user in the `colony-firewall` group (not root, not sudo) | connection refused/denied; AVC with the client's domain (`unconfined_t`) and `colony_firewall_runtime_t` |
| sqlite WAL in /var/lib | answer any prompt with a persistent choice (**a**, then `3`=always), then `ls /var/lib/colony-firewall/` - `rules.db-wal` and `rules.db-shm` must exist while the daemon runs | the `map` denial is the quiet one: no error anywhere, just journal-mode SQLite and a 2.5x write regression. An AVC with class `file` permission `map` on `colony_firewall_var_lib_t` is the tell |

Let the daemon run for at least a few minutes of normal use - browse
something, let NTP and DNS happen, `sudo dnf check-update` for the provenance
path. The rules that get missed by policies written away from the platform
are the periodic ones, not the startup ones.

## Step 4: collect the verdict

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

## Step 5: the same pass, enforcing

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

## Reporting

Open an issue containing:

- distro and release (`cat /etc/os-release`),
- `colony-firewalld --version`,
- whether the run was permissive or enforcing,
- the full `audit2allow -w -a` output, and the matching raw `ausearch -m AVC`
  lines.

A missing rule is a bug in `colony_firewall.te`, **not something to add
locally**. A local module would fix your machine and nobody else's, and the
next package update would reintroduce the gap for everyone whose machine it
never fixed. The one exception the README already carves out: if the denial
asks for `sys_admin`, that is a regression in the daemon to find, not a rule
to add anywhere.
