# Troubleshooting

The failure modes of an outbound firewall are unusually punishing: when it
breaks, *the network* breaks, and the tool you'd use to debug it may be on
the other side of the connection it just dropped. Read
[Testing over SSH](#testing-over-ssh-without-locking-yourself-out) before
enabling enforcement on any machine you reach over SSH.

## Daemon restarts and rule upgrades

Once loaded, both nft tables survive daemon stops and restarts. With no queue
listener, new tracked flows drop; established and related traffic retains its
authorization. To intentionally remove filtering, disable the corresponding
nft unit with `--now`:

```sh
sudo systemctl disable --now colony-firewall-nft colony-firewalld
sudo systemctl disable --now colony-firewall-nft-inbound
```

`disable` removes the network managers' requirement on the unit and reloads
systemd before stopping it. A plain `systemctl stop` keeps that requirement
loaded, so an active NetworkManager or systemd-networkd stops with the unit,
and starting the manager again loads the table again. Disable the daemon too
if filtering should stay off: starting it loads the outbound table. Uninstall
removes both tables and Colony's pinned BPF directory.

Never `restart` an nft unit, including from configuration management: it
deletes the table before loading it again, which leaves new flows unfiltered
for a moment, and it restarts the daemon and the network managers that
require the unit. `reload` replaces the table in one transaction.

Package upgrades reload active nft units atomically. After a manual upgrade,
run `systemctl daemon-reload`, then `systemctl reenable colony-firewall-nft`
(and the inbound unit only if already enabled; never the daemon, whose
`Also=` would enable a disabled nft unit), and
`systemctl reload colony-firewall-nft` (and the inbound unit if active) before
relying on the new rules. Reenable installs the native network-manager
requirements on existing deployments. A startup error saying the
legacy fast_allow nftables set could not be flushed means a mark left by an
older release may still be accepted; resolve that error and inspect the loaded
table. The nft units load
before the daemon. Failed daemon initialization leaves filtering installed;
a failed nft load blocks the daemon and the enabled NetworkManager or
systemd-networkd requirements. This covers those managers' startup after
enforcement is enabled, not initramfs networking or already configured
interfaces. Later external ruleset flushes also need operator coordination.

The inbound lockout guard reads persisted rules directly and never needs live
IPC. With an established remote session, unreadable saved rules prevent
activation. It uses Python's SQLite and TOML standard libraries; Python older
than 3.11 needs `CFC_RULES_DB` set to the actual configured database path for
this check. `CFC_INBOUND_FORCE=1` remains the explicit console override.

## Testing over SSH without locking yourself out

The outbound table cannot refuse a new inbound SSH session. It hooks
`output` and queues only `ct state new`, and everything `sshd` sends your
client is a reply on a connection the client opened, so it is
`ct state established` and never queued. That holds while the daemon is
down too. Two things can still cut you off:

- **The inbound table** (`colony-firewall-nft-inbound`, opt-in). It queues
  every new inbound connection, SSH included, and only an inbound Allow rule
  admits one. Its final `queue num 0` has no `bypass`, so while no daemon
  listens it drops every new inbound connection whatever the rules say. The
  session you enabled it from survives; the next one does not. Its lockout
  guard (see above) refuses to load the table when no inbound Allow rule
  could admit an established session, but it does not check the rule's
  source network, and no rule admits anything while the daemon is down.
- **Outbound lookups your login makes.** `sshd` and its PAM and NSS stack
  can open new outbound flows while you log in: reverse DNS with
  `UseDNS yes`, an LDAP, Kerberos, SSSD or RADIUS server. They are root
  processes, so with no root prompt subscriber they get `no_ui_action` at
  once (a denial under every profile), and while the daemon is down they
  drop. Accounts that resolve locally are unaffected. Find these flows with
  `sudo cfc prompts` or `cfc log --action deny` and allow each one scoped to
  its program and server, for example
  `sudo cfc rules add --exe <program> --dst-net <server> --dst-port <port> --protocol tcp --name login-ldap`.

Do not exempt port 22 in the outbound chain. It does nothing for reaching
the box, and `tcp dport 22 accept` lets every process on the host, attributed
or not, reach any address on that port without a verdict or a log line.

Use both of these the first time:

**1. Arm a dead-man's switch BEFORE applying the rules.** In a detached
shell that survives your SSH session:

```sh
sudo setsid sh -c 'sleep 300; nft delete table inet colony_firewall_inbound; nft delete table inet colony_firewall' &
```

Then enable enforcement. If you still have connectivity after testing,
cancel the timer (`sudo pkill -f '[n]ft delete table'`; the brackets keep
the pattern from matching the `sudo` running it), or, after it fired,
`sudo systemctl reload colony-firewall-nft` (and
`colony-firewall-nft-inbound` if it is enabled) to load the tables again.
If you locked yourself out, wait out the five minutes and both tables
delete themselves. Deleting the inbound table fails harmlessly when it was
never loaded.

**2. Know the console recovery.** From a local console, serial console, or
your VPS provider's emergency shell:

```sh
nft delete table inet colony_firewall_inbound   # admit inbound again
nft delete table inet colony_firewall           # stop enqueueing outbound
# or
systemctl start colony-firewalld                # give the queue a consumer again
```

Deleting the tables disables enforcement; starting the daemon resumes it,
and with it any inbound Allow rule you wrote.

## No network after enabling

Work down this list:

**Is the daemon actually running?**

```sh
systemctl status colony-firewalld
cfc status
```

If `systemctl` shows the unit dead while the nftables rule is loaded, you
are in the fail-closed state (see the
[matrix](#fail-open-vs-fail-closed-matrix)): new non-loopback flows are
queued to NFQUEUE 0 and nobody answers. Start the daemon or delete the table.

**Is the nftables table actually loaded?**

```sh
sudo nft list table inet colony_firewall
```

If this errors with "No such file or directory", nothing is being
enqueued - the daemon runs but enforces *nothing*, silently. This is the
usual state after a reboot if you only ever applied the snippet manually
with `nft -f`: nftables rules do not persist across reboots on their own.
Enable the companion unit (`colony-firewall-nft.service`) so the rule comes
back at boot.

**Do the queue numbers match?** The snippet says `queue num 0`; the daemon
binds the queue from `[nfqueue] queue_num` in `daemon.toml` (default 0).
If they differ, packets queue to a number nobody consumes - same lockout
as a dead daemon.

**The fail-open alternative.** If you would rather lose filtering than
lose the network when the daemon is down, add the `bypass` keyword to the
final queue rule of a local copy of the snippet (see
[Changing the shipped ruleset](#changing-the-shipped-ruleset)):

```
ct state new queue num 0 bypass
```

With `bypass`, the kernel accepts packets whenever no program is attached
to the queue. The tradeoff is exactly that: kill the daemon (or crash it)
and every outbound connection is silently allowed. Fail-closed is the
safer posture; `bypass` is the pragmatic one for remote machines you can't
reach a console for.

## The daemon exits immediately

A failed NFQUEUE bind now exits non-zero. It used to exit 0, which meant
systemd showed a happy unit while the fail-closed nftables rule quietly
blackholed the machine - so if the unit is `failed`, that is the
improvement working, and the reason is in the journal:

```sh
journalctl -u colony-firewalld -b --no-pager | tail -40
```

The daemon prints hint lines next to the failure. Four causes:

**Missing capability.** `failed to open NFQUEUE socket: ...` followed by
a `CAP_NET_ADMIN` hint. Run it via the bundled unit rather than by hand;
if you are running it by hand for development, use `--dry-run`, which
skips the bind entirely and still serves the gRPC/UI surface.

**Missing kernel module.**

```sh
lsmod | grep nfnetlink_queue
sudo modprobe nfnetlink_queue
```

**Queue number already taken.** `failed to bind NFQUEUE 0: ...` plus
`hint: another process may already own this queue number.` Something else
(a second copy of the daemon, opensnitch, a stray `nfqws`) owns it:

```sh
ss -f netlink | grep nfqueue
```

Either stop the other consumer, or move this daemon to a free number in
`[nfqueue] queue_num` **and** change the matching `queue num N` in your
nftables rule. The two must agree or you get the same lockout as a dead
daemon.

**The rule database cannot be opened.** Startup opens
`/var/lib/colony-firewall/rules.db` (`[storage] path`) before anything
else, so these fail on every start:

```sh
journalctl -u colony-firewalld -b -g 'opening rule store|durable storage requires|newer than this daemon supports'
```

- `durable storage requires WAL` or `synchronous=FULL`: the path is on a
  filesystem that cannot hold a WAL journal (a network share, for one), or
  outside the directories the unit can write. Keep `[storage] path` on local disk
  under `/var/lib/colony-firewall`.
- `newer than this daemon supports`: the package was downgraded. Reinstall
  the newer one, or restore a backup of `rules.db` that the older version
  wrote.
- Any other error under `opening rule store` or `purging transient rules`:
  usually a full `/var`. Free space and start the daemon again.

Once it starts cleanly the unit reports ready only after both the queue
and the control socket are bound, so `systemctl is-active` genuinely
means "filtering".

## Permission denied on the socket

The GUI will not connect, or `cfc` prints:

```
permission denied on /run/colony-firewall/cfc.sock - add your user to the
colony-firewall group (sudo usermod -aG colony-firewall $USER) then log
out and back in, or run as root. The group gives read access and lets the
Colony Firewall app and tray connect; firewall changes come from the app,
the tray or sudo cfc
```

The control socket is `root:colony-firewall` mode 0660, so the kernel
refuses the connection before the daemon ever sees it. Do exactly what
the message says:

```sh
sudo usermod -aG colony-firewall $USER
```

then **log out and back in**. A new terminal is not enough - group
membership is fixed at login, so your existing session still has the old
group set. `id -nG` tells you whether it took; `newgrp colony-firewall`
gets you a single shell with the group applied if you cannot log out
right now.

If it still fails, check the socket actually has the group:

```sh
ls -l /run/colony-firewall/cfc.sock
# expected: srw-rw---- 1 root colony-firewall ...
```

`srw-------` and root ownership means the group did not exist when the
daemon started. It warns about this at startup rather than refusing to
run:

```sh
journalctl -u colony-firewalld -g 'does not exist'
```

Create the group and restart the daemon:

```sh
sudo systemd-sysusers          # if the shipped sysusers fragment is installed
# or
sudo groupadd -r colony-firewall
sudo systemctl restart colony-firewalld
```

Two neighbouring errors that are *not* this one, and say so:

- `socket ... does not exist - is colony-firewalld running?` - nothing has
  ever bound it. Start the daemon, or you are pointing `--socket` at the
  wrong path.
- `stale socket at ... - the daemon crashed or was killed` - the file is
  there but nobody is listening. Restart the daemon.

Every one of these exits 4 ("daemon unreachable"), so scripts can tell
them apart from a bad argument (2) or a missing rule (3).

## A change is refused: "read-only access"

Since 0.8.0 only root and the installed Colony Firewall app and tray can
change the firewall. Everything else of yours, `cfc` without sudo included,
is read-only, and the daemon says why (exit 1):

```
read-only access: <reason>. Firewall changes are accepted only from the
installed Colony Firewall app and tray, or from root (sudo cfc ...).
```

- **From `cfc`**: run it with `sudo`. A non-root `cfc prompts` still shows
  prompts but cannot answer them, and does not count as a connected UI.
- **"this colony-firewall is not the installed /usr/bin/colony-firewall
  (restart it after an upgrade)"** or **"the caller did not seal itself at
  startup"**: the app or tray was upgraded under you, or is a 0.7 build.
  Quit and start it again (the tray from your session's autostart or by
  hand, `colony-firewall-tray &`). The tray tells you once in a
  notification when its binary was replaced, and shows the reason when an
  answer is refused. Until it restarts, the first prompt after the upgrade
  waits out `prompt_timeout_secs` and later ones take `no_ui_action`, unless
  the app is open and current.
- **"the caller loaded /home/…/something.so"**: a library from outside the
  root-owned system directories is mapped into the app, usually a global
  `LD_PRELOAD` (MangoHud, gamemode) or a user-installed Vulkan layer or
  GTK/input-method module. Start the app without it. The daemon refuses to
  trust a process that runs code it cannot vouch for.
- **"the caller is being traced"**: a debugger or `strace` is attached.
- **"the caller runs in a private mnt (or user) namespace"**: the app was
  started inside a sandbox or container wrapper. Start it directly.
- **"the connection's client end is unknown (unix_diag: …)"**: the kernel
  has no `unix_diag` support (module not loaded). `sudo modprobe unix_diag`;
  until then the app and tray are read-only and `sudo cfc` works.
- **"firewall changes require root, or the installed Colony Firewall app or
  tray run by a member of group 'colony-firewall'"**: you started the app
  from a session that predates joining the group. Log out and back in.

The journal names the caller and the reason for every refusal:

```sh
journalctl -u colony-firewalld -g 'refusing a firewall change'
```

## Pause, resume, import or an Allow rule asks for a password, or fails

Pause, resume and rule import change the whole firewall at once, and an
Allow rule that names no program lets every program through, so the app and
tray need an administrator password for them (polkit: every time for pause
and resume, kept a few minutes for the others). Root (`sudo cfc`) is never
asked. Rules that name a program, and Deny rules, never ask. What the
refusals mean:

- **"authorization dialog dismissed"**: you cancelled it.
- **"no polkit authentication agent answered in your session"**: nothing in
  your session shows polkit dialogs. Start one (`hyprpolkitagent`,
  `polkit-gnome-authentication-agent-1`, `lxqt-policykit-agent`; most full
  desktops already run one) or use `sudo cfc pause`.
- **"polkit is not installed or not running"** or **"the system D-Bus is
  unreachable"**: install polkit, or use `sudo cfc`.
- **"not authorized by polkit policy"**: a local polkit rule denies
  `org.projectcolony.firewall.pause`, `org.projectcolony.firewall.import-rules`
  or `org.projectcolony.firewall.allow-every-program` for you. `pkaction --verbose --action-id org.projectcolony.firewall.pause`
  shows the defaults; a missing action means the policy file is not
  installed in `/usr/share/polkit-1/actions/`.
- **"authorization timed out after 120 s"**: the dialog was left open; the
  daemon closed it.

## The daemon warns about `kernel.yama.ptrace_scope`

`kernel.yama.ptrace_scope is 1: a program of the desktop user can start the
installed app or tray under ptrace ...` is logged once at startup. It is not
an error: with that setting any program of yours can start the app under a
debugger, change its code before it seals itself and make changes as it,
and the daemon cannot tell afterwards. Setting
`kernel.yama.ptrace_scope = 2` closes that route; the commands are in
[HARDENING.md](HARDENING.md#the-control-socket-and-who-can-talk-to-it).
Debugging your own programs then needs root.

## Loopback and the local resolver

The snippet's `output` hook matches loopback traffic too. On systems using
systemd-resolved, every DNS query goes to the stub resolver at
`127.0.0.53:53` - over loopback. The shipped ruleset queues new loopback
flows with their own rule, just above the final queue rule:

```
oifname "lo" ct state new queue num 0 bypass
ct state new queue num 0
```

While the daemon runs, it judges them like any other flow: explicit rules
apply, and unmatched local IPC (the stub resolver, CUPS, a local dev
server) is allowed without prompting. While nothing listens on the queue,
`bypass` makes the kernel accept them, so local IPC keeps working when the
daemon is down. That includes the stub resolver's socket, but only for names
it can answer from its cache or local records: its queries to the upstream
servers are new non-loopback flows, so resolving anything else still needs
the daemon. Every non-loopback new flow still meets the fail-closed rule.

`bypass` only covers a daemon that is not listening. A daemon that listens
but whose single worker is stuck (an executable on a hung mount being
hashed, for instance) leaves new loopback flows, local DNS included,
waiting in the same queue; once it fills they drop until the watchdog
restarts the daemon, which takes up to about 90 seconds.

If you load a local copy of the snippet, compare it with the shipped one
after every upgrade: a copy without the loopback rule drops every new
loopback flow whenever the daemon is down, and one with an explicit
`oifname lo accept` skips the daemon for loopback entirely, so loopback
rules never apply.

Note the daemon already exempts its *own* reverse-DNS lookups internally
(they would otherwise deadlock the queue); the loopback rule is about
everyone else's DNS.

## Traffic that never reaches the daemon

The `output` chain (and the inbound one) only queues `ct state new`.
Two kinds of packet are settled in the kernel instead:

- **Link control is accepted.** IPv6 neighbour discovery and MLD, which
  conntrack itself marks untracked, and IGMP membership traffic. Only the
  hop limits (and, for MLD, the sources) the RFCs require match, so these
  stay on the link. Without them IPv6 neighbour resolution and multicast group
  membership stop working; ND and MLD never reach the queue, so no rule
  could restore them.
- **Other INVALID and UNTRACKED packets drop**, including flows an
  explicit `notrack` rule touched (a busy DNS or NTP server's tuning, for
  instance). An `accept` in another table does not override this chain's
  `policy drop`. To keep such flows, load a local copy of the snippet with
  an accept for them above the queue rules (see
  [Changing the shipped ruleset](#changing-the-shipped-ruleset)).

## Changing the shipped ruleset

`colony-firewall-nft.service` loads
`/usr/share/colony-firewall/nftables-snippet.conf`, and that file starts by
deleting any `table inet colony_firewall` already loaded. A table of that name
from `/etc/nftables.conf` or a manual `nft -f` is therefore replaced at boot,
whenever the daemon starts (it requires the unit) and on every package
upgrade (which reloads the unit). Carry changes as a local copy that the unit
loads instead:

```sh
sudo install -Dm644 /usr/share/colony-firewall/nftables-snippet.conf \
     /etc/colony-firewall/nftables-snippet.conf
sudoedit /etc/colony-firewall/nftables-snippet.conf
sudo systemctl edit colony-firewall-nft
```

and in the drop-in, override both commands (upgrades reload, so
`ExecReload=` matters as much as `ExecStart=`):

```
[Service]
ExecStart=
ExecStart=/usr/bin/nft -f /etc/colony-firewall/nftables-snippet.conf
ExecReload=
ExecReload=/usr/bin/nft -f /etc/colony-firewall/nftables-snippet.conf
```

Then `sudo systemctl reload colony-firewall-nft`. Keep the `add table` and
`delete table` lines at the top of the copy: they are what lets a reload
replace the table in one transaction. Upgrades do not touch the copy, so
compare it with the shipped file after each one. The inbound unit takes the
same drop-in with `nftables-inbound.conf`.

## Fail-open vs fail-closed matrix

What happens to a **new outbound connection** in each state:

| State                              | Without `bypass` on the final rule (shipped) | With `bypass`        |
|------------------------------------|--------------------------------|--------------------------------|
| Daemon up, nft rule loaded         | Filtered: rules, then prompts, then profile fallback | Same |
| Daemon down, nft rule loaded       | **Dropped. Outbound lockout** (new loopback flows still allowed) | Allowed, unfiltered (silent) |
| Daemon up, nft rule *not* loaded   | Allowed, unfiltered (silent - daemon sees nothing) | Same |
| Daemon paused (`cfc pause`)        | Rules still enforced; only *unmatched* flows pass instead of prompting. Auto-resumes | Same |

Pause has a deadline: it auto-resumes after `[pause] default_secs`
(default 10 minutes) or whatever `cfc pause --for` asked for, clamped to
24 hours. `cfc status` shows the resume time.

The two "silent" rows are the ones that bite: everything looks healthy
(`cfc status` answers, the GUI connects) but no packet is being judged.
`sudo nft list table inet colony_firewall` is the ground truth for whether
enforcement is on.

## Prompt timeouts per profile

When a connection matches no rule, the daemon asks the UI and waits. Two
settings in `daemon.toml` govern what happens when nobody answers:

- `no_ui_action` - the verdict when **no UI is connected at all** (no
  prompt is even shown).
- `timeout_action` - the verdict when a prompt was shown but **expired
  unanswered** after `prompt_timeout_secs`.

The named profiles are presets for these three values (and for
`inbound_action`, which only the opt-in inbound table uses):

| Profile  | `no_ui_action` | `timeout_action` | `prompt_timeout_secs` |
|----------|----------------|------------------|-----------------------|
| relaxed  | Deny           | Deny             | 60                    |
| balanced | Deny           | Deny             | 30 (default)          |
| strict   | Deny           | Deny             | 15                    |

No profile permits anything on its own: the presets differ only in how
long a prompt waits and, for the opt-in inbound table, whether an
unmatched flow is rejected or dropped. Only a stored rule, or a person
answering, allows a connection. You can still override either field
explicitly under `[default_policy]`; the point is that nothing does it
for you.

`timeout_action` is `Deny` in every profile on purpose: a prompt you
were shown and did not answer must not become an allow, or connecting
while nobody is at the keyboard is the easiest way through. If you truly
want the old allow-on-timeout behaviour, set it explicitly:
`timeout_action = "Allow"` under `[default_policy]`.

Under `strict`, "the UI wasn't running" means "everything was denied" -
which is the point, but is also why strict on a headless box with no
pre-seeded rules looks exactly like a dead network. See "Prompts never
appear on a headless server" below.

Uncommenting a `[default_policy]` field overrides *that one field* and
leaves the rest of the profile alone - so `profile = "strict"` plus
`prompt_timeout_secs = 30` is strict with a longer window, not balanced.
The profile and every `[default_policy]` field hot-reload on `SIGHUP`, as
does `[provenance]`; every other section needs a restart.

## Prompts never appear on a headless server

There is no GUI to pop them, so the daemon applies `no_ui_action` to
every unmatched flow without asking anyone: a denial under every
profile, which looks exactly like a dead network. This is the intended
behaviour: on a headless box "nobody is connected" is the permanent
state, and allowing would mean the machine has no outbound firewall at
all.

Confirm what you are in:

```sh
cfc status
# prompt policy    30s timeout -> deny, no UI -> deny
```

Inbound SSH is unaffected: the outbound ruleset never queues a session's
replies, and the opt-in inbound table judges by your inbound rules and
`inbound_action`, not `no_ui_action`. A login that needs the network (LDAP,
Kerberos, reverse DNS) is the exception; see
[Testing over SSH](#testing-over-ssh-without-locking-yourself-out).

Then pick one of three fixes:

**1. Answer prompts from the terminal.** This is what `sudo cfc prompts`
is for - it subscribes just like the GUI does, so the daemon starts asking
(without sudo it only watches, and the daemon keeps applying `no_ui_action`):

```sh
sudo cfc prompts
```

Keys are `a` allow, `d` deny, `r` reject, `s` skip (let it time out), `q`
quit; then a duration and, for persistent answers, a scope. It works over
SSH, and falls back to line-at-a-time input when stdin is a pipe.

Run it for a while, answer the traffic you expect, and you have a rule
set. For a bounded unattended window - during a package install, say -
`--auto-allow` or `--auto-deny` answer everything without asking, and
`--count N` exits after N prompts.

**2. Pre-seed rules and accept the fallback.** `sudo cfc rules
bundle add system` (also spelled `sudo cfc rules bootstrap-defaults`) covers
the usual system services. `cfc rules bundle list` shows the others:
`web` for installed browsers, `dev` for git/cargo/docker, `updates` for
apt/dnf/flatpak, each scoped to a specific executable, never to a bare
port. Entries whose program is not installed here are skipped and
reported. Add your own with
`sudo cfc rules add`. Anything you did not anticipate still hits
`no_ui_action`.

**3. Change the fallback, deliberately.** `no_ui_action = "Allow"` in
`[default_policy]` makes an unattended box fail open. No profile does
this for you any more, and you should think before writing it: it means
the firewall enforces only what you explicitly wrote down, and every
unanticipated connection, including a payload phoning home, goes out
unasked. Prefer (1) or (2). If you do set it, send `SIGHUP` and it takes
effect without a restart.

Note that `sudo cfc prompts` and the GUI can both be connected at once, and
both see the prompts addressed to you. Delivery is scoped by the uid
that owns the connecting process: you receive prompts for your own
processes, root receives everything, and traffic the daemon could not
attribute to any process goes to every session. Only a subscriber that
actually received a prompt can answer it, so a verdict from another
user's session is refused with "this prompt was not delivered to you".

One consequence worth knowing on a desktop: prompts for root-owned
processes are only delivered to a root subscriber. With none connected,
they resolve immediately with `no_ui_action` rather than waiting out the
timeout. If you want to answer those interactively, run `sudo cfc
prompts`. See docs/HARDENING.md for the full delivery table.

## Reject behaves like Deny

Symptom: a `Reject` answer or rule makes the application hang until its
own timeout instead of failing immediately.

**Check for the capability warning first.** Reject injects a real TCP RST
or ICMP port-unreachable, which needs `CAP_NET_RAW`. The daemon reports a
missing capability exactly once, at startup:

```sh
journalctl -u colony-firewalld -b -g 'raw socket setup failed'
```

```
raw socket setup failed (...); Reject rules will behave like Deny for
those families. CAP_NET_RAW is required - the bundled
colony-firewalld.service grants it.
```

This is non-fatal by design - the packet is still dropped, so the
security outcome is unchanged and only the user experience degrades. If
you see it, you are almost certainly running the daemon outside the
bundled unit, or with an edited unit that dropped `CAP_NET_RAW` from
`AmbientCapabilities` / `CapabilityBoundingSet`.

Two cases where Reject legitimately falls back to a plain drop:
protocols other than TCP and UDP (there is no meaningful refusal to send
for ICMP), and a packet too short to quote in an ICMP error.

## systemd keeps restarting the daemon

The unit sets `WatchdogSec=30`, and the daemon only sends heartbeats
while its packet worker is making progress. A restart with

```
Watchdog timeout (limit 30s)!
```

in the journal means the worker stopped responding, not that the machine
was idle - an idle worker still wakes every few milliseconds to check
for work, and that counts as progress, so an idle system is never killed. Look
for the daemon's own complaint just before the restart:

```sh
journalctl -u colony-firewalld -g 'NFQUEUE worker unresponsive'
```

Detection is bounded at roughly 90 seconds (a 10s heartbeat interval, a
60s stall threshold, a 30s watchdog). If this recurs, capture
`journalctl -u colony-firewalld -b -1` from before the restart and file
it - a wedged worker is a bug, not a tuning problem. As a stopgap you can
raise `WatchdogSec` with a drop-in
(`systemctl edit colony-firewalld`), but that trades a restarting daemon
for a stalled one, and under the fail-closed nftables rule a stalled
daemon is a dead network.

Restarts *without* a watchdog message are ordinary failures -
`Restart=on-failure` retrying a start that keeps failing, such as a queue
bind or the rule database. See "The daemon exits immediately" above. A
full disk at runtime does not restart the daemon: it costs event-log rows,
which the journal reports as `event log write failed`.

If manual restarts pile on top of the automatic ones, systemd can give up
with `start request repeated too quickly`. Fix the cause, then:

```sh
sudo systemctl reset-failed colony-firewalld && sudo systemctl start colony-firewalld
```

## Some rules are not being enforced

`cfc status` warns on stderr when rules on disk could not be loaded:

```
warning: 2 rule(s) on disk could not be loaded and are NOT being enforced
```

This means the JSON for those rows failed to parse - usually after
downgrading to an older daemon than the one that wrote them. The rows are
**preserved on disk**, never deleted, so upgrading again recovers them.
The ids are named in the journal:

```sh
journalctl -u colony-firewalld -g 'failed to deserialize'
```

If you need the rule back now and cannot upgrade, delete the offending
row with `sudo cfc rules remove <id>`, giving the full id from the journal,
and re-create it with `sudo cfc rules add`.

The same warning counts **quarantined** rows: rules an older version
accepted that the daemon now refuses (for example one scoped only on a
parent executable, which would match every process). They are not
applied, not listed, and preserved on disk. The journal names each one
and why:

```sh
journalctl -u colony-firewalld -g 'fails the API boundary'
```

Remove it with `sudo cfc rules remove <id>` (the full id) and re-create it
in a form the daemon accepts. `sudo cfc rules import --replace` also deletes
such rows.

## An Allow rule no longer lets a program through

Since 0.8.0 a Deny or Reject rule scoped to a program (`--exe` or
`--sha256`) wins over every Allow rule that names no program, however many
predicates that Allow has. A broad `allow --protocol tcp --dst-port 443`
therefore no longer admits a program that `deny --exe` refuses, and the
connect hooks may refuse that program outright. To let it through on some
destinations, add an Allow scoped to the same program and those
destinations (`--exe X --dst-port 443`): among program rules the more
specific one still wins. A `/0` network no longer counts when rules are
ranked either, so a rule that relied on `--dst-net 0.0.0.0/0` to outrank
another may now lose the tie to a Deny. `cfc rules list` shows the rules
involved; the hit counters show which one answers.

## A prompt says the program could not be identified

Since 0.8.0 a flow whose program is only partly known (no socket owner
found, a binary too large to hash, a process that exited first) is asked
about when a rule naming a program may apply to it, instead of being
refused in silence. The prompt names that rule and says the program could
not be fully identified; your answer applies to that connection only. With
no app, tray or `sudo cfc prompts` connected the flow takes `no_ui_action`,
and the event log shows it with that rule's id and source `default`.

The usual rule named is a program Deny or Reject (`deny --exe X`, often one
an earlier "Deny always" answer created): since 0.8.0 it beats every
generic Allow, so a flow from an unknown program no longer passes a generic
Allow it matches while that Deny might be about it. Unattributed UDP under
`allow --uid 1000 --protocol udp --dst-port 53` is the common case. No Allow
rule can settle this. Either scope the named Deny to destinations
(`--dst-port`, `--dst-net`) so it cannot apply to these flows, or make
attribution succeed (below). A `--sha256` Deny without `--exe` does the same
to every image over 64 MiB (Chromium, Electron, VS Code), since any of them
could be the denied one: re-create it with `--exe` as well.

These prompts appear even while paused or for loopback flows, because a
rule may be about them. If they are frequent, find out why attribution
fails. Run the daemon with `--debug` (`systemctl edit colony-firewalld`,
then repeat `ExecStart=` with `--debug` appended) and look for:

```sh
journalctl -u colony-firewalld -g 'udp attribution ambiguous|attribution budget expired|table unreadable|identity is incomplete'
```

"udp attribution ambiguous" means several sockets could own the datagram
(typically `SO_REUSEPORT` or a wildcard-bound socket shared across
programs); scope a rule on the port instead of the program for that
traffic.

## Where things live

| Thing                   | Path                                        |
|-------------------------|---------------------------------------------|
| Control socket (gRPC)   | `/run/colony-firewall/cfc.sock`             |
| Daemon config           | `/etc/colony-firewall/daemon.toml`          |
| Rules database (SQLite) | `/var/lib/colony-firewall/rules.db`         |
| systemd units           | `/usr/lib/systemd/system/colony-firewalld.service`, `colony-firewall-nft.service`, `colony-firewall-nft-inbound.service` |
| nftables rulesets       | `/usr/share/colony-firewall/nftables-snippet.conf`, `nftables-inbound.conf` |
| nftables tables         | `table inet colony_firewall` (chain `output`), `table inet colony_firewall_inbound` (opt-in) |
| polkit actions          | `/usr/share/polkit-1/actions/org.projectcolony.firewall.policy` |
| eBPF object (optional)  | `/usr/lib/colony-firewall/cfc-ebpf.o` (`[ebpf] object_path`) |

`cfc` takes `--socket <path>`, and the GUI and tray read the `CFC_SOCKET`
environment variable, to point at a non-default socket (useful with
`--dry-run` daemons during development).
