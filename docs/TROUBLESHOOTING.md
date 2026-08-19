# Troubleshooting

The failure modes of an outbound firewall are unusually punishing: when it
breaks, *the network* breaks, and the tool you'd use to debug it may be on
the other side of the connection it just dropped. Read the first section
before enabling enforcement on any machine you reach over SSH.

## Testing over SSH without locking yourself out

The shipped nftables snippet is **fail-closed**: `queue num 0` without the
`bypass` keyword means that if nothing is listening on NFQUEUE 0 (daemon
stopped, crashed, or not yet started), the kernel drops every *new*
outbound connection. Your established SSH session survives (`ct state new`
only matches new flows), but the moment it drops you cannot open a new one.

Three layers of protection, use all of them the first time:

**1. Allow SSH above the queue rule.** Edit your copy of the snippet so
port 22 never reaches NFQUEUE at all:

```
table inet colony_firewall {
    chain output {
        type filter hook output priority 0; policy accept;
        tcp dport 22 accept
        ct state new queue num 0
    }
}
```

(This exempts *outbound* SSH from filtering - for a remote machine you
manage, also make sure your *inbound* SSH path doesn't depend on any
process this firewall could deny, e.g. a DNS lookup in `sshd`'s PAM stack.)

**2. Arm a dead-man's switch BEFORE applying the rules.** In a detached
shell that survives your SSH session:

```sh
sudo setsid sh -c 'sleep 300 && nft delete table inet colony_firewall' &
```

Then apply the snippet. If you still have connectivity after testing,
cancel the timer (`sudo pkill -f 'nft delete table'`, or just re-apply the
snippet after the timer fires). If you locked yourself out, wait out the
five minutes and the table deletes itself.

**3. Know the console recovery.** From a local console, serial console, or
your VPS provider's emergency shell:

```sh
nft delete table inet colony_firewall   # stop enqueueing entirely
# or
systemctl start colony-firewalld        # give the queue a consumer again
```

Either one restores traffic; the first disables enforcement, the second
resumes it.

## No network after enabling

Work down this list:

**Is the daemon actually running?**

```sh
systemctl status colony-firewalld
cfc status
```

If `systemctl` shows the unit dead while the nftables rule is loaded, you
are in the fail-closed state described above: packets are queued to NFQUEUE
0 and nobody answers. Start the daemon or delete the table.

**Is the nftables table actually loaded?**

```sh
sudo nft list table inet colony_firewall
```

If this errors with "No such file or directory", nothing is being
enqueued - the daemon runs but enforces *nothing*, silently. This is the
usual state after a reboot if you only ever applied the snippet manually
with `nft -f`: nftables rules do not persist across reboots on their own.
Enable the companion unit (`colony-firewall-nft.service`) or merge the
snippet into `/etc/nftables.conf` so the rule comes back at boot.

**Do the queue numbers match?** The snippet says `queue num 0`; the daemon
binds the queue from `[nfqueue] queue_num` in `daemon.toml` (default 0).
If they differ, packets queue to a number nobody consumes - same lockout
as a dead daemon.

**The fail-open alternative.** If you would rather lose filtering than
lose the network when the daemon is down, add the `bypass` keyword:

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

The daemon prints hint lines next to the failure. Three causes:

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

Once it starts cleanly the unit reports ready only after both the queue
and the control socket are bound, so `systemctl is-active` genuinely
means "filtering".

## Permission denied on the socket

The GUI will not connect, or `cfc` prints:

```
permission denied on /run/colony-firewall/cfc.sock - add your user to the
colony-firewall group (sudo usermod -aG colony-firewall $USER) then log
out and back in, or run as root
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

## Loopback and the local resolver

The snippet's `output` hook matches loopback traffic too. On systems using
systemd-resolved, every DNS query goes to the stub resolver at
`127.0.0.53:53` - over loopback - so each lookup gets intercepted and can
prompt, time out, or (under `strict`) be denied. The symptom is DNS that
is slow, flaky, or dead while direct-by-IP connections work.

Exempt loopback above the queue rule:

```
table inet colony_firewall {
    chain output {
        type filter hook output priority 0; policy accept;
        oifname lo accept
        ct state new queue num 0
    }
}
```

Loopback traffic never leaves the machine, so exempting it costs you no
outbound coverage. The ruleset installed by the companion
`colony-firewall-nft.service` unit includes this exemption; the caveat
applies mainly if you carry an older copy of the snippet in your own
`/etc/nftables.conf`.

Note the daemon already exempts its *own* reverse-DNS lookups internally
(they would otherwise deadlock the queue); the loopback rule is about
everyone else's DNS.

## Fail-open vs fail-closed matrix

What happens to a **new outbound connection** in each state:

| State                              | Without `bypass` (shipped)     | With `bypass`                  |
|------------------------------------|--------------------------------|--------------------------------|
| Daemon up, nft rule loaded         | Filtered: rules, then prompts, then profile fallback | Same |
| Daemon down, nft rule loaded       | **Dropped. Total outbound lockout.** | Allowed, unfiltered (silent) |
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

The named profiles are just presets for these three values:

| Profile  | `no_ui_action` | `timeout_action` | `prompt_timeout_secs` |
|----------|----------------|------------------|-----------------------|
| relaxed  | Deny           | Deny             | 60                    |
| balanced | Deny           | Deny             | 30 (default)          |
| strict   | Deny           | Deny             | 15                    |

No profile permits anything on its own — the presets differ only in how
long a prompt waits. Only a stored rule, or a person answering, allows a
connection. You can still override either field explicitly under
`[default_policy]`; the point is that nothing does it for you.

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
All three fields hot-reload on `SIGHUP`; nothing else in `daemon.toml`
does.

## Prompts never appear on a headless server

There is no GUI to pop them, so the daemon applies `no_ui_action` to
every unmatched flow without asking anyone — a denial under every
profile, which looks exactly like a dead network. This is the intended
behaviour: on a headless box "nobody is connected" is the permanent
state, and allowing would mean the machine has no outbound firewall at
all.

Confirm what you are in:

```sh
cfc status
# prompt policy    30s timeout -> Deny, no UI -> Deny
```

Inbound SSH is unaffected — the ruleset hooks `output` on `ct state new`,
and an established session's replies are never queued — so you always
have a way back in to fix it.

Then pick one of three fixes:

**1. Answer prompts from the terminal.** This is what `cfc prompts` is
for - it subscribes just like the GUI does, so the daemon starts asking:

```sh
cfc prompts
```

Keys are `a` allow, `d` deny, `r` reject, `s` skip (let it time out), `q`
quit; then a duration and, for persistent answers, a scope. It works over
SSH, and falls back to line-at-a-time input when stdin is a pipe.

Run it for a while, answer the traffic you expect, and you have a rule
set. For a bounded unattended window - during a package install, say -
`--auto-allow` or `--auto-deny` answer everything without asking, and
`--count N` exits after N prompts.

**2. Pre-seed rules and accept the fallback.** `cfc rules
bundle add system` (also spelled `cfc rules bootstrap-defaults`) covers
the usual system services. `cfc rules bundle list` shows the others —
`web` for installed browsers, `dev` for git/cargo/npm, `updates` for
apt/dnf/flatpak — each scoped to a specific executable, never to a bare
port. Entries whose program is not installed here are skipped and
reported. Add your own with
`cfc rules add`. Anything you did not anticipate still hits
`no_ui_action`.

**3. Change the fallback — deliberately.** `no_ui_action = "Allow"` in
`[default_policy]` makes an unattended box fail open. No profile does
this for you any more, and you should think before writing it: it means
the firewall enforces only what you explicitly wrote down, and every
unanticipated connection — including a payload phoning home — goes out
unasked. Prefer (1) or (2). If you do set it, send `SIGHUP` and it takes
effect without a restart.

Note that `cfc prompts` and the GUI can both be connected at once, and
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
was idle - a worker parked in a blocking `recv` with nothing to do is
explicitly treated as healthy, so an idle system is never killed. Look
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
`Restart=on-failure` retrying a bind that keeps failing. See "The daemon
exits immediately" above.

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
row by id and re-create it with `cfc rules add`.

## Where things live

| Thing                   | Path                                        |
|-------------------------|---------------------------------------------|
| Control socket (gRPC)   | `/run/colony-firewall/cfc.sock`             |
| Daemon config           | `/etc/colony-firewall/daemon.toml`          |
| Rules database (SQLite) | `/var/lib/colony-firewall/rules.db`         |
| systemd unit            | `/usr/lib/systemd/system/colony-firewalld.service` |
| nftables table          | `table inet colony_firewall` (chain `output`) |

The UI and `cfc` both accept `--socket <path>` to point at a non-default
socket (useful with `--dry-run` daemons during development).
