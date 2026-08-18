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
| Daemon paused (`cfc pause`)        | Allowed - everything gets an accept verdict; auto-resumes after 10 minutes | Same |

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
| relaxed  | Allow          | Allow            | 60                    |
| balanced | Allow          | Allow            | 15 (default)          |
| strict   | Deny           | Deny             | 10                    |

Under `strict`, "the UI wasn't running" means "everything was denied" -
which is the point, but is also why strict on a headless box with no
pre-seeded rules looks exactly like a dead network. Uncommenting any
`[default_policy]` field in `daemon.toml` overrides the profile wholesale.

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
