# Hardening guide

This page is for users who already have Colony Firewall Control running
and want to move from "ask me about everything" toward an actual security
posture. It is opinionated and reflects what works in practice on a Linux
desktop, not what's theoretically pure.

## TL;DR

1. Start in `profile = "balanced"`, leave the UI running.
2. Click through prompts for a week. Save persistent rules as you go.
3. Run `cfc rules bootstrap-defaults` to install common system rules.
4. Once the prompt rate drops to maybe 1-2 a day, switch to
   `profile = "strict"` for fail-closed behavior.
5. Audit `cfc rules list` monthly. Remove rules for apps you no longer use.

## Choosing a profile

| Profile  | No UI    | Timeout  | Window | Use when                                      |
|----------|----------|----------|--------|------------------------------------------------|
| relaxed  | Allow    | Allow    | 60s    | Headless servers / can't always be at the UI   |
| balanced | Allow    | Allow    | 15s    | Daily-driver workstations (default)            |
| strict   | Deny     | Deny     | 10s    | Lockdown posture, UI always present            |

The danger with `strict` is bootstrap: if the daemon starts before your UI
session is up, every outbound flow gets denied until you log in. Network
managers retrying DNS will look like total network failure. **Only flip to
strict after you have rules for every always-on system service**.

`bootstrap-defaults` is intended to bridge that gap.

## What to allow first

System services that *must* always work:

- `/usr/lib/systemd/systemd-resolved` to port 53 (DNS stub)
- `/usr/lib/systemd/systemd-timesyncd` or `/usr/bin/chronyd` to port 123 (NTP)
- `/usr/lib/systemd/systemd-networkd` (DHCP if you use it - UDP 67/68)
- Your VPN client if any (WireGuard usually doesn't traverse NFQUEUE,
  but split-DNS resolvers might)

User-side conveniences that hit the network constantly:

- Package manager: `/usr/bin/pacman`, `/usr/bin/paru`, `/usr/bin/makepkg` -> :443
- Web browser: `/usr/lib/firefox/firefox`, `/opt/google/chrome/chrome` -> :443, :80
- IDE / editor: depends, but many phone home for telemetry - decide per app

You can install the system service rules with one command:

```sh
cfc rules bootstrap-defaults
```

This is idempotent: it skips rules already present by name.

## What to *deny* first

A short blocklist that pays off on most workstations:

- Any DNS-over-TLS or DoH client you didn't install on purpose
- Adobe / Microsoft / Google telemetry endpoints (use `dst_host` rules)
- Crashpad processes in browsers that you don't want phoning home

Example with the CLI:

```sh
cfc rules add --action deny --dst-host 'incoming.telemetry.mozilla.org' \
              --name 'block-firefox-telemetry'
```

### A warning about `dst_host`

Hostname matching is currently based on reverse DNS: the daemon does a
PTR lookup on the destination IP and matches `dst_host` against whatever
comes back. **PTR records are controlled by whoever controls the
destination IP** - a hostile server can name itself anything, including a
hostname you trust. Treat `dst_host` as best-effort display metadata and
a convenience for *deny* rules (a telemetry endpoint has no incentive to
hide its own PTR). Do **not** rely on hostname *allow* rules as a
security boundary: an attacker-controlled IP can trivially wear an
allowed name. For allow rules, pin `exe` + `dst_port` (+ `dst_net` where
destinations are stable) instead.

## Rule design principles

**Prefer narrow scopes.** A rule that only matches `exe + dst_port +
protocol` is much safer than `exe` alone - if a process is later
compromised, the attacker still can't pivot to arbitrary destinations.

**Watch the hit counter.** `cfc rules list` shows `hits` per rule. A rule
with zero hits after weeks of use is probably obsolete or wrong.

**Stable paths matter.** Symlinks like `/usr/bin/python` may point to a
different binary after an interpreter upgrade. When in doubt, target the
real path under `/usr/lib/...` or pin by SHA-256 (`scope.exe_sha256`).

## What this firewall does *not* protect against

- **Anything from root**: `/usr/bin/colony-firewalld` itself is trusted,
  and so is any other root process. Use this firewall alongside, not
  instead of, traditional access controls.
- **eBPF / unprivileged user namespaces**: a sufficiently privileged user
  can bypass NFQUEUE entirely with `unshare -rn` and a custom net namespace.
- **DNS-over-HTTPS embedded in browsers**: if the browser resolves names
  inside its own HTTPS connection, the firewall sees only the outer
  443/tcp flow. Block at the `dst_host` layer or disable DoH per-app.
- **Container traffic**: Docker / Podman / LXC route through their own
  bridges. You need to enqueue their veth interfaces explicitly in nftables.

## Socket access

The daemon's control socket (`/run/colony-firewall/cfc.sock`) is
group-gated: it is owned by root with group `colony-firewall`, and only
members of that group can talk to the daemon. To run the GUI or `cfc`
as your regular (unprivileged) user:

```sh
sudo usermod -aG colony-firewall $USER
```

then log out and back in for the group to take effect. Keep membership
tight - anyone in the group can rewrite rules and pause enforcement,
which is root-equivalent control over the firewall.

## When something stops working

Order of operations:

1. Switch profile back to `balanced` so the daemon stops actively denying
   things while you debug.
2. `cfc live` and reproduce the failure - the deny verdict will show in
   real time.
3. `cfc rules list | grep <app>` - is the rule too narrow?
4. Re-add a temporary "allow once" rule via the UI prompt.
5. After it works, narrow the rule back down.

## Backups

Before any large rule cleanup:

```sh
cfc rules export --out ~/cfc-rules-$(date +%F).json
```

Restore with:

```sh
cfc rules import --replace ~/cfc-rules-2026-05-25.json
```

`--replace` deletes everything first; without it, import is additive.
