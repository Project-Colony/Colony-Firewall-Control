# Profiles

`daemon.toml` accepts a `profile` key with three presets:

| Profile            | No UI | Timeout | Window | Inbound, no rule |
|--------------------|-------|---------|--------|------------------|
| relaxed            | Deny  | Deny    | 60s    | Reject           |
| balanced (default) | Deny  | Deny    | 30s    | Deny             |
| strict             | Deny  | Deny    | 15s    | Deny             |

No profile permits a connection on its own: a prompt you were shown and did
not answer must not become an allow, and with nobody subscribed to ask an
unmatched remote flow is denied too. The profiles differ in how long a
prompt waits, and in whether an unmatched inbound flow (only when the
inbound table is enabled) is refused or dropped. Every profile therefore
needs the starter rules from [First run](first-run.md#first-run) before
enforcement goes on.

A profile is a base, not a lock: any field you set under
`[default_policy]` overrides just that field. The profile and every
`[default_policy]` field hot-reload on `SIGHUP`, so you can retune the
policy without dropping a packet.
