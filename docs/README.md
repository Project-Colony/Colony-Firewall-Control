# Colony Firewall Control documentation

Sorted by who is reading, not by subject.

## Using Colony Firewall Control

| | |
|---|---|
| [guide/first-run.md](guide/first-run.md) | installing a source build by hand, and the steps every install needs before it protects anything |
| [guide/quick-start.md](guide/quick-start.md) | the app and `cfc` in practice, who may change what, scripting with `--json` |
| [guide/profiles.md](guide/profiles.md) | the relaxed, balanced and strict presets, and what each one decides |
| [HARDENING.md](HARDENING.md) | moving to a locked-down profile, the socket trust model, the audit trail |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | lockout recovery, no-network debugging, socket permissions, fail-open vs fail-closed |

## Reading the code

| | |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | the process model, the packet path, the repository layout, and why it is built that way |
| [DEVELOPMENT.md](DEVELOPMENT.md) | building, running without root, and what CI covers |
| [../packaging/README.md](../packaging/README.md) | what each package installs, and how a release is built and signed |

## Why it exists

| | |
|---|---|
| [ROADMAP.md](ROADMAP.md) | the done and remaining checklist, phase by phase |

Security policy and how to report a vulnerability: [../SECURITY.md](../SECURITY.md).
