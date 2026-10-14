# Colony Firewall Control documentation

Sorted by who is reading, not by subject.

## Using Colony Firewall Control

| | |
|---|---|
| [guide/first-run.md](guide/first-run.md) | installing a source build by hand, and the steps every install needs before it protects anything |
| [guide/quick-start.md](guide/quick-start.md) | the app and `cfc` in practice, who may change what, scripting with `--json` |
| [guide/preferences.md](guide/preferences.md) | language, theme, accent, text size, accessibility, prompt and notification options, and the file they are saved in |
| [guide/profiles.md](guide/profiles.md) | the relaxed, balanced and strict presets, and what each one decides |
| [guide/hardening.md](guide/hardening.md) | moving to a locked-down profile, the socket trust model, the audit trail, and what the firewall does not protect against |
| [guide/troubleshooting.md](guide/troubleshooting.md) | lockout recovery, no-network debugging, socket permissions, fail-open vs fail-closed |

## Reading the code

| | |
|---|---|
| [internals/architecture.md](internals/architecture.md) | the process model, the packet path, the eBPF programs, the repository layout, and why it is built that way |
| [internals/development.md](internals/development.md) | building, running without root, and what CI covers |
| [internals/packaging.md](internals/packaging.md) | what each package installs, and how a release is built and signed |
| [internals/selinux.md](internals/selinux.md) | what the SELinux module grants, what each denial costs, and how to validate it on an enforcing host |
| [internals/benchmarks.md](internals/benchmarks.md) | how the per-kernel latency numbers are measured in a VM, and how to read them |

## Why it exists

| | |
|---|---|
| [project/roadmap.md](project/roadmap.md) | the done and remaining checklist, phase by phase, and the open work found by using it |

Security policy and how to report a vulnerability: [../SECURITY.md](../SECURITY.md).
