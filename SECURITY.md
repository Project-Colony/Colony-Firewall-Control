# Security Policy

Colony Firewall Control is **beta software**. It runs a daemon as root with
`CAP_NET_ADMIN` and makes allow/deny decisions about your network traffic, so
security reports are taken seriously -- but expectations should match the
project's maturity: **there has been no external security audit yet**, and
interfaces may change without notice.

The explicit application confinement mode (`cfc applications run`, new in
0.7.0) is **experimental**, and its interface and platform requirements may
change.

## Supported Versions

Only the **latest release** and the current `main` branch receive security
fixes. Older releases are not supported; upgrade before reporting.

## Reporting a Vulnerability

Please report vulnerabilities **privately** via GitHub's security advisory
form for this repository:

- Go to the repository's **Security** tab -> **Report a vulnerability**, or
  use
  <https://github.com/Project-Colony/Colony-Firewall-Control/security/advisories/new>

Please do **not** open a public issue for anything you believe is exploitable
(privilege escalation via the daemon, rule-bypass of the NFQUEUE filter,
crafted-packet parsing crashes, socket permission problems, etc.).

What to expect:

- This is a single-maintainer hobby project; acknowledgement is best-effort,
  usually within a week.
- If the report is accepted, a fix will be worked on for the next release and
  you will be credited in the advisory unless you prefer otherwise.
- If it is declined, you will get a short explanation.

Dependency vulnerabilities are scanned continuously in CI with `cargo deny`
(RustSec advisory database); a report is still welcome if you spot an
exploitable path through a dependency before CI does.

## Verifying Releases

Release assets are not signed with a project key. From 0.8.0 the release
tarball carries a Sigstore-signed build provenance attestation, which ties its
digest to this repository's release workflow and the commit it built:

```sh
gh attestation verify colony-firewall-control-<V>-linux-x86_64.tar.zst \
    --repo Project-Colony/Colony-Firewall-Control
```

`SHA256SUMS` comes from the same job and is uploaded beside the tarball, so it
detects a damaged download, not a replaced one. The attached `PKGBUILD` pins
the hash of the source archive GitHub served when the tag was built; nothing
compares that archive with the tagged tree, so it binds the recipe to those
bytes and no further.
