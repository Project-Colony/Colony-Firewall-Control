# Changelog

All notable changes to Colony Firewall Control will be documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- New loopback flows now go through the queue instead of being accepted
  outright (`oifname "lo" accept` is gone from the outbound table). While the
  daemon runs, explicit rules apply to them, so a loopback Deny that 0.7.0
  never enforced now takes effect, and unmatched local IPC is still allowed
  without a prompt. Each new loopback connection pays the queue round trip.
- Socket attribution is stricter. TCP needs an exact connected tuple and never
  selects a listening socket, so an outbound flow no longer inherits a
  listener's rules. UDP accepts zero-remote and wildcard-local sockets only
  when every compatible socket agrees on its owner. The process and
  descriptor found must still hold the socket after the executable is read;
  otherwise the identity is unknown.
- GUI: "make rule" on a Live row seeds the program, port and protocol, the
  scope `cfc rules add --exe --dst-port --protocol` builds, instead of
  pinning the one address seen, which left the app denied on its next
  address (#46). A row without an identified program pins the address and
  never seeds `<unknown>`; an inbound row keeps its direction. "Customize"
  on a prompt seeds the same way. A saved rule logs the scope it stored, and
  a rule the editor refuses is also reported in the footer.
- GUI: a prompt arriving while others are pending no longer switches to the
  Prompts tab; only the first one does, and raises the window.
- `cfc rules import-opensnitch` stops before changing anything when a source
  rule cannot be converted (hostname and regexp rules among them), because
  dropping a narrow deny next to a broad allow imported a wider policy than
  the source with only a skip count to show for it. `--skip-unconvertible`
  imports the rest, naming each skipped file. **Breaking** for scripts that
  relied on the old additive behaviour.
- Bundles name the binary that connects. The rules for Firefox on Arch, git,
  cargo under rustup and apt pinned a launcher or front end that never shows
  up as the connecting executable, so they never fired. `web` and `dev` drop
  Epiphany, npm and pip, whose traffic comes from a shared WebKit helper or
  an interpreter. Hosts that installed `web`, `dev` or `updates` before keep
  the old rules: `cfc rules bundle remove NAME` then `bundle add NAME`
  replaces them, and `bundle add` names each one that pins an old path.
- Rule summaries in the GUI and `cfc rules list` show the protocol, a uid and
  `[pinned]` for a hash-pinned rule, so a scoped rule no longer reads as
  global.
- `cfc rules export` writes `expires_at_unix_ms` for timed rules, and import
  keeps that deadline instead of starting the full lifetime again. Older
  versions refuse an export that contains the field.
- Confinement: a refused launch exits 125 and its reason is in
  `journalctl -u cfc-app-ID.service`; it used to be discarded and reported
  as the application's status 1.

- The release tarball ships `install.sh` and `uninstall.sh`, generated from
  `pkg/colony.json`. No Colony app store client ever read that manifest or
  ran its `postInstall`/`preRemove`, so the tarball had no installer and the
  documented store channel did not exist; the docs now say so.
- Lifting filtering is `systemctl disable --now colony-firewall-nft` (plus
  `colony-firewalld` to keep it off), not a plain stop. A stop or restart
  propagates through the network managers' `Requires=` to NetworkManager and
  systemd-networkd. The docs now carry ruleset changes as a local copy loaded
  through a unit drop-in: a same-named table from `/etc/nftables.conf` is
  replaced at boot, on daemon start and on every upgrade.

### Security

- `cfc prompts`: keys typed while no prompt was shown, such as an answer
  typed just as a prompt expired, answered the next prompt as soon as it was
  printed, and an arrow key skipped one prompt and left `A` or `D` to answer
  the next. On a terminal, pending input is now discarded before each prompt.
- The CLI printed the daemon's reason for not saving a rule raw, and that
  reason can quote an executable path a local user named, escape sequences
  included. The client now escapes it for every front end, and escapes the
  backslash in every escaped string so a literal `\n` cannot pass for an
  escaped newline.
- Confinement: on kernels 6.17 to 7.1 the root gate's `BPF_PROG_QUERY`
  attribute was 32 bytes and the kernel wrote 8 bytes past it on the stack.
  The attribute now has its full size.
- GUI: `A`, `D`, `Shift+A` and `Shift+D` answered the newest prompt, the
  bottom card and often off-screen, from any tab and with Ctrl, Alt or Super
  held, so `Shift+A` on the card being read could write an always-allow rule
  for another program. They now answer the marked top card, only on the
  Prompts tab and without those modifiers. The keys are disarmed for one
  second whenever their target changes, and a card's buttons for one second
  after it appears, so input already on its way when the window was raised
  or a card moved does not answer it.
- GUI and tray: executable paths, command lines, working directories and DNS
  names were shown raw, so bidi and control characters could reorder or add
  lines to a prompt, and the tray's notification body was parsed as markup
  by dunst and mako, so a path could hide part of itself. They are now
  escaped as the CLI already did. The GUI's Remote row says whether the name
  is verified.
- An observed DNS answer could name an address with spaces and brackets,
  such as `google.com (1.2.3.4; verified hostname)`, and every client printed
  it before the real address and trust label. Observed names with anything
  but letters, digits, `-`, `_` and `.` are now dropped.
- While no daemon listens on the queue, new loopback flows are allowed
  (`oifname "lo" ct state new queue num 0 bypass`), so local services keep
  working when the daemon is down. Loopback Deny rules are not enforced then.
  Every other new flow stays fail-closed.

- The daemon unit sets `PrivateDevices=` (uid 0 could otherwise open block
  devices and write underneath `ProtectSystem=`), drops `AF_PACKET`, which
  nothing used, and lists more of the `/proc` and `/sys/fs` entries
  `ProtectKernelTunables=` covers. `docs/HARDENING.md` no longer claims
  `ProtectKernelTunables=` is set.
- The release tarball carries a Sigstore-signed build provenance
  attestation; `SECURITY.md` explains how to verify it and what
  `SHA256SUMS` and the attached `PKGBUILD` checksum do not prove.

- A running program whose file was literally named `curl (deleted)`, for
  instance in a user's own mount namespace, matched the rules for `curl`:
  the kernel's `" (deleted)"` suffix was dropped by text alone. It is now
  dropped only from an image with no link left.
- A daemon started by hand created its rule store with the shell's umask, so
  rules and other users' command lines were world-readable (or writable
  under umask 000). The store directory is now created 0700 and the database
  0600.
- The BPF object was vetted through its symlinks and then read through them
  again, so whoever controlled a link could swap it in between. The vetted
  target is what gets read now.
- The Arch build recipes and the prompt demo used fixed `/tmp` directories
  another local user could create first; they use `mktemp -d` now.

### Removed

- The Fast Allow userspace path, disabled since 0.7.0 because a socket mark
  cannot prove which process sends and so opened bypasses. `cfc --json status`
  no longer has a `fast_allow` key, `StatusResponse` field 16 is reserved, and
  the `[ebpf] fast_allow` and `fast_allow_mark` keys are ignored with a
  warning. For hosts upgrading from 0.4-0.6, startup still flushes the legacy
  nftables set. When the eBPF layer loads, it also disarms the legacy pinned
  maps and removes the old sendmsg link pins; with the layer off, without the
  object or after a failed load, those stay until reboot.
- The `cfc_sendmsg4`/`cfc_sendmsg6` programs, which nothing had attached since
  the Fast Allow userspace path went. The eBPF ABI is unchanged.
- `LogsDirectory=colony-firewall` and the `/var/log/colony-firewall` write
  access in the unit and the SELinux module (the `colony_firewall_log_t` type
  and the `colony_firewall_read_log` interface). The daemon logs to the
  journal and never wrote there. An existing directory is left in place.
- Unused library items: `cfc_core::CoreError`, `cfc_core::Result`,
  `cfc_core::ResolvedExe`, `exe_path::resolve_scope` and `Resolved::path`,
  together with dependencies no crate used.

### Fixed

- Since 0.7.0 the outbound table dropped IPv6 neighbour discovery and MLD,
  which conntrack marks untracked, so IPv6 stopped working on hosts that load
  it. Both tables now accept neighbour discovery, MLD and IGMP membership
  traffic in the kernel, limited to the hop limits and sources the RFCs
  require, so the inbound table no longer drops MLD or refuses IGMP queries
  either. Other untracked traffic, including explicit `notrack` flows, still
  drops; TROUBLESHOOTING.md says how to keep it.
- On kernels booted with `ipv6.disable=1` the missing `/proc/net/udp6` left
  every IPv4 UDP flow unattributed, so executable-scoped Allows such as the
  DNS, NTP and DHCP bootstrap rules refused. An absent table now counts as
  empty.
- Every refused packet was committed to SQLite with an fsync on the single
  packet thread before its verdict, so a flood of refused traffic stalled
  every new flow on the machine, and a store mutex held for 250 ms (a long
  `cfc log` query, the minute prune) or a full disk ended the daemon and
  dropped all new connections until systemd restarted it. Refusals are now
  queued after their verdict to the same bounded batch writer as Allow rows.
  Rows it cannot take are counted and logged instead of stopping anything.
- A disabled rule vanished from `cfc rules list` and the GUI after a daemon
  restart, so it could not be re-enabled or removed. Disabled rules now load
  at startup; lookups already skip them.
- Rules quarantined at load were reported only in the journal. `cfc status`
  and the GUI now count them with the rows that could not be loaded, and
  `cfc rules remove <id>` with the full id deletes such an unlisted row.
- `ApplyRules`, behind `cfc rules import` and `import --replace`, was the
  only mutating RPC that left no journal line. It now logs the caller's uid
  and pid, whether it replaced the rule set, and the applied and removed
  counts as "rules applied".
- Packets parked on a prompt that timed out were refused even when an
  "Allow always" given meanwhile for the same program now allowed them. A
  rule's Allow now takes precedence over the timeout or no-UI fallback; an
  explicit user answer still stands.
- Every new flow from an executable that was not root-sealed (anything under
  a home directory, and any program still running after its package was
  upgraded) reread and rehashed up to 64 MiB on the single packet thread, so
  one such program opening connections in a loop stalled new flows for the
  whole machine. Digests are cached again by device, inode, size, mtime and
  ctime, and only once ctime is two seconds old, so a changed file is always
  rehashed and an unchanged one never is.
- A process in its own mount namespace (`unshare -rm`, a container) could
  mount its own bytes at a host path such as `/usr/bin/curl` and match every
  path-only rule for the host's program, including prompt-created Allows that
  skip hash binding for root-sealed paths. An executable path that names a
  different file in the daemon's view is now reported as unknown. Container
  and Flatpak runtime binaries at such paths therefore lose their executable
  identity instead of borrowing the host's.
- The same namespace could still borrow the host's path by deleting its
  bytes once running: the kernel's `" (deleted)"` suffix was dropped, and a
  deleted image names no file to compare with. The suffix is now dropped only
  for a process in the daemon's user namespace, so a program in another one
  (`unshare -U`, a rootless container) that runs across its own upgrade
  matches its rules again only after a restart.
- Executables over 64 MiB, such as Chromium, Electron apps and VS Code, have
  no digest, so every queued packet from them, each retransmit and parallel
  connection, opened its own prompt. On a root-sealed path they now share one
  prompt per destination like any other program.
- The package-index warmer held the index's write lock for a whole rebuild,
  so the packet thread blocked behind it on the first flow from any newly
  seen binary: about 120 ms with pacman, up to 10 s with rpm during a `dnf`
  transaction. The packet thread now skips a busy or stale index, and that
  "not ready" answer is no longer cached for an hour as "not from a package";
  it shows as unknown until the index is ready.
- A failed `rpm -qa` (a query timing out at boot, for instance) left an
  empty package index that counted as current, so every binary showed as
  "not from a package" until the next package transaction. The index from a
  failed query is now retried at the next refresh, every two minutes, and
  provenance shows as unknown meanwhile.
- A refused `UpsertRule` or `ApplyRules` left nothing in the journal unless
  authorization refused it, so "never sent" and "sent and refused" looked the
  same (#46). Every refusal now logs the RPC, the caller's uid and pid, the
  status code and its message. Refusal messages no longer echo a client
  value of unbounded length.
- Rule hit counts drifted upward: a rule write between the 30 s flush's drain
  and merge stored the drained hits twice, and releasing a prompt credited a
  matching rule even when the user's answer was the one applied.
- A rule whose stored executable path later became an alias (a legacy
  `/bin/curl`, or a target a package turned into a symlink) could not be
  disabled, renamed or re-imported, only deleted. A path sent back unchanged
  is accepted; new and changed paths are still checked.
- A new timed rule took its creation date from the client, so a date in the
  future kept "allow for 90s" alive indefinitely. Dates are clamped to now.
- Enabled legacy hostname rules refuse flows that are logged as the default
  policy. The daemon now names each one in a warning at startup.
- eBPF: exit events usually arrived before the parent reaped the process and
  were dropped, so on kernels without `group_dead` an in-kernel deny outlived
  its process until a rule change or restart, where a recycled pid could
  inherit it. Candidates are now checked again until their group is gone.
  Overlapping verdict resyncs could also leave the older rule set's answers
  in the kernel, and a rule changed during the startup resync never reached
  it.
- A daemon started by hand under umask 000 created its socket directory
  world-writable, so a local user could replace the socket.
- GUI: a prompt card was dropped before its verdict reached the daemon, so a
  failed verdict left the flow to the timeout default with nothing to retry.
  The card now stays until the daemon answers. A customization whose prompt
  expired was closed with the user's edits; it now stays open as a new rule.
  Footer errors are no longer pushed out by a burst of warnings.
- GUI: Pause replaced Reconnect under the cursor as soon as the daemon came
  back, so a double-click on Reconnect paused enforcement. Pause now stays
  disabled for one second after connecting.
- Tray: on GNOME, three expired prompt bubbles held every actionable slot,
  so later prompts only reached the overflow bubble, which cannot answer
  them. Slots are freed once their prompt's deadline has passed, and the
  stale bubbles are closed.
- Confinement refused every launch while the daemon's DNS observer, on by
  default, was attached at the cgroup root, because the gate required the
  unit's effective filters to be exactly its own pair. Programs inherited
  from ancestors are now accepted; the unit's own pair must still be exact.
- Confinement: Ctrl-C while systemctl ran, a closed terminal or a dropped
  SSH session killed the launcher and left the tree running with its
  grants. SIGINT, SIGHUP, SIGQUIT and SIGTERM now stop the tree at any
  point, and its identity is printed before it starts.
- `cfc rules bootstrap-defaults` and `bundle add` failed on hosts seeded
  before 0.7.0, calling the bundle's own rules outside it. An identical
  same-named rule now counts as present, and `bundle remove` removes it; a
  different one still stops the command.
- `cfc rules bundle remove` deleted a bundle rule the user had edited into a
  deny. It now keeps any of its rules that is no longer an allow.
- OpenSnitch import passed `dest.ip` networks (`10.0.0.0/8/32`), bad CIDRs
  and ports above 65535 to the daemon, which refused the whole import
  without naming the file. They now fail their own file.
- The GUI's prompt subscription stayed open after the GUI dropped it, so the
  daemon held the next prompt for an absent listener until it timed out.

- RPM erase stopped NetworkManager: `%systemd_preun` stops the nft units
  with `--no-reload`, under the managers' loaded `Requires=`. `%preun` now
  disables them with a reload first.
- Package upgrades re-enabled an nft unit the admin had disabled, because
  reenabling the daemon follows its `Also=`. Only enabled nft units are
  reenabled now (pacman, RPM and the tarball).
- `pkg/PKGBUILD` refuses the `SKIP` checksum in `build()` too, so
  `makepkg --noprepare` cannot build an unverified archive.
- The release's LLVM pairing check compared against a version
  `bpf-linker --version` does not print, so it never fired; it now runs the
  same checks as `ebpf.yml`. A dispatched release's draft now tags the commit
  it was built from.

- A process's arguments were read whole, up to several MiB, and copied into
  every prompt, observation and client message. At most 4 KiB is kept now;
  a cut argument ends in `...`.
- GUI: saving a rule trimmed its executable path, retargeting a rule for a
  file whose name ends in a space.
- HARDENING.md says that with inbound filtering off a program outbound rules
  deny still answers inbound connections, that a deleted image is matched by
  its former path, and what a readable FUSE filesystem controls.
- TROUBLESHOOTING.md told remote administrators to add `tcp dport 22 accept`
  to a `policy accept` copy of the outbound chain. That let every process
  reach any host on port 22 unjudged, accepted INVALID and UNTRACKED traffic,
  dropped the loopback rule, and did nothing for reaching the box, since
  inbound SSH replies are never queued. The guide now names the real lockout
  risks (the inbound table, network lookups the login makes) and its
  dead-man's switch removes both tables.
- The docs now say what the 64 MiB hashing limit costs (hash-pinned rules
  refuse such a program; outside a root-owned path "Allow always" is not
  saved), that Docker grants `CAP_NET_RAW` by default, and that `cfc pause`,
  not a profile switch, lets unmatched flows through while debugging.
  SECURITY.md links the documented non-goals.
- HARDENING.md no longer says the unit's hand-written `ReadOnlyPaths`
  cover everything `ProtectKernelTunables` does: they leave `/proc/kallsyms`
  and `/proc/kcore` visible and any `/sys/fs` filesystem they do not name
  writable.

## [0.7.0] - 2026-09-30

### Added

- `cfc applications run` and `stop` provide opt-in, administrator-controlled
  confinement for fresh headless application trees. Network access is denied
  by default; `--allow IP` approves exact numeric peers for the whole tree
  across TCP/UDP ports, including any relay that peer provides. Ordinary CFC
  rules can further restrict new connections. Revocation stops the complete tree.
- The initial confinement profile requires x86_64 Linux, cgroup v2, systemd
  262+, Bubblewrap 0.13+, working system D-Bus and libbpf interface filters.
  Launches verify the native filters and require a sealed runtime on a
  supported local filesystem. Private namespaces, dropped capabilities and
  seccomp restrict local relays and inherited resources. Desktop services,
  shared home directories, standard input/output and live grant changes are
  unavailable. This mode covers only explicitly launched trees; ordinary
  socket attribution and established-flow authorization remain unchanged.

### Security

- All profile defaults now refuse unattended and unanswered connections.
  Explicit administrator overrides remain supported. Incomplete process
  identity and compatible undecidable rules refuse before pause or prompts.
- Fast Allow is disabled in every runtime configuration, including existing
  `fast_allow = true` settings. Allowed flows use NFQUEUE.
- Hostnames are diagnostic only. New hostname rules and imports are rejected;
  compatible legacy hostname rules refuse before a lower Allow or fallback.
  Replace them explicitly with executable or numeric destination scopes.
- New executable rules require the canonical target explicitly instead of
  silently rewriting aliases. This does not recover legacy alias intent or
  pin future executable contents; hash scopes remain a separate control.
- Parsed NFQUEUE Deny/Reject decisions commit to SQLite before their verdict
  or live publication. Audit failure drops the packet and stops the worker.
  Kernel drops, malformed packets and journal delivery are outside this gate.
- Enabled nftables units load independently before daemon initialization and
  are required by NetworkManager and systemd-networkd. Failed table loading
  blocks those managers; daemon failure leaves filtering installed. This
  contract excludes initramfs networking and already configured interfaces.
- Control mutations verify each peer's actual group credentials. Non-root
  prompt replies require delivery to that user, persisted prompt Allows retain the
  prompted image binding, and rule imports publish committed batches atomically.
- Packet attribution, rejection parsing and eBPF object selection validate
  their inputs more strictly. Build jobs use read-only repository permissions;
  release publication runs after successful builds with separate write access.

## [0.6.0] - 2026-09-28

### Changed

- The minimum supported Rust version increased from 1.88 to 1.89. Source
  builds and package builders now require Rust 1.89 or newer.
- Updated `notify-rust` to 4.18.0, `dns-lookup` to 4.0.1, `futures` to
  0.3.34, `chrono` to 0.4.45, and `ipnet` to 2.12.2.
- Updated the pinned Rust toolchain GitHub Action.

## [0.5.0] - 2026-09-06

### Security

- **The fast path could grant what the packet path denies.** The two deciders
  did not read the same uid: the packet path takes the uid from the kernel's
  exec record, the grant path resolves it from `/proc` at the time it decides.
  For a program that drops privileges after `exec` - `named`, `postfix`, a
  browser entering its sandbox - those differ, so `deny --exe X --uid 0` above
  `allow --exe X` was answered "deny" by one and "allow" by the other. A grant
  is process-wide and destination-blind, so the deny was not slower, it never
  applied. The grant side now abstains wherever a uid-scoped rule could reach
  the program, exactly as the deny side already did; those flows take the
  queue, where the uid has one answer. Hosts with no uid-scoped rule are
  unaffected.
- **A rule that could not be decided was walked past.** `matches_process`
  collapses "cannot say" into "does not match", so a `deny` scoped to
  `exe_sha256` over a binary the daemon cannot hash - over 64 MiB, unreadable,
  or a process whose image is already gone - handed the flow to a
  lower-precedence `allow`. The deny listed, ranked first and never fired.
  `RuleSet::lookup` is now three-valued: a rule that is *about* this flow but
  undecidable stops the walk, and the default applies instead of a rule its
  author wrote it to override. The connection half is tested first, so a rule
  its own destination excludes still abstains for nothing.
- **Hostnames observed on the wire could admit traffic.** Nothing correlates
  an observed DNS response to a query this host sent - the kernel gate is
  `source port == 53` and no more - so any peer answering from that port could
  assert any name for its own address and inherit whatever a `dst_host` rule
  allows it. Such a name may now refuse but may not admit; a reverse lookup,
  which is forward-confirmed, still does both. Deny rules written against a
  name keep working exactly as before, which is why the check runs one way
  only.
- **ICMP refusals were emitted for multicast and broadcast destinations,
  sourced from the group address.** Inbound, `dst_ip` is this machine - and
  for mDNS, SSDP, LLMNR or a DHCP offer it is the group the datagram was sent
  to. Refusing those put a martian source on the wire, one packet per packet
  received, at every neighbour that speaks multicast: an RFC 1122 and RFC 4443
  violation, a way to enumerate CFC hosts on a segment, and an answer to the
  DHCP server that breaks the lease. Both endpoints must now be ordinary
  unicast addresses before anything is forged.
- **Refusals that leave the machine are budgeted.** The destination came
  straight from the packet with no limit of any kind, so a spoofed source
  address turned the daemon into an unthrottled ICMP reflector - `nft reject`
  cannot be used that way because the kernel rate-limits `icmp_send`, and a
  raw socket with `IP_HDRINCL` is governed by nothing. Twenty per second off
  the machine, with a burst of twenty. Refusals to a local application are not
  budgeted: throttling those would restore the timeout the feature replaces.
- **`cfc status` reported `enforcing` forever once it had seen one packet.**
  The counter only goes up, so after the first connection the answer was "yes"
  for the daemon's life - including after `nft flush ruleset` or a firewall
  reload took the table away and the machine stopped being filtered. A packet
  counter cannot tell "nothing is filtered" from "nothing is happening", so
  the daemon now asks nftables directly, once a minute, and says what it
  found. An absent table inside the startup grace period is not alarming: the
  shipped units start the daemon before the one that loads the table.
- **An `exe_path` from the wire was unbounded.** A 4 MiB path passed every
  gate and then drove one `canonicalize(2)` per component - millions of
  syscalls - on the sixteen-slot blocking pool the prompt router also uses.
  Rules now refuse a path longer than `PATH_MAX`, which no process could match
  anyway. The rejection deliberately does not echo the path back.
- **`docs/HARDENING.md` understated the DNS risk it described.** It framed a
  forged observed answer as something an attacker must race the resolver for,
  "the same attacker who could also forge the forward lookup FCrDNS depends
  on". That is not the shape: nothing correlates an observed response to a
  query this host sent, so any peer the host sends a datagram to can reply
  from source port 53, with no spoofing and no guessing, and the application's
  own resolver never sees it. The section now says so, and says what the
  daemon does about it.
- **`ListEvents` skipped an unbounded number of rows.** `limit` was clamped
  and `offset` was not, so a read-only peer could make sqlite step and discard
  the whole event table per call, holding the global connection mutex.

### Fixed

- **Four raw sockets received a copy of every TCP segment and every ICMP
  packet on the machine, for the daemon's whole life.** They exist only to
  send refusals and are never read, but `IP_HDRINCL` governs sends alone: the
  kernel clones every matching packet into a buffer that could only fill and
  drop. They now carry a one-instruction filter that returns zero, the
  standard way to say send-only. Opened unconditionally at start, so this was
  a tax on every host running CFC, whether or not any rule ever rejected.
- **The hostname cache had no upper bound on one of its two insert paths.** A
  completed reverse lookup re-created its own key even when the reservation
  had already been evicted, so the map ratcheted upward by one per orphaned
  completion on any workload touching more distinct destinations than it
  holds. A completion with nothing to update is now dropped.

### Performance

- **One netlink socket per thread instead of one per queued packet.**
  Attribution opened, configured and closed an `AF_NETLINK` socket for every
  packet the queue handed up, on the single datapath thread. Measured on
  `scripts/vm-bench`: 0.28 ms of every queued flow at 3000 flows. Reuse is
  only safe because each request now carries its own sequence number and the
  reply is checked against it - every request used to carry `seq = 1`, so a
  late answer to a timed-out request would have been indistinguishable from
  the next one's, which is a wrong attribution rather than a slow one. The
  socket is discarded on anything but a cleanly-sequenced answer.

### Added

- **`scripts/vm-bench`**, which measures what the firewall costs on a machine
  it is allowed to arm. It assembles an initramfs from this host's own kernel
  modules, nftables, iproute2, python3 and the release binaries, boots it under
  KVM, and runs `scripts/bench-latency.sh` there against a real daemon - queue
  rule loaded, rules imported, fast path granting. Nothing is downloaded and
  nothing outside `target/vm-bench` is written. Each state differs from its
  neighbour in one thing, and two facts are recorded beside every measurement
  rather than assumed: what `cfc status` says the fast path is, and how many
  packets the kernel actually handed to userspace.

### Fixed

- **`docs/ARCHITECTURE.md` described a design that had been replaced.** It
  said the NFQUEUE worker blocks in `recv` while no prompt is outstanding -
  "no polling, no added latency" - which is the design `nfqueue.rs` replaced,
  and the opposite of what the shipped daemon does.
- **`nfqueue.rs` predicted half the idle beat per queued flow; it is a whole
  one.** "Mean: half that" holds for arrivals independent of the beat, not for
  a client connecting in series, where every connect lands just after the
  worker committed to a fresh wait. Measured by building the same daemon with
  `RECV_POLL_INTERVAL` at 200 us and running both in one guest.

### Measured

- **What the fast path is worth**, per new outbound TCP flow, median, on Linux
  7.2.2 under KVM: 0.0269 ms against 7.6083 ms through the queue at 3000
  flows, and 0.0268 against 5.6745 at 300. It costs 0.011 ms over having no
  firewall at all, and unlike the queue its cost does not grow with load,
  because those flows never reach the daemon. `TODO.md` 1a carries the whole
  table and what is still unattributed.

## [0.4.0] - 2026-09-05

### Added

- **Fast allow (opt-in, `[ebpf] fast_allow = true`).** A process a lasting
  rule allows outright no longer pays an NFQUEUE round trip per connection:
  the `cgroup/connect4|6` hooks mark its TCP sockets with a value the daemon
  draws at random on each start, and a `meta mark @fast_allow accept` rule the
  snippet ships with an *empty* set takes them ahead of the queue. New
  `sendmsg4|6` hooks run the same decision for UDP sends that carry a
  destination; since no UDP socket is ever marked, what they do there is strip
  a mark that should not be present. Grants
  reach processes that were already running, not only ones that exec after
  the rule: the daemon walks `/proc` at start and at every rule change. The
  mark is re-decided at every hook that opens a flow and stripped when the
  grant is gone; the kernel clears grants on exec and exit by itself; and a
  `CLOCK_BOOTTIME` deadline the daemon refreshes means a dead daemon leaves
  the machine fail-closed again within one deadline - 60 s, refreshed every
  10 s, or the shorter pair below. Fast-allowed
  flows are reported on a ring, with their destination named from the same
  reverse-DNS cache the packet path uses, so the live feed, rule hit counts
  and the `enforcing` heuristic keep telling the truth. Off by default for
  this first release; `cfc status` and the startup log line show
  `fast-allow live` or `off: <the one reason>`.

  Two things worth knowing before turning it on. **Only TCP sockets are
  marked**, deliberately: they are the only ones that pass a hook again, and
  the mark lives on the socket, so a mark given to anything else could never be
  taken back - not by a revocation, not by the deadline, not by the daemon
  dying. It costs little where it lands: a UDP peer that answers makes the flow
  conntrack-established and its later datagrams were not being queued anyway,
  so a marked UDP socket only kept gaining while its peer stayed silent, which
  is exactly when an unrevocable mark does the most damage. What is given up in
  practice is the fast path for QUIC. And the mark shares one 32-bit word with
  everything else on the machine: the daemon refuses values that collide with
  the fwmark selectors it knows (kube-proxy's two single-bit masks,
  Tailscale's, wg-quick's), and `[ebpf] fast_allow_mark` pins one by hand for a
  host with a selector it does not know.

  Two kernel facts weaken the guarantee without switching the path off, and
  `cfc status` says which: the exec/exit tracepoint links could not be pinned
  (a read-only bpffs; perf-event links have been pinnable since 5.15), or the
  exit tracepoint has no `group_dead` and a process's death cannot be told from
  one of its threads' - absent on 5.10 and 6.12 in the kernel matrix, present
  on 6.18. In both cases the grant deadline drops from sixty seconds to six,
  refreshed every two; in the second the daemon also re-checks every granted
  pid's start time on every beat and drops any that changed hands, since there
  the kernel's own eviction can miss a death while the daemon is alive. That
  second case was a refusal in the first design, which put the fast path out
  of reach of every kernel RHEL ships.

  The `cgroup/sendmsg` hooks are no longer required: with no UDP socket ever
  marked they can only strip a forged mark, so where the kernel refuses them
  (5.10 does) the path runs and the report notes what it runs without. On a
  restart the previous daemon's cookie-variant marker in bpffs is what tells
  the new one that the pinned connect programs carry the mark decision.

- **`scripts/bench-latency.sh`**, the veth bench the fast path has to be
  measured on: a network namespace on the other end of a veth pair, a TCP
  listener on each side, and connect latency in both directions reported as
  percentiles. It never touches nftables, the daemon or its rules; run it
  once per state and compare, on a VM where CFC may be armed.
- **The kernel matrix brackets RHEL 9.** A 5.15 entry joins 5.10: the LTS
  below and the LTS above the 5.14 that Rocky and RHEL 9 ship. What both
  allow, 5.14 allows unless Red Hat took it out; what only 5.15 allows, 5.14
  has only if they backported it; what both refuse, 5.14 may still have
  through a backport. Where the two disagree is the list of things to check
  on a Rocky host rather than assume. The first 5.15 run named one: it
  already takes the sendmsg hooks that 5.10 refuses, and neither has
  `group_dead`.
- **The startup report says what the fast path's kernel side is capable
  of** (`fast_path=ready|sendmsg-unavailable|basic-connect` on the log line,
  `none` where no connect hook attached), and the matrix test asserts it per
  kernel, along with `group_dead`, wherever a run has already shown the
  answer: 5.10 takes the connect hooks and refuses the sendmsg ones, 5.15 and
  6.12 take both and still have no `group_dead`, 6.18 and 7.1 have
  everything. A kernel that changes its answer fails in CI rather than
  degrading quietly on a host; one without a recorded answer is printed, and
  the matrix summary carries the line.

### Changed

- Three costs removed from paths every process on the machine takes, none of
  them measured on a live kernel yet, each argued from what the code does
  rather than from a number. The exec and
  exit programs deleted a fast-allow grant on every `execve` and every exit,
  unconditionally, on hosts where the feature is off (which is every host by
  default); the delete is now behind one array read of the mark, which is
  `UNARMED` exactly when the grant map is empty. Withdrawing the fast path left
  `FAST_ALLOW_MARK` armed in the pinned map, so a daemon restarted with
  `fast_allow = false` after an unclean death made every TCP `connect()` pay a
  `getsockopt` and two map reads to strip a mark nobody would ever set, for as
  long as it ran; withdrawing unarms. And the `/proc` walk that re-seeds grants
  on every rule change now asks first whether any rule could grant anyone, and
  a rule set of denies, timed allows and port-scoped allows is answered in a
  few comparisons instead. The verifier counts in the kernel matrix are the one
  measurement these changes get, and a count is not a runtime cost - the exec
  program may well verify a few instructions *longer* for the branch that lets
  it skip a hash delete at runtime.
- **eBPF ABI v4.** New maps and programs the connect hooks read; v3 pins
  would enforce fine and never mark, so a restarting daemon now replaces
  them rather than inheriting them. `verdict::ALLOW`, matched by the kernel
  and written by nobody for two releases, is gone.
- The daemon now runs `nft` to put its fast-allow value into one set and
  take it out again - the first time it touches nftables; the SELinux policy
  grants exactly that. The set is flushed at every start of the daemon - with
  the layer on, switched off in the config, or absent from the build - so a
  daemon that crashed while armed and came back in any of those states does
  not leave its predecessor's mark accepted; and once armed the daemon re-checks
  every minute that the element is still there, so an `nft -f` that reloads
  the ruleset is noticed and re-armed rather than reported as live. The
  nftables snippet gains the set and the accept rule; an older snippet leaves
  fast-allow off with the reason spelled out.

### Fixed

- The RPM spec still said 0.2.3 in the 0.3.0 tree, and nothing ran to say
  so: `scripts/check-versions.sh` now holds the spec, the PKGBUILD and the
  Colony manifest to `Cargo.toml` on every push, not only when a packaging
  path changes.

### Internals

- Two integration tests that each copied a binary and spawned it raced each
  other's fork (ETXTBSY on CI, the window between a fork and its exec, where
  the child still holds the other test's write descriptor); copy and spawn
  are now serialised behind one lock instead of retried past the race.
- Dependency bumps: rusqlite 0.40.2, libc 0.2.189, flate2 1.1.10,
  owo-colors 4.4.0, thiserror 2.0.20; `action-gh-release` 3.0.3.

## [0.3.0] - 2026-09-02

### Added

- **Hash-bound prompt allows.** Answering a prompt for a user-writable binary
  now binds the rule to the binary's sha256 rather than to its path, so a
  replacement does not inherit the permission the user granted the original.
- **Tray icon fallback**, so the indicator still appears where the themed icon
  cannot be loaded.
- **RPM packaging**, built end to end in CI alongside the Arch package.

### Fixed

- **Forty-seven findings from an adversarial audit of the 0.2.x line.** The
  one critical: the SELinux policy granted three capabilities it did not need.
- The VM matrix and SELinux CI jobs, whose failures had been masking each
  other across nine rounds.

### Internals

- The parchment palette now comes from `colony-ui` rather than from eleven
  hand-maintained constants in `cfc-ui`. The eleven names and their values are
  unchanged, so no call site moved.
- `colony-ui` 0.1.4, which fixes six palettes whose progress-bar track was the
  same colour as the card it sat on.

## [0.2.3] - 2026-08-27

### Added

- **Inbound filtering.** CFC now filters both directions, under one policy:
  nothing enters without a rule, and inbound never prompts - an exposed
  machine is scanned continuously, and a bubble per inbound SYN would be a
  denial of service on the user's attention. A separate opt-in unit
  (`colony-firewall-nft-inbound`) loads a fail-closed chain (`policy drop`),
  guarded twice at start: the daemon must be active, and a lockout pre-flight
  refuses to load if a live remote session has no rule to readmit it after a
  restart. The `inbound` bundle seeds mDNS/LLMNR/DHCP/SSH scoped to private
  ranges only.
- **In-kernel enforcement that survives the daemon - for new processes too.**
  The daemon compiles its process-wide deny rules into a pinned kernel table
  (`EXE_RULES`); the exec tracepoint consults it and writes verdicts itself.
  Kill the daemon: processes it knew keep their EPERM, and a denied binary
  *launched afterwards* is refused in 0 ms by the kernel alone. The daemon
  became a control plane. The exit tracepoint now evicts its own verdicts
  (using the kernel's `group_dead`, resolved from the live tracepoint format),
  so the pinned map cannot rot through pid recycling.
- **Content-bound rules.** `cfc rules add --exe <path> --pin-hash` binds a
  rule to the binary's sha256: replace the file and the rule stops applying,
  instead of the replacement inheriting the permission. Per-rule and off by
  default - a package update revokes such a rule too, by design.
- `cfc status` now reports *where* enforcement lives (`pinned`, `inherited`,
  `process`, `unavailable`) - losing the kernel layer is otherwise silent.

- **eBPF backend**. Compiled into the daemon by default; still gated at
  runtime by `[ebpf] enabled`, which remains off. Build without it with
  `cargo build -p cfc-daemon --no-default-features`.
  Three kernel programs: `sched_process_exec` / `sched_process_exit`
  fill a kernel-sourced process table, so attribution no longer races a
  short-lived process through `/proc`; `cgroup_skb/ingress` observes the
  DNS answers this host actually receives, and those outrank
  PTR-derived names in the hostname cache. Verified live on kernel
  7.1.8. The daemon degrades to `sock_diag` + `/proc` + PTR whenever the
  feature is off, the object is missing, or the load fails.
- `colony-firewall-tray`: a system-tray icon (StatusNotifierItem, so KDE
  and most bars natively; GNOME needs the AppIndicator extension) in the
  Windows Firewall Control mold. Shows enforcing / paused / unreachable
  at a glance, flags waiting prompts (attention icon + a rate-limited
  desktop notification), offers Pause 5 min / 30 min / 1 h / daemon
  default and Resume, and opens the GUI on left-click. Autostarts with
  the session; quitting the tray never touches the daemon.
- The GUI honors `$CFC_SOCKET`, so it can be pointed at a daemon on a
  non-default socket (a `--dry-run` instance, a test socket) without a
  rebuild - the CLI already had `--socket` for this.
- `bootstrap-defaults` now also seeds the DHCP clients (dhcpcd,
  NetworkManager, systemd-networkd; v4 renewals on 67/udp and DHCPv6 on
  547/udp). With enforcement starting before the network is configured,
  these are what let a `strict` machine get a lease at boot.

### Changed

- Inbound connect latency 2.78 ms -> 0.13 ms (the packet path no longer
  performs a socket lookup that cannot succeed for an inbound SYN); daemon
  RSS 78 MB -> ~31 MB; 18 threads -> 7; SQLite in WAL at full durability,
  2.5x faster event batches. Measured on a veth pair, method in the repo.

- **Filtering now starts before the network does.** Both units are
  ordered `Before=network-pre.target` (the systemd firewall convention)
  instead of after it: the daemon is listening on the queue and the
  nftables table is loaded before NetworkManager, systemd-networkd or
  dhcpcd configure a single interface. There is no window at boot where
  the network is up but filtering is not. The nft unit also `Wants=` the
  daemon, so enabling enforcement alone pulls the daemon in.

### Fixed

- **The inbound bundle opened three UDP ports to the whole internet.** Its
  mDNS, LLMNR and DHCP entries shipped without a source network, admitting
  unicast UDP from any address on earth; the comment above them promised the
  opposite. Now one entry per private range, with a bundle-wide test.
- A rule scoped to `exe_path = "<unknown>"` - the display placeholder for an
  unattributable process - matched every unattributable flow, which is every
  inbound flow. Four locks: the matcher, the API, load-time, and both UIs.
- `parent_exe` was counted in rule precedence but never compared, so a rule
  carrying it matched every process while outranking narrower rules. Refused
  at the API boundary until it can actually be evaluated.
- An unset rule direction now means outbound - its meaning before inbound
  filtering existed - instead of silently widening every pre-existing rule
  into an inbound admission the day the input chain is enabled.
- An unparseable inbound packet takes `inbound_action` (which cannot be
  Allow) instead of `no_ui_action` (which can).
- Deleting a deny rule now reliably lifts its in-kernel verdict, including
  for processes older than the attribution table's TTL.

## [0.2.0] - 2026-08-18

Four waves of correctness, security and usability work on top of the
0.1.0 alpha. The short version: one unanswered prompt no longer stalls
every new connection on the machine, the control socket is genuinely
access-controlled, a headless box can answer prompts from a terminal,
and every verdict is written to a queryable log.

### Added

#### Daemon (`colony-firewalld`)
- Pause toggle in the UI header and a `SetPaused` gRPC RPC. Status
  response carries the `paused` flag.
- Better startup diagnostics when NFQUEUE bind fails: hints for missing
  `CAP_NET_ADMIN`, missing `nfnetlink_queue` module, or queue-number
  collision.
- Persistent event log. Every observed connection and its verdict is
  written to an `events` table in the rules database, off the packet
  path (bounded queue, batched writes, dropped rather than blocking),
  and pruned to `[events] max_rows`.
- `ListEvents` RPC with executable-substring, action and since filters.
- `Reject` now sends a real refusal: a TCP RST for TCP flows, an ICMP /
  ICMPv6 port-unreachable for UDP, so the application fails immediately
  instead of hanging until its own timeout. Requires `CAP_NET_RAW`;
  without it the daemon warns once at startup and Reject behaves like
  Deny.
- `SIGHUP` hot-reloads `profile` and `[default_policy]` without dropping
  a packet or restarting. A config file that fails to parse is rejected
  and the running policy is kept.
- systemd `Type=notify` integration: `READY=1` is sent only once both
  the NFQUEUE and the control socket are bound, `WATCHDOG=1` heartbeats
  are withheld when the packet worker wedges, and `STOPPING=1` is sent
  on shutdown.
- `SIGTERM` joins `SIGINT` on the graceful shutdown path (final hit-count
  flush, control socket removed).
- New config sections: `[nfqueue]` (`queue_max_len`, `fail_open`),
  `[pause]` (`default_secs`), `[events]` (`max_rows`) and `[ipc]`
  (`group`, `require_group`).
- `cfc pause` accepts a duration; the daemon clamps it (24h maximum) and
  reports the real resume time, which `cfc status` and the UI display.
- `GetStatus` gained `enforcing` (a "no packets seen - is the nft rule
  loaded?" heuristic), `skipped_rules`, the effective prompt timeout and
  both fallback actions.
- Process attribution now covers unconnected UDP sockets (`sendto`
  without `connect`: mDNS, NTP, QUIC), wildcard-bound local addresses,
  and v4-mapped entries in the IPv6 socket tables (dual-stack Java, Go
  and node runtimes). These used to show up as an unknown process.
- A netlink `sock_diag` fast path for socket lookup, with a silent
  fallback to `/proc/net/*` when it misses.
- SHA-256 of the running binary (read through `/proc/<pid>/exe`, so a
  replaced-on-disk binary is still hashed correctly) is reported with
  each prompt.
- SQLite schema versioning (`PRAGMA user_version`) and a migration
  scaffold.

#### CLI (`cfc`)
- `cfc prompts` - answer connection prompts from a terminal. This is the
  headless gap: without a subscriber the daemon just applies its no-UI
  action. Shows the executable, pid, uid, command line and SHA-256 with
  a live countdown; `a`/`d`/`r`/`s` answer, then a duration and a scope
  mirroring the GUI's buttons. Falls back to line mode when stdin is not
  a TTY, and `--auto-allow` / `--auto-deny` cover scripts.
- `cfc log` - query the persisted verdict log
  (`--exe` / `--action` / `--since` / `--limit` / `--offset`).
- Global `--json` (or `-o json`) on every command; streaming commands
  emit NDJSON, one object per line.
- A documented exit-code contract: `0` ok, `1` runtime/RPC error, `2`
  usage, `3` not found, `4` daemon unreachable.
- `cfc live` gained an app column, hostnames in place of raw IPs where
  known, `--follow` (reconnects across daemon restarts) and filters:
  `--exe`, `--pid`, `--dst-port`, `--uid`, `--denied`.
- `cfc rules show`, `cfc rules enable` and `cfc rules disable`
  (idempotent, unlike `toggle`).
- Anywhere a rule id is accepted you may now pass a unique id prefix or
  the rule's name.
- Shell completions (`cfc completions bash|zsh|fish`) and man pages
  (`cfc man`), generated from the binary and installed by the PKGBUILD.

#### UI (`colony-firewall`)
- Prompt cards show the daemon's own deadline as a countdown bar, name
  the action that will fire if it runs out, and remove themselves when
  it does.
- Cards show the destination hostname where one is known, plus process
  details: full path, uid (or "unknown"), working directory, parent and
  SHA-256.
- Daemon-death detection: two failed polls flip the status badge, tear
  down the subscriptions and retry with a 3-5s backoff.
- Rules tab: sortable columns (name, hits, created), a created-at
  column, and a two-step confirmation before delete.
- Live tab: text and verdict filters, pause-with-buffering, colored
  verdicts, and per-row "make a rule" and "copy" actions.
- Stats tab: session top-10 apps and destinations, policy tiles, and
  banners for not-enforcing / skipped rules / paused.
- A status log (deduplicated, self-expiring, dismissible) replaces the
  single error string.
- Keyboard shortcuts: `A`/`D` answer the newest prompt, `Shift`
  persists, `1`-`4` switch tabs, `Esc`/`Enter` in the rule editor.

#### Packaging & infrastructure
- AUR-ready `pkg/PKGBUILD` plus a `-git` variant, a `.desktop` entry, an
  XDG autostart entry and a scalable icon.
- `colony-firewall-nft.service`: loads the nftables snippet at boot and
  deletes the table on stop, so a stopped or uninstalled daemon can no
  longer leave the machine blackholed.
- A `colony-firewall` group via a `sysusers.d` fragment, and a pacman
  install script that cleans up the nftables table on removal.
- `cargo-deny` (advisories, licenses, bans, sources) on PRs and weekly,
  Dependabot, all GitHub Actions pinned by commit SHA, `--locked`
  everywhere, a declared MSRV of 1.88 with a CI gate, a release
  workflow, and a script that keeps the version consistent across
  `Cargo.toml`, the PKGBUILD and `colony.json`.
- The Arch package is now built end to end on every push and pull
  request: CI runs a full `makepkg` on the `-git` recipe pointed at the
  checkout, so `build()`, `package()` and the install scriptlet are
  exercised without needing a published tag, plus a static
  `packaging-lint` gate (`bash -n`, sourceability,
  `makepkg --printsrcinfo`, `namcap`, `shellcheck` on the scriptlet).
- `scripts/check-release-assets.sh`: parses `pkg/colony.json`'s
  `postInstall` commands and fails if any file they install is not staged
  into the release tarball. Wired into `check.yml` and re-run by
  `release.yml`.
- The release workflow refuses to publish when the pushed tag does not
  match the `Cargo.toml` version, or when `CHANGELOG.md` has no section
  for it.
- At tag time the release job runs `updpkgsums`, asserts the `SKIP`
  checksum placeholder is gone, and attaches the AUR-ready `PKGBUILD`
  and `.SRCINFO` to the draft release.
- `docs/TROUBLESHOOTING.md`, a README "First run" section, and this
  `CHANGELOG.md`. The PKGBUILDs install `TROUBLESHOOTING.md` into
  `/usr/share/doc/`, which is where `cfc status` tells users to look.

### Changed
- `StatusResponse.connections_today` is now `connections_seen`. The
  counter was never daily: it counts since daemon start and resets on
  restart. The field number is unchanged, so the wire format is
  compatible; only the generated field name moves. Use `cfc log` /
  `ListEvents` for history that survives a restart.
- **Pausing no longer bypasses the rule engine.** Rules are still
  evaluated while paused, so explicit Deny and Reject rules stay
  enforced; pausing only stops *prompting*, and unmatched flows are
  allowed through. Pause is not a kill switch.
- Rule precedence is now deterministic instead of dependent on the
  order SQLite happened to return rows: most specific first, then Deny
  before Reject before Allow, then oldest first, then by id. Two
  conflicting rules always resolve the same way.
- `Duration` is enforced at lookup time - a `Seconds(n)` rule stops
  matching the moment it expires, and expired rows are reaped every 30
  seconds rather than lingering until restart.
- `Once` and `UntilRestart` rules are purged from the database at
  startup.
- The daemon writes its control socket as `root:colony-firewall` mode
  0660. If the group does not exist it warns with the fix and leaves the
  socket root-only rather than refusing to start.
- The NFQUEUE queue length and fail-open behaviour are configurable, and
  the kernel now reports the originating uid/gid with each packet
  (authoritative over anything found in `/proc`).
- Process lookups are cached with short TTLs (inode to pid, pid to
  process details keyed on process start time so pid reuse cannot alias,
  binary digest keyed on inode and mtime).
- `cfc status` reports whether the daemon is actually enforcing, and
  warns on stderr when it is not or when rules on disk failed to load.
- The systemd unit adds `SystemCallFilter=@system-service`,
  `SystemCallArchitectures=native`, `MemoryDenyWriteExecute`,
  `ProtectClock`, `ProtectHostname`, `RestrictSUIDSGID` and
  `UMask=0077`.
- Rules that fail to deserialize are counted and reported instead of
  silently vanishing; the rows are preserved on disk, never deleted.

### Fixed
- **One unanswered prompt could stall every new connection on the
  machine.** The NFQUEUE worker used to block waiting for each verdict
  in turn; it now parks pending packets and answers verdicts out of
  order. With nothing outstanding it still blocks in `recv`, so the
  common path costs nothing.
- Duplicate prompts for the same flow. SYN retransmits and parallel
  connections from the same program to the same destination now ride one
  prompt instead of each raising their own.
- A prompt whose subscriber disappeared could strand its packets
  forever; each pending prompt now gets its fallback applied.
- Answering `Once` used to be indistinguishable from `Always` once
  written to disk. Persisting an `Once` rule is now refused, and the UI
  disables the scope buttons for it.
- The CLI help described a bootstrap rule that did not exist.
- `cfc rules remove <unknown-id>` exited 0; it now exits 3.
- Connection failures used to surface as an opaque transport error. The
  CLI now distinguishes "the daemon is not running", "you are not in the
  `colony-firewall` group" and "the socket is stale", and names the
  command that fixes each.
- The UI silently swallowed a rejected verdict; an already-expired
  prompt now says so.
- An unattributed process was displayed as uid 0.
- **The MSRV job was not gating anything.** It asked
  `dtolnay/rust-toolchain` for 1.88, which only runs `rustup default`;
  the repo's `rust-toolchain.toml` (`channel = "stable"`) outranks the
  rustup default, so the job silently compiled with stable. It now pins
  `RUSTUP_TOOLCHAIN` and asserts `rustc --version` really is the MSRV.
- **The release tarball omitted three files `colony.json` installs**:
  the sysusers fragment, the XDG autostart entry and the icon. On the
  Colony store channel no `colony-firewall` group was created, so the
  control socket stayed root-only - the exact symptom the group work was
  meant to fix.
- The README's manual install never installed
  `colony-firewall-nft.service` or the nftables snippet, so First run
  step 1 failed with "Unit colony-firewall-nft.service not found" for
  anyone following it verbatim. Its Arch instructions pointed at the
  release PKGBUILD, whose source tarball does not exist before a tag is
  pushed.
- `PKGBUILD-git`'s `pkgver()` returned an empty string before the first
  tag: the `git describe | sed || fallback` pipeline reports sed's exit
  status, never git's, so the fallback could not fire and `makepkg`
  aborted with "pkgver is not allowed to be empty".

### Security
- **Unattributed traffic could match root's rules.** A process the
  daemon could not resolve was reported as uid 0 and gid 0, so a `uid =
  0` allow rule matched it. `uid` and `gid` are now optional end to end
  (core types, the wire protocol, and the UI), and a uid-scoped rule
  never matches an unknown process.
- **The control socket had no access control.** It is now chowned to
  `root:<group>` and chmodded 0660 before it serves anything, and every
  connection is checked against its peer credentials: mutating RPCs
  (`UpsertRule`, `DeleteRule`, `SetPaused`, `SubmitVerdict`) require uid
  0 or a socket that is genuinely group-gated, while read-only RPCs stay
  open to any peer that got past the file mode. Every mutating call and
  every Deny/Reject verdict is written to the journal with the calling
  uid and pid.
- **One desktop session could answer another's prompts.** The daemon
  tracks which subscribers actually received each prompt and refuses a
  verdict from anyone else (root excepted).
- **An unknown enum value on the wire became "Allow".** Decoding an
  unspecified or out-of-range action or duration is now an error
  (`InvalidArgument`) instead of falling through to the zero value,
  which was Allow.
- **`Reject` was a lie.** It handed the kernel the same DROP as `Deny`
  and sent nothing, so applications hung until their own timeout instead
  of failing fast. It now injects a real refusal (see Added), for every
  source of a Reject verdict: a persisted rule, an answered prompt, and
  a `reject` default policy alike. The verdict pipeline no longer
  collapses Reject into Deny on its way to the datapath.
- **A failed NFQUEUE bind exited 0.** Under the shipped fail-closed
  nftables rule that meant systemd considered the daemon started while
  the kernel dropped every new outbound connection. Open and bind
  failures now propagate, so the unit fails visibly and
  `Restart=on-failure` retries.
- **IPv6 extension headers could hide the real ports.** The parser
  assumed the transport header sat immediately after the fixed IPv6
  header, so a packet carrying a Hop-by-Hop or Destination-Options
  header was matched on garbage ports. The chain is now walked (bounded
  to 8 headers) and non-first fragments are classified as neither TCP
  nor UDP. Likewise, an IPv4 header claiming `ihl < 5` made the parser
  read "ports" from inside the IP header itself; that is now rejected.
- Documented the `dst_host` trust model in `docs/HARDENING.md`:
  hostnames come from reverse DNS, which the destination's own operator
  controls. The daemon forward-confirms every PTR answer and discards
  unconfirmed names, but `dst_host` is still best-effort and should not
  carry an allow rule on its own.
- Dependency advisories are gated in CI (`cargo-deny`), lockfile updates
  cleared the outstanding RustSec advisories, and GitHub Actions are
  pinned by commit SHA.

## [0.1.0] - 2026-05-25 (initial alpha)

First end-to-end usable build. Daemon filters real outbound traffic, UI
serves prompts, CLI exercises the full surface.

### Added

#### Daemon (`colony-firewalld`)
- NFQUEUE recv loop with IPv4/IPv6 + TCP/UDP/ICMP 5-tuple parsing
- Process resolution via `/proc/net/{tcp,udp}{,6}` + `/proc/*/fd`
- Decision engine with `RuleSet::lookup` and atomic upserts
- Reverse DNS cache (`dns-lookup`, 300s positive / 60s negative TTL)
- Self-pid skip so the daemon's own reverse-DNS queries don't deadlock
- SQLite rule store via `rusqlite`
- gRPC server over Unix domain socket (tonic 0.14 + hyper-util)
- `PromptRouter` bridging sync NFQUEUE worker to async UI subscribers
- Timeout fallback per `[default_policy]` config block
- Named profiles in config: `relaxed`, `balanced`, `strict`
- Atomic stats counters (uptime, total/allowed/denied, prompts pending)
- `--dry-run` flag that skips NFQUEUE bind for UI/CLI development
- systemd unit with `CAP_NET_ADMIN`, `ProtectSystem=strict`, etc.

#### UI (`colony-firewall`)
- iced 0.14 application with parchment + burgundy Colony theme
- Four tabs: Prompts / Rules / Live / Stats
- Prompt cards with five answer scopes (once, this app, this app + dst,
  deny once, deny app)
- Rules table with: add, edit, delete, enable/disable toggle, search
  by name / exe / host / net
- Live connection feed (subscription, capped at 500 entries)
- Stats counter cards (2s polling)
- Auto-reconnect on UDS errors with backoff
- Desktop notifications via `notify-rust` on every new prompt

#### CLI (`cfc`)
- `cfc status` - daemon counters
- `cfc rules list / add / remove / toggle`
- `cfc rules export [--out FILE]` / `import [--replace]` JSON
- `cfc rules import-opensnitch <path>` - migrates from opensnitch
- `cfc live` - colorized terminal feed (allow green, deny red)

#### Packaging & infra
- `pkg/PKGBUILD` (Arch / AUR)
- `pkg/colony.json` (Colony app store manifest)
- GitHub Actions: fmt + clippy `-D warnings` + tests + fast-profile build
- 29 unit tests across `cfc-core`, `cfc-daemon`

### License

GPL-3.0-or-later (derivative of opensnitch).
