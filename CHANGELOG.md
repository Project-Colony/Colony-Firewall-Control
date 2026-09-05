# Changelog

All notable changes to Colony Firewall Control will be documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  of** (`fast_path=ready|sendmsg-unavailable|basic-connect` on the log
  line, `none` where no connect hook attached), and the matrix test asserts it per kernel along with `group_dead`
  where a run has already shown the answer: 5.10 takes the connect hooks and
  refuses the sendmsg ones, 5.15 and 6.12 take both and still have no
  `group_dead`, 6.18 and 7.1 have everything. A kernel that changes its
  answer fails in CI rather than degrading quietly on a host; one without a
  recorded answer is
  printed, and the matrix summary carries the line.

### Changed

- Three costs removed from paths every process on the machine takes, none of
  them measured on a live kernel - this machine cannot run the daemon - and
  each argued from what the code does rather than from a number. The exec and
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
  grants exactly that. The set is flushed unconditionally at every start, so
  a daemon that crashed while armed and came back with the path off does not
  leave its predecessor's mark accepted; and once armed the daemon re-checks
  every minute that the element is still there, so an `nft -f` that reloads
  the ruleset is noticed and re-armed rather than reported as live. The
  nftables snippet gains the set and the accept rule; an older snippet leaves
  fast-allow off with the reason spelled out.

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
