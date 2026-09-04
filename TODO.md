# TODO

Work that is understood but not done, and the honest limits of what exists.

`docs/ROADMAP.md` is the phase plan. This file is narrower: things found by
using the thing, decisions taken with their reasoning, and the boundaries
someone would otherwise have to discover the hard way.

Ordered by what would change the most, not by effort.

---

## 1. In-kernel enforcement: what is left of it

Done, in `c281edb` and `c8fb04d`. `cgroup/connect4|6` refuse `connect()` for
programs already denied, before a packet exists, and their link is **pinned to
bpffs** so the denials survive the daemon being killed. Killing the daemon no
longer lifts anything; `nft delete table` no longer lifts the denies it holds.

Two pieces of it are deliberately not done, and both are real work rather than
oversights:

**1a. An in-kernel *allow* now buys the round trip - opt-in.** Done, along
the line sketched here (`bpf_setsockopt(SO_MARK)` on the connect path, an nft
rule ahead of the queue), and then reshaped by an adversarial review of the
design that stood 59 objections before a line was written. The three that
could not be patched, and what replaced them:

- *The mark lives on the socket, not in the map.* Revoking a grant left every
  already-marked socket marked, and an fd inherited across `execve` carried
  the bypass to a binary that earned nothing. So the mark is re-decided - set
  or stripped - at every flow start, `connect()` and `sendmsg()` alike, and
  sockets already carrying someone else's mark (a VPN, a proxy) are left
  alone in both directions. Exactly which hooks that is, is what the
  *implementation* review pinned down: `cgroup/sendmsg` runs for a send that
  carries a destination, not for `send()` on a connected socket. So **only TCP
  is ever marked** - an allowlist, after two narrower rules leaked in a row
  (refusing UDP at `connect()` alone left the sendmsg hooks marking sockets
  that were already connected; naming UDP at all missed UDP-Lite, DCCP and
  SCTP). The cost is nil in the case that matters: a UDP peer that answers
  makes the flow conntrack-established, and only `ct state new` is queued. What
  is given up is the fast path for QUIC, which was getting its first packet
  through it and nothing more.

  **Follow-up, deliberately not done here.** With no UDP socket ever marked,
  the two `cgroup/sendmsg` programs can no longer set a mark, and they can no
  longer strip one either: a strip fires only for *our current* mark, which by
  construction can only be on a TCP socket, while any other value takes the
  `FOREIGN_MARK` early return and is left alone. They are provably dead except
  as a speed bump against a process that forges the mark on an unconnected UDP
  socket - which, holding CAP_NET_RAW, can simply set it again. Removing them
  would delete two programs and ~300 verifier instructions each.

  Not free, though. `fast_path_attached()` uses their pins as the inherited
  path's only evidence of which connect variant is running, so that signal
  needs replacing first. And it does **not** unlock 5.10: that was claimed here
  once and was wrong - the eligibility ladder stops earlier. Worth doing the
  next time the ABI moves for another reason, not on its own.
- *`CAP_NET_RAW` can set `SO_MARK` since 5.17*, which docker grants by
  default. A published mark value is a bypass token. The value is drawn at
  random per start and lives in a pinned map and an nftables set, never in a
  package. Two things the implementation review added: the draw is sieved
  against the fwmark selectors other software uses - kube-proxy's masks are a
  single bit each, so an unsieved word collided half the time on a Kubernetes
  node - and the set is flushed unconditionally at start, because a value left
  accepted that nothing refreshes is one every past grantee can still read off
  its own socket with `getsockopt(SO_MARK)`.
- *A static accept rule is a token on every install.* The snippet ships the
  set empty; the daemon fills it only when the path is armed - the one thing
  the daemon does to nftables.

Grants are cleared in the kernel on exec and exit, so no daemon is needed for
the hand-over to fail safe; a `CLOCK_BOOTTIME` deadline the daemon refreshes
makes a dead daemon fail-closed within one deadline (60 s refreshed every 10 s,
or 6 s refreshed every 2 s where the lifecycle links cannot be pinned); and the
path stays off - with
the reason in `cfc status` - unless enforcement is pinned, exit is detected
exactly (`group_dead`), their ring consumers running, the cookie connect
variants *and* the sendmsg hooks verified, the nftables set present and holding
this daemon's mark, and `[ebpf] fast_allow` is set. Whether the exec/exit links
could be *pinned* is not on that list any more: it decides the grant deadline
(sixty seconds, or six) rather than whether the path runs at all - refusing it
withheld the feature from 5.10 through 5.14 for a risk the deadline bounds. The matrix drew that last line on
the first run: 5.10 accepts `bpf_getsockopt` on a connect hook and refuses it
on a sendmsg hook (`unknown func bpf_getsockopt#57`), 6.12 accepts both - so
on the RHEL-floor kernel the fast path reports itself off with that sentence,
rather than shipping half-present without the UDP re-decision that closes the
reused-socket hole. **Off by default** for this release: the
blast radius named above has not changed, only its edges.

An adversarial review of the *implementation* then found 23 confirmed defects
on top of the design's 59, all fixed on this branch. The ones worth
remembering as classes: a second decider that read the execve string and the
exec-time uid where every other decider reads `/proc` (which skipped
relative-exec processes entirely, so a grant survived its rule's deletion);
grants written with no liveness guard where the deny side had carried one
since it was written; and the feature being **inert for its own motivating
case** - nothing granted a process that was already running, so every restart
silently switched the fast path off for every long-lived program while
`cfc status` said `live`. What is not done: the latency win is not yet
*measured* on the veth bench - the number that justifies the feature is still
the pre-feature 0.28 ms per new flow - and 1b below is untouched.

**1b. Rules that depend on a destination still cannot be precomputed.**
`process_wide_action` deliberately answers `None` for them, which is correct and
also means a browser with a port-scoped rule gets no in-kernel enforcement at
all. A destination-keyed map would fix it and is a much larger design: the
kernel side would need to match addresses, and every DNS-name rule would have to
be resolved to addresses in advance.

---

## 2. RHEL / Rocky: what is left of it

Mostly done in `8db949b` and `b05eefc`: the SELinux module, the RPM provenance
backend, the `.spec`, and a 5.10 entry in the kernel matrix that sits *below*
RHEL 9's backported 5.14.

What remains needs a real enforcing machine - except 2b, which turned out to
be doable from CI after all:

**2a. The SELinux policy has never met an enforcing system.** It compiles
against the real `selinux-policy-devel` on Rocky 9 and Fedora, which proves
every type and interface it names exists there. It does not prove the rules
are *sufficient*, and nothing that runs in a container can. The protocol for
whoever has an enforcing VM is written and ready to run:
`packaging/selinux/TESTING.md` - permissive-domain first (a missing netlink
rule enforced is an outage, not a log line), one exercise per policy group,
`audit2allow -w -a` as the report. Open until someone actually runs it; a
missing rule it finds is a bug in `packaging/selinux/colony_firewall.te`,
not something to add locally.

**2b. Done - the `rpm end to end (fedora)` job in `rhel.yml` builds,
installs and verifies the RPM end to end, and has run green on every push
since.** It took three rounds to get there, none at a predicted failure
point: git's dubious-ownership refusal inside the container, then a
`pkgconfig(systemd)` build dependency Fedora 44's generator injects that the
spec never declares. (This file had been burned once by declaring CI verified
before it ran - see section 6 - so the previous wording here was "one green
run away"; the run came.) `rpmbuild -ba` in a Fedora container (the
tarball laid out the way `%autosetup` expects, built as an unprivileged
user), then a real `dnf install` of both packages: binaries report the
packaged version, units and the sysusers file land where the spec says, the
sysusers scriptlet really created the group, `rpm -V` comes back clean. The
caveat that keeps this honest: it proves the spec builds *on Fedora's
toolchain*. Rocky 9's own path - the `rust-toolset` module, since its
default repos stop short of the 1.88 MSRV - remains untried, so "the
deployment target can build this package" is still an assumption. Found
along the way: the release profile's `strip = true` leaves find-debuginfo
nothing to extract, which is a hard rpmbuild error on Fedora, not a warning;
the spec now sets `%global debug_package %{nil}` and says why.

**2c. The provenance subprocess is untested inside the unit's sandbox.** The
rpm backend runs `rpm -qa`, and the daemon's own `SystemCallFilter`,
`ProtectSystem=strict` and `MemoryDenyWriteExecute` all apply to that child. It
should be fine and it degrades safely if it is not - a warning and an empty
index - but "should be fine" is not "was observed".

---

## 3. Executable paths: what resolution does and does not fix

Rules now resolve their `exe_path` to the form `/proc/<pid>/exe` reports, at
every place a path is entered (`cfc_core::exe_path`). Three properties of that
are worth stating rather than discovering:

- **Forward-only.** Rules already on disk are never re-resolved. An install
  that wrote `/bin/curl` before this existed keeps an inert rule after
  upgrading. The repair is one round trip - `cfc rules export > r.json &&
  cfc rules import --replace r.json` - because upsert resolves.
- **A versioned symlink resolves to a version.** `/usr/bin/python ->
  python3.13` stores `python3.13` and stops applying when the symlink moves.
  Not a regression (the unresolved rule never matched either), but a new
  *time-dependent* failure, and worse for a Deny than an Allow.
- **It follows symlinks the path's owner controls.** A rule for
  `/home/bob/tool` pointing at `/usr/bin/curl` becomes a rule about curl. The
  CLI prints what it stored and the daemon warns; nothing pins the inode.

---

## 4. Rules bind to the binary where the path cannot be trusted

Done, along the exact line sketched here: bind on hash when the binary lives
somewhere a non-root user can write, bind on path otherwise, and say which in
the prompt. The seal judgment is the BPF-object vetting's own policy
(root-owned file, root-sealed ancestors, the sticky exception), moved to
`cfc_core::exe_path::is_root_sealed` so the two cannot drift. The hash is
taken at *prompt* time from `/proc/<pid>/exe` - the bytes the human is
deciding about - and carried by the router until the answer arrives
(`PromptBinding`), because at submit time the process may be gone or exec'd
into something else. The prompt announces it (`binds_to_hash` in the proto,
shown by all three clients), the response says what was stored
(`persist_note`), and a promised binding that falls through is spoken, never
silent.

Two boundaries drawn on purpose:

- **Denies never bind.** A hash-bound deny is one file swap away from
  covering nothing, while the path-bound one covers whatever bytes sit
  there next. The threat this feature answers is inherited *allows*.
- **CLI `rules add` does not auto-bind.** An explicit command gets exactly
  what it wrote; `--pin-hash` exists for the intent, and package updates
  invalidating hash-bound rules is a cost someone should choose knowingly.
  Prompts are different: nobody answering a bubble has made that choice, so
  the daemon makes the safe one and says so.

---

## 5. The tray icon fallback did not work where it was needed

`icon_pixmap` carries an embedded raster precisely so the tray is usable before
the package installs the theme SVG. Observed on quickshell/Noctalia: the host
honours `icon_name` only, so an uninstalled CFC showed a broken-image
placeholder rather than the fallback.

Fixed with the spec's own escape hatch, `IconThemePath`
(`crates/cfc-tray/src/theme.rs`). When "colony-firewall" is not installed
where icon lookup searches - probed across `$HOME/.icons`,
`$XDG_DATA_HOME/icons`, every `$XDG_DATA_DIRS` entry, and pixmaps - the tray
writes the packaged SVG (embedded at compile time from `pkg/`, so it is the
same artwork byte for byte) into `$XDG_RUNTIME_DIR/cfc-tray/icons` and exports
that directory, in both layouts hosts are known to use: a flat file for GTK's
unthemed lookup and a `hicolor` tree with an `index.theme` for strict Qt
lookup. With the theme installed nothing engages and the exported property is
the same empty string as before, so hosts that already worked see nothing new.
Without `$XDG_RUNTIME_DIR`, or when the write fails, the tray says so in one
warning naming the fix instead of leaving a placeholder to be puzzled over
(`/tmp` is deliberately not a fallback: a predictable name in a world-shared
directory is a symlink game).

The probe and the written tree are unit-tested; what is not verified is the
one thing that prompted this: nobody has yet watched quickshell/Noctalia
render the runtime path on a machine without the package. If it still shows a
placeholder there, the remaining suspect is how that host consumes
`IconThemePath`, not whether CFC exports it.

---

## 6. Verify the CI that was written for this

Done, the hard way. "Expect one round of correction on the first push" was
optimistic by a factor of nine: the vm matrix and selinux jobs took nine
rounds (#23), and nearly every round's error was another bug's mask - a
docker invocation, an ext4 guest that became a cpio initramfs, a mute
console, a glibc floor, a loopback nobody raised, one possessive apostrophe
inside an m4-quoted interface body, and a guest verdict that trusted qemu's
exit code. The predicted failure points (the Rocky dnf invocation, a wrong
interface name) were not among them. Every job has since run green
repeatedly, including the five-kernel matrix with enforcement-attach
assertions and both selinux containers; `release.yml`'s eBPF steps and the
Arch packaging path (`makepkg`, `namcap`, `50-strip.sh` on the BPF object)
were exercised for real by the v0.2.3 release, which took five tag attempts
of its own.

What this bought beyond green squares: the CI now asserts things it only
appeared to before - the LLVM pairing check could never fire, CFC_EXIT=0
covered a test filter matching zero tests, and the kernel matrix never
checked that enforcement attached. All three assert for real now.

---

## 7. The AUR package ships no BPF object

Deliberate, for a reason that is not going away on its own: on Arch `rustup`
conflicts with `rust`, which the packaging containers install, so
`rust-toolchain.toml` is inert inside `makepkg` and `-Z build-std` fails on
stable. An AUR install therefore gets `Degrade::ObjectMissing` and runs on
`sock_diag` + `/proc`.

Three ways out, none free:

1. leave it (what happens today - the Colony tarball has the object, AUR does not);
2. ship the object as a second `source=()` from the release assets - but that
   deadlocks against draft releases, and it would be the one shipped component
   no AUR user builds from source, which for kernel code deserves a hard think;
3. provision a proper chroot with rustup + bpf-linker.

---

## Limits, not bugs

These are properties of the design. They should be in the README before anyone
relies on the product, because the failure mode of *not* saying them is someone
believing they are protected when they are not.

**CFC is a detection and consent layer. It is not a containment boundary.**
SELinux is a containment boundary. The two are not substitutes.

What CFC actually guarantees: against an unprivileged adversary running as its
own executable and not injecting into anything, an outbound connection is
noticed and requires a decision. That is the dropper-calls-its-C2 case, and it
is a large share of real malware. It is a genuinely useful guarantee.

What defeats it completely:

| | |
|---|---|
| **Root** | narrower than it was, and still open. `nft delete table` no longer lifts the denials held in the kernel - those need `rm -rf /sys/fs/bpf/colony-firewall` as well, and anything not yet decided still falls through to a ruleset root can flush. CFC *is* root; it cannot confine root. |
| **Code inside an allowed process** | a browser extension, a script under an allowed interpreter, `ptrace`/`LD_PRELOAD` injection. Structural to every application firewall. Making Allow persistent (`72964b5`) improved usability and widened this. |
| **Loopback** | `oifname "lo" accept`, deliberately - filtering it stalls the systemd-resolved stub. Anything that can reach a local service which egresses is attributed to that service. |
| **DNS tunnelling** | the resolver must be allowed for anything to work. CFC *observes* answers; it does not inspect or block queries. |
| **Passed socket descriptors** | NFQUEUE gives a socket, not a pid. `SCM_RIGHTS` breaks the association; ring-0 exec tracking does not help here. |
| **Prompt fatigue** | demonstrated on this machine: ten Firefox prompts in a row, all denied, browser lost. A malicious installer generating thirty prompts trains the user to click Allow. |

And one tradeoff worth stating plainly: the ruleset is **fail-closed** (`ct
state new queue num 0`, no `bypass`). Killing the daemon drops all new outbound
traffic. That is the right choice for confidentiality and the wrong one for
availability - anything that can crash the daemon takes the machine's network
with it.

Since `c281edb` that cuts both ways in the daemon's favour: the pinned
`cgroup/connect4|6` programs keep refusing denied programs while the daemon is
down, so a crash no longer converts a deny into a maybe. It converts everything
else into a drop, which is the same tradeoff as before.

### Where CFC sits next to other things

Compared against, and none of them substitutes for another:

- **SELinux / AppArmor** - mandatory access control in the kernel, covering the
  whole syscall surface, confining root. Strictly stronger as *enforcement*.
  CFC answers a question it does not: which program, to which destination,
  decided interactively.
- **Proxmox `pve-firewall`** - a network firewall for virtualised
  infrastructure. Evaluates in kernel with no userspace round trip; CFC's
  NFQUEUE model is simply the wrong shape for a hypervisor's connection rate.
  It has no idea which process opened anything.
- **UTM appliances (e.g. Skyron / Heraklet)** - network perimeter: IDS/IPS,
  content filtering, VPN, captive portal, covering devices that cannot run an
  agent at all. A C2 over 443 to a reputable CDN passes their content filter
  and is exactly what CFC catches; inbound traffic and an IoT device are
  exactly what they catch and CFC cannot.

---

## Done, from one live session

Recorded because all three were invisible to 624 passing tests and were found
within twenty minutes of actually clicking things.

- **`cec0fe0`** - the tray never showed a single notification, for the whole
  life of the process. notify-rust's `SPEC_VERSION` lazy_static makes a
  blocking D-Bus call, dereferenced by any notification carrying image data -
  which is every one, because of the embedded icon. It builds a tokio runtime
  inside one and panics; lazy_static then marks itself poisoned, so every later
  notification fails too. Silently. The tray kept reporting
  `prompt stream subscribed` throughout.
- **`72964b5`** - "Allow" permitted one connection. A browser opens dozens per
  page, so the product was unusable on exactly the applications that matter,
  while the *only* one-click permanent choice was Block. Now Allow persists per
  executable, the WFC model.
- **`72964b5`** - "Open Colony Firewall" did nothing at all when the GUI was not
  installed: a `warn!` and no user-visible feedback, from the tray icon, the
  prompts line and the Details button alike.
- **`a_deny_rule_reaches_the_kernel_by_itself`** found nothing about the daemon
  and everything about the test: `#[tokio::test]` is single-threaded, so the
  `std::thread::sleep` waiting for the exec event starved the ring-buffer
  consumer that was supposed to deliver it. The test failed claiming the rule
  never reached the kernel. Worth recording because the same shape - block a
  current-thread runtime, then assert on what a spawned task was meant to do -
  will look like a product bug every time.
