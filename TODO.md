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

**1a. Fast Allow was removed.** It let a process a lasting Allow covered skip
NFQUEUE by marking its sockets. A socket mark does not attest the current
sender, and grants could outlive their intended executable or rule, so it
opened bypasses. It was disabled in 0.7.0 and its userspace side has since been
removed; allowed flows use NFQUEUE. The nft snippet no longer accepts the
legacy set, startup flushes it and disarms the legacy pinned maps the kernel
object still carries until an ABI bump, and upgrades reload active nft units
atomically. Reintroducing an in-kernel Allow needs sender attestation: a design
that verifies current socket ownership and revocation.

The previous latency measurements describe the removed implementation. The
remaining NFQUEUE cost still warrants measurement and optimization, with the
same application-policy semantics.

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
RHEL 9's backported 5.14. The matrix also carries 5.15 above it, so the pair
brackets the RHEL kernel: what both allow, 5.14 allows unless Red Hat took it
out; what only 5.15 allows, 5.14 has only if they backported it; what both
refuse, 5.14 may still have through a backport. Where the two disagree is the
list of things to check on a Rocky host rather than assume. Neither kernel has
`group_dead`.

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

Rules must name the form `/proc/<pid>/exe` reports (`cfc_core::exe_path`):
every place a new or changed path is entered refuses an alias and asks for
the canonical target. Three properties of that are worth stating rather than
discovering:

- **Stored rules keep their target.** Nothing re-resolves a rule on disk. An
  install that wrote `/bin/curl` before validation existed keeps an inert
  rule after upgrading, and so does a rule whose target a package update later
  turned into a symlink. Sending the stored path back unchanged (enable,
  disable, rename, `cfc rules export` then `import --replace`) is accepted;
  the repair is to edit the rule to name `/usr/bin/curl`.
- **A versioned target is a version.** `/usr/bin/python -> python3.13` has to
  be written as `python3.13`, and stops applying when the symlink moves. Not a
  regression (the alias never matched either), but a *time-dependent* failure,
  and worse for a Deny than an Allow.
- **The daemon cannot see every alias.** It runs with `ProtectHome=true` and
  `PrivateTmp=true`, so `/home/bob/tool -> /usr/bin/curl` looks like a target
  that is not installed yet and is accepted. The CLI and GUI check in the
  caller's own namespace first; a raw gRPC client is not stopped. Such a rule
  names a path the user controls and matches only that path, never curl.

Process resolution now rereads policy identity for every packet lookup; pid
and start time do not identify an executable across exec. Its path and digest
come from one opened mapped image, with metadata and link consistency checks.
Digests are cached by full image key, ctime included, once ctime has settled.
A raw exec-event filename is retained for diagnostics only; once `/proc` is
gone, the policy executable is unknown.
Shared or passed socket descriptors remain outside sender attribution, and
the mapped image is still a read-time snapshot rather than packet-time proof.

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

1. leave it (what happens today - the release tarball has the object, AUR does not);
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

CFC decides new tracked outbound flows when its table is loaded. This scope
excludes established/related traffic, local relays, inherited or passed sockets,
and packet-layer traffic. It is application consent, not domain or process
containment.

What defeats it completely:

| | |
|---|---|
| **Root** | narrower than it was, and still open. `nft delete table` no longer lifts the denials held in the kernel - those need `rm -rf /sys/fs/bpf/colony-firewall` as well, and anything not yet decided still falls through to a ruleset root can flush. CFC *is* root; it cannot confine root. |
| **Code inside an allowed process** | a browser extension, a script under an allowed interpreter, `ptrace`/`LD_PRELOAD` injection. Structural to every application firewall. Making Allow persistent (`72964b5`) improved usability and widened this. |
| **Loopback** | `oifname "lo" ct state new queue num 0 bypass`: the daemon judges new loopback flows while it runs (unmatched local IPC is allowed without prompting), and they are allowed unfiltered while no daemon listens, so local IPC survives a dead daemon (the systemd-resolved stub answers from its cache; its upstream queries are not loopback). In that window explicit loopback Deny rules are not enforced and nothing is logged. Anything that can reach a local service which egresses is attributed to that service. |
| **DNS tunnelling** | the resolver must be allowed for anything to work. CFC *observes* answers; it does not inspect or block queries. |
| **Inherited or passed socket descriptors** | Existing connection authorization is not rechecked for each sending executable; socket attribution is ambiguous when ownership is shared. |
| **CAP_NET_RAW packet sockets** | Packet-layer egress can bypass the IP OUTPUT hook. Layer-2 confinement is outside the shipped rules. |
| **Code inside the official app or tray** | the daemon accepts changes only from root and the installed, sealed app and tray, checking the running process (image, prologue, connection, tracer, file-backed executable mappings). Code already running inside them is not seen: a self-unmapping `LD_PRELOAD` payload living in anonymous memory, or synthetic X11/XWayland input clicking the GUI. Setgid binaries trusted by connect-time gid would close the first; not done. |
| **Prompt fatigue** | demonstrated on this machine: ten Firefox prompts in a row, all denied, browser lost. A malicious installer generating thirty prompts trains the user to click Allow. |

And one tradeoff worth stating plainly: the ruleset is **fail-closed for
everything except new loopback flows, which are allowed while no daemon
listens** (the final `ct state new queue num 0` has no `bypass`). Killing the
daemon drops all new non-loopback outbound traffic. That is the right choice for confidentiality and the wrong one for
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
