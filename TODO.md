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

**1a. An in-kernel *allow* buys nothing yet.** The connect hook cannot skip
NFQUEUE, so a pre-approved program still takes a userspace round trip per
connection - which is the actual latency cost of CFC, and it is paid dozens of
times per page load in a browser. Making it real needs
`bpf_setsockopt(SO_MARK)` on the connect path plus an nft rule that accepts the
mark before the queue rule. That is a performance change with a
traffic-bypasses-the-firewall blast radius, so it wants its own change and its
own tests, not a line in this one.

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

What remains is the part that cannot be done from here:

**2a. The SELinux policy has never met an enforcing system.** It compiles
against the real `selinux-policy-devel` on Rocky 9 and Fedora, which proves
every type and interface it names exists there. It does not prove the rules are
*sufficient*. Someone has to install it on an enforcing host, run the daemon
under load, and report what `audit2allow -w` asks for. A missing rule is a bug
in `packaging/selinux/colony_firewall.te`, not something to add locally.

**2b. Nothing has built the RPM end to end.** CI parses the spec and builds a
source RPM; a full `rpmbuild -ba` needs Rust >= 1.88, which Rocky 9 does not
ship in its default repos. Either a `rust-toolset` module dependency or a
build in a Fedora container, and neither has been tried.

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

## 4. Rules should bind to the binary, not to its path

A rule created from a prompt carries `exe_path` and leaves `exe_sha256` empty
(`crates/cfc-tray/src/model.rs`, `verdict_for`). The rule therefore follows the
*path*: replace the file at that path and the allow follows.

For `/usr/bin/*` this needs root, so it matters less. It matters a lot for any
allowed binary under a user-writable path.

The field and the machinery both already exist - provenance hashes the running
image. What is missing is a decision about *when* to bind to the hash, because
binding always means every package update invalidates every rule. Probably:
bind on hash when the binary lives somewhere a non-root user can write, bind on
path otherwise, and say which in the prompt.

---

## 5. The tray icon fallback does not work where it is needed

`icon_pixmap` carries an embedded raster precisely so the tray is usable before
the package installs the theme SVG. Observed on quickshell/Noctalia: the host
honours `icon_name` only, so an uninstalled CFC shows a broken-image
placeholder rather than the fallback.

Either the fallback needs to work on hosts that behave this way, or the tray
should notice it has no resolvable theme icon and say so.

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
