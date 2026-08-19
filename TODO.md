# TODO

Work that is understood but not done, and the honest limits of what exists.

`docs/ROADMAP.md` is the phase plan. This file is narrower: things found by
using the thing, decisions taken with their reasoning, and the boundaries
someone would otherwise have to discover the hard way.

Ordered by what would change the most, not by effort.

---

## 1. Decide in the kernel, not in userspace

**The only item here that changes what CFC *is*.**

Today the decision point is a userspace daemon behind NFQUEUE. That makes the
whole guarantee conditional on a chain: the nftables table must be loaded, the
daemon must be alive, the attribution must be right. Any root process breaks it
with one command:

```sh
nft delete table inet colony_firewall
```

A `cgroup/connect4` + `connect6` eBPF program can refuse a `connect()` **before
the syscall returns** - in kernel, with no userspace round trip, no daemon to
kill and no table to flush. It would not fix injection into an allowed process
or loopback-mediated egress (see *Limits* below), but it would remove the
"stop the daemon" bypass entirely and turn fail-closed into real enforcement.

Most of what it needs already exists: the loader, BTF offset resolution, the
ABI gate, the kernel CI matrix. What is missing is a program that *decides*
rather than observes, and a way to get a rule set into a BPF map that the
kernel side can consult without a userspace hop.

Open questions worth settling before writing code:

- Where do rules live kernel-side? A hash map keyed on `(cgroup, exe hash)` is
  the obvious shape, but exe identity in a BPF map is not free.
- What happens to prompts? An in-kernel deny cannot ask a question. Probably:
  the kernel enforces the *known* answers and unknown flows still go to
  NFQUEUE for a decision, which the daemon then installs into the map.
- Does this replace NFQUEUE or sit in front of it? In front, almost certainly -
  NFQUEUE stays for the interactive path.

---

## 2. RHEL / Rocky support

Asked for directly. It is a real project, not three lines - three separate
pieces, none of which exist:

**2a. SELinux policy module.** On a distribution whose whole argument is
SELinux enforcing, CFC would be blocked by it. The daemon calls `bpf()`, binds
NFQUEUE over netlink, creates a unix socket in `/run`, and loads a BPF object
from `/usr/lib`. Every one of those needs a policy rule. Shipping instructions
that say "set it permissive" would be the exact wrong advice on that platform,
so this has to be a real `.te`/`.fc` module.

**2b. RPM provenance backend.** `provenance::detect` only knows pacman and
dpkg (`crates/cfc-daemon/src/provenance.rs`). On Rocky every binary resolves to
`Unknown`, so the "does this file still match its package?" check silently does
nothing. Needs an rpmdb reader - and note the dpkg backend is already
*name-only* because dpkg records MD5; RPM records SHA-256, so an RPM backend
could actually verify, unlike dpkg.

**2c. `.spec` packaging.** Only the Arch PKGBUILD and the Colony manifest
exist.

**2d. CI blind spot.** The kernel matrix covers 6.12, 6.18, 7.1 and mainline.
RHEL 9 ships **5.14 with heavy backports** - a kernel whose version number says
almost nothing about which BPF features it has. It is exactly the shape of
kernel that surprises people, and nothing tests it.

---

## 3. Rules should bind to the binary, not to its path

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

## 4. The tray icon fallback does not work where it is needed

`icon_pixmap` carries an embedded raster precisely so the tray is usable before
the package installs the theme SVG. Observed on quickshell/Noctalia: the host
honours `icon_name` only, so an uninstalled CFC shows a broken-image
placeholder rather than the fallback.

Either the fallback needs to work on hosts that behave this way, or the tray
should notice it has no resolvable theme icon and say so.

---

## 5. Verify the CI that was written for this

None of `.github/workflows/ebpf.yml` has ever executed - a workflow cannot be
run from a working tree. The YAML parses, the two shell helpers run clean
locally, the ci-kernels digests and the `/boot/vmlinuz` path were confirmed
against the registry. **Expect one round of correction on the first push.**

Also unverified: the eBPF build steps added to `release.yml`, and Arch
packaging end to end (`makepkg`, `namcap`, and what `50-strip.sh` does to a BPF
object).

---

## 6. The AUR package ships no BPF object

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
| **Root** | one `nft delete table`. CFC *is* root; it cannot confine root. Item 1 above narrows this, never closes it. |
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
