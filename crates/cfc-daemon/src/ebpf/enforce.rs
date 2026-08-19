//! In-kernel `connect()` enforcement, and the bpffs pins that outlive the
//! daemon.
//!
//! Everything else in this crate observes. This module is the one part that
//! *decides* without a userspace round trip, and the reason it exists is a
//! single sentence in `TODO.md`: today any root process lifts the whole
//! guarantee with `nft delete table inet colony_firewall`, and killing the
//! daemon stops every future decision from being made at all.
//!
//! The mechanism is BPF link pinning. A link held only by a process dies with
//! that process; a link pinned into bpffs is held by the filesystem, so the
//! program stays attached and keeps refusing `connect()` after the daemon is
//! gone - killed, crashed, OOM'd or stopped by an attacker who got root. The
//! map it consults is pinned the same way, so the next daemon picks up exactly
//! the state the last one left.
//!
//! What this does not do, and cannot: confine root. Root can `rm` a pin, and
//! nothing running as root can stop that. What changes is the cost. "Stop the
//! daemon" no longer works, and neither does "flush the ruleset"; an attacker
//! has to know CFC specifically and go take the pins out.
//!
//! # Pin layout
//!
//! ```text
//! /sys/fs/bpf/colony-firewall/v1/
//!   connect4        pinned link  - IPv4 enforcement
//!   connect6        pinned link  - IPv6 enforcement
//!   VERDICTS        pinned map   - tgid -> verdict, written by the daemon
//!   ENFORCE_STATS   pinned map   - per-CPU counters
//! ```
//!
//! `v1` is [`cfc_ebpf_common::ABI_VERSION`]. It is in the *path* because an
//! object built against a different event layout is a different program and
//! must not inherit the previous one's pins; putting the version in a file
//! inside a shared directory would mean reading it before knowing whether it
//! can be trusted. Directories for other versions are unpinned on startup,
//! which is what makes an upgrade work: without it the old program would stay
//! attached forever, consulting a map nothing writes to, and the new one would
//! fail to attach with `EEXIST`.
//!
//! Nothing here survives a reboot. bpffs is an in-memory filesystem, so a
//! stale pin from a previous boot is not a case that exists.

use std::io;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use aya::maps::{HashMap as BpfHashMap, MapData, PerCpuArray};
use aya::programs::links::FdLink;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf;
use cfc_ebpf_common::{enforce_stat, ABI_VERSION};
use tracing::{debug, warn};

/// Where the kernel expects a bpffs to be mounted. systemd mounts it here on
/// every system this daemon targets; if it is absent, enforcement is skipped
/// rather than pinned somewhere else, because "somewhere else" would be a
/// directory on a real filesystem where `BPF_OBJ_PIN` fails anyway.
const BPFFS: &str = "/sys/fs/bpf";

/// `BPF_FS_MAGIC` from `include/uapi/linux/magic.h`. Checked because
/// `/sys/fs/bpf` existing as a plain directory - which is what it is before
/// anything mounts over it - is indistinguishable from the real thing by
/// `stat`, and pinning into it would silently do nothing useful.
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

/// One directory for all of CFC's pins, so an operator can see and remove the
/// whole thing in one step. Documented in the README as *the* way to lift
/// enforcement by hand.
const PIN_NAMESPACE: &str = "colony-firewall";

/// ELF symbol names, as with the other programs.
pub(super) const PROG_CONNECT4: &str = "cfc_connect4";
pub(super) const PROG_CONNECT6: &str = "cfc_connect6";

pub(super) const MAP_VERDICTS: &str = "VERDICTS";
pub(super) const MAP_STATS: &str = "ENFORCE_STATS";

/// Per-CPU counters, summed. See [`enforce_stat`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct EnforceStats {
    /// `connect()` calls allowed because the map held an allow.
    pub allowed: u64,
    /// `connect()` calls refused in-kernel, before a packet existed.
    pub denied: u64,
    /// `connect()` calls with no entry, which went on to the packet path.
    pub unknown: u64,
}

/// The directory this build pins into.
pub(super) fn pin_dir() -> PathBuf {
    Path::new(BPFFS)
        .join(PIN_NAMESPACE)
        .join(format!("v{ABI_VERSION}"))
}

/// True when `path` is on a bpffs mount.
fn is_bpffs(path: &Path) -> io::Result<bool> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `buf` is a valid, correctly sized statfs; `c` is NUL-terminated
    // and outlives the call.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut buf) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // `f_type` is already i64 on 64-bit and u32 on 32-bit; the conversion is
    // redundant on the arch clippy is looking at and required on the other.
    #[allow(clippy::useless_conversion)]
    Ok(i64::from(buf.f_type) == BPF_FS_MAGIC)
}

/// Makes sure the pin directory exists on a real bpffs, and removes the pins of
/// any other ABI version.
///
/// Returns `Err` when pinning is not possible at all, which is not fatal to the
/// daemon: the caller records it and attaches without pinning, which still
/// enforces for as long as the process lives.
pub(super) fn prepare() -> anyhow::Result<PathBuf> {
    let root = Path::new(BPFFS);
    if !is_bpffs(root).with_context(|| format!("stat {BPFFS}"))? {
        return Err(anyhow!(
            "{BPFFS} is not a bpffs mount (mount -t bpf bpffs {BPFFS}); \
             enforcement cannot be pinned and will stop when this daemon does"
        ));
    }
    let ns = root.join(PIN_NAMESPACE);
    std::fs::create_dir_all(&ns).with_context(|| format!("creating {}", ns.display()))?;
    unpin_other_versions(&ns);
    let dir = pin_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Removes pins left by an object with a different event ABI.
///
/// Best effort by design: a directory that cannot be cleaned is logged and
/// skipped, because failing here would refuse to start enforcement over a
/// leftover from a version that is no longer running anyway. The visible
/// consequence of a failure is the `EEXIST` from the subsequent attach, which
/// the caller reports with the same detail.
fn unpin_other_versions(namespace: &Path) {
    let mine = format!("v{ABI_VERSION}");
    let entries = match std::fs::read_dir(namespace) {
        Ok(e) => e,
        Err(e) => {
            debug!("cannot list {}: {e}", namespace.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == mine.as_str() {
            continue;
        }
        let path = entry.path();
        // `remove_dir_all` on bpffs unpins every object inside, which drops the
        // kernel's last reference to those links and detaches them.
        match std::fs::remove_dir_all(&path) {
            Ok(()) => warn!(
                "removed BPF pins from a previous event ABI at {}; \
                 its in-kernel enforcement is now detached",
                path.display()
            ),
            Err(e) => warn!(
                "could not remove stale BPF pins at {}: {e}; \
                 in-kernel enforcement may fail to attach",
                path.display()
            ),
        }
    }
}

/// True when both link pins are present, i.e. a previous daemon left
/// enforcement running and this one should steer it rather than replace it.
pub(super) fn already_attached(dir: &Path) -> bool {
    dir.join("connect4").exists() && dir.join("connect6").exists()
}

/// Loads, attaches and pins one `cgroup/connect*` program.
///
/// Returns the verified instruction count when the kernel reports it, matching
/// the other attach helpers.
fn attach_one(
    bpf: &mut Ebpf,
    name: &str,
    cgroup: &std::fs::File,
    pin: Option<&Path>,
) -> anyhow::Result<Option<u32>> {
    let prog: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("no program named `{name}` in the object"))?
        .try_into()
        .with_context(|| format!("`{name}` is not a cgroup_sock_addr program"))?;
    prog.load().context("verifier rejected the program")?;
    let insns = super::loader::verifier_cost(name, prog.info());
    // `Single`, as with the DNS observer: stacking a second copy would double
    // nothing here (the verdicts are idempotent), but it would hide a failed
    // cleanup, and cgroup programs are AND-ed - a leaked copy from an older
    // build would keep voting.
    let id = prog
        .attach(cgroup.as_fd(), CgroupAttachMode::Single)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("attaching {name} to the cgroup v2 root"))?;

    let Some(pin) = pin else {
        return Ok(insns);
    };
    // Taking the link is what stops `Ebpf`'s drop from detaching it. From here
    // the pin owns it: dropping the returned `PinnedLink` closes this process's
    // fd and leaves the kernel reference held by bpffs, which is the entire
    // point of this module.
    let link = prog
        .take_link(id)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("taking the {name} link"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(anyhow::Error::new)
        .with_context(|| format!("{name} link is not fd-based (needs kernel >= 5.7)"))?;
    fd_link
        .pin(pin)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("pinning {name} to {}", pin.display()))?;
    Ok(insns)
}

/// Attaches both connect programs, pinning them under `dir` when it is
/// `Some`.
///
/// `dir` is `None` when [`prepare`] failed: the programs still attach and still
/// enforce, they just stop when this process does. That is strictly better than
/// not attaching, and worse than pinning, so the caller says which happened.
pub(super) fn attach(
    bpf: &mut Ebpf,
    dir: Option<&Path>,
) -> anyhow::Result<Vec<(String, Option<u32>)>> {
    let root = super::cgroup::v2_root()
        .ok_or_else(|| anyhow!("no cgroup2 mount in /proc/mounts (unified hierarchy required)"))?;
    // Read-only, for the same reason as the DNS attach: the kernel wants the
    // cgroup as an attach target, and the unit makes cgroupfs read-only.
    let cgroup = std::fs::File::open(&root)
        .with_context(|| format!("opening cgroup v2 root {}", root.display()))?;

    let mut out = Vec::with_capacity(2);
    for (name, pin_name) in [(PROG_CONNECT4, "connect4"), (PROG_CONNECT6, "connect6")] {
        let pin = dir.map(|d| d.join(pin_name));
        let insns = attach_one(bpf, name, &cgroup, pin.as_deref())?;
        out.push((name.to_string(), insns));
    }
    Ok(out)
}

/// Removes entries for pids that no longer exist.
///
/// Necessary because the exit tracepoint is *not* pinned: while the daemon is
/// down nothing evicts, so a pid recycled in that window would inherit the
/// previous holder's verdict. Sweeping at startup closes it. A stale deny is
/// merely wrong in the safe direction; a stale allow would not be, which is why
/// this runs before the daemon writes anything new.
pub(super) fn sweep(verdicts: &mut BpfHashMap<&mut MapData, u32, u32>) -> usize {
    let stale: Vec<u32> = verdicts
        .keys()
        .flatten()
        .filter(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        .collect();
    let mut removed = 0;
    for pid in stale {
        if verdicts.remove(&pid).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Sums the per-CPU counters.
pub(super) fn stats(map: &PerCpuArray<&MapData, u64>) -> anyhow::Result<EnforceStats> {
    let read = |slot: u32| -> anyhow::Result<u64> {
        Ok(map
            .get(&slot, 0)
            .with_context(|| format!("reading {MAP_STATS}[{slot}]"))?
            .iter()
            .sum())
    };
    Ok(EnforceStats {
        allowed: read(enforce_stat::ALLOWED)?,
        denied: read(enforce_stat::DENIED)?,
        unknown: read(enforce_stat::UNKNOWN)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_directory_carries_the_event_abi_version() {
        let dir = pin_dir();
        assert!(
            dir.ends_with(format!("v{ABI_VERSION}")),
            "an object built against a different event layout must not inherit \
             these pins: {}",
            dir.display()
        );
        assert!(dir.starts_with(BPFFS));
    }

    #[test]
    fn a_plain_directory_is_not_mistaken_for_a_bpffs() {
        // /tmp is a tmpfs or a disk filesystem, never a bpffs. This is the case
        // that matters: `/sys/fs/bpf` exists as an ordinary directory when
        // nothing has mounted over it, and pinning into it would appear to work
        // while pinning nothing.
        assert!(!is_bpffs(Path::new("/tmp")).expect("statfs /tmp"));
    }

    #[test]
    fn a_missing_path_is_an_error_not_a_false_positive() {
        let e = is_bpffs(Path::new("/nonexistent-fbc93a2e")).expect_err("should fail");
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
    }

    /// The claim this whole module exists to make, checked end to end with no
    /// daemon in the picture.
    ///
    /// Sequence: load and attach with pinning, then **drop everything** - the
    /// `Ebpf`, the links, every fd this process holds. That is exactly what
    /// `kill -9` on the daemon does. Then reopen the map from its pin, write a
    /// deny for a child's pid, and watch the child's `connect()` come back
    /// `EPERM`. Nothing that could serve that verdict is alive except the
    /// kernel and bpffs.
    ///
    /// Root, and ignored by default like the other live tests:
    ///
    /// ```text
    /// cargo build -p cfc-daemon --tests
    /// sudo ./target/fast/deps/cfc_daemon-<hash> --ignored --nocapture \
    ///     enforces_a_pinned_deny
    /// ```
    #[tokio::test]
    #[ignore = "needs root and a BPF-capable kernel"]
    async fn enforces_a_pinned_deny_with_no_daemon_alive() {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::process::{Command, Stdio};

        if !nix::unistd::Uid::effective().is_root() {
            eprintln!("skipping: not root");
            return;
        }
        let object = std::env::var("CFC_EBPF_OBJECT")
            .unwrap_or_else(|_| super::super::DEFAULT_OBJECT_PATH.to_string());
        if !Path::new(&object).exists() {
            eprintln!("skipping: no object at {object}");
            return;
        }
        if !Path::new("/bin/bash").exists() {
            eprintln!("skipping: needs bash for /dev/tcp");
            return;
        }

        // A listener that will accept, so "connected" and "refused" are not the
        // same observation. Leaked deliberately: the child needs it alive.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();

        // 1. Bring enforcement up, pinned...
        let (attached, report) = super::super::loader::load_and_attach(
            Path::new(&object),
            crate::dns::DnsCache::new(),
            super::super::proc_table::KernelProcTable::new(),
            super::super::loader::Trust::Warn,
        )
        .expect("load");
        assert_eq!(
            report.enforcement,
            super::super::Enforcement::Pinned,
            "the point of the test is the pin: {:?}",
            report.notes
        );

        // 2. ...and now take the daemon away. Every fd, every link, the whole
        //    aya object. What is left is bpffs and the kernel.
        drop(attached);

        // 3. Reopen the verdict map through its pin alone.
        let pin = pin_dir().join(MAP_VERDICTS);
        let data = MapData::from_pin(&pin).expect("reopen the pinned VERDICTS map");
        let mut verdicts = BpfHashMap::<_, u32, u32>::try_from(aya::maps::Map::HashMap(data))
            .expect("VERDICTS is a hash map");

        // `read` blocks until the test says go, so the pid is known and the
        // verdict is in place before the connect happens. `exec 3<>` connects in
        // this same process rather than a fork, so the pid is the right one.
        let spawn = || {
            Command::new("/bin/bash")
                .arg("-c")
                .arg(format!(
                    "read -r _; \
                     if exec 3<>/dev/tcp/127.0.0.1/{port}; then echo CONNECTED; \
                     else echo REFUSED; fi"
                ))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn bash")
        };
        let go = |child: &mut std::process::Child| -> String {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(b"\n")
                .expect("write");
            let out = child.stdout.take().expect("stdout");
            let line = BufReader::new(out)
                .lines()
                .next()
                .and_then(Result::ok)
                .unwrap_or_default();
            let _ = child.wait();
            line
        };

        // 4. Denied.
        let mut denied = spawn();
        verdicts
            .insert(denied.id(), cfc_ebpf_common::verdict::DENY, 0)
            .expect("insert the deny");
        let refused = go(&mut denied);
        verdicts.remove(&denied.id()).ok();

        // 5. Not denied: same binary, same destination, no entry.
        let mut allowed = spawn();
        let connected = go(&mut allowed);

        assert_eq!(
            refused, "REFUSED",
            "a pid with a pinned deny must not reach {port}, with no daemon running"
        );
        assert_eq!(
            connected, "CONNECTED",
            "a pid with no entry must fall through to the packet path, not be denied"
        );
        println!("pinned deny enforced with no daemon process alive");

        // Leave the machine as we found it. The pins are the durable part, so
        // they have to be removed explicitly - that is the feature.
        drop(listener);
        let _ = std::fs::remove_dir_all(Path::new(BPFFS).join(PIN_NAMESPACE));
    }

    #[test]
    fn already_attached_needs_both_families() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!already_attached(dir.path()));
        std::fs::write(dir.path().join("connect4"), b"").expect("write");
        assert!(
            !already_attached(dir.path()),
            "half a pin is not enforcement; IPv6 would be unfiltered"
        );
        std::fs::write(dir.path().join("connect6"), b"").expect("write");
        assert!(already_attached(dir.path()));
    }
}
