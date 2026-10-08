//! Is the peer on a control connection the installed Colony Firewall app or
//! tray?
//!
//! Only those two programs (and root) may change the firewall. The daemon
//! cannot ask a process who it is, so it checks what the kernel says about
//! the process holding the connection, in this order:
//!
//! 1. its start time matches the one captured at accept (the "before" read);
//! 2. it runs in the host mount and user namespaces, so no private mount or
//!    user namespace can show it a different `/usr/bin`;
//! 3. it is not traced and its effective uid is the connection's uid;
//! 4. it is non-dumpable, which is the mark `seal_official_process` leaves:
//!    the kernel hands the files under `/proc/<pid>` to root exactly then;
//! 5. its image is, by device and inode, one of the allowlisted binaries,
//!    and that binary is root-owned, not group/other-writable, in root-owned
//!    directories nobody else can write (re-checked on every call, so an
//!    upgraded binary counts and the old, deleted image does not);
//! 6. it holds the client end of *this* connection itself, on a descriptor
//!    above stderr (the prologue closed every inherited one);
//! 7. every executable file mapping comes from a sealed path, which refuses
//!    an `LD_PRELOAD` or `LD_AUDIT` library loaded from the user's files;
//! 8. its start time still matches (the "after" read), so none of the above
//!    was read from a process that replaced it under the same pid.
//!
//! Steps 4 and 6 close the exec-after-connect route: connect, write a whole
//! request, then exec the official binary with the socket inherited. That
//! process has not run the prologue yet, or has closed the inherited
//! connection by the time it is sealed.
//!
//! What it cannot see: code already running inside the official image that
//! moved itself into anonymous memory (anonymous executable mappings are
//! not judged, GPU drivers JIT into them), and synthetic input to the GUI
//! under X11. See docs/HARDENING.md.

use crate::ipc::PeerId;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Packaged default for `[ipc] official_clients`: the installed GUI and tray.
pub const DEFAULT_CLIENTS: [&str; 2] =
    ["/usr/bin/colony-firewall", "/usr/bin/colony-firewall-tray"];

/// Checks `peer` against `allowlist`. Blocking (reads `/proc` and asks
/// sock_diag): call it from `spawn_blocking`. `Ok` carries the matched
/// allowlist entry; `Err` a reason fit to show the user.
pub fn check(peer: &PeerId, allowlist: &[PathBuf]) -> Result<PathBuf, String> {
    let pid = peer
        .pid
        .filter(|pid| *pid > 0)
        .ok_or("the caller's process id is unknown")? as u32;
    let (Some(start), Some(sock_ino)) = (peer.starttime, peer.sock_ino) else {
        return Err("the caller's process could not be identified".into());
    };
    bracketed(pid, start, crate::process_resolve::read_starttime, || {
        inspect(pid, peer.uid, sock_ino, allowlist)
    })
}

/// Runs `body` between two start-time reads that must both match `expected`.
fn bracketed<T>(
    pid: u32,
    expected: u64,
    read: impl Fn(u32) -> Option<u64>,
    body: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    const GONE: &str = "the caller exited, or its process id now names another process";
    if read(pid) != Some(expected) {
        return Err(GONE.into());
    }
    let outcome = body()?;
    if read(pid) != Some(expected) {
        return Err(GONE.into());
    }
    Ok(outcome)
}

fn inspect(pid: u32, uid: u32, sock_ino: u64, allowlist: &[PathBuf]) -> Result<PathBuf, String> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    for ns in ["mnt", "user"] {
        let theirs = std::fs::read_link(proc.join("ns").join(ns));
        let host = std::fs::read_link(Path::new("/proc/1/ns").join(ns));
        match (theirs, host) {
            (Ok(theirs), Ok(host)) if theirs == host => {}
            _ => return Err(format!("the caller runs in a private {ns} namespace")),
        }
    }
    let status = std::fs::read_to_string(proc.join("status"))
        .map_err(|e| format!("the caller's status is unreadable ({e})"))?;
    status_is_clean(&status, uid)?;
    // The kernel gives a non-dumpable process's /proc files to root (the
    // directory itself keeps the owner's uid, so a file inside is asked).
    let owner = std::fs::metadata(proc.join("status"))
        .map_err(|e| format!("the caller's /proc entry is unreadable ({e})"))?
        .uid();
    if owner != 0 {
        return Err(
            "the caller did not seal itself at startup (an old or modified build; \
             restart the app after an upgrade)"
                .into(),
        );
    }
    let matched = image_matches(&proc, allowlist)?;
    holds_connection(&proc, sock_ino)?;
    maps_are_sealed(
        &std::fs::read_to_string(proc.join("maps"))
            .map_err(|e| format!("the caller's memory map is unreadable ({e})"))?,
    )?;
    Ok(matched)
}

/// `TracerPid` is 0 and the effective uid is `uid`.
fn status_is_clean(status: &str, uid: u32) -> Result<(), String> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::split_whitespace)
    };
    let tracer = field("TracerPid:").and_then(|mut v| v.next()?.parse::<u32>().ok());
    match tracer {
        Some(0) => {}
        Some(_) => return Err("the caller is being traced".into()),
        None => return Err("the caller's status has no TracerPid".into()),
    }
    let effective = field("Uid:").and_then(|mut v| v.nth(1)?.parse::<u32>().ok());
    if effective != Some(uid) {
        return Err("the caller's effective uid is not the connection's uid".into());
    }
    Ok(())
}

/// The running image is one of the sealed allowlist entries, by dev/ino.
fn image_matches(proc: &Path, allowlist: &[PathBuf]) -> Result<PathBuf, String> {
    // stat follows the magic link to the mapped inode, even a deleted one.
    let image = std::fs::metadata(proc.join("exe"))
        .map_err(|e| format!("the caller's executable is unreadable ({e})"))?;
    let key = (image.dev(), image.ino());
    if let Some(entry) = allowlist
        .iter()
        .find(|entry| sealed_identity(entry) == Some(key))
    {
        return Ok(entry.clone());
    }
    let shown = std::fs::read_link(proc.join("exe")).unwrap_or_default();
    let name = shown
        .to_string_lossy()
        .trim_end_matches(crate::process_resolve::DELETED_SUFFIX)
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();
    Err(
        match allowlist.iter().find(|entry| {
            entry
                .file_name()
                .is_some_and(|f| f.to_string_lossy() == name)
        }) {
            Some(entry) => format!(
                "this {name} is not the installed {} (restart it after an upgrade)",
                entry.display()
            ),
            None => format!(
                "{} is not an installed Colony Firewall app or tray",
                shown.display()
            ),
        },
    )
}

/// `(dev, ino)` of `path` when it and every ancestor pass the sealed test:
/// a regular file (directories for the ancestors) owned by root and not
/// writable by group or other. No sticky-directory exception: the files the
/// daemon trusts here live in root-owned directories nobody else can write.
pub fn sealed_identity(path: &Path) -> Option<(u64, u64)> {
    use cfc_core::exe_path::file_is_sealed;
    if !path.is_absolute() {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || !file_is_sealed(meta.uid(), meta.mode()) {
        return None;
    }
    for dir in path.ancestors().skip(1) {
        let m = std::fs::symlink_metadata(dir).ok()?;
        if !m.is_dir() || !file_is_sealed(m.uid(), m.mode()) {
            return None;
        }
    }
    Some((meta.dev(), meta.ino()))
}

fn sealed_dir(path: &Path) -> bool {
    use cfc_core::exe_path::file_is_sealed;
    path.ancestors().all(|dir| {
        std::fs::symlink_metadata(dir)
            .is_ok_and(|m| m.is_dir() && file_is_sealed(m.uid(), m.mode()))
    })
}

/// The process holds the client end of the daemon's connection `sock_ino`
/// on a descriptor of its own above stderr.
fn holds_connection(proc: &Path, sock_ino: u64) -> Result<(), String> {
    let peer = crate::sock_diag::unix_peer_inode(sock_ino)
        .map_err(|e| format!("the connection's client end is unknown (unix_diag: {e})"))?;
    let wanted = format!("socket:[{peer}]");
    let fds = std::fs::read_dir(proc.join("fd"))
        .map_err(|e| format!("the caller's descriptors are unreadable ({e})"))?;
    let held = fds.filter_map(Result::ok).any(|entry| {
        entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| n >= 3)
            && std::fs::read_link(entry.path())
                .is_ok_and(|target| target.as_os_str() == wanted.as_str())
    });
    if held {
        Ok(())
    } else {
        Err("the connection is not held by the caller itself".into())
    }
}

/// Every executable file mapping comes from a sealed file.
///
/// A live path must be sealed and be the mapped inode. The device is not
/// compared: on btrfs `stat` reports the subvolume's device while the maps
/// line carries the superblock's, so they differ for every file. A deleted
/// path (a library an upgrade replaced while the app ran) must have a sealed
/// parent directory other than `/`: only root can have created a file there.
/// `/` is excluded because memfd and SysV shared memory show up as
/// `/memfd:…` and `/SYSV…` "(deleted)". Anonymous mappings are not judged:
/// GPU drivers JIT into them.
fn maps_are_sealed(maps: &str) -> Result<(), String> {
    let mut seen: HashMap<&str, bool> = HashMap::new();
    for line in maps.lines() {
        let mut fields = line.splitn(6, ' ');
        let (Some(_), Some(perms), Some(_), Some(_), Some(inode)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let path = fields.next().unwrap_or_default().trim_start();
        if !perms.contains('x') || !path.starts_with('/') {
            continue;
        }
        let ok = *seen.entry(path).or_insert_with(|| {
            match path.strip_suffix(crate::process_resolve::DELETED_SUFFIX) {
                Some(gone) => Path::new(gone)
                    .parent()
                    .is_some_and(|dir| dir != Path::new("/") && sealed_dir(dir)),
                None => inode.parse::<u64>().is_ok_and(|inode| {
                    sealed_identity(Path::new(path)).is_some_and(|(_, ino)| ino == inode)
                }),
            }
        });
        if !ok {
            return Err(format!("the caller loaded {path}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::process::{Child, Command};

    fn sealed(path: &str) -> bool {
        sealed_identity(Path::new(path)).is_some()
    }

    struct Reaped(Child);
    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn(program: &Path) -> Reaped {
        // A freshly copied binary can be briefly "busy": another test thread
        // forked while its write descriptor was open.
        let mut attempt = 0;
        let child = loop {
            match Command::new(program).arg("30").spawn() {
                Ok(child) => break Reaped(child),
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 100 => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("spawning {}: {e}", program.display()),
            }
        };
        // Wait for the exec to land, so /proc/<pid>/exe is the new image.
        let exe = PathBuf::from(format!("/proc/{}/exe", child.0.id()));
        for _ in 0..200 {
            if std::fs::read_link(&exe).is_ok_and(|p| p.ends_with(program.file_name().unwrap())) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        child
    }

    #[test]
    fn strict_sealed_rejects_sticky_and_group_writable_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tool");
        std::fs::write(&file, b"x").unwrap();
        assert!(!sealed(file.to_str().unwrap()), "user-owned");
        assert!(!sealed("relative/path"));
        assert!(!sealed("/tmp"), "a directory is not an image");
        // /tmp is sticky and world-writable: root-owned, still not sealed.
        assert!(!sealed_dir(Path::new("/tmp")));
        if sealed("/usr/bin/env") {
            assert!(sealed_dir(Path::new("/usr/bin")));
        } else {
            eprintln!("skipped: /usr/bin/env is not root-sealed here");
        }
    }

    #[test]
    fn an_installed_image_matches_by_dev_and_ino() {
        let sleep = Path::new("/usr/bin/sleep");
        if !sealed("/usr/bin/sleep") {
            eprintln!("skipped: /usr/bin/sleep is not root-sealed here");
            return;
        }
        let child = spawn(sleep);
        let proc = PathBuf::from(format!("/proc/{}", child.0.id()));
        assert_eq!(image_matches(&proc, &[sleep.into()]).unwrap(), sleep);

        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("sleep");
        std::fs::copy(sleep, &copy).unwrap();
        let copied = spawn(&copy);
        let proc = PathBuf::from(format!("/proc/{}", copied.0.id()));
        let error = image_matches(&proc, &[sleep.into()]).unwrap_err();
        assert!(
            error.contains("not the installed /usr/bin/sleep"),
            "{error}"
        );
    }

    #[test]
    fn a_deleted_image_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("sleep");
        if std::fs::copy("/usr/bin/sleep", &copy).is_err() {
            eprintln!("skipped: no /usr/bin/sleep");
            return;
        }
        let child = spawn(&copy);
        std::fs::remove_file(&copy).unwrap();
        let proc = PathBuf::from(format!("/proc/{}", child.0.id()));
        let error = image_matches(&proc, &["/usr/bin/sleep".into()]).unwrap_err();
        assert!(error.contains("restart"), "{error}");
    }

    #[test]
    fn tracer_pid_parsing() {
        let clean = "Name:\tx\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n";
        assert!(status_is_clean(clean, 1000).is_ok());
        let traced = clean.replace("TracerPid:\t0", "TracerPid:\t4242");
        assert_eq!(
            status_is_clean(&traced, 1000).unwrap_err(),
            "the caller is being traced"
        );
        assert!(status_is_clean("Uid:\t1000\t1000\t1000\t1000\n", 1000).is_err());
    }

    #[test]
    fn uid_mismatch_in_status_is_refused() {
        // Real uid 1000, effective uid 1001: the effective one decides.
        let status = "TracerPid:\t0\nUid:\t1000\t1001\t1000\t1000\n";
        assert!(status_is_clean(status, 1000).is_err());
        assert!(status_is_clean(status, 1001).is_ok());
    }

    #[test]
    fn non_dumpable_is_detected_from_proc_ownership() {
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipped: every /proc entry is root's when the tests run as root");
            return;
        }
        let owner = |pid: i32| {
            std::fs::metadata(format!("/proc/{pid}/status"))
                .unwrap()
                .uid()
        };
        // SAFETY: the child only makes raw syscalls and never returns.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                loop {
                    libc::pause();
                }
            }
        }
        let plain = spawn(Path::new("/usr/bin/sleep"));
        let mut sealed_owner = owner(child);
        for _ in 0..200 {
            if sealed_owner == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            sealed_owner = owner(child);
        }
        let plain_owner = owner(plain.0.id() as i32);
        // SAFETY: killing and reaping our own child.
        unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        assert_eq!(
            sealed_owner, 0,
            "a non-dumpable process's /proc files are root's"
        );
        assert_ne!(plain_owner, 0);
    }

    #[test]
    fn a_socket_held_only_on_stdio_does_not_count() {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let inode = |fd: i32| {
            // SAFETY: zeroed stat is valid out-param storage; fd is open.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
            st.st_ino
        };
        use std::os::fd::AsRawFd;
        if crate::sock_diag::unix_peer_inode(inode(ours.as_raw_fd())).is_err() {
            eprintln!("skipped: unix_diag unavailable here");
            return;
        }
        // This process holds `theirs` above stderr: it counts.
        assert!(holds_connection(Path::new("/proc/self"), inode(ours.as_raw_fd())).is_ok());
        // A child holding it only on stdout does not.
        let child = Reaped(
            Command::new("/usr/bin/sleep")
                .arg("30")
                .stdout(std::process::Stdio::from(std::os::fd::OwnedFd::from(
                    theirs,
                )))
                .spawn()
                .unwrap(),
        );
        let proc = PathBuf::from(format!("/proc/{}", child.0.id()));
        // Its fds are inspected by the test as the same user; the socket is
        // still ours, so ask about our end.
        let error = holds_connection(&proc, inode(ours.as_raw_fd())).unwrap_err();
        assert!(error.contains("not held"), "{error}");
    }

    #[test]
    fn maps_check_accepts_sealed_libraries_and_refuses_user_files() {
        if !sealed("/usr/bin/sleep") {
            eprintln!("skipped: /usr/bin/sleep is not root-sealed here");
            return;
        }
        let child = spawn(Path::new("/usr/bin/sleep"));
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", child.0.id())).unwrap();
        assert_eq!(maps_are_sealed(&maps), Ok(()));

        let own = std::env::current_exe().unwrap();
        if sealed(own.to_str().unwrap()) {
            eprintln!("skipped: the test binary itself is root-sealed");
        } else {
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            let error = maps_are_sealed(&maps).unwrap_err();
            assert!(error.starts_with("the caller loaded /"), "{error}");
        }

        // Synthetic lines: memfd and SysV mappings are refused, an anonymous
        // one is not judged, a library an upgrade replaced is accepted.
        let line = |path: &str| format!("7f00-7f01 r-xp 00000000 00:1c 99 {path}\n");
        assert!(maps_are_sealed(&line("/memfd:payload (deleted)")).is_err());
        assert!(maps_are_sealed(&line("/SYSV00000000 (deleted)")).is_err());
        assert!(maps_are_sealed("7f00-7f01 r-xp 00000000 00:00 0 \n").is_ok());
        if sealed_dir(Path::new("/usr/lib")) {
            assert!(maps_are_sealed(&line("/usr/lib/libgone.so.1 (deleted)")).is_ok());
        }
        assert!(maps_are_sealed(&line("/home/u/libgone.so.1 (deleted)")).is_err());
        assert!(
            maps_are_sealed("7f00-7f01 r--p 00000000 00:1c 99 /home/u/x.so\n").is_ok(),
            "not executable"
        );
    }

    #[test]
    fn starttime_changed_between_reads_is_refused() {
        let reads = Cell::new(0);
        let changing = |_| {
            reads.set(reads.get() + 1);
            Some(if reads.get() == 1 { 100 } else { 101 })
        };
        let error = bracketed(1, 100, changing, || Ok(())).unwrap_err();
        assert!(error.contains("another process"), "{error}");
        assert!(bracketed(
            1,
            100,
            |_| Some(99),
            || -> Result<(), String> { panic!("the body must not run after a failed first read") }
        )
        .is_err());
        assert_eq!(bracketed(1, 100, |_| Some(100), || Ok(7)), Ok(7));
    }
}
