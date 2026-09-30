//! Explicit application-tree confinement, independent of per-executable rules.

#[cfg(target_arch = "x86_64")]
mod filter;
#[cfg(target_arch = "x86_64")]
mod native;

use crate::{output::OutputFormat, ApplicationsCmd};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
#[cfg(target_arch = "x86_64")]
use std::os::{fd::AsRawFd, unix::process::CommandExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const CONTROL: &str = "/run/colony-firewall-apps";
const UNITS: &str = "/run/systemd/system";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    id: String,
    runtime: PathBuf,
    allow: Vec<IpAddr>,
    command: Vec<String>,
}

fn unit(id: &str) -> String {
    format!("cfc-app-{id}.service")
}
fn user(id: &str) -> String {
    format!("cfc_{}", &id[..27])
}
fn directory(id: &str) -> PathBuf {
    Path::new(CONTROL).join(id)
}

fn root() -> Result<()> {
    // This interface creates system services; it is never a setuid helper.
    ensure!(
        unsafe { libc::getuid() == 0 && libc::geteuid() == 0 },
        "application confinement requires an administrator (sudo)"
    );
    ensure!(
        cfg!(target_arch = "x86_64"),
        "application confinement is currently verified only on x86_64"
    );
    Ok(())
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn payload_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .skip(1)
                .all(|c| matches!(c, Component::Normal(_))),
        "application command must be an absolute path without aliases"
    );
    ensure!(
        path.components().count() > 1,
        "application command cannot name the root directory"
    );
    for reserved in ["/dev", "/proc", "/sys", "/tmp", "/run", "/home"] {
        ensure!(
            !path.starts_with(reserved),
            "application command cannot use a private API path"
        );
    }
    Ok(())
}

fn runtime_kind(uid: u32, mode: u32, directory: bool) -> bool {
    uid == 0
        && mode & 0o022 == 0
        && mode & libc::S_IFMT
            == if directory {
                libc::S_IFDIR
            } else {
                libc::S_IFREG
            }
}

fn sealed_directory(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        ensure!(
            meta.is_dir() && cfc_core::exe_path::dir_is_sealed(meta.uid(), meta.mode()),
            "unsealed control directory: {}",
            ancestor.display()
        );
    }
    Ok(())
}

fn trusted_binary(path: &Path) -> Result<PathBuf> {
    let resolved = fs::canonicalize(path)?;
    ensure!(
        cfc_core::exe_path::is_root_sealed(&resolved)?,
        "trusted launcher must be root-owned and sealed: {}",
        resolved.display()
    );
    Ok(resolved)
}

fn runtime_mounts(runtime: &Path, mounts: &str) -> Result<()> {
    let mut covered = false;
    for line in mounts.lines() {
        let (before, after) = line
            .split_once(" - ")
            .context("invalid mount information")?;
        let field = before
            .split_whitespace()
            .nth(4)
            .context("invalid mount information")?;
        let mount = PathBuf::from(
            field
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\"),
        );
        ensure!(
            mount == runtime || !mount.starts_with(runtime),
            "runtime cannot contain nested mounts"
        );
        if runtime.starts_with(&mount) {
            covered = true;
            let kind = after
                .split_whitespace()
                .next()
                .context("missing filesystem type")?;
            ensure!(
                matches!(
                    kind,
                    "ext2"
                        | "ext3"
                        | "ext4"
                        | "xfs"
                        | "btrfs"
                        | "f2fs"
                        | "tmpfs"
                        | "ramfs"
                        | "rootfs"
                        | "squashfs"
                        | "erofs"
                ),
                "runtime requires a supported local filesystem; found {kind} at {}",
                mount.display()
            );
        }
    }
    ensure!(covered, "runtime filesystem could not be verified");
    Ok(())
}

fn check_runtime(runtime: &Path, command: &[String]) -> Result<()> {
    ensure!(!command.is_empty(), "an application command is required");
    payload_path(Path::new(&command[0]))?;
    ensure!(runtime.is_absolute(), "runtime must be absolute");
    runtime_mounts(runtime, &fs::read_to_string("/proc/self/mountinfo")?)?;
    ensure!(
        fs::canonicalize(runtime)? == runtime,
        "runtime must name its absolute canonical directory"
    );
    sealed_directory(runtime)?;
    let mut pending = vec![runtime.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            runtime_kind(meta.uid(), meta.mode(), meta.is_dir()),
            "runtime must contain only sealed root-owned directories and regular files: {}",
            path.display()
        );
        if meta.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        }
    }
    for name in ["dev", "proc", "sys", "tmp", "run", "home"] {
        let path = runtime.join(name);
        ensure!(
            fs::symlink_metadata(&path)?.is_dir() && fs::read_dir(&path)?.next().is_none(),
            "runtime /{name} must be an empty directory"
        );
    }
    let executable = runtime.join(command[0].trim_start_matches('/'));
    let meta = fs::symlink_metadata(executable)?;
    ensure!(
        meta.is_file() && meta.mode() & 0o111 != 0,
        "runtime application must be an executable regular file"
    );
    Ok(())
}

fn manager(args: &[&str]) -> Result<String> {
    let result = Command::new("/usr/bin/systemctl")
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .output()
        .context("calling systemd")?;
    ensure!(
        result.status.success(),
        "systemd rejected the application operation: {}",
        crate::output::terminal_safe(&String::from_utf8_lossy(&result.stderr))
    );
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn unit_text(manifest: &Manifest, launcher: &Path) -> Result<String> {
    let launcher = launcher.to_str().context("launcher path must be UTF-8")?;
    ensure!(
        !launcher.contains(['\n', '\r', '\0']),
        "invalid launcher path"
    );
    let launcher = launcher
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    let peers = manifest
        .allow
        .iter()
        .map(|ip| format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!("[Unit]\nDescription=CFC confined application\n[Service]\nType=exec\nSlice=system.slice\nDynamicUser=yes\nUser={}\nExecStart=+:\"{}\" __cfc_application_gate {}\nIPAddressDeny=any\nIPAddressAllow={}\nIPAccounting=no\nRestrictNetworkInterfaces=~lo\nDelegate=no\nStandardInput=null\nStandardOutput=null\nStandardError=null\nKillMode=control-group\nTimeoutStopSec=5s\nNoNewPrivileges=yes\nRestart=no\nFileDescriptorStoreMax=0\nNotifyAccess=none\nUMask=0077\n", user(&manifest.id), launcher, manifest.id, peers))
}

#[cfg(target_arch = "x86_64")]
fn read_manifest(id: &str) -> Result<Manifest> {
    ensure!(valid_id(id), "invalid application identity");
    let path = directory(id).join("manifest.json");
    ensure!(
        cfc_core::exe_path::is_root_sealed(&path)?,
        "application manifest is not sealed"
    );
    let metadata = fs::metadata(&path)?;
    ensure!(
        metadata.len() <= 1_048_576,
        "application manifest is too large"
    );
    let manifest: Manifest = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        manifest.id == id,
        "application identity differs from its manifest"
    );
    Ok(manifest)
}

fn remove_if_present(path: &Path, directory: bool) -> Result<()> {
    let result = if directory {
        fs::remove_dir(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn cleanup_files(id: &str) -> Result<()> {
    remove_if_present(&Path::new(UNITS).join(unit(id)), false)?;
    remove_if_present(&directory(id).join("manifest.json"), false)?;
    remove_if_present(&directory(id), true)
}

fn stop(id: &str) -> Result<()> {
    ensure!(valid_id(id), "invalid application identity");
    let unit_path = Path::new(UNITS).join(unit(id));
    let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(unit(id));
    // A second administrator may already have stopped and removed this tree.
    let removed = || -> Result<bool> {
        Ok(!unit_path.try_exists()? && !cgroup.try_exists()? && !directory(id).try_exists()?)
    };
    if removed()? {
        return Ok(());
    }
    if let Err(error) = manager(&["stop", &unit(id)]) {
        if removed()? {
            return Ok(());
        }
        return Err(error);
    }
    if cgroup.try_exists()? {
        let events = fs::read_to_string(cgroup.join("cgroup.events"))?;
        ensure!(
            events.lines().any(|line| line == "populated 0"),
            "application tree is still populated; identity retained"
        );
    }
    cleanup_files(id)?;
    manager(&["daemon-reload"])?;
    Ok(())
}

pub(super) async fn run(command: ApplicationsCmd, format: OutputFormat) -> Result<()> {
    root()?;
    trusted_binary(Path::new("/usr/bin/systemctl"))?;
    match command {
        ApplicationsCmd::Stop { id } => {
            stop(&id)?;
        }
        ApplicationsCmd::Run {
            runtime,
            mut allow,
            command,
        } => {
            check_runtime(&runtime, &command)?;
            trusted_binary(Path::new("/usr/bin/bwrap"))?;
            trusted_binary(Path::new("/usr/bin/busctl"))?;
            allow.sort();
            allow.dedup();
            ensure!(
                allow.len() <= 64,
                "at most 64 exact peer addresses are supported"
            );
            ensure!(
                allow
                    .iter()
                    .all(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()),
                "peer addresses must be unicast and non-loopback"
            );
            let launcher = trusted_binary(&std::env::current_exe()?)?;
            fs::create_dir_all(CONTROL)?;
            sealed_directory(Path::new(CONTROL))?;
            sealed_directory(Path::new(UNITS))?;
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let manifest = Manifest {
                id: uuid::Uuid::new_v4().simple().to_string(),
                runtime,
                allow,
                command,
            };
            fs::DirBuilder::new()
                .mode(0o700)
                .create(directory(&manifest.id))?;
            let provisioned = (|| -> Result<()> {
                write_new(
                    &directory(&manifest.id).join("manifest.json"),
                    &serde_json::to_vec(&manifest)?,
                )?;
                write_new(
                    &Path::new(UNITS).join(unit(&manifest.id)),
                    unit_text(&manifest, &launcher)?.as_bytes(),
                )
            })();
            if let Err(error) = provisioned {
                let cleanup = cleanup_files(&manifest.id);
                return Err(error.context(format!(
                    "application preparation failed; cleanup: {cleanup:?}"
                )));
            }
            let application = unit(&manifest.id);
            let started =
                manager(&["daemon-reload"]).and_then(|_| manager(&["start", &application]));
            if let Err(error) = started {
                let cleanup = stop(&manifest.id);
                return Err(
                    error.context(format!("application setup failed; cleanup: {cleanup:?}"))
                );
            }
            if matches!(format, OutputFormat::Human) {
                eprintln!("Confined application: {}", manifest.id);
            }
            let outcome = async {
                let completed = loop {
                    if !directory(&manifest.id).exists() {
                        break false;
                    }
                    let state =
                        match manager(&["show", "--value", "--property=ActiveState", &application])
                        {
                            Ok(state) => state,
                            Err(_) if !directory(&manifest.id).exists() => break false,
                            Err(error) => return Err(error),
                        };
                    if state == "inactive" || state == "failed" {
                        break true;
                    }
                    ensure!(
                        state == "active" || state == "activating" || state == "deactivating",
                        "unexpected application state: {state}"
                    );
                    tokio::select! {
                        result = tokio::signal::ctrl_c() => { result?; break false; },
                        _ = terminate.recv() => break false,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {},
                    }
                };
                let status = if directory(&manifest.id).exists() {
                    match manager(&["show", "--value", "--property=ExecMainStatus", &application]) {
                        Ok(status) => status,
                        Err(_) if !directory(&manifest.id).exists() => String::from("0"),
                        Err(error) => return Err(error),
                    }
                } else {
                    String::from("0")
                };
                Ok::<_, anyhow::Error>((completed, status))
            }
            .await;
            let cleanup = stop(&manifest.id);
            let (completed, status) = outcome.map_err(|error| {
                error.context(format!(
                    "application observation failed; cleanup: {cleanup:?}"
                ))
            })?;
            cleanup?;
            if matches!(format, OutputFormat::Json) {
                println!(
                    "{}",
                    serde_json::json!({"id": manifest.id, "completed": completed, "application_status": status})
                );
            }
            ensure!(
                !completed || status == "0",
                "confined application failed with status {status}"
            );
        }
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn drop_privileges(uid: u32, gid: u32) -> Result<()> {
    // Everything after this point is confined to one reserved, non-root identity.
    unsafe {
        ensure!(
            libc::setgroups(0, std::ptr::null()) == 0,
            "cannot clear supplementary groups"
        );
        for capability in 0..64 {
            let rc = libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0);
            ensure!(
                rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL),
                "cannot drop capability bounding set"
            );
        }
        ensure!(
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0
            ) == 0,
            "cannot clear ambient capabilities"
        );
        ensure!(
            libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) == 0,
            "cannot disable retained capabilities"
        );
        ensure!(
            libc::setresgid(gid, gid, gid) == 0 && libc::setresuid(uid, uid, uid) == 0,
            "cannot drop application credentials"
        );
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Default)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let header = CapHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        let caps = [CapData::default(), CapData::default()];
        ensure!(
            libc::syscall(libc::SYS_capset, &header as *const CapHeader, caps.as_ptr()) == 0,
            "cannot clear application capabilities"
        );
        ensure!(
            libc::getuid() == uid
                && libc::geteuid() == uid
                && libc::getgid() == gid
                && libc::getegid() == gid,
            "application credential drop did not take effect"
        );
        ensure!(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
            "cannot require NoNewPrivileges"
        );
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let line = status
            .lines()
            .find(|line| line.starts_with(&format!("{field}:")))
            .context("missing capability attestation")?;
        ensure!(
            line.split_whitespace().nth(1) == Some("0000000000000000"),
            "application retained {field} capabilities"
        );
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub(super) fn gate(id: &str) -> Result<()> {
    root()?;
    let manifest = read_manifest(id)?;
    check_runtime(&manifest.runtime, &manifest.command)?;
    let bwrap = trusted_binary(Path::new("/usr/bin/bwrap"))?;
    let (uid, gid) = native::verify(&unit(id), &user(id), &manifest.allow)?;
    #[cfg(target_arch = "x86_64")]
    {
        let seccomp = filter::sealed_filter()?;
        drop_privileges(uid, gid)?;
        let mut launch = Command::new(bwrap);
        launch
            .env_clear()
            .args([
                "--unshare-user",
                "--unshare-pid",
                // Keep setup helpers outside the payload's PID view, including before seccomp.
                "--as-pid-1",
                "--unshare-ipc",
                "--unshare-uts",
                "--unshare-cgroup",
                "--disable-userns",
                "--assert-userns-disabled",
                "--uid",
                "65534",
                "--gid",
                "65534",
                "--cap-drop",
                "ALL",
                "--new-session",
                "--die-with-parent",
                "--clearenv",
                "--setenv",
                "HOME",
                "/home/cfc",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--chdir",
                "/home/cfc",
                "--ro-bind",
            ])
            .arg(&manifest.runtime)
            .arg("/")
            .args([
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/home",
                "--dir",
                "/home/cfc",
                "--seccomp",
                "3",
                "--",
            ])
            .args(&manifest.command)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let fd = seccomp.as_raw_fd();
        // pre_exec uses only async-signal-safe syscalls, and the gate has no runtime threads.
        unsafe {
            launch.pre_exec(move || {
                if fd != 3 && libc::dup2(fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let error = launch.exec();
        bail!("mandatory application isolation failed: {error}");
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn gate(_id: &str) -> Result<()> {
    bail!("application confinement currently requires x86_64 Linux")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_identity_and_payload_paths_do_not_accept_aliases() {
        assert!(valid_id("72b662e5725e462da9f337736024f921"));
        for id in [
            "",
            "../other",
            "72b662e5-725e-462d-a9f3-37736024f921",
            "72B662E5725E462DA9F337736024F921",
        ] {
            assert!(!valid_id(id), "{id}");
        }
        assert!(payload_path(Path::new("/usr/bin/tool")).is_ok());
        for path in ["tool", "/usr/../bin/tool", "/", "/proc/self/exe"] {
            assert!(payload_path(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn runtime_requires_regular_root_sealed_content() {
        assert!(runtime_kind(0, 0o100755, false));
        assert!(runtime_kind(0, 0o040755, true));
        for (uid, mode, directory) in [
            (1000, 0o100755, false),
            (0, 0o100775, false),
            (0, 0o140644, false),
            (0, 0o010644, false),
            (0, 0o120777, false),
            (0, 0o041777, true),
        ] {
            assert!(!runtime_kind(uid, mode, directory));
        }
    }

    #[test]
    fn unit_permissions_start_empty_and_escape_the_trusted_launcher() {
        let mut manifest = Manifest {
            id: String::from("72b662e5725e462da9f337736024f921"),
            runtime: PathBuf::from("/sealed/runtime"),
            allow: vec![],
            command: vec![String::from("/app/program")],
        };
        let text = unit_text(&manifest, Path::new("/usr/bin/cfc%$name")).unwrap();
        assert!(text.contains("\nIPAddressDeny=any\nIPAddressAllow=\n"));
        assert!(text.contains("\nRestrictNetworkInterfaces=~lo\n"));
        assert!(text.contains("ExecStart=+:\"/usr/bin/cfc%%$name\" __cfc_application_gate "));
        manifest.allow = vec![
            "203.0.113.7".parse().unwrap(),
            "2001:db8::7".parse().unwrap(),
        ];
        let text = unit_text(&manifest, Path::new("/usr/bin/cfc")).unwrap();
        assert!(text.contains("IPAddressAllow=203.0.113.7/32 2001:db8::7/128\n"));
        assert!(unit_text(&manifest, Path::new("/usr/bin/cfc\nExecStart=/other")).is_err());
    }

    #[test]
    fn runtime_rejects_filesystem_brokers_at_the_root_or_covering_ancestors() {
        let root = "1 0 0:1 / / rw - ext4 /dev/root rw\n";
        let runtime = Path::new("/sealed/runtime");
        assert!(runtime_mounts(runtime, root).is_ok());
        for kind in [
            "fuse",
            "fuse.sshfs",
            "fuseblk",
            "nfs",
            "cifs",
            "overlay",
            "unknown",
        ] {
            for mount in ["/sealed", "/sealed/runtime"] {
                let mounts = format!("{root}2 1 0:2 / {mount} rw - {kind} source rw\n");
                assert!(
                    runtime_mounts(runtime, &mounts).is_err(),
                    "{kind} at {mount}"
                );
            }
        }
        let nested = format!("{root}2 1 0:2 / /sealed/runtime/nested rw - tmpfs tmpfs rw\n");
        assert!(runtime_mounts(runtime, &nested).is_err());
        let unrelated = format!("{root}2 1 0:2 / /elsewhere rw - fuse.sshfs source rw\n");
        assert!(runtime_mounts(runtime, &unrelated).is_ok());
        let escaped = format!("{root}2 1 0:2 / /sealed\\040runtime rw - fuse.sshfs source rw\n");
        assert!(runtime_mounts(Path::new("/sealed runtime/app"), &escaped).is_err());
        assert!(runtime_mounts(runtime, "").is_err());
        assert!(runtime_mounts(runtime, "malformed").is_err());
    }
}
