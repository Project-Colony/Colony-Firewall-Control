//! Finding the cgroup v2 (unified) hierarchy root.
//!
//! The `cgroup_skb/ingress` DNS observer attaches to a cgroup, and attaching
//! to the v2 *root* is what makes it system-wide: every task on the machine is
//! in some descendant of it. On a modern systemd host that root is
//! `/sys/fs/cgroup`, but a hybrid or containerised host can put it elsewhere
//! (`/sys/fs/cgroup/unified` under the old hybrid layout), so the path is read
//! out of `/proc/mounts` rather than hard-coded.
//!
//! Nothing here is fatal: a host with no cgroup2 mount simply does not get DNS
//! answer capture, and the daemon says so and carries on.

use std::path::{Path, PathBuf};

/// Where the unified hierarchy lives on a systemd host. Preferred when it is
/// one of the mounts, because a hybrid host lists both it and the v1 mounts.
const PREFERRED: &str = "/sys/fs/cgroup";

/// Locates the cgroup v2 root by reading `/proc/mounts`.
pub fn v2_root() -> Option<PathBuf> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    v2_root_from_mounts(&mounts)
}

/// The pure half of [`v2_root`], so the parsing is testable without a host
/// that happens to be mounted the right way.
///
/// `/proc/mounts` columns are `device mountpoint fstype options dump pass`,
/// with octal escapes (`\040` for a space) in the device and mountpoint
/// fields. Only `cgroup2` rows are considered; `cgroup` (v1) rows cannot
/// carry a `cgroup_skb` program.
pub fn v2_root_from_mounts(mounts: &str) -> Option<PathBuf> {
    let mut first: Option<PathBuf> = None;
    for line in mounts.lines() {
        let mut cols = line.split_whitespace();
        let (Some(_device), Some(mountpoint)) = (cols.next(), cols.next()) else {
            continue;
        };
        if cols.next() != Some("cgroup2") {
            continue;
        }
        let path = PathBuf::from(unescape(mountpoint));
        if path == Path::new(PREFERRED) {
            return Some(path);
        }
        // Keep the first cgroup2 mount as the fallback, but keep scanning in
        // case the preferred one appears further down.
        first.get_or_insert(path);
    }
    first
}

/// Decodes the octal escapes the kernel writes into `/proc/mounts` for
/// characters that would otherwise break the column layout (space, tab,
/// newline, backslash).
fn unescape(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_string();
    }
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &raw[i + 1..i + 4];
            if let Ok(code) = u8::from_str_radix(digits, 8) {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HYBRID: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
";

    const UNIFIED: &str = "\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,size=8144836k,nr_inodes=1048576,inode64 0 0
";

    #[test]
    fn finds_the_unified_root_on_a_modern_host() {
        assert_eq!(
            v2_root_from_mounts(UNIFIED),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
    }

    #[test]
    fn falls_back_to_the_hybrid_location() {
        // /sys/fs/cgroup here is a tmpfs, not cgroup2; the real v2 root is
        // the `unified` subdirectory.
        assert_eq!(
            v2_root_from_mounts(HYBRID),
            Some(PathBuf::from("/sys/fs/cgroup/unified"))
        );
    }

    #[test]
    fn prefers_sys_fs_cgroup_even_when_it_is_not_first() {
        let mounts = "cgroup2 /run/other cgroup2 rw 0 0\ncgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n";
        assert_eq!(
            v2_root_from_mounts(mounts),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
    }

    #[test]
    fn v1_only_host_has_no_v2_root() {
        let mounts = "cgroup /sys/fs/cgroup/systemd cgroup rw,name=systemd 0 0\n";
        assert_eq!(v2_root_from_mounts(mounts), None);
        assert_eq!(v2_root_from_mounts(""), None);
    }

    #[test]
    fn decodes_octal_escapes_in_the_mountpoint() {
        let mounts = "cgroup2 /run/my\\040cgroups cgroup2 rw 0 0\n";
        assert_eq!(
            v2_root_from_mounts(mounts),
            Some(PathBuf::from("/run/my cgroups"))
        );
    }

    #[test]
    fn a_malformed_line_does_not_derail_the_scan() {
        let mounts = "garbage\n\ncgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n";
        assert_eq!(
            v2_root_from_mounts(mounts),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
    }
}
