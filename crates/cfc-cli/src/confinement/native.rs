//! Attest the native systemd cgroup filters before releasing the application.

use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

fn data<'a>(value: &'a Value, signature: &str) -> Result<&'a Value> {
    let object = value.as_object().context("malformed systemd reply")?;
    ensure!(
        object.len() == 2 && object.get("type").and_then(Value::as_str) == Some(signature),
        "unexpected systemd reply type (expected {signature})"
    );
    object.get("data").context("missing systemd reply data")
}

fn reply(value: &Value, signature: &str) -> Result<Value> {
    let values = data(value, signature)?
        .as_array()
        .context("malformed systemd method reply")?;
    ensure!(values.len() == 1, "expected one systemd method result");
    Ok(values[0].clone())
}

fn ip_prefixes(value: &Value) -> Result<BTreeSet<(IpAddr, u32)>> {
    let mut result = BTreeSet::new();
    for entry in value.as_array().context("malformed IP prefix list")? {
        let fields = entry.as_array().context("malformed IP prefix")?;
        ensure!(fields.len() == 3, "malformed IP prefix fields");
        let octets = fields[1]
            .as_array()
            .context("malformed IP prefix address")?
            .iter()
            .map(|n| {
                n.as_u64()
                    .filter(|n| *n <= 255)
                    .map(|n| n as u8)
                    .context("invalid IP address byte")
            })
            .collect::<Result<Vec<_>>>()?;
        let prefix = fields[2].as_u64().context("invalid IP prefix length")?;
        let address = match fields[0].as_i64() {
            Some(2) if octets.len() == 4 && prefix <= 32 => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap()))
            }
            Some(10) if octets.len() == 16 && prefix <= 128 => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap()))
            }
            _ => bail!("unsupported IP prefix family, size or length"),
        };
        ensure!(
            result.insert((address, prefix as u32)),
            "duplicate IP prefix"
        );
    }
    Ok(result)
}

/// The unit's own pair must be attached directly and run. Extra effective
/// programs come from ancestors, such as the daemon's DNS observer on the
/// cgroup root. They are accepted because these attach points only take
/// cgroup_skb programs, whose verdicts the kernel ANDs: another program can
/// drop more traffic, never admit what the native pair refuses.
fn program_set(direct: &[u32], effective: &[u32]) -> Result<()> {
    let expected: BTreeSet<_> = direct.iter().copied().collect();
    let actual: BTreeSet<_> = effective.iter().copied().collect();
    ensure!(
        direct.len() == 2 && expected.len() == 2 && !expected.contains(&0),
        "missing or duplicate native cgroup filters"
    );
    ensure!(
        actual.len() == effective.len() && !actual.contains(&0) && actual.is_superset(&expected),
        "unexpected effective cgroup filters"
    );
    Ok(())
}

pub(super) fn verify(unit: &str, user: &str, allow: &[IpAddr]) -> Result<(u32, u32)> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        platform::verify(unit, user, allow)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (unit, user, allow);
        bail!("application confinement requires x86_64 Linux")
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod platform {
    use super::*;
    use serde_json::{json, Map};
    use std::{
        ffi::CString,
        fs::{self, File},
        io, mem,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
        process::Command,
    };

    const DEST: &str = "org.freedesktop.systemd1";
    const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
    const MANAGER: &str = "org.freedesktop.systemd1.Manager";
    const UNIT: &str = "org.freedesktop.systemd1.Unit";
    const SERVICE: &str = "org.freedesktop.systemd1.Service";
    const SLICE: &str = "org.freedesktop.systemd1.Slice";
    type Properties = Map<String, Value>;

    fn bus(arguments: &[&str]) -> Result<Value> {
        let output = Command::new("/usr/bin/busctl")
            .args([
                "--system",
                "--json=short",
                "--no-pager",
                "--timeout=5s",
                "--",
            ])
            .args(arguments)
            .env_clear()
            .env("LANG", "C")
            .output()
            .context("cannot inspect the system manager")?;
        ensure!(
            output.status.success(),
            "system manager query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        serde_json::from_slice(&output.stdout).context("invalid system manager JSON")
    }

    fn manager(method: &str, signature: &str, argument: &str, result: &str) -> Result<Value> {
        reply(
            &bus(&[
                "call",
                DEST,
                MANAGER_PATH,
                MANAGER,
                method,
                signature,
                argument,
            ])?,
            result,
        )
    }

    fn get_unit(unit: &str) -> Result<String> {
        manager("GetUnit", "s", unit, "o")?
            .as_str()
            .map(str::to_owned)
            .context("invalid unit object path")
    }

    fn properties(path: &str, interface: &str) -> Result<Properties> {
        reply(
            &bus(&[
                "call",
                DEST,
                path,
                "org.freedesktop.DBus.Properties",
                "GetAll",
                "s",
                interface,
            ])?,
            "a{sv}",
        )?
        .as_object()
        .cloned()
        .context("invalid system manager property dictionary")
    }

    fn property<'a>(properties: &'a Properties, name: &str, signature: &str) -> Result<&'a Value> {
        data(
            properties
                .get(name)
                .with_context(|| format!("missing systemd property {name}"))?,
            signature,
        )
        .with_context(|| format!("invalid systemd property {name}"))
    }

    fn require(
        properties: &Properties,
        name: &str,
        signature: &str,
        expected: Value,
    ) -> Result<()> {
        ensure!(
            *property(properties, name, signature)? == expected,
            "unexpected systemd property {name}"
        );
        Ok(())
    }

    fn cgroup_properties(
        properties: &Properties,
        allowed: &BTreeSet<(IpAddr, u32)>,
        leaf: bool,
    ) -> Result<()> {
        require(properties, "Delegate", "b", json!(false))?;
        require(properties, "IPAccounting", "b", json!(false))?;
        for name in [
            "DelegateControllers",
            "IPIngressFilterPath",
            "IPEgressFilterPath",
        ] {
            require(properties, name, "as", json!([]))?;
        }
        require(properties, "DelegateSubgroup", "s", json!(""))?;
        require(properties, "BPFProgram", "a(ss)", json!([]))?;
        require(
            properties,
            "RestrictNetworkInterfaces",
            "(bas)",
            if leaf {
                json!([false, ["lo"]])
            } else {
                json!([false, []])
            },
        )?;
        ensure!(
            ip_prefixes(property(properties, "IPAddressAllow", "a(iayu)")?)? == *allowed,
            "unexpected native IP allowance"
        );
        let denied = ip_prefixes(property(properties, "IPAddressDeny", "a(iayu)")?)?;
        let expected = if leaf {
            BTreeSet::from([
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            ])
        } else {
            BTreeSet::new()
        };
        ensure!(denied == expected, "unexpected native IP denial");
        Ok(())
    }

    fn service_properties(properties: &Properties, user: &str, unit: &str) -> Result<()> {
        for (name, expected) in [
            ("Type", "exec"),
            ("User", user),
            ("Group", user),
            ("PAMName", ""),
            ("RootDirectory", ""),
            ("RootImage", ""),
            ("NetworkNamespacePath", ""),
            ("StandardInput", "null"),
            ("StandardOutput", "null"),
            ("StandardError", "null"),
            ("KillMode", "control-group"),
            ("Restart", "no"),
            ("NotifyAccess", "none"),
            ("Slice", "system.slice"),
        ] {
            require(properties, name, "s", json!(expected))?;
        }
        for (name, expected) in [
            ("DynamicUser", true),
            ("NoNewPrivileges", true),
            ("PrivateNetwork", false),
        ] {
            require(properties, name, "b", json!(expected))?;
        }
        for name in [
            "SupplementaryGroups",
            "ExtraFileDescriptorNames",
            "PassEnvironment",
            "Environment",
        ] {
            require(properties, name, "as", json!([]))?;
        }
        require(properties, "OpenFile", "a(sst)", json!([]))?;
        require(properties, "EnvironmentFiles", "a(sb)", json!([]))?;
        for name in [
            "ExecStartPre",
            "ExecStartPost",
            "ExecReload",
            "ExecStop",
            "ExecStopPost",
        ] {
            require(properties, name, "a(sasbttttuii)", json!([]))?;
        }
        for name in [
            "StandardInputFileDescriptorName",
            "StandardOutputFileDescriptorName",
            "StandardErrorFileDescriptorName",
        ] {
            require(properties, name, "s", json!(""))?;
        }
        require(properties, "FileDescriptorStoreMax", "u", json!(0))?;
        require(properties, "NFileDescriptorStore", "u", json!(0))?;
        require(properties, "UMask", "u", json!(0o77))?;
        require(properties, "TimeoutStopUSec", "t", json!(5_000_000))?;
        require(properties, "MainPID", "u", json!(std::process::id()))?;
        require(
            properties,
            "ControlGroup",
            "s",
            json!(format!("/system.slice/{unit}")),
        )?;
        let exe =
            fs::read_link("/proc/self/exe").context("cannot resolve native gate executable")?;
        gate_command(
            property(properties, "ExecStartEx", "a(sasasttttuii)")?,
            exe.to_str().context("non-UTF-8 gate path")?,
            unit,
        )
    }

    fn gate_command(start: &Value, exe: &str, unit: &str) -> Result<()> {
        let start = start.as_array().context("invalid native gate command")?;
        ensure!(start.len() == 1, "expected one native gate command");
        let command = start[0]
            .as_array()
            .context("invalid native gate command fields")?;
        ensure!(
            command.len() == 10,
            "invalid native gate command field count"
        );
        ensure!(
            command[0].as_str() == Some(exe),
            "unexpected native gate executable"
        );
        let id = unit
            .strip_prefix("cfc-app-")
            .and_then(|u| u.strip_suffix(".service"))
            .context("invalid application unit name")?;
        ensure!(
            command[1] == json!([exe, "__cfc_application_gate", id]),
            "unexpected native gate arguments"
        );
        let flags = command[2]
            .as_array()
            .context("invalid native gate execution flags")?;
        let flags: BTreeSet<_> = flags
            .iter()
            .map(|v| v.as_str().context("invalid native gate execution flag"))
            .collect::<Result<_>>()?;
        ensure!(
            flags == BTreeSet::from(["privileged", "no-env-expand"]),
            "unexpected native gate execution privileges"
        );
        Ok(())
    }

    #[cfg(test)]
    mod policy_tests {
        use super::*;

        #[test]
        fn declared_cgroup_policy_rejects_ancestor_grants_and_custom_filters() {
            let fixture = json!({
                "Delegate":{"type":"b","data":false},
                "IPAccounting":{"type":"b","data":false},
                "DelegateControllers":{"type":"as","data":[]},
                "DelegateSubgroup":{"type":"s","data":""},
                "IPIngressFilterPath":{"type":"as","data":[]},
                "IPEgressFilterPath":{"type":"as","data":[]},
                "BPFProgram":{"type":"a(ss)","data":[]},
                "RestrictNetworkInterfaces":{"type":"(bas)","data":[false,[]]},
                "IPAddressAllow":{"type":"a(iayu)","data":[]},
                "IPAddressDeny":{"type":"a(iayu)","data":[]}
            });
            let properties = fixture.as_object().unwrap();
            assert!(cgroup_properties(properties, &BTreeSet::new(), false).is_ok());
            for (name, replacement) in [
                ("IPAddressAllow", json!([[2, [0, 0, 0, 0], 0]])),
                ("IPAccounting", json!(true)),
                ("Delegate", json!(true)),
                ("IPIngressFilterPath", json!(["/unexpected"])),
                ("BPFProgram", json!([["ingress", "/unexpected"]])),
                ("RestrictNetworkInterfaces", json!([true, ["lo"]])),
            ] {
                let mut changed = fixture.clone();
                changed[name]["data"] = replacement;
                assert!(
                    cgroup_properties(changed.as_object().unwrap(), &BTreeSet::new(), false)
                        .is_err(),
                    "{name}"
                );
            }
            let mut leaf = fixture.clone();
            leaf["RestrictNetworkInterfaces"]["data"] = json!([false, ["lo"]]);
            leaf["IPAddressDeny"]["data"] = json!([
                [2, [0, 0, 0, 0], 0],
                [10, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0]
            ]);
            assert!(cgroup_properties(leaf.as_object().unwrap(), &BTreeSet::new(), true).is_ok());
            leaf["IPAddressAllow"]["data"] = json!([[2, [203, 0, 113, 7], 24]]);
            assert!(cgroup_properties(
                leaf.as_object().unwrap(),
                &BTreeSet::from([("203.0.113.7".parse().unwrap(), 32)]),
                true
            )
            .is_err());
        }

        #[test]
        fn synthetic_controls_use_normal_headers_and_the_correct_peer_direction() {
            let frame = packet("203.0.113.7".parse().unwrap(), true);
            assert_eq!(&frame[26..30], &[203, 0, 113, 7]);
            assert_eq!(&frame[30..34], &[198, 51, 100, 1]);
            let sum: u32 = frame[14..34]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_be_bytes(*b) as u32)
                .sum();
            assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff);
            let frame = packet("203.0.113.7".parse().unwrap(), false);
            assert_eq!(&frame[30..34], &[203, 0, 113, 7]);
            assert_eq!(&frame[26..30], &[198, 51, 100, 1]);
            let frame = packet("2001:db8::7".parse().unwrap(), false);
            assert_eq!(
                &frame[38..54],
                &[32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]
            );
            assert_ne!(&frame[60..62], &[0, 0]);
        }

        #[test]
        fn accepts_documented_native_gate_tuple_without_extra_commands() {
            let unit = "cfc-app-0123456789abcdef0123456789abcdef.service";
            let gate = json!([[
                "/trusted/cfc",
                [
                    "/trusted/cfc",
                    "__cfc_application_gate",
                    "0123456789abcdef0123456789abcdef"
                ],
                ["privileged", "no-env-expand"],
                0,
                0,
                0,
                0,
                123,
                0,
                0
            ]]);
            assert!(gate_command(&gate, "/trusted/cfc", unit).is_ok());
            let mut changed = gate.clone();
            changed[0][2] = json!(["privileged"]);
            assert!(gate_command(&changed, "/trusted/cfc", unit).is_err());
            changed = gate.clone();
            changed[0][1][1] = json!("other-gate");
            assert!(gate_command(&changed, "/trusted/cfc", unit).is_err());
            assert!(gate_command(&json!([gate[0], gate[0]]), "/trusted/cfc", unit).is_err());
        }
    }

    fn identity(user: &str) -> Result<u32> {
        let uid = manager("LookupDynamicUserByName", "s", user, "u")?
            .as_u64()
            .context("invalid dynamic UID")?;
        ensure!(
            (61184..=65519).contains(&uid),
            "identity is outside the dynamic UID range"
        );
        ensure!(
            manager("LookupDynamicUserByUID", "u", &uid.to_string(), "s")?.as_str() == Some(user),
            "dynamic identity reverse lookup mismatch"
        );
        // A DynamicUser may resolve to a static passwd entry. Never accept that fallback.
        let passwd =
            fs::read_to_string("/etc/passwd").context("cannot inspect static identities")?;
        ensure!(
            !passwd.lines().any(|line| {
                let f: Vec<_> = line.split(':').collect();
                f.first() == Some(&user)
                    || f.get(2).and_then(|n| n.parse::<u64>().ok()) == Some(uid)
            }),
            "dynamic identity collides with a static user"
        );
        let group = fs::read_to_string("/etc/group").context("cannot inspect static groups")?;
        ensure!(
            !group.lines().any(|line| {
                let f: Vec<_> = line.split(':').collect();
                f.first() == Some(&user)
                    || f.get(2).and_then(|n| n.parse::<u64>().ok()) == Some(uid)
            }),
            "dynamic identity collides with a static group"
        );
        Ok(uid as u32)
    }

    fn attest_properties(unit: &str, user: &str, allowed: &BTreeSet<(IpAddr, u32)>) -> Result<()> {
        let object = get_unit(unit)?;
        ensure!(
            manager("GetUnitByPID", "u", &std::process::id().to_string(), "o")?.as_str()
                == Some(&object),
            "gate process belongs to another unit"
        );
        let generic = properties(&object, UNIT)?;
        require(&generic, "Id", "s", json!(unit))?;
        require(&generic, "LoadState", "s", json!("loaded"))?;
        require(&generic, "Transient", "b", json!(false))?;
        require(&generic, "NeedDaemonReload", "b", json!(false))?;
        require(&generic, "TriggeredBy", "as", json!([]))?;
        require(
            &generic,
            "FragmentPath",
            "s",
            json!(format!("/run/systemd/system/{unit}")),
        )?;
        let fragment = property(&generic, "FragmentPath", "s")?
            .as_str()
            .context("invalid unit fragment path")?;
        let metadata = fs::symlink_metadata(fragment).context("cannot inspect native unit file")?;
        ensure!(
            Path::new(fragment).is_absolute()
                && metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "native unit file is not root controlled"
        );
        let service = properties(&object, SERVICE)?;
        service_properties(&service, user, unit)?;
        cgroup_properties(&service, allowed, true)?;
        // systemd folds all ancestor allow prefixes into the service's own native map.
        for (ancestor, path, slice) in [
            ("system.slice", "/system.slice", "-.slice"),
            ("-.slice", "/", ""),
        ] {
            let parent = properties(&get_unit(ancestor)?, SLICE)?;
            require(&parent, "ControlGroup", "s", json!(path))?;
            require(&parent, "Slice", "s", json!(slice))?;
            cgroup_properties(&parent, &BTreeSet::new(), false)?;
        }
        Ok(())
    }

    fn cgroup(unit: &str) -> Result<File> {
        let expected = format!("0::/system.slice/{unit}\n");
        ensure!(
            fs::read_to_string("/proc/self/cgroup")? == expected,
            "gate is not in the expected unified cgroup"
        );
        ensure!(
            fs::metadata("/proc/self/ns/cgroup")?.ino() == fs::metadata("/proc/1/ns/cgroup")?.ino(),
            "unexpected cgroup namespace"
        );
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let mounts: Vec<_> = mountinfo
            .lines()
            .filter(|line| {
                let f: Vec<_> = line.split_whitespace().collect();
                f.get(4) == Some(&"/sys/fs/cgroup")
            })
            .collect();
        ensure!(mounts.len() == 1, "ambiguous cgroup mount");
        let (before, after) = mounts[0]
            .split_once(" - ")
            .context("invalid cgroup mount metadata")?;
        ensure!(
            before.split_whitespace().nth(3) == Some("/")
                && after.split_whitespace().next() == Some("cgroup2"),
            "expected a complete cgroup v2 mount"
        );
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/sys/fs/cgroup/system.slice/{unit}"))?;
        let mut stat: libc::statfs = unsafe { mem::zeroed() };
        ensure!(
            unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } == 0,
            "cannot inspect cgroup filesystem"
        );
        ensure!(
            stat.f_type == 0x63677270,
            "native cgroup is not on cgroup v2"
        );
        Ok(file)
    }

    // The whole `bpf_attr.query` layout through `revision`, not only the fields
    // read here: kernels 6.17 to 7.1 write `revision` at offset 56 whatever
    // size the caller passed, so a shorter struct is overwritten past its end.
    #[repr(C)]
    #[derive(Default)]
    struct Query {
        target_fd: u32,
        attach_type: u32,
        query_flags: u32,
        attach_flags: u32,
        prog_ids: u64,
        prog_cnt: u32,
        padding: u32,
        prog_attach_flags: u64,
        link_ids: u64,
        link_attach_flags: u64,
        revision: u64,
    }
    const _: () = assert!(mem::size_of::<Query>() == 64);
    #[repr(C)]
    struct Info {
        fd: u32,
        len: u32,
        info: u64,
    }
    #[repr(C)]
    struct Element {
        fd: u32,
        padding: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    #[repr(C)]
    #[derive(Default)]
    struct TestRun {
        prog_fd: u32,
        retval: u32,
        data_size_in: u32,
        data_size_out: u32,
        data_in: u64,
        data_out: u64,
        repeat: u32,
        duration: u32,
        ctx_size_in: u32,
        ctx_size_out: u32,
        ctx_in: u64,
        ctx_out: u64,
        flags: u32,
        cpu: u32,
        batch_size: u32,
        padding: u32,
    }

    fn bpf<T>(command: u32, attribute: &mut T) -> Result<i32> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                command,
                attribute as *mut T,
                mem::size_of::<T>(),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("required BPF operation {command} failed"));
        }
        Ok(result as i32)
    }

    fn query(fd: &File, direction: u32, effective: bool) -> Result<Vec<u32>> {
        let mut ids = [0u32; 64];
        let mut attribute = Query {
            target_fd: fd.as_raw_fd() as u32,
            attach_type: direction,
            query_flags: u32::from(effective),
            prog_ids: ids.as_mut_ptr() as u64,
            prog_cnt: ids.len() as u32,
            ..Query::default()
        };
        bpf(16, &mut attribute)?;
        ensure!(
            attribute.prog_cnt as usize <= ids.len(),
            "too many cgroup programs"
        );
        Ok(ids[..attribute.prog_cnt as usize].to_vec())
    }

    fn program(id: u32, direction: u32) -> Result<(OwnedFd, bool)> {
        let fd = bpf(13, &mut [id, 0u32, 0u32])?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Keep the output zeroed; copying a prior info reply also copies kernel pointers.
        let mut info = [0u64; 40];
        let mut attribute = Info {
            fd: fd.as_raw_fd() as u32,
            len: mem::size_of_val(&info) as u32,
            info: info.as_mut_ptr() as u64,
        };
        bpf(15, &mut attribute)?;
        ensure!(
            attribute.len >= 80
                && info[0] as u32 == 8
                && (info[0] >> 32) as u32 == id
                && info[6] as u32 == 0,
            "unexpected cgroup program identity"
        );
        let mut name = Vec::new();
        name.extend(info[8].to_ne_bytes());
        name.extend(info[9].to_ne_bytes());
        let end = name
            .iter()
            .position(|b| *b == 0)
            .context("unterminated native BPF name")?;
        let name = std::str::from_utf8(&name[..end]).context("invalid native BPF name")?;
        let (ip, interface) = if direction == 0 {
            ("sd_fw_ingress", "sd_restrictif_i")
        } else {
            ("sd_fw_egress", "sd_restrictif_e")
        };
        ensure!(
            name == ip || name == interface,
            "unexpected cgroup filter {name}"
        );
        Ok((fd, name == ip))
    }

    fn native_maps(program: &OwnedFd, ip: bool, allowed: &[IpAddr], loopback: u32) -> Result<()> {
        let mut ids = [0u32; 8];
        let mut info = [0u64; 40];
        info[6] = (ids.len() as u64) << 32;
        info[7] = ids.as_mut_ptr() as u64;
        bpf(
            15,
            &mut Info {
                fd: program.as_raw_fd() as u32,
                len: mem::size_of_val(&info) as u32,
                info: info.as_mut_ptr() as u64,
            },
        )?;
        let count = (info[6] >> 32) as usize;
        ensure!(count <= ids.len(), "too many native policy maps");
        if ip {
            ensure!(
                count
                    == allowed
                        .iter()
                        .map(IpAddr::is_ipv4)
                        .collect::<BTreeSet<_>>()
                        .len(),
                "unexpected native IP map count"
            );
        }
        let mut seen_ips = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        for id in &ids[..count] {
            let fd = unsafe { OwnedFd::from_raw_fd(bpf(14, &mut [*id, 0u32, 0u32])?) };
            let mut metadata = [0u64; 12];
            bpf(
                15,
                &mut Info {
                    fd: fd.as_raw_fd() as u32,
                    len: mem::size_of_val(&metadata) as u32,
                    info: metadata.as_mut_ptr() as u64,
                },
            )?;
            let kind = metadata[0] as u32;
            let key_size = metadata[1] as u32 as usize;
            let value_size = (metadata[1] >> 32) as usize;
            let max_entries = metadata[2] as u32;
            let flags = (metadata[2] >> 32) as u32;
            let mut name = Vec::new();
            name.extend(metadata[3].to_ne_bytes());
            name.extend(metadata[4].to_ne_bytes());
            let end = name
                .iter()
                .position(|b| *b == 0)
                .context("unterminated native map name")?;
            let name = std::str::from_utf8(&name[..end])?;
            ensure!(seen_names.insert(name.to_owned()), "duplicate native map");
            if ip {
                ensure!(
                    kind == 11
                        && (key_size == 8 || key_size == 20)
                        && value_size == 8
                        && flags == 1,
                    "unexpected native IP map schema"
                );
                let mut current: Option<Vec<u8>> = None;
                for _ in 0..=allowed.len() {
                    let mut next = vec![0u8; key_size];
                    let mut attr = Element {
                        fd: fd.as_raw_fd() as u32,
                        padding: 0,
                        key: current.as_ref().map_or(0, |key| key.as_ptr() as u64),
                        value: next.as_mut_ptr() as u64,
                        flags: 0,
                    };
                    match bpf(4, &mut attr) {
                        Ok(_) => (),
                        Err(error)
                            if error
                                .downcast_ref::<io::Error>()
                                .and_then(io::Error::raw_os_error)
                                == Some(libc::ENOENT) =>
                        {
                            break
                        }
                        Err(error) => return Err(error),
                    }
                    let prefix = u32::from_ne_bytes(next[..4].try_into().unwrap());
                    let address = if key_size == 8 {
                        ensure!(prefix == 32, "non-host native IPv4 permission");
                        IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&next[4..]).unwrap()))
                    } else {
                        ensure!(prefix == 128, "non-host native IPv6 permission");
                        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&next[4..]).unwrap()))
                    };
                    let mut value = 0u64;
                    bpf(
                        1,
                        &mut Element {
                            fd: fd.as_raw_fd() as u32,
                            padding: 0,
                            key: next.as_ptr() as u64,
                            value: (&mut value as *mut u64) as u64,
                            flags: 0,
                        },
                    )?;
                    ensure!(
                        value == 1 && allowed.contains(&address) && seen_ips.insert(address),
                        "unexpected native IP map permission"
                    );
                    current = Some(next);
                }
            } else {
                let expected = match name {
                    "sd_restrictif" => {
                        ensure!(
                            kind == 1 && key_size == 4 && value_size == 1 && max_entries == 1,
                            "unexpected native interface list schema"
                        );
                        loopback
                    }
                    "restrict.rodata" => {
                        ensure!(
                            kind == 2
                                && key_size == 4
                                && value_size == 1
                                && max_entries == 1
                                && flags & 128 != 0,
                            "unexpected native interface mode schema"
                        );
                        0
                    }
                    _ => bail!("unexpected native interface map"),
                };
                let mut key = 0u32;
                bpf(
                    4,
                    &mut Element {
                        fd: fd.as_raw_fd() as u32,
                        padding: 0,
                        key: 0,
                        value: (&mut key as *mut u32) as u64,
                        flags: 0,
                    },
                )?;
                ensure!(key == expected, "unexpected native interface map key");
                let mut value = 1u8;
                bpf(
                    1,
                    &mut Element {
                        fd: fd.as_raw_fd() as u32,
                        padding: 0,
                        key: (&key as *const u32) as u64,
                        value: (&mut value as *mut u8) as u64,
                        flags: 0,
                    },
                )?;
                ensure!(value == 0, "unexpected native interface map mode");
                let mut next = 0u32;
                let error = match bpf(
                    4,
                    &mut Element {
                        fd: fd.as_raw_fd() as u32,
                        padding: 0,
                        key: (&key as *const u32) as u64,
                        value: (&mut next as *mut u32) as u64,
                        flags: 0,
                    },
                ) {
                    Ok(_) => bail!("unexpected extra native interface map key"),
                    Err(error) => error,
                };
                ensure!(
                    error
                        .downcast_ref::<io::Error>()
                        .and_then(io::Error::raw_os_error)
                        == Some(libc::ENOENT),
                    "native interface map enumeration failed"
                );
            }
        }
        if ip {
            ensure!(
                seen_ips == allowed.iter().copied().collect(),
                "native IP map permissions differ from the declared policy"
            );
        } else {
            ensure!(
                seen_names
                    == BTreeSet::from(["sd_restrictif".to_owned(), "restrict.rodata".to_owned()]),
                "missing native interface map"
            );
        }
        Ok(())
    }

    fn packet(peer: IpAddr, ingress: bool) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + if peer.is_ipv4() { 20 } else { 40 } + 8];
        frame[0..12].copy_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]);
        match peer {
            IpAddr::V4(peer) => {
                frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
                frame[14] = 0x45;
                frame[16..18].copy_from_slice(&28u16.to_be_bytes());
                frame[22] = 64;
                frame[23] = 17;
                let offset = if ingress { 26 } else { 30 };
                frame[offset..offset + 4].copy_from_slice(&peer.octets());
                let local = if ingress { 30 } else { 26 };
                frame[local..local + 4].copy_from_slice(&[198, 51, 100, 1]);
                let checksum = checksum(&frame[14..34]);
                frame[24..26].copy_from_slice(&checksum.to_be_bytes());
            }
            IpAddr::V6(peer) => {
                frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
                frame[14] = 0x60;
                frame[18..20].copy_from_slice(&8u16.to_be_bytes());
                frame[20] = 17;
                frame[21] = 64;
                let offset = if ingress { 22 } else { 38 };
                frame[offset..offset + 16].copy_from_slice(&peer.octets());
                let local = if ingress { 38 } else { 22 };
                frame[local..local + 16]
                    .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1).octets());
            }
        }
        let offset = frame.len() - 8;
        frame[offset..offset + 2].copy_from_slice(&12345u16.to_be_bytes());
        frame[offset + 2..offset + 4].copy_from_slice(&443u16.to_be_bytes());
        frame[offset + 4..offset + 6].copy_from_slice(&8u16.to_be_bytes());
        if peer.is_ipv6() {
            let mut pseudo = frame[22..54].to_vec();
            pseudo.extend([0, 0, 0, 8, 0, 0, 0, 17]);
            pseudo.extend(&frame[offset..]);
            let checksum = checksum(&pseudo);
            frame[offset + 6..offset + 8]
                .copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
        }
        frame
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_be_bytes(*b) as u32)
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn test_run(fd: &OwnedFd, packet: &[u8], interface: u32, verdict: u32) -> Result<()> {
        // __sk_buff input allows ingress_ifindex/ifindex. All other input fields stay zero.
        let mut context = [0u32; 48];
        context[9] = interface;
        context[10] = interface;
        let mut attribute = TestRun {
            prog_fd: fd.as_raw_fd() as u32,
            data_size_in: packet.len() as u32,
            data_in: packet.as_ptr() as u64,
            repeat: 1,
            ctx_size_in: mem::size_of_val(&context) as u32,
            ctx_in: context.as_ptr() as u64,
            ..TestRun::default()
        };
        bpf(10, &mut attribute)?;
        ensure!(
            attribute.retval == verdict,
            "native BPF filter failed a synthetic decision control"
        );
        Ok(())
    }

    fn interfaces() -> Result<(u32, u32)> {
        let loopback = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        ensure!(loopback != 0, "missing loopback interface");
        for entry in fs::read_dir("/sys/class/net")? {
            let entry = entry?;
            if entry.file_name() == "lo" {
                continue;
            }
            let name = CString::new(entry.file_name().as_encoded_bytes())?;
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index != 0 && index != loopback {
                return Ok((loopback, index));
            }
        }
        bail!("no non-loopback interface for native filter attestation")
    }

    fn denial_controls(allowed: &[IpAddr]) -> [IpAddr; 2] {
        let mut v4 = u32::from(Ipv4Addr::new(192, 0, 2, 254));
        while allowed.contains(&IpAddr::V4(Ipv4Addr::from(v4))) {
            v4 = v4.wrapping_add(1);
        }
        let mut v6 = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfffe));
        while allowed.contains(&IpAddr::V6(Ipv6Addr::from(v6))) {
            v6 = v6.wrapping_add(1);
        }
        [
            IpAddr::V4(Ipv4Addr::from(v4)),
            IpAddr::V6(Ipv6Addr::from(v6)),
        ]
    }

    fn filters(cgroup: &File, allowed: &[IpAddr]) -> Result<()> {
        let (loopback, external) = interfaces()?;
        for direction in [0, 1] {
            let direct = query(cgroup, direction, false)?;
            let effective = query(cgroup, direction, true)?;
            program_set(&direct, &effective)?;
            let mut kinds = BTreeSet::new();
            for id in &direct {
                let (fd, ip) = program(*id, direction)?;
                ensure!(kinds.insert(ip), "duplicate native filter kind");
                native_maps(&fd, ip, allowed, loopback)?;
                if ip {
                    for peer in allowed {
                        test_run(&fd, &packet(*peer, direction == 0), external, 1)?;
                    }
                    for peer in denial_controls(allowed) {
                        test_run(&fd, &packet(peer, direction == 0), external, 0)?;
                    }
                } else {
                    for peer in denial_controls(allowed) {
                        let packet = packet(peer, direction == 0);
                        test_run(&fd, &packet, loopback, 0)?;
                        test_run(&fd, &packet, external, 1)?;
                    }
                }
                native_maps(&fd, ip, allowed, loopback)?;
            }
            ensure!(
                query(cgroup, direction, false)? == direct
                    && query(cgroup, direction, true)? == effective,
                "native BPF attachments changed during attestation"
            );
        }
        Ok(())
    }

    pub(super) fn verify(unit: &str, user: &str, allow: &[IpAddr]) -> Result<(u32, u32)> {
        ensure!(
            unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
            "native gate requires real and effective root"
        );
        let id = unit
            .strip_prefix("cfc-app-")
            .and_then(|n| n.strip_suffix(".service"))
            .context("invalid application unit name")?;
        ensure!(
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && user == format!("cfc_{}", &id[..27]),
            "invalid application identity"
        );
        let version_reply = bus(&["get-property", DEST, MANAGER_PATH, MANAGER, "Version"])?;
        let version = data(&version_reply, "s")?
            .as_str()
            .context("invalid systemd version")?;
        let version: u32 = version
            .trim_start_matches('v')
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .context("missing systemd version")?
            .parse()
            .context("invalid systemd version")?;
        ensure!(
            version >= 262,
            "application confinement requires systemd 262 or newer"
        );
        let allowed: BTreeSet<_> = allow
            .iter()
            .map(|ip| (*ip, if ip.is_ipv4() { 32 } else { 128 }))
            .collect();
        ensure!(allowed.len() == allow.len(), "duplicate application peer");
        let cgroup = cgroup(unit)?;
        attest_properties(unit, user, &allowed)?;
        let uid = identity(user)?;
        filters(&cgroup, allow)?;
        attest_properties(unit, user, &allowed)?;
        ensure!(
            identity(user)? == uid,
            "dynamic identity changed during attestation"
        );
        // Native DynamicUser creates its primary group with the same numerical ID.
        Ok((uid, uid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Rejecting malformed replies must survive changing the external parser.
    #[test]
    fn method_reply_requires_one_typed_result() {
        assert_eq!(
            reply(&json!({"type":"u","data":[61234]}), "u").unwrap(),
            json!(61234)
        );
        for value in [
            json!({"type":"s","data":[61234]}),
            json!({"type":"u","data":[]}),
            json!({"type":"u","data":[61234,61235]}),
            json!({"type":"u","data":61234}),
        ] {
            assert!(reply(&value, "u").is_err());
        }
    }

    #[test]
    fn address_prefix_parser_rejects_ambiguous_policy() {
        let expected = BTreeSet::from([("192.0.2.1".parse().unwrap(), 32)]);
        assert_eq!(
            ip_prefixes(&json!([[2, [192, 0, 2, 1], 32]])).unwrap(),
            expected
        );
        assert!(ip_prefixes(&json!([])).unwrap().is_empty());
        for value in [
            json!([[2, [192, 0, 2, 1], 33]]),
            json!([[10, [0, 0, 0, 0], 128]]),
            json!([[2, [256, 0, 2, 1], 32]]),
            json!([[2, [192, 0, 2, 1], 32], [2, [192, 0, 2, 1], 32]]),
            json!([[2, [192, 0, 2, 1], 32, 0]]),
        ] {
            assert!(ip_prefixes(&value).is_err());
        }
    }

    #[test]
    fn effective_filters_must_run_the_direct_pair() {
        assert!(program_set(&[7, 9], &[9, 7]).is_ok());
        // An ancestor's program, such as CFC's DNS observer on the root.
        assert!(program_set(&[7, 9], &[7, 9, 10]).is_ok());
        for (direct, effective) in [
            (vec![], vec![]),
            (vec![7, 9], vec![7]),
            (vec![7, 9], vec![7, 10]),
            (vec![7, 9], vec![7, 9, 9]),
            (vec![7, 9], vec![7, 9, 0]),
            (vec![7, 7], vec![7, 7]),
            (vec![0, 9], vec![0, 9]),
        ] {
            assert!(program_set(&direct, &effective).is_err());
        }
    }
}
