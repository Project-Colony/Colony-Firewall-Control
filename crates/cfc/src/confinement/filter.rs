//! Final application syscall policy for the x86_64 confined application tree.
//!
//! This module creates a filter file; it never installs seccomp in this process.
//! Network peers and filesystem visibility are enforced by the launcher separately.

use std::fs::File;

/// A sealed, rewound native cBPF file for bubblewrap's `--seccomp` option.
pub fn sealed_filter() -> anyhow::Result<File> {
    use anyhow::Context;
    use std::io::{Seek, Write};
    use std::os::fd::{AsRawFd, FromRawFd};

    let program = filter_program();
    anyhow::ensure!(
        program.len() <= 4096,
        "seccomp program exceeds the kernel limit"
    );
    // SAFETY: a constant NUL-terminated name and supported memfd flags. This
    // only creates an owned file; no seccomp or privilege change occurs here.
    let fd = unsafe {
        libc::memfd_create(
            c"cfc-confinement-filter".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("creating confinement filter memfd");
    }
    // SAFETY: successful memfd_create transferred this new descriptor to us.
    let mut file = unsafe { File::from_raw_fd(fd) };
    for instruction in program {
        file.write_all(&instruction.code.to_ne_bytes())?;
        file.write_all(&[instruction.jt, instruction.jf])?;
        file.write_all(&instruction.k.to_ne_bytes())?;
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: the owned file is live and F_ADD_SEALS takes an integer mask.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error()).context("sealing confinement filter memfd");
    }
    file.rewind()
        .context("rewinding confinement filter memfd")?;
    Ok(file)
}

const ALLOW: u32 = 0x7fff_0000;
const KILL: u32 = 0x8000_0000;
const ENOSYS: u32 = 0x0005_0000 | libc::ENOSYS as u32;
const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
const NATIVE_ARCH: u32 = 0xc000_003e;

fn filter_program() -> Vec<libc::sock_filter> {
    let mut program = vec![
        statement(0x20, 4), // seccomp_data.arch
        jump(0x15, NATIVE_ARCH, 1, 0),
        statement(0x06, KILL),
        statement(0x20, 0),            // seccomp_data.nr
        jump(0x45, 0x4000_0000, 0, 1), // x32 uses the native arch with this syscall bit.
        statement(0x06, KILL),
    ];
    conditional(&mut program, libc::SYS_socket, socket_policy());
    conditional(&mut program, libc::SYS_clone, clone_policy());
    conditional(
        &mut program,
        libc::SYS_prctl,
        argument_options(
            0,
            &[
                libc::PR_SET_NAME as u32,
                libc::PR_GET_NAME as u32,
                libc::PR_GET_DUMPABLE as u32,
                libc::PR_GET_NO_NEW_PRIVS as u32,
                libc::PR_GET_SECCOMP as u32,
                libc::PR_GET_KEEPCAPS as u32,
                libc::PR_GET_SECUREBITS as u32,
                libc::PR_GET_PDEATHSIG as u32,
                libc::PR_GET_TIMERSLACK as u32,
                libc::PR_GET_THP_DISABLE as u32,
            ],
        ),
    );
    conditional(
        &mut program,
        libc::SYS_ioctl,
        argument_options(1, &[libc::FIONREAD as u32, libc::FIONBIO as u32]),
    );
    // The native dynamic linker and thread runtime manage their own FS/GS
    // bases. Do not allow compatibility VDSO mapping or unknown subcommands.
    conditional(
        &mut program,
        libc::SYS_arch_prctl,
        argument_options(
            0,
            &[
                0x1001, 0x1002, 0x1003, 0x1004, // ARCH_SET_GS, SET_FS, GET_FS, GET_GS.
            ],
        ),
    );
    // This final allowlist is deliberately independent of a blacklist. New
    // syscall interfaces, clone3 (glibc falls back to clone), io_uring and all
    // authority-changing interfaces receive ENOSYS unless listed explicitly.
    // File and process operations rely on the launcher's private mount/PID
    // view, no external descriptors, no capabilities and no-new-privileges.
    for nr in [
        // Ordinary files, private temporary data and descriptor operations.
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_preadv2,
        libc::SYS_pwritev2,
        libc::SYS_lseek,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_fcntl,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_getcwd,
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_rmdir,
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_link,
        libc::SYS_linkat,
        libc::SYS_symlink,
        libc::SYS_symlinkat,
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchmodat2,
        libc::SYS_chown,
        libc::SYS_fchown,
        libc::SYS_lchown,
        libc::SYS_fchownat,
        libc::SYS_umask,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_fadvise64,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
        libc::SYS_utimensat,
        libc::SYS_getxattr,
        libc::SYS_lgetxattr,
        libc::SYS_fgetxattr,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_flistxattr,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        libc::SYS_memfd_create,
        libc::SYS_sendfile,
        libc::SYS_splice,
        libc::SYS_tee,
        libc::SYS_vmsplice,
        // The process's own address space and ordinary thread runtime.
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_msync,
        libc::SYS_mincore,
        libc::SYS_madvise,
        libc::SYS_pkey_mprotect,
        libc::SYS_pkey_alloc,
        libc::SYS_pkey_free,
        libc::SYS_mlock,
        libc::SYS_munlock,
        libc::SYS_mlockall,
        libc::SYS_munlockall,
        libc::SYS_mlock2,
        libc::SYS_futex,
        libc::SYS_futex_waitv,
        libc::SYS_rseq,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        // Descendants remain in the same application tree and PID view.
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_getgroups,
        libc::SYS_capget,
        libc::SYS_getpgrp,
        libc::SYS_getpgid,
        libc::SYS_setpgid,
        libc::SYS_getsid,
        libc::SYS_setsid,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigpending,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_sigsuspend,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_sigaltstack,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        // Clocks, own resource controls and private event/pipe descriptors.
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_gettimeofday,
        libc::SYS_time,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_alarm,
        libc::SYS_getitimer,
        libc::SYS_setitimer,
        libc::SYS_timer_create,
        libc::SYS_timer_settime,
        libc::SYS_timer_gettime,
        libc::SYS_timer_getoverrun,
        libc::SYS_timer_delete,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_getrlimit,
        libc::SYS_setrlimit,
        libc::SYS_prlimit64,
        libc::SYS_getrusage,
        libc::SYS_times,
        libc::SYS_getpriority,
        libc::SYS_setpriority,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_setaffinity,
        libc::SYS_sched_getparam,
        libc::SYS_sched_setparam,
        libc::SYS_sched_getscheduler,
        libc::SYS_sched_setscheduler,
        libc::SYS_sched_get_priority_max,
        libc::SYS_sched_get_priority_min,
        libc::SYS_sched_rr_get_interval,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getrandom,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_eventfd,
        libc::SYS_eventfd2,
        libc::SYS_signalfd,
        libc::SYS_signalfd4,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_select,
        libc::SYS_pselect6,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_pwait2,
        libc::SYS_inotify_init,
        libc::SYS_inotify_init1,
        libc::SYS_inotify_add_watch,
        libc::SYS_inotify_rm_watch,
        // Only sockets created under socket_policy can reach these calls.
        // Native cgroup IP peer policy separately controls every peer.
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
    ] {
        program.push(jump(0x15, nr as u32, 0, 1));
        program.push(statement(0x06, ALLOW));
    }
    program.push(statement(0x06, ENOSYS));
    program
}

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn conditional(
    program: &mut Vec<libc::sock_filter>,
    nr: libc::c_long,
    body: Vec<libc::sock_filter>,
) {
    let skip = u8::try_from(body.len()).expect("constant seccomp branch fits a cBPF jump");
    program.push(jump(0x15, nr as u32, 0, skip));
    program.extend(body);
}

fn argument_options(index: u32, options: &[u32]) -> Vec<libc::sock_filter> {
    // These syscall parameters are native int/unsigned int; the kernel uses
    // their low 32 bits. Clone flags below are an unsigned long, checked whole.
    let mut body = vec![statement(0x20, 16 + 8 * index)];
    for option in options {
        body.push(jump(0x15, *option, 0, 1));
        body.push(statement(0x06, ALLOW));
    }
    body.push(statement(0x06, DENY));
    body
}

fn socket_policy() -> Vec<libc::sock_filter> {
    vec![
        statement(0x20, 16),
        jump(0x15, libc::AF_INET as u32, 2, 0),
        jump(0x15, libc::AF_INET6 as u32, 1, 0),
        statement(0x06, DENY),
        statement(0x20, 24),
        statement(0x54, !((libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32)),
        jump(0x15, libc::SOCK_STREAM as u32, 0, 5),
        statement(0x20, 32),
        jump(0x15, 0, 2, 0),
        jump(0x15, libc::IPPROTO_TCP as u32, 1, 0),
        statement(0x06, DENY),
        statement(0x06, ALLOW),
        jump(0x15, libc::SOCK_DGRAM as u32, 0, 5),
        statement(0x20, 32),
        jump(0x15, 0, 2, 0),
        jump(0x15, libc::IPPROTO_UDP as u32, 1, 0),
        statement(0x06, DENY),
        statement(0x06, ALLOW),
        statement(0x06, DENY),
    ]
}

fn clone_policy() -> Vec<libc::sock_filter> {
    let ordinary = libc::CLONE_VM
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SIGHAND
        | libc::CLONE_THREAD
        | libc::CLONE_SYSVSEM
        | libc::CLONE_SETTLS
        | libc::CLONE_PARENT_SETTID
        | libc::CLONE_CHILD_CLEARTID
        | libc::CLONE_CHILD_SETTID
        | libc::CLONE_VFORK
        | 0x7f; // Exit signal; 0x80 (CLONE_NEWTIME) stays refused.
    vec![
        statement(0x20, 20), // High half of the native unsigned-long flags.
        jump(0x15, 0, 1, 0),
        statement(0x06, DENY),
        statement(0x20, 16),
        jump(0x45, !(ordinary as u32), 0, 1),
        statement(0x06, DENY),
        statement(0x06, ALLOW),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;

    // A small interpreter for the actual emitted cBPF and seccomp_data bytes.
    // Tests do not execute restricted syscalls or install any host filter.
    fn interpret(program: &[libc::sock_filter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut data = [0_u8; 64];
        data[..4].copy_from_slice(&nr.to_ne_bytes());
        data[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (index, argument) in args.into_iter().enumerate() {
            data[16 + 8 * index..24 + 8 * index].copy_from_slice(&argument.to_ne_bytes());
        }
        let mut accumulator = 0;
        let mut pc = 0;
        for _ in 0..4096 {
            let instruction = &program[pc];
            pc += 1;
            match instruction.code {
                0x20 => {
                    let offset = instruction.k as usize;
                    accumulator = u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap());
                }
                0x15 => {
                    pc += if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    } as usize
                }
                0x45 => {
                    pc += if accumulator & instruction.k != 0 {
                        instruction.jt
                    } else {
                        instruction.jf
                    } as usize
                }
                0x54 => accumulator &= instruction.k,
                0x06 => return instruction.k,
                code => panic!("unsupported cBPF instruction {code:#x}"),
            }
        }
        panic!("filter did not terminate")
    }

    fn verdict(nr: libc::c_long, args: [u64; 6]) -> u32 {
        interpret(&filter_program(), NATIVE_ARCH, nr as u32, args)
    }

    #[test]
    fn foreign_and_x32_abis_are_killed() {
        let program = filter_program();
        for arch in [0x4000_0003, 0xc000_00b7, 0, u32::MAX] {
            assert_eq!(
                interpret(&program, arch, libc::SYS_read as u32, [0; 6]),
                KILL
            );
        }
        assert_eq!(
            interpret(
                &program,
                NATIVE_ARCH,
                0x4000_0000 | libc::SYS_read as u32,
                [0; 6]
            ),
            KILL
        );
        assert_eq!(verdict(libc::SYS_read, [0; 6]), ALLOW);
    }

    #[test]
    fn unknown_syscalls_and_clone3_are_enosys() {
        assert_eq!(verdict(999_999, [0; 6]), ENOSYS);
        assert_eq!(verdict(0x3fff_ffff, [0; 6]), ENOSYS);
        assert_eq!(verdict(libc::SYS_clone3, [0; 6]), ENOSYS);
    }

    #[test]
    fn alternative_io_authority_and_namespace_interfaces_are_unavailable() {
        for nr in [
            libc::SYS_socketpair,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_pidfd_getfd,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_mount,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_capset,
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_setresuid,
            libc::SYS_setresgid,
            libc::SYS_setgroups,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_open_by_handle_at,
            libc::SYS_userfaultfd,
            libc::SYS_mknod,
            libc::SYS_mknodat,
            libc::SYS_shmget,
            libc::SYS_semget,
            libc::SYS_msgget,
            libc::SYS_keyctl,
        ] {
            assert_eq!(verdict(nr, [0; 6]), ENOSYS, "syscall {nr}");
        }
    }

    #[test]
    fn tcp_udp_sockets_allow_only_their_native_families_types_and_flags() {
        for family in [libc::AF_INET, libc::AF_INET6] {
            for (kind, protocol) in [
                (libc::SOCK_STREAM, libc::IPPROTO_TCP),
                (libc::SOCK_DGRAM, libc::IPPROTO_UDP),
            ] {
                for flags in [
                    0,
                    libc::SOCK_CLOEXEC,
                    libc::SOCK_NONBLOCK,
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                ] {
                    for protocol in [0, protocol] {
                        assert_eq!(
                            verdict(
                                libc::SYS_socket,
                                [
                                    family as u64,
                                    (kind | flags) as u64,
                                    protocol as u64,
                                    0,
                                    0,
                                    0
                                ]
                            ),
                            ALLOW
                        );
                    }
                }
            }
        }
        for family in [libc::AF_UNIX, libc::AF_PACKET, libc::AF_NETLINK, 0, 999] {
            assert_eq!(
                verdict(
                    libc::SYS_socket,
                    [family as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
                ),
                DENY
            );
        }
        for kind in [
            libc::SOCK_RAW,
            libc::SOCK_SEQPACKET,
            libc::SOCK_RDM,
            libc::SOCK_STREAM | 0x100,
        ] {
            assert_eq!(
                verdict(
                    libc::SYS_socket,
                    [libc::AF_INET as u64, kind as u64, 0, 0, 0, 0]
                ),
                DENY
            );
        }
        for (kind, protocol) in [
            (libc::SOCK_STREAM, libc::IPPROTO_UDP),
            (libc::SOCK_DGRAM, libc::IPPROTO_TCP),
            (libc::SOCK_DGRAM, libc::IPPROTO_ICMP),
            (libc::SOCK_STREAM, 999),
        ] {
            assert_eq!(
                verdict(
                    libc::SYS_socket,
                    [libc::AF_INET6 as u64, kind as u64, protocol as u64, 0, 0, 0]
                ),
                DENY
            );
        }
    }

    #[test]
    fn ordinary_fork_and_thread_flags_work_without_new_namespaces() {
        let fork = libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID | libc::SIGCHLD;
        let thread = libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID;
        for flags in [libc::SIGCHLD as u64, fork as u64, thread as u64] {
            assert_eq!(verdict(libc::SYS_clone, [flags, 0, 0, 0, 0, 0]), ALLOW);
        }
        for flag in [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
            0x80,
            libc::CLONE_PIDFD,
        ] {
            assert_eq!(
                verdict(libc::SYS_clone, [(thread | flag) as u64, 0, 0, 0, 0, 0]),
                DENY
            );
        }
        assert_eq!(
            verdict(
                libc::SYS_clone,
                [thread as u64 | (1_u64 << 32), 0, 0, 0, 0, 0]
            ),
            DENY
        );
    }

    #[test]
    fn prctl_and_ioctl_have_bounded_non_authority_operations() {
        for option in [0x1001, 0x1002, 0x1003, 0x1004] {
            assert_eq!(
                verdict(libc::SYS_arch_prctl, [option, 0, 0, 0, 0, 0]),
                ALLOW
            );
        }
        for option in [0x1011, 0x1012, 0x1013, 999] {
            assert_eq!(verdict(libc::SYS_arch_prctl, [option, 0, 0, 0, 0, 0]), DENY);
        }
        for option in [
            libc::PR_SET_NAME,
            libc::PR_GET_NAME,
            libc::PR_GET_DUMPABLE,
            libc::PR_GET_NO_NEW_PRIVS,
            libc::PR_GET_SECCOMP,
        ] {
            assert_eq!(
                verdict(libc::SYS_prctl, [option as u64, 0, 0, 0, 0, 0]),
                ALLOW
            );
        }
        for option in [
            libc::PR_SET_SECCOMP,
            libc::PR_SET_KEEPCAPS,
            libc::PR_SET_SECUREBITS,
            libc::PR_CAP_AMBIENT,
            libc::PR_SET_PTRACER,
            libc::PR_SET_DUMPABLE,
            999,
        ] {
            assert_eq!(
                verdict(libc::SYS_prctl, [option as u64, 0, 0, 0, 0, 0]),
                DENY
            );
        }
        for request in [libc::FIONREAD, libc::FIONBIO] {
            assert_eq!(verdict(libc::SYS_ioctl, [0, request, 0, 0, 0, 0]), ALLOW);
        }
        for request in [
            libc::TIOCSTI,
            libc::TIOCSCTTY,
            libc::TIOCGWINSZ,
            0x8914,
            999,
        ] {
            assert_eq!(verdict(libc::SYS_ioctl, [0, request, 0, 0, 0, 0]), DENY);
        }
    }

    #[test]
    fn ordinary_elf_file_memory_thread_and_bwrap_final_operations_are_allowed() {
        for nr in [
            libc::SYS_openat,
            libc::SYS_newfstatat,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_brk,
            libc::SYS_futex,
            libc::SYS_set_robust_list,
            libc::SYS_set_tid_address,
            libc::SYS_rseq,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_wait4,
            libc::SYS_close,
            libc::SYS_close_range,
            libc::SYS_pipe2,
            libc::SYS_getrandom,
            libc::SYS_clock_gettime,
            libc::SYS_mkdirat,
            libc::SYS_unlinkat,
            libc::SYS_exit_group,
        ] {
            assert_eq!(verdict(nr, [0; 6]), ALLOW, "syscall {nr}");
        }
    }

    #[test]
    fn filter_memfd_is_sealed_rewound_and_contains_the_emitted_program() {
        let mut file = sealed_filter().unwrap();
        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        assert_eq!(
            seals,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL
        );
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let program = filter_program();
        assert_eq!(bytes.len(), program.len() * 8);
        let decoded: Vec<_> = bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|word| libc::sock_filter {
                code: u16::from_ne_bytes(word[..2].try_into().unwrap()),
                jt: word[2],
                jf: word[3],
                k: u32::from_ne_bytes(word[4..8].try_into().unwrap()),
            })
            .collect();
        assert_eq!(interpret(&decoded, NATIVE_ARCH, 999_999, [0; 6]), ENOSYS);
        let byte = 0_u8;
        assert_eq!(
            unsafe { libc::pwrite(file.as_raw_fd(), (&byte as *const u8).cast(), 1, 0) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }
}
