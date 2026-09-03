//! The one thing the daemon does to nftables: put its fast-allow mark into
//! the `fast_allow` set the snippet declares empty, and take it out again.
//!
//! Until this module existed the daemon never wrote to the ruleset. It sat on
//! the far end of NFQUEUE 0 and `colony-firewall-nft.service` owned every
//! rule; that boundary was kept on purpose. It moves for exactly one reason,
//! given in full in [`cfc_ebpf_common::fast_allow`]: the mark the connect
//! hooks set must be a per-start random value, so it cannot be a literal in
//! the snippet, so something at runtime has to tell nftables what it is. This
//! is that something, and it is kept to two statements: `add element` when
//! the fast path comes up, `flush set` at every start and at shutdown.
//!
//! # Why a child process
//!
//! `nft(8)` is run as a child, the way the provenance backend runs `rpm -qa`,
//! and with the same discipline: a fixed program path, a deadline with a kill
//! behind it, `LC_ALL=C`, stderr captured into the error and never parsed as
//! data. The alternative - speaking nf_tables netlink from the daemon - is a
//! batching protocol with its own cache semantics, for two statements the
//! package already `Requires: nftables` to make. One fork at start and one at
//! stop, both off the packet path.
//!
//! # What this module refuses to do
//!
//! Create the table or the set. Those belong to the snippet and its unit; a
//! daemon that made them on demand would be a daemon that quietly builds a
//! ruleset nobody loaded, and on a host without the snippet that ruleset
//! would be a fail-closed table with the wrong owner. A missing set is
//! reported as exactly that, with the fix. A missing table is reported as the
//! ordering it usually is: `colony-firewall-nft.service` is `After=` the
//! daemon, so at daemon start the table is normally not there *yet*, and at
//! stop (`PartOf=`) it is normally already gone. [`Absent`] tells the two
//! apart so the loader can retry the first, and [`disarm`] treats both as
//! nothing left to flush.
//!
//! # The value is a secret
//!
//! A forger holding `CAP_NET_RAW` but not `CAP_NET_ADMIN` can read neither the
//! ruleset nor the BPF map, and that is the whole argument for a random value.
//! The journal and `cfc status` are readable by more people than the ruleset
//! is, so the mark never appears in a log line or an error: nft echoes the
//! failing command back on stderr, and that echo is redacted before it goes
//! anywhere.

// The only caller is the loader, which is behind the `ebpf` feature. The
// module itself stays in every build so its tests run in the default suite,
// for the same reason `tracefs` does.
#![cfg_attr(not(feature = "ebpf"), allow(dead_code))]

use std::fmt;
use std::io::Read as _;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use cfc_ebpf_common::fast_allow;
use tracing::debug;

/// The family and table the snippet declares, and the set inside it. Named
/// once here and spelled into every command, so a rename in the snippet fails
/// the `list set` probe rather than silently arming nothing.
const FAMILY: &str = "inet";
const TABLE: &str = "colony_firewall";
const SET: &str = "fast_allow";

/// Where `nft` is looked for, first hit wins. Fixed paths rather than a
/// `PATH` search: this child runs as root with `CAP_NET_ADMIN`, and which
/// binary that is should not depend on an environment variable. `/usr/sbin`
/// first because on RHEL 9 it is the only spelling; Fedora 42+ and Arch
/// merged sbin into bin, and there both names resolve to the same file.
const NFT_CANDIDATES: [&str; 2] = ["/usr/sbin/nft", "/usr/bin/nft"];

/// How long one nft command is given before it is killed.
///
/// nft holds the nf_tables transaction lock for the length of its batch, and
/// waits for it when another process - a large `nft -f`, a container runtime
/// rewriting its chains - holds it first. A daemon that hangs at start or
/// stop behind that lock is worse than one whose fast path stays off, and at
/// shutdown a hang here would run into the unit's stop timeout. Five seconds
/// is far past any healthy command and far short of that timeout.
const NFT_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the deadline is re-checked while waiting; same value and same
/// reasoning as the rpm query's.
const NFT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Adds `mark` to `set fast_allow` in `table inet colony_firewall`.
///
/// Errors when the set does not exist (a snippet that predates it), when the
/// table is not loaded, when `nft` is missing, or when the command fails; the
/// loader turns any error into `FastAllow::Off(reason)` and never arms the
/// kernel side without it. The first two are an [`Absent`], reachable through
/// `downcast_ref`, because one of them is the normal state right after
/// startup and deserves a retry rather than a reason.
///
/// Refuses [`fast_allow::UNARMED`] outright: zero is the mark every socket
/// carries when nothing has marked it, and a zero element in the set would
/// accept every unmarked packet on the machine.
pub(super) fn arm(mark: u32) -> anyhow::Result<()> {
    if mark == fast_allow::UNARMED {
        bail!(
            "refusing to arm the fast path with mark {}: that is the mark of every \
             socket nothing has marked, and accepting it would accept everything",
            mark_literal(mark)
        );
    }
    match run(Op::ListSet) {
        Ok(()) => {}
        Err(failed) if failed.is_no_such_object() => {
            // Table or set? nft says "No such file or directory" for both and
            // only moves the caret. One more probe tells them apart, and it
            // runs on this path alone.
            let absent = match run(Op::ListTable) {
                Ok(()) => Absent::Set,
                Err(failed) if failed.is_no_such_object() => Absent::Table,
                Err(failed) => return Err(failed.into_error(Op::ListTable)),
            };
            return Err(anyhow::Error::new(absent));
        }
        Err(failed) => return Err(failed.into_error(Op::ListSet)),
    }
    let op = Op::AddElement(mark);
    run(op).map_err(|failed| failed.into_error(op))?;
    debug!("fast-allow mark added to set {FAMILY} {TABLE} {SET}");
    Ok(())
}

/// Flushes `set fast_allow`, so that no value (this daemon's or a previous
/// one's) is accepted by the ruleset. Called at every start before arming,
/// and at shutdown.
///
/// A missing table or a missing set is success: there is nothing in either
/// that could accept a mark, and at shutdown the table is usually already
/// gone - `colony-firewall-nft.service` is `PartOf=` the daemon and stops
/// first.
pub(super) fn disarm() -> anyhow::Result<()> {
    match run(Op::FlushSet) {
        Ok(()) => {
            debug!("fast-allow set flushed");
            Ok(())
        }
        Err(failed) if failed.is_no_such_object() => {
            debug!("fast-allow set not present, nothing to flush");
            Ok(())
        }
        Err(failed) => Err(failed.into_error(Op::FlushSet)),
    }
}

/// Why [`arm`] found nothing to arm.
///
/// Returned as the error itself rather than as context, so the loader can
/// `downcast_ref::<Absent>()` and treat the two differently: a missing table
/// is the expected state right after the daemon starts (the nft unit is
/// ordered after it) and is worth retrying; a missing set will not fix itself
/// and names its fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Absent {
    /// `table inet colony_firewall` is not loaded.
    Table,
    /// The table is loaded but carries no `fast_allow` set.
    Set,
}

impl fmt::Display for Absent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Absent::Table => write!(
                f,
                "table {FAMILY} {TABLE} is not loaded, so there is no {SET} set to arm; \
                 colony-firewall-nft.service loads it once the daemon is up"
            ),
            Absent::Set => write!(
                f,
                "the loaded nftables snippet predates {SET}; reinstall \
                 systemd/nftables-snippet.conf and restart colony-firewall-nft.service"
            ),
        }
    }
}

impl std::error::Error for Absent {}

/// The commands this module issues. Three do the work; `ListTable` exists
/// only to say which of two things is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `nft list set inet colony_firewall fast_allow`: does the set exist?
    /// Its output is discarded; the exit status is the answer.
    ListSet,
    /// `nft list table inet colony_firewall`, run only after `ListSet` failed.
    ListTable,
    /// `nft add element inet colony_firewall fast_allow { 0x<mark> }`.
    AddElement(u32),
    /// `nft flush set inet colony_firewall fast_allow`.
    FlushSet,
}

/// The argument vector for `op`, without the program.
///
/// Pure, and the part of this module that is tested without nft: what the
/// tests pin is that every command names the snippet's table and set, and
/// that the mark is spelled one way.
fn argv(op: Op) -> Vec<String> {
    let words: &[&str] = match op {
        Op::ListSet => &["list", "set", FAMILY, TABLE, SET],
        Op::ListTable => &["list", "table", FAMILY, TABLE],
        Op::AddElement(_) => &["add", "element", FAMILY, TABLE, SET],
        Op::FlushSet => &["flush", "set", FAMILY, TABLE, SET],
    };
    let mut argv: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    if let Op::AddElement(mark) = op {
        argv.push(format!("{{ {} }}", mark_literal(mark)));
    }
    argv
}

/// The mark as a `type mark` element: `0x` and exactly eight hex digits.
///
/// One fixed spelling, because nft echoes the failing command line back on
/// stderr verbatim and [`redact`] removes the literal by exact match; a
/// literal that could be spelled two ways could be leaked one of them.
fn mark_literal(mark: u32) -> String {
    format!("0x{mark:08x}")
}

/// One nft command that did not succeed.
enum Failed {
    /// nft ran to completion and said no. `stderr` is what it said: an
    /// `Error:` line, the command echoed back, a caret under the offending
    /// word.
    Nft { status: ExitStatus, stderr: String },
    /// nft could not be found or spawned, or overran [`NFT_TIMEOUT`].
    Run(anyhow::Error),
}

impl Failed {
    /// Whether nft said that the table or the set the command named does not
    /// exist. Both are `ENOENT`, and nft renders errno as `strerror` text;
    /// `LC_ALL=C` keeps that text English.
    fn is_no_such_object(&self) -> bool {
        matches!(self, Failed::Nft { stderr, .. } if stderr_names_no_such_object(stderr))
    }

    /// Folds into an error whose text is safe to log: the mark is redacted
    /// from the command line and from nft's echo of it.
    fn into_error(self, op: Op) -> anyhow::Error {
        let command = redact(op, format!("nft {}", argv(op).join(" ")));
        match self {
            Failed::Nft { status, stderr } => {
                anyhow!("{command} failed ({status}): {}", redact(op, stderr).trim())
            }
            Failed::Run(e) => e.context(format!("running {command}")),
        }
    }
}

/// The `strerror(ENOENT)` text nft prints for an object that does not exist,
/// identically for a table and for a set. Observed with nftables 1.1.7 - the
/// fixtures in the tests are its verbatim output. Deliberately not tied to
/// the caret line, whose layout is nft's to change.
fn stderr_names_no_such_object(stderr: &str) -> bool {
    stderr.contains("No such file or directory")
}

/// Replaces the mark literal with a placeholder. Only [`Op::AddElement`]
/// carries the mark; every other command's text is returned as it is.
fn redact(op: Op, text: String) -> String {
    match op {
        Op::AddElement(mark) => text.replace(&mark_literal(mark), "<mark>"),
        _ => text,
    }
}

/// The first of [`NFT_CANDIDATES`] that exists.
fn locate_nft() -> anyhow::Result<&'static str> {
    NFT_CANDIDATES
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| {
            anyhow!(
                "nft not found at {} (the package requires nftables, and without it \
                 colony-firewall-nft.service could not have loaded the table either)",
                NFT_CANDIDATES.join(" or ")
            )
        })
}

/// Runs one command to completion under [`NFT_TIMEOUT`].
///
/// stdout is discarded - nothing here parses nft's output, and the probe
/// wants only an exit status. stderr is read on its own thread while the
/// child runs, so an unexpectedly chatty nft cannot fill the pipe and
/// deadlock against a parent that waits before it reads.
fn run(op: Op) -> Result<(), Failed> {
    let program = locate_nft().map_err(Failed::Run)?;
    let mut child = Command::new(program)
        .args(argv(op))
        // errno text is matched (see `stderr_names_no_such_object`); a
        // translated "No such file or directory" would defeat that.
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Failed::Run(anyhow::Error::new(e).context(format!("spawning {program}"))))?;

    let mut stderr = child.stderr.take().expect("stderr was piped");
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stderr
            .read_to_end(&mut buf)
            .map(|_| String::from_utf8_lossy(&buf).into_owned())
    });

    let deadline = Instant::now() + NFT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                return Err(Failed::Run(
                    anyhow::Error::new(e).context("waiting for nft"),
                ))
            }
        }
        if Instant::now() >= deadline {
            // Killing closes the pipe, which ends the reader thread on its
            // own; nothing waits on it because there is nothing it could add.
            let _ = child.kill();
            let _ = child.wait();
            return Err(Failed::Run(anyhow!(
                "nft did not finish within {NFT_TIMEOUT:?} (another process may be \
                 holding the nftables transaction lock)"
            )));
        }
        std::thread::sleep(NFT_POLL_INTERVAL);
    };
    let stderr = reader
        .join()
        .map_err(|_| Failed::Run(anyhow!("nft stderr reader panicked")))?
        .map_err(|e| Failed::Run(anyhow::Error::new(e).context("reading nft stderr")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failed::Nft { status, stderr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;

    // Verbatim stderr of nftables 1.1.7, captured in a throwaway network
    // namespace. The first line is the same in every case; only the caret
    // moves, from under the table name to under the set name.
    const NO_TABLE_LIST: &str = "Error: No such file or directory\nlist set inet colony_firewall fast_allow\n              ^^^^^^^^^^^^^^^\n";
    const NO_SET_FLUSH: &str = "Error: No such file or directory\nflush set inet colony_firewall fast_allow\n                               ^^^^^^^^^^\n";
    const NO_SET_ADD: &str = "Error: No such file or directory\nadd element inet colony_firewall fast_allow { 0x1234abcd }\n                                 ^^^^^^^^^^\n";
    const SYNTAX_ERROR: &str = "Error: syntax error, unexpected newline\nexpected any of: <string>, last\nlist set inet colony_firewall\n                             ^\n";
    const NOT_PERMITTED: &str = "Error: Operation not permitted\nlist set inet colony_firewall fast_allow\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";

    fn exit_status(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn add_element_spells_the_mark_as_eight_hex_digits() {
        assert_eq!(
            argv(Op::AddElement(0x1234_abcd)),
            [
                "add",
                "element",
                "inet",
                "colony_firewall",
                "fast_allow",
                "{ 0x1234abcd }"
            ]
        );
        // A small value is padded rather than shortened: one spelling only,
        // which is what makes the redaction an exact match.
        assert_eq!(argv(Op::AddElement(7)).last().unwrap(), "{ 0x00000007 }");
        assert_eq!(mark_literal(u32::MAX), "0xffffffff");
    }

    #[test]
    fn every_set_command_names_the_snippets_table_and_set() {
        for op in [Op::ListSet, Op::AddElement(1), Op::FlushSet] {
            let argv = argv(op);
            assert_eq!(
                &argv[2..5],
                ["inet", "colony_firewall", "fast_allow"],
                "{op:?} does not address the snippet's set"
            );
        }
        assert_eq!(
            argv(Op::ListTable),
            ["list", "table", "inet", "colony_firewall"]
        );
    }

    #[test]
    fn list_and_flush_use_the_verbs_nft_understands() {
        assert_eq!(
            argv(Op::ListSet),
            ["list", "set", "inet", "colony_firewall", "fast_allow"]
        );
        assert_eq!(
            argv(Op::FlushSet),
            ["flush", "set", "inet", "colony_firewall", "fast_allow"]
        );
    }

    #[test]
    fn a_missing_table_and_a_missing_set_both_read_as_absent() {
        for stderr in [NO_TABLE_LIST, NO_SET_FLUSH, NO_SET_ADD] {
            assert!(
                stderr_names_no_such_object(stderr),
                "not classified as absent:\n{stderr}"
            );
            let failed = Failed::Nft {
                status: exit_status(1),
                stderr: stderr.to_string(),
            };
            assert!(failed.is_no_such_object());
        }
    }

    #[test]
    fn other_failures_do_not_read_as_absent() {
        for stderr in [SYNTAX_ERROR, NOT_PERMITTED, ""] {
            assert!(
                !stderr_names_no_such_object(stderr),
                "wrongly classified as absent:\n{stderr}"
            );
        }
        // A spawn failure is not nft saying anything, whatever its text.
        let failed = Failed::Run(anyhow!("No such file or directory"));
        assert!(!failed.is_no_such_object());
    }

    #[test]
    fn the_unarmed_value_is_refused_before_nft_runs() {
        // Zero is what every unmarked socket reads; accepting it would accept
        // everything. This must fail on a machine without nft, which is why
        // the guard comes before any command is built.
        let e = arm(fast_allow::UNARMED).expect_err("mark 0 must be refused");
        assert!(e.to_string().contains("0x00000000"), "{e}");
    }

    #[test]
    fn an_add_element_failure_never_names_the_mark() {
        let mark = 0x1234_abcd;
        let failed = Failed::Nft {
            status: exit_status(1),
            stderr: NO_SET_ADD.to_string(),
        };
        let text = format!("{:#}", failed.into_error(Op::AddElement(mark)));
        assert!(!text.contains("1234abcd"), "leaked: {text}");
        assert!(text.contains("<mark>"), "{text}");
        assert!(text.contains("exit status: 1"), "{text}");

        let failed = Failed::Run(anyhow!("spawning /usr/sbin/nft: permission denied"));
        let text = format!("{:#}", failed.into_error(Op::AddElement(mark)));
        assert!(!text.contains("1234abcd"), "leaked: {text}");
        assert!(text.contains("<mark>"), "{text}");
    }

    #[test]
    fn absent_names_its_fix_and_survives_the_error_chain() {
        let set = Absent::Set.to_string();
        assert!(set.contains("nftables-snippet.conf"), "{set}");
        assert!(set.contains("colony-firewall-nft.service"), "{set}");
        let table = Absent::Table.to_string();
        assert!(table.contains("not loaded"), "{table}");
        assert!(table.contains("colony-firewall-nft.service"), "{table}");

        // What the loader relies on to tell "retry" from "operator".
        let e = anyhow::Error::new(Absent::Table);
        assert_eq!(e.downcast_ref::<Absent>(), Some(&Absent::Table));
    }
}
