//! The daemon's two questions for nftables: is `table inet colony_firewall`
//! loaded, and, once at start, flush the legacy `fast_allow` set.
//!
//! The daemon does not write the ruleset. It sits on the far end of NFQUEUE 0
//! and `colony-firewall-nft.service` owns every rule. The flush is the one
//! exception, and it is a removal: Fast Allow (0.4.0 to 0.6) put a per-start
//! random mark into that set, and a daemon that crashed while armed left it
//! there, accepted by a ruleset nothing reloaded. Fast Allow is gone; the
//! flush stays until no supported upgrade path starts from a release that had
//! it.
//!
//! # Why a child process
//!
//! `nft(8)` is run as a child, the way the provenance backend runs `rpm -qa`,
//! and with the same discipline: a fixed program path, a deadline with a kill
//! behind it, `LC_ALL=C`, stderr captured into the error and never parsed as
//! data. Speaking nf_tables netlink from the daemon would be a batching
//! protocol with its own cache semantics, for two commands the package
//! already `Requires: nftables` to make. One fork at start and one a minute
//! for the probe, both off the packet path.

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use tracing::debug;

/// The family and table the snippet declares, and the legacy set inside it.
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
/// rewriting its chains - holds it first. A daemon that hangs at start behind
/// that lock is worse than one whose legacy flush is logged as failed. Five
/// seconds is far past any healthy command and far short of the unit's
/// start timeout.
const NFT_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the deadline is re-checked while waiting; same value and same
/// reasoning as the rpm query's.
const NFT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Whether `table inet colony_firewall` is loaded at all.
///
/// This is the question `cfc status`'s `enforcing` is really asking. Without
/// the table nothing reaches NFQUEUE, so nothing is filtered - and that state
/// is invisible from inside the daemon, which simply sees no packets. An idle
/// machine also sees no packets, which is why the packet counter alone cannot
/// tell the two apart and this probe exists.
///
/// A missing table answers `false`, not an error; anything else - nft absent,
/// the transaction lock held, a permission failure - is an error, because
/// "could not ask" and "asked and it is gone" must not read the same. The
/// caller keeps its previous answer on an error rather than claiming the
/// firewall vanished because a fork failed.
pub(super) fn table_loaded() -> anyhow::Result<bool> {
    let op = Op::ListTable;
    match run(op) {
        Ok(()) => Ok(true),
        Err(failed) if failed.is_no_such_object() => Ok(false),
        Err(failed) => Err(failed.into_error(op)),
    }
}

/// Flushes the legacy `set fast_allow`, so that no mark an older daemon left
/// there is accepted by the ruleset.
///
/// A missing table or a missing set is success: there is nothing in either
/// that could accept a mark. At boot `colony-firewall-nft.service` is ordered
/// before the daemon, so the table is normally loaded and this empties the set
/// it still declares.
pub(super) fn flush() -> anyhow::Result<()> {
    match run(Op::FlushSet) {
        Ok(()) => {
            debug!("legacy fast_allow set flushed");
            Ok(())
        }
        Err(failed) if failed.is_no_such_object() => {
            debug!("legacy fast_allow set not present, nothing to flush");
            Ok(())
        }
        Err(failed) => Err(failed.into_error(Op::FlushSet)),
    }
}

/// The commands this module issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `nft list table inet colony_firewall`: is the table loaded? Its output
    /// is discarded; the exit status is the answer.
    ListTable,
    /// `nft flush set inet colony_firewall fast_allow`.
    FlushSet,
}

/// The argument vector for `op`, without the program.
fn argv(op: Op) -> Vec<String> {
    let words: &[&str] = match op {
        Op::ListTable => &["list", "table", FAMILY, TABLE],
        Op::FlushSet => &["flush", "set", FAMILY, TABLE, SET],
    };
    words.iter().map(|w| w.to_string()).collect()
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

    fn into_error(self, op: Op) -> anyhow::Error {
        let command = format!("nft {}", argv(op).join(" "));
        match self {
            Failed::Nft { status, stderr } => {
                anyhow!("{command} failed ({status}): {}", stderr.trim())
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
    const SYNTAX_ERROR: &str = "Error: syntax error, unexpected newline\nexpected any of: <string>, last\nlist set inet colony_firewall\n                             ^\n";
    const NOT_PERMITTED: &str = "Error: Operation not permitted\nlist set inet colony_firewall fast_allow\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";

    fn exit_status(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn list_and_flush_use_the_verbs_nft_understands() {
        assert_eq!(
            argv(Op::ListTable),
            ["list", "table", "inet", "colony_firewall"]
        );
        assert_eq!(
            argv(Op::FlushSet),
            ["flush", "set", "inet", "colony_firewall", "fast_allow"]
        );
    }

    #[test]
    fn a_missing_table_and_a_missing_set_both_read_as_absent() {
        for stderr in [NO_TABLE_LIST, NO_SET_FLUSH] {
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
}
