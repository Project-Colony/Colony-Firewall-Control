//! Reading tracepoint record layout out of tracefs, so the kernel side does
//! not have to guess it.
//!
//! The `sched_process_exec` tracepoint carries the executed path as a
//! `__data_loc` field: a `u32` holding `(length << 16) | offset`, with the
//! offset relative to the start of the record. To find that word the program
//! needs to know where the field itself lives, and that is what tracefs
//! publishes:
//!
//! ```text
//! name: sched_process_exec
//! ID: 314
//! format:
//!         field:unsigned short common_type;         offset:0;  size:2;  signed:0;
//!         field:unsigned char common_flags;         offset:2;  size:1;  signed:0;
//!         field:unsigned char common_preempt_count; offset:3;  size:1;  signed:0;
//!         field:int common_pid;                     offset:4;  size:4;  signed:1;
//!
//!         field:__data_loc char[] filename;         offset:8;  size:4;  signed:0;
//!         field:pid_t pid;                          offset:12; size:4;  signed:1;
//! ```
//!
//! It has been 8 on every kernel this has run on, and the `common_*` header is
//! about as stable as anything in the tracepoint ABI. It is parsed anyway
//! because the cost of being wrong is invisible: reading four bytes of some
//! *other* field, decoding them as `(len << 16) | offset`, and copying a
//! plausible-looking path out of the middle of the record. Nothing downstream
//! can tell that apart from a real filename, so it would surface as a firewall
//! attributing connections to a program that does not exist.
//!
//! # Why this and not `tp_btf`
//!
//! A BTF-powered raw tracepoint sidesteps the format file entirely - it gets
//! `bprm->filename` straight from the kernel's own type information. It was
//! rejected because it makes BTF **mandatory** for the exec *and* exit
//! programs, where today BTF is optional and its absence costs only `ppid`. A
//! kernel built without `CONFIG_DEBUG_INFO_BTF` would go from "process
//! tracking, minus parent pids" to "no process tracking", which is a strange
//! trade for a change whose whole purpose is to widen the set of machines that
//! work. Its residual assumption - that `bprm` is raw-tracepoint argument 2 -
//! is also an undocumented internal detail whose failure mode is the same
//! silent wrong answer.
//!
//! Reading the format file adds no new dependency either: aya already reads
//! `<tracefs>/events/sched/sched_process_exec/id` to attach at all, a sibling
//! of `format` in the same directory. If `format` cannot be read, there is no
//! attached program for the offset to matter to.

use std::path::{Path, PathBuf};

/// Candidate tracefs mount points, in the order aya tries them.
///
/// Kept deliberately identical to aya's own `lib/aya/src/util.rs`
/// (`tracefs_path`): parsing a *different* mount than the one aya attaches
/// through would resolve the offset from one kernel interface and apply it to
/// another.
const TRACEFS_CANDIDATES: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// What the format file says about the `filename` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// A `__data_loc` field of the expected width, at this byte offset.
    Parsed(u32),
    /// The field exists but this program cannot read it: `__rel_loc` (whose
    /// offset is relative to the field, not the record) or a width other than
    /// 4. The kernel side must be told to skip the filename entirely rather
    /// than read the field it does not understand.
    Unsupported,
}

#[derive(Debug)]
pub enum TracefsError {
    /// No tracefs mount, or an empty one.
    NotMounted,
    /// The format file could not be read.
    Unreadable(std::io::Error),
    /// The file parsed, but has no `filename` field at all.
    NoSuchField,
}

impl std::fmt::Display for TracefsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotMounted => write!(
                f,
                "no tracefs mount at {} or {}",
                TRACEFS_CANDIDATES[0], TRACEFS_CANDIDATES[1]
            ),
            Self::Unreadable(e) => write!(f, "reading the tracepoint format file: {e}"),
            Self::NoSuchField => write!(f, "the format file declares no `filename` field"),
        }
    }
}

impl std::error::Error for TracefsError {}

/// Locates the tracefs mount, or `None`.
///
/// Mirrors aya's predicate: the directory must exist *and* be non-empty. A
/// bare mount point with nothing under it is what an unmounted tracefs looks
/// like, and treating it as present would send the parse at a path that
/// cannot answer.
pub fn find_tracefs() -> Option<PathBuf> {
    TRACEFS_CANDIDATES
        .iter()
        .map(Path::new)
        .find(|dir| {
            dir.is_dir()
                && std::fs::read_dir(dir)
                    .map(|mut entries| entries.next().is_some())
                    .unwrap_or(false)
        })
        .map(Path::to_path_buf)
}

/// Reads and parses `sched_process_exec`'s format file from the live system.
pub fn exec_filename_offset() -> Result<Resolution, TracefsError> {
    let tracefs = find_tracefs().ok_or(TracefsError::NotMounted)?;
    let path = tracefs.join("events/sched/sched_process_exec/format");
    let text = std::fs::read_to_string(&path).map_err(TracefsError::Unreadable)?;
    parse_exec_filename_offset(&text)
}

/// Byte offset of `group_dead` in `sched_process_exit`'s record.
///
/// `group_dead` is the kernel telling us the *process* is gone, as opposed to
/// one of its threads. Nothing else in the record says that, and the obvious
/// substitute - "the exiting task is the thread-group leader" - is wrong in
/// both directions: a leader can exit first via `pthread_exit()` while its
/// workers keep running, and a worker can be the last thread out.
///
/// `None` when the field is absent or not a 1-byte bool, which is how a kernel
/// too old to carry it reports itself.
pub fn exit_group_dead_offset() -> Result<Option<u32>, TracefsError> {
    let tracefs = find_tracefs().ok_or(TracefsError::NotMounted)?;
    let path = tracefs.join("events/sched/sched_process_exit/format");
    let text = std::fs::read_to_string(&path).map_err(TracefsError::Unreadable)?;
    Ok(parse_exit_group_dead_offset(&text))
}

/// The parser, split out so it can be tested against fixture text.
///
/// Keyed on the field name and its declared width. A `group_dead` that is not
/// a 1-byte bool is one this program does not know how to read, and reading it
/// wrong would evict verdicts for processes that are still running.
pub fn parse_exit_group_dead_offset(text: &str) -> Option<u32> {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("field:") else {
            continue;
        };
        let mut decl = None;
        let mut offset = None;
        let mut size = None;
        for part in rest.split(';') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("offset:") {
                offset = v.trim().parse::<u32>().ok();
            } else if let Some(v) = part.strip_prefix("size:") {
                size = v.trim().parse::<u32>().ok();
            } else if !part.is_empty() && decl.is_none() {
                decl = Some(part);
            }
        }
        let Some(decl) = decl else { continue };
        // `bool group_dead` - match the name at the end of the declaration so a
        // differently-spelled type still resolves.
        if decl.split_whitespace().last() != Some("group_dead") {
            continue;
        }
        return match (offset, size) {
            (Some(off), Some(1)) => Some(off),
            _ => None,
        };
    }
    None
}

/// The parser, split out so it can be tested against fixture text.
///
/// Keyed on the field **name**, not on "the first `__data_loc`". Those happen
/// to coincide on today's kernels, and would stop coinciding the moment a
/// variable-length field is added ahead of `filename` - which is exactly the
/// class of change this whole exercise exists to survive.
pub fn parse_exec_filename_offset(text: &str) -> Result<Resolution, TracefsError> {
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("field:") else {
            continue;
        };
        // `field:<type and name>;\toffset:N;\tsize:M;\tsigned:S;`
        let mut parts = rest.split(';').map(str::trim);
        let Some(decl) = parts.next() else {
            continue;
        };
        if !declares_filename(decl) {
            continue;
        }

        let offset = parts.clone().find_map(|p| p.strip_prefix("offset:"));
        let size = parts.find_map(|p| p.strip_prefix("size:"));
        let (Some(offset), Some(size)) = (offset, size) else {
            // The field is there but the line is not shaped like a field line.
            // Refuse rather than guess.
            return Ok(Resolution::Unsupported);
        };
        let (Ok(offset), Ok(size)) = (offset.trim().parse::<u32>(), size.trim().parse::<u32>())
        else {
            return Ok(Resolution::Unsupported);
        };

        // `__rel_loc` encodes its offset relative to the field rather than to
        // the record. The kernel side does not implement that, so say so
        // instead of handing back a number it would misuse.
        if !decl.contains("__data_loc") || size != 4 {
            return Ok(Resolution::Unsupported);
        }
        return Ok(Resolution::Parsed(offset));
    }
    Err(TracefsError::NoSuchField)
}

/// Whether a field declaration names the field `filename`.
///
/// The declaration is a C-ish type followed by the name, e.g.
/// `__data_loc char[] filename`. Matching on the last whitespace-separated
/// token avoids matching `filename` inside a type, and avoids matching a
/// different field whose *type* mentions it.
fn declares_filename(decl: &str) -> bool {
    decl.split_whitespace()
        .next_back()
        .map(|name| name.trim_end_matches("[]") == "filename")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real thing, from kernel 7.1.8.
    const REAL: &str = "\
name: sched_process_exec
ID: 314
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:pid_t old_pid;\toffset:16;\tsize:4;\tsigned:1;

print fmt: \"filename=%s pid=%d old_pid=%d\", __get_str(filename), REC->pid, REC->old_pid
";

    #[test]
    fn parses_a_real_format_file() {
        assert_eq!(
            parse_exec_filename_offset(REAL).unwrap(),
            Resolution::Parsed(8)
        );
    }

    #[test]
    fn follows_the_offset_when_the_header_grows() {
        // The whole reason this is parsed rather than assumed: two more
        // `common_*` fields push `filename` along, and the compiled-in 8 would
        // then point at `common_pid`.
        let grown = REAL
            .replace(
                "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;",
                "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
                 \tfield:int common_future;\toffset:8;\tsize:4;\tsigned:1;",
            )
            .replace(
                "char[] filename;\toffset:8;",
                "char[] filename;\toffset:12;",
            );
        assert_eq!(
            parse_exec_filename_offset(&grown).unwrap(),
            Resolution::Parsed(12)
        );
    }

    #[test]
    fn keys_on_the_field_name_not_on_the_first_data_loc() {
        // A variable-length field ahead of `filename` must not be mistaken for
        // it. Matching "the first __data_loc" would return 8 here and read the
        // wrong string forever.
        let with_earlier = REAL.replace(
            "\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;",
            "\tfield:__data_loc char[] cgroup;\toffset:8;\tsize:4;\tsigned:0;\n\
             \tfield:__data_loc char[] filename;\toffset:12;\tsize:4;\tsigned:0;",
        );
        assert_eq!(
            parse_exec_filename_offset(&with_earlier).unwrap(),
            Resolution::Parsed(12)
        );
    }

    #[test]
    fn rel_loc_is_unsupported_not_parsed() {
        // `__rel_loc` offsets are relative to the field, not the record. The
        // kernel side does not implement that, and returning Parsed(8) here
        // would make it read from the wrong place with full confidence.
        let rel = REAL.replace("__data_loc char[] filename", "__rel_loc char[] filename");
        assert_eq!(
            parse_exec_filename_offset(&rel).unwrap(),
            Resolution::Unsupported
        );
    }

    #[test]
    fn an_unexpected_width_is_unsupported() {
        let wide = REAL.replace(
            "char[] filename;\toffset:8;\tsize:4;",
            "char[] filename;\toffset:8;\tsize:8;",
        );
        assert_eq!(
            parse_exec_filename_offset(&wide).unwrap(),
            Resolution::Unsupported
        );
    }

    #[test]
    fn a_missing_field_is_an_error_not_a_guess() {
        let without = REAL.replace(
            "\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;\n",
            "",
        );
        assert!(matches!(
            parse_exec_filename_offset(&without),
            Err(TracefsError::NoSuchField)
        ));
    }

    #[test]
    fn garbage_never_panics() {
        // Fed anything at all, this must return, not unwind. It runs while the
        // daemon is starting up.
        for text in [
            "",
            "field:",
            "field:;;;;",
            "field:__data_loc char[] filename;",
            "field:__data_loc char[] filename;\toffset:;\tsize:;",
            "field:__data_loc char[] filename;\toffset:notanumber;\tsize:4;",
            "\0\0\0\0",
            &"field:x;".repeat(10_000),
        ] {
            let _ = parse_exec_filename_offset(text);
        }
    }

    #[test]
    fn does_not_match_a_field_whose_type_mentions_filename() {
        let decoy = REAL.replace(
            "\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;",
            "\tfield:struct filename * something;\toffset:8;\tsize:8;\tsigned:0;\n\
             \tfield:__data_loc char[] filename;\toffset:16;\tsize:4;\tsigned:0;",
        );
        assert_eq!(
            parse_exec_filename_offset(&decoy).unwrap(),
            Resolution::Parsed(16)
        );
    }

    /// Against the running kernel. Ignored by default because it asserts about
    /// the machine rather than about the code; run it with `--ignored` to check
    /// a new kernel.
    #[test]
    #[ignore = "reads /sys/kernel/tracing; run explicitly"]
    fn resolves_on_this_kernel() {
        match exec_filename_offset() {
            Ok(r) => println!("this kernel: {r:?}"),
            Err(e) => panic!("could not resolve: {e}"),
        }
    }
}

#[cfg(test)]
mod group_dead_tests {
    use super::*;

    /// The real record from a 7.1 kernel.
    const REAL: &str = "\
name: sched_process_exit
ID: 307
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:char comm[16];\toffset:8;\tsize:16;\tsigned:0;
\tfield:pid_t pid;\toffset:24;\tsize:4;\tsigned:1;
\tfield:int prio;\toffset:28;\tsize:4;\tsigned:1;
\tfield:bool group_dead;\toffset:32;\tsize:1;\tsigned:0;
";

    #[test]
    fn finds_group_dead_in_a_real_record() {
        assert_eq!(parse_exit_group_dead_offset(REAL), Some(32));
    }

    /// A kernel too old to carry the field. The caller must fall back rather
    /// than read a byte at a guessed offset.
    #[test]
    fn absent_field_resolves_to_none() {
        let older = REAL
            .lines()
            .filter(|l| !l.contains("group_dead"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse_exit_group_dead_offset(&older), None);
    }

    /// A `group_dead` that is not a 1-byte bool is one this program cannot
    /// read. Reading it anyway would evict verdicts for live processes.
    #[test]
    fn a_field_of_the_wrong_width_is_refused() {
        let odd = REAL.replace("size:1;\tsigned:0;\n", "size:4;\tsigned:0;\n");
        assert_eq!(parse_exit_group_dead_offset(&odd), None);
    }

    /// The offset must come from the field named `group_dead`, not from
    /// whatever happens to sit at 32 in some other kernel's layout.
    #[test]
    fn a_reordered_record_still_resolves_by_name() {
        let moved = REAL.replace(
            "\tfield:bool group_dead;\toffset:32;\tsize:1;\tsigned:0;",
            "\tfield:int extra;\toffset:32;\tsize:4;\tsigned:1;\n\tfield:bool group_dead;\toffset:36;\tsize:1;\tsigned:0;",
        );
        assert_eq!(parse_exit_group_dead_offset(&moved), Some(36));
    }
}
