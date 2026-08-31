//! Resolving an executable path to the form the kernel will report it in.
//!
//! # Why this exists
//!
//! Rule matching is exact `PathBuf` equality (`RuleScope::matches_process`),
//! and the process side of that comparison comes from `/proc/<pid>/exe` — which
//! the kernel resolves for us: symlinks followed, `.`/`..` gone, the real
//! inode's path. So the two sides can only disagree because of what a *human*
//! typed on the rule side.
//!
//! That disagreement is silent and total. A rule for `/bin/curl` on a
//! usr-merged host, where `/bin` is a symlink to `usr/bin`, shows up in
//! `cfc rules list`, ranks by specificity above less specific rules, and never
//! fires — because every real curl reports `/usr/bin/curl`. The rule looks
//! present and does nothing, which is the worst failure a firewall rule can
//! have: it is indistinguishable from working.
//!
//! # What this does not do
//!
//! It does not run on the packet path. Canonicalising at match time would put
//! filesystem I/O in front of every unmatched connection, to fix a problem that
//! only exists where a path is *entered*. Rules are canonicalised once, when
//! they are created.
//!
//! It also does not turn a path that cannot be resolved into an error. A rule
//! for a program that is not installed yet is a legitimate thing to write, and
//! refusing it would be worse than storing it verbatim. Callers that can say
//! something useful about that case — the CLI can, the daemon cannot — are
//! expected to warn.
//!
//! # Three properties worth knowing before relying on this
//!
//! **A versioned symlink resolves to a version.** `/usr/bin/python ->
//! python3.13` stores `/usr/bin/python3.13`, which stops applying the next time
//! that symlink moves — silently, with the rule still listed and still
//! plausible. Matching-wise this is not a regression (the unresolved rule never
//! matched either), but it is a *new, time-dependent* failure and it is the one
//! a reader should expect. It matters most for a Deny: an allow that stops
//! applying prompts, a deny that stops applying does not.
//!
//! **Resolution follows symlinks whoever owns the path controls.** A rule
//! written for `/home/bob/tool`, where Bob has pointed that at `/usr/bin/curl`,
//! is stored as a rule about curl — and for an Allow that widens the policy to
//! every user's curl. The CLI prints what it stored for exactly this reason;
//! the daemon logs it at warn. Nothing pins the inode, so this is a plain
//! time-of-check/time-of-use gap and always was.
//!
//! **It is forward-only.** Rules already on disk are never re-resolved: the
//! daemon loads them as written, so an install that wrote `/bin/curl` before
//! this existed keeps an inert rule after upgrading. The repair is one round
//! trip, because import re-upserts every rule and upsert resolves:
//!
//! ```sh
//! cfc rules export > rules.json && cfc rules import --replace rules.json
//! ```

use std::path::{Path, PathBuf};

/// What resolving `path` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// The path was already the one the kernel will report.
    Unchanged(PathBuf),
    /// Resolved to a different path; the rule should store this one.
    ///
    /// Carries the original so a caller can tell the user what changed —
    /// silently rewriting what someone typed is its own kind of surprise.
    Rewritten { from: PathBuf, to: PathBuf },
    /// Nothing is there to resolve. The path is kept verbatim; a rule using it
    /// will not match until the file exists, and may not match then either.
    Missing(PathBuf),
    /// The directories exist and resolve, but the file itself does not.
    ///
    /// Split out from both neighbours because it is both things at once and
    /// collapsing it into either loses something: reported as `Rewritten` it
    /// claims a path the kernel does not report (nothing is there), and
    /// reported as `Missing` it throws away the directory resolution that makes
    /// the stored path right once the program is installed.
    RewrittenButMissing { from: PathBuf, to: PathBuf },
    /// Not an absolute path. `/proc/<pid>/exe` is always absolute, so a
    /// relative rule path can never match anything.
    Relative(PathBuf),
}

impl Resolved {
    /// The path to store, whatever happened.
    pub fn path(&self) -> &Path {
        match self {
            Self::Unchanged(p) | Self::Missing(p) | Self::Relative(p) => p,
            Self::Rewritten { to, .. } | Self::RewrittenButMissing { to, .. } => to,
        }
    }

    /// Consumes into the path to store.
    pub fn into_path(self) -> PathBuf {
        match self {
            Self::Unchanged(p) | Self::Missing(p) | Self::Relative(p) => p,
            Self::Rewritten { to, .. } | Self::RewrittenButMissing { to, .. } => to,
        }
    }

    /// True when a rule built from this will not match anything as it stands.
    pub fn is_inert(&self) -> bool {
        matches!(
            self,
            Self::Missing(_) | Self::Relative(_) | Self::RewrittenButMissing { .. }
        )
    }

    /// One line for a human, or `None` when there is nothing worth saying.
    pub fn note(&self) -> Option<String> {
        match self {
            Self::Unchanged(_) => None,
            Self::Rewritten { from, to } => Some(format!(
                "resolved {} to {} (the kernel reports the second, so a rule for \
                 the first would never match)",
                from.display(),
                to.display()
            )),
            Self::RewrittenButMissing { from, to } => Some(format!(
                "{} resolves to {}, but nothing is installed there yet; the rule \
                 is stored against the resolved path and will match once it is - \
                 unless the program installs as a symlink, which would need the \
                 rule rewritten",
                from.display(),
                to.display()
            )),
            Self::Missing(p) => Some(format!(
                "{} does not exist; the rule is stored as written, and if the \
                 path turns out to be a symlink once the program is installed \
                 it will need rewriting to the real path",
                p.display()
            )),
            Self::Relative(p) => Some(format!(
                "{} is not an absolute path; /proc reports absolute paths, so \
                 this rule can never match",
                p.display()
            )),
        }
    }
}

/// Resolves an executable path the way `/proc/<pid>/exe` reports it.
///
/// Touches the filesystem. Never fails: an unresolvable path comes back
/// verbatim, classified, for the caller to comment on.
pub fn resolve(path: &Path) -> Resolved {
    if !path.is_absolute() {
        return Resolved::Relative(path.to_path_buf());
    }
    // A trailing separator makes `canonicalize` answer ENOTDIR even for a real
    // file, which would report a perfectly good rule as "does not exist" —
    // `Path` comparison is component-wise, so `/usr/bin/curl/` matches
    // `/usr/bin/curl` at packet time regardless. Strip it before asking the
    // filesystem anything, so the diagnostics describe the file rather than
    // the spelling.
    let trimmed;
    let path = {
        let raw = path.as_os_str().as_encoded_bytes();
        if raw.len() > 1 && raw.ends_with(b"/") {
            let end = raw.iter().rposition(|b| *b != b'/').map_or(1, |i| i + 1);
            // SAFETY: the slice ends on a component boundary of a valid
            // `OsStr`, since `/` is never part of a multi-byte sequence.
            trimmed = PathBuf::from(unsafe {
                std::ffi::OsStr::from_encoded_bytes_unchecked(&raw[..end])
            });
            trimmed.as_path()
        } else {
            path
        }
    };
    match std::fs::canonicalize(path) {
        Ok(real) if real == path => Resolved::Unchanged(real),
        Ok(real) => Resolved::Rewritten {
            from: path.to_path_buf(),
            to: real,
        },
        // The file is not there. Giving up on the whole path here was a real
        // gap: `/bin/notyet` on a usr-merged host would be stored verbatim and
        // stay inert *after* the program was installed, because nothing
        // re-resolves a stored rule — while the note cheerfully promised it
        // would start matching. Resolve the deepest ancestor that does exist
        // and re-attach the missing tail, so the directory half of the
        // usr-merge is handled even when the leaf is absent.
        Err(_) => match resolve_via_ancestor(path) {
            // The file is still not there - that is why we are here - so this is
            // never a plain `Rewritten`. Saying so is what keeps the "you have
            // not installed this" warning that the first version of the ancestor
            // walk silently deleted.
            Some(to) if to != path => Resolved::RewrittenButMissing {
                from: path.to_path_buf(),
                to,
            },
            _ => Resolved::Missing(path.to_path_buf()),
        },
    }
}

/// Canonicalises the longest existing prefix of `path` and re-appends the rest.
///
/// Returns `None` when no ancestor resolves, or when the components that would
/// have to be re-attached contain anything that cannot be reasoned about
/// without touching the filesystem — `..` past an unresolved component would
/// mean guessing.
fn resolve_via_ancestor(path: &Path) -> Option<PathBuf> {
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cursor = path;
    loop {
        let parent = cursor.parent()?;
        let name = cursor.file_name()?;
        if name == ".." {
            return None;
        }
        tail.push(name);
        // `is_dir()` matters: an ancestor that resolves to a *file* would
        // otherwise yield a path nothing can ever occupy - `/usr/bin/curl` is a
        // binary, so `/usr/bin/curl/plugins/tool` is not a place - and that was
        // reported as a confident rewrite.
        if let Ok(real) = std::fs::canonicalize(parent) {
            if !real.is_dir() {
                return None;
            }
            let mut out = real;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return Some(out);
        }
        cursor = parent;
    }
}

/// Resolves in place, returning what happened. `None` when the scope names no
/// executable.
pub fn resolve_scope(scope: &mut crate::RuleScope) -> Option<Resolved> {
    let current = scope.exe_path.as_deref()?;
    let outcome = resolve(current);
    scope.exe_path = Some(outcome.path().to_path_buf());
    Some(outcome)
}

/// Whether a *directory* on the way to an executable is sealed against
/// non-root replacement.
///
/// Root-owned and not group/world-writable, or root-owned, world-writable and
/// **sticky** - the `/tmp` shape, where a non-root user still cannot rename
/// or remove root's files. A pure function of (uid, mode) so the policy can
/// be tested exhaustively without root or a filesystem that can express
/// every case.
///
/// This pair started life in the daemon's BPF-object vetting and moved here
/// when rule hash-binding needed the identical judgment: "can a non-root
/// user swap the bytes behind this path" is one question, and two copies of
/// its answer had already drifted apart once elsewhere in this codebase.
pub fn dir_is_sealed(uid: u32, mode: u32) -> bool {
    uid == 0 && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}

/// Whether the file itself is sealed. No sticky exception: the bit means
/// nothing on a regular file.
pub fn file_is_sealed(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

/// Whether nothing short of root can replace the bytes behind `path`.
///
/// True only when the file *and every ancestor directory* pass the sealed
/// tests above: a root-owned file under a directory someone else can rename
/// is not a sealed file. Symlinks are resolved first - judging the link and
/// trusting the target would check the wrong file.
///
/// Two callers, two consequences:
/// * the daemon binds a prompt-created **allow** to the binary's hash when
///   this says false - a path anyone can rewrite must not carry a standing
///   path-keyed allow;
/// * the CLI suggests `--pin-hash` for the same reason.
///
/// Errors are the caller's to interpret: a path that cannot even be stat'd
/// is certainly not sealed, but *why* it cannot matters differently to a
/// daemon (process may have exited) and a CLI (typo).
pub fn is_root_sealed(path: &std::path::Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let real = std::fs::canonicalize(path)?;
    let meta = std::fs::metadata(&real)?;
    if !meta.is_file() || !file_is_sealed(meta.uid(), meta.mode()) {
        return Ok(false);
    }
    for dir in real.ancestors().skip(1) {
        let m = std::fs::metadata(dir)?;
        if !dir_is_sealed(m.uid(), m.mode()) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn a_symlinked_path_is_rewritten_to_its_target() {
        // The usr-merge case, built rather than assumed: a rule written for the
        // link would never match, because /proc reports the target.
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real-binary");
        std::fs::write(&real, b"#!/bin/sh\n").expect("write");
        let link = dir.path().join("link-to-binary");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        match resolve(&link) {
            Resolved::Rewritten { from, to } => {
                assert_eq!(from, link);
                assert_eq!(to, std::fs::canonicalize(&real).expect("canon"));
            }
            other => panic!("expected a rewrite, got {other:?}"),
        }
    }

    #[test]
    fn a_symlinked_parent_directory_is_rewritten_too() {
        // `/bin -> usr/bin` is a *directory* symlink, which is exactly the
        // shape of the usr-merge and the one a caller is least likely to spot.
        let dir = tempfile::tempdir().expect("tempdir");
        let realdir = dir.path().join("usr-bin");
        std::fs::create_dir(&realdir).expect("mkdir");
        std::fs::write(realdir.join("curl"), b"x").expect("write");
        let linkdir = dir.path().join("bin");
        std::os::unix::fs::symlink(&realdir, &linkdir).expect("symlink");

        let outcome = resolve(&linkdir.join("curl"));
        assert!(
            matches!(outcome, Resolved::Rewritten { .. }),
            "got {outcome:?}"
        );
        assert_eq!(
            outcome.path(),
            std::fs::canonicalize(realdir.join("curl")).expect("canon")
        );
    }

    #[test]
    fn an_already_canonical_path_is_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = std::fs::canonicalize(dir.path()).expect("canon").join("f");
        std::fs::write(&real, b"x").expect("write");
        assert_eq!(resolve(&real), Resolved::Unchanged(real.clone()));
        assert!(resolve(&real).note().is_none(), "nothing to tell the user");
    }

    #[test]
    fn a_missing_path_is_kept_verbatim_and_flagged() {
        // Writing a rule for a program you are about to install is legitimate;
        // refusing it would be worse than storing it. But it is inert until the
        // file exists, and the caller has to be able to say so.
        let p = PathBuf::from("/nonexistent-8f2c1a/curl");
        let outcome = resolve(&p);
        assert_eq!(outcome, Resolved::Missing(p.clone()));
        assert_eq!(outcome.path(), p);
        assert!(outcome.is_inert());
        assert!(outcome.note().expect("a note").contains("does not exist"));
    }

    #[test]
    fn a_missing_leaf_under_a_symlinked_directory_still_resolves() {
        // The gap the first version left, and the one that matters most: on a
        // usr-merged host `/bin` is a symlink, so a rule written for a program
        // not yet installed (`/bin/mytool`) was stored verbatim and stayed
        // inert *after* installation - nothing re-resolves a stored rule.
        let dir = tempfile::tempdir().expect("tempdir");
        let realdir = dir.path().join("usr-bin");
        std::fs::create_dir(&realdir).expect("mkdir");
        let linkdir = dir.path().join("bin");
        std::os::unix::fs::symlink(&realdir, &linkdir).expect("symlink");

        let wanted = linkdir.join("not-installed-yet");
        let outcome = resolve(&wanted);
        assert!(
            matches!(outcome, Resolved::RewrittenButMissing { .. }),
            "the existing parent must still be resolved, and the absent file \
             still reported: {outcome:?}"
        );
        let stored = outcome.into_path();
        assert_eq!(
            stored,
            std::fs::canonicalize(&realdir)
                .expect("canon")
                .join("not-installed-yet")
        );

        // And once the program is installed, that stored path is exactly what
        // canonicalize reports - which is what /proc will report too.
        std::fs::write(realdir.join("not-installed-yet"), b"x").expect("write");
        assert_eq!(
            stored,
            std::fs::canonicalize(realdir.join("not-installed-yet")).expect("canon")
        );
    }

    #[test]
    fn a_not_yet_installed_program_is_still_flagged_even_when_the_directory_resolves() {
        // The ancestor walk was added so `/bin/mytool` would be stored as
        // `/usr/bin/mytool`. It also silently turned "you have not installed
        // this" into a confident rewrite, so the only warning a user ever got
        // about a missing program disappeared - on exactly the usr-merged host
        // the walk exists for.
        let dir = tempfile::tempdir().expect("tempdir");
        let realdir = dir.path().join("usr-bin");
        std::fs::create_dir(&realdir).expect("mkdir");
        std::os::unix::fs::symlink(&realdir, dir.path().join("bin")).expect("symlink");

        let outcome = resolve(&dir.path().join("bin").join("not-installed"));
        assert!(
            matches!(outcome, Resolved::RewrittenButMissing { .. }),
            "both facts must survive: {outcome:?}"
        );
        assert!(
            outcome.is_inert(),
            "a rule for a program that is not there matches nothing, resolved or not"
        );
        // Still stored against the resolved directory, which is the point.
        assert_eq!(
            outcome.path(),
            std::fs::canonicalize(&realdir)
                .expect("canon")
                .join("not-installed")
        );
        let note = outcome.note().expect("a note");
        assert!(note.contains("nothing is installed there yet"), "{note}");
    }

    #[test]
    fn an_ancestor_that_is_a_file_is_not_a_place_anything_can_live() {
        // `/usr/bin/curl` is a binary, so `/usr/bin/curl/plugins/tool` is not a
        // path - and reporting it as a resolved rewrite told the operator a rule
        // was fine when it could never fire.
        let dir = tempfile::tempdir().expect("tempdir");
        let realdir = dir.path().join("usr-bin");
        std::fs::create_dir(&realdir).expect("mkdir");
        std::fs::write(realdir.join("curl"), b"x").expect("write");
        std::os::unix::fs::symlink(&realdir, dir.path().join("bin")).expect("symlink");

        let outcome = resolve(
            &dir.path()
                .join("bin")
                .join("curl")
                .join("plugins")
                .join("tool"),
        );
        assert!(matches!(outcome, Resolved::Missing(_)), "{outcome:?}");
        assert!(outcome.is_inert());
    }

    #[test]
    fn a_path_with_no_resolvable_ancestor_is_still_missing() {
        let outcome = resolve(Path::new("/nonexistent-4b1e9c/deeper/still/prog"));
        assert!(matches!(outcome, Resolved::Missing(_)), "{outcome:?}");
        assert!(outcome.is_inert());
    }

    #[test]
    fn a_trailing_slash_does_not_produce_a_false_warning() {
        // canonicalize answers ENOTDIR for `/usr/bin/curl/`, which the first
        // version reported as "does not exist" - a scary warning about a rule
        // that matches perfectly well, because PathBuf equality is
        // component-wise and the trailing slash is not a component.
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("prog");
        std::fs::write(&f, b"x").expect("write");
        let with_slash = PathBuf::from(format!("{}/", f.display()));

        let outcome = resolve(&with_slash);
        assert!(
            !outcome.is_inert(),
            "a real file must not be reported as missing: {outcome:?}"
        );
        assert_eq!(outcome.path(), std::fs::canonicalize(&f).expect("canon"));
    }

    #[test]
    fn a_relative_path_can_never_match_and_says_so() {
        let outcome = resolve(Path::new("bin/curl"));
        assert!(matches!(outcome, Resolved::Relative(_)));
        assert!(outcome.is_inert());
        assert!(outcome.note().expect("a note").contains("absolute"));
    }

    #[test]
    fn resolving_a_scope_updates_it_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("prog");
        std::fs::write(&real, b"x").expect("write");
        let link = dir.path().join("prog-link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let mut scope = crate::RuleScope::any();
        scope.exe_path = Some(link);
        let outcome = resolve_scope(&mut scope).expect("the scope names an exe");
        assert!(matches!(outcome, Resolved::Rewritten { .. }));
        assert_eq!(
            scope.exe_path.as_deref(),
            Some(std::fs::canonicalize(&real).expect("canon").as_path())
        );

        // A scope with no exe is not an error and is not touched.
        let mut empty = crate::RuleScope::any();
        assert!(resolve_scope(&mut empty).is_none());
        assert_eq!(empty.exe_path, None);
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    #[test]
    fn the_sealed_bit_tests_match_the_loader_policy() {
        // File: root-owned, not group/world-writable. These are the exact
        // cases the BPF-object vetting was proven against; the predicate
        // moved here, the truth table must not move with it.
        assert!(file_is_sealed(0, 0o100644));
        assert!(file_is_sealed(0, 0o100600));
        assert!(!file_is_sealed(1000, 0o100644), "non-root owner");
        assert!(!file_is_sealed(0, 0o100664), "group-writable");
        assert!(!file_is_sealed(0, 0o100666), "world-writable");

        // Directory: same, plus the sticky exception for the /tmp shape.
        assert!(dir_is_sealed(0, 0o040755));
        assert!(dir_is_sealed(0, 0o041777), "sticky world-writable is /tmp");
        assert!(!dir_is_sealed(0, 0o040777), "world-writable, no sticky");
        assert!(!dir_is_sealed(1000, 0o040755), "non-root owner");
    }

    #[test]
    fn a_users_own_file_is_not_sealed() {
        // A temp dir is owned by the running (non-root) user, so both the
        // file and its parent fail the seal - the exact shape of
        // ~/.local/bin that hash-binding exists for. (Under root the parent
        // would pass; the file check still runs, so the assertion holds
        // unless the whole ancestry is root-sealed, which a fresh tempdir
        // under /tmp never is: /tmp itself is sticky, but the tempdir is
        // mode 700 and owned by whoever runs the tests.)
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("tool");
        std::fs::write(&file, b"#!/bin/sh\n").expect("write");
        let sealed = is_root_sealed(&file).expect("stat succeeds");
        if euid() == Some(0) {
            // Under root the ownership half passes and the verdict depends
            // on the tempdir's mode alone; the test would assert nothing
            // reliable, so it asserts nothing at all.
            return;
        }
        assert!(
            !sealed,
            "a user-owned file under a user-owned dir is not sealed"
        );
    }

    #[test]
    fn a_missing_path_is_an_error_not_a_verdict() {
        assert!(is_root_sealed(std::path::Path::new("/nonexistent/cfc-x")).is_err());
    }

    /// From /proc/self/status - no libc dependency for one call.
    fn euid() -> Option<u32> {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    }
}
