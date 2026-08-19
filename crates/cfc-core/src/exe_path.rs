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
    /// Not an absolute path. `/proc/<pid>/exe` is always absolute, so a
    /// relative rule path can never match anything.
    Relative(PathBuf),
}

impl Resolved {
    /// The path to store, whatever happened.
    pub fn path(&self) -> &Path {
        match self {
            Self::Unchanged(p) | Self::Missing(p) | Self::Relative(p) => p,
            Self::Rewritten { to, .. } => to,
        }
    }

    /// Consumes into the path to store.
    pub fn into_path(self) -> PathBuf {
        match self {
            Self::Unchanged(p) | Self::Missing(p) | Self::Relative(p) => p,
            Self::Rewritten { to, .. } => to,
        }
    }

    /// True when a rule built from this will not match anything as it stands.
    pub fn is_inert(&self) -> bool {
        matches!(self, Self::Missing(_) | Self::Relative(_))
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
            Some(to) if to != path => Resolved::Rewritten {
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
        if let Ok(real) = std::fs::canonicalize(parent) {
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
            matches!(outcome, Resolved::Rewritten { .. }),
            "the existing parent must still be resolved: {outcome:?}"
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
