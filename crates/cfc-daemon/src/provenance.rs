//! Binary package provenance: "does this binary still match what the
//! distribution installed?"
//!
//! Windows Firewall Control can print `Signed: Yes (Canon Inc.)` because
//! Windows binaries carry Authenticode signatures. Linux binaries do not,
//! but the package manager already keeps a per-file cryptographic digest of
//! everything it installed, which answers a stronger question: not "who
//! claims to have built this" but "is this still the exact file the distro
//! shipped".
//!
//! # The comparison that matters
//!
//! The digest we compare against the package record is the one
//! [`crate::process_resolve`] already computed by hashing `/proc/<pid>/exe`,
//! i.e. the file object the *kernel actually mapped* for the running
//! process. The package record describes the file at that same path *on
//! disk*. Those are usually the same bytes; when they are not,
//! [`Provenance::Modified`] is exactly the interesting event, because the
//! binary that is running is not the binary the package shipped (replaced,
//! patched, or the on-disk file swapped under a still-running process). We
//! never re-hash anything here.
//!
//! # Backends
//!
//! [`Pacman`] (Arch) is fully verifying. [`Dpkg`] (Debian/Ubuntu) is
//! best-effort *name only*: dpkg records MD5, and pulling in an MD5
//! implementation to verify a hash that is no longer collision-resistant is
//! not worth a new dependency, so a dpkg host gets a package name with
//! [`Provenance::Unknown`]. That pairing - `package: Some(..)` with
//! `Unknown` - is the honest encoding of "owned, but unverifiable here".
//!
//! # Cost, and why it is never on the hot path
//!
//! [`describe`] is called once per `Process` *construction*, which the
//! process cache in [`crate::process_resolve`] already collapses to roughly
//! once per (pid, starttime). Underneath, two more caches: the path ->
//! package index is built once and reused until the package database's
//! mtime changes, and per-executable lookups are memoized by
//! (dev, inode, mtime) with a TTL. A steady-state packet does zero I/O
//! here.

use anyhow::Context as _;
use cfc_core::Provenance;
use flate2::read::GzDecoder;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, trace, warn};

use crate::process_resolve::TtlCache;

/// Canonical location of the pacman local database.
pub const PACMAN_LOCAL_DB: &str = "/var/lib/pacman/local";
/// Canonical location of the dpkg per-package metadata directory.
pub const DPKG_INFO_DB: &str = "/var/lib/dpkg/info";

/// Package records are keyed by (dev, inode, mtime) of the executable, so a
/// replaced file misses the cache on its own. The TTL is a memory backstop
/// and a bound on how long a `pacman -U` of the *same* file can go unseen.
const LOOKUP_CACHE_TTL: Duration = Duration::from_secs(3600);

const LOOKUP_CACHE_CAP: usize = 1024;

/// Index builds slower than this are unusual enough to warn about (once).
const SLOW_INDEX_BUILD: Duration = Duration::from_secs(1);

/// What a package database knows about one installed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFile {
    /// `"<name> <version>"`, e.g. `"curl 8.21.0-1"`.
    pub package: String,
    /// The digest the database recorded for this exact path, when it
    /// records one we can actually check. `None` means "owned, but this
    /// backend cannot vouch for the bytes".
    pub sha256: Option<String>,
}

/// A distribution package database, viewed as a path -> record lookup.
pub trait PackageDb: Send + Sync {
    /// Human-readable backend name, for logs.
    fn name(&self) -> &'static str;

    /// The package record for an absolute path, or `None` when no installed
    /// package owns it.
    fn lookup(&self, exe: &Path) -> Option<PackageFile>;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Set by [`crate::config::Config::load_or_default`], so the knob follows
/// the config file's lifecycle (including SIGHUP reload) without every
/// caller having to thread it down the packet path.
static ENABLED: AtomicBool = AtomicBool::new(true);

/// Enables or disables provenance lookups process-wide (`[provenance]
/// enabled` in daemon.toml). Disabling takes effect for the next `Process`
/// built; already-cached results are simply not consulted.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// The detected backend for this host, resolved once. `None` on a system
/// with neither a pacman nor a dpkg database (or when detection raced a
/// package manager mid-install and found neither).
static BACKEND: LazyLock<Option<Box<dyn PackageDb>>> = LazyLock::new(|| {
    detect(
        Path::new(PACMAN_LOCAL_DB),
        Path::new(RPM_DB),
        Path::new(DPKG_INFO_DB),
    )
});

#[allow(clippy::type_complexity)]
static LOOKUP_CACHE: LazyLock<Mutex<TtlCache<(u64, u64, i64, i64), Option<PackageFile>>>> =
    LazyLock::new(|| Mutex::new(TtlCache::new(LOOKUP_CACHE_TTL, LOOKUP_CACHE_CAP)));

/// Picks a backend by which database directory exists.
///
/// Ordered by how much the answer is worth, not alphabetically. pacman and rpm
/// both record SHA-256 and can therefore say something about the *bytes*; dpkg
/// records MD5 and can only name the package. On the (unusual but real - think
/// a converted image, or a container with both trees mounted) host carrying
/// more than one, preferring a backend that can verify is preferring the answer
/// that means something.
///
/// pacman before rpm only because a host with a pacman database is an Arch
/// host; nothing else ships one.
pub fn detect(pacman_root: &Path, rpm_root: &Path, dpkg_root: &Path) -> Option<Box<dyn PackageDb>> {
    if pacman_root.is_dir() {
        return Some(Box::new(Pacman::new(pacman_root.to_path_buf())));
    }
    if rpm_root.is_dir() {
        return Some(Box::new(Rpm::new(rpm_root.to_path_buf())));
    }
    if dpkg_root.is_dir() {
        return Some(Box::new(Dpkg::new(dpkg_root.to_path_buf())));
    }
    None
}

/// Answers the provenance question for one executable.
///
/// `exe` is the on-disk path the package database describes;
/// `running_sha256` is the digest of the bytes the kernel mapped, taken
/// from `/proc/<pid>/exe` by [`crate::process_resolve`]. Nothing is hashed
/// here. See the module docs for why comparing those two specifically is
/// the point.
///
/// Returns the `(package, provenance)` pair to store on
/// [`cfc_core::Process`].
pub fn describe(exe: &Path, running_sha256: Option<&str>) -> (Option<String>, Provenance) {
    if !enabled() {
        return (None, Provenance::Unknown);
    }
    // Only absolute real paths can be owned by a package. `<unknown>` and
    // `<deleted>` placeholders, and the " (deleted)" suffix the kernel
    // appends for an unlinked binary, are not paths we can ask about.
    if !exe.is_absolute()
        || exe
            .to_string_lossy()
            .ends_with(crate::process_resolve::DELETED_SUFFIX)
    {
        return (None, Provenance::Unknown);
    }
    let Some(db) = BACKEND.as_ref() else {
        return (None, Provenance::Unknown);
    };
    // A path we cannot stat is a path we cannot judge: a binary in another
    // mount namespace (a container's /usr/bin/nginx is not ours), or one
    // unlinked between reading /proc and getting here. Falling through to
    // `decide` would call that `Unpackaged` and cry wolf about a file that
    // may well be perfectly packaged - somewhere we cannot see.
    let Ok(meta) = std::fs::metadata(exe) else {
        return (None, Provenance::Unknown);
    };
    let record = cached_lookup(db.as_ref(), exe, &meta);
    let provenance = decide(record.as_ref(), running_sha256);
    (record.map(|r| r.package), provenance)
}

/// The decision table, split out so it is testable without any filesystem.
///
/// | package record | recorded digest | running digest | result |
/// |---|---|---|---|
/// | absent  | -       | -        | `Unpackaged` |
/// | present | absent  | -        | `Unknown` (package name still set) |
/// | present | present | absent   | `Unknown` (nothing to compare) |
/// | present | present | equal    | `Verified` |
/// | present | present | differs  | `Modified` |
///
/// "Owned but unverifiable" is deliberately *not* a fifth variant: the pair
/// (`package: Some`, `Unknown`) already says it, costs no proto value, and
/// keeps every consumer's match arms to the four states that mean something
/// operationally. Only the dpkg backend can produce it.
fn decide(record: Option<&PackageFile>, running_sha256: Option<&str>) -> Provenance {
    let Some(record) = record else {
        return Provenance::Unpackaged;
    };
    match (record.sha256.as_deref(), running_sha256) {
        (Some(recorded), Some(running)) if recorded.eq_ignore_ascii_case(running) => {
            Provenance::Verified
        }
        (Some(_), Some(_)) => Provenance::Modified,
        _ => Provenance::Unknown,
    }
}

/// Memoizes one backend lookup per (dev, inode, mtime) of the executable.
///
/// The key is already content-addressed for our purposes: replacing the
/// file changes the inode or the mtime, so a swapped binary can never be
/// answered from a stale entry.
fn cached_lookup(db: &dyn PackageDb, exe: &Path, meta: &std::fs::Metadata) -> Option<PackageFile> {
    let key = (meta.dev(), meta.ino(), meta.mtime(), meta.mtime_nsec());
    let now = Instant::now();
    if let Some(hit) = LOOKUP_CACHE.lock().get(&key, now) {
        return hit;
    }
    let record = db.lookup(exe);
    LOOKUP_CACHE.lock().insert(key, record.clone(), now);
    record
}

// ---------------------------------------------------------------------------
// Shared path -> package index
// ---------------------------------------------------------------------------

/// Path -> owning package, plus the database stamp it was built from.
struct Index {
    /// mtime of the database root when this index was built. Both package
    /// managers bump it on install/remove, which is precisely when the
    /// index goes stale.
    stamp: Option<SystemTime>,
    /// Package identifiers, indexed by the values in `owner`. For pacman
    /// these are directory names (`"curl-8.21.0-1"`), for dpkg the package
    /// name from `<pkg>.list`.
    packages: Vec<Box<str>>,
    /// Recorded digest per path hash, for backends that carry one inline.
    ///
    /// Empty for pacman, which reads digests lazily out of one package's
    /// `mtree`, and for dpkg, which records only MD5. Only rpm populates it,
    /// because `rpm -qa` hands back names, paths and digests in a single pass
    /// and a second query per binary would mean another subprocess against a
    /// database `dnf` may be holding open.
    ///
    /// Raw 32 bytes rather than the 64-character hex string: on a full RHEL
    /// install that is ~8 MB instead of ~18 MB, and the hex round trip happens
    /// once per newly-seen executable rather than 200,000 times at build.
    digests: HashMap<u64, [u8; 32]>,
    /// Hash of the absolute path -> index into `packages`.
    ///
    /// The paths themselves are *not* stored. A full path table for a
    /// desktop Arch install is ~520k entries and ~35 MB of string data;
    /// keeping only a 64-bit hash brings the whole index to roughly 10 MB.
    /// With ~5e5 entries the birthday probability of any collision at all
    /// is ~1e-8, and a collision degrades to "reports the wrong package
    /// name with no digest", never to a wrong Verified/Modified verdict:
    /// the digest lookup in that package's mtree simply would not find the
    /// path.
    owner: HashMap<u64, u32>,
}

impl Index {
    fn empty(stamp: Option<SystemTime>) -> Self {
        Self {
            stamp,
            packages: Vec::new(),
            digests: HashMap::new(),
            owner: HashMap::new(),
        }
    }

    /// The digest this backend recorded for `key`, as lowercase hex.
    fn digest(&self, key: u64) -> Option<String> {
        self.digests.get(&key).map(|raw| {
            let mut out = String::with_capacity(64);
            for b in raw {
                use std::fmt::Write as _;
                let _ = write!(out, "{b:02x}");
            }
            out
        })
    }

    fn get(&self, key: u64) -> Option<String> {
        self.owner
            .get(&key)
            .map(|&i| self.packages[i as usize].to_string())
    }

    /// Records every path in `paths` as owned by `package`. A package that
    /// contributed no paths is not stored at all.
    fn add_package(&mut self, package: &str, paths: impl Iterator<Item = String>) {
        let Ok(id) = u32::try_from(self.packages.len()) else {
            return;
        };
        let mut any = false;
        for path in paths {
            self.owner.insert(path_hash(Path::new(&path)), id);
            any = true;
        }
        if any {
            self.packages.push(package.to_string().into_boxed_str());
        }
    }

    /// Records one file, with the digest the database vouches for when there
    /// is one this build can compare against.
    ///
    /// `package_id` comes from [`Self::intern_package`], so a caller feeding
    /// files one at a time does not repeat the package name per file.
    fn add_file(&mut self, package_id: u32, path: &str, digest: Option<[u8; 32]>) {
        let key = path_hash(Path::new(path));
        self.owner.insert(key, package_id);
        if let Some(d) = digest {
            self.digests.insert(key, d);
        }
    }

    /// Reserves a slot for `package` and returns its id.
    ///
    /// Unlike [`Self::add_package`] this stores the name unconditionally, so a
    /// caller that turns out to contribute no files leaves one unused string
    /// behind. That is the right trade for a streaming parser, which cannot
    /// know a package's file count before it has read them.
    fn intern_package(&mut self, package: &str) -> Option<u32> {
        let id = u32::try_from(self.packages.len()).ok()?;
        self.packages.push(package.to_string().into_boxed_str());
        Some(id)
    }

    fn shrink(mut self) -> Self {
        self.packages.shrink_to_fit();
        self.digests.shrink_to_fit();
        self.owner.shrink_to_fit();
        self
    }
}

/// Lazily-built, mtime-invalidated index shared by both backends.
struct IndexCache {
    root: PathBuf,
    backend: &'static str,
    index: RwLock<Option<Index>>,
    /// One warn per process for a slow build, not one per rebuild.
    warned_slow: AtomicBool,
}

/// Hand back to the kernel what building the index borrowed.
///
/// The index itself is small on purpose - it keeps a 64-bit hash per path
/// rather than the path, so a desktop Arch install costs about 14 MB.
/// *Building* it is not small: every installed package's `files` list is read
/// into a String, parsed, hashed, and dropped. On the owner's machine that is
/// 66 MB of package database through the allocator in a few hundred
/// milliseconds.
///
/// glibc does not return that to the OS when it is freed. It keeps it in the
/// arena for reuse, which is the right default for a program that will allocate
/// again - and the wrong one for a daemon that does this once at startup and
/// then sits still for weeks. The freed pages stayed resident: reading the
/// daemon's own memory afterwards showed a 40 MB mapping still full of icon
/// paths from packages nobody had asked about, half of it zeroes.
///
/// `malloc_trim` is the one-line answer. It is glibc-specific, so it is a
/// no-op elsewhere; failing to trim costs memory, never correctness, which is
/// why nothing here checks the return value.
fn release_index_scratch() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: `malloc_trim` takes a byte count of padding to retain and only
    // touches the allocator's own free lists. It cannot invalidate a live
    // pointer: memory still owned by the program is not eligible.
    unsafe {
        libc::malloc_trim(0);
    }
}

impl IndexCache {
    fn new(root: PathBuf, backend: &'static str) -> Self {
        Self {
            root,
            backend,
            index: RwLock::new(None),
            warned_slow: AtomicBool::new(false),
        }
    }

    /// mtime of the database root, or `None` if it cannot be read.
    ///
    /// `None` compares unequal to any real timestamp, so a database that
    /// becomes unreadable invalidates the index it was built from. Two
    /// consecutive `None`s do compare equal, which is what stops an
    /// unreadable root from rebuilding an empty index on every lookup.
    fn stamp(&self) -> Option<SystemTime> {
        std::fs::metadata(&self.root).ok()?.modified().ok()
    }

    /// The package owning `exe`, building or rebuilding the index if the
    /// database has changed underneath us since the last build.
    fn owner_of(
        &self,
        exe: &Path,
        build: impl FnOnce(Option<SystemTime>) -> Index,
    ) -> Option<String> {
        self.record_of(exe, build).map(|(pkg, _)| pkg)
    }

    /// The package owning `exe` *and* the digest the index carries for it, for
    /// backends that record one inline. The second element is always `None`
    /// for pacman and dpkg; see [`Index::digests`].
    fn record_of(
        &self,
        exe: &Path,
        build: impl FnOnce(Option<SystemTime>) -> Index,
    ) -> Option<(String, Option<String>)> {
        let stamp = self.stamp();
        let key = path_hash(exe);

        if let Some(idx) = self.index.read().as_ref() {
            if idx.stamp == stamp {
                return idx.get(key).map(|p| (p, idx.digest(key)));
            }
        }

        let mut guard = self.index.write();
        // Another thread may have rebuilt it while we waited for the lock.
        if guard.as_ref().map(|i| i.stamp) != Some(stamp) {
            let started = Instant::now();
            let idx = build(stamp);
            let took = started.elapsed();
            debug!(
                backend = self.backend,
                packages = idx.packages.len(),
                files = idx.owner.len(),
                elapsed_ms = took.as_millis(),
                "built package path index"
            );
            if took > SLOW_INDEX_BUILD && !self.warned_slow.swap(true, Ordering::Relaxed) {
                warn!(
                    backend = self.backend,
                    elapsed_ms = took.as_millis(),
                    packages = idx.packages.len(),
                    "package provenance index build was slow; \
                     set [provenance] enabled = false in daemon.toml to switch it off"
                );
            }
            *guard = Some(idx);
            release_index_scratch();
        }
        let idx = guard.as_ref()?;
        idx.get(key).map(|p| (p, idx.digest(key)))
    }
}

// ---------------------------------------------------------------------------
// pacman
// ---------------------------------------------------------------------------

/// Arch's local database: `<root>/<name>-<ver>-<rel>/{desc,files,mtree}`.
///
/// Two-stage by design. `files` is plain text and cheap to scan, so one
/// pass over every package's `files` builds the path -> package index.
/// `mtree` is gzipped and holds the digests, so it is parsed lazily for the
/// single package that turned out to own the path in question - one gzip
/// stream per newly-seen binary instead of ~1300 per lookup.
pub struct Pacman {
    cache: IndexCache,
}

impl Pacman {
    pub fn new(root: PathBuf) -> Self {
        Self {
            cache: IndexCache::new(root, "pacman"),
        }
    }

    /// One pass over `<root>/*/files`. Unreadable entries are skipped, not
    /// fatal: a half-installed package must not blind the whole index.
    fn build_index(&self, stamp: Option<SystemTime>) -> Index {
        let mut idx = Index::empty(stamp);
        let Ok(entries) = std::fs::read_dir(&self.cache.root) else {
            return idx;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path().join("files")) else {
                continue;
            };
            let dir_name = entry.file_name().to_string_lossy().into_owned();
            idx.add_package(&dir_name, parse_files_list(&text));
        }
        idx.shrink()
    }
}

impl PackageDb for Pacman {
    fn name(&self) -> &'static str {
        "pacman"
    }

    fn lookup(&self, exe: &Path) -> Option<PackageFile> {
        let dir = self.cache.owner_of(exe, |s| self.build_index(s))?;
        let (name, version) = split_pkg_dir(&dir);
        let mtree = self.cache.root.join(&dir).join("mtree");
        let sha256 = match mtree_digest_for(&mtree, exe) {
            Ok(d) => d,
            Err(e) => {
                trace!(path = %mtree.display(), "reading mtree failed: {e}");
                None
            }
        };
        Some(PackageFile {
            package: format!("{name} {version}"),
            sha256,
        })
    }
}

/// Splits a pacman package directory name into `(name, version)`.
///
/// The directory is `<name>-<pkgver>-<pkgrel>`, and *the name may itself
/// contain hyphens* (`adwaita-icon-theme-50.0-1`). Splitting from the left
/// is the classic way to get this wrong; neither pkgver nor pkgrel may
/// contain a hyphen, so the split is always at the last two.
fn split_pkg_dir(dir: &str) -> (&str, &str) {
    match dir.rmatch_indices('-').nth(1) {
        Some((i, _)) => (&dir[..i], &dir[i + 1..]),
        // Not shaped like a package directory; hand it back whole rather
        // than inventing a version.
        None => (dir, ""),
    }
}

/// Yields the absolute regular-file paths listed in a pacman `files` file.
///
/// The format is a `%FILES%` header followed by one repo-relative path per
/// line with no leading slash. Directories carry a trailing slash and are
/// skipped - a directory is never an executable and would otherwise let a
/// shared `usr/bin/` entry claim ownership of every binary. The file may
/// also carry a `%BACKUP%` section (`etc/foo<TAB><md5>`), which is a
/// different shape entirely and must not be parsed as paths.
fn parse_files_list(text: &str) -> impl Iterator<Item = String> + '_ {
    let mut in_files = false;
    text.lines().filter_map(move |line| {
        if line.starts_with('%') {
            in_files = line.trim() == "%FILES%";
            return None;
        }
        let line = line.trim_end_matches(['\r']);
        if !in_files || line.is_empty() || line.ends_with('/') {
            return None;
        }
        Some(format!("/{}", line.trim_start_matches('/')))
    })
}

/// Pulls the `sha256digest` recorded for one exact path out of a gzipped
/// mtree, streaming and stopping at the first match.
///
/// mtree lines look like
/// `./usr/bin/curl time=1782282358.0 size=223624 sha256digest=fde5...`
/// with a leading `./`. `#`-comments, `/set` (defaults applied to following
/// lines) and `/unset` are handled; paths are vis(3)-escaped, so `\040` is
/// a space. Anything unparseable is skipped rather than aborting the scan -
/// a single mangled line must not hide a digest further down.
fn mtree_digest_for(mtree: &Path, target: &Path) -> std::io::Result<Option<String>> {
    let file = std::fs::File::open(mtree)?;
    let reader = BufReader::new(GzDecoder::new(file));
    let target = target.as_os_str().as_encoded_bytes();
    let mut defaults: HashMap<String, String> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("/set ") {
            for (k, v) in keywords(rest) {
                defaults.insert(k.to_string(), v.to_string());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("/unset ") {
            for word in rest.split_whitespace() {
                defaults.remove(word);
            }
            continue;
        }
        if line.starts_with('/') {
            // Some other mtree directive we do not model.
            continue;
        }
        let (raw_path, rest) = split_first_field(line);
        // "./usr/bin/curl" -> "/usr/bin/curl". A bare "." is the root entry.
        let Some(rel) = raw_path.strip_prefix('.') else {
            continue;
        };
        if rel.is_empty() {
            continue;
        }
        if unescape_mtree(rel) != target {
            continue;
        }
        // Line keywords win over /set defaults.
        let digest = keywords(rest)
            .find(|(k, _)| *k == "sha256digest")
            .map(|(_, v)| v.to_string())
            .or_else(|| defaults.get("sha256digest").cloned());
        return Ok(digest.filter(|d| !d.is_empty()));
    }
    Ok(None)
}

/// Splits `"<path> k=v k=v"` into the path and the keyword tail. A line
/// with no whitespace at all is a truncated record: it still names a path,
/// it just carries no keywords.
fn split_first_field(line: &str) -> (&str, &str) {
    line.split_once(char::is_whitespace).unwrap_or((line, ""))
}

/// `key=value` pairs from an mtree line tail. Bare words (keywords with no
/// value) are ignored rather than treated as a malformed line.
fn keywords(s: &str) -> impl Iterator<Item = (&str, &str)> {
    s.split_whitespace().filter_map(|w| w.split_once('='))
}

/// Undoes mtree's vis(3)-style escaping: `\ooo` is an octal byte (`\040` is
/// a space) and `\\` is a literal backslash. A stray backslash that starts
/// neither is kept verbatim - better a path we simply never match than a
/// panic on a hand-edited database.
fn unescape_mtree(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
            out.push(b'\\');
            i += 2;
            continue;
        }
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
        match octal {
            Some(digits) => {
                let v = digits
                    .iter()
                    .fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
                out.push(v as u8);
                i += 4;
            }
            None => {
                out.push(b'\\');
                i += 1;
            }
        }
    }
    out
}

fn path_hash(path: &Path) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.as_os_str().as_encoded_bytes().hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------------------
// rpm
// ---------------------------------------------------------------------------

/// Canonical location of the rpm database directory.
pub const RPM_DB: &str = "/var/lib/rpm";

/// Digs an errno out of an error chain.
///
/// Local rather than shared with the eBPF loader's copy: that one lives behind
/// the `ebpf` cargo feature, and provenance has to work in every build.
fn errno_of(err: &anyhow::Error) -> Option<i32> {
    err.chain()
        .find_map(|c| c.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
}

/// How long `rpm -qa` is given before it is killed and the index left empty.
///
/// Not a performance knob - a safety one. `dnf` holds the rpmdb open for the
/// length of a transaction, and a query that arrives mid-upgrade waits for it.
/// Without a bound, a `dnf update` on a slow disk would block whichever thread
/// is building the index, and that thread is on the packet path. Ten seconds
/// is far past any healthy query on the biggest installs and far short of a
/// package transaction.
const RPM_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the timeout is re-checked while waiting. Small enough that the
/// deadline means something, large enough not to spin.
const RPM_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// RHEL, Rocky, Fedora, SUSE - and the only backend here that can actually
/// verify a binary.
///
/// # Why this one shells out
///
/// The other two backends read plain text out of the package database. rpm's
/// is a binary store whose *format* has changed three times in the versions
/// this daemon has to run on: Berkeley DB on RHEL 7-8, sqlite on RHEL 9 and
/// 10, ndb on some SUSE builds. Reading it directly would mean either a sqlite
/// dependency plus an RPM header decoder, or a promise to track a format that
/// has not held still. `rpm(8)` reads all three and is on every host that has
/// the database at all.
///
/// The cost is a subprocess, so it is spent **once per index generation**, not
/// once per lookup: a single `rpm -qa` streams every package, path and digest
/// in one pass, and [`IndexCache`] rebuilds only when `/var/lib/rpm` changes -
/// which is to say when something is installed or removed. A per-lookup query
/// would have been the smaller change and the worse one: every newly-seen
/// binary would be another process contending for the same database lock.
///
/// # Why it can verify when dpkg cannot
///
/// rpm has recorded SHA-256 in `FILEDIGESTS` since 4.6 (RHEL 6). Older
/// packages, and anything built with `%_source_filedigest_algorithm 1`, record
/// MD5 instead. The two are told apart by length - 64 hex characters against
/// 32 - and an MD5 digest is dropped rather than compared, which lands that
/// file in the same "owned, unverifiable" state as everything under dpkg. See
/// [`parse_rpm_line`].
pub struct Rpm {
    cache: IndexCache,
    /// The `rpm` binary. A field so tests can point it at a stub instead of
    /// requiring rpm to be installed on whatever runs them.
    program: PathBuf,
    /// [`RPM_QUERY_TIMEOUT`] in production. A field so the test that proves the
    /// bound exists does not have to spend the real ceiling proving it.
    timeout: Duration,
}

impl Rpm {
    pub fn new(root: PathBuf) -> Self {
        Self::with_program(root, PathBuf::from("rpm"))
    }

    fn with_program(root: PathBuf, program: PathBuf) -> Self {
        Self {
            cache: IndexCache::new(root, "rpm"),
            program,
            timeout: RPM_QUERY_TIMEOUT,
        }
    }

    /// One `rpm -qa` pass, streamed.
    ///
    /// A failure of any kind - rpm missing, the database locked, the query
    /// timing out - yields an *empty* index rather than propagating. That is
    /// the same answer this host gave before this backend existed
    /// (`Unpackaged` everywhere), and it is the only answer that keeps a
    /// package transaction from being able to stall the firewall.
    fn build_index(&self, stamp: Option<SystemTime>) -> Index {
        let mut idx = Index::empty(stamp);
        let out = match self.run_query() {
            Ok(out) => out,
            Err(e) => {
                warn!(
                    "rpm provenance query failed: {e}; \
                     binaries on this host will report as unpackaged"
                );
                return idx;
            }
        };
        let mut current: Option<(String, u32)> = None;
        for line in out.lines() {
            let Some((package, path, digest)) = parse_rpm_line(line) else {
                continue;
            };
            // Lines arrive grouped by package, so the name is interned once per
            // group rather than once per file.
            let id = match &current {
                Some((name, id)) if name == package => *id,
                _ => {
                    let Some(id) = idx.intern_package(package) else {
                        break;
                    };
                    current = Some((package.to_string(), id));
                    id
                }
            };
            idx.add_file(id, path, digest);
        }
        idx.shrink()
    }

    /// Runs the query with a deadline, killing it if it overruns.
    ///
    /// One retry on `ETXTBSY`. That errno means someone holds the binary open
    /// for writing, which for `rpm` means rpm is being upgraded - a transient
    /// condition where an empty provenance index is a worse answer than waiting
    /// 50 ms. Found by a test that writes a script and execs it from a
    /// multi-threaded binary, where another thread's `fork()` briefly inherits
    /// the still-open write fd; the production case is rarer and the remedy is
    /// the same.
    fn run_query(&self) -> anyhow::Result<String> {
        match self.run_query_once() {
            Err(e) if errno_of(&e) == Some(libc::ETXTBSY) => {
                std::thread::sleep(Duration::from_millis(50));
                self.run_query_once()
            }
            other => other,
        }
    }

    fn run_query_once(&self) -> anyhow::Result<String> {
        use std::process::{Command, Stdio};

        let mut child = Command::new(&self.program)
            .arg("-qa")
            .arg("--dbpath")
            .arg(&self.cache.root)
            .arg("--qf")
            .arg(RPM_QUERY_FORMAT)
            // Locale affects nothing in this format, but a stray LC_ALL that
            // makes rpm emit a translated warning on stderr should not end up
            // parsed as data. stderr is discarded outright for the same reason.
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {}", self.program.display()))?;

        // Read on this thread while the child writes: the output is tens of
        // megabytes on a full install, which is far past a pipe buffer, so
        // waiting first and reading after would deadlock.
        let mut stdout = child.stdout.take().expect("stdout was piped");
        let reader = std::thread::spawn(move || {
            let mut buf = String::new();
            use std::io::Read as _;
            stdout.read_to_string(&mut buf).map(|_| buf)
        });

        let deadline = Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(e) => return Err(anyhow::Error::new(e).context("waiting for rpm")),
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!(
                    "rpm did not answer within {:?} (a package transaction may hold \
                     the database); leaving the provenance index empty",
                    self.timeout
                );
            }
            std::thread::sleep(RPM_POLL_INTERVAL);
        }
        reader
            .join()
            .map_err(|_| anyhow::anyhow!("rpm output reader panicked"))?
            .context("reading rpm output")
    }
}

/// One line per *file*, not per package.
///
/// `[...]` iterates the file arrays together, so the scalar name and version
/// repeat on every line. That redundancy is the point: it makes the output a
/// stream that can be parsed without holding a package's file list in memory,
/// and [`Rpm::build_index`] interns the repeated name once per group.
///
/// `%{FILEMODES:perms}` is carried only to drop directories. A directory entry
/// would otherwise let `/usr/bin` claim ownership of every binary under it -
/// the same trap the pacman backend avoids by skipping trailing slashes.
const RPM_QUERY_FORMAT: &str =
    "[%{NAME} %{VERSION}-%{RELEASE}\t%{FILEMODES:perms}\t%{FILENAMES}\t%{FILEDIGESTS}\n]";

/// Splits one [`RPM_QUERY_FORMAT`] line into `(package, path, digest)`.
///
/// Returns `None` for anything that is not a regular file's record: rpm writes
/// warnings and `(none)` placeholders into the same stream, and a directory
/// must never be indexed as an owner.
///
/// The digest is `Some` only for a 64-character hex string. rpm may record
/// MD5 (32 characters) on older packages, and an empty field for directories,
/// symlinks and `%ghost` entries; both become `None`, which [`decide`] renders
/// as "owned, unverifiable" with the package name still set.
fn parse_rpm_line(line: &str) -> Option<(&str, &str, Option<[u8; 32]>)> {
    let mut fields = line.split('\t');
    let package = fields.next()?;
    let modes = fields.next()?;
    let path = fields.next()?;
    let digest = fields.next().unwrap_or("");
    if fields.next().is_some() {
        // A path containing a tab would land here. rpm allows it; indexing a
        // truncated path would be worse than skipping the file.
        return None;
    }
    // `-rwxr-xr-x` for a regular file; `d`, `l`, `c`, `b`, `s`, `p` otherwise.
    if !modes.starts_with('-') {
        return None;
    }
    if package.is_empty() || !path.starts_with('/') {
        return None;
    }
    Some((package, path, parse_sha256_hex(digest)))
}

/// Decodes exactly 64 lowercase-or-uppercase hex characters into 32 bytes.
///
/// Length is the discriminator between rpm's SHA-256 and MD5 digests, so this
/// is deliberately strict about it: a 32-character MD5 must come back `None`
/// rather than being padded into something that would compare unequal to every
/// real digest and report a clean file as [`Provenance::Modified`].
fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Some(out)
}

impl PackageDb for Rpm {
    fn name(&self) -> &'static str {
        "rpm"
    }

    fn lookup(&self, exe: &Path) -> Option<PackageFile> {
        let (package, sha256) = self.cache.record_of(exe, |s| self.build_index(s))?;
        Some(PackageFile { package, sha256 })
    }
}

// ---------------------------------------------------------------------------
// dpkg
// ---------------------------------------------------------------------------

/// Debian/Ubuntu, name only.
///
/// `<root>/<pkg>.list` gives path -> package the same way pacman's `files`
/// does. Integrity would come from `<root>/<pkg>.md5sums`, but dpkg records
/// **MD5 only**; verifying against it would mean adding an MD5 dependency
/// to assert a property MD5 can no longer carry. So this backend reports
/// the owning package and leaves `sha256` `None`, which [`decide`] renders
/// as [`Provenance::Unknown`] *with the package name set*. Correctness over
/// coverage: a Debian user learns "this came from apt's coreutils" and is
/// told nothing about the bytes, rather than being told a comforting lie.
pub struct Dpkg {
    cache: IndexCache,
}

impl Dpkg {
    pub fn new(root: PathBuf) -> Self {
        Self {
            cache: IndexCache::new(root, "dpkg"),
        }
    }

    fn build_index(&self, stamp: Option<SystemTime>) -> Index {
        let mut idx = Index::empty(stamp);
        let Ok(entries) = std::fs::read_dir(&self.cache.root) else {
            return idx;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            // `<pkg>.list`, where <pkg> may be architecture-qualified
            // ("libc6:amd64.list"). Keep the qualifier: it is part of how
            // the package is named on that host.
            let Some(pkg) = name.strip_suffix(".list") else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let pkg = pkg.to_string();
            idx.add_package(&pkg, parse_dpkg_list(&text));
        }
        idx.shrink()
    }
}

/// Absolute paths from a dpkg `<pkg>.list`.
///
/// Unlike pacman's `files`, directories are listed exactly like files, so
/// they cannot be filtered out. That is harmless here: a directory entry
/// can only ever answer a lookup for a directory, and an executable path
/// never is one.
fn parse_dpkg_list(text: &str) -> impl Iterator<Item = String> + '_ {
    text.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() || line == "/." || !line.starts_with('/') {
            return None;
        }
        Some(line.to_string())
    })
}

impl PackageDb for Dpkg {
    fn name(&self) -> &'static str {
        "dpkg"
    }

    fn lookup(&self, exe: &Path) -> Option<PackageFile> {
        let pkg = self.cache.owner_of(exe, |s| self.build_index(s))?;
        Some(PackageFile {
            package: pkg,
            // Deliberately unverified; see the type docs.
            sha256: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    // -- mtree parsing ------------------------------------------------------

    /// Builds a gzipped mtree at `path` from raw text.
    fn write_mtree(path: &Path, body: &str) {
        let f = std::fs::File::create(path).unwrap();
        let mut gz = GzEncoder::new(f, Compression::fast());
        gz.write_all(body.as_bytes()).unwrap();
        gz.finish().unwrap();
    }

    /// The real thing: header, a /set line, the exact line format pacman
    /// writes, an escaped path, a directory, a symlink with no digest, and
    /// a truncated/garbage line.
    const MTREE: &str = concat!(
        "#mtree\n",
        "/set type=file uid=0 gid=0 mode=644\n",
        "./.PKGINFO time=1782282358.0 size=1268 sha256digest=92835fe83d3c93f4\n",
        "/set mode=755\n",
        "./usr time=1782282358.0 type=dir\n",
        "./usr/bin time=1782282358.0 type=dir\n",
        "./usr/bin/curl time=1782282358.0 size=223624 sha256digest=fde59bde5e1ffc1476eaa85c49fc9935e007b8c5410df6e7dc9b53fb3ce8ec04\n",
        "./usr/bin/curl-config time=1782282358.0 size=6057 sha256digest=f896849a5706e44c2558156e90d0576bcd4f8d3e990c7a7facf1b774b25e48d8\n",
        "./usr/share/x/Librem\\0405.conf time=1781523786.0 size=700 sha256digest=5326b590a6f015c7fccde8a773c87534e81b1943c1a479ebdc33cd99db3ad640\n",
        "./usr/lib/link time=1781523786.0 type=link link=../bin/curl\n",
        "./usr/bin/truncated\n",
        "\x00\x01garbage line with no equals\n",
        "/unset mode\n",
    );

    fn mtree_fixture(dir: &Path) -> PathBuf {
        let p = dir.join("mtree");
        write_mtree(&p, MTREE);
        p
    }

    #[test]
    fn mtree_returns_the_digest_for_the_right_path() {
        let tmp = tempfile::tempdir().unwrap();
        let m = mtree_fixture(tmp.path());
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/bin/curl")).unwrap(),
            Some("fde59bde5e1ffc1476eaa85c49fc9935e007b8c5410df6e7dc9b53fb3ce8ec04".into())
        );
        // A different file in the same package, so the scan really keys on
        // the path and not on "first digest wins".
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/bin/curl-config")).unwrap(),
            Some("f896849a5706e44c2558156e90d0576bcd4f8d3e990c7a7facf1b774b25e48d8".into())
        );
    }

    #[test]
    fn mtree_unescapes_octal_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let m = mtree_fixture(tmp.path());
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/share/x/Librem 5.conf")).unwrap(),
            Some("5326b590a6f015c7fccde8a773c87534e81b1943c1a479ebdc33cd99db3ad640".into())
        );
        // The escaped form must NOT match literally.
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/share/x/Librem\\0405.conf")).unwrap(),
            None
        );
    }

    #[test]
    fn mtree_missing_and_digestless_paths_are_none_not_panics() {
        let tmp = tempfile::tempdir().unwrap();
        let m = mtree_fixture(tmp.path());
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/bin/nope")).unwrap(),
            None
        );
        // Directory and symlink entries carry no sha256digest.
        assert_eq!(mtree_digest_for(&m, Path::new("/usr/bin")).unwrap(), None);
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/lib/link")).unwrap(),
            None
        );
        // Truncated record: path present, no keywords at all.
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/bin/truncated")).unwrap(),
            None
        );
    }

    #[test]
    fn mtree_set_default_digest_is_tolerated() {
        // pacman never writes a sha256digest into /set, but the format
        // allows it and we must not crash - or ignore it.
        let tmp = tempfile::tempdir().unwrap();
        let m = tmp.path().join("mtree");
        write_mtree(
            &m,
            "#mtree\n/set type=file sha256digest=deadbeef\n./usr/bin/a time=1.0 size=1\n\
             ./usr/bin/b time=1.0 size=1 sha256digest=cafe\n/unset sha256digest\n\
             ./usr/bin/c time=1.0 size=1\n",
        );
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/bin/a")).unwrap(),
            Some("deadbeef".into())
        );
        // A line's own keyword beats the default.
        assert_eq!(
            mtree_digest_for(&m, Path::new("/usr/bin/b")).unwrap(),
            Some("cafe".into())
        );
        assert_eq!(mtree_digest_for(&m, Path::new("/usr/bin/c")).unwrap(), None);
    }

    #[test]
    fn mtree_that_is_not_gzip_is_an_error_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let m = tmp.path().join("mtree");
        std::fs::write(&m, b"this is not gzip at all\n").unwrap();
        assert!(mtree_digest_for(&m, Path::new("/usr/bin/curl")).is_err());
        assert!(mtree_digest_for(Path::new("/nonexistent/mtree"), Path::new("/x")).is_err());
    }

    #[test]
    fn unescape_handles_backslashes_and_stray_escapes() {
        assert_eq!(unescape_mtree("a\\040b"), b"a b".to_vec());
        assert_eq!(unescape_mtree("a\\\\b"), b"a\\b".to_vec());
        // \9 is not octal: keep the backslash rather than eating the byte.
        assert_eq!(unescape_mtree("a\\9b"), b"a\\9b".to_vec());
        // Truncated escape at end of string.
        assert_eq!(unescape_mtree("ab\\"), b"ab\\".to_vec());
        assert_eq!(unescape_mtree("ab\\04"), b"ab\\04".to_vec());
    }

    // -- `files` parsing ----------------------------------------------------

    #[test]
    fn files_list_skips_the_header_and_directories() {
        let text = "%FILES%\nusr/\nusr/bin/\nusr/bin/curl\nusr/bin/curl-config\n";
        let got: Vec<String> = parse_files_list(text).collect();
        assert_eq!(got, vec!["/usr/bin/curl", "/usr/bin/curl-config"]);
    }

    #[test]
    fn files_list_normalises_a_leading_slash_and_ignores_blanks() {
        // Paths are written without a leading slash; tolerate one anyway
        // and never emit "//usr/bin/x".
        let text = "%FILES%\n/usr/bin/a\n\nusr/bin/b\n";
        let got: Vec<String> = parse_files_list(text).collect();
        assert_eq!(got, vec!["/usr/bin/a", "/usr/bin/b"]);
    }

    #[test]
    fn files_list_stops_at_the_backup_section() {
        // %BACKUP% rows are "path<TAB>md5" and must not be read as paths.
        let text =
            "%FILES%\nusr/bin/bash\netc/bash.bashrc\n\n%BACKUP%\netc/bash.bashrc\t3f31a9e9\n";
        let got: Vec<String> = parse_files_list(text).collect();
        assert_eq!(got, vec!["/usr/bin/bash", "/etc/bash.bashrc"]);
    }

    #[test]
    fn files_list_without_a_header_yields_nothing() {
        assert_eq!(parse_files_list("usr/bin/curl\n").count(), 0);
    }

    // -- package directory name splitting -----------------------------------

    #[test]
    fn package_dir_splits_from_the_right() {
        assert_eq!(split_pkg_dir("curl-8.21.0-1"), ("curl", "8.21.0-1"));
        // The trap: a name that itself contains hyphens.
        assert_eq!(
            split_pkg_dir("adwaita-icon-theme-50.0-1"),
            ("adwaita-icon-theme", "50.0-1")
        );
        assert_eq!(split_pkg_dir("7zip-26.02-1"), ("7zip", "26.02-1"));
        assert_eq!(split_pkg_dir("aalib-1.4rc5-19"), ("aalib", "1.4rc5-19"));
        // Epoch versions keep their colon in the version half.
        assert_eq!(split_pkg_dir("gnutls-1:3.8.13-2"), ("gnutls", "1:3.8.13-2"));
        // Malformed: hand it back whole rather than inventing a version.
        assert_eq!(split_pkg_dir("nohyphens"), ("nohyphens", ""));
        assert_eq!(split_pkg_dir("one-hyphen"), ("one-hyphen", ""));
    }

    // -- decision table -----------------------------------------------------

    fn record(sha: Option<&str>) -> PackageFile {
        PackageFile {
            package: "curl 8.21.0-1".into(),
            sha256: sha.map(Into::into),
        }
    }

    #[test]
    fn decision_table() {
        // Owned, digests agree.
        assert_eq!(
            decide(Some(&record(Some("aa"))), Some("aa")),
            Provenance::Verified
        );
        // Owned, digests disagree: the loud case.
        assert_eq!(
            decide(Some(&record(Some("aa"))), Some("bb")),
            Provenance::Modified
        );
        // Nobody owns the path.
        assert_eq!(decide(None, Some("aa")), Provenance::Unpackaged);
        assert_eq!(decide(None, None), Provenance::Unpackaged);
        // Owned but the database records no digest (dpkg): "packaged
        // without verification" is Unknown with the package name kept.
        assert_eq!(decide(Some(&record(None)), Some("aa")), Provenance::Unknown);
        // Owned and a digest exists, but we could not hash the running
        // binary (oversized, unreadable): nothing to compare.
        assert_eq!(decide(Some(&record(Some("aa"))), None), Provenance::Unknown);
    }

    #[test]
    fn digest_comparison_is_case_insensitive() {
        assert_eq!(
            decide(Some(&record(Some("ABCdef"))), Some("abcDEF")),
            Provenance::Verified
        );
    }

    // -- backend detection + end-to-end over fake trees ---------------------

    /// Builds a fake pacman tree with one package owning /usr/bin/curl.
    fn fake_pacman(root: &Path, digest: &str) {
        let pkg = root.join("curl-8.21.0-1");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("files"),
            "%FILES%\nusr/\nusr/bin/\nusr/bin/curl\nusr/bin/curl-config\n",
        )
        .unwrap();
        write_mtree(
            &pkg.join("mtree"),
            &format!(
                "#mtree\n/set type=file uid=0 gid=0 mode=755\n\
                 ./usr/bin/curl time=1782282358.0 size=223624 sha256digest={digest}\n"
            ),
        );
    }

    #[test]
    fn pacman_backend_finds_package_and_digest() {
        let tmp = tempfile::tempdir().unwrap();
        fake_pacman(tmp.path(), "abc123");
        let db = Pacman::new(tmp.path().to_path_buf());

        let hit = db.lookup(Path::new("/usr/bin/curl")).unwrap();
        assert_eq!(hit.package, "curl 8.21.0-1");
        assert_eq!(hit.sha256.as_deref(), Some("abc123"));
        assert_eq!(decide(Some(&hit), Some("abc123")), Provenance::Verified);
        assert_eq!(decide(Some(&hit), Some("999")), Provenance::Modified);

        // Owned but absent from mtree (a file listed in `files` only):
        // package known, nothing to verify.
        let hit = db.lookup(Path::new("/usr/bin/curl-config")).unwrap();
        assert_eq!(hit.package, "curl 8.21.0-1");
        assert_eq!(hit.sha256, None);
        assert_eq!(decide(Some(&hit), Some("abc123")), Provenance::Unknown);

        // Nobody owns it.
        assert_eq!(db.lookup(Path::new("/tmp/curl")), None);
        assert_eq!(decide(None, Some("abc123")), Provenance::Unpackaged);
    }

    #[test]
    fn pacman_index_rebuilds_when_the_db_mtime_changes() {
        let tmp = tempfile::tempdir().unwrap();
        fake_pacman(tmp.path(), "abc123");
        let db = Pacman::new(tmp.path().to_path_buf());
        assert!(db.lookup(Path::new("/usr/bin/wget")).is_none());

        // Install another package; the root's mtime moves.
        let pkg = tmp.path().join("wget-1.25.0-2");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("files"), "%FILES%\nusr/bin/wget\n").unwrap();
        write_mtree(
            &pkg.join("mtree"),
            "#mtree\n./usr/bin/wget time=1.0 size=1 sha256digest=feed\n",
        );
        // Force a visibly different mtime even on a coarse-grained clock.
        filetime_bump(tmp.path());

        let hit = db.lookup(Path::new("/usr/bin/wget")).unwrap();
        assert_eq!(hit.package, "wget 1.25.0-2");
        assert_eq!(hit.sha256.as_deref(), Some("feed"));
    }

    /// Nudges a directory's mtime forward without needing the `filetime`
    /// crate: create and remove a scratch entry, then assert it moved.
    fn filetime_bump(dir: &Path) {
        let before = std::fs::metadata(dir).unwrap().modified().unwrap();
        for i in 0..1000 {
            let probe = dir.join(format!(".cfc-bump-{i}"));
            std::fs::create_dir(&probe).unwrap();
            std::fs::remove_dir(&probe).unwrap();
            if std::fs::metadata(dir).unwrap().modified().unwrap() != before {
                return;
            }
        }
        panic!("directory mtime never advanced");
    }

    #[test]
    fn dpkg_backend_is_name_only() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("curl.list"),
            "/.\n/usr\n/usr/bin\n/usr/bin/curl\n",
        )
        .unwrap();
        // md5sums exist on a real system; we deliberately never read them.
        std::fs::write(tmp.path().join("curl.md5sums"), "abc  usr/bin/curl\n").unwrap();

        let db = Dpkg::new(tmp.path().to_path_buf());
        let hit = db.lookup(Path::new("/usr/bin/curl")).unwrap();
        assert_eq!(hit.package, "curl");
        assert_eq!(hit.sha256, None, "dpkg records MD5 only; we do not verify");
        assert_eq!(decide(Some(&hit), Some("whatever")), Provenance::Unknown);
        assert_eq!(db.lookup(Path::new("/tmp/curl")), None);
    }

    #[test]
    fn dpkg_keeps_the_architecture_qualifier() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("libc6:amd64.list"), "/usr/bin/ldd\n").unwrap();
        let db = Dpkg::new(tmp.path().to_path_buf());
        assert_eq!(
            db.lookup(Path::new("/usr/bin/ldd")).unwrap().package,
            "libc6:amd64"
        );
    }

    // --- rpm ------------------------------------------------------------

    const SHA_CURL: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const MD5_OLD: &str = "22222222222222222222222222222222";

    /// A stand-in for `rpm(8)` that prints `out` and exits.
    ///
    /// The real binary is not required to test this: what is being tested is
    /// the parse and the timeout, not rpm itself. A shell script also lets a
    /// test make rpm hang, which no installed rpm would do on demand.
    fn fake_rpm(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("fake-rpm");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn rpm_with_output(dir: &Path, lines: &str) -> Rpm {
        let db = dir.join("rpmdb");
        std::fs::create_dir_all(&db).unwrap();
        // `cat <<'EOF'` keeps tabs and avoids any quoting of the payload.
        let prog = fake_rpm(dir, &format!("cat <<'CFCEOF'\n{lines}CFCEOF"));
        Rpm::with_program(db, prog)
    }

    #[test]
    fn rpm_reports_the_package_and_verifies_against_a_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let db = rpm_with_output(
            tmp.path(),
            &format!(
                "curl 8.0.1-1.el9\t-rwxr-xr-x\t/usr/bin/curl\t{SHA_CURL}\n\
                 curl 8.0.1-1.el9\tdrwxr-xr-x\t/usr/share/doc/curl\t\n"
            ),
        );
        let rec = db.lookup(Path::new("/usr/bin/curl")).expect("owned");
        assert_eq!(rec.package, "curl 8.0.1-1.el9");
        assert_eq!(rec.sha256.as_deref(), Some(SHA_CURL));

        // The directory in that output must not have been indexed: if it had,
        // /usr/share/doc/curl would answer for its whole subtree.
        assert!(db.lookup(Path::new("/usr/share/doc/curl")).is_none());
        assert!(db.lookup(Path::new("/usr/bin/wget")).is_none());
    }

    #[test]
    fn rpm_drops_an_md5_digest_rather_than_comparing_it() {
        // An old package, or one built with %_source_filedigest_algorithm 1.
        // Reporting the MD5 as if it were a SHA-256 would make `decide` compare
        // it against the running digest and call a clean file Modified.
        let tmp = tempfile::tempdir().unwrap();
        let db = rpm_with_output(
            tmp.path(),
            &format!("ancient 1.0-1\t-rwxr-xr-x\t/usr/bin/ancient\t{MD5_OLD}\n"),
        );
        let rec = db.lookup(Path::new("/usr/bin/ancient")).expect("owned");
        assert_eq!(rec.package, "ancient 1.0-1");
        assert_eq!(
            rec.sha256, None,
            "an MD5 must land in the owned-but-unverifiable state, not be compared"
        );
        assert_eq!(
            decide(Some(&rec), Some("whatever")),
            Provenance::Unknown,
            "and it must read as Unknown, never Modified"
        );
    }

    #[test]
    fn rpm_that_does_not_answer_leaves_the_index_empty_rather_than_blocking() {
        // The `dnf` case: a transaction holds the database and the query waits.
        // The firewall must not wait with it - the thread building this index
        // is on the packet path.
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("rpmdb");
        std::fs::create_dir_all(&db).unwrap();
        let prog = fake_rpm(tmp.path(), "sleep 30");
        let mut rpm = Rpm::with_program(db, prog);
        // The shipped ceiling is 10s; there is nothing to learn from spending
        // it here. What matters is that a deadline exists, is honoured, and is
        // far below the child's own lifetime.
        rpm.timeout = Duration::from_millis(300);

        let started = Instant::now();
        let e = rpm.run_query().expect_err("a hung rpm must be an error");
        let took = started.elapsed();
        assert!(
            took >= rpm.timeout,
            "it gave up before the deadline: took {took:?}, error was: {e:#}"
        );
        assert!(
            took < Duration::from_secs(10),
            "the query was not bounded: took {took:?}"
        );
    }

    #[test]
    fn a_busy_binary_is_retried_rather_than_reported_as_an_empty_index() {
        // ETXTBSY means someone holds the binary open for writing. For `rpm`
        // that is rpm upgrading itself; in this suite it is another test
        // thread's fork() inheriting a still-open write fd, which made all
        // three spawning tests flake about one run in twenty.
        //
        // The script starts unwritable-and-busy by being held open for writing
        // here, and becomes runnable once that handle drops - which is exactly
        // the shape the retry exists for.
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("rpmdb");
        std::fs::create_dir_all(&db).unwrap();
        let prog = tmp.path().join("busy-rpm");
        let mut f = std::fs::File::create(&prog).unwrap();
        f.write_all(b"#!/bin/sh\necho ok\n").unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();

        let rpm = Rpm::with_program(db, prog);
        let handle = std::thread::spawn(move || {
            // Still open for writing when the first attempt runs; released well
            // inside the 50 ms the retry waits.
            std::thread::sleep(Duration::from_millis(20));
            drop(f);
        });
        let out = rpm.run_query();
        handle.join().unwrap();
        assert!(
            out.is_ok(),
            "a transiently busy binary must be retried, not turned into an \
             empty index: {:?}",
            out.err()
        );
    }

    #[test]
    fn a_missing_rpm_binary_is_an_empty_index_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("rpmdb");
        std::fs::create_dir_all(&db).unwrap();
        let rpm = Rpm::with_program(db, tmp.path().join("no-such-rpm"));
        assert!(rpm.lookup(Path::new("/usr/bin/curl")).is_none());
    }

    #[test]
    fn rpm_line_parsing_rejects_what_is_not_a_file_record() {
        // Warnings and placeholders share the stream with real records.
        assert!(parse_rpm_line("").is_none());
        assert!(parse_rpm_line("warning: something happened").is_none());
        assert!(parse_rpm_line("pkg 1.0-1\tdrwxr-xr-x\t/usr/bin\t").is_none());
        assert!(
            parse_rpm_line("pkg 1.0-1\tlrwxrwxrwx\t/usr/bin/link\t").is_none(),
            "a symlink is not the file whose bytes are running"
        );
        assert!(
            parse_rpm_line("pkg 1.0-1\t-rwxr-xr-x\trelative/path\t").is_none(),
            "rpm paths are absolute; anything else is a parse that went wrong"
        );
        assert!(
            parse_rpm_line("pkg 1.0-1\t-rwxr-xr-x\t/usr/bin/a\tb\textra").is_none(),
            "a tab inside a path truncates it; skipping the file is the safe half"
        );

        let line = format!("pkg 1.0-1\t-rwxr-xr-x\t/usr/bin/a\t{SHA_CURL}");
        let (pkg, path, digest) = parse_rpm_line(&line).unwrap();
        assert_eq!((pkg, path), ("pkg 1.0-1", "/usr/bin/a"));
        assert!(digest.is_some());

        // No digest at all: a %ghost file, or one rpm chose not to record.
        let (_, _, none) = parse_rpm_line("pkg 1.0-1\t-rw-r--r--\t/var/log/x\t").unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn sha256_hex_is_decoded_strictly() {
        assert_eq!(parse_sha256_hex(SHA_CURL).unwrap()[0], 0x11);
        assert_eq!(
            parse_sha256_hex(&SHA_CURL.to_uppercase()).unwrap()[0],
            0x11,
            "rpm has emitted both cases over the years"
        );
        assert!(parse_sha256_hex("").is_none());
        assert!(parse_sha256_hex(MD5_OLD).is_none(), "32 chars is MD5");
        assert!(
            parse_sha256_hex(&"z".repeat(64)).is_none(),
            "right length, not hex"
        );
    }

    #[test]
    fn the_index_round_trips_a_digest_through_hex() {
        // The index stores 32 raw bytes and hands back a hex string; a bug in
        // either direction would compare unequal to every running digest and
        // report every packaged binary as Modified.
        let mut idx = Index::empty(None);
        let id = idx.intern_package("curl 8.0.1-1.el9").unwrap();
        idx.add_file(id, "/usr/bin/curl", parse_sha256_hex(SHA_CURL));
        let key = path_hash(Path::new("/usr/bin/curl"));
        assert_eq!(idx.digest(key).as_deref(), Some(SHA_CURL));
    }

    #[test]
    fn detection_prefers_a_backend_that_can_verify_and_gives_up_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let pac = tmp.path().join("pacman");
        let rpm = tmp.path().join("rpm");
        let deb = tmp.path().join("dpkg");
        let none = tmp.path().join("nothing");

        assert!(
            detect(&none, &none, &none).is_none(),
            "no database anywhere"
        );

        std::fs::create_dir_all(&deb).unwrap();
        assert_eq!(detect(&none, &none, &deb).map(|d| d.name()), Some("dpkg"));

        // rpm records SHA-256 and dpkg records MD5, so on a host carrying both
        // trees the one that can say something about the bytes must win.
        std::fs::create_dir_all(&rpm).unwrap();
        assert_eq!(
            detect(&none, &rpm, &deb).map(|d| d.name()),
            Some("rpm"),
            "rpm wins over dpkg: only one of them can verify"
        );

        std::fs::create_dir_all(&pac).unwrap();
        assert_eq!(
            detect(&pac, &rpm, &deb).map(|d| d.name()),
            Some("pacman"),
            "a pacman database means an Arch host; nothing else ships one"
        );
    }

    #[test]
    fn broken_packages_do_not_blind_the_index() {
        let tmp = tempfile::tempdir().unwrap();
        fake_pacman(tmp.path(), "abc123");
        // A half-installed package: directory with no `files` at all.
        std::fs::create_dir_all(tmp.path().join("halfinstalled-1.0-1")).unwrap();
        // And a stray regular file in the db root.
        std::fs::write(tmp.path().join("ALPM_DB_VERSION"), "9\n").unwrap();

        let db = Pacman::new(tmp.path().to_path_buf());
        assert_eq!(
            db.lookup(Path::new("/usr/bin/curl")).unwrap().package,
            "curl 8.21.0-1"
        );
    }

    #[test]
    fn describe_is_inert_for_non_absolute_and_deleted_binaries() {
        // These short-circuit before any backend is consulted, so they are
        // safe to assert regardless of what this host has installed.
        assert_eq!(
            describe(Path::new("<unknown>"), Some("aa")),
            (None, Provenance::Unknown)
        );
        assert_eq!(
            describe(Path::new("/usr/bin/curl (deleted)"), Some("aa")),
            (None, Provenance::Unknown)
        );
        // A path we cannot stat must read "cannot say", never "not from a
        // package" - that distinction is the difference between silence and
        // a false alarm on the one signal users are meant to act on.
        assert_eq!(
            describe(Path::new("/nonexistent/cfc-provenance-probe"), Some("aa")),
            (None, Provenance::Unknown)
        );
    }

    // -- real machine ------------------------------------------------------

    /// Drives the real production entry point against this host's actual
    /// package database. Ignored by default (it needs an Arch box with curl
    /// installed); run with
    /// `cargo test -p cfc-daemon -- --ignored --nocapture real_machine`.
    #[test]
    #[ignore = "reads the real /var/lib/pacman; Arch-only"]
    fn real_machine_curl_is_verified_and_a_tmp_copy_is_not() {
        // ENABLED is process-wide and config.rs's tests toggle it; pin it
        // so this test cannot be raced into a false pass.
        set_enabled(true);
        let backend = BACKEND.as_ref().expect("a package database on this host");
        println!("backend: {}", backend.name());

        let curl = Path::new("/usr/bin/curl");
        // Hash the real file the way process_resolve does, from the bytes
        // on disk.
        let running = sha256_of(curl);
        println!("/usr/bin/curl running sha256 = {running}");

        // Cold: this call also builds the whole path index.
        let started = Instant::now();
        let (package, provenance) = describe(curl, Some(&running));
        println!(
            "/usr/bin/curl -> package {package:?} provenance {provenance:?} \
             (cold, incl. index build: {:?})",
            started.elapsed()
        );
        assert_eq!(package.as_deref(), Some("curl 8.21.0-1"));
        assert_eq!(
            provenance,
            Provenance::Verified,
            "an untouched /usr/bin/curl must verify"
        );

        // Warm: index and per-exe record are both cached now.
        let started = Instant::now();
        let again = describe(curl, Some(&running));
        println!(
            "/usr/bin/curl (warm) -> {again:?} in {:?}",
            started.elapsed()
        );
        assert_eq!(again, (package.clone(), Provenance::Verified));

        // The same path with different running bytes is the security case:
        // the file the kernel mapped is not the file the package shipped.
        let tampered = describe(curl, Some(&"0".repeat(64)));
        println!("/usr/bin/curl with a foreign digest -> {tampered:?}");
        assert_eq!(
            tampered,
            (Some("curl 8.21.0-1".to_string()), Provenance::Modified)
        );

        // A byte-identical copy in /tmp is owned by nobody: the dropper case.
        let tmp = tempfile::tempdir().unwrap();
        let copy = tmp.path().join("curl");
        std::fs::copy(curl, &copy).unwrap();
        let dropped = describe(&copy, Some(&running));
        println!("{} -> {dropped:?}", copy.display());
        assert_eq!(
            dropped,
            (None, Provenance::Unpackaged),
            "identical bytes, but no package owns that path"
        );
    }

    #[cfg(test)]
    fn sha256_of(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        let mut f = std::fs::File::open(path).unwrap();
        let mut h = Sha256::new();
        std::io::copy(&mut f, &mut h).unwrap();
        format!("{:x}", h.finalize())
    }
}
