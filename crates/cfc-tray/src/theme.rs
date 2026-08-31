//! Runtime icon-theme fallback for SNI hosts that honour `icon_name` only.
//!
//! `icon_pixmap` carries an embedded raster precisely so the tray is
//! usable before the package installs the theme SVG - and some hosts
//! never look at it. Observed on quickshell/Noctalia: the host resolves
//! `icon_name` against the icon theme and, failing that, shows a
//! broken-image placeholder instead of falling back to the pixmap. The
//! spec's escape hatch for exactly this case is `IconThemePath`: an
//! extra directory the host adds to its icon search path. So when
//! "colony-firewall" is not resolvable in this session's theme
//! directories, the packaged SVG is written under
//! `$XDG_RUNTIME_DIR/cfc-tray/icons` and that path is exported.
//!
//! This only engages when the theme icon is absent. With the package
//! installed the exported path stays empty, which is byte for byte what
//! the tray exported before this module existed - hosts that already
//! worked see nothing new.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// The themed icon name, installed by the package to
/// `hicolor/scalable/apps`. The probe and the runtime theme both key on
/// it, so it lives here and `main` borrows it.
pub const ICON_NAME: &str = "colony-firewall";

/// The packaged theme icon. `include_str!` reaches outside the crate on
/// purpose: `pkg/colony-firewall.svg` is the file `PKGBUILD` installs
/// into hicolor, and embedding *that* file keeps one artwork - the tray
/// shows the same icon whether the package installed it or this module
/// wrote it at runtime. If the asset moves, this stops compiling, which
/// is the right way to find out.
const ICON_SVG: &str = include_str!("../../../pkg/colony-firewall.svg");

/// Extensions an icon lookup accepts, per the icon theme spec.
const ICON_EXTENSIONS: [&str; 3] = ["svg", "png", "xpm"];

/// The index a strict host needs. Qt only treats a search path as
/// holding a theme once `<path>/hicolor/index.theme` names its
/// directories; without it a host that *replaces* its search paths with
/// ours (rather than appending) would resolve nothing. GTK is looser
/// and also finds the flat copy written next to it.
const INDEX_THEME: &str = "\
[Icon Theme]
Name=Hicolor
Comment=Runtime fallback written by colony-firewall-tray
Hidden=true
Directories=scalable/apps

[scalable/apps]
Size=64
MinSize=8
MaxSize=512
Type=Scalable
Context=Applications
";

/// Where this session's icon lookup searches, per the freedesktop icon
/// theme spec: `$HOME/.icons` (legacy), `$XDG_DATA_HOME/icons`, the
/// `icons` of every `$XDG_DATA_DIRS` entry, and the flat
/// `/usr/share/pixmaps`. Unset *and empty* variables get their spec
/// defaults, the same reading `socket_path_from_env` gives `CFC_SOCKET`.
fn icon_roots(
    home: Option<&OsStr>,
    data_home: Option<&OsStr>,
    data_dirs: Option<&OsStr>,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let home = home.filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(h) = &home {
        roots.push(h.join(".icons"));
    }
    match data_home.filter(|v| !v.is_empty()) {
        Some(dh) => roots.push(PathBuf::from(dh).join("icons")),
        None => {
            if let Some(h) = &home {
                roots.push(h.join(".local/share/icons"));
            }
        }
    }
    let dirs = data_dirs
        .filter(|v| !v.is_empty())
        .map(OsStr::to_os_string)
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    for dir in std::env::split_paths(&dirs) {
        if !dir.as_os_str().is_empty() {
            roots.push(dir.join("icons"));
        }
    }
    roots.push(PathBuf::from("/usr/share/pixmaps"));
    roots
}

/// True when `name` is installed where the probe looks: flat in a root
/// (the pixmaps convention) or under any `hicolor/<size>/apps/`.
///
/// Deliberately hicolor-only rather than a walk of every installed
/// theme: hicolor is the fallback every theme chain ends in and the
/// directory the package installs into. The bias that buys is the safe
/// one - a miss here only puts an extra, identical icon on the host's
/// search path, while the probe can never claim "installed" for an icon
/// no fallback chain would find.
fn theme_icon_installed(roots: &[PathBuf], name: &str) -> bool {
    let named = |dir: &Path| {
        ICON_EXTENSIONS
            .iter()
            .any(|ext| dir.join(format!("{name}.{ext}")).is_file())
    };
    roots.iter().any(|root| {
        if named(root) {
            return true;
        }
        // A missing or unreadable hicolor is just "not here".
        std::fs::read_dir(root.join("hicolor"))
            .map(|entries| entries.flatten().any(|e| named(&e.path().join("apps"))))
            .unwrap_or(false)
    })
}

/// Writes the embedded SVG as a small self-contained icon theme at
/// `root`, in both layouts hosts are known to use:
///
/// ```text
/// root/colony-firewall.svg                       flat, GTK unthemed lookup
/// root/hicolor/index.theme
/// root/hicolor/scalable/apps/colony-firewall.svg
/// ```
///
/// Rewritten on every start, so upgraded artwork replaces stale copies.
fn write_runtime_theme(root: &Path) -> std::io::Result<()> {
    let apps = root.join("hicolor/scalable/apps");
    std::fs::create_dir_all(&apps)?;
    std::fs::write(root.join(format!("{ICON_NAME}.svg")), ICON_SVG)?;
    std::fs::write(root.join("hicolor/index.theme"), INDEX_THEME)?;
    std::fs::write(apps.join(format!("{ICON_NAME}.svg")), ICON_SVG)?;
    Ok(())
}

/// The directory to export as the SNI `IconThemePath`, or `None` to
/// export nothing.
///
/// `None` on the happy path - the theme icon is installed, and shadowing
/// it would help nobody - and on the two failure paths, each with one
/// warning that names the fix instead of leaving a placeholder to be
/// puzzled over. `$XDG_RUNTIME_DIR` is the only place considered,
/// deliberately not `/tmp`: a predictable name in a world-shared
/// directory is a symlink game waiting to happen, and a session without
/// a runtime dir has bigger problems than an icon.
pub fn runtime_icon_theme_path() -> Option<PathBuf> {
    let env = |k: &str| std::env::var_os(k);
    let roots = icon_roots(
        env("HOME").as_deref(),
        env("XDG_DATA_HOME").as_deref(),
        env("XDG_DATA_DIRS").as_deref(),
    );
    if theme_icon_installed(&roots, ICON_NAME) {
        debug!("\"{ICON_NAME}\" theme icon is installed; no runtime fallback needed");
        return None;
    }
    let Some(runtime) = env("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) else {
        warn!(
            "the \"{ICON_NAME}\" theme icon is not installed and $XDG_RUNTIME_DIR is \
             not set, so hosts that honour icon_name only will show a placeholder - \
             install the package's icon into hicolor, or use a host that honours \
             icon_pixmap"
        );
        return None;
    };
    let root = PathBuf::from(runtime).join("cfc-tray/icons");
    match write_runtime_theme(&root) {
        Ok(()) => {
            info!(
                path = %root.display(),
                "theme icon not installed; exporting a runtime IconThemePath"
            );
            Some(root)
        }
        Err(e) => {
            warn!(
                "writing the runtime icon theme to {}: {e} - hosts that honour \
                 icon_name only will show a placeholder (icon_pixmap hosts still \
                 get the embedded raster)",
                root.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<&OsStr> {
        Some(OsStr::new(s))
    }

    #[test]
    fn embedded_svg_is_the_real_artwork() {
        assert!(ICON_SVG.contains("<svg"), "not an SVG at all");
        assert!(
            ICON_SVG.trim_end().ends_with("</svg>"),
            "truncated or not the whole file"
        );
    }

    #[test]
    fn icon_roots_defaults_when_nothing_is_set() {
        let roots = icon_roots(os("/home/u"), None, None);
        assert_eq!(
            roots,
            [
                PathBuf::from("/home/u/.icons"),
                "/home/u/.local/share/icons".into(),
                "/usr/local/share/icons".into(),
                "/usr/share/icons".into(),
                "/usr/share/pixmaps".into(),
            ]
        );
    }

    #[test]
    fn icon_roots_honours_the_xdg_variables() {
        let roots = icon_roots(os("/home/u"), os("/data/home"), os("/a:/b"));
        assert_eq!(
            roots,
            [
                PathBuf::from("/home/u/.icons"),
                "/data/home/icons".into(),
                "/a/icons".into(),
                "/b/icons".into(),
                "/usr/share/pixmaps".into(),
            ]
        );
    }

    #[test]
    fn icon_roots_treats_empty_as_unset() {
        // An empty HOME drops both home-derived roots rather than
        // producing "/.icons"; empty XDG variables fall back to defaults.
        let roots = icon_roots(os(""), os(""), os(""));
        assert_eq!(
            roots,
            [
                PathBuf::from("/usr/local/share/icons"),
                "/usr/share/icons".into(),
                "/usr/share/pixmaps".into(),
            ]
        );
    }

    #[test]
    fn probe_misses_on_empty_and_absent_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let roots = vec![tmp.path().to_path_buf(), tmp.path().join("does-not-exist")];
        assert!(!theme_icon_installed(&roots, ICON_NAME));
    }

    #[test]
    fn probe_finds_the_icon_under_any_hicolor_size_dir() {
        for dir in ["scalable", "22x22", "48x48"] {
            for ext in ICON_EXTENSIONS {
                let tmp = tempfile::tempdir().unwrap();
                let apps = tmp.path().join("hicolor").join(dir).join("apps");
                std::fs::create_dir_all(&apps).unwrap();
                std::fs::write(apps.join(format!("{ICON_NAME}.{ext}")), "x").unwrap();
                assert!(
                    theme_icon_installed(&[tmp.path().to_path_buf()], ICON_NAME),
                    "missed hicolor/{dir}/apps/{ICON_NAME}.{ext}"
                );
            }
        }
    }

    #[test]
    fn probe_finds_a_flat_pixmap() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(format!("{ICON_NAME}.png")), "x").unwrap();
        assert!(theme_icon_installed(&[tmp.path().to_path_buf()], ICON_NAME));
    }

    #[test]
    fn probe_ignores_other_names_and_non_apps_contexts() {
        let tmp = tempfile::tempdir().unwrap();
        let scalable = tmp.path().join("hicolor/scalable");
        std::fs::create_dir_all(scalable.join("apps")).unwrap();
        std::fs::create_dir_all(scalable.join("mimetypes")).unwrap();
        // Right context, wrong name.
        std::fs::write(scalable.join("apps/other-app.svg"), "x").unwrap();
        // Right name, wrong context.
        std::fs::write(scalable.join(format!("mimetypes/{ICON_NAME}.svg")), "x").unwrap();
        // A directory *named* like the icon must not count as a file.
        std::fs::create_dir_all(tmp.path().join(format!("{ICON_NAME}.png"))).unwrap();
        assert!(!theme_icon_installed(
            &[tmp.path().to_path_buf()],
            ICON_NAME
        ));
    }

    #[test]
    fn runtime_theme_writes_both_layouts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("icons");
        write_runtime_theme(&root).unwrap();

        let flat = std::fs::read_to_string(root.join(format!("{ICON_NAME}.svg"))).unwrap();
        let themed =
            std::fs::read_to_string(root.join(format!("hicolor/scalable/apps/{ICON_NAME}.svg")))
                .unwrap();
        assert_eq!(flat, ICON_SVG);
        assert_eq!(themed, ICON_SVG);

        // What was written must satisfy the probe it is the fallback for.
        assert!(theme_icon_installed(&[root], ICON_NAME));
    }

    #[test]
    fn index_theme_names_the_directory_the_svg_lands_in() {
        // Guards INDEX_THEME and write_runtime_theme against drifting
        // apart: every directory the index promises must hold the icon.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        write_runtime_theme(&root).unwrap();

        let index = std::fs::read_to_string(root.join("hicolor/index.theme")).unwrap();
        let dirs = index
            .lines()
            .find_map(|l| l.strip_prefix("Directories="))
            .expect("index.theme lists no Directories=");
        assert!(!dirs.is_empty());
        for dir in dirs.split(',') {
            let icon = root
                .join("hicolor")
                .join(dir)
                .join(format!("{ICON_NAME}.svg"));
            assert!(
                icon.is_file(),
                "index promises {dir} but {icon:?} is missing"
            );
            // And the per-directory section Qt requires exists.
            assert!(index.contains(&format!("[{dir}]")));
        }
    }

    #[test]
    fn runtime_theme_overwrites_a_stale_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(format!("{ICON_NAME}.svg")), "stale artwork").unwrap();
        write_runtime_theme(&root).unwrap();
        let flat = std::fs::read_to_string(root.join(format!("{ICON_NAME}.svg"))).unwrap();
        assert_eq!(flat, ICON_SVG);
    }
}
