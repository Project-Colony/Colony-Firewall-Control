//! Build automation for Colony Firewall Control.
//!
//! Currently one job: build `crates/cfc-ebpf` for the BPF target. That crate
//! lives in its own cargo workspace with its own `rust-toolchain.toml`, so the
//! only thing this task really does is run cargo with the right cwd — which is
//! precisely what a plain `[alias]` cannot do.
//!
//! ```text
//! cargo xtask build-ebpf            # release (the default; debug BPF is huge)
//! cargo xtask build-ebpf --debug
//! cargo xtask build-ebpf --target bpfeb-unknown-none
//! cargo xtask ebpf-path             # print where the object lands
//! ```

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const DEFAULT_TARGET: &str = "bpfel-unknown-none";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    match cmd {
        "build-ebpf" => match build_ebpf(&args[1..]) {
            Ok(path) => {
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                println!("\nbuilt {} ({size} bytes)", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        "ebpf-path" => {
            let opts = Options::parse(&args[1..]);
            println!("{}", object_path(&opts).display());
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("error: unknown task `{other}`\n");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "cargo xtask <task>\n\
         \n\
         Tasks:\n  \
           build-ebpf [--debug] [--target <triple>]   build the BPF object\n  \
           ebpf-path  [--debug] [--target <triple>]   print the object path\n"
    );
}

struct Options {
    release: bool,
    target: String,
}

impl Options {
    fn parse(args: &[String]) -> Self {
        let mut opts = Options {
            release: true,
            target: DEFAULT_TARGET.to_string(),
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--debug" => opts.release = false,
                "--release" => opts.release = true,
                "--target" => {
                    if let Some(t) = it.next() {
                        opts.target = t.clone();
                    }
                }
                _ => {}
            }
        }
        opts
    }

    fn profile_dir(&self) -> &'static str {
        if self.release {
            "release"
        } else {
            "debug"
        }
    }
}

/// Repository root, derived from this crate's manifest dir (`crates/xtask`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/xtask is two levels below the repo root")
        .to_path_buf()
}

fn ebpf_dir() -> PathBuf {
    repo_root().join("crates/cfc-ebpf")
}

/// Where cargo drops the linked object: named after the crate, no extension.
fn cargo_output_path(opts: &Options) -> PathBuf {
    ebpf_dir()
        .join("target")
        .join(&opts.target)
        .join(opts.profile_dir())
        .join("cfc-ebpf")
}

/// What everything downstream expects: `cfc-ebpf.o`.
///
/// The daemon's `DEFAULT_OBJECT_PATH`, both PKGBUILDs, `pkg/colony.json` and
/// the release tarball all use the `.o` name, while cargo emits the bare crate
/// name. Renaming it here rather than in each recipe is what stops
/// `check-release-assets.sh` from comparing a staged `cfc-ebpf` against a
/// manifest entry for `cfc-ebpf.o` and finding nothing.
fn object_path(opts: &Options) -> PathBuf {
    cargo_output_path(opts).with_extension("o")
}

fn build_ebpf(args: &[String]) -> Result<PathBuf, String> {
    let opts = Options::parse(args);
    let dir = ebpf_dir();
    if !dir.join("Cargo.toml").is_file() {
        return Err(format!("{} is not a cargo package", dir.display()));
    }

    // `cargo` here is whatever rustup shim is on PATH; `crates/cfc-ebpf`
    // carries its own `rust-toolchain.toml` pinning nightly, so running with
    // cwd = that directory automatically selects the right toolchain. We must
    // scrub the inherited toolchain/cargo env, otherwise a parent
    // `cargo`/`rustup` invocation pins us back to stable.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("CARGO")
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        // Both PKGBUILDs export CARGO_TARGET_DIR. An absolute value silently
        // relocates the whole target tree, so the build would succeed and
        // `object_path()` would then look somewhere the object is not.
        .env_remove("CARGO_TARGET_DIR")
        .arg("build")
        .arg("--target")
        .arg(&opts.target)
        .arg("-Z")
        .arg("build-std=core");
    if opts.release {
        cmd.arg("--release");
    }

    println!(
        "running `cargo build --target {} -Z build-std=core{}` in {}",
        opts.target,
        if opts.release { " --release" } else { "" },
        dir.display()
    );

    let status = cmd
        .status()
        .map_err(|e| format!("failed to spawn cargo: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build failed with {status}"));
    }

    let built = cargo_output_path(&opts);
    if !built.is_file() {
        return Err(format!(
            "expected object at {} but it is missing",
            built.display()
        ));
    }
    // Give it the name every consumer already uses. A copy rather than a
    // rename so a rebuild is idempotent and cargo's own freshness tracking
    // still has its file where it left it.
    let out = object_path(&opts);
    std::fs::copy(&built, &out)
        .map_err(|e| format!("copying {} to {}: {e}", built.display(), out.display()))?;
    Ok(out)
}
