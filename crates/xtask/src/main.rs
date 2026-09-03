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
        "ebpf-check" => {
            let opts = Options::parse(&args[1..]);
            match ebpf_check(&object_path(&opts)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
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
           ebpf-path  [--debug] [--target <triple>]   print the object path\n  \
           ebpf-check [--debug] [--target <triple>]   check the object is loadable\n"
    );
}

// ---------------------------------------------------------------------------
// ebpf-check
// ---------------------------------------------------------------------------

/// `EM_BPF`.
const EM_BPF: u16 = 247;
/// `SHT_SYMTAB`.
const SHT_SYMTAB: u32 = 2;

/// Everything the daemon's loader looks up by name. If any of these is missing
/// the object will fail at run time on a user's machine; this turns that into a
/// build failure here.
const REQUIRED_SYMBOLS: &[&str] = &[
    // programs (aya keys `program_mut` on the symbol, not the section)
    "cfc_sched_process_exec",
    "cfc_sched_process_exit",
    "cfc_dns_ingress",
    // the two that enforce rather than observe; their link is pinned to bpffs
    "cfc_connect4",
    "cfc_connect6",
    // fallback variants for kernels without bpf_get_socket_cookie on
    // sock_addr programs; the loader tries the cookie ones first
    "cfc_connect4_basic",
    "cfc_connect6_basic",
    "cfc_sendmsg4",
    "cfc_sendmsg6",
    // maps
    "EXEC_EVENTS",
    "EXIT_EVENTS",
    "DNS_PACKETS",
    // pinned by name into /sys/fs/bpf, so their names are load-bearing across
    // daemon restarts, not just within one load
    "VERDICTS",
    "ENFORCE_STATS",
    "DENY_EVENTS",
    "SOCK_PIDS",
    // patchable .rodata globals
    "TASK_REAL_PARENT_OFFSET",
    "TASK_TGID_OFFSET",
    "EXEC_FILENAME_DATA_LOC",
    // the ABI stamp the loader requires with must_exist = true. Keep in step
    // with `cfc_ebpf_common::ABI_SYMBOL`.
    "CFC_EBPF_ABI_V4",
];

/// Sections whose absence would break loading or diagnostics.
const REQUIRED_SECTIONS: &[&str] = &[".BTF", ".BTF.ext", "license"];

/// Structural checks on the built object.
///
/// Deliberately thresholdless: it answers "would the loader find what it looks
/// for?", not "is this program cheap?". Static section size is a poor proxy for
/// verifier cost anyway - `cfc_dns_ingress` is 355 instructions on disk and
/// 17,058 through the verifier, and it is the second number that meets the
/// kernel's budget. Numeric ceilings belong in the daemon's root test, which
/// has the real count.
///
/// No dependencies, per this crate's rule, so the ELF is parsed by hand. That
/// is ~60 lines of fixed-offset reads and is worth it: a `readelf` dependency
/// would make the check silently skip on a machine without binutils.
fn ebpf_check(path: &Path) -> Result<(), String> {
    let buf = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let rd = Elf::parse(&buf)?;

    if rd.machine != EM_BPF {
        return Err(format!(
            "{} is e_machine {}, not EM_BPF ({EM_BPF}) - wrong target?",
            path.display(),
            rd.machine
        ));
    }

    let sections = rd.section_names(&buf)?;
    let symbols = rd.symbol_names(&buf)?;

    let mut missing = Vec::new();
    for want in REQUIRED_SYMBOLS {
        if !symbols.iter().any(|s| s == want) {
            missing.push(format!("symbol `{want}`"));
        }
    }
    for want in REQUIRED_SECTIONS {
        if !sections.iter().any(|(n, _)| n == want) {
            missing.push(format!("section `{want}`"));
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "{} is missing {} the loader needs:\n  {}",
            path.display(),
            if missing.len() == 1 {
                "something"
            } else {
                "things"
            },
            missing.join("\n  ")
        ));
    }

    println!("{}: ok", path.display());
    println!("  e_machine EM_BPF, {} symbols", symbols.len());
    for (name, size) in &sections {
        if name.starts_with(".BTF") || name.starts_with("tracepoint") || name.starts_with("cgroup")
        {
            println!("  {name}: {size} bytes");
        }
    }
    Ok(())
}

/// The handful of ELF64 fields this check needs.
struct Elf {
    machine: u16,
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    shstrndx: usize,
}

impl Elf {
    fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 64 || &buf[0..4] != b"\x7fELF" {
            return Err("not an ELF file".to_string());
        }
        if buf[4] != 2 {
            return Err("not ELF64".to_string());
        }
        // Little-endian only: `bpfel-unknown-none`. A big-endian object would
        // need byte-swapping throughout, and this project does not build one.
        if buf[5] != 1 {
            return Err("not little-endian (bpfeb objects are not checked here)".to_string());
        }
        Ok(Self {
            machine: u16le(buf, 18),
            shoff: u64le(buf, 40) as usize,
            shentsize: u16le(buf, 58) as usize,
            shnum: u16le(buf, 60) as usize,
            shstrndx: u16le(buf, 62) as usize,
        })
    }

    fn section(&self, buf: &[u8], i: usize) -> Result<(u32, u32, usize, usize, usize), String> {
        let off = self
            .shoff
            .checked_add(
                i.checked_mul(self.shentsize)
                    .ok_or("section index overflow")?,
            )
            .ok_or("section table overflow")?;
        if off + 64 > buf.len() {
            return Err(format!("section header {i} runs past the end of the file"));
        }
        Ok((
            u32le(buf, off),               // sh_name
            u32le(buf, off + 4),           // sh_type
            u64le(buf, off + 24) as usize, // sh_offset
            u64le(buf, off + 32) as usize, // sh_size
            u32le(buf, off + 40) as usize, // sh_link
        ))
    }

    fn section_names(&self, buf: &[u8]) -> Result<Vec<(String, usize)>, String> {
        let (_, _, stroff, strsize, _) = self.section(buf, self.shstrndx)?;
        let mut out = Vec::with_capacity(self.shnum);
        for i in 0..self.shnum {
            let (name, _, _, size, _) = self.section(buf, i)?;
            out.push((str_at(buf, stroff, strsize, name as usize), size));
        }
        Ok(out)
    }

    fn symbol_names(&self, buf: &[u8]) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for i in 0..self.shnum {
            let (_, kind, off, size, link) = self.section(buf, i)?;
            if kind != SHT_SYMTAB {
                continue;
            }
            let (_, _, stroff, strsize, _) = self.section(buf, link)?;
            // Elf64_Sym is 24 bytes: st_name u32, st_info u8, st_other u8,
            // st_shndx u16, st_value u64, st_size u64.
            let mut p = off;
            while p + 24 <= off + size && p + 24 <= buf.len() {
                let name = u32le(buf, p) as usize;
                if name != 0 {
                    out.push(str_at(buf, stroff, strsize, name));
                }
                p += 24;
            }
        }
        if out.is_empty() {
            return Err("no symbol table (was the object stripped?)".to_string());
        }
        Ok(out)
    }
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64le(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// NUL-terminated string at `off + idx` inside a string table, clamped to the
/// table so a corrupt index cannot walk off the end.
fn str_at(buf: &[u8], off: usize, size: usize, idx: usize) -> String {
    let start = off.saturating_add(idx);
    let end = off.saturating_add(size).min(buf.len());
    if start >= end {
        return String::new();
    }
    let slice = &buf[start..end];
    let n = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..n]).into_owned()
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
