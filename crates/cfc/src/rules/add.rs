//! `cfc rules add`.

use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};
use anyhow::Context;
use cfc_client::{proto, Client};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct AddArgs {
    /// Human-readable rule name.
    #[arg(long)]
    pub name: Option<String>,

    /// Verdict to apply when the rule matches.
    #[arg(long, value_enum, default_value_t = ActionArg::Allow)]
    pub action: ActionArg,

    /// How long to keep the rule.
    #[arg(long, value_enum, default_value_t = DurationArg::Always)]
    pub duration: DurationArg,

    /// Which direction this rule is about. Omitted means **outbound**.
    ///
    /// Not "both". Every rule written before inbound filtering existed omitted
    /// this and every one was about traffic leaving, so unset keeps that
    /// meaning - otherwise enabling the input chain would silently reinterpret
    /// all of them. Admitting traffic into this machine needs `--direction in`,
    /// always.
    ///
    /// Inbound rules are how you authorise traffic *into* this machine:
    /// nothing gets in without one. Note that inbound, `--dst-port` is the
    /// port on THIS host and `--src-net` is the peer - `--dst-net` is refused,
    /// because inbound the destination is you.
    #[arg(long, value_enum)]
    pub direction: Option<DirectionArg>,

    /// Match flows whose source IP falls in this CIDR.
    ///
    /// The inbound counterpart of --dst-net: "who may reach us".
    #[arg(long = "src-net")]
    pub src_net: Option<String>,

    /// Match flows coming from this source port.
    #[arg(long = "src-port")]
    pub src_port: Option<u16>,

    /// Match flows from this executable path.
    #[arg(long)]
    pub exe: Option<PathBuf>,

    /// Bind the rule to the executable's *contents*, not just its path.
    ///
    /// Reads `--exe` now, hashes it, and stores that digest in the rule. The
    /// rule then stops applying the moment the file at that path changes -
    /// a package update, a rebuild, or someone putting a different program
    /// there. Without this, a rule follows the path: replace the file and the
    /// replacement inherits the permission.
    ///
    /// The cost is that an ordinary update revokes the rule too, so this is
    /// per-rule and off by default. Use it where the answer matters more than
    /// the convenience.
    #[arg(long = "pin-hash", requires = "exe")]
    pub pin_hash: bool,

    /// Bind the rule to this exact sha256, given as 64 hex characters.
    ///
    /// The explicit form of `--pin-hash`, for a digest you already have -
    /// from `cfc rules show`, from a build, or from a vendor.
    #[arg(long = "sha256", conflicts_with = "pin_hash", requires = "exe")]
    pub sha256: Option<String>,

    /// Match flows owned by this uid.
    #[arg(long)]
    pub uid: Option<u32>,

    /// Unsupported: hostnames are diagnostic only; use --dst-net for numeric policy.
    #[arg(long = "dst-host")]
    pub dst_host: Option<String>,

    /// Match flows whose dst IP falls in this CIDR (e.g. 192.0.2.0/24).
    #[arg(long = "dst-net")]
    pub dst_net: Option<String>,

    /// Match flows targeting this destination port.
    #[arg(long = "dst-port")]
    pub dst_port: Option<u16>,

    /// Match flows of this protocol.
    #[arg(long, value_enum)]
    pub protocol: Option<ProtocolArg>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ActionArg {
    Allow,
    Deny,
    Reject,
}

impl ActionArg {
    pub fn to_proto(self) -> proto::Action {
        match self {
            ActionArg::Allow => proto::Action::Allow,
            ActionArg::Deny => proto::Action::Deny,
            ActionArg::Reject => proto::Action::Reject,
        }
    }
}

/// Durations `rules add` can actually store. `once` is deliberately absent:
/// it answers a single prompt and the daemon refuses to persist it on every
/// upsert, so offering it here advertised a flag value whose only possible
/// outcome was a wire error naming no flag. The prompt flow still uses
/// `Duration::Once` legitimately - it submits a verdict, not a rule - and
/// does so through `proto::Duration` directly, not this enum.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DurationArg {
    UntilRestart,
    Always,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ProtocolArg {
    Tcp,
    Udp,
    Icmp,
}

/// `--direction in|out`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DirectionArg {
    /// Traffic this machine is sending.
    #[value(alias = "outbound")]
    Out,
    /// Traffic arriving at this machine.
    #[value(alias = "inbound")]
    In,
}

impl DirectionArg {
    fn to_proto(self) -> proto::Direction {
        match self {
            DirectionArg::Out => proto::Direction::Outbound,
            DirectionArg::In => proto::Direction::Inbound,
        }
    }
}

impl ProtocolArg {
    fn to_proto(self) -> proto::Protocol {
        match self {
            ProtocolArg::Tcp => proto::Protocol::Tcp,
            ProtocolArg::Udp => proto::Protocol::Udp,
            ProtocolArg::Icmp => proto::Protocol::Icmp,
        }
    }
}

pub async fn add(client: &mut Client, args: AddArgs, format: OutputFormat) -> CliResult {
    cfc_core::RuleScope {
        dst_host: args.dst_host.clone(),
        ..cfc_core::RuleScope::any()
    }
    .reject_hostname_policy()
    .map_err(anyhow::Error::msg)?;
    if let Some(net) = &args.dst_net {
        net.parse::<ipnet::IpNet>()
            .with_context(|| format!("--dst-net {net} is not a valid CIDR"))?;
    }
    if let Some(net) = &args.src_net {
        net.parse::<ipnet::IpNet>()
            .with_context(|| format!("--src-net {net} is not a valid CIDR"))?;
    }
    // Caught here as well as at the daemon, so the message can name the flag
    // the user typed rather than the wire field.
    if matches!(args.direction, Some(DirectionArg::In)) {
        if args.dst_net.is_some() {
            return Err(anyhow::anyhow!(
                "--dst-net cannot be combined with --direction in: inbound, the \
                 destination is this machine. Use --src-net to say which peers \
                 may reach you."
            )
            .into());
        }
        if args.dst_host.is_some() {
            return Err(anyhow::anyhow!(
                "--dst-host cannot be combined with --direction in: inbound, the \
                 destination is this machine."
            )
            .into());
        }
        // Same class of trap, different predicate: inbound flows are never
        // attributed to a program (the daemon's resolver refuses to try), so
        // a program-scoped inbound rule lists, ranks, and never fires - and
        // an allow that silently admits nothing invites its author to widen
        // it. The daemon refuses this too; caught here so the message can
        // name the flags.
        if args.exe.is_some() || args.pin_hash || args.sha256.is_some() {
            return Err(anyhow::anyhow!(
                "--exe, --pin-hash and --sha256 cannot be combined with \
                 --direction in: inbound flows cannot be attributed to a \
                 program, so the rule would never fire. Scope inbound rules \
                 with --src-net and --dst-port instead."
            )
            .into());
        }
    }

    let duration = match args.duration {
        DurationArg::UntilRestart => proto::Duration::UntilRestart,
        DurationArg::Always => proto::Duration::Always,
    };

    // Require the mapped target explicitly; silently snapshotting an alias
    // would lose the operator's intent when that alias is retargeted.
    let exe = match args.exe.as_deref() {
        Some(p) => {
            let outcome = cfc_core::exe_path::resolve_policy(p).map_err(CliError::runtime)?;
            if let Some(note) = outcome.note() {
                if outcome.is_inert() {
                    eprintln!("warning: {}", output::terminal_safe(&note));
                } else {
                    eprintln!("note: {}", output::terminal_safe(&note));
                }
            }
            outcome.into_path().to_string_lossy().into_owned()
        }
        None => String::new(),
    };

    // Resolve the digest before building the scope: a `--pin-hash` that cannot
    // read the file must fail loudly rather than quietly write a path-only rule
    // the user believes is content-bound.
    let exe_sha256 = match (&args.sha256, args.pin_hash) {
        (Some(hex), _) => cfc_core::rule::canonical_exe_sha256(hex)
            .map_err(|e| CliError::Runtime(anyhow::anyhow!("--sha256: {e}")))?,
        (None, true) => {
            let path = std::path::Path::new(&exe);
            match sha256_of(path) {
                Ok(hex) => {
                    eprintln!("note: pinned to sha256 {hex}");
                    hex
                }
                Err(e) => {
                    return Err(CliError::Runtime(anyhow::anyhow!(
                        "--pin-hash could not read {}: {e}",
                        path.display()
                    )))
                }
            }
        }
        (None, false) => String::new(),
    };

    let scope = proto::RuleScope {
        exe_path: exe,
        exe_sha256,
        parent_exe: String::new(),
        uid: args.uid.unwrap_or(0),
        has_uid: args.uid.is_some(),
        dst_host: args.dst_host.clone().unwrap_or_default(),
        dst_net: args.dst_net.clone().unwrap_or_default(),
        dst_port: args.dst_port.map(u32::from).unwrap_or(0),
        has_dst_port: args.dst_port.is_some(),
        direction: args.direction.map(|d| d.to_proto() as i32).unwrap_or(0),
        has_direction: args.direction.is_some(),
        src_net: args.src_net.clone().unwrap_or_default(),
        src_port: args.src_port.map(u32::from).unwrap_or(0),
        has_src_port: args.src_port.is_some(),
        protocol: args.protocol.map(|p| p.to_proto() as i32).unwrap_or(0),
        has_protocol: args.protocol.is_some(),
    };

    let name = args.name.unwrap_or_else(|| "cli-added".into());
    let rule = proto::RuleInfo {
        duration_seconds: 0,
        id: String::new(),
        name: name.clone(),
        enabled: true,
        action: args.action.to_proto() as i32,
        duration: duration as i32,
        scope: Some(scope),
        created_at_unix_ms: 0,
        hit_count: 0,
    };

    let id = client.upsert_rule(rule).await?;
    if format.is_json() {
        return output::print_json(&serde_json::json!({ "id": id, "name": name }));
    }
    println!("added rule {id}");
    Ok(())
}

/// Largest binary the daemon will hash, so `--pin-hash` cannot write a rule
/// the daemon can never satisfy. The shared constant replaced a mirrored
/// value whose "keep in step" comment was the only thing holding the two
/// sides together.
const SHA256_MAX_LEN: u64 = cfc_core::rule::SHA256_MAX_LEN;

/// Streaming sha256 of a file, as lowercase hex.
///
/// Matches what the daemon computes for a running process: it hashes
/// `/proc/<pid>/exe`, which is the same bytes as the file on disk for an
/// unmodified binary. A rule pinned here and a process running that file
/// therefore agree.
fn sha256_of(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::{Digest as _, Sha256};
    let f = std::fs::File::open(path)?;
    // The daemon refuses to hash anything over this, so a rule pinned to a
    // larger binary could never match: `proc.sha256` would be `None` and
    // `matches_process` would answer false forever. For a *deny* that is a
    // rule that silently never fires - the CLI would confirm success and the
    // program would keep its network. Refuse here instead of writing it.
    let len = f.metadata()?.len();
    if len > SHA256_MAX_LEN {
        return Err(std::io::Error::other(format!(
            "{} is {:.1} MiB; the daemon does not hash anything over {} MiB, so a \
             rule pinned to it could never match",
            path.display(),
            len as f64 / (1024.0 * 1024.0),
            SHA256_MAX_LEN / (1024 * 1024)
        )));
    }
    let mut f = f;
    // Read in a loop rather than io::copy, and hex-encode by hand rather than
    // with `{:x}`. RustCrypto 0.11 drops `io::Write` on the hashers and returns
    // an `Array` that no longer implements `LowerHex`, so both idioms stop
    // compiling - which is what Dependabot #8 surfaced. This form compiles
    // against 0.10 and 0.11 alike, so the bump becomes a version bump again.
    //
    // Worth the care: this digest is what `--pin-hash` binds a rule to. A rule
    // that hashes differently from the daemon does not fail loudly, it simply
    // never matches.
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        use std::io::Read as _;
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

#[cfg(test)]
mod add_args_tests {
    use super::*;

    /// The daemon unconditionally refuses to persist a `Once` rule, so `add`
    /// must not offer it: every `--duration once` invocation died with a wire
    /// error naming no flag. Locked at the clap layer - reintroducing the
    /// variant is what would break this.
    #[test]
    fn rules_add_does_not_offer_a_duration_it_cannot_store() {
        use clap::ValueEnum as _;
        let offered: Vec<String> = DurationArg::value_variants()
            .iter()
            .filter_map(|v| v.to_possible_value())
            .map(|p| p.get_name().to_string())
            .collect();
        assert!(!offered.iter().any(|s| s == "once"), "{offered:?}");
        assert!(offered.iter().any(|s| s == "until-restart"), "{offered:?}");
        assert!(offered.iter().any(|s| s == "always"), "{offered:?}");
    }
}
