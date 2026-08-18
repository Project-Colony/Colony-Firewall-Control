//! Colony Firewall Control - CLI control tool.

use anyhow::Context;
use cfc_client::{convert, proto, Client};
use clap::{Parser, Subcommand, ValueEnum};
use futures::StreamExt;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "cfc", version, about = "Control the Colony Firewall daemon")]
struct Cli {
    #[arg(long, default_value = cfc_proto::DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show daemon status.
    Status,
    /// Rules CRUD.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// Stream live connections to the terminal.
    Live,
    /// Temporarily allow all flows (auto-resumes after 10 minutes).
    Pause,
    /// Resume normal filtering immediately.
    Resume,
}

#[derive(Debug, Subcommand)]
enum RulesCmd {
    /// List all persistent rules.
    List,
    /// Delete a rule by id.
    Remove { id: String },
    /// Toggle a rule's enabled state by id.
    Toggle { id: String },
    /// Add a new rule.
    Add(AddArgs),
    /// Export all rules as JSON to stdout.
    Export {
        /// Write to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import rules from a JSON file (or stdin if omitted).
    Import {
        /// File to read; reads stdin if omitted.
        file: Option<PathBuf>,
        /// Replace mode: delete all existing rules first.
        #[arg(long)]
        replace: bool,
    },
    /// Import rules from an opensnitch rules directory or single JSON file.
    ImportOpensnitch {
        /// Path to opensnitch rules dir (e.g. /etc/opensnitchd/rules) or a single .json.
        path: PathBuf,
        /// Replace mode: delete all existing rules first.
        #[arg(long)]
        replace: bool,
    },
    /// Install a small set of sensible starter rules: system DNS, NTP,
    /// pacman/paru mirrors, SSH client, your default browser.
    BootstrapDefaults {
        /// Skip already-installed defaults (matched by name).
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, clap::Args)]
struct AddArgs {
    /// Human-readable rule name.
    #[arg(long)]
    name: Option<String>,

    /// Verdict to apply when the rule matches.
    #[arg(long, value_enum, default_value_t = ActionArg::Allow)]
    action: ActionArg,

    /// How long to keep the rule.
    #[arg(long, value_enum, default_value_t = DurationArg::Always)]
    duration: DurationArg,

    /// Match flows from this executable path.
    #[arg(long)]
    exe: Option<PathBuf>,

    /// Match flows owned by this uid.
    #[arg(long)]
    uid: Option<u32>,

    /// Match flows whose dst hostname equals this string.
    #[arg(long = "dst-host")]
    dst_host: Option<String>,

    /// Match flows whose dst IP falls in this CIDR (e.g. 192.0.2.0/24).
    #[arg(long = "dst-net")]
    dst_net: Option<String>,

    /// Match flows targeting this destination port.
    #[arg(long = "dst-port")]
    dst_port: Option<u16>,

    /// Match flows of this protocol.
    #[arg(long, value_enum)]
    protocol: Option<ProtocolArg>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ActionArg {
    Allow,
    Deny,
    Reject,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DurationArg {
    Once,
    UntilRestart,
    Always,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProtocolArg {
    Tcp,
    Udp,
    Icmp,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let mut client = Client::connect(&cli.socket)
        .await
        .with_context(|| format!("connecting to {}", cli.socket.display()))?;

    match cli.cmd {
        Command::Status => cmd_status(&mut client).await?,
        Command::Rules { cmd } => match cmd {
            RulesCmd::List => cmd_rules_list(&mut client).await?,
            RulesCmd::Remove { id } => cmd_rules_remove(&mut client, &id).await?,
            RulesCmd::Toggle { id } => cmd_rules_toggle(&mut client, &id).await?,
            RulesCmd::Add(args) => cmd_rules_add(&mut client, args).await?,
            RulesCmd::Export { out } => cmd_rules_export(&mut client, out).await?,
            RulesCmd::Import { file, replace } => {
                cmd_rules_import(&mut client, file, replace).await?
            }
            RulesCmd::ImportOpensnitch { path, replace } => {
                cmd_rules_import_opensnitch(&mut client, path, replace).await?
            }
            RulesCmd::BootstrapDefaults { dry_run } => {
                cmd_rules_bootstrap_defaults(&mut client, dry_run).await?
            }
        },
        Command::Live => cmd_live(&mut client).await?,
        Command::Pause => {
            // duration_secs = 0: use the daemon's configured default. The
            // daemon decides and reports the real deadline, so print that
            // rather than guessing.
            let resp = client.set_paused(true, 0).await?;
            println!(
                "paused = {} (auto-resumes {})",
                resp.paused,
                format_resume_at(resp.resume_at_unix_ms)
            );
        }
        Command::Resume => {
            let resp = client.set_paused(false, 0).await?;
            println!("paused = {}", resp.paused);
        }
    }

    Ok(())
}

/// Renders the daemon-reported auto-resume instant. The daemon owns the
/// pause duration, so this never assumes a length.
fn format_resume_at(resume_at_unix_ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(resume_at_unix_ms) {
        Some(t) => {
            let secs = (resume_at_unix_ms - chrono::Utc::now().timestamp_millis()).max(0) / 1000;
            format!(
                "at {} (in {secs}s)",
                t.with_timezone(&chrono::Local).format("%H:%M:%S")
            )
        }
        None => "at an unknown time".to_string(),
    }
}

async fn cmd_status(client: &mut Client) -> anyhow::Result<()> {
    let s = client.status().await?;
    println!("version          {}", s.version);
    println!("uptime           {}s", s.uptime_seconds);
    println!("paused           {}", if s.paused { "yes" } else { "no" });
    if s.paused && s.resume_at_unix_ms > 0 {
        println!("resumes          {}", format_resume_at(s.resume_at_unix_ms));
    }
    println!("rules            {}", s.rules_count);
    println!("prompts pending  {}", s.prompts_pending);
    println!(
        "connections      {} (allowed: {}, denied: {})",
        s.connections_today, s.connections_allowed, s.connections_denied
    );
    Ok(())
}

async fn cmd_rules_list(client: &mut Client) -> anyhow::Result<()> {
    let rules = client.list_rules().await?;
    if rules.is_empty() {
        println!("(no rules)");
        return Ok(());
    }
    println!("{:<36}  {:<13}  {:<5}  summary", "id", "duration", "on");
    println!("{}", "-".repeat(80));
    for r in rules {
        println!(
            "{:<36}  {:<13}  {:<5}  {}",
            r.id,
            convert::duration_label(r.duration),
            if r.enabled { "yes" } else { "no" },
            convert::rule_summary(&r)
        );
    }
    Ok(())
}

async fn cmd_rules_remove(client: &mut Client, id: &str) -> anyhow::Result<()> {
    let deleted = client.delete_rule(id).await?;
    if deleted {
        println!("deleted {id}");
    } else {
        println!("no rule with id {id}");
    }
    Ok(())
}

async fn cmd_rules_toggle(client: &mut Client, id: &str) -> anyhow::Result<()> {
    let rules = client.list_rules().await?;
    let Some(mut rule) = rules.into_iter().find(|r| r.id == id) else {
        anyhow::bail!("no rule with id {id}");
    };
    rule.enabled = !rule.enabled;
    client.upsert_rule(rule.clone()).await?;
    println!(
        "{}: {}",
        id,
        if rule.enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

async fn cmd_rules_add(client: &mut Client, args: AddArgs) -> anyhow::Result<()> {
    if let Some(net) = &args.dst_net {
        net.parse::<ipnet::IpNet>()
            .with_context(|| format!("--dst-net {net} is not a valid CIDR"))?;
    }

    let action = match args.action {
        ActionArg::Allow => proto::Action::Allow,
        ActionArg::Deny => proto::Action::Deny,
        ActionArg::Reject => proto::Action::Reject,
    };
    let duration = match args.duration {
        DurationArg::Once => proto::Duration::Once,
        DurationArg::UntilRestart => proto::Duration::UntilRestart,
        DurationArg::Always => proto::Duration::Always,
    };

    let scope = proto::RuleScope {
        exe_path: args
            .exe
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        exe_sha256: String::new(),
        parent_exe: String::new(),
        uid: args.uid.unwrap_or(0),
        has_uid: args.uid.is_some(),
        dst_host: args.dst_host.clone().unwrap_or_default(),
        dst_net: args.dst_net.clone().unwrap_or_default(),
        dst_port: args.dst_port.map(u32::from).unwrap_or(0),
        has_dst_port: args.dst_port.is_some(),
        protocol: args
            .protocol
            .map(|p| match p {
                ProtocolArg::Tcp => proto::Protocol::Tcp as i32,
                ProtocolArg::Udp => proto::Protocol::Udp as i32,
                ProtocolArg::Icmp => proto::Protocol::Icmp as i32,
            })
            .unwrap_or(0),
        has_protocol: args.protocol.is_some(),
    };

    let rule = proto::RuleInfo {
        id: String::new(),
        name: args.name.unwrap_or_else(|| "cli-added".into()),
        enabled: true,
        action: action as i32,
        duration: duration as i32,
        scope: Some(scope),
        created_at_unix_ms: 0,
        hit_count: 0,
    };

    let id = client.upsert_rule(rule).await?;
    println!("added rule {id}");
    Ok(())
}

async fn cmd_rules_export(client: &mut Client, out: Option<PathBuf>) -> anyhow::Result<()> {
    let rules = client.list_rules().await?;
    let json = serde_json::to_string_pretty(&proto_rules_to_export(&rules))?;
    match out {
        Some(path) => {
            std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        }
        None => println!("{json}"),
    }
    Ok(())
}

async fn cmd_rules_import(
    client: &mut Client,
    file: Option<PathBuf>,
    replace: bool,
) -> anyhow::Result<()> {
    let json = match file {
        Some(p) => {
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?
        }
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading stdin")?;
            buf
        }
    };

    let rules: Vec<ExportedRule> = serde_json::from_str(&json).context("parsing JSON")?;

    if replace {
        let existing = client.list_rules().await?;
        for r in existing {
            let _ = client.delete_rule(&r.id).await;
        }
    }

    let mut added = 0u32;
    for r in rules {
        let pb = r.into_proto();
        client.upsert_rule(pb).await?;
        added += 1;
    }
    println!("imported {added} rules");
    Ok(())
}

async fn cmd_live(client: &mut Client) -> anyhow::Result<()> {
    use owo_colors::{OwoColorize, Stream::Stdout};

    let mut stream = client.stream_connections("cfc-cli".into()).await?;
    println!(
        "{:<8} {:<5} {:<6} {:<21} -> {:<21}  {:<6}",
        "time".bold(),
        "proto".bold(),
        "pid".bold(),
        "src".bold(),
        "dst".bold(),
        "verdict".bold(),
    );
    while let Some(item) = stream.next().await {
        let ev = match item {
            Ok(e) => e,
            Err(e) => {
                eprintln!("stream error: {e}");
                break;
            }
        };
        let conn = match &ev.connection {
            Some(c) => c,
            None => continue,
        };
        let proc = ev.process.as_ref();
        let time = chrono::DateTime::from_timestamp_millis(conn.timestamp_unix_ms)
            .map(|t| t.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "?".into());
        let pid = proc
            .map(|p| p.pid.to_string())
            .unwrap_or_else(|| "?".into());
        let src = format!("{}:{}", conn.src_ip, conn.src_port);
        let dst = format!("{}:{}", conn.dst_ip, conn.dst_port);
        let verdict_label = convert::action_label(ev.verdict);
        let verdict_colored = match cfc_proto::v1::Action::try_from(ev.verdict)
            .unwrap_or(cfc_proto::v1::Action::Unspecified)
        {
            cfc_proto::v1::Action::Allow => {
                format!("{}", verdict_label.if_supports_color(Stdout, |s| s.green()))
            }
            cfc_proto::v1::Action::Deny | cfc_proto::v1::Action::Reject => {
                format!("{}", verdict_label.if_supports_color(Stdout, |s| s.red()))
            }
            _ => verdict_label.to_string(),
        };
        println!(
            "{:<8} {:<5} {:<6} {:<21} -> {:<21}  {}",
            time.if_supports_color(Stdout, |s| s.dimmed()),
            convert::protocol_label(conn.protocol),
            pid,
            src,
            dst.if_supports_color(Stdout, |s| s.cyan()),
            verdict_colored,
        );
    }
    Ok(())
}

/// Format for `cfc rules export` / `import`. Wire-compatible with the
/// in-process Rule type but stable across daemon versions.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ExportedRule {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default = "default_true")]
    enabled: bool,
    action: String,
    #[serde(default = "default_duration")]
    duration: String,
    #[serde(default)]
    scope: ExportedScope,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct ExportedScope {
    #[serde(default)]
    exe_path: Option<String>,
    #[serde(default)]
    exe_sha256: Option<String>,
    #[serde(default)]
    parent_exe: Option<String>,
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    dst_host: Option<String>,
    #[serde(default)]
    dst_net: Option<String>,
    #[serde(default)]
    dst_port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_duration() -> String {
    "always".to_string()
}

impl ExportedRule {
    fn into_proto(self) -> proto::RuleInfo {
        let action = match self.action.to_ascii_lowercase().as_str() {
            "deny" => proto::Action::Deny,
            "reject" => proto::Action::Reject,
            _ => proto::Action::Allow,
        };
        let duration = match self.duration.to_ascii_lowercase().as_str() {
            "once" => proto::Duration::Once,
            "until-restart" | "until_restart" => proto::Duration::UntilRestart,
            _ => proto::Duration::Always,
        };
        let protocol_idx =
            self.scope
                .protocol
                .as_deref()
                .map(|p| match p.to_ascii_lowercase().as_str() {
                    "tcp" => proto::Protocol::Tcp as i32,
                    "udp" => proto::Protocol::Udp as i32,
                    "icmp" => proto::Protocol::Icmp as i32,
                    _ => 0,
                });
        let scope = proto::RuleScope {
            exe_path: self.scope.exe_path.unwrap_or_default(),
            exe_sha256: self.scope.exe_sha256.unwrap_or_default(),
            parent_exe: self.scope.parent_exe.unwrap_or_default(),
            uid: self.scope.uid.unwrap_or(0),
            has_uid: self.scope.uid.is_some(),
            dst_host: self.scope.dst_host.unwrap_or_default(),
            dst_net: self.scope.dst_net.unwrap_or_default(),
            dst_port: self.scope.dst_port.map(u32::from).unwrap_or(0),
            has_dst_port: self.scope.dst_port.is_some(),
            protocol: protocol_idx.unwrap_or(0),
            has_protocol: protocol_idx.is_some(),
        };
        proto::RuleInfo {
            id: self.id,
            name: self.name,
            enabled: self.enabled,
            action: action as i32,
            duration: duration as i32,
            scope: Some(scope),
            created_at_unix_ms: 0,
            hit_count: 0,
        }
    }
}

fn proto_rules_to_export(rules: &[proto::RuleInfo]) -> Vec<ExportedRule> {
    rules
        .iter()
        .map(|r| {
            let scope = r.scope.as_ref();
            let opt_string = |s: &str| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            };
            ExportedRule {
                id: r.id.clone(),
                name: r.name.clone(),
                enabled: r.enabled,
                action: convert::action_label(r.action).to_string(),
                duration: convert::duration_label(r.duration).to_string(),
                scope: ExportedScope {
                    exe_path: scope.and_then(|s| opt_string(&s.exe_path)),
                    exe_sha256: scope.and_then(|s| opt_string(&s.exe_sha256)),
                    parent_exe: scope.and_then(|s| opt_string(&s.parent_exe)),
                    uid: scope.and_then(|s| s.has_uid.then_some(s.uid)),
                    dst_host: scope.and_then(|s| opt_string(&s.dst_host)),
                    dst_net: scope.and_then(|s| opt_string(&s.dst_net)),
                    dst_port: scope.and_then(|s| s.has_dst_port.then_some(s.dst_port as u16)),
                    protocol: scope
                        .and_then(|s| s.has_protocol.then_some(s.protocol))
                        .map(|p| convert::protocol_label(p).to_string()),
                },
            }
        })
        .collect()
}

// ----- opensnitch import ----------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct OsnRule {
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_allow_str")]
    action: String,
    #[serde(default = "default_duration")]
    duration: String,
    #[serde(default)]
    operator: Option<OsnOperator>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type")]
enum OsnOperator {
    Simple(OsnSimple),
    Regexp(OsnSimple),
    List(OsnList),
}

#[derive(Debug, serde::Deserialize)]
struct OsnSimple {
    operand: String,
    #[serde(default)]
    data: String,
}

#[derive(Debug, serde::Deserialize)]
struct OsnList {
    #[serde(default)]
    #[allow(dead_code)]
    operand: String,
    #[serde(default)]
    list: Vec<OsnOperator>,
}

fn default_allow_str() -> String {
    "allow".into()
}

async fn cmd_rules_import_opensnitch(
    client: &mut Client,
    path: PathBuf,
    replace: bool,
) -> anyhow::Result<()> {
    let files: Vec<PathBuf> = if path.is_dir() {
        std::fs::read_dir(&path)
            .with_context(|| format!("reading dir {}", path.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect()
    } else {
        vec![path.clone()]
    };

    if files.is_empty() {
        anyhow::bail!("no .json files found under {}", path.display());
    }

    if replace {
        let existing = client.list_rules().await?;
        for r in existing {
            let _ = client.delete_rule(&r.id).await;
        }
    }

    let mut imported = 0u32;
    let mut skipped = 0u32;
    for file in &files {
        let json =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let osn: OsnRule = match serde_json::from_str(&json) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: parse error: {e}", file.display());
                skipped += 1;
                continue;
            }
        };
        match convert_opensnitch(file, osn) {
            Ok(rule) => {
                client.upsert_rule(rule).await?;
                imported += 1;
            }
            Err(e) => {
                eprintln!("skip {}: {e}", file.display());
                skipped += 1;
            }
        }
    }
    println!("imported {imported} rules ({skipped} skipped)");
    Ok(())
}

fn convert_opensnitch(file: &std::path::Path, osn: OsnRule) -> anyhow::Result<proto::RuleInfo> {
    let action = match osn.action.to_ascii_lowercase().as_str() {
        "deny" | "drop" => proto::Action::Deny,
        "reject" => proto::Action::Reject,
        _ => proto::Action::Allow,
    };
    let duration = match osn.duration.to_ascii_lowercase().as_str() {
        "once" => proto::Duration::Once,
        "until restart" | "until-restart" | "restart" => proto::Duration::UntilRestart,
        _ => proto::Duration::Always,
    };

    let mut scope = proto::RuleScope::default();
    if let Some(op) = osn.operator {
        apply_operator(&op, &mut scope)?;
    }

    let scope_empty = scope.exe_path.is_empty()
        && scope.dst_host.is_empty()
        && scope.dst_net.is_empty()
        && !scope.has_dst_port
        && !scope.has_protocol
        && !scope.has_uid;
    if scope_empty {
        anyhow::bail!("no convertible predicates");
    }

    let name = osn.name.unwrap_or_else(|| {
        file.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "opensnitch-import".into())
    });

    Ok(proto::RuleInfo {
        id: String::new(),
        name,
        enabled: osn.enabled,
        action: action as i32,
        duration: duration as i32,
        scope: Some(scope),
        created_at_unix_ms: 0,
        hit_count: 0,
    })
}

fn apply_operator(op: &OsnOperator, scope: &mut proto::RuleScope) -> anyhow::Result<()> {
    match op {
        OsnOperator::Simple(s) | OsnOperator::Regexp(s) => apply_simple(s, scope),
        OsnOperator::List(l) => {
            for sub in &l.list {
                apply_operator(sub, scope)?;
            }
            Ok(())
        }
    }
}

fn apply_simple(s: &OsnSimple, scope: &mut proto::RuleScope) -> anyhow::Result<()> {
    match s.operand.as_str() {
        "process.path" => scope.exe_path = s.data.clone(),
        "process.hash.sha256" => scope.exe_sha256 = s.data.clone(),
        "user.id" => {
            if let Ok(uid) = s.data.parse::<u32>() {
                scope.uid = uid;
                scope.has_uid = true;
            }
        }
        "dest.host" | "dest.domain" => scope.dst_host = s.data.clone(),
        "dest.ip" => {
            // single IP -> /32 or /128
            if s.data.contains(':') {
                scope.dst_net = format!("{}/128", s.data);
            } else {
                scope.dst_net = format!("{}/32", s.data);
            }
        }
        "dest.network" => scope.dst_net = s.data.clone(),
        "dest.port" => {
            if let Ok(port) = s.data.parse::<u32>() {
                scope.dst_port = port;
                scope.has_dst_port = true;
            }
        }
        "protocol" => {
            let proto = match s.data.to_ascii_uppercase().as_str() {
                "TCP" => Some(proto::Protocol::Tcp as i32),
                "UDP" => Some(proto::Protocol::Udp as i32),
                "ICMP" => Some(proto::Protocol::Icmp as i32),
                _ => None,
            };
            if let Some(p) = proto {
                scope.protocol = p;
                scope.has_protocol = true;
            }
        }
        // Operands we don't yet support: process.command, process.id,
        // iface.in/out. Silently skip them.
        _ => {}
    }
    Ok(())
}

// ----- bootstrap defaults --------------------------------------------------

struct DefaultRule {
    name: &'static str,
    exe: Option<&'static str>,
    dst_host: Option<&'static str>,
    dst_port: Option<u16>,
    protocol: Option<proto::Protocol>,
}

fn default_rules() -> Vec<DefaultRule> {
    vec![
        // DNS - systemd-resolved owns the stub
        DefaultRule {
            name: "default-systemd-resolved-dns",
            exe: Some("/usr/lib/systemd/systemd-resolved"),
            dst_host: None,
            dst_port: Some(53),
            protocol: None,
        },
        // NTP - timesyncd or chrony
        DefaultRule {
            name: "default-systemd-timesyncd",
            exe: Some("/usr/lib/systemd/systemd-timesyncd"),
            dst_host: None,
            dst_port: Some(123),
            protocol: Some(proto::Protocol::Udp),
        },
        DefaultRule {
            name: "default-chrony",
            exe: Some("/usr/bin/chronyd"),
            dst_host: None,
            dst_port: Some(123),
            protocol: Some(proto::Protocol::Udp),
        },
        // Package managers - hit HTTPS mirrors
        DefaultRule {
            name: "default-pacman-https",
            exe: Some("/usr/bin/pacman"),
            dst_host: None,
            dst_port: Some(443),
            protocol: Some(proto::Protocol::Tcp),
        },
        DefaultRule {
            name: "default-paru-https",
            exe: Some("/usr/bin/paru"),
            dst_host: None,
            dst_port: Some(443),
            protocol: Some(proto::Protocol::Tcp),
        },
        // SSH client
        DefaultRule {
            name: "default-ssh-client",
            exe: Some("/usr/bin/ssh"),
            dst_host: None,
            dst_port: Some(22),
            protocol: Some(proto::Protocol::Tcp),
        },
    ]
}

async fn cmd_rules_bootstrap_defaults(client: &mut Client, dry_run: bool) -> anyhow::Result<()> {
    let existing = client.list_rules().await?;
    let existing_names: std::collections::HashSet<String> =
        existing.iter().map(|r| r.name.clone()).collect();

    let mut added = 0u32;
    let mut skipped = 0u32;
    for d in default_rules() {
        if existing_names.contains(d.name) {
            skipped += 1;
            continue;
        }
        if dry_run {
            println!("would add: {}", d.name);
            added += 1;
            continue;
        }

        let scope = proto::RuleScope {
            exe_path: d.exe.unwrap_or("").to_string(),
            exe_sha256: String::new(),
            parent_exe: String::new(),
            uid: 0,
            has_uid: false,
            dst_host: d.dst_host.unwrap_or("").to_string(),
            dst_net: String::new(),
            dst_port: d.dst_port.map(u32::from).unwrap_or(0),
            has_dst_port: d.dst_port.is_some(),
            protocol: d.protocol.map(|p| p as i32).unwrap_or(0),
            has_protocol: d.protocol.is_some(),
        };
        let rule = proto::RuleInfo {
            id: String::new(),
            name: d.name.to_string(),
            enabled: true,
            action: proto::Action::Allow as i32,
            duration: proto::Duration::Always as i32,
            scope: Some(scope),
            created_at_unix_ms: 0,
            hit_count: 0,
        };
        client.upsert_rule(rule).await?;
        println!("added: {}", d.name);
        added += 1;
    }
    println!(
        "{}: {added} added, {skipped} already present",
        if dry_run { "dry-run" } else { "done" }
    );
    Ok(())
}

#[cfg(test)]
mod opensnitch_tests {
    use super::*;
    use std::path::Path;

    fn parse(json: &str) -> anyhow::Result<proto::RuleInfo> {
        let osn: OsnRule = serde_json::from_str(json)?;
        convert_opensnitch(Path::new("test.json"), osn)
    }

    #[test]
    fn simple_process_path() {
        let r = parse(
            r#"{
              "name": "firefox-https",
              "enabled": true,
              "action": "allow",
              "duration": "always",
              "operator": {
                "type": "simple",
                "operand": "process.path",
                "data": "/usr/lib/firefox/firefox"
              }
            }"#,
        )
        .unwrap();
        assert_eq!(r.name, "firefox-https");
        assert_eq!(r.action, proto::Action::Allow as i32);
        let scope = r.scope.unwrap();
        assert_eq!(scope.exe_path, "/usr/lib/firefox/firefox");
    }

    #[test]
    fn list_of_predicates() {
        let r = parse(
            r#"{
              "name": "curl-443",
              "enabled": true,
              "action": "allow",
              "duration": "always",
              "operator": {
                "type": "list",
                "operand": "list",
                "list": [
                  {"type": "simple", "operand": "process.path", "data": "/usr/bin/curl"},
                  {"type": "simple", "operand": "dest.port", "data": "443"},
                  {"type": "simple", "operand": "protocol", "data": "TCP"}
                ]
              }
            }"#,
        )
        .unwrap();
        let scope = r.scope.unwrap();
        assert_eq!(scope.exe_path, "/usr/bin/curl");
        assert_eq!(scope.dst_port, 443);
        assert!(scope.has_dst_port);
        assert_eq!(scope.protocol, proto::Protocol::Tcp as i32);
        assert!(scope.has_protocol);
    }

    #[test]
    fn deny_action_recognized() {
        let r = parse(
            r#"{
              "name": "block-evil",
              "action": "deny",
              "duration": "once",
              "operator": {
                "type": "simple",
                "operand": "dest.host",
                "data": "evil.example"
              }
            }"#,
        )
        .unwrap();
        assert_eq!(r.action, proto::Action::Deny as i32);
        assert_eq!(r.duration, proto::Duration::Once as i32);
        assert_eq!(r.scope.unwrap().dst_host, "evil.example");
    }

    #[test]
    fn dest_ip_becomes_cidr() {
        let r = parse(
            r#"{
              "name": "block-ip",
              "action": "deny",
              "operator": {"type": "simple", "operand": "dest.ip", "data": "1.2.3.4"}
            }"#,
        )
        .unwrap();
        assert_eq!(r.scope.unwrap().dst_net, "1.2.3.4/32");
    }

    #[test]
    fn ipv6_dest_ip_becomes_128_cidr() {
        let r = parse(
            r#"{
              "name": "block-v6",
              "action": "deny",
              "operator": {"type": "simple", "operand": "dest.ip", "data": "2001:db8::1"}
            }"#,
        )
        .unwrap();
        assert_eq!(r.scope.unwrap().dst_net, "2001:db8::1/128");
    }

    #[test]
    fn empty_rule_rejected() {
        // No operator at all -> no convertible predicates -> error.
        let err = parse(
            r#"{
              "name": "nothing",
              "action": "allow"
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no convertible predicates"));
    }

    #[test]
    fn unknown_operands_silently_skipped() {
        // process.command isn't supported but the rule has a valid
        // process.path too - the latter alone is enough.
        let r = parse(
            r#"{
              "name": "mixed",
              "action": "allow",
              "operator": {
                "type": "list",
                "operand": "list",
                "list": [
                  {"type": "simple", "operand": "process.command", "data": "curl -s X"},
                  {"type": "simple", "operand": "process.path", "data": "/usr/bin/curl"}
                ]
              }
            }"#,
        )
        .unwrap();
        assert_eq!(r.scope.unwrap().exe_path, "/usr/bin/curl");
    }

    #[test]
    fn regexp_type_treated_like_simple() {
        let r = parse(
            r#"{
              "name": "rxp",
              "action": "allow",
              "operator": {"type": "regexp", "operand": "process.path", "data": "/usr/bin/.*"}
            }"#,
        )
        .unwrap();
        // We don't actually evaluate regex but the data lands in exe_path.
        assert_eq!(r.scope.unwrap().exe_path, "/usr/bin/.*");
    }
}
