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
}

#[derive(Debug, Subcommand)]
enum RulesCmd {
    /// List all persistent rules.
    List,
    /// Delete a rule by id.
    Remove { id: String },
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
            RulesCmd::Add(args) => cmd_rules_add(&mut client, args).await?,
            RulesCmd::Export { out } => cmd_rules_export(&mut client, out).await?,
            RulesCmd::Import { file, replace } => {
                cmd_rules_import(&mut client, file, replace).await?
            }
        },
        Command::Live => cmd_live(&mut client).await?,
    }

    Ok(())
}

async fn cmd_status(client: &mut Client) -> anyhow::Result<()> {
    let s = client.status().await?;
    println!("version          {}", s.version);
    println!("uptime           {}s", s.uptime_seconds);
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
    let mut stream = client.stream_connections("cfc-cli".into()).await?;
    println!(
        "{:<8} {:<5} {:<6} {:<21} -> {:<21}  {:<6}",
        "time", "proto", "pid", "src", "dst", "verdict"
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
        println!(
            "{:<8} {:<5} {:<6} {:<21} -> {:<21}  {}",
            time,
            convert::protocol_label(conn.protocol),
            pid,
            src,
            dst,
            convert::action_label(ev.verdict)
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
