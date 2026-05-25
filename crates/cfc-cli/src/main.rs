//! Colony Firewall Control - CLI control tool.

use anyhow::Context;
use cfc_client::{convert, Client};
use clap::{Parser, Subcommand};
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
    println!("connections      {} (allowed: {}, denied: {})",
        s.connections_today, s.connections_allowed, s.connections_denied);
    Ok(())
}

async fn cmd_rules_list(client: &mut Client) -> anyhow::Result<()> {
    let rules = client.list_rules().await?;
    if rules.is_empty() {
        println!("(no rules)");
        return Ok(());
    }
    println!("{:<36}  {:<8}  {:<5}  {}", "id", "duration", "on", "summary");
    println!("{}", "-".repeat(80));
    for r in rules {
        println!(
            "{:<36}  {:<8}  {:<5}  {}",
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

async fn cmd_live(client: &mut Client) -> anyhow::Result<()> {
    let mut stream = client.stream_connections("cfc-cli".into()).await?;
    println!("{:<8} {:<5} {:<6} {:<21} -> {:<21}  {:<6}", "time", "proto", "pid", "src", "dst", "verdict");
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
        let pid = proc.map(|p| p.pid.to_string()).unwrap_or_else(|| "?".into());
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
