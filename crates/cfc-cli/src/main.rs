//! Colony Firewall Control - CLI control tool.

use clap::{Parser, Subcommand};
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

    match cli.cmd {
        Command::Status => {
            println!("daemon socket: {}", cli.socket.display());
            println!("(Phase 1 will connect and call GetStatus over UDS)");
        }
        Command::Rules { cmd } => match cmd {
            RulesCmd::List => println!("(Phase 1: ListRules)"),
            RulesCmd::Remove { id } => println!("(Phase 1: DeleteRule {id})"),
        },
        Command::Live => println!("(Phase 1: StreamConnections feed)"),
    }

    Ok(())
}
