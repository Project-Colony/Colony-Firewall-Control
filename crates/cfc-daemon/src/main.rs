//! Colony Firewall daemon entry point.

use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

mod config;
mod convert;
mod decision;
mod dns;
mod ipc;
mod nfqueue;
mod packet;
mod process_resolve;
mod prompts;
mod stats;
mod storage;

#[derive(Debug, Parser)]
#[command(name = "colony-firewalld", version, about)]
struct Args {
    /// Path to TOML config file.
    #[arg(long, default_value = "/etc/colony-firewall/daemon.toml")]
    config: PathBuf,

    /// Override the IPC socket path.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Run in foreground with verbose logging.
    #[arg(long)]
    debug: bool,

    /// Skip NFQUEUE bind. Useful for testing the gRPC + UI surface without
    /// root or actually filtering traffic. The daemon still serves
    /// ListRules/UpsertRule/GetStatus over the UDS, but never intercepts
    /// any packets and never emits Live/Prompt events.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let filter = if args.debug {
        "debug"
    } else {
        "info,cfc_daemon=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "colony-firewalld starting"
    );

    let cfg = config::Config::load_or_default(&args.config).context("loading config")?;

    let store = storage::RuleStore::open(&cfg.storage.path).context("opening rule store")?;

    let engine = decision::Engine::new(store.snapshot()?, cfg.default_policy);

    let socket_path = args
        .socket
        .unwrap_or_else(|| PathBuf::from(cfc_proto::DEFAULT_SOCKET_PATH));

    let (observed_tx, _) = tokio::sync::broadcast::channel(1024);
    let stats = stats::Stats::new();
    let dns_cache = dns::DnsCache::new();
    let router = prompts::PromptRouter::new(cfg.default_policy, stats.clone());

    let (ipc_handle, prompt_tx) = ipc::spawn(
        socket_path.clone(),
        engine.clone(),
        store.clone(),
        observed_tx.clone(),
        router,
        stats.clone(),
    )
    .await
    .context("starting IPC server")?;

    let nfq_handle = if args.dry_run {
        info!("--dry-run set: skipping NFQUEUE bind");
        tokio::spawn(async {
            std::future::pending::<()>().await;
        })
    } else {
        nfqueue::spawn(
            cfg.nfqueue.queue_num,
            engine.clone(),
            prompt_tx,
            observed_tx,
            stats,
            dns_cache,
        )
        .await
        .context("starting NFQUEUE worker")?
    };

    // Periodic hit-count flush so the persisted rule.hit_count reflects
    // recent matches even if the daemon crashes.
    let flush_engine = engine.clone();
    let flush_store = store.clone();
    let flush_handle = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        tick.tick().await; // skip immediate fire
        loop {
            tick.tick().await;
            let deltas = flush_engine.drain_hits();
            if !deltas.is_empty() {
                if let Err(e) = flush_store.merge_hit_counts(&deltas) {
                    tracing::warn!("hit-count flush failed: {e}");
                }
            }
        }
    });

    info!(socket = %socket_path.display(), "ready");

    tokio::select! {
        r = ipc_handle => r.context("ipc task crashed")?,
        r = nfq_handle => r.context("nfqueue task crashed")?,
        r = flush_handle => r.context("hit-flush task crashed")?,
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, flushing hits and shutting down");
            let deltas = engine.drain_hits();
            if !deltas.is_empty() {
                if let Err(e) = store.merge_hit_counts(&deltas) {
                    tracing::warn!("final hit-count flush failed: {e}");
                }
            }
        }
    }

    Ok(())
}
