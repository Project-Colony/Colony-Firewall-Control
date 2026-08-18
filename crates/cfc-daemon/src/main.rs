//! Colony Firewall daemon entry point.

use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

// The daemon's internals live in the library target (`src/lib.rs`) so the
// integration tests can assemble the same graph this binary does. This file
// stays the only place that wires them together for real.
use cfc_daemon::{config, decision, dns, ipc, nfqueue, prompts, sd_notify, stats, storage};

/// How stale the NFQUEUE worker's busy-stamp may get before the watchdog
/// task considers the worker wedged and withholds the systemd heartbeat.
/// Must comfortably exceed the worker's longest legitimate busy stretch
/// (per-packet work is milliseconds) and, combined with WatchdogSec=30 in
/// the unit, bounds wedged-daemon detection at roughly 90 seconds.
const WORKER_STALL_MS: i64 = 60_000;

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

    // The default policy is shared between the decision engine and the
    // prompt router and hot-reloads on SIGHUP (see `reload_policy`).
    // Everything else is bound at startup and does NOT hot-reload:
    // [nfqueue] queue_num / queue_max_len / fail_open, [storage] path and
    // the IPC socket path all require a restart to change.
    let policy: decision::SharedPolicy = Arc::new(std::sync::RwLock::new(cfg.default_policy));

    let engine = decision::Engine::new(store.snapshot()?, policy.clone());

    let socket_path = args
        .socket
        .unwrap_or_else(|| PathBuf::from(cfc_proto::DEFAULT_SOCKET_PATH));

    let (observed_tx, _) = tokio::sync::broadcast::channel(1024);
    let stats = stats::Stats::new();
    let dns_cache = dns::DnsCache::new();
    // Verdict responses flow from the async prompt router back to the
    // NFQUEUE worker thread over a std channel.
    let (verdict_tx, verdict_rx) = std::sync::mpsc::channel();
    let router = prompts::PromptRouter::new(policy.clone(), stats.clone(), verdict_tx);

    // Persist every decided flow into the events table. Subscribes to the
    // live feed before the datapath starts so nothing is missed, and never
    // blocks it (bounded queue + drop counting, see ipc.rs).
    ipc::spawn_event_pipeline(store.clone(), &observed_tx, cfg.events.max_rows);

    let (mut ipc_handle, prompt_tx) = ipc::spawn(
        ipc::IpcOptions {
            socket_path: socket_path.clone(),
            ipc: cfg.ipc.clone(),
            pause_default_secs: cfg.pause.default_secs,
            dry_run: args.dry_run,
        },
        engine.clone(),
        store.clone(),
        observed_tx.clone(),
        router,
        stats.clone(),
        policy.clone(),
    )
    .await
    .context("starting IPC server")?;

    let (mut nfq_handle, last_activity) = if args.dry_run {
        info!("--dry-run set: skipping NFQUEUE bind");
        (
            tokio::spawn(async { std::future::pending::<anyhow::Result<()>>().await }),
            Arc::new(AtomicI64::new(nfqueue::unix_ms())),
        )
    } else {
        nfqueue::spawn(
            &cfg.nfqueue,
            engine.clone(),
            prompt_tx,
            verdict_rx,
            observed_tx,
            stats,
            dns_cache,
        )
        .context("starting NFQUEUE worker")?
    };

    // Periodic maintenance: flush hit-count deltas so the persisted
    // rule.hit_count reflects recent matches even if the daemon crashes,
    // and prune expired Seconds-duration rules (lookup already skips them;
    // this reclaims the rows while the daemon runs).
    let flush_engine = engine.clone();
    let flush_store = store.clone();
    let mut flush_handle = tokio::spawn(async move {
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
            match flush_store.purge_expired(chrono::Utc::now().timestamp_millis()) {
                Ok(n) if n > 0 => tracing::debug!(removed = n, "purged expired rules"),
                Ok(_) => {}
                Err(e) => tracing::warn!("expired-rule purge failed: {e}"),
            }
            // Persisted events are pruned to [events] max_rows by the
            // event-writer task (ipc::spawn_event_pipeline), which owns
            // that table's whole lifecycle.
        }
    });

    // Watchdog heartbeat. sd_notify::notify() no-ops without
    // $NOTIFY_SOCKET, so this runs harmlessly outside systemd too. The
    // worker stamps `last_activity` once per loop iteration; a negative
    // stamp means it is parked in a blocking kernel recv (healthy for
    // arbitrarily long on an idle system), a positive stamp older than
    // WORKER_STALL_MS means it wedged mid-iteration: withhold WATCHDOG=1
    // so systemd's WatchdogSec kills and restarts the daemon.
    let wd_activity = last_activity.clone();
    let wd_dry_run = args.dry_run;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            tick.tick().await;
            let stamp = wd_activity.load(Ordering::Relaxed);
            let healthy = wd_dry_run || stamp < 0 || nfqueue::unix_ms() - stamp < WORKER_STALL_MS;
            if healthy {
                if let Err(e) = sd_notify::notify(&["WATCHDOG=1"]) {
                    tracing::warn!("sd_notify WATCHDOG=1 failed: {e}");
                }
            } else {
                tracing::error!(
                    stalled_ms = nfqueue::unix_ms() - stamp,
                    "NFQUEUE worker unresponsive; withholding watchdog heartbeat"
                );
            }
        }
    });

    // Readiness / failure semantics under Type=notify: READY=1 goes out
    // only after ipc::spawn bound the control socket AND nfqueue::spawn
    // bound the queue. On a failed bind, spawn returns Err and main exits
    // non-zero *before* READY, so systemd marks the unit failed and
    // Restart=on-failure retries with backoff.
    if let Err(e) = sd_notify::notify(&["READY=1"]) {
        warn!("sd_notify READY=1 failed: {e}");
    }
    info!(socket = %socket_path.display(), "ready");

    // Persistent signal streams (not per-iteration futures) so nothing is
    // dropped and re-registered while the SIGHUP arm re-arms the loop.
    // SignalKind::interrupt() is Ctrl-C; this daemon is Linux-only.
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;

    // SIGINT (foreground ^C) and SIGTERM (systemd stop) both take the
    // graceful shutdown path below. SIGHUP reloads the shared default
    // policy and re-arms.
    loop {
        tokio::select! {
            r = &mut ipc_handle => {
                r.context("ipc task crashed")?;
                break;
            }
            r = &mut nfq_handle => {
                r.context("nfqueue task crashed")?.context("nfqueue worker failed")?;
                break;
            }
            r = &mut flush_handle => {
                r.context("hit-flush task crashed")?;
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT received, flushing hits and shutting down");
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, flushing hits and shutting down");
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received, reloading config");
                reload_policy(&args.config, &policy);
            }
        }
    }

    let _ = sd_notify::notify(&["STOPPING=1"]);
    let deltas = engine.drain_hits();
    if !deltas.is_empty() {
        if let Err(e) = store.merge_hit_counts(&deltas) {
            tracing::warn!("final hit-count flush failed: {e}");
        }
    }
    // Best-effort removal of the control socket so no stale file lingers
    // (ipc::spawn also unlinks before bind, so a crash that leaves one
    // behind is still recoverable on the next start).
    if let Err(e) = std::fs::remove_file(&socket_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(socket = %socket_path.display(), "removing control socket failed: {e}");
        }
    }

    Ok(())
}

/// SIGHUP handler: re-reads the config file and swaps the shared default
/// policy in place.
///
/// - On read/parse errors the running policy is kept: a bad edit must
///   never take down or degrade a live firewall.
/// - Only `profile` / `[default_policy]` hot-reload. `[nfqueue]`
///   (queue_num, queue_max_len, fail_open), `[storage]` and the IPC
///   socket path are bound at startup and require a restart to change.
fn reload_policy(path: &std::path::Path, policy: &decision::SharedPolicy) {
    match config::Config::load_or_default(path) {
        Ok(new_cfg) => {
            let old = {
                let mut guard = policy
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::mem::replace(&mut *guard, new_cfg.default_policy)
            };
            info!(
                profile = new_cfg.profile.as_deref().unwrap_or("<none>"),
                old = ?old,
                new = ?new_cfg.default_policy,
                "default policy reloaded"
            );
        }
        Err(e) => {
            error!("config reload failed; keeping current policy: {e:#}");
        }
    }
}
