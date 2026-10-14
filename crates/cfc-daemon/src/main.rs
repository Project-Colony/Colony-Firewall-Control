//! Colony Firewall daemon entry point.

use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};

// The daemon's internals live in the library target (`src/lib.rs`) so the
// integration tests can assemble the same graph this binary does. This file
// stays the only place that wires them together for real.
use cfc_daemon::{
    config, decision, dns, ebpf, ipc, maintenance, nfqueue, prompts, sd_notify, stats, storage,
};

/// How long `main` waits for the tokio runtime -- in particular its
/// blocking pool, where the NFQUEUE worker lives -- to wind down before
/// abandoning it and letting the process exit anyway.
///
/// The worker observes its stop flag within milliseconds, so this grace is
/// never spent in practice; it exists so that a *wedged* blocking thread
/// can never hold the process hostage the way a plain `Runtime` drop
/// (which waits forever) used to.
const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

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

/// Owns the runtime explicitly instead of using `#[tokio::main]`.
///
/// `#[tokio::main]` drops the `Runtime` when the async body returns, and
/// `Runtime::drop` shuts the blocking pool down with *no* timeout: it waits
/// forever for every blocking thread to return. The NFQUEUE worker is one
/// of those threads, so anything that kept it from returning turned every
/// daemon stop into a hang until systemd's `TimeoutStopSec` fired and
/// SIGKILLed us. Driving the runtime by hand lets `shutdown_timeout` put a
/// hard ceiling on that: whatever the worker is doing, the process exits.
fn main() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        // One worker per core is tokio's default and the wrong shape for this
        // daemon. Nothing CPU-bound runs on the runtime: the packet loop is a
        // `spawn_blocking` thread of its own, reverse DNS and exe resolution
        // are `spawn_blocking` too, and what is left on the workers - the IPC
        // server, the prompt router, the event writer, the flush timer, the
        // ring-buffer consumer - is a dozen tasks that spend their lives
        // waiting on a socket or a channel.
        //
        // The cost of the default was not CPU, it was address space. glibc
        // gives each contending thread its own malloc arena, and on a 16-core
        // machine that meant 14 arenas of ~63 MB: 1.07 GB of virtual mappings
        // behind 78 MB of resident memory, for a daemon whose useful heap is
        // 22 MB. Four workers is more than this ever needs and keeps the
        // arena count in single digits.
        //
        // Deliberately a constant, not `min(4, cores)`: a single-core machine
        // still gets four workers, which is correct - they are IO-bound, so
        // oversubscribing costs a few kB of stack and nothing else, and a
        // firewall that deadlocks because it ran out of workers on a small VM
        // would be a much worse bug than the one this fixes.
        .worker_threads(4)
        // And a ceiling on the blocking pool, which tokio leaves at 512.
        // `dns.rs` runs its blocking resolver calls here, at most eight at
        // once (`LOOKUP_MAX_IN_FLIGHT`), and rule validation and provenance
        // use the same pool. Nothing should ever need 512 threads at 2 MiB of
        // stack reservation plus an arena apiece. Sixteen is plenty - the
        // packet worker permanently occupies one of them - and excess calls
        // then queue instead of spawning.
        .max_blocking_threads(16)
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let result = runtime.block_on(run());
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
    result
}

async fn run() -> anyhow::Result<()> {
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

    // Every verdict is persisted by the bounded async event pipeline: the
    // worker queues its refusals into `events` after the verdict, and Allow
    // rows come off the live feed. No packet waits for the database.
    let events = ipc::spawn_event_pipeline(store.clone(), &observed_tx, cfg.events.max_rows);

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

    let mut nfq = if args.dry_run {
        info!("--dry-run set: skipping NFQUEUE bind");
        nfqueue::NfqHandles::inert(tokio::spawn(async {
            std::future::pending::<anyhow::Result<()>>().await
        }))
    } else {
        nfqueue::spawn(
            &cfg.nfqueue,
            engine.clone(),
            prompt_tx,
            verdict_rx,
            observed_tx.clone(),
            stats.clone(),
            events,
            // Cloned rather than moved: the eBPF consumers write observed DNS
            // answers into the same cache, and they are started after READY=1
            // (see below) so the handle has to outlive this call.
            dns_cache.clone(),
        )
        .context("starting NFQUEUE worker")?
    };

    let mut flush_handle = maintenance::spawn_hit_flush(engine.clone(), store.clone());
    maintenance::spawn_provenance_warmer();
    maintenance::spawn_nft_presence_probe(stats.clone());
    maintenance::spawn_watchdog(nfq.last_activity.clone(), args.dry_run);

    // Readiness / failure semantics under Type=notify: READY=1 goes out
    // only after ipc::spawn bound the control socket AND nfqueue::spawn
    // bound the queue. On a failed bind, spawn returns Err and main exits
    // non-zero *before* READY, so systemd marks the unit failed and
    // Restart=on-failure retries with backoff.
    if let Err(e) = sd_notify::notify(&["READY=1"]) {
        warn!("sd_notify READY=1 failed: {e}");
    }
    info!(socket = %socket_path.display(), "ready");

    // eBPF enrichment. **After READY=1, deliberately.**
    //
    // Filtering is already live at this point - nfqueue::spawn has bound the
    // queue - and everything below is a cache that makes later answers better.
    // Putting it before READY would put two BTF parses, map creation and three
    // verifier runs on the path to readiness on every boot, for a unit that is
    // `Type=notify` and ordered `Before=network-pre.target`. Worse, the object
    // is read from a path: on a stale NFS or autofs mount that read blocks
    // until systemd's start timeout fires, with the fail-closed nftables table
    // already installed and no daemon behind it. That is a machine with no
    // outbound network, caused by an enrichment layer that is allowed to fail.
    //
    // The cost is a short window where the first few packets are attributed by
    // sock_diag + /proc alone, which is exactly what the daemon does when the
    // layer is unavailable anyway.
    //
    // Flush the legacy fast_allow nftables set before the layer comes up,
    // whatever its mode and whether or not it is compiled in: a mark an older
    // daemon left there would otherwise stay accepted. Not under --dry-run,
    // which touches nothing.
    if !args.dry_run {
        ebpf::flush_legacy_fast_allow_set();
    }

    // Held for the daemon's lifetime: dropping it detaches the programs.
    let _ebpf = ebpf::start(
        // `--dry-run` means "tell me what you would do without touching the
        // machine". Creating BPF maps and claiming the exclusive root-cgroup
        // slot is emphatically touching the machine.
        &if args.dry_run {
            // Say it here rather than leaving the layer's own note to guess:
            // it reports what it did, not who decided.
            info!("--dry-run set: not loading the eBPF layer");
            let mut c = cfg.ebpf.clone();
            c.enabled = config::EbpfMode::Off;
            c
        } else {
            cfg.ebpf.clone()
        },
        dns_cache.clone(),
        ebpf::proc_table::global().clone(),
        // The engine is what turns an `exec` into an in-kernel verdict. Passing
        // it here rather than having the layer reach for a global keeps the
        // direction of the dependency the same as everywhere else: the eBPF
        // layer is handed what it may read, and owns nothing the daemon needs.
        Some(engine.clone()),
    );
    _ebpf.report.log();
    // Publish it so `cfc status` can say where enforcement lives without anyone
    // having to go and read the journal.
    ebpf::set_enforcement_level(_ebpf.report.enforcement);

    // Persistent signal streams (not per-iteration futures) so nothing is
    // dropped and re-registered while the SIGHUP arm re-arms the loop.
    // SignalKind::interrupt() is Ctrl-C; this daemon is Linux-only.
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;

    // SIGINT (foreground ^C) and SIGTERM (systemd stop) both take the
    // graceful shutdown path below. SIGHUP reloads the shared default
    // policy and re-arms. A crashing task carries its error out of the loop
    // rather than returning straight away, so the shutdown sequence below
    // (stop the worker, flush hits, unlink the socket) runs on that path
    // too.
    let outcome: anyhow::Result<()> = loop {
        tokio::select! {
            r = &mut ipc_handle => {
                break r.context("ipc task crashed");
            }
            r = &mut nfq.task => {
                break r
                    .context("nfqueue task crashed")
                    .and_then(|inner| inner.context("nfqueue worker failed"));
            }
            r = &mut flush_handle => {
                break r.context("hit-flush task crashed");
            }
            _ = sigint.recv() => {
                info!("SIGINT received, flushing hits and shutting down");
                break Ok(());
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, flushing hits and shutting down");
                break Ok(());
            }
            _ = sighup.recv() => {
                info!("SIGHUP received, reloading config");
                maintenance::reload_policy(&args.config, &policy);
            }
        }
    };

    // First, before any of the slower cleanup: tell the NFQUEUE worker to
    // leave its loop, so its blocking thread is already on the way out by
    // the time `main` shuts the runtime down.
    nfq.request_stop();

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

    outcome
}
