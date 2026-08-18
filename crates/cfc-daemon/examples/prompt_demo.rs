//! Prompt-flow demo daemon.
//!
//! Assembles the daemon's real internals (store, engine, router, IPC) on a
//! plain socket — no root, no NFQUEUE — and emits a synthetic prompt every
//! 25 seconds, exactly like the integration harness does. Point any client
//! at it to exercise the full prompt round-trip interactively:
//!
//! ```sh
//! cargo run -p cfc-daemon --example prompt_demo
//! CFC_SOCKET=/tmp/cfc-demo/cfc.sock colony-firewall-tray   # or the GUI/cfc
//! ```
//!
//! Verdicts coming back over the worker channel are printed, so you can see
//! a notification button click arrive where the NFQUEUE worker would
//! normally apply it. Packets are imaginary; nothing is filtered.

use cfc_core::Action;
use cfc_core::{Connection, Direction, Process, Protocol};
use cfc_daemon::config::{DefaultPolicy, IpcConfig};
use cfc_daemon::decision::{Engine, SharedPolicy};
use cfc_daemon::ipc::{self, IpcOptions};
use cfc_daemon::nfqueue::PromptRequest;
use cfc_daemon::prompts::PromptRouter;
use cfc_daemon::stats::Stats;
use cfc_daemon::storage::RuleStore;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;

const SOCKET: &str = "/tmp/cfc-demo/cfc.sock";

/// A rotating cast of pretend applications, so successive prompts look
/// different in the notification.
const CAST: &[(&str, &str, u16)] = &[
    ("/usr/bin/curl", "api.github.com", 443),
    ("/usr/bin/ssh", "backup.example.net", 22),
    ("/usr/lib/firefox/firefox", "telemetry.example.com", 443),
    ("/usr/bin/python3", "203.0.113.99", 8080),
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .with_target(false)
        .init();

    let dir = PathBuf::from("/tmp/cfc-demo");
    std::fs::create_dir_all(&dir)?;

    let store = RuleStore::open(&dir.join("rules.db"))?;
    // 45s per prompt: enough time to read a notification and pick a
    // button. Timeout denies, like every shipped profile — an unanswered
    // question is not consent.
    let policy: SharedPolicy = Arc::new(std::sync::RwLock::new(DefaultPolicy {
        no_ui_action: Action::Allow,
        timeout_action: Action::Deny,
        prompt_timeout_secs: 45,
    }));
    let engine = Engine::new(store.snapshot()?, policy.clone());
    let (observed_tx, _) = broadcast::channel(256);
    let stats = Stats::new();
    let (verdict_tx, verdict_rx) = std::sync::mpsc::channel();
    let router = PromptRouter::new(policy.clone(), stats.clone(), verdict_tx);
    ipc::spawn_event_pipeline(store.clone(), &observed_tx, 10_000);

    let (_ipc, prompt_tx) = ipc::spawn(
        IpcOptions {
            socket_path: PathBuf::from(SOCKET),
            ipc: IpcConfig {
                group: "colony-firewall".into(),
                // Demo socket in /tmp: let the invoking user talk to it.
                require_group: false,
            },
            pause_default_secs: 120,
            dry_run: true,
        },
        engine,
        store,
        observed_tx,
        router,
        stats,
        policy,
    )
    .await?;

    // Stand-in for the NFQUEUE worker: print every verdict that would have
    // been applied to the parked packet.
    std::thread::spawn(move || {
        while let Ok(pv) = verdict_rx.recv() {
            tracing::info!(
                prompt_id = pv.prompt_id,
                action = ?pv.verdict.action,
                source = ?pv.verdict.source,
                "verdict arrived at the (pretend) worker"
            );
        }
    });

    let uid = nix::unistd::Uid::current().as_raw();
    tracing::info!(
        socket = SOCKET,
        uid,
        "demo daemon up - a prompt fires every 25s"
    );

    let mut prompt_id: u64 = 1;
    loop {
        let (exe, host, port) = CAST[(prompt_id as usize - 1) % CAST.len()];
        // Prompt delivery is uid-scoped: own the pretend process so this
        // session's tray/GUI actually receives it.
        let mut process = Process::unknown(4242);
        process.exe = PathBuf::from(exe);
        process.uid = Some(uid);
        let connection = Connection::new(
            Protocol::Tcp,
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            54321,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            port,
        )
        .with_host(host);

        tracing::info!(prompt_id, exe, host, "emitting demo prompt");
        if prompt_tx
            .send(PromptRequest {
                prompt_id,
                connection,
                process,
            })
            .await
            .is_err()
        {
            anyhow::bail!("prompt channel closed");
        }
        prompt_id += 1;
        tokio::time::sleep(std::time::Duration::from_secs(25)).await;
    }
}
