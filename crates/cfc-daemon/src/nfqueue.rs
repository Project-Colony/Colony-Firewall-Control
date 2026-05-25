//! NFQUEUE intercept worker.
//!
//! Owns the netfilter queue file descriptor. For every packet handed by the
//! kernel, parses the 5-tuple, resolves the owning process, asks the
//! decision engine, and writes back ACCEPT or DROP.
//!
//! NOTE: this is currently a skeleton. Real packet parsing, process
//! resolution and prompt round-trip land in Phase 1.

use crate::decision::Engine;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub type PromptTx = mpsc::Sender<PromptRequest>;

/// A request from the NFQUEUE worker to the IPC layer asking for a verdict.
pub struct PromptRequest {
    pub connection: cfc_core::Connection,
    pub process: cfc_core::Process,
    pub responder: tokio::sync::oneshot::Sender<cfc_core::Verdict>,
}

pub async fn spawn(
    queue_num: u16,
    _engine: Engine,
    _prompt_tx: PromptTx,
) -> anyhow::Result<JoinHandle<()>> {
    info!(queue_num, "NFQUEUE worker would attach here");

    let handle = tokio::task::spawn_blocking(move || {
        // TODO Phase 1: open nfq::Queue, loop recv -> parse -> resolve ->
        // engine.evaluate() -> set_verdict(). For now we just park.
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            warn!("nfqueue worker is a stub - no packets being processed yet");
        }
    });

    // Wrap the JoinHandle<()> from spawn_blocking into a future-shaped one.
    Ok(tokio::spawn(async move {
        let _ = handle.await;
    }))
}
