//! NFQUEUE intercept worker.

use crate::decision::{Decision, Engine};
use crate::packet;
use crate::process_resolve;
use crate::stats::Stats;
use cfc_core::{Action, Connection, Direction, Process, Verdict};
use nfq::{Queue, Verdict as NfqVerdict};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

pub type PromptTx = mpsc::Sender<PromptRequest>;

/// A request from the NFQUEUE worker to the IPC layer asking for a verdict.
pub struct PromptRequest {
    pub connection: Connection,
    pub process: Process,
    pub responder: oneshot::Sender<Verdict>,
}

/// Observed connection (post-decision) broadcast to the live feed.
#[derive(Debug, Clone)]
pub struct ObservedConnection {
    pub connection: Connection,
    pub process: Process,
    pub verdict: Verdict,
}

pub async fn spawn(
    queue_num: u16,
    engine: Engine,
    _prompt_tx: PromptTx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
) -> anyhow::Result<JoinHandle<()>> {
    info!(queue_num, "opening NFQUEUE");

    let mut queue = match Queue::open() {
        Ok(q) => q,
        Err(e) => {
            error!("failed to open NFQUEUE socket: {e}. NFQUEUE worker disabled");
            return Ok(tokio::spawn(async {}));
        }
    };
    if let Err(e) = queue.bind(queue_num) {
        error!(
            queue_num,
            "failed to bind NFQUEUE: {e}. Are we running as root with CAP_NET_ADMIN?"
        );
        return Ok(tokio::spawn(async {}));
    }

    info!(queue_num, "NFQUEUE bound, entering recv loop");

    let handle = tokio::task::spawn_blocking(move || {
        recv_loop(queue, engine, observed_tx, stats);
    });

    Ok(tokio::spawn(async move {
        if let Err(e) = handle.await {
            error!("NFQUEUE blocking task joined with error: {e}");
        }
    }))
}

fn recv_loop(
    mut queue: Queue,
    engine: Engine,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
) {
    loop {
        let mut msg = match queue.recv() {
            Ok(m) => m,
            Err(e) => {
                error!("NFQUEUE recv error: {e}, sleeping then retrying");
                std::thread::sleep(std::time::Duration::from_millis(250));
                continue;
            }
        };

        let payload = msg.get_payload();
        let conn = match packet::parse(payload, Direction::Outbound) {
            Ok(c) => c,
            Err(e) => {
                debug!("dropping unparseable packet: {e}");
                msg.set_verdict(NfqVerdict::Accept);
                let _ = queue.verdict(msg);
                continue;
            }
        };

        let pid_hint = process_resolve::pid_for_socket(
            conn.protocol,
            conn.src_ip,
            conn.src_port,
            conn.dst_ip,
            conn.dst_port,
        );
        let proc = match pid_hint {
            Some(pid) => process_resolve::resolve(pid),
            None => Process::unknown(0),
        };
        let conn = if let Some(pid) = pid_hint {
            conn.with_process(pid, proc.uid)
        } else {
            conn
        };

        let decision = engine.evaluate(&conn, &proc);
        let verdict = match decision {
            Decision::Resolved(v) => v,
            Decision::NeedsPrompt { fallback } => {
                trace!(
                    pid = ?conn.pid,
                    dst = %conn.dst_ip,
                    port = conn.dst_port,
                    "no rule match - applying default policy (Phase 1e will prompt UI)"
                );
                fallback
            }
        };

        let nfq_verdict = match verdict.action {
            Action::Allow => NfqVerdict::Accept,
            Action::Deny | Action::Reject => NfqVerdict::Drop,
        };

        msg.set_verdict(nfq_verdict);
        if let Err(e) = queue.verdict(msg) {
            warn!("setting NFQUEUE verdict failed: {e}");
        }

        match verdict.action {
            Action::Allow => stats.record_allow(),
            Action::Deny | Action::Reject => stats.record_deny(),
        }

        let _ = observed_tx.send(ObservedConnection {
            connection: conn,
            process: proc,
            verdict,
        });
    }
}
