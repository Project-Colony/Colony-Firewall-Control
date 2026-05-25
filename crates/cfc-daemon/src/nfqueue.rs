//! NFQUEUE intercept worker.

use crate::decision::{Decision, Engine};
use crate::dns::DnsCache;
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
    prompt_tx: PromptTx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
    dns_cache: DnsCache,
) -> anyhow::Result<JoinHandle<()>> {
    info!(queue_num, "opening NFQUEUE");

    let mut queue = match Queue::open() {
        Ok(q) => q,
        Err(e) => {
            error!("failed to open NFQUEUE socket: {e}");
            error!("hint: NFQUEUE needs CAP_NET_ADMIN. Run as root or via the");
            error!("hint: bundled colony-firewalld.service systemd unit. If both");
            error!("hint: are in place, check that the nfnetlink_queue kernel");
            error!("hint: module is loaded:  modprobe nfnetlink_queue");
            error!("NFQUEUE worker disabled - daemon continues running for UI tests");
            return Ok(tokio::spawn(async {}));
        }
    };
    if let Err(e) = queue.bind(queue_num) {
        error!(queue_num, "failed to bind NFQUEUE {queue_num}: {e}");
        error!("hint: another process may already own this queue number.");
        error!("hint: list owners with:  ss -f netlink | grep nfqueue");
        error!("hint: or pick a different number in /etc/colony-firewall/daemon.toml");
        error!("hint: under [nfqueue] queue_num = N, and update the matching nft rule.");
        return Ok(tokio::spawn(async {}));
    }

    info!(queue_num, "NFQUEUE bound, entering recv loop");

    let handle = tokio::task::spawn_blocking(move || {
        recv_loop(queue, engine, prompt_tx, observed_tx, stats, dns_cache);
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
    prompt_tx: PromptTx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
    dns_cache: DnsCache,
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

        // Paused mode: short-circuit to ACCEPT, no parsing, no engine work.
        if stats.is_paused() {
            msg.set_verdict(NfqVerdict::Accept);
            let _ = queue.verdict(msg);
            continue;
        }

        let payload = msg.get_payload();
        let mut conn = match packet::parse(payload, Direction::Outbound) {
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

        // Always allow our own traffic. Otherwise the daemon's reverse DNS
        // resolver would itself be intercepted, deadlocking on a verdict
        // we can't produce until the resolver returns.
        if let Some(pid) = pid_hint {
            if dns_cache.is_self(pid) {
                msg.set_verdict(NfqVerdict::Accept);
                let _ = queue.verdict(msg);
                continue;
            }
        }

        let proc = match pid_hint {
            Some(pid) => process_resolve::resolve(pid),
            None => Process::unknown(0),
        };
        if let Some(pid) = pid_hint {
            conn = conn.with_process(pid, proc.uid);
        }

        // Attach cached hostname if any, kick off a fresh lookup for next time.
        if let Some(host) = dns_cache.lookup_cached(conn.dst_ip) {
            conn = conn.with_host(host);
        }
        dns_cache.enqueue_lookup(conn.dst_ip);

        let decision = engine.evaluate(&conn, &proc);
        let verdict = match decision {
            Decision::Resolved(v) => v,
            Decision::NeedsPrompt { fallback } => {
                let (tx, rx) = oneshot::channel();
                let req = PromptRequest {
                    connection: conn.clone(),
                    process: proc.clone(),
                    responder: tx,
                };
                match prompt_tx.blocking_send(req) {
                    Ok(()) => match rx.blocking_recv() {
                        Ok(v) => v,
                        Err(_) => {
                            trace!("prompt channel dropped, falling back");
                            fallback
                        }
                    },
                    Err(_) => {
                        trace!("prompt_tx closed, falling back");
                        fallback
                    }
                }
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
