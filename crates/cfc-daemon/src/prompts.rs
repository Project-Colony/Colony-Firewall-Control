//! Prompt router.
//!
//! Bridges the sync NFQUEUE worker (which produces `PromptRequest`s through
//! a bounded tokio mpsc) with async UI subscribers (which receive
//! `PromptEvent`s via a broadcast channel). Responses travel back to the
//! worker over the std-mpsc verdict channel as `PromptVerdict`s.
//!
//! Exactly-once resolution: for every prompt, precisely one of {user
//! answer, timeout sweeper, no-UI fast path, vanished-subscriber reclaim}
//! sends the `PromptVerdict`. The `pending` set is the arbiter - whichever
//! path removes the id first wins, the loser is ignored.

use crate::config::DefaultPolicy;
use crate::convert;
use crate::decision::SharedPolicy;
use crate::nfqueue::{PromptRequest, PromptVerdict, VerdictTx};
use crate::stats::Stats;
use cfc_core::{Action, Verdict};
use cfc_proto::v1 as pb;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, trace, warn};

#[derive(Clone)]
pub struct PromptRouter {
    inner: Arc<RouterInner>,
}

struct RouterInner {
    /// Prompt ids broadcast to the UI and not yet resolved. Present means
    /// "unresolved"; the first resolution path to remove an id sends the
    /// verdict.
    pending: Mutex<HashSet<u64>>,
    broadcast_tx: broadcast::Sender<pb::PromptEvent>,
    default_policy: SharedPolicy,
    stats: Stats,
    /// Response path back to the NFQUEUE worker thread. std mpsc is
    /// unbounded, so sending from async context never blocks.
    verdict_tx: VerdictTx,
}

impl RouterInner {
    /// Copies the current shared policy. SIGHUP swaps it at runtime, so
    /// each read observes the latest reload (poisoning is unrecoverable
    /// only in theory: writers just store a Copy value, so recover it).
    fn policy(&self) -> DefaultPolicy {
        *self
            .default_policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn no_ui_verdict(&self) -> Verdict {
        match self.policy().no_ui_action {
            Action::Allow => Verdict::default_allow(),
            _ => Verdict::default_deny(),
        }
    }
}

impl PromptRouter {
    pub fn new(default_policy: SharedPolicy, stats: Stats, verdict_tx: VerdictTx) -> Self {
        let (broadcast_tx, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(RouterInner {
                pending: Mutex::new(HashSet::new()),
                broadcast_tx,
                default_policy,
                stats,
                verdict_tx,
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<pb::PromptEvent> {
        self.inner.broadcast_tx.subscribe()
    }

    /// Resolves a pending prompt with the user's verdict. Returns false if
    /// the id is unknown or the prompt already resolved another way (e.g.
    /// it timed out first), in which case the verdict is discarded.
    pub fn submit(&self, prompt_id: &str, verdict: Verdict) -> bool {
        let Ok(id) = prompt_id.parse::<u64>() else {
            return false;
        };
        if !self.inner.pending.lock().remove(&id) {
            return false;
        }
        self.inner.stats.prompts_dec();
        let _ = self.inner.verdict_tx.send(PromptVerdict {
            prompt_id: id,
            verdict,
        });
        true
    }

    fn enqueue(&self, req: PromptRequest) {
        let prompt_id = req.prompt_id;
        // Read the shared policy at prompt-creation time so a SIGHUP
        // reload affects every subsequent prompt without a restart.
        let timeout = Duration::from_secs(self.inner.policy().prompt_timeout_secs as u64);

        // If no UI is subscribed, the prompt would just expire to default.
        // Cut the round-trip: answer immediately with no_ui_action.
        if self.inner.broadcast_tx.receiver_count() == 0 {
            trace!("no UI subscribers; answering with no_ui_action");
            let _ = self.inner.verdict_tx.send(PromptVerdict {
                prompt_id,
                verdict: self.inner.no_ui_verdict(),
            });
            return;
        }

        let event = pb::PromptEvent {
            prompt_id: prompt_id.to_string(),
            connection: Some(convert::connection_to_pb(&req.connection)),
            process: Some(convert::process_to_pb(&req.process)),
            deadline_unix_ms: chrono::Utc::now().timestamp_millis() + timeout.as_millis() as i64,
        };

        self.inner.pending.lock().insert(prompt_id);
        self.inner.stats.prompts_inc();

        if self.inner.broadcast_tx.send(event).is_err() {
            // All receivers vanished between the count check and the
            // send. Reclaim and fall back.
            if self.inner.pending.lock().remove(&prompt_id) {
                self.inner.stats.prompts_dec();
                let _ = self.inner.verdict_tx.send(PromptVerdict {
                    prompt_id,
                    verdict: self.inner.no_ui_verdict(),
                });
            }
            return;
        }

        // Timeout sweeper: if nobody answered by `timeout`, apply
        // timeout_action.
        let inner = self.inner.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            if inner.pending.lock().remove(&prompt_id) {
                inner.stats.prompts_dec();
                debug!(prompt_id, "prompt timed out");
                let v = match inner.policy().timeout_action {
                    Action::Allow => Verdict::default_allow(),
                    _ => Verdict::default_deny(),
                };
                let _ = inner.verdict_tx.send(PromptVerdict {
                    prompt_id,
                    verdict: v,
                });
            }
        });
    }
}

/// Pumps `PromptRequest`s from the NFQUEUE worker into the router.
pub async fn run_router_task(mut prompt_rx: mpsc::Receiver<PromptRequest>, router: PromptRouter) {
    while let Some(req) = prompt_rx.recv().await {
        router.enqueue(req);
    }
    warn!("prompt router channel closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfc_core::{Connection, Direction, Process, Protocol, VerdictSource};
    use std::net::{IpAddr, Ipv4Addr};

    fn dp(prompt_timeout_secs: u32) -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: Action::Deny,
            timeout_action: Action::Deny,
            prompt_timeout_secs,
        }
    }

    fn shared(dp: DefaultPolicy) -> SharedPolicy {
        Arc::new(std::sync::RwLock::new(dp))
    }

    fn req(prompt_id: u64) -> PromptRequest {
        PromptRequest {
            prompt_id,
            connection: Connection::new(
                Protocol::Tcp,
                Direction::Outbound,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                1234,
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                443,
            ),
            process: Process::unknown(1),
        }
    }

    fn user_allow() -> Verdict {
        Verdict {
            action: Action::Allow,
            source: VerdictSource::UserPrompt,
        }
    }

    #[tokio::test]
    async fn no_ui_answers_immediately_with_no_ui_action() {
        let (tx, rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(dp(15)), Stats::new(), tx);
        router.enqueue(req(7));
        let pv = rx.try_recv().expect("verdict should already be queued");
        assert_eq!(pv.prompt_id, 7);
        assert_eq!(pv.verdict.action, Action::Deny);
        // Nothing is pending: a late submit is rejected.
        assert!(!router.submit("7", user_allow()));
    }

    #[tokio::test]
    async fn user_answer_resolves_exactly_once() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Stats::new();
        let router = PromptRouter::new(shared(dp(3600)), stats.clone(), tx);
        let mut sub = router.subscribe();

        router.enqueue(req(1));
        let event = sub.recv().await.unwrap();
        assert_eq!(event.prompt_id, "1");
        assert_eq!(stats.prompts_pending(), 1);

        assert!(router.submit("1", user_allow()));
        assert_eq!(stats.prompts_pending(), 0);
        let pv = rx.try_recv().unwrap();
        assert_eq!(pv.prompt_id, 1);
        assert_eq!(pv.verdict.action, Action::Allow);

        // A second answer loses: rejected, no duplicate verdict.
        assert!(!router.submit("1", user_allow()));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unknown_or_malformed_prompt_id_rejected() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(dp(15)), Stats::new(), tx);
        assert!(!router.submit("12345", user_allow()));
        assert!(!router.submit("not-a-number", user_allow()));
    }

    #[tokio::test]
    async fn policy_reload_applies_to_subsequent_prompts() {
        let (tx, rx) = std::sync::mpsc::channel();
        let policy = shared(dp(15)); // no_ui_action: Deny
        let router = PromptRouter::new(policy.clone(), Stats::new(), tx);

        // No UI subscribed: the fast path answers with no_ui_action.
        router.enqueue(req(1));
        assert_eq!(rx.try_recv().unwrap().verdict.action, Action::Deny);

        // Swap the shared policy in place (what SIGHUP does in main).
        policy.write().unwrap().no_ui_action = Action::Allow;

        router.enqueue(req(2));
        assert_eq!(rx.try_recv().unwrap().verdict.action, Action::Allow);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_resolves_with_timeout_action() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Stats::new();
        let router = PromptRouter::new(shared(dp(1)), stats.clone(), tx);
        let _sub = router.subscribe(); // keep a UI "connected"

        router.enqueue(req(9));
        assert_eq!(stats.prompts_pending(), 1);

        // Paused time auto-advances past the sweeper's deadline.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let pv = rx.try_recv().expect("timeout verdict should be queued");
        assert_eq!(pv.prompt_id, 9);
        assert_eq!(pv.verdict.action, Action::Deny);
        assert_eq!(stats.prompts_pending(), 0);
        // The user answering afterwards is a no-op.
        assert!(!router.submit("9", user_allow()));
        assert!(rx.try_recv().is_err());
    }
}
