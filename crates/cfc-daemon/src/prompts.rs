//! Prompt router.
//!
//! Bridges the sync NFQUEUE worker (which produces `PromptRequest`s through
//! a blocking mpsc) with async UI subscribers (which receive `PromptEvent`s
//! via a broadcast channel). When the UI answers, `submit()` resolves the
//! pending oneshot the worker is blocking on. If no UI is connected or no
//! answer arrives within the timeout, the configured default policy fires.

use crate::config::DefaultPolicy;
use crate::convert;
use crate::nfqueue::PromptRequest;
use crate::stats::Stats;
use cfc_core::{Action, Verdict};
use cfc_proto::v1 as pb;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, trace, warn};

#[derive(Clone)]
pub struct PromptRouter {
    inner: Arc<RouterInner>,
}

struct RouterInner {
    pending: Mutex<HashMap<String, oneshot::Sender<Verdict>>>,
    broadcast_tx: broadcast::Sender<pb::PromptEvent>,
    default_policy: DefaultPolicy,
    stats: Stats,
}

impl PromptRouter {
    pub fn new(default_policy: DefaultPolicy, stats: Stats) -> Self {
        let (broadcast_tx, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(RouterInner {
                pending: Mutex::new(HashMap::new()),
                broadcast_tx,
                default_policy,
                stats,
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<pb::PromptEvent> {
        self.inner.broadcast_tx.subscribe()
    }

    pub fn submit(&self, prompt_id: &str, verdict: Verdict) -> bool {
        let mut pending = self.inner.pending.lock();
        if let Some(sender) = pending.remove(prompt_id) {
            drop(pending);
            self.inner.stats.prompts_dec();
            let _ = sender.send(verdict);
            true
        } else {
            false
        }
    }

    fn enqueue(&self, req: PromptRequest) {
        let prompt_id = uuid::Uuid::new_v4().to_string();
        let timeout =
            Duration::from_secs(self.inner.default_policy.prompt_timeout_secs as u64);

        // If no UI is subscribed, the prompt would just expire to default.
        // Cut the round-trip: answer immediately with no_ui_action.
        if self.inner.broadcast_tx.receiver_count() == 0 {
            let v = match self.inner.default_policy.no_ui_action {
                Action::Allow => Verdict::default_allow(),
                _ => Verdict::default_deny(),
            };
            trace!("no UI subscribers; answering with no_ui_action");
            let _ = req.responder.send(v);
            return;
        }

        let event = pb::PromptEvent {
            prompt_id: prompt_id.clone(),
            connection: Some(convert::connection_to_pb(&req.connection)),
            process: Some(convert::process_to_pb(&req.process)),
            deadline_unix_ms: chrono::Utc::now().timestamp_millis()
                + timeout.as_millis() as i64,
        };

        {
            let mut pending = self.inner.pending.lock();
            pending.insert(prompt_id.clone(), req.responder);
        }
        self.inner.stats.prompts_inc();

        match self.inner.broadcast_tx.send(event) {
            Ok(_) => {}
            Err(_) => {
                // All receivers vanished between the count check and the
                // send. Reclaim and fall back.
                if let Some(sender) = self.inner.pending.lock().remove(&prompt_id) {
                    self.inner.stats.prompts_dec();
                    let v = match self.inner.default_policy.no_ui_action {
                        Action::Allow => Verdict::default_allow(),
                        _ => Verdict::default_deny(),
                    };
                    let _ = sender.send(v);
                }
                return;
            }
        }

        // Timeout sweeper: if nobody answered by `timeout`, apply
        // timeout_action.
        let inner = self.inner.clone();
        let id_for_timeout = prompt_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let sender_opt = inner.pending.lock().remove(&id_for_timeout);
            if let Some(sender) = sender_opt {
                inner.stats.prompts_dec();
                debug!(prompt_id = %id_for_timeout, "prompt timed out");
                let v = match inner.default_policy.timeout_action {
                    Action::Allow => Verdict::default_allow(),
                    _ => Verdict::default_deny(),
                };
                let _ = sender.send(v);
            }
        });
    }
}

/// Pumps `PromptRequest`s from the NFQUEUE worker into the router.
pub async fn run_router_task(
    mut prompt_rx: mpsc::Receiver<PromptRequest>,
    router: PromptRouter,
) {
    while let Some(req) = prompt_rx.recv().await {
        router.enqueue(req);
    }
    warn!("prompt router channel closed");
}
