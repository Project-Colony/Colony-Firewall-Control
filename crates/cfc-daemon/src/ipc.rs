//! gRPC server over a Unix domain socket.

use crate::convert;
use crate::decision::Engine;
use crate::nfqueue::{ObservedConnection, PromptRequest, PromptTx};
use crate::prompts::PromptRouter;
use crate::stats::Stats;
use crate::storage::RuleStore;
use anyhow::Context;
use std::path::PathBuf;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use cfc_proto::v1::{
    firewall_server::{Firewall, FirewallServer},
    ConnectionEvent, DeleteRuleRequest, DeleteRuleResponse, ListRulesRequest, ListRulesResponse,
    PromptEvent, StatusRequest, StatusResponse, SubscribeRequest, UpsertRuleRequest,
    UpsertRuleResponse, VerdictRequest, VerdictResponse,
};

struct FirewallService {
    engine: Engine,
    store: RuleStore,
    observed_tx: broadcast::Sender<ObservedConnection>,
    router: PromptRouter,
    stats: Stats,
}

#[tonic::async_trait]
impl Firewall for FirewallService {
    type StreamPromptsStream = tokio_stream::wrappers::ReceiverStream<Result<PromptEvent, Status>>;

    async fn stream_prompts(
        &self,
        _req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::StreamPromptsStream>, Status> {
        let (tx, rx) = mpsc::channel(64);
        let mut sub = self.router.subscribe();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("prompt stream client lagged by {n} prompts");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn submit_verdict(
        &self,
        req: Request<VerdictRequest>,
    ) -> Result<Response<VerdictResponse>, Status> {
        let req = req.into_inner();
        let action = convert::action_from_pb(req.action);
        let verdict = cfc_core::Verdict {
            action,
            source: cfc_core::VerdictSource::UserPrompt,
        };

        if let Some(scope_pb) = req.persist_scope.clone() {
            let scope = convert::scope_from_pb(&scope_pb);
            let duration = convert::duration_from_pb(req.duration);
            let rule = cfc_core::Rule {
                id: uuid::Uuid::new_v4(),
                name: format!("user prompt {}", req.prompt_id),
                enabled: true,
                action,
                duration,
                scope,
                created_at: chrono::Utc::now(),
                hit_count: 0,
            };
            if let Err(e) = self.store.upsert(&rule) {
                warn!("failed to persist rule from prompt verdict: {e}");
            } else {
                self.engine.upsert_rule(rule);
            }
        }

        let accepted = self.router.submit(&req.prompt_id, verdict);
        Ok(Response::new(VerdictResponse {
            accepted,
            error: if accepted {
                String::new()
            } else {
                format!("no pending prompt with id {}", req.prompt_id)
            },
        }))
    }

    async fn list_rules(
        &self,
        _req: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        let snapshot = self.engine.snapshot();
        let rules = snapshot.rules.iter().map(convert::rule_to_pb).collect();
        Ok(Response::new(ListRulesResponse { rules }))
    }

    async fn upsert_rule(
        &self,
        req: Request<UpsertRuleRequest>,
    ) -> Result<Response<UpsertRuleResponse>, Status> {
        let proto = req
            .into_inner()
            .rule
            .ok_or_else(|| Status::invalid_argument("rule required"))?;
        let rule = convert::rule_from_pb(&proto).map_err(Status::invalid_argument)?;
        self.store
            .upsert(&rule)
            .map_err(|e| Status::internal(format!("storage: {e}")))?;
        let id = rule.id.to_string();
        self.engine.upsert_rule(rule);
        Ok(Response::new(UpsertRuleResponse {
            id,
            error: String::new(),
        }))
    }

    async fn delete_rule(
        &self,
        req: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, Status> {
        let id_str = req.into_inner().id;
        let id = uuid::Uuid::parse_str(&id_str)
            .map_err(|e| Status::invalid_argument(format!("bad uuid: {e}")))?;
        let deleted = self
            .store
            .delete(id)
            .map_err(|e| Status::internal(format!("storage: {e}")))?;
        if deleted {
            self.engine.remove_rule(id);
        }
        Ok(Response::new(DeleteRuleResponse { deleted }))
    }

    type StreamConnectionsStream =
        tokio_stream::wrappers::ReceiverStream<Result<ConnectionEvent, Status>>;

    async fn stream_connections(
        &self,
        _req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::StreamConnectionsStream>, Status> {
        let (tx, rx) = mpsc::channel(256);
        let mut sub = self.observed_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(obs) => {
                        let ev = ConnectionEvent {
                            connection: Some(convert::connection_to_pb(&obs.connection)),
                            process: Some(convert::process_to_pb(&obs.process)),
                            verdict: convert::verdict_to_pb_action(&obs.verdict) as i32,
                            rule_id: match obs.verdict.source {
                                cfc_core::VerdictSource::Rule(id) => id.to_string(),
                                _ => String::new(),
                            },
                        };
                        if tx.send(Ok(ev)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("connection stream client lagged by {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn get_status(
        &self,
        _req: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let rules_count = self.engine.snapshot().rules.len() as u64;
        Ok(Response::new(StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.stats.uptime_seconds(),
            rules_count,
            prompts_pending: self.stats.prompts_pending(),
            connections_today: self.stats.connections_total(),
            connections_allowed: self.stats.connections_allowed(),
            connections_denied: self.stats.connections_denied(),
            paused: self.stats.is_paused(),
        }))
    }

    async fn set_paused(
        &self,
        req: Request<cfc_proto::v1::SetPausedRequest>,
    ) -> Result<Response<cfc_proto::v1::SetPausedResponse>, Status> {
        let paused = req.into_inner().paused;
        let generation = self.stats.set_paused(paused);
        tracing::info!("paused = {paused} (generation {generation})");

        // Safety net: if we just paused, schedule an auto-resume in 10
        // minutes. The generation check makes this a no-op if the user
        // toggles again before the timer fires.
        if paused {
            let stats = self.stats.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                if stats.pause_generation() == generation && stats.is_paused() {
                    stats.set_paused(false);
                    tracing::info!("auto-unpaused after 10 min (generation {generation})");
                }
            });
        }

        Ok(Response::new(cfc_proto::v1::SetPausedResponse { paused }))
    }
}

pub async fn spawn(
    socket_path: PathBuf,
    engine: Engine,
    store: RuleStore,
    observed_tx: broadcast::Sender<ObservedConnection>,
    router: PromptRouter,
    stats: Stats,
) -> anyhow::Result<(JoinHandle<()>, PromptTx)> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let _ = std::fs::remove_file(&socket_path);

    let (prompt_tx, prompt_rx) = mpsc::channel::<PromptRequest>(256);

    let router_for_pump = router.clone();
    tokio::spawn(async move {
        crate::prompts::run_router_task(prompt_rx, router_for_pump).await;
    });

    let service = FirewallService {
        engine,
        store,
        observed_tx,
        router,
        stats,
    };

    let uds = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);

    info!(socket = %socket_path.display(), "IPC listening");

    let handle = tokio::spawn(async move {
        let result = tonic::transport::Server::builder()
            .add_service(FirewallServer::new(service))
            .serve_with_incoming(incoming)
            .await;
        if let Err(e) = result {
            tracing::error!("IPC server exited: {e}");
        }
    });

    Ok((handle, prompt_tx))
}
