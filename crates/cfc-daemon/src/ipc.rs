//! gRPC server over a Unix domain socket.
//!
//! Skeleton: opens the socket and accepts connections, but service handlers
//! are stubs returning `Unimplemented` for now. Phase 1 wires them to the
//! decision engine + storage.

use crate::decision::Engine;
use crate::nfqueue::{PromptRequest, PromptTx};
use crate::storage::RuleStore;
use anyhow::Context;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};
use tracing::info;

use cfc_proto::v1::{
    firewall_server::{Firewall, FirewallServer},
    DeleteRuleRequest, DeleteRuleResponse, ListRulesRequest, ListRulesResponse,
    StatusRequest, StatusResponse, SubscribeRequest, UpsertRuleRequest,
    UpsertRuleResponse, VerdictRequest, VerdictResponse,
};

struct FirewallService {
    #[allow(dead_code)]
    engine: Engine,
    #[allow(dead_code)]
    store: RuleStore,
    #[allow(dead_code)]
    prompt_tx: PromptTx,
}

#[tonic::async_trait]
impl Firewall for FirewallService {
    type StreamPromptsStream =
        tokio_stream::wrappers::ReceiverStream<Result<cfc_proto::v1::PromptEvent, Status>>;

    async fn stream_prompts(
        &self,
        _req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::StreamPromptsStream>, Status> {
        Err(Status::unimplemented("StreamPrompts: Phase 1"))
    }

    async fn submit_verdict(
        &self,
        _req: Request<VerdictRequest>,
    ) -> Result<Response<VerdictResponse>, Status> {
        Err(Status::unimplemented("SubmitVerdict: Phase 1"))
    }

    async fn list_rules(
        &self,
        _req: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        Err(Status::unimplemented("ListRules: Phase 1"))
    }

    async fn upsert_rule(
        &self,
        _req: Request<UpsertRuleRequest>,
    ) -> Result<Response<UpsertRuleResponse>, Status> {
        Err(Status::unimplemented("UpsertRule: Phase 1"))
    }

    async fn delete_rule(
        &self,
        _req: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, Status> {
        Err(Status::unimplemented("DeleteRule: Phase 1"))
    }

    type StreamConnectionsStream = tokio_stream::wrappers::ReceiverStream<
        Result<cfc_proto::v1::ConnectionEvent, Status>,
    >;

    async fn stream_connections(
        &self,
        _req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::StreamConnectionsStream>, Status> {
        Err(Status::unimplemented("StreamConnections: Phase 1"))
    }

    async fn get_status(
        &self,
        _req: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        Ok(Response::new(StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: 0,
            rules_count: 0,
            prompts_pending: 0,
            connections_today: 0,
            connections_allowed: 0,
            connections_denied: 0,
        }))
    }
}

pub async fn spawn(
    socket_path: PathBuf,
    engine: Engine,
    store: RuleStore,
) -> anyhow::Result<(JoinHandle<()>, PromptTx)> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let _ = std::fs::remove_file(&socket_path);

    let (prompt_tx, _prompt_rx) = mpsc::channel::<PromptRequest>(256);

    let service = FirewallService {
        engine,
        store,
        prompt_tx: prompt_tx.clone(),
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
