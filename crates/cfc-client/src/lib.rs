//! Colony Firewall Control - shared client.
//!
//! Wraps the tonic-generated `FirewallClient` with a Unix-domain-socket
//! transport. Used by `cfc-ui` and `cfc-cli`.

use anyhow::Context;
use cfc_proto::v1::firewall_client::FirewallClient;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub mod convert;

pub use cfc_proto::v1 as proto;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connecting to {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("rpc: {0}")]
    Rpc(#[from] tonic::Status),

    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),
}

#[derive(Clone)]
pub struct Client {
    inner: FirewallClient<Channel>,
}

impl Client {
    pub async fn connect(socket_path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let path = socket_path.as_ref().to_path_buf();
        let connect_path = path.clone();

        let endpoint = Endpoint::try_from("http://localhost")
            .context("building endpoint")
            .map_err(|e| ClientError::Connect {
                path: path.clone(),
                source: e.into(),
            })?
            .timeout(Duration::from_secs(5));

        let channel = endpoint
            .connect_with_connector(service_fn(move |_: Uri| {
                let p = connect_path.clone();
                async move {
                    let stream = UnixStream::connect(p).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| ClientError::Connect {
                path,
                source: Box::new(e),
            })?;

        Ok(Self {
            inner: FirewallClient::new(channel),
        })
    }

    pub fn raw(&mut self) -> &mut FirewallClient<Channel> {
        &mut self.inner
    }

    pub async fn status(&mut self) -> Result<proto::StatusResponse, ClientError> {
        let resp = self.inner.get_status(proto::StatusRequest {}).await?;
        Ok(resp.into_inner())
    }

    pub async fn list_rules(&mut self) -> Result<Vec<proto::RuleInfo>, ClientError> {
        let resp = self.inner.list_rules(proto::ListRulesRequest {}).await?;
        Ok(resp.into_inner().rules)
    }

    pub async fn upsert_rule(&mut self, rule: proto::RuleInfo) -> Result<String, ClientError> {
        let resp = self
            .inner
            .upsert_rule(proto::UpsertRuleRequest { rule: Some(rule) })
            .await?;
        Ok(resp.into_inner().id)
    }

    pub async fn delete_rule(&mut self, id: &str) -> Result<bool, ClientError> {
        let resp = self
            .inner
            .delete_rule(proto::DeleteRuleRequest { id: id.to_string() })
            .await?;
        Ok(resp.into_inner().deleted)
    }

    /// Pauses or resumes enforcement. `duration_secs = 0` asks the daemon
    /// to use its configured default; the daemon clamps the value and
    /// reports the effective deadline in `resume_at_unix_ms`, so callers
    /// must read it from the response rather than assume one.
    pub async fn set_paused(
        &mut self,
        paused: bool,
        duration_secs: u32,
    ) -> Result<proto::SetPausedResponse, ClientError> {
        let resp = self
            .inner
            .set_paused(proto::SetPausedRequest {
                paused,
                duration_secs,
            })
            .await?;
        Ok(resp.into_inner())
    }

    pub async fn submit_verdict(
        &mut self,
        prompt_id: &str,
        action: proto::Action,
        duration: proto::Duration,
        persist_scope: Option<proto::RuleScope>,
    ) -> Result<bool, ClientError> {
        let req = proto::VerdictRequest {
            prompt_id: prompt_id.to_string(),
            action: action as i32,
            duration: duration as i32,
            persist_scope,
        };
        let resp = self.inner.submit_verdict(req).await?;
        Ok(resp.into_inner().accepted)
    }

    pub async fn stream_connections(
        &mut self,
        client_id: String,
    ) -> Result<tonic::Streaming<proto::ConnectionEvent>, ClientError> {
        let resp = self
            .inner
            .stream_connections(proto::SubscribeRequest { client_id })
            .await?;
        Ok(resp.into_inner())
    }

    pub async fn stream_prompts(
        &mut self,
        client_id: String,
    ) -> Result<tonic::Streaming<proto::PromptEvent>, ClientError> {
        let resp = self
            .inner
            .stream_prompts(proto::SubscribeRequest { client_id })
            .await?;
        Ok(resp.into_inner())
    }
}
