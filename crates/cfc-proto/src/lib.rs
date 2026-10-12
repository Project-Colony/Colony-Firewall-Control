//! Colony Firewall Control - gRPC IPC bindings.
//!
//! Generated from `proto/cfc.proto`. Speaks daemon <-> UI/CLI over a Unix
//! domain socket (typically `/run/colony-firewall/cfc.sock`).

// Generated code. Clippy 1.99's double_must_use fires inside the
// #[async_trait] that tonic emits for the server trait; nothing here can
// change that. unknown_lints keeps older clippy versions quiet about the name.
#[allow(unknown_lints, clippy::double_must_use)]
pub mod v1 {
    tonic::include_proto!("cfc.v1");
}

pub use v1::{
    firewall_client::FirewallClient, firewall_server::FirewallServer, Action as ProtoAction,
    ConnectionInfo, Direction as ProtoDirection, Duration as ProtoDuration, ProcessInfo,
    PromptEvent, Protocol as ProtoProtocol, RuleInfo, RuleScope as ProtoRuleScope, VerdictRequest,
    VerdictResponse,
};

/// Default socket path used by the daemon and clients.
pub const DEFAULT_SOCKET_PATH: &str = "/run/colony-firewall/cfc.sock";

/// How the daemon's refusal of a change from a peer that may only read
/// begins. The app shows a lasting read-only notice when a refusal starts
/// with it, so the daemon builds that refusal from this constant.
pub const READ_ONLY_DENIAL: &str = "read-only access";
