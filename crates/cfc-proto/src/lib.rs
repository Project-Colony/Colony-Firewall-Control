//! Colony Firewall Control - gRPC IPC bindings.
//!
//! Generated from `proto/cfc.proto`. Speaks daemon <-> UI/CLI over a Unix
//! domain socket (typically `/run/colony-firewall/cfc.sock`).

pub mod v1 {
    tonic::include_proto!("cfc.v1");
}

pub use v1::{
    firewall_client::FirewallClient, firewall_server::FirewallServer,
    Action as ProtoAction, ConnectionInfo, Direction as ProtoDirection,
    Duration as ProtoDuration, ProcessInfo, PromptEvent, Protocol as ProtoProtocol,
    RuleInfo, RuleScope as ProtoRuleScope, VerdictRequest, VerdictResponse,
};

/// Default socket path used by the daemon and clients.
pub const DEFAULT_SOCKET_PATH: &str = "/run/colony-firewall/cfc.sock";
