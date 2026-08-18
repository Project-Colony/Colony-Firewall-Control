//! Typed CLI errors and the exit-code contract.
//!
//! Scripts need to tell "the daemon is not there" from "your rule id was
//! wrong" from "the RPC failed" without parsing stderr, so every failure
//! path funnels through [`CliError`] and its [`CliError::exit_code`].

use cfc_client::ClientError;

/// Everything worked.
pub const EXIT_OK: i32 = 0;
/// Runtime failure: an RPC was refused, a file could not be read, ...
pub const EXIT_RUNTIME: i32 = 1;
/// Usage error. Emitted by clap itself, listed here for documentation.
pub const EXIT_USAGE: i32 = 2;
/// The thing you named (rule id, prompt id) does not exist.
pub const EXIT_NOT_FOUND: i32 = 3;
/// The daemon could not be reached at all.
pub const EXIT_UNREACHABLE: i32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// `{0:#}` renders the whole anyhow context chain on one line.
    #[error("{0:#}")]
    Runtime(anyhow::Error),

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Unreachable(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Runtime(_) => EXIT_RUNTIME,
            CliError::NotFound(_) => EXIT_NOT_FOUND,
            CliError::Unreachable(_) => EXIT_UNREACHABLE,
        }
    }

    pub fn runtime(msg: impl Into<String>) -> Self {
        CliError::Runtime(anyhow::anyhow!(msg.into()))
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        CliError::NotFound(msg.into())
    }
}

impl From<anyhow::Error> for CliError {
    fn from(e: anyhow::Error) -> Self {
        CliError::Runtime(e)
    }
}

impl From<ClientError> for CliError {
    fn from(e: ClientError) -> Self {
        if e.is_unreachable() {
            return CliError::Unreachable(e.to_string());
        }
        match &e {
            // The daemon says the thing is gone; that is exit 3, not a
            // generic RPC failure.
            ClientError::Rpc(status) if status.code() == tonic::Code::NotFound => {
                CliError::NotFound(status.message().to_string())
            }
            _ => CliError::Runtime(anyhow::Error::new(e)),
        }
    }
}

pub type CliResult<T = ()> = Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_the_documented_contract() {
        assert_eq!(CliError::runtime("boom").exit_code(), 1);
        assert_eq!(CliError::not_found("no rule").exit_code(), 3);
        assert_eq!(
            CliError::Unreachable("no socket".into()).exit_code(),
            EXIT_UNREACHABLE
        );
        assert_eq!(EXIT_OK, 0);
        assert_eq!(EXIT_USAGE, 2);
    }

    #[test]
    fn unreachable_client_errors_map_to_4() {
        let err: CliError = ClientError::SocketMissing {
            path: "/run/cfc.sock".into(),
        }
        .into();
        assert_eq!(err.exit_code(), EXIT_UNREACHABLE);
        assert!(err.to_string().contains("colony-firewalld"));

        let err: CliError = ClientError::PermissionDenied {
            path: "/run/cfc.sock".into(),
        }
        .into();
        assert_eq!(err.exit_code(), EXIT_UNREACHABLE);

        let err: CliError = ClientError::StaleSocket {
            path: "/run/cfc.sock".into(),
        }
        .into();
        assert_eq!(err.exit_code(), EXIT_UNREACHABLE);
    }

    #[test]
    fn rpc_errors_map_to_1_except_not_found() {
        let err: CliError = ClientError::Rpc(tonic::Status::internal("bad")).into();
        assert_eq!(err.exit_code(), EXIT_RUNTIME);

        let err: CliError = ClientError::Rpc(tonic::Status::not_found("no rule 7")).into();
        assert_eq!(err.exit_code(), EXIT_NOT_FOUND);

        // Unavailable means "the daemon is not answering" -> 4.
        let err: CliError = ClientError::Rpc(tonic::Status::unavailable("gone")).into();
        assert_eq!(err.exit_code(), EXIT_UNREACHABLE);
    }

    #[test]
    fn anyhow_context_chain_is_preserved_on_one_line() {
        use anyhow::Context;
        let e: anyhow::Error = Err::<(), _>(std::io::Error::other("disk on fire"))
            .context("writing /tmp/x")
            .unwrap_err();
        let err: CliError = e.into();
        let msg = err.to_string();
        assert!(msg.contains("writing /tmp/x"), "{msg}");
        assert!(msg.contains("disk on fire"), "{msg}");
    }
}
