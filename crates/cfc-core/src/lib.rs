//! Colony Firewall Control - shared types.
//!
//! Data model used by the daemon, UI, and CLI. No I/O here, only definitions.

pub mod connection;
pub mod exe_path;
pub mod process;
pub mod rule;
pub mod verdict;

pub use connection::{Connection, Direction, Protocol};
pub use exe_path::Resolved as ResolvedExe;
pub use process::{Process, Provenance};
pub use rule::{Action, Duration, Rule, RuleScope, RuleSet};
pub use verdict::{Verdict, VerdictSource};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid rule: {0}")]
    InvalidRule(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
