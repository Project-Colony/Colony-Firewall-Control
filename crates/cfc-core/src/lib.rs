//! Colony Firewall Control - shared types.
//!
//! Data model used by the daemon, UI, and CLI. No I/O here, only definitions.

pub mod connection;
pub mod exe_path;
pub mod process;
pub mod rule;
pub mod verdict;

pub use connection::{Connection, Direction, Protocol};
pub use process::{Process, Provenance, UNKNOWN_EXE};
pub use rule::{Action, Duration, Rule, RuleScope, RuleSet};
pub use verdict::{Verdict, VerdictSource};
