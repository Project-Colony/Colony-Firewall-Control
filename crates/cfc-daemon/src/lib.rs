//! Colony Firewall daemon internals.
//!
//! The daemon ships as the `colony-firewalld` binary (`src/main.rs`). This
//! library target exists so the same internals can be assembled by
//! integration tests (`tests/ipc_integration.rs`) - a real `RuleStore`,
//! `Engine`, `PromptRouter` and `ipc::spawn` on a socket in a temp dir -
//! without root and without binding NFQUEUE. `main.rs` is a thin wrapper
//! that wires these modules together exactly as before.
//!
//! This is **not** a stable public API. The modules are `pub` only so the
//! test harness can build the same graph `main` does; nothing outside this
//! crate (and its tests) should depend on it.

pub mod config;
pub mod convert;
pub mod decision;
pub mod dns;
pub mod ipc;
pub mod nfqueue;
pub mod packet;
pub mod process_resolve;
pub mod prompts;
pub mod provenance;
pub mod reject;
pub mod sd_notify;
pub mod sock_diag;
pub mod stats;
pub mod storage;
