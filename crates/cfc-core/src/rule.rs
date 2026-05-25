//! Rule: a persisted decision policy that maps Connection -> Verdict.
//!
//! Loosely modeled on opensnitch's rule format, simplified for v0.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Duration {
    Once,
    UntilRestart,
    Always,
    Seconds(u32),
}

/// What this rule matches on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleScope {
    pub exe_path: Option<PathBuf>,
    pub exe_sha256: Option<String>,
    pub parent_exe: Option<PathBuf>,
    pub uid: Option<u32>,
    pub dst_host: Option<String>,
    pub dst_net: Option<IpNet>,
    pub dst_port: Option<u16>,
    pub protocol: Option<crate::Protocol>,
}

impl RuleScope {
    pub fn any() -> Self {
        Self {
            exe_path: None,
            exe_sha256: None,
            parent_exe: None,
            uid: None,
            dst_host: None,
            dst_net: None,
            dst_port: None,
            protocol: None,
        }
    }

    pub fn matches(&self, conn: &crate::Connection, proc: &crate::Process) -> bool {
        if let Some(p) = &self.exe_path {
            if &proc.exe != p {
                return false;
            }
        }
        if let Some(h) = &self.exe_sha256 {
            match &proc.sha256 {
                Some(s) if s == h => {}
                _ => return false,
            }
        }
        if let Some(u) = self.uid {
            if proc.uid != u {
                return false;
            }
        }
        if let Some(h) = &self.dst_host {
            match &conn.dst_host {
                Some(d) if d == h => {}
                _ => return false,
            }
        }
        if let Some(net) = self.dst_net {
            if !net.contains(&conn.dst_ip) {
                return false;
            }
        }
        if let Some(port) = self.dst_port {
            if conn.dst_port != port {
                return false;
            }
        }
        if let Some(proto) = self.protocol {
            if conn.protocol != proto {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: uuid::Uuid,
    pub name: String,
    pub enabled: bool,
    pub action: Action,
    pub duration: Duration,
    pub scope: RuleScope,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub hit_count: u64,
}

impl Rule {
    pub fn new(name: impl Into<String>, action: Action, scope: RuleScope) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            enabled: true,
            action,
            duration: Duration::Always,
            scope,
            created_at: chrono::Utc::now(),
            hit_count: 0,
        }
    }
}

/// In-memory snapshot of all rules; the daemon walks this in priority order.
#[derive(Debug, Default, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn lookup(
        &self,
        conn: &crate::Connection,
        proc: &crate::Process,
    ) -> Option<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.enabled)
            .find(|r| r.scope.matches(conn, proc))
    }
}
