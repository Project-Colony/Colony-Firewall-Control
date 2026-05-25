//! Verdict: the decision returned to the kernel for a Connection.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictSource {
    /// Matched an existing persistent rule.
    Rule(uuid::Uuid),
    /// User answered a live prompt.
    UserPrompt,
    /// Default policy applied (no rule, no UI available).
    DefaultPolicy,
    /// Daemon couldn't resolve in time and fell back.
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub action: crate::Action,
    pub source: VerdictSource,
}

impl Verdict {
    pub fn allow_from_rule(rule_id: uuid::Uuid) -> Self {
        Self {
            action: crate::Action::Allow,
            source: VerdictSource::Rule(rule_id),
        }
    }

    pub fn deny_from_rule(rule_id: uuid::Uuid) -> Self {
        Self {
            action: crate::Action::Deny,
            source: VerdictSource::Rule(rule_id),
        }
    }

    pub fn default_allow() -> Self {
        Self {
            action: crate::Action::Allow,
            source: VerdictSource::DefaultPolicy,
        }
    }

    pub fn default_deny() -> Self {
        Self {
            action: crate::Action::Deny,
            source: VerdictSource::DefaultPolicy,
        }
    }
}
