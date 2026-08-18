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
    /// Carries a rule's action through verbatim.
    ///
    /// Deny and Reject must stay distinct all the way to the datapath:
    /// both drop the packet, but Reject additionally injects a TCP RST or
    /// ICMP unreachable so the application fails fast. Collapsing them
    /// here would silently turn every persisted Reject rule into a Deny.
    pub fn from_rule(action: crate::Action, rule_id: uuid::Uuid) -> Self {
        Self {
            action,
            source: VerdictSource::Rule(rule_id),
        }
    }

    pub fn allow_from_rule(rule_id: uuid::Uuid) -> Self {
        Self::from_rule(crate::Action::Allow, rule_id)
    }

    pub fn deny_from_rule(rule_id: uuid::Uuid) -> Self {
        Self::from_rule(crate::Action::Deny, rule_id)
    }

    /// Carries a default-policy action through verbatim, for the same
    /// reason as [`Verdict::from_rule`]: a policy of `reject` configured in
    /// `daemon.toml` must actually reject.
    pub fn from_policy(action: crate::Action) -> Self {
        Self {
            action,
            source: VerdictSource::DefaultPolicy,
        }
    }

    pub fn default_allow() -> Self {
        Self::from_policy(crate::Action::Allow)
    }

    pub fn default_deny() -> Self {
        Self::from_policy(crate::Action::Deny)
    }
}
