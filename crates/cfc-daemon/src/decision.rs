//! Decision engine: maps (Connection, Process) to a Verdict.
//!
//! Hot path. The NFQUEUE worker calls `evaluate()` once per packet of
//! interest. If a rule matches, we return immediately. Otherwise we ask the
//! UI (via `pending_prompts`) and fall back to the configured default policy.

use crate::config::DefaultPolicy;
use cfc_core::{Action, Connection, Process, Rule, RuleSet, Verdict};
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    rules: RwLock<RuleSet>,
    default_policy: DefaultPolicy,
}

pub enum Decision {
    /// A persistent rule matched. Return the verdict immediately.
    Resolved(Verdict),
    /// No rule matched. Caller should prompt the user.
    NeedsPrompt { fallback: Verdict },
}

impl Engine {
    pub fn new(rules: RuleSet, default_policy: DefaultPolicy) -> Self {
        Self {
            inner: Arc::new(EngineInner {
                rules: RwLock::new(rules),
                default_policy,
            }),
        }
    }

    /// Evaluate without blocking. Returns `Resolved` if a rule matches,
    /// otherwise `NeedsPrompt`.
    pub fn evaluate(&self, conn: &Connection, proc: &Process) -> Decision {
        let rules = self.inner.rules.read();
        if let Some(rule) = rules.lookup(conn, proc) {
            let verdict = match rule.action {
                Action::Allow => Verdict::allow_from_rule(rule.id),
                Action::Deny | Action::Reject => Verdict::deny_from_rule(rule.id),
            };
            return Decision::Resolved(verdict);
        }
        let fallback = match self.inner.default_policy.no_ui_action {
            Action::Allow => Verdict::default_allow(),
            Action::Deny | Action::Reject => Verdict::default_deny(),
        };
        Decision::NeedsPrompt { fallback }
    }

    pub fn upsert_rule(&self, rule: Rule) {
        let mut rs = self.inner.rules.write();
        if let Some(existing) = rs.rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule;
        } else {
            rs.rules.push(rule);
        }
    }

    pub fn remove_rule(&self, id: uuid::Uuid) {
        self.inner.rules.write().rules.retain(|r| r.id != id);
    }

    pub fn snapshot(&self) -> RuleSet {
        self.inner.rules.read().clone()
    }
}
