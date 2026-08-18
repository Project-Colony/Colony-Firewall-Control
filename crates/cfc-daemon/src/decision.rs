//! Decision engine: maps (Connection, Process) to a Verdict.
//!
//! Hot path. The NFQUEUE worker calls `evaluate()` once per packet of
//! interest. If a rule matches, we return immediately. Otherwise we ask the
//! UI (via `pending_prompts`) and fall back to the configured default policy.

use crate::config::DefaultPolicy;
use cfc_core::{Action, Connection, Process, Rule, RuleSet, Verdict};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;

/// Default policy shared between the decision engine, the prompt router
/// and the SIGHUP reload path in `main`. std `RwLock` (not parking_lot):
/// reads are cheap and uncontended, writes happen only on config reload,
/// and no new dependency is pulled into the hot path.
pub type SharedPolicy = Arc<std::sync::RwLock<DefaultPolicy>>;

#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    rules: RwLock<RuleSet>,
    default_policy: SharedPolicy,
    /// Per-rule hit counter increments. Merged into the persisted
    /// `Rule::hit_count` on snapshot() and periodically flushed.
    hits: Mutex<HashMap<uuid::Uuid, u64>>,
}

pub enum Decision {
    /// A persistent rule matched. Return the verdict immediately.
    Resolved(Verdict),
    /// No rule matched. Caller should prompt the user.
    NeedsPrompt { fallback: Verdict },
}

impl Engine {
    pub fn new(mut rules: RuleSet, default_policy: SharedPolicy) -> Self {
        // Storage iteration order is arbitrary; establish the deterministic
        // precedence order (most-specific first, deny before allow on ties)
        // before the first lookup.
        rules.sort_deterministic();
        Self {
            inner: Arc::new(EngineInner {
                rules: RwLock::new(rules),
                default_policy,
                hits: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Evaluate without blocking. Returns `Resolved` if a rule matches,
    /// otherwise `NeedsPrompt`.
    pub fn evaluate(&self, conn: &Connection, proc: &Process) -> Decision {
        let now_unix_ms = chrono::Utc::now().timestamp_millis();
        let rule_match = {
            let rules = self.inner.rules.read();
            rules
                .lookup(conn, proc, now_unix_ms)
                .map(|r| (r.id, r.action))
        };
        if let Some((rule_id, action)) = rule_match {
            *self.inner.hits.lock().entry(rule_id).or_insert(0) += 1;
            let verdict = match action {
                Action::Allow => Verdict::allow_from_rule(rule_id),
                Action::Deny | Action::Reject => Verdict::deny_from_rule(rule_id),
            };
            return Decision::Resolved(verdict);
        }
        Decision::NeedsPrompt {
            fallback: self.fallback_verdict(),
        }
    }

    /// The verdict applied when no rule matches and prompting is
    /// impossible (no UI connected, prompt channel saturated, unparseable
    /// packet): the configured `no_ui_action`.
    pub fn fallback_verdict(&self) -> Verdict {
        // A poisoned lock can only mean a writer panicked mid-store of a
        // Copy value; recover the value rather than poisoning the packet
        // path.
        let no_ui_action = self
            .inner
            .default_policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .no_ui_action;
        match no_ui_action {
            Action::Allow => Verdict::default_allow(),
            Action::Deny | Action::Reject => Verdict::default_deny(),
        }
    }

    pub fn upsert_rule(&self, rule: Rule) {
        let mut rs = self.inner.rules.write();
        if let Some(existing) = rs.rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule;
        } else {
            rs.rules.push(rule);
        }
        // Re-establish precedence order: the upsert may have changed the
        // rule's scope/action/enabled bit, any of which affect its slot.
        rs.sort_deterministic();
    }

    pub fn remove_rule(&self, id: uuid::Uuid) {
        self.inner.rules.write().rules.retain(|r| r.id != id);
    }

    pub fn snapshot(&self) -> RuleSet {
        let mut rs = self.inner.rules.read().clone();
        let hits = self.inner.hits.lock();
        for rule in &mut rs.rules {
            if let Some(extra) = hits.get(&rule.id) {
                rule.hit_count = rule.hit_count.saturating_add(*extra);
            }
        }
        rs
    }

    /// Returns the live hit deltas accumulated since the last `drain_hits`
    /// (or since startup) and resets them. Used by the periodic flush so
    /// the in-memory deltas get merged into sqlite without double-counting.
    pub fn drain_hits(&self) -> HashMap<uuid::Uuid, u64> {
        std::mem::take(&mut *self.inner.hits.lock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultPolicy;
    use cfc_core::{Direction, Protocol, RuleScope, VerdictSource};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn shared(dp: DefaultPolicy) -> SharedPolicy {
        Arc::new(std::sync::RwLock::new(dp))
    }

    fn dp_allow() -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: Action::Allow,
            timeout_action: Action::Allow,
            prompt_timeout_secs: 15,
        }
    }

    fn dp_deny() -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: Action::Deny,
            timeout_action: Action::Deny,
            prompt_timeout_secs: 10,
        }
    }

    fn conn(dst_port: u16) -> Connection {
        Connection::new(
            Protocol::Tcp,
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            54321,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_port,
        )
    }

    fn proc(exe: &str) -> Process {
        Process {
            pid: 100,
            ppid: Some(1),
            uid: Some(1000),
            gid: Some(1000),
            exe: PathBuf::from(exe),
            cmdline: vec![exe.to_string()],
            cwd: None,
            sha256: None,
            started_at: None,
        }
    }

    fn allow_port_rule(port: u16) -> Rule {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(port);
        Rule::new(format!("allow-{port}"), Action::Allow, scope)
    }

    fn deny_port_rule(port: u16) -> Rule {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(port);
        Rule::new(format!("deny-{port}"), Action::Deny, scope)
    }

    #[test]
    fn no_rules_returns_needs_prompt() {
        let engine = Engine::new(RuleSet::default(), shared(dp_allow()));
        match engine.evaluate(&conn(443), &proc("/usr/bin/curl")) {
            Decision::NeedsPrompt { fallback } => {
                assert_eq!(fallback.action, Action::Allow);
            }
            _ => panic!("expected NeedsPrompt"),
        }
    }

    #[test]
    fn matching_allow_rule_resolves_to_allow() {
        let mut rs = RuleSet::default();
        rs.rules.push(allow_port_rule(443));
        let engine = Engine::new(rs, shared(dp_deny()));
        match engine.evaluate(&conn(443), &proc("/usr/bin/curl")) {
            Decision::Resolved(v) => {
                assert_eq!(v.action, Action::Allow);
                assert!(matches!(v.source, VerdictSource::Rule(_)));
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn matching_deny_rule_resolves_to_deny() {
        let mut rs = RuleSet::default();
        rs.rules.push(deny_port_rule(443));
        let engine = Engine::new(rs, shared(dp_allow()));
        match engine.evaluate(&conn(443), &proc("/usr/bin/curl")) {
            Decision::Resolved(v) => assert_eq!(v.action, Action::Deny),
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn fallback_respects_default_policy_deny() {
        let engine = Engine::new(RuleSet::default(), shared(dp_deny()));
        match engine.evaluate(&conn(443), &proc("/usr/bin/curl")) {
            Decision::NeedsPrompt { fallback } => {
                assert_eq!(fallback.action, Action::Deny);
            }
            _ => panic!("expected NeedsPrompt"),
        }
    }

    #[test]
    fn upsert_rule_takes_effect_immediately() {
        let engine = Engine::new(RuleSet::default(), shared(dp_allow()));
        // No rule -> NeedsPrompt.
        assert!(matches!(
            engine.evaluate(&conn(443), &proc("/usr/bin/curl")),
            Decision::NeedsPrompt { .. }
        ));

        engine.upsert_rule(allow_port_rule(443));

        assert!(matches!(
            engine.evaluate(&conn(443), &proc("/usr/bin/curl")),
            Decision::Resolved(_)
        ));
    }

    #[test]
    fn remove_rule_clears_match() {
        let rule = allow_port_rule(443);
        let id = rule.id;
        let mut rs = RuleSet::default();
        rs.rules.push(rule);
        let engine = Engine::new(rs, shared(dp_allow()));

        assert!(matches!(
            engine.evaluate(&conn(443), &proc("/usr/bin/curl")),
            Decision::Resolved(_)
        ));

        engine.remove_rule(id);
        assert!(matches!(
            engine.evaluate(&conn(443), &proc("/usr/bin/curl")),
            Decision::NeedsPrompt { .. }
        ));
    }

    #[test]
    fn conflicting_rules_resolve_deny_regardless_of_load_order() {
        // allow-443 and deny-443 have equal specificity; the deterministic
        // precedence order must pick deny no matter how storage handed the
        // rules to Engine::new.
        let allow = allow_port_rule(443);
        let deny = deny_port_rule(443);

        for rules in [
            vec![allow.clone(), deny.clone()],
            vec![deny.clone(), allow.clone()],
        ] {
            let engine = Engine::new(RuleSet { rules }, shared(dp_allow()));
            match engine.evaluate(&conn(443), &proc("/usr/bin/curl")) {
                Decision::Resolved(v) => assert_eq!(v.action, Action::Deny),
                _ => panic!("expected Resolved"),
            }
        }
    }

    #[test]
    fn policy_reload_changes_fallback_verdict() {
        // Simulates the SIGHUP path in main: the shared policy is swapped
        // in place and the engine's fallback follows without a rebuild.
        let policy = shared(dp_allow());
        let engine = Engine::new(RuleSet::default(), policy.clone());
        assert_eq!(engine.fallback_verdict().action, Action::Allow);

        *policy.write().unwrap() = dp_deny();
        assert_eq!(engine.fallback_verdict().action, Action::Deny);
        match engine.evaluate(&conn(443), &proc("/usr/bin/curl")) {
            Decision::NeedsPrompt { fallback } => {
                assert_eq!(fallback.action, Action::Deny);
            }
            _ => panic!("expected NeedsPrompt"),
        }
    }

    #[test]
    fn snapshot_clones_rules() {
        let mut rs = RuleSet::default();
        rs.rules.push(allow_port_rule(80));
        rs.rules.push(allow_port_rule(443));
        let engine = Engine::new(rs, shared(dp_allow()));

        let snap = engine.snapshot();
        assert_eq!(snap.rules.len(), 2);

        // Mutating the snapshot must not affect the engine.
        drop(snap);
        assert_eq!(engine.snapshot().rules.len(), 2);
    }
}
