//! Decision engine: maps (Connection, Process) to a Verdict.
//!
//! Hot path. The NFQUEUE worker calls `evaluate()` once per packet of
//! interest. If a rule matches, we return immediately. Otherwise we ask the
//! UI (via `pending_prompts`) and fall back to the configured default policy.

use crate::config::DefaultPolicy;
use cfc_core::{Connection, Process, Rule, RuleSet, Verdict};
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
            // Verbatim: a Reject rule must reach the datapath as Reject so
            // the refusal is actually injected, not silently downgraded.
            return Decision::Resolved(Verdict::from_rule(action, rule_id));
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
        Verdict::from_policy(no_ui_action)
    }

    /// Restores the fields the daemon owns onto an incoming rule.
    ///
    /// `hit_count` and `created_at` are daemon state, not something a
    /// client gets to set on an existing rule. Every client does a
    /// read-modify-write (the GUI's edit and enable/disable buttons, `cfc
    /// rules enable|disable`, `cfc rules import`), and what it read back
    /// was the persisted count *plus* the not-yet-flushed delta. Echoing
    /// that in the upsert stored the delta, while the delta itself stayed
    /// pending and got added again at the next flush — so every toggle
    /// inflated the count. Taking the daemon's own values makes the
    /// round-trip lossless no matter what the client sends.
    ///
    /// A rule id the daemon does not know is left untouched: it is a new
    /// rule, and `convert::rule_from_pb` stamps its creation time.
    pub fn preserve_server_owned(&self, rule: &mut Rule) {
        let rules = self.inner.rules.read();
        if let Some(existing) = rules.rules.iter().find(|r| r.id == rule.id) {
            rule.hit_count = existing.hit_count;
            rule.created_at = existing.created_at;
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

    /// The rule set as callers should see it: persisted counts plus the
    /// deltas not yet flushed. Lock order is rules-then-hits everywhere
    /// (see `drain_hits`).
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
    ///
    /// The deltas are also folded into the in-memory rules on the way out.
    /// Without that, draining would make `snapshot` (and therefore
    /// ListRules) fall back to the counts loaded at startup plus only the
    /// deltas since the last flush - so every 30s flush would visibly reset
    /// the hit counts in the UI even though sqlite had them all along.
    ///
    /// Takes `rules` before `hits`, matching `snapshot`, so the two can
    /// never deadlock against each other.
    pub fn drain_hits(&self) -> HashMap<uuid::Uuid, u64> {
        let mut rules = self.inner.rules.write();
        let deltas = std::mem::take(&mut *self.inner.hits.lock());
        for rule in &mut rules.rules {
            if let Some(extra) = deltas.get(&rule.id) {
                rule.hit_count = rule.hit_count.saturating_add(*extra);
            }
        }
        deltas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultPolicy;
    use cfc_core::Action;
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
    fn reject_rule_stays_reject() {
        // Deny and Reject both drop the packet, but only Reject injects a
        // RST/ICMP refusal in the worker. If the engine downgraded Reject
        // to Deny here, every persisted Reject rule would silently behave
        // as Deny and the injection would only ever fire for prompts.
        let mut scope = RuleScope::any();
        scope.dst_port = Some(443);
        let rule = Rule::new("reject-443", Action::Reject, scope);
        let rule_id = rule.id;
        let mut rs = RuleSet::default();
        rs.rules.push(rule);
        let engine = Engine::new(rs, shared(dp_allow()));

        match engine.evaluate(&conn(443), &proc("/usr/bin/curl")) {
            Decision::Resolved(v) => {
                assert_eq!(v.action, Action::Reject);
                assert_eq!(v.source, VerdictSource::Rule(rule_id));
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn reject_default_policy_stays_reject() {
        let policy = DefaultPolicy {
            no_ui_action: Action::Reject,
            timeout_action: Action::Reject,
            prompt_timeout_secs: 15,
        };
        let engine = Engine::new(RuleSet::default(), shared(policy));

        let fallback = engine.fallback_verdict();
        assert_eq!(fallback.action, Action::Reject);
        assert_eq!(fallback.source, VerdictSource::DefaultPolicy);
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

    #[test]
    fn upsert_cannot_inflate_the_hit_count_of_an_existing_rule() {
        // Every client does a read-modify-write: it reads a rule (count =
        // persisted + unflushed delta), flips a field, sends it back. If
        // the daemon stored that echoed count, the delta would land twice
        // -- once now, once at the next flush.
        let rule = allow_port_rule(443);
        let id = rule.id;
        let mut rs = RuleSet::default();
        rs.rules.push(rule);
        let engine = Engine::new(rs, shared(dp_allow()));

        engine.evaluate(&conn(443), &proc("/usr/bin/curl"));
        engine.evaluate(&conn(443), &proc("/usr/bin/curl"));

        // What a client would read back, then echo in an upsert.
        let mut echoed = engine.snapshot().rules[0].clone();
        assert_eq!(echoed.hit_count, 2);
        echoed.enabled = false;
        let forged_created_at = echoed.created_at;

        engine.preserve_server_owned(&mut echoed);
        assert_eq!(
            echoed.hit_count, 0,
            "the delta is still pending, not stored"
        );
        assert_eq!(echoed.created_at, forged_created_at);
        engine.upsert_rule(echoed);

        // The toggle applied, and the two hits are still counted exactly once.
        let deltas = engine.drain_hits();
        assert_eq!(deltas.get(&id).copied().unwrap_or(0), 2);
        assert_eq!(engine.snapshot().rules[0].hit_count, 2);
        assert!(!engine.snapshot().rules[0].enabled);
    }

    #[test]
    fn preserve_server_owned_leaves_an_unknown_rule_alone() {
        let engine = Engine::new(RuleSet::default(), shared(dp_allow()));
        let mut fresh = allow_port_rule(80);
        let before = fresh.clone();
        engine.preserve_server_owned(&mut fresh);
        assert_eq!(fresh.created_at, before.created_at);
        assert_eq!(fresh.hit_count, before.hit_count);
    }

    #[test]
    fn draining_hits_does_not_reset_the_reported_count() {
        // The periodic flush drains deltas into sqlite. If draining did not
        // also fold them into the in-memory rules, ListRules would drop
        // back to the startup count every 30 seconds.
        let mut rs = RuleSet::default();
        rs.rules.push(allow_port_rule(443));
        let engine = Engine::new(rs, shared(dp_allow()));

        engine.evaluate(&conn(443), &proc("/usr/bin/curl"));
        engine.evaluate(&conn(443), &proc("/usr/bin/curl"));
        assert_eq!(engine.snapshot().rules[0].hit_count, 2);

        let deltas = engine.drain_hits();
        assert_eq!(deltas.values().sum::<u64>(), 2, "deltas go to storage");
        assert_eq!(
            engine.snapshot().rules[0].hit_count,
            2,
            "and stay visible after the flush"
        );

        engine.evaluate(&conn(443), &proc("/usr/bin/curl"));
        assert_eq!(engine.snapshot().rules[0].hit_count, 3);
        // A second drain must not re-report what storage already merged.
        assert_eq!(engine.drain_hits().values().sum::<u64>(), 1);
    }
}
