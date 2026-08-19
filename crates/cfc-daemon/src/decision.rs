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
    /// Called after the rule set changes.
    ///
    /// Exists for one caller: the in-kernel verdict map, whose contents are a
    /// *function* of the rules and therefore go stale the moment a rule is
    /// added or removed. Without this, a "Block always" answered from a prompt
    /// would be enforced by the packet path but never reach the kernel for the
    /// process it was about - so killing the daemon would lift the block that
    /// had just been asked for, which is precisely the failure the pinned layer
    /// exists to prevent.
    ///
    /// A plain boxed closure rather than a trait: there is one observer, it
    /// needs no state of its own that the closure cannot capture, and keeping
    /// it a `Weak` capture on the caller's side is what stops the cycle
    /// (the observer holds this `Engine`).
    on_change: RwLock<Option<Box<dyn Fn() + Send + Sync>>>,
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
                on_change: RwLock::new(None),
            }),
        }
    }

    /// Registers the callback invoked after every rule-set change.
    ///
    /// One observer, last writer wins. The callback must not touch this engine
    /// re-entrantly: it runs after the rules lock is dropped, but taking the
    /// write lock again from inside would deadlock a future caller that holds
    /// it.
    pub fn set_on_change(&self, f: Box<dyn Fn() + Send + Sync>) {
        *self.inner.on_change.write() = Some(f);
    }

    fn notify_changed(&self) {
        if let Some(f) = self.inner.on_change.read().as_ref() {
            f();
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

    /// The action that holds for this process no matter where it connects, if
    /// the rules say one does.
    ///
    /// Answers a question the packet path never has to ask: at `exec` time
    /// there is no connection yet, so the only rules that can be applied are
    /// the ones whose answer does not depend on one. The `cgroup/connect4|6`
    /// programs consult the result before a destination has even been chosen.
    ///
    /// Deliberately conservative. Rules are already in precedence order
    /// (most-specific first, deny before allow), and the walk stops at the
    /// *first* rule that could apply to this process:
    ///
    /// * if that rule constrains a destination, there is no process-wide
    ///   answer - a higher-precedence conditional rule would be overridden by
    ///   anything precomputed from a lower one, so the packet path keeps the
    ///   decision;
    /// * otherwise its action is the answer, because nothing above it can
    ///   match and it matches everything below it would have.
    ///
    /// A rule the caller cannot evaluate - see
    /// [`RuleScope::undecidable_for`] - also ends the walk with `None`, for
    /// the same reason: it might have been the one that mattered.
    ///
    /// `None` means "ask the packet path", which is always a safe answer: it
    /// is what happened before this existed.
    pub fn process_wide_action(&self, proc: &Process) -> Option<cfc_core::Action> {
        let now_unix_ms = chrono::Utc::now().timestamp_millis();
        let rules = self.inner.rules.read();
        for rule in rules
            .rules
            .iter()
            .filter(|r| r.enabled && !r.is_expired(now_unix_ms))
        {
            // An inbound rule cannot apply to `connect()`, which is outbound
            // by definition. Skip it rather than abstaining, and the
            // difference is not academic: an inbound rule names a port and a
            // source, never an executable, so `matches_process` says yes to
            // *every* process on the machine. Abstaining on it therefore
            // switched off in-kernel enforcement machine-wide.
            //
            // Measured, because it was not theoretical: with the shipped
            // `inbound` bundle installed, a plain `deny --exe <path>` rule
            // produced no `in-kernel deny installed` for a live matching
            // process, and every refusal came from the userspace packet path.
            // Disabling those four rules made the same test install the
            // kernel verdict immediately.
            if rule.scope.direction == Some(cfc_core::Direction::Inbound) {
                continue;
            }
            if rule.scope.undecidable_for(proc) {
                return None;
            }
            if !rule.scope.matches_process(proc) {
                continue;
            }
            return (!rule.scope.constrains_destination()).then_some(rule.action);
        }
        None
    }

    /// How many rules are loaded, without copying any of them.
    ///
    /// `snapshot()` clones the whole set - every name, every `PathBuf`, every
    /// `Option<String>` in every scope - which is right for `ListRules` and
    /// absurd for `GetStatus`, which wanted `.len()` and was called about
    /// once a second per connected client, forever.
    pub fn rule_count(&self) -> usize {
        self.inner.rules.read().rules.len()
    }

    /// What an inbound flow gets when no rule matches.
    ///
    /// Separate from `no_ui_action` because it answers a different question.
    /// `no_ui_action` is "nobody is there to ask"; this is "we are not asking,
    /// by design". Conflating them would mean a machine that starts prompting
    /// for inbound traffic the moment a GUI connects.
    ///
    /// There is no configuration to make this Allow, and that is deliberate:
    /// the whole point of the inbound chain is that nothing enters without
    /// having been authorised, and an allow-by-default inbound firewall is an
    /// accept-everything chain with extra steps. Authorising is what rules are
    /// for. `Reject` rather than `Deny` is offered because on a LAN an
    /// immediate refusal is kinder than a timeout, but it is still a refusal.
    pub fn inbound_default(&self) -> cfc_core::Action {
        self.inner
            .default_policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .inbound_action
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
        {
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
        // Outside the scope above: the observer re-reads the rules.
        self.notify_changed();
    }

    pub fn remove_rule(&self, id: uuid::Uuid) {
        self.inner.rules.write().rules.retain(|r| r.id != id);
        self.notify_changed();
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
            inbound_action: Action::Deny,
            prompt_timeout_secs: 15,
        }
    }

    fn dp_deny() -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: Action::Deny,
            timeout_action: Action::Deny,
            inbound_action: Action::Deny,
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
            ppid: Some(1),
            uid: Some(1000),
            gid: Some(1000),
            exe: PathBuf::from(exe),
            cmdline: vec![exe.to_string()],
            ..Process::unknown(100)
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

    fn exe_rule(name: &str, exe: &str, action: Action) -> Rule {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from(exe));
        Rule::new(name, action, scope)
    }

    fn engine_with(rules: Vec<Rule>) -> Engine {
        Engine::new(RuleSet { rules }, shared(dp_deny()))
    }

    // --- process_wide_action -------------------------------------------
    //
    // This is what the `cgroup/connect4|6` programs are steered by, and it
    // answers before a destination exists. Every case below is about the same
    // question: when is it safe to precommit an answer the packet path will
    // never get to revise?

    #[test]
    fn an_inbound_rule_does_not_switch_off_in_kernel_enforcement() {
        // The exact shape the shipped `inbound` bundle installs: a port and a
        // protocol, no executable. `matches_process` therefore says yes to
        // every process on the machine, and the rule sorts ahead of a plain
        // exe deny. Counting it as "constrains the destination" - which it
        // does, for the packet path - used to make this abstain, and one such
        // rule was enough to stop every in-kernel verdict being written.
        let mut inbound = RuleScope::any();
        inbound.direction = Some(cfc_core::Direction::Inbound);
        inbound.dst_port = Some(22);
        inbound.protocol = Some(cfc_core::Protocol::Tcp);

        let mut deny = RuleScope::any();
        deny.exe_path = Some(PathBuf::from("/usr/bin/curl"));

        let engine = engine_with(vec![
            Rule::new("inbound-ssh".to_string(), Action::Allow, inbound),
            Rule::new("deny-curl".to_string(), Action::Deny, deny),
        ]);

        assert_eq!(
            engine.process_wide_action(&proc("/usr/bin/curl")),
            Some(Action::Deny),
            "an inbound rule must be skipped by the connect hooks, not abstained on"
        );
    }

    /// ...and skipping it must not turn an inbound rule into an outbound one.
    #[test]
    fn an_inbound_rule_is_never_precommitted_to_the_connect_hooks() {
        let mut inbound = RuleScope::any();
        inbound.direction = Some(cfc_core::Direction::Inbound);
        inbound.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        let engine = engine_with(vec![Rule::new(
            "inbound-deny".to_string(),
            Action::Deny,
            inbound,
        )]);
        assert_eq!(
            engine.process_wide_action(&proc("/usr/bin/curl")),
            None,
            "an inbound deny must never refuse an outbound connect()"
        );
    }

    #[test]
    fn an_unconditional_exe_rule_is_a_process_wide_answer() {
        let engine = engine_with(vec![exe_rule("deny-curl", "/usr/bin/curl", Action::Deny)]);
        assert_eq!(
            engine.process_wide_action(&proc("/usr/bin/curl")),
            Some(Action::Deny)
        );
        assert_eq!(engine.process_wide_action(&proc("/usr/bin/wget")), None);
    }

    #[test]
    fn a_destination_scoped_rule_is_never_a_process_wide_answer() {
        // The rule matches this process, but only for port 443. Precomputing
        // its action would apply it to every destination.
        let engine = engine_with(vec![deny_port_rule(443)]);
        assert_eq!(engine.process_wide_action(&proc("/usr/bin/curl")), None);
    }

    #[test]
    fn a_higher_precedence_conditional_rule_blocks_the_answer() {
        // allow curl -> :443, deny curl everywhere. The deny is *not* the
        // process-wide answer: curl reaching 443 is allowed, and an in-kernel
        // deny would refuse it before the packet path could say so.
        let mut allow_443 = exe_rule("allow-curl-443", "/usr/bin/curl", Action::Allow);
        allow_443.scope.dst_port = Some(443);
        let engine = engine_with(vec![
            allow_443,
            exe_rule("deny-curl", "/usr/bin/curl", Action::Deny),
        ]);
        assert_eq!(engine.process_wide_action(&proc("/usr/bin/curl")), None);
    }

    #[test]
    fn a_conditional_rule_for_another_process_does_not_block_the_answer() {
        // Same shape as above, but the conditional rule names a different
        // binary, so it can be ruled out without a destination.
        let mut allow_443 = exe_rule("allow-wget-443", "/usr/bin/wget", Action::Allow);
        allow_443.scope.dst_port = Some(443);
        let engine = engine_with(vec![
            allow_443,
            exe_rule("deny-curl", "/usr/bin/curl", Action::Deny),
        ]);
        assert_eq!(
            engine.process_wide_action(&proc("/usr/bin/curl")),
            Some(Action::Deny)
        );
    }

    #[test]
    fn an_unhashed_process_gets_no_answer_when_a_hash_rule_could_apply() {
        // The caller is the exec path, which does not hash binaries. Skipping
        // the hash-scoped allow and falling through to the deny below it would
        // install an in-kernel deny that the packet path - which does know the
        // hash - would never have applied.
        let mut allow_hash = exe_rule("allow-known-curl", "/usr/bin/curl", Action::Allow);
        allow_hash.scope.exe_sha256 = Some("abc123".to_string());
        let engine = engine_with(vec![
            allow_hash,
            exe_rule("deny-curl", "/usr/bin/curl", Action::Deny),
        ]);
        assert_eq!(engine.process_wide_action(&proc("/usr/bin/curl")), None);

        // With the hash known, the walk can proceed normally.
        let mut hashed = proc("/usr/bin/curl");
        hashed.sha256 = Some("abc123".to_string());
        assert_eq!(engine.process_wide_action(&hashed), Some(Action::Allow));
    }

    #[test]
    fn a_hash_rule_for_another_binary_does_not_block_the_answer() {
        let mut allow_hash = exe_rule("allow-known-wget", "/usr/bin/wget", Action::Allow);
        allow_hash.scope.exe_sha256 = Some("abc123".to_string());
        let engine = engine_with(vec![
            allow_hash,
            exe_rule("deny-curl", "/usr/bin/curl", Action::Deny),
        ]);
        assert_eq!(
            engine.process_wide_action(&proc("/usr/bin/curl")),
            Some(Action::Deny)
        );
    }

    #[test]
    fn a_disabled_or_expired_rule_is_not_a_process_wide_answer() {
        let mut disabled = exe_rule("deny-curl", "/usr/bin/curl", Action::Deny);
        disabled.enabled = false;
        assert_eq!(
            engine_with(vec![disabled]).process_wide_action(&proc("/usr/bin/curl")),
            None
        );

        let mut expired = exe_rule("deny-curl", "/usr/bin/curl", Action::Deny);
        expired.duration = cfc_core::Duration::Seconds(1);
        expired.created_at = chrono::Utc::now() - chrono::Duration::hours(1);
        assert_eq!(
            engine_with(vec![expired]).process_wide_action(&proc("/usr/bin/curl")),
            None
        );
    }

    #[test]
    fn no_rules_at_all_means_ask_the_packet_path() {
        // Never the default policy: `no_ui_action` is what the *prompt* path
        // falls back to after asking, and precommitting it here would refuse
        // every process on a Deny profile before a prompt could ever be shown.
        assert_eq!(
            engine_with(vec![]).process_wide_action(&proc("/usr/bin/curl")),
            None
        );
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
            inbound_action: Action::Deny,
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
