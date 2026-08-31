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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Duration {
    Once,
    UntilRestart,
    #[default]
    Always,
    Seconds(u32),
}

/// What this rule matches on.
///
/// Every predicate is optional; `#[serde(default)]` on each field keeps old
/// readers compatible with scopes serialized by newer versions that add
/// fields (unknown fields are ignored, missing fields fall back to `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleScope {
    /// Which way the flow goes. `None` means **outbound**, not both.
    ///
    /// Load-bearing for inbound rules, and the reason `src_net`/`src_port`
    /// exist below: `dst_*` is the packet's destination, so it means the remote
    /// peer outbound and **this machine** inbound. A rule that does not say
    /// which direction it is about therefore means different things to the two
    /// hooks. Outbound-only rules can leave it unset - that was every rule
    /// before inbound filtering existed, and they keep working.
    #[serde(default)]
    pub direction: Option<crate::Direction>,
    #[serde(default)]
    pub exe_path: Option<PathBuf>,
    #[serde(default)]
    pub exe_sha256: Option<String>,
    #[serde(default)]
    pub parent_exe: Option<PathBuf>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub dst_host: Option<String>,
    #[serde(default)]
    pub dst_net: Option<IpNet>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    /// The packet's *source* network: the remote peer on an inbound flow, this
    /// machine on an outbound one.
    ///
    /// Exists because `dst_net` cannot express "who may reach us" - inbound,
    /// the destination is always this host. `reject_inbound_destination_scope`
    /// turns the mistake into an error rather than a rule that quietly matches
    /// nothing.
    #[serde(default)]
    pub src_net: Option<IpNet>,
    /// The packet's source port. Rarely useful outbound (it is ephemeral);
    /// inbound it is the port the peer is calling from.
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<crate::Protocol>,
}

/// Largest executable either side will hash for an `exe_sha256` predicate.
///
/// One constant, two enforcers, and they must agree: the daemon refuses to
/// hash a running image past this (a hash-scoped rule then abstains and the
/// packet path decides), and the CLI's `--pin-hash` refuses to *create* a
/// rule past it - otherwise the CLI could happily pin a digest the daemon
/// will never compute, producing a rule that lists, ranks, and never fires.
/// The two copies lived in their own crates for a while with a keep-in-step
/// comment doing the work of a type system; this is the constant that
/// comment described.
pub const SHA256_MAX_LEN: u64 = 64 * 1024 * 1024;

/// Canonical form of an `exe_sha256` predicate: 64 lowercase hex characters.
///
/// The daemon computes digests in lowercase hex and matches by exact string
/// equality, so a rule carrying `ABCD…`, whitespace, or a truncated digest
/// would list, rank, and never fire - indistinguishable from working. Every
/// door a digest can enter through (the wire, `rules import`, `--sha256`)
/// funnels through this instead of trusting its caller's casing.
///
/// Two error shapes on purpose: "wrong length" and "right length, wrong
/// character" are different mistakes, and a message that says "must be 64
/// hexadecimal characters; got 64 of them" helps nobody.
pub fn canonical_exe_sha256(hex: &str) -> Result<String, String> {
    let hex = hex.trim().to_ascii_lowercase();
    if hex.len() != 64 {
        return Err(format!(
            "exe_sha256 must be 64 hexadecimal characters; got {}",
            hex.len()
        ));
    }
    if let Some(bad) = hex.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("exe_sha256 must be hexadecimal; `{bad}` is not"));
    }
    Ok(hex)
}

impl RuleScope {
    pub fn any() -> Self {
        Self {
            direction: None,
            src_net: None,
            src_port: None,
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

    /// Number of populated (`Some`) predicates. Higher means more specific;
    /// [`RuleSet::sort_deterministic`] orders more-specific rules first.
    ///
    /// `direction` is deliberately not counted. An unset direction already
    /// means outbound in `matches` (`None` and `Some(Outbound)` accept the
    /// same flows), so counting it made two spellings of the same rule rank
    /// differently - the explicit one outranked the implicit one at the
    /// closed-wins tie-break while narrowing nothing. And a flow only ever
    /// competes against rules of its own direction, so the predicate can
    /// never distinguish two candidates. A side effect that is also correct:
    /// a scope constraining *only* the direction now counts as constraining
    /// nothing, and `reject_unscoped` refuses it - "allow every inbound flow
    /// from anyone" was never a rule this store should hold.
    pub fn specificity(&self) -> u8 {
        [
            self.src_net.is_some(),
            self.src_port.is_some(),
            self.exe_path.is_some(),
            self.exe_sha256.is_some(),
            self.parent_exe.is_some(),
            self.uid.is_some(),
            self.dst_host.is_some(),
            self.dst_net.is_some(),
            self.dst_port.is_some(),
            self.protocol.is_some(),
        ]
        .into_iter()
        .filter(|set| *set)
        .count() as u8
    }

    /// True when this scope says anything at all about *where* a connection
    /// goes.
    ///
    /// A scope that does not is one whose answer is the same for every
    /// destination, which is what makes it safe to precompute - see
    /// `Engine::process_wide_action` and the `cgroup/connect4|6` programs,
    /// which decide before a destination has been chosen.
    pub fn constrains_destination(&self) -> bool {
        self.dst_host.is_some()
            || self.dst_net.is_some()
            || self.dst_port.is_some()
            || self.protocol.is_some()
            // Source predicates are destination-shaped for this purpose: they
            // describe the flow, not the process, so they cannot be answered
            // at exec time either.
            || self.src_net.is_some()
            || self.src_port.is_some()
            // And an inbound-scoped rule must never reach the connect hooks at
            // all: `cgroup/connect4|6` fire on outbound connect() by
            // definition, so precomputing an inbound deny there would refuse
            // the wrong traffic entirely.
            || self.direction == Some(crate::Direction::Inbound)
    }

    /// Refuse a scope carrying `parent_exe`.
    ///
    /// The field exists, `specificity` counts it, and `matches_process` never
    /// compares it - so a rule scoped on it matches **every** process
    /// regardless of its parent, while sorting ahead of rules that are
    /// genuinely narrower. "Deny whatever bash launched" would deny
    /// everything, and the extra predicate is what pushes it to the front.
    ///
    /// Honouring it means resolving the parent's executable at match time,
    /// which `Process` cannot do today: it carries `ppid`, not the parent's
    /// path. Until it can, accepting the predicate is a fail-open dressed as a
    /// narrowing, so it is refused instead.
    ///
    /// Nothing creates one - there is no CLI flag and no UI path - but the
    /// proto API and `cfc rules import` both take the field, which is exactly
    /// how the `<unknown>` rule got onto a real machine.
    pub fn reject_unmatchable_parent(&self) -> Result<(), String> {
        let Some(parent) = &self.parent_exe else {
            return Ok(());
        };
        Err(format!(
            "cannot scope a rule on parent_exe ({}): the predicate is not \
             evaluated, so the rule would match every process rather than the \
             ones launched by it - and it would outrank narrower rules while \
             doing so. Scope on the executable itself.",
            parent.display()
        ))
    }

    /// Refuse a scope whose `exe_path` is not an absolute path.
    ///
    /// Rules match on absolute executable paths, so a relative one can never
    /// fire - and one specific non-absolute value is worse than useless. The
    /// prompt path renders an unidentified program as [`crate::UNKNOWN_EXE`],
    /// and answering "always allow" for such a flow used to write that string
    /// into `exe_path`. The result read as "allow this one program" and
    /// behaved as "allow everything I cannot identify".
    ///
    /// The matcher no longer honours it either, so this is the second of two
    /// locks: one stops the rule being written, one stops it mattering if an
    /// older database already holds it.
    pub fn reject_unmatchable_exe(&self) -> Result<(), String> {
        let Some(exe) = &self.exe_path else {
            return Ok(());
        };
        if exe.as_os_str() == crate::UNKNOWN_EXE {
            return Err(format!(
                "cannot scope a rule to {}: that is what this program shows \
                 when it could not identify the process, not a path. Such a \
                 rule would match every flow that cannot be attributed, which \
                 is every inbound flow. Scope it to a real executable, or use \
                 a port and source instead.",
                crate::UNKNOWN_EXE
            ));
        }
        if !exe.is_absolute() {
            return Err(format!(
                "exe path {} is not absolute; rules match on absolute \
                 executable paths, so a relative one can never fire",
                exe.display()
            ));
        }
        Ok(())
    }

    /// Rejects an inbound scope that constrains the packet's *destination*.
    ///
    /// Inbound, the destination is this machine: `dst_net` matches one of our
    /// own addresses and `dst_host` a name for ourselves. Someone writing
    /// `--direction in --dst-net 203.0.113.0/24` means "from that network" and
    /// gets a rule that matches nothing - the exact shape of failure this
    /// project spent a day removing elsewhere, where a rule reads like policy
    /// and enforces something else.
    ///
    /// `dst_port` is deliberately *not* rejected: inbound it is our listening
    /// port, which is the most useful inbound predicate there is
    /// (`--direction in --dst-port 22`).
    pub fn reject_inbound_destination_scope(&self) -> Result<(), String> {
        if self.direction != Some(crate::Direction::Inbound) {
            return Ok(());
        }
        let offender = if self.dst_net.is_some() {
            "dst_net"
        } else if self.dst_host.is_some() {
            "dst_host"
        } else {
            return Ok(());
        };
        Err(format!(
            "an inbound rule cannot be scoped on {offender}: inbound, the \
             destination is this machine. To restrict which peers may reach \
             you, use src_net. To restrict which of your ports they may \
             reach, use dst_port."
        ))
    }

    /// Rejects an inbound scope that names a program.
    ///
    /// Inbound flows are never attributed to a process: the daemon's resolver
    /// refuses to even try (see nfqueue - "an inbound flow must not pay for
    /// socket attribution", enforced by a test). A rule with `direction: in`
    /// and an `exe_path` or
    /// `exe_sha256` therefore lists, ranks, and never fires - the worst
    /// failure a rule can have, because it is indistinguishable from working.
    /// An allow written that way admits nothing, and its author, watching the
    /// port stay closed, widens it - which is how a scoped rule becomes an
    /// unscoped one. Refused at every door instead: here for the daemon, and
    /// in the CLI with messages that name the flags.
    pub fn reject_unattributable_inbound_scope(&self) -> Result<(), String> {
        if self.direction != Some(crate::Direction::Inbound) {
            return Ok(());
        }
        let offender = if self.exe_path.is_some() {
            "an executable path"
        } else if self.exe_sha256.is_some() {
            "an executable hash"
        } else {
            return Ok(());
        };
        Err(format!(
            "an inbound rule cannot be scoped on {offender}: inbound flows \
             cannot be attributed to a program, so the rule would never fire. \
             Scope inbound rules on src_net and dst_port instead."
        ))
    }

    /// True when this scope cannot be evaluated against `proc` because the
    /// process's identity is only partly known.
    ///
    /// Exactly one predicate can be in that position: `exe_sha256`. Hashing a
    /// binary is not something the `exec` path does - it costs a full read of
    /// the file - so a caller deciding at exec time has `proc.sha256 == None`
    /// and genuinely cannot say whether a hash-scoped rule applies.
    ///
    /// Treating "cannot say" as "does not match" would be a real bug rather
    /// than a rounding error: precedence is ordered, so silently skipping a
    /// hash-scoped *allow* would hand the decision to a lower-precedence
    /// *deny* that the packet path - which does know the hash - would never
    /// have applied.
    ///
    /// Scopes already excluded by something knowable are decidable: a missing
    /// hash does not matter for a rule whose `exe_path` names a different
    /// binary.
    pub fn undecidable_for(&self, proc: &crate::Process) -> bool {
        if self.exe_sha256.is_none() || proc.sha256.is_some() {
            return false;
        }
        if let Some(p) = &self.exe_path {
            // An unidentified process satisfies no exe-scoped rule. Comparing
            // the placeholder as if it were a path made a single rule match
            // every unattributable flow - and inbound flows are always
            // unattributable, so it silently admitted all of them.
            if !proc.exe_is_known() || &proc.exe != p {
                return false;
            }
        }
        if let Some(u) = self.uid {
            if proc.uid != Some(u) {
                return false;
            }
        }
        true
    }

    /// The process half of [`Self::matches`], on its own.
    ///
    /// Split out so a caller that has a process but no connection can ask
    /// "could this rule ever apply here?". [`Self::matches`] is defined in
    /// terms of it, so the two cannot drift.
    pub fn matches_process(&self, proc: &crate::Process) -> bool {
        if let Some(p) = &self.exe_path {
            // An unidentified process satisfies no exe-scoped rule. Comparing
            // the placeholder as if it were a path made a single rule match
            // every unattributable flow - and inbound flows are always
            // unattributable, so it silently admitted all of them.
            if !proc.exe_is_known() || &proc.exe != p {
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
            // An unattributed process (`Process::unknown`, uid = None) never
            // matches a uid-scoped rule; we must not treat "unknown" as any
            // concrete uid (least of all root's uid 0).
            if proc.uid != Some(u) {
                return false;
            }
        }
        true
    }

    pub fn matches(&self, conn: &crate::Connection, proc: &crate::Process) -> bool {
        if !self.matches_process(proc) {
            return false;
        }
        // First, because it is the cheapest and the most likely to exclude:
        // an inbound rule must never fire on outbound traffic or the reverse.
        // An unset direction means **outbound**, not "both".
        //
        // It reads like a widening and it is the opposite. Every rule written
        // before inbound filtering existed left this unset, and every one of
        // them was written about traffic leaving this machine. Treating unset
        // as "both" silently reinterpreted all of them the day the input chain
        // was enabled: `allow --protocol tcp --dst-port 8080` with no exe stops
        // meaning "this machine may reach 8080 anywhere" and starts also
        // meaning "anyone may reach 8080 here", because inbound `dst_port` is
        // *our* port.
        //
        // So unset keeps the meaning it always had, and admitting traffic needs
        // `--direction in` - which is how the CLI, the bundles and the docs
        // already describe it. Nothing that was written can change meaning
        // under its author.
        match self.direction {
            Some(d) if conn.direction != d => return false,
            None if conn.direction != crate::Direction::Outbound => return false,
            _ => {}
        }
        if let Some(net) = self.src_net {
            if !net.contains(&conn.src_ip) {
                return false;
            }
        }
        if let Some(port) = self.src_port {
            if conn.src_port != port {
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

/// A persisted rule.
///
/// Serde contract: `id`, `name`, `action`, `scope`, and `created_at` are
/// required; `enabled` (true), `duration` (`Always`), and `hit_count` (0)
/// default when absent so older snapshots keep parsing after fields grow
/// defaults. Unknown fields are ignored (no `deny_unknown_fields`), so newer
/// writers do not break older readers. Frozen v0.1.0 wire-format fixtures
/// live in `crates/cfc-core/testdata/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: uuid::Uuid,
    pub name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub action: Action,
    #[serde(default)]
    pub duration: Duration,
    pub scope: RuleScope,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub hit_count: u64,
}

fn default_enabled() -> bool {
    true
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

    /// True when this rule should no longer match at `now_unix_ms`.
    ///
    /// Only `Duration::Seconds(n)` expires here: the rule stops matching once
    /// `created_at + n` seconds have elapsed. `Always` and `UntilRestart`
    /// never expire at lookup time (`UntilRestart` rules are purged from
    /// storage at daemon startup instead). `Once` also returns false: real
    /// once-semantics need per-hit tracking, so the ipc layer will reject
    /// persisting `Once` rules in a later wave rather than pretending they
    /// expire here.
    ///
    /// Public so storage can also use it to purge expired rows.
    pub fn is_expired(&self, now_unix_ms: i64) -> bool {
        match self.duration {
            Duration::Seconds(n) => {
                self.created_at.timestamp_millis() + (n as i64) * 1000 <= now_unix_ms
            }
            Duration::Once | Duration::UntilRestart | Duration::Always => false,
        }
    }
}

/// In-memory snapshot of all rules; the daemon walks this in priority order.
///
/// Priority order is established by [`RuleSet::sort_deterministic`], which
/// must be re-run after any insert, replace, or enable/disable toggle.
#[derive(Debug, Default, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

/// Lower rank = evaluated first on specificity ties: restrictive actions
/// (Deny, then Reject) beat Allow so a conflict resolves closed, not open.
fn action_rank(action: Action) -> u8 {
    match action {
        Action::Deny => 0,
        Action::Reject => 1,
        Action::Allow => 2,
    }
}

impl RuleSet {
    /// Sort rules into deterministic precedence order:
    ///
    /// 1. specificity DESC — more `Some(..)` scope predicates first;
    /// 2. action severity — Deny, then Reject, before Allow on ties;
    /// 3. `created_at` ASC — oldest rule first;
    /// 4. `id` ASC — final total-order tiebreak.
    ///
    /// Must be called whenever the set is (re)built or a rule is inserted,
    /// replaced, or toggled, so `lookup`'s first-match walk is stable across
    /// daemon restarts regardless of storage iteration order.
    pub fn sort_deterministic(&mut self) {
        self.rules.sort_by_key(|r| {
            (
                std::cmp::Reverse(r.scope.specificity()),
                action_rank(r.action),
                r.created_at,
                r.id,
            )
        });
    }

    /// Find the winning enabled, non-expired rule for `(conn, proc)`.
    ///
    /// Precedence contract: most-specific scope wins; deny beats allow at
    /// equal specificity; oldest rule first on remaining ties. This holds
    /// because the set is kept in [`RuleSet::sort_deterministic`] order and
    /// `lookup` returns the first match of that walk.
    ///
    /// `now_unix_ms` is the current wall-clock time; rules whose
    /// `Duration::Seconds(..)` window has elapsed are skipped (see
    /// [`Rule::is_expired`]).
    pub fn lookup(
        &self,
        conn: &crate::Connection,
        proc: &crate::Process,
        now_unix_ms: i64,
    ) -> Option<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.enabled && !r.is_expired(now_unix_ms))
            .find(|r| r.scope.matches(conn, proc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Connection, Direction, Process, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn mk_conn() -> Connection {
        Connection::new(
            Protocol::Tcp,
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            54321,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            443,
        )
    }

    fn mk_proc(exe: &str) -> Process {
        Process {
            ppid: Some(1),
            uid: Some(1000),
            gid: Some(1000),
            exe: PathBuf::from(exe),
            cmdline: vec![exe.to_string()],
            ..Process::unknown(100)
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    #[test]
    fn empty_set_returns_none() {
        let set = RuleSet::default();
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");
        assert!(set.lookup(&conn, &proc, now()).is_none());
    }

    #[test]
    fn matches_by_exe_only() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        let rule = Rule::new("curl", Action::Allow, scope);

        let set = RuleSet {
            rules: vec![rule.clone()],
        };
        let conn = mk_conn();

        assert!(set
            .lookup(&conn, &mk_proc("/usr/bin/curl"), now())
            .is_some());
        assert!(set
            .lookup(&conn, &mk_proc("/usr/bin/wget"), now())
            .is_none());
    }

    #[test]
    fn matches_by_dst_port_only() {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(443);
        let rule = Rule::new("https", Action::Allow, scope);

        let set = RuleSet { rules: vec![rule] };
        let proc = mk_proc("/usr/bin/curl");
        let mut conn = mk_conn();

        assert!(set.lookup(&conn, &proc, now()).is_some());
        conn.dst_port = 80;
        assert!(set.lookup(&conn, &proc, now()).is_none());
    }

    #[test]
    fn matches_by_cidr() {
        let mut scope = RuleScope::any();
        scope.dst_net = Some("10.0.0.0/8".parse().unwrap());
        let rule = Rule::new("rfc1918-10", Action::Deny, scope);

        let set = RuleSet { rules: vec![rule] };
        let proc = mk_proc("/usr/bin/curl");
        let mut conn = mk_conn();

        conn.dst_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(set.lookup(&conn, &proc, now()).is_some());

        conn.dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(set.lookup(&conn, &proc, now()).is_none());
    }

    #[test]
    fn multiple_predicates_must_all_match() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        scope.dst_port = Some(443);
        scope.protocol = Some(Protocol::Tcp);
        let rule = Rule::new("curl-https-tcp", Action::Allow, scope);

        let set = RuleSet { rules: vec![rule] };
        let proc = mk_proc("/usr/bin/curl");

        // All three match -> hit.
        let mut conn = mk_conn();
        assert!(set.lookup(&conn, &proc, now()).is_some());

        // Wrong port -> miss.
        conn.dst_port = 80;
        assert!(set.lookup(&conn, &proc, now()).is_none());

        // Wrong proto -> miss.
        conn.dst_port = 443;
        conn.protocol = Protocol::Udp;
        assert!(set.lookup(&conn, &proc, now()).is_none());

        // Wrong exe -> miss.
        conn.protocol = Protocol::Tcp;
        assert!(set
            .lookup(&conn, &mk_proc("/usr/bin/python"), now())
            .is_none());
    }

    #[test]
    fn disabled_rules_skipped() {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(443);
        let mut rule = Rule::new("https", Action::Allow, scope);
        rule.enabled = false;

        let set = RuleSet { rules: vec![rule] };
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");
        assert!(set.lookup(&conn, &proc, now()).is_none());
    }

    /// Was `first_matching_rule_wins`, which codified whatever Vec order the
    /// set happened to be built in (allow-443 beat deny-curl only because it
    /// was pushed first). Under the deterministic precedence contract both
    /// rules have specificity 1, so the tie breaks on action severity and
    /// deny-curl must win.
    #[test]
    fn deny_beats_allow_at_equal_specificity() {
        let mut scope_a = RuleScope::any();
        scope_a.dst_port = Some(443);
        let allow = Rule::new("allow-https", Action::Allow, scope_a);

        let mut scope_b = RuleScope::any();
        scope_b.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        let deny = Rule::new("deny-curl", Action::Deny, scope_b);

        assert_eq!(allow.scope.specificity(), 1);
        assert_eq!(deny.scope.specificity(), 1);

        let mut set = RuleSet {
            rules: vec![allow, deny],
        };
        set.sort_deterministic();
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");

        let hit = set.lookup(&conn, &proc, now()).expect("should match");
        assert_eq!(hit.action, Action::Deny);
        assert_eq!(hit.name, "deny-curl");
    }

    #[test]
    fn more_specific_rule_wins_regardless_of_action() {
        // Specificity 2 allow beats specificity 1 deny: specificity is the
        // primary key, severity only breaks ties.
        let mut broad = RuleScope::any();
        broad.dst_port = Some(443);
        let deny = Rule::new("deny-443", Action::Deny, broad);

        let mut narrow = RuleScope::any();
        narrow.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        narrow.dst_port = Some(443);
        let allow = Rule::new("allow-curl-443", Action::Allow, narrow);

        let mut set = RuleSet {
            rules: vec![deny, allow],
        };
        set.sort_deterministic();
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");

        let hit = set.lookup(&conn, &proc, now()).expect("should match");
        assert_eq!(hit.name, "allow-curl-443");
        assert_eq!(hit.action, Action::Allow);
    }

    #[test]
    fn lookup_result_independent_of_insertion_order() {
        let mut scope_a = RuleScope::any();
        scope_a.dst_port = Some(443);
        let allow = Rule::new("allow-https", Action::Allow, scope_a);

        let mut scope_b = RuleScope::any();
        scope_b.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        let deny = Rule::new("deny-curl", Action::Deny, scope_b);

        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");
        let at = now();

        let mut forward = RuleSet {
            rules: vec![allow.clone(), deny.clone()],
        };
        forward.sort_deterministic();
        let mut reverse = RuleSet {
            rules: vec![deny, allow],
        };
        reverse.sort_deterministic();

        let hit_fwd = forward.lookup(&conn, &proc, at).expect("should match");
        let hit_rev = reverse.lookup(&conn, &proc, at).expect("should match");
        assert_eq!(hit_fwd.id, hit_rev.id);
        assert_eq!(hit_fwd.name, "deny-curl");
    }

    #[test]
    fn equal_specificity_and_action_oldest_wins() {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(443);

        let mut old = Rule::new("old-allow", Action::Allow, scope.clone());
        old.created_at = chrono::DateTime::from_timestamp_millis(1_000).unwrap();
        let mut new = Rule::new("new-allow", Action::Allow, scope);
        new.created_at = chrono::DateTime::from_timestamp_millis(2_000).unwrap();

        let mut set = RuleSet {
            rules: vec![new, old],
        };
        set.sort_deterministic();

        let hit = set
            .lookup(&mk_conn(), &mk_proc("/usr/bin/curl"), now())
            .expect("should match");
        assert_eq!(hit.name, "old-allow");
    }

    #[test]
    fn uid_predicate() {
        let mut scope = RuleScope::any();
        scope.uid = Some(1000);
        let rule = Rule::new("uid-1000", Action::Allow, scope);

        let set = RuleSet { rules: vec![rule] };
        let conn = mk_conn();

        assert!(set.lookup(&conn, &mk_proc("/anything"), now()).is_some());

        let mut other = mk_proc("/anything");
        other.uid = Some(2000);
        assert!(set.lookup(&conn, &other, now()).is_none());
    }

    #[test]
    fn uid_scope_never_matches_unattributed_process() {
        // Regression: Process::unknown used to fabricate uid 0, so a rule
        // scoped to uid 0 (root) matched traffic we could not attribute.
        let mut scope = RuleScope::any();
        scope.uid = Some(0);
        let rule = Rule::new("uid-root", Action::Allow, scope);

        let set = RuleSet { rules: vec![rule] };
        let conn = mk_conn();
        let unknown = Process::unknown(0);
        assert_eq!(unknown.uid, None);
        assert!(set.lookup(&conn, &unknown, now()).is_none());
    }

    #[test]
    fn seconds_rule_expires_at_lookup() {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(443);
        let mut rule = Rule::new("allow-443-1h", Action::Allow, scope);
        rule.duration = Duration::Seconds(3600);
        rule.created_at = chrono::DateTime::from_timestamp_millis(1_000_000).unwrap();

        let set = RuleSet { rules: vec![rule] };
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");

        let created = 1_000_000i64;
        let expiry = created + 3600 * 1000;

        // Still inside the window -> matches.
        assert!(set.lookup(&conn, &proc, created + 1).is_some());
        assert!(set.lookup(&conn, &proc, expiry - 1).is_some());
        // At and after expiry -> skipped.
        assert!(set.lookup(&conn, &proc, expiry).is_none());
        assert!(set.lookup(&conn, &proc, expiry + 1).is_none());
    }

    #[test]
    fn non_seconds_durations_never_expire_at_lookup() {
        for duration in [Duration::Once, Duration::UntilRestart, Duration::Always] {
            let mut rule = Rule::new("r", Action::Allow, RuleScope::any());
            rule.duration = duration;
            rule.created_at = chrono::DateTime::from_timestamp_millis(0).unwrap();
            assert!(
                !rule.is_expired(i64::MAX),
                "{duration:?} must not expire at lookup time"
            );
        }
    }

    #[test]
    fn specificity_counts_populated_predicates() {
        assert_eq!(RuleScope::any().specificity(), 0);

        let mut one = RuleScope::any();
        one.dst_port = Some(443);
        assert_eq!(one.specificity(), 1);

        let full = RuleScope {
            direction: Some(crate::Direction::Outbound),
            src_net: Some("192.168.0.0/16".parse().unwrap()),
            src_port: Some(51234),
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
            exe_sha256: Some("deadbeef".into()),
            parent_exe: Some(PathBuf::from("/bin/bash")),
            uid: Some(1000),
            dst_host: Some("example.com".into()),
            dst_net: Some("10.0.0.0/8".parse().unwrap()),
            dst_port: Some(443),
            protocol: Some(Protocol::Tcp),
        };
        // 10, not 11: direction is populated above and deliberately does not
        // count. `None` and `Some(Outbound)` match the same flows, so counting
        // it let two spellings of one rule rank differently at the
        // closed-wins tie-break.
        assert_eq!(full.specificity(), 10);

        let mut direction_only = RuleScope::any();
        direction_only.direction = Some(crate::Direction::Inbound);
        assert_eq!(
            direction_only.specificity(),
            0,
            "a scope constraining only the direction constrains nothing"
        );
    }

    #[test]
    fn explicit_outbound_does_not_outrank_implicit_outbound() {
        // The regression that removed direction from the count: two rules
        // identical except for spelling out the default direction must tie,
        // so the deny-beats-allow tie-break decides - not the spelling.
        let mut spelled = RuleScope::any();
        spelled.dst_port = Some(443);
        spelled.direction = Some(crate::Direction::Outbound);
        let mut implied = RuleScope::any();
        implied.dst_port = Some(443);
        assert_eq!(spelled.specificity(), implied.specificity());
    }

    // --- frozen v0.1.0 wire-format fixtures ------------------------------
    // Captured from the serialization produced before the serde(default)
    // annotations were added; these must keep parsing forever.

    #[test]
    fn fixture_exe_scoped_parses() {
        let rule: Rule =
            serde_json::from_str(include_str!("../testdata/rule_exe_scoped_v010.json")).unwrap();
        assert_eq!(rule.name, "exe-scoped");
        assert_eq!(rule.action, Action::Allow);
        assert_eq!(rule.duration, Duration::Always);
        assert_eq!(rule.scope.exe_path, Some(PathBuf::from("/usr/bin/curl")));
        assert_eq!(rule.scope.specificity(), 1);
    }

    #[test]
    fn fixture_host_scoped_parses() {
        let rule: Rule =
            serde_json::from_str(include_str!("../testdata/rule_host_scoped_v010.json")).unwrap();
        assert_eq!(rule.name, "host-scoped");
        assert_eq!(rule.action, Action::Deny);
        assert_eq!(rule.duration, Duration::UntilRestart);
        assert_eq!(rule.scope.dst_host.as_deref(), Some("example.com"));
        assert_eq!(rule.scope.specificity(), 1);
    }

    #[test]
    fn fixture_net_port_scoped_parses() {
        let rule: Rule =
            serde_json::from_str(include_str!("../testdata/rule_net_port_scoped_v010.json"))
                .unwrap();
        assert_eq!(rule.name, "net-port-scoped");
        assert_eq!(rule.action, Action::Reject);
        assert_eq!(rule.duration, Duration::Seconds(3600));
        assert_eq!(rule.scope.dst_net, Some("10.0.0.0/8".parse().unwrap()));
        assert_eq!(rule.scope.dst_port, Some(443));
        assert_eq!(rule.scope.specificity(), 2);
    }

    #[test]
    fn fixture_uid_scoped_parses() {
        let rule: Rule =
            serde_json::from_str(include_str!("../testdata/rule_uid_scoped_v010.json")).unwrap();
        assert_eq!(rule.name, "uid-scoped");
        assert_eq!(rule.duration, Duration::Once);
        assert_eq!(rule.scope.uid, Some(1000));
        assert_eq!(rule.scope.specificity(), 1);
    }

    #[test]
    fn fixture_full_scope_parses() {
        let rule: Rule =
            serde_json::from_str(include_str!("../testdata/rule_full_scope_v010.json")).unwrap();
        assert_eq!(rule.name, "full-scope");
        assert_eq!(rule.scope.specificity(), 8);
        assert_eq!(rule.scope.protocol, Some(Protocol::Tcp));
        assert_eq!(rule.scope.dst_net, Some("93.184.216.0/24".parse().unwrap()));
    }

    /// Documents the non-`deny_unknown_fields` contract: newer writers may
    /// add fields and this version must still parse the rule.
    #[test]
    fn fixture_with_unknown_extra_fields_parses() {
        let rule: Rule =
            serde_json::from_str(include_str!("../testdata/rule_unknown_extra_field.json"))
                .unwrap();
        assert_eq!(rule.name, "forward-compat-extra-field");
        assert_eq!(rule.scope.exe_path, Some(PathBuf::from("/usr/bin/curl")));
    }

    /// Documents the serde(default) contract: a rule missing `enabled`,
    /// `duration`, `hit_count`, and most scope fields still parses with the
    /// documented defaults.
    #[test]
    fn fixture_missing_defaulted_fields_parses() {
        let rule: Rule = serde_json::from_str(include_str!(
            "../testdata/rule_missing_defaulted_fields.json"
        ))
        .unwrap();
        assert_eq!(rule.name, "minimal-required-only");
        assert!(rule.enabled, "enabled must default to true");
        assert_eq!(rule.duration, Duration::Always);
        assert_eq!(rule.hit_count, 0);
        assert_eq!(rule.scope.exe_path, Some(PathBuf::from("/usr/bin/curl")));
        assert_eq!(rule.scope.uid, None);
        assert_eq!(rule.scope.specificity(), 1);
    }
}

#[cfg(test)]
mod inbound_scope_tests {
    use super::*;

    /// Inbound, the destination is always this machine, so `dst_net` and
    /// `dst_host` cannot express anything. Accepting them would produce a rule
    /// that reads like policy and matches nothing.
    #[test]
    fn an_inbound_rule_may_not_be_scoped_on_the_destination() {
        for (label, mutate) in [
            (
                "dst_net",
                Box::new(|s: &mut RuleScope| s.dst_net = Some("10.0.0.0/8".parse().unwrap()))
                    as Box<dyn Fn(&mut RuleScope)>,
            ),
            (
                "dst_host",
                Box::new(|s: &mut RuleScope| s.dst_host = Some("example.com".into())),
            ),
        ] {
            let mut scope = RuleScope::any();
            scope.direction = Some(crate::Direction::Inbound);
            mutate(&mut scope);
            let err = scope
                .reject_inbound_destination_scope()
                .expect_err("inbound rule scoped on the destination must be refused");
            assert!(err.contains(label), "the error must name the field: {err}");
            assert!(
                err.contains("src_net"),
                "the error must say what to use instead: {err}"
            );
            // The message reaches a terminal; runs of whitespace mean the line
            // continuations were lost.
            assert!(!err.contains("  "), "collapsed continuation in: {err:?}");
        }
    }

    /// `dst_port` is the useful inbound predicate - it is the port on *this*
    /// host - and must keep working.
    #[test]
    fn an_inbound_rule_may_be_scoped_on_the_port_and_the_source() {
        let mut scope = RuleScope::any();
        scope.direction = Some(crate::Direction::Inbound);
        scope.dst_port = Some(22);
        scope.src_net = Some("192.168.0.0/16".parse().unwrap());
        scope.src_port = Some(1234);
        assert!(scope.reject_inbound_destination_scope().is_ok());
    }

    /// The guard keys off the direction, so an outbound or unscoped rule -
    /// every rule that existed before this feature - is untouched.
    #[test]
    fn the_guard_does_not_touch_outbound_or_undirected_rules() {
        for dir in [None, Some(crate::Direction::Outbound)] {
            let mut scope = RuleScope::any();
            scope.direction = dir;
            scope.dst_net = Some("10.0.0.0/8".parse().unwrap());
            scope.dst_host = Some("example.com".into());
            assert!(
                scope.reject_inbound_destination_scope().is_ok(),
                "{dir:?} rules must keep their destination scopes"
            );
        }
    }
}

#[cfg(test)]
mod placeholder_exe_tests {
    use super::*;
    use crate::{Process, UNKNOWN_EXE};

    /// The bug this exists to prevent, stated as a property.
    ///
    /// A real database held `exe_path = "<unknown>"` with no other predicate,
    /// action Allow. It had 285 hits and, once the inbound chain was enabled,
    /// admitted every inbound connection - the rules meant to govern inbound
    /// were never consulted, because this one matched first and said yes.
    #[test]
    fn an_unidentified_process_matches_no_exe_scoped_rule() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from(UNKNOWN_EXE));

        let unknown = Process::unknown(4242);
        assert!(
            !unknown.exe_is_known(),
            "the placeholder must not read as a known path"
        );
        assert!(
            !scope.matches_process(&unknown),
            "a rule naming the placeholder must not match an unidentified process"
        );
    }

    /// The same for a rule naming a real program: an unidentified process is
    /// not that program either, so it must not match.
    #[test]
    fn an_unidentified_process_does_not_match_a_real_exe_rule() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        assert!(!scope.matches_process(&Process::unknown(1)));
    }

    #[test]
    fn a_rule_scoped_to_the_placeholder_is_refused_at_creation() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from(UNKNOWN_EXE));
        let err = scope.reject_unmatchable_exe().expect_err("must be refused");
        assert!(err.contains(UNKNOWN_EXE), "{err}");
        assert!(!err.contains("  "), "collapsed continuation in: {err:?}");
    }

    #[test]
    fn a_relative_exe_is_refused_because_it_could_never_fire() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("curl"));
        assert!(scope.reject_unmatchable_exe().is_err());
    }

    #[test]
    fn an_ordinary_absolute_exe_is_accepted() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        assert!(scope.reject_unmatchable_exe().is_ok());
        assert!(RuleScope::any().reject_unmatchable_exe().is_ok());
    }
}

#[cfg(test)]
mod content_binding_tests {
    use super::*;
    use crate::Process;

    fn hashed(exe: &str, sha: Option<&str>) -> Process {
        Process {
            exe: PathBuf::from(exe),
            sha256: sha.map(str::to_string),
            ..Process::unknown(1)
        }
    }

    /// The property `--pin-hash` sells: the rule follows the *contents*, so a
    /// binary swapped in at the same path does not inherit the permission.
    #[test]
    fn a_replaced_binary_does_not_inherit_the_rule() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        scope.exe_sha256 = Some("aa".repeat(32));

        assert!(
            scope.matches_process(&hashed("/usr/bin/curl", Some(&"aa".repeat(32)))),
            "the pinned binary must still match"
        );
        assert!(
            !scope.matches_process(&hashed("/usr/bin/curl", Some(&"bb".repeat(32)))),
            "a different binary at the same path must not match"
        );
    }

    /// An unknown hash is not a match, and must never be read as one. This is
    /// the direction that matters: treating "cannot say" as "yes" would let a
    /// replaced binary keep an allow.
    #[test]
    fn an_unknown_hash_never_satisfies_a_pinned_rule() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        scope.exe_sha256 = Some("aa".repeat(32));
        assert!(!scope.matches_process(&hashed("/usr/bin/curl", None)));
    }

    /// ...but it must abstain rather than decide, so a lower-precedence deny
    /// cannot be applied in its place at exec time.
    #[test]
    fn an_unknown_hash_makes_the_scope_undecidable() {
        let mut scope = RuleScope::any();
        scope.exe_sha256 = Some("aa".repeat(32));
        assert!(scope.undecidable_for(&hashed("/usr/bin/curl", None)));
        assert!(!scope.undecidable_for(&hashed("/usr/bin/curl", Some(&"aa".repeat(32)))));
    }

    /// A rule with no hash is unaffected: path binding stays the default.
    #[test]
    fn a_rule_without_a_hash_still_matches_by_path() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        assert!(scope.matches_process(&hashed("/usr/bin/curl", Some(&"bb".repeat(32)))));
        assert!(scope.matches_process(&hashed("/usr/bin/curl", None)));
    }
}

#[cfg(test)]
mod parent_exe_tests {
    use super::*;
    use crate::Process;

    /// `parent_exe` is scored but never compared, so a rule carrying it matches
    /// everything while sorting ahead of rules that actually are narrower.
    #[test]
    fn a_parent_scoped_rule_is_refused_because_it_would_match_everything() {
        let mut scope = RuleScope::any();
        scope.parent_exe = Some(PathBuf::from("/bin/bash"));

        // The trap, demonstrated: it matches a process bash never launched.
        let unrelated = Process {
            exe: PathBuf::from("/usr/bin/curl"),
            ..Process::unknown(1)
        };
        assert!(
            scope.matches_process(&unrelated),
            "precondition: the predicate is not evaluated"
        );
        // And it scores as though it narrowed something.
        assert!(scope.specificity() > RuleScope::any().specificity());

        let err = scope
            .reject_unmatchable_parent()
            .expect_err("must be refused");
        assert!(err.contains("parent_exe"), "{err}");
        assert!(!err.contains("  "), "collapsed continuation: {err:?}");
    }

    #[test]
    fn a_scope_without_a_parent_is_untouched() {
        assert!(RuleScope::any().reject_unmatchable_parent().is_ok());
    }
}
