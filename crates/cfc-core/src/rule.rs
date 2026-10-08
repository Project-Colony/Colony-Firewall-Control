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
    /// Legacy policy only: retained as uncertainty at its original priority.
    /// New rules must use numeric `dst_net`; DNS names are diagnostic only.
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

/// Longest `exe_path` a rule may carry.
///
/// `PATH_MAX` on Linux is 4096 including the terminator, so nothing longer can
/// name a file that exists. Rules are matched by exact string equality against
/// `/proc/<pid>/exe`, so a longer one is unmatchable by construction.
pub const MAX_EXE_PATH_LEN: usize = 4096;

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
    ///
    /// A `/0` network is not counted either, for the same reason: it narrows
    /// nothing within its address family, so `--dst-net 0.0.0.0/0` must not
    /// lift a rule above a genuinely narrower one. Matching is unchanged
    /// (an IPv4 `/0` still excludes IPv6 flows), only the ranking.
    pub fn specificity(&self) -> u8 {
        let narrows = |net: &Option<IpNet>| net.is_some_and(|n| n.prefix_len() > 0);
        [
            narrows(&self.src_net),
            self.src_port.is_some(),
            self.exe_path.is_some(),
            self.exe_sha256.is_some(),
            self.parent_exe.is_some(),
            self.uid.is_some(),
            self.dst_host.is_some(),
            narrows(&self.dst_net),
            self.dst_port.is_some(),
            self.protocol.is_some(),
        ]
        .into_iter()
        .filter(|set| *set)
        .count() as u8
    }

    /// True when this scope names a program: an `exe_path` or `exe_sha256`
    /// predicate.
    ///
    /// The line [`RuleSet::lookup`] draws for precedence: a Deny or Reject
    /// that names a program wins over every Allow that names none.
    pub fn names_program(&self) -> bool {
        self.exe_path.is_some() || self.exe_sha256.is_some()
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

    /// Hostnames decorate flows; DNS cannot authenticate the application name
    /// or prove that an address has no other aliases. New policy must use a
    /// numeric destination network instead of a diagnostic name.
    pub fn reject_hostname_policy(&self) -> Result<(), String> {
        if self.dst_host.is_some() {
            return Err("dst_host is diagnostic only and cannot scope a rule; use an explicit numeric dst_net (/32 for IPv4, /128 for IPv6)".into());
        }
        Ok(())
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
        // The value is not echoed: it is any length a client sent, and the
        // message becomes a gRPC status and a log line.
        if self.parent_exe.is_none() {
            return Ok(());
        }
        Err("cannot scope a rule on parent_exe: the predicate is not \
             evaluated, so the rule would match every process rather than the \
             ones launched by it - and it would outrank narrower rules while \
             doing so. Scope on the executable itself."
            .to_string())
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
        // A path no filesystem can hold is a path no process can be running,
        // so such a rule can never fire - the same test as the two below, for
        // a value that arrives over the wire.
        //
        // The bound is here rather than at the wire because this is the gate
        // both writers already run. What it stops is not a bad rule: it is the
        // work of *rejecting* one. `exe_path` is a bare proto string, capped
        // only by the 4 MiB decode limit, and resolution walks one
        // `canonicalize(2)` per path component from the leaf upward - about
        // two million syscalls for a 4 MiB path, on a blocking pool of
        // sixteen that the prompt router also depends on.
        //
        // First, and the message deliberately does not print the path: the
        // arms below format it into a string that becomes a gRPC status and a
        // log line, which for this input would be the denial-of-service
        // repeated on the way out.
        if exe.as_os_str().len() > MAX_EXE_PATH_LEN {
            return Err(format!(
                "exe path is {} bytes; the kernel cannot hold a path longer \
                 than {MAX_EXE_PATH_LEN}, so no process could ever match it",
                exe.as_os_str().len()
            ));
        }
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
        } else if self.uid.is_some() {
            "a user ID"
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
    /// Missing executable, UID or digest is uncertainty, not evidence that
    /// a rule does not match. Known incompatible predicates still exclude
    /// the rule before any missing identity is considered.
    pub fn undecidable_for(&self, proc: &crate::Process) -> bool {
        if let Some(p) = &self.exe_path {
            if proc.exe_is_known() && &proc.exe != p {
                return false;
            }
        }
        if let (Some(expected), Some(actual)) = (&self.exe_sha256, &proc.sha256) {
            if expected != actual {
                return false;
            }
        }
        if let Some(u) = self.uid {
            if proc.uid.is_some_and(|actual| actual != u) {
                return false;
            }
        }
        (self.exe_path.is_some() && !proc.exe_is_known())
            || (self.exe_sha256.is_some() && proc.sha256.is_none())
            || (self.uid.is_some() && proc.uid.is_none())
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
        self.matches_process(proc) && self.matches_connection(conn)
    }

    /// The connection half of [`Self::matches`], on its own.
    ///
    /// The mirror of [`Self::matches_process`], and split out for the mirror
    /// reason: a caller that has a connection needs to ask "could this rule
    /// be about this flow at all?" *before* asking whether the process half
    /// can be decided. Without that order, a rule undecidable for the process
    /// would stop the search for every flow, including the ones its own
    /// destination predicates exclude - `deny --exe X --sha256 H
    /// --dst-port 25` would abstain on a connection to port 80, which it can
    /// never be about. [`Self::matches`] is defined in terms of both halves,
    /// so none of the three can drift.
    pub fn matches_connection(&self, conn: &crate::Connection) -> bool {
        self.dst_host.is_none() && self.matches_known_connection(conn)
    }

    /// Checks the numeric scope while preserving an unevaluable legacy name.
    fn matches_known_connection(&self, conn: &crate::Connection) -> bool {
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
            // Older wire conversions manufactured Other(_), which cannot be
            // expressed by the supported policy API. A legacy named rule
            // retains that uncertainty and its original specificity.
            let unsupported_legacy =
                self.dst_host.is_some() && matches!(proto, crate::Protocol::Other(_));
            if !unsupported_legacy && conn.protocol != proto {
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
    /// Only `Duration::Seconds(n)` expires here, at `created_at + n` seconds.
    /// Startup purges `UntilRestart` and `Once` rules separately.
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
    /// 1. specificity DESC - more scope predicates first (see
    ///    [`RuleScope::specificity`]);
    /// 2. action severity - Deny, then Reject, before Allow on ties;
    /// 3. `created_at` ASC - oldest rule first;
    /// 4. `id` ASC - final total-order tiebreak.
    ///
    /// [`RuleSet::lookup`] applies one override on top of this order (a
    /// program Deny beats a generic Allow); it cannot live in the sort key.
    ///
    /// Must be called whenever the set is (re)built or a rule is inserted,
    /// replaced, or toggled, so `lookup`'s walk is stable across daemon
    /// restarts regardless of storage iteration order.
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
    /// Precedence contract:
    ///
    /// 1. A Deny or Reject rule that names a program
    ///    ([`RuleScope::names_program`]) wins over every Allow rule that names
    ///    none, whatever their predicate counts. "Deny this program" means
    ///    that program, even where a broader "allow HTTPS" ranks higher.
    /// 2. Otherwise the most-specific scope wins; deny beats allow at equal
    ///    specificity; oldest rule first on remaining ties. Rules that name a
    ///    program keep this order among themselves, so `allow --exe X
    ///    --dst-port 443` still beats `deny --exe X`.
    ///
    /// The set is kept in [`RuleSet::sort_deterministic`] order, which is the
    /// second point alone. The first is applied here, during the walk, and not
    /// in the sort key: the relation is not a total order (a program Allow of
    /// specificity 3 beats a program Deny of 2, which beats a generic Allow of
    /// 5, which beats a generic Deny of 4, which beats the program Allow), so
    /// no comparator could express it.
    ///
    /// `now_unix_ms` is the current wall-clock time; rules whose
    /// `Duration::Seconds(..)` window has elapsed are skipped (see
    /// [`Rule::is_expired`]).
    ///
    /// A rule this process cannot be checked against (see
    /// [`RuleScope::undecidable_for`]) or a legacy hostname rule is walked
    /// past and remembered. The definite winner then answers only if every
    /// way those rules could resolve gives the same action; otherwise the
    /// answer is [`Match::Undecidable`]. See [`Match`].
    pub fn lookup(
        &self,
        conn: &crate::Connection,
        proc: &crate::Process,
        now_unix_ms: i64,
    ) -> Match<'_> {
        // The rule reported when the outcome is open. A legacy hostname rule
        // takes the slot from an identity one: the caller refuses it rather
        // than prompting.
        let mut undecided: Option<&Rule> = None;
        // Whether an undecided Allow, or an undecided Deny/Reject, was passed.
        let mut maybe_allow = false;
        let mut maybe_closed = false;
        // The first definite Allow that names no program. Held, not returned:
        // a program Deny ranked below it may still override it.
        let mut generic_allow: Option<&Rule> = None;
        let mut winner = None;
        for rule in self
            .rules
            .iter()
            .filter(|r| r.enabled && !r.is_expired(now_unix_ms))
        {
            // Once a generic Allow is held, only a program rule can change
            // the answer: anything else ranks below it and loses by order.
            if generic_allow.is_some() && !rule.scope.names_program() {
                continue;
            }
            // The connection half first, so a rule's own destination
            // predicates can exclude it before its process half is ever
            // questioned. Without that order an undecidable rule would abstain
            // for flows it can never be about.
            if !rule.scope.matches_known_connection(conn) {
                continue;
            }
            let missing_process = rule.scope.undecidable_for(proc);
            if !missing_process && !rule.scope.matches_process(proc) {
                continue;
            }
            // No PTR, including a forward-confirmed PTR, establishes the
            // application's intended hostname or enumerates every alias.
            // Keep a legacy name at its original priority as uncertainty.
            if missing_process || rule.scope.dst_host.is_some() {
                if undecided
                    .is_none_or(|u| u.scope.dst_host.is_none() && rule.scope.dst_host.is_some())
                {
                    undecided = Some(rule);
                }
                if rule.action == Action::Allow {
                    maybe_allow = true;
                } else {
                    maybe_closed = true;
                }
                continue;
            }
            winner = Some(match generic_allow {
                // A lower program Allow cannot turn the answer into a refusal.
                Some(held) if rule.action == Action::Allow => held,
                None if rule.action == Action::Allow && !rule.scope.names_program() => {
                    generic_allow = Some(rule);
                    continue;
                }
                _ => rule,
            });
            break;
        }
        let Some(winner) = winner.or(generic_allow) else {
            return undecided.map_or(Match::None, Match::Undecidable);
        };
        // Every resolution of the undecided rules gives the winner's action.
        let settled = if winner.action == Action::Allow {
            !maybe_closed
        } else {
            !maybe_allow
        };
        match undecided {
            Some(first) if !settled => Match::Undecidable(first),
            _ => Match::Rule(winner),
        }
    }
}

/// What [`RuleSet::lookup`] found.
///
/// Three outcomes, not two, and the third is the whole point. Precedence is
/// ordered, so a rule that cannot be decided must not be ignored: the rules
/// beneath it are the ones its author wrote it to override. When it and the
/// rule that would otherwise answer agree on the action, that rule answers;
/// when they disagree, nobody does.
///
/// The case in the field is a `deny` scoped to `exe_sha256` over a binary the
/// daemon cannot hash - over 64 MiB, unreadable, or a process whose image is
/// already gone. `matches_process` collapses "cannot say" into "does not
/// match", so the walk continued and a lower-precedence `allow --exe X` won.
/// The deny listed, ranked first, and never fired - indistinguishable from
/// working. `RuleScope::undecidable_for` was written for exactly this hazard
/// and its own documentation says so, but it was only ever consulted on the
/// fast path, where the mirror case (an abstaining *allow* handing the flow to
/// a lower *deny*) had been noticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match<'a> {
    /// This rule answered.
    Rule(&'a Rule),
    /// This rule could apply, but the process identity (exe, uid or digest)
    /// or a legacy hostname cannot be decided, and the rules that could apply
    /// disagree. The caller asks the user, with the identity shown as unknown;
    /// a legacy hostname rule (`dst_host`) is refused instead, since no answer
    /// can establish the name.
    Undecidable(&'a Rule),
    /// No rule is about this flow.
    None,
}

impl<'a> Match<'a> {
    /// The rule that answered, if one did. An abstention is not an answer.
    pub fn rule(self) -> Option<&'a Rule> {
        match self {
            Self::Rule(r) => Some(r),
            _ => None,
        }
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

    #[test]
    fn legacy_hostname_policy_never_yields_to_a_disagreeing_lower_allow() {
        for action in [Action::Allow, Action::Deny, Action::Reject] {
            let mut named = RuleScope::any();
            named.exe_path = Some("/usr/bin/curl".into());
            named.dst_host = Some("example.org".into());
            named.dst_port = Some(443);
            named.dst_net = Some("1.2.3.4/32".parse().unwrap());
            named.src_net = Some("192.168.1.0/24".parse().unwrap());
            named.src_port = Some(54321);
            named.protocol = Some(Protocol::Tcp);
            let mut set = RuleSet {
                rules: vec![
                    Rule::new("legacy-name", action, named),
                    Rule::new(
                        "lower-allow",
                        Action::Allow,
                        RuleScope {
                            dst_port: Some(443),
                            ..RuleScope::any()
                        },
                    ),
                ],
            };
            set.sort_deterministic();
            let proc = mk_proc("/usr/bin/curl");
            for host in [None, Some("example.org"), Some("alternate.example.org")] {
                for verified in [false, true] {
                    let mut conn = mk_conn();
                    conn.dst_host = host.map(str::to_owned);
                    conn.dst_host_verified = verified;
                    // A legacy Allow over a lower Allow: both resolutions
                    // allow, so the lower rule answers. A legacy refusal over
                    // it stays open, whatever the PTR says.
                    let result = set.lookup(&conn, &proc, now());
                    if action == Action::Allow {
                        assert!(
                            matches!(result, Match::Rule(r) if r.name == "lower-allow"),
                            "{host:?} verified={verified}"
                        );
                    } else {
                        assert!(
                            matches!(result, Match::Undecidable(r) if r.name == "legacy-name"),
                            "{action:?} {host:?} verified={verified}"
                        );
                    }
                    assert!(!set.rules[0].scope.matches(&conn, &proc));
                }
            }
            let mut other_port = mk_conn();
            other_port.dst_port = 80;
            assert!(matches!(set.lookup(&other_port, &proc, now()), Match::None));
            for incompatible in [
                Connection {
                    dst_ip: "1.2.3.5".parse().unwrap(),
                    ..mk_conn()
                },
                Connection {
                    src_ip: "192.168.2.1".parse().unwrap(),
                    ..mk_conn()
                },
                Connection {
                    src_port: 12345,
                    ..mk_conn()
                },
                Connection {
                    protocol: Protocol::Udp,
                    ..mk_conn()
                },
            ] {
                assert!(
                    matches!(set.lookup(&incompatible, &proc, now()), Match::Rule(r) if r.name == "lower-allow")
                );
            }
            let other_process = mk_proc("/usr/bin/wget");
            assert!(
                matches!(set.lookup(&mk_conn(), &other_process, now()), Match::Rule(r) if r.name == "lower-allow")
            );
        }
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
    fn hostname_policy_never_definitely_matches_a_connection() {
        let scope = RuleScope {
            dst_host: Some("Example.COM.".into()),
            ..RuleScope::any()
        };
        let mut conn = mk_conn();
        for host in [None, Some("example.com"), Some("another.example.com")] {
            conn.dst_host = host.map(str::to_owned);
            assert!(!scope.matches_connection(&conn));
        }
    }

    #[test]
    fn legacy_hostname_with_unsupported_protocol_preserves_its_guard() {
        for protocol in [Protocol::Other(0), Protocol::Other(47)] {
            let scope = RuleScope {
                dst_host: Some("example.org".into()),
                protocol: Some(protocol),
                dst_port: Some(443),
                uid: Some(1000),
                ..RuleScope::any()
            };
            let mut set = RuleSet {
                rules: vec![
                    Rule::new("legacy-name", Action::Deny, scope),
                    Rule::new(
                        "lower-allow",
                        Action::Allow,
                        RuleScope {
                            dst_port: Some(443),
                            ..RuleScope::any()
                        },
                    ),
                ],
            };
            set.sort_deterministic();
            let proc = mk_proc("/usr/bin/curl");
            assert_eq!(set.rules[0].scope.specificity(), 4);
            assert!(
                matches!(set.lookup(&mk_conn(), &proc, now()), Match::Undecidable(r) if r.name == "legacy-name")
            );
            let other_port = Connection {
                dst_port: 80,
                ..mk_conn()
            };
            assert!(matches!(set.lookup(&other_port, &proc, now()), Match::None));
            let other_uid = Process {
                uid: Some(1001),
                ..proc
            };
            assert!(
                matches!(set.lookup(&mk_conn(), &other_uid, now()), Match::Rule(r) if r.name == "lower-allow")
            );
        }
    }

    #[test]
    fn inbound_uid_is_rejected_like_other_unattributable_identity() {
        let mut scope = RuleScope::any();
        scope.direction = Some(Direction::Inbound);
        scope.uid = Some(1000);
        scope.dst_port = Some(443);
        assert!(scope.reject_unattributable_inbound_scope().is_err());
        scope.direction = Some(Direction::Outbound);
        assert!(scope.reject_unattributable_inbound_scope().is_ok());
    }

    #[test]
    fn missing_identity_does_not_exclude_a_possible_deny() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        assert!(scope.undecidable_for(&Process::unknown(0)));
        assert!(!scope.undecidable_for(&mk_proc("/usr/bin/wget")));
        scope.uid = Some(1001);
        assert!(!scope.undecidable_for(&mk_proc("/usr/bin/curl")));
        scope.exe_path = None;
        assert!(scope.undecidable_for(&Process::unknown(0)));
    }

    #[test]
    fn undecidable_closed_rule_cannot_hide_a_definite_closed_rule() {
        let mut set = deny_by_hash_over_allow(None);
        set.rules[1].action = Action::Reject;
        set.sort_deterministic();
        let result = set.lookup(&mk_conn(), &mk_proc("/usr/bin/curl"), now());
        assert_eq!(result.rule().map(|r| r.action), Some(Action::Reject));
    }

    /// The rule set the defect needs: a hash-scoped deny ranking above a
    /// plain allow for the same program.
    fn deny_by_hash_over_allow(dst_port: Option<u16>) -> RuleSet {
        let mut hashed = RuleScope::any();
        hashed.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        hashed.exe_sha256 = Some("aa".repeat(32));
        hashed.dst_port = dst_port;
        let mut plain = RuleScope::any();
        plain.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        let mut set = RuleSet {
            rules: vec![
                Rule::new("deny-that-binary".to_string(), Action::Deny, hashed),
                Rule::new("allow-curl".to_string(), Action::Allow, plain),
            ],
        };
        set.sort_deterministic();
        set
    }

    #[test]
    fn a_deny_that_cannot_be_decided_does_not_hand_the_flow_to_an_allow() {
        let set = deny_by_hash_over_allow(None);
        let conn = mk_conn();

        // With the digest in hand the deny answers, as it always did.
        let mut hashed = mk_proc("/usr/bin/curl");
        hashed.sha256 = Some("aa".repeat(32));
        assert_eq!(
            set.lookup(&conn, &hashed, now()).rule().map(|r| r.action),
            Some(Action::Deny)
        );

        // Without it - a binary over the hashing cap, an unreadable image, a
        // process whose image is already gone - the deny cannot be decided.
        // It must stop the walk, not be skipped: the allow beneath it is the
        // rule its author wrote the deny to override.
        let unhashed = mk_proc("/usr/bin/curl");
        assert_eq!(unhashed.sha256, None);
        match set.lookup(&conn, &unhashed, now()) {
            Match::Undecidable(r) => assert_eq!(r.name, "deny-that-binary"),
            other => panic!("expected an abstention, got {other:?}"),
        }
        assert!(
            set.lookup(&conn, &unhashed, now()).rule().is_none(),
            "an abstention is not an answer"
        );
    }

    #[test]
    fn an_undecidable_rule_only_abstains_for_flows_it_could_be_about() {
        // The trap in the fix: keying the abstention on the process alone
        // would let `deny --exe X --sha256 H --dst-port 25` stop the walk for
        // a connection to port 443, which that rule can never be about.
        let set = deny_by_hash_over_allow(Some(25));
        let unhashed = mk_proc("/usr/bin/curl");

        // Port 443: the deny's own destination predicate excludes it, so the
        // allow answers normally.
        let conn = mk_conn();
        assert_eq!(conn.dst_port, 443);
        assert_eq!(
            set.lookup(&conn, &unhashed, now()).rule().map(|r| r.action),
            Some(Action::Allow),
            "a rule excluded by its own destination must not abstain"
        );

        // Port 25: now it is about this flow, and it abstains.
        let mut smtp = mk_conn();
        smtp.dst_port = 25;
        assert!(matches!(
            set.lookup(&smtp, &unhashed, now()),
            Match::Undecidable(_)
        ));
    }

    #[test]
    fn matches_is_still_exactly_its_two_halves() {
        // The split must not have changed what `matches` means.
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");
        for scope in [
            RuleScope::any(),
            {
                let mut s = RuleScope::any();
                s.exe_path = Some(PathBuf::from("/usr/bin/curl"));
                s
            },
            {
                let mut s = RuleScope::any();
                s.dst_port = Some(443);
                s
            },
            {
                let mut s = RuleScope::any();
                s.dst_port = Some(80);
                s
            },
            {
                let mut s = RuleScope::any();
                s.exe_path = Some(PathBuf::from("/usr/bin/wget"));
                s
            },
            {
                let mut s = RuleScope::any();
                s.direction = Some(Direction::Inbound);
                s
            },
        ] {
            assert_eq!(
                scope.matches(&conn, &proc),
                scope.matches_process(&proc) && scope.matches_connection(&conn),
                "the halves must recompose into the whole for {scope:?}"
            );
        }
    }

    #[test]
    fn empty_set_returns_none() {
        let set = RuleSet::default();
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");
        assert!(set.lookup(&conn, &proc, now()).rule().is_none());
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
            .rule()
            .is_some());
        assert!(set
            .lookup(&conn, &mk_proc("/usr/bin/wget"), now())
            .rule()
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

        assert!(set.lookup(&conn, &proc, now()).rule().is_some());
        conn.dst_port = 80;
        assert!(set.lookup(&conn, &proc, now()).rule().is_none());
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
        assert!(set.lookup(&conn, &proc, now()).rule().is_some());

        conn.dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(set.lookup(&conn, &proc, now()).rule().is_none());
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
        assert!(set.lookup(&conn, &proc, now()).rule().is_some());

        // Wrong port -> miss.
        conn.dst_port = 80;
        assert!(set.lookup(&conn, &proc, now()).rule().is_none());

        // Wrong proto -> miss.
        conn.dst_port = 443;
        conn.protocol = Protocol::Udp;
        assert!(set.lookup(&conn, &proc, now()).rule().is_none());

        // Wrong exe -> miss.
        conn.protocol = Protocol::Tcp;
        assert!(set
            .lookup(&conn, &mk_proc("/usr/bin/python"), now())
            .rule()
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
        assert!(set.lookup(&conn, &proc, now()).rule().is_none());
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

        let hit = set
            .lookup(&conn, &proc, now())
            .rule()
            .expect("should match");
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

        let hit = set
            .lookup(&conn, &proc, now())
            .rule()
            .expect("should match");
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

        let hit_fwd = forward
            .lookup(&conn, &proc, at)
            .rule()
            .expect("should match");
        let hit_rev = reverse
            .lookup(&conn, &proc, at)
            .rule()
            .expect("should match");
        assert_eq!(hit_fwd.id, hit_rev.id);
        assert_eq!(hit_fwd.name, "deny-curl");
    }

    fn scoped(name: &str, action: Action, scope: RuleScope) -> Rule {
        Rule::new(name, action, scope)
    }

    fn sorted(rules: Vec<Rule>) -> RuleSet {
        let mut set = RuleSet { rules };
        set.sort_deterministic();
        set
    }

    fn winner<'a>(set: &'a RuleSet, conn: &Connection, proc: &Process) -> Option<&'a str> {
        set.lookup(conn, proc, now())
            .rule()
            .map(|r| r.name.as_str())
    }

    #[test]
    fn a_program_deny_beats_a_more_specific_generic_allow() {
        // The scenario that made the override necessary: "deny this agent"
        // lost to "allow HTTPS" because the allow carried two predicates.
        let set = sorted(vec![
            scoped(
                "deny-telemetry",
                Action::Deny,
                RuleScope {
                    exe_path: Some("/opt/telemetry-agent".into()),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "allow-https",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        assert_eq!(set.rules[0].name, "allow-https", "the sort is unchanged");
        let conn = mk_conn();
        assert_eq!(
            winner(&set, &conn, &mk_proc("/opt/telemetry-agent")),
            Some("deny-telemetry")
        );
        assert_eq!(
            winner(&set, &conn, &mk_proc("/usr/bin/curl")),
            Some("allow-https")
        );
    }

    #[test]
    fn a_program_reject_beats_a_three_predicate_generic_allow() {
        let set = sorted(vec![
            scoped(
                "reject-x",
                Action::Reject,
                RuleScope {
                    exe_sha256: Some("aa".repeat(32)),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "allow-net",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    dst_net: Some("1.2.3.0/24".parse().unwrap()),
                    ..RuleScope::any()
                },
            ),
        ]);
        let hashed = Process {
            sha256: Some("aa".repeat(32)),
            ..mk_proc("/usr/bin/x")
        };
        assert_eq!(winner(&set, &mk_conn(), &hashed), Some("reject-x"));
    }

    #[test]
    fn a_more_specific_program_allow_still_beats_a_program_deny() {
        let set = sorted(vec![
            scoped(
                "deny-x",
                Action::Deny,
                RuleScope {
                    exe_path: Some("/usr/bin/x".into()),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "allow-x-443",
                Action::Allow,
                RuleScope {
                    exe_path: Some("/usr/bin/x".into()),
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        let x = mk_proc("/usr/bin/x");
        assert_eq!(winner(&set, &mk_conn(), &x), Some("allow-x-443"));
        let http = Connection {
            dst_port: 80,
            ..mk_conn()
        };
        assert_eq!(winner(&set, &http, &x), Some("deny-x"));
    }

    #[test]
    fn a_program_allow_below_a_generic_allow_leaves_it_the_answer() {
        let set = sorted(vec![
            scoped(
                "allow-x",
                Action::Allow,
                RuleScope {
                    exe_path: Some("/usr/bin/x".into()),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "allow-https",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        assert_eq!(
            winner(&set, &mk_conn(), &mk_proc("/usr/bin/x")),
            Some("allow-https")
        );
    }

    #[test]
    fn a_generic_deny_keeps_the_old_order_against_generic_allows() {
        // The override is about rules that name a program. Between rules that
        // name none, specificity still decides, whatever the action.
        let set = sorted(vec![
            scoped(
                "deny-443",
                Action::Deny,
                RuleScope {
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "allow-tcp-443",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        assert_eq!(
            winner(&set, &mk_conn(), &mk_proc("/usr/bin/curl")),
            Some("allow-tcp-443")
        );
    }

    fn exe(path: &str) -> RuleScope {
        RuleScope {
            exe_path: Some(path.into()),
            ..RuleScope::any()
        }
    }

    #[test]
    fn an_undecidable_allow_yields_to_a_definite_allow_below() {
        // One "allow this program" rule used to make every unattributed flow
        // undecidable, so ICMP that a generic rule allows was refused.
        let set = sorted(vec![
            scoped("allow-firefox", Action::Allow, exe("/usr/bin/firefox")),
            scoped(
                "allow-icmp",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Icmp),
                    ..RuleScope::any()
                },
            ),
        ]);
        let ping = Connection {
            protocol: Protocol::Icmp,
            src_port: 0,
            dst_port: 0,
            ..mk_conn()
        };
        assert_eq!(
            winner(&set, &ping, &Process::unknown(0)),
            Some("allow-icmp")
        );
    }

    #[test]
    fn undecidable_allow_over_a_definite_deny_is_undecidable() {
        let set = sorted(vec![
            scoped(
                "allow-firefox",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    ..exe("/usr/bin/firefox")
                },
            ),
            scoped(
                "deny-https",
                Action::Deny,
                RuleScope {
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        assert!(matches!(
            set.lookup(&mk_conn(), &Process::unknown(0), now()),
            Match::Undecidable(r) if r.name == "allow-firefox"
        ));
    }

    #[test]
    fn undecidable_deny_over_a_definite_allow_is_undecidable() {
        let set = sorted(vec![
            scoped("deny-x", Action::Deny, exe("/usr/bin/x")),
            scoped(
                "allow-https",
                Action::Allow,
                RuleScope {
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        assert!(matches!(
            set.lookup(&mk_conn(), &Process::unknown(0), now()),
            Match::Undecidable(r) if r.name == "deny-x"
        ));
        // With no rule that disagrees, the refusal is settled either way.
        let deny_only = sorted(vec![
            scoped("deny-x", Action::Deny, exe("/usr/bin/x")),
            scoped(
                "deny-https",
                Action::Deny,
                RuleScope {
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        assert_eq!(
            winner(&deny_only, &mk_conn(), &Process::unknown(0)),
            Some("deny-https")
        );
    }

    #[test]
    fn an_undecidable_program_allow_under_a_generic_allow_keeps_a_program_deny_open() {
        // allow --sha256 H --dst-port 443 ranks above deny --exe /usr/bin/y.
        // If the image hashes to H, that Allow ends the walk under the generic
        // Allow and the answer is Allow; if not, the program Deny wins. With
        // no digest, neither can be claimed.
        let set = sorted(vec![
            scoped(
                "allow-net",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    dst_net: Some("1.2.3.0/24".parse().unwrap()),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "allow-h",
                Action::Allow,
                RuleScope {
                    exe_sha256: Some("aa".repeat(32)),
                    dst_port: Some(443),
                    protocol: Some(Protocol::Tcp),
                    ..RuleScope::any()
                },
            ),
            scoped("deny-y", Action::Deny, exe("/usr/bin/y")),
        ]);
        let unhashed = mk_proc("/usr/bin/y");
        assert!(matches!(
            set.lookup(&mk_conn(), &unhashed, now()),
            Match::Undecidable(r) if r.name == "allow-h"
        ));
        let mut hashed = mk_proc("/usr/bin/y");
        hashed.sha256 = Some("aa".repeat(32));
        assert_eq!(winner(&set, &mk_conn(), &hashed), Some("allow-net"));
        hashed.sha256 = Some("cc".repeat(32));
        assert_eq!(winner(&set, &mk_conn(), &hashed), Some("deny-y"));
    }

    #[test]
    fn an_unknown_process_under_a_program_deny_and_a_generic_allow_is_undecidable() {
        // The program Deny could be the one that overrides the Allow, and the
        // process cannot be checked against it.
        let set = sorted(vec![
            scoped(
                "deny-x",
                Action::Deny,
                RuleScope {
                    exe_path: Some("/usr/bin/x".into()),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "allow-https",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        assert!(matches!(
            set.lookup(&mk_conn(), &Process::unknown(0), now()),
            Match::Undecidable(r) if r.name == "deny-x"
        ));
        // A known other program is decided: the Deny cannot be about it.
        assert_eq!(
            winner(&set, &mk_conn(), &mk_proc("/usr/bin/curl")),
            Some("allow-https")
        );
    }

    #[test]
    fn lookup_is_independent_of_insertion_order_with_the_override() {
        // Four rules whose pairwise precedence is a cycle: program allow (3)
        // beats program deny (2) by specificity, which beats generic allow (5)
        // by the override, which beats generic deny (4) by specificity, which
        // beats the program allow (3) by specificity. The answer must still
        // not depend on the order the rules arrived in.
        let x = "/usr/bin/x";
        let net = || Some("1.2.3.0/24".parse().unwrap());
        let src = || Some("192.168.1.0/24".parse().unwrap());
        let rules = [
            scoped(
                "program-allow",
                Action::Allow,
                RuleScope {
                    exe_path: Some(x.into()),
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "program-deny",
                Action::Deny,
                RuleScope {
                    exe_path: Some(x.into()),
                    protocol: Some(Protocol::Tcp),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "generic-allow",
                Action::Allow,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    dst_net: net(),
                    src_net: src(),
                    src_port: Some(54321),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "generic-deny",
                Action::Deny,
                RuleScope {
                    protocol: Some(Protocol::Tcp),
                    dst_port: Some(443),
                    dst_net: net(),
                    src_net: src(),
                    ..RuleScope::any()
                },
            ),
        ];
        let proc = mk_proc(x);
        let conn = mk_conn();
        let mut answers = std::collections::BTreeSet::new();
        for a in 0..4 {
            for b in (0..4).filter(|b| *b != a) {
                for c in (0..4).filter(|c| *c != a && *c != b) {
                    let d = 6 - a - b - c;
                    let set = sorted([a, b, c, d].map(|i| rules[i].clone()).to_vec());
                    answers.insert(winner(&set, &conn, &proc).map(str::to_owned));
                }
            }
        }
        assert_eq!(
            answers.into_iter().collect::<Vec<_>>(),
            [Some("generic-allow".to_owned())]
        );

        // Without the program allow, the program deny overrides the generic
        // allow above it.
        let set = sorted(rules[1..].to_vec());
        assert_eq!(winner(&set, &conn, &proc), Some("program-deny"));
    }

    #[test]
    fn slash_zero_networks_add_no_specificity() {
        let any_v4 = RuleScope {
            dst_net: Some("0.0.0.0/0".parse().unwrap()),
            dst_port: Some(443),
            ..RuleScope::any()
        };
        assert_eq!(any_v4.specificity(), 1);
        let any_v6_source = RuleScope {
            src_net: Some("::/0".parse().unwrap()),
            ..RuleScope::any()
        };
        assert_eq!(any_v6_source.specificity(), 0);
        let half = RuleScope {
            dst_net: Some("0.0.0.0/1".parse().unwrap()),
            ..RuleScope::any()
        };
        assert_eq!(half.specificity(), 1);

        // Only the ranking changed: an IPv4 `/0` still excludes IPv6 flows.
        let v6 = Connection {
            dst_ip: "2001:db8::1".parse().unwrap(),
            src_ip: "2001:db8::2".parse().unwrap(),
            ..mk_conn()
        };
        let proc = mk_proc("/usr/bin/curl");
        assert!(any_v4.matches(&mk_conn(), &proc));
        assert!(!any_v4.matches(&v6, &proc));
    }

    #[test]
    fn a_slash_zero_rule_does_not_outrank_by_count() {
        // Both now count one predicate, so the tie-break decides: closed wins.
        let set = sorted(vec![
            scoped(
                "allow-all-v4-tcp",
                Action::Allow,
                RuleScope {
                    dst_net: Some("0.0.0.0/0".parse().unwrap()),
                    protocol: Some(Protocol::Tcp),
                    ..RuleScope::any()
                },
            ),
            scoped(
                "deny-443",
                Action::Deny,
                RuleScope {
                    dst_port: Some(443),
                    ..RuleScope::any()
                },
            ),
        ]);
        assert_eq!(
            winner(&set, &mk_conn(), &mk_proc("/usr/bin/curl")),
            Some("deny-443")
        );
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
            .rule()
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

        assert!(set
            .lookup(&conn, &mk_proc("/anything"), now())
            .rule()
            .is_some());

        let mut other = mk_proc("/anything");
        other.uid = Some(2000);
        assert!(set.lookup(&conn, &other, now()).rule().is_none());
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
        assert!(set.lookup(&conn, &unknown, now()).rule().is_none());
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
        assert!(set.lookup(&conn, &proc, created + 1).rule().is_some());
        assert!(set.lookup(&conn, &proc, expiry - 1).rule().is_some());
        // At and after expiry -> skipped.
        assert!(set.lookup(&conn, &proc, expiry).rule().is_none());
        assert!(set.lookup(&conn, &proc, expiry + 1).rule().is_none());
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

    /// A refusal becomes a gRPC status and a log line, so a 4 MiB value must
    /// not come back out in it, whichever check refuses it first.
    #[test]
    fn refusals_never_echo_an_oversized_path() {
        let huge = "a".repeat(MAX_EXE_PATH_LEN * 4);
        for exe in [huge.clone(), format!("/{huge}")] {
            let mut scope = RuleScope::any();
            scope.exe_path = Some(PathBuf::from(exe));
            let err = scope.reject_unmatchable_exe().expect_err("refused");
            assert!(err.len() < 512, "{} bytes", err.len());
        }
        let mut scope = RuleScope::any();
        scope.parent_exe = Some(PathBuf::from(format!("/{huge}")));
        let err = scope.reject_unmatchable_parent().expect_err("refused");
        assert!(err.len() < 512, "{} bytes", err.len());
    }
}
