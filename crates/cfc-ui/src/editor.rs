//! The rule editor: its form state, how it is seeded (from a stored rule,
//! a prompt or an observed flow) and how a form becomes a rule to send.

use cfc_client::proto;

use crate::format;
use crate::i18n::{t, t_fmt};

#[derive(Debug, Clone)]
pub struct RuleEditor {
    /// Some when editing an existing rule, None when creating a new one.
    pub editing_id: Option<String>,
    pub prompt_id: Option<String>,
    pub prompt_hash_required: bool,
    pub duration_seconds: u32,
    pub name: String,
    pub action: proto::Action,
    pub duration: proto::Duration,
    pub exe: String,
    pub dst_host: String,
    pub dst_net: String,
    pub dst_port: String,
    pub protocol: Option<proto::Protocol>,
    pub validation: Option<String>,
    /// Metadata of the rule being edited, carried through untouched.
    ///
    /// `UpsertRule` overwrites the stored row wholesale, so emitting zeroes
    /// here would reset the creation date to now, drop the hit count and
    /// silently re-enable a rule the user had turned off. A brand-new rule
    /// keeps the defaults below and lets the daemon fill them in.
    pub created_at_unix_ms: i64,
    pub hit_count: u64,
    pub enabled: bool,
    /// The edited rule's scope, so the predicates this editor has no widget
    /// for are carried through untouched.
    ///
    /// `cfc rules add --uid`, an imported opensnitch ruleset, or a
    /// checksum-pinned rule can all set these. Rebuilding the scope from
    /// the visible fields alone would silently *widen* such a rule on
    /// save: a deny scoped to one uid would start matching every user,
    /// a sha256-pinned allow would lose its binary pin, and an inbound rule
    /// (unset direction means outbound) would turn outbound with its source
    /// scope gone. Its visible fields are stale once the form is edited, so
    /// only [`hidden_scope_is_set`], [`hidden_scope_summary`] and the
    /// unchanged-path check read it, and saving overwrites them from the form.
    pub carried_scope: proto::RuleScope,
}

/// True when `scope` carries a constraint the editor cannot show, so the view
/// can tell the user rather than let them assume the visible fields are the
/// whole rule.
pub fn hidden_scope_is_set(scope: &proto::RuleScope) -> bool {
    scope.has_uid
        || !scope.exe_sha256.is_empty()
        || !scope.parent_exe.is_empty()
        || scope.has_direction
        || !scope.src_net.is_empty()
        || scope.has_src_port
}

/// One-line human summary of the hidden predicates, for that notice.
pub fn hidden_scope_summary(scope: &proto::RuleScope) -> String {
    let mut parts = Vec::new();
    if scope.has_direction {
        parts.push(
            t(match proto::Direction::try_from(scope.direction) {
                Ok(proto::Direction::Inbound) => "scope_inbound",
                Ok(proto::Direction::Outbound) => "scope_outbound",
                _ => "scope_direction_unknown",
            })
            .to_string(),
        );
    }
    if !scope.src_net.is_empty() {
        parts.push(t_fmt("scope_from", &[("net", &scope.src_net)]));
    }
    if scope.has_src_port {
        parts.push(t_fmt(
            "scope_src_port",
            &[("port", &scope.src_port.to_string())],
        ));
    }
    if scope.has_uid {
        parts.push(t_fmt("scope_uid", &[("uid", &scope.uid.to_string())]));
    }
    if !scope.parent_exe.is_empty() {
        parts.push(t_fmt("scope_parent", &[("exe", &scope.parent_exe)]));
    }
    if !scope.exe_sha256.is_empty() {
        let short: String = scope.exe_sha256.chars().take(12).collect();
        parts.push(t_fmt("scope_sha256", &[("digest", &short)]));
    }
    parts.join(", ")
}

impl Default for RuleEditor {
    fn default() -> Self {
        Self {
            editing_id: None,
            prompt_id: None,
            prompt_hash_required: false,
            duration_seconds: 0,
            name: String::new(),
            action: proto::Action::Allow,
            duration: proto::Duration::Always,
            exe: String::new(),
            dst_host: String::new(),
            dst_net: String::new(),
            dst_port: String::new(),
            protocol: None,
            validation: None,
            created_at_unix_ms: 0,
            hit_count: 0,
            enabled: true,
            carried_scope: proto::RuleScope::default(),
        }
    }
}

impl RuleEditor {
    pub fn from_existing(rule: &proto::RuleInfo) -> Self {
        let scope = rule.scope.as_ref();
        let protocol = scope
            .and_then(|s| s.has_protocol.then_some(s.protocol))
            .and_then(|p| proto::Protocol::try_from(p).ok())
            .filter(|p| !matches!(p, proto::Protocol::Unspecified));
        Self {
            editing_id: Some(rule.id.clone()),
            prompt_id: None,
            prompt_hash_required: false,
            duration_seconds: rule.duration_seconds,
            name: rule.name.clone(),
            action: proto::Action::try_from(rule.action).unwrap_or(proto::Action::Allow),
            duration: proto::Duration::try_from(rule.duration).unwrap_or(proto::Duration::Always),
            exe: scope.map(|s| s.exe_path.clone()).unwrap_or_default(),
            dst_host: scope.map(|s| s.dst_host.clone()).unwrap_or_default(),
            dst_net: scope.map(|s| s.dst_net.clone()).unwrap_or_default(),
            dst_port: scope
                .and_then(|s| s.has_dst_port.then_some(s.dst_port))
                .map(|p| p.to_string())
                .unwrap_or_default(),
            protocol,
            validation: None,
            created_at_unix_ms: rule.created_at_unix_ms,
            hit_count: rule.hit_count,
            enabled: rule.enabled,
            carried_scope: scope.cloned().unwrap_or_default(),
        }
    }

    /// Seeds the editor from a pending prompt ("Customize this rule before
    /// creating it").
    ///
    /// The connection remains pending until Save submits an explicit verdict,
    /// or the daemon applies its timeout policy. In that second case the
    /// editor stays open as a new rule (see `App::detach_orphaned_editor`).
    pub fn from_prompt(ev: &proto::PromptEvent) -> Self {
        let exe = ev
            .process
            .as_ref()
            .map(|p| p.exe.as_str())
            .unwrap_or_default();
        let (src_ip, dst_ip, dst_port, protocol, direction) = match ev.connection.as_ref() {
            Some(c) => (
                c.src_ip.as_str(),
                c.dst_ip.as_str(),
                c.dst_port,
                c.protocol,
                c.direction,
            ),
            None => ("", "", 0, 0, 0),
        };
        let mut editor = Self::from_observed(exe, src_ip, dst_ip, dst_port, protocol, direction);
        editor.prompt_id = Some(ev.prompt_id.clone());
        editor.prompt_hash_required = ev.binds_to_hash;
        if ev.binds_to_hash {
            editor.carried_scope.exe_sha256 = ev
                .process
                .as_ref()
                .map(|p| p.sha256.clone())
                .unwrap_or_default();
        }
        editor
    }

    /// Seeds the editor from an observed flow (live feed "make rule", and
    /// a prompt's "Customize").
    ///
    /// When the executable can scope a rule, the seed is that program on
    /// that port and protocol, the same scope `cfc rules add --exe
    /// --dst-port --protocol` builds. Pinning the one address seen made a
    /// rule the next connection of the same service, to another CDN address
    /// or over IPv6, did not match, so the app stayed denied after "make
    /// rule" while the CLI rule worked (#46). The user can still type an
    /// address into the destination field.
    ///
    /// Otherwise the placeholder for an unidentified process is never
    /// seeded, since a rule on it is refused, and the numeric endpoint is
    /// pinned instead so the rule does not cover the whole port. DNS names
    /// stay diagnostic.
    ///
    /// An inbound flow keeps its direction (without it the rule would be an
    /// outbound one to our own address) and pins the one peer seen as its
    /// source. Inbound, the destination is this machine, which the daemon
    /// refuses as a scope, and the editor has no source field: a seed on our
    /// own address could not be saved, and clearing it opened the port to
    /// every peer.
    pub fn from_observed(
        exe: &str,
        src_ip: &str,
        dst_ip: &str,
        dst_port: u32,
        protocol: i32,
        direction: i32,
    ) -> Self {
        let protocol = proto::Protocol::try_from(protocol)
            .ok()
            .filter(|p| !matches!(p, proto::Protocol::Unspecified));
        let inbound = direction == proto::Direction::Inbound as i32;
        // Inbound flows are never attributed to a program.
        let scopable = !inbound && cfc_client::convert::exe_is_rule_scopable(exe);
        Self {
            name: String::new(),
            exe: if scopable {
                exe.to_string()
            } else {
                String::new()
            },
            dst_host: String::new(),
            dst_net: if scopable || inbound {
                String::new()
            } else {
                format::host_cidr(dst_ip)
            },
            dst_port: if dst_port == 0 {
                String::new()
            } else {
                dst_port.to_string()
            },
            protocol,
            carried_scope: proto::RuleScope {
                direction: if inbound { direction } else { 0 },
                has_direction: inbound,
                src_net: if inbound {
                    format::host_cidr(src_ip)
                } else {
                    String::new()
                },
                ..Default::default()
            },
            ..Self::default()
        }
    }
}

/// `"rule saved: allow /usr/bin/curl -> *:443 tcp, always"`.
pub fn saved_rule_line(rule: &proto::RuleInfo) -> String {
    use cfc_client::convert;
    let summary = convert::rule_summary(rule)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let key = if rule.enabled {
        "log_rule_saved"
    } else {
        "log_rule_saved_disabled"
    };
    t_fmt(
        key,
        &[
            ("summary", &summary),
            ("duration", &format::duration_label(rule)),
        ],
    )
}

pub fn build_rule_from_editor(ed: &RuleEditor) -> Result<proto::RuleInfo, String> {
    let name = if ed.name.trim().is_empty() {
        "ui-added".to_string()
    } else {
        ed.name.trim().to_string()
    };

    cfc_core::RuleScope {
        dst_host: (!ed.dst_host.is_empty()).then(|| ed.dst_host.clone()),
        ..cfc_core::RuleScope::any()
    }
    .reject_hostname_policy()?;

    let dst_port = if ed.dst_port.trim().is_empty() {
        None
    } else {
        Some(
            ed.dst_port
                .trim()
                .parse::<u16>()
                .map_err(|_| t_fmt("error_port", &[("port", &ed.dst_port)]))?,
        )
    };

    let dst_net = ed.dst_net.trim();
    if !dst_net.is_empty() {
        dst_net
            .parse::<ipnet::IpNet>()
            .map_err(|e| t_fmt("error_dst_net", &[("error", &e.to_string())]))?;
    }

    // The daemon rejects a persisted Once rule outright; catch it here so
    // the user gets a sentence instead of a gRPC status.
    if matches!(
        ed.duration,
        proto::Duration::Once | proto::Duration::Unspecified
    ) {
        return Err(t("error_saved_duration").into());
    }

    if ed.duration == proto::Duration::Seconds
        && (ed.duration_seconds == 0 || ed.editing_id.is_none() || ed.prompt_id.is_some())
    {
        return Err(t("error_timed").into());
    }

    if ed.prompt_hash_required
        && ed.action == proto::Action::Allow
        && ed.carried_scope.exe_sha256.is_empty()
    {
        return Err(t("error_hash_required").into());
    }

    // Need at least one scope predicate, else the rule would match
    // everything. Carried predicates count: a uid-only rule created from
    // the CLI is narrow, and refusing to save it would make it uneditable.
    let scope_empty = ed.exe.trim().is_empty()
        && ed.dst_host.trim().is_empty()
        && dst_net.is_empty()
        && dst_port.is_none()
        && ed.protocol.is_none()
        && !hidden_scope_is_set(&ed.carried_scope);
    if scope_empty {
        return Err(t("error_scope_empty").into());
    }

    // Validate in the user's namespace as well as the daemon's: ProtectHome
    // and PrivateTmp hide exactly the paths a person commonly enters.
    // Not trimmed: a file name may end in a space, and saving a rule for
    // "/opt/app " must not quietly retarget it to "/opt/app".
    // An edited rule's unchanged path is sent back as stored, as the daemon
    // expects: it may have become an alias since, and refusing it here left
    // such a rule impossible to rename or retarget anywhere but the CLI.
    let typed = ed.exe.as_str();
    let exe = if typed.trim().is_empty() {
        String::new()
    } else if ed.editing_id.is_some() && typed == ed.carried_scope.exe_path {
        typed.to_string()
    } else {
        cfc_core::exe_path::resolve_policy(std::path::Path::new(typed))?
            .into_path()
            .to_string_lossy()
            .into_owned()
    };

    // Every field this form shows is rebuilt from it; everything else is
    // carried, so a predicate the editor cannot show is never dropped and the
    // rule never widens on save.
    let scope = proto::RuleScope {
        exe_path: exe,
        dst_host: ed.dst_host.trim().to_string(),
        dst_net: dst_net.to_string(),
        dst_port: dst_port.map(u32::from).unwrap_or(0),
        has_dst_port: dst_port.is_some(),
        protocol: ed.protocol.map(|p| p as i32).unwrap_or(0),
        has_protocol: ed.protocol.is_some(),
        ..ed.carried_scope.clone()
    };

    Ok(proto::RuleInfo {
        id: ed.editing_id.clone().unwrap_or_default(),
        name,
        // Carried from the edited rule (defaults for a new one) - see
        // RuleEditor: the daemon replaces the whole row with this message.
        enabled: ed.enabled,
        action: ed.action as i32,
        duration: ed.duration as i32,
        duration_seconds: ed.duration_seconds,
        scope: Some(scope),
        created_at_unix_ms: ed.created_at_unix_ms,
        hit_count: ed.hit_count,
    })
}

/// The rule to send for an enable/disable toggle: exactly what the daemon
/// last reported, with only `enabled` flipped. Anything reconstructed here
/// would write the UI's stale view of `hit_count` / `created_at` back over
/// the daemon's own.
pub fn toggled_rule(rule: &proto::RuleInfo) -> proto::RuleInfo {
    proto::RuleInfo {
        enabled: !rule.enabled,
        ..rule.clone()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn editor_with_scope() -> RuleEditor {
        RuleEditor {
            exe: "/usr/bin/curl".into(),
            ..RuleEditor::default()
        }
    }

    #[test]
    fn editor_rejects_a_persisted_once_rule() {
        let mut ed = editor_with_scope();
        ed.duration = proto::Duration::Once;
        let err = build_rule_from_editor(&ed).unwrap_err();
        assert!(err.contains("Until restart"), "{err}");
    }

    #[test]
    fn editing_a_timed_rule_preserves_its_exact_lifetime() {
        let mut rule = existing_rule();
        rule.duration = proto::Duration::Seconds as i32;
        rule.duration_seconds = 90;
        let mut editor = RuleEditor::from_existing(&rule);
        let saved = build_rule_from_editor(&editor).unwrap();
        assert_eq!(saved.duration, rule.duration);
        assert_eq!(saved.duration_seconds, 90);
        editor.duration_seconds = 0;
        assert!(build_rule_from_editor(&editor).is_err());
        editor.duration_seconds = 90;
        editor.prompt_id = Some("pending".into());
        assert!(build_rule_from_editor(&editor).is_err());
    }

    #[test]
    fn editor_requires_at_least_one_predicate() {
        let ed = RuleEditor::default();
        assert!(build_rule_from_editor(&ed).is_err());
    }

    #[test]
    fn editor_refuses_hostname_policy_without_dropping_it() {
        let mut ed = editor_with_scope();
        ed.dst_host = "example.org".into();
        assert!(build_rule_from_editor(&ed).is_err());
        assert_eq!(ed.dst_host, "example.org");
        ed.dst_host.clear();
        ed.dst_net = "2001:db8::1/128".into();
        assert!(build_rule_from_editor(&ed).is_ok());
    }

    #[test]
    fn editor_keeps_an_executable_path_verbatim() {
        let mut ed = editor_with_scope();
        ed.exe = "/usr/bin/cfc-test-app ".into();
        let rule = build_rule_from_editor(&ed).unwrap();
        assert_eq!(rule.scope.unwrap().exe_path, "/usr/bin/cfc-test-app ");
    }

    #[test]
    fn editor_builds_a_persistable_rule() {
        let rule = build_rule_from_editor(&editor_with_scope()).unwrap();
        assert_eq!(rule.duration, proto::Duration::Always as i32);
        assert_eq!(rule.scope.unwrap().exe_path, "/usr/bin/curl");
    }

    #[test]
    fn editor_sends_an_unchanged_alias_back_but_refuses_a_typed_one() {
        // /proc/self/exe is a symlink on every Linux, so it stands in for a
        // stored path that has since become an alias.
        let mut rule = existing_rule();
        rule.scope.as_mut().unwrap().exe_path = "/proc/self/exe".into();
        let mut ed = RuleEditor::from_existing(&rule);
        ed.name = "renamed".into();
        let saved = build_rule_from_editor(&ed).expect("unchanged path is kept");
        assert_eq!(saved.scope.unwrap().exe_path, "/proc/self/exe");

        let mut fresh = editor_with_scope();
        fresh.exe = "/proc/self/exe".into();
        assert!(build_rule_from_editor(&fresh).is_err());
    }

    #[test]
    fn observed_seed_scopes_by_program_or_pins_the_endpoint_without_one() {
        let ed = RuleEditor::from_observed("/bin/x", "", "1.2.3.4", 443, 1, 0);
        assert_eq!(ed.exe, "/bin/x");
        assert!(ed.dst_host.is_empty());
        assert!(
            ed.dst_net.is_empty(),
            "a program rule is not pinned to one address"
        );
        assert_eq!(ed.dst_port, "443");

        for exe in [cfc_client::convert::UNKNOWN_EXE, ""] {
            let ed = RuleEditor::from_observed(exe, "", "2001:db8::1", 0, 0, 0);
            assert!(ed.exe.is_empty(), "{exe:?} is never seeded");
            assert_eq!(ed.dst_net, "2001:db8::1/128");
            assert!(ed.dst_port.is_empty());
            assert!(ed.protocol.is_none());
        }

        // Inbound: the peer seen, never our own address, which the daemon
        // refuses as an inbound scope.
        let inbound = proto::Direction::Inbound as i32;
        let ed = RuleEditor::from_observed(
            cfc_client::convert::UNKNOWN_EXE,
            "192.168.1.20",
            "10.0.0.2",
            8384,
            1,
            inbound,
        );
        let scope = build_rule_from_editor(&ed).unwrap().scope.unwrap();
        assert!(scope.has_direction);
        assert_eq!(scope.direction, inbound);
        assert_eq!(scope.src_net, "192.168.1.20/32");
        assert!(scope.dst_net.is_empty());
        assert!(scope.exe_path.is_empty());
        assert_eq!(scope.dst_port, 8384);
    }

    #[test]
    fn a_saved_rule_is_described_by_its_stored_scope() {
        let rule = proto::RuleInfo {
            action: proto::Action::Allow as i32,
            duration: proto::Duration::Always as i32,
            enabled: true,
            scope: Some(proto::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                dst_port: 443,
                has_dst_port: true,
                protocol: proto::Protocol::Tcp as i32,
                has_protocol: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let line = saved_rule_line(&rule);
        assert!(
            line.starts_with("rule saved: allow /usr/bin/curl -> *:443 tcp"),
            "{line}"
        );
    }

    /// A rule as the daemon reports it: created a while ago, already hit,
    /// and deliberately switched off by the user.
    fn existing_rule() -> proto::RuleInfo {
        proto::RuleInfo {
            id: "rule-1".into(),
            name: "let curl out".into(),
            enabled: false,
            action: proto::Action::Deny as i32,
            duration: proto::Duration::Always as i32,
            scope: Some(proto::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                dst_port: 443,
                has_dst_port: true,
                ..Default::default()
            }),
            created_at_unix_ms: 1_700_000_000_000,
            hit_count: 42,
            duration_seconds: 0,
        }
    }

    /// A rule narrowed by predicates the editor has no widget for - the
    /// shape `cfc rules add --uid` and opensnitch imports produce.
    fn rule_with_hidden_scope() -> proto::RuleInfo {
        proto::RuleInfo {
            scope: Some(proto::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                exe_sha256: "abc123def456abc123def456abc123def456abc123def456".into(),
                parent_exe: "/usr/bin/bash".into(),
                uid: 1000,
                has_uid: true,
                ..Default::default()
            }),
            ..existing_rule()
        }
    }

    #[test]
    fn editing_keeps_scope_predicates_the_editor_cannot_show() {
        // Dropping these would WIDEN the rule: a deny scoped to one uid
        // would start matching every user on the host, and a checksum-
        // pinned allow would lose its binary pin.
        let original = rule_with_hidden_scope();
        let mut ed = RuleEditor::from_existing(&original);
        ed.dst_port = "8443".into(); // the user changes only the port

        let sent = build_rule_from_editor(&ed).expect("valid");
        let scope = sent.scope.expect("scope");
        let orig = original.scope.unwrap();
        assert_eq!(scope.uid, orig.uid);
        assert!(scope.has_uid);
        assert_eq!(scope.exe_sha256, orig.exe_sha256);
        assert_eq!(scope.parent_exe, orig.parent_exe);
        assert_eq!(scope.dst_port, 8443, "the intended edit still applies");
    }

    #[test]
    fn a_rule_scoped_only_by_hidden_predicates_is_still_editable() {
        // Validation must count carried predicates, else a uid-only rule
        // could never be saved from the GUI at all.
        let uid_only = proto::RuleInfo {
            scope: Some(proto::RuleScope {
                uid: 1000,
                has_uid: true,
                ..Default::default()
            }),
            ..existing_rule()
        };
        let ed = RuleEditor::from_existing(&uid_only);
        assert!(hidden_scope_is_set(&ed.carried_scope));
        assert!(build_rule_from_editor(&ed).is_ok());

        // A genuinely empty scope is still refused.
        let empty = RuleEditor {
            name: "everything".into(),
            ..RuleEditor::default()
        };
        assert!(build_rule_from_editor(&empty).is_err());
    }

    #[test]
    fn hidden_scope_summary_names_each_predicate() {
        let ed = RuleEditor::from_existing(&rule_with_hidden_scope());
        let summary = hidden_scope_summary(&ed.carried_scope);
        assert!(summary.contains("uid 1000"), "{summary}");
        assert!(summary.contains("/usr/bin/bash"), "{summary}");
        assert!(summary.contains("sha256 abc123def456"), "{summary}");
        assert!(!hidden_scope_is_set(&proto::RuleScope::default()));
    }

    #[test]
    fn editing_a_rule_preserves_its_metadata() {
        let original = existing_rule();
        let mut ed = RuleEditor::from_existing(&original);
        // The user changes one field and saves.
        ed.dst_port = "8443".into();

        let rebuilt = build_rule_from_editor(&ed).unwrap();
        assert_eq!(rebuilt.id, original.id);
        assert_eq!(
            rebuilt.created_at_unix_ms, original.created_at_unix_ms,
            "editing must not reset the creation date"
        );
        assert_eq!(
            rebuilt.hit_count, original.hit_count,
            "editing must not zero the hit count"
        );
        assert!(
            !rebuilt.enabled,
            "editing must not re-enable a rule the user disabled"
        );
        assert_eq!(rebuilt.scope.unwrap().dst_port, 8443);
    }

    #[test]
    fn a_new_rule_starts_with_empty_metadata() {
        let rule = build_rule_from_editor(&editor_with_scope()).unwrap();
        assert!(rule.id.is_empty(), "the daemon assigns the id");
        assert_eq!(rule.created_at_unix_ms, 0, "the daemon stamps the creation");
        assert_eq!(rule.hit_count, 0);
        assert!(rule.enabled);
    }

    #[test]
    fn a_rule_seeded_from_an_observed_flow_is_new() {
        let ed = RuleEditor::from_observed("/bin/x", "", "1.2.3.4", 443, 1, 0);
        assert_eq!(ed.created_at_unix_ms, 0);
        assert_eq!(ed.hit_count, 0);
        assert!(ed.enabled);
        assert!(ed.editing_id.is_none());
    }

    #[test]
    fn toggling_enabled_changes_nothing_else() {
        let original = existing_rule();
        let toggled = toggled_rule(&original);
        assert!(toggled.enabled);
        assert_eq!(
            toggled,
            proto::RuleInfo {
                enabled: true,
                ..original.clone()
            },
            "the toggle must round-trip the rule as received"
        );
        // Toggling twice is a no-op: no hit count drift per click.
        assert_eq!(toggled_rule(&toggled), original);
    }

    pub(crate) fn prompt_event() -> proto::PromptEvent {
        proto::PromptEvent {
            prompt_id: "p1".into(),
            connection: Some(proto::ConnectionInfo {
                protocol: proto::Protocol::Tcp as i32,
                dst_ip: "93.184.216.34".into(),
                dst_port: 443,
                dst_host: "example.com".into(),
                ..Default::default()
            }),
            process: Some(proto::ProcessInfo {
                exe: "/usr/bin/curl".into(),
                ..Default::default()
            }),
            deadline_unix_ms: 1_700_000_015_000,
            binds_to_hash: false,
            undecided_rule_id: String::new(),
        }
    }

    #[test]
    fn customization_cannot_save_an_allow_without_its_required_hash() {
        let mut event = prompt_event();
        event.binds_to_hash = true;
        let mut editor = RuleEditor::from_prompt(&event);
        assert!(build_rule_from_editor(&editor).is_err());
        editor.action = proto::Action::Deny;
        assert!(build_rule_from_editor(&editor).is_ok());
    }

    #[test]
    fn customizing_a_prompt_preserves_the_promised_digest() {
        let mut event = prompt_event();
        event.binds_to_hash = true;
        event.process.as_mut().unwrap().sha256 = "a".repeat(64);
        let editor = RuleEditor::from_prompt(&event);
        assert_eq!(
            build_rule_from_editor(&editor)
                .unwrap()
                .scope
                .unwrap()
                .exe_sha256,
            "a".repeat(64)
        );
    }

    #[test]
    fn customizing_a_prompt_seeds_a_new_rule_from_it() {
        let ed = RuleEditor::from_prompt(&prompt_event());
        assert_eq!(ed.exe, "/usr/bin/curl");
        assert!(ed.dst_host.is_empty());
        assert!(ed.dst_net.is_empty());
        assert_eq!(ed.dst_port, "443");
        assert_eq!(ed.protocol, Some(proto::Protocol::Tcp));
        // It is a new rule, not an edit of an existing one.
        assert!(ed.editing_id.is_none());
        assert_eq!(ed.created_at_unix_ms, 0);
        // Whatever the user saves has to be persistable, so it must not
        // inherit the prompt's one-off semantics.
        assert_eq!(ed.duration, proto::Duration::Always);
        assert!(build_rule_from_editor(&ed).is_ok());
    }

    #[test]
    fn customizing_an_empty_prompt_does_not_seed_a_match_everything_rule() {
        let ed = RuleEditor::from_prompt(&proto::PromptEvent::default());
        assert!(ed.exe.is_empty());
        assert!(ed.dst_host.is_empty());
        assert!(ed.dst_net.is_empty());
        assert!(ed.protocol.is_none());
        // Nothing to scope on, so saving is refused rather than silently
        // writing a rule that matches every program.
        assert!(build_rule_from_editor(&ed).is_err());
    }
}
