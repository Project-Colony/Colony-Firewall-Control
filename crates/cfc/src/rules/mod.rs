//! `cfc rules ...`: id resolution and list/show/remove/enable here, one
//! file per other subcommand group.

mod add;
mod bundles;
mod catalog;
mod export;
mod opensnitch;

pub use add::{add, ActionArg, AddArgs};
pub use bundles::{bootstrap_defaults, bundle_add, bundle_list, bundle_remove};
pub use export::{export, import};
pub use opensnitch::import_opensnitch;

use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};
use cfc_client::{convert, proto, Client};
use export::{proto_rules_to_export, RuleDetail};

// ---------------------------------------------------------------------------
// Id / name resolution
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    /// More than one rule matched. Carries `(id, name)` for every
    /// candidate so the caller can print something actionable.
    Ambiguous(Vec<(String, String)>),
}

/// Finds the rule a user meant by `needle`.
///
/// Accepted, in order of decreasing specificity: the full id, an exact
/// name, a unique id prefix, a unique case-insensitive name. Typing 36
/// characters of UUID to toggle a rule is not ergonomics.
pub fn resolve_rule<'a>(
    rules: &'a [proto::RuleInfo],
    needle: &str,
) -> Result<&'a proto::RuleInfo, ResolveError> {
    if needle.is_empty() {
        return Err(ResolveError::NotFound);
    }

    if let Some(r) = rules.iter().find(|r| r.id == needle) {
        return Ok(r);
    }

    let exact_name: Vec<&proto::RuleInfo> = rules.iter().filter(|r| r.name == needle).collect();
    if let Some(one) = single(&exact_name) {
        return Ok(one);
    }
    if exact_name.len() > 1 {
        return Err(ambiguous(&exact_name));
    }

    let prefix: Vec<&proto::RuleInfo> = rules.iter().filter(|r| r.id.starts_with(needle)).collect();
    if let Some(one) = single(&prefix) {
        return Ok(one);
    }
    if prefix.len() > 1 {
        return Err(ambiguous(&prefix));
    }

    let lower = needle.to_lowercase();
    let by_name: Vec<&proto::RuleInfo> = rules
        .iter()
        .filter(|r| r.name.to_lowercase() == lower)
        .collect();
    if let Some(one) = single(&by_name) {
        return Ok(one);
    }
    if by_name.len() > 1 {
        return Err(ambiguous(&by_name));
    }

    Err(ResolveError::NotFound)
}

fn single<'a>(matches: &[&'a proto::RuleInfo]) -> Option<&'a proto::RuleInfo> {
    match matches {
        [only] => Some(only),
        _ => None,
    }
}

fn ambiguous(matches: &[&proto::RuleInfo]) -> ResolveError {
    ResolveError::Ambiguous(
        matches
            .iter()
            .map(|r| (r.id.clone(), r.name.clone()))
            .collect(),
    )
}

/// Resolution against the live daemon, with the CLI's exit-code mapping:
/// nothing matched is exit 3, an ambiguous match is a runtime error.
async fn resolve_via_daemon(
    client: &mut Client,
    needle: &str,
) -> Result<proto::RuleInfo, CliError> {
    let rules = client.list_rules().await?;
    match resolve_rule(&rules, needle) {
        Ok(r) => Ok(r.clone()),
        Err(ResolveError::NotFound) => Err(CliError::not_found(format!(
            "no rule matching {needle:?} (try an id, an id prefix, or a rule name)"
        ))),
        Err(ResolveError::Ambiguous(candidates)) => {
            let list = candidates
                .iter()
                .map(|(id, name)| format!("\n  {id}  {}", output::terminal_safe(name)))
                .collect::<String>();
            Err(CliError::runtime(format!(
                "{needle:?} matches {} rules:{list}",
                candidates.len()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub async fn list(client: &mut Client, format: OutputFormat) -> CliResult {
    let rules = client.list_rules().await?;
    if format.is_json() {
        return output::print_json(&proto_rules_to_export(&rules));
    }
    if rules.is_empty() {
        println!("(no rules)");
        return Ok(());
    }

    let name_w = rules
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, 32);
    println!(
        "{:<8}  {:<3}  {:<13}  {:>5}  {:<name_w$}  rule",
        "id", "on", "duration", "hits", "name"
    );
    for r in &rules {
        println!(
            "{:<8}  {:<3}  {:<13}  {:>5}  {:<name_w$}  {}",
            short_id(&r.id),
            if r.enabled { "yes" } else { "no" },
            convert::rule_duration_label(r),
            r.hit_count,
            output::truncate(&r.name, name_w),
            // Already display-safe.
            convert::rule_summary(r)
        );
    }
    Ok(())
}

pub async fn show(client: &mut Client, needle: &str, format: OutputFormat) -> CliResult {
    let rule = resolve_via_daemon(client, needle).await?;
    if format.is_json() {
        return output::print_json(&RuleDetail::from_proto(&rule));
    }
    let scope = rule.scope.clone().unwrap_or_default();
    let dash = |s: &str| {
        if s.is_empty() {
            "-".to_string()
        } else {
            output::terminal_safe(s)
        }
    };
    println!("id           {}", rule.id);
    println!("name         {}", output::terminal_safe(&rule.name));
    println!("enabled      {}", if rule.enabled { "yes" } else { "no" });
    println!("action       {}", convert::action_label(rule.action));
    println!("duration     {}", convert::rule_duration_label(&rule));
    println!(
        "created      {}",
        if rule.created_at_unix_ms > 0 {
            output::local_datetime(rule.created_at_unix_ms)
        } else {
            "-".into()
        }
    );
    println!("hits         {}", rule.hit_count);
    println!("summary      {}", convert::rule_summary(&rule));
    println!("scope:");
    // Not dashed when unset: an absent direction is not "unconstrained", it
    // means outbound (the matcher's contract - unset kept the meaning every
    // pre-inbound rule was written with). Printing "-" here made an inbound
    // rule indistinguishable from an outbound one in the only human-readable
    // detail view there is.
    println!(
        "  direction  {}",
        if scope.has_direction {
            convert::direction_label(scope.direction).to_string()
        } else {
            "out (unset)".into()
        }
    );
    println!("  exe        {}", dash(&scope.exe_path));
    println!("  sha256     {}", dash(&scope.exe_sha256));
    println!("  parent-exe {}", dash(&scope.parent_exe));
    println!(
        "  uid        {}",
        if scope.has_uid {
            scope.uid.to_string()
        } else {
            "-".into()
        }
    );
    println!("  src-net    {}", dash(&scope.src_net));
    println!(
        "  src-port   {}",
        if scope.has_src_port {
            scope.src_port.to_string()
        } else {
            "-".into()
        }
    );
    println!("  dst-host   {}", dash(&scope.dst_host));
    println!("  dst-net    {}", dash(&scope.dst_net));
    println!(
        "  dst-port   {}",
        if scope.has_dst_port {
            scope.dst_port.to_string()
        } else {
            "-".into()
        }
    );
    println!(
        "  protocol   {}",
        if scope.has_protocol {
            convert::protocol_label(scope.protocol).to_string()
        } else {
            "-".into()
        }
    );
    Ok(())
}

pub async fn remove(client: &mut Client, needle: &str, format: OutputFormat) -> CliResult {
    let (id, name) = match resolve_via_daemon(client, needle).await {
        Ok(rule) => (rule.id, rule.name),
        // A quarantined or unreadable row is never listed, so nothing
        // resolves to it, but the daemon deletes it by the full id the
        // journal names.
        Err(CliError::NotFound(_)) if uuid::Uuid::parse_str(needle).is_ok() => {
            (needle.to_string(), String::new())
        }
        Err(e) => return Err(e),
    };
    let deleted = client.delete_rule(&id).await?;
    if !deleted {
        // Either a race with another client or an id that was never there:
        // "not found" for the caller either way.
        return Err(CliError::not_found(format!("no rule with id {id}")));
    }
    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "deleted": true, "id": id, "name": name,
        }));
    }
    println!("deleted {} ({})", id, output::terminal_safe(&name));
    Ok(())
}

/// `enable` / `disable` / `toggle` share one path: read, decide the target
/// state, write only when it differs. Idempotent by construction.
pub async fn set_enabled(
    client: &mut Client,
    needle: &str,
    target: Option<bool>,
    format: OutputFormat,
) -> CliResult {
    let mut rule = resolve_via_daemon(client, needle).await?;
    let was = rule.enabled;
    let want = target.unwrap_or(!was);

    // No executable validation here: the path is the stored one, sent back
    // unchanged, and the daemon validates only new or changed paths. Checking
    // it again refused to disable a rule whose target became an alias.
    if want != was {
        rule.enabled = want;
        client.upsert_rule(rule.clone()).await?;
    }

    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "id": rule.id,
            "name": rule.name,
            "was_enabled": was,
            "enabled": want,
            "changed": want != was,
        }));
    }
    let label = |b: bool| if b { "enabled" } else { "disabled" };
    if want == was {
        println!(
            "{} ({}): already {}",
            rule.id,
            output::terminal_safe(&rule.name),
            label(was)
        );
    } else {
        println!(
            "{} ({}): {} -> {}",
            rule.id,
            output::terminal_safe(&rule.name),
            label(was),
            label(want)
        );
    }
    Ok(())
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    fn rule(id: &str, name: &str) -> proto::RuleInfo {
        proto::RuleInfo {
            duration_seconds: 0,
            id: id.to_string(),
            name: name.to_string(),
            enabled: true,
            action: proto::Action::Allow as i32,
            duration: proto::Duration::Always as i32,
            scope: Some(proto::RuleScope::default()),
            created_at_unix_ms: 0,
            hit_count: 0,
        }
    }

    fn sample() -> Vec<proto::RuleInfo> {
        vec![
            rule("1f0a5c7e-1111-4000-8000-000000000001", "allow-pacman"),
            rule("1f0a9999-2222-4000-8000-000000000002", "allow-ssh"),
            rule("abcd0000-3333-4000-8000-000000000003", "Allow-SSH-Alt"),
        ]
    }

    #[test]
    fn full_id_wins() {
        let rules = sample();
        let r = resolve_rule(&rules, "1f0a5c7e-1111-4000-8000-000000000001").unwrap();
        assert_eq!(r.name, "allow-pacman");
    }

    #[test]
    fn unique_prefix_resolves() {
        let rules = sample();
        assert_eq!(resolve_rule(&rules, "1f0a5").unwrap().name, "allow-pacman");
        assert_eq!(resolve_rule(&rules, "abcd").unwrap().name, "Allow-SSH-Alt");
    }

    #[test]
    fn ambiguous_prefix_lists_candidates() {
        let rules = sample();
        match resolve_rule(&rules, "1f0a") {
            Err(ResolveError::Ambiguous(c)) => {
                assert_eq!(c.len(), 2);
                assert!(c.iter().any(|(_, n)| n == "allow-pacman"));
                assert!(c.iter().any(|(_, n)| n == "allow-ssh"));
            }
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn exact_name_resolves() {
        let rules = sample();
        assert!(resolve_rule(&rules, "allow-pacman")
            .unwrap()
            .id
            .starts_with("1f0a5c7e"));
    }

    #[test]
    fn case_insensitive_name_is_a_last_resort() {
        let rules = sample();
        // "ALLOW-SSH-ALT" only matches case-insensitively.
        assert_eq!(
            resolve_rule(&rules, "ALLOW-SSH-ALT").unwrap().name,
            "Allow-SSH-Alt"
        );
    }

    #[test]
    fn exact_name_beats_a_case_insensitive_one() {
        let rules = vec![rule("aaaa1111", "Web"), rule("bbbb2222", "web")];
        assert_eq!(resolve_rule(&rules, "web").unwrap().id, "bbbb2222");
    }

    #[test]
    fn duplicate_names_are_ambiguous() {
        let rules = vec![rule("aaaa1111", "dup"), rule("bbbb2222", "dup")];
        assert!(matches!(
            resolve_rule(&rules, "dup"),
            Err(ResolveError::Ambiguous(_))
        ));
    }

    #[test]
    fn nothing_matching_is_not_found() {
        let rules = sample();
        assert_eq!(resolve_rule(&rules, "zzz"), Err(ResolveError::NotFound));
        assert_eq!(resolve_rule(&rules, ""), Err(ResolveError::NotFound));
        assert_eq!(resolve_rule(&[], "anything"), Err(ResolveError::NotFound));
    }

    #[test]
    fn short_ids_are_prefix_resolvable() {
        let rules = sample();
        let short = short_id(&rules[0].id);
        assert_eq!(short, "1f0a5c7e");
        // What `rules list` prints must be enough to act on.
        assert_eq!(resolve_rule(&rules, &short).unwrap().name, "allow-pacman");
        assert_eq!(short_id("abc"), "abc");
    }
}
