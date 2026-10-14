//! `cfc rules export` / `import` and the JSON rule format they share with
//! `rules list --json` and `rules show --json`.

use crate::error::CliResult;
use crate::output::{self, OutputFormat};
use anyhow::Context;
use cfc_client::{convert, proto, Client};
use std::path::PathBuf;

pub async fn export(client: &mut Client, out: Option<PathBuf>) -> CliResult {
    let rules = client.list_rules().await?;
    let json =
        serde_json::to_string_pretty(&proto_rules_to_export(&rules)).context("serialising JSON")?;
    match out {
        Some(path) => {
            std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        }
        None => println!("{json}"),
    }
    Ok(())
}

pub async fn import(
    client: &mut Client,
    file: Option<PathBuf>,
    replace: bool,
    format: OutputFormat,
) -> CliResult {
    let json = match file {
        Some(p) => {
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?
        }
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading stdin")?;
            buf
        }
    };

    let rules: Vec<ExportedRule> = serde_json::from_str(&json).context("parsing JSON")?;

    // Parse and validate the complete file before the atomic server-side batch.
    let stored = client.list_rules().await?;
    let mut pending = Vec::with_capacity(rules.len());
    let mut problems = Vec::new();
    let mut seen_ids: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for r in rules {
        match r.try_into_proto() {
            Ok(pb) => {
                if let Err(e) = check_new_exe(&pb, &stored) {
                    problems.push(e);
                    continue;
                }
                // Two rules sharing an id are not two rules: the second upsert
                // overwrites the first, so the file describes a state the
                // import cannot produce and the count printed at the end is
                // higher than what the daemon ends up holding. Under --replace
                // the operator also loses a rule they believe they imported.
                if !pb.id.is_empty() {
                    // `try_into_proto` canonicalised it, so equal ids are equal
                    // strings here whatever the file spelled.
                    //
                    // `entry` rather than `insert`: with three rules sharing an
                    // id, insert would overwrite the stored name each round and
                    // the third message would name the second - a rule that was
                    // itself rejected and never imported.
                    let key = pb.id.clone();
                    if let Some(first) = seen_ids.get(&key) {
                        let first = first.clone();
                        problems.push(format!(
                            "rules `{first}` and `{}` share the id `{}`; each rule \
                             needs its own, or an empty one to be assigned a new id",
                            pb.name, pb.id
                        ));
                        continue;
                    }
                    seen_ids.insert(key, pb.name.clone());
                }
                pending.push(pb)
            }
            Err(e) => problems.push(e),
        }
    }
    if !problems.is_empty() {
        // Every problem, not just the first: an operator fixing an export by
        // hand should learn about all of them in one pass.
        for p in &problems {
            eprintln!("  {}", output::terminal_safe(p));
        }
        return Err(anyhow::anyhow!(
            "{} of {} rules could not be read; nothing was changed",
            problems.len(),
            problems.len() + pending.len()
        )
        .into());
    }

    // An empty file is almost never what someone means by "replace my rules
    // with this", and against a fail-closed ruleset the consequence of being
    // wrong is the whole machine's outbound network. `--replace` with nothing
    // to import is refused; deleting every rule has its own command.
    if replace && pending.is_empty() {
        return Err(anyhow::anyhow!(
            "refusing --replace with an empty rule set: that would delete every \
             rule and leave the machine filtering with none. Remove --replace to \
             import nothing, or delete rules explicitly."
        )
        .into());
    }

    let response = client
        .apply_rules(pending, replace)
        .await
        .context("import refused; no rules were changed")?;
    let imported = response.ids.len();
    let removed = response.removed;

    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "imported": imported,
            "removed": removed,
        }));
    }
    if replace {
        println!("imported {imported} rules, removed {removed} that were not in the file");
    } else {
        println!("imported {imported} rules");
    }
    Ok(())
}

/// Validates an imported rule's executable path in the caller's namespace,
/// where `ProtectHome` and `PrivateTmp` hide nothing, before the daemon does
/// in its own.
///
/// A rule that sends back the path already stored under its id is left alone,
/// as the daemon leaves it: that path may have become an alias since it was
/// written, and refusing it made a `--replace` restore of an export fail for
/// as long as such a rule existed.
fn check_new_exe(rule: &proto::RuleInfo, stored: &[proto::RuleInfo]) -> Result<(), String> {
    let Some(exe) = rule
        .scope
        .as_ref()
        .map(|scope| scope.exe_path.as_str())
        .filter(|exe| !exe.is_empty())
    else {
        return Ok(());
    };
    let kept = !rule.id.is_empty()
        && stored
            .iter()
            .any(|old| old.id == rule.id && old.scope.as_ref().is_some_and(|s| s.exe_path == exe));
    if kept {
        return Ok(());
    }
    cfc_core::exe_path::resolve_policy(std::path::Path::new(exe))
        .map(drop)
        .map_err(|error| format!("rule `{}`: {error}", rule.name))
}

// ---------------------------------------------------------------------------
// Export / import format
// ---------------------------------------------------------------------------

/// Format for `cfc rules export` / `import` and `rules list --json`.
/// Wire-compatible with the in-process Rule type but stable across daemon
/// versions.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedRule {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub action: String,
    #[serde(default = "default_duration")]
    pub duration: String,
    #[serde(default)]
    pub duration_seconds: u32,
    /// When a `seconds` rule runs out. Without it a restored backup started
    /// the full lifetime again, so an expired temporary Allow came back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<i64>,
    #[serde(default)]
    pub scope: ExportedScope,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedScope {
    #[serde(default)]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub exe_sha256: Option<String>,
    #[serde(default)]
    pub parent_exe: Option<String>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub dst_host: Option<String>,
    #[serde(default)]
    pub dst_net: Option<String>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<String>,
    /// "in" or "out". Absent retains the historical outbound meaning.
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub src_net: Option<String>,
    #[serde(default)]
    pub src_port: Option<u16>,
}

/// `rules show --json`: the export shape plus the read-only bookkeeping
/// fields, which import must never carry.
#[derive(Debug, serde::Serialize)]
pub struct RuleDetail {
    #[serde(flatten)]
    pub rule: ExportedRule,
    pub hit_count: u64,
    pub created_at_unix_ms: i64,
    pub created_at: Option<String>,
    pub summary: String,
}

impl RuleDetail {
    pub fn from_proto(r: &proto::RuleInfo) -> Self {
        Self {
            rule: exported_rule(r),
            hit_count: r.hit_count,
            created_at_unix_ms: r.created_at_unix_ms,
            created_at: output::rfc3339(r.created_at_unix_ms),
            summary: convert::rule_summary(r),
        }
    }
}

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_duration() -> String {
    "always".to_string()
}

impl ExportedRule {
    /// Converts one imported rule, **refusing** anything it does not recognise.
    ///
    /// This used to be `into_proto`, and every one of its three string matches
    /// ended in `_ =>` a permissive default - most seriously
    /// `_ => proto::Action::Allow`. A typo (`block`, `denied`), a truncated
    /// file, or a rule exported by a newer version therefore imported as an
    /// **allow**. It was the only string-to-enum mapping in the product that
    /// did not fail closed, and it sat on the path an operator uses to restore
    /// rules after an incident - the moment they can least afford it.
    ///
    /// The daemon now rejects an unspecified protocol too (`convert.rs`), so
    /// this is the outer of two gates rather than the only one; it exists to
    /// name the offending rule and field, which the wire error cannot.
    pub fn try_into_proto(self) -> Result<proto::RuleInfo, String> {
        let name = self.name.clone();
        let bad = |field: &str, value: &str, allowed: &str| {
            format!("rule `{name}`: unknown {field} `{value}` (expected one of: {allowed})")
        };

        let action = match self.action.to_ascii_lowercase().as_str() {
            "allow" => proto::Action::Allow,
            "deny" => proto::Action::Deny,
            "reject" => proto::Action::Reject,
            other => return Err(bad("action", other, "allow, deny, reject")),
        };
        for (field, value) in [
            ("exe_path", self.scope.exe_path.as_deref()),
            ("exe_sha256", self.scope.exe_sha256.as_deref()),
            ("parent_exe", self.scope.parent_exe.as_deref()),
            ("dst_host", self.scope.dst_host.as_deref()),
            ("dst_net", self.scope.dst_net.as_deref()),
            ("src_net", self.scope.src_net.as_deref()),
        ] {
            if value.is_some_and(|value| value.trim().is_empty()) {
                return Err(format!("rule `{name}`: {field} is present but empty"));
            }
        }
        cfc_core::RuleScope {
            dst_host: self.scope.dst_host.clone(),
            ..cfc_core::RuleScope::any()
        }
        .reject_hostname_policy()
        .map_err(|e| format!("rule `{name}`: {e}"))?;
        let duration = match self.duration.to_ascii_lowercase().as_str() {
            "always" => proto::Duration::Always,
            "seconds" if self.duration_seconds > 0 => proto::Duration::Seconds,
            "once" => proto::Duration::Once,
            "until-restart" | "until_restart" => proto::Duration::UntilRestart,
            other => return Err(bad("duration", other, "always, once, until-restart")),
        };
        if duration != proto::Duration::Seconds && self.duration_seconds != 0 {
            return Err(format!(
                "rule `{name}`: duration_seconds requires duration `seconds`"
            ));
        }
        // The daemon keeps a past creation time, so the rule ends when the
        // exported one did; one already past is stored expired.
        let created_at_unix_ms = match self.expires_at_unix_ms {
            None => 0,
            Some(_) if duration != proto::Duration::Seconds => {
                return Err(format!(
                    "rule `{name}`: expires_at_unix_ms requires duration `seconds`"
                ))
            }
            Some(at) => at
                .saturating_sub(i64::from(self.duration_seconds) * 1000)
                .max(1),
        };
        let direction_idx = match self.scope.direction.as_deref() {
            None => None,
            Some(d) => Some(match d.to_ascii_lowercase().as_str() {
                "out" | "outbound" => proto::Direction::Outbound as i32,
                "in" | "inbound" => proto::Direction::Inbound as i32,
                other => return Err(bad("direction", other, "in, out")),
            }),
        };
        if let Some(net) = self.scope.src_net.as_deref() {
            net.parse::<ipnet::IpNet>()
                .map_err(|e| format!("rule `{name}`: bad src_net `{net}`: {e}"))?;
        }
        // The same trap the daemon rejects, caught here so the message can name
        // the rule in a 200-line file.
        if direction_idx == Some(proto::Direction::Inbound as i32)
            && (self.scope.dst_net.is_some() || self.scope.dst_host.is_some())
        {
            return Err(format!(
                "rule `{name}`: an inbound rule cannot be scoped on dst_net or \
                 dst_host - inbound, the destination is this machine. Use \
                 src_net for the peer."
            ));
        }
        // Same trap, program-shaped: inbound flows are never attributed to a
        // process, so a program-scoped inbound rule can never fire. The
        // daemon refuses it; refused here first so the message names the rule.
        if direction_idx == Some(proto::Direction::Inbound as i32)
            && (self.scope.exe_path.is_some() || self.scope.exe_sha256.is_some())
        {
            return Err(format!(
                "rule `{name}`: an inbound rule cannot be scoped on a program \
                 - inbound flows cannot be attributed, so the rule would \
                 never fire. Scope it on src_net and dst_port instead."
            ));
        }
        // The three refusals below mirror the daemon's own gates
        // (reject_unmatchable_parent, reject_unmatchable_exe, and the
        // canonical digest form). Without them a file passes the local
        // validate-first pass, then dies at the daemon mid-apply - recreating
        // the partial import this whole function exists to prevent.
        if let Some(parent) = self.scope.parent_exe.as_deref() {
            return Err(format!(
                "rule `{name}`: parent_exe (`{parent}`) is not an evaluated \
                 predicate - the daemon refuses it because such a rule would \
                 match every process while outranking narrower rules. Scope \
                 on the executable itself."
            ));
        }
        if let Some(exe) = self.scope.exe_path.as_deref() {
            if exe == cfc_core::UNKNOWN_EXE {
                return Err(format!(
                    "rule `{name}`: exe_path `{exe}` is the placeholder for an \
                     unidentified process, not a path; such a rule would match \
                     every unattributable flow"
                ));
            }
            if exe.len() > cfc_core::rule::MAX_EXE_PATH_LEN {
                return Err(format!("rule `{name}`: executable path is too long"));
            }
            if !std::path::Path::new(exe).is_absolute() {
                return Err(format!(
                    "rule `{name}`: exe_path `{exe}` is not absolute; rules \
                     match on absolute executable paths, so it could never fire"
                ));
            }
        }
        let exe_sha256 = match self.scope.exe_sha256.as_deref() {
            Some(h) => Some(
                cfc_core::rule::canonical_exe_sha256(h)
                    .map_err(|e| format!("rule `{name}`: {e}"))?,
            ),
            None => None,
        };
        let src_net = self.scope.src_net.clone();
        let src_port = self.scope.src_port;
        let protocol_idx = match self.scope.protocol.as_deref() {
            None => None,
            Some(p) => Some(match p.to_ascii_lowercase().as_str() {
                "tcp" => proto::Protocol::Tcp as i32,
                "udp" => proto::Protocol::Udp as i32,
                "icmp" => proto::Protocol::Icmp as i32,
                other => return Err(bad("protocol", other, "tcp, udp, icmp")),
            }),
        };
        // Local validation names the failing rule before sending the batch.
        if let Some(net) = self.scope.dst_net.as_deref() {
            net.parse::<ipnet::IpNet>()
                .map_err(|e| format!("rule `{name}`: bad dst_net `{net}`: {e}"))?;
        }
        // Give import errors local names; the daemon independently validates
        // the complete batch before its transaction.
        if duration == proto::Duration::Once {
            return Err(format!(
                "rule `{name}`: duration `once` answers a single prompt and cannot be \
                 stored; use always or until-restart"
            ));
        }
        let constrains_something = self.scope.exe_path.is_some()
            || self.scope.exe_sha256.is_some()
            || self.scope.parent_exe.is_some()
            || self.scope.uid.is_some()
            || self.scope.dst_host.is_some()
            || self.scope.dst_net.is_some()
            || self.scope.dst_port.is_some()
            || self.scope.src_net.is_some()
            || self.scope.src_port.is_some()
            || protocol_idx.is_some();
        if !constrains_something {
            return Err(format!(
                "rule `{name}`: scope constrains nothing, so it would match every \
                 process and every destination"
            ));
        }
        // Canonicalised, not merely validated. `parse_str` accepts hyphenated,
        // 32-char, braced and urn spellings of the same id; keeping whichever
        // one the file used meant two spellings of one id looked like two ids to
        // the duplicate check, and looked different again from what the daemon
        // lists back. Both bugs disappear if the parsed value is what travels.
        let id = if self.id.is_empty() {
            String::new()
        } else {
            uuid::Uuid::parse_str(&self.id)
                .map_err(|e| format!("rule `{name}`: bad id `{}`: {e}", self.id))?
                .to_string()
        };
        let scope = proto::RuleScope {
            exe_path: self.scope.exe_path.unwrap_or_default(),
            exe_sha256: exe_sha256.unwrap_or_default(),
            parent_exe: self.scope.parent_exe.unwrap_or_default(),
            uid: self.scope.uid.unwrap_or(0),
            has_uid: self.scope.uid.is_some(),
            dst_host: self.scope.dst_host.unwrap_or_default(),
            dst_net: self.scope.dst_net.unwrap_or_default(),
            dst_port: self.scope.dst_port.map(u32::from).unwrap_or(0),
            has_dst_port: self.scope.dst_port.is_some(),
            protocol: protocol_idx.unwrap_or(0),
            has_protocol: protocol_idx.is_some(),
            direction: direction_idx.unwrap_or(0),
            has_direction: direction_idx.is_some(),
            src_net: src_net.unwrap_or_default(),
            src_port: src_port.map(u32::from).unwrap_or(0),
            has_src_port: src_port.is_some(),
        };
        Ok(proto::RuleInfo {
            id,
            name: self.name,
            enabled: self.enabled,
            action: action as i32,
            duration: duration as i32,
            duration_seconds: self.duration_seconds,
            scope: Some(scope),
            created_at_unix_ms,
            hit_count: 0,
        })
    }
}

pub fn exported_rule(r: &proto::RuleInfo) -> ExportedRule {
    let scope = r.scope.as_ref();
    let opt_string = |s: &str| {
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    };
    ExportedRule {
        id: r.id.clone(),
        name: r.name.clone(),
        enabled: r.enabled,
        action: convert::action_label(r.action).to_string(),
        duration: convert::duration_label(r.duration).to_string(),
        duration_seconds: r.duration_seconds,
        expires_at_unix_ms: (r.duration == proto::Duration::Seconds as i32
            && r.created_at_unix_ms > 0)
            .then(|| r.created_at_unix_ms + i64::from(r.duration_seconds) * 1000),
        scope: ExportedScope {
            exe_path: scope.and_then(|s| opt_string(&s.exe_path)),
            exe_sha256: scope.and_then(|s| opt_string(&s.exe_sha256)),
            parent_exe: scope.and_then(|s| opt_string(&s.parent_exe)),
            uid: scope.and_then(|s| s.has_uid.then_some(s.uid)),
            dst_host: scope.and_then(|s| opt_string(&s.dst_host)),
            dst_net: scope.and_then(|s| opt_string(&s.dst_net)),
            dst_port: scope.and_then(|s| s.has_dst_port.then_some(s.dst_port as u16)),
            protocol: scope
                .and_then(|s| s.has_protocol.then_some(s.protocol))
                .map(|p| convert::protocol_label(p).to_string()),
            direction: scope
                .and_then(|s| s.has_direction.then_some(s.direction))
                .map(|d| convert::direction_label(d).to_string()),
            src_net: scope.and_then(|s| opt_string(&s.src_net)),
            src_port: scope.and_then(|s| s.has_src_port.then_some(s.src_port as u16)),
        },
    }
}

pub fn proto_rules_to_export(rules: &[proto::RuleInfo]) -> Vec<ExportedRule> {
    rules.iter().map(exported_rule).collect()
}

#[cfg(test)]
mod json_tests {
    use super::*;

    #[test]
    fn native_import_rejects_unknown_and_empty_predicates() {
        let unknown = r#"[{"name":"t","action":"allow","scope":{"exe_path":"/usr/bin/curl","dst_hostname":"example.com"}}]"#;
        assert!(serde_json::from_str::<Vec<ExportedRule>>(unknown).is_err());
        let mut rule = exported("allow");
        rule.scope.dst_host = Some(String::new());
        assert!(rule.try_into_proto().is_err());
    }

    // A legacy rule whose path became an alias blocked every restore.
    #[test]
    fn import_checks_only_a_new_or_changed_executable_path() {
        // /proc/self/exe is a symlink on every Linux: an alias.
        let mut rule = exported("allow");
        rule.id = "1f0a5c7e-0000-4000-8000-000000000001".into();
        rule.scope.exe_path = Some("/proc/self/exe".into());
        let pb = rule
            .try_into_proto()
            .expect("the daemon decides on aliases");
        assert!(check_new_exe(&pb, &[]).is_err());
        assert!(check_new_exe(&pb, std::slice::from_ref(&pb)).is_ok());
        let mut moved = pb.clone();
        moved.scope.as_mut().unwrap().exe_path = "/proc/self/cwd".into();
        assert!(check_new_exe(&moved, std::slice::from_ref(&pb)).is_err());
    }

    // A restored backup used to start a timed Allow's lifetime again.
    #[test]
    fn a_timed_rule_keeps_its_deadline_through_export_and_import() {
        let mut rule = exported("allow").try_into_proto().unwrap();
        rule.duration = proto::Duration::Seconds as i32;
        rule.duration_seconds = 3600;
        rule.created_at_unix_ms = 1_000_000;
        let back = exported_rule(&rule);
        assert_eq!(back.expires_at_unix_ms, Some(4_600_000));
        assert_eq!(back.try_into_proto().unwrap().created_at_unix_ms, 1_000_000);
        let mut always = exported("allow");
        always.expires_at_unix_ms = Some(4_600_000);
        assert!(always.try_into_proto().is_err());
        assert_eq!(
            exported_rule(&exported("allow").try_into_proto().unwrap()).expires_at_unix_ms,
            None
        );
    }

    fn exported(action: &str) -> ExportedRule {
        ExportedRule {
            id: String::new(),
            name: "t".into(),
            enabled: true,
            action: action.into(),
            duration: "always".into(),
            duration_seconds: 0,
            expires_at_unix_ms: None,
            scope: ExportedScope {
                exe_path: Some("/usr/bin/curl".into()),
                exe_sha256: None,
                parent_exe: None,
                uid: None,
                dst_host: None,
                dst_net: None,
                dst_port: None,
                protocol: None,
                direction: None,
                src_net: None,
                src_port: None,
            },
        }
    }

    #[test]
    fn an_unknown_action_is_refused_and_never_becomes_allow() {
        // The single most dangerous line this change removes. `_ => Allow`
        // meant a typo, a truncated file, or a rule written by a newer version
        // imported as an **allow** - on the path an operator uses to restore
        // rules after an incident.
        for typo in ["block", "denied", "DENY ", "", "drop"] {
            let e = match exported(typo).try_into_proto() {
                Ok(_) => panic!("`{typo}` must not be accepted"),
                Err(e) => e,
            };
            assert!(e.contains("unknown action"), "{e}");
            assert!(
                e.contains("allow, deny, reject"),
                "the message must say what is valid: {e}"
            );
        }
        // The three real ones still work, in any case.
        for good in ["allow", "Deny", "REJECT"] {
            assert!(exported(good).try_into_proto().is_ok(), "{good}");
        }
    }

    #[test]
    fn an_unknown_duration_or_protocol_is_refused_too() {
        let mut r = exported("deny");
        r.duration = "forever".into();
        assert!(r.try_into_proto().unwrap_err().contains("unknown duration"));

        let mut r = exported("deny");
        r.scope.protocol = Some("sctp".into());
        assert!(r.try_into_proto().unwrap_err().contains("unknown protocol"));

        // Absent is not unknown.
        let mut r = exported("deny");
        r.scope.protocol = None;
        assert!(r.try_into_proto().is_ok());
    }

    #[test]
    fn a_malformed_dst_net_is_caught_before_the_daemon_sees_it() {
        // The daemon rejects it too, but only one rule at a time - by then
        // earlier rules in the file have already been applied. Catching it here
        // is what lets the import report the offending rule by name and change
        // nothing at all.
        let mut r = exported("allow");
        r.scope.dst_net = Some("10.0.0.0/33".into());
        let e = r.try_into_proto().unwrap_err();
        assert!(e.contains("dst_net"), "{e}");
        assert!(e.contains("`t`"), "the message must name the rule: {e}");
    }

    #[test]
    fn a_malformed_id_is_caught_before_anything_is_applied() {
        let mut r = exported("allow");
        r.id = "not-a-uuid".into();
        assert!(r.try_into_proto().unwrap_err().contains("bad id"));

        // Empty means "mint a new one", which is how a hand-written file works.
        let mut r = exported("allow");
        r.id = String::new();
        assert!(r.try_into_proto().is_ok());
    }

    #[test]
    fn the_error_names_the_rule_so_a_large_file_is_actionable() {
        let mut r = exported("block");
        r.name = "allow-updates".into();
        let e = r.try_into_proto().unwrap_err();
        assert!(
            e.contains("allow-updates"),
            "an import of 200 rules is unusable without this: {e}"
        );
    }

    #[test]
    fn imported_hostname_policy_is_refused_without_substitution() {
        for action in ["allow", "deny", "reject"] {
            let mut rule = exported(action);
            rule.scope.dst_host = Some("example.org".into());
            rule.scope.dst_net = Some("1.2.3.4/32".into());
            assert!(rule.try_into_proto().is_err());
        }
    }

    #[test]
    fn export_preserves_legacy_hostname_policy_for_explicit_review() {
        let rule = proto::RuleInfo {
            scope: Some(proto::RuleScope {
                dst_host: "Example.ORG.".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let exported = exported_rule(&rule);
        assert_eq!(exported.scope.dst_host.as_deref(), Some("Example.ORG."));
        let json = serde_json::to_string(&exported).unwrap();
        let back: ExportedRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scope.dst_host.as_deref(), Some("Example.ORG."));
    }

    #[test]
    fn export_round_trips_through_json() {
        let scope = proto::RuleScope {
            exe_path: "/usr/bin/curl".into(),
            exe_sha256: String::new(),
            parent_exe: String::new(),
            uid: 1000,
            has_uid: true,
            dst_host: String::new(),
            dst_net: "93.184.216.34/32".into(),
            dst_port: 443,
            has_dst_port: true,
            protocol: proto::Protocol::Tcp as i32,
            has_protocol: true,
            direction: 0,
            has_direction: false,
            src_net: String::new(),
            src_port: 0,
            has_src_port: false,
        };
        let original = proto::RuleInfo {
            duration_seconds: 0,
            id: "3f1b8a0e-5c4d-4e2a-9b7f-1a2b3c4d5e6f".into(),
            name: "curl-https".into(),
            enabled: false,
            action: proto::Action::Deny as i32,
            duration: proto::Duration::UntilRestart as i32,
            scope: Some(scope),
            created_at_unix_ms: 1_700_000_000_000,
            hit_count: 7,
        };

        let json = serde_json::to_string(&exported_rule(&original)).unwrap();
        let back: ExportedRule = serde_json::from_str(&json).unwrap();
        let pb = back
            .try_into_proto()
            .expect("a rule we exported must import");

        assert_eq!(pb.id, "3f1b8a0e-5c4d-4e2a-9b7f-1a2b3c4d5e6f");
        assert_eq!(pb.name, "curl-https");
        assert!(!pb.enabled);
        assert_eq!(pb.action, proto::Action::Deny as i32);
        assert_eq!(pb.duration, proto::Duration::UntilRestart as i32);
        let s = pb.scope.unwrap();
        assert_eq!(s.exe_path, "/usr/bin/curl");
        assert_eq!(s.uid, 1000);
        assert!(s.has_uid);
        assert!(s.dst_host.is_empty());
        assert_eq!(s.dst_net, "93.184.216.34/32");
        assert_eq!(s.dst_port, 443);
        assert!(s.has_dst_port);
        assert_eq!(s.protocol, proto::Protocol::Tcp as i32);
        // hit_count / created_at are daemon-owned and must not ride along.
        assert_eq!(pb.hit_count, 0);
        assert_eq!(pb.created_at_unix_ms, 0);
    }

    #[test]
    fn unset_scope_fields_serialise_as_null() {
        let pb = proto::RuleInfo {
            duration_seconds: 0,
            id: "id-2".into(),
            name: "bare".into(),
            enabled: true,
            action: proto::Action::Allow as i32,
            duration: proto::Duration::Always as i32,
            scope: Some(proto::RuleScope::default()),
            created_at_unix_ms: 0,
            hit_count: 0,
        };
        let v = serde_json::to_value(exported_rule(&pb)).unwrap();
        assert_eq!(v["scope"]["exe_path"], serde_json::Value::Null);
        assert_eq!(v["scope"]["uid"], serde_json::Value::Null);
        assert_eq!(v["scope"]["dst_port"], serde_json::Value::Null);
        assert_eq!(v["action"], "allow");
        assert_eq!(v["duration"], "always");
    }

    #[test]
    fn rule_detail_carries_bookkeeping_fields_flattened() {
        let pb = proto::RuleInfo {
            duration_seconds: 0,
            id: "id-3".into(),
            name: "detail".into(),
            enabled: true,
            action: proto::Action::Reject as i32,
            duration: proto::Duration::Always as i32,
            scope: Some(proto::RuleScope::default()),
            created_at_unix_ms: 1_700_000_000_000,
            hit_count: 42,
        };
        let v = serde_json::to_value(RuleDetail::from_proto(&pb)).unwrap();
        assert_eq!(v["id"], "id-3");
        assert_eq!(v["action"], "reject");
        assert_eq!(v["hit_count"], 42);
        assert!(v["created_at"].as_str().unwrap().starts_with("2023-"));
        assert!(v["summary"].as_str().unwrap().contains("reject"));
    }
}
