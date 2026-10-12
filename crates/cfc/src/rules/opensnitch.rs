//! `cfc rules import-opensnitch`.

use super::export::{default_duration, default_true};
use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};
use anyhow::Context;
use cfc_client::{proto, Client};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// opensnitch import
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct OsnRule {
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    action: String,
    #[serde(default = "default_duration")]
    duration: String,
    #[serde(default)]
    operator: Option<OsnOperator>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type")]
enum OsnOperator {
    Simple(OsnSimple),
    Regexp(OsnSimple),
    List(OsnList),
}

#[derive(Debug, serde::Deserialize)]
struct OsnSimple {
    operand: String,
    data: String,
}

#[derive(Debug, serde::Deserialize)]
struct OsnList {
    #[serde(default)]
    #[allow(dead_code)]
    operand: String,
    #[serde(default)]
    list: Vec<OsnOperator>,
}

pub async fn import_opensnitch(
    client: &mut Client,
    path: PathBuf,
    replace: bool,
    skip_unconvertible: bool,
    format: OutputFormat,
) -> CliResult {
    let mut files: Vec<PathBuf> = if path.is_dir() {
        std::fs::read_dir(&path)
            .with_context(|| format!("reading dir {}", path.display()))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .context("reading OpenSnitch directory entries")?
            .into_iter()
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect()
    } else {
        vec![path.clone()]
    };

    files.sort();
    if files.is_empty() {
        return Err(CliError::runtime(format!(
            "no .json files found under {}",
            path.display()
        )));
    }

    // Unsupported rules may be skipped only when asked, and never in replace
    // mode: a skipped deny next to an imported allow is a wider policy than
    // the source, and the skip count alone did not say so.
    let mut pending = Vec::new();
    let mut skipped = 0u32;
    for file in &files {
        let json =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let osn: OsnRule = match serde_json::from_str(&json) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{}",
                    output::terminal_safe(&format!("skip {}: parse error: {e}", file.display()))
                );
                skipped += 1;
                continue;
            }
        };
        match convert_opensnitch(file, osn) {
            Ok(rule) => pending.push(rule),
            Err(e) => {
                eprintln!(
                    "{}",
                    output::terminal_safe(&format!("skip {}: {e}", file.display()))
                );
                skipped += 1;
            }
        }
    }
    if replace && skipped > 0 {
        return Err(anyhow::anyhow!("refusing --replace: {skipped} source rules could not be converted; nothing was changed").into());
    }
    if skipped > 0 && !skip_unconvertible {
        return Err(anyhow::anyhow!(
            "refusing to import: {skipped} source rules could not be converted, and \
             importing the rest would drop their restrictions; nothing was changed. \
             Rewrite them, or pass --skip-unconvertible to import the rest anyway"
        )
        .into());
    }
    if replace && pending.is_empty() {
        return Err(anyhow::anyhow!(
            "refusing --replace: none of the {} file(s) converted, so this would \
             delete every existing rule and import nothing",
            files.len()
        )
        .into());
    }

    let response = client
        .apply_rules(pending, replace)
        .await
        .context("OpenSnitch import refused; no rules were changed")?;
    let imported = response.ids.len();
    let removed = response.removed;

    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "imported": imported, "skipped": skipped, "removed": removed,
        }));
    }
    println!("imported {imported} rules ({skipped} skipped, {removed} removed)");
    Ok(())
}

fn convert_opensnitch(file: &std::path::Path, osn: OsnRule) -> anyhow::Result<proto::RuleInfo> {
    // Fails closed, for the same reason `ExportedRule::try_into_proto` does: an
    // unrecognised or missing action must never become an Allow. This one is
    // reachable from the migration path the README advertises, so a foreign
    // file's vocabulary decides what gets allowed - the worst possible input to
    // trust. A rule that cannot be converted stops the import, or is skipped
    // and named under --skip-unconvertible, like anything else it does not
    // understand.
    let action = match osn.action.to_ascii_lowercase().as_str() {
        "allow" | "accept" => proto::Action::Allow,
        "deny" | "drop" => proto::Action::Deny,
        "reject" => proto::Action::Reject,
        other => {
            anyhow::bail!("unknown action `{other}` (expected allow, accept, deny, drop or reject)")
        }
    };
    let duration = match osn.duration.to_ascii_lowercase().as_str() {
        "always" => proto::Duration::Always,
        "once" => anyhow::bail!("Once rules cannot be persisted"),
        "until restart" | "until-restart" | "restart" => proto::Duration::UntilRestart,
        other => {
            anyhow::bail!("unknown duration `{other}` (expected always, once or until restart)")
        }
    };

    let mut scope = proto::RuleScope::default();
    if let Some(op) = osn.operator {
        apply_operator(&op, &mut scope)?;
    }
    if !scope.exe_path.is_empty() {
        cfc_core::exe_path::resolve_policy(std::path::Path::new(&scope.exe_path))
            .map_err(anyhow::Error::msg)?;
    }

    let scope_empty = scope.exe_sha256.is_empty()
        && scope.exe_path.is_empty()
        && scope.dst_host.is_empty()
        && scope.dst_net.is_empty()
        && !scope.has_dst_port
        && !scope.has_protocol
        && !scope.has_uid;
    if scope_empty {
        anyhow::bail!("no convertible predicates");
    }

    let name = osn.name.unwrap_or_else(|| {
        file.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "opensnitch-import".into())
    });

    Ok(proto::RuleInfo {
        duration_seconds: 0,
        id: String::new(),
        name,
        enabled: osn.enabled,
        action: action as i32,
        duration: duration as i32,
        scope: Some(scope),
        created_at_unix_ms: 0,
        hit_count: 0,
    })
}

// The contract for everything below: a converted rule must never be WIDER
// than the opensnitch rule it came from. Every predicate is either translated
// faithfully or fails the whole rule (the caller skips it and says why).
// Silently dropping the untranslatable part used to be the behaviour, and for
// an allow that is exactly backwards: "allow curl to reach uid 1000's flows on
// port 443" minus the parts that did not parse becomes "allow curl to reach
// anything" - a rule the source file never contained.
fn apply_operator(op: &OsnOperator, scope: &mut proto::RuleScope) -> anyhow::Result<()> {
    match op {
        OsnOperator::Simple(s) => apply_simple(s, scope),
        // A regexp pattern stored as a literal matches nothing (a never-firing
        // deny) or, worse, would need only one widening edit to "fix". This
        // firewall matches exact values; there is no faithful translation.
        OsnOperator::Regexp(s) => anyhow::bail!(
            "operand `{}` is a regexp (`{}`) and this firewall matches exact \
             values; importing the pattern as a literal would produce a rule \
             that never fires. Rewrite it as one rule per concrete value.",
            s.operand,
            s.data
        ),
        OsnOperator::List(l) => {
            if l.list.is_empty() {
                anyhow::bail!("empty predicate list");
            }
            for sub in &l.list {
                apply_operator(sub, scope)?;
            }
            Ok(())
        }
    }
}

fn apply_simple(s: &OsnSimple, scope: &mut proto::RuleScope) -> anyhow::Result<()> {
    if s.data.trim().is_empty() {
        anyhow::bail!("operand `{}` has empty data", s.operand);
    }
    // A list with two `dest.ip` entries means "either of these" in
    // opensnitch; overwriting would keep only the last and silently drop the
    // rest of the disjunction. One value per predicate, or the rule fails.
    fn set_once(field: &str, slot: &mut String, value: String) -> anyhow::Result<()> {
        if !slot.is_empty() && *slot != value {
            anyhow::bail!(
                "operand `{field}` appears more than once (`{slot}` then \
                 `{value}`); this firewall holds one value per predicate, so \
                 import one rule per value instead"
            );
        }
        *slot = value;
        Ok(())
    }
    match s.operand.as_str() {
        "process.path" => set_once("process.path", &mut scope.exe_path, s.data.clone())?,
        "process.hash.sha256" => {
            let hex = cfc_core::rule::canonical_exe_sha256(&s.data)
                .map_err(|e| anyhow::anyhow!("operand `process.hash.sha256`: {e}"))?;
            set_once("process.hash.sha256", &mut scope.exe_sha256, hex)?;
        }
        "user.id" => {
            if scope.has_uid {
                anyhow::bail!("operand `user.id` appears more than once");
            }
            scope.uid = s
                .data
                .parse::<u32>()
                .map_err(|_| anyhow::anyhow!("operand `user.id`: `{}` is not a uid", s.data))?;
            scope.has_uid = true;
        }
        "dest.host" | "dest.domain" => anyhow::bail!(
            "hostname policy is unsupported; use an explicit numeric dest.ip or dest.network"
        ),
        // Parsed here, as the daemon will: one bad value must skip its own
        // file with a reason, not fail the whole batch at the daemon.
        "dest.ip" => {
            let ip = s.data.parse::<std::net::IpAddr>().map_err(|_| {
                anyhow::anyhow!("operand `dest.ip`: `{}` is not an IP address", s.data)
            })?;
            // single IP -> /32 or /128
            let net = ipnet::IpNet::from(ip).to_string();
            set_once("dest.ip", &mut scope.dst_net, net)?;
        }
        "dest.network" => {
            let net = s.data.parse::<ipnet::IpNet>().map_err(|_| {
                anyhow::anyhow!("operand `dest.network`: `{}` is not a CIDR network", s.data)
            })?;
            set_once("dest.network", &mut scope.dst_net, net.to_string())?;
        }
        "dest.port" => {
            if scope.has_dst_port {
                anyhow::bail!("operand `dest.port` appears more than once");
            }
            scope.dst_port = s.data.parse::<u16>().map(u32::from).map_err(|_| {
                anyhow::anyhow!("operand `dest.port`: `{}` is not a port number", s.data)
            })?;
            scope.has_dst_port = true;
        }
        "protocol" => {
            if scope.has_protocol {
                anyhow::bail!("operand `protocol` appears more than once");
            }
            scope.protocol = match s.data.to_ascii_uppercase().as_str() {
                "TCP" => proto::Protocol::Tcp as i32,
                "UDP" => proto::Protocol::Udp as i32,
                "ICMP" => proto::Protocol::Icmp as i32,
                other => anyhow::bail!(
                    "operand `protocol`: `{other}` has no equivalent here \
                     (expected tcp, udp or icmp)"
                ),
            };
            scope.has_protocol = true;
        }
        other => anyhow::bail!(
            "operand `{other}` has no equivalent in this firewall; dropping \
             it would import a wider rule than the file contains"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod opensnitch_tests {
    use super::*;

    #[test]
    fn opensnitch_requires_action_and_nonempty_predicates() {
        assert!(parse(
            r#"{"operator":{"type":"simple","operand":"process.path","data":"/usr/bin/curl"}}"#
        )
        .is_err());
        assert!(parse(r#"{"action":"allow","operator":{"type":"list","operand":"list","list":[{"type":"simple","operand":"process.path","data":""},{"type":"simple","operand":"dest.port","data":"443"}]}}"#).is_err());
    }

    use std::path::Path;

    fn parse(json: &str) -> anyhow::Result<proto::RuleInfo> {
        let osn: OsnRule = serde_json::from_str(json)?;
        convert_opensnitch(Path::new("test.json"), osn)
    }

    #[test]
    fn simple_process_path() {
        let r = parse(
            r#"{
              "name": "firefox-https",
              "enabled": true,
              "action": "allow",
              "duration": "always",
              "operator": {
                "type": "simple",
                "operand": "process.path",
                "data": "/usr/lib/firefox/firefox"
              }
            }"#,
        )
        .unwrap();
        assert_eq!(r.name, "firefox-https");
        assert_eq!(r.action, proto::Action::Allow as i32);
        let scope = r.scope.unwrap();
        assert_eq!(scope.exe_path, "/usr/lib/firefox/firefox");
    }

    #[test]
    fn list_of_predicates() {
        let r = parse(
            r#"{
              "name": "curl-443",
              "enabled": true,
              "action": "allow",
              "duration": "always",
              "operator": {
                "type": "list",
                "operand": "list",
                "list": [
                  {"type": "simple", "operand": "process.path", "data": "/usr/bin/curl"},
                  {"type": "simple", "operand": "dest.port", "data": "443"},
                  {"type": "simple", "operand": "protocol", "data": "TCP"}
                ]
              }
            }"#,
        )
        .unwrap();
        let scope = r.scope.unwrap();
        assert_eq!(scope.exe_path, "/usr/bin/curl");
        assert_eq!(scope.dst_port, 443);
        assert!(scope.has_dst_port);
        assert_eq!(scope.protocol, proto::Protocol::Tcp as i32);
        assert!(scope.has_protocol);
    }

    #[test]
    fn opensnitch_hostname_policy_is_refused_without_substitution() {
        for operand in ["dest.host", "dest.domain"] {
            let source = format!(
                r#"{{"action":"deny","duration":"always","operator":{{"type":"simple","operand":"{operand}","data":"example.org"}}}}"#
            );
            assert!(parse(&source).is_err());
        }
    }

    #[test]
    fn deny_action_recognized() {
        let r = parse(
            r#"{
              "name": "block-evil",
              "action": "deny",
              "duration": "always",
              "operator": {
                "type": "simple",
                "operand": "dest.ip",
                "data": "1.2.3.4"
              }
            }"#,
        )
        .unwrap();
        assert_eq!(r.action, proto::Action::Deny as i32);
        assert_eq!(r.duration, proto::Duration::Always as i32);
        assert_eq!(r.scope.unwrap().dst_net, "1.2.3.4/32");
    }

    #[test]
    fn dest_ip_becomes_cidr() {
        let r = parse(
            r#"{
              "name": "block-ip",
              "action": "deny",
              "operator": {"type": "simple", "operand": "dest.ip", "data": "1.2.3.4"}
            }"#,
        )
        .unwrap();
        assert_eq!(r.scope.unwrap().dst_net, "1.2.3.4/32");
    }

    #[test]
    fn ipv6_dest_ip_becomes_128_cidr() {
        let r = parse(
            r#"{
              "name": "block-v6",
              "action": "deny",
              "operator": {"type": "simple", "operand": "dest.ip", "data": "2001:db8::1"}
            }"#,
        )
        .unwrap();
        assert_eq!(r.scope.unwrap().dst_net, "2001:db8::1/128");
    }

    // These used to pass conversion and then fail the whole batch at the
    // daemon, so one bad file stopped the import without being named.
    #[test]
    fn malformed_addresses_and_ports_fail_their_own_file() {
        for (operand, data) in [
            ("dest.ip", "10.0.0.0/8"),
            ("dest.ip", "example.org"),
            ("dest.network", "10.0.0.0/33"),
            ("dest.network", "10.0.0.1"),
            ("dest.port", "70000"),
        ] {
            let source = format!(
                r#"{{"action":"deny","duration":"always","operator":{{"type":"simple","operand":"{operand}","data":"{data}"}}}}"#
            );
            assert!(parse(&source).is_err(), "{operand} {data}");
        }
        let r = parse(r#"{"action":"deny","operator":{"type":"simple","operand":"dest.network","data":"10.0.0.0/8"}}"#).unwrap();
        assert_eq!(r.scope.unwrap().dst_net, "10.0.0.0/8");
    }

    #[test]
    fn empty_rule_rejected() {
        // No operator at all -> no convertible predicates -> error.
        let err = parse(
            r#"{
              "name": "nothing",
              "action": "allow"
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no convertible predicates"));
    }

    #[test]
    fn unknown_operands_fail_the_rule_instead_of_widening_it() {
        // This test used to assert the opposite: the unsupported
        // process.command was dropped and the rule imported on process.path
        // alone. But the source rule said "curl, when invoked as `curl -s X`"
        // and the import said "curl, always" - an allow wider than the file
        // contained, on the migration path the README advertises. A predicate
        // that cannot be translated now fails the rule, which the caller
        // skips and reports.
        let err = parse(
            r#"{
              "name": "mixed",
              "action": "allow",
              "operator": {
                "type": "list",
                "operand": "list",
                "list": [
                  {"type": "simple", "operand": "process.command", "data": "curl -s X"},
                  {"type": "simple", "operand": "process.path", "data": "/usr/bin/curl"}
                ]
              }
            }"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("process.command"),
            "the message must name the operand that could not travel: {err}"
        );
    }

    #[test]
    fn regexp_rules_are_refused_not_imported_as_literals() {
        // Also inverted: the pattern used to land in exe_path verbatim, where
        // it matched no real path ever - a rule that lists, ranks, and never
        // fires.
        let err = parse(
            r#"{
              "name": "rxp",
              "action": "allow",
              "operator": {"type": "regexp", "operand": "process.path", "data": "/usr/bin/.*"}
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("regexp"), "{err}");
        assert!(err.to_string().contains("/usr/bin/.*"), "{err}");
    }

    #[test]
    fn repeated_operands_fail_instead_of_last_one_winning() {
        // Two dest.ip entries are a disjunction in opensnitch; keeping only
        // the last would silently drop half of it.
        let err = parse(
            r#"{
              "name": "two-ips",
              "action": "deny",
              "operator": {
                "type": "list",
                "operand": "list",
                "list": [
                  {"type": "simple", "operand": "dest.ip", "data": "192.0.2.1"},
                  {"type": "simple", "operand": "dest.ip", "data": "192.0.2.2"}
                ]
              }
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("more than once"), "{err}");
    }

    #[test]
    fn unparseable_predicate_values_fail_the_rule() {
        // `user.id: root` used to be dropped, turning "allow for root only"
        // into "allow for every uid".
        let err = parse(
            r#"{
              "name": "root-only",
              "action": "allow",
              "operator": {
                "type": "list",
                "operand": "list",
                "list": [
                  {"type": "simple", "operand": "process.path", "data": "/usr/bin/curl"},
                  {"type": "simple", "operand": "user.id", "data": "root"}
                ]
              }
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("user.id"), "{err}");
    }
}
