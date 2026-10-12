//! `cfc rules bundle list|add|remove` and `bootstrap-defaults`.

use super::catalog::{bundles, pre_0_7_entries, Bundle, BundleRule};
use super::short_id;
use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};
use cfc_client::{proto, Client};
use std::path::PathBuf;

/// Finds a bundle by name, or lists what there is.
fn find_bundle(name: &str) -> Result<Bundle, CliError> {
    let all = bundles();
    let known: Vec<&str> = all.iter().map(|b| b.name).collect();
    all.into_iter()
        .find(|b| b.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            CliError::not_found(format!(
                "no bundle named {name:?}; known bundles: {}",
                known.join(", ")
            ))
        })
}

/// What a bundle would do on *this* machine.
struct Planned {
    /// Entries whose program is installed here, with the path as /proc will
    /// report it - not necessarily the candidate that matched.
    present: Vec<(&'static str, PathBuf)>,
    /// Entries skipped because no candidate exists, or only a launcher does.
    absent: Vec<&'static str>,
}

fn plan(bundle: &Bundle) -> Planned {
    let mut present = Vec::new();
    let mut absent = Vec::new();
    for r in &bundle.rules {
        match r.resolve() {
            Some(exe) => present.push((r.name, exe)),
            None => absent.push(r.name),
        }
    }
    Planned { present, absent }
}

/// The rule `bundle add` sends for one entry, resolved to a concrete `exe`.
///
/// Exists as its own function so a test can exercise the exact mapping the
/// install path uses. When this was inlined, the call site passed `None` for
/// two of the fields and nothing noticed until a rule was read back off disk.
fn proto_for(spec: &BundleRule, exe: &str) -> proto::RuleInfo {
    // `direction`/`src_net` are what an inbound bundle entry needs; every
    // outbound one leaves them unset.
    proto::RuleInfo {
        duration_seconds: 0,
        id: String::new(),
        name: spec.name.to_string(),
        enabled: true,
        action: proto::Action::Allow as i32,
        duration: proto::Duration::Always as i32,
        scope: Some(proto::RuleScope {
            exe_path: exe.to_string(),
            exe_sha256: String::new(),
            parent_exe: String::new(),
            uid: 0,
            has_uid: false,
            dst_host: String::new(),
            dst_net: String::new(),
            dst_port: spec.dst_port.map(u32::from).unwrap_or(0),
            has_dst_port: spec.dst_port.is_some(),
            protocol: spec.protocol.map(|p| p as i32).unwrap_or(0),
            has_protocol: spec.protocol.is_some(),
            direction: spec.direction.map(|d| d as i32).unwrap_or(0),
            has_direction: spec.direction.is_some(),
            src_net: spec.src_net.unwrap_or_default().to_string(),
            src_port: 0,
            has_src_port: false,
        }),
        created_at_unix_ms: 0,
        hit_count: 0,
    }
}

/// Whether `rule` grants exactly what `wanted` would: same action, duration and
/// scope. Name, id and enabled state are not policy.
fn same_policy(rule: &proto::RuleInfo, wanted: &proto::RuleInfo) -> bool {
    rule.action == wanted.action
        && rule.duration == wanted.duration
        && rule.duration_seconds == wanted.duration_seconds
        && rule.scope == wanted.scope
}

/// Ids of the rules that are this bundle's own entries as seeded before 0.7.0
/// gave bundle rules deterministic ids: same name, and granting exactly what
/// the entry would install here now, or what 0.3.0 through 0.7.0 installed
/// here (see `catalog::PRE_0_7_CHANGED`). `bundle add` counts them as present and
/// `bundle remove` removes them; an edited copy is neither.
fn legacy_copies(
    bundle: &Bundle,
    existing: &[proto::RuleInfo],
) -> std::collections::HashSet<String> {
    let now = bundle.rules.iter().filter_map(|r| Some((*r, r.resolve()?)));
    let then = pre_0_7_entries(bundle)
        .into_iter()
        .filter_map(|r| Some((r, r.resolve_pre_0_7()?)));
    let wanted: Vec<proto::RuleInfo> = now
        .chain(then)
        .map(|(spec, exe)| proto_for(&spec, &exe.to_string_lossy()))
        .collect();
    existing
        .iter()
        .filter(|rule| {
            wanted
                .iter()
                .any(|w| w.name == rule.name && same_policy(rule, w))
        })
        .map(|rule| rule.id.clone())
        .collect()
}

fn bundle_rule_id(bundle: &str, name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("colony-firewall-bundle\0{bundle}\0{name}"));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Uuid::from_bytes(bytes).to_string()
}

/// `cfc rules bundle list`
pub async fn bundle_list(client: &mut Client, format: OutputFormat) -> CliResult {
    let existing: std::collections::HashSet<String> = client
        .list_rules()
        .await?
        .into_iter()
        .map(|r| r.id)
        .collect();

    let all = bundles();
    if format.is_json() {
        let rows: Vec<_> = all
            .iter()
            .map(|b| {
                let p = plan(b);
                serde_json::json!({
                    "name": b.name,
                    "summary": b.summary,
                    "entries": b.rules.len(),
                    "available_here": p.present.len(),
                    "installed": p.present.iter().filter(|(n, _)| existing.contains(&bundle_rule_id(b.name, n))).count(),
                })
            })
            .collect();
        return output::print_json(&serde_json::json!({ "bundles": rows }));
    }

    println!(
        "{:<10}  {:>9}  {:>9}  summary",
        "bundle", "available", "installed"
    );
    for b in &all {
        let p = plan(b);
        let installed = p
            .present
            .iter()
            .filter(|(n, _)| existing.contains(&bundle_rule_id(b.name, n)))
            .count();
        println!(
            "{:<10}  {:>9}  {:>9}  {}",
            b.name,
            format!("{}/{}", p.present.len(), b.rules.len()),
            installed,
            b.summary
        );
    }
    println!("\n`available` counts entries whose program is installed on this machine.");
    Ok(())
}

/// `cfc rules bundle add <name>`
pub async fn bundle_add(
    client: &mut Client,
    name: &str,
    dry_run: bool,
    format: OutputFormat,
) -> CliResult {
    let bundle = find_bundle(name)?;
    // Borrow the entries rather than rebuilding them. A field-by-field copy
    // here silently dropped `direction` and `src_net` once already, turning
    // "allow ssh inbound from the LAN" into an undirected "allow tcp/22" -
    // a rule that reads like policy and enforces something wider. A reference
    // cannot lose a field the next time one is added.
    let by_name: std::collections::HashMap<&str, &BundleRule> =
        bundle.rules.iter().map(|r| (r.name, r)).collect();

    let existing = client.list_rules().await?;

    let planned = plan(&bundle);
    let mut added = Vec::new();
    let mut skipped_present = 0u32;
    // A rule with an entry's name but another id was not installed by this
    // bundle. A copy seeded before 0.7.0 counts as present; any other one
    // stops the command before it changes anything.
    let legacy = legacy_copies(&bundle, &existing);
    for (rule_name, _) in &planned.present {
        let id = bundle_rule_id(bundle.name, rule_name);
        if let Some(rule) = existing
            .iter()
            .find(|rule| rule.name == *rule_name && rule.id != id && !legacy.contains(&rule.id))
        {
            return Err(CliError::runtime(format!(
                "bundle rule `{rule_name}` collides with rule {} of the same name, which this \
                 bundle did not install and which differs from it; rename or remove that rule \
                 and retry. Nothing was changed",
                short_id(&rule.id)
            )));
        }
    }

    for (rule_name, exe) in &planned.present {
        let id = bundle_rule_id(bundle.name, rule_name);
        if let Some(rule) = existing
            .iter()
            .find(|rule| rule.id == id || (rule.name == *rule_name && legacy.contains(&rule.id)))
        {
            let stored = rule.scope.as_ref().map_or("", |s| s.exe_path.as_str());
            if !format.is_json() && std::path::Path::new(stored) != exe.as_path() {
                println!(
                    "kept: {rule_name} pins {}, but this bundle now names {}; \
                     `bundle remove` and `bundle add` replace it",
                    output::terminal_safe(stored),
                    output::terminal_safe(&exe.to_string_lossy())
                );
            }
            skipped_present += 1;
            continue;
        }
        let spec = &by_name[*rule_name];
        if !dry_run {
            let mut rule = proto_for(spec, &exe.to_string_lossy());
            rule.id = id;
            client.upsert_rule(rule).await?;
        }
        if !format.is_json() {
            println!(
                "{}: {rule_name}  ({}{})",
                if dry_run { "would add" } else { "added" },
                output::terminal_safe(&exe.to_string_lossy()),
                spec.dst_port
                    .map(|p| format!(" -> :{p}"))
                    .unwrap_or_default()
            );
        }
        added.push(*rule_name);
    }

    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "bundle": bundle.name,
            "dry_run": dry_run,
            "added": added.len(),
            "already_present": skipped_present,
            "not_installed_here": planned.absent,
            "rules": added,
        }));
    }

    // Saying what was skipped is the point, not a footnote: a bundle that
    // quietly installs four of seven rules looks identical to one that
    // installed everything, and the difference is which programs can reach the
    // network.
    if !planned.absent.is_empty() {
        println!(
            "\nno program here that a rule can match (not installed, or only a launcher), so skipped ({}):",
            planned.absent.len()
        );
        for n in &planned.absent {
            println!("  {n}");
        }
    }
    println!(
        "\n{}: {} added, {skipped_present} already present, {} skipped",
        if dry_run { "dry-run" } else { "done" },
        added.len(),
        planned.absent.len()
    );
    Ok(())
}

/// `cfc rules bundle remove <name>`
///
/// Removes the deterministic IDs this bundle gives its rules, and the copies
/// of its entries seeded before 0.7.0 that still grant exactly what the entry
/// grants now or granted then (see [`legacy_copies`]), dropped entries
/// included. Any other rule, same name or not, is kept.
pub async fn bundle_remove(
    client: &mut Client,
    name: &str,
    dry_run: bool,
    format: OutputFormat,
) -> CliResult {
    let bundle = find_bundle(name)?;
    // Dropped entries included: older versions installed them too.
    let owned: std::collections::HashSet<String> = bundle
        .rules
        .iter()
        .chain(&pre_0_7_entries(&bundle))
        .map(|r| bundle_rule_id(bundle.name, r.name))
        .collect();

    let existing = client.list_rules().await?;
    let legacy = legacy_copies(&bundle, &existing);
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for r in existing
        .iter()
        .filter(|r| owned.contains(&r.id) || legacy.contains(&r.id))
    {
        // Bundles install only Allows. An editor keeps the id, so one that is
        // now a Deny or Reject is the user's decision, and deleting it would
        // let the traffic it stops through to the prompt or the default.
        if r.action != proto::Action::Allow as i32 {
            if !format.is_json() {
                println!(
                    "kept: {} ({}) was changed from allow; remove it by id if it should go",
                    short_id(&r.id),
                    output::terminal_safe(&r.name)
                );
            }
            kept.push(r.name.clone());
            continue;
        }
        if !dry_run {
            client.delete_rule(&r.id).await?;
        }
        if !format.is_json() {
            println!(
                "{}: {} ({})",
                if dry_run { "would remove" } else { "removed" },
                short_id(&r.id),
                output::terminal_safe(&r.name)
            );
        }
        removed.push(r.name.clone());
    }

    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "bundle": bundle.name,
            "dry_run": dry_run,
            "removed": removed.len(),
            "rules": removed,
            "kept": kept,
        }));
    }
    println!(
        "{}: {} removed",
        if dry_run { "dry-run" } else { "done" },
        removed.len()
    );
    Ok(())
}

/// `cfc rules bootstrap-defaults`, kept as the name people already know.
///
/// Exactly `bundle add system`. It predates bundles and is referenced from the
/// README, the packaging notes and TROUBLESHOOTING, so it stays - but there is
/// only one implementation behind the two spellings.
pub async fn bootstrap_defaults(
    client: &mut Client,
    dry_run: bool,
    format: OutputFormat,
) -> CliResult {
    bundle_add(client, "system", dry_run, format).await
}

#[cfg(test)]
mod bundle_tests {
    use super::*;

    // Hosts seeded before 0.7.0 hold the bundle's rules under random ids.
    // An identical copy is the bundle's own, for add and for remove; an
    // edited one is not.
    #[test]
    fn a_pre_0_7_copy_of_a_bundle_rule_counts_only_while_unchanged() {
        let bundle = find_bundle("inbound").unwrap();
        let entry = &bundle.rules[0];
        let wanted = proto_for(entry, "");
        let mut legacy = wanted.clone();
        legacy.id = "11111111-1111-4111-8111-111111111111".into();
        legacy.enabled = false;
        let mut deny = legacy.clone();
        deny.id = "22222222-2222-4222-8222-222222222222".into();
        deny.action = proto::Action::Deny as i32;
        let mut wider = legacy.clone();
        wider.id = "33333333-3333-4333-8333-333333333333".into();
        wider.scope.as_mut().unwrap().src_net.clear();
        let mut elsewhere = legacy.clone();
        elsewhere.id = "44444444-4444-4444-8444-444444444444".into();
        elsewhere.scope.as_mut().unwrap().exe_path = "/usr/local/bin/sshd".into();
        let found = legacy_copies(&bundle, &[legacy, deny, wider, elsewhere]);
        assert_eq!(
            found,
            std::collections::HashSet::from(["11111111-1111-4111-8111-111111111111".to_owned()])
        );
    }

    // `/usr/bin/firefox` on Arch is `exec /usr/lib/firefox/firefox`, and
    // `/usr/bin/cargo` under rustup is the rustup proxy. Neither is ever
    // /proc/<pid>/exe, so a rule pinned to one never fires.
    #[test]
    fn launchers_are_skipped_for_the_binary_that_connects() {
        let dir = std::env::temp_dir().join(format!("cfc-bundle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let script = dir.join("firefox");
        let real = dir.join("firefox-bin");
        let proxy = dir.join("rustup");
        std::fs::write(&script, "#!/bin/sh\nexec firefox-bin \"$@\"\n").unwrap();
        std::fs::write(&real, b"\x7fELF").unwrap();
        std::fs::write(&proxy, b"\x7fELF").unwrap();
        let leak = |p: &std::path::Path| -> &'static str {
            Box::leak(p.to_str().unwrap().to_owned().into_boxed_str())
        };
        let entry = |candidates: Vec<&'static str>| BundleRule {
            name: "test",
            exe_candidates: Box::leak(candidates.into_boxed_slice()),
            dst_port: Some(443),
            protocol: None,
            direction: None,
            src_net: None,
        };
        let resolved = entry(vec![leak(&script), leak(&real)]).resolve();
        assert_eq!(
            resolved,
            Some(cfc_core::exe_path::resolve(&real).into_path())
        );
        assert_eq!(entry(vec![leak(&script)]).resolve(), None);
        assert_eq!(entry(vec![leak(&proxy)]).resolve(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // 0.6.0 pinned the first candidate that existed, a launcher included, and
    // installed entries later versions re-pathed or dropped. Those copies are
    // still the bundle's own.
    #[test]
    fn a_pre_0_7_copy_pinned_to_the_old_path_is_the_bundles_own() {
        let dir = std::env::temp_dir().join(format!("cfc-bundle-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let script = dir.join("browser");
        let real = dir.join("browser-bin");
        std::fs::write(&script, "#!/bin/sh\nexec browser-bin \"$@\"\n").unwrap();
        std::fs::write(&real, b"\x7fELF").unwrap();
        let leak = |p: &std::path::Path| -> &'static str {
            Box::leak(p.to_str().unwrap().to_owned().into_boxed_str())
        };
        let entry = BundleRule {
            name: "test-https",
            exe_candidates: Box::leak(vec![leak(&script), leak(&real)].into_boxed_slice()),
            dst_port: Some(443),
            protocol: Some(proto::Protocol::Tcp),
            direction: None,
            src_net: None,
        };
        let bundle = Bundle {
            name: "test",
            summary: "",
            rules: vec![entry],
        };
        let seeded = |id: &str, exe: &std::path::Path| {
            let mut rule = proto_for(
                &entry,
                &cfc_core::exe_path::resolve(exe)
                    .into_path()
                    .to_string_lossy(),
            );
            rule.id = id.into();
            rule
        };
        let old = seeded("11111111-1111-4111-8111-111111111111", &script);
        let new = seeded("22222222-2222-4222-8222-222222222222", &real);
        let other = seeded("33333333-3333-4333-8333-333333333333", &dir);
        assert_eq!(
            legacy_copies(&bundle, &[old, new, other]),
            std::collections::HashSet::from([
                "11111111-1111-4111-8111-111111111111".to_owned(),
                "22222222-2222-4222-8222-222222222222".to_owned(),
            ])
        );
        std::fs::remove_dir_all(dir).unwrap();

        // The shipped history: a re-pathed entry keeps its scope apart from
        // the path, and the dropped ones are still known by name.
        let mut dropped = Vec::new();
        for bundle in bundles() {
            for past in pre_0_7_entries(&bundle) {
                match bundle.rules.iter().find(|r| r.name == past.name) {
                    Some(now) => assert_eq!(
                        (now.dst_port, now.protocol, now.direction, now.src_net),
                        (past.dst_port, past.protocol, past.direction, past.src_net),
                        "{}",
                        past.name
                    ),
                    None => dropped.push(past.name),
                }
            }
        }
        dropped.sort_unstable();
        assert_eq!(
            dropped,
            [
                "dev-npm-https",
                "dev-pip-https",
                "web-epiphany-http",
                "web-epiphany-https"
            ]
        );
    }

    /// The invariant the whole feature rests on.
    ///
    /// A bundle that installed a bare "allow tcp/443" outbound would re-open
    /// exactly the hole this program exists to close: a payload phoning home
    /// uses 443 like everything else, and a port-shaped rule cannot tell it
    /// from a browser. The type makes `exe_candidates` mandatory; this makes
    /// "empty list" - the way round it - impossible too.
    ///
    /// Inbound is the one exception, and it is not a loophole. There is no
    /// executable to name: the connection arrives before any process has
    /// accepted it, so the thing being authorised is genuinely a port, not a
    /// program. What replaces the exe as the narrowing predicate is the port
    /// itself, so an inbound entry that names neither is still refused - that
    /// would be "accept anything", which no bundle may install in either
    /// direction.
    #[test]
    fn every_bundle_rule_names_an_executable_or_is_a_scoped_inbound_one() {
        for b in bundles() {
            for r in &b.rules {
                if r.exe_candidates.is_empty() {
                    assert_eq!(
                        r.direction,
                        Some(proto::Direction::Inbound),
                        "{}/{} names no executable, which is only allowed for an \
                         inbound entry; outbound it would match on port alone",
                        b.name,
                        r.name
                    );
                    assert!(
                        r.dst_port.is_some(),
                        "{}/{} is inbound with neither an executable nor a port, \
                         so it would admit any new connection",
                        b.name,
                        r.name
                    );
                    continue;
                }
                for c in r.exe_candidates {
                    assert!(
                        c.starts_with('/'),
                        "{}/{}: candidate {c:?} is not absolute; rules match on \
                         absolute exe paths, so a relative one can never fire",
                        b.name,
                        r.name
                    );
                }
            }
        }
    }

    /// No inbound bundle entry may admit the whole internet.
    ///
    /// The `inbound` bundle shipped with `src_net: None` on mDNS, LLMNR and
    /// DHCP - three permanent Allow rules taking unicast UDP from any address
    /// on earth, on ports that are well-known reflection and spoofing
    /// surfaces. The bundle's own comment promised the opposite. An unscoped
    /// inbound entry is not "the LAN", it is the internet, and nothing in the
    /// type system says so.
    #[test]
    fn every_inbound_bundle_entry_names_a_source_network() {
        for b in bundles() {
            for r in &b.rules {
                if r.direction != Some(proto::Direction::Inbound) {
                    continue;
                }
                let net = r.src_net.unwrap_or_else(|| {
                    panic!(
                        "{}/{} admits any source: an inbound allow with no src_net \
                         is open to the internet",
                        b.name, r.name
                    )
                });
                let net: ipnet::IpNet = net
                    .parse()
                    .unwrap_or_else(|e| panic!("{}/{}: bad src_net {net:?}: {e}", b.name, r.name));
                // And it must be a range a LAN actually lives in - RFC1918,
                // IPv4 link-local, or IPv6 link-local (fe80::/10, where v6
                // mDNS/LLMNR speakers source from). Notably NOT a v6 global
                // or ULA range: the inbound chain filters dual-stack, and a
                // bundle must never widen past the link.
                let private = [
                    "192.168.0.0/16",
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "169.254.0.0/16",
                    "fe80::/10",
                ]
                .iter()
                .map(|s| s.parse::<ipnet::IpNet>().unwrap())
                .any(|p| p.contains(&net));
                assert!(
                    private,
                    "{}/{}: src_net {net} is not a private range",
                    b.name, r.name
                );
            }
        }
    }

    /// Every predicate in a bundle entry must survive the trip to the daemon.
    ///
    /// This is a regression test with a scar: `bundle add` used to rebuild the
    /// entry field-by-field on the way to `allow_rule`, and the rebuild passed
    /// `None` for `direction` and `src_net`. `cfc rules bundle add inbound`
    /// reported "4 added" and wrote four rules that said "allow tcp/22" with no
    /// direction and no source - wider than what the bundle says, and wider in
    /// the outbound direction too. Nothing caught it because the definitions
    /// were tested and the wire format was tested, but not the step between.
    #[test]
    fn bundle_add_sends_every_predicate_the_entry_declares() {
        for b in bundles() {
            for r in &b.rules {
                let sent = proto_for(r, "/usr/bin/example");
                let scope = sent.scope.as_ref().expect("a bundle rule must be scoped");

                assert_eq!(
                    scope.has_direction,
                    r.direction.is_some(),
                    "{}/{}: direction lost between the entry and the wire",
                    b.name,
                    r.name
                );
                if let Some(d) = r.direction {
                    assert_eq!(scope.direction, d as i32, "{}/{}", b.name, r.name);
                }

                let sent_src_net = (!scope.src_net.is_empty()).then_some(scope.src_net.as_str());
                assert_eq!(
                    sent_src_net, r.src_net,
                    "{}/{}: src_net lost between the entry and the wire",
                    b.name, r.name
                );

                assert_eq!(
                    scope.has_dst_port,
                    r.dst_port.is_some(),
                    "{}/{}: dst_port lost",
                    b.name,
                    r.name
                );
                if let Some(p) = r.dst_port {
                    assert_eq!(scope.dst_port, u32::from(p), "{}/{}", b.name, r.name);
                }

                assert_eq!(
                    scope.has_protocol,
                    r.protocol.is_some(),
                    "{}/{}: protocol lost",
                    b.name,
                    r.name
                );
            }
        }
    }

    /// The inbound bundle's mDNS/LLMNR promise is dual-stack, because the
    /// inbound chain is (`table inet`). With only IPv4 CIDRs, IPv6 queries
    /// from neighbours' fe80:: addresses matched no rule and hit the inbound
    /// default - which config forbids being Allow - so v6-only speakers
    /// vanished from discovery in exactly the hard-to-attribute way the
    /// bundle's own comment warns about.
    #[test]
    fn the_inbound_bundle_covers_v6_linklocal_mdns_and_llmnr() {
        let inbound = bundles()
            .into_iter()
            .find(|b| b.name == "inbound")
            .expect("the inbound bundle exists");
        for port in [5353u16, 5355] {
            assert!(
                inbound
                    .rules
                    .iter()
                    .any(|r| { r.dst_port == Some(port) && r.src_net == Some("fe80::/10") }),
                "no fe80::/10 entry for port {port}: the bundle would break \
                 IPv6 mDNS/LLMNR while promising LAN discovery"
            );
        }

        // And the rule model genuinely matches a v6 link-local source against
        // that CIDR - otherwise the entries would list, rank, and never fire.
        let scope = cfc_core::RuleScope {
            direction: Some(cfc_core::Direction::Inbound),
            src_net: Some("fe80::/10".parse().unwrap()),
            dst_port: Some(5353),
            protocol: Some(cfc_core::Protocol::Udp),
            ..cfc_core::RuleScope::any()
        };
        let unattributed = cfc_core::Process::unknown(0);
        let v6_neighbour = cfc_core::Connection::new(
            cfc_core::Protocol::Udp,
            cfc_core::Direction::Inbound,
            "fe80::1234:5678:9abc:def0".parse().unwrap(),
            5353,
            "ff02::fb".parse().unwrap(),
            5353,
        );
        assert!(
            scope.matches(&v6_neighbour, &unattributed),
            "an fe80:: mDNS packet must match the v6 link-local entry"
        );

        // Family mismatch is a non-match, not a wildcard: the v6 entry must
        // not quietly admit IPv4 peers.
        let v4_neighbour = cfc_core::Connection::new(
            cfc_core::Protocol::Udp,
            cfc_core::Direction::Inbound,
            "192.168.1.20".parse().unwrap(),
            5353,
            "224.0.0.251".parse().unwrap(),
            5353,
        );
        assert!(!scope.matches(&v4_neighbour, &unattributed));
    }

    /// `bundle remove` deletes by exact rule name. If two bundles ever shared
    /// one, removing either would silently take the other's rule with it.
    #[test]
    fn rule_names_are_unique_across_every_bundle() {
        let mut seen: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
        for b in bundles() {
            for r in &b.rules {
                if let Some(other) = seen.insert(r.name.to_string(), b.name) {
                    panic!(
                        "rule name {:?} is in both `{other}` and `{}`; removing \
                         one bundle would delete the other's rule",
                        r.name, b.name
                    );
                }
            }
        }
    }

    #[test]
    fn bundle_names_are_unique() {
        let names: Vec<&str> = bundles().iter().map(|b| b.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            names.len(),
            "duplicate bundle name in {names:?}"
        );
    }

    /// `bootstrap-defaults` is now `bundle add system`, and people have that
    /// command in scripts and in the README. The rule *names* are the
    /// contract, because they are what makes it idempotent across upgrades:
    /// the set may gain members, but must never silently lose or rename one.
    #[test]
    fn the_system_bundle_still_contains_the_original_twelve() {
        const ORIGINAL: &[&str] = &[
            "default-systemd-resolved-dns",
            "default-systemd-timesyncd",
            "default-chrony",
            "default-pacman-https",
            "default-paru-https",
            "default-ssh-client",
            "default-dhcpcd",
            "default-dhcpcd-v6",
            "default-networkmanager-dhcp",
            "default-networkmanager-dhcp6",
            "default-networkd-dhcp",
            "default-networkd-dhcp6",
        ];
        let system = bundles()
            .into_iter()
            .find(|b| b.name == "system")
            .expect("the `system` bundle must exist: bootstrap-defaults delegates to it");
        let have: std::collections::HashSet<&str> = system.rules.iter().map(|r| r.name).collect();
        for want in ORIGINAL {
            assert!(
                have.contains(want),
                "{want} disappeared from the `system` bundle; an upgrade would \
                 stop recognising the rule it installed last time and add a \
                 duplicate under a new name"
            );
        }
    }

    /// `resolve` must pick the first candidate that exists, and answer `None`
    /// rather than guessing when none does.
    #[test]
    fn resolve_picks_the_first_existing_candidate() {
        // /proc/self/exe and / are the two paths that certainly exist on any
        // Linux running this test; only the first is a file.
        let r = BundleRule {
            name: "t",
            exe_candidates: &["/definitely/not/here", "/proc/self/exe"],
            dst_port: Some(443),
            protocol: Some(proto::Protocol::Tcp),
            direction: None,
            src_net: None,
        };
        // /proc/self/exe is itself a symlink to the running binary, so this
        // also proves the candidate is resolved rather than stored verbatim -
        // a rule for the link would never match.
        let got = r.resolve().expect("the second candidate exists");
        assert_eq!(
            got,
            std::fs::canonicalize("/proc/self/exe").expect("canonicalize")
        );
        assert_ne!(got, PathBuf::from("/proc/self/exe"));

        let none = BundleRule {
            name: "t",
            exe_candidates: &["/definitely/not/here", "/nor/here"],
            ..r
        };
        assert_eq!(
            none.resolve(),
            None,
            "a missing program must be skipped, not guessed"
        );

        // A directory is not an executable; `is_file` is what rejects it.
        let dir = BundleRule {
            name: "t",
            exe_candidates: &["/tmp"],
            ..r
        };
        assert_eq!(
            dir.resolve(),
            None,
            "a directory must not resolve as a program"
        );
    }

    /// Every bundle a user can name must be reachable, and an unknown one must
    /// say what there is rather than failing blankly.
    #[test]
    fn find_bundle_is_case_insensitive_and_lists_alternatives_on_a_miss() {
        assert!(find_bundle("SYSTEM").is_ok());
        assert!(find_bundle("system").is_ok());
        let e = match find_bundle("nope") {
            Err(e) => e.to_string(),
            Ok(b) => panic!("`nope` should not resolve, got `{}`", b.name),
        };
        for b in bundles() {
            assert!(
                e.contains(b.name),
                "the error should list `{}`: {e}",
                b.name
            );
        }
    }
}
