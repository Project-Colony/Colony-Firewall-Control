//! `cfc rules ...`: CRUD, import/export and id resolution.

use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};
use anyhow::Context;
use cfc_client::{convert, proto, Client};
use std::path::PathBuf;

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
                .map(|(id, name)| format!("\n  {id}  {name}"))
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
            convert::duration_label(r.duration),
            r.hit_count,
            output::truncate(&r.name, name_w),
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
            s.to_string()
        }
    };
    println!("id           {}", rule.id);
    println!("name         {}", rule.name);
    println!("enabled      {}", if rule.enabled { "yes" } else { "no" });
    println!("action       {}", convert::action_label(rule.action));
    println!("duration     {}", convert::duration_label(rule.duration));
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
    let rule = resolve_via_daemon(client, needle).await?;
    let deleted = client.delete_rule(&rule.id).await?;
    if !deleted {
        // The rule was listed a moment ago, so this is a race with another
        // client rather than a typo - still "not found" for the caller.
        return Err(CliError::not_found(format!(
            "rule {} disappeared before it could be deleted",
            rule.id
        )));
    }
    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "deleted": true, "id": rule.id, "name": rule.name,
        }));
    }
    println!("deleted {} ({})", rule.id, rule.name);
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
        println!("{} ({}): already {}", rule.id, rule.name, label(was));
    } else {
        println!(
            "{} ({}): {} -> {}",
            rule.id,
            rule.name,
            label(was),
            label(want)
        );
    }
    Ok(())
}

#[derive(Debug, clap::Args)]
pub struct AddArgs {
    /// Human-readable rule name.
    #[arg(long)]
    pub name: Option<String>,

    /// Verdict to apply when the rule matches.
    #[arg(long, value_enum, default_value_t = ActionArg::Allow)]
    pub action: ActionArg,

    /// How long to keep the rule.
    #[arg(long, value_enum, default_value_t = DurationArg::Always)]
    pub duration: DurationArg,

    /// Match flows from this executable path.
    #[arg(long)]
    pub exe: Option<PathBuf>,

    /// Match flows owned by this uid.
    #[arg(long)]
    pub uid: Option<u32>,

    /// Match flows whose dst hostname equals this string.
    #[arg(long = "dst-host")]
    pub dst_host: Option<String>,

    /// Match flows whose dst IP falls in this CIDR (e.g. 192.0.2.0/24).
    #[arg(long = "dst-net")]
    pub dst_net: Option<String>,

    /// Match flows targeting this destination port.
    #[arg(long = "dst-port")]
    pub dst_port: Option<u16>,

    /// Match flows of this protocol.
    #[arg(long, value_enum)]
    pub protocol: Option<ProtocolArg>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ActionArg {
    Allow,
    Deny,
    Reject,
}

impl ActionArg {
    pub fn to_proto(self) -> proto::Action {
        match self {
            ActionArg::Allow => proto::Action::Allow,
            ActionArg::Deny => proto::Action::Deny,
            ActionArg::Reject => proto::Action::Reject,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum DurationArg {
    Once,
    UntilRestart,
    Always,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ProtocolArg {
    Tcp,
    Udp,
    Icmp,
}

impl ProtocolArg {
    fn to_proto(self) -> proto::Protocol {
        match self {
            ProtocolArg::Tcp => proto::Protocol::Tcp,
            ProtocolArg::Udp => proto::Protocol::Udp,
            ProtocolArg::Icmp => proto::Protocol::Icmp,
        }
    }
}

pub async fn add(client: &mut Client, args: AddArgs, format: OutputFormat) -> CliResult {
    if let Some(net) = &args.dst_net {
        net.parse::<ipnet::IpNet>()
            .with_context(|| format!("--dst-net {net} is not a valid CIDR"))?;
    }

    let duration = match args.duration {
        DurationArg::Once => proto::Duration::Once,
        DurationArg::UntilRestart => proto::Duration::UntilRestart,
        DurationArg::Always => proto::Duration::Always,
    };

    // Resolve the path to the form /proc reports, and say so. Rules match on
    // exact string equality, so `--exe /bin/curl` on a usr-merged host produces
    // a rule that lists, ranks by specificity, and never fires - the worst
    // failure a rule can have, because it is indistinguishable from working.
    let exe = match args.exe.as_deref() {
        Some(p) => {
            let outcome = cfc_core::exe_path::resolve(p);
            if let Some(note) = outcome.note() {
                if outcome.is_inert() {
                    eprintln!("warning: {note}");
                } else {
                    eprintln!("note: {note}");
                }
            }
            outcome.into_path().to_string_lossy().into_owned()
        }
        None => String::new(),
    };

    let scope = proto::RuleScope {
        exe_path: exe,
        exe_sha256: String::new(),
        parent_exe: String::new(),
        uid: args.uid.unwrap_or(0),
        has_uid: args.uid.is_some(),
        dst_host: args.dst_host.clone().unwrap_or_default(),
        dst_net: args.dst_net.clone().unwrap_or_default(),
        dst_port: args.dst_port.map(u32::from).unwrap_or(0),
        has_dst_port: args.dst_port.is_some(),
        protocol: args.protocol.map(|p| p.to_proto() as i32).unwrap_or(0),
        has_protocol: args.protocol.is_some(),
    };

    let name = args.name.unwrap_or_else(|| "cli-added".into());
    let rule = proto::RuleInfo {
        id: String::new(),
        name: name.clone(),
        enabled: true,
        action: args.action.to_proto() as i32,
        duration: duration as i32,
        scope: Some(scope),
        created_at_unix_ms: 0,
        hit_count: 0,
    };

    let id = client.upsert_rule(rule).await?;
    if format.is_json() {
        return output::print_json(&serde_json::json!({ "id": id, "name": name }));
    }
    println!("added rule {id}");
    Ok(())
}

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

    // --- 1. validate everything before touching anything --------------------
    //
    // The old order was: delete every existing rule, then upsert one at a time
    // and abort on the first failure. A single unrecognised field therefore
    // left the daemon with an **emptied** rule set and a partial import - and
    // because the nftables ruleset is fail-closed, an emptied rule set is not a
    // degraded firewall, it is a machine with no outbound network. Validating
    // first turns that class of failure into "nothing happened, here is why".
    let mut pending = Vec::with_capacity(rules.len());
    let mut problems = Vec::new();
    for r in rules {
        match r.try_into_proto() {
            Ok(pb) => pending.push(pb),
            Err(e) => problems.push(e),
        }
    }
    if !problems.is_empty() {
        // Every problem, not just the first: an operator fixing an export by
        // hand should learn about all of them in one pass.
        for p in &problems {
            eprintln!("  {p}");
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

    // --- 2. apply, in the order that has no empty window --------------------
    //
    // Upserts first, deletions last. There is no server-side transaction, so
    // something has to be the failure window; making it "old rules linger"
    // rather than "no rules at all" is the only choice that cannot take the
    // machine's network down. Lingering rules are the status quo of a second
    // ago, not a new grant.
    let existing = if replace {
        client.list_rules().await?
    } else {
        Vec::new()
    };

    let mut imported = 0u32;
    let mut imported_ids = std::collections::HashSet::new();
    for pb in pending {
        let name = pb.name.clone();
        // The id the *daemon* returns, not the one the file carried. `parse_str`
        // accepts uppercase, braced and 32-char forms; the daemon stores the
        // canonical lowercase-hyphenated one and lists it back that way. Keying
        // this set on the file's spelling meant an id that differed only in
        // case upserted onto an existing rule and was then deleted by the
        // cleanup below as "absent from the import" - the exact bug the e2e
        // test was written to pin, invisible to it because the fake daemon
        // echoed the id back verbatim.
        //
        // Using the response also covers the mint-a-new-one case, where the
        // file has no id at all and only the daemon knows what it became.
        let assigned = client.upsert_rule(pb).await.with_context(|| {
            format!("importing rule `{name}`; {imported} rules were already applied")
        })?;
        imported_ids.insert(assigned);
        imported += 1;
    }

    // Only now, and only for rules the import did not already carry: an
    // imported rule that shares an id with an existing one was *updated* by the
    // upsert above, so deleting it here would throw away the thing just
    // imported. That is the bug this set exists to prevent.
    let mut removed = 0u32;
    if replace {
        for r in &existing {
            if imported_ids.contains(r.id.as_str()) {
                continue;
            }
            // `delete_rule` answers whether a rule was actually there; another
            // client may have removed it between the listing above and now.
            // Counting it anyway would report a removal that did not happen.
            if client
                .delete_rule(&r.id)
                .await
                .with_context(|| format!("removing rule `{}`, absent from the import", r.id))?
            {
                removed += 1;
            }
        }
    }

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

// ---------------------------------------------------------------------------
// Export / import format
// ---------------------------------------------------------------------------

/// Format for `cfc rules export` / `import` and `rules list --json`.
/// Wire-compatible with the in-process Rule type but stable across daemon
/// versions.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
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
    pub scope: ExportedScope,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
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

fn default_true() -> bool {
    true
}

fn default_duration() -> String {
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
        let duration = match self.duration.to_ascii_lowercase().as_str() {
            "always" => proto::Duration::Always,
            "once" => proto::Duration::Once,
            "until-restart" | "until_restart" => proto::Duration::UntilRestart,
            other => return Err(bad("duration", other, "always, once, until-restart")),
        };
        let protocol_idx = match self.scope.protocol.as_deref() {
            None => None,
            Some(p) => Some(match p.to_ascii_lowercase().as_str() {
                "tcp" => proto::Protocol::Tcp as i32,
                "udp" => proto::Protocol::Udp as i32,
                "icmp" => proto::Protocol::Icmp as i32,
                other => return Err(bad("protocol", other, "tcp, udp, icmp")),
            }),
        };
        // Checked here as well as in the daemon so the message can say which
        // rule in the file is at fault; the daemon only ever sees one rule at a
        // time and cannot.
        if let Some(net) = self.scope.dst_net.as_deref() {
            net.parse::<ipnet::IpNet>()
                .map_err(|e| format!("rule `{name}`: bad dst_net `{net}`: {e}"))?;
        }
        if !self.id.is_empty() {
            uuid::Uuid::parse_str(&self.id)
                .map_err(|e| format!("rule `{name}`: bad id `{}`: {e}", self.id))?;
        }
        let scope = proto::RuleScope {
            exe_path: self.scope.exe_path.unwrap_or_default(),
            exe_sha256: self.scope.exe_sha256.unwrap_or_default(),
            parent_exe: self.scope.parent_exe.unwrap_or_default(),
            uid: self.scope.uid.unwrap_or(0),
            has_uid: self.scope.uid.is_some(),
            dst_host: self.scope.dst_host.unwrap_or_default(),
            dst_net: self.scope.dst_net.unwrap_or_default(),
            dst_port: self.scope.dst_port.map(u32::from).unwrap_or(0),
            has_dst_port: self.scope.dst_port.is_some(),
            protocol: protocol_idx.unwrap_or(0),
            has_protocol: protocol_idx.is_some(),
        };
        Ok(proto::RuleInfo {
            id: self.id,
            name: self.name,
            enabled: self.enabled,
            action: action as i32,
            duration: duration as i32,
            scope: Some(scope),
            created_at_unix_ms: 0,
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
        },
    }
}

pub fn proto_rules_to_export(rules: &[proto::RuleInfo]) -> Vec<ExportedRule> {
    rules.iter().map(exported_rule).collect()
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

// ---------------------------------------------------------------------------
// opensnitch import
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct OsnRule {
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_allow_str")]
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
    #[serde(default)]
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

fn default_allow_str() -> String {
    "allow".into()
}

pub async fn import_opensnitch(
    client: &mut Client,
    path: PathBuf,
    replace: bool,
    format: OutputFormat,
) -> CliResult {
    let files: Vec<PathBuf> = if path.is_dir() {
        std::fs::read_dir(&path)
            .with_context(|| format!("reading dir {}", path.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect()
    } else {
        vec![path.clone()]
    };

    if files.is_empty() {
        return Err(CliError::runtime(format!(
            "no .json files found under {}",
            path.display()
        )));
    }

    // Same shape as `import`, and for the same reason: this used to delete every
    // existing rule *first*, then upsert one at a time and abort with `?` on the
    // first daemon rejection. That was already a way to end up with an emptied
    // rule set against a fail-closed table; making `scope_from_pb` strict about
    // CIDRs turned it from unlikely into ordinary, because opensnitch rule files
    // carry destination data this converter passes through untouched.
    //
    // Convert everything first. A file that will not convert is skipped and
    // counted, as before - opensnitch exports routinely contain rules with no
    // CFC equivalent - but a *daemon* rejection now cannot happen after the
    // deletions, because the deletions happen last.
    let mut pending = Vec::new();
    let mut skipped = 0u32;
    for file in &files {
        let json =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let osn: OsnRule = match serde_json::from_str(&json) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip {}: parse error: {e}", file.display());
                skipped += 1;
                continue;
            }
        };
        match convert_opensnitch(file, osn) {
            Ok(rule) => pending.push(rule),
            Err(e) => {
                eprintln!("skip {}: {e}", file.display());
                skipped += 1;
            }
        }
    }
    if replace && pending.is_empty() {
        return Err(anyhow::anyhow!(
            "refusing --replace: none of the {} file(s) converted, so this would \
             delete every existing rule and import nothing",
            files.len()
        )
        .into());
    }

    // Upserts first, deletions last - see `import`.
    let existing = if replace {
        client.list_rules().await?
    } else {
        Vec::new()
    };

    let mut imported = 0u32;
    let mut imported_ids = std::collections::HashSet::new();
    for rule in pending {
        let name = rule.name.clone();
        let assigned = client.upsert_rule(rule).await.with_context(|| {
            format!("importing `{name}`; {imported} rules were already applied")
        })?;
        imported_ids.insert(assigned);
        imported += 1;
    }

    let mut removed = 0u32;
    if replace {
        for r in &existing {
            if imported_ids.contains(r.id.as_str()) {
                continue;
            }
            if client
                .delete_rule(&r.id)
                .await
                .with_context(|| format!("removing rule `{}`, absent from the import", r.id))?
            {
                removed += 1;
            }
        }
    }

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
    // trust. A rule that cannot be converted is skipped and counted, which is
    // already how this command handles anything it does not understand.
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
        "once" => proto::Duration::Once,
        "until restart" | "until-restart" | "restart" => proto::Duration::UntilRestart,
        other => {
            anyhow::bail!("unknown duration `{other}` (expected always, once or until restart)")
        }
    };

    let mut scope = proto::RuleScope::default();
    if let Some(op) = osn.operator {
        apply_operator(&op, &mut scope)?;
    }

    let scope_empty = scope.exe_path.is_empty()
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

fn apply_operator(op: &OsnOperator, scope: &mut proto::RuleScope) -> anyhow::Result<()> {
    match op {
        OsnOperator::Simple(s) | OsnOperator::Regexp(s) => apply_simple(s, scope),
        OsnOperator::List(l) => {
            for sub in &l.list {
                apply_operator(sub, scope)?;
            }
            Ok(())
        }
    }
}

fn apply_simple(s: &OsnSimple, scope: &mut proto::RuleScope) -> anyhow::Result<()> {
    match s.operand.as_str() {
        "process.path" => scope.exe_path = s.data.clone(),
        "process.hash.sha256" => scope.exe_sha256 = s.data.clone(),
        "user.id" => {
            if let Ok(uid) = s.data.parse::<u32>() {
                scope.uid = uid;
                scope.has_uid = true;
            }
        }
        "dest.host" | "dest.domain" => scope.dst_host = s.data.clone(),
        "dest.ip" => {
            // single IP -> /32 or /128
            if s.data.contains(':') {
                scope.dst_net = format!("{}/128", s.data);
            } else {
                scope.dst_net = format!("{}/32", s.data);
            }
        }
        "dest.network" => scope.dst_net = s.data.clone(),
        "dest.port" => {
            if let Ok(port) = s.data.parse::<u32>() {
                scope.dst_port = port;
                scope.has_dst_port = true;
            }
        }
        "protocol" => {
            let proto = match s.data.to_ascii_uppercase().as_str() {
                "TCP" => Some(proto::Protocol::Tcp as i32),
                "UDP" => Some(proto::Protocol::Udp as i32),
                "ICMP" => Some(proto::Protocol::Icmp as i32),
                _ => None,
            };
            if let Some(p) = proto {
                scope.protocol = p;
                scope.has_protocol = true;
            }
        }
        // Operands we don't yet support: process.command, process.id,
        // iface.in/out. Silently skip them.
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bootstrap defaults
// ---------------------------------------------------------------------------

/// One rule a bundle would install.
///
/// # Every entry names an executable. On purpose.
///
/// A bundle must never install a bare "allow tcp/443". That is precisely the
/// hole this program exists to close: a payload phoning home uses 443 exactly
/// like a browser does, and a port-shaped rule cannot tell them apart. What
/// makes a rule worth having is the pairing - *this binary* may reach *this
/// port* - so `exe_candidates` is not optional and there is no way to express
/// a rule without it.
///
/// # Why a list of candidates
///
/// Binary paths differ per distribution: `/usr/bin/NetworkManager` on Arch,
/// `/usr/sbin/NetworkManager` on Debian. Hardcoding one path would make a
/// bundle silently install nothing useful on half the machines that run it.
/// The first candidate that **exists on this machine** is used; if none does,
/// the entry is skipped and said out loud, so "installed 4 of 7, skipped 3 not
/// present" is a normal, legible outcome rather than a silent partial success.
struct BundleRule {
    name: &'static str,
    /// Absolute paths to try, in order. First one that exists wins.
    exe_candidates: &'static [&'static str],
    dst_host: Option<&'static str>,
    dst_port: Option<u16>,
    protocol: Option<proto::Protocol>,
}

impl BundleRule {
    /// The path to use on this machine, or `None` if the program is not here.
    ///
    /// `is_file()` follows symlinks, so the first *existing* candidate can be a
    /// link — and a rule stored for the link never matches, because /proc
    /// reports the target. The shipped lists happen to put `/usr/...` first
    /// everywhere, so they escaped this by luck rather than design; a
    /// distribution that lays things out differently would not have.
    fn resolve(&self) -> Option<PathBuf> {
        self.exe_candidates
            .iter()
            .copied()
            .find(|p| std::path::Path::new(p).is_file())
            .map(|p| cfc_core::exe_path::resolve(std::path::Path::new(p)).into_path())
    }
}

/// A named, selectable set of rules.
struct Bundle {
    name: &'static str,
    summary: &'static str,
    rules: Vec<BundleRule>,
}

/// Every bundle this build knows about.
///
/// `system` is byte-for-byte the set `bootstrap-defaults` has always
/// installed - same twelve rule names, same ports - so that command keeps
/// working and existing installs see no change. What it gains is alternative
/// paths for distributions that put these binaries elsewhere.
fn bundles() -> Vec<Bundle> {
    use proto::Protocol::{Tcp, Udp};
    vec![
        Bundle {
            name: "system",
            summary: "what a machine needs to boot, resolve names, keep time and be updated",
            rules: vec![
                // DNS - systemd-resolved owns the stub.
                BundleRule {
                    name: "default-systemd-resolved-dns",
                    exe_candidates: &[
                        "/usr/lib/systemd/systemd-resolved",
                        "/lib/systemd/systemd-resolved",
                    ],
                    dst_host: None,
                    dst_port: Some(53),
                    protocol: None,
                },
                // NTP - timesyncd or chrony.
                BundleRule {
                    name: "default-systemd-timesyncd",
                    exe_candidates: &[
                        "/usr/lib/systemd/systemd-timesyncd",
                        "/lib/systemd/systemd-timesyncd",
                    ],
                    dst_host: None,
                    dst_port: Some(123),
                    protocol: Some(Udp),
                },
                BundleRule {
                    name: "default-chrony",
                    exe_candidates: &["/usr/bin/chronyd", "/usr/sbin/chronyd"],
                    dst_host: None,
                    dst_port: Some(123),
                    protocol: Some(Udp),
                },
                // Package managers - HTTPS mirrors.
                BundleRule {
                    name: "default-pacman-https",
                    exe_candidates: &["/usr/bin/pacman"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "default-paru-https",
                    exe_candidates: &["/usr/bin/paru"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                // SSH client.
                BundleRule {
                    name: "default-ssh-client",
                    exe_candidates: &["/usr/bin/ssh"],
                    dst_host: None,
                    dst_port: Some(22),
                    protocol: Some(Tcp),
                },
                // DHCP clients. The units are ordered Before=network-pre.target,
                // so filtering is live before any interface is configured: these
                // rules are what lets the machine get a lease at boot with no UI
                // connected yet to answer prompts. (The very first DISCOVER goes
                // over an AF_PACKET raw socket that bypasses netfilter anyway;
                // these cover the routed unicast renewals, v4 on 67/udp and
                // DHCPv6 on 547/udp.)
                BundleRule {
                    name: "default-dhcpcd",
                    exe_candidates: &["/usr/bin/dhcpcd", "/usr/sbin/dhcpcd"],
                    dst_host: None,
                    dst_port: Some(67),
                    protocol: Some(Udp),
                },
                BundleRule {
                    name: "default-dhcpcd-v6",
                    exe_candidates: &["/usr/bin/dhcpcd", "/usr/sbin/dhcpcd"],
                    dst_host: None,
                    dst_port: Some(547),
                    protocol: Some(Udp),
                },
                BundleRule {
                    name: "default-networkmanager-dhcp",
                    exe_candidates: &["/usr/bin/NetworkManager", "/usr/sbin/NetworkManager"],
                    dst_host: None,
                    dst_port: Some(67),
                    protocol: Some(Udp),
                },
                BundleRule {
                    name: "default-networkmanager-dhcp6",
                    exe_candidates: &["/usr/bin/NetworkManager", "/usr/sbin/NetworkManager"],
                    dst_host: None,
                    dst_port: Some(547),
                    protocol: Some(Udp),
                },
                BundleRule {
                    name: "default-networkd-dhcp",
                    exe_candidates: &[
                        "/usr/lib/systemd/systemd-networkd",
                        "/lib/systemd/systemd-networkd",
                    ],
                    dst_host: None,
                    dst_port: Some(67),
                    protocol: Some(Udp),
                },
                BundleRule {
                    name: "default-networkd-dhcp6",
                    exe_candidates: &[
                        "/usr/lib/systemd/systemd-networkd",
                        "/lib/systemd/systemd-networkd",
                    ],
                    dst_host: None,
                    dst_port: Some(547),
                    protocol: Some(Udp),
                },
            ],
        },
        Bundle {
            name: "updates",
            summary: "package managers beyond pacman/paru, which are in `system`",
            rules: vec![
                BundleRule {
                    name: "updates-apt-https",
                    exe_candidates: &["/usr/bin/apt-get", "/usr/lib/apt/methods/https"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                // Debian mirrors are still commonly plain HTTP; the packages
                // are signed, so the transport is not what protects them.
                BundleRule {
                    name: "updates-apt-http",
                    exe_candidates: &["/usr/bin/apt-get", "/usr/lib/apt/methods/http"],
                    dst_host: None,
                    dst_port: Some(80),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "updates-dnf-https",
                    exe_candidates: &["/usr/bin/dnf", "/usr/bin/dnf5"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "updates-flatpak-https",
                    exe_candidates: &["/usr/bin/flatpak"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "updates-yay-https",
                    exe_candidates: &["/usr/bin/yay"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
            ],
        },
        Bundle {
            name: "web",
            summary: "installed browsers, for HTTPS and the HTTP that redirects to it",
            rules: browser_rules(),
        },
        Bundle {
            name: "dev",
            summary: "the tools that fetch code and dependencies",
            rules: vec![
                // git speaks both: HTTPS remotes and ssh:// remotes.
                BundleRule {
                    name: "dev-git-https",
                    exe_candidates: &["/usr/bin/git"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "dev-git-ssh",
                    exe_candidates: &["/usr/bin/git"],
                    dst_host: None,
                    dst_port: Some(22),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "dev-cargo-https",
                    exe_candidates: &["/usr/bin/cargo"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "dev-npm-https",
                    exe_candidates: &["/usr/bin/npm", "/usr/bin/node"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "dev-pip-https",
                    exe_candidates: &["/usr/bin/pip", "/usr/bin/pip3"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
                BundleRule {
                    name: "dev-docker-https",
                    exe_candidates: &["/usr/bin/dockerd", "/usr/bin/podman"],
                    dst_host: None,
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                },
            ],
        },
    ]
}

/// One HTTPS and one HTTP rule per browser this build knows about.
///
/// HTTP is included because a great deal of the web is still reached by an
/// http:// link that redirects; a browser allowed only 443 fails in a way
/// users read as "the internet is broken" rather than "the firewall did that".
fn browser_rules() -> Vec<BundleRule> {
    /// `(rule stem, candidate paths)`.
    const BROWSERS: &[(&str, &[&str])] = &[
        ("firefox", &["/usr/bin/firefox", "/usr/lib/firefox/firefox"]),
        ("librewolf", &["/usr/bin/librewolf"]),
        (
            "chromium",
            &["/usr/bin/chromium", "/usr/lib/chromium/chromium"],
        ),
        ("chrome", &["/usr/bin/google-chrome-stable"]),
        ("brave", &["/usr/bin/brave"]),
        ("vivaldi", &["/usr/bin/vivaldi-stable"]),
        ("epiphany", &["/usr/bin/epiphany"]),
    ];

    // `&'static str` names are needed by `BundleRule`, and these are built at
    // run time, so the table below is spelled out rather than formatted. It is
    // the price of keeping rule names stable and greppable.
    const HTTPS: u16 = 443;
    const HTTP: u16 = 80;
    let mut out = Vec::with_capacity(BROWSERS.len() * 2);
    for (stem, paths) in BROWSERS {
        for (port, suffix) in [(HTTPS, "https"), (HTTP, "http")] {
            out.push(BundleRule {
                // Leaked once, at startup, for a fixed and tiny set. The
                // alternative is threading lifetimes through the whole bundle
                // type for names that live as long as the process anyway.
                name: Box::leak(format!("web-{stem}-{suffix}").into_boxed_str()),
                exe_candidates: paths,
                dst_host: None,
                dst_port: Some(port),
                protocol: Some(proto::Protocol::Tcp),
            });
        }
    }
    out
}

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
    /// Entries skipped because no candidate path exists.
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

fn allow_rule(
    name: &str,
    exe: &str,
    port: Option<u16>,
    proto_: Option<proto::Protocol>,
) -> proto::RuleInfo {
    proto::RuleInfo {
        id: String::new(),
        name: name.to_string(),
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
            dst_port: port.map(u32::from).unwrap_or(0),
            has_dst_port: port.is_some(),
            protocol: proto_.map(|p| p as i32).unwrap_or(0),
            has_protocol: proto_.is_some(),
        }),
        created_at_unix_ms: 0,
        hit_count: 0,
    }
}

/// `cfc rules bundle list`
pub async fn bundle_list(client: &mut Client, format: OutputFormat) -> CliResult {
    let existing: std::collections::HashSet<String> = client
        .list_rules()
        .await?
        .into_iter()
        .map(|r| r.name)
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
                    "installed": p.present.iter().filter(|(n, _)| existing.contains(*n)).count(),
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
            .filter(|(n, _)| existing.contains(*n))
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
    let by_name: std::collections::HashMap<String, BundleRule> = bundle
        .rules
        .iter()
        .map(|r| {
            (
                r.name.to_string(),
                BundleRule {
                    name: r.name,
                    exe_candidates: r.exe_candidates,
                    dst_host: r.dst_host,
                    dst_port: r.dst_port,
                    protocol: r.protocol,
                },
            )
        })
        .collect();

    let existing: std::collections::HashSet<String> = client
        .list_rules()
        .await?
        .into_iter()
        .map(|r| r.name)
        .collect();

    let planned = plan(&bundle);
    let mut added = Vec::new();
    let mut skipped_present = 0u32;

    for (rule_name, exe) in &planned.present {
        if existing.contains(*rule_name) {
            skipped_present += 1;
            continue;
        }
        let spec = &by_name[*rule_name];
        if !dry_run {
            client
                .upsert_rule(allow_rule(
                    rule_name,
                    &exe.to_string_lossy(),
                    spec.dst_port,
                    spec.protocol,
                ))
                .await?;
        }
        if !format.is_json() {
            println!(
                "{}: {rule_name}  ({}{})",
                if dry_run { "would add" } else { "added" },
                exe.display(),
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
            "\nnot installed on this machine, so skipped ({}):",
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
/// Matches on the exact rule names the bundle defines, never on a prefix: a
/// prefix would also delete a rule someone hand-wrote and happened to name
/// `web-something`.
pub async fn bundle_remove(
    client: &mut Client,
    name: &str,
    dry_run: bool,
    format: OutputFormat,
) -> CliResult {
    let bundle = find_bundle(name)?;
    let owned: std::collections::HashSet<&str> = bundle.rules.iter().map(|r| r.name).collect();

    let existing = client.list_rules().await?;
    let mut removed = Vec::new();
    for r in existing.iter().filter(|r| owned.contains(r.name.as_str())) {
        if !dry_run {
            client.delete_rule(&r.id).await?;
        }
        if !format.is_json() {
            println!(
                "{}: {} ({})",
                if dry_run { "would remove" } else { "removed" },
                short_id(&r.id),
                r.name
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
mod resolve_tests {
    use super::*;

    fn rule(id: &str, name: &str) -> proto::RuleInfo {
        proto::RuleInfo {
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

#[cfg(test)]
mod json_tests {
    use super::*;

    fn exported(action: &str) -> ExportedRule {
        ExportedRule {
            id: String::new(),
            name: "t".into(),
            enabled: true,
            action: action.into(),
            duration: "always".into(),
            scope: ExportedScope {
                exe_path: Some("/usr/bin/curl".into()),
                exe_sha256: None,
                parent_exe: None,
                uid: None,
                dst_host: None,
                dst_net: None,
                dst_port: None,
                protocol: None,
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
    fn export_round_trips_through_json() {
        let scope = proto::RuleScope {
            exe_path: "/usr/bin/curl".into(),
            exe_sha256: String::new(),
            parent_exe: String::new(),
            uid: 1000,
            has_uid: true,
            dst_host: "example.com".into(),
            dst_net: String::new(),
            dst_port: 443,
            has_dst_port: true,
            protocol: proto::Protocol::Tcp as i32,
            has_protocol: true,
        };
        let original = proto::RuleInfo {
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
        assert_eq!(s.dst_host, "example.com");
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

#[cfg(test)]
mod bundle_tests {
    use super::*;

    /// The invariant the whole feature rests on.
    ///
    /// A bundle that installed a bare "allow tcp/443" would re-open exactly
    /// the hole this program exists to close: a payload phoning home uses 443
    /// like everything else, and a port-shaped rule cannot tell it from a
    /// browser. The type makes `exe_candidates` mandatory; this makes "empty
    /// list" - the way round it - impossible too.
    #[test]
    fn every_bundle_rule_names_an_executable() {
        for b in bundles() {
            for r in &b.rules {
                assert!(
                    !r.exe_candidates.is_empty(),
                    "{}/{} has no candidate path, so it would match on port alone",
                    b.name,
                    r.name
                );
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
            dst_host: None,
            dst_port: Some(443),
            protocol: Some(proto::Protocol::Tcp),
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

#[cfg(test)]
mod opensnitch_tests {
    use super::*;
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
    fn deny_action_recognized() {
        let r = parse(
            r#"{
              "name": "block-evil",
              "action": "deny",
              "duration": "once",
              "operator": {
                "type": "simple",
                "operand": "dest.host",
                "data": "evil.example"
              }
            }"#,
        )
        .unwrap();
        assert_eq!(r.action, proto::Action::Deny as i32);
        assert_eq!(r.duration, proto::Duration::Once as i32);
        assert_eq!(r.scope.unwrap().dst_host, "evil.example");
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
    fn unknown_operands_silently_skipped() {
        // process.command isn't supported but the rule has a valid
        // process.path too - the latter alone is enough.
        let r = parse(
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
        .unwrap();
        assert_eq!(r.scope.unwrap().exe_path, "/usr/bin/curl");
    }

    #[test]
    fn regexp_type_treated_like_simple() {
        let r = parse(
            r#"{
              "name": "rxp",
              "action": "allow",
              "operator": {"type": "regexp", "operand": "process.path", "data": "/usr/bin/.*"}
            }"#,
        )
        .unwrap();
        // We don't actually evaluate regex but the data lands in exe_path.
        assert_eq!(r.scope.unwrap().exe_path, "/usr/bin/.*");
    }
}
