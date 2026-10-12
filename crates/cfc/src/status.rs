//! `cfc status`, `cfc pause` and `cfc resume`.

use crate::error::{CliError, CliResult};
use crate::humantime;
use crate::output::{self, OutputFormat};
use cfc_client::{convert, proto, Client};

#[derive(Debug, serde::Serialize)]
struct StatusJson {
    version: String,
    uptime_seconds: u64,
    enforcing: bool,
    enforcement: String,
    paused: bool,
    resume_at_unix_ms: i64,
    resume_at: Option<String>,
    resume_in_seconds: Option<i64>,
    rules_count: u64,
    skipped_rules: u64,
    prompts_pending: u64,
    connections_seen: u64,
    connections_allowed: u64,
    connections_denied: u64,
    timeout_action: String,
    no_ui_action: String,
    prompt_timeout_secs: u32,
    warnings: Vec<String>,
}

fn status_json(s: &proto::StatusResponse, now_unix_ms: i64) -> StatusJson {
    StatusJson {
        version: s.version.clone(),
        uptime_seconds: s.uptime_seconds,
        enforcing: s.enforcing,
        enforcement: s.enforcement.clone(),
        paused: s.paused,
        resume_at_unix_ms: s.resume_at_unix_ms,
        resume_at: output::rfc3339(s.resume_at_unix_ms),
        resume_in_seconds: (s.paused && s.resume_at_unix_ms > 0)
            .then(|| ((s.resume_at_unix_ms - now_unix_ms).max(0)) / 1000),
        rules_count: s.rules_count,
        skipped_rules: s.skipped_rules,
        prompts_pending: s.prompts_pending,
        connections_seen: s.connections_seen,
        connections_allowed: s.connections_allowed,
        connections_denied: s.connections_denied,
        timeout_action: convert::action_label(s.timeout_action).to_string(),
        no_ui_action: convert::action_label(s.no_ui_action).to_string(),
        prompt_timeout_secs: s.prompt_timeout_secs,
        warnings: status_warnings(s),
    }
}

/// Conditions the user has to know about, in both output modes.
fn status_warnings(s: &proto::StatusResponse) -> Vec<String> {
    let mut w = Vec::new();
    if !s.enforcing {
        w.push(
            "no packets seen - is the nftables rule loaded? see docs/TROUBLESHOOTING.md"
                .to_string(),
        );
    }
    if s.skipped_rules > 0 {
        w.push(format!(
            "{} rule(s) on disk could not be loaded and are NOT being enforced",
            s.skipped_rules
        ));
    }
    w
}

/// The paused cell: "no", or "yes (resumes in 4m 30s at 18:20:11)".
/// Says where enforcement lives, and whether it outlives the daemon.
///
/// Spelled out rather than printed raw because the word alone does not carry
/// the consequence. "process" and "pinned" both mean the kernel is refusing
/// connect() - the difference is only what happens when this daemon stops, and
/// that difference is the whole reason the layer exists.
fn enforcement_cell(level: &str) -> String {
    match level {
        "pinned" => "yes (pinned - survives this daemon)".to_string(),
        "inherited" => "yes (inherited from a previous daemon's pins)".to_string(),
        "process" => "yes (this process only - lifted when it stops)".to_string(),
        "unavailable" => "no (the kernel refused the programs)".to_string(),
        "off" => "no (not enabled, or the object never loaded)".to_string(),
        "starting" => "not decided yet (the daemon is still starting)".to_string(),
        // A daemon that predates this field sends the proto3 default. Saying
        // nothing at all would read as an empty answer rather than an absent
        // one.
        "" => "unknown (this daemon is too old to say)".to_string(),
        // A daemon newer than this CLI. Say what it said rather than guess.
        other => other.to_string(),
    }
}

fn paused_cell(s: &proto::StatusResponse, now_unix_ms: i64) -> String {
    if !s.paused {
        return "no".to_string();
    }
    if s.resume_at_unix_ms <= 0 {
        return "yes".to_string();
    }
    let left = ((s.resume_at_unix_ms - now_unix_ms).max(0)) / 1000;
    format!(
        "yes (resumes in {} at {})",
        humantime::format_secs(left),
        output::local_time(s.resume_at_unix_ms)
    )
}

pub async fn cmd_status(client: &mut Client, format: OutputFormat) -> CliResult {
    let s = client.status().await?;
    let now = chrono::Utc::now().timestamp_millis();

    if format.is_json() {
        return output::print_json(&status_json(&s, now));
    }

    println!("version          {}", s.version);
    println!(
        "uptime           {}",
        humantime::format_secs(s.uptime_seconds as i64)
    );
    println!(
        "enforcing        {}",
        if s.enforcing { "yes" } else { "no" }
    );
    println!("  in-kernel      {}", enforcement_cell(&s.enforcement));
    println!("paused           {}", paused_cell(&s, now));
    println!("rules            {}", s.rules_count);
    println!("prompts pending  {}", s.prompts_pending);
    println!(
        "connections      {} (allowed: {}, denied: {})",
        s.connections_seen, s.connections_allowed, s.connections_denied
    );
    println!(
        "prompt policy    {}s timeout -> {}, no UI -> {}",
        s.prompt_timeout_secs,
        convert::action_label(s.timeout_action),
        convert::action_label(s.no_ui_action)
    );
    for w in status_warnings(&s) {
        eprintln!("warning: {w}");
    }
    Ok(())
}

pub async fn cmd_pause(
    client: &mut Client,
    duration: Option<std::time::Duration>,
    format: OutputFormat,
) -> CliResult {
    // 0 means "use the daemon's configured default": the daemon owns both
    // the default and the maximum, and reports the real deadline.
    let secs = match duration {
        Some(d) => u32::try_from(d.as_secs())
            .map_err(|_| CliError::runtime("--for is too large (max ~136 years)"))?,
        None => 0,
    };
    let resp = client.set_paused(true, secs).await?;
    let now = chrono::Utc::now().timestamp_millis();
    let left = ((resp.resume_at_unix_ms - now).max(0)) / 1000;

    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "paused": resp.paused,
            "resume_at_unix_ms": resp.resume_at_unix_ms,
            "resume_at": output::rfc3339(resp.resume_at_unix_ms),
            "resume_in_seconds": left,
        }));
    }
    if resp.resume_at_unix_ms > 0 {
        println!(
            "paused; auto-resumes at {} (in {})",
            output::local_time(resp.resume_at_unix_ms),
            humantime::format_secs(left)
        );
    } else {
        println!("paused = {}", resp.paused);
    }
    Ok(())
}

pub async fn cmd_resume(client: &mut Client, format: OutputFormat) -> CliResult {
    let resp = client.set_paused(false, 0).await?;
    if format.is_json() {
        return output::print_json(&serde_json::json!({ "paused": resp.paused }));
    }
    println!("paused = {}", resp.paused);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(paused: bool, resume_at: i64) -> proto::StatusResponse {
        proto::StatusResponse {
            version: "0.1.0".into(),
            uptime_seconds: 3661,
            rules_count: 12,
            prompts_pending: 1,
            connections_seen: 100,
            connections_allowed: 90,
            connections_denied: 10,
            paused,
            resume_at_unix_ms: resume_at,
            timeout_action: proto::Action::Deny as i32,
            no_ui_action: proto::Action::Allow as i32,
            prompt_timeout_secs: 15,
            skipped_rules: 0,
            enforcing: true,
            enforcement: "pinned".to_string(),
        }
    }

    #[test]
    fn paused_cell_counts_down() {
        let now = 1_700_000_000_000;
        assert_eq!(paused_cell(&status(false, 0), now), "no");
        assert_eq!(paused_cell(&status(true, 0), now), "yes");
        let cell = paused_cell(&status(true, now + 270_000), now);
        assert!(cell.starts_with("yes (resumes in 4m 30s at "), "{cell}");
        // A deadline already in the past must not render as negative.
        let cell = paused_cell(&status(true, now - 5_000), now);
        assert!(cell.contains("resumes in 0s"), "{cell}");
    }

    #[test]
    fn warnings_fire_on_not_enforcing_and_skipped_rules() {
        let mut s = status(false, 0);
        assert!(status_warnings(&s).is_empty());

        s.enforcing = false;
        let w = status_warnings(&s);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("nftables"));
        assert!(w[0].contains("docs/TROUBLESHOOTING.md"));

        s.skipped_rules = 3;
        let w = status_warnings(&s);
        assert_eq!(w.len(), 2);
        assert!(w[1].contains("3 rule(s)"));
        assert!(w[1].contains("NOT being enforced"));
    }

    #[test]
    fn status_json_shape_carries_the_wave_three_fields() {
        let now = 1_700_000_000_000;
        let mut s = status(true, now + 60_000);
        s.skipped_rules = 2;
        s.enforcing = false;
        let v = serde_json::to_value(status_json(&s, now)).unwrap();

        assert_eq!(v["version"], "0.1.0");
        assert_eq!(v["enforcing"], false);
        assert_eq!(v["paused"], true);
        assert_eq!(v["resume_in_seconds"], 60);
        assert!(v["resume_at"].as_str().unwrap().starts_with("2023-"));
        assert_eq!(v["skipped_rules"], 2);
        assert_eq!(v["timeout_action"], "deny");
        assert_eq!(v["no_ui_action"], "allow");
        assert_eq!(v["prompt_timeout_secs"], 15);
        assert_eq!(v["warnings"].as_array().unwrap().len(), 2);
    }

    /// The proto3 default is what an older daemon sends, and what a new one
    /// sends before startup has answered; the text mode must say what the
    /// blank means rather than print nothing.
    #[test]
    fn an_absent_enforcement_level_reads_as_unknown() {
        assert!(enforcement_cell("").starts_with("unknown ("));
    }

    #[test]
    fn status_json_omits_resume_fields_when_running() {
        let now = 1_700_000_000_000;
        let v = serde_json::to_value(status_json(&status(false, 0), now)).unwrap();
        assert_eq!(v["resume_at"], serde_json::Value::Null);
        assert_eq!(v["resume_in_seconds"], serde_json::Value::Null);
        assert_eq!(v["warnings"].as_array().unwrap().len(), 0);
    }
}
