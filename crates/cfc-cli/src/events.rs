//! `cfc log`: the persisted verdict/audit log ("what did X contact?").

use crate::error::CliResult;
use crate::output::{self, OutputFormat};
use crate::rules::ActionArg;
use cfc_client::{convert, proto, Client};
use std::time::Duration;

#[derive(Debug, clap::Args)]
pub struct LogArgs {
    /// Maximum number of records. 0 asks the daemon for its default page
    /// size; the daemon caps the maximum either way.
    #[arg(long, default_value_t = 50)]
    pub limit: u32,

    /// Skip this many records (paging, newest first).
    #[arg(long, default_value_t = 0)]
    pub offset: u32,

    /// Only records whose executable path contains this substring.
    #[arg(long)]
    pub exe: Option<String>,

    /// Only records with this verdict.
    #[arg(long, value_enum)]
    pub action: Option<ActionArg>,

    /// Only records newer than this, e.g. 2h, 30m, 1d.
    #[arg(long, value_parser = crate::humantime::parse_duration_arg)]
    pub since: Option<Duration>,
}

/// Builds the wire request. Pure, so the `--since` -> absolute-instant
/// conversion is testable.
pub fn build_request(args: &LogArgs, now_unix_ms: i64) -> proto::ListEventsRequest {
    proto::ListEventsRequest {
        limit: args.limit,
        offset: args.offset,
        exe_contains: args.exe.clone().unwrap_or_default(),
        action_filter: args
            .action
            .map(|a| a.to_proto() as i32)
            .unwrap_or(proto::Action::Unspecified as i32),
        since_unix_ms: args
            .since
            .map(|d| now_unix_ms - (d.as_secs() as i64) * 1000)
            .unwrap_or(0),
    }
}

#[derive(Debug, serde::Serialize)]
struct EventJson<'a> {
    ts_unix_ms: i64,
    time: Option<String>,
    action: &'a str,
    source: &'a str,
    protocol: Option<&'a str>,
    exe: Option<&'a str>,
    pid: Option<u32>,
    uid: Option<u32>,
    src_ip: Option<&'a str>,
    src_port: u32,
    dst_ip: Option<&'a str>,
    dst_port: u32,
    dst_host: Option<&'a str>,
    rule_id: Option<&'a str>,
}

/// Empty proto strings mean "absent"; JSON should say null, not "".
fn opt(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn to_json(e: &proto::Event) -> EventJson<'_> {
    EventJson {
        ts_unix_ms: e.ts_unix_ms,
        time: output::rfc3339(e.ts_unix_ms),
        action: convert::action_label(e.action),
        source: &e.source,
        protocol: opt(&e.proto),
        exe: opt(&e.exe),
        pid: (e.pid != 0).then_some(e.pid),
        uid: e.uid,
        src_ip: opt(&e.src_ip),
        src_port: e.src_port,
        dst_ip: opt(&e.dst_ip),
        dst_port: e.dst_port,
        dst_host: opt(&e.dst_host),
        rule_id: opt(&e.rule_id),
    }
}

/// The destination column: hostname when the daemon resolved one.
fn destination(e: &proto::Event) -> String {
    let host = if e.dst_host.is_empty() {
        e.dst_ip.as_str()
    } else {
        e.dst_host.as_str()
    };
    if host.is_empty() {
        return "?".to_string();
    }
    format!("{host}:{}", e.dst_port)
}

fn app(e: &proto::Event) -> String {
    if e.exe.is_empty() {
        return "?".to_string();
    }
    std::path::Path::new(&e.exe)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| e.exe.clone())
}

pub async fn run(client: &mut Client, args: LogArgs, format: OutputFormat) -> CliResult {
    let req = build_request(&args, chrono::Utc::now().timestamp_millis());
    let events = client.list_events(req).await?;

    if format.is_json() {
        let rows: Vec<EventJson> = events.iter().map(to_json).collect();
        return output::print_json(&rows);
    }

    if events.is_empty() {
        println!("(no matching events)");
        return Ok(());
    }

    println!(
        "{:<19}  {:<7}  {:<18}  {:<7}  {:<30}  {:<5}  source",
        "time", "action", "app", "pid", "destination", "proto"
    );
    for e in &events {
        println!(
            "{:<19}  {:<7}  {:<18}  {:<7}  {:<30}  {:<5}  {}",
            output::local_datetime(e.ts_unix_ms),
            convert::action_label(e.action),
            output::truncate(&app(e), 18),
            if e.pid == 0 {
                "?".to_string()
            } else {
                e.pid.to_string()
            },
            output::truncate(&destination(e), 30),
            if e.proto.is_empty() { "?" } else { &e.proto },
            if e.source.is_empty() { "?" } else { &e.source },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> LogArgs {
        LogArgs {
            limit: 50,
            offset: 0,
            exe: None,
            action: None,
            since: None,
        }
    }

    #[test]
    fn empty_filters_leave_the_request_unconstrained() {
        let req = build_request(&args(), 1_700_000_000_000);
        assert_eq!(req.limit, 50);
        assert_eq!(req.offset, 0);
        assert_eq!(req.exe_contains, "");
        assert_eq!(req.action_filter, proto::Action::Unspecified as i32);
        assert_eq!(req.since_unix_ms, 0);
    }

    #[test]
    fn since_becomes_an_absolute_instant() {
        let now = 1_700_000_000_000;
        let a = LogArgs {
            since: Some(Duration::from_secs(7200)),
            ..args()
        };
        assert_eq!(build_request(&a, now).since_unix_ms, now - 7_200_000);
    }

    #[test]
    fn action_and_exe_filters_are_forwarded() {
        let a = LogArgs {
            exe: Some("firefox".into()),
            action: Some(ActionArg::Deny),
            ..args()
        };
        let req = build_request(&a, 0);
        assert_eq!(req.exe_contains, "firefox");
        assert_eq!(req.action_filter, proto::Action::Deny as i32);
    }

    fn sample_event() -> proto::Event {
        proto::Event {
            ts_unix_ms: 1_700_000_000_000,
            proto: "tcp".into(),
            src_ip: "192.0.2.10".into(),
            src_port: 5555,
            dst_ip: "93.184.216.34".into(),
            dst_port: 443,
            dst_host: "example.com".into(),
            exe: "/usr/bin/curl".into(),
            pid: 4242,
            uid: Some(1000),
            action: proto::Action::Deny as i32,
            source: "rule".into(),
            rule_id: "r-1".into(),
        }
    }

    #[test]
    fn json_shape_is_stable() {
        let v = serde_json::to_value(to_json(&sample_event())).unwrap();
        assert_eq!(v["action"], "deny");
        assert_eq!(v["exe"], "/usr/bin/curl");
        assert_eq!(v["uid"], 1000);
        assert_eq!(v["dst_host"], "example.com");
        assert_eq!(v["source"], "rule");
        assert_eq!(v["rule_id"], "r-1");
        assert!(v["time"].as_str().unwrap().starts_with("2023-"));
    }

    #[test]
    fn unattributed_rows_stay_null_not_zero() {
        let mut e = sample_event();
        e.uid = None;
        e.pid = 0;
        e.exe = String::new();
        e.dst_host = String::new();
        let v = serde_json::to_value(to_json(&e)).unwrap();
        assert_eq!(v["uid"], serde_json::Value::Null);
        assert_eq!(v["pid"], serde_json::Value::Null);
        assert_eq!(v["exe"], serde_json::Value::Null);
        assert_eq!(v["dst_host"], serde_json::Value::Null);
        assert_eq!(app(&e), "?");
        assert_eq!(destination(&e), "93.184.216.34:443");
    }

    #[test]
    fn destination_prefers_hostname_and_survives_empty_rows() {
        let e = sample_event();
        assert_eq!(destination(&e), "example.com:443");
        assert_eq!(app(&e), "curl");

        let blank = proto::Event {
            ts_unix_ms: 0,
            proto: String::new(),
            src_ip: String::new(),
            src_port: 0,
            dst_ip: String::new(),
            dst_port: 0,
            dst_host: String::new(),
            exe: String::new(),
            pid: 0,
            uid: None,
            action: proto::Action::Unspecified as i32,
            source: String::new(),
            rule_id: String::new(),
        };
        assert_eq!(destination(&blank), "?");
    }
}
