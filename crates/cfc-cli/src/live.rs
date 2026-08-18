//! `cfc live`: the streaming connection feed.

use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};
use cfc_client::{convert, proto, Client, StreamItem};
use futures::StreamExt;
use owo_colors::{OwoColorize, Stream::Stdout};
use std::path::Path;

/// Client-side filters. The daemon streams everything; narrowing here
/// keeps the RPC surface unchanged and lets several terminals watch
/// different slices of the same feed.
#[derive(Debug, Default, Clone, clap::Args)]
pub struct LiveFilters {
    /// Only flows from this executable: full path, basename, or a
    /// substring of the basename.
    #[arg(long)]
    pub exe: Option<String>,

    /// Only flows from this pid.
    #[arg(long)]
    pub pid: Option<u32>,

    /// Only flows to this destination port.
    #[arg(long = "dst-port")]
    pub dst_port: Option<u16>,

    /// Only flows owned by this uid.
    #[arg(long)]
    pub uid: Option<u32>,

    /// Only blocked flows (deny or reject).
    #[arg(long)]
    pub denied: bool,
}

/// Does `exe` (an absolute path from the daemon) satisfy `pattern`?
///
/// A pattern containing `/` is treated as a path and must match exactly;
/// anything else matches the basename exactly or as a substring, so
/// `--exe firefox` works without knowing the install prefix.
pub fn exe_matches(pattern: &str, exe: &str) -> bool {
    if exe.is_empty() || pattern.is_empty() {
        return false;
    }
    if exe == pattern {
        return true;
    }
    let base = Path::new(exe)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if base == pattern {
        return true;
    }
    !pattern.contains('/') && base.contains(pattern)
}

/// Pure filter predicate, so the matching rules are testable without a
/// daemon.
pub fn matches(f: &LiveFilters, ev: &proto::ConnectionEvent) -> bool {
    let Some(conn) = ev.connection.as_ref() else {
        return false;
    };
    let proc = ev.process.as_ref();

    if let Some(pattern) = &f.exe {
        let exe = proc.map(|p| p.exe.as_str()).unwrap_or("");
        if !exe_matches(pattern, exe) {
            return false;
        }
    }
    if let Some(pid) = f.pid {
        if proc.map(|p| p.pid) != Some(pid) {
            return false;
        }
    }
    if let Some(uid) = f.uid {
        // An unattributed flow has no uid; it must not pass a uid filter.
        if proc.and_then(|p| p.uid) != Some(uid) {
            return false;
        }
    }
    if let Some(port) = f.dst_port {
        if conn.dst_port != u32::from(port) {
            return false;
        }
    }
    if f.denied {
        let a = proto::Action::try_from(ev.verdict).unwrap_or(proto::Action::Unspecified);
        if !matches!(a, proto::Action::Deny | proto::Action::Reject) {
            return false;
        }
    }
    true
}

/// The destination as a user thinks of it: the resolved hostname when the
/// daemon has one, the literal IP otherwise.
pub fn destination(conn: &proto::ConnectionInfo) -> String {
    let host = if conn.dst_host.is_empty() {
        conn.dst_ip.as_str()
    } else {
        conn.dst_host.as_str()
    };
    format!("{host}:{}", conn.dst_port)
}

#[derive(Debug, serde::Serialize)]
struct LiveEventJson<'a> {
    ts_unix_ms: i64,
    time: String,
    protocol: &'a str,
    direction: &'a str,
    pid: Option<u32>,
    uid: Option<u32>,
    exe: Option<&'a str>,
    src_ip: &'a str,
    src_port: u32,
    dst_ip: &'a str,
    dst_port: u32,
    dst_host: Option<&'a str>,
    verdict: &'a str,
    rule_id: Option<&'a str>,
}

fn to_json<'a>(
    ev: &'a proto::ConnectionEvent,
    conn: &'a proto::ConnectionInfo,
) -> LiveEventJson<'a> {
    let proc = ev.process.as_ref();
    LiveEventJson {
        ts_unix_ms: conn.timestamp_unix_ms,
        time: output::local_datetime(conn.timestamp_unix_ms),
        protocol: convert::protocol_label(conn.protocol),
        direction: convert::direction_label(conn.direction),
        pid: proc.map(|p| p.pid),
        uid: proc.and_then(|p| p.uid),
        exe: proc.map(|p| p.exe.as_str()).filter(|s| !s.is_empty()),
        src_ip: &conn.src_ip,
        src_port: conn.src_port,
        dst_ip: &conn.dst_ip,
        dst_port: conn.dst_port,
        dst_host: Some(conn.dst_host.as_str()).filter(|s| !s.is_empty()),
        verdict: convert::action_label(ev.verdict),
        rule_id: Some(ev.rule_id.as_str()).filter(|s| !s.is_empty()),
    }
}

fn print_header() {
    // Colour codes count towards `{:<n}` widths, so pad first and colour
    // the padded string - otherwise every column drifts.
    let head = format!(
        "{:<8} {:<5} {:<7} {:<18} {:<22} -> {:<28} {:<7}",
        "time", "proto", "pid", "app", "src", "dst", "verdict"
    );
    println!("{}", head.if_supports_color(Stdout, |s| s.bold()));
}

fn print_row(ev: &proto::ConnectionEvent, conn: &proto::ConnectionInfo) {
    let proc = ev.process.as_ref();
    let time = output::local_time(conn.timestamp_unix_ms);
    let pid = proc
        .map(|p| p.pid.to_string())
        .unwrap_or_else(|| "?".into());
    let app = proc
        .map(convert::process_display)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "?".into());
    let src = format!("{}:{}", conn.src_ip, conn.src_port);

    // Pad before colouring: escape sequences count towards `{:<n}` widths,
    // which is why the pre-wave-3 output drifted a column per coloured cell.
    let dst = format!("{:<28}", output::truncate(&destination(conn), 28));
    let verdict = format!("{:<7}", convert::action_label(ev.verdict));
    let verdict = match proto::Action::try_from(ev.verdict).unwrap_or(proto::Action::Unspecified) {
        proto::Action::Allow => format!("{}", verdict.if_supports_color(Stdout, |s| s.green())),
        proto::Action::Deny | proto::Action::Reject => {
            format!("{}", verdict.if_supports_color(Stdout, |s| s.red()))
        }
        proto::Action::Unspecified => verdict,
    };
    println!(
        "{} {:<5} {:<7} {:<18} {:<22} -> {} {}",
        format!("{time:<8}").if_supports_color(Stdout, |s| s.dimmed()),
        convert::protocol_label(conn.protocol),
        pid,
        output::truncate(&app, 18),
        src,
        dst.if_supports_color(Stdout, |s| s.cyan()),
        verdict,
    );
}

fn emit(ev: &proto::ConnectionEvent, filters: &LiveFilters, format: OutputFormat) -> CliResult {
    if !matches(filters, ev) {
        return Ok(());
    }
    let Some(conn) = ev.connection.as_ref() else {
        return Ok(());
    };
    if format.is_json() {
        output::print_ndjson(&to_json(ev, conn))
    } else {
        print_row(ev, conn);
        Ok(())
    }
}

/// One-shot mode: stream until the daemon goes away, then fail. A `cfc
/// live` that silently exits 0 when the daemon restarts is a trap for
/// anything watching it.
pub async fn run_once(
    client: &mut Client,
    filters: LiveFilters,
    format: OutputFormat,
) -> CliResult {
    let mut stream = client.stream_connections("cfc-cli".into()).await?;
    if !format.is_json() {
        print_header();
    }
    while let Some(item) = stream.next().await {
        match item {
            Ok(ev) => emit(&ev, &filters, format)?,
            Err(status) => {
                return Err(CliError::runtime(format!(
                    "stream lost: {status} (use --follow to reconnect automatically)"
                )))
            }
        }
    }
    Err(CliError::runtime(
        "stream closed by the daemon (use --follow to reconnect automatically)",
    ))
}

/// Follow mode: reconnects forever, marking each reconnection. Survives a
/// daemon restart, which is what a `cfc live` left in tmux needs.
pub async fn run_follow(socket: &Path, filters: LiveFilters, format: OutputFormat) -> CliResult {
    let mut stream = cfc_client::stream_connections_resilient(socket, "cfc-cli".into());
    let mut first = true;
    if !format.is_json() {
        print_header();
    }
    while let Some(item) = stream.next().await {
        match item {
            StreamItem::Connected => {
                if first {
                    first = false;
                } else if format.is_json() {
                    output::print_ndjson(&serde_json::json!({"event": "reconnected"}))?;
                } else {
                    println!("-- reconnected --");
                }
            }
            StreamItem::Event(ev) => emit(&ev, &filters, format)?,
            StreamItem::Disconnected(err) => {
                if format.is_json() {
                    output::print_ndjson(
                        &serde_json::json!({"event": "disconnected", "error": err.to_string()}),
                    )?;
                } else {
                    eprintln!("-- disconnected: {err} (retrying) --");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        exe: &str,
        pid: u32,
        uid: Option<u32>,
        dst_port: u32,
        verdict: proto::Action,
    ) -> proto::ConnectionEvent {
        proto::ConnectionEvent {
            connection: Some(proto::ConnectionInfo {
                id: "c1".into(),
                timestamp_unix_ms: 1_700_000_000_000,
                protocol: proto::Protocol::Tcp as i32,
                direction: proto::Direction::Outbound as i32,
                src_ip: "192.0.2.10".into(),
                src_port: 4242,
                dst_ip: "93.184.216.34".into(),
                dst_port,
                dst_host: "example.com".into(),
            }),
            process: Some(proto::ProcessInfo {
                pid,
                ppid: 1,
                uid,
                gid: None,
                exe: exe.into(),
                cmdline: vec![],
                cwd: String::new(),
                sha256: String::new(),
                package: String::new(),
                provenance: proto::Provenance::Unspecified as i32,
            }),
            verdict: verdict as i32,
            rule_id: String::new(),
        }
    }

    #[test]
    fn exe_pattern_forms() {
        assert!(exe_matches("/usr/bin/curl", "/usr/bin/curl"));
        assert!(exe_matches("curl", "/usr/bin/curl"));
        assert!(exe_matches("cur", "/usr/bin/curl"));
        assert!(!exe_matches("curl", "/usr/bin/wget"));
        // A path pattern must match exactly, never as a substring.
        assert!(!exe_matches("/usr/bin", "/usr/bin/curl"));
        assert!(!exe_matches("curl", ""));
        assert!(!exe_matches("", "/usr/bin/curl"));
    }

    #[test]
    fn no_filters_pass_everything() {
        let f = LiveFilters::default();
        assert!(matches(
            &f,
            &event("/usr/bin/curl", 10, Some(1000), 443, proto::Action::Allow)
        ));
    }

    #[test]
    fn each_filter_narrows() {
        let ev = event("/usr/bin/curl", 10, Some(1000), 443, proto::Action::Allow);

        let f = LiveFilters {
            exe: Some("curl".into()),
            ..Default::default()
        };
        assert!(matches(&f, &ev));
        let f = LiveFilters {
            exe: Some("wget".into()),
            ..Default::default()
        };
        assert!(!matches(&f, &ev));

        let f = LiveFilters {
            pid: Some(10),
            ..Default::default()
        };
        assert!(matches(&f, &ev));
        let f = LiveFilters {
            pid: Some(11),
            ..Default::default()
        };
        assert!(!matches(&f, &ev));

        let f = LiveFilters {
            dst_port: Some(443),
            ..Default::default()
        };
        assert!(matches(&f, &ev));
        let f = LiveFilters {
            dst_port: Some(80),
            ..Default::default()
        };
        assert!(!matches(&f, &ev));

        let f = LiveFilters {
            uid: Some(1000),
            ..Default::default()
        };
        assert!(matches(&f, &ev));
        let f = LiveFilters {
            uid: Some(0),
            ..Default::default()
        };
        assert!(!matches(&f, &ev));
    }

    #[test]
    fn unattributed_flows_never_match_a_uid_filter() {
        let mut ev = event("/usr/bin/curl", 10, None, 443, proto::Action::Allow);
        let f = LiveFilters {
            uid: Some(0),
            ..Default::default()
        };
        assert!(!matches(&f, &ev), "uid=None must not read as uid 0");
        ev.process = None;
        assert!(!matches(&f, &ev));
    }

    #[test]
    fn denied_filter_keeps_deny_and_reject_only() {
        let f = LiveFilters {
            denied: true,
            ..Default::default()
        };
        assert!(!matches(
            &f,
            &event("/x", 1, None, 80, proto::Action::Allow)
        ));
        assert!(matches(&f, &event("/x", 1, None, 80, proto::Action::Deny)));
        assert!(matches(
            &f,
            &event("/x", 1, None, 80, proto::Action::Reject)
        ));
    }

    #[test]
    fn filters_combine_as_and() {
        let ev = event("/usr/bin/curl", 10, Some(1000), 443, proto::Action::Deny);
        let f = LiveFilters {
            exe: Some("curl".into()),
            dst_port: Some(443),
            denied: true,
            ..Default::default()
        };
        assert!(matches(&f, &ev));
        let f = LiveFilters { pid: Some(99), ..f };
        assert!(!matches(&f, &ev));
    }

    #[test]
    fn events_without_a_connection_are_dropped() {
        let mut ev = event("/usr/bin/curl", 10, Some(1000), 443, proto::Action::Allow);
        ev.connection = None;
        assert!(!matches(&LiveFilters::default(), &ev));
    }

    #[test]
    fn destination_prefers_the_hostname() {
        let ev = event("/usr/bin/curl", 10, Some(1000), 443, proto::Action::Allow);
        let conn = ev.connection.as_ref().unwrap();
        assert_eq!(destination(conn), "example.com:443");

        let mut bare = conn.clone();
        bare.dst_host = String::new();
        assert_eq!(destination(&bare), "93.184.216.34:443");
    }

    #[test]
    fn json_shape_has_the_process_and_hostname() {
        let ev = event("/usr/bin/curl", 10, Some(1000), 443, proto::Action::Deny);
        let conn = ev.connection.as_ref().unwrap();
        let v = serde_json::to_value(to_json(&ev, conn)).unwrap();
        assert_eq!(v["exe"], "/usr/bin/curl");
        assert_eq!(v["pid"], 10);
        assert_eq!(v["uid"], 1000);
        assert_eq!(v["dst_host"], "example.com");
        assert_eq!(v["verdict"], "deny");
        assert_eq!(v["protocol"], "tcp");
        assert_eq!(v["rule_id"], serde_json::Value::Null);
    }

    #[test]
    fn json_omits_unknown_process_fields() {
        let mut ev = event("", 0, None, 53, proto::Action::Allow);
        ev.process = None;
        let conn = ev.connection.as_ref().unwrap();
        let v = serde_json::to_value(to_json(&ev, conn)).unwrap();
        assert_eq!(v["exe"], serde_json::Value::Null);
        assert_eq!(v["uid"], serde_json::Value::Null);
        assert_eq!(v["pid"], serde_json::Value::Null);
    }
}
