//! Pure display helpers - countdowns, destination labels, timestamps.
//!
//! Deliberately free of iced types so the fiddly arithmetic (deadlines,
//! CIDR widths, truncation) can be unit-tested without a renderer.

use cfc_client::proto;

/// Prompt lifetime assumed when the daemon does not report one, so the
/// countdown bar still has a sane denominator.
pub const FALLBACK_PROMPT_TIMEOUT_SECS: u32 = 15;

/// Whole seconds left before `deadline_unix_ms`, rounded up, clamped at 0.
///
/// `None` means the daemon attached no deadline (field is 0) - the prompt
/// then only leaves the list when the user answers it.
pub fn remaining_secs(deadline_unix_ms: i64, now_ms: i64) -> Option<i64> {
    if deadline_unix_ms <= 0 {
        return None;
    }
    let diff = deadline_unix_ms - now_ms;
    if diff <= 0 {
        return Some(0);
    }
    Some(diff.div_euclid(1000) + i64::from(diff.rem_euclid(1000) != 0))
}

/// True once the daemon's own timer has certainly fired. Prompts without a
/// deadline never expire client-side.
pub fn is_expired(deadline_unix_ms: i64, now_ms: i64) -> bool {
    deadline_unix_ms > 0 && now_ms >= deadline_unix_ms
}

/// `"8s"` / `"1m 05s"`.
pub fn format_countdown(secs: i64) -> String {
    let secs = secs.max(0);
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m {:02}s", secs / 60, secs % 60)
    }
}

/// Fraction of the prompt's lifetime still remaining, in `0.0..=1.0`.
pub fn countdown_fraction(deadline_unix_ms: i64, now_ms: i64, total_secs: u32) -> f32 {
    let total = if total_secs == 0 {
        FALLBACK_PROMPT_TIMEOUT_SECS
    } else {
        total_secs
    };
    let Some(left) = remaining_secs(deadline_unix_ms, now_ms) else {
        return 1.0;
    };
    (left as f32 / total as f32).clamp(0.0, 1.0)
}

/// Present tense, for "…&nbsp;allows automatically in 8s".
pub fn fallback_verb(action: i32) -> &'static str {
    match proto::Action::try_from(action).unwrap_or(proto::Action::Unspecified) {
        proto::Action::Allow => "allows",
        proto::Action::Deny => "denies",
        proto::Action::Reject => "rejects",
        proto::Action::Unspecified => "answers",
    }
}

/// Past tense, for the "expired -> allowed by default" log line.
pub fn fallback_past(action: i32) -> &'static str {
    match proto::Action::try_from(action).unwrap_or(proto::Action::Unspecified) {
        proto::Action::Allow => "allowed",
        proto::Action::Deny => "denied",
        proto::Action::Reject => "rejected",
        proto::Action::Unspecified => "answered",
    }
}

/// `"example.com (93.184.216.34:443)"`, or bare `ip:port` when the daemon
/// could not name the destination.
pub fn dest_display(dst_host: &str, dst_ip: &str, dst_port: u32) -> String {
    let ip = if dst_ip.is_empty() { "?" } else { dst_ip };
    if dst_host.is_empty() {
        format!("{ip}:{dst_port}")
    } else {
        format!("{dst_host} ({ip}:{dst_port})")
    }
}

/// The name a rule should be scoped to: the hostname when we know it,
/// otherwise the literal address.
pub fn dest_key(dst_host: &str, dst_ip: &str) -> String {
    if dst_host.is_empty() {
        if dst_ip.is_empty() {
            "unknown".to_string()
        } else {
            dst_ip.to_string()
        }
    } else {
        dst_host.to_string()
    }
}

/// Single-address CIDR for `ip`. IPv6 needs /128; the old hardcoded /32
/// silently produced an unparseable scope for v6 flows.
pub fn host_cidr(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => format!("{ip}/128"),
        Ok(std::net::IpAddr::V4(_)) => format!("{ip}/32"),
        Err(_) => String::new(),
    }
}

/// First 16 hex chars, enough to eyeball against a known-good digest.
pub fn truncate_sha(sha: &str) -> String {
    if sha.is_empty() {
        "unknown".to_string()
    } else if sha.len() > 16 {
        format!("{}...", &sha[..16])
    } else {
        sha.to_string()
    }
}

/// Wall-clock rendering of a proto timestamp, UTC (matching the live feed).
pub fn format_unix_ms(ms: i64) -> String {
    if ms <= 0 {
        return "-".to_string();
    }
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// Clock time only, for the live feed and the status log.
pub fn format_clock_ms(ms: i64) -> String {
    if ms <= 0 {
        return "?".to_string();
    }
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// Longest connection-failure detail rendered verbatim.
///
/// cfc-client's actionable messages end with the fix ("add your user to the
/// colony-firewall group..."), so the clip has to be generous enough to keep
/// the longest of them whole; past that we are looking at a runaway gRPC
/// status, not advice.
pub const CONNECTION_HINT_MAX: usize = 220;

/// Normalizes a connection-failure detail for display.
///
/// Collapses the whitespace these messages carry from being written across
/// source lines - both so the badge line does not gain stray gaps and so
/// the status log's exact-text coalescing actually fires on repeats - then
/// clips to `max_chars`.
pub fn connection_hint(detail: &str, max_chars: usize) -> String {
    let normalized = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.chars().count() <= max_chars {
        return normalized;
    }
    let head: String = normalized.chars().take(max_chars).collect();
    format!("{head}...")
}

/// The single status-log line for a failed connection.
///
/// Deterministic for a given detail, so a daemon that stays down coalesces
/// into one counted entry instead of scrolling the log - and the reason
/// (missing socket, group permissions, stale socket) is visible instead of
/// being swallowed by a fixed "unreachable" string.
pub fn unreachable_log_line(detail: &str) -> String {
    let hint = connection_hint(detail, CONNECTION_HINT_MAX);
    if hint.is_empty() {
        "daemon unreachable, retrying...".to_string()
    } else {
        format!("daemon unreachable, retrying... - {hint}")
    }
}

/// "resumes in 4m 32s" for a paused daemon, using the deadline the daemon
/// actually reported rather than whatever the UI asked for.
pub fn format_resume_in(resume_at_unix_ms: i64, now_ms: i64) -> String {
    match remaining_secs(resume_at_unix_ms, now_ms) {
        None => "until resumed manually".to_string(),
        Some(0) => "resuming...".to_string(),
        Some(s) => format!("resumes in {}", format_countdown(s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_secs_rounds_up_and_clamps() {
        assert_eq!(remaining_secs(0, 1_000), None);
        assert_eq!(remaining_secs(-5, 1_000), None);
        assert_eq!(remaining_secs(10_000, 1_000), Some(9));
        // 8.4s left still reads as "9s" so the label never lies downward.
        assert_eq!(remaining_secs(10_000, 1_600), Some(9));
        assert_eq!(remaining_secs(10_000, 2_000), Some(8));
        assert_eq!(remaining_secs(10_000, 10_000), Some(0));
        assert_eq!(remaining_secs(10_000, 99_000), Some(0));
    }

    #[test]
    fn is_expired_only_with_a_deadline() {
        assert!(!is_expired(0, i64::MAX));
        assert!(!is_expired(10_000, 9_999));
        assert!(is_expired(10_000, 10_000));
        assert!(is_expired(10_000, 10_001));
    }

    #[test]
    fn countdown_formatting() {
        assert_eq!(format_countdown(-3), "0s");
        assert_eq!(format_countdown(0), "0s");
        assert_eq!(format_countdown(8), "8s");
        assert_eq!(format_countdown(59), "59s");
        assert_eq!(format_countdown(60), "1m 00s");
        assert_eq!(format_countdown(65), "1m 05s");
        assert_eq!(format_countdown(600), "10m 00s");
    }

    #[test]
    fn countdown_fraction_is_bounded() {
        assert_eq!(countdown_fraction(20_000, 10_000, 20), 0.5);
        assert_eq!(countdown_fraction(20_000, 20_000, 20), 0.0);
        // A deadline further out than the advertised timeout still clamps.
        assert_eq!(countdown_fraction(100_000, 0, 20), 1.0);
        // No deadline: full bar rather than a divide-by-zero.
        assert_eq!(countdown_fraction(0, 5_000, 0), 1.0);
    }

    #[test]
    fn fallback_labels_cover_every_action() {
        assert_eq!(fallback_verb(proto::Action::Allow as i32), "allows");
        assert_eq!(fallback_verb(proto::Action::Deny as i32), "denies");
        assert_eq!(fallback_verb(proto::Action::Reject as i32), "rejects");
        assert_eq!(fallback_verb(9999), "answers");
        assert_eq!(fallback_past(proto::Action::Allow as i32), "allowed");
        assert_eq!(fallback_past(proto::Action::Deny as i32), "denied");
        assert_eq!(fallback_past(proto::Action::Reject as i32), "rejected");
    }

    #[test]
    fn dest_display_prefers_the_hostname() {
        assert_eq!(
            dest_display("example.com", "93.184.216.34", 443),
            "example.com (93.184.216.34:443)"
        );
        assert_eq!(dest_display("", "93.184.216.34", 443), "93.184.216.34:443");
        assert_eq!(dest_display("", "", 53), "?:53");
    }

    #[test]
    fn dest_key_prefers_the_hostname() {
        assert_eq!(dest_key("example.com", "1.2.3.4"), "example.com");
        assert_eq!(dest_key("", "1.2.3.4"), "1.2.3.4");
        assert_eq!(dest_key("", ""), "unknown");
    }

    #[test]
    fn host_cidr_widths() {
        assert_eq!(host_cidr("10.0.0.1"), "10.0.0.1/32");
        assert_eq!(host_cidr("2001:db8::1"), "2001:db8::1/128");
        assert_eq!(host_cidr("not-an-ip"), "");
    }

    #[test]
    fn sha_truncation() {
        assert_eq!(truncate_sha(""), "unknown");
        assert_eq!(truncate_sha("abcd"), "abcd");
        assert_eq!(
            truncate_sha(&"a".repeat(64)),
            format!("{}...", "a".repeat(16))
        );
    }

    #[test]
    fn timestamps_degrade_gracefully() {
        assert_eq!(format_unix_ms(0), "-");
        assert_eq!(format_unix_ms(-1), "-");
        assert_eq!(format_unix_ms(1_700_000_000_000), "2023-11-14 22:13");
        assert_eq!(format_clock_ms(0), "?");
        assert_eq!(format_clock_ms(1_700_000_000_000), "22:13:20");
    }

    #[test]
    fn connection_hint_collapses_whitespace() {
        assert_eq!(connection_hint("", 80), "");
        assert_eq!(connection_hint("   \n  ", 80), "");
        assert_eq!(
            connection_hint("permission   denied\n on  /run/x", 80),
            "permission denied on /run/x"
        );
    }

    #[test]
    fn connection_hint_clips_without_splitting_a_char() {
        assert_eq!(connection_hint("abcdef", 3), "abc...");
        // Multi-byte input must clip by character, not by byte.
        let wide = "é".repeat(10);
        assert_eq!(connection_hint(&wide, 4), format!("{}...", "é".repeat(4)));
        assert_eq!(
            connection_hint("abc", 3),
            "abc",
            "exactly at the cap is kept"
        );
    }

    #[test]
    fn unreachable_line_keeps_the_actionable_advice() {
        // Verbatim shape of cfc_client::ClientError::PermissionDenied, the
        // most likely first-run failure now that the socket is group-gated.
        let detail = "permission denied on /run/colony-firewall/cfc.sock - add your user to \
                      the colony-firewall group (sudo usermod -aG colony-firewall $USER) then \
                      log out and back in, or run as root";
        let line = unreachable_log_line(detail);
        assert!(
            line.starts_with("daemon unreachable, retrying... - "),
            "{line}"
        );
        assert!(line.contains("colony-firewall group"), "{line}");
        assert!(line.contains("usermod"), "{line}");
    }

    #[test]
    fn unreachable_line_is_stable_so_retries_coalesce() {
        let detail = "socket /run/x does not exist -\n  is colony-firewalld running?";
        assert_eq!(unreachable_log_line(detail), unreachable_log_line(detail));
        // Whitespace-only variation must not produce a second log entry.
        assert_eq!(
            unreachable_log_line(detail),
            unreachable_log_line("socket /run/x does not exist - is colony-firewalld running?")
        );
    }

    #[test]
    fn unreachable_line_without_a_detail_falls_back() {
        assert_eq!(unreachable_log_line(""), "daemon unreachable, retrying...");
        assert_eq!(
            unreachable_log_line("  "),
            "daemon unreachable, retrying..."
        );
    }

    #[test]
    fn resume_phrasing() {
        assert_eq!(format_resume_in(0, 1_000), "until resumed manually");
        assert_eq!(format_resume_in(1_000, 1_000), "resuming...");
        assert_eq!(format_resume_in(61_000, 1_000), "resumes in 1m 00s");
    }
}
