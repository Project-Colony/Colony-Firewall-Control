//! Output-format plumbing shared by every subcommand.

use crate::error::CliResult;
use anyhow::Context;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Aligned, colourised text meant for a human.
    Human,
    /// Machine-readable JSON. Streaming commands emit NDJSON (one object
    /// per line, flushed as it arrives).
    Json,
}

impl OutputFormat {
    pub fn is_json(self) -> bool {
        self == OutputFormat::Json
    }
}

/// Prints one pretty-printed JSON document (object or array).
pub fn print_json<T: serde::Serialize>(value: &T) -> CliResult {
    let s = serde_json::to_string_pretty(value).context("serialising JSON")?;
    println!("{s}");
    Ok(())
}

/// Prints one NDJSON record and flushes, so a piped consumer sees events
/// as they happen rather than when the pipe buffer fills.
pub fn print_ndjson<T: serde::Serialize>(value: &T) -> CliResult {
    let s = serde_json::to_string(value).context("serialising JSON")?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{s}").context("writing stdout")?;
    out.flush().context("flushing stdout")?;
    Ok(())
}

/// Renders a unix-millis instant as a local wall-clock time.
pub fn local_time(unix_ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(unix_ms) {
        Some(t) => t
            .with_timezone(&chrono::Local)
            .format("%H:%M:%S")
            .to_string(),
        None => "?".to_string(),
    }
}

/// Renders a unix-millis instant as a local date and time.
pub fn local_datetime(unix_ms: i64) -> String {
    match chrono::DateTime::from_timestamp_millis(unix_ms) {
        Some(t) => t
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        None => "?".to_string(),
    }
}

/// RFC 3339 rendering for JSON output; empty string for "never".
pub fn rfc3339(unix_ms: i64) -> Option<String> {
    if unix_ms <= 0 {
        return None;
    }
    chrono::DateTime::from_timestamp_millis(unix_ms).map(|t| t.to_rfc3339())
}

/// Clips a cell to `width` characters, marking the cut with `~` so a
/// truncated path is never mistaken for a real one.
pub fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width || width == 0 {
        return s.to_string();
    }
    let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
    out.push('~');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_marks_the_cut() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("0123456789", 6), "01234~");
        assert_eq!(truncate("exact", 5), "exact");
        assert_eq!(truncate("anything", 0), "anything");
    }

    #[test]
    fn json_flag_is_the_only_machine_mode() {
        assert!(OutputFormat::Json.is_json());
        assert!(!OutputFormat::Human.is_json());
    }

    #[test]
    fn zero_timestamps_have_no_rfc3339() {
        assert!(rfc3339(0).is_none());
        assert!(rfc3339(-1).is_none());
        assert!(rfc3339(1_700_000_000_000).is_some());
    }

    #[test]
    fn bad_timestamps_render_as_question_mark() {
        assert_eq!(local_time(i64::MAX), "?");
        assert_eq!(local_datetime(i64::MAX), "?");
    }
}
