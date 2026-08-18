//! A small duration parser for `--for` / `--since`.
//!
//! Deliberately hand-rolled: the accepted grammar is tiny, and a wrong
//! parse here silently changes how long enforcement stays off.

use std::time::Duration;

/// Parses `30s`, `5m`, `2h`, `1d`, `1h30m`, or a bare number of seconds.
///
/// Units are `s`, `m`, `h`, `d` and may be repeated in one string; a bare
/// integer means seconds. Everything else is an error rather than a
/// best-effort guess.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }

    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut saw_component = false;

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        if digits.is_empty() {
            return Err(format!(
                "invalid duration {input:?}: expected digits before {ch:?}"
            ));
        }
        let value: u64 = digits
            .parse()
            .map_err(|_| format!("invalid duration {input:?}: {digits} is out of range"))?;
        digits.clear();
        let secs = match ch.to_ascii_lowercase() {
            's' => Some(value),
            'm' => value.checked_mul(60),
            'h' => value.checked_mul(3600),
            'd' => value.checked_mul(86_400),
            other => {
                return Err(format!(
                    "invalid duration {input:?}: unknown unit {other:?} (use s, m, h or d)"
                ))
            }
        }
        .ok_or_else(|| format!("invalid duration {input:?}: overflow"))?;
        total = total
            .checked_add(secs)
            .ok_or_else(|| format!("invalid duration {input:?}: overflow"))?;
        saw_component = true;
    }

    // Trailing digits with no unit: only legal when they are the whole
    // input, in which case they mean seconds.
    if !digits.is_empty() {
        if saw_component {
            return Err(format!(
                "invalid duration {input:?}: trailing {digits} has no unit"
            ));
        }
        total = digits
            .parse()
            .map_err(|_| format!("invalid duration {input:?}: out of range"))?;
    }

    Ok(Duration::from_secs(total))
}

/// clap value parser wrapper.
pub fn parse_duration_arg(s: &str) -> Result<Duration, String> {
    parse_duration(s)
}

/// Renders a number of seconds the way the status line wants it: `2h 5m`,
/// `45s`, `0s`.
pub fn format_secs(total: i64) -> String {
    if total <= 0 {
        return "0s".to_string();
    }
    let (d, h, m, s) = (
        total / 86_400,
        (total % 86_400) / 3600,
        (total % 3600) / 60,
        total % 60,
    );
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d}d"));
    }
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 {
        parts.push(format!("{m}m"));
    }
    if s > 0 && d == 0 {
        parts.push(format!("{s}s"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_number_is_seconds() {
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration(" 90 ").unwrap(), Duration::from_secs(90));
    }

    #[test]
    fn single_units() {
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_duration("2H").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn compound_units_add_up() {
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(
            parse_duration("1d2h3m4s").unwrap(),
            Duration::from_secs(86_400 + 7200 + 180 + 4)
        );
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "  ", "h", "5x", "1.5h", "m5", "-5s", "1h30"] {
            assert!(parse_duration(bad).is_err(), "expected {bad:?} to fail");
        }
    }

    #[test]
    fn rejects_overflow() {
        assert!(parse_duration("99999999999999999999d").is_err());
        assert!(parse_duration(&format!("{}d", u64::MAX)).is_err());
    }

    #[test]
    fn formats_seconds_for_humans() {
        assert_eq!(format_secs(0), "0s");
        assert_eq!(format_secs(-5), "0s");
        assert_eq!(format_secs(45), "45s");
        assert_eq!(format_secs(90), "1m 30s");
        assert_eq!(format_secs(3600), "1h");
        assert_eq!(format_secs(3661), "1h 1m 1s");
        assert_eq!(format_secs(86_400 + 3600), "1d 1h");
    }
}
