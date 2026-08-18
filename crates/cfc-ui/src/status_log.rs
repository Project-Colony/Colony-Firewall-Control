//! A small ring of timestamped status lines.
//!
//! Replaces the single overwritable `last_error` string: repeated messages
//! collapse into one entry with a counter (the 2s reconnect loops used to
//! rewrite the footer forever), informational lines expire on their own,
//! and anything the user must actually act on stays until dismissed.

use std::collections::VecDeque;

/// Entries kept at once. Older ones fall off the back.
pub const CAP: usize = 5;

/// How long a non-sticky entry stays visible.
pub const TTL_MS: i64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn glyph(self) -> &'static str {
        match self {
            Severity::Info => "•",
            Severity::Warn => "⚠",
            Severity::Error => "✖",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub severity: Severity,
    pub text: String,
    /// Wall clock of the most recent occurrence.
    pub at_ms: i64,
    /// How many times this exact line has been pushed.
    pub count: u32,
    /// Sticky entries survive `prune`; rule-save and verdict failures are
    /// sticky because they mean the user's intent was not carried out.
    pub sticky: bool,
}

impl LogEntry {
    /// `"daemon unreachable, retrying... (x4)"`
    pub fn display(&self) -> String {
        if self.count > 1 {
            format!("{} (x{})", self.text, self.count)
        } else {
            self.text.clone()
        }
    }
}

#[derive(Debug, Default)]
pub struct StatusLog {
    entries: VecDeque<LogEntry>,
}

impl StatusLog {
    /// Records `text`, coalescing with an identical live entry rather than
    /// appending a duplicate. Newest first.
    pub fn push(&mut self, severity: Severity, text: impl Into<String>, at_ms: i64, sticky: bool) {
        let text = text.into();
        if let Some(pos) = self.entries.iter().position(|e| e.text == text) {
            let mut existing = self.entries.remove(pos).expect("position is in range");
            existing.count = existing.count.saturating_add(1);
            existing.at_ms = at_ms;
            existing.severity = severity;
            existing.sticky |= sticky;
            self.entries.push_front(existing);
            return;
        }
        self.entries.push_front(LogEntry {
            severity,
            text,
            at_ms,
            count: 1,
            sticky,
        });
        while self.entries.len() > CAP {
            self.entries.pop_back();
        }
    }

    pub fn info(&mut self, text: impl Into<String>, at_ms: i64) {
        self.push(Severity::Info, text, at_ms, false);
    }

    pub fn warn(&mut self, text: impl Into<String>, at_ms: i64) {
        self.push(Severity::Warn, text, at_ms, false);
    }

    /// Sticky by construction: an error the user must see and dismiss.
    pub fn error(&mut self, text: impl Into<String>, at_ms: i64) {
        self.push(Severity::Error, text, at_ms, true);
    }

    /// Drops non-sticky entries older than [`TTL_MS`].
    pub fn prune(&mut self, now_ms: i64) {
        self.entries
            .retain(|e| e.sticky || now_ms.saturating_sub(e.at_ms) < TTL_MS);
    }

    pub fn dismiss(&mut self, index: usize) {
        if index < self.entries.len() {
            let _ = self.entries.remove(index);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_coalesce_instead_of_filling_the_ring() {
        let mut log = StatusLog::default();
        for i in 0..8 {
            log.info("daemon unreachable, retrying...", 1_000 + i);
        }
        assert_eq!(log.len(), 1);
        let e = log.iter().next().unwrap();
        assert_eq!(e.count, 8);
        assert_eq!(e.at_ms, 1_007);
        assert_eq!(e.display(), "daemon unreachable, retrying... (x8)");
    }

    #[test]
    fn single_occurrence_has_no_counter_suffix() {
        let mut log = StatusLog::default();
        log.info("hello", 0);
        assert_eq!(log.iter().next().unwrap().display(), "hello");
    }

    #[test]
    fn newest_entry_is_first_and_ring_is_capped() {
        let mut log = StatusLog::default();
        for i in 0..(CAP + 3) {
            log.info(format!("line {i}"), i as i64);
        }
        assert_eq!(log.len(), CAP);
        assert_eq!(log.iter().next().unwrap().text, format!("line {}", CAP + 2));
        // The oldest lines were evicted.
        assert!(!log.iter().any(|e| e.text == "line 0"));
    }

    #[test]
    fn coalescing_moves_the_entry_back_to_the_front() {
        let mut log = StatusLog::default();
        log.info("old", 0);
        log.info("new", 1);
        log.info("old", 2);
        assert_eq!(log.iter().next().unwrap().text, "old");
    }

    #[test]
    fn prune_expires_info_but_keeps_sticky_errors() {
        let mut log = StatusLog::default();
        log.info("transient", 0);
        log.error("rule rejected by daemon", 0);
        log.prune(TTL_MS - 1);
        assert_eq!(log.len(), 2, "nothing expires before the TTL");
        log.prune(TTL_MS);
        assert_eq!(log.len(), 1);
        assert_eq!(log.iter().next().unwrap().severity, Severity::Error);
    }

    #[test]
    fn re_pushing_a_sticky_text_keeps_it_sticky() {
        let mut log = StatusLog::default();
        log.error("boom", 0);
        log.info("boom", 1);
        log.prune(TTL_MS * 10);
        assert_eq!(log.len(), 1, "stickiness must not be downgraded");
    }

    #[test]
    fn dismiss_is_index_safe() {
        let mut log = StatusLog::default();
        log.info("a", 0);
        log.dismiss(7);
        assert_eq!(log.len(), 1);
        log.dismiss(0);
        assert!(log.is_empty());
    }
}
