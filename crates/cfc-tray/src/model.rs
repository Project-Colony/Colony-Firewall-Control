//! Pure tray state: what the last status poll saw and how that maps onto
//! the menu. Everything in this module is I/O-free so it can be unit
//! tested without a daemon, a D-Bus session, or a clock.

use cfc_client::ClientError;

/// At most one desktop notification per this many milliseconds, however
/// fast prompts arrive.
pub const NOTIFY_MIN_INTERVAL_MS: i64 = 30_000;

/// The pause durations offered by the submenu. `0` means "the daemon's
/// configured default" ([pause] default_secs), matching the SetPaused
/// contract.
pub const PAUSE_CHOICES: [(&str, u32); 4] = [
    ("For 5 min", 300),
    ("For 30 min", 1800),
    ("For 1 h", 3600),
    ("Daemon default", 0),
];

/// What the last GetStatus poll saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonView {
    /// Before the first poll has completed.
    Connecting,
    /// The poll failed; `hint` is one short actionable line derived from
    /// the [`ClientError`].
    Unreachable { hint: String },
    Reachable {
        enforcing: bool,
        paused: bool,
        resume_at_unix_ms: i64,
        prompts_pending: u64,
    },
}

/// Which pause control the menu shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseControl {
    /// The "Pause" submenu with duration choices.
    Offer,
    /// A single "Resume now" item (shown while paused).
    ResumeNow,
}

/// A pure description of the menu, mapped 1:1 onto ksni items by the
/// tray. Testable without any D-Bus types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuModel {
    /// First line, always present, never clickable.
    pub status_line: String,
    /// "N prompt(s) waiting" entry; clicking opens the GUI. `None` when
    /// nothing is pending or the daemon is unreachable.
    pub prompts_line: Option<String>,
    /// Pause / resume controls. `None` while the daemon is unreachable
    /// (there is nothing to pause).
    pub pause: Option<PauseControl>,
}

/// One short line the user can act on, derived from the client error.
/// The full [`ClientError`] messages are the authority; these are their
/// one-menu-line abbreviations.
pub fn unreachable_hint(err: &ClientError) -> String {
    match err {
        ClientError::SocketMissing { .. } => {
            "daemon not running? (systemctl status colony-firewalld)".into()
        }
        ClientError::PermissionDenied { .. } => {
            "no socket access — join the colony-firewall group".into()
        }
        ClientError::StaleSocket { .. } => "stale socket — restart colony-firewalld".into(),
        ClientError::Connect { .. } | ClientError::Transport(_) => {
            "connection failed — is colony-firewalld healthy?".into()
        }
        ClientError::Rpc(_) | ClientError::StreamClosed => "daemon answered with an error".into(),
    }
}

/// "2h 05m" / "5m 00s" / "42s". Negative input clamps to "0s".
pub fn format_countdown(secs: i64) -> String {
    let s = secs.max(0);
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {sec:02}s")
    } else {
        format!("{sec}s")
    }
}

/// The one-line status shown at the top of the menu.
///
/// Precedence: unreachable > NOT enforcing > paused > enforcing. "NOT
/// enforcing" outranks "Paused" because a daemon outside the packet path
/// is the more severe condition, and the paused state stays visible
/// through the "Resume now" item either way.
pub fn status_line(view: &DaemonView, now_unix_ms: i64) -> String {
    match view {
        DaemonView::Connecting => "Connecting to colony-firewalld…".into(),
        DaemonView::Unreachable { hint } => format!("Daemon unreachable: {hint}"),
        DaemonView::Reachable {
            enforcing: false, ..
        } => "NOT enforcing — nft rule loaded?".into(),
        DaemonView::Reachable {
            paused: true,
            resume_at_unix_ms,
            ..
        } => {
            let remaining_ms = resume_at_unix_ms.saturating_sub(now_unix_ms);
            if *resume_at_unix_ms <= 0 || remaining_ms <= 0 {
                "Paused".into()
            } else {
                // Round up so a fresh 5-minute pause reads "5m 00s", not
                // "4m 59s".
                let secs = (remaining_ms + 999) / 1000;
                format!("Paused — resumes in {}", format_countdown(secs))
            }
        }
        DaemonView::Reachable { .. } => "Enforcing".into(),
    }
}

/// The "N prompt(s) waiting" line, when anything is pending.
pub fn prompts_line(view: &DaemonView) -> Option<String> {
    match view {
        DaemonView::Reachable {
            prompts_pending: n @ 1..,
            ..
        } => {
            let noun = if *n == 1 { "prompt" } else { "prompts" };
            Some(format!("{n} {noun} waiting"))
        }
        _ => None,
    }
}

/// Tooltip body: the status line, plus the pending-prompt count when
/// anything is waiting.
pub fn tooltip_description(view: &DaemonView, now_unix_ms: i64) -> String {
    let base = status_line(view, now_unix_ms);
    match prompts_line(view) {
        Some(line) => format!("{base} — {line}"),
        None => base,
    }
}

/// Maps the daemon view onto the menu.
pub fn menu_model(view: &DaemonView, now_unix_ms: i64) -> MenuModel {
    let pause = match view {
        DaemonView::Reachable { paused: true, .. } => Some(PauseControl::ResumeNow),
        DaemonView::Reachable { .. } => Some(PauseControl::Offer),
        DaemonView::Connecting | DaemonView::Unreachable { .. } => None,
    };
    MenuModel {
        status_line: status_line(view, now_unix_ms),
        prompts_line: prompts_line(view),
        pause,
    }
}

/// Decides when a "prompts waiting" desktop notification fires: only when
/// the pending count *increased* since the previous reachable poll, and
/// at most once per [`NOTIFY_MIN_INTERVAL_MS`].
#[derive(Debug, Default)]
pub struct NotifyGate {
    last_count: u64,
    last_notified_at_ms: Option<i64>,
}

impl NotifyGate {
    /// Feed one reachable poll. Returns `true` when a notification should
    /// be shown now.
    pub fn on_poll(&mut self, prompts_pending: u64, now_unix_ms: i64) -> bool {
        let increased = prompts_pending > self.last_count;
        self.last_count = prompts_pending;
        if !increased {
            return false;
        }
        if let Some(t) = self.last_notified_at_ms {
            if now_unix_ms.saturating_sub(t) < NOTIFY_MIN_INTERVAL_MS {
                return false;
            }
        }
        self.last_notified_at_ms = Some(now_unix_ms);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn reachable(
        enforcing: bool,
        paused: bool,
        resume_at_unix_ms: i64,
        prompts_pending: u64,
    ) -> DaemonView {
        DaemonView::Reachable {
            enforcing,
            paused,
            resume_at_unix_ms,
            prompts_pending,
        }
    }

    // --- status line -------------------------------------------------------

    #[test]
    fn enforcing_status_line() {
        assert_eq!(
            status_line(&reachable(true, false, 0, 0), 1_000),
            "Enforcing"
        );
    }

    #[test]
    fn not_enforcing_names_the_nft_rule() {
        assert_eq!(
            status_line(&reachable(false, false, 0, 0), 1_000),
            "NOT enforcing — nft rule loaded?"
        );
    }

    #[test]
    fn not_enforcing_outranks_paused() {
        // A daemon outside the packet path is the more severe condition;
        // saying "Paused" would imply things resume into a working state.
        let line = status_line(&reachable(false, true, 999_999_999, 0), 1_000);
        assert!(line.starts_with("NOT enforcing"), "{line}");
    }

    #[test]
    fn paused_counts_down_and_rounds_up() {
        // Exactly 5 minutes left.
        let now = 10_000_000;
        let view = reachable(true, true, now + 300_000, 0);
        assert_eq!(status_line(&view, now), "Paused — resumes in 5m 00s");
        // 1ms into the pause the display still reads 5m (rounds up).
        assert_eq!(status_line(&view, now + 1), "Paused — resumes in 5m 00s");
        // Deep into it.
        assert_eq!(status_line(&view, now + 299_000), "Paused — resumes in 1s");
    }

    #[test]
    fn paused_with_expired_or_unknown_deadline_is_plain() {
        let now = 10_000_000;
        assert_eq!(
            status_line(&reachable(true, true, now - 1, 0), now),
            "Paused"
        );
        assert_eq!(status_line(&reachable(true, true, 0, 0), now), "Paused");
    }

    #[test]
    fn unreachable_status_line_carries_the_hint() {
        let view = DaemonView::Unreachable {
            hint: "daemon not running? (systemctl status colony-firewalld)".into(),
        };
        assert_eq!(
            status_line(&view, 0),
            "Daemon unreachable: daemon not running? (systemctl status colony-firewalld)"
        );
    }

    // --- countdown formatting ----------------------------------------------

    #[test]
    fn countdown_formats_by_magnitude() {
        assert_eq!(format_countdown(0), "0s");
        assert_eq!(format_countdown(-5), "0s");
        assert_eq!(format_countdown(42), "42s");
        assert_eq!(format_countdown(59), "59s");
        assert_eq!(format_countdown(60), "1m 00s");
        assert_eq!(format_countdown(299), "4m 59s");
        assert_eq!(format_countdown(3599), "59m 59s");
        assert_eq!(format_countdown(3600), "1h 00m");
        assert_eq!(format_countdown(3660), "1h 01m");
        assert_eq!(format_countdown(86_400), "24h 00m");
    }

    // --- unreachable hints --------------------------------------------------

    #[test]
    fn hints_are_short_and_actionable() {
        let p = PathBuf::from("/run/colony-firewall/cfc.sock");
        let cases: [(ClientError, &str); 4] = [
            (
                ClientError::SocketMissing { path: p.clone() },
                "systemctl status colony-firewalld",
            ),
            (
                ClientError::PermissionDenied { path: p.clone() },
                "colony-firewall group",
            ),
            (
                ClientError::StaleSocket { path: p.clone() },
                "restart colony-firewalld",
            ),
            (
                ClientError::Connect {
                    path: p,
                    source: Box::new(std::io::Error::other("boom")),
                },
                "colony-firewalld healthy",
            ),
        ];
        for (err, needle) in cases {
            let hint = unreachable_hint(&err);
            assert!(hint.contains(needle), "{hint:?} should contain {needle:?}");
            assert!(!hint.contains('\n'), "hint must be one line: {hint:?}");
            assert!(hint.len() < 80, "hint must stay short: {hint:?}");
        }
    }

    // --- menu model ---------------------------------------------------------

    #[test]
    fn running_daemon_offers_the_pause_submenu() {
        let m = menu_model(&reachable(true, false, 0, 0), 0);
        assert_eq!(m.status_line, "Enforcing");
        assert_eq!(m.prompts_line, None);
        assert_eq!(m.pause, Some(PauseControl::Offer));
    }

    #[test]
    fn paused_daemon_offers_resume_instead() {
        let m = menu_model(&reachable(true, true, 0, 0), 0);
        assert_eq!(m.pause, Some(PauseControl::ResumeNow));
    }

    #[test]
    fn unreachable_daemon_has_no_pause_control_and_no_prompts() {
        let m = menu_model(&DaemonView::Unreachable { hint: "x".into() }, 0);
        assert!(m.status_line.starts_with("Daemon unreachable: "));
        assert_eq!(m.prompts_line, None);
        assert_eq!(m.pause, None);
    }

    #[test]
    fn connecting_has_no_controls_yet() {
        let m = menu_model(&DaemonView::Connecting, 0);
        assert_eq!(m.prompts_line, None);
        assert_eq!(m.pause, None);
    }

    #[test]
    fn prompts_line_pluralizes() {
        assert_eq!(prompts_line(&reachable(true, false, 0, 0)), None);
        assert_eq!(
            prompts_line(&reachable(true, false, 0, 1)),
            Some("1 prompt waiting".into())
        );
        assert_eq!(
            prompts_line(&reachable(true, false, 0, 3)),
            Some("3 prompts waiting".into())
        );
    }

    #[test]
    fn pause_choices_include_the_daemon_default() {
        // duration_secs = 0 is the SetPaused contract for "daemon default";
        // exactly one choice must use it.
        assert_eq!(PAUSE_CHOICES.iter().filter(|(_, s)| *s == 0).count(), 1);
        assert_eq!(PAUSE_CHOICES.len(), 4);
        assert!(PAUSE_CHOICES.contains(&("For 5 min", 300)));
        assert!(PAUSE_CHOICES.contains(&("For 30 min", 1800)));
        assert!(PAUSE_CHOICES.contains(&("For 1 h", 3600)));
    }

    // --- tooltip ------------------------------------------------------------

    #[test]
    fn tooltip_is_state_plus_prompt_count() {
        assert_eq!(
            tooltip_description(&reachable(true, false, 0, 0), 0),
            "Enforcing"
        );
        assert_eq!(
            tooltip_description(&reachable(true, false, 0, 2), 0),
            "Enforcing — 2 prompts waiting"
        );
    }

    // --- notification gate --------------------------------------------------

    #[test]
    fn gate_fires_on_increase_only() {
        let mut g = NotifyGate::default();
        assert!(g.on_poll(1, 0)); // 0 -> 1: fire
        assert!(!g.on_poll(1, 60_000)); // unchanged: no
        assert!(!g.on_poll(0, 120_000)); // resolved: no
        assert!(g.on_poll(2, 180_000)); // 0 -> 2: fire
    }

    #[test]
    fn gate_rate_limits_to_one_per_interval() {
        let mut g = NotifyGate::default();
        assert!(g.on_poll(1, 0));
        // More prompts, but within the 30s window: suppressed.
        assert!(!g.on_poll(2, NOTIFY_MIN_INTERVAL_MS - 1));
        // Another increase after the window: fires.
        assert!(g.on_poll(3, NOTIFY_MIN_INTERVAL_MS + 1));
    }

    #[test]
    fn gate_suppressed_increase_is_not_retried_without_a_new_increase() {
        let mut g = NotifyGate::default();
        assert!(g.on_poll(1, 0));
        assert!(!g.on_poll(2, 1_000)); // suppressed by the rate limit
                                       // Window has passed but the count did not increase again.
        assert!(!g.on_poll(2, NOTIFY_MIN_INTERVAL_MS + 1_000));
    }

    #[test]
    fn gate_first_poll_with_pending_prompts_fires() {
        // Fresh login with prompts already queued: the user should hear
        // about them.
        let mut g = NotifyGate::default();
        assert!(g.on_poll(5, 123));
    }
}
