//! Pure tray state: what the last status poll saw and how that maps onto
//! the menu. Everything in this module is I/O-free so it can be unit
//! tested without a daemon, a D-Bus session, or a clock.

use cfc_client::{proto, ClientError};

/// At most one desktop notification per this many milliseconds, however
/// fast prompts arrive. Only used by the generic (non-actionable)
/// fallback path; actionable notifications are one-per-prompt by design.
pub const NOTIFY_MIN_INTERVAL_MS: i64 = 30_000;

/// At most this many actionable prompt notifications on screen at once;
/// prompts beyond the cap fold into one collapsed overflow notification.
pub const MAX_ACTIONABLE_NOTIFICATIONS: usize = 3;

/// Floor for a prompt notification's expire timeout. A deadline that is
/// already past still gets a brief, visible bubble rather than a 0ms
/// ("never expire") or negative ("server default") timeout.
pub const MIN_PROMPT_TIMEOUT_MS: u32 = 1_000;

/// Notification action keys. `default` is the freedesktop key invoked by
/// clicking the notification body itself.
pub const KEY_DEFAULT: &str = "default";
pub const KEY_ALLOW: &str = "allow";
pub const KEY_DENY: &str = "deny";
pub const KEY_BLOCK: &str = "block";
/// notify-rust reports dismissal/expiry as this pseudo-action key.
pub const KEY_CLOSED: &str = "__closed";

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

/// Whether the notification server can do per-prompt actionable
/// notifications at all. Decided once at startup from
/// `org.freedesktop.Notifications.GetCapabilities`; without "actions" the
/// tray keeps the generic [`NotifyGate`]-driven count notification.
pub fn actions_supported(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == "actions")
}

/// A pure description of one actionable prompt notification, mapped 1:1
/// onto a notify-rust `Notification` by the tray.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptNotification {
    /// "<process> wants to connect" - the whole headline, so the bold
    /// first line of the bubble reads as a sentence on its own.
    pub summary: String,
    /// The destination on the first line and the full exe path on the
    /// second, so the path never runs into the prose.
    pub body: String,
    /// Remaining time until the prompt's deadline, clamped to at least
    /// [`MIN_PROMPT_TIMEOUT_MS`]. When it expires unanswered the daemon
    /// applies its timeout_action; the tray does nothing.
    pub timeout_ms: u32,
    /// Whether "Block app always" is offered. False when the prompt has
    /// no exe path: a RuleScope with an empty exe_path would be a
    /// match-everything deny rule, not an app block.
    pub offer_block: bool,
}

/// Maps one PromptEvent onto the notification shown for it.
pub fn prompt_notification(ev: &proto::PromptEvent, now_unix_ms: i64) -> PromptNotification {
    let exe = ev.process.as_ref().map_or("", |p| p.exe.as_str());
    let name = match ev.process.as_ref() {
        Some(p) => cfc_client::convert::process_display(p),
        None => "An unknown process".to_string(),
    };
    let summary = format!("{name} wants to connect");
    // "93.184.216.34:443" is not something anyone can make a decision
    // about; prefer the resolved hostname whenever the daemon has one.
    let target = match ev.connection.as_ref() {
        Some(c) => {
            let host = [c.dst_host.as_str(), c.dst_ip.as_str(), "unknown"]
                .into_iter()
                .find(|s| !s.is_empty())
                .expect("literal fallback");
            format!(
                "{host}:{} ({})",
                c.dst_port,
                cfc_client::convert::protocol_label(c.protocol)
            )
        }
        None => "an unknown destination".to_string(),
    };
    let mut body = target;
    if !exe.is_empty() {
        body.push('\n');
        body.push_str(exe);
    }
    let remaining = ev.deadline_unix_ms.saturating_sub(now_unix_ms);
    let timeout_ms = remaining.clamp(i64::from(MIN_PROMPT_TIMEOUT_MS), i64::from(u32::MAX)) as u32;
    PromptNotification {
        summary,
        body,
        timeout_ms,
        offer_block: !exe.is_empty(),
    }
}

/// What a notification button click means.
///
/// # Why Allow persists and Deny does not
///
/// The two permanent choices are the two that answer the question the user is
/// actually being asked: *may this program use the network?* That is a
/// property of the program, not of one TCP connection, and it is how a person
/// thinks about it - the same shape Windows Firewall Control uses, where you
/// authorise the executable once and never see it again.
///
/// Allow used to be one-shot, and it made the product unusable on the
/// applications people use most. A browser opens dozens of connections to
/// render one page: every one of them was a separate bubble, and answering
/// "yes" to each was not a thing anyone would do. Observed live - a user
/// denied ten prompts in a row to make them stop and lost their browser
/// entirely, while Steam and a chat client, which hold a few long-lived
/// connections, worked fine. The flaw only bit the applications that matter.
///
/// Deny stays one-shot on purpose. "Not right now" and "never" are genuinely
/// different answers, and the permanent form of no already has its own button.
/// Keeping the transient option on the refusing side, where a mistake costs a
/// retry rather than access, is the right way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptChoice {
    /// "Allow": this program may use the network, from now on. Persists a
    /// rule scoped to the exe, mirroring [`Self::BlockAlways`].
    AllowAlways,
    /// "Deny": refuse this one connection. Ask again next time.
    DenyOnce,
    /// "Block app": deny and persist a rule for this exe.
    BlockAlways,
}

/// Maps a notification action key to a verdict choice. [`KEY_DEFAULT`]
/// (open the GUI) and [`KEY_CLOSED`] (dismissed/expired) are not verdicts
/// and map to `None`.
pub fn choice_from_key(key: &str) -> Option<PromptChoice> {
    match key {
        KEY_ALLOW => Some(PromptChoice::AllowAlways),
        KEY_DENY => Some(PromptChoice::DenyOnce),
        KEY_BLOCK => Some(PromptChoice::BlockAlways),
        _ => None,
    }
}

/// The SubmitVerdict triple for a choice.
///
/// Once verdicts must never carry a persist_scope - the daemon rejects a
/// persisted Once outright. Both `Always` choices persist, scoped to the
/// prompting exe and nothing else: the rule says *this program*, never this
/// port or this address, so allowing a browser does not also allow whatever
/// else happens to talk to the same host.
pub fn verdict_for(
    choice: PromptChoice,
    exe: &str,
) -> (proto::Action, proto::Duration, Option<proto::RuleScope>) {
    // Both persisted choices are the same rule with the verdict flipped, so
    // they are built the same way rather than written out twice.
    let for_this_exe = |action| {
        (
            action,
            proto::Duration::Always,
            Some(proto::RuleScope {
                exe_path: exe.to_string(),
                ..Default::default()
            }),
        )
    };
    match choice {
        PromptChoice::AllowAlways => for_this_exe(proto::Action::Allow),
        PromptChoice::BlockAlways => for_this_exe(proto::Action::Deny),
        PromptChoice::DenyOnce => (proto::Action::Deny, proto::Duration::Once, None),
    }
}

/// Body of the brief confirmation after "Block app always" succeeded.
pub fn block_confirmation(exe: &str) -> String {
    format!("Rule created: deny {} always", exe_display_name(exe))
}

/// Said when the verdict applied but the standing rule did not get saved.
///
/// Deliberately not phrased as a success with a caveat: the user asked for a
/// lasting answer and did not get one, so the next connection from this program
/// will prompt again. Telling them that now is what stops it looking like the
/// firewall forgot.
pub fn rule_not_saved(exe: &str, why: Option<&str>) -> String {
    let name = exe_display_name(exe);
    match why {
        Some(w) => format!("{name}: the answer applied, but no lasting rule was saved ({w})"),
        None => format!("{name}: the answer applied, but no lasting rule was saved"),
    }
}

/// Body of the brief confirmation after "Allow" created a rule.
///
/// Worth showing rather than succeeding silently: the button now grants
/// standing access, and the user should be told that in the same breath - both
/// so they know they will not be asked again, and so an accidental click is
/// something they can see and undo rather than discover months later.
pub fn allow_confirmation(exe: &str) -> String {
    format!("Rule created: allow {} always", exe_display_name(exe))
}

/// The basename, for a message meant to be read at a glance.
fn exe_display_name(exe: &str) -> String {
    std::path::Path::new(exe)
        .file_name()
        .map_or_else(|| exe.to_string(), |n| n.to_string_lossy().into_owned())
}

/// How a newly arrived prompt is surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptPresentation {
    /// Its own actionable notification (a free slot exists).
    Actionable,
    /// Folded into the single collapsed notification, which now covers
    /// `count` prompts.
    Overflow { count: u64 },
}

/// Decides actionable-vs-collapsed for one new prompt, given how many
/// actionable notifications are on screen and how many prompts the
/// current overflow bubble already covers.
pub fn present_prompt(active_actionable: usize, overflowed: u64) -> PromptPresentation {
    if active_actionable < MAX_ACTIONABLE_NOTIFICATIONS {
        PromptPresentation::Actionable
    } else {
        PromptPresentation::Overflow {
            count: overflowed.saturating_add(1),
        }
    }
}

/// Body of the collapsed overflow notification.
pub fn overflow_body(count: u64) -> String {
    let noun = if count == 1 {
        "connection"
    } else {
        "connections"
    };
    format!("{count} more {noun} waiting — open Colony Firewall")
}

#[cfg(test)]
mod tests {

    #[test]
    fn the_not_saved_message_does_not_read_as_a_success() {
        // The failure it describes is silent otherwise: the verdict applied, so
        // the connection went through, and the user has no way to know their
        // standing answer did not stick until the next prompt appears.
        let m = rule_not_saved("/usr/bin/firefox", Some("storage: disk full"));
        assert!(m.contains("firefox"), "{m}");
        assert!(m.contains("no lasting rule"), "{m}");
        assert!(m.contains("disk full"), "the cause is worth carrying: {m}");
        assert!(
            !m.to_lowercase().contains("rule created"),
            "it must not be mistakable for the confirmation it replaces: {m}"
        );

        // And it stands on its own when the daemon gave no reason.
        let bare = rule_not_saved("/usr/bin/firefox", None);
        assert!(bare.contains("no lasting rule"), "{bare}");
    }
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

    // --- prompt notification mapping ---------------------------------------

    fn prompt_event(exe: &str, host: &str, ip: &str, deadline_unix_ms: i64) -> proto::PromptEvent {
        proto::PromptEvent {
            prompt_id: "42".into(),
            connection: Some(proto::ConnectionInfo {
                protocol: proto::Protocol::Tcp as i32,
                dst_ip: ip.into(),
                dst_port: 443,
                dst_host: host.into(),
                ..Default::default()
            }),
            process: Some(proto::ProcessInfo {
                pid: 1234,
                exe: exe.into(),
                ..Default::default()
            }),
            deadline_unix_ms,
        }
    }

    #[test]
    fn prompt_notification_prefers_host_over_ip() {
        let n = prompt_notification(
            &prompt_event("/usr/bin/curl", "example.com", "93.184.216.34", 0),
            0,
        );
        assert!(n.body.starts_with("example.com:443 (tcp)"), "{}", n.body);
    }

    #[test]
    fn prompt_notification_falls_back_to_ip_then_unknown() {
        let n = prompt_notification(&prompt_event("/usr/bin/curl", "", "93.184.216.34", 0), 0);
        assert!(n.body.starts_with("93.184.216.34:443 (tcp)"), "{}", n.body);
        let n = prompt_notification(&prompt_event("/usr/bin/curl", "", "", 0), 0);
        assert!(n.body.starts_with("unknown:443 (tcp)"), "{}", n.body);
    }

    #[test]
    fn prompt_notification_summary_is_the_exe_basename() {
        let n = prompt_notification(&prompt_event("/usr/bin/curl", "example.com", "", 0), 0);
        assert_eq!(n.summary, "curl wants to connect");
    }

    #[test]
    fn prompt_notification_body_carries_the_full_exe_on_a_second_line() {
        let n = prompt_notification(&prompt_event("/usr/bin/curl", "example.com", "", 0), 0);
        assert_eq!(n.body, "example.com:443 (tcp)\n/usr/bin/curl");
    }

    #[test]
    fn prompt_notification_without_exe_offers_no_block_and_stays_one_line() {
        // No exe path: "Block app always" would need RuleScope { exe_path },
        // and an empty exe_path is a match-everything rule, not an app block.
        let n = prompt_notification(&prompt_event("", "example.com", "", 0), 0);
        assert!(!n.offer_block);
        assert!(!n.body.contains('\n'), "{}", n.body);
        assert_eq!(n.summary, "pid:1234 wants to connect"); // no-exe form
        let with_exe = prompt_notification(&prompt_event("/usr/bin/curl", "e.com", "", 0), 0);
        assert!(with_exe.offer_block);
    }

    #[test]
    fn prompt_notification_without_process_reads_unknown() {
        let mut ev = prompt_event("", "example.com", "", 0);
        ev.process = None;
        let n = prompt_notification(&ev, 0);
        assert_eq!(n.summary, "An unknown process wants to connect");
        assert!(!n.offer_block);
    }

    #[test]
    fn prompt_timeout_is_the_remaining_time_until_the_deadline() {
        let now = 1_000_000;
        let n = prompt_notification(&prompt_event("/x", "h", "", now + 30_000), now);
        assert_eq!(n.timeout_ms, 30_000);
    }

    #[test]
    fn prompt_timeout_clamps_to_at_least_one_second() {
        let now = 1_000_000;
        // Already past, exactly now, and barely ahead all clamp up: 0ms
        // means "never expire" to the server and negative means "server
        // default", neither of which tracks the daemon's deadline.
        for deadline in [now - 5_000, now, now + 1, now + 999] {
            let n = prompt_notification(&prompt_event("/x", "h", "", deadline), now);
            assert_eq!(n.timeout_ms, MIN_PROMPT_TIMEOUT_MS, "deadline {deadline}");
        }
        // And an absurdly far deadline still fits the u32 the server takes.
        let n = prompt_notification(&prompt_event("/x", "h", "", i64::MAX), now);
        assert_eq!(n.timeout_ms, u32::MAX);
    }

    // --- choice -> verdict mapping ------------------------------------------

    #[test]
    fn once_verdicts_never_carry_a_persist_scope() {
        // The daemon rejects a persisted Once outright; this must be bare.
        let (a, d, s) = verdict_for(PromptChoice::DenyOnce, "/usr/bin/curl");
        assert_eq!((a, d), (proto::Action::Deny, proto::Duration::Once));
        assert_eq!(s, None);
    }

    /// The answer to "may this program use the network?" is about the
    /// program, so Allow persists - the same shape as Block, verdict flipped.
    ///
    /// It used to be one-shot, and that made the product unusable on exactly
    /// the applications people care about: a browser opens dozens of
    /// connections per page, each one its own bubble. Found by using it.
    #[test]
    fn allow_persists_a_rule_for_the_exe_like_block_does() {
        let (a, d, s) = verdict_for(PromptChoice::AllowAlways, "/usr/bin/firefox");
        assert_eq!((a, d), (proto::Action::Allow, proto::Duration::Always));
        let scope = s.expect("Allow must persist a rule");
        assert_eq!(scope.exe_path, "/usr/bin/firefox");

        // Scoped to the program and nothing else. A port or host in here
        // would mean allowing a browser also allowed anything else that
        // happened to talk to the same place.
        assert!(scope.dst_host.is_empty());
        assert!(scope.dst_net.is_empty());
        assert!(!scope.has_dst_port);
        assert!(!scope.has_protocol);
        assert!(!scope.has_uid);

        // Same rule as Block, opposite verdict - which is the property that
        // makes the two buttons symmetrical.
        let (block_a, block_d, block_s) =
            verdict_for(PromptChoice::BlockAlways, "/usr/bin/firefox");
        assert_eq!(block_d, d);
        assert_eq!(block_s.map(|b| b.exe_path), Some(scope.exe_path));
        assert_ne!(block_a, a);
    }

    #[test]
    fn allow_confirmation_names_the_program() {
        let msg = allow_confirmation("/usr/bin/firefox");
        assert!(msg.contains("firefox"), "{msg}");
        assert!(msg.contains("allow"), "{msg}");
        // The basename, not the whole path: this is read at a glance.
        assert!(!msg.contains("/usr/bin/"), "{msg}");
    }

    #[test]
    fn block_verdict_persists_a_deny_scoped_to_the_exe() {
        let (a, d, s) = verdict_for(PromptChoice::BlockAlways, "/usr/bin/curl");
        assert_eq!((a, d), (proto::Action::Deny, proto::Duration::Always));
        let scope = s.expect("block must carry a scope");
        assert_eq!(scope.exe_path, "/usr/bin/curl");
        // Nothing else narrows or widens the rule.
        assert_eq!(
            scope,
            proto::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn action_keys_map_to_choices_and_nothing_else_does() {
        assert_eq!(choice_from_key(KEY_ALLOW), Some(PromptChoice::AllowAlways));
        assert_eq!(choice_from_key(KEY_DENY), Some(PromptChoice::DenyOnce));
        assert_eq!(choice_from_key(KEY_BLOCK), Some(PromptChoice::BlockAlways));
        assert_eq!(choice_from_key(KEY_DEFAULT), None);
        assert_eq!(choice_from_key(KEY_CLOSED), None);
        assert_eq!(choice_from_key("bogus"), None);
    }

    #[test]
    fn block_confirmation_names_the_basename() {
        assert_eq!(
            block_confirmation("/usr/bin/curl"),
            "Rule created: deny curl always"
        );
    }

    // --- collapse beyond the cap --------------------------------------------

    #[test]
    fn prompts_below_the_cap_get_their_own_notification() {
        for active in 0..MAX_ACTIONABLE_NOTIFICATIONS {
            assert_eq!(present_prompt(active, 0), PromptPresentation::Actionable);
        }
    }

    #[test]
    fn prompts_at_or_beyond_the_cap_collapse_and_count_up() {
        assert_eq!(
            present_prompt(MAX_ACTIONABLE_NOTIFICATIONS, 0),
            PromptPresentation::Overflow { count: 1 }
        );
        assert_eq!(
            present_prompt(MAX_ACTIONABLE_NOTIFICATIONS, 4),
            PromptPresentation::Overflow { count: 5 }
        );
        // Even a weird over-cap active count collapses.
        assert_eq!(
            present_prompt(MAX_ACTIONABLE_NOTIFICATIONS + 2, 0),
            PromptPresentation::Overflow { count: 1 }
        );
    }

    #[test]
    fn overflow_body_counts_and_pluralizes() {
        assert_eq!(
            overflow_body(1),
            "1 more connection waiting — open Colony Firewall"
        );
        assert_eq!(
            overflow_body(4),
            "4 more connections waiting — open Colony Firewall"
        );
    }

    // --- capability fallback -------------------------------------------------

    #[test]
    fn actionable_mode_requires_the_actions_capability() {
        let caps = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(actions_supported(&caps(&[
            "body",
            "actions",
            "icon-static"
        ])));
        assert!(!actions_supported(&caps(&["body", "icon-static"])));
        assert!(!actions_supported(&caps(&[])));
        // Substrings must not count.
        assert!(!actions_supported(&caps(&["actions-icons"])));
    }
}
