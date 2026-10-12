//! The application state, its messages, and how it draws and subscribes.
//! How it reacts to a message is in [`update`].

mod update;

#[cfg(test)]
mod tests;

use cfc_client::{proto, Client};
use iced::keyboard;
use iced::widget::{button, column, container, row, Space};
use iced::{Element, Length, Subscription, Task};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

use crate::editor::{saved_rule_line, RuleEditor};
use crate::i18n::{t, t_fmt};
use crate::session_stats::SessionStats;
use crate::status_log::StatusLog;
use crate::theme::{sz, ui_text};
use crate::views::live::VerdictFilter;
use crate::views::rules::RuleSort;
use crate::{format, streams, theme, views};

const SOCKET_PATH: &str = "/run/colony-firewall/cfc.sock";
const LIVE_CAP: usize = 500;

/// Consecutive failed status polls before the daemon is declared gone. One
/// failure is a hiccup; two in a row (4s) is a dead socket.
const STATUS_FAILURES_BEFORE_DEAD: u32 = 2;

/// Refresh the rule list on every Nth status tick so hit counts stay live
/// without hammering the daemon (5 x 2s = every 10s).
const RULES_REFRESH_EVERY_TICKS: u32 = 5;

/// How long the Delete button stays armed waiting for the confirm click.
pub const DELETE_CONFIRM_MS: i64 = 3_000;

/// Cadence of the countdown tick while prompts are pending. Fast enough for
/// a smooth bar, slow enough to stay off the CPU when nothing is pending.
const DEADLINE_TICK_MS: u64 = 400;

/// How long a prompt's verdict controls stay disabled after the card
/// appears, how long the keyboard target stays disarmed after it changes,
/// and how long Pause stays disabled after a reconnect. A click or key press
/// already on its way when the layout changed (the window was raised, a card
/// arrived, the card above expired, Pause replaced Reconnect) must not land
/// on a control the user never saw.
const PROMPT_ARM_MS: i64 = 1_000;

pub struct App {
    pub socket_path: PathBuf,
    pub tab: Tab,
    pub daemon: DaemonState,
    pub rules: Vec<proto::RuleInfo>,
    pub live: VecDeque<proto::ConnectionEvent>,
    pub prompts: Vec<PromptCard>,
    /// The card the A/D keys answer and when they may: `(prompt_id,
    /// armed_at_ms)`. See [`App::sync_key_target`].
    pub key_target: Option<(String, i64)>,
    pub status: Option<proto::StatusResponse>,
    pub log: StatusLog,
    pub editor: Option<RuleEditor>,
    pub rules_filter: String,
    pub rules_sort: RuleSort,
    /// Rule id whose Delete button is armed, plus when it was armed.
    pub pending_delete: Option<(String, i64)>,
    pub live_filter: String,
    pub live_verdict: VerdictFilter,
    /// Snapshot rendered while the feed is paused. The buffer behind it
    /// keeps filling, so nothing is lost.
    pub live_frozen: Option<Vec<proto::ConnectionEvent>>,
    pub live_new: usize,
    pub session: SessionStats,
    /// Consecutive `StatusLoaded(Err)` since the last success.
    pub status_failures: u32,
    pub status_ticks: u32,
    /// Failed reconnect attempts, feeding the backoff.
    pub retry_attempts: u32,
    /// When Pause last took its header slot: a handshake (it replaces
    /// Reconnect) or enforcement resuming (it replaces Resume). Pause stays
    /// disabled for [`PROMPT_ARM_MS`] after it (see [`App::pause_armed`]).
    pub pause_shown_at_ms: i64,
    /// A pause or resume request is in flight, possibly waiting on the
    /// administrator password dialog. Pause and Resume stay disabled.
    pub pause_pending: bool,
    pub retry_at_ms: Option<i64>,
    /// Set when a gRPC stream drops; the badge shows "reconnecting" instead
    /// of the footer being rewritten every two seconds.
    pub stream_trouble: bool,
    /// Cached wall clock, refreshed on every tick so views stay pure.
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct PromptCard {
    /// `deadline_unix_ms` is the wall clock at which the daemon answers this
    /// prompt itself; 0 means it attached no deadline.
    pub event: proto::PromptEvent,
    /// Wall clock before which the verdict buttons stay disabled: a second
    /// after the card arrives, and again after it moves up.
    pub armed_at_ms: i64,
    /// A verdict for it is on its way to the daemon. The card stays until
    /// the daemon confirms, so a verdict that never arrived can be given
    /// again instead of leaving the flow to the timeout default.
    pub submitting: bool,
}

impl PromptCard {
    fn new(event: proto::PromptEvent, now_ms: i64) -> Self {
        Self {
            event,
            armed_at_ms: now_ms.saturating_add(PROMPT_ARM_MS),
            submitting: false,
        }
    }

    /// Whether its verdict controls accept input.
    pub fn armed(&self, now_ms: i64) -> bool {
        !self.submitting && now_ms >= self.armed_at_ms
    }
}

/// A verdict that did not do what the user asked.
#[derive(Debug, Clone)]
pub struct VerdictFailure {
    pub prompt_id: String,
    /// The daemon applied the answer and only the lasting rule failed. The
    /// prompt is gone then, so its card must not come back.
    pub applied: bool,
    pub message: String,
}

/// How loudly a newly arrived prompt announces itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attention {
    /// Leave the window and the tab alone; the sidebar badge counts it.
    None,
    /// Show the Prompts tab and pull the window in front of whatever the
    /// user is looking at.
    TabAndRaise,
}

/// Decides what the arrival of a prompt does to the window.
///
/// `pending_before` is the queue length *before* this prompt was pushed, so
/// only the 0 -> 1 transition switches the tab and raises. A burst of ten
/// prompts must not slam the window into the user's face ten times, and a
/// user who left the Prompts tab with prompts pending already knows about
/// them: switching the tab under their cursor again would turn the click
/// they were making on a rule row into a click on a verdict. A queue that
/// drains and then refills is a genuinely new interruption and may raise
/// again.
///
/// An open rule editor suppresses all of it. Focus-stealing is disruptive
/// at the best of times, and yanking the tab out from under someone
/// half-way through a form loses what they had typed.
pub fn prompt_attention(pending_before: usize, editor_open: bool) -> Attention {
    if editor_open || pending_before > 0 {
        Attention::None
    } else {
        Attention::TabAndRaise
    }
}

/// Brings the window forward so a prompt cannot be missed.
///
/// `gain_focus` is documented as a no-op on a minimized window, so the
/// un-minimize has to come first. `latest()` addresses the window this
/// single-window application actually owns rather than assuming an id.
fn raise_window() -> Task<Message> {
    iced::window::latest().and_then(|id| {
        Task::batch([
            iced::window::minimize(id, false),
            iced::window::gain_focus(id),
        ])
    })
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Prompts,
    Rules,
    Live,
    Stats,
}

#[derive(Debug, Clone)]
pub enum DaemonState {
    Connecting,
    Connected,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
    Reconnect,
    HandshakeDone(Result<HandshakeData, String>),
    RulesLoaded(Result<Vec<proto::RuleInfo>, String>),
    DeleteRule(String),
    RuleDeleted(Result<(String, bool), String>),
    StatusLoaded(Result<proto::StatusResponse, String>),
    StatusTick,
    /// Fast tick, alive only while prompts are pending.
    DeadlineTick,
    /// Slow tick, alive only while disconnected; drives the backoff retry.
    RetryTick,
    /// A gRPC subscription came (back) up. cfc-client reports this itself,
    /// so the badge no longer has to wait for the next event to recover.
    StreamConnected,
    LiveEvent(proto::ConnectionEvent),
    LiveStreamEnded(String),
    PromptEvent(proto::PromptEvent),
    PromptStreamEnded(String),
    /// "Customize this rule before creating it": opens the rule editor
    /// seeded from the prompt while leaving its verdict pending.
    CustomizePromptRule(String),
    SubmitVerdict {
        prompt_id: String,
        action: proto::Action,
        scope: Option<proto::RuleScope>,
        duration: proto::Duration,
    },
    VerdictSubmitted(Result<(String, bool, Option<String>), VerdictFailure>),
    OpenEditor,
    EditExistingRule(String),
    CloseEditor,
    ToggleRuleEnabled(String),
    RulesFilterChanged(String),
    RulesSortBy(RuleSort),
    LiveFilterChanged(String),
    LiveVerdictFilter(VerdictFilter),
    ToggleLivePause,
    /// Opens the rule editor pre-filled from an observed connection.
    MakeRuleFromEvent {
        exe: String,
        src_ip: String,
        dst_ip: String,
        dst_port: u32,
        protocol: i32,
        direction: i32,
    },
    CopyText(String),
    DismissLogEntry(usize),
    DismissAllLog,
    Key(KeyPress),
    TogglePaused,
    /// `(paused, resume_at_unix_ms)` as reported by the daemon.
    PausedSet(Result<(bool, i64), String>),
    EditorName(String),
    EditorAction(proto::Action),
    EditorDuration(proto::Duration),
    EditorExe(String),
    EditorDstHost(String),
    EditorDstNet(String),
    EditorDstPort(String),
    EditorProtocol(Option<proto::Protocol>),
    SaveRule,
    RuleSaved(Result<String, String>),
    PromptRuleSaved(Result<(String, bool, Option<String>), VerdictFailure>),
}

/// Raw key press forwarded from the subscription. The decision of what a
/// key means needs App state (newest prompt, editor open), so it is taken
/// in `update` rather than in the subscription closure.
#[derive(Debug, Clone)]
pub struct KeyPress {
    pub key: keyboard::Key,
    pub modifiers: keyboard::Modifiers,
}

#[derive(Debug, Clone)]
pub struct HandshakeData {
    pub status: proto::StatusResponse,
    pub rules: Vec<proto::RuleInfo>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Reconnect delay after `attempt` consecutive failures: 3s, 4s, then 5s
/// forever. Bounded so a daemon restart is picked up promptly.
pub fn backoff_secs(attempt: u32) -> i64 {
    (3 + i64::from(attempt)).min(5)
}

/// Control socket to connect to: `$CFC_SOCKET` when set, else the
/// packaged default. The CLI has `--socket` for the same reason - pointing
/// a client at a daemon running somewhere else (a `--dry-run` instance, a
/// test socket in a temp dir) shouldn't require a rebuild.
fn socket_path_from_env() -> PathBuf {
    match std::env::var_os("CFC_SOCKET") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(SOCKET_PATH),
    }
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let app = Self {
            socket_path: socket_path_from_env(),
            tab: Tab::Prompts,
            daemon: DaemonState::Connecting,
            rules: Vec::new(),
            live: VecDeque::with_capacity(LIVE_CAP),
            prompts: Vec::new(),
            key_target: None,
            status: None,
            log: StatusLog::default(),
            editor: None,
            rules_filter: String::new(),
            rules_sort: RuleSort::default(),
            pending_delete: None,
            live_filter: String::new(),
            live_verdict: VerdictFilter::All,
            live_frozen: None,
            live_new: 0,
            session: SessionStats::default(),
            status_failures: 0,
            status_ticks: 0,
            retry_attempts: 0,
            retry_at_ms: None,
            pause_shown_at_ms: 0,
            pause_pending: false,
            stream_trouble: false,
            now_ms: now_ms(),
        };
        let socket = app.socket_path.clone();
        (
            app,
            Task::perform(handshake(socket), Message::HandshakeDone),
        )
    }

    pub fn title(&self) -> String {
        "Colony Firewall Control".to_string()
    }

    fn connected(&self) -> bool {
        matches!(self.daemon, DaemonState::Connected)
    }

    /// Pause takes the place of Reconnect, at the right end of the header,
    /// as soon as a handshake lands, and the place of Resume as soon as
    /// enforcement resumes. The second click of a double-click on Reconnect
    /// or Resume would otherwise switch enforcement off with no
    /// confirmation.
    fn pause_armed(&self) -> bool {
        self.now_ms >= self.pause_shown_at_ms.saturating_add(PROMPT_ARM_MS)
    }

    fn connect_task(&mut self) -> Task<Message> {
        self.daemon = DaemonState::Connecting;
        self.retry_at_ms = None;
        let socket = self.socket_path.clone();
        Task::perform(handshake(socket), Message::HandshakeDone)
    }

    /// Moves to `Failed` and arms the backoff retry.
    ///
    /// The log line carries cfc-client's reason (missing socket, group
    /// permissions, stale socket) rather than a fixed string, and stays
    /// byte-identical across retries so the ring coalesces it into one
    /// counted entry instead of scrolling everything else away.
    fn mark_failed(&mut self, detail: String) {
        let was_connected = self.connected();
        let line = format::unreachable_log_line(&detail);
        self.daemon = DaemonState::Failed(detail);
        self.status_failures = 0;
        self.stream_trouble = false;
        let delay = backoff_secs(self.retry_attempts);
        self.retry_attempts = self.retry_attempts.saturating_add(1);
        self.retry_at_ms = Some(self.now_ms + delay * 1000);
        self.log.warn(line, self.now_ms);
        if was_connected {
            info!("lost connection to daemon");
        }
    }

    /// Per-tick maintenance that does not touch the network: expire log
    /// entries, expire the armed delete, and retire prompts the daemon has
    /// already answered on its own.
    fn housekeeping(&mut self) {
        self.log.prune(self.now_ms);

        if let Some((_, armed_at)) = &self.pending_delete {
            if self.now_ms.saturating_sub(*armed_at) > DELETE_CONFIRM_MS {
                self.pending_delete = None;
            }
        }

        let timeout_action = self
            .status
            .as_ref()
            .map(|s| s.timeout_action)
            .unwrap_or(proto::Action::Unspecified as i32);

        let now = self.now_ms;
        let mut expired: Vec<String> = Vec::new();
        self.retire_cards(|p| {
            if format::is_expired(p.event.deadline_unix_ms, now) {
                expired.push(prompt_label(&p.event));
                false
            } else {
                true
            }
        });
        self.detach_orphaned_editor();
        for label in expired {
            self.log.warn(
                t_fmt(
                    "log_prompt_expired",
                    &[
                        ("prompt", &label),
                        ("verdict", format::fallback_past(timeout_action)),
                    ],
                ),
                now,
            );
        }
        self.sync_key_target();
    }

    /// Points the keyboard at the top card and disarms it for
    /// [`PROMPT_ARM_MS`] whenever that card changes.
    ///
    /// The top card is the oldest one, first on screen and first to expire,
    /// and a new arrival never displaces it. Re-arming on every change means
    /// a key press already on its way when the card above expired or was
    /// answered does not land on the card that just moved up.
    fn sync_key_target(&mut self) {
        let top = self.key_target_card().map(|card| &card.event.prompt_id);
        if self.key_target.as_ref().map(|(id, _)| id) != top {
            self.key_target = top.map(|id| (id.clone(), self.now_ms.saturating_add(PROMPT_ARM_MS)));
        }
    }

    /// The top card that is not already being answered.
    fn key_target_card(&self) -> Option<&PromptCard> {
        self.prompts.iter().find(|card| !card.submitting)
    }

    /// Keeps a customization whose prompt is gone (expired, answered
    /// elsewhere, stream dropped) open as a plain new rule.
    ///
    /// It used to be closed, which threw away the rule the user was
    /// building and any error banner explaining why a save failed. Save now
    /// stores the rule with `UpsertRule`, since there is no prompt left to
    /// answer.
    fn detach_orphaned_editor(&mut self) {
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        if editor
            .prompt_id
            .as_ref()
            .is_some_and(|id| !self.prompts.iter().any(|card| &card.event.prompt_id == id))
        {
            editor.prompt_id = None;
            self.log.warn(t("log_customized_prompt_gone"), self.now_ms);
        }
    }

    /// Drops the cards `keep` rejects and disarms, for [`PROMPT_ARM_MS`],
    /// every card that moved up to take a dropped card's place.
    ///
    /// A card's buttons are otherwise armed from its arrival, so the second
    /// click of a double-click on one card, or a click on a card that
    /// expired under the cursor, landed on the button of the program below
    /// that just moved into the same spot.
    fn retire_cards(&mut self, mut keep: impl FnMut(&PromptCard) -> bool) {
        let rearm_at = self.now_ms.saturating_add(PROMPT_ARM_MS);
        let mut moved = false;
        self.prompts.retain_mut(|card| {
            if !keep(card) {
                moved = true;
                return false;
            }
            if moved {
                card.armed_at_ms = card.armed_at_ms.max(rearm_at);
            }
            true
        });
    }

    /// Settles the card a verdict was sent for: gone once the daemon has
    /// applied an answer, answerable again when nothing was applied.
    fn settle_card(&mut self, prompt_id: &str, applied: bool) {
        // The arming window below counts from now, not from the last tick.
        self.now_ms = now_ms();
        if applied {
            self.retire_cards(|card| card.event.prompt_id != prompt_id);
        } else if let Some(card) = self
            .prompts
            .iter_mut()
            .find(|card| card.event.prompt_id == prompt_id)
        {
            card.submitting = false;
        }
        self.sync_key_target();
    }

    pub fn view(&self) -> Element<'_, Message> {
        let paused = self.status.as_ref().map(|s| s.paused).unwrap_or(false);

        let sidebar = views::sidebar::view(self.tab, self.prompts.len());
        let header = self.header_bar(paused);
        let body: Element<'_, Message> = match self.tab {
            Tab::Prompts => views::prompts::view(
                &self.prompts,
                &self.rules,
                self.status.as_ref(),
                self.now_ms,
            ),
            Tab::Rules => views::rules::view(views::rules::ListArgs {
                rules: &self.rules,
                filter: &self.rules_filter,
                editor: self.editor.as_ref(),
                sort: self.rules_sort,
                pending_delete: self.pending_delete.as_ref(),
                now_ms: self.now_ms,
            }),
            Tab::Live => views::live::view(views::live::ListArgs {
                live: &self.live,
                frozen: self.live_frozen.as_deref(),
                filter: &self.live_filter,
                verdict: self.live_verdict,
                new_while_paused: self.live_new,
            }),
            Tab::Stats => views::stats::view(self.status.as_ref(), &self.session, self.now_ms),
        };

        let body_card = container(body)
            .padding(12)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(theme::card);

        let main_panel = column![
            header,
            self.connection_hint(),
            container(body_card).padding([10, 12]).height(Length::Fill),
            self.status_area(),
        ];

        row![sidebar, main_panel].into()
    }

    /// Why the connection failed, directly under the "disconnected" badge.
    ///
    /// cfc-client knows exactly what went wrong and how to fix it; the badge
    /// alone leaves a first-run user staring at red with no hint that the
    /// answer is usually group membership. Its own full-width line so the
    /// (long) advice wraps instead of squeezing the header row.
    fn connection_hint(&self) -> Element<'_, Message> {
        let DaemonState::Failed(detail) = &self.daemon else {
            return Space::new().into();
        };
        let hint = format::connection_hint(detail, format::CONNECTION_HINT_MAX);
        if hint.is_empty() {
            return Space::new().into();
        }
        container(ui_text(hint).size(sz(11)))
            .padding([6, 16])
            .width(Length::Fill)
            .style(theme::banner_err)
            .into()
    }

    /// The status ring: newest first, each line individually dismissable.
    fn status_area(&self) -> Element<'_, Message> {
        if self.log.is_empty() {
            return Space::new().into();
        }

        let mut lines: Vec<Element<'_, Message>> = Vec::with_capacity(self.log.len() + 1);
        for (i, entry) in self.log.iter().enumerate() {
            lines.push(
                row![
                    ui_text(format!(
                        "{} {} {}",
                        entry.severity.glyph(),
                        format::format_clock_ms(entry.at_ms),
                        entry.display()
                    ))
                    .size(sz(11)),
                    Space::new().width(Length::Fill),
                    button(ui_text("×").size(sz(11)))
                        .padding([0, 6])
                        .on_press(Message::DismissLogEntry(i))
                        .style(theme::subtle_icon),
                ]
                .spacing(6)
                .align_y(iced::Alignment::Center)
                .into(),
            );
        }
        if self.log.len() > 1 {
            lines.push(
                row![
                    Space::new().width(Length::Fill),
                    button(ui_text(t("log_dismiss_all")).size(sz(10)))
                        .padding([0, 6])
                        .on_press(Message::DismissAllLog)
                        .style(theme::subtle_icon),
                ]
                .into(),
            );
        }

        container(column(lines).spacing(2))
            .padding([6, 12])
            .width(Length::Fill)
            .style(theme::footer_bar)
            .into()
    }

    fn header_bar(&self, paused: bool) -> Element<'_, Message> {
        let (badge_key, badge_style): (&str, fn(&iced::Theme) -> iced::widget::container::Style) =
            match &self.daemon {
                DaemonState::Connecting => ("badge_connecting", theme::badge_warn),
                DaemonState::Connected => {
                    if paused {
                        ("badge_paused", theme::badge_warn)
                    } else if self.stream_trouble {
                        ("badge_reconnecting", theme::badge_warn)
                    } else {
                        ("badge_connected", theme::badge_ok)
                    }
                }
                DaemonState::Failed(_) => ("badge_disconnected", theme::badge_err),
            };

        let badge = container(ui_text(format!("● {}", t(badge_key))).size(sz(11)))
            .padding([3, 10])
            .style(badge_style);

        // Enforcement can be off while the socket is perfectly healthy;
        // that deserves its own badge, not a green "connected".
        let enforcing_badge: Element<'_, Message> = match &self.status {
            Some(s) if self.connected() && !s.enforcing => {
                container(ui_text(format!("⚠ {}", t("badge_not_enforcing"))).size(sz(11)))
                    .padding([3, 10])
                    .style(theme::badge_err)
                    .into()
            }
            _ => Space::new().into(),
        };

        let pause_btn: Element<'_, Message> = if self.connected() {
            if paused {
                button(ui_text(t("button_resume")).size(sz(12)))
                    .padding([4, 14])
                    .on_press_maybe((!self.pause_pending).then_some(Message::TogglePaused))
                    .style(iced::widget::button::primary)
                    .into()
            } else {
                button(ui_text(t("button_pause")).size(sz(12)))
                    .padding([4, 14])
                    .on_press_maybe(
                        (self.pause_armed() && !self.pause_pending)
                            .then_some(Message::TogglePaused),
                    )
                    .style(iced::widget::button::secondary)
                    .into()
            }
        } else {
            Space::new().into()
        };

        let reconnect: Element<'_, Message> = match &self.daemon {
            DaemonState::Failed(_) => {
                let label = match self
                    .retry_at_ms
                    .and_then(|at| format::remaining_secs(at, self.now_ms).filter(|s| *s > 0))
                {
                    Some(s) => t_fmt("button_reconnect_in", &[("secs", &s.to_string())]),
                    None => t("button_reconnect").to_string(),
                };
                button(ui_text(label).size(sz(12)))
                    .padding([4, 14])
                    .on_press(Message::Reconnect)
                    .style(iced::widget::button::primary)
                    .into()
            }
            _ => Space::new().into(),
        };

        let title_text = t(match self.tab {
            Tab::Prompts => "title_prompts",
            Tab::Rules => "tab_rules",
            Tab::Live => "title_live",
            Tab::Stats => "tab_stats",
        });

        let inner = row![
            ui_text(title_text).size(sz(18)),
            Space::new().width(Length::Fill),
            enforcing_badge,
            badge,
            pause_btn,
            reconnect,
        ]
        .spacing(12)
        .align_y(iced::Alignment::Center)
        .padding([12, 16]);

        container(inner)
            .width(Length::Fill)
            .style(theme::header_bar)
            .into()
    }

    pub fn theme(&self) -> iced::Theme {
        theme::iced_theme()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![keyboard::listen().filter_map(|event| match event {
            keyboard::Event::KeyPressed { key, modifiers, .. } => {
                Some(Message::Key(KeyPress { key, modifiers }))
            }
            _ => None,
        })];

        if self.connected() {
            subs.push(iced::time::every(Duration::from_secs(2)).map(|_| Message::StatusTick));
            // Countdown cadence, only while there is something to count down.
            if !self.prompts.is_empty() {
                subs.push(
                    iced::time::every(Duration::from_millis(DEADLINE_TICK_MS))
                        .map(|_| Message::DeadlineTick),
                );
            }
            subs.push(streams::live_subscription(self.socket_path.clone()));
            subs.push(streams::prompts_subscription(self.socket_path.clone()));
        } else {
            // Drives the backoff retry from both Connecting and Failed.
            subs.push(iced::time::every(Duration::from_secs(1)).map(|_| Message::RetryTick));
        }

        Subscription::batch(subs)
    }
}

/// Short "curl -> example.com:443" used in log lines about a prompt.
fn prompt_label(ev: &proto::PromptEvent) -> String {
    let proc = ev
        .process
        .as_ref()
        .map(cfc_client::convert::process_display)
        .unwrap_or_else(|| t("unknown").into());
    let dest = ev
        .connection
        .as_ref()
        .map(|c| {
            format!(
                "{}:{}",
                format::dest_key(&c.dst_host, &c.dst_ip),
                c.dst_port
            )
        })
        .unwrap_or_else(|| "?".into());
    format!("{proc} -> {dest}")
}

async fn handshake(path: PathBuf) -> Result<HandshakeData, String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    let status = client.status().await.map_err(|e| e.to_string())?;
    let rules = client.list_rules().await.map_err(|e| e.to_string())?;
    Ok(HandshakeData { status, rules })
}

async fn fetch_status(path: PathBuf) -> Result<proto::StatusResponse, String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    client.status().await.map_err(|e| e.to_string())
}

async fn delete_rule(path: PathBuf, id: String) -> Result<(String, bool), String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    let ok = client.delete_rule(&id).await.map_err(|e| e.to_string())?;
    Ok((id, ok))
}

/// Returns `(paused, resume_at_unix_ms)`. `duration_secs = 0` lets the
/// daemon apply its configured default and report the real deadline. The
/// daemon asks polkit first, so this may wait on a password dialog.
async fn set_paused(path: PathBuf, paused: bool) -> Result<(bool, i64), String> {
    let mut client = Client::connect_interactive(&path)
        .await
        .map_err(|e| e.to_string())?;
    let resp = client
        .set_paused(paused, 0)
        .await
        .map_err(|e| e.to_string())?;
    Ok((resp.paused, resp.resume_at_unix_ms))
}

async fn fetch_rules(path: PathBuf) -> Result<Vec<proto::RuleInfo>, String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    client.list_rules().await.map_err(|e| e.to_string())
}

/// Saves `rule` and returns the log line describing what was stored.
///
/// No executable validation here: the editor validates a path the user typed
/// or changed, and the enable toggle sends the stored path back unchanged,
/// which the daemon accepts as is. Checking it again refused to toggle a rule
/// whose target had since become an alias.
///
/// An Allow that names no program waits on an administrator password: the
/// daemon asks polkit first.
async fn upsert_rule(path: PathBuf, rule: proto::RuleInfo) -> Result<String, String> {
    let line = saved_rule_line(&rule);
    let mut client = Client::connect_interactive(&path)
        .await
        .map_err(|e| e.to_string())?;
    client.upsert_rule(rule).await.map_err(|e| e.to_string())?;
    Ok(line)
}

async fn submit_verdict(
    path: PathBuf,
    prompt_id: String,
    action: proto::Action,
    scope: Option<proto::RuleScope>,
    duration: proto::Duration,
    require_confirmed_rule: bool,
) -> Result<(String, bool, Option<String>), VerdictFailure> {
    let wanted_rule = scope.is_some();
    let fail = |applied: bool, message: String| VerdictFailure {
        prompt_id: prompt_id.clone(),
        applied,
        message,
    };
    // A customized rule may be an Allow for every program, which waits on an
    // administrator password before it is stored.
    let connected = if require_confirmed_rule {
        Client::connect_interactive(&path).await
    } else {
        Client::connect(&path).await
    };
    let mut client = connected.map_err(|e| fail(false, e.to_string()))?;
    let outcome = client
        .submit_verdict(&prompt_id, action, duration, scope)
        .await
        .map_err(|e| fail(false, e.to_string()))?;
    // A verdict that applied but saved no rule is not a success to report
    // quietly: the user asked for a lasting answer, did not get one, and will
    // be prompted again by the next connection from the same program.
    if outcome.accepted && wanted_rule && outcome.rule_persisted == Some(false) {
        return Err(fail(
            true,
            outcome
                .persist_error
                .unwrap_or_else(|| t("error_no_lasting_rule").to_string()),
        ));
    }
    if outcome.accepted && require_confirmed_rule && outcome.rule_persisted != Some(true) {
        return Err(fail(true, t("error_rule_unconfirmed").into()));
    }
    Ok((prompt_id, outcome.accepted, outcome.persist_note))
}
