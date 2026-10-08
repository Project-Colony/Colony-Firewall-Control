//! Colony Firewall Control - UI entry point.

mod format;
mod session_stats;
mod status_log;
mod streams;
mod theme;
mod views;

use cfc_client::{proto, Client};
use iced::keyboard;
use iced::widget::{button, column, container, row, text, Space};
use iced::{Element, Length, Subscription, Task};
use session_stats::SessionStats;
use status_log::StatusLog;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;
use views::live::VerdictFilter;
use views::prompts::PromptAction;
use views::rules::RuleSort;

const SOCKET_PATH: &str = "/run/colony-firewall/cfc.sock";
const LIVE_CAP: usize = 500;

/// Consecutive failed status polls before the daemon is declared gone. One
/// failure is a hiccup; two in a row (4s) is a dead socket.
const STATUS_FAILURES_BEFORE_DEAD: u32 = 2;

/// Refresh the rule list on every Nth status tick so hit counts stay live
/// without hammering the daemon (5 x 2s = every 10s).
const RULES_REFRESH_EVERY_TICKS: u32 = 5;

/// How long the Delete button stays armed waiting for the confirm click.
const DELETE_CONFIRM_MS: i64 = 3_000;

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

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,cfc_ui=info")),
        )
        .init();

    iced::application(App::new, App::update, App::view)
        .title(App::title)
        .theme(App::theme)
        .subscription(App::subscription)
        .run()
}

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
    pub retry_at_ms: Option<i64>,
    /// Set when a gRPC stream drops; the badge shows "reconnecting" instead
    /// of the footer being rewritten every two seconds.
    pub stream_trouble: bool,
    /// Cached wall clock, refreshed on every tick so views stay pure.
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct RuleEditor {
    /// Some when editing an existing rule, None when creating a new one.
    pub editing_id: Option<String>,
    pub prompt_id: Option<String>,
    pub prompt_hash_required: bool,
    pub duration_seconds: u32,
    pub name: String,
    pub action: proto::Action,
    pub duration: proto::Duration,
    pub exe: String,
    pub dst_host: String,
    pub dst_net: String,
    pub dst_port: String,
    pub protocol: Option<proto::Protocol>,
    pub validation: Option<String>,
    /// Metadata of the rule being edited, carried through untouched.
    ///
    /// `UpsertRule` overwrites the stored row wholesale, so emitting zeroes
    /// here would reset the creation date to now, drop the hit count and
    /// silently re-enable a rule the user had turned off. A brand-new rule
    /// keeps the defaults below and lets the daemon fill them in.
    pub created_at_unix_ms: i64,
    pub hit_count: u64,
    pub enabled: bool,
    /// The edited rule's scope, so the predicates this editor has no widget
    /// for are carried through untouched.
    ///
    /// `cfc rules add --uid`, an imported opensnitch ruleset, or a
    /// checksum-pinned rule can all set these. Rebuilding the scope from
    /// the visible fields alone would silently *widen* such a rule on
    /// save: a deny scoped to one uid would start matching every user,
    /// a sha256-pinned allow would lose its binary pin, and an inbound rule
    /// (unset direction means outbound) would turn outbound with its source
    /// scope gone. Its visible fields are stale once the form is edited, so
    /// only [`hidden_scope_is_set`], [`hidden_scope_summary`] and the
    /// unchanged-path check read it, and saving overwrites them from the form.
    pub carried_scope: proto::RuleScope,
}

/// True when `scope` carries a constraint the editor cannot show, so the view
/// can tell the user rather than let them assume the visible fields are the
/// whole rule.
pub fn hidden_scope_is_set(scope: &proto::RuleScope) -> bool {
    scope.has_uid
        || !scope.exe_sha256.is_empty()
        || !scope.parent_exe.is_empty()
        || scope.has_direction
        || !scope.src_net.is_empty()
        || scope.has_src_port
}

/// One-line human summary of the hidden predicates, for that notice.
pub fn hidden_scope_summary(scope: &proto::RuleScope) -> String {
    let mut parts = Vec::new();
    if scope.has_direction {
        parts.push(
            match proto::Direction::try_from(scope.direction) {
                Ok(proto::Direction::Inbound) => "inbound",
                Ok(proto::Direction::Outbound) => "outbound",
                _ => "direction ?",
            }
            .to_string(),
        );
    }
    if !scope.src_net.is_empty() {
        parts.push(format!("from {}", scope.src_net));
    }
    if scope.has_src_port {
        parts.push(format!("src port {}", scope.src_port));
    }
    if scope.has_uid {
        parts.push(format!("uid {}", scope.uid));
    }
    if !scope.parent_exe.is_empty() {
        parts.push(format!("parent {}", scope.parent_exe));
    }
    if !scope.exe_sha256.is_empty() {
        let short: String = scope.exe_sha256.chars().take(12).collect();
        parts.push(format!("sha256 {short}..."));
    }
    parts.join(", ")
}

impl Default for RuleEditor {
    fn default() -> Self {
        Self {
            editing_id: None,
            prompt_id: None,
            prompt_hash_required: false,
            duration_seconds: 0,
            name: String::new(),
            action: proto::Action::Allow,
            duration: proto::Duration::Always,
            exe: String::new(),
            dst_host: String::new(),
            dst_net: String::new(),
            dst_port: String::new(),
            protocol: None,
            validation: None,
            created_at_unix_ms: 0,
            hit_count: 0,
            enabled: true,
            carried_scope: proto::RuleScope::default(),
        }
    }
}

impl RuleEditor {
    pub fn from_existing(rule: &proto::RuleInfo) -> Self {
        let scope = rule.scope.as_ref();
        let protocol = scope
            .and_then(|s| s.has_protocol.then_some(s.protocol))
            .and_then(|p| proto::Protocol::try_from(p).ok())
            .filter(|p| !matches!(p, proto::Protocol::Unspecified));
        Self {
            editing_id: Some(rule.id.clone()),
            prompt_id: None,
            prompt_hash_required: false,
            duration_seconds: rule.duration_seconds,
            name: rule.name.clone(),
            action: proto::Action::try_from(rule.action).unwrap_or(proto::Action::Allow),
            duration: proto::Duration::try_from(rule.duration).unwrap_or(proto::Duration::Always),
            exe: scope.map(|s| s.exe_path.clone()).unwrap_or_default(),
            dst_host: scope.map(|s| s.dst_host.clone()).unwrap_or_default(),
            dst_net: scope.map(|s| s.dst_net.clone()).unwrap_or_default(),
            dst_port: scope
                .and_then(|s| s.has_dst_port.then_some(s.dst_port))
                .map(|p| p.to_string())
                .unwrap_or_default(),
            protocol,
            validation: None,
            created_at_unix_ms: rule.created_at_unix_ms,
            hit_count: rule.hit_count,
            enabled: rule.enabled,
            carried_scope: scope.cloned().unwrap_or_default(),
        }
    }

    /// Seeds the editor from a pending prompt ("Customize this rule before
    /// creating it").
    ///
    /// The connection remains pending until Save submits an explicit verdict,
    /// or the daemon applies its timeout policy. In that second case the
    /// editor stays open as a new rule (see `App::detach_orphaned_editor`).
    pub fn from_prompt(ev: &proto::PromptEvent) -> Self {
        let exe = ev
            .process
            .as_ref()
            .map(|p| p.exe.as_str())
            .unwrap_or_default();
        let (src_ip, dst_ip, dst_port, protocol, direction) = match ev.connection.as_ref() {
            Some(c) => (
                c.src_ip.as_str(),
                c.dst_ip.as_str(),
                c.dst_port,
                c.protocol,
                c.direction,
            ),
            None => ("", "", 0, 0, 0),
        };
        let mut editor = Self::from_observed(exe, src_ip, dst_ip, dst_port, protocol, direction);
        editor.prompt_id = Some(ev.prompt_id.clone());
        editor.prompt_hash_required = ev.binds_to_hash;
        if ev.binds_to_hash {
            editor.carried_scope.exe_sha256 = ev
                .process
                .as_ref()
                .map(|p| p.sha256.clone())
                .unwrap_or_default();
        }
        editor
    }

    /// Seeds the editor from an observed flow (live feed "make rule", and
    /// a prompt's "Customize").
    ///
    /// When the executable can scope a rule, the seed is that program on
    /// that port and protocol, the same scope `cfc rules add --exe
    /// --dst-port --protocol` builds. Pinning the one address seen made a
    /// rule the next connection of the same service, to another CDN address
    /// or over IPv6, did not match, so the app stayed denied after "make
    /// rule" while the CLI rule worked (#46). The user can still type an
    /// address into the destination field.
    ///
    /// Otherwise the placeholder for an unidentified process is never
    /// seeded, since a rule on it is refused, and the numeric endpoint is
    /// pinned instead so the rule does not cover the whole port. DNS names
    /// stay diagnostic.
    ///
    /// An inbound flow keeps its direction (without it the rule would be an
    /// outbound one to our own address) and pins the one peer seen as its
    /// source. Inbound, the destination is this machine, which the daemon
    /// refuses as a scope, and the editor has no source field: a seed on our
    /// own address could not be saved, and clearing it opened the port to
    /// every peer.
    pub fn from_observed(
        exe: &str,
        src_ip: &str,
        dst_ip: &str,
        dst_port: u32,
        protocol: i32,
        direction: i32,
    ) -> Self {
        let protocol = proto::Protocol::try_from(protocol)
            .ok()
            .filter(|p| !matches!(p, proto::Protocol::Unspecified));
        let inbound = direction == proto::Direction::Inbound as i32;
        // Inbound flows are never attributed to a program.
        let scopable = !inbound && cfc_client::convert::exe_is_rule_scopable(exe);
        Self {
            name: String::new(),
            exe: if scopable {
                exe.to_string()
            } else {
                String::new()
            },
            dst_host: String::new(),
            dst_net: if scopable || inbound {
                String::new()
            } else {
                format::host_cidr(dst_ip)
            },
            dst_port: if dst_port == 0 {
                String::new()
            } else {
                dst_port.to_string()
            },
            protocol,
            carried_scope: proto::RuleScope {
                direction: if inbound { direction } else { 0 },
                has_direction: inbound,
                src_net: if inbound {
                    format::host_cidr(src_ip)
                } else {
                    String::new()
                },
                ..Default::default()
            },
            ..Self::default()
        }
    }
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
/// packaged default. The CLI has `--socket` for the same reason — pointing
/// a client at a daemon running somewhere else (a `--dry-run` instance, a
/// test socket in a temp dir) shouldn't require a rebuild.
fn socket_path_from_env() -> PathBuf {
    match std::env::var_os("CFC_SOCKET") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(SOCKET_PATH),
    }
}

impl App {
    fn new() -> (Self, Task<Message>) {
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
            stream_trouble: false,
            now_ms: now_ms(),
        };
        let socket = app.socket_path.clone();
        (
            app,
            Task::perform(handshake(socket), Message::HandshakeDone),
        )
    }

    fn title(&self) -> String {
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
                format!(
                    "{label}: prompt expired -> {} by default",
                    format::fallback_past(timeout_action)
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
            self.log.warn(
                "the prompt being customized is gone; Save now stores a new rule",
                self.now_ms,
            );
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

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::TabSelected(t) => {
                self.tab = t;
                Task::none()
            }
            Message::Reconnect => {
                self.retry_attempts = 0;
                self.connect_task()
            }
            Message::HandshakeDone(Ok(data)) => {
                self.now_ms = now_ms();
                self.pause_shown_at_ms = self.now_ms;
                self.daemon = DaemonState::Connected;
                self.status = Some(data.status);
                self.rules = data.rules;
                self.status_failures = 0;
                self.retry_attempts = 0;
                self.retry_at_ms = None;
                self.stream_trouble = false;
                self.log.prune(self.now_ms);
                info!("connected to daemon");
                Task::none()
            }
            Message::HandshakeDone(Err(e)) => {
                self.mark_failed(e);
                Task::none()
            }
            Message::RulesLoaded(Ok(rules)) => {
                self.rules = rules;
                Task::none()
            }
            Message::RulesLoaded(Err(e)) => {
                self.log
                    .warn(format!("listing rules failed: {e}"), self.now_ms);
                Task::none()
            }
            Message::DeleteRule(id) => {
                // Two-step: the first click arms, the second (within
                // DELETE_CONFIRM_MS) actually deletes.
                let armed = self.pending_delete.as_ref().is_some_and(|(pending, at)| {
                    *pending == id && self.now_ms.saturating_sub(*at) <= DELETE_CONFIRM_MS
                });
                if !armed {
                    self.pending_delete = Some((id, self.now_ms));
                    return Task::none();
                }
                self.pending_delete = None;
                let socket = self.socket_path.clone();
                Task::perform(delete_rule(socket, id), Message::RuleDeleted)
            }
            Message::RuleDeleted(Ok((id, true))) => {
                self.rules.retain(|r| r.id != id);
                self.log.info("rule deleted", self.now_ms);
                Task::none()
            }
            Message::RuleDeleted(Ok((_, false))) => {
                self.log
                    .warn("rule was already gone on the daemon", self.now_ms);
                Task::none()
            }
            Message::RuleDeleted(Err(e)) => {
                self.log.error(format!("delete failed: {e}"), self.now_ms);
                Task::none()
            }
            Message::StatusLoaded(Ok(s)) => {
                // A timed pause ran out, or another client resumed.
                if self.status.as_ref().is_some_and(|old| old.paused) && !s.paused {
                    self.pause_shown_at_ms = self.now_ms;
                }
                self.status = Some(s);
                self.status_failures = 0;
                self.stream_trouble = false;
                Task::none()
            }
            Message::StatusLoaded(Err(e)) => {
                // A single miss is a hiccup; two in a row means the daemon
                // is gone and the "connected" badge would be a lie.
                self.status_failures = self.status_failures.saturating_add(1);
                if self.status_failures >= STATUS_FAILURES_BEFORE_DEAD {
                    self.mark_failed(e);
                }
                Task::none()
            }
            Message::StatusTick => {
                self.now_ms = now_ms();
                self.housekeeping();
                if !self.connected() {
                    return Task::none();
                }
                self.status_ticks = self.status_ticks.wrapping_add(1);
                let mut tasks = vec![Task::perform(
                    fetch_status(self.socket_path.clone()),
                    Message::StatusLoaded,
                )];
                if self.status_ticks.is_multiple_of(RULES_REFRESH_EVERY_TICKS) {
                    tasks.push(Task::perform(
                        fetch_rules(self.socket_path.clone()),
                        Message::RulesLoaded,
                    ));
                }
                Task::batch(tasks)
            }
            Message::DeadlineTick => {
                self.now_ms = now_ms();
                self.housekeeping();
                Task::none()
            }
            Message::RetryTick => {
                self.now_ms = now_ms();
                self.housekeeping();
                match self.retry_at_ms {
                    Some(at) if self.now_ms >= at => self.connect_task(),
                    _ => Task::none(),
                }
            }
            Message::StreamConnected => {
                self.stream_trouble = false;
                Task::none()
            }
            Message::LiveEvent(ev) => {
                self.stream_trouble = false;
                self.session.record(&ev);
                self.live.push_front(ev);
                while self.live.len() > LIVE_CAP {
                    self.live.pop_back();
                }
                if self.live_frozen.is_some() {
                    self.live_new = self.live_new.saturating_add(1);
                }
                Task::none()
            }
            Message::LiveStreamEnded(e) => {
                // cfc-client reconnects on its own with a capped backoff;
                // surface it once as connection state, not as footer spam.
                self.stream_trouble = true;
                info!("live stream interrupted: {e}");
                Task::none()
            }
            Message::PromptEvent(ev) => {
                // No desktop notification here: the tray owns prompt
                // notifications now - two bubbles per prompt would train
                // users to ignore them. The GUI shows its card either way.
                self.stream_trouble = false;
                // The arming deadline is measured from now, not from the
                // last tick, which can be two seconds old.
                self.now_ms = now_ms();
                // A prompt is a held-open connection with a deadline on it;
                // a card the user only sees if they happen to be looking at
                // the right tab is not an ask, it is a countdown they lose.
                let attention = prompt_attention(self.prompts.len(), self.editor.is_some());
                self.prompts.push(PromptCard::new(ev, self.now_ms));
                self.sync_key_target();
                match attention {
                    Attention::None => Task::none(),
                    Attention::TabAndRaise => {
                        self.tab = Tab::Prompts;
                        raise_window()
                    }
                }
            }
            Message::PromptStreamEnded(e) => {
                self.stream_trouble = true;
                self.prompts.clear();
                self.detach_orphaned_editor();
                info!("prompt stream interrupted: {e}");
                Task::none()
            }
            Message::CustomizePromptRule(prompt_id) => {
                let Some(card) = self.prompts.iter().find(|p| p.event.prompt_id == prompt_id)
                else {
                    return Task::none();
                };
                self.editor = Some(RuleEditor::from_prompt(&card.event));
                self.tab = Tab::Rules;
                Task::none()
            }
            Message::SubmitVerdict {
                prompt_id,
                action,
                scope,
                duration,
            } => {
                // One verdict per card at a time. The card stays, disabled,
                // until the daemon confirms (see `settle_card`).
                let Some(card) = self
                    .prompts
                    .iter_mut()
                    .find(|p| p.event.prompt_id == prompt_id && !p.submitting)
                else {
                    return Task::none();
                };
                card.submitting = true;
                self.sync_key_target();
                let socket = self.socket_path.clone();
                Task::perform(
                    submit_verdict(socket, prompt_id, action, scope, duration, false),
                    Message::VerdictSubmitted,
                )
            }
            Message::VerdictSubmitted(Ok((prompt_id, true, note))) => {
                self.settle_card(&prompt_id, true);
                // The daemon telling the user something true about the rule
                // it stored - today, that a user-writable binary was
                // hash-bound and a swapped file will prompt again. Shown in
                // the log line the verdict already earns; silence would
                // leave "always" quietly meaning less than it reads.
                if let Some(note) = note {
                    self.log.info(note, self.now_ms);
                }
                // A verdict may have persisted a rule; refresh so the Rules
                // tab shows it now rather than after some unrelated action.
                let socket = self.socket_path.clone();
                Task::perform(fetch_rules(socket), Message::RulesLoaded)
            }
            Message::VerdictSubmitted(Ok((prompt_id, false, _))) => {
                self.settle_card(&prompt_id, true);
                // The daemon had already answered this prompt itself. The
                // old code swallowed this, so the user believed they had
                // allowed something the timeout had actually decided.
                self.log.error(
                    "prompt already expired - the daemon answered it",
                    self.now_ms,
                );
                Task::none()
            }
            Message::VerdictSubmitted(Err(failure)) => {
                self.settle_card(&failure.prompt_id, failure.applied);
                let still = if failure.applied {
                    ""
                } else {
                    " - the prompt is still waiting for an answer"
                };
                self.log.error(
                    format!("verdict failed: {}{still}", failure.message),
                    self.now_ms,
                );
                Task::none()
            }
            Message::OpenEditor => {
                self.editor = Some(RuleEditor::default());
                Task::none()
            }
            Message::EditExistingRule(id) => {
                if let Some(rule) = self.rules.iter().find(|r| r.id == id) {
                    self.editor = Some(RuleEditor::from_existing(rule));
                }
                Task::none()
            }
            Message::CloseEditor => {
                self.editor = None;
                Task::none()
            }
            Message::ToggleRuleEnabled(id) => {
                let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) else {
                    return Task::none();
                };
                let updated = toggled_rule(rule);
                // Optimistic: the row flips now, the next RulesLoaded (or
                // the RuleSaved error path) re-reads the daemon's truth.
                rule.enabled = updated.enabled;
                let socket = self.socket_path.clone();
                Task::perform(upsert_rule(socket, updated), Message::RuleSaved)
            }
            Message::RulesFilterChanged(s) => {
                self.rules_filter = s;
                Task::none()
            }
            Message::RulesSortBy(sort) => {
                self.rules_sort = sort;
                Task::none()
            }
            Message::LiveFilterChanged(s) => {
                self.live_filter = s;
                Task::none()
            }
            Message::LiveVerdictFilter(v) => {
                self.live_verdict = v;
                Task::none()
            }
            Message::ToggleLivePause => {
                if self.live_frozen.is_some() {
                    self.live_frozen = None;
                    self.live_new = 0;
                } else {
                    self.live_frozen = Some(self.live.iter().cloned().collect());
                    self.live_new = 0;
                }
                Task::none()
            }
            Message::MakeRuleFromEvent {
                exe,
                src_ip,
                dst_ip,
                dst_port,
                protocol,
                direction,
            } => {
                self.editor = Some(RuleEditor::from_observed(
                    &exe, &src_ip, &dst_ip, dst_port, protocol, direction,
                ));
                self.tab = Tab::Rules;
                Task::none()
            }
            Message::CopyText(s) => iced::clipboard::write(s),
            Message::DismissLogEntry(i) => {
                self.log.dismiss(i);
                Task::none()
            }
            Message::DismissAllLog => {
                self.log.clear();
                Task::none()
            }
            Message::Key(kp) => {
                self.now_ms = now_ms();
                self.handle_key(kp)
            }
            Message::TogglePaused => {
                let current = self.status.as_ref().map(|s| s.paused).unwrap_or(false);
                if !current && !self.pause_armed() {
                    return Task::none();
                }
                let socket = self.socket_path.clone();
                Task::perform(set_paused(socket, !current), Message::PausedSet)
            }
            Message::PausedSet(Ok((paused, resume_at_unix_ms))) => {
                if !paused {
                    self.now_ms = now_ms();
                    self.pause_shown_at_ms = self.now_ms;
                }
                if let Some(s) = &mut self.status {
                    s.paused = paused;
                    s.resume_at_unix_ms = resume_at_unix_ms;
                }
                if paused {
                    self.log.warn(
                        format!(
                            "enforcement paused - {}",
                            format::format_resume_in(resume_at_unix_ms, self.now_ms)
                        ),
                        self.now_ms,
                    );
                } else {
                    self.log.info("enforcement resumed", self.now_ms);
                }
                Task::none()
            }
            Message::PausedSet(Err(e)) => {
                self.log.error(format!("pause failed: {e}"), self.now_ms);
                Task::none()
            }
            Message::EditorName(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.name = s;
                }
                Task::none()
            }
            Message::EditorAction(a) => {
                if let Some(ed) = &mut self.editor {
                    ed.action = a;
                }
                Task::none()
            }
            Message::EditorDuration(d) => {
                if let Some(ed) = &mut self.editor {
                    ed.duration = d;
                    if d != proto::Duration::Seconds {
                        ed.duration_seconds = 0;
                    }
                }
                Task::none()
            }
            Message::EditorExe(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.exe = s;
                }
                Task::none()
            }
            Message::EditorDstHost(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_host = s;
                }
                Task::none()
            }
            Message::EditorDstNet(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_net = s;
                }
                Task::none()
            }
            Message::EditorDstPort(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_port = s;
                }
                Task::none()
            }
            Message::EditorProtocol(p) => {
                if let Some(ed) = &mut self.editor {
                    ed.protocol = p;
                }
                Task::none()
            }
            Message::SaveRule => {
                // The prompt may have expired since the last tick.
                self.detach_orphaned_editor();
                let Some(editor) = &mut self.editor else {
                    return Task::none();
                };
                match build_rule_from_editor(editor) {
                    Ok(rule) => {
                        editor.validation = None;
                        let socket = self.socket_path.clone();
                        if let Some(prompt_id) = editor.prompt_id.clone() {
                            let action = editor.action;
                            let duration = editor.duration;
                            let scope = rule.scope;
                            // Held, not dropped, until the daemon answers:
                            // a dropped card closed this editor on the next
                            // tick and took a failed save's banner with it.
                            let Some(card) = self
                                .prompts
                                .iter_mut()
                                .find(|c| c.event.prompt_id == prompt_id && !c.submitting)
                            else {
                                return Task::none();
                            };
                            card.submitting = true;
                            self.sync_key_target();
                            Task::perform(
                                submit_verdict(socket, prompt_id, action, scope, duration, true),
                                Message::PromptRuleSaved,
                            )
                        } else {
                            Task::perform(upsert_rule(socket, rule), Message::RuleSaved)
                        }
                    }
                    Err(e) => {
                        // Also in the footer: the banner sits at the bottom
                        // of the form and can be below the fold, which made
                        // Save look like it did nothing.
                        self.log
                            .error(format!("saving rule failed: {e}"), self.now_ms);
                        editor.validation = Some(e);
                        Task::none()
                    }
                }
            }
            Message::PromptRuleSaved(Ok((id, true, note))) => {
                self.editor = None;
                self.update(Message::VerdictSubmitted(Ok((id, true, note))))
            }
            Message::PromptRuleSaved(Ok((id, false, _))) => {
                self.editor = None;
                self.update(Message::VerdictSubmitted(Ok((id, false, None))))
            }
            Message::PromptRuleSaved(Err(failure)) => {
                // The editor stays open with the error. If the answer was
                // applied the card is gone, and the editor then turns into a
                // plain new rule the user can save again.
                self.settle_card(&failure.prompt_id, failure.applied);
                self.detach_orphaned_editor();
                self.update(Message::RuleSaved(Err(failure.message)))
            }
            Message::RuleSaved(Ok(line)) => {
                // Say what was stored: closing the editor in silence read
                // as accepted whatever scope the rule ended up with.
                self.log.info(line, self.now_ms);
                self.editor = None;
                let socket = self.socket_path.clone();
                Task::perform(fetch_rules(socket), Message::RulesLoaded)
            }
            Message::RuleSaved(Err(e)) => {
                if let Some(ed) = &mut self.editor {
                    ed.validation = Some(e.clone());
                }
                self.log
                    .error(format!("saving rule failed: {e}"), self.now_ms);
                // The optimistic enable/disable toggle may now disagree
                // with the daemon; re-read the truth.
                let socket = self.socket_path.clone();
                Task::perform(fetch_rules(socket), Message::RulesLoaded)
            }
        }
    }

    /// Keyboard shortcuts. The subscription only delivers key presses no
    /// widget consumed, so a focused text input still swallows its own
    /// typing.
    fn handle_key(&mut self, kp: KeyPress) -> Task<Message> {
        use keyboard::key::Named;

        // While the editor is open only Esc/Enter apply - everything else
        // would fire under the user's fingers mid-form.
        if self.editor.is_some() {
            return match kp.key {
                keyboard::Key::Named(Named::Escape) => self.update(Message::CloseEditor),
                keyboard::Key::Named(Named::Enter) => self.update(Message::SaveRule),
                _ => Task::none(),
            };
        }

        match kp.key {
            keyboard::Key::Named(Named::Escape) => {
                // Nothing to close: clear whatever is nagging in the footer.
                self.pending_delete = None;
                self.log.clear();
                Task::none()
            }
            keyboard::Key::Character(ref c) => {
                // Only bare keys and Shift are ours. Ctrl+A is "select all"
                // out of habit, and Alt and Super chords belong to the
                // desktop; none of them may answer a prompt.
                if kp.modifiers.control() || kp.modifiers.alt() || kp.modifiers.logo() {
                    return Task::none();
                }
                let shift = kp.modifiers.shift();
                let on_prompts = self.tab == Tab::Prompts;
                match c.to_lowercase().as_str() {
                    // The verdict keys only work where the card they answer
                    // is on screen.
                    "a" if on_prompts => self.answer_key_target(if shift {
                        PromptAction::AllowProgram
                    } else {
                        PromptAction::AllowOnce
                    }),
                    "d" if on_prompts => self.answer_key_target(if shift {
                        PromptAction::BlockProgram
                    } else {
                        PromptAction::BlockOnce
                    }),
                    "1" => self.update(Message::TabSelected(Tab::Prompts)),
                    "2" => self.update(Message::TabSelected(Tab::Rules)),
                    "3" => self.update(Message::TabSelected(Tab::Live)),
                    "4" => self.update(Message::TabSelected(Tab::Stats)),
                    _ => Task::none(),
                }
            }
            _ => Task::none(),
        }
    }

    /// Answers the top card, the one marked as the keyboard target, with
    /// the same verdict the matching button would submit. Does nothing while
    /// the target is disarmed (see [`App::sync_key_target`]).
    ///
    /// It used to answer the newest prompt, which is the bottom card and
    /// often below the fold: the user read the card at the top, pressed
    /// Shift+A, and wrote an always-allow rule for a program they never saw.
    ///
    /// A program-scoped choice on a flow with no executable path has no
    /// honest verdict (see `verdict_for`), so it degrades to the one-off
    /// answer of the same action rather than doing nothing: the user
    /// pressed Shift+D to stop a connection, and stopping it is the part
    /// that matters.
    fn answer_key_target(&mut self, choice: PromptAction) -> Task<Message> {
        self.sync_key_target();
        if !self
            .key_target
            .as_ref()
            .is_some_and(|(_, armed_at)| self.now_ms >= *armed_at)
        {
            return Task::none();
        }
        let Some(card) = self.key_target_card() else {
            return Task::none();
        };
        let ev = &card.event;
        let fallback = match choice {
            PromptAction::AllowProgram | PromptAction::AllowOnce => PromptAction::AllowOnce,
            PromptAction::BlockProgram | PromptAction::BlockOnce => PromptAction::BlockOnce,
        };
        let Some(verdict) = views::prompts::verdict_for(choice, ev)
            .or_else(|| views::prompts::verdict_for(fallback, ev))
        else {
            return Task::none();
        };
        let prompt_id = ev.prompt_id.clone();
        self.update(Message::SubmitVerdict {
            prompt_id,
            action: verdict.action,
            scope: verdict.scope,
            duration: verdict.duration,
        })
    }

    fn view(&self) -> Element<'_, Message> {
        let paused = self.status.as_ref().map(|s| s.paused).unwrap_or(false);

        let sidebar = self.sidebar();
        let header = self.header_bar(paused);
        let body: Element<'_, Message> = match self.tab {
            Tab::Prompts => views::prompts::view(&self.prompts, self.status.as_ref(), self.now_ms),
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
        container(text(hint).size(11))
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
                    text(format!(
                        "{} {} {}",
                        entry.severity.glyph(),
                        format::format_clock_ms(entry.at_ms),
                        entry.display()
                    ))
                    .size(11),
                    Space::new().width(Length::Fill),
                    button(text("×").size(11))
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
                    button(text("dismiss all").size(10))
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

    fn sidebar(&self) -> Element<'_, Message> {
        let title_block = column![text("Colony").size(20), text("Firewall Control").size(14),]
            .spacing(2)
            .padding([18, 16]);

        let nav = column![
            nav_item("Prompts", Tab::Prompts, self.tab, self.prompts.len()),
            nav_item("Rules", Tab::Rules, self.tab, 0),
            nav_item("Live", Tab::Live, self.tab, 0),
            nav_item("Stats", Tab::Stats, self.tab, 0),
        ]
        .spacing(0);

        let hints = column![
            text("1-4  switch tab").size(9),
            text("Keys answer the top prompt:").size(9),
            text("A  allow once").size(9),
            text("D  block for now").size(9),
            text("Shift+A  always allow program").size(9),
            text("Shift+D  always block program").size(9),
        ]
        .spacing(1)
        .padding([6, 16]);

        let inner = column![
            title_block,
            divider(),
            nav,
            Space::new().height(Length::Fill),
            hints,
            container(text(format!("v{}", env!("CARGO_PKG_VERSION"))).size(10)).padding([6, 16]),
        ]
        .height(Length::Fill);

        container(inner)
            .width(Length::Fixed(190.0))
            .height(Length::Fill)
            .style(theme::sidebar_bg)
            .into()
    }

    fn header_bar(&self, paused: bool) -> Element<'_, Message> {
        let (badge_label, badge_style): (&str, fn(&iced::Theme) -> iced::widget::container::Style) =
            match &self.daemon {
                DaemonState::Connecting => ("● connecting", theme::badge_warn),
                DaemonState::Connected => {
                    if paused {
                        ("● paused", theme::badge_warn)
                    } else if self.stream_trouble {
                        ("● reconnecting", theme::badge_warn)
                    } else {
                        ("● connected", theme::badge_ok)
                    }
                }
                DaemonState::Failed(_) => ("● disconnected", theme::badge_err),
            };

        let badge = container(text(badge_label).size(11))
            .padding([3, 10])
            .style(badge_style);

        // Enforcement can be off while the socket is perfectly healthy;
        // that deserves its own badge, not a green "connected".
        let enforcing_badge: Element<'_, Message> = match &self.status {
            Some(s) if self.connected() && !s.enforcing => {
                container(text("⚠ not enforcing").size(11))
                    .padding([3, 10])
                    .style(theme::badge_err)
                    .into()
            }
            _ => Space::new().into(),
        };

        let pause_btn: Element<'_, Message> = if self.connected() {
            if paused {
                button(text("Resume").size(12))
                    .padding([4, 14])
                    .on_press(Message::TogglePaused)
                    .style(iced::widget::button::primary)
                    .into()
            } else {
                button(text("Pause").size(12))
                    .padding([4, 14])
                    .on_press_maybe(self.pause_armed().then_some(Message::TogglePaused))
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
                    Some(s) => format!("Reconnect ({s}s)"),
                    None => "Reconnect".to_string(),
                };
                button(text(label).size(12))
                    .padding([4, 14])
                    .on_press(Message::Reconnect)
                    .style(iced::widget::button::primary)
                    .into()
            }
            _ => Space::new().into(),
        };

        let title_text = match self.tab {
            Tab::Prompts => "Pending prompts",
            Tab::Rules => "Rules",
            Tab::Live => "Live connections",
            Tab::Stats => "Stats",
        };

        let inner = row![
            text(title_text).size(18),
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

    fn theme(&self) -> iced::Theme {
        theme::parchment()
    }

    fn subscription(&self) -> Subscription<Message> {
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
        .unwrap_or_else(|| "unknown".into());
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

fn nav_item<'a>(label: &'a str, this: Tab, current: Tab, badge: usize) -> Element<'a, Message> {
    let is_active = this == current;
    let label_text = text(label).size(14);
    let row_content: Element<'_, Message> = if badge > 0 {
        row![
            label_text,
            Space::new().width(Length::Fill),
            container(text(badge.to_string()).size(11))
                .padding([1, 7])
                .style(theme::badge_err),
        ]
        .align_y(iced::Alignment::Center)
        .into()
    } else {
        row![label_text].into()
    };

    let btn = button(row_content)
        .on_press(Message::TabSelected(this))
        .padding([10, 18])
        .width(Length::Fill);

    if is_active {
        btn.style(theme::nav_item_active).into()
    } else {
        btn.style(theme::nav_item_inactive).into()
    }
}

fn divider<'a>() -> Element<'a, Message> {
    container(Space::new().height(Length::Fixed(1.0)))
        .width(Length::Fill)
        .style(|_| iced::widget::container::Style {
            background: Some(iced::Background::Color(theme::HAIRLINE)),
            ..Default::default()
        })
        .into()
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
/// daemon apply its configured default and report the real deadline.
async fn set_paused(path: PathBuf, paused: bool) -> Result<(bool, i64), String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
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
async fn upsert_rule(path: PathBuf, rule: proto::RuleInfo) -> Result<String, String> {
    let line = saved_rule_line(&rule);
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    client.upsert_rule(rule).await.map_err(|e| e.to_string())?;
    Ok(line)
}

/// `"rule saved: allow /usr/bin/curl -> *:443 tcp, always"`.
fn saved_rule_line(rule: &proto::RuleInfo) -> String {
    use cfc_client::convert;
    let summary = convert::rule_summary(rule)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let disabled = if rule.enabled { "" } else { ", disabled" };
    format!(
        "rule saved: {summary}, {}{disabled}",
        convert::rule_duration_label(rule)
    )
}

fn build_rule_from_editor(ed: &RuleEditor) -> Result<proto::RuleInfo, String> {
    let name = if ed.name.trim().is_empty() {
        "ui-added".to_string()
    } else {
        ed.name.trim().to_string()
    };

    cfc_core::RuleScope {
        dst_host: (!ed.dst_host.is_empty()).then(|| ed.dst_host.clone()),
        ..cfc_core::RuleScope::any()
    }
    .reject_hostname_policy()?;

    let dst_port = if ed.dst_port.trim().is_empty() {
        None
    } else {
        Some(
            ed.dst_port
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("\"{}\" is not a valid port", ed.dst_port))?,
        )
    };

    let dst_net = ed.dst_net.trim();
    if !dst_net.is_empty() {
        dst_net
            .parse::<ipnet::IpNet>()
            .map_err(|e| format!("dst-net invalid: {e}"))?;
    }

    // The daemon rejects a persisted Once rule outright; catch it here so
    // the user gets a sentence instead of a gRPC status.
    if matches!(
        ed.duration,
        proto::Duration::Once | proto::Duration::Unspecified
    ) {
        return Err("a saved rule needs \"Until restart\" or \"Always\"".into());
    }

    if ed.duration == proto::Duration::Seconds
        && (ed.duration_seconds == 0 || ed.editing_id.is_none() || ed.prompt_id.is_some())
    {
        return Err(
            "only an existing timed rule with a positive lifetime can retain Seconds".into(),
        );
    }

    if ed.prompt_hash_required
        && ed.action == proto::Action::Allow
        && ed.carried_scope.exe_sha256.is_empty()
    {
        return Err(
            "the prompted image could not be hashed; only a one-time Allow is available".into(),
        );
    }

    // Need at least one scope predicate, else the rule would match
    // everything. Carried predicates count: a uid-only rule created from
    // the CLI is narrow, and refusing to save it would make it uneditable.
    let scope_empty = ed.exe.trim().is_empty()
        && ed.dst_host.trim().is_empty()
        && dst_net.is_empty()
        && dst_port.is_none()
        && ed.protocol.is_none()
        && !hidden_scope_is_set(&ed.carried_scope);
    if scope_empty {
        return Err(
            "rule must restrict at least one of: exe, dst-host, dst-net, dst-port, protocol".into(),
        );
    }

    // Validate in the user's namespace as well as the daemon's: ProtectHome
    // and PrivateTmp hide exactly the paths a person commonly enters.
    // Not trimmed: a file name may end in a space, and saving a rule for
    // "/opt/app " must not quietly retarget it to "/opt/app".
    // An edited rule's unchanged path is sent back as stored, as the daemon
    // expects: it may have become an alias since, and refusing it here left
    // such a rule impossible to rename or retarget anywhere but the CLI.
    let typed = ed.exe.as_str();
    let exe = if typed.trim().is_empty() {
        String::new()
    } else if ed.editing_id.is_some() && typed == ed.carried_scope.exe_path {
        typed.to_string()
    } else {
        cfc_core::exe_path::resolve_policy(std::path::Path::new(typed))?
            .into_path()
            .to_string_lossy()
            .into_owned()
    };

    // Every field this form shows is rebuilt from it; everything else is
    // carried, so a predicate the editor cannot show is never dropped and the
    // rule never widens on save.
    let scope = proto::RuleScope {
        exe_path: exe,
        dst_host: ed.dst_host.trim().to_string(),
        dst_net: dst_net.to_string(),
        dst_port: dst_port.map(u32::from).unwrap_or(0),
        has_dst_port: dst_port.is_some(),
        protocol: ed.protocol.map(|p| p as i32).unwrap_or(0),
        has_protocol: ed.protocol.is_some(),
        ..ed.carried_scope.clone()
    };

    Ok(proto::RuleInfo {
        id: ed.editing_id.clone().unwrap_or_default(),
        name,
        // Carried from the edited rule (defaults for a new one) - see
        // RuleEditor: the daemon replaces the whole row with this message.
        enabled: ed.enabled,
        action: ed.action as i32,
        duration: ed.duration as i32,
        duration_seconds: ed.duration_seconds,
        scope: Some(scope),
        created_at_unix_ms: ed.created_at_unix_ms,
        hit_count: ed.hit_count,
    })
}

/// The rule to send for an enable/disable toggle: exactly what the daemon
/// last reported, with only `enabled` flipped. Anything reconstructed here
/// would write the UI's stale view of `hit_count` / `created_at` back over
/// the daemon's own.
fn toggled_rule(rule: &proto::RuleInfo) -> proto::RuleInfo {
    proto::RuleInfo {
        enabled: !rule.enabled,
        ..rule.clone()
    }
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
    let mut client = Client::connect(&path)
        .await
        .map_err(|e| fail(false, e.to_string()))?;
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
                .unwrap_or_else(|| "the answer applied, but no lasting rule was saved".to_string()),
        ));
    }
    if outcome.accepted && require_confirmed_rule && outcome.rule_persisted != Some(true) {
        return Err(fail(true, "the verdict applied, but this daemon did not confirm a standing rule; restart the updated daemon".into()));
    }
    Ok((prompt_id, outcome.accepted, outcome.persist_note))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_between_three_and_five_seconds() {
        assert_eq!(backoff_secs(0), 3);
        assert_eq!(backoff_secs(1), 4);
        assert_eq!(backoff_secs(2), 5);
        assert_eq!(backoff_secs(50), 5);
        assert_eq!(backoff_secs(u32::MAX), 5);
    }

    fn editor_with_scope() -> RuleEditor {
        RuleEditor {
            exe: "/usr/bin/curl".into(),
            ..RuleEditor::default()
        }
    }

    #[test]
    fn editor_rejects_a_persisted_once_rule() {
        let mut ed = editor_with_scope();
        ed.duration = proto::Duration::Once;
        let err = build_rule_from_editor(&ed).unwrap_err();
        assert!(err.contains("Until restart"), "{err}");
    }

    #[test]
    fn editing_a_timed_rule_preserves_its_exact_lifetime() {
        let mut rule = existing_rule();
        rule.duration = proto::Duration::Seconds as i32;
        rule.duration_seconds = 90;
        let mut editor = RuleEditor::from_existing(&rule);
        let saved = build_rule_from_editor(&editor).unwrap();
        assert_eq!(saved.duration, rule.duration);
        assert_eq!(saved.duration_seconds, 90);
        editor.duration_seconds = 0;
        assert!(build_rule_from_editor(&editor).is_err());
        editor.duration_seconds = 90;
        editor.prompt_id = Some("pending".into());
        assert!(build_rule_from_editor(&editor).is_err());
    }

    #[test]
    fn editor_requires_at_least_one_predicate() {
        let ed = RuleEditor::default();
        assert!(build_rule_from_editor(&ed).is_err());
    }

    #[test]
    fn editor_refuses_hostname_policy_without_dropping_it() {
        let mut ed = editor_with_scope();
        ed.dst_host = "example.org".into();
        assert!(build_rule_from_editor(&ed).is_err());
        assert_eq!(ed.dst_host, "example.org");
        ed.dst_host.clear();
        ed.dst_net = "2001:db8::1/128".into();
        assert!(build_rule_from_editor(&ed).is_ok());
    }

    #[test]
    fn editor_keeps_an_executable_path_verbatim() {
        let mut ed = editor_with_scope();
        ed.exe = "/usr/bin/cfc-test-app ".into();
        let rule = build_rule_from_editor(&ed).unwrap();
        assert_eq!(rule.scope.unwrap().exe_path, "/usr/bin/cfc-test-app ");
    }

    #[test]
    fn editor_builds_a_persistable_rule() {
        let rule = build_rule_from_editor(&editor_with_scope()).unwrap();
        assert_eq!(rule.duration, proto::Duration::Always as i32);
        assert_eq!(rule.scope.unwrap().exe_path, "/usr/bin/curl");
    }

    #[test]
    fn editor_sends_an_unchanged_alias_back_but_refuses_a_typed_one() {
        // /proc/self/exe is a symlink on every Linux, so it stands in for a
        // stored path that has since become an alias.
        let mut rule = existing_rule();
        rule.scope.as_mut().unwrap().exe_path = "/proc/self/exe".into();
        let mut ed = RuleEditor::from_existing(&rule);
        ed.name = "renamed".into();
        let saved = build_rule_from_editor(&ed).expect("unchanged path is kept");
        assert_eq!(saved.scope.unwrap().exe_path, "/proc/self/exe");

        let mut fresh = editor_with_scope();
        fresh.exe = "/proc/self/exe".into();
        assert!(build_rule_from_editor(&fresh).is_err());
    }

    #[test]
    fn observed_seed_scopes_by_program_or_pins_the_endpoint_without_one() {
        let ed = RuleEditor::from_observed("/bin/x", "", "1.2.3.4", 443, 1, 0);
        assert_eq!(ed.exe, "/bin/x");
        assert!(ed.dst_host.is_empty());
        assert!(
            ed.dst_net.is_empty(),
            "a program rule is not pinned to one address"
        );
        assert_eq!(ed.dst_port, "443");

        for exe in [cfc_client::convert::UNKNOWN_EXE, ""] {
            let ed = RuleEditor::from_observed(exe, "", "2001:db8::1", 0, 0, 0);
            assert!(ed.exe.is_empty(), "{exe:?} is never seeded");
            assert_eq!(ed.dst_net, "2001:db8::1/128");
            assert!(ed.dst_port.is_empty());
            assert!(ed.protocol.is_none());
        }

        // Inbound: the peer seen, never our own address, which the daemon
        // refuses as an inbound scope.
        let inbound = proto::Direction::Inbound as i32;
        let ed = RuleEditor::from_observed(
            cfc_client::convert::UNKNOWN_EXE,
            "192.168.1.20",
            "10.0.0.2",
            8384,
            1,
            inbound,
        );
        let scope = build_rule_from_editor(&ed).unwrap().scope.unwrap();
        assert!(scope.has_direction);
        assert_eq!(scope.direction, inbound);
        assert_eq!(scope.src_net, "192.168.1.20/32");
        assert!(scope.dst_net.is_empty());
        assert!(scope.exe_path.is_empty());
        assert_eq!(scope.dst_port, 8384);
    }

    /// Issue #46: "make rule" on a LIVE row must either send the rule or say
    /// why not, and the rule it sends for an identified program must have
    /// the CLI's scope (program, port, protocol), not a hostname or one IP.
    #[test]
    fn live_seeded_rule_is_sent_or_reported() {
        use proto::Protocol::{Icmp, Tcp, Udp};
        let rows: [(&str, &str, u32, proto::Protocol); 8] = [
            ("/usr/bin/curl", "93.184.216.34", 443, Tcp),
            ("/usr/bin/curl", "2001:db8::1", 443, Tcp),
            ("/usr/bin/curl", "9.9.9.9", 53, Udp),
            ("/usr/bin/curl", "93.184.216.34", 0, Icmp),
            (cfc_client::convert::UNKNOWN_EXE, "93.184.216.34", 443, Tcp),
            ("", "93.184.216.34", 443, Tcp),
            ("relative/path", "93.184.216.34", 443, Tcp),
            (
                cfc_client::convert::UNKNOWN_EXE,
                "",
                0,
                proto::Protocol::Unspecified,
            ),
        ];
        for (exe, dst_ip, dst_port, protocol) in rows {
            let (mut app, _) = App::new();
            let _ = app.update(Message::MakeRuleFromEvent {
                exe: exe.into(),
                src_ip: "10.0.0.2".into(),
                dst_ip: dst_ip.into(),
                dst_port,
                protocol: protocol as i32,
                direction: 0,
            });
            let ed = app.editor.as_ref().expect("editor opened");
            if let Ok(rule) = build_rule_from_editor(ed) {
                let scope = rule.scope.unwrap();
                assert!(scope.dst_host.is_empty(), "{exe} {dst_ip}");
                if cfc_client::convert::exe_is_rule_scopable(exe) {
                    assert_eq!(scope.exe_path, exe);
                    assert!(scope.dst_net.is_empty(), "{exe} {dst_ip}");
                    assert_eq!(scope.has_dst_port, dst_port != 0);
                    assert!(scope.has_protocol);
                } else {
                    assert!(scope.exe_path.is_empty(), "{exe:?} never reaches a rule");
                }
            }
            let errors_before = app
                .log
                .iter()
                .filter(|e| e.severity == status_log::Severity::Error)
                .count();
            let sent = app.update(Message::SaveRule).units();
            let errors = app
                .log
                .iter()
                .filter(|e| e.severity == status_log::Severity::Error)
                .count();
            assert!(
                sent == 1 || errors > errors_before,
                "{exe:?} {dst_ip}: Save neither sent the rule nor said why"
            );
        }
    }

    #[test]
    fn a_saved_rule_is_described_by_its_stored_scope() {
        let rule = proto::RuleInfo {
            action: proto::Action::Allow as i32,
            duration: proto::Duration::Always as i32,
            enabled: true,
            scope: Some(proto::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                dst_port: 443,
                has_dst_port: true,
                protocol: proto::Protocol::Tcp as i32,
                has_protocol: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let line = saved_rule_line(&rule);
        assert!(
            line.starts_with("rule saved: allow /usr/bin/curl -> *:443 tcp"),
            "{line}"
        );
    }

    /// A rule as the daemon reports it: created a while ago, already hit,
    /// and deliberately switched off by the user.
    fn existing_rule() -> proto::RuleInfo {
        proto::RuleInfo {
            id: "rule-1".into(),
            name: "let curl out".into(),
            enabled: false,
            action: proto::Action::Deny as i32,
            duration: proto::Duration::Always as i32,
            scope: Some(proto::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                dst_port: 443,
                has_dst_port: true,
                ..Default::default()
            }),
            created_at_unix_ms: 1_700_000_000_000,
            hit_count: 42,
            duration_seconds: 0,
        }
    }

    /// A rule narrowed by predicates the editor has no widget for — the
    /// shape `cfc rules add --uid` and opensnitch imports produce.
    fn rule_with_hidden_scope() -> proto::RuleInfo {
        proto::RuleInfo {
            scope: Some(proto::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                exe_sha256: "abc123def456abc123def456abc123def456abc123def456".into(),
                parent_exe: "/usr/bin/bash".into(),
                uid: 1000,
                has_uid: true,
                ..Default::default()
            }),
            ..existing_rule()
        }
    }

    #[test]
    fn editing_keeps_scope_predicates_the_editor_cannot_show() {
        // Dropping these would WIDEN the rule: a deny scoped to one uid
        // would start matching every user on the host, and a checksum-
        // pinned allow would lose its binary pin.
        let original = rule_with_hidden_scope();
        let mut ed = RuleEditor::from_existing(&original);
        ed.dst_port = "8443".into(); // the user changes only the port

        let sent = build_rule_from_editor(&ed).expect("valid");
        let scope = sent.scope.expect("scope");
        let orig = original.scope.unwrap();
        assert_eq!(scope.uid, orig.uid);
        assert!(scope.has_uid);
        assert_eq!(scope.exe_sha256, orig.exe_sha256);
        assert_eq!(scope.parent_exe, orig.parent_exe);
        assert_eq!(scope.dst_port, 8443, "the intended edit still applies");
    }

    #[test]
    fn a_rule_scoped_only_by_hidden_predicates_is_still_editable() {
        // Validation must count carried predicates, else a uid-only rule
        // could never be saved from the GUI at all.
        let uid_only = proto::RuleInfo {
            scope: Some(proto::RuleScope {
                uid: 1000,
                has_uid: true,
                ..Default::default()
            }),
            ..existing_rule()
        };
        let ed = RuleEditor::from_existing(&uid_only);
        assert!(hidden_scope_is_set(&ed.carried_scope));
        assert!(build_rule_from_editor(&ed).is_ok());

        // A genuinely empty scope is still refused.
        let empty = RuleEditor {
            name: "everything".into(),
            ..RuleEditor::default()
        };
        assert!(build_rule_from_editor(&empty).is_err());
    }

    #[test]
    fn hidden_scope_summary_names_each_predicate() {
        let ed = RuleEditor::from_existing(&rule_with_hidden_scope());
        let summary = hidden_scope_summary(&ed.carried_scope);
        assert!(summary.contains("uid 1000"), "{summary}");
        assert!(summary.contains("/usr/bin/bash"), "{summary}");
        assert!(summary.contains("sha256 abc123def456"), "{summary}");
        assert!(!hidden_scope_is_set(&proto::RuleScope::default()));
    }

    #[test]
    fn editing_a_rule_preserves_its_metadata() {
        let original = existing_rule();
        let mut ed = RuleEditor::from_existing(&original);
        // The user changes one field and saves.
        ed.dst_port = "8443".into();

        let rebuilt = build_rule_from_editor(&ed).unwrap();
        assert_eq!(rebuilt.id, original.id);
        assert_eq!(
            rebuilt.created_at_unix_ms, original.created_at_unix_ms,
            "editing must not reset the creation date"
        );
        assert_eq!(
            rebuilt.hit_count, original.hit_count,
            "editing must not zero the hit count"
        );
        assert!(
            !rebuilt.enabled,
            "editing must not re-enable a rule the user disabled"
        );
        assert_eq!(rebuilt.scope.unwrap().dst_port, 8443);
    }

    #[test]
    fn a_new_rule_starts_with_empty_metadata() {
        let rule = build_rule_from_editor(&editor_with_scope()).unwrap();
        assert!(rule.id.is_empty(), "the daemon assigns the id");
        assert_eq!(rule.created_at_unix_ms, 0, "the daemon stamps the creation");
        assert_eq!(rule.hit_count, 0);
        assert!(rule.enabled);
    }

    #[test]
    fn a_rule_seeded_from_an_observed_flow_is_new() {
        let ed = RuleEditor::from_observed("/bin/x", "", "1.2.3.4", 443, 1, 0);
        assert_eq!(ed.created_at_unix_ms, 0);
        assert_eq!(ed.hit_count, 0);
        assert!(ed.enabled);
        assert!(ed.editing_id.is_none());
    }

    #[test]
    fn toggling_enabled_changes_nothing_else() {
        let original = existing_rule();
        let toggled = toggled_rule(&original);
        assert!(toggled.enabled);
        assert_eq!(
            toggled,
            proto::RuleInfo {
                enabled: true,
                ..original.clone()
            },
            "the toggle must round-trip the rule as received"
        );
        // Toggling twice is a no-op: no hit count drift per click.
        assert_eq!(toggled_rule(&toggled), original);
    }

    #[test]
    fn a_failed_connection_logs_the_actionable_reason_once() {
        let detail = "permission denied on /run/colony-firewall/cfc.sock - add your user to \
                      the colony-firewall group (sudo usermod -aG colony-firewall $USER) then \
                      log out and back in, or run as root";
        let mut log = StatusLog::default();
        // Four retry rounds against a daemon that stays down.
        for i in 0..4 {
            log.warn(format::unreachable_log_line(detail), 1_000 + i);
        }
        assert_eq!(log.len(), 1, "retries must coalesce, not scroll the ring");
        let entry = log.iter().next().unwrap();
        assert_eq!(entry.count, 4);
        assert!(entry.display().contains("colony-firewall group"));
        assert!(entry.display().ends_with("(x4)"));
    }

    fn prompt_event() -> proto::PromptEvent {
        proto::PromptEvent {
            prompt_id: "p1".into(),
            connection: Some(proto::ConnectionInfo {
                protocol: proto::Protocol::Tcp as i32,
                dst_ip: "93.184.216.34".into(),
                dst_port: 443,
                dst_host: "example.com".into(),
                ..Default::default()
            }),
            process: Some(proto::ProcessInfo {
                exe: "/usr/bin/curl".into(),
                ..Default::default()
            }),
            deadline_unix_ms: 1_700_000_015_000,
            binds_to_hash: false,
        }
    }

    #[test]
    fn customization_waits_for_a_verdict_and_drops_stale_actions() {
        let (mut app, _) = App::new();
        let event = prompt_event();
        app.prompts.push(PromptCard::new(event.clone(), 0));
        let task = app.update(Message::CustomizePromptRule(event.prompt_id.clone()));
        assert_eq!(task.units(), 0, "opening the editor issues no verdict RPC");
        assert_eq!(app.prompts.len(), 1, "the prompt remains pending");
        assert_eq!(
            app.editor.as_ref().unwrap().prompt_id.as_ref(),
            Some(&event.prompt_id)
        );
        let _ = app.update(Message::PromptStreamEnded("disconnected".into()));
        assert!(app.prompts.is_empty());
        assert!(
            app.editor.as_ref().unwrap().prompt_id.is_none(),
            "the edits stay, as a plain rule"
        );
        assert_eq!(
            app.update(Message::CustomizePromptRule(event.prompt_id))
                .units(),
            0
        );
        assert!(app.editor.as_ref().unwrap().prompt_id.is_none());
    }

    #[test]
    fn an_expired_prompt_keeps_its_customization_as_a_new_rule() {
        let (mut app, _) = App::new();
        let event = prompt_event();
        app.prompts.push(PromptCard::new(event.clone(), 0));
        let mut editor = RuleEditor::from_prompt(&event);
        editor.name = "careful".into();
        app.editor = Some(editor);
        app.now_ms = event.deadline_unix_ms + 1;
        app.housekeeping();
        assert!(app.prompts.is_empty());
        let editor = app.editor.as_ref().expect("the edits are kept");
        assert!(editor.prompt_id.is_none());
        assert_eq!(editor.name, "careful");
        // Save now stores the rule instead of answering a dead prompt.
        assert_eq!(app.update(Message::SaveRule).units(), 1);
    }

    #[test]
    fn a_verdict_that_was_not_applied_leaves_the_prompt_answerable() {
        let (mut app, _) = App::new();
        let event = prompt_event();
        app.prompts.push(PromptCard::new(event.clone(), 0));
        let submit = || Message::SubmitVerdict {
            prompt_id: event.prompt_id.clone(),
            action: proto::Action::Deny,
            scope: None,
            duration: proto::Duration::Once,
        };
        assert_eq!(app.update(submit()).units(), 1);
        assert!(app.prompts[0].submitting, "held until the daemon confirms");
        assert_eq!(app.update(submit()).units(), 0, "one verdict at a time");

        let failure = |applied| VerdictFailure {
            prompt_id: event.prompt_id.clone(),
            applied,
            message: "connection refused".into(),
        };
        let _ = app.update(Message::VerdictSubmitted(Err(failure(false))));
        assert_eq!(app.prompts.len(), 1);
        assert!(!app.prompts[0].submitting, "it can be answered again");

        let _ = app.update(submit());
        let _ = app.update(Message::VerdictSubmitted(Err(failure(true))));
        assert!(app.prompts.is_empty(), "an applied answer retires the card");
    }

    #[test]
    fn customization_cannot_save_an_allow_without_its_required_hash() {
        let mut event = prompt_event();
        event.binds_to_hash = true;
        let mut editor = RuleEditor::from_prompt(&event);
        assert!(build_rule_from_editor(&editor).is_err());
        editor.action = proto::Action::Deny;
        assert!(build_rule_from_editor(&editor).is_ok());
    }

    #[test]
    fn customizing_a_prompt_preserves_the_promised_digest() {
        let mut event = prompt_event();
        event.binds_to_hash = true;
        event.process.as_mut().unwrap().sha256 = "a".repeat(64);
        let editor = RuleEditor::from_prompt(&event);
        assert_eq!(
            build_rule_from_editor(&editor)
                .unwrap()
                .scope
                .unwrap()
                .exe_sha256,
            "a".repeat(64)
        );
    }

    #[test]
    fn customizing_a_prompt_seeds_a_new_rule_from_it() {
        let ed = RuleEditor::from_prompt(&prompt_event());
        assert_eq!(ed.exe, "/usr/bin/curl");
        assert!(ed.dst_host.is_empty());
        assert!(ed.dst_net.is_empty());
        assert_eq!(ed.dst_port, "443");
        assert_eq!(ed.protocol, Some(proto::Protocol::Tcp));
        // It is a new rule, not an edit of an existing one.
        assert!(ed.editing_id.is_none());
        assert_eq!(ed.created_at_unix_ms, 0);
        // Whatever the user saves has to be persistable, so it must not
        // inherit the prompt's one-off semantics.
        assert_eq!(ed.duration, proto::Duration::Always);
        assert!(build_rule_from_editor(&ed).is_ok());
    }

    #[test]
    fn customizing_an_empty_prompt_does_not_seed_a_match_everything_rule() {
        let ed = RuleEditor::from_prompt(&proto::PromptEvent::default());
        assert!(ed.exe.is_empty());
        assert!(ed.dst_host.is_empty());
        assert!(ed.dst_net.is_empty());
        assert!(ed.protocol.is_none());
        // Nothing to scope on, so saving is refused rather than silently
        // writing a rule that matches every program.
        assert!(build_rule_from_editor(&ed).is_err());
    }

    #[test]
    fn a_first_prompt_raises_the_window_and_a_burst_does_not() {
        // 0 -> 1 is the interruption worth stealing focus for.
        assert_eq!(prompt_attention(0, false), Attention::TabAndRaise);
        // 1 -> 2, 2 -> 3: the user already knows about the queue, and a tab
        // switch under their cursor would turn a click into a verdict.
        assert_eq!(prompt_attention(1, false), Attention::None);
        assert_eq!(prompt_attention(9, false), Attention::None);
        // Drained and refilled: a genuinely new interruption.
        assert_eq!(prompt_attention(0, false), Attention::TabAndRaise);
    }

    #[test]
    fn an_open_rule_editor_suppresses_the_raise_and_the_tab_switch() {
        // Yanking the tab out from under a half-filled form loses it.
        assert_eq!(prompt_attention(0, true), Attention::None);
        assert_eq!(prompt_attention(3, true), Attention::None);
    }

    fn key(c: &str, modifiers: keyboard::Modifiers) -> KeyPress {
        KeyPress {
            key: keyboard::Key::Character(c.into()),
            modifiers,
        }
    }

    fn prompt(id: &str, exe: &str) -> proto::PromptEvent {
        let mut ev = prompt_event();
        ev.prompt_id = id.into();
        ev.process.as_mut().unwrap().exe = exe.into();
        ev.deadline_unix_ms = 0;
        ev
    }

    #[test]
    fn verdict_keys_answer_the_armed_top_card_only() {
        let (mut app, _) = App::new();
        app.now_ms = 1_000_000;
        app.prompts.push(PromptCard::new(
            prompt("top", "/usr/lib/firefox/firefox"),
            0,
        ));
        app.prompts.push(PromptCard::new(
            prompt("below", "/home/u/.cache/x/updater"),
            0,
        ));
        let shift = keyboard::Modifiers::SHIFT;

        // The top card just became the target: a press already on its way
        // answers nothing.
        assert_eq!(app.handle_key(key("A", shift)).units(), 0);
        assert_eq!(app.prompts.len(), 2);

        app.now_ms += PROMPT_ARM_MS;
        // Chords and other tabs never answer.
        for m in [
            keyboard::Modifiers::CTRL,
            keyboard::Modifiers::ALT,
            keyboard::Modifiers::LOGO,
            keyboard::Modifiers::CTRL | shift,
        ] {
            assert_eq!(app.handle_key(key("a", m)).units(), 0, "{m:?}");
        }
        app.tab = Tab::Rules;
        assert_eq!(app.handle_key(key("a", shift)).units(), 0);
        app.tab = Tab::Prompts;

        assert_eq!(app.handle_key(key("A", shift)).units(), 1);
        assert!(app.prompts[0].submitting, "the top card is answered");
        assert!(!app.prompts[1].submitting, "not the newest");

        // The card that moved up is disarmed again.
        assert_eq!(
            app.handle_key(key("a", keyboard::Modifiers::empty()))
                .units(),
            0
        );
    }

    #[test]
    fn a_card_that_moves_up_is_disarmed_again() {
        let (mut app, _) = App::new();
        app.prompts.push(PromptCard::new(
            prompt("top", "/usr/lib/firefox/firefox"),
            0,
        ));
        app.prompts.push(PromptCard::new(
            prompt("below", "/home/u/.cache/x/updater"),
            0,
        ));
        assert!(app.prompts[1].armed(app.now_ms));
        let _ = app.update(Message::SubmitVerdict {
            prompt_id: "top".into(),
            action: proto::Action::Allow,
            scope: None,
            duration: proto::Duration::Always,
        });
        let _ = app.update(Message::VerdictSubmitted(Ok(("top".into(), true, None))));
        // The second click of a double-click lands on the card that took
        // the answered one's place.
        assert_eq!(app.prompts[0].event.prompt_id, "below");
        assert!(!app.prompts[0].armed(app.now_ms));
        assert!(app.prompts[0].armed(app.now_ms + PROMPT_ARM_MS));
    }

    #[test]
    fn pause_ignores_a_click_right_after_resuming() {
        let (mut app, _) = App::new();
        app.status = Some(proto::StatusResponse {
            paused: true,
            ..Default::default()
        });
        assert_eq!(app.update(Message::TogglePaused).units(), 1, "Resume");
        let _ = app.update(Message::PausedSet(Ok((false, 0))));
        assert_eq!(app.update(Message::TogglePaused).units(), 0);
        app.now_ms += PROMPT_ARM_MS;
        assert_eq!(app.update(Message::TogglePaused).units(), 1);
    }

    #[test]
    fn pause_ignores_a_click_right_after_reconnecting() {
        let (mut app, _) = App::new();
        let _ = app.update(Message::HandshakeDone(Ok(HandshakeData {
            status: proto::StatusResponse::default(),
            rules: Vec::new(),
        })));
        assert_eq!(app.update(Message::TogglePaused).units(), 0);
        app.now_ms += PROMPT_ARM_MS;
        assert_eq!(app.update(Message::TogglePaused).units(), 1);
    }

    #[test]
    fn a_prompt_card_is_disarmed_right_after_it_appears() {
        let card = PromptCard::new(prompt("p", "/usr/bin/curl"), 5_000);
        assert!(!card.armed(5_000));
        assert!(!card.armed(5_000 + PROMPT_ARM_MS - 1));
        assert!(card.armed(5_000 + PROMPT_ARM_MS));
    }
}
