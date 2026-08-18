//! Colony Firewall Control - system tray icon.
//!
//! A StatusNotifierItem (the KDE/freedesktop tray spec, spoken natively by
//! KDE and by GNOME through the AppIndicator extension) showing the
//! daemon's state at a glance: enforcing / paused / unreachable, the
//! number of prompts waiting for a verdict, quick pause/resume, and a
//! left-click that opens the GUI. It only *talks* to the daemon over the
//! same control socket as the GUI and CLI - quitting the tray never
//! touches the daemon.

mod icon;
mod model;

use anyhow::Context as _;
use cfc_client::{proto, Client, StreamItem};
use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, TrayMethods as _};
use model::{DaemonView, NotifyGate, PauseControl, PromptChoice, PromptPresentation};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt as _};
use tracing::{debug, info, warn};

/// GetStatus poll cadence, reachable or not. Failures ride the same
/// ticker, so an absent daemon costs one connect attempt every 3s, never
/// a tight loop.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Notification app name. Without it the server derives one from the
/// binary ("Colony-firewall-tray"), which reads like a process listing.
const APP_NAME: &str = "Colony Firewall";

/// Themed icon name, used as the app icon. The embedded raster from
/// [`notification_image`] is attached as well: the theme name only
/// resolves once the package has installed the SVG and the desktop's
/// icon cache has picked it up, and a firewall prompt showing a generic
/// bell is a prompt the user does not recognise.
const NOTIFY_ICON: &str = "colony-firewall";

/// The embedded shield, built once and reused by every bubble.
fn notification_image() -> Option<notify_rust::Image> {
    static IMAGE: std::sync::OnceLock<Option<notify_rust::Image>> = std::sync::OnceLock::new();
    IMAGE
        .get_or_init(|| {
            let (w, h, rgba) = icon::notification_rgba();
            notify_rust::Image::from_rgba(w, h, rgba)
                .inspect_err(|e| warn!("building the notification icon: {e}"))
                .ok()
        })
        .clone()
}

/// Applies the shared presentation every Colony bubble uses.
fn brand(n: &mut notify_rust::Notification) -> &mut notify_rust::Notification {
    n.appname(APP_NAME).icon(NOTIFY_ICON);
    if let Some(image) = notification_image() {
        n.image_data(image);
    }
    n
}

/// The GUI binary, resolved via PATH. The environment (including
/// `CFC_SOCKET`) is inherited, so the GUI talks to the same daemon.
const GUI_BIN: &str = "colony-firewall";

/// Control socket: `$CFC_SOCKET` when set, else the packaged default -
/// the same resolution the GUI uses.
fn socket_path_from_env() -> PathBuf {
    match std::env::var_os("CFC_SOCKET") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(cfc_proto::DEFAULT_SOCKET_PATH),
    }
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// How long to wait for the notification server to answer
/// GetCapabilities before giving up and using the generic path.
const CAPABILITY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Subscriber id the daemon sees for this tray's StreamPrompts.
const CLIENT_ID: &str = "colony-firewall-tray";

/// What a menu click or a resolved notification asks the main loop to do.
/// Menu callbacks run on the tray service task and notification waits on
/// blocking tasks; neither may touch the client, so they only send.
#[derive(Debug, Clone)]
enum Cmd {
    Pause(u32),
    Resume,
    OpenGui,
    Quit,
    /// An actionable prompt notification resolved: a button, the body
    /// (the `default` action), or dismissed/expired (`__closed`).
    PromptResult {
        prompt_id: String,
        exe: String,
        key: String,
    },
    /// The collapsed overflow notification was shown; `id` is the server
    /// id needed to update its count in place later.
    OverflowShown {
        id: u32,
    },
    /// The collapsed overflow notification resolved.
    OverflowResult {
        key: String,
    },
}

struct TrayApp {
    view: DaemonView,
    tx: mpsc::UnboundedSender<Cmd>,
    icons: Vec<ksni::Icon>,
}

impl TrayApp {
    fn send(&self, cmd: Cmd) {
        // The only way this fails is the main loop being gone, and then
        // the whole process is on its way out anyway.
        let _ = self.tx.send(cmd);
    }
}

impl ksni::Tray for TrayApp {
    fn id(&self) -> String {
        "colony-firewall-tray".into()
    }

    fn title(&self) -> String {
        "Colony Firewall".into()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }

    fn status(&self) -> ksni::Status {
        match &self.view {
            DaemonView::Reachable {
                prompts_pending: 1..,
                ..
            } => ksni::Status::NeedsAttention,
            DaemonView::Reachable { .. } => ksni::Status::Active,
            // Muted while there is nothing to report on; hosts may hide
            // or dim a Passive item.
            DaemonView::Connecting | DaemonView::Unreachable { .. } => ksni::Status::Passive,
        }
    }

    fn icon_name(&self) -> String {
        // Installed by the package to hicolor/scalable/apps.
        "colony-firewall".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        // Embedded fallback for hosts/setups without the theme icon.
        self.icons.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: "colony-firewall".into(),
            icon_pixmap: Vec::new(),
            title: "Colony Firewall".into(),
            description: model::tooltip_description(&self.view, now_unix_ms()),
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(Cmd::OpenGui);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let m = model::menu_model(&self.view, now_unix_ms());

        let mut items: Vec<MenuItem<Self>> = vec![StandardItem {
            label: m.status_line,
            enabled: false,
            ..Default::default()
        }
        .into()];

        if let Some(line) = m.prompts_line {
            items.push(
                StandardItem {
                    label: line,
                    activate: Box::new(|t: &mut Self| t.send(Cmd::OpenGui)),
                    ..Default::default()
                }
                .into(),
            );
        }

        match m.pause {
            Some(PauseControl::Offer) => items.push(
                SubMenu {
                    label: "Pause".into(),
                    submenu: model::PAUSE_CHOICES
                        .iter()
                        .map(|&(label, secs)| {
                            StandardItem {
                                label: label.into(),
                                activate: Box::new(move |t: &mut Self| t.send(Cmd::Pause(secs))),
                                ..Default::default()
                            }
                            .into()
                        })
                        .collect(),
                    ..Default::default()
                }
                .into(),
            ),
            Some(PauseControl::ResumeNow) => items.push(
                StandardItem {
                    label: "Resume now".into(),
                    activate: Box::new(|t: &mut Self| t.send(Cmd::Resume)),
                    ..Default::default()
                }
                .into(),
            ),
            None => {}
        }

        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Open Colony Firewall".into(),
                activate: Box::new(|t: &mut Self| t.send(Cmd::OpenGui)),
                ..Default::default()
            }
            .into(),
        );
        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Quit tray".into(),
                activate: Box::new(|t: &mut Self| t.send(Cmd::Quit)),
                ..Default::default()
            }
            .into(),
        );
        items
    }

    fn watcher_online(&self) {
        info!("StatusNotifierWatcher online, tray registered");
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        // Keep waiting: at login the tray often starts before the desktop
        // finishes bringing its SNI host up.
        warn!(
            "StatusNotifierWatcher offline ({reason:?}) - waiting for it to return \
             (GNOME needs the AppIndicator extension for SNI trays)"
        );
        true
    }
}

/// One GetStatus round-trip. Keeps the client across polls and drops it
/// on any failure so the next tick reconnects from scratch.
async fn poll_once(client: &mut Option<Client>, socket: &Path) -> DaemonView {
    if client.is_none() {
        match Client::connect(socket).await {
            Ok(c) => *client = Some(c),
            Err(e) => {
                debug!("connect failed: {e}");
                return DaemonView::Unreachable {
                    hint: model::unreachable_hint(&e),
                };
            }
        }
    }
    let c = client.as_mut().expect("connected above");
    match c.status().await {
        Ok(s) => DaemonView::Reachable {
            enforcing: s.enforcing,
            paused: s.paused,
            resume_at_unix_ms: s.resume_at_unix_ms,
            prompts_pending: s.prompts_pending,
        },
        Err(e) => {
            debug!("GetStatus failed: {e}");
            *client = None;
            DaemonView::Unreachable {
                hint: model::unreachable_hint(&e),
            }
        }
    }
}

/// Poll, notify if warranted, push the new view into the tray. Returns
/// `false` when the tray service is gone and the loop should end.
///
/// `generic_notify` gates the count notification: it stays on only when
/// the notification server cannot do actions, so users never get both a
/// per-prompt bubble and the generic one for the same prompt.
async fn refresh(
    handle: &ksni::Handle<TrayApp>,
    client: &mut Option<Client>,
    socket: &Path,
    gate: &mut NotifyGate,
    was_reachable: &mut Option<bool>,
    generic_notify: bool,
) -> bool {
    let view = poll_once(client, socket).await;

    let up = matches!(view, DaemonView::Reachable { .. });
    if *was_reachable != Some(up) {
        match &view {
            DaemonView::Unreachable { hint } => warn!("daemon unreachable: {hint}"),
            _ => info!("daemon reachable"),
        }
        *was_reachable = Some(up);
    }

    if let DaemonView::Reachable {
        prompts_pending, ..
    } = view
    {
        if generic_notify && gate.on_poll(prompts_pending, now_unix_ms()) {
            notify_pending(prompts_pending);
        }
    }

    handle.update(|t| t.view = view).await.is_some()
}

/// Ask the daemon to pause (`duration_secs`, 0 = daemon default) or
/// resume. Failures are logged, never fatal - the next poll will show the
/// truth either way.
async fn set_paused(client: &mut Option<Client>, socket: &Path, paused: bool, duration_secs: u32) {
    let verb = if paused { "pause" } else { "resume" };
    if client.is_none() {
        match Client::connect(socket).await {
            Ok(c) => *client = Some(c),
            Err(e) => {
                warn!("cannot {verb}: {e}");
                return;
            }
        }
    }
    let c = client.as_mut().expect("connected above");
    match c.set_paused(paused, duration_secs).await {
        Ok(resp) => debug!(
            paused = resp.paused,
            resume_at_unix_ms = resp.resume_at_unix_ms,
            "{verb} acknowledged"
        ),
        Err(e) => {
            warn!("{verb} failed: {e}");
            *client = None;
        }
    }
}

/// Launches the GUI, detached: resolved via PATH, environment (including
/// `CFC_SOCKET`) inherited. A reaper thread waits on the child so it
/// never lingers as a zombie while the tray keeps running.
fn open_gui() {
    use std::process::{Command, Stdio};
    match Command::new(GUI_BIN)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            info!(pid = child.id(), "launched {GUI_BIN}");
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => warn!("launching {GUI_BIN}: {e} (is it installed and on PATH?)"),
    }
}

/// Generic on purpose: GetStatus only carries counts, not which process
/// or destination is waiting - the GUI has the details. Only shown when
/// the notification server cannot do actions (see [`refresh`]).
fn notify_pending(count: u64) {
    // notify-rust's show() blocks on D-Bus; keep it off the poll loop.
    tokio::task::spawn_blocking(move || {
        let noun = if count == 1 {
            "connection"
        } else {
            "connections"
        };
        let mut n = notify_rust::Notification::new();
        let _ = brand(&mut n)
            .summary("Colony Firewall: verdict needed")
            .body(&format!(
                "{count} {noun} waiting for a verdict — open Colony Firewall"
            ))
            .timeout(notify_rust::Timeout::Milliseconds(8000))
            .show();
    });
}

/// A short, non-actionable follow-up ("rule created", "too late"). 5s,
/// normal urgency.
fn notify_brief(body: String) {
    tokio::task::spawn_blocking(move || {
        let mut n = notify_rust::Notification::new();
        let _ = brand(&mut n)
            .summary("Colony Firewall")
            .body(&body)
            .timeout(notify_rust::Timeout::Milliseconds(5000))
            .show();
    });
}

/// The collapsed overflow bubble, on screen or on its way there.
///
/// `Opening` covers the gap between spawning the blocking show task and
/// its `Cmd::OverflowShown` coming back; prompts arriving in that window
/// only bump the count, and the count is reconciled on `OverflowShown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverflowBubble {
    Down,
    Opening,
    Up(u32),
}

/// Live actionable-notification bookkeeping, owned by the main loop.
struct PromptNotifier {
    tx: mpsc::UnboundedSender<Cmd>,
    /// Prompt ids with an actionable notification currently on screen.
    active: HashSet<String>,
    /// Prompts folded into the overflow bubble since it appeared.
    overflow_count: u64,
    bubble: OverflowBubble,
}

impl PromptNotifier {
    fn new(tx: mpsc::UnboundedSender<Cmd>) -> Self {
        Self {
            tx,
            active: HashSet::new(),
            overflow_count: 0,
            bubble: OverflowBubble::Down,
        }
    }

    /// One prompt arrived: its own actionable notification while a slot
    /// is free, otherwise folded into the single overflow bubble.
    fn on_prompt(&mut self, ev: &proto::PromptEvent) {
        match model::present_prompt(self.active.len(), self.overflow_count) {
            PromptPresentation::Actionable => self.show_actionable(ev),
            PromptPresentation::Overflow { count } => {
                self.overflow_count = count;
                self.show_or_update_overflow();
            }
        }
    }

    fn show_actionable(&mut self, ev: &proto::PromptEvent) {
        let n = model::prompt_notification(ev, now_unix_ms());
        let prompt_id = ev.prompt_id.clone();
        self.active.insert(prompt_id.clone());
        let exe = ev
            .process
            .as_ref()
            .map(|p| p.exe.clone())
            .unwrap_or_default();
        let tx = self.tx.clone();
        // One blocking task per shown notification: show() and
        // wait_for_action() both block on D-Bus, and the wait lasts until
        // the user acts or the bubble expires.
        tokio::task::spawn_blocking(move || {
            let mut notification = notify_rust::Notification::new();
            brand(&mut notification)
                .summary(&n.summary)
                .body(&n.body)
                .timeout(notify_rust::Timeout::Milliseconds(n.timeout_ms))
                // Verdicts first and short: these are what the user came
                // for, and long labels wrap the button row onto a second
                // line. "Details" is the freedesktop `default` action, so
                // clicking the bubble body opens the GUI too.
                .action(model::KEY_ALLOW, "Allow")
                .action(model::KEY_DENY, "Deny");
            if n.offer_block {
                notification.action(model::KEY_BLOCK, "Block app");
            }
            notification.action(model::KEY_DEFAULT, "Details");
            let done = move |key: &str| {
                // Failing only means the main loop is gone; the process
                // is on its way out.
                let _ = tx.send(Cmd::PromptResult {
                    prompt_id,
                    exe,
                    key: key.to_string(),
                });
            };
            match notification.show() {
                Ok(handle) => handle.wait_for_action(done),
                Err(e) => {
                    warn!("showing prompt notification: {e}");
                    // Free the slot; the daemon's timeout_action covers
                    // the prompt itself.
                    done(model::KEY_CLOSED);
                }
            }
        });
    }

    /// Show the overflow bubble, or update its count in place. Only the
    /// first show spawns a wait task: an in-place replace keeps the
    /// server id, so the original wait keeps listening for the whole
    /// bubble lifetime and exactly one `OverflowResult` comes back.
    fn show_or_update_overflow(&mut self) {
        let body = model::overflow_body(self.overflow_count);
        match self.bubble {
            OverflowBubble::Down => {
                self.bubble = OverflowBubble::Opening;
                let tx = self.tx.clone();
                tokio::task::spawn_blocking(move || {
                    let shown = overflow_notification(&body).show();
                    match shown {
                        Ok(handle) => {
                            let _ = tx.send(Cmd::OverflowShown { id: handle.id() });
                            handle.wait_for_action(|key: &str| {
                                let _ = tx.send(Cmd::OverflowResult {
                                    key: key.to_string(),
                                });
                            });
                        }
                        Err(e) => {
                            warn!("showing overflow notification: {e}");
                            let _ = tx.send(Cmd::OverflowResult {
                                key: model::KEY_CLOSED.to_string(),
                            });
                        }
                    }
                });
            }
            // Count already bumped; reconciled when OverflowShown lands.
            OverflowBubble::Opening => {}
            OverflowBubble::Up(id) => {
                tokio::task::spawn_blocking(move || {
                    let _ = overflow_notification(&body).id(id).show();
                });
            }
        }
    }

    /// The overflow bubble reported its server id. Re-show if prompts
    /// piled up while it was opening, so the visible count catches up.
    fn on_overflow_shown(&mut self, id: u32) {
        self.bubble = OverflowBubble::Up(id);
        if self.overflow_count > 1 {
            self.show_or_update_overflow();
        }
    }

    /// The overflow bubble resolved (clicked or closed); reset so the
    /// next over-cap prompt starts a fresh bubble and count.
    fn on_overflow_result(&mut self) {
        self.bubble = OverflowBubble::Down;
        self.overflow_count = 0;
    }

    /// The prompt stream dropped: every pending prompt died with it.
    /// Forget them so post-reconnect prompts get fresh slots; bubbles
    /// still on screen resolve through their own wait tasks (a late
    /// click just gets accepted=false from the daemon).
    fn on_disconnect(&mut self) {
        self.active.clear();
        self.overflow_count = 0;
    }
}

/// The collapsed "N more connections waiting" notification. Actionable
/// only through the default (body-click) action, which opens the GUI.
fn overflow_notification(body: &str) -> notify_rust::Notification {
    let mut n = notify_rust::Notification::new();
    brand(&mut n)
        .summary("Several connections are waiting")
        .body(body)
        .timeout(notify_rust::Timeout::Milliseconds(8000))
        .action(model::KEY_DEFAULT, "Open Colony Firewall");
    n
}

/// Sends the verdict for one answered prompt. Late answers (the daemon
/// already applied its default) surface as a brief follow-up; a created
/// block rule gets a brief confirmation. Allow/Deny once succeed silently.
async fn submit_prompt_verdict(
    client: &mut Option<Client>,
    socket: &Path,
    prompt_id: &str,
    choice: PromptChoice,
    exe: &str,
) {
    if choice == PromptChoice::BlockAlways && exe.is_empty() {
        // A RuleScope with an empty exe_path is a match-everything deny
        // rule. The button is not offered for exe-less prompts, but never
        // trust the notification server that far.
        warn!(prompt_id, "block verdict without an exe path ignored");
        return;
    }
    if client.is_none() {
        match Client::connect(socket).await {
            Ok(c) => *client = Some(c),
            Err(e) => {
                warn!("cannot submit verdict: {e}");
                return;
            }
        }
    }
    let c = client.as_mut().expect("connected above");
    let (action, duration, scope) = model::verdict_for(choice, exe);
    match c.submit_verdict(prompt_id, action, duration, scope).await {
        Ok(true) => {
            debug!(prompt_id, ?choice, "verdict accepted");
            if choice == PromptChoice::BlockAlways {
                notify_brief(model::block_confirmation(exe));
            }
        }
        Ok(false) => {
            info!(prompt_id, "verdict too late - prompt already resolved");
            notify_brief("Too late — the daemon already applied its default".into());
        }
        Err(e) => {
            warn!("submitting verdict: {e}");
            *client = None;
        }
    }
}

/// Asks the notification server whether it renders action buttons.
///
/// Deliberately *not* `notify_rust::get_capabilities`: that helper is
/// blocking, and its zbus backend deadlocks when driven from inside this
/// process's tokio runtime — the tray hung at startup before ever
/// reaching its first poll. Talking to the bus directly keeps the call
/// async, and the timeout means a wedged or absent notification server
/// costs two seconds instead of the whole run.
///
/// On any failure the answer is "no actions": that keeps the tray on the
/// generic count notification and, crucially, stops it from subscribing
/// to the prompt feed — subscribing while unable to answer would make the
/// daemon hold every prompt for the full timeout instead of applying its
/// no-subscriber fast path.
async fn probe_actions_supported() -> bool {
    let probe = async {
        let conn = zbus::Connection::session().await?;
        let caps: Vec<String> = conn
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "GetCapabilities",
                &(),
            )
            .await?
            .body()
            .deserialize()?;
        Ok::<_, anyhow::Error>(model::actions_supported(&caps))
    };

    match tokio::time::timeout(CAPABILITY_PROBE_TIMEOUT, probe).await {
        Ok(Ok(supported)) => supported,
        Ok(Err(e)) => {
            warn!("querying notification capabilities: {e} - using the generic fallback");
            false
        }
        Err(_) => {
            warn!(
                "notification server did not answer GetCapabilities within \
                 {CAPABILITY_PROBE_TIMEOUT:?} - using the generic fallback"
            );
            false
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let socket = socket_path_from_env();
    info!(socket = %socket.display(), "starting colony-firewall-tray");

    let (tx, mut rx) = mpsc::unbounded_channel();
    // Notification wait tasks route their results over the same channel
    // as menu clicks; the main loop is the only place the client lives.
    let handle_tx = tx.clone();
    let tray = TrayApp {
        view: DaemonView::Connecting,
        tx,
        icons: icon::all()
            .into_iter()
            .map(|p| ksni::Icon {
                width: p.width as i32,
                height: p.height as i32,
                data: p.argb,
            })
            .collect(),
    };

    // assume_sni_available: at login this process may beat the desktop's
    // SNI host; wait for it (watcher_offline logs) instead of dying. The
    // trade-off is that on a desktop with no SNI support at all the tray
    // waits forever - preferable for an autostarted helper.
    let handle = tray.assume_sni_available(true).spawn().await.context(
        "registering the tray on the session bus (no D-Bus session? \
             GNOME needs the AppIndicator extension for SNI trays)",
    )?;

    // One capability probe decides the notification strategy for the
    // whole run: per-prompt actionable bubbles when the server advertises
    // "actions", else the generic NotifyGate-driven count notification.
    let actions_supported = probe_actions_supported().await;
    info!(actions_supported, "notification strategy chosen");

    // Subscribe to the prompt feed only in actionable mode. Subscribing
    // makes the daemon hold this uid's prompts for the full
    // prompt_timeout_secs instead of applying the no-subscriber fast
    // path - worth it exactly when the tray can answer them, harmful
    // when it cannot.
    let mut prompts: Option<Pin<Box<dyn Stream<Item = StreamItem<proto::PromptEvent>> + Send>>> =
        actions_supported.then(|| {
            Box::pin(cfc_client::stream_prompts_resilient(
                socket.clone(),
                CLIENT_ID.to_string(),
            )) as _
        });

    let mut client: Option<Client> = None;
    let mut gate = NotifyGate::default();
    let mut notifier = PromptNotifier::new(handle_tx);
    let mut was_reachable: Option<bool> = None;
    let generic = !actions_supported;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !refresh(&handle, &mut client, &socket, &mut gate, &mut was_reachable, generic).await {
                    break;
                }
            }
            item = next_prompt(&mut prompts) => match item {
                Some(StreamItem::Connected) => info!("prompt stream subscribed"),
                Some(StreamItem::Event(ev)) => notifier.on_prompt(&ev),
                Some(StreamItem::Disconnected(e)) => {
                    debug!("prompt stream lost: {e} (reconnecting)");
                    notifier.on_disconnect();
                }
                // The resilient stream only ends when dropped; treat a
                // spurious end like a disconnect and stop listening.
                None => {
                    warn!("prompt stream ended");
                    notifier.on_disconnect();
                    prompts = None;
                }
            },
            cmd = rx.recv() => match cmd {
                None => break,
                Some(Cmd::Quit) => {
                    info!("quit requested - the daemon keeps running");
                    handle.shutdown().await;
                    break;
                }
                Some(Cmd::OpenGui) => open_gui(),
                Some(Cmd::Pause(secs)) => {
                    set_paused(&mut client, &socket, true, secs).await;
                    // Refresh immediately so the menu flips to "Resume
                    // now" without waiting out the poll interval.
                    if !refresh(&handle, &mut client, &socket, &mut gate, &mut was_reachable, generic).await {
                        break;
                    }
                }
                Some(Cmd::Resume) => {
                    set_paused(&mut client, &socket, false, 0).await;
                    if !refresh(&handle, &mut client, &socket, &mut gate, &mut was_reachable, generic).await {
                        break;
                    }
                }
                Some(Cmd::PromptResult { prompt_id, exe, key }) => {
                    // Slot freed regardless of outcome. After a stream
                    // drop the id is already gone; remove is a no-op.
                    notifier.active.remove(&prompt_id);
                    if key == model::KEY_DEFAULT {
                        open_gui();
                    } else if let Some(choice) = model::choice_from_key(&key) {
                        submit_prompt_verdict(&mut client, &socket, &prompt_id, choice, &exe).await;
                    }
                    // KEY_CLOSED / anything else: dismissed or expired -
                    // the daemon's timeout_action covers it.
                }
                Some(Cmd::OverflowShown { id }) => notifier.on_overflow_shown(id),
                Some(Cmd::OverflowResult { key }) => {
                    notifier.on_overflow_result();
                    if key == model::KEY_DEFAULT {
                        open_gui();
                    }
                }
            }
        }
    }
    Ok(())
}

/// `next()` on the optional prompt stream; pends forever when there is
/// none (generic fallback mode), so the select loop needs no special
/// casing.
async fn next_prompt(
    prompts: &mut Option<Pin<Box<dyn Stream<Item = StreamItem<proto::PromptEvent>> + Send>>>,
) -> Option<StreamItem<proto::PromptEvent>> {
    match prompts {
        Some(s) => s.next().await,
        None => std::future::pending().await,
    }
}
