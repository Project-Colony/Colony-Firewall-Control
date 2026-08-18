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
use cfc_client::Client;
use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, TrayMethods as _};
use model::{DaemonView, NotifyGate, PauseControl};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// GetStatus poll cadence, reachable or not. Failures ride the same
/// ticker, so an absent daemon costs one connect attempt every 3s, never
/// a tight loop.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

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

/// What a menu click asks the main loop to do. Menu callbacks run on the
/// tray service task and must not block, so they only send.
#[derive(Debug, Clone, Copy)]
enum Cmd {
    Pause(u32),
    Resume,
    OpenGui,
    Quit,
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
async fn refresh(
    handle: &ksni::Handle<TrayApp>,
    client: &mut Option<Client>,
    socket: &Path,
    gate: &mut NotifyGate,
    was_reachable: &mut Option<bool>,
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
        if gate.on_poll(prompts_pending, now_unix_ms()) {
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
/// or destination is waiting - the GUI has the details.
fn notify_pending(count: u64) {
    // notify-rust's show() blocks on D-Bus; keep it off the poll loop.
    tokio::task::spawn_blocking(move || {
        let noun = if count == 1 {
            "connection"
        } else {
            "connections"
        };
        let _ = notify_rust::Notification::new()
            .summary("Colony Firewall: verdict needed")
            .body(&format!(
                "{count} {noun} waiting for a verdict — open Colony Firewall"
            ))
            .icon("colony-firewall")
            .timeout(notify_rust::Timeout::Milliseconds(8000))
            .show();
    });
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

    let mut client: Option<Client> = None;
    let mut gate = NotifyGate::default();
    let mut was_reachable: Option<bool> = None;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !refresh(&handle, &mut client, &socket, &mut gate, &mut was_reachable).await {
                    break;
                }
            }
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
                    if !refresh(&handle, &mut client, &socket, &mut gate, &mut was_reachable).await {
                        break;
                    }
                }
                Some(Cmd::Resume) => {
                    set_paused(&mut client, &socket, false, 0).await;
                    if !refresh(&handle, &mut client, &socket, &mut gate, &mut was_reachable).await {
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}
