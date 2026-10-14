//! The main loop: polls the daemon, follows its prompt stream, and carries
//! out what the menu and the notifications ask for.

use anyhow::Context as _;
use cfc_client::{proto, Client, StreamItem};
use ksni::TrayMethods as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt as _};
use tracing::{debug, info, warn};

use crate::i18n::{t, t_fmt};
use crate::model::{self, DaemonView, NotifyGate, PromptChoice};
use crate::notify::{
    notify_brief, notify_pending, probe_actions_supported, with_note, PromptNotifier,
};
use crate::prefs::TrayPreferences;
use crate::tray::{Cmd, TrayApp};
use crate::{icon, theme};

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

pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Subscriber id the daemon sees for this tray's StreamPrompts.
const CLIENT_ID: &str = "colony-firewall-tray";

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
/// resume, on a task of its own: the daemon asks polkit first, and the
/// password dialog may stay open for up to two minutes, during which the
/// main loop must keep showing prompts. The outcome comes back as
/// [`Cmd::PauseDone`].
fn spawn_set_paused(
    tx: mpsc::UnboundedSender<Cmd>,
    socket: PathBuf,
    paused: bool,
    duration_secs: u32,
) {
    tokio::spawn(async move {
        let verb = if paused { "pause" } else { "resume" };
        let result = async {
            let mut client = Client::connect_interactive(&socket).await?;
            client.set_paused(paused, duration_secs).await
        }
        .await;
        let _ = tx.send(Cmd::PauseDone(match result {
            Ok(resp) => {
                debug!(
                    paused = resp.paused,
                    resume_at_unix_ms = resp.resume_at_unix_ms,
                    "{verb} acknowledged"
                );
                Ok(())
            }
            Err(e) => {
                warn!("{verb} failed: {e}");
                Err(model::pause_failed_body(paused, &e))
            }
        }));
    });
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
        Err(e) => {
            warn!("launching {GUI_BIN}: {e} (is it installed and on PATH?)");
            // A log line is not feedback. Every route into the GUI - the tray
            // icon, the "N prompts waiting" item, the "Details" button on a
            // prompt bubble - failed by doing *nothing at all*, which reads as
            // a broken tray rather than a missing binary. Found the same way
            // as everything else here: by clicking it and watching nothing
            // happen.
            notify_brief(t_fmt("cannot_open_gui", &[("program", GUI_BIN)]));
        }
    }
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
    // A RuleScope with an empty exe_path matches EVERYTHING. As a deny that
    // is a machine with no network; as an allow it is a firewall that permits
    // every program on the system. Both persisted choices are refused here
    // rather than only the block one - the buttons are not offered for
    // exe-less prompts, but a notification server is not something to trust
    // that far.
    if matches!(
        choice,
        PromptChoice::BlockAlways | PromptChoice::AllowAlways
    ) && exe.is_empty()
    {
        warn!(
            prompt_id,
            ?choice,
            "persisted verdict without an exe path ignored"
        );
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
    // Whether a standing rule was even asked for. `verdict_for` degrades a
    // persisted choice to a one-shot verdict when the exe cannot scope a rule
    // ("<unknown>", a relative execve-fallback path) - and the Allow button is
    // offered on every prompt, so that path is reachable from a stock
    // notification server, not only a misbehaving one.
    let wanted_rule = scope.is_some();
    match c.submit_verdict(prompt_id, action, duration, scope).await {
        Ok(o) if o.accepted => {
            debug!(prompt_id, ?choice, "verdict accepted");
            // Both persisted choices confirm. Allow now grants standing
            // access, so saying so is what makes an accidental click
            // something the user can notice and undo.
            //
            // Confirming on `accepted` alone was a lie waiting to happen: the
            // verdict reaching the connection and the rule reaching the disk
            // are separate outcomes, and a full or read-only /var/lib leaves
            // the first true and the second false. Announcing a standing rule
            // that does not exist is worse than announcing nothing - the user
            // stops watching for the prompt that will come back.
            //
            // Keying the confirmation off the button alone was the same lie
            // one branch over: the silent degrade above submits no scope, the
            // client then reports `rule_persisted: None` (nothing was asked),
            // and the None arm read "Rule created: allow <unknown> always"
            // for a verdict that created nothing.
            match (choice, o.rule_persisted) {
                (PromptChoice::DenyOnce | PromptChoice::AllowOnce, _) => {}
                // A persisted choice that fell back to answering once: no
                // rule was requested, so no rule may be announced - and
                // silence would read as success to the user who clicked
                // Allow expecting to never be asked again.
                _ if !wanted_rule => {
                    info!(
                        prompt_id,
                        ?choice,
                        exe,
                        "persisted choice degraded to a one-shot verdict"
                    );
                    notify_brief(model::one_shot_fallback(choice, exe));
                }
                // `None` here is a daemon that did not say - an older build,
                // most likely one not yet restarted after an upgrade.
                // Reporting a loss on silence would cry wolf on every single
                // answer.
                (PromptChoice::BlockAlways, Some(true) | None) => {
                    notify_brief(with_note(model::block_confirmation(exe), &o.persist_note))
                }
                (PromptChoice::AllowAlways, Some(true) | None) => {
                    // The note is the daemon telling the user something true
                    // about the rule it just stored - today, that a
                    // user-writable binary was hash-bound and a swapped file
                    // will prompt again. Dropping it would leave "Allowed
                    // always" quietly meaning less than it reads.
                    notify_brief(with_note(model::allow_confirmation(exe), &o.persist_note))
                }
                (_, Some(false)) => {
                    warn!(prompt_id, ?choice, "verdict applied but no rule was saved");
                    notify_brief(model::rule_not_saved(exe, o.persist_error.as_deref()));
                }
            }
        }
        Ok(_) => {
            info!(prompt_id, "verdict too late - prompt already resolved");
            notify_brief(t("verdict_too_late").into());
        }
        Err(e) => {
            warn!("submitting verdict: {e}");
            if let Some(body) = model::verdict_refused_body(&e) {
                notify_brief(body);
            }
            *client = None;
        }
    }
}

pub async fn run(sealed: std::io::Result<()>) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    if let Err(error) = sealed {
        warn!("could not seal the process ({error}); the daemon will treat this tray as read-only");
    }
    // The app's choices, as they were when the tray started.
    let prefs = TrayPreferences::load();
    prefs.apply_language();

    let socket = socket_path_from_env();
    info!(socket = %socket.display(), "starting colony-firewall-tray");

    let (tx, mut rx) = mpsc::unbounded_channel();
    // Notification wait tasks route their results over the same channel
    // as menu clicks; the main loop is the only place the client lives.
    let handle_tx = tx.clone();
    let pause_tx = tx.clone();
    // A pause or resume is waiting on the daemon (and maybe on a password
    // dialog); further clicks are ignored until it answers.
    let mut pause_in_flight = false;
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
        // Resolved before the tray registers, so the host's first
        // property read already sees it.
        icon_theme_path: theme::runtime_icon_theme_path(),
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
    // With prompt notifications off in Preferences, neither: the tray only
    // shows its icon and menu.
    let notify_prompts = prefs.prompt_notifications;
    let actions_supported = notify_prompts && probe_actions_supported().await;
    info!(
        notify_prompts,
        actions_supported, "notification strategy chosen"
    );

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
    let generic = notify_prompts && !actions_supported;
    // Set once the tray has said its binary was replaced under it.
    let mut told_replaced = false;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                notifier.reclaim_expired();
                // After an upgrade the daemon refuses this process: say so
                // instead of failing every answer and pause quietly.
                if !told_replaced
                    && std::fs::read_link("/proc/self/exe").is_ok_and(|exe| model::replaced_on_disk(&exe))
                {
                    told_replaced = true;
                    notify_brief(model::replaced_body());
                }
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
                Some(Cmd::Pause(_) | Cmd::Resume) if pause_in_flight => {
                    debug!("pause or resume already waiting; click ignored");
                }
                Some(Cmd::Pause(secs)) => {
                    pause_in_flight = true;
                    spawn_set_paused(pause_tx.clone(), socket.clone(), true, secs);
                }
                Some(Cmd::Resume) => {
                    pause_in_flight = true;
                    spawn_set_paused(pause_tx.clone(), socket.clone(), false, 0);
                }
                Some(Cmd::PauseDone(result)) => {
                    pause_in_flight = false;
                    if let Err(body) = result {
                        notify_brief(body);
                    }
                    // Refresh immediately so the menu flips to "Resume
                    // now" without waiting out the poll interval.
                    if !refresh(&handle, &mut client, &socket, &mut gate, &mut was_reachable, generic).await {
                        break;
                    }
                }
                Some(Cmd::PromptResult { prompt_id, exe, key }) => {
                    // Slot freed regardless of outcome. After a stream
                    // drop the id is already gone; remove is a no-op.
                    let current = notifier.active.remove(&prompt_id).is_some();
                    if key == model::KEY_DEFAULT {
                        open_gui();
                    } else if current {
                        if let Some(choice) = model::choice_from_key(&key) {
                        submit_prompt_verdict(&mut client, &socket, &prompt_id, choice, &exe).await;
                        }
                    }
                    // KEY_CLOSED / anything else: dismissed or expired -
                    // the daemon's timeout_action covers it.
                }
                Some(Cmd::PromptShown { prompt_id, id }) => notifier.on_prompt_shown(&prompt_id, id),
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
