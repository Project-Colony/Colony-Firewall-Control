//! Desktop notifications: the actionable prompt bubbles, the overflow
//! bubble, the generic count fallback and brief follow-ups.

use anyhow::Context as _;
use cfc_client::proto;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::app::now_unix_ms;
use crate::i18n::{t, t_fmt};
use crate::model::{self, PromptPresentation};
use crate::tray::Cmd;
use crate::{answers, icon, theme};

/// Notification app name. Without it the server derives one from the
/// binary ("Colony-firewall-tray"), which reads like a process listing.
const APP_NAME: &str = "Colony Firewall";

/// Themed icon name, used as the app icon. The embedded raster from
/// [`notification_image`] is attached as well: the theme name only
/// resolves once the package has installed the SVG and the desktop's
/// icon cache has picked it up, and a firewall prompt showing a generic
/// bell is a prompt the user does not recognise.
const NOTIFY_ICON: &str = theme::ICON_NAME;

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

/// How long to wait for the notification server to answer
/// GetCapabilities before giving up and using the generic path.
const CAPABILITY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs a notify-rust call on a thread with **no tokio runtime context**.
///
/// `tokio::task::spawn_blocking` is the obvious choice and is the wrong one,
/// which is why this exists rather than the call being inlined. Threads in
/// tokio's blocking pool belong to the runtime and keep its context
/// installed; notify-rust's D-Bus calls build their own internal runtime, and
/// nesting one inside the other panics with *"Cannot start a runtime from
/// within a runtime"*.
///
/// That alone would only lose one notification. What makes it fatal is what
/// happens next: the panic poisons notify-rust's `lazy_static`, so **every
/// later notification in the process fails too**, with
/// `Once instance has previously been poisoned`. The tray keeps running,
/// keeps reporting `prompt stream subscribed`, keeps receiving prompts - and
/// silently shows nothing for the rest of its life. Observed exactly that way
/// on a live daemon: prompts arrived, timed out unanswered, and the user saw
/// no bubble at all.
///
/// A plain OS thread carries no runtime context, so the nested runtime is
/// free to exist. Each one is short-lived - a single notification, bounded by
/// its own timeout - and detached; the number in flight is bounded upstream by
/// the overflow bubble, which collapses the tail into one.
///
/// Related: [`actions_supported`] avoids `notify_rust::get_capabilities` for a
/// sibling reason. Anything in this crate that calls into notify-rust's
/// blocking D-Bus path has to answer the same question about where it runs.
fn on_notification_thread<F: FnOnce() + Send + 'static>(f: F) {
    if let Err(e) = std::thread::Builder::new()
        .name("cfc-notify".to_string())
        .spawn(f)
    {
        // Out of threads. Nothing to be done about it here, and the daemon's
        // timeout_action still covers any prompt this would have shown.
        warn!("could not spawn a notification thread: {e}");
    }
}

/// Generic on purpose: GetStatus only carries counts, not which process
/// or destination is waiting - the GUI has the details. Only shown when
/// the notification server cannot do actions (see [`crate::app::refresh`]).
pub fn notify_pending(count: u64) {
    // notify-rust's show() blocks on D-Bus; keep it off the poll loop.
    on_notification_thread(move || {
        let key = if count == 1 {
            "notify_pending_one"
        } else {
            "notify_pending_many"
        };
        let mut n = notify_rust::Notification::new();
        let _ = brand(&mut n)
            .summary(t("notify_verdict_needed"))
            .body(&t_fmt(key, &[("count", &count.to_string())]))
            .timeout(notify_rust::Timeout::Milliseconds(8000))
            .show();
    });
}

/// Appends the daemon's persist note to a confirmation, when there is one.
///
/// The note is a fact about the stored rule (today: it was bound to the
/// binary's hash, or a promised binding fell through) - never a failure,
/// which takes the rule_not_saved branch instead.
pub fn with_note(mut msg: String, note: &Option<String>) -> String {
    if let Some(n) = note.as_deref() {
        msg.push('\n');
        msg.push_str(n);
    }
    msg
}

/// A short, non-actionable follow-up ("rule created", "too late"). 5s,
/// normal urgency. The body is escaped like a prompt's (see
/// [`model::body_markup`]).
pub fn notify_brief(body: String) {
    on_notification_thread(move || {
        let mut n = notify_rust::Notification::new();
        let _ = brand(&mut n)
            .summary("Colony Firewall")
            .body(&model::body_markup(&body))
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
pub struct PromptNotifier {
    tx: mpsc::UnboundedSender<Cmd>,
    /// Prompts with an actionable notification currently on screen.
    pub active: HashMap<String, model::Slot>,
    /// Prompts folded into the overflow bubble since it appeared.
    overflow_count: u64,
    bubble: OverflowBubble,
}

impl PromptNotifier {
    pub fn new(tx: mpsc::UnboundedSender<Cmd>) -> Self {
        Self {
            tx,
            active: HashMap::new(),
            overflow_count: 0,
            bubble: OverflowBubble::Down,
        }
    }

    /// One prompt arrived: its own actionable notification while a slot
    /// is free, otherwise folded into the single overflow bubble.
    pub fn on_prompt(&mut self, ev: &proto::PromptEvent) {
        self.reclaim_expired();
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
        self.active.insert(
            prompt_id.clone(),
            model::Slot {
                deadline_unix_ms: ev.deadline_unix_ms,
                server_id: None,
            },
        );
        let exe = ev
            .process
            .as_ref()
            .map(|p| p.exe.clone())
            .unwrap_or_default();
        let tx = self.tx.clone();
        let mut notification = notify_rust::Notification::new();
        brand(&mut notification)
            .summary(&n.summary)
            .body(&n.body)
            .timeout(notify_rust::Timeout::Milliseconds(n.timeout_ms))
            // Verdicts first and short: these are what the user came
            // for, and long labels wrap the button row onto a second
            // line. "Details" is the freedesktop `default` action, so
            // clicking the bubble body opens the GUI too.
            .action(model::KEY_ALLOW_ONCE, t("action_allow_once"));
        if n.offer_block {
            notification.action(model::KEY_ALLOW, t("action_allow_always"));
        }
        notification.action(model::KEY_DENY, t("action_deny"));
        if n.offer_block {
            notification.action(model::KEY_BLOCK, t("action_block"));
        }
        notification.action(model::KEY_DEFAULT, t("action_details"));
        // Waited for past the prompt's deadline: by then the slot is
        // reclaimed and the bubble closed, so this only ends a wait whose
        // server vanished without saying so.
        let wait = Duration::from_millis(
            u64::try_from(ev.deadline_unix_ms.saturating_sub(now_unix_ms())).unwrap_or(0),
        ) + ANSWER_GRACE;
        tokio::spawn(async move {
            let key = match await_answer(notification, &prompt_id, &tx, wait).await {
                Ok(key) => key,
                Err(e) => {
                    // The daemon's timeout_action covers the prompt itself.
                    warn!("prompt notification: {e}");
                    model::KEY_CLOSED.to_string()
                }
            };
            // Failing only means the main loop is gone; the process is on
            // its way out.
            let _ = tx.send(Cmd::PromptResult {
                prompt_id,
                exe,
                key,
            });
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
                on_notification_thread(move || {
                    let shown = overflow_notification(&body).show();
                    match shown {
                        Ok(handle) => {
                            let _ = tx.send(Cmd::OverflowShown { id: handle.id() });
                            // notify-rust takes this answer from any sender
                            // (see `answers`); here that can only open the GUI.
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
                on_notification_thread(move || {
                    let _ = overflow_notification(&body).id(id).show();
                });
            }
        }
    }

    /// The overflow bubble reported its server id. Re-show if prompts
    /// piled up while it was opening, so the visible count catches up.
    pub fn on_overflow_shown(&mut self, id: u32) {
        self.bubble = OverflowBubble::Up(id);
        if self.overflow_count > 1 {
            self.show_or_update_overflow();
        }
    }

    /// The overflow bubble resolved (clicked or closed); reset so the
    /// next over-cap prompt starts a fresh bubble and count.
    pub fn on_overflow_result(&mut self) {
        self.bubble = OverflowBubble::Down;
        self.overflow_count = 0;
    }

    /// The prompt stream dropped: every pending prompt died with it.
    /// Forget them so post-reconnect prompts get fresh slots; bubbles
    /// still on screen resolve through their own wait tasks (a late
    /// click just gets accepted=false from the daemon).
    pub fn on_disconnect(&mut self) {
        self.active.clear();
        self.overflow_count = 0;
    }

    /// Frees the slots of prompts past their deadline and closes their
    /// bubbles (see [`model::reclaim_expired`]).
    pub fn reclaim_expired(&mut self) {
        close_notifications(model::reclaim_expired(&mut self.active, now_unix_ms()));
    }

    /// The bubble for `prompt_id` is on screen as `id`. If its slot was
    /// already reclaimed, the prompt is over and the bubble goes too.
    pub fn on_prompt_shown(&mut self, prompt_id: &str, id: u32) {
        match self.active.get_mut(prompt_id) {
            Some(slot) => slot.server_id = Some(id),
            None => close_notifications(vec![id]),
        }
    }
}

/// How long past a prompt's deadline its bubble's answer is waited for.
const ANSWER_GRACE: Duration = Duration::from_secs(10);

/// Shows `notification` and returns the key the user picked, as told by the
/// notification server only (see [`answers`]); [`model::KEY_CLOSED`] when it
/// closed or `wait` ran out.
async fn await_answer(
    notification: notify_rust::Notification,
    prompt_id: &str,
    tx: &mpsc::UnboundedSender<Cmd>,
    wait: Duration,
) -> anyhow::Result<String> {
    let conn = zbus::Connection::session().await?;
    let mut answers = answers::Answers::subscribe(&conn).await?;
    // show() blocks on D-Bus through zbus's own runtime, which must not be
    // entered from this one: a plain thread does it.
    let (shown_tx, shown) = tokio::sync::oneshot::channel();
    on_notification_thread(move || {
        let _ = shown_tx.send(notification.show().map(|handle| handle.id()));
    });
    let id = shown
        .await
        .context("no thread to show the notification")?
        .context("showing the notification")?;
    let _ = tx.send(Cmd::PromptShown {
        prompt_id: prompt_id.to_string(),
        id,
    });
    Ok(tokio::time::timeout(wait, answers.next_for(id))
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| model::KEY_CLOSED.to_string()))
}

/// Closes notification bubbles by server id, off the main loop.
///
/// The bubble's handle is consumed by the thread waiting on it, so this is
/// the D-Bus `CloseNotification` call made directly. The server then emits
/// `NotificationClosed`, which ends that wait.
fn close_notifications(ids: Vec<u32>) {
    if ids.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let close = async {
            let conn = zbus::Connection::session().await?;
            for id in ids {
                conn.call_method(
                    Some("org.freedesktop.Notifications"),
                    "/org/freedesktop/Notifications",
                    Some("org.freedesktop.Notifications"),
                    "CloseNotification",
                    &(id,),
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        match tokio::time::timeout(CAPABILITY_PROBE_TIMEOUT, close).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!("closing an expired prompt notification: {e}"),
            Err(_) => debug!("closing an expired prompt notification timed out"),
        }
    });
}

/// The collapsed "N more connections waiting" notification. Actionable
/// only through the default (body-click) action, which opens the GUI.
fn overflow_notification(body: &str) -> notify_rust::Notification {
    let mut n = notify_rust::Notification::new();
    brand(&mut n)
        .summary(t("overflow_title"))
        .body(body)
        .timeout(notify_rust::Timeout::Milliseconds(8000))
        .action(model::KEY_DEFAULT, t("menu_open"));
    n
}

/// Asks the notification server whether it renders action buttons.
///
/// Deliberately *not* `notify_rust::get_capabilities`: that helper is
/// blocking, and its zbus backend deadlocks when driven from inside this
/// process's tokio runtime - the tray hung at startup before ever
/// reaching its first poll. Talking to the bus directly keeps the call
/// async, and the timeout means a wedged or absent notification server
/// costs two seconds instead of the whole run.
///
/// On any failure the answer is "no actions": that keeps the tray on the
/// generic count notification and, crucially, stops it from subscribing
/// to the prompt feed - subscribing while unable to answer would make the
/// daemon hold every prompt for the full timeout instead of applying its
/// no-subscriber fast path.
pub async fn probe_actions_supported() -> bool {
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

/// Forces notify-rust's `SPEC_VERSION` while no tokio runtime exists.
///
/// This is the difference between a tray that shows prompts and one that
/// silently shows nothing, and it is worth the paragraph.
///
/// `SPEC_VERSION` is a `lazy_static` whose initialiser makes a **blocking**
/// D-Bus call (`get_server_information`). It is dereferenced whenever a
/// notification carrying image data is built - which is every bubble this tray
/// shows, because [`brand`] attaches the embedded shield. Under the `zbus`
/// backend that blocking call constructs a tokio runtime, and constructing one
/// anywhere a runtime is already entered panics with *"Cannot start a runtime
/// from within a runtime"*.
///
/// The panic is not the damage. `lazy_static` marks a panicking initialiser as
/// poisoned, so **every later deref panics too** - and since every bubble
/// derefs it, the tray never shows another notification for the rest of its
/// life. It keeps polling, keeps reporting `prompt stream subscribed`, keeps
/// receiving prompts, and stays completely silent. That is exactly how it was
/// found: on a live daemon, prompts arriving and timing out unanswered with no
/// bubble ever reaching the screen.
///
/// Touching it here, from `main` before the runtime is built, makes the one
/// blocking call on a thread that has no runtime to nest inside. Every later
/// deref is then a plain memory read.
///
/// This is why `main` builds its runtime by hand instead of using
/// `#[tokio::main]`: the attribute would wrap this line in the runtime it is
/// trying to stay out of.
/// No `cfg` guard on a feature name here, deliberately. `SPEC_VERSION` exists
/// under notify-rust's own `images_no_default_features`, which this workspace
/// turns on for it - but that is a *dependency's* feature, and `cfg(feature =
/// ...)` in this crate can only see this crate's own. Writing one would
/// compile, always evaluate false, and silently skip the warm-up: the exact
/// failure this function exists to prevent, reintroduced by the guard meant to
/// protect it. If the workspace ever drops that feature, this stops compiling,
/// which is the right way to find out.
pub fn warm_notification_spec_version() {
    let _ = *notify_rust::SPEC_VERSION;
}
