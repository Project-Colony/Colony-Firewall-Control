//! The tray item itself: what the StatusNotifierItem shows and what its
//! menu offers. Clicks only send a [`Cmd`] to the main loop in [`crate::app`].

use ksni::menu::{StandardItem, SubMenu};
use ksni::MenuItem;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::app::now_unix_ms;
use crate::model::{self, DaemonView, PauseControl};
use crate::theme;

/// What a menu click or a resolved notification asks the main loop to do.
/// Menu callbacks run on the tray service task and notification waits on
/// blocking tasks; neither may touch the client, so they only send.
#[derive(Debug, Clone)]
pub enum Cmd {
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
    /// An actionable prompt notification was shown; `id` is the server id
    /// needed to close it once its prompt is over.
    PromptShown {
        prompt_id: String,
        id: u32,
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
    /// A pause or resume request finished; `Err` is the reason to show.
    PauseDone(Result<(), String>),
}

pub struct TrayApp {
    pub view: DaemonView,
    pub tx: mpsc::UnboundedSender<Cmd>,
    pub icons: Vec<ksni::Icon>,
    /// Runtime directory exported as the SNI `IconThemePath`; `None`
    /// (the common case) exports nothing. See [`theme`].
    pub icon_theme_path: Option<PathBuf>,
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
        // Installed by the package to hicolor/scalable/apps; when it is
        // not, `icon_theme_path` below makes the same name resolvable.
        theme::ICON_NAME.into()
    }

    fn icon_theme_path(&self) -> String {
        // Empty (the ksni default, what the tray always exported) unless
        // the startup probe found no installed theme icon - the fallback
        // for hosts that honour icon_name only and never read the pixmap.
        self.icon_theme_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        // Embedded fallback for hosts/setups without the theme icon.
        self.icons.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: theme::ICON_NAME.into(),
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
