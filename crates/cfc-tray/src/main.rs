//! Colony Firewall Control - system tray icon.
//!
//! A StatusNotifierItem (the KDE/freedesktop tray spec, spoken natively by
//! KDE and by GNOME through the AppIndicator extension) showing the
//! daemon's state at a glance: enforcing / paused / unreachable, the
//! number of prompts waiting for a verdict, quick pause/resume, and a
//! left-click that opens the GUI. It only *talks* to the daemon over the
//! same control socket as the GUI and CLI - quitting the tray never
//! touches the daemon.

mod answers;
mod app;
mod icon;
mod model;
mod notify;
mod theme;
mod tray;

use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    if let Some(line) = cfc_client::version_line(
        std::env::args_os(),
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
    ) {
        println!("{line}");
        return Ok(());
    }
    // First, before D-Bus or the runtime exist: the daemon accepts answers
    // and pause requests only from a sealed, installed copy of this tray.
    let sealed = cfc_client::seal_official_process();
    notify::warm_notification_spec_version();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?
        .block_on(app::run(sealed))
}
