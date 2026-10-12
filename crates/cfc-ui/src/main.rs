//! Colony Firewall Control - UI entry point.

mod app;
mod editor;
mod format;
mod session_stats;
mod status_log;
mod streams;
mod theme;
mod views;

use app::App;

fn main() -> iced::Result {
    if let Some(line) = cfc_client::version_line(
        std::env::args_os(),
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
    ) {
        println!("{line}");
        return Ok(());
    }
    // First, before any thread, display or daemon connection exists: the
    // daemon accepts changes only from a sealed, installed copy of this app.
    let sealed = cfc_client::seal_official_process();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,cfc_ui=info")),
        )
        .init();
    if let Err(error) = sealed {
        tracing::warn!(
            "could not seal the process ({error}); the daemon will treat this app as read-only"
        );
    }

    // Parchment is this app's identity, and stays the theme until the user
    // picks another.
    colony_ui::set_active_theme("parchment", "light");
    colony_ui::fonts::BYTES
        .into_iter()
        .fold(
            iced::application(App::new, App::update, App::view),
            |app, font| app.font(font),
        )
        .default_font(colony_ui::ui_font())
        .title(App::title)
        .theme(App::theme)
        .subscription(App::subscription)
        .run()
}
