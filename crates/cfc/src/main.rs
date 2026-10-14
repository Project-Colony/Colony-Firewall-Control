//! Colony Firewall Control - CLI control tool.

mod commands;
mod confinement;
mod error;
mod events;
mod humantime;
mod live;
mod output;
mod prompts;
mod rules;
mod status;
mod tty;

fn main() {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() == Some(std::ffi::OsStr::new("__cfc_application_gate")) {
        let id = args.next();
        let result = match (id.as_deref().and_then(std::ffi::OsStr::to_str), args.next()) {
            (Some(id), None) => confinement::gate(id),
            _ => Err(anyhow::anyhow!("invalid application gate invocation")),
        };
        // The unit sends this stream to the journal; the launcher points there.
        if let Err(error) = result {
            eprintln!("cfc: {}", output::terminal_safe(&format!("{error:#}")));
        }
        std::process::exit(confinement::GATE_REFUSED);
    }
    commands::cli_main();
}
