//! Colony Firewall Control - CLI control tool.

mod error;
mod events;
mod humantime;
mod live;
mod output;
mod prompts;
mod rules;
mod tty;

use crate::error::{CliError, CliResult};
use crate::output::OutputFormat;
use anyhow::Context;
use cfc_client::{convert, proto, Client};
use clap::{CommandFactory, Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;

const LONG_ABOUT: &str = "\
Control the Colony Firewall daemon.

Exit codes:
  0  success
  1  runtime or RPC error (including an ambiguous rule reference)
  2  usage error (bad flags or arguments)
  3  not found (no rule matches the given id, id prefix or name)
  4  daemon unreachable (not running, stale socket, or no socket permission)

Anywhere a rule id is accepted you may also pass a unique id prefix or the
rule's name.";

#[derive(Debug, Parser)]
#[command(
    name = "cfc",
    version,
    about = "Control the Colony Firewall daemon",
    long_about = LONG_ABOUT
)]
struct Cli {
    #[arg(long, global = true, default_value = cfc_proto::DEFAULT_SOCKET_PATH)]
    socket: Option<PathBuf>,

    /// Output format. `json` is machine-readable; streaming commands emit
    /// NDJSON (one object per line).
    #[arg(short = 'o', long, value_enum, global = true)]
    output: Option<OutputFormat>,

    /// Shorthand for `--output json`.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Command,
}

impl Cli {
    fn format(&self) -> OutputFormat {
        if self.json {
            OutputFormat::Json
        } else {
            self.output.unwrap_or(OutputFormat::Human)
        }
    }

    fn socket(&self) -> PathBuf {
        self.socket
            .clone()
            .unwrap_or_else(|| PathBuf::from(cfc_proto::DEFAULT_SOCKET_PATH))
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show daemon status.
    Status,
    /// Rules CRUD.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// Answer connection prompts from this terminal.
    ///
    /// Without a subscriber the daemon applies its no-UI action to every
    /// prompt, so this is how a headless machine gets a say.
    ///
    /// Keys: a=allow, d=deny, r=reject, s=skip (let it time out), q=quit.
    /// Then a duration (1=once, 2=until restart, 3=always) and, for the
    /// last two, a scope (1=this app + port, 2=this app, 3=this
    /// destination). "Once" answers the prompt without writing a rule.
    ///
    /// On a terminal each key takes effect immediately. When stdin is a
    /// pipe there is no raw mode, so answers are read a line at a time and
    /// must be confirmed with Enter. With --json no questions are asked:
    /// prompts are printed as NDJSON and only --auto-allow / --auto-deny
    /// answer them.
    Prompts(prompts::PromptArgs),
    /// Stream live connections to the terminal.
    Live {
        /// Reconnect automatically when the daemon restarts. Without it,
        /// losing the stream is an error (exit 1).
        #[arg(short, long)]
        follow: bool,

        #[command(flatten)]
        filters: live::LiveFilters,
    },
    /// Query the persisted verdict log ("what did this app contact?").
    Log(events::LogArgs),
    /// Temporarily allow all flows.
    Pause {
        /// How long to stay paused, e.g. 30m, 2h. Omitted means the
        /// daemon's configured default; the daemon clamps the maximum.
        #[arg(long = "for", value_name = "DURATION",
              value_parser = humantime::parse_duration_arg)]
        duration: Option<std::time::Duration>,
    },
    /// Resume normal filtering immediately.
    Resume,
    /// Print a shell completion script.
    #[command(hide = true)]
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the roff man page to stdout.
    #[command(hide = true)]
    Man {
        /// Write one page per (sub)command into this directory instead:
        /// cfc.1, cfc-rules.1, cfc-rules-list.1, ... This is what the
        /// SUBCOMMANDS cross references in cfc.1 point at.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum RulesCmd {
    /// List all persistent rules.
    List,
    /// Show every field of one rule.
    Show { id: String },
    /// Delete a rule.
    Remove { id: String },
    /// Flip a rule's enabled state.
    Toggle { id: String },
    /// Enable a rule (idempotent).
    Enable { id: String },
    /// Disable a rule (idempotent).
    Disable { id: String },
    /// Add a new rule.
    Add(rules::AddArgs),
    /// Export all rules as JSON to stdout.
    Export {
        /// Write to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import rules from a JSON file (or stdin if omitted).
    Import {
        /// File to read; reads stdin if omitted.
        file: Option<PathBuf>,
        /// Replace mode: make the rule set match the file. Nothing is applied unless every rule reads cleanly; rules in the file are written first, then any not in it are removed.
        #[arg(long)]
        replace: bool,
    },
    /// Import rules from an opensnitch rules directory or single JSON file.
    ImportOpensnitch {
        /// Path to opensnitch rules dir (e.g. /etc/opensnitchd/rules) or a single .json.
        path: PathBuf,
        /// Replace mode: make the rule set match the file. Nothing is applied unless every rule reads cleanly; rules in the file are written first, then any not in it are removed.
        #[arg(long)]
        replace: bool,
    },
    /// Install a small set of sensible starter rules: system DNS, NTP
    /// (timesyncd/chrony), DHCP clients (dhcpcd/NetworkManager/networkd),
    /// pacman/paru HTTPS, and the SSH client.
    BootstrapDefaults {
        /// List what would be installed without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Install or remove a named set of allow rules.
    ///
    /// Every outbound rule in a bundle names an executable - there is no way
    /// to write "allow tcp/443" here, because a payload phoning home uses 443
    /// exactly like a browser does and a port-shaped rule cannot tell them
    /// apart. Inbound entries are the exception, and not a loophole: the
    /// connection arrives before any process has accepted it, so there is no
    /// executable to name and the port itself is the narrowing predicate. An
    /// inbound entry with neither is refused.
    ///
    /// Entries whose program is not installed on this machine are skipped and
    /// reported, so "4 added, 3 skipped" is a normal outcome.
    Bundle {
        #[command(subcommand)]
        cmd: BundleCmd,
    },
}

#[derive(Subcommand, Debug)]
enum BundleCmd {
    /// Show the bundles, how many of their entries apply here, and how many
    /// are already installed.
    List,
    /// Install a bundle's rules.
    Add {
        /// Bundle name (see `cfc rules bundle list`).
        name: String,
        /// Show what would be installed without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the rules a bundle installed.
    ///
    /// Matches the bundle's exact rule names, never a prefix, so a rule you
    /// wrote yourself is never caught by it.
    Remove {
        /// Bundle name (see `cfc rules bundle list`).
        name: String,
        /// Show what would be removed without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Parsing is handled by hand so the usage exit code is part of the
    // documented contract rather than a clap default that could drift.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            // `--help` / `--version` are successes printed to stdout.
            std::process::exit(if e.use_stderr() {
                error::EXIT_USAGE
            } else {
                error::EXIT_OK
            });
        }
    };
    let code = match run(cli).await {
        Ok(()) => error::EXIT_OK,
        Err(e) => {
            eprintln!("cfc: {e}");
            e.exit_code()
        }
    };
    // stdout is block-buffered when piped; process::exit skips the
    // destructors that would otherwise flush it.
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

async fn run(cli: Cli) -> CliResult {
    let format = cli.format();
    let socket = cli.socket();

    match cli.cmd {
        // Commands that must work with no daemon at all (packaging, docs).
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
            Ok(())
        }
        Command::Man { dir } => match dir {
            Some(dir) => {
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
                clap_mangen::generate_to(Cli::command(), &dir)
                    .with_context(|| format!("writing man pages to {}", dir.display()))?;
                Ok(())
            }
            None => {
                let man = clap_mangen::Man::new(Cli::command());
                man.render(&mut std::io::stdout())
                    .context("rendering the man page")?;
                Ok(())
            }
        },
        // `live --follow` owns its own (re)connection, so it must not fail
        // just because the daemon is not up yet.
        Command::Live {
            follow: true,
            filters,
        } => live::run_follow(&socket, filters, format).await,
        cmd => {
            let mut client = Client::connect(&socket).await?;
            dispatch(cmd, &mut client, &socket, format).await
        }
    }
}

async fn dispatch(
    cmd: Command,
    client: &mut Client,
    socket: &std::path::Path,
    format: OutputFormat,
) -> CliResult {
    let client = &mut *client;
    match cmd {
        Command::Status => cmd_status(client, format).await,
        Command::Rules { cmd } => match cmd {
            RulesCmd::List => rules::list(client, format).await,
            RulesCmd::Show { id } => rules::show(client, &id, format).await,
            RulesCmd::Remove { id } => rules::remove(client, &id, format).await,
            RulesCmd::Toggle { id } => rules::set_enabled(client, &id, None, format).await,
            RulesCmd::Enable { id } => rules::set_enabled(client, &id, Some(true), format).await,
            RulesCmd::Disable { id } => rules::set_enabled(client, &id, Some(false), format).await,
            RulesCmd::Add(args) => rules::add(client, args, format).await,
            RulesCmd::Export { out } => rules::export(client, out).await,
            RulesCmd::Import { file, replace } => {
                rules::import(client, file, replace, format).await
            }
            RulesCmd::ImportOpensnitch { path, replace } => {
                rules::import_opensnitch(client, path, replace, format).await
            }
            RulesCmd::Bundle { cmd } => match cmd {
                BundleCmd::List => rules::bundle_list(client, format).await,
                BundleCmd::Add { name, dry_run } => {
                    rules::bundle_add(client, &name, dry_run, format).await
                }
                BundleCmd::Remove { name, dry_run } => {
                    rules::bundle_remove(client, &name, dry_run, format).await
                }
            },
            RulesCmd::BootstrapDefaults { dry_run } => {
                rules::bootstrap_defaults(client, dry_run, format).await
            }
        },
        Command::Prompts(args) => prompts::run(socket, client, args, format).await,
        Command::Live { filters, .. } => live::run_once(client, filters, format).await,
        Command::Log(args) => events::run(client, args, format).await,
        Command::Pause { duration } => cmd_pause(client, duration, format).await,
        Command::Resume => cmd_resume(client, format).await,
        Command::Completions { .. } | Command::Man { .. } => unreachable!("handled by run()"),
    }
}

// ---------------------------------------------------------------------------
// status / pause / resume
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
struct StatusJson {
    version: String,
    uptime_seconds: u64,
    enforcing: bool,
    enforcement: String,
    paused: bool,
    resume_at_unix_ms: i64,
    resume_at: Option<String>,
    resume_in_seconds: Option<i64>,
    rules_count: u64,
    skipped_rules: u64,
    prompts_pending: u64,
    connections_seen: u64,
    connections_allowed: u64,
    connections_denied: u64,
    timeout_action: String,
    no_ui_action: String,
    prompt_timeout_secs: u32,
    warnings: Vec<String>,
}

fn status_json(s: &proto::StatusResponse, now_unix_ms: i64) -> StatusJson {
    StatusJson {
        version: s.version.clone(),
        uptime_seconds: s.uptime_seconds,
        enforcing: s.enforcing,
        enforcement: s.enforcement.clone(),
        paused: s.paused,
        resume_at_unix_ms: s.resume_at_unix_ms,
        resume_at: output::rfc3339(s.resume_at_unix_ms),
        resume_in_seconds: (s.paused && s.resume_at_unix_ms > 0)
            .then(|| ((s.resume_at_unix_ms - now_unix_ms).max(0)) / 1000),
        rules_count: s.rules_count,
        skipped_rules: s.skipped_rules,
        prompts_pending: s.prompts_pending,
        connections_seen: s.connections_seen,
        connections_allowed: s.connections_allowed,
        connections_denied: s.connections_denied,
        timeout_action: convert::action_label(s.timeout_action).to_string(),
        no_ui_action: convert::action_label(s.no_ui_action).to_string(),
        prompt_timeout_secs: s.prompt_timeout_secs,
        warnings: status_warnings(s),
    }
}

/// Conditions the user has to know about, in both output modes.
fn status_warnings(s: &proto::StatusResponse) -> Vec<String> {
    let mut w = Vec::new();
    if !s.enforcing {
        w.push(
            "no packets seen - is the nftables rule loaded? see docs/TROUBLESHOOTING.md"
                .to_string(),
        );
    }
    if s.skipped_rules > 0 {
        w.push(format!(
            "{} rule(s) on disk could not be loaded and are NOT being enforced",
            s.skipped_rules
        ));
    }
    w
}

/// The paused cell: "no", or "yes (resumes in 4m 30s at 18:20:11)".
/// Says where enforcement lives, and whether it outlives the daemon.
///
/// Spelled out rather than printed raw because the word alone does not carry
/// the consequence. "process" and "pinned" both mean the kernel is refusing
/// connect() - the difference is only what happens when this daemon stops, and
/// that difference is the whole reason the layer exists.
fn enforcement_cell(level: &str) -> String {
    match level {
        "pinned" => "yes (pinned - survives this daemon)".to_string(),
        "inherited" => "yes (inherited from a previous daemon's pins)".to_string(),
        "process" => "yes (this process only - lifted when it stops)".to_string(),
        "unavailable" => "no (the kernel refused the programs)".to_string(),
        "off" => "no (not enabled, or the object never loaded)".to_string(),
        // A daemon newer than this CLI. Say what it said rather than guess.
        other => other.to_string(),
    }
}

fn paused_cell(s: &proto::StatusResponse, now_unix_ms: i64) -> String {
    if !s.paused {
        return "no".to_string();
    }
    if s.resume_at_unix_ms <= 0 {
        return "yes".to_string();
    }
    let left = ((s.resume_at_unix_ms - now_unix_ms).max(0)) / 1000;
    format!(
        "yes (resumes in {} at {})",
        humantime::format_secs(left),
        output::local_time(s.resume_at_unix_ms)
    )
}

async fn cmd_status(client: &mut Client, format: OutputFormat) -> CliResult {
    let s = client.status().await?;
    let now = chrono::Utc::now().timestamp_millis();

    if format.is_json() {
        return output::print_json(&status_json(&s, now));
    }

    println!("version          {}", s.version);
    println!(
        "uptime           {}",
        humantime::format_secs(s.uptime_seconds as i64)
    );
    println!(
        "enforcing        {}",
        if s.enforcing { "yes" } else { "no" }
    );
    println!("  in-kernel      {}", enforcement_cell(&s.enforcement));
    println!("paused           {}", paused_cell(&s, now));
    println!("rules            {}", s.rules_count);
    println!("prompts pending  {}", s.prompts_pending);
    println!(
        "connections      {} (allowed: {}, denied: {})",
        s.connections_seen, s.connections_allowed, s.connections_denied
    );
    println!(
        "prompt policy    {}s timeout -> {}, no UI -> {}",
        s.prompt_timeout_secs,
        convert::action_label(s.timeout_action),
        convert::action_label(s.no_ui_action)
    );
    for w in status_warnings(&s) {
        eprintln!("warning: {w}");
    }
    Ok(())
}

async fn cmd_pause(
    client: &mut Client,
    duration: Option<std::time::Duration>,
    format: OutputFormat,
) -> CliResult {
    // 0 means "use the daemon's configured default": the daemon owns both
    // the default and the maximum, and reports the real deadline.
    let secs = match duration {
        Some(d) => u32::try_from(d.as_secs())
            .map_err(|_| CliError::runtime("--for is too large (max ~136 years)"))?,
        None => 0,
    };
    let resp = client.set_paused(true, secs).await?;
    let now = chrono::Utc::now().timestamp_millis();
    let left = ((resp.resume_at_unix_ms - now).max(0)) / 1000;

    if format.is_json() {
        return output::print_json(&serde_json::json!({
            "paused": resp.paused,
            "resume_at_unix_ms": resp.resume_at_unix_ms,
            "resume_at": output::rfc3339(resp.resume_at_unix_ms),
            "resume_in_seconds": left,
        }));
    }
    if resp.resume_at_unix_ms > 0 {
        println!(
            "paused; auto-resumes at {} (in {})",
            output::local_time(resp.resume_at_unix_ms),
            humantime::format_secs(left)
        );
    } else {
        println!("paused = {}", resp.paused);
    }
    Ok(())
}

async fn cmd_resume(client: &mut Client, format: OutputFormat) -> CliResult {
    let resp = client.set_paused(false, 0).await?;
    if format.is_json() {
        return output::print_json(&serde_json::json!({ "paused": resp.paused }));
    }
    println!("paused = {}", resp.paused);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn status(paused: bool, resume_at: i64) -> proto::StatusResponse {
        proto::StatusResponse {
            version: "0.1.0".into(),
            uptime_seconds: 3661,
            rules_count: 12,
            prompts_pending: 1,
            connections_seen: 100,
            connections_allowed: 90,
            connections_denied: 10,
            paused,
            resume_at_unix_ms: resume_at,
            timeout_action: proto::Action::Deny as i32,
            no_ui_action: proto::Action::Allow as i32,
            prompt_timeout_secs: 15,
            skipped_rules: 0,
            enforcing: true,
            enforcement: "pinned".to_string(),
        }
    }

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn json_is_a_shorthand_for_output_json() {
        let cli = Cli::parse_from(["cfc", "--json", "status"]);
        assert!(cli.format().is_json());
        let cli = Cli::parse_from(["cfc", "-o", "json", "status"]);
        assert!(cli.format().is_json());
        let cli = Cli::parse_from(["cfc", "status"]);
        assert!(!cli.format().is_json());
        // --json wins over an explicit human, so `--json` always means JSON.
        let cli = Cli::parse_from(["cfc", "-o", "human", "--json", "status"]);
        assert!(cli.format().is_json());
    }

    #[test]
    fn global_flags_work_after_the_subcommand() {
        let cli = Cli::parse_from(["cfc", "rules", "list", "--json", "--socket", "/tmp/x.sock"]);
        assert!(cli.format().is_json());
        assert_eq!(cli.socket(), PathBuf::from("/tmp/x.sock"));
    }

    #[test]
    fn socket_defaults_to_the_shared_constant() {
        let cli = Cli::parse_from(["cfc", "status"]);
        assert_eq!(cli.socket(), PathBuf::from(cfc_proto::DEFAULT_SOCKET_PATH));
    }

    #[test]
    fn pause_for_accepts_humantime() {
        let cli = Cli::parse_from(["cfc", "pause", "--for", "30m"]);
        match cli.cmd {
            Command::Pause { duration } => {
                assert_eq!(duration, Some(std::time::Duration::from_secs(1800)))
            }
            other => panic!("expected pause, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["cfc", "pause", "--for", "banana"]).is_err());
    }

    #[test]
    fn auto_allow_and_auto_deny_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["cfc", "prompts", "--auto-deny", "--auto-allow"]).is_err());
        assert!(Cli::try_parse_from(["cfc", "prompts", "--auto-deny"]).is_ok());
    }

    #[test]
    fn exit_code_contract_is_documented_in_the_long_help() {
        for line in [
            "0  success",
            "1  runtime",
            "2  usage",
            "3  not found",
            "4  daemon unreachable",
        ] {
            assert!(LONG_ABOUT.contains(line), "missing {line:?} from --help");
        }
    }

    #[test]
    fn paused_cell_counts_down() {
        let now = 1_700_000_000_000;
        assert_eq!(paused_cell(&status(false, 0), now), "no");
        assert_eq!(paused_cell(&status(true, 0), now), "yes");
        let cell = paused_cell(&status(true, now + 270_000), now);
        assert!(cell.starts_with("yes (resumes in 4m 30s at "), "{cell}");
        // A deadline already in the past must not render as negative.
        let cell = paused_cell(&status(true, now - 5_000), now);
        assert!(cell.contains("resumes in 0s"), "{cell}");
    }

    #[test]
    fn warnings_fire_on_not_enforcing_and_skipped_rules() {
        let mut s = status(false, 0);
        assert!(status_warnings(&s).is_empty());

        s.enforcing = false;
        let w = status_warnings(&s);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("nftables"));
        assert!(w[0].contains("docs/TROUBLESHOOTING.md"));

        s.skipped_rules = 3;
        let w = status_warnings(&s);
        assert_eq!(w.len(), 2);
        assert!(w[1].contains("3 rule(s)"));
        assert!(w[1].contains("NOT being enforced"));
    }

    #[test]
    fn status_json_shape_carries_the_wave_three_fields() {
        let now = 1_700_000_000_000;
        let mut s = status(true, now + 60_000);
        s.skipped_rules = 2;
        s.enforcing = false;
        let v = serde_json::to_value(status_json(&s, now)).unwrap();

        assert_eq!(v["version"], "0.1.0");
        assert_eq!(v["enforcing"], false);
        assert_eq!(v["paused"], true);
        assert_eq!(v["resume_in_seconds"], 60);
        assert!(v["resume_at"].as_str().unwrap().starts_with("2023-"));
        assert_eq!(v["skipped_rules"], 2);
        assert_eq!(v["timeout_action"], "deny");
        assert_eq!(v["no_ui_action"], "allow");
        assert_eq!(v["prompt_timeout_secs"], 15);
        assert_eq!(v["warnings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn status_json_omits_resume_fields_when_running() {
        let now = 1_700_000_000_000;
        let v = serde_json::to_value(status_json(&status(false, 0), now)).unwrap();
        assert_eq!(v["resume_at"], serde_json::Value::Null);
        assert_eq!(v["resume_in_seconds"], serde_json::Value::Null);
        assert_eq!(v["warnings"].as_array().unwrap().len(), 0);
    }
}
