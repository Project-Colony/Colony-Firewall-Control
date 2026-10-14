//! The command line: its clap definition, parsing, exit codes and the
//! dispatch to each subcommand.

use crate::error::{self, CliResult};
use crate::output::{self, OutputFormat};
use crate::{confinement, events, humantime, live, prompts, rules, status};
use anyhow::Context;
use cfc_client::Client;
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
rule's name.

Changing the firewall (adding, editing, removing or importing rules, pause and
resume, answering prompts) needs root: run cfc with sudo, or use the Colony
Firewall app or tray. As a regular user cfc is read-only and the daemon
answers a change with the reason it refused it (exit 1).";

#[derive(Debug, Parser)]
#[command(
    name = "cfc",
    version,
    about = "Control the Colony Firewall daemon",
    long_about = LONG_ABOUT
)]
struct Cli {
    #[arg(long, global = true, default_value = cfc_proto::DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

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
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Launch or stop an explicitly confined application tree (administrator only).
    Applications {
        #[command(subcommand)]
        cmd: ApplicationsCmd,
    },
    /// Show daemon status.
    Status,
    /// Rules CRUD (changes need sudo).
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },
    /// Answer connection prompts from this terminal (needs sudo).
    ///
    /// Without a subscriber the daemon applies its no-UI action to every
    /// prompt, so this is how a headless machine gets a say: run it as
    /// `sudo cfc prompts`. As a regular user it only watches; the daemon
    /// neither counts it as a UI nor accepts its answers.
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
    /// Temporarily allow all flows (needs sudo; the app and tray ask for an
    /// administrator password instead).
    Pause {
        /// How long to stay paused, e.g. 30m, 2h. Omitted means the
        /// daemon's configured default; the daemon clamps the maximum.
        #[arg(long = "for", value_name = "DURATION",
              value_parser = humantime::parse_duration)]
        duration: Option<std::time::Duration>,
    },
    /// Resume normal filtering immediately (needs sudo).
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
    /// Delete a rule (needs sudo).
    Remove { id: String },
    /// Flip a rule's enabled state (needs sudo).
    Toggle { id: String },
    /// Enable a rule (idempotent; needs sudo).
    Enable { id: String },
    /// Disable a rule (idempotent; needs sudo).
    Disable { id: String },
    /// Add a new rule (needs sudo).
    Add(rules::AddArgs),
    /// Export all rules as JSON to stdout.
    Export {
        /// Write to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import rules from a JSON file, or stdin if omitted (needs sudo).
    Import {
        /// File to read; reads stdin if omitted.
        file: Option<PathBuf>,
        /// Replace mode: make the rule set match the source in one atomic batch. Every source rule must validate before anything changes.
        #[arg(long)]
        replace: bool,
    },
    /// Import rules from an opensnitch rules directory or single JSON file (needs sudo).
    ///
    /// Rules with no faithful equivalent here (hostnames, regexps, unknown
    /// operands) cannot be converted. By default one of them stops the import
    /// before anything changes, because dropping a narrow deny while importing
    /// a broad allow imports a wider policy than the source.
    ImportOpensnitch {
        /// Path to opensnitch rules dir (e.g. /etc/opensnitchd/rules) or a single .json.
        path: PathBuf,
        /// Replace mode: make the rule set match the source in one atomic batch. Every source rule must validate before anything changes.
        #[arg(long)]
        replace: bool,
        /// Import the rules that convert and skip, with a reason, those that do not.
        #[arg(long, conflicts_with = "replace")]
        skip_unconvertible: bool,
    },
    /// Install a small set of sensible starter rules (needs sudo): system DNS, NTP
    /// (timesyncd/chrony), DHCP clients (dhcpcd/NetworkManager/networkd),
    /// pacman/paru HTTPS, and the SSH client.
    BootstrapDefaults {
        /// List what would be installed without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Install or remove a named set of allow rules (needs sudo).
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
    /// Matches the ids the bundle gave its rules, never a name or a prefix,
    /// so a rule you wrote yourself is never caught by it. Rules seeded
    /// before 0.7.0 are removed only while identical to what the entry
    /// installs now or installed then.
    /// A bundle rule you edited into a deny or reject is kept.
    Remove {
        /// Bundle name (see `cfc rules bundle list`).
        name: String,
        /// Show what would be removed without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ApplicationsCmd {
    /// Start a fresh headless application with no network permission by default.
    Run {
        /// Administrator-owned runtime containing only sealed directories and regular files.
        #[arg(long)]
        runtime: PathBuf,
        /// Authorize an exact numeric peer IP across TCP/UDP ports for the whole tree.
        /// Ordinary CFC rules remain an additional restriction on new flows.
        #[arg(long = "allow", value_name = "IP")]
        allow: Vec<std::net::IpAddr>,
        /// Absolute executable inside the runtime, followed by its arguments.
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Stop every process in a confined tree before releasing its permissions.
    Stop { id: String },
}

#[tokio::main]
pub async fn cli_main() {
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
            eprintln!("cfc: {}", output::terminal_safe(&e.to_string()));
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
    let socket = cli.socket;

    match cli.cmd {
        Command::Applications { cmd } => confinement::run(cmd, format).await.map_err(Into::into),
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
        Command::Status => status::cmd_status(client, format).await,
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
            RulesCmd::ImportOpensnitch {
                path,
                replace,
                skip_unconvertible,
            } => rules::import_opensnitch(client, path, replace, skip_unconvertible, format).await,
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
        Command::Pause { duration } => status::cmd_pause(client, duration, format).await,
        Command::Resume => status::cmd_resume(client, format).await,
        Command::Applications { .. } | Command::Completions { .. } | Command::Man { .. } => {
            unreachable!("handled by run()")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

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
        assert_eq!(cli.socket, PathBuf::from("/tmp/x.sock"));
    }

    #[test]
    fn confined_payload_arguments_cannot_become_launcher_permissions() {
        let cli = Cli::try_parse_from([
            "cfc",
            "applications",
            "run",
            "--runtime",
            "/sealed/runtime",
            "--",
            "/app/program",
            "--allow",
            "203.0.113.7",
            "--json",
        ])
        .unwrap();
        assert!(!cli.format().is_json());
        match cli.cmd {
            Command::Applications {
                cmd: ApplicationsCmd::Run { allow, command, .. },
            } => {
                assert!(allow.is_empty());
                assert_eq!(
                    command,
                    ["/app/program", "--allow", "203.0.113.7", "--json"]
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(Cli::try_parse_from([
            "cfc",
            "applications",
            "run",
            "--runtime",
            "/sealed/runtime",
            "--allow",
            "example.com",
            "--",
            "/app/program",
        ])
        .is_err());
    }

    #[test]
    fn socket_defaults_to_the_shared_constant() {
        let cli = Cli::parse_from(["cfc", "status"]);
        assert_eq!(cli.socket, PathBuf::from(cfc_proto::DEFAULT_SOCKET_PATH));
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
}
