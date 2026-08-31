//! `cfc prompts`: answer connection prompts from a terminal.
//!
//! Without this, a headless box has no subscriber at all and the daemon
//! short-circuits every prompt to its `no_ui_action`. With it, ssh is a
//! first-class front-end for the firewall.

use crate::error::{CliError, CliResult};
use crate::output::{self, OutputFormat};
use crate::tty::{self, Key, RawMode};
use anyhow::Context;
use cfc_client::{convert, proto, Client, StreamItem};
use futures::StreamExt;
use owo_colors::{OwoColorize, Stream::Stdout};
use std::io::Write;
use std::path::Path;
use tokio::sync::mpsc::UnboundedReceiver;

#[derive(Debug, clap::Args)]
pub struct PromptArgs {
    /// Answer every prompt with deny, no questions asked. For scripts and
    /// headless boxes that want a hard default without a GUI.
    #[arg(long, conflicts_with = "auto_allow")]
    pub auto_deny: bool,

    /// Answer every prompt with allow. Dangerous; useful for a bounded
    /// window (e.g. during an install) or in tests.
    #[arg(long)]
    pub auto_allow: bool,

    /// Exit after this many prompts. 0 means run until interrupted.
    #[arg(long, default_value_t = 0)]
    pub count: u32,
}

impl PromptArgs {
    fn auto(&self) -> Option<proto::Action> {
        if self.auto_deny {
            Some(proto::Action::Deny)
        } else if self.auto_allow {
            Some(proto::Action::Allow)
        } else {
            None
        }
    }
}

/// What the user picked for a prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    Answer(proto::Action),
    /// Let it time out: the daemon applies its configured timeout action.
    Skip,
    Quit,
    Expired,
}

/// Which flows a persisted rule should cover. Mirrors the GUI's buttons so
/// the two front-ends create the same rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// This executable talking to this port over this protocol.
    ExeAndPort,
    /// This executable, anywhere.
    Exe,
    /// This destination, from any executable.
    Destination,
}

/// Builds the rule scope for a prompt, or `None` when the event lacks the
/// fields that scope needs (an unattributed process has no exe to pin).
///
/// The exe test is [`convert::exe_is_rule_scopable`] - the same predicate the
/// GUI and the tray use - not a bare emptiness check. An unattributed process
/// arrives with the non-empty `<unknown>` placeholder as its exe, and this
/// function used to pin that string into the rule: the doc above promised
/// `None`, the daemon persisted the rule, the CLI reported success, and the
/// rule could never fire because the matcher refuses the placeholder. The
/// user was told a standing allow existed while the prompts kept coming.
pub fn build_scope(
    scope: Scope,
    process: Option<&proto::ProcessInfo>,
    conn: Option<&proto::ConnectionInfo>,
) -> Option<proto::RuleScope> {
    let scopable_exe =
        |p: &proto::ProcessInfo| convert::exe_is_rule_scopable(&p.exe).then(|| p.exe.clone());
    let mut out = proto::RuleScope::default();
    match scope {
        Scope::Exe => {
            out.exe_path = process.and_then(scopable_exe)?;
        }
        Scope::ExeAndPort => {
            let exe = process.and_then(scopable_exe)?;
            let c = conn?;
            out.exe_path = exe;
            out.dst_port = c.dst_port;
            out.has_dst_port = true;
            out.protocol = c.protocol;
            out.has_protocol = true;
        }
        Scope::Destination => {
            let c = conn?;
            if !c.dst_host.is_empty() {
                out.dst_host = c.dst_host.clone();
            } else if !c.dst_ip.is_empty() {
                out.dst_net = if c.dst_ip.contains(':') {
                    format!("{}/128", c.dst_ip)
                } else {
                    format!("{}/32", c.dst_ip)
                };
            } else {
                return None;
            }
        }
    }
    Some(out)
}

#[derive(Debug, serde::Serialize)]
struct PromptJson<'a> {
    prompt_id: &'a str,
    deadline_unix_ms: i64,
    protocol: Option<&'a str>,
    exe: Option<&'a str>,
    pid: Option<u32>,
    uid: Option<u32>,
    cmdline: Option<String>,
    sha256: Option<&'a str>,
    /// Owning package as "<name> <version>", null when none/unknown.
    package: Option<&'a str>,
    /// One of "verified" | "modified" | "unpackaged" | "unknown".
    provenance: Option<&'a str>,
    src_ip: Option<&'a str>,
    src_port: u32,
    dst_ip: Option<&'a str>,
    dst_port: u32,
    dst_host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<bool>,
}

/// Empty proto strings mean "absent"; JSON should say null, not "".
fn opt(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn to_json<'a>(
    ev: &'a proto::PromptEvent,
    verdict: Option<&'a str>,
    accepted: Option<bool>,
) -> PromptJson<'a> {
    let proc = ev.process.as_ref();
    let conn = ev.connection.as_ref();
    PromptJson {
        prompt_id: &ev.prompt_id,
        deadline_unix_ms: ev.deadline_unix_ms,
        protocol: conn.map(|c| convert::protocol_label(c.protocol)),
        exe: proc.and_then(|p| opt(&p.exe)),
        pid: proc.map(|p| p.pid),
        uid: proc.and_then(|p| p.uid),
        cmdline: proc
            .filter(|p| !p.cmdline.is_empty())
            .map(|p| p.cmdline.join(" ")),
        sha256: proc.and_then(|p| opt(&p.sha256)),
        package: proc.and_then(|p| opt(&p.package)),
        provenance: proc.map(|p| convert::provenance_token(p.provenance)),
        src_ip: conn.and_then(|c| opt(&c.src_ip)),
        src_port: conn.map(|c| c.src_port).unwrap_or(0),
        dst_ip: conn.and_then(|c| opt(&c.dst_ip)),
        dst_port: conn.map(|c| c.dst_port).unwrap_or(0),
        dst_host: conn.and_then(|c| opt(&c.dst_host)),
        verdict,
        accepted,
    }
}

/// The destination line: hostname when known, otherwise the IP, always
/// with the port and protocol.
pub fn describe_destination(conn: Option<&proto::ConnectionInfo>) -> String {
    let Some(c) = conn else {
        return "unknown destination".to_string();
    };
    let proto_label = convert::protocol_label(c.protocol);
    if c.dst_host.is_empty() {
        format!("{proto_label} {}:{}", c.dst_ip, c.dst_port)
    } else {
        format!("{proto_label} {}:{} ({})", c.dst_host, c.dst_port, c.dst_ip)
    }
}

/// The process line: exe, pid and uid, with "unknown" rather than a
/// misleading uid 0 when the flow could not be attributed.
pub fn describe_process(proc: Option<&proto::ProcessInfo>) -> String {
    match proc {
        None => "unknown process".to_string(),
        Some(p) => {
            let exe = if p.exe.is_empty() {
                "?"
            } else {
                p.exe.as_str()
            };
            format!("{exe} (pid {}, uid {})", p.pid, convert::uid_label(p.uid))
        }
    }
}

/// First 12 hex characters: enough to eyeball, short enough to read.
pub fn short_sha(sha: &str) -> Option<String> {
    if sha.is_empty() {
        return None;
    }
    Some(sha.chars().take(12).collect())
}

fn secs_left(deadline_unix_ms: i64, now_unix_ms: i64) -> i64 {
    if deadline_unix_ms <= 0 {
        return i64::MAX;
    }
    (deadline_unix_ms - now_unix_ms).div_euclid(1000).max(0)
}

// ---------------------------------------------------------------------------
// Terminal interaction
// ---------------------------------------------------------------------------

struct Term {
    keys: UnboundedReceiver<u8>,
    /// True when stdin is not a terminal: input arrives a line at a time
    /// and must be confirmed with Enter.
    line_mode: bool,
    /// True when stdout is a terminal and an in-place countdown is useful.
    countdown: bool,
    _raw: Option<RawMode>,
}

enum Input {
    Key(char),
    TimedOut,
    Interrupted,
    Closed,
}

/// The signals that must end the session cleanly.
///
/// Raw mode is undone by `Drop`, which only runs if the loop unwinds, so a
/// SIGTERM that killed the process outright would leave the user's shell
/// with no echo. Catching it here keeps the terminal sane either way.
struct Signals {
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
}

impl Signals {
    fn install() -> anyhow::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            int: signal(SignalKind::interrupt()).context("installing the SIGINT handler")?,
            term: signal(SignalKind::terminate()).context("installing the SIGTERM handler")?,
        })
    }

    async fn wait(&mut self) {
        tokio::select! {
            _ = self.int.recv() => {}
            _ = self.term.recv() => {}
        }
    }
}

impl Term {
    fn open() -> anyhow::Result<Self> {
        let raw = RawMode::enable().context("switching the terminal to raw mode")?;
        Ok(Self {
            keys: tty::spawn_key_reader(),
            line_mode: raw.is_none(),
            countdown: tty::stdout_is_tty(),
            _raw: raw,
        })
    }

    /// Waits for one of `valid` keys, redrawing a countdown until the
    /// prompt's deadline passes.
    async fn choose(
        &mut self,
        signals: &mut Signals,
        label: &str,
        valid: &[char],
        deadline_unix_ms: i64,
    ) -> Input {
        let mut pending: Option<char> = None;
        loop {
            let now = chrono::Utc::now().timestamp_millis();
            let left = secs_left(deadline_unix_ms, now);
            if left == 0 {
                self.clear_line();
                return Input::TimedOut;
            }
            self.draw(label, left);

            let tick = tokio::time::sleep(std::time::Duration::from_millis(500));
            tokio::select! {
                _ = signals.wait() => {
                    self.clear_line();
                    return Input::Interrupted;
                }
                _ = tick => continue,
                byte = self.keys.recv() => {
                    let Some(byte) = byte else {
                        self.clear_line();
                        return Input::Closed;
                    };
                    match tty::classify(byte) {
                        Key::Char(c) if self.line_mode => {
                            // Remember the first character of the line and
                            // act on it when Enter arrives.
                            if pending.is_none() && valid.contains(&c) {
                                pending = Some(c);
                            }
                        }
                        Key::Char(c) => {
                            if valid.contains(&c) {
                                self.clear_line();
                                return Input::Key(c);
                            }
                        }
                        Key::Enter if self.line_mode => {
                            if let Some(c) = pending.take() {
                                self.clear_line();
                                return Input::Key(c);
                            }
                        }
                        Key::Escape => {
                            self.clear_line();
                            return Input::Key('s');
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn draw(&self, label: &str, secs_left: i64) {
        if !self.countdown {
            return;
        }
        let countdown = if secs_left == i64::MAX {
            String::new()
        } else {
            format!("  [{secs_left}s]")
        };
        print!("\r\x1b[K{label}{countdown} ");
        let _ = std::io::stdout().flush();
    }

    fn clear_line(&self) {
        if self.countdown {
            print!("\r\x1b[K");
            let _ = std::io::stdout().flush();
        }
    }

    /// Prints the one-shot question used in line mode, where there is no
    /// countdown to carry the instructions.
    fn announce(&self, label: &str) {
        if !self.countdown {
            println!("{label}");
        }
    }
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

pub async fn run(
    socket: &Path,
    client: &mut Client,
    args: PromptArgs,
    format: OutputFormat,
) -> CliResult {
    // The daemon's own defaults, used to explain what happened when a
    // prompt expires under the user's fingers.
    let status = client.status().await?;
    let timeout_action = convert::action_label(status.timeout_action).to_string();

    let auto = args.auto();
    let interactive = auto.is_none() && !format.is_json();

    let mut term = if interactive {
        Some(Term::open().map_err(CliError::Runtime)?)
    } else {
        None
    };
    let mut signals = Signals::install()?;

    if !format.is_json() {
        match auto {
            Some(a) => println!(
                "answering every prompt with {} (Ctrl-C to stop)",
                convert::action_label(a as i32)
            ),
            None if interactive => println!(
                "waiting for prompts; a=allow d=deny r=reject s=skip q=quit (Ctrl-C to stop)"
            ),
            None => println!("watching prompts (no --auto-* given: prompts will time out)"),
        }
    }

    let mut stream = cfc_client::stream_prompts_resilient(socket, "cfc-cli".into());
    let mut seen = 0u32;
    let mut connected_once = false;

    loop {
        let item = tokio::select! {
            _ = signals.wait() => break,
            item = stream.next() => item,
        };
        let Some(item) = item else { break };

        match item {
            StreamItem::Connected => {
                if connected_once && !format.is_json() {
                    println!("-- reconnected --");
                }
                connected_once = true;
            }
            StreamItem::Disconnected(err) => {
                if format.is_json() {
                    output::print_ndjson(
                        &serde_json::json!({"event": "disconnected", "error": err.to_string()}),
                    )?;
                } else {
                    eprintln!("-- disconnected: {err} (retrying) --");
                }
            }
            StreamItem::Event(ev) => {
                let quit = handle_prompt(
                    client,
                    &ev,
                    auto,
                    term.as_mut(),
                    &mut signals,
                    format,
                    &timeout_action,
                )
                .await?;
                seen += 1;
                if quit || (args.count > 0 && seen >= args.count) {
                    break;
                }
            }
        }
    }

    if !format.is_json() {
        println!();
    }
    Ok(())
}

/// Handles one prompt. Returns true when the user asked to quit.
#[allow(clippy::too_many_arguments)]
async fn handle_prompt(
    client: &mut Client,
    ev: &proto::PromptEvent,
    auto: Option<proto::Action>,
    term: Option<&mut Term>,
    signals: &mut Signals,
    format: OutputFormat,
    timeout_action: &str,
) -> Result<bool, CliError> {
    // Automated modes answer immediately and never persist a rule: an
    // unattended process should not be writing firewall policy.
    if let Some(action) = auto {
        let accepted = submit(client, &ev.prompt_id, action, proto::Duration::Once, None).await?;
        report(ev, action, accepted, format, timeout_action)?;
        return Ok(false);
    }

    if format.is_json() {
        output::print_ndjson(&to_json(ev, None, None))?;
        return Ok(false);
    }

    let Some(term) = term else {
        // No terminal and no --auto-*: show it and let it time out.
        print_prompt(ev);
        return Ok(false);
    };

    print_prompt(ev);

    let label = "answer: [a]llow [d]eny [r]eject [s]kip [q]uit";
    term.announce(label);
    let choice = match term
        .choose(
            signals,
            label,
            &['a', 'd', 'r', 's', 'q'],
            ev.deadline_unix_ms,
        )
        .await
    {
        Input::Key('a') => Choice::Answer(proto::Action::Allow),
        Input::Key('d') => Choice::Answer(proto::Action::Deny),
        Input::Key('r') => Choice::Answer(proto::Action::Reject),
        Input::Key('q') => Choice::Quit,
        Input::Key(_) => Choice::Skip,
        Input::TimedOut => Choice::Expired,
        Input::Interrupted | Input::Closed => Choice::Quit,
    };

    let action = match choice {
        Choice::Quit => return Ok(true),
        Choice::Skip => {
            println!("  skipped (the daemon will apply {timeout_action} at the deadline)");
            return Ok(false);
        }
        Choice::Expired => {
            println!("  expired (daemon applied {timeout_action})");
            return Ok(false);
        }
        Choice::Answer(a) => a,
    };

    // Duration. "Once" answers this prompt only and persists nothing: the
    // daemon rejects DURATION_ONCE for a persisted rule, so a scope
    // necessarily implies until-restart or always.
    let dur_label = "duration: [1] once (no rule) [2] until restart [3] always [s]kip";
    term.announce(dur_label);
    let duration = match term
        .choose(
            signals,
            dur_label,
            &['1', '2', '3', 's', 'q'],
            ev.deadline_unix_ms,
        )
        .await
    {
        Input::Key('1') => None,
        Input::Key('2') => Some(proto::Duration::UntilRestart),
        Input::Key('3') => Some(proto::Duration::Always),
        Input::Key('q') | Input::Interrupted | Input::Closed => return Ok(true),
        Input::Key(_) => {
            println!("  skipped (the daemon will apply {timeout_action} at the deadline)");
            return Ok(false);
        }
        Input::TimedOut => {
            println!("  expired (daemon applied {timeout_action})");
            return Ok(false);
        }
    };

    let (duration, scope) = match duration {
        None => (proto::Duration::Once, None),
        Some(duration) => {
            let scope_label = "scope: [1] this app + port [2] this app [3] this destination";
            term.announce(scope_label);
            let picked = match term
                .choose(
                    signals,
                    scope_label,
                    &['1', '2', '3', 'q'],
                    ev.deadline_unix_ms,
                )
                .await
            {
                Input::Key('1') => Scope::ExeAndPort,
                Input::Key('2') => Scope::Exe,
                Input::Key('3') => Scope::Destination,
                Input::Key(_) | Input::Interrupted | Input::Closed => return Ok(true),
                Input::TimedOut => {
                    println!("  expired (daemon applied {timeout_action})");
                    return Ok(false);
                }
            };
            match build_scope(picked, ev.process.as_ref(), ev.connection.as_ref()) {
                Some(s) => (duration, Some(s)),
                None => {
                    // Nothing to pin the rule to; answer this prompt only
                    // rather than writing a rule that matches everything.
                    println!(
                        "  (not enough process/destination detail for a rule; answering once)"
                    );
                    (proto::Duration::Once, None)
                }
            }
        }
    };

    let accepted = submit(client, &ev.prompt_id, action, duration, scope).await?;
    report(ev, action, accepted, format, timeout_action)?;
    Ok(false)
}

async fn submit(
    client: &mut Client,
    prompt_id: &str,
    action: proto::Action,
    duration: proto::Duration,
    scope: Option<proto::RuleScope>,
) -> Result<bool, CliError> {
    let wanted_rule = scope.is_some();
    let outcome = client
        .submit_verdict(prompt_id, action, duration, scope)
        .await?;
    // Said out loud rather than folded into the boolean: `accepted` is about
    // the connection, not about the rule, and an operator answering prompts
    // needs to know a standing answer did not stick.
    if outcome.accepted && wanted_rule && outcome.rule_persisted == Some(false) {
        eprintln!(
            "warning: {}",
            outcome
                .persist_error
                .as_deref()
                .unwrap_or("the answer applied, but no lasting rule was saved")
        );
    }
    Ok(outcome.accepted)
}

fn report(
    ev: &proto::PromptEvent,
    action: proto::Action,
    accepted: bool,
    format: OutputFormat,
    timeout_action: &str,
) -> CliResult {
    let label = convert::action_label(action as i32);
    if format.is_json() {
        return output::print_ndjson(&to_json(ev, Some(label), Some(accepted)));
    }
    if accepted {
        println!("  {label} -> {}", ev.prompt_id);
    } else {
        println!("  expired (daemon applied {timeout_action})");
    }
    Ok(())
}

fn print_prompt(ev: &proto::PromptEvent) {
    let proc = ev.process.as_ref();
    println!();
    println!("prompt {}", ev.prompt_id);
    println!("  process  {}", describe_process(proc));
    if let Some(p) = proc {
        if !p.cmdline.is_empty() {
            println!("  cmdline  {}", p.cmdline.join(" "));
        }
        if let Some(sha) = short_sha(&p.sha256) {
            println!("  sha256   {sha}");
        }
        // Skipped entirely on hosts with no package database, where it
        // would be a permanent "unknown" on every prompt.
        if convert::has_provenance(p) {
            let label = convert::provenance_label(p);
            if p.provenance == proto::Provenance::Modified as i32 {
                // Same red as a deny: a binary that no longer matches its
                // package is a genuine red flag, not a footnote.
                println!(
                    "  package  {}",
                    label.if_supports_color(Stdout, |s| s.red())
                );
            } else {
                println!("  package  {label}");
            }
        }
    }
    println!(
        "  target   {}",
        describe_destination(ev.connection.as_ref())
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process() -> proto::ProcessInfo {
        proto::ProcessInfo {
            pid: 4242,
            ppid: 1,
            uid: Some(1000),
            gid: Some(1000),
            exe: "/usr/bin/curl".into(),
            cmdline: vec!["curl".into(), "https://example.com".into()],
            cwd: "/home/u".into(),
            sha256: "9f2c1a3b4d5e6f708192a3b4c5d6e7f8".into(),
            package: "curl 8.21.0-1".into(),
            provenance: proto::Provenance::Verified as i32,
        }
    }

    fn conn() -> proto::ConnectionInfo {
        proto::ConnectionInfo {
            id: "c1".into(),
            timestamp_unix_ms: 1_700_000_000_000,
            protocol: proto::Protocol::Tcp as i32,
            direction: proto::Direction::Outbound as i32,
            src_ip: "192.0.2.10".into(),
            src_port: 5555,
            dst_ip: "93.184.216.34".into(),
            dst_port: 443,
            dst_host: "example.com".into(),
        }
    }

    #[test]
    fn exe_and_port_scope_mirrors_the_gui() {
        let s = build_scope(Scope::ExeAndPort, Some(&process()), Some(&conn())).unwrap();
        assert_eq!(s.exe_path, "/usr/bin/curl");
        assert_eq!(s.dst_port, 443);
        assert!(s.has_dst_port);
        assert_eq!(s.protocol, proto::Protocol::Tcp as i32);
        assert!(s.has_protocol);
        assert!(s.dst_host.is_empty());
        assert!(!s.has_uid);
    }

    #[test]
    fn exe_scope_is_only_the_exe() {
        let s = build_scope(Scope::Exe, Some(&process()), Some(&conn())).unwrap();
        assert_eq!(s.exe_path, "/usr/bin/curl");
        assert!(!s.has_dst_port);
        assert!(!s.has_protocol);
        assert!(s.dst_net.is_empty());
    }

    #[test]
    fn destination_scope_prefers_the_hostname() {
        let s = build_scope(Scope::Destination, Some(&process()), Some(&conn())).unwrap();
        assert_eq!(s.dst_host, "example.com");
        assert!(s.exe_path.is_empty());
        assert!(s.dst_net.is_empty());
    }

    #[test]
    fn destination_scope_falls_back_to_a_host_cidr() {
        let mut c = conn();
        c.dst_host = String::new();
        let s = build_scope(Scope::Destination, None, Some(&c)).unwrap();
        assert_eq!(s.dst_net, "93.184.216.34/32");

        c.dst_ip = "2001:db8::1".into();
        let s = build_scope(Scope::Destination, None, Some(&c)).unwrap();
        assert_eq!(s.dst_net, "2001:db8::1/128");
    }

    #[test]
    fn scopes_need_the_fields_they_pin() {
        // No process -> no exe-based rule; refusing beats writing a rule
        // that matches every process on the box.
        assert!(build_scope(Scope::Exe, None, Some(&conn())).is_none());
        assert!(build_scope(Scope::ExeAndPort, None, Some(&conn())).is_none());
        assert!(build_scope(Scope::Destination, Some(&process()), None).is_none());

        let mut p = process();
        p.exe = String::new();
        assert!(build_scope(Scope::Exe, Some(&p), Some(&conn())).is_none());

        let mut c = conn();
        c.dst_host = String::new();
        c.dst_ip = String::new();
        assert!(build_scope(Scope::Destination, None, Some(&c)).is_none());
    }

    #[test]
    fn an_unscopable_exe_pins_no_rule() {
        // `<unknown>` is what the daemon shows for a process it could not
        // identify - a non-empty string, so the old `!is_empty()` filter let
        // it through and "always allow / this app" persisted a rule that
        // reads as one program and can never fire (the matcher refuses the
        // placeholder). The GUI and the tray already gate on
        // `exe_is_rule_scopable`; the CLI must use the same predicate.
        let mut p = process();
        p.exe = convert::UNKNOWN_EXE.to_string();
        assert!(build_scope(Scope::Exe, Some(&p), Some(&conn())).is_none());
        assert!(build_scope(Scope::ExeAndPort, Some(&p), Some(&conn())).is_none());

        // A relative execve-fallback path can never match /proc's absolute
        // one either; same predicate, same refusal.
        p.exe = "curl".to_string();
        assert!(build_scope(Scope::Exe, Some(&p), Some(&conn())).is_none());

        // The destination scope needs no exe, so it still works for an
        // unattributed flow - that is the rule shape such prompts should use.
        p.exe = convert::UNKNOWN_EXE.to_string();
        let s = build_scope(Scope::Destination, Some(&p), Some(&conn())).unwrap();
        assert_eq!(s.dst_host, "example.com");
        assert!(s.exe_path.is_empty());
    }

    #[test]
    fn descriptions_never_invent_a_root_uid() {
        let mut p = process();
        p.uid = None;
        assert!(describe_process(Some(&p)).contains("uid unknown"));
        assert_eq!(describe_process(None), "unknown process");
        assert!(describe_process(Some(&process())).contains("uid 1000"));
    }

    #[test]
    fn destination_description_includes_protocol_and_host() {
        assert_eq!(
            describe_destination(Some(&conn())),
            "tcp example.com:443 (93.184.216.34)"
        );
        let mut c = conn();
        c.dst_host = String::new();
        assert_eq!(describe_destination(Some(&c)), "tcp 93.184.216.34:443");
        assert_eq!(describe_destination(None), "unknown destination");
    }

    #[test]
    fn sha_is_shortened_but_not_invented() {
        assert_eq!(short_sha("").as_deref(), None);
        assert_eq!(
            short_sha("9f2c1a3b4d5e6f70").as_deref(),
            Some("9f2c1a3b4d5e")
        );
        assert_eq!(short_sha("abc").as_deref(), Some("abc"));
    }

    #[test]
    fn countdown_never_goes_negative_and_zero_deadlines_never_expire() {
        let now = 1_700_000_000_000;
        assert_eq!(secs_left(now + 10_000, now), 10);
        assert_eq!(secs_left(now - 10_000, now), 0);
        assert_eq!(secs_left(now, now), 0);
        // deadline 0 means the daemon did not set one: never time out.
        assert_eq!(secs_left(0, now), i64::MAX);
    }

    #[test]
    fn auto_flags_select_one_action() {
        let deny = PromptArgs {
            auto_deny: true,
            auto_allow: false,
            count: 0,
        };
        assert_eq!(deny.auto(), Some(proto::Action::Deny));
        let allow = PromptArgs {
            auto_deny: false,
            auto_allow: true,
            count: 0,
        };
        assert_eq!(allow.auto(), Some(proto::Action::Allow));
        let interactive = PromptArgs {
            auto_deny: false,
            auto_allow: false,
            count: 0,
        };
        assert_eq!(interactive.auto(), None);
    }

    #[test]
    fn json_prompt_shape_carries_process_and_verdict() {
        let ev = proto::PromptEvent {
            prompt_id: "17".into(),
            connection: Some(conn()),
            process: Some(process()),
            deadline_unix_ms: 1_700_000_030_000,
        };
        let v = serde_json::to_value(to_json(&ev, None, None)).unwrap();
        assert_eq!(v["prompt_id"], "17");
        assert_eq!(v["exe"], "/usr/bin/curl");
        assert_eq!(v["uid"], 1000);
        assert_eq!(v["dst_host"], "example.com");
        assert_eq!(v["cmdline"], "curl https://example.com");
        assert_eq!(v["package"], "curl 8.21.0-1");
        assert_eq!(v["provenance"], "verified");
        assert!(
            v.get("verdict").is_none(),
            "verdict omitted when unanswered"
        );

        let v = serde_json::to_value(to_json(&ev, Some("deny"), Some(true))).unwrap();
        assert_eq!(v["verdict"], "deny");
        assert_eq!(v["accepted"], true);
    }
}
