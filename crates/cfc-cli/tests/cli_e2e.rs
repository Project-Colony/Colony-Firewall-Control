//! End-to-end tests for the `cfc` binary, against a fake daemon.
//!
//! The interesting parts of prompts, live and log (subscribe, answer,
//! stream loss, exit codes) only happen across a real socket. This stands
//! up a minimal Firewall service on a UDS and drives the actual binary
//! against it, so what is tested is what a user runs.

use cfc_proto::v1 as pb;
use cfc_proto::v1::firewall_server::{Firewall, FirewallServer};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::{Request, Response, Status};

#[derive(Debug, Clone)]
struct Verdict {
    prompt_id: String,
    action: i32,
    duration: i32,
    scope: Option<pb::RuleScope>,
}

#[derive(Default)]
struct FakeDaemon {
    verdicts: Arc<Mutex<Vec<Verdict>>>,
    /// Rules the daemon already holds, served by `ListRules`.
    existing: Arc<Mutex<Vec<pb::RuleInfo>>>,
    /// Every mutation in the order it arrived. `import` correctness is entirely
    /// about that order, so recording it is the test.
    calls: Arc<Mutex<Vec<Call>>>,
    /// Answer SubmitVerdict with "applied, but the rule was not saved" - the
    /// state a full or read-only /var/lib produces.
    rule_persist_fails: bool,
    /// Rule names whose upsert should fail, so a mid-file import failure can be
    /// tested. Without this the fake daemon has no failure mode at all and the
    /// central atomicity claim goes unexercised.
    upsert_fails_for: Arc<Mutex<Vec<String>>>,
}

/// One mutation seen by the fake daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Upsert(String),
    Delete(String),
}

#[tonic::async_trait]
impl Firewall for FakeDaemon {
    type StreamPromptsStream = ReceiverStream<Result<pb::PromptEvent, Status>>;
    type StreamConnectionsStream = ReceiverStream<Result<pb::ConnectionEvent, Status>>;

    async fn stream_prompts(
        &self,
        _req: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::StreamPromptsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let ev = pb::PromptEvent {
                prompt_id: "42".into(),
                connection: Some(pb::ConnectionInfo {
                    id: "c1".into(),
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    protocol: pb::Protocol::Tcp as i32,
                    direction: pb::Direction::Outbound as i32,
                    src_ip: "192.0.2.10".into(),
                    src_port: 5555,
                    dst_ip: "93.184.216.34".into(),
                    dst_port: 443,
                    dst_host: "example.com".into(),
                }),
                process: Some(pb::ProcessInfo {
                    pid: 4242,
                    ppid: 1,
                    uid: Some(1000),
                    gid: Some(1000),
                    exe: "/usr/bin/curl".into(),
                    cmdline: vec!["curl".into(), "https://example.com".into()],
                    cwd: "/home/u".into(),
                    sha256: "9f2c1a3b4d5e6f70".into(),
                    package: "curl 8.21.0-1".into(),
                    provenance: pb::Provenance::Verified as i32,
                }),
                // Far enough out that a slow CI box cannot expire it.
                deadline_unix_ms: chrono::Utc::now().timestamp_millis() + 60_000,
                binds_to_hash: false,
            };
            let _ = tx.send(Ok(ev)).await;
            // Hold the stream open; the CLI is expected to leave on its own
            // once --count is satisfied.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn submit_verdict(
        &self,
        req: Request<pb::VerdictRequest>,
    ) -> Result<Response<pb::VerdictResponse>, Status> {
        let req = req.into_inner();
        let wanted_rule = req.persist_scope.is_some();
        self.verdicts.lock().unwrap().push(Verdict {
            prompt_id: req.prompt_id,
            action: req.action,
            duration: req.duration,
            scope: req.persist_scope,
        });
        // A real daemon reports the rule separately from the verdict, and can
        // apply one without saving the other.
        let persisted = wanted_rule && !self.rule_persist_fails;
        Ok(Response::new(pb::VerdictResponse {
            accepted: true,
            error: String::new(),
            persisted_rule_id: if persisted {
                "11111111-1111-4111-8111-111111111111".to_string()
            } else {
                String::new()
            },
            persist_error: if wanted_rule && self.rule_persist_fails {
                "storage: disk full".to_string()
            } else {
                String::new()
            },
            persist_note: String::new(),
        }))
    }

    async fn get_status(
        &self,
        _req: Request<pb::StatusRequest>,
    ) -> Result<Response<pb::StatusResponse>, Status> {
        Ok(Response::new(pb::StatusResponse {
            version: "test".into(),
            uptime_seconds: 5,
            rules_count: 0,
            prompts_pending: 1,
            connections_seen: 0,
            connections_allowed: 0,
            connections_denied: 0,
            paused: false,
            resume_at_unix_ms: 0,
            timeout_action: pb::Action::Deny as i32,
            no_ui_action: pb::Action::Deny as i32,
            prompt_timeout_secs: 15,
            skipped_rules: 2,
            enforcing: false,
            enforcement: "pinned".to_string(),
            fast_allow: "off: [ebpf] fast_allow is not set".to_string(),
        }))
    }

    async fn list_rules(
        &self,
        _req: Request<pb::ListRulesRequest>,
    ) -> Result<Response<pb::ListRulesResponse>, Status> {
        Ok(Response::new(pb::ListRulesResponse {
            rules: self.existing.lock().unwrap().clone(),
        }))
    }

    async fn upsert_rule(
        &self,
        req: Request<pb::UpsertRuleRequest>,
    ) -> Result<Response<pb::UpsertRuleResponse>, Status> {
        let r = req
            .into_inner()
            .rule
            .ok_or_else(|| Status::invalid_argument("rule required"))?;
        if self.upsert_fails_for.lock().unwrap().contains(&r.name) {
            return Err(Status::invalid_argument(format!(
                "rule `{}` refused by this test daemon",
                r.name
            )));
        }
        // A real daemon parses the id and stores the canonical form, so an
        // uppercase or braced spelling comes back lowercase-hyphenated. Echoing
        // it verbatim is what let the import bug hide.
        let id = if r.id.is_empty() {
            format!("minted-{}", self.calls.lock().unwrap().len())
        } else {
            r.id.to_ascii_lowercase()
        };
        self.calls.lock().unwrap().push(Call::Upsert(id.clone()));
        Ok(Response::new(pb::UpsertRuleResponse {
            id,
            error: String::new(),
        }))
    }

    async fn delete_rule(
        &self,
        req: Request<pb::DeleteRuleRequest>,
    ) -> Result<Response<pb::DeleteRuleResponse>, Status> {
        let id = req.into_inner().id;
        self.calls.lock().unwrap().push(Call::Delete(id));
        Ok(Response::new(pb::DeleteRuleResponse { deleted: true }))
    }

    /// Sends one event and then closes the stream, which is what a daemon
    /// restart looks like to a subscriber.
    async fn stream_connections(
        &self,
        _req: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::StreamConnectionsStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let _ = tx
                .send(Ok(pb::ConnectionEvent {
                    connection: Some(pb::ConnectionInfo {
                        id: "c1".into(),
                        timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                        protocol: pb::Protocol::Tcp as i32,
                        direction: pb::Direction::Outbound as i32,
                        src_ip: "192.0.2.10".into(),
                        src_port: 5555,
                        dst_ip: "93.184.216.34".into(),
                        dst_port: 443,
                        dst_host: "example.com".into(),
                    }),
                    process: Some(pb::ProcessInfo {
                        pid: 4242,
                        ppid: 1,
                        uid: Some(1000),
                        gid: Some(1000),
                        exe: "/usr/bin/curl".into(),
                        cmdline: vec![],
                        cwd: String::new(),
                        sha256: String::new(),
                        package: String::new(),
                        provenance: pb::Provenance::Unspecified as i32,
                    }),
                    verdict: pb::Action::Deny as i32,
                    rule_id: "r-7".into(),
                }))
                .await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn set_paused(
        &self,
        _req: Request<pb::SetPausedRequest>,
    ) -> Result<Response<pb::SetPausedResponse>, Status> {
        Err(Status::unimplemented("not used by this test"))
    }

    async fn list_events(
        &self,
        _req: Request<pb::ListEventsRequest>,
    ) -> Result<Response<pb::ListEventsResponse>, Status> {
        let events = vec![pb::Event {
            ts_unix_ms: chrono::Utc::now().timestamp_millis(),
            proto: "tcp".into(),
            src_ip: "192.0.2.10".into(),
            src_port: 5555,
            dst_ip: "93.184.216.34".into(),
            dst_port: 443,
            dst_host: "example.com".into(),
            exe: "/usr/bin/curl".into(),
            pid: 4242,
            uid: Some(1000),
            action: pb::Action::Deny as i32,
            source: "rule".into(),
            rule_id: "r-7".into(),
        }];
        Ok(Response::new(pb::ListEventsResponse {
            total_returned: events.len() as u64,
            events,
        }))
    }
}

/// A socket path short enough for `sun_path` (108 bytes), unlike a path
/// under a deeply nested target dir.
fn socket_path(tag: &str) -> std::path::PathBuf {
    let unique = format!(
        "cfc-test-{tag}-{}-{}.sock",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    );
    std::env::temp_dir().join(unique)
}

fn run_cli(args: &[&str], timeout: Duration) -> std::process::Output {
    run_cli_with_stdin(args, None, timeout)
}

/// Runs the real binary, optionally feeding it keystrokes.
///
/// Piped stdin is not a terminal, so the CLI takes its documented
/// line-mode path: one answer per line, confirmed with Enter.
fn run_cli_with_stdin(
    args: &[&str],
    stdin_text: Option<&str>,
    timeout: Duration,
) -> std::process::Output {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_cfc"))
        .args(args)
        .stdin(if stdin_text.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning cfc");

    if let Some(text) = stdin_text {
        use std::io::Write;
        let mut pipe = child.stdin.take().expect("stdin pipe");
        pipe.write_all(text.as_bytes()).expect("writing stdin");
        // Dropping the pipe is EOF, which the CLI reads as "the user
        // left". Every byte written above is already queued for the
        // reader, so the answers are consumed before that lands.
    }

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("polling cfc") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                panic!("cfc {args:?} did not exit within {timeout:?}");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    child.wait_with_output().expect("collecting cfc output")
}

async fn serve(path: std::path::PathBuf, fake: FakeDaemon) -> tokio::task::JoinHandle<()> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("binding the test socket");
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(FirewallServer::new(fake))
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await;
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_deny_answers_one_prompt_and_exits() {
    let path = socket_path("prompts");
    let verdicts = Arc::new(Mutex::new(Vec::new()));
    let server = serve(
        path.clone(),
        FakeDaemon {
            verdicts: verdicts.clone(),
            ..Default::default()
        },
    )
    .await;

    let sock = path.to_string_lossy().into_owned();
    let out = tokio::task::spawn_blocking(move || {
        run_cli(
            &[
                "--socket",
                &sock,
                "prompts",
                "--auto-deny",
                "--count",
                "1",
                "--json",
            ],
            Duration::from_secs(20),
        )
    })
    .await
    .unwrap();

    server.abort();
    let _ = std::fs::remove_file(&path);

    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "cfc prompts failed: {:?}\n{stderr}",
        out.status
    );

    // The verdict actually reached the daemon...
    let got = verdicts.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "expected exactly one verdict, got {got:?}");
    assert_eq!(got[0].prompt_id, "42");
    assert_eq!(got[0].action, pb::Action::Deny as i32);
    // ...as a one-shot answer: an unattended run must not write rules.
    assert_eq!(got[0].duration, pb::Duration::Once as i32);
    assert!(got[0].scope.is_none(), "auto mode must not persist a scope");

    // ...and the NDJSON line describes it.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("\"verdict\""))
        .unwrap_or_else(|| panic!("no verdict line in output:\n{stdout}"));
    let v: serde_json::Value = serde_json::from_str(line).expect("NDJSON line parses");
    assert_eq!(v["prompt_id"], "42");
    assert_eq!(v["verdict"], "deny");
    assert_eq!(v["accepted"], true);
    assert_eq!(v["exe"], "/usr/bin/curl");
    assert_eq!(v["uid"], 1000);
    assert_eq!(v["dst_host"], "example.com");
    assert_eq!(v["package"], "curl 8.21.0-1");
    assert_eq!(v["provenance"], "verified");
}

/// Drives the interactive decision tree over piped stdin (line mode).
async fn answer_interactively(tag: &str, keys: &'static str) -> (Vec<Verdict>, String) {
    let path = socket_path(tag);
    let verdicts = Arc::new(Mutex::new(Vec::new()));
    let server = serve(
        path.clone(),
        FakeDaemon {
            verdicts: verdicts.clone(),
            ..Default::default()
        },
    )
    .await;

    let sock = path.to_string_lossy().into_owned();
    let out = tokio::task::spawn_blocking(move || {
        run_cli_with_stdin(
            &["--socket", &sock, "prompts", "--count", "1"],
            Some(keys),
            Duration::from_secs(20),
        )
    })
    .await
    .unwrap();

    server.abort();
    let _ = std::fs::remove_file(&path);

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "cfc prompts failed: {:?}\n{}\n{stdout}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let got = verdicts.lock().unwrap().clone();
    (got, stdout)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answering_once_persists_no_rule() {
    // allow -> once
    let (got, stdout) = answer_interactively("once", "a\n1\n").await;

    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].action, pb::Action::Allow as i32);
    assert_eq!(got[0].duration, pb::Duration::Once as i32);
    // "Once" must send no scope: the daemon rejects DURATION_ONCE for a
    // persisted rule, so a scope here would fail the whole verdict.
    assert!(got[0].scope.is_none(), "{got:?}");

    // The prompt was actually rendered with the details a user needs.
    assert!(stdout.contains("/usr/bin/curl"), "{stdout}");
    assert!(stdout.contains("uid 1000"), "{stdout}");
    assert!(stdout.contains("example.com:443"), "{stdout}");
    assert!(stdout.contains("9f2c1a3b4d5e"), "sha256 missing:\n{stdout}");
    // Package provenance: the whole point is that it reaches the user's
    // eyes at decision time, not just the wire.
    assert!(
        stdout.contains("curl 8.21.0-1 (verified)"),
        "provenance missing:\n{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answering_with_a_scope_persists_a_rule() {
    // deny -> always -> this app
    let (got, _) = answer_interactively("scope", "d\n3\n2\n").await;

    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].action, pb::Action::Deny as i32);
    assert_eq!(got[0].duration, pb::Duration::Always as i32);
    let scope = got[0].scope.clone().expect("expected a persisted scope");
    assert_eq!(scope.exe_path, "/usr/bin/curl");
    assert!(!scope.has_dst_port, "'this app' must not pin the port");
    assert!(!scope.has_uid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exe_and_port_scope_pins_the_port_and_protocol() {
    // reject -> until restart -> this app + port
    let (got, _) = answer_interactively("exeport", "r\n2\n1\n").await;

    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].action, pb::Action::Reject as i32);
    assert_eq!(got[0].duration, pb::Duration::UntilRestart as i32);
    let scope = got[0].scope.clone().expect("expected a persisted scope");
    assert_eq!(scope.exe_path, "/usr/bin/curl");
    assert_eq!(scope.dst_port, 443);
    assert!(scope.has_dst_port);
    assert_eq!(scope.protocol, pb::Protocol::Tcp as i32);
    assert!(scope.has_protocol);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skipping_submits_nothing() {
    let (got, stdout) = answer_interactively("skip", "s\n").await;
    assert!(got.is_empty(), "skip must not submit a verdict: {got:?}");
    assert!(stdout.contains("skipped"), "{stdout}");
    // The user is told what the daemon will do instead.
    assert!(stdout.contains("deny"), "{stdout}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_json_round_trips_over_a_real_socket() {
    let path = socket_path("status");
    let server = serve(path.clone(), FakeDaemon::default()).await;

    let sock = path.to_string_lossy().into_owned();
    let out = tokio::task::spawn_blocking(move || {
        run_cli(
            &["--socket", &sock, "status", "--json"],
            Duration::from_secs(20),
        )
    })
    .await
    .unwrap();

    server.abort();
    let _ = std::fs::remove_file(&path);

    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("status --json is valid JSON");
    assert_eq!(v["version"], "test");
    assert_eq!(v["enforcing"], false);
    assert_eq!(v["skipped_rules"], 2);
    assert_eq!(v["timeout_action"], "deny");
    // The daemon's own sentence, verbatim: a script must be able to read
    // the reason, not only that there is one.
    assert_eq!(v["fast_allow"], "off: [ebpf] fast_allow is not set");
    // Both warnings must be machine-readable too, not just printed.
    let warnings = v["warnings"].as_array().expect("warnings array");
    assert_eq!(warnings.len(), 2, "{warnings:?}");
}

#[test]
fn unknown_socket_exits_four_with_an_actionable_message() {
    let missing = socket_path("missing");
    let out = run_cli(
        &["--socket", &missing.to_string_lossy(), "status"],
        Duration::from_secs(20),
    );
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("colony-firewalld"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn log_renders_rows_in_both_modes() {
    let path = socket_path("log");
    let server = serve(path.clone(), FakeDaemon::default()).await;
    let sock = path.to_string_lossy().into_owned();

    let (human, json) = tokio::task::spawn_blocking(move || {
        let human = run_cli(
            &["--socket", &sock, "log", "--limit", "5"],
            Duration::from_secs(20),
        );
        let json = run_cli(
            &["--socket", &sock, "log", "--limit", "5", "--json"],
            Duration::from_secs(20),
        );
        (human, json)
    })
    .await
    .unwrap();

    server.abort();
    let _ = std::fs::remove_file(&path);

    assert!(human.status.success());
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("destination"), "no header:\n{text}");
    assert!(text.contains("curl"), "no app column:\n{text}");
    assert!(text.contains("example.com:443"), "no hostname:\n{text}");
    assert!(text.contains("deny"), "no verdict:\n{text}");

    assert!(json.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).expect("log --json parses");
    let rows = v.as_array().expect("log --json is an array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["exe"], "/usr/bin/curl");
    assert_eq!(rows[0]["action"], "deny");
    assert_eq!(rows[0]["source"], "rule");
    assert_eq!(rows[0]["uid"], 1000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_without_follow_fails_when_the_stream_ends() {
    let path = socket_path("live");
    let server = serve(path.clone(), FakeDaemon::default()).await;
    let sock = path.to_string_lossy().into_owned();

    let out = tokio::task::spawn_blocking(move || {
        run_cli(
            &["--socket", &sock, "live", "--json"],
            Duration::from_secs(20),
        )
    })
    .await
    .unwrap();

    server.abort();
    let _ = std::fs::remove_file(&path);

    // The event was emitted...
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .next()
        .unwrap_or_else(|| panic!("no event line:\n{stdout}"));
    let v: serde_json::Value = serde_json::from_str(line).expect("NDJSON parses");
    assert_eq!(v["exe"], "/usr/bin/curl");
    assert_eq!(v["dst_host"], "example.com");
    assert_eq!(v["verdict"], "deny");
    assert_eq!(v["rule_id"], "r-7");

    // ...and losing the stream is an error, not a silent exit 0.
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--follow"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_filters_are_applied_client_side() {
    let path = socket_path("livefilter");
    let server = serve(path.clone(), FakeDaemon::default()).await;
    let sock = path.to_string_lossy().into_owned();

    let out = tokio::task::spawn_blocking(move || {
        run_cli(
            &["--socket", &sock, "live", "--json", "--exe", "wget"],
            Duration::from_secs(20),
        )
    })
    .await
    .unwrap();

    server.abort();
    let _ = std::fs::remove_file(&path);

    assert!(
        out.stdout.is_empty(),
        "a non-matching event was printed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(1));
}

// ---------------------------------------------------------------------------
// `cfc rules import`
//
// The correctness of import is entirely about *ordering and atomicity*, which
// no unit test on the conversion can see. These drive the real binary against
// a daemon that records every mutation in the order it arrives.
// ---------------------------------------------------------------------------

fn rule_json(id: &str, name: &str, action: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","enabled":true,"action":"{action}",
             "duration":"always","scope":{{"exe_path":"/usr/bin/curl"}}}}"#
    )
}

async fn import_fixture(
    tag: &str,
    existing: Vec<pb::RuleInfo>,
) -> (
    std::path::PathBuf,
    Arc<Mutex<Vec<Call>>>,
    tokio::task::JoinHandle<()>,
) {
    import_fixture_failing(tag, existing, Vec::new()).await
}

/// Same, but the daemon refuses the named rules - the only way to exercise a
/// failure that lands *after* some rules have already been applied.
async fn import_fixture_failing(
    tag: &str,
    existing: Vec<pb::RuleInfo>,
    refuse: Vec<String>,
) -> (
    std::path::PathBuf,
    Arc<Mutex<Vec<Call>>>,
    tokio::task::JoinHandle<()>,
) {
    let path = socket_path(tag);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = serve(
        path.clone(),
        FakeDaemon {
            existing: Arc::new(Mutex::new(existing)),
            calls: calls.clone(),
            upsert_fails_for: Arc::new(Mutex::new(refuse)),
            ..Default::default()
        },
    )
    .await;
    (path, calls, server)
}

fn stub_rule(id: &str, name: &str) -> pb::RuleInfo {
    pb::RuleInfo {
        id: id.into(),
        name: name.into(),
        enabled: true,
        action: pb::Action::Allow as i32,
        duration: pb::Duration::Always as i32,
        scope: None,
        created_at_unix_ms: 0,
        hit_count: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_with_an_unknown_action_changes_nothing_at_all() {
    // The failure this replaces: delete everything, then abort on the first bad
    // rule, leaving an emptied rule set against a fail-closed nftables table -
    // i.e. a machine with no outbound network, from a typo.
    let existing = vec![stub_rule("11111111-1111-4111-8111-111111111111", "keep-me")];
    let (path, calls, server) = import_fixture("import-bad", existing).await;

    let good = rule_json("22222222-2222-4222-8222-222222222222", "ok", "deny");
    let bad = rule_json("33333333-3333-4333-8333-333333333333", "typo", "block");
    let json = format!("[{good},{bad}]");

    let out = run_cli_with_stdin(
        &[
            "--socket",
            path.to_str().unwrap(),
            "rules",
            "import",
            "--replace",
        ],
        Some(&json),
        Duration::from_secs(10),
    );

    assert!(
        !out.status.success(),
        "an unreadable file must fail the command"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown action"), "stderr: {err}");
    assert!(
        err.contains("typo"),
        "the offending rule must be named: {err}"
    );
    assert!(err.contains("nothing was changed"), "stderr: {err}");
    assert!(
        calls.lock().unwrap().is_empty(),
        "not one mutation may reach the daemon: {:?}",
        calls.lock().unwrap()
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_replace_upserts_before_it_deletes() {
    // There is no server-side transaction, so something has to be the failure
    // window. Making it "old rules linger" rather than "no rules at all" is the
    // only ordering that cannot take the machine's network down.
    let existing = vec![stub_rule("11111111-1111-4111-8111-111111111111", "old")];
    let (path, calls, server) = import_fixture("import-order", existing).await;

    let json = format!(
        "[{}]",
        rule_json("22222222-2222-4222-8222-222222222222", "new", "deny")
    );
    let out = run_cli_with_stdin(
        &[
            "--socket",
            path.to_str().unwrap(),
            "rules",
            "import",
            "--replace",
        ],
        Some(&json),
        Duration::from_secs(10),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let calls = calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            Call::Upsert("22222222-2222-4222-8222-222222222222".into()),
            Call::Delete("11111111-1111-4111-8111-111111111111".into()),
        ],
        "the new rule must exist before the old one is removed"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_replace_does_not_delete_what_it_just_imported() {
    // The bug this test exists for: `--replace` deleting every pre-existing
    // rule would throw away the ones the import had just *updated*, because an
    // imported rule that shares an id with an existing one is an update.
    let shared = "11111111-1111-4111-8111-111111111111";
    let existing = vec![
        stub_rule(shared, "shared"),
        stub_rule("44444444-4444-4444-8444-444444444444", "stale"),
    ];
    let (path, calls, server) = import_fixture("import-shared", existing).await;

    let json = format!("[{}]", rule_json(shared, "shared-updated", "deny"));
    let out = run_cli_with_stdin(
        &[
            "--socket",
            path.to_str().unwrap(),
            "rules",
            "import",
            "--replace",
        ],
        Some(&json),
        Duration::from_secs(10),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let calls = calls.lock().unwrap().clone();
    assert!(
        calls.contains(&Call::Upsert(shared.into())),
        "the shared rule must have been updated: {calls:?}"
    );
    assert!(
        !calls.contains(&Call::Delete(shared.into())),
        "and must NOT then be deleted: {calls:?}"
    );
    assert!(
        calls.contains(&Call::Delete("44444444-4444-4444-8444-444444444444".into())),
        "while a rule absent from the file is still removed: {calls:?}"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_without_replace_never_deletes() {
    let existing = vec![stub_rule("11111111-1111-4111-8111-111111111111", "old")];
    let (path, calls, server) = import_fixture("import-additive", existing).await;

    let json = format!(
        "[{}]",
        rule_json("22222222-2222-4222-8222-222222222222", "new", "allow")
    );
    let out = run_cli_with_stdin(
        &["--socket", path.to_str().unwrap(), "rules", "import"],
        Some(&json),
        Duration::from_secs(10),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = calls.lock().unwrap().clone();
    assert!(
        !calls.iter().any(|c| matches!(c, Call::Delete(_))),
        "an additive import must not remove anything: {calls:?}"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upsert_that_fails_midway_leaves_the_old_rules_in_place() {
    // The central claim of the reordering, and the one case the earlier tests
    // could not reach: validation passes, the apply phase starts, and the
    // daemon refuses a rule anyway (a duration it will not persist, a storage
    // error, version skew). "Old rules linger" must hold - an emptied rule set
    // against a fail-closed table is a machine with no outbound network.
    let existing = vec![
        stub_rule("11111111-1111-4111-8111-111111111111", "old-a"),
        stub_rule("55555555-5555-4555-8555-555555555555", "old-b"),
    ];
    let (path, calls, server) =
        import_fixture_failing("import-midway", existing, vec!["boom".to_string()]).await;

    let ok = rule_json("22222222-2222-4222-8222-222222222222", "fine", "deny");
    let bad = rule_json("33333333-3333-4333-8333-333333333333", "boom", "deny");
    let json = format!("[{ok},{bad}]");

    let out = run_cli_with_stdin(
        &[
            "--socket",
            path.to_str().unwrap(),
            "rules",
            "import",
            "--replace",
        ],
        Some(&json),
        Duration::from_secs(10),
    );
    assert!(
        !out.status.success(),
        "a refused rule must fail the command"
    );

    let calls = calls.lock().unwrap().clone();
    assert!(
        !calls.iter().any(|c| matches!(c, Call::Delete(_))),
        "nothing may be deleted once the apply phase has failed: {calls:?}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("boom"),
        "the message must name the rule that failed: {err}"
    );
    assert!(
        err.contains("1 rules were already applied"),
        "and say how far it got, because the state is now partial: {err}"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uppercase_id_updates_the_rule_instead_of_deleting_it() {
    // `Uuid::parse_str` accepts uppercase; the daemon stores and lists the
    // canonical lowercase form. Keying the skip-set on the file's spelling meant
    // the rule was upserted and then deleted as "absent from the import" - and
    // the first version of this suite could not see it, because the fake daemon
    // echoed the id back verbatim instead of canonicalising it.
    let shared_lower = "11111111-1111-4111-8111-111111111111";
    let (path, calls, server) =
        import_fixture("import-case", vec![stub_rule(shared_lower, "shared")]).await;

    let json = format!(
        "[{}]",
        rule_json(&shared_lower.to_ascii_uppercase(), "shared", "deny")
    );
    let out = run_cli_with_stdin(
        &[
            "--socket",
            path.to_str().unwrap(),
            "rules",
            "import",
            "--replace",
        ],
        Some(&json),
        Duration::from_secs(10),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let calls = calls.lock().unwrap().clone();
    assert!(
        !calls.iter().any(|c| matches!(c, Call::Delete(_))),
        "the rule the import carried must survive it: {calls:?}"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_rules_sharing_an_id_are_refused_before_anything_is_applied() {
    // The second upsert overwrites the first, so the file describes a state the
    // import cannot produce; the printed count would exceed what the daemon
    // holds, and under --replace a rule the operator believes they imported
    // would not exist.
    let (path, calls, server) = import_fixture("import-dup", Vec::new()).await;
    let id = "22222222-2222-4222-8222-222222222222";
    let json = format!(
        "[{},{}]",
        rule_json(id, "one", "allow"),
        rule_json(id, "two", "deny")
    );

    let out = run_cli_with_stdin(
        &["--socket", path.to_str().unwrap(), "rules", "import"],
        Some(&json),
        Duration::from_secs(10),
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("share the id"), "{err}");
    assert!(
        calls.lock().unwrap().is_empty(),
        "a file describing a state it cannot produce must change nothing"
    );
    server.abort();
}
