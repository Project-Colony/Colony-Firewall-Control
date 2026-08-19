//! End-to-end tests for the daemon's control plane.
//!
//! These assemble the daemon's **real** internals - `RuleStore` on a temp
//! sqlite file, `Engine` over a `SharedPolicy`, `Stats`, `PromptRouter`
//! with its worker-side verdict channel, the observed-connection broadcast
//! and `ipc::spawn` on a socket inside the temp dir - and drive them
//! through the same `cfc_client::Client` the UI and CLI use. Nothing here
//! needs root or NFQUEUE: the packet datapath is replaced by pushing
//! `PromptRequest`s / `ObservedConnection`s directly, which is exactly what
//! the worker thread does.
//!
//! What that buys over `scripts/smoke-test.sh` (which drives the real
//! binary but can do neither): the prompt round-trip needs a
//! `StreamPrompts` subscriber that answers, and pause auto-resume needs
//! control over time.
//!
//! # Socket access control in tests
//!
//! The tests run unprivileged, so the socket in the temp dir can be neither
//! `root:colony-firewall` nor mode 0660: `secure_socket` leaves it 0600 and
//! reports `group_gated = false`. Fixtures therefore set `require_group =
//! false` (exactly what `scripts/smoke-test.sh` does) so mutating RPCs are
//! reachable. [`require_group_refuses_non_root_mutation`] covers the
//! opposite, production-shaped case.
//!
//! # Time
//!
//! Everything the daemon schedules (prompt timeout, pause auto-resume,
//! event batching) is a `tokio::time` timer, so the tests advance the
//! runtime clock instead of sleeping - see [`advance_until`]. No test waits
//! a real second.
//!
//! Every fixture uses a fresh temp dir (unique db + socket), so tests are
//! hermetic and can run in parallel.

use cfc_client::{proto as pb, Client, ClientError};
use cfc_core::{Action, Connection, Direction, Process, Protocol, Verdict, VerdictSource};
use cfc_daemon::config::{DefaultPolicy, IpcConfig};
use cfc_daemon::decision::{Engine, SharedPolicy};
use cfc_daemon::ipc::{self, IpcOptions};
use cfc_daemon::nfqueue::{ObservedConnection, PromptRequest, PromptTx, PromptVerdict};
use cfc_daemon::prompts::PromptRouter;
use cfc_daemon::stats::Stats;
use cfc_daemon::storage::{EventFilter, EventRow, RuleStore};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Real-time budget for "this should already have happened". Long enough
/// that a loaded CI box never trips it, short enough that a genuine hang
/// fails loudly instead of wedging the suite.
const SETTLE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct TestDaemonBuilder {
    policy: DefaultPolicy,
    require_group: bool,
    pause_default_secs: u64,
    /// `Some(max_rows)` also spawns the event-persistence pipeline, the way
    /// `main` does.
    event_pipeline: Option<u32>,
}

impl TestDaemonBuilder {
    fn policy(mut self, policy: DefaultPolicy) -> Self {
        self.policy = policy;
        self
    }

    fn require_group(mut self, require: bool) -> Self {
        self.require_group = require;
        self
    }

    fn pause_default_secs(mut self, secs: u64) -> Self {
        self.pause_default_secs = secs;
        self
    }

    fn event_pipeline(mut self, max_rows: u32) -> Self {
        self.event_pipeline = Some(max_rows);
        self
    }

    async fn build(self) -> TestDaemon {
        let dir = tempfile::Builder::new()
            .prefix("cfc-it-")
            .tempdir()
            .expect("creating temp dir");
        let db = dir.path().join("rules.db");
        let socket = dir.path().join("cfc.sock");

        let store = RuleStore::open(&db).expect("opening rule store");
        let policy: SharedPolicy = Arc::new(std::sync::RwLock::new(self.policy));
        let engine = Engine::new(store.snapshot().expect("initial snapshot"), policy.clone());
        let (observed_tx, _) = broadcast::channel(256);
        let stats = Stats::new();
        // Worker side of the prompt round-trip: the NFQUEUE thread owns this
        // receiver in production.
        let (verdict_tx, verdicts) = std::sync::mpsc::channel();
        let router = PromptRouter::new(policy.clone(), stats.clone(), verdict_tx);

        if let Some(max_rows) = self.event_pipeline {
            ipc::spawn_event_pipeline(store.clone(), &observed_tx, max_rows);
        }

        let (handle, prompt_tx) = ipc::spawn(
            IpcOptions {
                socket_path: socket.clone(),
                ipc: IpcConfig {
                    // A group that cannot exist: `secure_socket` then never
                    // chowns, so `group_gated` is false whether or not these
                    // tests happen to run as root. That keeps the
                    // authorization assertions deterministic.
                    group: format!("cfc-absent-{}", uuid::Uuid::new_v4()),
                    require_group: self.require_group,
                },
                pause_default_secs: self.pause_default_secs,
                dry_run: false,
            },
            engine,
            store.clone(),
            observed_tx.clone(),
            router,
            stats.clone(),
            policy.clone(),
        )
        .await
        .expect("starting IPC server");

        wait_for_socket(&socket).await;

        TestDaemon {
            socket,
            db,
            store,
            stats,
            policy,
            observed_tx,
            prompt_tx,
            verdicts,
            ipc: handle,
            _dir: dir,
        }
    }
}

struct TestDaemon {
    socket: PathBuf,
    db: PathBuf,
    store: RuleStore,
    stats: Stats,
    policy: SharedPolicy,
    observed_tx: broadcast::Sender<ObservedConnection>,
    prompt_tx: PromptTx,
    verdicts: Receiver<PromptVerdict>,
    ipc: JoinHandle<()>,
    /// Deleted last, when the fixture drops.
    _dir: TempDir,
}

impl TestDaemon {
    fn builder() -> TestDaemonBuilder {
        TestDaemonBuilder {
            // Deny/Deny makes an accidental fallback obvious; the long
            // prompt timeout keeps the sweeper out of the way of tests that
            // are not about timing out.
            policy: DefaultPolicy {
                no_ui_action: Action::Deny,
                timeout_action: Action::Deny,
                inbound_action: cfc_core::Action::Deny,
                prompt_timeout_secs: 3600,
            },
            require_group: false,
            pause_default_secs: 600,
            event_pipeline: None,
        }
    }

    async fn build() -> Self {
        Self::builder().build().await
    }

    async fn client(&self) -> Client {
        Client::connect(&self.socket)
            .await
            .expect("connecting to the test daemon")
    }

    /// Hands the router a prompt exactly as the NFQUEUE worker would, about
    /// a process this uid owns - so a subscriber from this process is
    /// entitled to see it.
    async fn push_prompt(&self, prompt_id: u64) {
        self.push_prompt_for(prompt_id, own_process()).await;
    }

    /// As [`push_prompt`](Self::push_prompt), but for a caller-chosen
    /// process (i.e. a caller-chosen owner uid).
    async fn push_prompt_for(&self, prompt_id: u64, process: Process) {
        self.prompt_tx
            .send(PromptRequest {
                prompt_id,
                connection: connection(443),
                process,
            })
            .await
            .expect("prompt channel closed");
    }

    /// Next verdict handed back to the worker thread. Used where an RPC
    /// produced the verdict synchronously, so it is already queued; the
    /// poll is only slack for a loaded machine.
    async fn next_verdict(&self) -> PromptVerdict {
        let deadline = std::time::Instant::now() + SETTLE;
        loop {
            match self.try_verdict() {
                Some(v) => return v,
                None => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "no verdict reached the worker within {SETTLE:?}"
                    );
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    }

    /// Like [`next_verdict`](Self::next_verdict), but for a verdict only a
    /// timer can produce: advances the clock in one-second hops (spending
    /// no real time) until it appears or `budget` of simulated time is up.
    async fn next_verdict_within(&self, budget: Duration) -> PromptVerdict {
        let step = Duration::from_secs(1);
        let mut spent = Duration::ZERO;
        loop {
            if let Some(v) = self.try_verdict() {
                return v;
            }
            assert!(
                spent < budget,
                "no verdict after {budget:?} of simulated time"
            );
            jump(step).await;
            spent += step;
        }
    }

    fn try_verdict(&self) -> Option<PromptVerdict> {
        match self.verdicts.try_recv() {
            Ok(v) => Some(v),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => panic!("verdict channel disconnected"),
        }
    }

    fn assert_no_verdict(&self) {
        assert!(
            self.try_verdict().is_none(),
            "unexpected extra verdict on the worker channel"
        );
    }

    fn event_count(&self) -> usize {
        self.store
            .query_events(100, 0, EventFilter::default())
            .expect("querying events")
            .len()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.ipc.abort();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Awaits readiness rather than sleeping: returns as soon as the socket
/// accepts a connection. `ipc::spawn` binds before it returns, so this is
/// normally a single successful connect.
async fn wait_for_socket(path: &Path) {
    let deadline = std::time::Instant::now() + SETTLE;
    loop {
        match tokio::net::UnixStream::connect(path).await {
            Ok(_) => return,
            Err(e) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{} never accepted connections: {e}",
                    path.display()
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
}

/// Moves the tokio clock forward by `d` with no real waiting.
///
/// The clock is frozen only for the jump and resumed immediately: a paused
/// clock auto-advances to the next deadline whenever the runtime idles, so
/// awaiting a gRPC round-trip (or a millisecond poll) while paused could
/// fire timers the test never asked for - including the client's own
/// request timeout. Nothing here awaits anything but `yield_now`, which
/// always leaves a ready task and therefore never lets the runtime idle.
async fn jump(d: Duration) {
    settle().await;
    tokio::time::pause();
    tokio::time::advance(d).await;
    tokio::time::resume();
    settle().await;
}

/// Lets already-woken tasks (timer callbacks, the event feeder) run.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// Advances the clock in `step` hops until `cond` holds, spending no real
/// time.
///
/// Hops rather than one big jump because the daemon arms its timers inside
/// spawned tasks: a timer whose task has not been polled yet is not
/// registered, and an interval that has just fired schedules its next
/// deadline from the instant it fired. Stepping makes the test independent
/// of *when* a task happened to be polled; one big jump is not.
async fn advance_until(what: &str, step: Duration, max_steps: u32, mut cond: impl FnMut() -> bool) {
    for _ in 0..max_steps {
        if cond() {
            return;
        }
        jump(step).await;
    }
    assert!(
        cond(),
        "{what} did not happen within {:?} of simulated time",
        step * max_steps
    );
}

async fn next_message<T>(stream: &mut tonic::Streaming<T>) -> T {
    tokio::time::timeout(SETTLE, stream.message())
        .await
        .expect("stream produced nothing in time")
        .expect("stream failed")
        .expect("stream closed by the daemon")
}

fn status_of(err: ClientError) -> tonic::Status {
    match err {
        ClientError::Rpc(status) => status,
        other => panic!("expected an RPC status, got: {other}"),
    }
}

/// True when this test process is root, in which case peer-credential
/// checks are bypassed by design (root may do everything).
fn running_as_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

fn connection(dst_port: u16) -> Connection {
    Connection::new(
        Protocol::Tcp,
        Direction::Outbound,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        54321,
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        dst_port,
    )
}

fn process() -> Process {
    let mut p = Process::unknown(4242);
    p.exe = PathBuf::from("/usr/bin/curl");
    p.uid = Some(1000);
    p
}

/// Uid this test process runs as - which is also the uid every client here
/// connects with, since they are all this process.
fn self_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}

/// A process owned by whoever is running the suite. Prompt delivery is
/// uid-scoped, so a prompt that the harness expects a subscriber to
/// *receive* must be about a process this uid owns - the normal
/// single-desktop-session shape.
fn own_process() -> Process {
    let mut p = process();
    p.uid = Some(self_uid());
    p
}

fn observed(dst_port: u16, action: Action) -> ObservedConnection {
    ObservedConnection {
        connection: connection(dst_port),
        process: process(),
        verdict: Verdict {
            action,
            source: VerdictSource::DefaultPolicy,
        },
    }
}

fn scope_port(port: u32) -> pb::RuleScope {
    pb::RuleScope {
        dst_port: port,
        has_dst_port: true,
        ..Default::default()
    }
}

fn rule_pb(name: &str, action: pb::Action, scope: pb::RuleScope) -> pb::RuleInfo {
    pb::RuleInfo {
        id: String::new(),
        name: name.to_string(),
        enabled: true,
        action: action as i32,
        duration: pb::Duration::Always as i32,
        scope: Some(scope),
        created_at_unix_ms: 0,
        hit_count: 0,
    }
}

fn event_row(ts: i64, exe: &str, action: &str) -> EventRow {
    EventRow {
        id: 0,
        ts_unix_ms: ts,
        proto: Some("tcp".into()),
        src_ip: Some("10.0.0.5".into()),
        src_port: Some(54321),
        dst_ip: Some("1.1.1.1".into()),
        dst_port: Some(443),
        dst_host: Some("example.com".into()),
        exe: Some(exe.into()),
        pid: Some(4242),
        uid: Some(1000),
        action: action.into(),
        source: "rule".into(),
        rule_id: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Prompt round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prompt_round_trip_answers_the_worker_and_persists_the_rule() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;

    // Subscribing first matters: with no subscriber the router short-circuits
    // to no_ui_action instead of broadcasting. `stream_prompts` returns only
    // after the server handler has subscribed, so this ordering is enough.
    let mut prompts = client
        .stream_prompts("test".into())
        .await
        .expect("subscribing to prompts");

    d.push_prompt(42).await;

    let event = next_message(&mut prompts).await;
    assert_eq!(event.prompt_id, "42");
    assert_eq!(event.connection.expect("connection").dst_port, 443);
    assert_eq!(event.process.expect("process").exe, "/usr/bin/curl");
    assert!(event.deadline_unix_ms > chrono::Utc::now().timestamp_millis());
    // The router counts a prompt as pending before it broadcasts it.
    assert_eq!(d.stats.prompts_pending(), 1);

    let accepted = client
        .submit_verdict(
            "42",
            pb::Action::Allow,
            pb::Duration::Always,
            Some(scope_port(443)),
        )
        .await
        .expect("submitting the verdict")
        .accepted;
    assert!(accepted, "the prompt was pending, so the answer must land");

    // (a) the worker gets exactly the verdict the user picked...
    let verdict = d.next_verdict().await;
    assert_eq!(verdict.prompt_id, 42);
    assert_eq!(verdict.verdict.action, Action::Allow);
    assert_eq!(verdict.verdict.source, VerdictSource::UserPrompt);
    // ...once.
    d.assert_no_verdict();
    assert_eq!(d.stats.prompts_pending(), 0);

    // (c) and the persist scope became a real rule.
    let rules = client.list_rules().await.expect("listing rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "user prompt 42");
    assert_eq!(rules[0].action, pb::Action::Allow as i32);
    assert_eq!(rules[0].scope.as_ref().expect("scope").dst_port, 443);
    // Persisted, not just held in the engine: a reopened store sees it too.
    let reopened = RuleStore::open(&d.db).expect("reopening the store");
    assert_eq!(reopened.snapshot().expect("snapshot").rules.len(), 1);
}

#[tokio::test]
async fn prompt_answered_without_a_scope_persists_nothing() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;
    let mut prompts = client
        .stream_prompts("test".into())
        .await
        .expect("subscribing to prompts");

    d.push_prompt(7).await;
    assert_eq!(next_message(&mut prompts).await.prompt_id, "7");

    let accepted = client
        .submit_verdict("7", pb::Action::Deny, pb::Duration::Once, None)
        .await
        .expect("submitting the verdict")
        .accepted;
    assert!(accepted);

    assert_eq!(d.next_verdict().await.verdict.action, Action::Deny);
    // Duration::Once is legal for a one-shot answer; it is rejected only
    // when it would have to be persisted as a rule.
    assert!(client.list_rules().await.expect("listing rules").is_empty());
}

// ---------------------------------------------------------------------------
// 2. Prompt timeout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prompt_timeout_falls_back_and_makes_a_late_answer_a_no_op() {
    // The router's sweeper is a tokio::time::sleep, so a 30s timeout is
    // reachable without waiting 30 real seconds.
    let d = TestDaemon::builder()
        .policy(DefaultPolicy {
            no_ui_action: Action::Allow,
            timeout_action: Action::Deny,
            inbound_action: cfc_core::Action::Deny,
            prompt_timeout_secs: 30,
        })
        .build()
        .await;
    let mut client = d.client().await;
    let mut prompts = client
        .stream_prompts("test".into())
        .await
        .expect("subscribing to prompts");

    d.push_prompt(9).await;
    assert_eq!(next_message(&mut prompts).await.prompt_id, "9");
    assert_eq!(d.stats.prompts_pending(), 1);

    // Nobody answers.
    let verdict = d.next_verdict_within(Duration::from_secs(60)).await;
    assert_eq!(verdict.prompt_id, 9);
    assert_eq!(
        verdict.verdict.action,
        Action::Deny,
        "a timeout must apply timeout_action, not no_ui_action"
    );
    assert_eq!(d.stats.prompts_pending(), 0);

    // The user answering afterwards must not produce a second verdict.
    let accepted = client
        .submit_verdict("9", pb::Action::Allow, pb::Duration::Always, None)
        .await
        .expect("submitting a late verdict")
        .accepted;
    assert!(!accepted, "a resolved prompt cannot be answered again");
    d.assert_no_verdict();
}

// ---------------------------------------------------------------------------
// 3. Prompt ownership (wave 3)
// ---------------------------------------------------------------------------

/// The full guarantee - peer A cannot answer peer B's prompt - needs two
/// *client* peers with different uids, which a single-uid test process
/// cannot produce: a second connection from this same process is
/// indistinguishable from the first. What is reachable end-to-end is
/// everything that does not need a second client: a prompt this uid was
/// never handed is refused ([`verdict_for_an_undelivered_prompt_is_refused`]),
/// a prompt about a process this uid owns *is* delivered
/// ([`prompt_round_trip_answers_the_worker_and_persists_the_rule`], whose
/// prompt is owned by `self_uid()`), a prompt owned by a *different* uid is
/// not ([`prompt_for_another_uid_is_not_delivered`]), and an unattributed
/// one reaches everyone ([`unattributed_prompt_is_delivered_to_any_session`]).
/// The uid-vs-uid predicate itself is covered by the `should_deliver` unit
/// tests in `src/prompts.rs`.
#[tokio::test]
async fn verdict_for_an_undelivered_prompt_is_refused() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;
    // A subscriber exists, but this prompt id was never broadcast to it.
    let _prompts = client
        .stream_prompts("test".into())
        .await
        .expect("subscribing to prompts");

    let result = client
        .submit_verdict("999999", pb::Action::Allow, pb::Duration::Always, None)
        .await;

    if running_as_root() {
        // Root is exempt from the ownership check, so it gets as far as the
        // router, which has no such prompt.
        assert!(!result.expect("root may submit").accepted, "no such prompt");
    } else {
        let status = status_of(result.expect_err("the ownership check must refuse"));
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(
            status.message().contains("not delivered to you"),
            "unexpected message: {}",
            status.message()
        );
    }
    d.assert_no_verdict();
}

/// A prompt about another user's process is never handed to this session,
/// and - because no subscriber may see it - it resolves immediately with
/// `no_ui_action` instead of stalling the packet until `timeout_action`.
#[tokio::test]
async fn prompt_for_another_uid_is_not_delivered() {
    if running_as_root() {
        // uid 0 is entitled to every prompt by design, so there is no
        // "another uid" this process could fail to be shown.
        return;
    }
    // Two distinguishable outcomes: Allow can only have come from the
    // no-audience fast path, Deny only from the timeout sweeper.
    let d = TestDaemon::builder()
        .policy(DefaultPolicy {
            no_ui_action: Action::Allow,
            timeout_action: Action::Deny,
            inbound_action: cfc_core::Action::Deny,
            prompt_timeout_secs: 30,
        })
        .build()
        .await;
    let mut client = d.client().await;
    let mut prompts = client
        .stream_prompts("test".into())
        .await
        .expect("subscribing to prompts");

    let mut foreign = process();
    foreign.uid = Some(self_uid().wrapping_add(1));
    d.push_prompt_for(77, foreign).await;

    let verdict = d.next_verdict().await;
    assert_eq!(verdict.prompt_id, 77);
    assert_eq!(
        verdict.verdict.action,
        Action::Allow,
        "a prompt no session may see must take the no_ui_action fast path, \
         not wait out prompt_timeout_secs"
    );
    assert_eq!(d.stats.prompts_pending(), 0, "it never became pending");

    // And the stream really saw nothing: the verdict above is already the
    // whole story, so a short budget is enough to prove the absence.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), prompts.message())
            .await
            .is_err(),
        "another session's prompt must not reach this stream"
    );

    // Not delivered means not answerable, either.
    let result = client
        .submit_verdict("77", pb::Action::Deny, pb::Duration::Once, None)
        .await;
    let status = status_of(result.expect_err("the ownership check must refuse"));
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    d.assert_no_verdict();
}

/// Unattributed traffic (the process exited before /proc could be read) has
/// no owner to match, so every session is offered it. Deliberate: the
/// alternative is that nobody is ever asked about it.
#[tokio::test]
async fn unattributed_prompt_is_delivered_to_any_session() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;
    let mut prompts = client
        .stream_prompts("test".into())
        .await
        .expect("subscribing to prompts");

    let mut orphan = process();
    orphan.uid = None;
    d.push_prompt_for(78, orphan).await;

    let event = next_message(&mut prompts).await;
    assert_eq!(event.prompt_id, "78");
    assert_eq!(
        event.process.expect("process").uid,
        None,
        "the wire must keep 'unknown owner' distinct from uid 0"
    );

    // Delivered, therefore answerable.
    assert!(
        client
            .submit_verdict("78", pb::Action::Deny, pb::Duration::Once, None)
            .await
            .expect("submitting the verdict")
            .accepted
    );
    assert_eq!(d.next_verdict().await.verdict.action, Action::Deny);
}

// ---------------------------------------------------------------------------
// Peer-credential authorization (wave 3)
// ---------------------------------------------------------------------------

/// The production shape: `require_group = true` with a socket the daemon
/// could not gate (no such group / not root). Mutating RPCs must be refused
/// for non-root peers; read-only RPCs must still work.
#[tokio::test]
async fn require_group_refuses_non_root_mutation() {
    let d = TestDaemon::builder().require_group(true).build().await;
    let mut client = d.client().await;

    // Read-only stays open: layer 1 (the socket mode) already decided who
    // may connect at all.
    client.status().await.expect("status is read-only");
    assert!(client
        .list_rules()
        .await
        .expect("list_rules is read-only")
        .is_empty());

    let result = client
        .upsert_rule(rule_pb("blocked", pb::Action::Deny, scope_port(25)))
        .await;

    if running_as_root() {
        assert!(
            result.is_ok(),
            "root may always mutate, gated socket or not"
        );
    } else {
        let status = status_of(result.expect_err("a non-root mutation must be refused"));
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(
            status.message().contains("uid 0"),
            "unexpected message: {}",
            status.message()
        );
        // And nothing was written on the way to the refusal.
        assert!(client.list_rules().await.expect("listing rules").is_empty());
    }
}

// ---------------------------------------------------------------------------
// 4. Rules CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rules_crud_round_trip_and_deterministic_order() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;

    // Inserted in an order that does *not* match the precedence order, so
    // the assertion below can only pass if the daemon sorts.
    let broad_allow = client
        .upsert_rule(rule_pb("broad-allow", pb::Action::Allow, scope_port(443)))
        .await
        .expect("upserting broad-allow");
    let specific_allow = client
        .upsert_rule(rule_pb(
            "specific-allow",
            pb::Action::Allow,
            pb::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                protocol: pb::Protocol::Tcp as i32,
                has_protocol: true,
                ..scope_port(443)
            },
        ))
        .await
        .expect("upserting specific-allow");
    let broad_deny = client
        .upsert_rule(rule_pb("broad-deny", pb::Action::Deny, scope_port(443)))
        .await
        .expect("upserting broad-deny");

    // specificity DESC, then Deny before Allow on ties (see
    // RuleSet::sort_deterministic).
    let names: Vec<String> = client
        .list_rules()
        .await
        .expect("listing rules")
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(names, ["specific-allow", "broad-deny", "broad-allow"]);

    // An upsert carrying an existing id replaces in place rather than adding.
    let mut renamed = rule_pb("broad-deny-renamed", pb::Action::Deny, scope_port(443));
    renamed.id.clone_from(&broad_deny);
    let same_id = client.upsert_rule(renamed).await.expect("re-upserting");
    assert_eq!(same_id, broad_deny);
    let rules = client.list_rules().await.expect("listing rules");
    assert_eq!(rules.len(), 3);
    assert!(rules.iter().any(|r| r.name == "broad-deny-renamed"));

    // Delete: a known id once, then not again.
    assert!(client
        .delete_rule(&broad_allow)
        .await
        .expect("deleting a known rule"));
    assert!(
        !client
            .delete_rule(&broad_allow)
            .await
            .expect("deleting twice"),
        "a second delete reports not-found rather than failing"
    );
    // An unknown but well-formed id is simply not found.
    assert!(!client
        .delete_rule(&uuid::Uuid::new_v4().to_string())
        .await
        .expect("deleting an unknown id"));
    // A malformed id is a client error.
    let status = status_of(
        client
            .delete_rule("not-a-uuid")
            .await
            .expect_err("a malformed id must be rejected"),
    );
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    let left: Vec<String> = client
        .list_rules()
        .await
        .expect("listing rules")
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(left.len(), 2);
    assert!(left.contains(&specific_allow));
    assert!(left.contains(&broad_deny));
    // The deletion reached sqlite, not just the engine.
    let reopened = RuleStore::open(&d.db).expect("reopening the store");
    assert_eq!(reopened.snapshot().expect("snapshot").rules.len(), 2);
}

/// Wave-3 fail-closed conversions: nothing a default-initialized or
/// version-skewed client can send may be silently interpreted.
#[tokio::test]
async fn rules_upsert_rejects_unpersistable_and_unspecified_input() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;

    let cases: Vec<(&str, pb::RuleInfo)> = vec![
        ("Once cannot be persisted", {
            let mut r = rule_pb("once", pb::Action::Deny, scope_port(25));
            r.duration = pb::Duration::Once as i32;
            r
        }),
        ("unspecified action", {
            let mut r = rule_pb("no-action", pb::Action::Deny, scope_port(25));
            r.action = pb::Action::Unspecified as i32;
            r
        }),
        ("unspecified duration", {
            let mut r = rule_pb("no-duration", pb::Action::Deny, scope_port(25));
            r.duration = pb::Duration::Unspecified as i32;
            r
        }),
        ("out-of-range action", {
            let mut r = rule_pb("bad-action", pb::Action::Deny, scope_port(25));
            r.action = 99;
            r
        }),
    ];

    for (what, rule) in cases {
        let err = client
            .upsert_rule(rule)
            .await
            .err()
            .unwrap_or_else(|| panic!("{what} must be rejected"));
        assert_eq!(
            status_of(err).code(),
            tonic::Code::InvalidArgument,
            "{what}"
        );
    }

    // A request with no rule at all is equally a client error.
    let status = client
        .raw()
        .upsert_rule(pb::UpsertRuleRequest { rule: None })
        .await
        .expect_err("a missing rule must be rejected");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    assert!(
        client.list_rules().await.expect("listing rules").is_empty(),
        "a rejected upsert must not persist anything"
    );
}

// ---------------------------------------------------------------------------
// 5. Pause
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pause_reports_its_deadline_and_auto_resumes() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;

    let before = chrono::Utc::now().timestamp_millis();
    let resp = client.set_paused(true, 60).await.expect("pausing");
    let after = chrono::Utc::now().timestamp_millis();
    assert!(resp.paused);
    assert!(
        resp.resume_at_unix_ms >= before + 60_000 && resp.resume_at_unix_ms <= after + 60_000,
        "resume_at {} outside [{}, {}]",
        resp.resume_at_unix_ms,
        before + 60_000,
        after + 60_000
    );

    let status = client.status().await.expect("status");
    assert!(status.paused);
    assert_eq!(status.resume_at_unix_ms, resp.resume_at_unix_ms);
    assert!(d.stats.is_paused());

    // The auto-resume timer is tokio-based, so this costs no real time.
    advance_until("auto-resume", Duration::from_secs(10), 12, || {
        !d.stats.is_paused()
    })
    .await;

    let status = client.status().await.expect("status");
    assert!(!status.paused);
    assert_eq!(
        status.resume_at_unix_ms, 0,
        "a daemon that is not paused has no deadline"
    );
}

#[tokio::test]
async fn pause_without_a_duration_uses_the_configured_default() {
    let d = TestDaemon::builder().pause_default_secs(120).build().await;
    let mut client = d.client().await;

    let before = chrono::Utc::now().timestamp_millis();
    let resp = client.set_paused(true, 0).await.expect("pausing");
    assert!(resp.resume_at_unix_ms >= before + 120_000);
    assert!(resp.resume_at_unix_ms <= chrono::Utc::now().timestamp_millis() + 120_000);

    // Still paused long after a shorter default would have expired...
    jump(Duration::from_secs(30)).await;
    assert!(d.stats.is_paused(), "the pause is 120s, not 30s");
    // ...and resumed once the configured default elapses.
    advance_until(
        "auto-resume at the default",
        Duration::from_secs(15),
        12,
        || !d.stats.is_paused(),
    )
    .await;
}

/// Generation-counter semantics: an explicit resume invalidates the pending
/// auto-resume, so it cannot later end a *newer* pause.
#[tokio::test]
async fn explicit_resume_invalidates_the_pending_auto_resume() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;

    client.set_paused(true, 60).await.expect("pausing"); // timer A, +60s
    let resumed = client.set_paused(false, 0).await.expect("resuming");
    assert!(!resumed.paused);
    assert_eq!(resumed.resume_at_unix_ms, 0);
    assert!(!d.stats.is_paused());

    let second = client.set_paused(true, 3600).await.expect("re-pausing"); // timer B

    // Timer A fires somewhere in here. Its generation is stale, so it must
    // do nothing at all.
    jump(Duration::from_secs(120)).await;

    let status = client.status().await.expect("status");
    assert!(
        status.paused,
        "a stale auto-resume must not end a newer pause"
    );
    assert_eq!(status.resume_at_unix_ms, second.resume_at_unix_ms);

    // Timer B still works.
    advance_until(
        "the live timer to auto-resume",
        Duration::from_secs(300),
        15,
        || !d.stats.is_paused(),
    )
    .await;
    assert!(!client.status().await.expect("status").paused);
}

// ---------------------------------------------------------------------------
// 6. ListEvents
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_events_filters_and_pages() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;

    // Fixed timestamps keep the ordering assertions exact.
    d.store
        .insert_events(&[
            event_row(1000, "/usr/bin/curl", "Allow"),
            event_row(2000, "/usr/bin/wget", "Deny"),
            event_row(3000, "/usr/bin/curl", "Deny"),
            event_row(4000, "/usr/bin/firefox", "Allow"),
        ])
        .expect("seeding events");

    // Newest first, and limit = 0 means the daemon's default page size.
    let all = client
        .list_events(pb::ListEventsRequest::default())
        .await
        .expect("listing events");
    assert_eq!(all.len(), 4);
    assert_eq!(all[0].ts_unix_ms, 4000);
    assert_eq!(all[3].ts_unix_ms, 1000);
    assert_eq!(all[0].dst_host, "example.com");
    assert_eq!(all[0].uid, Some(1000));
    assert_eq!(all[3].action, pb::Action::Allow as i32);

    // Paging.
    let page = client
        .list_events(pb::ListEventsRequest {
            limit: 2,
            offset: 1,
            ..Default::default()
        })
        .await
        .expect("listing page 2");
    assert_eq!(
        page.iter().map(|e| e.ts_unix_ms).collect::<Vec<_>>(),
        [3000, 2000]
    );

    // exe substring.
    let curls = client
        .list_events(pb::ListEventsRequest {
            exe_contains: "curl".into(),
            ..Default::default()
        })
        .await
        .expect("filtering by exe");
    assert_eq!(curls.len(), 2);
    assert!(curls.iter().all(|e| e.exe == "/usr/bin/curl"));

    // action.
    let denies = client
        .list_events(pb::ListEventsRequest {
            action_filter: pb::Action::Deny as i32,
            ..Default::default()
        })
        .await
        .expect("filtering by action");
    assert_eq!(denies.len(), 2);
    assert!(denies.iter().all(|e| e.action == pb::Action::Deny as i32));

    // since.
    let recent = client
        .list_events(pb::ListEventsRequest {
            since_unix_ms: 3000,
            ..Default::default()
        })
        .await
        .expect("filtering by since");
    assert_eq!(recent.len(), 2);

    // Filters AND together, and total_returned matches the page.
    let combined = client
        .raw()
        .list_events(pb::ListEventsRequest {
            limit: 10,
            exe_contains: "curl".into(),
            action_filter: pb::Action::Deny as i32,
            since_unix_ms: 2000,
            ..Default::default()
        })
        .await
        .expect("combined filter")
        .into_inner();
    assert_eq!(combined.events.len(), 1);
    assert_eq!(combined.events[0].ts_unix_ms, 3000);
    assert_eq!(combined.total_returned, 1);

    // An unrecognised action filter is rejected rather than ignored.
    let status = client
        .raw()
        .list_events(pb::ListEventsRequest {
            action_filter: 99,
            ..Default::default()
        })
        .await
        .expect_err("an unknown action filter must be rejected");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// The other half of that surface: rows the daemon writes itself, from the
/// live feed, through the batching pipeline `main` spawns.
#[tokio::test]
async fn observed_connections_reach_list_events_through_the_pipeline() {
    let d = TestDaemon::builder().event_pipeline(1000).build().await;
    let mut client = d.client().await;

    d.observed_tx
        .send(observed(443, Action::Allow))
        .expect("the pipeline is subscribed");
    d.observed_tx
        .send(observed(25, Action::Deny))
        .expect("the pipeline is subscribed");

    // The writer batches for a second before it touches sqlite.
    advance_until("events to be written", Duration::from_secs(1), 10, || {
        d.event_count() == 2
    })
    .await;

    let events = client
        .list_events(pb::ListEventsRequest::default())
        .await
        .expect("listing events");
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .any(|e| e.dst_port == 443 && e.action == pb::Action::Allow as i32));
    assert!(events
        .iter()
        .any(|e| e.dst_port == 25 && e.action == pb::Action::Deny as i32));
    assert!(events.iter().all(|e| e.exe == "/usr/bin/curl"));
}

// ---------------------------------------------------------------------------
// 7. GetStatus
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_reports_rules_policy_and_skipped_rows() {
    let d = TestDaemon::builder()
        .policy(DefaultPolicy {
            no_ui_action: Action::Allow,
            timeout_action: Action::Reject,
            inbound_action: cfc_core::Action::Deny,
            prompt_timeout_secs: 42,
        })
        .build()
        .await;
    let mut client = d.client().await;

    let status = client.status().await.expect("status");
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(status.rules_count, 0);
    assert_eq!(status.prompts_pending, 0);
    assert_eq!(status.connections_seen, 0);
    assert!(!status.paused);
    assert_eq!(status.resume_at_unix_ms, 0);
    assert_eq!(status.skipped_rules, 0);
    // The live SharedPolicy, not a copy taken at startup.
    assert_eq!(status.no_ui_action, pb::Action::Allow as i32);
    assert_eq!(status.timeout_action, pb::Action::Reject as i32);
    assert_eq!(status.prompt_timeout_secs, 42);
    // Nothing has been seen yet, but we are inside the grace period, so the
    // daemon does not yet claim to be out of the packet path.
    assert!(status.enforcing);
    // `Stats` measures uptime with std::time::Instant - real time, immune to
    // tokio's clock - so a sub-second test can only assert that it is sane.
    // Asserting "nonzero" would mean sleeping a real second for nothing.
    assert!(status.uptime_seconds < 60);

    client
        .upsert_rule(rule_pb("counted", pb::Action::Deny, scope_port(25)))
        .await
        .expect("upserting");
    assert_eq!(client.status().await.expect("status").rules_count, 1);

    // A SIGHUP-style policy swap is visible without a restart.
    *d.policy.write().expect("policy lock") = DefaultPolicy {
        no_ui_action: Action::Deny,
        timeout_action: Action::Deny,
        inbound_action: cfc_core::Action::Deny,
        prompt_timeout_secs: 7,
    };
    let status = client.status().await.expect("status");
    assert_eq!(status.no_ui_action, pb::Action::Deny as i32);
    assert_eq!(status.prompt_timeout_secs, 7);

    // A rule row that no longer deserializes must be *counted*, not hidden:
    // it means rules exist on disk that are not being enforced.
    rusqlite::Connection::open(&d.db)
        .expect("opening the db directly")
        .execute(
            "INSERT INTO rules(id, enabled, data) VALUES('bad-row', 1, '{\"not\":\"a rule\"}')",
            [],
        )
        .expect("inserting a corrupt row");
    // The counter is refreshed by a load, exactly as at daemon start.
    let snapshot = d.store.snapshot().expect("snapshot");
    assert_eq!(snapshot.rules.len(), 1, "the corrupt row is skipped");

    let status = client.status().await.expect("status");
    assert_eq!(status.skipped_rules, 1);
    assert_eq!(status.rules_count, 1, "skipped rows are not enforced");
}

// ---------------------------------------------------------------------------
// 8. StreamConnections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stream_connections_maps_the_live_feed() {
    let d = TestDaemon::build().await;
    let mut client = d.client().await;

    let mut stream = client
        .stream_connections("test".into())
        .await
        .expect("subscribing to connections");

    let rule_id = uuid::Uuid::new_v4();
    let mut conn = connection(443);
    conn.dst_host = Some("example.com".into());
    d.observed_tx
        .send(ObservedConnection {
            connection: conn,
            process: process(),
            verdict: Verdict::deny_from_rule(rule_id),
        })
        .expect("a subscriber exists");

    let event = next_message(&mut stream).await;
    assert_eq!(event.verdict, pb::Action::Deny as i32);
    assert_eq!(event.rule_id, rule_id.to_string());

    let c = event.connection.expect("connection");
    assert_eq!(c.src_ip, "10.0.0.5");
    assert_eq!(c.src_port, 54321);
    assert_eq!(c.dst_ip, "1.1.1.1");
    assert_eq!(c.dst_port, 443);
    assert_eq!(c.dst_host, "example.com");
    assert_eq!(c.protocol, pb::Protocol::Tcp as i32);
    assert_eq!(c.direction, pb::Direction::Outbound as i32);

    let p = event.process.expect("process");
    assert_eq!(p.pid, 4242);
    assert_eq!(p.exe, "/usr/bin/curl");
    assert_eq!(p.uid, Some(1000));

    // A verdict with no rule behind it leaves rule_id empty rather than
    // inventing one.
    d.observed_tx
        .send(observed(80, Action::Allow))
        .expect("a subscriber exists");
    let event = next_message(&mut stream).await;
    assert_eq!(event.verdict, pb::Action::Allow as i32);
    assert!(event.rule_id.is_empty());
}
