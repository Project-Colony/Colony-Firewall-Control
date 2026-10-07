//! gRPC server over a Unix domain socket.
//!
//! # Trust model
//!
//! The daemon runs as root and controls the machine's packet filter, so the
//! control socket is the whole attack surface. Access is gated in two
//! layers:
//!
//! 1. **The socket file.** After bind, the daemon chowns the socket to
//!    `root:<[ipc] group>` and chmods it `0660`. The kernel therefore
//!    refuses `connect(2)` to anyone outside that group. Membership *is*
//!    the credential; there is no in-band authentication. If the group
//!    cannot be resolved (package installed without the sysusers fragment)
//!    the daemon logs a prominent warning, leaves the socket `0600`
//!    (root-only) and keeps running, so a root CLI still works.
//!
//! 2. **Per-RPC peer credentials.** Mutations require uid 0 or actual
//!    membership of the configured group. The kernel peer gid proves primary
//!    membership. Supplementary membership requires `/proc/<peer pid>/status`
//!    with the same effective uid and process starttime captured at accept.
//!    Missing evidence is refused. `require_group = false` explicitly opts
//!    out for deployments authorizing their control socket another way.
//!
//! Consequence worth stating plainly: **every member of the configured
//! group is fully trusted.** Group membership grants the ability to allow
//! or deny any traffic on the host. It is not a multi-user privilege
//! boundary; put only administrators of this machine in it.
//!
//! # Prompt ownership
//!
//! Prompts travel on one broadcast, but they are *addressed*. Two steps:
//!
//! 1. **Delivery is uid-scoped.** Each subscriber stream drops events it is
//!    not entitled to see ([`should_deliver`]): a prompt goes to the
//!    session that owns the process it is about, plus root (which sees
//!    everything), plus - when the process could not be attributed at all -
//!    everyone. So another user's UI never even learns the prompt id.
//! 2. **Answers are checked against who was told.** A stream records
//!    `prompt_id -> peer uid` as it hands an event to its client
//!    ([`PromptAudience`]); `SubmitVerdict` requires the caller's uid to
//!    appear in that prompt's audience. Root may always answer.
//!
//! Step 2 alone was bookkeeping without teeth - every subscriber received
//! every prompt, so every subscriber was in every audience. Step 1 is what
//! makes the recorded audience mean "the sessions this prompt was for".

use crate::config::IpcConfig;
use crate::convert;
use crate::decision::{Engine, SharedPolicy};
use crate::nfqueue::{ObservedConnection, PromptRequest, PromptTx};
use crate::prompts::{should_deliver, PromptRouter};
use crate::stats::Stats;
use crate::storage::{EventFilter, EventRow, RuleStore};
use anyhow::Context;
use futures::StreamExt;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tonic::transport::server::{Connected, UdsConnectInfo};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

/// Validates a rule's explicit executable target without blocking IPC.
///
/// `canonicalize` is a synchronous syscall on a path any `colony-firewall`
/// group member supplies, and this runs inside a `#[tonic::async_trait]`
/// handler on the shared runtime. A path under a hung NFS mount or an
/// unreachable autofs trigger would otherwise park a worker thread with no
/// timeout; enough concurrent calls and the prompt-delivery tasks stall, which
/// resolves every waiting connection to `no_ui_action` - Deny. The same
/// reasoning already puts `dns.rs` and `nfqueue.rs`'s blocking calls on the
/// blocking pool.
///
/// Missing canonical targets support preinstallation; aliases, other lookup
/// failures and worker failures refuse the policy write.
///
/// Advisory for paths the unit's sandbox hides: under `ProtectHome` and
/// `PrivateTmp` an alias in `/home` or `/tmp` looks like a target that is not
/// installed yet and is accepted. The CLI and GUI run the same check in the
/// caller's namespace first. The stored path is still matched literally, so
/// such a rule never applies to the alias's target.
async fn resolve_exe_off_thread(scope: &mut cfc_core::RuleScope) -> Result<(), Status> {
    let Some(current) = scope.exe_path.clone() else {
        return Ok(());
    };
    let outcome = tokio::task::spawn_blocking(move || cfc_core::exe_path::resolve_policy(&current))
        .await
        .map_err(|error| {
            Status::internal(format!(
                "executable policy validation worker failed: {error}"
            ))
        })?
        .map_err(Status::invalid_argument)?;
    if let Some(note) = outcome.note() {
        info!("rule exe path: {note}");
    }
    scope.exe_path = Some(outcome.into_path());
    Ok(())
}

/// Whether `rule` sends back the executable path already stored under its id.
///
/// That path was validated when it was written, or predates validation, and
/// sending it back changes nothing about what the rule matches. Validating it
/// again refused every edit of a rule whose target had since become an alias
/// (a package update turned it into a symlink, or a legacy `/bin/curl`), so
/// disabling, renaming or re-importing it failed and only delete was left. A
/// new rule or a changed path is still validated.
fn keeps_stored_exe(stored: &cfc_core::RuleSet, rule: &cfc_core::Rule) -> bool {
    rule.scope.exe_path.is_some()
        && stored
            .rules
            .iter()
            .any(|old| old.id == rule.id && old.scope.exe_path == rule.scope.exe_path)
}

/// Logs a rule write the daemon refused, with its reason.
///
/// Without it the journal held only successful writes and authorization
/// refusals, so "the client never sent it" and "the daemon refused it" looked
/// the same (issue #46). Authorization refusals are logged by `authorize`.
fn log_refusal(rpc: &'static str, peer: PeerId, status: &Status) {
    warn!(
        rpc,
        peer_uid = peer.uid,
        peer_pid = ?peer.pid,
        code = ?status.code(),
        reason = status.message(),
        outcome = "refused",
        "rule write refused"
    );
}

fn bind_prompt_allow(
    rule: &mut cfc_core::Rule,
    binding: &crate::prompts::PromptBinding,
) -> Result<(), String> {
    if rule.action != cfc_core::Action::Allow || !binding.hash_expected {
        return Ok(());
    }
    if rule.scope.exe_path != binding.exe || binding.exe.is_none() {
        return Err(
            "the persisted Allow must name the prompted image; its executable path changed".into(),
        );
    }
    let hash = binding
        .sha256
        .as_ref()
        .ok_or("the prompted executable requires a hash, but its image could not be hashed")?;
    if rule
        .scope
        .exe_sha256
        .as_ref()
        .is_some_and(|existing| existing != hash)
    {
        return Err("the persisted Allow hash differs from the prompted image".into());
    }
    rule.scope.exe_sha256 = Some(hash.clone());
    Ok(())
}

use cfc_proto::v1::{
    firewall_server::{Firewall, FirewallServer},
    ApplyRulesRequest, ApplyRulesResponse, ConnectionEvent, DeleteRuleRequest, DeleteRuleResponse,
    ListEventsRequest, ListEventsResponse, ListRulesRequest, ListRulesResponse, PromptEvent,
    RuleInfo, SetPausedRequest, SetPausedResponse, StatusRequest, StatusResponse, SubscribeRequest,
    UpsertRuleRequest, UpsertRuleResponse, VerdictRequest, VerdictResponse,
};

/// Hard ceiling on a pause, regardless of what a client asks for. A pause
/// is "stop filtering", so it must always end by itself.
const MAX_PAUSE_SECS: u64 = 24 * 60 * 60;

/// How long the daemon may see zero packets before `enforcing` flips false.
const ENFORCING_GRACE_SECS: u64 = 60;

/// Page size used when a client asks for `limit = 0`, and the ceiling on
/// what it may ask for.
const DEFAULT_EVENT_PAGE: u32 = 100;
const MAX_EVENT_PAGE: u32 = 1000;

/// Largest `offset` a `ListEvents` request may skip to.
///
/// `limit` was clamped and `offset` was not, and sqlite pays for a skipped row
/// much as it pays for a returned one: `OFFSET n` steps and discards n rows,
/// applying the `instr(exe, ?)` filter to each, with no index to help. The
/// event table is capped at `[events] max_rows`, so any offset past this can
/// only ever return nothing - clamping it removes no reachable page.
const MAX_EVENT_OFFSET: u32 = 1_000_000;

/// Depth of the datapath -> event-writer queue. The writer batches, so this
/// only needs to absorb a burst, never sustained throughput.
const EVENT_QUEUE_DEPTH: usize = 4096;
/// Rows per database transaction, and the maximum time a row waits for one.
const EVENT_BATCH_ROWS: usize = 256;
const EVENT_BATCH_INTERVAL_SECS: u64 = 1;
/// How often the writer trims the events table to `[events] max_rows`.
const EVENT_PRUNE_INTERVAL_SECS: u64 = 60;
/// Emit a warning every N dropped events rather than once per drop.
const EVENT_DROP_LOG_EVERY: u64 = 1000;

/// Bound on remembered prompt audiences. Prompts resolve within seconds, so
/// this only ever holds live entries plus a little slack.
const AUDIENCE_CAP: usize = 4096;

// ---------------------------------------------------------------------------
// Peer identity and authorization
// ---------------------------------------------------------------------------

/// Credentials of the process on the other end of the connection, as
/// reported by the kernel (`SO_PEERCRED`) - unforgeable by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerId {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    pub starttime: Option<u64>,
}

/// Privilege an RPC requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Observing daemon state.
    ReadOnly,
    /// Changing the firewall's behaviour.
    Mutate,
}

/// Outcome of securing the socket file, and the policy knobs that decide
/// what it implies for callers.
#[derive(Debug, Clone)]
struct SocketAuth {
    group: String,
    group_gid: Option<u32>,
    /// True only when the socket really is `root:<group>` mode 0660, i.e.
    /// the kernel is enforcing group membership on `connect(2)`.
    group_gated: bool,
    require_group: bool,
}

/// Pure policy over membership proved from the individual peer credentials.
fn authorize_uid(uid: u32, level: Access, group_member: bool, require_group: bool) -> bool {
    match level {
        // Layer 1 (socket mode) already decided who may connect at all.
        Access::ReadOnly => true,
        Access::Mutate => uid == 0 || !require_group || group_member,
    }
}

/// Extracts kernel-reported peer credentials from a request.
fn peer_of<T>(req: &Request<T>) -> Result<PeerId, Status> {
    if let Some(peer) = req.extensions().get::<PeerId>() {
        return Ok(*peer);
    }
    let info = req
        .extensions()
        .get::<UdsConnectInfo>()
        .ok_or_else(|| Status::permission_denied("connection carries no peer credentials"))?;
    let cred = info
        .peer_cred
        .ok_or_else(|| Status::permission_denied("peer credentials unavailable"))?;
    Ok(PeerId {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: cred.pid(),
        starttime: cred
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .and_then(crate::process_resolve::read_starttime),
    })
}

struct PeerStream {
    stream: tokio::net::UnixStream,
    peer: PeerId,
}

impl PeerStream {
    fn new(stream: tokio::net::UnixStream) -> std::io::Result<Self> {
        let credentials = stream.peer_cred()?;
        let pid = credentials.pid();
        let starttime = pid
            .and_then(|pid| u32::try_from(pid).ok())
            .and_then(crate::process_resolve::read_starttime);
        Ok(Self {
            stream,
            peer: PeerId {
                uid: credentials.uid(),
                gid: credentials.gid(),
                pid,
                starttime,
            },
        })
    }
}
impl Connected for PeerStream {
    type ConnectInfo = PeerId;
    fn connect_info(&self) -> PeerId {
        self.peer
    }
}
impl AsyncRead for PeerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}
impl AsyncWrite for PeerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, bytes)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

fn peer_is_group_member(peer: PeerId, gid: Option<u32>) -> bool {
    let Some(gid) = gid else {
        return false;
    };
    if peer.gid == gid {
        return true;
    }
    let Some(pid) = peer.pid.filter(|pid| *pid > 0) else {
        return false;
    };
    if peer.starttime.is_none()
        || crate::process_resolve::read_starttime(pid as u32) != peer.starttime
    {
        return false;
    }
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    status_proves_group(&status, peer.uid, gid)
        && crate::process_resolve::read_starttime(pid as u32) == peer.starttime
}

fn status_proves_group(status: &str, uid: u32, gid: u32) -> bool {
    let effective_uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|values| values.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok());
    effective_uid == Some(uid)
        && status
            .lines()
            .find_map(|line| line.strip_prefix("Groups:"))
            .is_some_and(|groups| {
                groups
                    .split_whitespace()
                    .any(|value| value.parse::<u32>().ok() == Some(gid))
            })
}

// ---------------------------------------------------------------------------
// Prompt ownership
// ---------------------------------------------------------------------------

/// Which peers actually received a given prompt. See the module docs.
#[derive(Default)]
struct PromptAudience {
    inner: Mutex<AudienceInner>,
}

#[derive(Default)]
struct AudienceInner {
    by_prompt: HashMap<u64, HashSet<u32>>,
    /// Insertion order, for FIFO eviction once `AUDIENCE_CAP` is reached.
    order: VecDeque<u64>,
}

impl PromptAudience {
    /// Notes that `uid` was handed `prompt_id`.
    fn record(&self, prompt_id: u64, uid: u32) {
        let mut g = self.inner.lock();
        let first_sighting = !g.by_prompt.contains_key(&prompt_id);
        g.by_prompt.entry(prompt_id).or_default().insert(uid);
        if first_sighting {
            g.order.push_back(prompt_id);
        }
        while g.order.len() > AUDIENCE_CAP {
            if let Some(old) = g.order.pop_front() {
                g.by_prompt.remove(&old);
            }
        }
    }

    /// True when `uid` is entitled to answer `prompt_id`.
    fn allows(&self, prompt_id: u64, uid: u32) -> bool {
        self.inner
            .lock()
            .by_prompt
            .get(&prompt_id)
            .is_some_and(|s| s.contains(&uid))
    }

    /// Drops the bookkeeping for a resolved prompt.
    fn forget(&self, prompt_id: u64) {
        let mut g = self.inner.lock();
        if g.by_prompt.remove(&prompt_id).is_some() {
            g.order.retain(|id| *id != prompt_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

struct FirewallService {
    engine: Engine,
    store: RuleStore,
    observed_tx: broadcast::Sender<ObservedConnection>,
    router: PromptRouter,
    stats: Stats,
    /// Live default policy; SIGHUP swaps it, so status reflects reloads.
    policy: SharedPolicy,
    auth: SocketAuth,
    audience: Arc<PromptAudience>,
    /// Wall-clock deadline of the current pause, 0 when not paused. Held
    /// here rather than in `Stats` so the pause timer and `GetStatus` agree.
    resume_at_ms: Arc<AtomicI64>,
    pause_default_secs: u64,
    dry_run: bool,
    mutations: Mutex<()>,
}

impl FirewallService {
    /// Resolves the caller and checks it may perform `level`.
    fn authorize<T>(&self, req: &Request<T>, level: Access) -> Result<PeerId, Status> {
        let peer = peer_of(req)?;
        if authorize_uid(
            peer.uid,
            level,
            peer_is_group_member(peer, self.auth.group_gid),
            self.auth.require_group,
        ) {
            return Ok(peer);
        }
        warn!(
            peer_uid = peer.uid,
            peer_pid = ?peer.pid,
            group = %self.auth.group,
            "refusing mutating RPC: caller is not a member of the configured group"
        );
        Err(Status::permission_denied(format!(
            "mutating RPCs require uid 0 or membership of group '{}'",
            self.auth.group
        )))
    }

    async fn upsert_rule_checked(
        &self,
        peer: PeerId,
        req: UpsertRuleRequest,
    ) -> Result<UpsertRuleResponse, Status> {
        let proto = req
            .rule
            .ok_or_else(|| Status::invalid_argument("rule required"))?;
        let mut rule = convert::rule_from_pb(&proto).map_err(Status::invalid_argument)?;
        convert::reject_unpersistable_duration(rule.duration).map_err(Status::invalid_argument)?;
        // Every caller must select the canonical mapped target explicitly.
        // Missing targets with unchanged ancestry remain valid for preinstallation.
        if !keeps_stored_exe(&self.engine.snapshot(), &rule) {
            resolve_exe_off_thread(&mut rule.scope).await?;
        }
        // hit_count and created_at belong to the daemon: a client editing a
        // rule must not be able to rewrite its history, deliberately or (as
        // every read-modify-write client did) by echoing back a count that
        // already included an unflushed delta.
        let _mutation = self.mutations.lock();
        if rule.duration == cfc_core::Duration::Always
            && self.engine.snapshot().rules.iter().any(|old| {
                old.id == rule.id && matches!(old.duration, cfc_core::Duration::Seconds(_))
            })
        {
            return Err(Status::invalid_argument(
                "a timed rule cannot become Always in place; delete it and create a new rule",
            ));
        }
        self.engine.preserve_server_owned(&mut rule);
        self.store
            .upsert(&rule)
            .map_err(|e| Status::internal(format!("storage: {e}")))?;
        let id = rule.id.to_string();
        info!(
            rpc = "UpsertRule",
            peer_uid = peer.uid,
            peer_pid = ?peer.pid,
            rule_id = %id,
            action = ?rule.action,
            duration = ?rule.duration,
            enabled = rule.enabled,
            outcome = "ok",
            "rule upserted"
        );
        self.engine.upsert_rule(rule);
        Ok(UpsertRuleResponse {
            id,
            error: String::new(),
        })
    }

    async fn apply_rules_checked(
        &self,
        peer: PeerId,
        req: ApplyRulesRequest,
    ) -> Result<ApplyRulesResponse, Status> {
        if req.replace && req.rules.is_empty() {
            return Err(Status::invalid_argument("refusing an empty replacement"));
        }
        let mut pending = Vec::with_capacity(req.rules.len());
        let mut ids = HashSet::new();
        let stored = self.engine.snapshot();
        for proto in req.rules {
            let mut rule = convert::rule_from_pb(&proto).map_err(Status::invalid_argument)?;
            convert::reject_unpersistable_duration(rule.duration)
                .map_err(Status::invalid_argument)?;
            if !ids.insert(rule.id) {
                return Err(Status::invalid_argument("duplicate rule id"));
            }
            if !keeps_stored_exe(&stored, &rule) {
                resolve_exe_off_thread(&mut rule.scope).await?;
            }
            pending.push(rule);
        }
        let _mutation = self.mutations.lock();
        let existing = self.engine.snapshot();
        for rule in &mut pending {
            if rule.duration == cfc_core::Duration::Always
                && existing.rules.iter().any(|old| {
                    old.id == rule.id && matches!(old.duration, cfc_core::Duration::Seconds(_))
                })
            {
                return Err(Status::invalid_argument(
                    "a timed rule cannot become Always in place; delete it and create a new rule",
                ));
            }
            self.engine.preserve_server_owned(rule);
        }
        let removed = self
            .store
            .apply_rules(&pending, req.replace)
            .map_err(|e| Status::internal(format!("storage: {e}")))?;
        let assigned: Vec<String> = pending.iter().map(|rule| rule.id.to_string()).collect();
        info!(
            rpc = "ApplyRules",
            peer_uid = peer.uid,
            peer_pid = ?peer.pid,
            replace = req.replace,
            applied = assigned.len(),
            removed,
            rule_ids = ?assigned,
            outcome = "ok",
            "rules applied"
        );
        let mut final_rules = if req.replace {
            Vec::new()
        } else {
            self.engine.snapshot().rules
        };
        final_rules.retain(|rule| !ids.contains(&rule.id));
        final_rules.extend(pending);
        self.engine.replace_rules(final_rules);
        Ok(ApplyRulesResponse {
            ids: assigned,
            removed: u32::try_from(removed).unwrap_or(u32::MAX),
        })
    }

    fn policy(&self) -> crate::config::DefaultPolicy {
        *self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[tonic::async_trait]
impl Firewall for FirewallService {
    type StreamPromptsStream = tokio_stream::wrappers::ReceiverStream<Result<PromptEvent, Status>>;

    async fn stream_prompts(
        &self,
        req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::StreamPromptsStream>, Status> {
        let peer = self.authorize(&req, Access::ReadOnly)?;
        let (tx, rx) = mpsc::channel(64);
        let mut sub = self.router.subscribe(peer.uid);
        let audience = self.audience.clone();
        let uid = peer.uid;
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        // Addressing: the feed is shared, this stream is
                        // not. Skip prompts about another session's
                        // process, so this peer never learns the id and
                        // never enters the prompt's audience. A prompt
                        // with no process info at all (the router always
                        // fills it in, so: never) counts as unattributed
                        // rather than being dropped on the floor.
                        let owner_uid = event.process.as_ref().and_then(|p| p.uid);
                        if !should_deliver(owner_uid, uid) {
                            if tx.is_closed() {
                                break;
                            }
                            continue;
                        }
                        // Record before handing the event over: this
                        // subscriber is about to learn the prompt id, so it
                        // must be entitled to answer it by the time it can.
                        if let Ok(id) = event.prompt_id.parse::<u64>() {
                            audience.record(id, uid);
                        }
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("prompt stream client lagged by {n} prompts");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn submit_verdict(
        &self,
        req: Request<VerdictRequest>,
    ) -> Result<Response<VerdictResponse>, Status> {
        let peer = self.authorize(&req, Access::Mutate)?;
        let req = req.into_inner();

        // Ownership: only a peer this prompt was actually delivered to may
        // answer it. Root is exempt (it can do everything anyway).
        let numeric_id = req.prompt_id.parse::<u64>().ok();
        if peer.uid != 0 {
            let owned = numeric_id.is_some_and(|id| self.audience.allows(id, peer.uid));
            if !owned {
                warn!(
                    rpc = "SubmitVerdict",
                    peer_uid = peer.uid,
                    peer_pid = ?peer.pid,
                    prompt_id = %req.prompt_id,
                    outcome = "permission_denied",
                    "verdict rejected: prompt was not delivered to this peer"
                );
                return Err(Status::permission_denied(
                    "this prompt was not delivered to you",
                ));
            }
        }

        let action = convert::action_from_pb(req.action).map_err(Status::invalid_argument)?;
        let verdict = cfc_core::Verdict {
            action,
            source: cfc_core::VerdictSource::UserPrompt,
        };

        // The prompt is answered FIRST, and the standing rule only follows if
        // the answer landed.
        //
        // The other order persisted unconditionally and then discovered the
        // prompt was gone - so a click on a card whose prompt had already timed
        // out created a permanent rule while every client said "too late". For
        // "Allow always" that is standing network access granted by a click the
        // user was told did nothing. Prompt ids start from a random seed each
        // session (`nfqueue::prompt_session_seed`), which makes a stale card
        // naming a live id unlikely, not impossible. A verdict that reached
        // nothing should leave nothing behind.
        let binding = self.router.submit(&req.prompt_id, verdict);
        let accepted = binding.is_some();
        if let Some(id) = numeric_id {
            self.audience.forget(id);
        }

        let mut persisted_rule = None;
        let mut persist_error = String::new();
        let mut persist_note = String::new();
        if let (Some(binding), Some(scope_pb)) = (binding, req.persist_scope.clone()) {
            // One authority on what a storable rule is: `rule_from_pb`, the
            // same conversion the UpsertRule path runs, gates and all. This
            // path used to replicate a single gate of the list by hand
            // (`reject_unscoped`), so the *higher volume* of the two paths -
            // every "Allow always" click in the tray, every prompt answered in
            // the GUI - happily persisted scopes UpsertRule refuses: a
            // parent_exe-only scope that matches every process, or the
            // `<unknown>` placeholder as an exe. A copied gate list would just
            // drift again the next time one is added.
            let rule_pb = RuleInfo {
                id: String::new(),
                name: format!("user prompt {}", req.prompt_id),
                enabled: true,
                action: req.action,
                duration: req.duration,
                scope: Some(scope_pb),
                created_at_unix_ms: 0,
                hit_count: 0,
                duration_seconds: 0,
            };
            match convert::rule_from_pb(&rule_pb).and_then(|rule| {
                convert::reject_unpersistable_duration(rule.duration)?;
                Ok(rule)
            }) {
                Ok(mut rule) => {
                    // Persist only an explicit mapped target. The one-time
                    // verdict is already applied, so report a rejected standing
                    // policy through persist_error rather than retrying it.
                    if let Err(error) = bind_prompt_allow(&mut rule, &binding) {
                        persist_error = format!("the verdict was applied, but the standing rule could not be saved: {error}");
                        return Ok(Response::new(VerdictResponse {
                            accepted,
                            persisted_rule_id: String::new(),
                            persist_error,
                            persist_note,
                            error: String::new(),
                        }));
                    }
                    if let Err(error) = resolve_exe_off_thread(&mut rule.scope).await {
                        persist_error = format!("the verdict was applied, but the standing rule could not be saved: {error}");
                        return Ok(Response::new(VerdictResponse {
                            accepted,
                            persisted_rule_id: String::new(),
                            persist_error,
                            persist_note,
                            error: String::new(),
                        }));
                    }
                    if rule.action == cfc_core::Action::Allow && binding.hash_expected {
                        persist_note = "the allow is bound to the prompted binary's sha256; a changed file will prompt again".into();
                    }
                    let _mutation = self.mutations.lock();
                    match self.store.upsert(&rule) {
                        Ok(()) => {
                            persisted_rule = Some(rule.id);
                            self.engine.upsert_rule(rule);
                        }
                        Err(e) => {
                            // Reported to the caller, not only to the journal.
                            // The verdict itself is still valid and still
                            // applies to the waiting connection - only the
                            // standing rule failed - so this must not turn
                            // into `accepted = false`. But a client that says
                            // "Rule created" on the strength of `accepted`
                            // alone is telling the user something untrue,
                            // which for a firewall is the worst kind of wrong.
                            warn!("failed to persist rule from prompt verdict: {e}");
                            persist_error = format!(
                                "the verdict was applied, but the \
                                 standing rule could not be saved: {e}"
                            );
                        }
                    }
                }
                Err(e) => {
                    // NOT a Status error: the verdict was already submitted
                    // above and reached the waiting connection, so failing the
                    // RPC now would tell the client nothing happened when half
                    // of it did - and the client would invite a retry of a
                    // prompt that no longer exists. The rule degrades to a
                    // one-shot answer instead, and the reason travels back so
                    // the client can say why no standing rule exists.
                    warn!("refusing to persist rule from prompt verdict: {e}");
                    persist_error = format!(
                        "the verdict was applied, but the \
                         standing rule could not be saved: {e}"
                    );
                }
            }
        }

        info!(
            rpc = "SubmitVerdict",
            peer_uid = peer.uid,
            peer_pid = ?peer.pid,
            prompt_id = %req.prompt_id,
            action = ?action,
            persisted_rule = ?persisted_rule,
            outcome = if accepted { "accepted" } else { "no-such-prompt" },
            "verdict submitted"
        );

        Ok(Response::new(VerdictResponse {
            accepted,
            persisted_rule_id: persisted_rule.map(|id| id.to_string()).unwrap_or_default(),
            persist_error,
            persist_note,
            error: if accepted {
                String::new()
            } else {
                format!("no pending prompt with id {}", req.prompt_id)
            },
        }))
    }

    async fn list_rules(
        &self,
        req: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        self.authorize(&req, Access::ReadOnly)?;
        let snapshot = self.engine.snapshot();
        let rules = snapshot.rules.iter().map(convert::rule_to_pb).collect();
        Ok(Response::new(ListRulesResponse { rules }))
    }

    async fn upsert_rule(
        &self,
        req: Request<UpsertRuleRequest>,
    ) -> Result<Response<UpsertRuleResponse>, Status> {
        let peer = self.authorize(&req, Access::Mutate)?;
        self.upsert_rule_checked(peer, req.into_inner())
            .await
            .map(Response::new)
            .inspect_err(|status| log_refusal("UpsertRule", peer, status))
    }

    async fn apply_rules(
        &self,
        req: Request<ApplyRulesRequest>,
    ) -> Result<Response<ApplyRulesResponse>, Status> {
        let peer = self.authorize(&req, Access::Mutate)?;
        self.apply_rules_checked(peer, req.into_inner())
            .await
            .map(Response::new)
            .inspect_err(|status| log_refusal("ApplyRules", peer, status))
    }

    async fn delete_rule(
        &self,
        req: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, Status> {
        let peer = self.authorize(&req, Access::Mutate)?;
        let id_str = req.into_inner().id;
        let id = uuid::Uuid::parse_str(&id_str)
            .map_err(|e| Status::invalid_argument(format!("bad uuid: {e}")))?;
        let _mutation = self.mutations.lock();
        let deleted = self
            .store
            .delete(id)
            .map_err(|e| Status::internal(format!("storage: {e}")))?;
        if deleted {
            self.engine.remove_rule(id);
        }
        info!(
            rpc = "DeleteRule",
            peer_uid = peer.uid,
            peer_pid = ?peer.pid,
            rule_id = %id_str,
            outcome = if deleted { "deleted" } else { "not-found" },
            "rule delete"
        );
        Ok(Response::new(DeleteRuleResponse { deleted }))
    }

    type StreamConnectionsStream =
        tokio_stream::wrappers::ReceiverStream<Result<ConnectionEvent, Status>>;

    async fn stream_connections(
        &self,
        req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::StreamConnectionsStream>, Status> {
        self.authorize(&req, Access::ReadOnly)?;
        let (tx, rx) = mpsc::channel(256);
        let mut sub = self.observed_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(obs) => {
                        let ev = ConnectionEvent {
                            connection: Some(convert::connection_to_pb(&obs.connection)),
                            process: Some(convert::process_to_pb(&obs.process)),
                            verdict: convert::verdict_to_pb_action(&obs.verdict) as i32,
                            rule_id: match obs.verdict.source {
                                cfc_core::VerdictSource::Rule(id) => id.to_string(),
                                _ => String::new(),
                            },
                        };
                        if tx.send(Ok(ev)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("connection stream client lagged by {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn get_status(
        &self,
        req: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        self.authorize(&req, Access::ReadOnly)?;
        let rules_count = self.engine.rule_count() as u64;
        let policy = self.policy();
        let paused = self.stats.is_paused();
        let uptime_seconds = self.stats.uptime_seconds();
        let connections_seen = self.stats.connections_total();
        Ok(Response::new(StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds,
            rules_count,
            prompts_pending: self.stats.prompts_pending(),
            connections_seen,
            connections_allowed: self.stats.connections_allowed(),
            connections_denied: self.stats.connections_denied(),
            paused,
            resume_at_unix_ms: if paused {
                self.resume_at_ms.load(Ordering::Relaxed)
            } else {
                0
            },
            timeout_action: convert::action_to_pb(policy.timeout_action) as i32,
            no_ui_action: convert::action_to_pb(policy.no_ui_action) as i32,
            prompt_timeout_secs: policy.prompt_timeout_secs,
            skipped_rules: self.store.skipped_rules() as u64,
            enforcing: enforcing_heuristic(
                self.dry_run,
                connections_seen,
                uptime_seconds,
                self.stats.nft_table(),
            ),
            enforcement: crate::ebpf::enforcement_level()
                .map_or("starting", |l| l.as_str())
                .to_string(),
        }))
    }

    async fn set_paused(
        &self,
        req: Request<SetPausedRequest>,
    ) -> Result<Response<SetPausedResponse>, Status> {
        let peer = self.authorize(&req, Access::Mutate)?;
        let msg = req.into_inner();

        if !msg.paused {
            let generation = self.stats.set_paused(false);
            self.resume_at_ms.store(0, Ordering::Relaxed);
            info!(
                rpc = "SetPaused",
                peer_uid = peer.uid,
                peer_pid = ?peer.pid,
                paused = false,
                generation,
                outcome = "ok",
                "resumed enforcing"
            );
            return Ok(Response::new(SetPausedResponse {
                paused: false,
                resume_at_unix_ms: 0,
            }));
        }

        let requested = requested_pause_secs(msg.duration_secs, self.pause_default_secs);
        let secs = resolve_pause_secs(msg.duration_secs, self.pause_default_secs);
        if requested > secs {
            warn!(
                requested_secs = requested,
                capped_secs = secs,
                "pause duration exceeds the {MAX_PAUSE_SECS}s maximum; clamping"
            );
        }

        let resume_at = chrono::Utc::now().timestamp_millis() + (secs as i64) * 1000;
        let generation = self.stats.set_paused(true);
        self.resume_at_ms.store(resume_at, Ordering::Relaxed);
        info!(
            rpc = "SetPaused",
            peer_uid = peer.uid,
            peer_pid = ?peer.pid,
            paused = true,
            duration_secs = secs,
            resume_at_unix_ms = resume_at,
            generation,
            outcome = "ok",
            "paused; will auto-resume"
        );

        // Safety net: a pause must always end. The generation check makes
        // this a no-op if the user toggles again before the timer fires.
        let stats = self.stats.clone();
        let resume_cell = self.resume_at_ms.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            if stats.pause_generation() == generation && stats.is_paused() {
                stats.set_paused(false);
                resume_cell.store(0, Ordering::Relaxed);
                info!(
                    after_secs = secs,
                    generation, "auto-resumed enforcing after pause expired"
                );
            }
        });

        Ok(Response::new(SetPausedResponse {
            paused: true,
            resume_at_unix_ms: resume_at,
        }))
    }

    async fn list_events(
        &self,
        req: Request<ListEventsRequest>,
    ) -> Result<Response<ListEventsResponse>, Status> {
        self.authorize(&req, Access::ReadOnly)?;
        let (limit, offset, filter) =
            event_query_from_pb(&req.into_inner()).map_err(Status::invalid_argument)?;
        let rows = self
            .store
            .query_events(limit, offset, filter)
            .map_err(|e| Status::internal(format!("storage: {e}")))?;
        let events: Vec<_> = rows.iter().map(convert::event_row_to_pb).collect();
        Ok(Response::new(ListEventsResponse {
            total_returned: events.len() as u64,
            events,
        }))
    }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// What the client effectively asked for, before clamping: an explicit
/// `duration_secs`, or the daemon default when it sent 0.
fn requested_pause_secs(duration_secs: u32, default_secs: u64) -> u64 {
    if duration_secs == 0 {
        default_secs
    } else {
        duration_secs as u64
    }
}

/// Effective pause length. 0 means "daemon default"; a zero or absurd
/// default is clamped into `1..=MAX_PAUSE_SECS` so a pause always ends.
fn resolve_pause_secs(duration_secs: u32, default_secs: u64) -> u64 {
    requested_pause_secs(duration_secs, default_secs).clamp(1, MAX_PAUSE_SECS)
}

/// Best-effort "are we actually in the packet path?".
///
/// `--dry-run` never binds NFQUEUE, so it reports false unconditionally:
/// nothing is being filtered and saying otherwise would be a lie. Outside
/// dry-run, seeing no packet at all after the grace period almost always
/// means the nftables/iptables rule that feeds NFQUEUE is not loaded.
fn enforcing_heuristic(
    dry_run: bool,
    packets_seen: u64,
    uptime_secs: u64,
    table: crate::stats::TablePresence,
) -> bool {
    use crate::stats::TablePresence;
    if dry_run {
        return false;
    }
    let starting = uptime_secs <= ENFORCING_GRACE_SECS;
    match table {
        // Evidence, not a guess, so it decides. The packet counter below
        // never decreases, so on its own it could only ever answer "yes, once
        // upon a time" - exactly wrong in the case that matters, a ruleset
        // removed under a running daemon.
        TablePresence::Present => true,
        // Also evidence, but only once the machine has had time to load it.
        // The shipped unit ordering starts this daemon *first* and
        // `colony-firewall-nft.service` after it, so an absent table is the
        // expected state for the first moments of every boot - and saying
        // "not enforcing" then would be a false alarm on every start, in the
        // field people are told to read.
        TablePresence::Absent => starting,
        // The probe has not run yet, or could not run at all - no nft binary,
        // no permission, the transaction lock held. Fall back to what the
        // daemon can see for itself.
        TablePresence::Unknown => packets_seen > 0 || starting,
    }
}

/// Maps a `ListEvents` request onto the storage query. Rejects an
/// unrecognised action filter rather than silently ignoring it.
fn event_query_from_pb(req: &ListEventsRequest) -> Result<(u32, u32, EventFilter), String> {
    let limit = if req.limit == 0 {
        DEFAULT_EVENT_PAGE
    } else {
        req.limit.min(MAX_EVENT_PAGE)
    };
    let action = if req.action_filter == cfc_proto::v1::Action::Unspecified as i32 {
        None
    } else {
        Some(convert::action_db_str(convert::action_from_pb(req.action_filter)?).to_string())
    };
    let filter = EventFilter {
        exe_contains: (!req.exe_contains.is_empty()).then(|| req.exe_contains.clone()),
        action,
        since_ts_unix_ms: (req.since_unix_ms > 0).then_some(req.since_unix_ms),
    };
    Ok((limit, req.offset.min(MAX_EVENT_OFFSET), filter))
}

// ---------------------------------------------------------------------------
// Socket access control
// ---------------------------------------------------------------------------

/// Looks up a group by name. Returns `Ok(None)` when the group simply does
/// not exist (the common "sysusers fragment not installed" case), `Err` for
/// a genuine lookup failure. Never panics.
fn resolve_group_gid(name: &str) -> Result<Option<u32>, String> {
    match nix::unistd::Group::from_name(name) {
        Ok(Some(g)) => Ok(Some(g.gid.as_raw())),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Chowns the freshly-bound socket to `root:<group>` and chmods it 0660.
///
/// Never fails startup: if the group is missing or the daemon is not root,
/// it warns loudly and retains owner-only socket access (0600). RPC
/// authorization independently verifies the individual peer's group credentials.
fn secure_socket(path: &Path, ipc: &IpcConfig) -> SocketAuth {
    let mut auth = SocketAuth {
        group: ipc.group.clone(),
        group_gid: None,
        group_gated: false,
        require_group: ipc.require_group,
    };

    let gid = match resolve_group_gid(&ipc.group) {
        Ok(Some(gid)) => Some(gid),
        Ok(None) => {
            warn!(
                group = %ipc.group,
                socket = %path.display(),
                "group '{}' does not exist: leaving the control socket root-only. \
                 The UI and non-root CLI cannot connect. Install the sysusers fragment \
                 (systemd/colony-firewall.sysusers -> /usr/lib/sysusers.d/colony-firewall.conf, \
                 then `systemd-sysusers`) or create it with \
                 `groupadd -r {}`, then add your desktop user with \
                 `usermod -aG {} <user>` and restart the daemon.",
                ipc.group, ipc.group, ipc.group
            );
            None
        }
        Err(e) => {
            warn!(
                group = %ipc.group,
                "group lookup failed ({e}); leaving the control socket root-only"
            );
            None
        }
    };

    auth.group_gid = gid;
    if let Some(gid) = gid {
        match std::os::unix::fs::chown(path, Some(0), Some(gid)) {
            Ok(()) => auth.group_gated = true,
            Err(e) => warn!(
                group = %ipc.group,
                gid,
                "chown of the control socket failed ({e}); leaving it root-only"
            ),
        }
    }

    // chmod after chown so the socket is never group-readable by the wrong
    // group, not even briefly.
    let mode = if auth.group_gated { 0o660 } else { 0o600 };
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        warn!(
            socket = %path.display(),
            "chmod {mode:o} of the control socket failed: {e}"
        );
        // The mode is unknown now; do not claim the kernel is gating access.
        auth.group_gated = false;
    }

    if auth.group_gated {
        info!(
            socket = %path.display(),
            group = %ipc.group,
            "control socket secured root:{} 0660", ipc.group
        );
    }
    auth
}

// ---------------------------------------------------------------------------
// Event persistence pipeline
// ---------------------------------------------------------------------------

/// The bounded queue into the event writer.
///
/// `push` never waits. The packet worker delivers its verdict first and
/// records it second, so a slow fsync, a long `ListEvents` holding the store
/// mutex or a full disk costs audit rows - counted and logged - and never
/// stalls or ends the datapath. Every refusal is also logged to the journal
/// as "connection blocked" before it is queued.
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<EventRow>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    pub(crate) fn channel(depth: usize) -> (Self, mpsc::Receiver<EventRow>) {
        let (tx, rx) = mpsc::channel(depth);
        let sink = Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (sink, rx)
    }

    /// Queues one row for the writer, or counts it as dropped.
    pub fn push(&self, row: EventRow) {
        if self.tx.try_send(row).is_err() {
            count_dropped(&self.dropped, 1, "event log queue full");
        }
    }

    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Adds `n` to the drop counter and warns on the first drop and every
/// `EVENT_DROP_LOG_EVERY` after it, rather than once per row.
fn count_dropped(dropped: &AtomicU64, n: u64, why: &str) {
    let before = dropped.fetch_add(n, Ordering::Relaxed);
    let total = before + n;
    if before == 0 || before / EVENT_DROP_LOG_EVERY != total / EVENT_DROP_LOG_EVERY {
        warn!(
            dropped = total,
            "{why}; events were not persisted (the packet path never waits for persistence)"
        );
    }
}

/// Starts the event persistence pipeline and returns the sink the packet
/// worker queues its refusals into.
///
/// - Refusals are pushed straight into the bounded queue by the worker, so
///   they never depend on the lossy live feed.
/// - A *feeder* converts Allow observations from the live feed to
///   [`EventRow`]s and pushes them the same way.
/// - A *writer* drains the queue in batches of `EVENT_BATCH_ROWS` or every
///   second, whichever comes first, and trims the table to `max_rows` once a
///   minute.
///
/// Every row lost on the way (queue full, feeder lag, failed batch commit)
/// is counted in one counter and logged.
pub fn spawn_event_pipeline(
    store: RuleStore,
    observed_tx: &broadcast::Sender<ObservedConnection>,
    max_rows: u32,
) -> EventSink {
    let (sink, rx) = EventSink::channel(EVENT_QUEUE_DEPTH);
    let mut sub = observed_tx.subscribe();

    let feeder = sink.clone();
    tokio::spawn(async move {
        loop {
            match sub.recv().await {
                Ok(obs) => {
                    if obs.verdict.action != cfc_core::Action::Allow {
                        continue;
                    }
                    feeder.push(convert::event_row_from_observed(
                        &obs.connection,
                        &obs.process,
                        &obs.verdict,
                    ));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    count_dropped(
                        &feeder.dropped,
                        n,
                        "event log feeder lagged behind the live feed",
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        info!("event log feeder stopped: live feed closed");
    });

    tokio::spawn(event_writer_task(store, rx, sink.dropped.clone(), max_rows));
    sink
}

async fn event_writer_task(
    store: RuleStore,
    mut rx: mpsc::Receiver<EventRow>,
    dropped: Arc<AtomicU64>,
    max_rows: u32,
) {
    let mut batch: Vec<EventRow> = Vec::with_capacity(EVENT_BATCH_ROWS);
    let mut flush =
        tokio::time::interval(std::time::Duration::from_secs(EVENT_BATCH_INTERVAL_SECS));
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut prune =
        tokio::time::interval(std::time::Duration::from_secs(EVENT_PRUNE_INTERVAL_SECS));
    prune.tick().await; // skip the immediate fire

    loop {
        tokio::select! {
            row = rx.recv() => match row {
                Some(row) => {
                    batch.push(row);
                    if batch.len() >= EVENT_BATCH_ROWS {
                        write_batch(&store, &mut batch, &dropped);
                    }
                }
                None => {
                    write_batch(&store, &mut batch, &dropped);
                    info!("event log writer stopped: queue closed");
                    return;
                }
            },
            _ = flush.tick() => write_batch(&store, &mut batch, &dropped),
            _ = prune.tick() => match store.prune_events(max_rows) {
                Ok(n) if n > 0 => tracing::debug!(removed = n, cap = max_rows, "pruned old events"),
                Ok(_) => {}
                Err(e) => warn!("event prune failed: {e}"),
            },
        }
    }
}

fn write_batch(store: &RuleStore, batch: &mut Vec<EventRow>, dropped: &AtomicU64) {
    if batch.is_empty() {
        return;
    }
    if let Err(e) = store.insert_events(batch) {
        let total = dropped.fetch_add(batch.len() as u64, Ordering::Relaxed) + batch.len() as u64;
        warn!(
            rows = batch.len(),
            dropped = total,
            "event log write failed: {e:#}"
        );
    }
    batch.clear();
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

/// Everything `spawn` needs that is not a shared runtime handle.
pub struct IpcOptions {
    pub socket_path: PathBuf,
    pub ipc: IpcConfig,
    /// `[pause] default_secs`, used when a client sends `duration_secs = 0`.
    pub pause_default_secs: u64,
    /// Whether the daemon was started with `--dry-run` (affects the
    /// `enforcing` field in status).
    pub dry_run: bool,
}

pub async fn spawn(
    opts: IpcOptions,
    engine: Engine,
    store: RuleStore,
    observed_tx: broadcast::Sender<ObservedConnection>,
    router: PromptRouter,
    stats: Stats,
    policy: SharedPolicy,
) -> anyhow::Result<(JoinHandle<()>, PromptTx)> {
    let socket_path = opts.socket_path;
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let _ = std::fs::remove_file(&socket_path);

    let (prompt_tx, prompt_rx) = mpsc::channel::<PromptRequest>(256);

    let router_for_pump = router.clone();
    tokio::spawn(async move {
        crate::prompts::run_router_task(prompt_rx, router_for_pump).await;
    });

    // Establish restrictive creation permissions before the listening inode exists.
    unsafe {
        libc::umask(0o077);
    }
    let uds = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;
    // Tighten ownership/mode before the first client can connect.
    let auth = secure_socket(&socket_path, &opts.ipc);
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds)
        .map(|stream| stream.and_then(PeerStream::new));

    let service = FirewallService {
        engine,
        store,
        observed_tx,
        router,
        stats,
        policy,
        auth,
        audience: Arc::new(PromptAudience::default()),
        resume_at_ms: Arc::new(AtomicI64::new(0)),
        pause_default_secs: opts.pause_default_secs,
        dry_run: opts.dry_run,
        mutations: Mutex::new(()),
    };

    info!(socket = %socket_path.display(), "IPC listening");

    let handle = tokio::spawn(async move {
        let result = tonic::transport::Server::builder()
            .add_service(FirewallServer::new(service))
            .serve_with_incoming(incoming)
            .await;
        if let Err(e) = result {
            tracing::error!("IPC server exited: {e}");
        }
    });

    Ok((handle, prompt_tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::TablePresence;

    #[tokio::test]
    async fn executable_policy_validation_refuses_alias_without_rewriting_scope() {
        let directory = tempfile::tempdir().unwrap();
        let target = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("target");
        std::fs::write(&target, b"local policy test data").unwrap();
        let alias = target.with_file_name("alias");
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        let mut scope = cfc_core::RuleScope::any();
        scope.exe_path = Some(alias.clone());
        let error = resolve_exe_off_thread(&mut scope).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(scope.exe_path, Some(alias));
        scope.exe_path = Some(target.clone());
        resolve_exe_off_thread(&mut scope).await.unwrap();
        assert_eq!(scope.exe_path, Some(target));
    }

    #[test]
    fn only_an_unchanged_stored_exe_skips_validation() {
        let mut scope = cfc_core::RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/bin/curl"));
        let old = cfc_core::Rule::new("legacy", cfc_core::Action::Deny, scope);
        let stored = cfc_core::RuleSet {
            rules: vec![old.clone()],
        };
        let mut toggled = old.clone();
        toggled.enabled = false;
        assert!(keeps_stored_exe(&stored, &toggled));
        let mut moved = old.clone();
        moved.scope.exe_path = Some(PathBuf::from("/bin/wget"));
        assert!(!keeps_stored_exe(&stored, &moved));
        let mut fresh = old.clone();
        fresh.id = uuid::Uuid::new_v4();
        assert!(!keeps_stored_exe(&stored, &fresh));
    }

    // -- authorization ------------------------------------------------------

    #[test]
    fn read_only_rpcs_are_open_to_any_connected_peer() {
        for gated in [true, false] {
            for require in [true, false] {
                assert!(authorize_uid(1000, Access::ReadOnly, gated, require));
                assert!(authorize_uid(0, Access::ReadOnly, gated, require));
            }
        }
    }

    #[test]
    fn root_may_always_mutate() {
        for gated in [true, false] {
            assert!(authorize_uid(0, Access::Mutate, gated, true));
        }
    }

    #[test]
    fn non_root_mutation_requires_proved_peer_group_membership() {
        // Only proved peer membership authorizes a non-root mutation.
        assert!(authorize_uid(1000, Access::Mutate, true, true));
        // A socket mode is not membership evidence for an individual peer.
        assert!(!authorize_uid(1000, Access::Mutate, false, true));
        // Explicit opt-out: the admin gates the socket some other way.
        assert!(authorize_uid(1000, Access::Mutate, false, false));
    }

    #[test]
    fn supplementary_group_evidence_must_match_the_kernel_peer_uid() {
        let status = "Uid:\t1000 1000 1000 1000\nGroups:\t10 20 30\n";
        assert!(status_proves_group(status, 1000, 20));
        assert!(!status_proves_group(status, 1001, 20));
        assert!(!status_proves_group(status, 1000, 40));
        assert!(!status_proves_group("Groups: 20", 1000, 20));
    }

    #[test]
    fn promised_binding_never_degrades_to_path_only() {
        use cfc_core::{Action, Rule, RuleScope};
        let mut rule = Rule::new(
            "test",
            Action::Allow,
            RuleScope {
                exe_path: Some("/tmp/tool".into()),
                ..RuleScope::any()
            },
        );
        let mut binding = crate::prompts::PromptBinding {
            exe: rule.scope.exe_path.clone(),
            hash_expected: true,
            sha256: None,
        };
        assert!(bind_prompt_allow(&mut rule, &binding).is_err());
        binding.sha256 = Some("a".repeat(64));
        assert!(bind_prompt_allow(&mut rule, &binding).is_ok());
        assert_eq!(rule.scope.exe_sha256, binding.sha256);
        rule.scope.exe_path = Some("/tmp/other".into());
        assert!(bind_prompt_allow(&mut rule, &binding).is_err());
    }

    // -- group resolution ---------------------------------------------------

    #[test]
    fn missing_group_resolves_to_none_without_panicking() {
        let name = format!("cfc-no-such-group-{}", uuid::Uuid::new_v4());
        assert_eq!(resolve_group_gid(&name), Ok(None));
        // Embedded NUL is rejected by the lookup, not by a panic.
        assert!(matches!(resolve_group_gid("bad\0name"), Ok(None) | Err(_)));
    }

    #[test]
    fn root_group_resolves_on_linux() {
        // "root" exists on every Linux system this daemon targets; proves
        // the happy path actually returns a gid.
        assert!(matches!(resolve_group_gid("root"), Ok(Some(_))));
    }

    // -- pause --------------------------------------------------------------

    #[test]
    fn pause_zero_means_daemon_default() {
        assert_eq!(resolve_pause_secs(0, 600), 600);
        assert_eq!(resolve_pause_secs(0, 30), 30);
    }

    #[test]
    fn pause_explicit_duration_wins_over_default() {
        assert_eq!(resolve_pause_secs(45, 600), 45);
    }

    #[test]
    fn pause_is_clamped_to_the_maximum() {
        assert_eq!(resolve_pause_secs(u32::MAX, 600), MAX_PAUSE_SECS);
        assert_eq!(resolve_pause_secs(0, u64::MAX), MAX_PAUSE_SECS);
        // Exactly at the cap is untouched.
        assert_eq!(
            resolve_pause_secs(MAX_PAUSE_SECS as u32, 600),
            MAX_PAUSE_SECS
        );
    }

    #[test]
    fn pause_never_resolves_to_forever() {
        // A misconfigured `default_secs = 0` must not mean "pause until
        // someone notices".
        assert_eq!(resolve_pause_secs(0, 0), 1);
    }

    #[test]
    fn clamping_is_detectable_for_the_warning() {
        assert!(requested_pause_secs(u32::MAX, 600) > resolve_pause_secs(u32::MAX, 600));
        assert_eq!(requested_pause_secs(45, 600), resolve_pause_secs(45, 600));
    }

    // -- enforcing heuristic ------------------------------------------------

    #[test]
    fn a_removed_ruleset_stops_reading_as_enforcing() {
        // The defect this replaces: `packets_seen` only ever goes up, so once
        // one packet had been seen the answer was "yes" for the life of the
        // daemon - including after the table was flushed out from under it and
        // nothing was being filtered at all.
        assert!(
            !enforcing_heuristic(false, 1_000_000, 100_000, TablePresence::Absent),
            "a machine whose table is gone is not enforcing, however many \
             packets it saw before that"
        );
        // And the other way: a table that is loaded settles the question on a
        // machine so idle it has never seen a packet.
        assert!(
            enforcing_heuristic(false, 0, 100_000, TablePresence::Present),
            "an idle machine with the table loaded is enforcing"
        );
        // --dry-run still overrides everything: nothing is bound to the queue,
        // so a loaded table filters nothing of ours.
        assert!(!enforcing_heuristic(true, 0, 5, TablePresence::Present));
    }

    #[test]
    fn an_absent_table_is_not_alarming_while_the_machine_is_still_starting() {
        // The shipped units start this daemon before the one that loads the
        // table, and the probe fires as soon as it is spawned - so on every
        // single boot the first answer is "absent". Reporting that verbatim
        // told the user their firewall was off for the first minute of every
        // start, which is a false alarm in the one field they are pointed at.
        assert!(
            enforcing_heuristic(false, 0, 1, TablePresence::Absent),
            "an absent table inside the grace period is a machine still coming up"
        );
        assert!(
            !enforcing_heuristic(false, 0, ENFORCING_GRACE_SECS + 1, TablePresence::Absent),
            "past it, absent means absent"
        );
        // And the grace period does not extend to a table that is there.
        assert!(enforcing_heuristic(false, 0, 1, TablePresence::Present));
    }

    #[test]
    fn enforcing_is_false_only_after_a_silent_grace_period() {
        // Fresh start, nothing seen yet: assume healthy.
        assert!(enforcing_heuristic(false, 0, 5, TablePresence::Unknown));
        // Still nothing after the grace period: the nft rule is missing.
        assert!(!enforcing_heuristic(
            false,
            0,
            ENFORCING_GRACE_SECS + 1,
            TablePresence::Unknown
        ));
        // Any traffic at all proves we are in the path.
        assert!(enforcing_heuristic(
            false,
            1,
            100_000,
            TablePresence::Unknown
        ));
    }

    #[test]
    fn dry_run_never_claims_to_be_enforcing() {
        assert!(!enforcing_heuristic(true, 0, 5, TablePresence::Unknown));
        assert!(!enforcing_heuristic(
            true,
            999,
            100_000,
            TablePresence::Unknown
        ));
    }

    // -- event query mapping ------------------------------------------------

    fn list_req() -> ListEventsRequest {
        ListEventsRequest::default()
    }

    #[test]
    fn event_query_defaults_are_sane() {
        let (limit, offset, filter) = event_query_from_pb(&list_req()).unwrap();
        assert_eq!(limit, DEFAULT_EVENT_PAGE);
        assert_eq!(offset, 0);
        assert_eq!(filter.exe_contains, None);
        assert_eq!(filter.action, None);
        assert_eq!(filter.since_ts_unix_ms, None);
    }

    #[test]
    fn event_query_limit_is_capped() {
        let req = ListEventsRequest {
            limit: u32::MAX,
            ..list_req()
        };
        assert_eq!(event_query_from_pb(&req).unwrap().0, MAX_EVENT_PAGE);
    }

    #[test]
    fn event_query_maps_every_filter() {
        let req = ListEventsRequest {
            limit: 10,
            offset: 5,
            exe_contains: "curl".into(),
            action_filter: cfc_proto::v1::Action::Deny as i32,
            since_unix_ms: 1234,
        };
        let (limit, offset, filter) = event_query_from_pb(&req).unwrap();
        assert_eq!(limit, 10);
        assert_eq!(offset, 5);
        assert_eq!(filter.exe_contains.as_deref(), Some("curl"));
        // Must match exactly what the writer persists.
        assert_eq!(filter.action.as_deref(), Some("Deny"));
        assert_eq!(filter.since_ts_unix_ms, Some(1234));
    }

    #[test]
    fn event_query_rejects_an_unknown_action_filter() {
        let req = ListEventsRequest {
            action_filter: 99,
            ..list_req()
        };
        assert!(event_query_from_pb(&req).is_err());
    }

    #[test]
    fn event_query_ignores_a_non_positive_since() {
        for since in [0, -1] {
            let req = ListEventsRequest {
                since_unix_ms: since,
                ..list_req()
            };
            assert_eq!(event_query_from_pb(&req).unwrap().2.since_ts_unix_ms, None);
        }
    }

    // -- prompt ownership ---------------------------------------------------

    #[test]
    fn only_a_peer_that_received_a_prompt_may_answer_it() {
        let a = PromptAudience::default();
        a.record(7, 1000);
        assert!(a.allows(7, 1000));
        assert!(!a.allows(7, 1001));
        assert!(!a.allows(8, 1000));
    }

    #[test]
    fn several_subscribers_may_share_a_prompt() {
        let a = PromptAudience::default();
        a.record(7, 1000);
        a.record(7, 1001);
        assert!(a.allows(7, 1000));
        assert!(a.allows(7, 1001));
    }

    #[test]
    fn forgetting_a_prompt_revokes_the_right_to_answer_it() {
        let a = PromptAudience::default();
        a.record(7, 1000);
        a.forget(7);
        assert!(!a.allows(7, 1000));
        // Idempotent.
        a.forget(7);
    }

    /// What the per-subscriber task in [`FirewallService::stream_prompts`]
    /// does to one broadcast event: skip it unless this peer may see it,
    /// otherwise record the peer as entitled to answer.
    fn deliver_to(audience: &PromptAudience, prompt_id: u64, owner_uid: Option<u32>, uid: u32) {
        if should_deliver(owner_uid, uid) {
            audience.record(prompt_id, uid);
        }
    }

    #[test]
    fn only_the_owning_session_enters_a_prompts_audience() {
        // The gap this closes: before delivery was uid-scoped, every
        // subscriber received every prompt and so ended up in every
        // audience, which made the SubmitVerdict check vacuous.
        let a = PromptAudience::default();
        for uid in [0, 1000, 1001] {
            deliver_to(&a, 7, Some(1000), uid);
        }
        assert!(a.allows(7, 1000), "the owner was shown the prompt");
        assert!(a.allows(7, 0), "root sees everything");
        assert!(
            !a.allows(7, 1001),
            "another session never received it, so it may not answer it"
        );
    }

    #[test]
    fn unattributed_prompts_admit_every_session() {
        let a = PromptAudience::default();
        for uid in [0, 1000, 1001] {
            deliver_to(&a, 7, None, uid);
        }
        for uid in [0, 1000, 1001] {
            assert!(a.allows(7, uid), "uid {uid} was shown an unowned prompt");
        }
    }

    #[test]
    fn a_root_owned_prompt_admits_only_root() {
        let a = PromptAudience::default();
        for uid in [0, 1000] {
            deliver_to(&a, 7, Some(0), uid);
        }
        assert!(a.allows(7, 0));
        assert!(!a.allows(7, 1000));
    }

    #[test]
    fn audience_evicts_oldest_prompts_beyond_the_cap() {
        let a = PromptAudience::default();
        for id in 0..(AUDIENCE_CAP as u64 + 10) {
            a.record(id, 1000);
        }
        let g = a.inner.lock();
        assert!(g.by_prompt.len() <= AUDIENCE_CAP);
        assert!(g.order.len() <= AUDIENCE_CAP);
        drop(g);
        // The newest survive, the oldest are gone.
        assert!(a.allows(AUDIENCE_CAP as u64 + 9, 1000));
        assert!(!a.allows(0, 1000));
    }

    // -- event pipeline -----------------------------------------------------

    fn observed(dst_port: u16, action: cfc_core::Action) -> ObservedConnection {
        use std::net::{IpAddr, Ipv4Addr};
        let mut process = cfc_core::Process::unknown(1234);
        process.exe = std::path::PathBuf::from("/usr/bin/curl");
        ObservedConnection {
            connection: cfc_core::Connection::new(
                cfc_core::Protocol::Tcp,
                cfc_core::Direction::Outbound,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                4321,
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                dst_port,
            ),
            process,
            verdict: cfc_core::Verdict {
                action,
                source: cfc_core::VerdictSource::DefaultPolicy,
            },
        }
    }

    #[tokio::test(start_paused = true)]
    async fn event_pipeline_persists_the_live_feed() {
        let store = RuleStore::open_in_memory().unwrap();
        let (tx, _rx) = broadcast::channel(64);
        let sink = spawn_event_pipeline(store.clone(), &tx, 1000);

        tx.send(observed(443, cfc_core::Action::Allow)).unwrap();
        // The worker queues a refusal itself and then publishes it; the
        // feeder must not record it a second time.
        let blocked = observed(80, cfc_core::Action::Deny);
        sink.push(convert::event_row_from_observed(
            &blocked.connection,
            &blocked.process,
            &blocked.verdict,
        ));
        tx.send(blocked).unwrap();

        // Well past the batch interval; paused time auto-advances.
        tokio::time::sleep(std::time::Duration::from_secs(
            EVENT_BATCH_INTERVAL_SECS + 1,
        ))
        .await;

        let rows = store.query_events(10, 0, EventFilter::default()).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|r| r.dst_port == Some(443) && r.action == "Allow"));
        assert!(rows
            .iter()
            .any(|r| r.dst_port == Some(80) && r.action == "Deny"));
        assert!(rows
            .iter()
            .all(|r| r.exe.as_deref() == Some("/usr/bin/curl")));

        // The action strings the writer produces are exactly what the
        // ListEvents filter searches for.
        let (limit, offset, filter) = event_query_from_pb(&ListEventsRequest {
            action_filter: cfc_proto::v1::Action::Deny as i32,
            ..ListEventsRequest::default()
        })
        .unwrap();
        let denies = store.query_events(limit, offset, filter).unwrap();
        assert_eq!(denies.len(), 1);
        assert_eq!(denies[0].dst_port, Some(80));
    }

    #[tokio::test(start_paused = true)]
    async fn event_pipeline_prunes_to_the_configured_cap() {
        let store = RuleStore::open_in_memory().unwrap();
        let (tx, _rx) = broadcast::channel(64);
        spawn_event_pipeline(store.clone(), &tx, 2);

        for port in 1..=5u16 {
            tx.send(observed(port, cfc_core::Action::Allow)).unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            EVENT_PRUNE_INTERVAL_SECS + 2,
        ))
        .await;

        let rows = store.query_events(10, 0, EventFilter::default()).unwrap();
        assert_eq!(rows.len(), 2, "table should be trimmed to max_rows");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_store_costs_counted_rows_never_a_stall() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.db");
        let store = RuleStore::open(&path).unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_audit BEFORE INSERT ON events \
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        let (tx, _rx) = broadcast::channel(64);
        let sink = spawn_event_pipeline(store.clone(), &tx, 1000);
        let blocked = observed(80, cfc_core::Action::Deny);
        let row = convert::event_row_from_observed(
            &blocked.connection,
            &blocked.process,
            &blocked.verdict,
        );
        for _ in 0..3 {
            sink.push(row.clone());
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            EVENT_BATCH_INTERVAL_SECS + 1,
        ))
        .await;
        assert_eq!(sink.dropped(), 3);

        // A full queue drops the row at once instead of waiting for room.
        let (full, _rx) = EventSink::channel(1);
        full.push(row.clone());
        full.push(row);
        assert_eq!(full.dropped(), 1);
    }

    #[test]
    fn recording_the_same_peer_twice_does_not_grow_the_queue() {
        let a = PromptAudience::default();
        for _ in 0..10 {
            a.record(7, 1000);
        }
        let g = a.inner.lock();
        assert_eq!(g.order.len(), 1);
        assert_eq!(g.by_prompt.len(), 1);
    }
}
