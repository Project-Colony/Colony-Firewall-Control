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
//! 2. **Per-RPC peer credentials.** Every connection carries `SO_PEERCRED`
//!    (tonic's [`UdsConnectInfo`]). Mutating RPCs - `UpsertRule`,
//!    `DeleteRule`, `SetPaused`, `SubmitVerdict` - require either uid 0 or
//!    a socket that is genuinely group-gated (layer 1 succeeded). If the
//!    chown/chmod failed and an admin loosened the mode by hand, non-root
//!    mutations are refused rather than silently trusted. `require_group =
//!    false` opts out of that second check for sites gating the socket some
//!    other way (filesystem ACLs). Read-only RPCs - `ListRules`,
//!    `GetStatus`, `StreamConnections`, `StreamPrompts`, `ListEvents` - are
//!    allowed for any peer that got through layer 1.
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
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tonic::transport::server::UdsConnectInfo;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use cfc_proto::v1::{
    firewall_server::{Firewall, FirewallServer},
    ConnectionEvent, DeleteRuleRequest, DeleteRuleResponse, ListEventsRequest, ListEventsResponse,
    ListRulesRequest, ListRulesResponse, PromptEvent, SetPausedRequest, SetPausedResponse,
    StatusRequest, StatusResponse, SubscribeRequest, UpsertRuleRequest, UpsertRuleResponse,
    VerdictRequest, VerdictResponse,
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
    pub pid: Option<i32>,
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
    /// True only when the socket really is `root:<group>` mode 0660, i.e.
    /// the kernel is enforcing group membership on `connect(2)`.
    group_gated: bool,
    require_group: bool,
}

/// Pure authorization policy, split out from the request plumbing so it can
/// be exercised without a live socket.
fn authorize_uid(uid: u32, level: Access, group_gated: bool, require_group: bool) -> bool {
    match level {
        // Layer 1 (socket mode) already decided who may connect at all.
        Access::ReadOnly => true,
        Access::Mutate => uid == 0 || !require_group || group_gated,
    }
}

/// Extracts kernel-reported peer credentials from a request.
fn peer_of<T>(req: &Request<T>) -> Result<PeerId, Status> {
    let info = req
        .extensions()
        .get::<UdsConnectInfo>()
        .ok_or_else(|| Status::permission_denied("connection carries no peer credentials"))?;
    let cred = info
        .peer_cred
        .ok_or_else(|| Status::permission_denied("peer credentials unavailable"))?;
    Ok(PeerId {
        uid: cred.uid(),
        pid: cred.pid(),
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
}

impl FirewallService {
    /// Resolves the caller and checks it may perform `level`.
    fn authorize<T>(&self, req: &Request<T>, level: Access) -> Result<PeerId, Status> {
        let peer = peer_of(req)?;
        if authorize_uid(
            peer.uid,
            level,
            self.auth.group_gated,
            self.auth.require_group,
        ) {
            return Ok(peer);
        }
        warn!(
            peer_uid = peer.uid,
            peer_pid = ?peer.pid,
            group = %self.auth.group,
            "refusing mutating RPC: socket is not group-gated and caller is not root"
        );
        Err(Status::permission_denied(format!(
            "mutating RPCs require uid 0 or a socket owned by group '{}'",
            self.auth.group
        )))
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

        let mut persisted_rule = None;
        if let Some(scope_pb) = req.persist_scope.clone() {
            let scope = convert::scope_from_pb(&scope_pb);
            let duration =
                convert::duration_from_pb(req.duration).map_err(Status::invalid_argument)?;
            convert::reject_unpersistable_duration(duration).map_err(Status::invalid_argument)?;
            let rule = cfc_core::Rule {
                id: uuid::Uuid::new_v4(),
                name: format!("user prompt {}", req.prompt_id),
                enabled: true,
                action,
                duration,
                scope,
                created_at: chrono::Utc::now(),
                hit_count: 0,
            };
            if let Err(e) = self.store.upsert(&rule) {
                warn!("failed to persist rule from prompt verdict: {e}");
            } else {
                persisted_rule = Some(rule.id);
                self.engine.upsert_rule(rule);
            }
        }

        let accepted = self.router.submit(&req.prompt_id, verdict);
        if let Some(id) = numeric_id {
            self.audience.forget(id);
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
        let proto = req
            .into_inner()
            .rule
            .ok_or_else(|| Status::invalid_argument("rule required"))?;
        let rule = convert::rule_from_pb(&proto).map_err(Status::invalid_argument)?;
        convert::reject_unpersistable_duration(rule.duration).map_err(Status::invalid_argument)?;
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
        Ok(Response::new(UpsertRuleResponse {
            id,
            error: String::new(),
        }))
    }

    async fn delete_rule(
        &self,
        req: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, Status> {
        let peer = self.authorize(&req, Access::Mutate)?;
        let id_str = req.into_inner().id;
        let id = uuid::Uuid::parse_str(&id_str)
            .map_err(|e| Status::invalid_argument(format!("bad uuid: {e}")))?;
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
        let rules_count = self.engine.snapshot().rules.len() as u64;
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
            enforcing: enforcing_heuristic(self.dry_run, connections_seen, uptime_seconds),
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
fn enforcing_heuristic(dry_run: bool, packets_seen: u64, uptime_secs: u64) -> bool {
    if dry_run {
        return false;
    }
    packets_seen > 0 || uptime_secs <= ENFORCING_GRACE_SECS
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
    Ok((limit, req.offset, filter))
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
/// it warns loudly, leaves the socket root-only (0600) and reports
/// `group_gated = false`, which in turn makes non-root mutating RPCs fail
/// the second authorization layer.
fn secure_socket(path: &Path, ipc: &IpcConfig) -> SocketAuth {
    let mut auth = SocketAuth {
        group: ipc.group.clone(),
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

/// Subscribes to the observed-connection feed and persists every decided
/// flow into the `events` table.
///
/// Two tasks so the datapath is never blocked by sqlite:
///
/// - a *feeder* that converts broadcast items to [`EventRow`]s and
///   `try_send`s them into a bounded queue, counting (never awaiting on)
///   drops;
/// - a *writer* that drains the queue in batches of `EVENT_BATCH_ROWS` or
///   every second, whichever comes first, and trims the table to
///   `max_rows` once a minute.
pub fn spawn_event_pipeline(
    store: RuleStore,
    observed_tx: &broadcast::Sender<ObservedConnection>,
    max_rows: u32,
) {
    let (tx, rx) = mpsc::channel::<EventRow>(EVENT_QUEUE_DEPTH);
    let mut sub = observed_tx.subscribe();

    tokio::spawn(async move {
        let dropped = AtomicU64::new(0);
        loop {
            match sub.recv().await {
                Ok(obs) => {
                    let row = convert::event_row_from_observed(
                        &obs.connection,
                        &obs.process,
                        &obs.verdict,
                    );
                    // Audit trail for every blocked flow, independent of
                    // whether the row makes it to disk.
                    if matches!(
                        obs.verdict.action,
                        cfc_core::Action::Deny | cfc_core::Action::Reject
                    ) {
                        info!(
                            action = ?obs.verdict.action,
                            source = convert::verdict_source_db_str(&obs.verdict.source),
                            exe = %obs.process.exe.display(),
                            pid = obs.process.pid,
                            uid = ?obs.process.uid,
                            dst = %format_args!("{}:{}", obs.connection.dst_ip, obs.connection.dst_port),
                            "connection blocked"
                        );
                    }
                    if tx.try_send(row).is_err() {
                        let n = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                        if n == 1 || n.is_multiple_of(EVENT_DROP_LOG_EVERY) {
                            warn!(
                                dropped = n,
                                "event log queue full; dropping events (the packet path is \
                                 never blocked for persistence)"
                            );
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(missed = n, "event log feeder lagged behind the live feed");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        info!("event log feeder stopped: live feed closed");
    });

    tokio::spawn(event_writer_task(store, rx, max_rows));
}

async fn event_writer_task(store: RuleStore, mut rx: mpsc::Receiver<EventRow>, max_rows: u32) {
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
                        write_batch(&store, &mut batch);
                    }
                }
                None => {
                    write_batch(&store, &mut batch);
                    info!("event log writer stopped: queue closed");
                    return;
                }
            },
            _ = flush.tick() => write_batch(&store, &mut batch),
            _ = prune.tick() => match store.prune_events(max_rows) {
                Ok(n) if n > 0 => tracing::debug!(removed = n, cap = max_rows, "pruned old events"),
                Ok(_) => {}
                Err(e) => warn!("event prune failed: {e}"),
            },
        }
    }
}

fn write_batch(store: &RuleStore, batch: &mut Vec<EventRow>) {
    if batch.is_empty() {
        return;
    }
    if let Err(e) = store.insert_events(batch) {
        warn!(rows = batch.len(), "event log write failed: {e}");
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

    let uds = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;
    // Tighten ownership/mode before the first client can connect.
    let auth = secure_socket(&socket_path, &opts.ipc);
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);

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
    fn non_root_mutation_requires_a_group_gated_socket() {
        // Socket really is root:group 0660 -> connecting proved membership.
        assert!(authorize_uid(1000, Access::Mutate, true, true));
        // Group missing / chown failed -> the socket is not proof of
        // anything, so refuse non-root mutation.
        assert!(!authorize_uid(1000, Access::Mutate, false, true));
        // Explicit opt-out: the admin gates the socket some other way.
        assert!(authorize_uid(1000, Access::Mutate, false, false));
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
    fn enforcing_is_false_only_after_a_silent_grace_period() {
        // Fresh start, nothing seen yet: assume healthy.
        assert!(enforcing_heuristic(false, 0, 5));
        // Still nothing after the grace period: the nft rule is missing.
        assert!(!enforcing_heuristic(false, 0, ENFORCING_GRACE_SECS + 1));
        // Any traffic at all proves we are in the path.
        assert!(enforcing_heuristic(false, 1, 100_000));
    }

    #[test]
    fn dry_run_never_claims_to_be_enforcing() {
        assert!(!enforcing_heuristic(true, 0, 5));
        assert!(!enforcing_heuristic(true, 999, 100_000));
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
        spawn_event_pipeline(store.clone(), &tx, 1000);

        tx.send(observed(443, cfc_core::Action::Allow)).unwrap();
        tx.send(observed(80, cfc_core::Action::Deny)).unwrap();

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
