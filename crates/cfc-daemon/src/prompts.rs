//! Prompt router.
//!
//! Bridges the sync NFQUEUE worker (which produces `PromptRequest`s through
//! a bounded tokio mpsc) with async UI subscribers (which receive
//! `PromptEvent`s via a broadcast channel). Responses travel back to the
//! worker over the std-mpsc verdict channel as `PromptVerdict`s.
//!
//! Exactly-once resolution: for every prompt, precisely one of {user
//! answer, timeout sweeper, no-UI fast path, vanished-subscriber reclaim}
//! sends the `PromptVerdict`. The `pending` map is the arbiter - whichever
//! path removes the id first wins, the loser is ignored.
//!
//! # Uid-scoped delivery
//!
//! The transport is still a single broadcast, but a prompt is *addressed*:
//! [`should_deliver`] decides, per subscriber, whether it may see a given
//! prompt. `ipc.rs` applies it when handing events to a client stream; the
//! router applies the very same predicate over its census of live
//! subscriber uids ([`RouterInner::has_audience`]) so the "nobody is
//! listening, answer with `no_ui_action` now" fast path stays truthful. One
//! predicate, two call sites: they cannot drift into a state where a prompt
//! is broadcast that no stream will ever deliver.

use crate::config::DefaultPolicy;
use crate::convert;
use crate::decision::SharedPolicy;
use crate::nfqueue::{PromptRequest, PromptVerdict, VerdictTx};
use crate::stats::Stats;
use cfc_core::Verdict;
use cfc_proto::v1 as pb;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, trace, warn};

/// May the `StreamPrompts` subscriber running as `subscriber_uid` be shown
/// a prompt about a process owned by `process_uid`?
///
/// Three cases, in the order they matter:
///
/// 1. **Root sees everything.** uid 0 already controls the machine, and the
///    root CLI is the recovery path when no desktop session is up.
/// 2. **Same owner.** A prompt about uid 1000's browser belongs to uid
///    1000's session and nobody else's. This is the actual isolation:
///    another logged-in user's UI is not handed the event at all, so it
///    never learns the prompt id, and `SubmitVerdict`'s audience check
///    refuses it even if the id were guessed.
/// 3. **Unattributed traffic goes to everyone.** `process_uid == None`
///    means /proc attribution failed (the process exited before it could be
///    read). Deliberate trade-off: nobody can *claim* such a flow, so
///    restricting it would mean no session ever gets asked and every
///    unattributed connection would silently fall to `timeout_action` /
///    `no_ui_action` - a fail-open-shaped regression in the exact case
///    where a human should look. Prompting everyone is the lesser evil,
///    and it is only reachable for flows the daemon could not attribute.
///
/// Note the consequence of (2) with no (1): on a host where the only UI
/// runs as an ordinary user, prompts for *root-owned* processes (system
/// daemons) are not delivered to it. They resolve by policy instead - see
/// the fast path in [`PromptRouter::enqueue`]. Run a root subscriber (the
/// CLI) if you want to be asked about system daemons.
pub fn should_deliver(process_uid: Option<u32>, subscriber_uid: u32) -> bool {
    subscriber_uid == 0 || process_uid.is_none_or(|owner| owner == subscriber_uid)
}

#[derive(Clone)]
pub struct PromptRouter {
    inner: Arc<RouterInner>,
}

/// What the daemon remembers about a prompt between showing it and hearing
/// the answer.
///
/// The router used to keep only the id, which made `SubmitVerdict` decide
/// about a process it could no longer see. The binding restores exactly the
/// two facts the persist path needs: which executable the prompt was about
/// (so a scope the user edited away from it is left alone), and the sha256
/// of the *running image* when that executable lives somewhere a non-root
/// user could rewrite. The hash is computed at prompt time, from
/// `/proc/<pid>/exe` - the bytes the human is actually deciding about - not
/// at submit time, when the process may be gone or may have exec'd into
/// something else, and not from the on-disk path, which can be swapped in
/// the window between exec and prompt.
#[derive(Debug, Clone, Default)]
pub struct PromptBinding {
    /// The resolved executable the prompt was about, when known.
    pub exe: Option<std::path::PathBuf>,
    /// True when the path was judged rewritable by a non-root user at prompt
    /// time, i.e. a persisted allow *should* be hash-bound. Carried so the
    /// submit path can tell "never promised" from "promised and the hash
    /// below is missing" without re-judging a path whose file may have
    /// changed since the judgment that mattered.
    pub hash_expected: bool,
    /// The running image's digest, present only when `hash_expected` and the
    /// bytes could be read within the shared size cap.
    pub sha256: Option<String>,
}

struct RouterInner {
    /// Prompts broadcast to the UI and not yet resolved, with what was known
    /// about each at prompt time. Present means "unresolved"; the first
    /// resolution path to remove an id sends the verdict.
    pending: Mutex<HashMap<u64, PromptBinding>>,
    broadcast_tx: broadcast::Sender<pb::PromptEvent>,
    /// Census of live `StreamPrompts` subscribers: peer uid -> how many
    /// streams that uid has open. Maintained by [`PromptSubscription`],
    /// which registers on creation and deregisters on drop, so it tracks
    /// the broadcast receivers exactly as closely as
    /// `broadcast_tx.receiver_count()` did - a stream whose client has gone
    /// away is only noticed when the next send to it fails.
    subscribers: Mutex<HashMap<u32, usize>>,
    default_policy: SharedPolicy,
    stats: Stats,
    /// Response path back to the NFQUEUE worker thread. std mpsc is
    /// unbounded, so sending from async context never blocks.
    verdict_tx: VerdictTx,
}

impl RouterInner {
    fn register(&self, uid: u32) {
        *self.subscribers.lock().entry(uid).or_insert(0) += 1;
    }

    fn unregister(&self, uid: u32) {
        let mut g = self.subscribers.lock();
        if let Some(n) = g.get_mut(&uid) {
            *n -= 1;
            if *n == 0 {
                g.remove(&uid);
            }
        }
    }

    /// True when at least one live subscriber would actually be handed a
    /// prompt about a process owned by `process_uid`. Same predicate as the
    /// per-stream filter, so "the router broadcast it" and "some stream
    /// will deliver it" mean the same thing.
    fn has_audience(&self, process_uid: Option<u32>) -> bool {
        self.subscribers
            .lock()
            .keys()
            .any(|&uid| should_deliver(process_uid, uid))
    }

    /// Copies the current shared policy. SIGHUP swaps it at runtime, so
    /// each read observes the latest reload (poisoning is unrecoverable
    /// only in theory: writers just store a Copy value, so recover it).
    fn policy(&self) -> DefaultPolicy {
        *self
            .default_policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Verbatim, so a policy of `reject` genuinely rejects rather than
    /// quietly dropping (see `Verdict::from_policy`).
    fn no_ui_verdict(&self) -> Verdict {
        Verdict::from_policy(self.policy().no_ui_action)
    }
}

impl PromptRouter {
    pub fn new(default_policy: SharedPolicy, stats: Stats, verdict_tx: VerdictTx) -> Self {
        let (broadcast_tx, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(RouterInner {
                pending: Mutex::new(HashMap::new()),
                broadcast_tx,
                subscribers: Mutex::new(HashMap::new()),
                default_policy,
                stats,
                verdict_tx,
            }),
        }
    }

    /// Subscribes the peer running as `peer_uid` to the prompt feed.
    ///
    /// The uid is the kernel-reported `SO_PEERCRED` uid of the client, not
    /// anything the client said about itself; it decides which prompts the
    /// subscription may see (see [`should_deliver`]) and is counted in the
    /// router's census until the returned value is dropped.
    pub fn subscribe(&self, peer_uid: u32) -> PromptSubscription {
        self.inner.register(peer_uid);
        PromptSubscription {
            rx: self.inner.broadcast_tx.subscribe(),
            inner: self.inner.clone(),
            uid: peer_uid,
        }
    }

    /// Resolves a pending prompt with the user's verdict. Returns what the
    /// prompt remembered about its process, or `None` if the id is unknown or
    /// the prompt already resolved another way (e.g. it timed out first), in
    /// which case the verdict is discarded.
    pub fn submit(&self, prompt_id: &str, verdict: Verdict) -> Option<PromptBinding> {
        let id = prompt_id.parse::<u64>().ok()?;
        let binding = self.inner.pending.lock().remove(&id)?;
        self.inner.stats.prompts_dec();
        let _ = self.inner.verdict_tx.send(PromptVerdict {
            prompt_id: id,
            verdict,
        });
        Some(binding)
    }

    fn enqueue(&self, req: PromptRequest, binding: PromptBinding) {
        let prompt_id = req.prompt_id;
        let owner_uid = req.process.uid;
        // Read the shared policy at prompt-creation time so a SIGHUP
        // reload affects every subsequent prompt without a restart.
        let timeout = Duration::from_secs(self.inner.policy().prompt_timeout_secs as u64);

        // If no UI *that may see this prompt* is subscribed, the prompt
        // would just expire to default. Cut the round-trip: answer
        // immediately with no_ui_action. Asking the census rather than
        // `broadcast_tx.receiver_count()` is what keeps that honest now
        // that delivery is uid-scoped: a prompt for uid 1001's process
        // with only uid 1000's UI connected has no audience, and saying
        // "no UI" is the truth for it - waiting out prompt_timeout_secs
        // would stall the packet for nothing and then answer with the
        // wrong knob (timeout_action instead of no_ui_action).
        if !self.inner.has_audience(owner_uid) {
            trace!(
                prompt_id,
                owner_uid = ?owner_uid,
                "no UI subscriber may see this prompt; answering with no_ui_action"
            );
            let _ = self.inner.verdict_tx.send(PromptVerdict {
                prompt_id,
                verdict: self.inner.no_ui_verdict(),
            });
            return;
        }

        let event = pb::PromptEvent {
            prompt_id: prompt_id.to_string(),
            connection: Some(convert::connection_to_pb(&req.connection)),
            process: Some(convert::process_to_pb(&req.process)),
            deadline_unix_ms: chrono::Utc::now().timestamp_millis() + timeout.as_millis() as i64,
            // Said before the user answers, because "your allow will follow
            // the hash, not the path" changes what clicking Allow means.
            binds_to_hash: binding.sha256.is_some(),
        };

        self.inner.pending.lock().insert(prompt_id, binding);
        self.inner.stats.prompts_inc();

        if self.inner.broadcast_tx.send(event).is_err() {
            // All receivers vanished between the census check and the
            // send. Reclaim and fall back.
            if self.inner.pending.lock().remove(&prompt_id).is_some() {
                self.inner.stats.prompts_dec();
                let _ = self.inner.verdict_tx.send(PromptVerdict {
                    prompt_id,
                    verdict: self.inner.no_ui_verdict(),
                });
            }
            return;
        }

        // Timeout sweeper: if nobody answered by `timeout`, apply
        // timeout_action.
        let inner = self.inner.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            if inner.pending.lock().remove(&prompt_id).is_some() {
                inner.stats.prompts_dec();
                debug!(prompt_id, "prompt timed out");
                let _ = inner.verdict_tx.send(PromptVerdict {
                    prompt_id,
                    verdict: Verdict::from_policy(inner.policy().timeout_action),
                });
            }
        });
    }
}

/// One client's view of the prompt feed.
///
/// Wraps the broadcast receiver together with the peer uid it belongs to,
/// and keeps that uid in the router's subscriber census for exactly as long
/// as it lives - so the router's "can anyone see this prompt?" question and
/// the stream's "may I show this prompt?" answer are always about the same
/// set of subscribers.
pub struct PromptSubscription {
    rx: broadcast::Receiver<pb::PromptEvent>,
    inner: Arc<RouterInner>,
    uid: u32,
}

impl PromptSubscription {
    /// Next prompt on the feed - including ones this subscriber may not
    /// see. Filtering is the caller's job ([`should_deliver`]); the
    /// broadcast is shared, so every subscriber observes every event and
    /// drops what is not addressed to it.
    pub async fn recv(&mut self) -> Result<pb::PromptEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}

impl Drop for PromptSubscription {
    fn drop(&mut self) {
        self.inner.unregister(self.uid);
    }
}

/// Pumps `PromptRequest`s from the NFQUEUE worker into the router.
pub async fn run_router_task(mut prompt_rx: mpsc::Receiver<PromptRequest>, router: PromptRouter) {
    while let Some(req) = prompt_rx.recv().await {
        // Off the async threads: the sealed check is a handful of stats, but
        // the hash behind it reads up to the shared size cap. Prompts are
        // sequential through this channel anyway, and the packet the prompt
        // is about is parked waiting on a *human* - milliseconds of hashing
        // are free here and would not be on the NFQUEUE worker.
        let process = req.process.clone();
        let binding = tokio::task::spawn_blocking(move || compute_binding(&process))
            .await
            .unwrap_or_default();
        router.enqueue(req, binding);
    }
    warn!("prompt router channel closed");
}

/// What to remember about this prompt's process, judged now, while it runs.
///
/// The digest is taken from `/proc/<pid>/exe` - the running image - only when
/// the executable's own path is not root-sealed. A sealed path (root-owned,
/// unwritable ancestors all the way up) keeps path-keyed rules meaningful; an
/// unsealed one means anyone who can write the file inherits every allow its
/// path has earned, which is what binding exists to stop. Denies never bind
/// (see the persist path): a hash-bound deny is one file swap away from not
/// applying, while the path-bound one covers whatever bytes sit there next.
fn compute_binding(process: &cfc_core::Process) -> PromptBinding {
    compute_binding_from(
        process,
        std::path::Path::new(&format!("/proc/{}/exe", process.pid)),
    )
}

/// The image path is a parameter so tests can point it at a file of their
/// own making: the real one is `/proc/<pid>/exe`, whose size and ownership
/// are whatever the machine running the tests happens to be - the first
/// version asserted against the test binary itself and learned that a debug
/// build is over the hashing cap.
fn compute_binding_from(process: &cfc_core::Process, image: &std::path::Path) -> PromptBinding {
    if !process.exe_is_known() || !process.exe.is_absolute() {
        return PromptBinding::default();
    }
    let exe = process.exe.clone();
    // Stat failure reads as unsealed: a path that cannot even be examined is
    // certainly not root-sealed, and the hash below answers from /proc
    // regardless of what the on-disk path is doing.
    if cfc_core::exe_path::is_root_sealed(&exe).unwrap_or(false) {
        return PromptBinding {
            exe: Some(exe),
            hash_expected: false,
            sha256: None,
        };
    }
    let sha256 = crate::process_resolve::sha256_file(image, cfc_core::rule::SHA256_MAX_LEN);
    if sha256.is_none() {
        debug!(
            pid = process.pid,
            exe = %exe.display(),
            "user-writable executable could not be hashed; a persisted allow \
             will follow the path"
        );
    }
    PromptBinding {
        exe: Some(exe),
        hash_expected: true,
        sha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfc_core::Action;
    use cfc_core::{Connection, Direction, Process, Protocol, VerdictSource};
    use std::net::{IpAddr, Ipv4Addr};

    fn dp(prompt_timeout_secs: u32) -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: Action::Deny,
            timeout_action: Action::Deny,
            inbound_action: Action::Deny,
            prompt_timeout_secs,
        }
    }

    fn shared(dp: DefaultPolicy) -> SharedPolicy {
        Arc::new(std::sync::RwLock::new(dp))
    }

    /// A prompt about an *unattributed* process (uid `None`), which every
    /// subscriber may see.
    fn req(prompt_id: u64) -> PromptRequest {
        PromptRequest {
            prompt_id,
            connection: Connection::new(
                Protocol::Tcp,
                Direction::Outbound,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                1234,
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                443,
            ),
            process: Process::unknown(1),
        }
    }

    /// A prompt about a process owned by `uid`.
    fn req_owned_by(prompt_id: u64, uid: u32) -> PromptRequest {
        let mut r = req(prompt_id);
        r.process.uid = Some(uid);
        r
    }

    fn user_allow() -> Verdict {
        Verdict {
            action: Action::Allow,
            source: VerdictSource::UserPrompt,
        }
    }

    // -- delivery filter ----------------------------------------------------

    #[test]
    fn a_prompt_goes_to_the_session_that_owns_the_process() {
        assert!(should_deliver(Some(1000), 1000));
        assert!(!should_deliver(Some(1000), 1001));
        assert!(!should_deliver(Some(1001), 1000));
    }

    #[test]
    fn root_sees_every_prompt() {
        for owner in [None, Some(0), Some(1000), Some(u32::MAX)] {
            assert!(should_deliver(owner, 0), "root must see {owner:?}");
        }
    }

    #[test]
    fn a_root_owned_process_is_not_shown_to_an_ordinary_session() {
        // The flip side of "root sees everything": a system daemon's
        // prompt is not another user's business, so only a root subscriber
        // is offered it. With no root UI it resolves by policy.
        assert!(!should_deliver(Some(0), 1000));
        assert!(should_deliver(Some(0), 0));
    }

    #[test]
    fn unattributed_traffic_is_offered_to_everyone() {
        // Deliberate: nobody owns it, so restricting it would mean nobody
        // is ever asked about it.
        assert!(should_deliver(None, 0));
        assert!(should_deliver(None, 1000));
        assert!(should_deliver(None, 65534));
    }

    #[tokio::test]
    async fn a_prompt_no_subscriber_may_see_is_answered_immediately() {
        // The fast path must key off "can anyone see this?", not "is
        // anyone connected?" - otherwise this prompt would stall for the
        // whole timeout and then answer with the wrong policy knob.
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Stats::new();
        let router = PromptRouter::new(shared(dp(3600)), stats.clone(), tx);
        let _sub = router.subscribe(1000);

        router.enqueue(req_owned_by(5, 1001), PromptBinding::default());

        let pv = rx.try_recv().expect("verdict should already be queued");
        assert_eq!(pv.prompt_id, 5);
        assert_eq!(pv.verdict.action, Action::Deny); // no_ui_action
        assert_eq!(pv.verdict.source, VerdictSource::DefaultPolicy);
        // It never became pending, so nothing can answer it late.
        assert_eq!(stats.prompts_pending(), 0);
        assert!(router.submit("5", user_allow()).is_none());
    }

    #[tokio::test]
    async fn a_prompt_a_subscriber_may_see_is_broadcast() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Stats::new();
        let router = PromptRouter::new(shared(dp(3600)), stats.clone(), tx);
        let mut sub = router.subscribe(1000);

        router.enqueue(req_owned_by(6, 1000), PromptBinding::default());

        assert_eq!(sub.recv().await.unwrap().prompt_id, "6");
        assert_eq!(stats.prompts_pending(), 1);
        assert!(rx.try_recv().is_err(), "the UI owes us an answer");
    }

    #[tokio::test]
    async fn a_root_subscriber_is_an_audience_for_every_prompt() {
        let (tx, rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(dp(3600)), Stats::new(), tx);
        let mut sub = router.subscribe(0);

        router.enqueue(req_owned_by(8, 1001), PromptBinding::default());

        assert_eq!(sub.recv().await.unwrap().prompt_id, "8");
        assert!(rx.try_recv().is_err(), "root's UI owes us an answer");
    }

    #[tokio::test]
    async fn dropping_the_last_subscription_restores_the_no_ui_fast_path() {
        let (tx, rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(dp(3600)), Stats::new(), tx);

        // Two windows for the same uid: the first drop must not deregister
        // the session.
        let sub_a = router.subscribe(1000);
        let sub_b = router.subscribe(1000);
        drop(sub_a);
        router.enqueue(req_owned_by(1, 1000), PromptBinding::default());
        assert!(rx.try_recv().is_err(), "uid 1000 still has a UI open");

        drop(sub_b);
        router.enqueue(req_owned_by(2, 1000), PromptBinding::default());
        assert_eq!(
            rx.try_recv().expect("no UI left; answer now").prompt_id,
            2,
            "the census must forget a closed subscription"
        );
    }

    // -- resolution paths ---------------------------------------------------

    #[tokio::test]
    async fn no_ui_reject_policy_stays_reject() {
        // A `no_ui_action = "reject"` policy must reach the worker as
        // Reject so the refusal is injected; collapsing it to Deny would
        // make the configured policy a lie.
        let policy = DefaultPolicy {
            no_ui_action: Action::Reject,
            timeout_action: Action::Reject,
            inbound_action: Action::Deny,
            prompt_timeout_secs: 15,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(policy), Stats::new(), tx);
        router.enqueue(req(11), PromptBinding::default());
        let pv = rx.try_recv().expect("verdict should already be queued");
        assert_eq!(pv.verdict.action, Action::Reject);
        assert_eq!(pv.verdict.source, VerdictSource::DefaultPolicy);
    }

    #[tokio::test]
    async fn no_ui_answers_immediately_with_no_ui_action() {
        let (tx, rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(dp(15)), Stats::new(), tx);
        router.enqueue(req(7), PromptBinding::default());
        let pv = rx.try_recv().expect("verdict should already be queued");
        assert_eq!(pv.prompt_id, 7);
        assert_eq!(pv.verdict.action, Action::Deny);
        // Nothing is pending: a late submit is rejected.
        assert!(router.submit("7", user_allow()).is_none());
    }

    #[tokio::test]
    async fn user_answer_resolves_exactly_once() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Stats::new();
        let router = PromptRouter::new(shared(dp(3600)), stats.clone(), tx);
        let mut sub = router.subscribe(1000);

        router.enqueue(req(1), PromptBinding::default());
        let event = sub.recv().await.unwrap();
        assert_eq!(event.prompt_id, "1");
        assert_eq!(stats.prompts_pending(), 1);

        assert!(router.submit("1", user_allow()).is_some());
        assert_eq!(stats.prompts_pending(), 0);
        let pv = rx.try_recv().unwrap();
        assert_eq!(pv.prompt_id, 1);
        assert_eq!(pv.verdict.action, Action::Allow);

        // A second answer loses: rejected, no duplicate verdict.
        assert!(router.submit("1", user_allow()).is_none());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unknown_or_malformed_prompt_id_rejected() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(dp(15)), Stats::new(), tx);
        assert!(router.submit("12345", user_allow()).is_none());
        assert!(router.submit("not-a-number", user_allow()).is_none());
    }

    #[tokio::test]
    async fn policy_reload_applies_to_subsequent_prompts() {
        let (tx, rx) = std::sync::mpsc::channel();
        let policy = shared(dp(15)); // no_ui_action: Deny
        let router = PromptRouter::new(policy.clone(), Stats::new(), tx);

        // No UI subscribed: the fast path answers with no_ui_action.
        router.enqueue(req(1), PromptBinding::default());
        assert_eq!(rx.try_recv().unwrap().verdict.action, Action::Deny);

        // Swap the shared policy in place (what SIGHUP does in main).
        policy.write().unwrap().no_ui_action = Action::Allow;

        router.enqueue(req(2), PromptBinding::default());
        assert_eq!(rx.try_recv().unwrap().verdict.action, Action::Allow);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_resolves_with_timeout_action() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Stats::new();
        let router = PromptRouter::new(shared(dp(1)), stats.clone(), tx);
        let _sub = router.subscribe(1000); // keep a UI "connected"

        router.enqueue(req(9), PromptBinding::default());
        assert_eq!(stats.prompts_pending(), 1);

        // Paused time auto-advances past the sweeper's deadline.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let pv = rx.try_recv().expect("timeout verdict should be queued");
        assert_eq!(pv.prompt_id, 9);
        assert_eq!(pv.verdict.action, Action::Deny);
        assert_eq!(stats.prompts_pending(), 0);
        // The user answering afterwards is a no-op.
        assert!(router.submit("9", user_allow()).is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_user_writable_binary_earns_a_hash_binding() {
        // A file of the test's own making stands in for both the rule path
        // and the running image - the ~/.local/bin shape binding exists for.
        // Under root the ancestry judgment flips, so the test skips rather
        // than asserts a coin toss.
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\nexit 0\n").expect("write");
        if cfc_core::exe_path::is_root_sealed(&exe).unwrap_or(false) {
            return;
        }
        let proc = Process {
            pid: 4242,
            exe: exe.clone(),
            ..Process::unknown(4242)
        };
        let binding = compute_binding_from(&proc, &exe);
        assert!(
            binding.hash_expected,
            "a user-writable path must expect a hash"
        );
        let sha = binding
            .sha256
            .expect("the image is readable and under the cap");
        assert_eq!(sha.len(), 64);
        assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(binding.exe.as_deref(), Some(exe.as_path()));
    }

    #[test]
    fn an_oversized_image_expects_a_hash_it_cannot_have() {
        // The over-the-cap path: hash_expected stays true - the persist
        // side turns that into a spoken note instead of a silent
        // path-keyed allow - but no digest is produced. Exercised with the
        // real cap by pointing the image at a file that does not exist,
        // which takes the same None path without writing 64 MiB in a test.
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"x").expect("write");
        if cfc_core::exe_path::is_root_sealed(&exe).unwrap_or(false) {
            return;
        }
        let proc = Process {
            pid: 4242,
            exe: exe.clone(),
            ..Process::unknown(4242)
        };
        let binding = compute_binding_from(&proc, &dir.path().join("gone"));
        assert!(binding.hash_expected);
        assert!(binding.sha256.is_none());
    }

    #[test]
    fn a_root_sealed_binary_is_left_path_keyed() {
        // /usr/bin/env is root-owned 0755 under root-owned ancestors on any
        // machine these tests run on; if this one is somehow not, the test
        // has nothing true to assert.
        let sealed = std::path::Path::new("/usr/bin/env");
        if !cfc_core::exe_path::is_root_sealed(sealed).unwrap_or(false) {
            return;
        }
        let proc = Process {
            pid: std::process::id(),
            exe: sealed.to_path_buf(),
            ..Process::unknown(std::process::id())
        };
        let binding = compute_binding(&proc);
        assert!(!binding.hash_expected);
        assert!(binding.sha256.is_none(), "sealed paths never hash");
    }

    #[test]
    fn an_unattributed_process_earns_no_binding() {
        let binding = compute_binding(&Process::unknown(1));
        assert!(!binding.hash_expected);
        assert!(binding.sha256.is_none());
        assert!(binding.exe.is_none());
    }

    #[tokio::test]
    async fn submit_returns_the_binding_the_prompt_stored() {
        // What travels: enqueue remembers, the event announces, submit
        // returns - the three legs the persist path stands on.
        let (tx, _rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(dp(3600)), Stats::new(), tx);
        let mut sub = router.subscribe(1000);

        let binding = PromptBinding {
            exe: Some(std::path::PathBuf::from("/home/u/.local/bin/tool")),
            hash_expected: true,
            sha256: Some("ab".repeat(32)),
        };
        router.enqueue(req_owned_by(9, 1000), binding);

        let event = sub.recv().await.unwrap();
        assert!(event.binds_to_hash, "the prompt must announce the binding");

        let got = router.submit("9", user_allow()).expect("pending");
        assert_eq!(got.sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(
            got.exe.as_deref(),
            Some(std::path::Path::new("/home/u/.local/bin/tool"))
        );
    }

    #[tokio::test]
    async fn a_sealed_prompt_does_not_announce_a_binding() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let router = PromptRouter::new(shared(dp(3600)), Stats::new(), tx);
        let mut sub = router.subscribe(1000);
        router.enqueue(req_owned_by(10, 1000), PromptBinding::default());
        let event = sub.recv().await.unwrap();
        assert!(!event.binds_to_hash);
    }
}
