//! NFQUEUE intercept worker.
//!
//! A dedicated blocking thread owns the packet queue exclusively and runs
//! [`Worker::run`]. Per-packet decision logic lives in the pure
//! [`handle_packet`] pipeline (parse -> self-DNS bypass -> process
//! attribution -> hostname attach -> rule evaluation), which is unit-tested
//! without root through the [`ProcessResolver`] / [`HostCache`] seams; the
//! loop wrapped around it -- prompt dedup, verdict fan-out, recv error
//! budget, shutdown -- is unit-tested through the [`PacketQueue`] seam.
//!
//! Prompting is asynchronous: packets awaiting a user verdict are parked in
//! the worker's `waiters` table while the rest of the datapath keeps
//! verdicting, so a single unanswered prompt no longer stalls every flow
//! behind it. Repeat SYNs and parallel connections of the same flow attach
//! to the already-outstanding prompt instead of re-prompting.
//!
//! Channel topology:
//!
//! ```text
//! worker --PromptRequest (tokio mpsc)--> prompt router (async)
//! worker <--PromptVerdict (std mpsc)---- prompt router
//! ```
//!
//! # Recv mode, and why the worker never parks indefinitely
//!
//! The queue is kept in NONBLOCKING mode for the worker's whole life and
//! every idle iteration waits at most [`RECV_POLL_INTERVAL`] on the verdict
//! channel. That is a deliberate change from the earlier design, where an
//! idle worker parked in a blocking kernel `recv()`:
//!
//! - A thread parked in a blocking `recv()` cannot be woken from outside.
//!   `nfq` 0.2 keeps the netlink socket's descriptor private (no
//!   `AsRawFd`, no `SO_RCVTIMEO` setter), so the queue can neither be
//!   `poll()`ed with a timeout nor shut down; and closing a descriptor
//!   another thread is blocked on is unsound anyway (the number is free
//!   for reuse the moment it is closed).
//! - A worker that cannot be woken never observes [`Worker::stop`], never
//!   returns, and tokio's blocking pool then refuses to shut down -- which
//!   is precisely the 90-second `TimeoutStopSec` hang on every daemon stop
//!   that this replaces.
//!
//! The price is that while the worker is idle the first packet of an
//! intercepted flow can wait up to one [`RECV_POLL_INTERVAL`] (mean: half
//! that) in the kernel queue, and that the idle worker wakes at that
//! cadence. It is the same cadence the loop already paid whenever a prompt
//! was outstanding, and single-digit milliseconds on connection setup is a
//! far better trade than a minute and a half on every restart. If `nfq`
//! ever exposes the netlink fd, move the idle wait to a `poll()` on it:
//! that buys back the zero added latency *and* keeps the bounded stop.

use crate::config::NfqConfig;
use crate::decision::{Decision, Engine};
use crate::dns::DnsCache;
use crate::packet;
use crate::process_resolve;
use crate::reject::Rejecter;
use crate::stats::Stats;
use anyhow::Context as _;
use cfc_core::{Action, Connection, Direction, Process, Protocol, Verdict};
use nfq::{Message, Queue, Verdict as NfqVerdict};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

/// Consecutive hard `recv` errors tolerated before the worker gives up and
/// the daemon exits non-zero (transient errors reset the count).
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 100;

/// Backoff after a hard `recv` error, so a permanently broken socket drains
/// the error budget over ~25s instead of spinning a core.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(250);

/// How long an idle iteration waits on the verdict channel before trying
/// the queue again. Bounds both the worker's shutdown latency and the extra
/// latency an intercepted packet can pick up; see the module docs.
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// `NF_INET_LOCAL_IN` - a packet addressed to this machine.
const NF_INET_LOCAL_IN: u8 = 1;
/// `NF_INET_LOCAL_OUT` - a packet this machine is sending.
const NF_INET_LOCAL_OUT: u8 = 3;

/// Which way a packet is going, from the hook that queued it.
///
/// Only `LOCAL_OUT` is outbound; everything else is treated as inbound. That
/// asymmetry is the fail-closed direction, and it is worth being explicit
/// about why, because the obvious reading is backwards: inbound is the
/// *stricter* policy here, not the looser one. An outbound flow can prompt the
/// user and can be allowed by an outbound rule; an inbound flow does neither -
/// it matches a rule or it takes `inbound_action`, which cannot be Allow. So
/// an unexpected hook (someone added a `forward` rule by hand) lands on
/// default-deny rather than on the path that can end in Allow.
///
/// This cannot black-hole ordinary traffic by mistake: the hook number comes
/// from `nfqnl_msg_packet_hdr`, which the kernel sends with every packet and
/// which nfq asserts is present before handing us a message. It is never a
/// zero default, so locally-generated packets are always hook 3 and always
/// read as outbound.
fn direction_for_hook(hook: u8) -> Direction {
    match hook {
        NF_INET_LOCAL_OUT => Direction::Outbound,
        NF_INET_LOCAL_IN => Direction::Inbound,
        // Not one of the two local hooks, so not something the shipped
        // ruleset produces. Same answer as LOCAL_IN, different reason: this
        // arm is the fail-closed default, not a classification.
        _ => Direction::Inbound,
    }
}

/// Coarse wall-clock unix milliseconds for the watchdog stamps. Only
/// differences are compared, so occasional NTP steps are harmless at the
/// minute-scale staleness threshold.
pub fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

pub type PromptTx = mpsc::Sender<PromptRequest>;

/// Sender half of the verdict back-channel (async prompt router -> worker
/// thread). std mpsc: unbounded, so `send` never blocks an async task.
pub type VerdictTx = Sender<PromptVerdict>;
/// Receiver half of the verdict back-channel, owned by the worker thread.
pub type VerdictRx = Receiver<PromptVerdict>;

/// A request from the NFQUEUE worker to the prompt router asking for a
/// user verdict on a flow.
pub struct PromptRequest {
    /// Worker-allocated id; the router echoes it back in [`PromptVerdict`].
    pub prompt_id: u64,
    pub connection: Connection,
    pub process: Process,
}

/// A resolved prompt flowing back from the router to the worker.
#[derive(Debug, Clone, Copy)]
pub struct PromptVerdict {
    pub prompt_id: u64,
    pub verdict: Verdict,
}

/// Observed connection (post-decision) broadcast to the live feed.
#[derive(Debug, Clone)]
pub struct ObservedConnection {
    pub connection: Connection,
    pub process: Process,
    pub verdict: Verdict,
}

/// One packet taken off the queue, as the worker needs to see it.
///
/// Deliberately borrow-based: `payload` hands back the buffer the message
/// already owns, so the datapath never copies packet bytes.
trait PacketMessage {
    fn payload(&self) -> &[u8];
    /// Socket owner from NFQA_UID, when the kernel reported it.
    fn uid(&self) -> Option<u32>;
    /// Socket group from NFQA_GID, when the kernel reported it.
    fn gid(&self) -> Option<u32>;
    /// Which netfilter hook queued this packet, as `NF_INET_*`.
    ///
    /// The kernel tells us, so the daemon does not have to guess from the
    /// addresses - and guessing would be wrong on a multi-homed or routed
    /// host. This is what makes one queue able to serve both chains.
    fn hook(&self) -> u8;
    fn set_verdict(&mut self, verdict: NfqVerdict);
}

/// The worker's view of the kernel queue.
///
/// Implemented for [`nfq::Queue`] as a pure forwarding impl with no
/// behaviour of its own, and by a scripted fake in the tests -- which is
/// what makes [`Worker::run`], the prompt-dedup state machine and the recv
/// error budget testable without root or a live NFQUEUE.
trait PacketQueue {
    type Msg: PacketMessage;

    /// `true` puts the queue in nonblocking mode: `recv` then reports
    /// [`std::io::ErrorKind::WouldBlock`] instead of parking when the queue
    /// is empty.
    fn set_nonblocking(&mut self, nonblocking: bool);
    fn recv(&mut self) -> std::io::Result<Self::Msg>;
    /// Hands the message's verdict back to the kernel, consuming it.
    fn verdict(&mut self, msg: Self::Msg) -> std::io::Result<()>;
}

impl PacketMessage for Message {
    fn payload(&self) -> &[u8] {
        self.get_payload()
    }

    fn uid(&self) -> Option<u32> {
        self.get_uid()
    }

    fn gid(&self) -> Option<u32> {
        self.get_gid()
    }

    fn hook(&self) -> u8 {
        self.get_hook()
    }

    fn set_verdict(&mut self, verdict: NfqVerdict) {
        Message::set_verdict(self, verdict);
    }
}

impl PacketQueue for Queue {
    type Msg = Message;

    fn set_nonblocking(&mut self, nonblocking: bool) {
        Queue::set_nonblocking(self, nonblocking);
    }

    fn recv(&mut self) -> std::io::Result<Message> {
        Queue::recv(self)
    }

    fn verdict(&mut self, msg: Message) -> std::io::Result<()> {
        Queue::verdict(self, msg)
    }
}

/// What [`spawn`] hands back to `main`.
pub struct NfqHandles {
    /// Resolves when the worker leaves its loop: `Ok` on a requested stop,
    /// `Err` once the recv error budget is exhausted.
    pub task: JoinHandle<anyhow::Result<()>>,
    /// Watchdog liveness cell (see [`Worker::last_activity`]) for main's
    /// WATCHDOG=1 heartbeat task.
    pub last_activity: Arc<AtomicI64>,
    /// Shutdown request, observed at the top of every loop iteration.
    stop: Arc<AtomicBool>,
}

impl NfqHandles {
    /// Handles for a daemon that never bound a queue (`--dry-run`): the
    /// caller supplies whatever task stands in for the datapath, and the
    /// liveness stamp is fixed at startup (main skips the staleness check
    /// entirely in dry-run mode).
    pub fn inert(task: JoinHandle<anyhow::Result<()>>) -> Self {
        Self {
            task,
            last_activity: Arc::new(AtomicI64::new(unix_ms())),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Asks the worker to leave its loop. Returns immediately; the worker
    /// notices within one [`RECV_POLL_INTERVAL`] plus whatever packet it is
    /// mid-way through.
    ///
    /// `Relaxed` is enough: the flag carries no data, and the only thing
    /// that must happen-before anything is the worker's own return.
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Binds the queue and starts the worker thread.
pub fn spawn(
    cfg: &NfqConfig,
    engine: Engine,
    prompt_tx: PromptTx,
    verdict_rx: VerdictRx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
    dns_cache: DnsCache,
) -> anyhow::Result<NfqHandles> {
    let queue_num = cfg.queue_num;
    info!(queue_num, "opening NFQUEUE");

    let mut queue = match Queue::open() {
        Ok(q) => q,
        Err(e) => {
            error!("failed to open NFQUEUE socket: {e}");
            error!("hint: NFQUEUE needs CAP_NET_ADMIN. Run as root or via the");
            error!("hint: bundled colony-firewalld.service systemd unit. If both");
            error!("hint: are in place, check that the nfnetlink_queue kernel");
            error!("hint: module is loaded:  modprobe nfnetlink_queue");
            error!("hint: to test the gRPC/UI surface without root, use --dry-run");
            return Err(anyhow::Error::from(e).context("opening NFQUEUE socket"));
        }
    };
    if let Err(e) = queue.bind(queue_num) {
        error!(queue_num, "failed to bind NFQUEUE {queue_num}: {e}");
        error!("hint: another process may already own this queue number.");
        error!("hint: list owners with:  ss -f netlink | grep nfqueue");
        error!("hint: or pick a different number in /etc/colony-firewall/daemon.toml");
        error!("hint: under [nfqueue] queue_num = N, and update the matching nft rule.");
        return Err(anyhow::Error::from(e).context(format!("binding NFQUEUE {queue_num}")));
    }

    // Queue tuning is best-effort: older kernels reject some of these
    // config messages, which is no reason not to filter at all.
    if let Err(e) = queue.set_queue_max_len(queue_num, cfg.queue_max_len) {
        warn!(
            len = cfg.queue_max_len,
            "setting NFQUEUE max length failed (older kernel?): {e}"
        );
    }
    if let Err(e) = queue.set_fail_open(queue_num, cfg.fail_open) {
        warn!(
            fail_open = cfg.fail_open,
            "setting NFQUEUE fail-open failed (older kernel?): {e}"
        );
    }
    if let Err(e) = queue.set_recv_uid_gid(queue_num, true) {
        warn!("enabling NFQUEUE uid/gid reporting failed (older kernel?): {e}");
    }

    info!(
        queue_num,
        queue_max_len = cfg.queue_max_len,
        fail_open = cfg.fail_open,
        "NFQUEUE bound, entering recv loop"
    );

    // Opened once here (never per packet) so a missing CAP_NET_RAW is
    // reported exactly once at startup; see [`Rejecter`].
    let rejecter = Rejecter::open();

    let last_activity = Arc::new(AtomicI64::new(unix_ms()));
    let stop = Arc::new(AtomicBool::new(false));
    let worker = Worker {
        queue,
        engine,
        rejecter,
        prompt_tx,
        verdict_rx,
        observed_tx,
        stats,
        dns: Box::new(dns_cache),
        resolver: Box::new(ProcfsResolver),
        waiters: HashMap::new(),
        pending_flows: HashMap::new(),
        next_prompt_id: 1,
        verdict_channel_open: true,
        tuning: Tuning::default(),
        stop: stop.clone(),
        last_activity: last_activity.clone(),
    };
    let blocking = tokio::task::spawn_blocking(move || worker.run());

    let task = tokio::spawn(async move {
        match blocking.await {
            Ok(result) => result,
            Err(e) => Err(anyhow::anyhow!("NFQUEUE blocking task panicked: {e}")),
        }
    });
    Ok(NfqHandles {
        task,
        last_activity,
        stop,
    })
}

/// Identity of a flow for prompt dedup: one outstanding prompt per
/// (origin, destination, protocol). The source port is deliberately not
/// part of the key so SYN retransmits *and* parallel connections from the
/// same app to the same destination share a single prompt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    origin: FlowOrigin,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: Protocol,
}

/// Prompt-dedup origin: the executable path when attribution succeeded,
/// otherwise the pid (0 when even the pid is unknown).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FlowOrigin {
    Exe(PathBuf),
    Pid(u32),
}

impl FlowKey {
    fn for_flow(conn: &Connection, proc: &Process) -> Self {
        let origin = if !proc.exe_is_known() {
            FlowOrigin::Pid(proc.pid)
        } else {
            FlowOrigin::Exe(proc.exe.clone())
        };
        Self {
            origin,
            dst_ip: conn.dst_ip,
            dst_port: conn.dst_port,
            protocol: conn.protocol,
        }
    }
}

/// Per-prompt bookkeeping on the worker thread.
struct PendingPrompt<M> {
    flow: FlowKey,
    connection: Connection,
    process: Process,
    /// Every packet parked on this prompt; all get the same verdict.
    packets: Vec<M>,
    /// Applied if the router disappears before answering.
    fallback: Verdict,
}

/// Loop timings. Constant in production; the tests shrink them so that
/// draining a hundred-error budget or waiting out a poll cadence costs no
/// wall-clock.
#[derive(Debug, Clone, Copy)]
struct Tuning {
    poll_interval: Duration,
    error_backoff: Duration,
    max_consecutive_recv_errors: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            poll_interval: RECV_POLL_INTERVAL,
            error_backoff: RECV_ERROR_BACKOFF,
            max_consecutive_recv_errors: MAX_CONSECUTIVE_RECV_ERRORS,
        }
    }
}

/// State owned by the NFQUEUE worker thread.
///
/// Invariants:
///
/// - `waiters.len()` == number of outstanding prompts, and every entry
///   holds at least one parked packet.
/// - `pending_flows` and `waiters` form a bijection: each waiter's `flow`
///   maps back to its prompt id and vice versa. Both entries are created
///   together in [`Worker::park_for_prompt`] and removed together in
///   [`Worker::resolve_prompt`]. A violation is repaired and logged, never
///   panicked on: this state machine runs *on* the datapath.
/// - The queue socket is nonblocking for the worker's whole life, so no
///   iteration can park for longer than `tuning.poll_interval` and the
///   stop flag is always observed within that bound (see the module docs
///   for why the earlier blocking-when-idle mode had to go).
struct Worker<Q: PacketQueue> {
    queue: Q,
    engine: Engine,
    /// Injects the TCP RST / ICMP port-unreachable that makes
    /// [`Action::Reject`] differ from [`Action::Deny`]. Inert (drop-only)
    /// when raw sockets are unavailable.
    rejecter: Rejecter,
    prompt_tx: PromptTx,
    verdict_rx: VerdictRx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
    /// Reverse-DNS / self-identification seam; [`DnsCache`] in production.
    dns: Box<dyn HostCache + Send>,
    /// Process attribution seam; [`ProcfsResolver`] in production.
    resolver: Box<dyn ProcessResolver + Send>,
    waiters: HashMap<u64, PendingPrompt<Q::Msg>>,
    pending_flows: HashMap<FlowKey, u64>,
    next_prompt_id: u64,
    /// Cleared once the router hangs up. The idle path must stop calling
    /// `recv_timeout` after that: a disconnected channel returns instantly,
    /// which would turn the idle wait into a busy loop.
    verdict_channel_open: bool,
    tuning: Tuning,
    /// Set by main's shutdown path; observed at the top of every iteration.
    stop: Arc<AtomicBool>,
    /// Watchdog liveness cell shared with main's heartbeat task: the
    /// unix-ms at which the loop last turned. Since no iteration blocks for
    /// longer than `tuning.poll_interval`, a stale stamp means the worker
    /// wedged and main withholds the WATCHDOG=1 heartbeat.
    last_activity: Arc<AtomicI64>,
}

impl<Q: PacketQueue> Worker<Q> {
    fn run(mut self) -> anyhow::Result<()> {
        // Everything below assumes recv never parks indefinitely; establish
        // that here rather than trusting the caller to have done it.
        self.queue.set_nonblocking(true);

        let mut consecutive_errors: u32 = 0;
        loop {
            if self.stop.load(Ordering::Relaxed) {
                info!("stop requested; NFQUEUE worker leaving its recv loop");
                return Ok(());
            }
            // Watchdog heartbeat source: one stamp per iteration. main's
            // heartbeat task withholds WATCHDOG=1 once this goes stale.
            self.stamp_activity();
            self.drain_verdicts();

            match self.queue.recv() {
                Ok(msg) => {
                    consecutive_errors = 0;
                    self.handle_message(msg);
                }
                // No packet ready: spend the beat waiting for a verdict.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => self.idle_wait(),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    consecutive_errors += 1;
                    error!("NFQUEUE recv error ({consecutive_errors} consecutive): {e}");
                    if consecutive_errors >= self.tuning.max_consecutive_recv_errors {
                        return Err(e).context(format!(
                            "NFQUEUE recv failed {consecutive_errors} times in a row"
                        ));
                    }
                    std::thread::sleep(self.tuning.error_backoff);
                }
            }
        }
    }

    /// Stamps the watchdog cell with "the loop turned just now".
    fn stamp_activity(&self) {
        self.last_activity.store(unix_ms(), Ordering::Relaxed);
    }

    /// The queue had nothing ready. Wait a short beat on the verdict
    /// channel instead of spinning; this is also what bounds how long the
    /// stop flag can go unobserved.
    fn idle_wait(&mut self) {
        if !self.verdict_channel_open {
            // Nothing left to wait for, and `recv_timeout` on a hung-up
            // channel returns instantly: pace the loop by hand.
            std::thread::sleep(self.tuning.poll_interval);
            return;
        }
        match self.verdict_rx.recv_timeout(self.tuning.poll_interval) {
            Ok(pv) => self.resolve_prompt(pv),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => self.close_verdict_channel(),
        }
    }

    /// Drains every verdict the router has produced so far.
    fn drain_verdicts(&mut self) {
        if !self.verdict_channel_open {
            return;
        }
        loop {
            match self.verdict_rx.try_recv() {
                Ok(pv) => self.resolve_prompt(pv),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.close_verdict_channel();
                    return;
                }
            }
        }
    }

    /// The router is gone for good: remember it (so the idle path stops
    /// polling a dead channel) and unstrand whatever was parked.
    fn close_verdict_channel(&mut self) {
        self.verdict_channel_open = false;
        self.flush_waiters_disconnected();
    }

    /// The router side of the verdict channel is gone; no pending prompt
    /// can ever resolve. Apply each prompt's fallback so its parked packets
    /// aren't stranded until the kernel times them out.
    fn flush_waiters_disconnected(&mut self) {
        if self.waiters.is_empty() {
            return;
        }
        warn!(
            count = self.waiters.len(),
            "verdict channel disconnected; applying fallback to outstanding prompts"
        );
        let ids: Vec<u64> = self.waiters.keys().copied().collect();
        for prompt_id in ids {
            let verdict = self.waiters[&prompt_id].fallback;
            self.resolve_prompt(PromptVerdict { prompt_id, verdict });
        }
    }

    /// Applies a resolved prompt: verdicts every parked packet, drops the
    /// waiters + pending_flows entries, records stats once (one prompt ==
    /// one logical connection) and publishes the observation.
    fn resolve_prompt(&mut self, pv: PromptVerdict) {
        let Some(pending) = self.waiters.remove(&pv.prompt_id) else {
            // Late duplicate (the prompt already resolved another way);
            // the first resolution won.
            trace!(
                prompt_id = pv.prompt_id,
                "verdict for already-resolved prompt, ignoring"
            );
            return;
        };
        self.pending_flows.remove(&pending.flow);

        for msg in pending.packets {
            // Per packet, not per prompt: a Reject response is derived from
            // the individual segment (its sequence numbers, its source
            // port), and parallel connections share one prompt.
            self.apply_action(msg, pv.verdict.action);
        }

        record(&self.stats, pv.verdict.action);
        let _ = self.observed_tx.send(ObservedConnection {
            connection: pending.connection,
            process: pending.process,
            verdict: pv.verdict,
        });
    }

    fn handle_message(&mut self, msg: Q::Msg) {
        let meta = PacketMeta {
            uid: msg.uid(),
            gid: msg.gid(),
            direction: direction_for_hook(msg.hook()),
        };
        let deps = PipelineDeps {
            engine: &self.engine,
            stats: &self.stats,
            dns: self.dns.as_ref(),
            resolver: self.resolver.as_ref(),
        };
        match handle_packet(msg.payload(), &meta, &deps) {
            PacketOutcome::Silent(verdict) => self.send_verdict(msg, verdict),
            PacketOutcome::Deliver {
                connection,
                process,
                verdict,
            } => {
                self.apply_action(msg, verdict.action);
                let _ = self.observed_tx.send(ObservedConnection {
                    connection,
                    process,
                    verdict,
                });
            }
            PacketOutcome::Prompt {
                connection,
                process,
                fallback,
            } => self.park_for_prompt(msg, connection, process, fallback),
        }
    }

    /// Parks a packet awaiting a user verdict. If the flow already has an
    /// outstanding prompt the packet rides it; otherwise a new prompt is
    /// dispatched to the router. If the router can't take it (channel full
    /// or closed), the fallback applies immediately.
    fn park_for_prompt(
        &mut self,
        msg: Q::Msg,
        connection: Connection,
        process: Process,
        fallback: Verdict,
    ) {
        let flow = FlowKey::for_flow(&connection, &process);
        if let Some(&prompt_id) = self.pending_flows.get(&flow) {
            if let Some(pending) = self.waiters.get_mut(&prompt_id) {
                trace!(
                    prompt_id,
                    "flow already prompting; parking packet on existing prompt"
                );
                pending.packets.push(msg);
                return;
            }
            // The waiters/pending_flows bijection documented on [`Worker`]
            // was violated: a flow points at a prompt that no longer
            // exists. Killing the worker thread over it would take the
            // whole datapath down, so drop the stale mapping and let the
            // packet open a fresh prompt below.
            error!(
                prompt_id,
                "pending_flows entry without matching waiters entry; re-prompting flow"
            );
            self.pending_flows.remove(&flow);
        }

        let prompt_id = self.next_prompt_id;
        self.next_prompt_id += 1;
        let req = PromptRequest {
            prompt_id,
            connection: connection.clone(),
            process: process.clone(),
        };
        match self.prompt_tx.try_send(req) {
            Ok(()) => {
                self.pending_flows.insert(flow.clone(), prompt_id);
                self.waiters.insert(
                    prompt_id,
                    PendingPrompt {
                        flow,
                        connection,
                        process,
                        packets: vec![msg],
                        fallback,
                    },
                );
            }
            Err(e) => {
                // Router saturated or gone: apply the default policy now
                // rather than stranding the packet.
                trace!("prompt channel unavailable ({e}); applying fallback");
                self.apply_action(msg, fallback.action);
                record(&self.stats, fallback.action);
                let _ = self.observed_tx.send(ObservedConnection {
                    connection,
                    process,
                    verdict: fallback,
                });
            }
        }
    }

    /// Applies a policy action to a queued packet.
    ///
    /// Deny and Reject both hand the kernel the same verdict (Drop) - they
    /// differ only in what the application sees. Reject additionally
    /// injects the refusal the peer would have sent (TCP RST / ICMP port
    /// unreachable) so the app fails immediately instead of retransmitting
    /// until its own timeout. The injection is best-effort: if it can't be
    /// sent the packet is still dropped, i.e. Reject degrades to Deny.
    fn apply_action(&mut self, msg: Q::Msg, action: Action) {
        if action == Action::Reject {
            self.inject_refusal(&msg);
        }
        self.send_verdict(msg, nfq_verdict_for(action));
    }

    /// Reparses this specific packet (cheap, and only on the Reject path)
    /// because the refusal depends on per-segment fields the pipeline's
    /// [`Connection`] does not carry - TCP sequence numbers and the bytes
    /// quoted back in an ICMP error.
    fn inject_refusal(&self, msg: &Q::Msg) {
        let payload = msg.payload();
        // The direction does not change the refusal - `reject` swaps the
        // 5-tuple to answer whoever sent the packet, which is right both ways -
        // but pass the true one anyway rather than a literal that happens not
        // to be read yet.
        match packet::parse(payload, direction_for_hook(msg.hook())) {
            Ok(conn) => {
                let outcome = self.rejecter.reject(&conn, payload);
                trace!(?outcome, dst = %conn.dst_ip, "reject response");
            }
            Err(e) => trace!("reject: unparseable packet ({e}); dropping only"),
        }
    }

    fn send_verdict(&mut self, mut msg: Q::Msg, verdict: NfqVerdict) {
        msg.set_verdict(verdict);
        if let Err(e) = self.queue.verdict(msg) {
            warn!("setting NFQUEUE verdict failed: {e}");
        }
    }
}

/// Process attribution seam so [`handle_packet`] is testable without a
/// live /proc.
trait ProcessResolver {
    fn pid_for_socket(
        &self,
        protocol: Protocol,
        direction: Direction,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<u32>;
    fn resolve(&self, pid: u32) -> Process;
}

/// Production resolver backed by /proc.
struct ProcfsResolver;

impl ProcessResolver for ProcfsResolver {
    fn pid_for_socket(
        &self,
        protocol: Protocol,
        direction: Direction,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<u32> {
        process_resolve::pid_for_socket(protocol, direction, src_ip, src_port, dst_ip, dst_port)
    }

    fn resolve(&self, pid: u32) -> Process {
        process_resolve::resolve(pid)
    }
}

/// Reverse-DNS / self-identification seam, backed by [`DnsCache`] in
/// production.
trait HostCache {
    fn is_self(&self, pid: u32) -> bool;
    fn cached_host(&self, ip: IpAddr) -> Option<String>;
    fn enqueue(&self, ip: IpAddr);
}

impl HostCache for DnsCache {
    fn is_self(&self, pid: u32) -> bool {
        DnsCache::is_self(self, pid)
    }

    fn cached_host(&self, ip: IpAddr) -> Option<String> {
        self.lookup_cached(ip)
    }

    fn enqueue(&self, ip: IpAddr) {
        self.enqueue_lookup(ip)
    }
}

/// Kernel-provided metadata accompanying a queued packet.
#[derive(Debug, Clone, Copy)]
struct PacketMeta {
    /// Socket owner from NFQA_UID; authoritative when present.
    uid: Option<u32>,
    /// Socket group from NFQA_GID; authoritative when present.
    gid: Option<u32>,
    /// Which way this packet is going, from the netfilter hook.
    direction: Direction,
}

/// Environment for [`handle_packet`].
struct PipelineDeps<'a> {
    engine: &'a Engine,
    stats: &'a Stats,
    dns: &'a dyn HostCache,
    resolver: &'a dyn ProcessResolver,
}

/// Outcome of the pure per-packet decision pipeline.
#[derive(Debug)]
enum PacketOutcome {
    /// Immediate verdict with nothing to observe (self traffic, packets we
    /// can't parse). Not counted in stats.
    Silent(NfqVerdict),
    /// Immediate verdict, already recorded in stats; the caller publishes
    /// the observation.
    Deliver {
        connection: Connection,
        process: Process,
        verdict: Verdict,
    },
    /// No rule matched and prompting is enabled: ask the user, applying
    /// `fallback` if no prompt can be delivered. Stats are recorded when
    /// the prompt resolves.
    Prompt {
        connection: Connection,
        process: Process,
        fallback: Verdict,
    },
}

/// Pure per-packet decision pipeline: parse -> self-DNS bypass -> process
/// attribution -> hostname attach -> rule evaluation -> outcome. No queue
/// I/O and no channel sends; the worker loop translates the outcome.
fn handle_packet(payload: &[u8], meta: &PacketMeta, deps: &PipelineDeps) -> PacketOutcome {
    let mut conn = match packet::parse(payload, meta.direction) {
        Ok(c) => c,
        Err(e) => {
            // An unparseable packet can't be attributed or matched against
            // rules, and there is nothing meaningful to prompt about;
            // apply the configured default policy instead of blindly
            // accepting.
            debug!("unparseable packet: {e}; applying default policy");
            return PacketOutcome::Silent(nfq_verdict_for(deps.engine.fallback_verdict().action));
        }
    };

    // Inbound is not asked, rather than asked and told nothing.
    //
    // `pid_for_socket` searches for a socket already holding this 4-tuple.
    // An inbound SYN has none - nothing has accepted it yet - so the search
    // could only ever miss, and missing meant reading /proc/net/tcp and
    // /proc/net/tcp6: 2.40 ms per packet for an answer of `None`.
    //
    // The resolver refuses inbound too. Two locks for one hole, because this
    // one is silent: the verdict is identical either way, so nothing would
    // have failed - the firewall would just be fourteen times slower on the
    // inbound side and say nothing about it.
    let pid_hint = if conn.direction == Direction::Inbound {
        None
    } else {
        deps.resolver.pid_for_socket(
            conn.protocol,
            conn.direction,
            conn.src_ip,
            conn.src_port,
            conn.dst_ip,
            conn.dst_port,
        )
    };

    // Always allow our own traffic. Otherwise the daemon's reverse DNS
    // resolver would itself be intercepted, deadlocking on a verdict
    // we can't produce until the resolver returns.
    if let Some(pid) = pid_hint {
        if deps.dns.is_self(pid) {
            return PacketOutcome::Silent(NfqVerdict::Accept);
        }
    }

    let mut proc = match pid_hint {
        Some(pid) => deps.resolver.resolve(pid),
        None => Process::unknown(0),
    };
    // The kernel-reported socket uid/gid come from the sk_buff itself and
    // are authoritative; they override anything the racy /proc walk found
    // (or failed to find).
    if let Some(uid) = meta.uid {
        proc.uid = Some(uid);
    }
    if let Some(gid) = meta.gid {
        proc.gid = Some(gid);
    }

    if let Some(pid) = pid_hint {
        // proc.uid is None when attribution failed entirely; keep it None
        // on the connection too instead of fabricating uid 0.
        conn = conn.with_process(pid, proc.uid);
    } else {
        // No pid, but the kernel may still have told us the uid.
        conn.uid = proc.uid;
    }

    // Attach cached hostname if any, kick off a fresh lookup for next time.
    if let Some(host) = deps.dns.cached_host(conn.dst_ip) {
        conn = conn.with_host(host);
    }
    deps.dns.enqueue(conn.dst_ip);

    match deps.engine.evaluate(&conn, &proc) {
        Decision::Resolved(verdict) => {
            record(deps.stats, verdict.action);
            PacketOutcome::Deliver {
                connection: conn,
                process: proc,
                verdict,
            }
        }
        Decision::NeedsPrompt { fallback } => {
            // Inbound never asks.
            //
            // The decision the owner took, and it is not a shortcut: nothing
            // comes in without having been authorised, and authorising happens
            // by writing a rule, not by answering a bubble. A prompt per
            // inbound SYN would be a denial of service on the user's attention
            // - an exposed machine is scanned continuously, and the traffic is
            // not caused by anything they did - and prompt fatigue is already
            // in this project's own threat model as a way it gets defeated.
            //
            // `pause` deliberately does not lift this either: pause means
            // "stop asking me", and there is nothing here to ask.
            if conn.direction == Direction::Inbound {
                let verdict = Verdict::from_policy(deps.engine.inbound_default());
                debug!(
                    src = %conn.src_ip,
                    port = conn.dst_port,
                    action = ?verdict.action,
                    "inbound flow matched no rule; applying the inbound default"
                );
                record(deps.stats, verdict.action);
                return PacketOutcome::Deliver {
                    connection: conn,
                    process: proc,
                    verdict,
                };
            }
            if deps.stats.is_paused() {
                // Paused means "stop prompting", not "stop filtering":
                // rules above still applied; only unmatched flows pass
                // without a prompt.
                debug!(dst = %conn.dst_ip, "paused: allowing unmatched flow without prompting");
                let verdict = Verdict::default_allow();
                record(deps.stats, verdict.action);
                return PacketOutcome::Deliver {
                    connection: conn,
                    process: proc,
                    verdict,
                };
            }
            PacketOutcome::Prompt {
                connection: conn,
                process: proc,
                fallback,
            }
        }
    }
}

/// Maps a policy action onto the kernel verdict. Reject shares Drop with
/// Deny: the difference is the refusal [`Worker::apply_action`] injects
/// alongside it, not the verdict itself.
fn nfq_verdict_for(action: Action) -> NfqVerdict {
    match action {
        Action::Allow => NfqVerdict::Accept,
        Action::Deny | Action::Reject => NfqVerdict::Drop,
    }
}

fn record(stats: &Stats, action: Action) {
    match action {
        Action::Allow => stats.record_allow(),
        Action::Deny | Action::Reject => stats.record_deny(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultPolicy;
    use cfc_core::{Rule, RuleScope, RuleSet};
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use std::time::Instant;

    const IPPROTO_TCP: u8 = 6;

    /// Minimal IPv4/TCP packet: 1.2.3.4:5555 -> 5.6.7.8:`dst_port`.
    fn tcp_packet(dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = IPPROTO_TCP;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[20..22].copy_from_slice(&5555u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    fn dp_allow() -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: Action::Allow,
            timeout_action: Action::Allow,
            inbound_action: Action::Deny,
            prompt_timeout_secs: 15,
        }
    }

    fn dp_deny() -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: Action::Deny,
            timeout_action: Action::Deny,
            inbound_action: Action::Deny,
            prompt_timeout_secs: 10,
        }
    }

    fn allow_port_rule(port: u16) -> Rule {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(port);
        Rule::new(format!("allow-{port}"), Action::Allow, scope)
    }

    fn deny_port_rule(port: u16) -> Rule {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(port);
        Rule::new(format!("deny-{port}"), Action::Deny, scope)
    }

    fn test_process(pid: u32, exe: &str) -> Process {
        Process {
            ppid: Some(1),
            uid: Some(1000),
            gid: Some(1000),
            exe: PathBuf::from(exe),
            cmdline: vec![exe.to_string()],
            ..Process::unknown(pid)
        }
    }

    struct StubResolver {
        pid: Option<u32>,
        process: Process,
        /// How many times the packet path asked for socket attribution.
        ///
        /// Counted because "did not call it" is the property worth pinning on
        /// the inbound path: the real resolver's answer there was always
        /// `None`, so a regression would not change any verdict - it would
        /// just silently cost 2.4 ms a packet again.
        socket_lookups: std::sync::atomic::AtomicUsize,
    }

    impl ProcessResolver for StubResolver {
        fn pid_for_socket(
            &self,
            _protocol: Protocol,
            _direction: Direction,
            _src_ip: IpAddr,
            _src_port: u16,
            _dst_ip: IpAddr,
            _dst_port: u16,
        ) -> Option<u32> {
            self.socket_lookups
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.pid
        }

        fn resolve(&self, _pid: u32) -> Process {
            self.process.clone()
        }
    }

    struct StubDns {
        self_pid: Option<u32>,
        host: Option<String>,
    }

    impl HostCache for StubDns {
        fn is_self(&self, pid: u32) -> bool {
            self.self_pid == Some(pid)
        }

        fn cached_host(&self, _ip: IpAddr) -> Option<String> {
            self.host.clone()
        }

        fn enqueue(&self, _ip: IpAddr) {}
    }

    const NO_META: PacketMeta = PacketMeta {
        uid: None,
        gid: None,
        direction: Direction::Outbound,
    };

    /// The same, for a packet the kernel queued from the input hook.
    const INBOUND_META: PacketMeta = PacketMeta {
        uid: None,
        gid: None,
        direction: Direction::Inbound,
    };

    struct TestEnv {
        engine: Engine,
        stats: Stats,
        dns: StubDns,
        resolver: StubResolver,
    }

    impl TestEnv {
        fn new(rules: Vec<Rule>, policy: DefaultPolicy) -> Self {
            Self {
                engine: Engine::new(RuleSet { rules }, Arc::new(std::sync::RwLock::new(policy))),
                stats: Stats::new(),
                dns: StubDns {
                    self_pid: None,
                    host: None,
                },
                resolver: StubResolver {
                    pid: Some(4242),
                    process: test_process(4242, "/usr/bin/curl"),
                    socket_lookups: std::sync::atomic::AtomicUsize::new(0),
                },
            }
        }

        fn handle(&self, payload: &[u8], meta: &PacketMeta) -> PacketOutcome {
            let deps = PipelineDeps {
                engine: &self.engine,
                stats: &self.stats,
                dns: &self.dns,
                resolver: &self.resolver,
            };
            handle_packet(payload, meta, &deps)
        }
    }

    // ---- Inbound ----
    //
    // The property the owner asked for, in the words they used: nothing comes
    // in without having been authorised. These pin the three ways that could
    // silently stop being true.

    /// An inbound flow must not pay for socket attribution.
    ///
    /// Every step of `pid_for_socket` looks for a socket whose 4-tuple is
    /// already this flow. For an inbound SYN no such socket exists - nothing
    /// has accepted it - so the search always missed, and missing cost a read
    /// of /proc/net/tcp and /proc/net/tcp6: 2.40 ms per packet, measured.
    /// Inbound connect latency was 2.78 ms median against 0.28 ms outbound
    /// over the same link; skipping the search takes it to 0.19 ms.
    ///
    /// The verdict is unaffected either way, which is exactly why this needs a
    /// test: a regression here changes no behaviour at all, it just makes the
    /// firewall fourteen times slower on one side and says nothing.
    #[test]
    fn an_inbound_flow_does_not_pay_for_socket_attribution() {
        let env = TestEnv::new(vec![], dp_deny());
        env.handle(&tcp_packet(22), &INBOUND_META);
        assert_eq!(
            env.resolver
                .socket_lookups
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the inbound path asked for socket attribution that cannot succeed"
        );
    }

    /// ...and the outbound path still does, because there it works.
    #[test]
    fn an_outbound_flow_still_resolves_its_process() {
        let env = TestEnv::new(vec![], dp_deny());
        env.handle(&tcp_packet(443), &NO_META);
        assert_eq!(
            env.resolver
                .socket_lookups
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// Only `LOCAL_OUT` is outbound. An unexpected hook must land on the
    /// inbound side, because that is the side that cannot end in Allow.
    #[test]
    fn an_unexpected_hook_is_treated_as_inbound_not_outbound() {
        assert_eq!(direction_for_hook(NF_INET_LOCAL_OUT), Direction::Outbound);
        assert_eq!(direction_for_hook(NF_INET_LOCAL_IN), Direction::Inbound);
        // NF_INET_FORWARD. Someone hand-added a `forward` rule; routed traffic
        // must not inherit the path that can prompt and can be allowed.
        assert_eq!(direction_for_hook(2), Direction::Inbound);
    }

    /// The load-bearing one. `dp_allow()` has `no_ui_action: Allow`, so a
    /// pipeline that fell through to the ordinary no-UI fallback would accept
    /// this packet. It must take `inbound_action` instead.
    #[test]
    fn an_unmatched_inbound_flow_is_denied_even_when_no_ui_action_is_allow() {
        let env = TestEnv::new(vec![], dp_allow());
        match env.handle(&tcp_packet(22), &INBOUND_META) {
            PacketOutcome::Deliver { verdict, .. } => {
                assert_eq!(verdict.action, Action::Deny);
            }
            other => panic!("inbound must never prompt or accept by default, got {other:?}"),
        }
    }

    /// ...and it is genuinely `inbound_action` being read, not a Deny constant
    /// that happens to agree with it.
    #[test]
    fn the_inbound_default_is_the_configured_one() {
        let policy = DefaultPolicy {
            no_ui_action: Action::Allow,
            timeout_action: Action::Allow,
            inbound_action: Action::Reject,
            prompt_timeout_secs: 15,
        };
        let env = TestEnv::new(vec![], policy);
        match env.handle(&tcp_packet(22), &INBOUND_META) {
            PacketOutcome::Deliver { verdict, .. } => {
                assert_eq!(verdict.action, Action::Reject);
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    /// Authorising is what rules are for: an inbound rule admits the flow.
    #[test]
    fn an_inbound_rule_admits_an_inbound_flow() {
        let mut scope = RuleScope::any();
        scope.direction = Some(Direction::Inbound);
        scope.dst_port = Some(22);
        scope.src_net = Some("1.2.3.0/24".parse().unwrap());
        let rule = Rule::new("ssh-in".to_string(), Action::Allow, scope);

        // tcp_packet() sources from 1.2.3.4, inside the rule's src_net.
        match TestEnv::new(vec![rule], dp_deny()).handle(&tcp_packet(22), &INBOUND_META) {
            PacketOutcome::Deliver { verdict, .. } => {
                assert_eq!(verdict.action, Action::Allow);
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    /// The direction predicate has to bite in both directions, or every
    /// pre-existing outbound rule silently becomes an inbound hole the day
    /// the input chain is enabled. `allow_port_rule` leaves direction unset -
    /// the shape every rule had before this feature - so this also pins that
    /// "unset" does not mean "inbound too" for a port that matches.
    #[test]
    fn an_outbound_only_rule_does_not_admit_the_same_port_inbound() {
        let mut scope = RuleScope::any();
        scope.direction = Some(Direction::Outbound);
        scope.dst_port = Some(22);
        let rule = Rule::new("ssh-out".to_string(), Action::Allow, scope);

        match TestEnv::new(vec![rule], dp_deny()).handle(&tcp_packet(22), &INBOUND_META) {
            PacketOutcome::Deliver { verdict, .. } => {
                assert_eq!(verdict.action, Action::Deny, "outbound rule leaked inbound");
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    /// The src_net predicate is the only thing standing between "ssh from the
    /// LAN" and "ssh from anywhere", so a miss must not fall through to allow.
    #[test]
    fn an_inbound_rule_does_not_admit_a_peer_outside_its_src_net() {
        let mut scope = RuleScope::any();
        scope.direction = Some(Direction::Inbound);
        scope.dst_port = Some(22);
        scope.src_net = Some("192.168.0.0/16".parse().unwrap());
        let rule = Rule::new("ssh-lan".to_string(), Action::Allow, scope);

        // The packet comes from 1.2.3.4, which is not in 192.168.0.0/16.
        match TestEnv::new(vec![rule], dp_deny()).handle(&tcp_packet(22), &INBOUND_META) {
            PacketOutcome::Deliver { verdict, .. } => {
                assert_eq!(verdict.action, Action::Deny);
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    #[test]
    fn rule_hit_allow_delivers_allow() {
        let env = TestEnv::new(vec![allow_port_rule(443)], dp_deny());
        match env.handle(&tcp_packet(443), &NO_META) {
            PacketOutcome::Deliver {
                connection,
                verdict,
                ..
            } => {
                assert_eq!(verdict.action, Action::Allow);
                assert_eq!(connection.dst_port, 443);
                assert_eq!(connection.pid, Some(4242));
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
        assert_eq!(env.stats.connections_allowed(), 1);
        assert_eq!(env.stats.connections_denied(), 0);
    }

    #[test]
    fn rule_hit_deny_delivers_deny() {
        let env = TestEnv::new(vec![deny_port_rule(443)], dp_allow());
        match env.handle(&tcp_packet(443), &NO_META) {
            PacketOutcome::Deliver { verdict, .. } => {
                assert_eq!(verdict.action, Action::Deny);
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
        assert_eq!(env.stats.connections_denied(), 1);
    }

    #[test]
    fn no_rule_returns_prompt_with_policy_fallback() {
        let env = TestEnv::new(vec![], dp_deny());
        match env.handle(&tcp_packet(443), &NO_META) {
            PacketOutcome::Prompt {
                connection,
                process,
                fallback,
            } => {
                assert_eq!(fallback.action, Action::Deny);
                assert_eq!(connection.pid, Some(4242));
                assert_eq!(process.exe, PathBuf::from("/usr/bin/curl"));
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
        // Nothing recorded until the prompt resolves.
        assert_eq!(env.stats.connections_total(), 0);
    }

    #[test]
    fn paused_deny_rule_still_denied() {
        let env = TestEnv::new(vec![deny_port_rule(443)], dp_allow());
        env.stats.set_paused(true);
        match env.handle(&tcp_packet(443), &NO_META) {
            PacketOutcome::Deliver { verdict, .. } => {
                assert_eq!(verdict.action, Action::Deny);
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
        assert_eq!(env.stats.connections_denied(), 1);
    }

    #[test]
    fn paused_unknown_flow_allowed_without_prompt() {
        let env = TestEnv::new(vec![], dp_deny());
        env.stats.set_paused(true);
        match env.handle(&tcp_packet(443), &NO_META) {
            PacketOutcome::Deliver { verdict, .. } => {
                assert_eq!(verdict.action, Action::Allow);
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
        assert_eq!(env.stats.connections_allowed(), 1);
    }

    #[test]
    fn malformed_packet_applies_default_policy() {
        // Truncated IPv4 header.
        let env = TestEnv::new(vec![], dp_allow());
        assert!(matches!(
            env.handle(&[0x45, 0, 0], &NO_META),
            PacketOutcome::Silent(NfqVerdict::Accept)
        ));

        let env = TestEnv::new(vec![], dp_deny());
        assert!(matches!(
            env.handle(&[0x45, 0, 0], &NO_META),
            PacketOutcome::Silent(NfqVerdict::Drop)
        ));
        // Unknown IP version too.
        assert!(matches!(
            env.handle(&[0x90, 0, 0, 0], &NO_META),
            PacketOutcome::Silent(NfqVerdict::Drop)
        ));
        // Unattributable garbage is not counted as a connection.
        assert_eq!(env.stats.connections_total(), 0);
    }

    #[test]
    fn self_dns_bypass_accepts_silently() {
        // Even with a deny rule that would match, the daemon's own traffic
        // must pass or the reverse resolver deadlocks.
        let mut env = TestEnv::new(vec![deny_port_rule(53)], dp_deny());
        env.dns.self_pid = Some(4242);
        assert!(matches!(
            env.handle(&tcp_packet(53), &NO_META),
            PacketOutcome::Silent(NfqVerdict::Accept)
        ));
        assert_eq!(env.stats.connections_total(), 0);
    }

    #[test]
    fn kernel_uid_gid_overrides_proc_values() {
        let env = TestEnv::new(vec![], dp_allow());
        let meta = PacketMeta {
            uid: Some(0),
            gid: Some(0),
            direction: Direction::Outbound,
        };
        match env.handle(&tcp_packet(443), &meta) {
            PacketOutcome::Prompt {
                connection,
                process,
                ..
            } => {
                // /proc said 1000/1000; the kernel's 0/0 wins.
                assert_eq!(process.uid, Some(0));
                assert_eq!(process.gid, Some(0));
                assert_eq!(connection.uid, Some(0));
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn kernel_uid_attached_even_without_pid() {
        let mut env = TestEnv::new(vec![], dp_allow());
        env.resolver.pid = None;
        let meta = PacketMeta {
            uid: Some(1000),
            gid: None,
            direction: Direction::Outbound,
        };
        match env.handle(&tcp_packet(443), &meta) {
            PacketOutcome::Prompt {
                connection,
                process,
                ..
            } => {
                assert_eq!(connection.pid, None);
                assert_eq!(connection.uid, Some(1000));
                assert_eq!(process.uid, Some(1000));
                assert_eq!(process.gid, None);
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    #[test]
    fn cached_hostname_attached() {
        let mut env = TestEnv::new(vec![], dp_allow());
        env.dns.host = Some("example.org".into());
        match env.handle(&tcp_packet(443), &NO_META) {
            PacketOutcome::Prompt { connection, .. } => {
                assert_eq!(connection.dst_host.as_deref(), Some("example.org"));
            }
            other => panic!("expected Prompt, got {other:?}"),
        }
    }

    // ---- FlowKey dedup ----

    fn conn_to(dst_port: u16, src_port: u16) -> Connection {
        Connection::new(
            Protocol::Tcp,
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            src_port,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_port,
        )
    }

    #[test]
    fn flow_key_dedups_retransmits_and_parallel_connections() {
        let proc = test_process(100, "/usr/bin/curl");
        // Same flow, different Connection instances (fresh uuid/timestamp).
        assert_eq!(
            FlowKey::for_flow(&conn_to(443, 1111), &proc),
            FlowKey::for_flow(&conn_to(443, 1111), &proc)
        );
        // Parallel connection: different source port, same key.
        assert_eq!(
            FlowKey::for_flow(&conn_to(443, 1111), &proc),
            FlowKey::for_flow(&conn_to(443, 2222), &proc)
        );
        // Different destination port: different key.
        assert_ne!(
            FlowKey::for_flow(&conn_to(443, 1111), &proc),
            FlowKey::for_flow(&conn_to(80, 1111), &proc)
        );
    }

    #[test]
    fn flow_key_uses_exe_when_known_else_pid() {
        let conn = conn_to(443, 1111);
        // Same app, different pids: one prompt.
        assert_eq!(
            FlowKey::for_flow(&conn, &test_process(1, "/usr/bin/curl")),
            FlowKey::for_flow(&conn, &test_process(2, "/usr/bin/curl"))
        );
        // Different apps: separate prompts.
        assert_ne!(
            FlowKey::for_flow(&conn, &test_process(1, "/usr/bin/curl")),
            FlowKey::for_flow(&conn, &test_process(1, "/usr/bin/wget"))
        );
        // Unattributed processes fall back to the pid.
        assert_eq!(
            FlowKey::for_flow(&conn, &Process::unknown(7)),
            FlowKey::for_flow(&conn, &Process::unknown(7))
        );
        assert_ne!(
            FlowKey::for_flow(&conn, &Process::unknown(7)),
            FlowKey::for_flow(&conn, &Process::unknown(8))
        );
    }

    // ---- Worker loop, driven through the PacketQueue seam ----
    //
    // These exercise the parts the pure pipeline tests above cannot reach:
    // the recv loop itself, the prompt-dedup state machine, the recv error
    // budget, the verdict back-channel and shutdown. No root, no NFQUEUE,
    // no /proc and no DNS -- the queue, the process resolver and the host
    // cache are all stubs.

    /// A packet from [`FakeQueue`]: an owned payload plus a slot for the
    /// verdict the worker sets on it.
    #[derive(Debug, Clone)]
    struct FakeMsg {
        id: u32,
        payload: Vec<u8>,
        uid: Option<u32>,
        gid: Option<u32>,
        hook: u8,
        verdict: Option<NfqVerdict>,
    }

    impl FakeMsg {
        fn new(id: u32, payload: Vec<u8>) -> Self {
            Self {
                id,
                payload,
                uid: None,
                gid: None,
                hook: NF_INET_LOCAL_OUT,
                verdict: None,
            }
        }
    }

    impl PacketMessage for FakeMsg {
        fn hook(&self) -> u8 {
            self.hook
        }

        fn payload(&self) -> &[u8] {
            &self.payload
        }

        fn uid(&self) -> Option<u32> {
            self.uid
        }

        fn gid(&self) -> Option<u32> {
            self.gid
        }

        fn set_verdict(&mut self, verdict: NfqVerdict) {
            self.verdict = Some(verdict);
        }
    }

    /// Everything the tests want to know about what the worker did to the
    /// queue. The worker consumes the queue by value, so this lives behind
    /// an `Arc` the harness keeps a handle to.
    #[derive(Default)]
    struct QueueLog {
        /// (packet id, verdict), in the order the worker verdicted them.
        verdicts: Vec<(u32, NfqVerdict)>,
        /// Every `set_nonblocking` argument, in order.
        modes: Vec<bool>,
        /// recv calls, so a test can tell a turning loop from a stuck one.
        recv_calls: u64,
    }

    struct FakeQueue {
        /// Scripted recv results, consumed front to back. Once exhausted
        /// every recv reports WouldBlock, exactly like an idle queue.
        script: VecDeque<std::io::Result<FakeMsg>>,
        log: Arc<Mutex<QueueLog>>,
    }

    impl PacketQueue for FakeQueue {
        type Msg = FakeMsg;

        fn set_nonblocking(&mut self, nonblocking: bool) {
            self.log.lock().unwrap().modes.push(nonblocking);
        }

        fn recv(&mut self) -> std::io::Result<FakeMsg> {
            self.log.lock().unwrap().recv_calls += 1;
            self.script
                .pop_front()
                .unwrap_or_else(|| Err(std::io::ErrorKind::WouldBlock.into()))
        }

        fn verdict(&mut self, msg: FakeMsg) -> std::io::Result<()> {
            let verdict = msg.verdict.expect("worker verdicted without a verdict");
            self.log.lock().unwrap().verdicts.push((msg.id, verdict));
            Ok(())
        }
    }

    /// Fast loop timings: no test should pay a real 250 ms error backoff or
    /// wait out a hundred-deep error budget.
    fn test_tuning() -> Tuning {
        Tuning {
            poll_interval: Duration::from_millis(1),
            error_backoff: Duration::ZERO,
            max_consecutive_recv_errors: 3,
        }
    }

    fn recv_error() -> std::io::Error {
        std::io::Error::from_raw_os_error(libc::ENOSPC)
    }

    /// A [`Worker`] over a scripted queue, plus every channel end and log a
    /// test needs to observe it.
    struct LoopHarness {
        worker: Option<Worker<FakeQueue>>,
        log: Arc<Mutex<QueueLog>>,
        stop: Arc<AtomicBool>,
        stats: Stats,
        /// `Option` so a test can hang up on the worker by dropping it.
        verdict_tx: Option<VerdictTx>,
        prompt_rx: mpsc::Receiver<PromptRequest>,
        observed_rx: broadcast::Receiver<ObservedConnection>,
    }

    impl LoopHarness {
        fn new(
            script: Vec<std::io::Result<FakeMsg>>,
            rules: Vec<Rule>,
            policy: DefaultPolicy,
        ) -> Self {
            let log = Arc::new(Mutex::new(QueueLog::default()));
            let (prompt_tx, prompt_rx) = mpsc::channel(16);
            let (verdict_tx, verdict_rx) = std::sync::mpsc::channel();
            let (observed_tx, observed_rx) = broadcast::channel(16);
            let stats = Stats::new();
            let stop = Arc::new(AtomicBool::new(false));
            let worker = Worker {
                queue: FakeQueue {
                    script: script.into(),
                    log: log.clone(),
                },
                engine: Engine::new(RuleSet { rules }, Arc::new(std::sync::RwLock::new(policy))),
                rejecter: Rejecter::open(),
                prompt_tx,
                verdict_rx,
                observed_tx,
                stats: stats.clone(),
                dns: Box::new(StubDns {
                    self_pid: None,
                    host: None,
                }),
                resolver: Box::new(StubResolver {
                    pid: Some(4242),
                    process: test_process(4242, "/usr/bin/curl"),
                    socket_lookups: std::sync::atomic::AtomicUsize::new(0),
                }),
                waiters: HashMap::new(),
                pending_flows: HashMap::new(),
                next_prompt_id: 1,
                verdict_channel_open: true,
                tuning: test_tuning(),
                stop: stop.clone(),
                last_activity: Arc::new(AtomicI64::new(unix_ms())),
            };
            Self {
                worker: Some(worker),
                log,
                stop,
                stats,
                verdict_tx: Some(verdict_tx),
                prompt_rx,
                observed_rx,
            }
        }

        fn with_tuning(mut self, tuning: Tuning) -> Self {
            self.worker().tuning = tuning;
            self
        }

        /// The not-yet-started worker, for tests that drive one method
        /// instead of the whole loop.
        fn worker(&mut self) -> &mut Worker<FakeQueue> {
            self.worker.as_mut().expect("worker already started")
        }

        /// Runs the loop on its own thread. The returned channel yields the
        /// loop's result, which lets tests put a *bound* on shutdown
        /// instead of blocking forever in `JoinHandle::join`.
        fn start(&mut self) -> Receiver<anyhow::Result<()>> {
            let worker = self.worker.take().expect("worker already started");
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = done_tx.send(worker.run());
            });
            done_rx
        }

        fn verdicts(&self) -> Vec<(u32, NfqVerdict)> {
            self.log.lock().unwrap().verdicts.clone()
        }

        fn modes(&self) -> Vec<bool> {
            self.log.lock().unwrap().modes.clone()
        }

        fn recv_calls(&self) -> u64 {
            self.log.lock().unwrap().recv_calls
        }

        fn send_verdict(&self, prompt_id: u64, verdict: Verdict) {
            self.verdict_tx
                .as_ref()
                .expect("verdict channel dropped")
                .send(PromptVerdict { prompt_id, verdict })
                .expect("worker still listening");
        }

        /// Asks the loop to stop and asserts it does so promptly. The
        /// timeout is generous on purpose: the point is "bounded", not "in
        /// exactly N ms", so a loaded machine can't make this flake.
        fn stop_and_expect_ok(&self, done: &Receiver<anyhow::Result<()>>) {
            self.stop.store(true, Ordering::Relaxed);
            let result = done
                .recv_timeout(Duration::from_secs(5))
                .expect("worker left its loop after the stop flag was set");
            result.expect("a requested stop is not an error");
        }
    }

    /// Polls until `cond` holds. Returns whether it ever did.
    fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    /// Waits for the worker to dispatch a prompt.
    fn next_prompt(rx: &mut mpsc::Receiver<PromptRequest>) -> Option<PromptRequest> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(req) = rx.try_recv() {
                return Some(req);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        None
    }

    #[test]
    fn loop_drives_a_rule_hit_packet_to_a_verdict() {
        let mut h = LoopHarness::new(
            vec![Ok(FakeMsg::new(7, tcp_packet(443)))],
            vec![allow_port_rule(443)],
            dp_deny(),
        );
        let done = h.start();

        assert!(wait_until(|| h.verdicts().len() == 1), "packet verdicted");
        assert_eq!(h.verdicts(), vec![(7, NfqVerdict::Accept)]);
        assert_eq!(h.stats.connections_allowed(), 1);

        let observed = h.observed_rx.try_recv().expect("observation published");
        assert_eq!(observed.verdict.action, Action::Allow);

        h.stop_and_expect_ok(&done);
    }

    #[test]
    fn loop_parks_a_prompt_and_releases_it_on_the_verdict() {
        let mut h = LoopHarness::new(
            vec![Ok(FakeMsg::new(7, tcp_packet(443)))],
            vec![],
            dp_deny(),
        );
        let done = h.start();

        let req = next_prompt(&mut h.prompt_rx).expect("prompt dispatched");
        assert_eq!(req.connection.dst_port, 443);
        // Parked, not verdicted: the datapath keeps running around it.
        assert!(h.verdicts().is_empty());
        assert_eq!(h.stats.connections_total(), 0);

        h.send_verdict(req.prompt_id, Verdict::default_allow());

        assert!(
            wait_until(|| h.verdicts().len() == 1),
            "parked packet freed"
        );
        assert_eq!(h.verdicts(), vec![(7, NfqVerdict::Accept)]);
        assert_eq!(h.stats.connections_allowed(), 1);
        let observed = h.observed_rx.try_recv().expect("observation published");
        assert_eq!(observed.verdict.action, Action::Allow);

        h.stop_and_expect_ok(&done);
    }

    #[test]
    fn two_packets_of_one_flow_share_a_prompt_and_both_get_verdicted() {
        let mut h = LoopHarness::new(
            vec![
                Ok(FakeMsg::new(1, tcp_packet(443))),
                Ok(FakeMsg::new(2, tcp_packet(443))),
            ],
            vec![],
            dp_deny(),
        );
        let done = h.start();

        let req = next_prompt(&mut h.prompt_rx).expect("prompt dispatched");
        // Both scripted packets consumed, plus at least one WouldBlock.
        assert!(wait_until(|| h.recv_calls() >= 3), "both packets consumed");
        assert!(
            h.prompt_rx.try_recv().is_err(),
            "the second packet rode the outstanding prompt"
        );

        h.send_verdict(req.prompt_id, Verdict::default_deny());

        assert!(wait_until(|| h.verdicts().len() == 2), "both packets freed");
        let mut got = h.verdicts();
        got.sort_by_key(|(id, _)| *id);
        assert_eq!(got, vec![(1, NfqVerdict::Drop), (2, NfqVerdict::Drop)]);
        // One prompt is one logical connection, counted once.
        assert_eq!(h.stats.connections_denied(), 1);

        h.stop_and_expect_ok(&done);
    }

    #[test]
    fn distinct_flows_get_distinct_prompts() {
        let mut h = LoopHarness::new(
            vec![
                Ok(FakeMsg::new(1, tcp_packet(443))),
                Ok(FakeMsg::new(2, tcp_packet(8443))),
            ],
            vec![],
            dp_deny(),
        );
        let done = h.start();

        let a = next_prompt(&mut h.prompt_rx).expect("first prompt");
        let b = next_prompt(&mut h.prompt_rx).expect("second prompt");
        assert_ne!(a.prompt_id, b.prompt_id);

        // Resolving one releases only its own packet.
        h.send_verdict(a.prompt_id, Verdict::default_allow());
        assert!(wait_until(|| h.verdicts().len() == 1), "one packet freed");
        assert_eq!(h.verdicts(), vec![(1, NfqVerdict::Accept)]);

        h.send_verdict(b.prompt_id, Verdict::default_deny());
        assert!(wait_until(|| h.verdicts().len() == 2), "other packet freed");
        assert_eq!(h.verdicts()[1], (2, NfqVerdict::Drop));

        h.stop_and_expect_ok(&done);
    }

    #[test]
    fn queue_is_put_in_nonblocking_mode_once_and_stays_there() {
        // The pre-shutdown design toggled the socket's recv mode with
        // `waiters` emptiness; it is now nonblocking for the worker's whole
        // life so that no iteration can park past the stop flag. See the
        // module docs.
        let mut h = LoopHarness::new(
            vec![Ok(FakeMsg::new(1, tcp_packet(443)))],
            vec![],
            dp_deny(),
        );
        let done = h.start();

        // Run through both states: a prompt outstanding, then resolved.
        let req = next_prompt(&mut h.prompt_rx).expect("prompt dispatched");
        h.send_verdict(req.prompt_id, Verdict::default_allow());
        assert!(wait_until(|| h.verdicts().len() == 1), "prompt resolved");
        let calls = h.recv_calls();
        assert!(
            wait_until(|| h.recv_calls() > calls + 2),
            "loop still turning"
        );

        h.stop_and_expect_ok(&done);
        assert_eq!(h.modes(), vec![true]);
    }

    #[test]
    fn recv_error_budget_gives_up_after_the_limit() {
        let mut h = LoopHarness::new(
            vec![Err(recv_error()), Err(recv_error()), Err(recv_error())],
            vec![],
            dp_deny(),
        );
        let done = h.start();

        let result = done
            .recv_timeout(Duration::from_secs(5))
            .expect("worker returned");
        let err = result.expect_err("budget exhausted");
        assert!(
            format!("{err:#}").contains("3 times in a row"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn recv_error_budget_resets_on_a_successful_recv() {
        // Two errors, a good packet, two more errors: never three in a row,
        // so the worker must still be running.
        let mut h = LoopHarness::new(
            vec![
                Err(recv_error()),
                Err(recv_error()),
                Ok(FakeMsg::new(9, tcp_packet(443))),
                Err(recv_error()),
                Err(recv_error()),
            ],
            vec![allow_port_rule(443)],
            dp_deny(),
        );
        let done = h.start();

        assert!(wait_until(|| h.verdicts().len() == 1), "packet verdicted");
        assert_eq!(h.verdicts(), vec![(9, NfqVerdict::Accept)]);
        assert!(
            done.try_recv().is_err(),
            "worker survived a reset error budget"
        );

        h.stop_and_expect_ok(&done);
    }

    #[test]
    fn idle_wait_consumes_a_verdict_from_the_channel() {
        // The WouldBlock path is where a verdict arriving while the queue
        // is empty gets picked up; drive it directly so the test does not
        // race `drain_verdicts` for the same message.
        let mut h = LoopHarness::new(vec![], vec![], dp_deny());
        h.worker().park_for_prompt(
            FakeMsg::new(4, tcp_packet(443)),
            conn_to(443, 1111),
            test_process(4242, "/usr/bin/curl"),
            Verdict::default_deny(),
        );
        let req = h.prompt_rx.try_recv().expect("prompt dispatched");
        assert!(h.verdicts().is_empty());

        h.send_verdict(req.prompt_id, Verdict::default_allow());
        h.worker().idle_wait();

        assert_eq!(h.verdicts(), vec![(4, NfqVerdict::Accept)]);
        assert!(h.worker().waiters.is_empty());
        assert!(h.worker().pending_flows.is_empty());
    }

    #[test]
    fn verdict_channel_disconnect_applies_fallbacks() {
        let mut h = LoopHarness::new(
            vec![Ok(FakeMsg::new(3, tcp_packet(443)))],
            vec![],
            dp_deny(),
        );
        let done = h.start();

        let _req = next_prompt(&mut h.prompt_rx).expect("prompt dispatched");
        assert!(h.verdicts().is_empty());

        // The router goes away without answering.
        drop(h.verdict_tx.take());

        assert!(wait_until(|| h.verdicts().len() == 1), "fallback applied");
        assert_eq!(h.verdicts(), vec![(3, NfqVerdict::Drop)]);
        assert_eq!(h.stats.connections_denied(), 1);

        h.stop.store(true, Ordering::Relaxed);
        done.recv_timeout(Duration::from_secs(5))
            .expect("worker left its loop")
            .expect("a requested stop is not an error");
    }

    #[test]
    fn idle_wait_paces_itself_once_the_router_has_hung_up() {
        // A disconnected std channel makes `recv_timeout` return
        // instantly, so without the `verdict_channel_open` latch the idle
        // path would spin a core for the rest of the daemon's life.
        let mut h = LoopHarness::new(vec![], vec![], dp_deny()).with_tuning(Tuning {
            poll_interval: Duration::from_millis(30),
            ..test_tuning()
        });
        drop(h.verdict_tx.take());

        // First call notices the hangup...
        h.worker().idle_wait();
        assert!(!h.worker().verdict_channel_open);

        // ...after which the wait is paced by hand.
        let started = Instant::now();
        h.worker().idle_wait();
        assert!(
            started.elapsed() >= Duration::from_millis(20),
            "idle wait returned in {:?}, i.e. it is spinning",
            started.elapsed()
        );
    }

    #[test]
    fn stop_flag_ends_the_loop_while_it_is_idle() {
        // The shutdown regression this guards: an idle worker used to park
        // in a blocking kernel recv forever, so the runtime's blocking pool
        // never shut down and the daemon hung until systemd SIGKILLed it.
        // Production poll interval on purpose -- this asserts the real
        // shutdown bound, not a test-tuned one.
        let mut h = LoopHarness::new(vec![], vec![], dp_deny()).with_tuning(Tuning::default());
        let done = h.start();
        assert!(wait_until(|| h.recv_calls() >= 3), "loop is idling");

        let started = Instant::now();
        h.stop.store(true, Ordering::Relaxed);
        done.recv_timeout(Duration::from_secs(5))
            .expect("idle worker left its loop")
            .expect("a requested stop is not an error");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stop took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn stop_flag_ends_the_loop_with_prompts_outstanding() {
        let mut h = LoopHarness::new(
            vec![Ok(FakeMsg::new(1, tcp_packet(443)))],
            vec![],
            dp_deny(),
        );
        let done = h.start();
        let _req = next_prompt(&mut h.prompt_rx).expect("prompt dispatched");

        let started = Instant::now();
        h.stop_and_expect_ok(&done);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stop took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn stale_pending_flow_entry_reprompts_instead_of_panicking() {
        // The waiters/pending_flows bijection is an invariant, not a
        // guarantee: violating it used to `.expect()` and take the whole
        // datapath thread down with it.
        let mut h = LoopHarness::new(vec![], vec![], dp_deny());
        let conn = conn_to(443, 1111);
        let proc = test_process(4242, "/usr/bin/curl");
        let flow = FlowKey::for_flow(&conn, &proc);
        h.worker().pending_flows.insert(flow.clone(), 99);

        h.worker().park_for_prompt(
            FakeMsg::new(5, tcp_packet(443)),
            conn,
            proc,
            Verdict::default_deny(),
        );

        let req = h.prompt_rx.try_recv().expect("flow re-prompted");
        assert_eq!(req.prompt_id, 1);
        assert_eq!(h.worker().pending_flows.get(&flow), Some(&1));
        assert_eq!(h.worker().waiters.len(), 1);
        assert!(h.verdicts().is_empty(), "the packet is parked, not dropped");
    }
}
