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
//! to the already-outstanding prompt instead of re-prompting -- up to
//! [`MAX_PACKETS_PER_PROMPT`] of them; past that, extra packets take the
//! prompt's fallback verdict rather than a kernel queue slot.
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
//! intercepted flow waits in the kernel queue for the rest of the current
//! beat, and that the idle worker wakes at that cadence.
//!
//! "Mean: half of one interval" is what this comment used to claim, and it
//! is only true of arrivals that are independent of the beat. A client that
//! connects in series is not: each connect lands just after the worker
//! observed an empty queue and committed to a fresh wait, so it pays close
//! to a whole interval, every time. Measured in `scripts/vm-bench` by
//! building this file with the constant at 200 us and running both daemons
//! in one guest - 4.90 ms of 5.67 at 300 flows, 5.24 ms of 7.61 at 3000 -
//! rather than inferred from the shape of a distribution, which is how this
//! path has been misread before.
//!
//! It remains a far better trade than a minute and a half on every restart,
//! and the fast path takes the whole round trip away for a process a lasting
//! rule allows. If `nfq` ever exposes the netlink fd, move the idle wait to
//! a `poll()` on it: that buys back the added latency *and* keeps the
//! bounded stop.

use crate::config::NfqConfig;
use crate::decision::{Decision, Engine};
use crate::dns::DnsCache;
use crate::ipc::EventSink;
use crate::packet;
use crate::process_resolve;
use crate::reject::Rejecter;
use crate::stats::Stats;
use anyhow::Context as _;
use cfc_core::{Action, Connection, Direction, Process, Protocol, Verdict, VerdictSource};
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

/// How many prompts may be waiting for an answer at once.
///
/// Not a UI limit - it is one axis of a residency bound, and it is worth
/// being explicit that it is only one: this caps how many prompts hold
/// packets, [`MAX_PACKETS_PER_PROMPT`] caps how many packets each of them
/// holds. Every parked packet pins the 68 KiB buffer it arrived in *and* a
/// slot in the kernel queue, so the two caps together are worth
/// 512 x 4 = 2048 packets: ~136 MB of worst-case residency inside the
/// packet worker, and half the default 4096-slot queue. Neither cap bounds
/// anything alone - this one sat at 1 while a single chatty flow parked
/// packets without limit, because [`FlowKey`] folds a whole flow onto one
/// prompt.
const MAX_PARKED_PROMPTS: usize = 512;

/// How many packets one prompt may hold parked at once, first one included.
///
/// The scarce resource is not daemon memory but the kernel queue: an
/// enqueued packet keeps one of the `queue_max_len` slots (4096 by default,
/// set at bind time in [`spawn`]) until its verdict, and [`FlowKey`]
/// deliberately folds every packet of a flow onto one prompt. Without this
/// bound, one unanswered prompt over a chatty flow - unreplied UDP is
/// conntrack-NEW on every datagram, so each one is queued - filled the
/// whole queue inside a single prompt timeout, and the kernel then dropped
/// every ct-state-new packet machine-wide, inbound included.
/// [`MAX_PARKED_PROMPTS`] never fired against it: `waiters.len()` sat at 1.
///
/// Four covers what riding exists for - the first packet plus a retransmit
/// or a couple of parallel connections - and it is chosen against the
/// queue: one prompt pins at most 4 of 4096 slots, and even all 512
/// prompts at this cap pin 2048, half the default queue, so parked packets
/// can never starve live ones. Overflow takes the prompt's fallback
/// instead of a slot; a dropped SYN is retransmitted, and the retry lands
/// on whatever the answer produced.
const MAX_PACKETS_PER_PROMPT: usize = 4;

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
    /// A rule that may apply but cannot be decided, because the process
    /// identity is incomplete. See [`Decision::NeedsPrompt`].
    pub undecided: Option<uuid::Uuid>,
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
    /// The rule that could not be decided for this flow, when that is why it
    /// was prompted. See [`Decision::NeedsPrompt`].
    pub undecided: Option<uuid::Uuid>,
}

impl ObservedConnection {
    /// The rule recorded with this flow: the one that answered, or else the
    /// one that could not be decided. A rule id with a source other than
    /// `rule` therefore means "this rule could not be decided".
    pub fn rule_id(&self) -> Option<uuid::Uuid> {
        match self.verdict.source {
            cfc_core::VerdictSource::Rule(id) => Some(id),
            _ => self.undecided,
        }
    }
}

/// Logs a refusal to the journal, then publishes to the bounded, lossy live
/// feed.
pub fn publish_observation(tx: &broadcast::Sender<ObservedConnection>, obs: ObservedConnection) {
    if obs.verdict.action != Action::Allow {
        info!(
            action = ?obs.verdict.action,
            source = crate::convert::verdict_source_db_str(&obs.verdict.source),
            exe = ?obs.process.exe,
            pid = obs.process.pid,
            uid = ?obs.process.uid,
            dst = %format_args!("{}:{}", obs.connection.dst_ip, obs.connection.dst_port),
            undecided_rule = ?obs.undecided,
            "connection blocked"
        );
    }
    let _ = tx.send(obs);
}

fn prompt_session_seed() -> u64 {
    uuid::Uuid::new_v4().as_u128() as u64 & (u64::MAX >> 1)
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
    /// Kernel output interface index; zero means it was not reported.
    fn outdev(&self) -> u32;
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

    fn outdev(&self) -> u32 {
        self.get_outdev()
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
#[allow(clippy::too_many_arguments)] // shared daemon handles; no new runtime wrapper
pub fn spawn(
    cfg: &NfqConfig,
    engine: Engine,
    prompt_tx: PromptTx,
    verdict_rx: VerdictRx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
    events: EventSink,
    dns_cache: DnsCache,
) -> anyhow::Result<NfqHandles> {
    anyhow::ensure!(
        !cfg.fail_open,
        "NFQUEUE fail_open bypasses mandatory verdict auditing"
    );
    // Interface metadata, rather than destination addresses, includes every
    // local host address routed over lo. A missing index cannot grant access.
    // SAFETY: the C string is terminated and valid for this read-only query.
    let loopback_ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    anyhow::ensure!(
        loopback_ifindex != 0,
        "resolving loopback output interface: {}",
        std::io::Error::last_os_error()
    );
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
        loopback_ifindex,
        engine,
        rejecter,
        prompt_tx,
        verdict_rx,
        observed_tx,
        stats,
        events,
        dns: Box::new(dns_cache),
        resolver: Box::new(ProcfsResolver),
        waiters: HashMap::new(),
        pending_flows: HashMap::new(),
        next_prompt_id: prompt_session_seed(),
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
/// (UID, executable image, destination, protocol). The source port is deliberately not
/// part of the key so SYN retransmits *and* parallel connections from the
/// same app to the same destination share a single prompt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    origin: FlowOrigin,
    uid: Option<u32>,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: Protocol,
}

/// Only a known image may share a prompt; uncertain identities never do.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FlowOrigin {
    /// `sha256` is `None` only for a root-sealed path.
    Exe {
        path: PathBuf,
        sha256: Option<String>,
    },
    Unattributed(uuid::Uuid),
}

impl FlowKey {
    fn for_flow(conn: &Connection, proc: &Process) -> Self {
        let origin = match (&proc.sha256, proc.exe_is_known(), proc.uid) {
            (Some(sha256), true, Some(_)) => FlowOrigin::Exe {
                path: proc.exe.clone(),
                sha256: Some(sha256.clone()),
            },
            // Images over 64 MiB (Chromium, Electron, VS Code) have no
            // digest. A root-sealed path still names one image only root can
            // change, and the resolver publishes it only when it names the
            // mapped file here, which is why a standing Allow for it is
            // path-only. Without this every packet, retransmits included,
            // opened its own prompt.
            (None, true, Some(_))
                if cfc_core::exe_path::is_root_sealed(&proc.exe).unwrap_or(false) =>
            {
                FlowOrigin::Exe {
                    path: proc.exe.clone(),
                    sha256: None,
                }
            }
            // Neither a PID nor a path identifies an unknown execution.
            // Such packets must receive independent authorization.
            _ => FlowOrigin::Unattributed(uuid::Uuid::new_v4()),
        };
        Self {
            origin,
            uid: proc.uid,
            dst_ip: conn.dst_ip,
            dst_port: conn.dst_port,
            protocol: conn.protocol,
        }
    }
}

/// Per-prompt bookkeeping on the worker thread.
struct PendingPrompt<M> {
    flow: FlowKey,
    /// Current closed policy is checked separately for every parked packet.
    packets: Vec<ParkedPacket<M>>,
    /// Applied if the router disappears before answering.
    fallback: Verdict,
}

struct ParkedPacket<M> {
    message: M,
    connection: Connection,
    process: Process,
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
    loopback_ifindex: u32,
    engine: Engine,
    /// Injects the TCP RST / ICMP port-unreachable that makes
    /// [`Action::Reject`] differ from [`Action::Deny`]. Inert (drop-only)
    /// when raw sockets are unavailable.
    rejecter: Rejecter,
    prompt_tx: PromptTx,
    verdict_rx: VerdictRx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
    /// Refusal rows go here, after the verdict; see [`Worker::deliver`].
    events: EventSink,
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
    /// unix-ms at which the loop last turned. The idle wait is bounded and
    /// nothing on this thread waits for storage. A stale stamp means main
    /// must withhold the WATCHDOG=1 heartbeat.
    last_activity: Arc<AtomicI64>,
}

impl<Q: PacketQueue> Worker<Q> {
    fn run(mut self) -> anyhow::Result<()> {
        // Everything below assumes recv never parks indefinitely; establish
        // that here rather than trusting the caller to have done it.
        self.queue.set_nonblocking(true);

        // This thread is the datapath, and it is the only one. Saying so once
        // here covers everything reached from it, however deep: in particular
        // a provenance lookup that finds the package index stale or being
        // rebuilt answers "not ready" rather than rebuilding it or waiting
        // for the rebuild, which reads every installed package's file list.
        // Measured cold on the owner's machine, that rebuild took 123 ms -
        // and since this loop is a single thread, that
        // is not one slow packet, it is every flow on the machine stopping
        // together. `provenance::warm` does the build off this thread.
        crate::provenance::mark_datapath_thread();

        let mut consecutive_errors: u32 = 0;
        loop {
            if self.stop.load(Ordering::Relaxed) {
                info!("stop requested; NFQUEUE worker leaving its recv loop");
                return Ok(());
            }
            // Watchdog heartbeat source: one stamp per iteration. main's
            // heartbeat task withholds WATCHDOG=1 once this goes stale.
            self.stamp_activity();
            self.drain_verdicts()?;

            match self.queue.recv() {
                Ok(msg) => {
                    consecutive_errors = 0;
                    self.handle_message(msg)?;
                }
                // No packet ready: spend the beat waiting for a verdict.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => self.idle_wait()?,
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
    fn idle_wait(&mut self) -> anyhow::Result<()> {
        if !self.verdict_channel_open {
            // Nothing left to wait for, and `recv_timeout` on a hung-up
            // channel returns instantly: pace the loop by hand.
            std::thread::sleep(self.tuning.poll_interval);
            return Ok(());
        }
        match self.verdict_rx.recv_timeout(self.tuning.poll_interval) {
            Ok(pv) => self.resolve_prompt(pv)?,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => self.close_verdict_channel()?,
        }
        Ok(())
    }

    /// Drains every verdict the router has produced so far.
    fn drain_verdicts(&mut self) -> anyhow::Result<()> {
        if !self.verdict_channel_open {
            return Ok(());
        }
        loop {
            match self.verdict_rx.try_recv() {
                Ok(pv) => self.resolve_prompt(pv)?,
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => {
                    return self.close_verdict_channel();
                }
            }
        }
    }

    /// The router is gone for good: remember it (so the idle path stops
    /// polling a dead channel) and unstrand whatever was parked.
    fn close_verdict_channel(&mut self) -> anyhow::Result<()> {
        self.verdict_channel_open = false;
        self.flush_waiters_disconnected()
    }

    /// The router side of the verdict channel is gone; no pending prompt
    /// can ever resolve. Apply each prompt's fallback so its parked packets
    /// aren't stranded until the kernel times them out.
    fn flush_waiters_disconnected(&mut self) -> anyhow::Result<()> {
        if self.waiters.is_empty() {
            return Ok(());
        }
        warn!(
            count = self.waiters.len(),
            "verdict channel disconnected; applying fallback to outstanding prompts"
        );
        let ids: Vec<u64> = self.waiters.keys().copied().collect();
        for prompt_id in ids {
            let verdict = self.waiters[&prompt_id].fallback;
            self.resolve_prompt(PromptVerdict { prompt_id, verdict })?;
        }
        Ok(())
    }

    /// Applies a resolved prompt: verdicts every parked packet, drops the
    /// waiters + pending_flows entries, and records each actual verdict.
    fn resolve_prompt(&mut self, pv: PromptVerdict) -> anyhow::Result<()> {
        let Some(pending) = self.waiters.remove(&pv.prompt_id) else {
            // Late duplicate (the prompt already resolved another way);
            // the first resolution won.
            trace!(
                prompt_id = pv.prompt_id,
                "verdict for already-resolved prompt, ignoring"
            );
            return Ok(());
        };
        self.pending_flows.remove(&pending.flow);

        for packet in pending.packets {
            // Per packet, not per prompt: a Reject response is derived from
            // the individual segment (its sequence numbers, its source
            // port), and parallel connections share one prompt.
            let mut undecided = None;
            let verdict = match self.engine.peek(&packet.connection, &packet.process) {
                // A refusal decided since the prompt opened always wins.
                Decision::Resolved(current) if current.action != Action::Allow => current,
                // So does a rule's Allow over a fallback nobody chose: a rule
                // added while this prompt waited (another prompt's "Allow
                // always" for the same program) must not lose to the timeout
                // Deny. A user's own answer stands.
                Decision::Resolved(current)
                    if matches!(current.source, VerdictSource::Rule(_))
                        && matches!(
                            pv.verdict.source,
                            VerdictSource::DefaultPolicy | VerdictSource::Timeout
                        ) =>
                {
                    current
                }
                // The user's answer applies to a flow whose identity is
                // incomplete: no rule can decide it, that is why it was asked.
                Decision::NeedsPrompt { undecided: u, .. } => {
                    undecided = u;
                    pv.verdict
                }
                _ => pv.verdict,
            };
            // Only a rule whose answer was applied gets the hit.
            if let VerdictSource::Rule(id) = verdict.source {
                self.engine.count_hit(id);
            }
            self.deliver(
                packet.message,
                ObservedConnection {
                    connection: packet.connection,
                    process: packet.process,
                    verdict,
                    undecided,
                },
            )?;
        }
        Ok(())
    }

    fn handle_message(&mut self, msg: Q::Msg) -> anyhow::Result<()> {
        let meta = PacketMeta {
            uid: msg.uid(),
            gid: msg.gid(),
            direction: direction_for_hook(msg.hook()),
            loopback: msg.hook() == NF_INET_LOCAL_OUT
                && self.loopback_ifindex != 0
                && msg.outdev() == self.loopback_ifindex,
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
            } => self.deliver(
                msg,
                ObservedConnection {
                    connection,
                    process,
                    verdict,
                    undecided: None,
                },
            ),
            PacketOutcome::Prompt {
                connection,
                process,
                fallback,
                undecided,
            } => self.park_for_prompt(msg, connection, process, fallback, undecided),
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
        undecided: Option<uuid::Uuid>,
    ) -> anyhow::Result<()> {
        let flow = FlowKey::for_flow(&connection, &process);
        if let Some(&prompt_id) = self.pending_flows.get(&flow) {
            if let Some(pending) = self.waiters.get_mut(&prompt_id) {
                // Riding is bounded per prompt, not just per table: the cap
                // on `waiters` below counts prompts, and counting prompts
                // bounds nothing when every packet of a flood shares one -
                // which is exactly what `FlowKey` makes them do. Each packet
                // parked here keeps a kernel queue slot until the verdict,
                // so an unbounded ride let one unanswered prompt fill the
                // queue and blackhole every new flow on the machine. Past
                // the cap, overflow takes the same path as every other
                // packet that cannot park.
                if pending.packets.len() >= MAX_PACKETS_PER_PROMPT {
                    trace!(
                        prompt_id,
                        parked = pending.packets.len(),
                        "prompt already holds its packet cap; applying the fallback"
                    );
                    return self.deliver_fallback(msg, connection, process, fallback, undecided);
                }
                trace!(
                    prompt_id,
                    "flow already prompting; parking packet on existing prompt"
                );
                pending.packets.push(ParkedPacket {
                    message: msg,
                    connection,
                    process,
                });
                return Ok(());
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

        // A parked packet is not free. Each one holds the nfq `Message` it
        // arrived in, and that owns the 68 KiB netlink receive buffer the
        // kernel copied it into - so 512 unanswered prompts is at least
        // ~34 MB pinned inside the packet worker, and nothing bounded the
        // prompt count. A process opening new flows faster than a human
        // answers bubbles - a torrent client reaching for peers, a scan -
        // reaches that in seconds.
        //
        // Over the cap, take the same branch as a saturated router below:
        // apply `fallback`, which is the configured `no_ui_action`. That is
        // fail-closed on every shipped profile, and it replaces an
        // out-of-memory path with a verdict.
        if self.waiters.len() >= MAX_PARKED_PROMPTS {
            trace!(
                parked = self.waiters.len(),
                "prompt backlog at its cap; applying the fallback rather than parking"
            );
            return self.deliver_fallback(msg, connection, process, fallback, undecided);
        }

        let prompt_id = self.next_prompt_id;
        self.next_prompt_id = self
            .next_prompt_id
            .checked_add(1)
            .unwrap_or_else(prompt_session_seed);
        let req = PromptRequest {
            prompt_id,
            connection: connection.clone(),
            process: process.clone(),
            undecided,
        };
        match self.prompt_tx.try_send(req) {
            Ok(()) => {
                self.pending_flows.insert(flow.clone(), prompt_id);
                self.waiters.insert(
                    prompt_id,
                    PendingPrompt {
                        flow,
                        packets: vec![ParkedPacket {
                            message: msg,
                            connection,
                            process,
                        }],
                        fallback,
                    },
                );
            }
            Err(e) => {
                // Router saturated or gone: apply the default policy now
                // rather than stranding the packet.
                trace!("prompt channel unavailable ({e}); applying fallback");
                return self.deliver_fallback(msg, connection, process, fallback, undecided);
            }
        }
        Ok(())
    }

    /// Answers a packet with the prompt fallback right now, with everything
    /// a resolved prompt would have produced: the verdict, the stats count
    /// and the feed entry. Every path that cannot park - a prompt at its
    /// packet cap, the prompt backlog at its cap, a saturated or vanished
    /// router - comes through here, because the backlog-cap branch once
    /// applied only the verdict: the flood it existed for was denied with
    /// nothing in the stats, nothing in the feed, and only a trace line to
    /// say so.
    fn deliver_fallback(
        &mut self,
        msg: Q::Msg,
        connection: Connection,
        process: Process,
        fallback: Verdict,
        undecided: Option<uuid::Uuid>,
    ) -> anyhow::Result<()> {
        self.deliver(
            msg,
            ObservedConnection {
                connection,
                process,
                verdict: fallback,
                undecided,
            },
        )
    }

    /// Verdicts the packet, then records it. A refusal row goes straight
    /// into the event writer's bounded queue rather than through the lossy
    /// live feed. Nothing here waits for storage: an fsync per refusal on
    /// this single thread let a deny flood stall every new flow on the
    /// machine, and a failed commit used to end the worker, which took all
    /// networking down until systemd restarted the daemon. A row the queue
    /// cannot take is counted and logged by [`EventSink`]; the journal line
    /// from [`publish_observation`] still names the refusal.
    fn deliver(&mut self, msg: Q::Msg, obs: ObservedConnection) -> anyhow::Result<()> {
        self.apply_action(msg, obs.verdict.action)?;
        if obs.verdict.action == Action::Allow {
            self.dns.enqueue(obs.connection.dst_ip);
        } else {
            self.events
                .push(crate::convert::event_row_from_observed(&obs));
        }
        record(&self.stats, obs.verdict.action);
        publish_observation(&self.observed_tx, obs);
        Ok(())
    }

    /// Applies a policy action to a queued packet.
    ///
    /// Deny and Reject both hand the kernel the same verdict (Drop) - they
    /// differ only in what the application sees. Reject additionally
    /// injects the refusal the peer would have sent (TCP RST / ICMP port
    /// unreachable) so the app fails immediately instead of retransmitting
    /// until its own timeout. The injection is best-effort: if it can't be
    /// sent the packet is still dropped, i.e. Reject degrades to Deny.
    fn apply_action(&mut self, msg: Q::Msg, action: Action) -> anyhow::Result<()> {
        if action == Action::Reject {
            self.inject_refusal(&msg);
        }
        self.send_verdict(msg, nfq_verdict_for(action))
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

    fn send_verdict(&mut self, mut msg: Q::Msg, verdict: NfqVerdict) -> anyhow::Result<()> {
        msg.set_verdict(verdict);
        self.queue.verdict(msg).context("setting NFQUEUE verdict")
    }
}

/// Process attribution seam so [`handle_packet`] is testable without a
/// live /proc.
trait ProcessResolver {
    #[allow(clippy::too_many_arguments)] // socket tuple plus kernel UID attribution
    fn socket_owner(
        &self,
        protocol: Protocol,
        direction: Direction,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        uid: Option<u32>,
    ) -> Option<process_resolve::SocketOwner>;
    fn resolve(&self, owner: &process_resolve::SocketOwner) -> Process;
}

/// Production resolver backed by /proc.
struct ProcfsResolver;

impl ProcessResolver for ProcfsResolver {
    fn socket_owner(
        &self,
        protocol: Protocol,
        direction: Direction,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        uid: Option<u32>,
    ) -> Option<process_resolve::SocketOwner> {
        process_resolve::socket_owner(protocol, direction, src_ip, src_port, dst_ip, dst_port, uid)
    }

    fn resolve(&self, owner: &process_resolve::SocketOwner) -> Process {
        owner.resolve()
    }
}

/// Reverse-DNS / self-identification seam, backed by [`DnsCache`] in
/// production.
trait HostCache {
    fn is_self(&self, pid: u32) -> bool;
    /// The name for this address, and whether it was confirmed to belong to
    /// it. Both, because the packet path needs the name for the record and the
    /// confirmation for the decision, and asking twice would race.
    fn cached_host(&self, ip: IpAddr) -> Option<(String, bool)>;
    fn enqueue(&self, ip: IpAddr);
}

impl HostCache for DnsCache {
    fn is_self(&self, pid: u32) -> bool {
        DnsCache::is_self(self, pid)
    }

    fn cached_host(&self, ip: IpAddr) -> Option<(String, bool)> {
        self.cached_named(ip)
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
    /// Kernel OUTPUT interface is lo; includes local non-loopback addresses.
    loopback: bool,
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
    /// Parsed decision, verdicted, recorded and counted by [`Worker::deliver`].
    Deliver {
        connection: Connection,
        process: Process,
        verdict: Verdict,
    },
    /// No rule answered and prompting is enabled: ask the user, applying
    /// `fallback` if no prompt can be delivered. Stats are recorded when
    /// the prompt resolves. `undecided` names the rule that may apply but
    /// could not be decided, if that is why.
    Prompt {
        connection: Connection,
        process: Process,
        fallback: Verdict,
        undecided: Option<uuid::Uuid>,
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
            // The direction is known even when the bytes are not, and the two
            // defaults are not interchangeable: `no_ui_action` may be Allow,
            // while `inbound_action` cannot be - config refuses it precisely so
            // inbound can never default-permit. A crafted inbound packet that
            // fails to parse must not be the way round that.
            let action = if meta.direction == Direction::Inbound {
                deps.engine.inbound_default()
            } else {
                deps.engine.fallback_verdict().action
            };
            debug!(?meta.direction, "unparseable packet: {e}; applying the default for its direction");
            return PacketOutcome::Silent(nfq_verdict_for(action));
        }
    };

    // Inbound is not asked, rather than asked and told nothing.
    //
    // `socket_owner` searches for a socket already holding this 4-tuple.
    // An inbound SYN has none - nothing has accepted it yet - so the search
    // could only ever miss, and missing meant reading /proc/net/tcp and
    // /proc/net/tcp6: 2.40 ms per packet for an answer of `None`.
    //
    // The resolver refuses inbound too. Two locks for one hole, because this
    // one is silent: the verdict is identical either way, so nothing would
    // have failed - the firewall would just be fourteen times slower on the
    // inbound side and say nothing about it.
    let owner = if conn.direction == Direction::Inbound {
        None
    } else {
        deps.resolver.socket_owner(
            conn.protocol,
            conn.direction,
            conn.src_ip,
            conn.src_port,
            conn.dst_ip,
            conn.dst_port,
            meta.uid,
        )
    };
    let pid_hint = owner.as_ref().map(process_resolve::SocketOwner::pid);

    // Always allow our own traffic. Otherwise the daemon's reverse DNS
    // resolver would itself be intercepted, deadlocking on a verdict
    // we can't produce until the resolver returns.
    if let Some(pid) = pid_hint {
        if deps.dns.is_self(pid) && meta.uid == Some(0) {
            return PacketOutcome::Silent(NfqVerdict::Accept);
        }
    }

    let mut proc = match owner.as_ref() {
        Some(owner) => deps.resolver.resolve(owner),
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

    // Cached policy names never cause network work for a refused flow.
    if let Some((host, verified)) = deps.dns.cached_host(conn.dst_ip) {
        conn = conn.with_host_verified(host, verified);
    }

    match deps.engine.evaluate(&conn, &proc) {
        Decision::Resolved(verdict) => PacketOutcome::Deliver {
            connection: conn,
            process: proc,
            verdict,
        },
        Decision::NeedsPrompt {
            fallback,
            undecided,
        } => {
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
                return PacketOutcome::Deliver {
                    connection: conn,
                    process: proc,
                    verdict,
                };
            }
            // Preserve desktop IPC for unmatched local flows after explicit
            // policy has had its say. Neither this nor pause lifts a flow a
            // rule may be about: its identity is incomplete, so it is asked.
            if meta.loopback && undecided.is_none() {
                return PacketOutcome::Deliver {
                    connection: conn,
                    process: proc,
                    verdict: Verdict::default_allow(),
                };
            }
            if deps.stats.is_paused() && undecided.is_none() {
                // Paused means "stop prompting", not "stop filtering":
                // rules above still applied; only unmatched flows pass
                // without a prompt.
                debug!(dst = %conn.dst_ip, "paused: allowing unmatched flow without prompting");
                let verdict = Verdict::default_allow();
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
                undecided,
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
mod tests;
