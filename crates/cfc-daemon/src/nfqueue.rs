//! NFQUEUE intercept worker.
//!
//! A dedicated blocking thread owns the [`nfq::Queue`] exclusively and runs
//! [`Worker::run`]. Per-packet decision logic lives in the pure
//! [`handle_packet`] pipeline (parse -> self-DNS bypass -> process
//! attribution -> hostname attach -> rule evaluation), which is unit-tested
//! without root through the [`ProcessResolver`] / [`HostCache`] seams.
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
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

/// Consecutive hard `recv` errors tolerated before the worker gives up and
/// the daemon exits non-zero (transient errors reset the count).
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 100;

/// How long the worker waits on the verdict channel between nonblocking
/// recv attempts while prompts are outstanding.
const VERDICT_POLL_INTERVAL: Duration = Duration::from_millis(5);

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

/// Binds the queue and starts the worker thread. On success, also returns
/// the worker's watchdog liveness cell (see [`Worker::last_activity`]) for
/// main's WATCHDOG=1 heartbeat task.
pub fn spawn(
    cfg: &NfqConfig,
    engine: Engine,
    prompt_tx: PromptTx,
    verdict_rx: VerdictRx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
    dns_cache: DnsCache,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, Arc<AtomicI64>)> {
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
    let worker = Worker {
        queue,
        engine,
        rejecter,
        prompt_tx,
        verdict_rx,
        observed_tx,
        stats,
        dns_cache,
        waiters: HashMap::new(),
        pending_flows: HashMap::new(),
        next_prompt_id: 1,
        nonblocking: false,
        last_activity: last_activity.clone(),
    };
    let blocking = tokio::task::spawn_blocking(move || worker.run());

    let handle = tokio::spawn(async move {
        match blocking.await {
            Ok(result) => result,
            Err(e) => Err(anyhow::anyhow!("NFQUEUE blocking task panicked: {e}")),
        }
    });
    Ok((handle, last_activity))
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
        let origin = if proc.exe.as_os_str() == "<unknown>" {
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
struct PendingPrompt {
    flow: FlowKey,
    connection: Connection,
    process: Process,
    /// Every packet parked on this prompt; all get the same verdict.
    packets: Vec<Message>,
    /// Applied if the router disappears before answering.
    fallback: Verdict,
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
///   [`Worker::resolve_prompt`].
/// - The queue socket is in blocking mode iff `waiters` is empty
///   ([`Worker::sync_recv_mode`]): the normal path pays zero polling
///   latency, and while prompts are outstanding the loop alternates
///   nonblocking recv with short verdict-channel waits so neither packets
///   nor verdicts can stall the other.
struct Worker {
    queue: Queue,
    engine: Engine,
    /// Injects the TCP RST / ICMP port-unreachable that makes
    /// [`Action::Reject`] differ from [`Action::Deny`]. Inert (drop-only)
    /// when raw sockets are unavailable.
    rejecter: Rejecter,
    prompt_tx: PromptTx,
    verdict_rx: VerdictRx,
    observed_tx: broadcast::Sender<ObservedConnection>,
    stats: Stats,
    dns_cache: DnsCache,
    waiters: HashMap<u64, PendingPrompt>,
    pending_flows: HashMap<FlowKey, u64>,
    next_prompt_id: u64,
    /// Mirrors the queue socket's recv mode (nfq has no getter).
    nonblocking: bool,
    /// Watchdog liveness cell shared with main's heartbeat task. Positive
    /// value: last unix-ms the worker was busy in its loop (a stale
    /// positive stamp means the worker wedged mid-iteration and the
    /// WATCHDOG=1 heartbeat is withheld). Negative value: parked in a
    /// blocking kernel `recv` since `-value`, which is healthy for
    /// arbitrarily long on an idle system.
    last_activity: Arc<AtomicI64>,
}

impl Worker {
    fn run(mut self) -> anyhow::Result<()> {
        let mut consecutive_errors: u32 = 0;
        loop {
            // Watchdog heartbeat source: one stamp per iteration. main's
            // heartbeat task withholds WATCHDOG=1 once this goes stale.
            self.stamp_activity(false);
            self.drain_verdicts();
            self.sync_recv_mode();

            // A blocking recv (no prompts outstanding) legitimately parks
            // until the next packet arrives -- possibly minutes on an idle
            // system. Mark the parked state so the watchdog can tell "no
            // traffic" from "wedged". The nonblocking path returns within
            // ~VERDICT_POLL_INTERVAL and needs no marker.
            if !self.nonblocking {
                self.stamp_activity(true);
            }
            let received = self.queue.recv();
            self.stamp_activity(false);

            match received {
                Ok(msg) => {
                    consecutive_errors = 0;
                    self.handle_message(msg);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Nonblocking mode and no packet ready: wait a short
                    // beat for a verdict instead of spinning.
                    match self.verdict_rx.recv_timeout(VERDICT_POLL_INTERVAL) {
                        Ok(pv) => self.resolve_prompt(pv),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => self.flush_waiters_disconnected(),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    consecutive_errors += 1;
                    error!("NFQUEUE recv error ({consecutive_errors} consecutive): {e}");
                    if consecutive_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                        return Err(e).context(format!(
                            "NFQUEUE recv failed {consecutive_errors} times in a row"
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }

    /// Stamps the watchdog cell (see the `last_activity` field docs):
    /// `parked == false` stores `+now_ms` (busy in the loop),
    /// `parked == true` stores `-now_ms` (about to block in a kernel recv).
    fn stamp_activity(&self, parked: bool) {
        let now = unix_ms();
        self.last_activity
            .store(if parked { -now } else { now }, Ordering::Relaxed);
    }

    /// Drains every verdict the router has produced so far.
    fn drain_verdicts(&mut self) {
        loop {
            match self.verdict_rx.try_recv() {
                Ok(pv) => self.resolve_prompt(pv),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.flush_waiters_disconnected();
                    return;
                }
            }
        }
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

    /// Blocking recv when no prompts are outstanding (zero-latency normal
    /// path); nonblocking + short verdict polls otherwise.
    fn sync_recv_mode(&mut self) {
        let want = !self.waiters.is_empty();
        if want != self.nonblocking {
            self.queue.set_nonblocking(want);
            self.nonblocking = want;
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

    fn handle_message(&mut self, msg: Message) {
        let meta = PacketMeta {
            uid: msg.get_uid(),
            gid: msg.get_gid(),
        };
        let deps = PipelineDeps {
            engine: &self.engine,
            stats: &self.stats,
            dns: &self.dns_cache,
            resolver: &ProcfsResolver,
        };
        match handle_packet(msg.get_payload(), &meta, &deps) {
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
        msg: Message,
        connection: Connection,
        process: Process,
        fallback: Verdict,
    ) {
        let flow = FlowKey::for_flow(&connection, &process);
        if let Some(&prompt_id) = self.pending_flows.get(&flow) {
            trace!(
                prompt_id,
                "flow already prompting; parking packet on existing prompt"
            );
            self.waiters
                .get_mut(&prompt_id)
                .expect("pending_flows entry without matching waiters entry")
                .packets
                .push(msg);
            return;
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
    fn apply_action(&mut self, msg: Message, action: Action) {
        if action == Action::Reject {
            self.inject_refusal(&msg);
        }
        self.send_verdict(msg, nfq_verdict_for(action));
    }

    /// Reparses this specific packet (cheap, and only on the Reject path)
    /// because the refusal depends on per-segment fields the pipeline's
    /// [`Connection`] does not carry - TCP sequence numbers and the bytes
    /// quoted back in an ICMP error.
    fn inject_refusal(&self, msg: &Message) {
        let payload = msg.get_payload();
        match packet::parse(payload, Direction::Outbound) {
            Ok(conn) => {
                let outcome = self.rejecter.reject(&conn, payload);
                trace!(?outcome, dst = %conn.dst_ip, "reject response");
            }
            Err(e) => trace!("reject: unparseable packet ({e}); dropping only"),
        }
    }

    fn send_verdict(&mut self, mut msg: Message, verdict: NfqVerdict) {
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
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Option<u32> {
        process_resolve::pid_for_socket(protocol, src_ip, src_port, dst_ip, dst_port)
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
    let mut conn = match packet::parse(payload, Direction::Outbound) {
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

    let pid_hint = deps.resolver.pid_for_socket(
        conn.protocol,
        conn.src_ip,
        conn.src_port,
        conn.dst_ip,
        conn.dst_port,
    );

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
    use std::net::Ipv4Addr;

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
            prompt_timeout_secs: 15,
        }
    }

    fn dp_deny() -> DefaultPolicy {
        DefaultPolicy {
            no_ui_action: Action::Deny,
            timeout_action: Action::Deny,
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
            pid,
            ppid: Some(1),
            uid: Some(1000),
            gid: Some(1000),
            exe: PathBuf::from(exe),
            cmdline: vec![exe.to_string()],
            cwd: None,
            sha256: None,
            started_at: None,
        }
    }

    struct StubResolver {
        pid: Option<u32>,
        process: Process,
    }

    impl ProcessResolver for StubResolver {
        fn pid_for_socket(
            &self,
            _protocol: Protocol,
            _src_ip: IpAddr,
            _src_port: u16,
            _dst_ip: IpAddr,
            _dst_port: u16,
        ) -> Option<u32> {
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
}
