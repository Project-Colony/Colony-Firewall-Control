use super::*;
use crate::config::DefaultPolicy;
use cfc_core::{Rule, RuleScope, RuleSet};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Instant;

const IPPROTO_TCP: u8 = 6;

/// A card left over from an earlier session must not name the id this
/// session hands out first, so ids do not restart at a fixed value.
#[test]
fn each_session_starts_prompt_ids_from_a_fresh_seed() {
    assert_ne!(prompt_session_seed(), prompt_session_seed());
}

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
        sha256: Some("aa".repeat(32)),
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
    fn socket_owner(
        &self,
        _protocol: Protocol,
        _direction: Direction,
        _src_ip: IpAddr,
        _src_port: u16,
        _dst_ip: IpAddr,
        _dst_port: u16,
        _uid: Option<u32>,
    ) -> Option<process_resolve::SocketOwner> {
        self.socket_lookups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.pid.map(process_resolve::SocketOwner::for_test)
    }

    fn resolve(&self, _owner: &process_resolve::SocketOwner) -> Process {
        self.process.clone()
    }
}

struct StubDns {
    self_pid: Option<u32>,
    host: Option<String>,
    /// Whether the stubbed name is confirmed against the address. `true`
    /// by default so a test that only cares about the name keeps meaning
    /// what it meant; a test about the trust distinction sets it.
    host_verified: bool,
}

impl Default for StubDns {
    fn default() -> Self {
        Self {
            self_pid: None,
            host: None,
            host_verified: true,
        }
    }
}

impl HostCache for StubDns {
    fn is_self(&self, pid: u32) -> bool {
        self.self_pid == Some(pid)
    }

    fn cached_host(&self, _ip: IpAddr) -> Option<(String, bool)> {
        self.host.clone().map(|h| (h, self.host_verified))
    }

    fn enqueue(&self, _ip: IpAddr) {}
}

const NO_META: PacketMeta = PacketMeta {
    uid: None,
    gid: None,
    direction: Direction::Outbound,
    loopback: false,
};

/// The same, for a packet the kernel queued from the input hook.
const INBOUND_META: PacketMeta = PacketMeta {
    uid: None,
    gid: None,
    direction: Direction::Inbound,
    loopback: false,
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
                ..Default::default()
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

/// Past the cap, a flow takes the configured fallback instead of being
/// parked.
///
/// Every parked packet holds the nfq message it arrived in, and that owns
/// the 68 KiB netlink buffer the kernel copied it into. Nothing bounded
/// the count, so a process opening flows faster than a human answers
/// bubbles - a torrent client reaching for peers, a scan - grew it until
/// the worker ran out of memory. Overflow now takes the same branch a
/// saturated prompt router already took, which is fail-closed - and it
/// is the whole branch: the denial is counted and published, not just
/// verdicted. It used to be verdict-only, so the flood this cap exists
/// for was denied with nothing in the stats and nothing in the feed.
#[test]
fn a_prompt_backlog_at_its_cap_falls_back_instead_of_parking() {
    let mut h = LoopHarness::new(vec![], vec![], dp_deny());

    // Fill to the cap through the real path, so the state is exactly what
    // production would hold.
    for i in 0..MAX_PARKED_PROMPTS {
        h.worker()
            .park_for_prompt(
                FakeMsg::new(i as u32, tcp_packet(443)),
                // A distinct destination per park: `FlowKey` folds packets of
                // the same flow onto one prompt, which is the behaviour under
                // test elsewhere and would collapse this to a single waiter.
                conn_to(1024 + i as u16, 1111),
                test_process(4242, "/usr/bin/curl"),
                Verdict::default_deny(),
                None,
            )
            .unwrap();
        // Drain as we go: the harness channel holds 16, and a full channel
        // takes the saturation branch instead of parking - which is the
        // *other* fallback path and would hide what this test is about.
        while h.prompt_rx.try_recv().is_ok() {}
    }
    assert_eq!(h.worker().waiters.len(), MAX_PARKED_PROMPTS);
    let parked_verdicts = h.verdicts().len();

    // One more. It must be answered, not parked.
    let overflow_id = MAX_PARKED_PROMPTS as u32 + 1;
    h.worker()
        .park_for_prompt(
            FakeMsg::new(overflow_id, tcp_packet(443)),
            conn_to(9000, 1111),
            test_process(4242, "/usr/bin/curl"),
            Verdict::default_deny(),
            None,
        )
        .unwrap();

    assert_eq!(
        h.worker().waiters.len(),
        MAX_PARKED_PROMPTS,
        "the backlog grew past its cap"
    );
    let new_verdicts: Vec<_> = h.verdicts().into_iter().skip(parked_verdicts).collect();
    assert_eq!(
        new_verdicts,
        vec![(overflow_id, NfqVerdict::Drop)],
        "overflow must take the fallback verdict, and dp_deny() means Drop"
    );
    // The saturated-router branch counts and publishes what it denies;
    // this branch claims to be the same branch, so it must too.
    assert_eq!(
        h.stats.connections_denied(),
        1,
        "the fallback denial is counted"
    );
    let observed = h
        .observed_rx
        .try_recv()
        .expect("the fallback denial reaches the feed");
    assert_eq!(observed.verdict.action, Action::Deny);
}

/// A flow that keeps sending while its prompt sits unanswered must not
/// park without bound.
///
/// [`FlowKey`] folds every packet of a flow onto one prompt on purpose,
/// so [`MAX_PARKED_PROMPTS`] never bites - `waiters.len()` sits at 1 -
/// and each parked packet keeps a kernel queue slot until the verdict.
/// Unbounded riding let one chatty flow (unreplied UDP, a SYN spray
/// across source ports) fill the whole queue within a prompt timeout
/// and blackhole every new flow on the machine. Past the per-prompt
/// cap, overflow is answered with the fallback, counted and published
/// like any other denial, while the prompt itself stays intact.
#[test]
fn a_full_prompt_answers_overflow_with_the_fallback_instead_of_parking() {
    let mut h = LoopHarness::new(vec![], vec![], dp_deny());

    // One flow throughout: the destination stays fixed and the source
    // port varies, as a parallel-connection burst would.
    for i in 0..MAX_PACKETS_PER_PROMPT {
        h.worker()
            .park_for_prompt(
                FakeMsg::new(i as u32, tcp_packet(443)),
                conn_to(443, 1111 + i as u16),
                test_process(4242, "/usr/bin/curl"),
                Verdict::default_deny(),
                None,
            )
            .unwrap();
    }
    assert_eq!(h.worker().waiters.len(), 1, "one flow is one prompt");
    assert!(h.verdicts().is_empty(), "up to the cap, packets park");
    assert_eq!(h.stats.connections_total(), 0);

    // One more packet of the same flow. It must be answered, not parked.
    let overflow_id = MAX_PACKETS_PER_PROMPT as u32;
    h.worker()
        .park_for_prompt(
            FakeMsg::new(overflow_id, tcp_packet(443)),
            conn_to(443, 9999),
            test_process(4242, "/usr/bin/curl"),
            Verdict::default_deny(),
            None,
        )
        .unwrap();

    assert_eq!(
        h.verdicts(),
        vec![(overflow_id, NfqVerdict::Drop)],
        "overflow must take the fallback verdict, and dp_deny() means Drop"
    );
    assert_eq!(
        h.stats.connections_denied(),
        1,
        "the overflow denial is counted"
    );
    let observed = h
        .observed_rx
        .try_recv()
        .expect("the overflow denial reaches the feed");
    assert_eq!(observed.verdict.action, Action::Deny);
    assert_eq!(observed.connection.src_port, 9999);

    // The prompt survives its own overflow: resolving it frees exactly
    // the packets that parked, none of them double-verdicted.
    let req = h.prompt_rx.try_recv().expect("prompt dispatched");
    h.send_verdict(req.prompt_id, Verdict::default_allow());
    h.worker().drain_verdicts().unwrap();

    let expected: Vec<_> = std::iter::once((overflow_id, NfqVerdict::Drop))
        .chain((0..MAX_PACKETS_PER_PROMPT).map(|i| (i as u32, NfqVerdict::Accept)))
        .collect();
    assert_eq!(h.verdicts(), expected);
    // Each parked packet receives its own policy decision and audit record.
    assert_eq!(h.stats.connections_allowed(), MAX_PACKETS_PER_PROMPT as u64);
    assert!(h.worker().waiters.is_empty());
    assert!(h.worker().pending_flows.is_empty());
}

/// The worker must declare its thread to be the datapath.
///
/// That declaration is what stops a provenance lookup from rebuilding the
/// package index under the packets - 123 ms with every flow on the machine
/// waiting. Removing the one line that makes it breaks nothing visibly,
/// which is exactly why it is asserted here.
#[test]
fn the_worker_declares_its_thread_to_be_the_datapath() {
    let mut h = LoopHarness::new(vec![], vec![], dp_deny());
    let worker = h.worker.take().unwrap();
    // Stop before the first iteration: `run` marks the thread on the way
    // in, so an empty loop is enough to observe it.
    h.stop.store(true, Ordering::Relaxed);

    std::thread::spawn(move || {
        assert!(
            !crate::provenance::is_datapath_thread(),
            "a fresh thread must not start out marked"
        );
        worker.run().unwrap();
        assert!(
            crate::provenance::is_datapath_thread(),
            "the worker did not declare its thread; provenance builds will \
             stall the datapath again"
        );
    })
    .join()
    .unwrap();
}

/// An undirected rule is outbound-only.
///
/// Every rule written before inbound filtering left the direction unset,
/// and every one was about traffic leaving. Treating unset as "both"
/// reinterpreted all of them the day the input chain was enabled: a
/// port-only allow stops meaning "we may reach 8080" and starts also
/// meaning "anyone may reach 8080 here", because inbound `dst_port` is
/// *our* port.
#[test]
fn an_undirected_rule_does_not_admit_inbound() {
    let mut scope = RuleScope::any();
    scope.dst_port = Some(443);
    let rule = Rule::new("port-only".to_string(), Action::Allow, scope);

    // Outbound: it applies, as it always did.
    match TestEnv::new(vec![rule.clone()], dp_deny()).handle(&tcp_packet(443), &NO_META) {
        PacketOutcome::Deliver { verdict, .. } => assert_eq!(verdict.action, Action::Allow),
        other => panic!("expected Deliver, got {other:?}"),
    }
    // Inbound: it must not.
    match TestEnv::new(vec![rule], dp_deny()).handle(&tcp_packet(443), &INBOUND_META) {
        PacketOutcome::Deliver { verdict, .. } => assert_eq!(
            verdict.action,
            Action::Deny,
            "an undirected rule admitted inbound traffic"
        ),
        other => panic!("expected Deliver, got {other:?}"),
    }
}

/// An unparseable *inbound* packet takes `inbound_action`, which cannot be
/// Allow - not `no_ui_action`, which can.
#[test]
fn an_unparseable_inbound_packet_cannot_default_to_allow() {
    let policy = DefaultPolicy {
        no_ui_action: Action::Allow,
        timeout_action: Action::Allow,
        inbound_action: Action::Deny,
        prompt_timeout_secs: 15,
    };
    let env = TestEnv::new(vec![], policy);
    // Two bytes: a version nibble and nothing else to parse.
    match env.handle(&[0x45, 0x00], &INBOUND_META) {
        PacketOutcome::Silent(v) => assert_eq!(
            v,
            NfqVerdict::Drop,
            "a crafted inbound packet must not be the way round the inbound default"
        ),
        other => panic!("expected Silent, got {other:?}"),
    }
    // Outbound keeps taking no_ui_action, which here is Allow.
    match env.handle(&[0x45, 0x00], &NO_META) {
        PacketOutcome::Silent(v) => assert_eq!(v, NfqVerdict::Accept),
        other => panic!("expected Silent, got {other:?}"),
    }
}

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
    assert_eq!(env.stats.connections_allowed(), 0);
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
    assert_eq!(env.stats.connections_denied(), 0);
}

#[test]
fn no_rule_returns_prompt_with_policy_fallback() {
    let env = TestEnv::new(vec![], dp_deny());
    match env.handle(&tcp_packet(443), &NO_META) {
        PacketOutcome::Prompt {
            connection,
            process,
            fallback,
            ..
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
    assert_eq!(env.stats.connections_denied(), 0);
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
    assert_eq!(env.stats.connections_allowed(), 0);
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
    let meta = PacketMeta {
        uid: Some(0),
        ..NO_META
    };
    assert!(matches!(
        env.handle(&tcp_packet(53), &meta),
        PacketOutcome::Silent(NfqVerdict::Accept)
    ));
    assert_eq!(env.stats.connections_total(), 0);
}

#[test]
fn a_socket_hint_does_not_exempt_a_different_uid_from_policy() {
    let mut env = TestEnv::new(vec![deny_port_rule(53)], dp_deny());
    env.dns.self_pid = Some(4242);
    let meta = PacketMeta {
        uid: Some(1000),
        ..NO_META
    };
    match env.handle(&tcp_packet(53), &meta) {
        PacketOutcome::Deliver { verdict, .. } => assert_eq!(verdict.action, Action::Deny),
        other => panic!("a foreign UID must follow policy, got {other:?}"),
    }
}

#[test]
fn decisions_do_not_start_dns_enrichment_before_delivery() {
    struct CountingDns(std::sync::atomic::AtomicUsize);
    impl HostCache for CountingDns {
        fn is_self(&self, _: u32) -> bool {
            false
        }
        fn cached_host(&self, _: IpAddr) -> Option<(String, bool)> {
            None
        }
        fn enqueue(&self, _: IpAddr) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let dns = CountingDns(std::sync::atomic::AtomicUsize::new(0));
    let env = TestEnv::new(vec![deny_port_rule(443)], dp_deny());
    let deps = PipelineDeps {
        engine: &env.engine,
        stats: &env.stats,
        dns: &dns,
        resolver: &env.resolver,
    };
    assert!(matches!(
        handle_packet(&tcp_packet(443), &NO_META, &deps),
        PacketOutcome::Deliver { .. }
    ));
    assert_eq!(dns.0.load(Ordering::Relaxed), 0);
    env.engine.upsert_rule(allow_port_rule(80));
    let _ = handle_packet(&tcp_packet(80), &NO_META, &deps);
    assert_eq!(dns.0.load(Ordering::Relaxed), 0);
}

#[test]
fn blocked_packet_is_logged_without_a_live_feed_receiver() {
    let mut h = LoopHarness::new(vec![], vec![deny_port_rule(443)], dp_deny());
    drop(h.observed_rx);
    h.worker
        .as_mut()
        .unwrap()
        .handle_message(FakeMsg::new(7, tcp_packet(443)))
        .unwrap();
    let rows: Vec<_> = std::iter::from_fn(|| h.events.try_recv().ok()).collect();
    assert_eq!(
        rows.len(),
        1,
        "refusal must survive absent live-feed receivers"
    );
    assert_eq!(rows[0].action, "Deny");
    assert_eq!(rows[0].dst_ip.as_deref(), Some("5.6.7.8"));
    assert_eq!(rows[0].dst_port, Some(443));
}

#[test]
fn kernel_uid_gid_overrides_proc_values() {
    let env = TestEnv::new(vec![], dp_allow());
    let meta = PacketMeta {
        uid: Some(0),
        gid: Some(0),
        ..NO_META
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
        ..NO_META
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

#[test]
fn legacy_hostname_policy_refuses_independently_of_diagnostic_dns() {
    let named = |action| {
        let mut scope = RuleScope::any();
        scope.dst_host = Some("example.org".to_string());
        Rule::new("legacy-name", action, scope)
    };
    for action in [Action::Allow, Action::Deny, Action::Reject] {
        for host in [None, Some("example.org"), Some("alternate.example.org")] {
            for verified in [false, true] {
                let mut env = TestEnv::new(vec![named(action)], dp_allow());
                env.dns.host = host.map(str::to_owned);
                env.dns.host_verified = verified;
                match env.handle(&tcp_packet(443), &NO_META) {
                    PacketOutcome::Deliver {
                        connection,
                        verdict,
                        ..
                    } => {
                        assert_eq!(connection.dst_host.as_deref(), host);
                        assert_eq!(verdict.action, Action::Deny);
                    }
                    other => panic!("uncertain hostname policy must refuse, got {other:?}"),
                }
            }
        }
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
fn prompts_do_not_share_authorization_between_users_or_images() {
    let conn = conn_to(443, 5555);
    let mut owner = test_process(1, "/usr/bin/curl");
    owner.sha256 = Some("aa".repeat(32));
    let mut other = owner.clone();
    other.uid = Some(1001);
    assert_ne!(
        FlowKey::for_flow(&conn, &owner),
        FlowKey::for_flow(&conn, &other)
    );
    other.uid = owner.uid;
    other.sha256 = Some("bb".repeat(32));
    assert_ne!(
        FlowKey::for_flow(&conn, &owner),
        FlowKey::for_flow(&conn, &other)
    );
}

#[test]
fn prompt_release_checks_each_packets_current_policy() {
    let mut h = LoopHarness::new(vec![], vec![], dp_deny());
    let mut first = conn_to(443, 5555);
    first.src_port = 10000;
    let mut second = first.clone();
    second.src_port = 10001;
    let mut process = test_process(4242, "/usr/bin/curl");
    process.sha256 = Some("aa".repeat(32));
    h.worker()
        .park_for_prompt(
            FakeMsg::new(1, tcp_packet(443)),
            first,
            process.clone(),
            Verdict::default_deny(),
            None,
        )
        .unwrap();
    h.worker()
        .park_for_prompt(
            FakeMsg::new(2, tcp_packet(443)),
            second,
            process,
            Verdict::default_deny(),
            None,
        )
        .unwrap();
    let request = h.prompt_rx.try_recv().unwrap();
    let mut deny = deny_port_rule(443);
    deny.scope.src_port = Some(10001);
    h.worker().engine.upsert_rule(deny);
    h.worker()
        .resolve_prompt(PromptVerdict {
            prompt_id: request.prompt_id,
            verdict: Verdict::default_allow(),
        })
        .unwrap();
    assert_eq!(
        h.verdicts(),
        vec![(1, NfqVerdict::Accept), (2, NfqVerdict::Drop)]
    );
}

fn exe_rule(action: Action, exe: &str) -> Rule {
    let mut scope = RuleScope::any();
    scope.exe_path = Some(PathBuf::from(exe));
    Rule::new(format!("{action:?} {exe}"), action, scope)
}

/// Minimal IPv4/UDP packet: 1.2.3.4:5555 -> 5.6.7.8:`dst_port`.
fn udp_packet(dst_port: u16) -> Vec<u8> {
    let mut pkt = tcp_packet(dst_port);
    pkt.truncate(28);
    pkt[9] = 17;
    pkt
}

/// The process could not be attributed: no socket owner was found, as for
/// ambiguous UDP or an expired attribution budget.
fn unattributed(env: &mut TestEnv) {
    env.resolver.pid = None;
}

fn expect_undecided_prompt(outcome: PacketOutcome, rule: &Rule, fallback: Action) {
    match outcome {
        PacketOutcome::Prompt {
            undecided,
            fallback: f,
            ..
        } => {
            assert_eq!(undecided, Some(rule.id));
            assert_eq!(f.action, fallback);
            assert_eq!(f.source, VerdictSource::DefaultPolicy);
        }
        other => panic!("expected an undecided prompt, got {other:?}"),
    }
}

#[test]
fn an_unattributed_flow_under_a_program_allow_is_prompted_not_dropped() {
    let rule = exe_rule(Action::Allow, "/usr/bin/firefox");
    for policy in [dp_allow(), dp_deny()] {
        let no_ui_action = policy.no_ui_action;
        let mut env = TestEnv::new(vec![rule.clone()], policy);
        unattributed(&mut env);
        expect_undecided_prompt(env.handle(&tcp_packet(443), &NO_META), &rule, no_ui_action);
    }
}

#[test]
fn an_undecided_flow_is_prompted_while_paused() {
    // Pause means "stop asking about flows no rule is about"; a program
    // rule may be about this one.
    let mut rule = deny_port_rule(443);
    rule.scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
    let mut env = TestEnv::new(vec![rule.clone()], dp_allow());
    unattributed(&mut env);
    env.stats.set_paused(true);
    expect_undecided_prompt(env.handle(&tcp_packet(443), &NO_META), &rule, Action::Allow);
}

#[test]
fn ambiguous_udp_under_a_program_deny_is_prompted() {
    let rule = exe_rule(Action::Deny, "/usr/bin/x");
    let mut env = TestEnv::new(vec![rule.clone()], dp_deny());
    unattributed(&mut env);
    expect_undecided_prompt(env.handle(&udp_packet(53), &NO_META), &rule, Action::Deny);
}

#[test]
fn ambiguous_udp_with_no_rules_is_prompted() {
    let mut env = TestEnv::new(vec![], dp_deny());
    unattributed(&mut env);
    match env.handle(&udp_packet(53), &NO_META) {
        PacketOutcome::Prompt { undecided, .. } => assert_eq!(undecided, None),
        other => panic!("expected a prompt, got {other:?}"),
    }
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
    // An unknown execution cannot share authorization, even at one PID.
    assert_ne!(
        FlowKey::for_flow(&conn, &Process::unknown(7)),
        FlowKey::for_flow(&conn, &Process::unknown(7))
    );
    assert_ne!(
        FlowKey::for_flow(&conn, &Process::unknown(7)),
        FlowKey::for_flow(&conn, &Process::unknown(8))
    );
}

#[test]
fn digest_less_images_share_a_prompt_only_on_a_sealed_path() {
    let sealed = "/usr/bin/env";
    if !cfc_core::exe_path::is_root_sealed(std::path::Path::new(sealed)).unwrap_or(false) {
        return;
    }
    let conn = conn_to(443, 1111);
    let digest_less = |pid, exe: &str| Process {
        sha256: None,
        ..test_process(pid, exe)
    };
    // Over 64 MiB, so no digest: retransmits and siblings still share.
    assert_eq!(
        FlowKey::for_flow(&conn, &digest_less(1, sealed)),
        FlowKey::for_flow(&conn, &digest_less(2, sealed))
    );
    let other_user = Process {
        uid: Some(1001),
        ..digest_less(2, sealed)
    };
    assert_ne!(
        FlowKey::for_flow(&conn, &digest_less(1, sealed)),
        FlowKey::for_flow(&conn, &other_user)
    );
    // A path its user can rewrite is no identity without the digest.
    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("tool");
    std::fs::write(&tool, b"user image").unwrap();
    let tool = tool.to_str().unwrap();
    assert_ne!(
        FlowKey::for_flow(&conn, &digest_less(1, tool)),
        FlowKey::for_flow(&conn, &digest_less(1, tool))
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
    outdev: u32,
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
            outdev: 0,
            verdict: None,
        }
    }
}

impl PacketMessage for FakeMsg {
    fn outdev(&self) -> u32 {
        self.outdev
    }

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
    /// The event writer's end of the worker's [`EventSink`].
    events: mpsc::Receiver<crate::storage::EventRow>,
}

impl LoopHarness {
    fn new(script: Vec<std::io::Result<FakeMsg>>, rules: Vec<Rule>, policy: DefaultPolicy) -> Self {
        let log = Arc::new(Mutex::new(QueueLog::default()));
        let (prompt_tx, prompt_rx) = mpsc::channel(16);
        let (verdict_tx, verdict_rx) = std::sync::mpsc::channel();
        let (observed_tx, observed_rx) = broadcast::channel(16);
        let stats = Stats::new();
        let (sink, events) = EventSink::channel(256);
        let stop = Arc::new(AtomicBool::new(false));
        let worker = Worker {
            queue: FakeQueue {
                script: script.into(),
                log: log.clone(),
            },
            loopback_ifindex: 1,
            engine: Engine::new(RuleSet { rules }, Arc::new(std::sync::RwLock::new(policy))),
            rejecter: Rejecter::open(),
            prompt_tx,
            verdict_rx,
            observed_tx,
            stats: stats.clone(),
            events: sink,
            dns: Box::new(StubDns {
                self_pid: None,
                host: None,
                ..Default::default()
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
            events,
        }
    }

    fn with_event_queue_depth(mut self, depth: usize) -> Self {
        let (sink, events) = EventSink::channel(depth);
        self.worker().events = sink;
        self.events = events;
        self
    }

    /// Every row the worker has queued for the event writer so far.
    fn audited(&mut self) -> Vec<crate::storage::EventRow> {
        std::iter::from_fn(|| self.events.try_recv().ok()).collect()
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
fn parsed_refusals_are_queued_for_the_event_writer() {
    let mut reject = deny_port_rule(80);
    reject.action = Action::Reject;
    let mut h = LoopHarness::new(vec![], vec![deny_port_rule(443), reject], dp_deny());
    h.worker()
        .handle_message(FakeMsg::new(1, tcp_packet(443)))
        .unwrap();
    h.worker()
        .handle_message(FakeMsg::new(2, tcp_packet(80)))
        .unwrap();
    assert_eq!(
        h.verdicts(),
        vec![(1, NfqVerdict::Drop), (2, NfqVerdict::Drop)]
    );
    let actions: Vec<_> = h.audited().into_iter().map(|r| r.action).collect();
    assert_eq!(actions, vec!["Deny", "Reject"]);
    assert_eq!(
        h.observed_rx.try_recv().unwrap().verdict.action,
        Action::Deny
    );
    assert_eq!(
        h.observed_rx.try_recv().unwrap().verdict.action,
        Action::Reject
    );
}

#[test]
fn a_full_event_queue_costs_the_row_not_the_packet_or_the_worker() {
    let mut h = LoopHarness::new(
        vec![
            Ok(FakeMsg::new(1, tcp_packet(443))),
            Ok(FakeMsg::new(2, tcp_packet(443))),
            Ok(FakeMsg::new(3, tcp_packet(80))),
        ],
        vec![deny_port_rule(443), allow_port_rule(80)],
        dp_deny(),
    )
    .with_event_queue_depth(1);
    let sink = h.worker().events.clone();
    let done = h.start();
    assert!(wait_until(|| h.verdicts().len() == 3));
    h.stop_and_expect_ok(&done);
    assert_eq!(
        h.verdicts(),
        vec![
            (1, NfqVerdict::Drop),
            (2, NfqVerdict::Drop),
            (3, NfqVerdict::Accept)
        ]
    );
    assert_eq!(sink.dropped(), 1);
    assert_eq!(h.audited().len(), 1);
    assert_eq!(h.stats.connections_total(), 3);
}

#[test]
fn prompt_refusals_and_unavailable_router_use_the_same_audit_gate() {
    let mut h = LoopHarness::new(vec![], vec![], dp_deny());
    h.worker()
        .handle_message(FakeMsg::new(1, tcp_packet(443)))
        .unwrap();
    let prompt = h.prompt_rx.try_recv().unwrap();
    h.worker()
        .resolve_prompt(PromptVerdict {
            prompt_id: prompt.prompt_id,
            verdict: Verdict::from_policy(Action::Reject),
        })
        .unwrap();
    h.prompt_rx.close();
    h.worker()
        .handle_message(FakeMsg::new(2, tcp_packet(80)))
        .unwrap();
    assert_eq!(
        h.verdicts(),
        vec![(1, NfqVerdict::Drop), (2, NfqVerdict::Drop)]
    );
    let rows = h.audited();
    assert!(rows.iter().any(|r| r.action == "Reject"));
    assert!(rows.iter().any(|r| r.action == "Deny"));
    assert_eq!(h.stats.connections_denied(), 2);
}

#[test]
fn a_rule_allow_added_while_parked_beats_the_fallback_but_not_the_user() {
    for (answer, expected) in [
        (Verdict::from_policy(Action::Deny), NfqVerdict::Accept),
        (
            Verdict {
                action: Action::Deny,
                source: VerdictSource::UserPrompt,
            },
            NfqVerdict::Drop,
        ),
    ] {
        let mut h = LoopHarness::new(vec![], vec![], dp_deny());
        h.worker()
            .handle_message(FakeMsg::new(1, tcp_packet(443)))
            .unwrap();
        let prompt = h.prompt_rx.try_recv().unwrap();
        let rule = allow_port_rule(443);
        let id = rule.id;
        h.worker().engine.upsert_rule(rule);
        h.worker()
            .resolve_prompt(PromptVerdict {
                prompt_id: prompt.prompt_id,
                verdict: answer,
            })
            .unwrap();
        assert_eq!(h.verdicts(), vec![(1, expected)], "{answer:?}");
        // The rule is credited only when its answer was the one applied.
        let hits = h.worker().engine.snapshot().rules[0].hit_count;
        assert_eq!(
            hits,
            u64::from(expected == NfqVerdict::Accept),
            "{answer:?}"
        );
        assert_eq!(h.worker().engine.snapshot().rules[0].id, id);
    }
}

#[test]
fn loopback_unmatched_flows_keep_the_nonprompting_local_default() {
    // The output interface, including local host addresses, defines this
    // exception. IPv4 loopback, IPv6 loopback, and a local host address
    // must all retain the same desktop IPC behavior.
    let mut ipv4 = tcp_packet(53);
    ipv4[12..16].copy_from_slice(&[127, 0, 0, 1]);
    ipv4[16..20].copy_from_slice(&[127, 0, 0, 53]);
    let mut ipv6 = vec![0u8; 44];
    ipv6[0] = 0x60;
    ipv6[6] = 6;
    ipv6[23] = 1;
    ipv6[39] = 1;
    ipv6[40..42].copy_from_slice(&5555u16.to_be_bytes());
    ipv6[42..44].copy_from_slice(&53u16.to_be_bytes());
    for payload in [ipv4, ipv6, tcp_packet(53)] {
        let mut h = LoopHarness::new(vec![], vec![], dp_deny());
        let mut msg = FakeMsg::new(1, payload);
        msg.outdev = 1;
        h.worker().handle_message(msg).unwrap();
        assert_eq!(h.verdicts(), vec![(1, NfqVerdict::Accept)]);
        assert!(h.prompt_rx.try_recv().is_err(), "local IPC must not prompt");
        assert_eq!(h.stats.connections_allowed(), 1);
    }
}

#[test]
fn loopback_addresses_without_the_local_output_interface_still_prompt() {
    for outdev in [0, 2] {
        let mut h = LoopHarness::new(vec![], vec![], dp_deny());
        let mut payload = tcp_packet(53);
        payload[16..20].copy_from_slice(&[127, 0, 0, 53]);
        let mut msg = FakeMsg::new(1, payload);
        msg.outdev = outdev;
        h.worker().handle_message(msg).unwrap();
        assert!(h.verdicts().is_empty());
        assert!(h.prompt_rx.try_recv().is_ok());
    }
}

#[test]
fn loopback_closed_rules_are_audited_even_when_paused() {
    for action in [Action::Deny, Action::Reject] {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        let rule = Rule::new("local application refusal", action, scope);
        let mut h = LoopHarness::new(vec![], vec![rule], dp_deny());
        h.stats.set_paused(true);
        let mut payload = tcp_packet(53);
        // Policy needs only ports. No complete TCP header keeps refusal
        // injection inert while testing the real verdict and audit path.
        payload.truncate(24);
        let mut msg = FakeMsg::new(1, payload);
        msg.outdev = 1;
        h.worker().handle_message(msg).unwrap();
        assert_eq!(h.verdicts(), vec![(1, NfqVerdict::Drop)]);
        assert_eq!(h.audited().len(), 1);
        assert_eq!(h.observed_rx.try_recv().unwrap().verdict.action, action);
        assert!(h.prompt_rx.try_recv().is_err());
    }
}

/// A [`LoopHarness`] whose resolver attributes nothing.
fn unattributed_harness(rules: Vec<Rule>, policy: DefaultPolicy) -> LoopHarness {
    let mut h = LoopHarness::new(vec![], rules, policy);
    h.worker().resolver = Box::new(StubResolver {
        pid: None,
        process: Process::unknown(0),
        socket_lookups: std::sync::atomic::AtomicUsize::new(0),
    });
    h
}

#[test]
fn an_undecided_loopback_flow_is_prompted() {
    let rule = exe_rule(Action::Deny, "/usr/bin/curl");
    let mut h = unattributed_harness(vec![rule.clone()], dp_deny());
    h.stats.set_paused(true);
    let mut msg = FakeMsg::new(1, tcp_packet(53));
    msg.outdev = 1;
    h.worker().handle_message(msg).unwrap();
    assert!(h.verdicts().is_empty(), "the packet waits for the answer");
    let req = h.prompt_rx.try_recv().expect("prompt dispatched");
    assert_eq!(req.undecided, Some(rule.id));
}

#[test]
fn resolve_prompt_applies_the_users_allow_to_an_undecided_flow() {
    // Before, the per-packet re-check turned an undecided flow into a
    // Deny whatever the user answered.
    let rule = exe_rule(Action::Deny, "/usr/bin/curl");
    let mut h = unattributed_harness(vec![rule.clone()], dp_deny());
    h.worker()
        .handle_message(FakeMsg::new(1, tcp_packet(443)))
        .unwrap();
    let req = h.prompt_rx.try_recv().expect("prompt dispatched");
    h.send_verdict(
        req.prompt_id,
        Verdict {
            action: Action::Allow,
            source: VerdictSource::UserPrompt,
        },
    );
    h.worker().drain_verdicts().unwrap();
    assert_eq!(h.verdicts(), vec![(1, NfqVerdict::Accept)]);
    let observed = h.observed_rx.try_recv().unwrap();
    assert_eq!(observed.undecided, Some(rule.id));
    assert_eq!(observed.rule_id(), Some(rule.id));
}

#[test]
fn an_undecided_prompt_past_the_cap_takes_no_ui_action() {
    let rule = exe_rule(Action::Deny, "/usr/bin/curl");
    let mut h = unattributed_harness(vec![rule.clone()], dp_deny());
    // Unknown identities never share a prompt, so every packet parks its
    // own until the backlog cap.
    for i in 0..MAX_PARKED_PROMPTS {
        h.worker()
            .handle_message(FakeMsg::new(i as u32, tcp_packet(443)))
            .unwrap();
        while h.prompt_rx.try_recv().is_ok() {}
    }
    assert!(h.verdicts().is_empty());
    let overflow = MAX_PARKED_PROMPTS as u32;
    h.worker()
        .handle_message(FakeMsg::new(overflow, tcp_packet(443)))
        .unwrap();
    assert_eq!(h.verdicts(), vec![(overflow, NfqVerdict::Drop)]);
    let audited = h.audited();
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].source, "default");
    assert_eq!(audited[0].rule_id, Some(rule.id.to_string()));
}

#[test]
fn loopback_keeps_the_root_daemon_dns_exception() {
    let mut h = LoopHarness::new(vec![], vec![deny_port_rule(53)], dp_deny());
    h.worker().dns = Box::new(StubDns {
        self_pid: Some(4242),
        ..Default::default()
    });
    let mut msg = FakeMsg::new(1, tcp_packet(53));
    msg.outdev = 1;
    msg.uid = Some(0);
    h.worker().handle_message(msg).unwrap();
    assert_eq!(h.verdicts(), vec![(1, NfqVerdict::Accept)]);
    assert!(h.prompt_rx.try_recv().is_err());
    assert_eq!(h.stats.connections_total(), 0);
}

/// Counts reverse-DNS lookups `deliver` asks for.
struct CountingDns(Arc<std::sync::atomic::AtomicUsize>);
impl HostCache for CountingDns {
    fn is_self(&self, _: u32) -> bool {
        false
    }
    fn cached_host(&self, _: IpAddr) -> Option<(String, bool)> {
        None
    }
    fn enqueue(&self, _: IpAddr) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn refused_deliveries_ask_for_no_reverse_dns() {
    // A refused process must not make the daemon resolve an address it
    // chose: that is a DNS side channel out of a denied program.
    let mut reject = deny_port_rule(443);
    reject.action = Action::Reject;
    for rule in [deny_port_rule(443), reject] {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut h = LoopHarness::new(vec![], vec![rule], dp_deny());
        h.worker().dns = Box::new(CountingDns(calls.clone()));
        h.worker()
            .handle_message(FakeMsg::new(1, tcp_packet(443)))
            .unwrap();
        assert_eq!(h.verdicts(), vec![(1, NfqVerdict::Drop)]);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn allowed_delivery_enriches_and_counts_once_without_a_refusal_audit() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut h = LoopHarness::new(vec![], vec![allow_port_rule(443)], dp_deny());
    h.worker().dns = Box::new(CountingDns(calls.clone()));
    h.worker()
        .handle_message(FakeMsg::new(1, tcp_packet(443)))
        .unwrap();
    assert_eq!(h.verdicts(), vec![(1, NfqVerdict::Accept)]);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(h.stats.connections_allowed(), 1);
    assert_eq!(
        h.observed_rx.try_recv().unwrap().verdict.action,
        Action::Allow
    );
    assert!(h.audited().is_empty(), "Allow rows come off the live feed");
}

#[test]
fn live_feed_lag_does_not_lose_parsed_refusal_audits() {
    let mut h = LoopHarness::new(vec![], vec![deny_port_rule(443)], dp_deny());
    for id in 0..64 {
        h.worker()
            .handle_message(FakeMsg::new(id, tcp_packet(443)))
            .unwrap();
    }
    assert!(matches!(
        h.observed_rx.try_recv(),
        Err(broadcast::error::TryRecvError::Lagged(_))
    ));
    assert_eq!(h.audited().len(), 64);
    assert_eq!(h.verdicts().len(), 64);
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
    // Both packet verdicts are counted even though the prompt is shared.
    assert_eq!(h.stats.connections_denied(), 2);

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
    h.worker()
        .park_for_prompt(
            FakeMsg::new(4, tcp_packet(443)),
            conn_to(443, 1111),
            test_process(4242, "/usr/bin/curl"),
            Verdict::default_deny(),
            None,
        )
        .unwrap();
    let req = h.prompt_rx.try_recv().expect("prompt dispatched");
    assert!(h.verdicts().is_empty());

    h.send_verdict(req.prompt_id, Verdict::default_allow());
    h.worker().idle_wait().unwrap();

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
    h.worker().idle_wait().unwrap();
    assert!(!h.worker().verdict_channel_open);

    // ...after which the wait is paced by hand.
    let started = Instant::now();
    h.worker().idle_wait().unwrap();
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

    h.worker()
        .park_for_prompt(
            FakeMsg::new(5, tcp_packet(443)),
            conn,
            proc,
            Verdict::default_deny(),
            None,
        )
        .unwrap();

    let req = h.prompt_rx.try_recv().expect("flow re-prompted");
    assert_eq!(req.prompt_id, 1);
    assert_eq!(h.worker().pending_flows.get(&flow), Some(&1));
    assert_eq!(h.worker().waiters.len(), 1);
    assert!(h.verdicts().is_empty(), "the packet is parked, not dropped");
}
