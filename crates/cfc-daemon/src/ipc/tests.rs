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
fn gate_table() {
    // (peer uid, daemon uid, group proved) -> standing
    let cases = [
        (0, 0, false, Gate::Privileged),
        (0, 0, true, Gate::Privileged),
        (1000, 1000, false, Gate::Privileged),
        (0, 1000, false, Gate::Privileged),
        (1000, 0, true, Gate::NeedOfficial),
        (1000, 0, false, Gate::DenyGroup),
    ];
    for (peer, own, group_ok, want) in cases {
        assert_eq!(gate(peer, own, group_ok), want, "{peer} {own} {group_ok}");
    }
}

// -- the service's authorization table ---------------------------------

const OWN_UID: u32 = 999;
const GROUP_GID: u32 = 4242;
/// The pid the stub official check accepts.
const OFFICIAL_PID: i32 = 77;

/// An official client whose binary is replaced after its first check.
const UPGRADED_PID: i32 = 4243;

fn stub_official(peer: &PeerId, _: &[PathBuf]) -> Result<PathBuf, String> {
    static UPGRADED_CHECKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if peer.pid == Some(UPGRADED_PID) {
        return if UPGRADED_CHECKS.fetch_add(1, Ordering::Relaxed) == 0 {
            Ok(PathBuf::from("/usr/bin/colony-firewall-tray"))
        } else {
            Err(
                "this colony-firewall-tray is not the installed one (restart it after an upgrade)"
                    .into(),
            )
        };
    }
    if peer.pid == Some(OFFICIAL_PID) {
        Ok(PathBuf::from("/usr/bin/colony-firewall"))
    } else {
        Err("not the installed app".into())
    }
}

fn polkit_allows(
    _: PeerId,
    _: &'static str,
) -> futures::future::BoxFuture<'static, Result<(), String>> {
    Box::pin(async { Ok(()) })
}

fn polkit_denies(
    _: PeerId,
    _: &'static str,
) -> futures::future::BoxFuture<'static, Result<(), String>> {
    Box::pin(async { Err("authorization dialog dismissed".to_string()) })
}

fn polkit_must_not_be_asked(
    _: PeerId,
    action: &'static str,
) -> futures::future::BoxFuture<'static, Result<(), String>> {
    panic!("polkit was asked for {action}")
}

fn service(require_group: bool) -> FirewallService {
    service_with(require_group, polkit_allows)
}

fn service_with(require_group: bool, polkit: PolkitCheck) -> FirewallService {
    let store = RuleStore::open_in_memory().unwrap();
    let policy: SharedPolicy = Arc::new(std::sync::RwLock::new(crate::config::DefaultPolicy {
        no_ui_action: cfc_core::Action::Deny,
        timeout_action: cfc_core::Action::Deny,
        inbound_action: cfc_core::Action::Deny,
        prompt_timeout_secs: 3600,
    }));
    let engine = Engine::new(store.snapshot().unwrap(), policy.clone());
    let stats = Stats::new();
    let (verdict_tx, verdicts) = std::sync::mpsc::channel();
    // Verdicts are not asserted here; keep the receiver alive.
    std::mem::forget(verdicts);
    FirewallService {
        router: PromptRouter::new(policy.clone(), stats.clone(), verdict_tx),
        engine,
        store,
        observed_tx: broadcast::channel(16).0,
        stats,
        policy,
        control: Control {
            auth: SocketAuth {
                group: "cfc-test".into(),
                group_gid: Some(GROUP_GID),
                group_gated: true,
                require_group,
            },
            own_uid: OWN_UID,
            official_clients: Arc::from(Vec::new()),
            official: stub_official,
        },
        polkit,
        audience: Arc::new(PromptAudience::default()),
        resume_at_ms: Arc::new(AtomicI64::new(0)),
        pause_default_secs: 600,
        dry_run: true,
    }
}

fn peer(uid: u32, gid: u32, pid: i32) -> PeerId {
    PeerId {
        uid,
        gid,
        pid: Some(pid),
        starttime: None,
        sock_ino: None,
    }
}

fn request<T>(message: T, peer: PeerId) -> Request<T> {
    let mut req = Request::new(message);
    req.extensions_mut().insert(peer);
    req
}

fn rule_pb() -> RuleInfo {
    let mut rule = cfc_core::Rule::new(
        "smtp",
        cfc_core::Action::Deny,
        cfc_core::RuleScope {
            dst_port: Some(25),
            ..cfc_core::RuleScope::any()
        },
    );
    rule.name = "smtp".into();
    convert::rule_to_pb(&rule)
}

/// Which change RPCs `peer` got through, in the order UpsertRule,
/// DeleteRule, SetPaused, ApplyRules. A refusal must be
/// PERMISSION_DENIED; any other error fails the test.
async fn changes(svc: &FirewallService, peer: PeerId) -> [bool; 4] {
    fn passed<T>(result: Result<T, Status>) -> bool {
        match result {
            Ok(_) => true,
            Err(status) => {
                assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}");
                false
            }
        }
    }
    let upsert = svc
        .upsert_rule(request(
            UpsertRuleRequest {
                rule: Some(rule_pb()),
            },
            peer,
        ))
        .await;
    let delete = svc
        .delete_rule(request(
            DeleteRuleRequest {
                id: uuid::Uuid::new_v4().to_string(),
            },
            peer,
        ))
        .await;
    let pause = svc
        .set_paused(request(
            SetPausedRequest {
                paused: false,
                duration_secs: 0,
            },
            peer,
        ))
        .await;
    let apply = svc
        .apply_rules(request(
            ApplyRulesRequest {
                rules: vec![rule_pb()],
                replace: false,
            },
            peer,
        ))
        .await;
    [passed(upsert), passed(delete), passed(pause), passed(apply)]
}

async fn reads(svc: &FirewallService, peer: PeerId) {
    svc.list_rules(request(ListRulesRequest {}, peer))
        .await
        .unwrap();
    svc.get_status(request(StatusRequest {}, peer))
        .await
        .unwrap();
    svc.list_events(request(ListEventsRequest::default(), peer))
        .await
        .unwrap();
    svc.stream_connections(request(SubscribeRequest::default(), peer))
        .await
        .unwrap();
    svc.stream_prompts(request(SubscribeRequest::default(), peer))
        .await
        .unwrap();
}

#[tokio::test]
async fn authorization_table() {
    let root = peer(0, 0, 1);
    let own = peer(OWN_UID, OWN_UID, 2);
    let official_member = peer(1000, GROUP_GID, OFFICIAL_PID);
    let official_outsider = peer(1001, 1001, OFFICIAL_PID);
    let read_only_member = peer(1000, GROUP_GID, 5);
    let all = [true; 4];
    let none = [false; 4];

    let svc = service(true);
    for (who, want) in [
        (root, all),
        (own, all),
        (official_member, all),
        (official_outsider, none),
        (read_only_member, none),
    ] {
        reads(&svc, who).await;
        assert_eq!(changes(&svc, who).await, want, "{who:?}");
    }

    // require_group = false waives the group check, never the image check.
    let svc = service(false);
    assert_eq!(changes(&svc, official_outsider).await, all);
    assert_eq!(changes(&svc, read_only_member).await, none);
    assert_eq!(changes(&svc, peer(1002, 1002, 6)).await, none);

    // Pause and import need polkit from the official client, and only
    // from it: a refusal there leaves the single-rule edits alone.
    let svc = service_with(true, polkit_denies);
    assert_eq!(
        changes(&svc, official_member).await,
        [true, true, false, false]
    );
    assert_eq!(changes(&svc, root).await, all);
    assert_eq!(changes(&svc, own).await, all);
}

#[tokio::test]
async fn polkit_is_never_asked_for_root_or_for_prompt_answers() {
    let svc = service_with(true, polkit_must_not_be_asked);
    for who in [peer(0, 0, 1), peer(OWN_UID, OWN_UID, 2)] {
        assert_eq!(changes(&svc, who).await, [true; 4]);
    }
    let official = peer(1000, GROUP_GID, OFFICIAL_PID);
    let [upsert, delete, ..] = changes_without_elevation(&svc, official).await;
    assert!(upsert && delete);
    let _ui = pending_prompt(&svc).await;
    assert!(
        svc.submit_verdict(answer(official))
            .await
            .unwrap()
            .into_inner()
            .accepted
    );
}

/// UpsertRule and DeleteRule only.
async fn changes_without_elevation(svc: &FirewallService, peer: PeerId) -> [bool; 2] {
    let upsert = svc
        .upsert_rule(request(
            UpsertRuleRequest {
                rule: Some(rule_pb()),
            },
            peer,
        ))
        .await
        .is_ok();
    let delete = svc
        .delete_rule(request(
            DeleteRuleRequest {
                id: uuid::Uuid::new_v4().to_string(),
            },
            peer,
        ))
        .await
        .is_ok();
    [upsert, delete]
}

#[tokio::test]
async fn a_denied_polkit_leaves_the_firewall_unpaused() {
    let svc = service_with(true, polkit_denies);
    let official = peer(1000, GROUP_GID, OFFICIAL_PID);
    let status = svc
        .set_paused(request(
            SetPausedRequest {
                paused: true,
                duration_secs: 60,
            },
            official,
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(
        status.message().contains("dismissed"),
        "{}",
        status.message()
    );
    assert!(status.message().contains(crate::polkit::PAUSE));
    assert!(!svc.stats.is_paused());

    let status = svc
        .apply_rules(request(
            ApplyRulesRequest {
                rules: vec![rule_pb()],
                replace: true,
            },
            official,
        ))
        .await
        .unwrap_err();
    assert!(status.message().contains(crate::polkit::IMPORT_RULES));
    assert_eq!(svc.engine.rule_count(), 0, "the store is unchanged");
}

#[tokio::test]
async fn resume_also_requires_polkit() {
    let svc = service_with(true, polkit_denies);
    svc.set_paused(request(
        SetPausedRequest {
            paused: true,
            duration_secs: 60,
        },
        peer(0, 0, 1),
    ))
    .await
    .unwrap();
    let status = svc
        .set_paused(request(
            SetPausedRequest {
                paused: false,
                duration_secs: 0,
            },
            peer(1000, GROUP_GID, OFFICIAL_PID),
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(svc.stats.is_paused(), "still paused");
}

#[tokio::test]
async fn a_read_only_refusal_says_why_and_what_to_use_instead() {
    let svc = service(true);
    let status = svc
        .set_paused(request(
            SetPausedRequest::default(),
            peer(1000, GROUP_GID, 5),
        ))
        .await
        .unwrap_err();
    assert!(status
        .message()
        .starts_with("read-only access: not the installed app."));
    assert!(
        status.message().contains("sudo cfc"),
        "{}",
        status.message()
    );
    assert!(!svc.stats.is_paused());

    let status = svc
        .set_paused(request(
            SetPausedRequest::default(),
            peer(1001, 1001, OFFICIAL_PID),
        ))
        .await
        .unwrap_err();
    assert!(
        status.message().contains("member of group 'cfc-test'"),
        "{}",
        status.message()
    );
}

/// A pending prompt about uid 1000's process, with an answering UI so it
/// waits, and uid 1000 in its audience.
async fn pending_prompt(svc: &FirewallService) -> crate::prompts::PromptSubscription {
    use std::net::{IpAddr, Ipv4Addr};
    let ui = svc.router.subscribe(1000, true);
    let (tx, rx) = mpsc::channel(4);
    tokio::spawn(crate::prompts::run_router_task(rx, svc.router.clone()));
    let mut process = cfc_core::Process::unknown(4321);
    process.uid = Some(1000);
    tx.send(PromptRequest {
        prompt_id: 5,
        connection: cfc_core::Connection::new(
            cfc_core::Protocol::Tcp,
            cfc_core::Direction::Outbound,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            40000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        ),
        process,
        undecided: None,
    })
    .await
    .unwrap();
    while svc.stats.prompts_pending() == 0 {
        tokio::task::yield_now().await;
    }
    svc.audience.record(5, 1000);
    ui
}

fn answer(peer: PeerId) -> Request<VerdictRequest> {
    request(
        VerdictRequest {
            prompt_id: "5".into(),
            action: cfc_proto::v1::Action::Allow as i32,
            duration: cfc_proto::v1::Duration::Once as i32,
            persist_scope: None,
        },
        peer,
    )
}

/// `allow dst_port 443` for every program, or for `exe` when given.
fn allow_pb(exe: Option<&str>, enabled: bool) -> RuleInfo {
    let mut rule = cfc_core::Rule::new(
        "https",
        cfc_core::Action::Allow,
        cfc_core::RuleScope {
            dst_port: Some(443),
            exe_sha256: exe.map(str::to_string),
            ..cfc_core::RuleScope::any()
        },
    );
    rule.enabled = enabled;
    convert::rule_to_pb(&rule)
}

async fn upsert(svc: &FirewallService, rule: RuleInfo, who: PeerId) -> Result<(), Status> {
    svc.upsert_rule(request(UpsertRuleRequest { rule: Some(rule) }, who))
        .await
        .map(drop)
}

#[test]
fn only_an_enabled_allow_naming_no_program_opens_for_every_program() {
    let rule = |pb: RuleInfo| convert::rule_from_pb(&pb).unwrap();
    assert!(opens_for_every_program(&rule(allow_pb(None, true))));
    assert!(!opens_for_every_program(&rule(allow_pb(None, false))));
    let hash = "a".repeat(64);
    assert!(!opens_for_every_program(&rule(allow_pb(Some(&hash), true))));
    assert!(!opens_for_every_program(&rule(rule_pb())), "a Deny");
}

#[tokio::test]
async fn an_allow_for_every_program_needs_polkit_from_the_app() {
    let official = peer(1000, GROUP_GID, OFFICIAL_PID);
    let svc = service_with(true, polkit_denies);
    let status = upsert(&svc, allow_pb(None, true), official)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(
        status.message().contains(crate::polkit::GENERIC_ALLOW),
        "{}",
        status.message()
    );
    assert_eq!(svc.engine.rule_count(), 0, "nothing was stored");

    // Granted, it is stored; a disabled one, a program's Allow and a
    // Deny never ask, and neither does root.
    let svc = service_with(true, polkit_allows);
    upsert(&svc, allow_pb(None, true), official).await.unwrap();
    let svc = service_with(true, polkit_must_not_be_asked);
    let hash = "a".repeat(64);
    upsert(&svc, allow_pb(None, false), official).await.unwrap();
    upsert(&svc, allow_pb(Some(&hash), true), official)
        .await
        .unwrap();
    upsert(&svc, rule_pb(), official).await.unwrap();
    upsert(&svc, allow_pb(None, true), peer(0, 0, 1))
        .await
        .unwrap();
    assert_eq!(svc.engine.rule_count(), 4);
}

#[tokio::test]
async fn a_prompt_answer_customized_to_every_program_needs_polkit() {
    let svc = service_with(true, polkit_denies);
    let _ui = pending_prompt(&svc).await;
    let mut req = answer(peer(1000, GROUP_GID, OFFICIAL_PID));
    req.get_mut().duration = cfc_proto::v1::Duration::Always as i32;
    req.get_mut().persist_scope = allow_pb(None, true).scope;
    let reply = svc.submit_verdict(req).await.unwrap().into_inner();
    assert!(reply.accepted, "the answer itself still applies");
    assert!(reply.persisted_rule_id.is_empty());
    assert!(
        reply.persist_error.contains(crate::polkit::GENERIC_ALLOW),
        "{}",
        reply.persist_error
    );
    assert_eq!(svc.engine.rule_count(), 0);
}

#[tokio::test]
async fn an_upgraded_client_stops_counting_as_a_ui_at_its_next_prompt() {
    use std::net::{IpAddr, Ipv4Addr};
    let svc = service(true);
    let mut stream = svc
        .stream_prompts(request(
            SubscribeRequest::default(),
            peer(1000, GROUP_GID, UPGRADED_PID),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(svc.router.has_answering_ui(1000), "official at subscribe");

    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(crate::prompts::run_router_task(rx, svc.router.clone()));
    let mut process = cfc_core::Process::unknown(4321);
    process.uid = Some(1000);
    tx.send(PromptRequest {
        prompt_id: 9,
        connection: cfc_core::Connection::new(
            cfc_core::Protocol::Tcp,
            cfc_core::Direction::Outbound,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            40000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        ),
        process,
        undecided: None,
    })
    .await
    .unwrap();

    let status = stream.next().await.unwrap().unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(status.message().contains("restart"), "{}", status.message());
    assert!(stream.next().await.is_none(), "the stream ended");
    for _ in 0..1000 {
        if !svc.router.has_answering_ui(1000) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(!svc.router.has_answering_ui(1000), "no longer a UI");
    assert!(!svc.audience.allows(9, 1000), "and never told the id");
}

#[tokio::test]
async fn read_only_peer_cannot_answer_even_its_own_prompt() {
    let svc = service(true);
    let _ui = pending_prompt(&svc).await;
    let status = svc
        .submit_verdict(answer(peer(1000, GROUP_GID, 5)))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(svc.stats.prompts_pending(), 1, "the prompt still waits");
}

#[tokio::test]
async fn official_peer_answers_without_password() {
    let svc = service(true);
    let _ui = pending_prompt(&svc).await;
    let reply = svc
        .submit_verdict(answer(peer(1000, GROUP_GID, OFFICIAL_PID)))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.accepted);
    assert_eq!(svc.stats.prompts_pending(), 0);
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
        undecided: None,
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
    sink.push(convert::event_row_from_observed(&blocked));
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
    let row = convert::event_row_from_observed(&blocked);
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
