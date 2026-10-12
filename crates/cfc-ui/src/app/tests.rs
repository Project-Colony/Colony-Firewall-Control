use super::*;
use crate::editor::build_rule_from_editor;
use crate::editor::tests::prompt_event;
use crate::status_log;

#[test]
fn backoff_is_bounded_between_three_and_five_seconds() {
    assert_eq!(backoff_secs(0), 3);
    assert_eq!(backoff_secs(1), 4);
    assert_eq!(backoff_secs(2), 5);
    assert_eq!(backoff_secs(50), 5);
    assert_eq!(backoff_secs(u32::MAX), 5);
}

/// Issue #46: "make rule" on a LIVE row must either send the rule or say
/// why not, and the rule it sends for an identified program must have
/// the CLI's scope (program, port, protocol), not a hostname or one IP.
#[test]
fn live_seeded_rule_is_sent_or_reported() {
    use proto::Protocol::{Icmp, Tcp, Udp};
    let rows: [(&str, &str, u32, proto::Protocol); 8] = [
        ("/usr/bin/curl", "93.184.216.34", 443, Tcp),
        ("/usr/bin/curl", "2001:db8::1", 443, Tcp),
        ("/usr/bin/curl", "9.9.9.9", 53, Udp),
        ("/usr/bin/curl", "93.184.216.34", 0, Icmp),
        (cfc_client::convert::UNKNOWN_EXE, "93.184.216.34", 443, Tcp),
        ("", "93.184.216.34", 443, Tcp),
        ("relative/path", "93.184.216.34", 443, Tcp),
        (
            cfc_client::convert::UNKNOWN_EXE,
            "",
            0,
            proto::Protocol::Unspecified,
        ),
    ];
    for (exe, dst_ip, dst_port, protocol) in rows {
        let (mut app, _) = App::new();
        let _ = app.update(Message::MakeRuleFromEvent {
            exe: exe.into(),
            src_ip: "10.0.0.2".into(),
            dst_ip: dst_ip.into(),
            dst_port,
            protocol: protocol as i32,
            direction: 0,
        });
        let ed = app.editor.as_ref().expect("editor opened");
        if let Ok(rule) = build_rule_from_editor(ed) {
            let scope = rule.scope.unwrap();
            assert!(scope.dst_host.is_empty(), "{exe} {dst_ip}");
            if cfc_client::convert::exe_is_rule_scopable(exe) {
                assert_eq!(scope.exe_path, exe);
                assert!(scope.dst_net.is_empty(), "{exe} {dst_ip}");
                assert_eq!(scope.has_dst_port, dst_port != 0);
                assert!(scope.has_protocol);
            } else {
                assert!(scope.exe_path.is_empty(), "{exe:?} never reaches a rule");
            }
        }
        let errors_before = app
            .log
            .iter()
            .filter(|e| e.severity == status_log::Severity::Error)
            .count();
        let sent = app.update(Message::SaveRule).units();
        let errors = app
            .log
            .iter()
            .filter(|e| e.severity == status_log::Severity::Error)
            .count();
        assert!(
            sent == 1 || errors > errors_before,
            "{exe:?} {dst_ip}: Save neither sent the rule nor said why"
        );
    }
}

#[test]
fn a_failed_connection_logs_the_actionable_reason_once() {
    let detail = "permission denied on /run/colony-firewall/cfc.sock - add your user to \
                  the colony-firewall group (sudo usermod -aG colony-firewall $USER) then \
                  log out and back in, or run as root";
    let mut log = StatusLog::default();
    // Four retry rounds against a daemon that stays down.
    for i in 0..4 {
        log.warn(format::unreachable_log_line(detail), 1_000 + i);
    }
    assert_eq!(log.len(), 1, "retries must coalesce, not scroll the ring");
    let entry = log.iter().next().unwrap();
    assert_eq!(entry.count, 4);
    assert!(entry.display().contains("colony-firewall group"));
    assert!(entry.display().ends_with("(x4)"));
}

#[test]
fn customization_waits_for_a_verdict_and_drops_stale_actions() {
    let (mut app, _) = App::new();
    let event = prompt_event();
    app.prompts.push(PromptCard::new(event.clone(), 0));
    let task = app.update(Message::CustomizePromptRule(event.prompt_id.clone()));
    assert_eq!(task.units(), 0, "opening the editor issues no verdict RPC");
    assert_eq!(app.prompts.len(), 1, "the prompt remains pending");
    assert_eq!(
        app.editor.as_ref().unwrap().prompt_id.as_ref(),
        Some(&event.prompt_id)
    );
    let _ = app.update(Message::PromptStreamEnded("disconnected".into()));
    assert!(app.prompts.is_empty());
    assert!(
        app.editor.as_ref().unwrap().prompt_id.is_none(),
        "the edits stay, as a plain rule"
    );
    assert_eq!(
        app.update(Message::CustomizePromptRule(event.prompt_id))
            .units(),
        0
    );
    assert!(app.editor.as_ref().unwrap().prompt_id.is_none());
}

#[test]
fn an_expired_prompt_keeps_its_customization_as_a_new_rule() {
    let (mut app, _) = App::new();
    let event = prompt_event();
    app.prompts.push(PromptCard::new(event.clone(), 0));
    let mut editor = RuleEditor::from_prompt(&event);
    editor.name = "careful".into();
    app.editor = Some(editor);
    app.now_ms = event.deadline_unix_ms + 1;
    app.housekeeping();
    assert!(app.prompts.is_empty());
    let editor = app.editor.as_ref().expect("the edits are kept");
    assert!(editor.prompt_id.is_none());
    assert_eq!(editor.name, "careful");
    // Save now stores the rule instead of answering a dead prompt.
    assert_eq!(app.update(Message::SaveRule).units(), 1);
}

#[test]
fn a_verdict_that_was_not_applied_leaves_the_prompt_answerable() {
    let (mut app, _) = App::new();
    let event = prompt_event();
    app.prompts.push(PromptCard::new(event.clone(), 0));
    let submit = || Message::SubmitVerdict {
        prompt_id: event.prompt_id.clone(),
        action: proto::Action::Deny,
        scope: None,
        duration: proto::Duration::Once,
    };
    assert_eq!(app.update(submit()).units(), 1);
    assert!(app.prompts[0].submitting, "held until the daemon confirms");
    assert_eq!(app.update(submit()).units(), 0, "one verdict at a time");

    let failure = |applied| VerdictFailure {
        prompt_id: event.prompt_id.clone(),
        applied,
        message: "connection refused".into(),
    };
    let _ = app.update(Message::VerdictSubmitted(Err(failure(false))));
    assert_eq!(app.prompts.len(), 1);
    assert!(!app.prompts[0].submitting, "it can be answered again");

    let _ = app.update(submit());
    let _ = app.update(Message::VerdictSubmitted(Err(failure(true))));
    assert!(app.prompts.is_empty(), "an applied answer retires the card");
}

#[test]
fn a_first_prompt_raises_the_window_and_a_burst_does_not() {
    // 0 -> 1 is the interruption worth stealing focus for.
    assert_eq!(prompt_attention(0, false), Attention::TabAndRaise);
    // 1 -> 2, 2 -> 3: the user already knows about the queue, and a tab
    // switch under their cursor would turn a click into a verdict.
    assert_eq!(prompt_attention(1, false), Attention::None);
    assert_eq!(prompt_attention(9, false), Attention::None);
    // Drained and refilled: a genuinely new interruption.
    assert_eq!(prompt_attention(0, false), Attention::TabAndRaise);
}

#[test]
fn an_open_rule_editor_suppresses_the_raise_and_the_tab_switch() {
    // Yanking the tab out from under a half-filled form loses it.
    assert_eq!(prompt_attention(0, true), Attention::None);
    assert_eq!(prompt_attention(3, true), Attention::None);
}

fn key(c: &str, modifiers: keyboard::Modifiers) -> KeyPress {
    KeyPress {
        key: keyboard::Key::Character(c.into()),
        modifiers,
    }
}

fn prompt(id: &str, exe: &str) -> proto::PromptEvent {
    let mut ev = prompt_event();
    ev.prompt_id = id.into();
    ev.process.as_mut().unwrap().exe = exe.into();
    ev.deadline_unix_ms = 0;
    ev
}

#[test]
fn verdict_keys_answer_the_armed_top_card_only() {
    let (mut app, _) = App::new();
    app.now_ms = 1_000_000;
    app.prompts.push(PromptCard::new(
        prompt("top", "/usr/lib/firefox/firefox"),
        0,
    ));
    app.prompts.push(PromptCard::new(
        prompt("below", "/home/u/.cache/x/updater"),
        0,
    ));
    let shift = keyboard::Modifiers::SHIFT;

    // The top card just became the target: a press already on its way
    // answers nothing.
    assert_eq!(app.handle_key(key("A", shift)).units(), 0);
    assert_eq!(app.prompts.len(), 2);

    app.now_ms += PROMPT_ARM_MS;
    // Chords and other tabs never answer.
    for m in [
        keyboard::Modifiers::CTRL,
        keyboard::Modifiers::ALT,
        keyboard::Modifiers::LOGO,
        keyboard::Modifiers::CTRL | shift,
    ] {
        assert_eq!(app.handle_key(key("a", m)).units(), 0, "{m:?}");
    }
    app.tab = Tab::Rules;
    assert_eq!(app.handle_key(key("a", shift)).units(), 0);
    app.tab = Tab::Prompts;

    assert_eq!(app.handle_key(key("A", shift)).units(), 1);
    assert!(app.prompts[0].submitting, "the top card is answered");
    assert!(!app.prompts[1].submitting, "not the newest");

    // The card that moved up is disarmed again.
    assert_eq!(
        app.handle_key(key("a", keyboard::Modifiers::empty()))
            .units(),
        0
    );
}

#[test]
fn a_card_that_moves_up_is_disarmed_again() {
    let (mut app, _) = App::new();
    app.prompts.push(PromptCard::new(
        prompt("top", "/usr/lib/firefox/firefox"),
        0,
    ));
    app.prompts.push(PromptCard::new(
        prompt("below", "/home/u/.cache/x/updater"),
        0,
    ));
    assert!(app.prompts[1].armed(app.now_ms));
    let _ = app.update(Message::SubmitVerdict {
        prompt_id: "top".into(),
        action: proto::Action::Allow,
        scope: None,
        duration: proto::Duration::Always,
    });
    let _ = app.update(Message::VerdictSubmitted(Ok(("top".into(), true, None))));
    // The second click of a double-click lands on the card that took
    // the answered one's place.
    assert_eq!(app.prompts[0].event.prompt_id, "below");
    assert!(!app.prompts[0].armed(app.now_ms));
    assert!(app.prompts[0].armed(app.now_ms + PROMPT_ARM_MS));
}

#[test]
fn pause_ignores_a_click_right_after_resuming() {
    let (mut app, _) = App::new();
    app.status = Some(proto::StatusResponse {
        paused: true,
        ..Default::default()
    });
    assert_eq!(app.update(Message::TogglePaused).units(), 1, "Resume");
    let _ = app.update(Message::PausedSet(Ok((false, 0))));
    assert_eq!(app.update(Message::TogglePaused).units(), 0);
    app.now_ms += PROMPT_ARM_MS;
    assert_eq!(app.update(Message::TogglePaused).units(), 1);
}

#[test]
fn pause_waits_for_authorization_and_ignores_clicks_meanwhile() {
    let (mut app, _) = App::new();
    app.status = Some(proto::StatusResponse::default());
    app.now_ms += PROMPT_ARM_MS;
    assert_eq!(app.update(Message::TogglePaused).units(), 1);
    assert!(app.pause_pending);
    assert_eq!(app.update(Message::TogglePaused).units(), 0, "in flight");
    let _ = app.update(Message::PausedSet(Err(
        "authorization dialog dismissed (polkit action org.projectcolony.firewall.pause)".into(),
    )));
    assert!(!app.pause_pending);
    assert_eq!(app.update(Message::TogglePaused).units(), 1);
}

#[test]
fn pause_ignores_a_click_right_after_reconnecting() {
    let (mut app, _) = App::new();
    let _ = app.update(Message::HandshakeDone(Ok(HandshakeData {
        status: proto::StatusResponse::default(),
        rules: Vec::new(),
    })));
    assert_eq!(app.update(Message::TogglePaused).units(), 0);
    app.now_ms += PROMPT_ARM_MS;
    assert_eq!(app.update(Message::TogglePaused).units(), 1);
}

#[test]
fn a_prompt_card_is_disarmed_right_after_it_appears() {
    let card = PromptCard::new(prompt("p", "/usr/bin/curl"), 5_000);
    assert!(!card.armed(5_000));
    assert!(!card.armed(5_000 + PROMPT_ARM_MS - 1));
    assert!(card.armed(5_000 + PROMPT_ARM_MS));
}
