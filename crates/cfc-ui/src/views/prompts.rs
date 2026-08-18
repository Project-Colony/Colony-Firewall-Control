//! The prompt queue: one card per flow the daemon is holding open.
//!
//! Laid out the way Windows Firewall Control lays out its connection
//! prompt, because the shape works: a title that says what happened and
//! when, a labelled table of everything you need to recognise the program,
//! and then a small number of large, explicitly-worded choices whose second
//! line spells out what the click will actually persist.
//!
//! Every card carries the daemon's own deadline, so the countdown here is
//! the same clock the daemon will act on - not a guess.

use cfc_client::{convert, proto};
use iced::widget::{button, column, container, progress_bar, row, scrollable, text, Space};
use iced::{Element, Font, Length};

use crate::{format, Message, PromptCard};

/// Below this many seconds the countdown turns amber.
const URGENT_SECS: i64 = 5;

/// Widest command line rendered before it is clipped. Wide enough for a
/// realistic invocation, narrow enough that one pathological `java -cp ...`
/// cannot push the action buttons off the card.
const CMDLINE_MAX_CHARS: usize = 96;

/// Width of the label column, so every value starts at the same x.
const LABEL_WIDTH: f32 = 104.0;

/// The one row rendered large: it is the answer to "what is asking?".
const PROGRAM_LABEL: &str = "Program";

pub fn view<'a>(
    prompts: &'a [PromptCard],
    status: Option<&'a proto::StatusResponse>,
    now_ms: i64,
) -> Element<'a, Message> {
    if prompts.is_empty() {
        return container(
            column![
                text("No pending prompts").size(18),
                text("Outbound flows without a matching rule will appear here for you to allow or block.").size(12),
                text("Keyboard: A allow once / D block for now; Shift+A always allow this program, Shift+D always block it.").size(11),
            ]
            .spacing(8),
        )
        .padding(16)
        .width(Length::Fill)
        .height(Length::Fill)
        .into();
    }

    let timeout_action = status
        .map(|s| s.timeout_action)
        .unwrap_or(proto::Action::Unspecified as i32);
    let timeout_secs = status.map(|s| s.prompt_timeout_secs).unwrap_or(0);

    let cards: Vec<Element<'a, Message>> = prompts
        .iter()
        .map(|c| prompt_card(c, timeout_action, timeout_secs, now_ms))
        .collect();

    container(scrollable(column(cards).spacing(12).padding(8)).height(Length::Fill))
        .padding(8)
        .into()
}

// --- Pure model ---------------------------------------------------------

/// One row of the detail table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailRow {
    pub label: &'static str,
    /// Value as rendered - already clipped where clipping was needed.
    pub value: String,
    /// Muted aside after the value, e.g. why a checksum is missing.
    pub note: &'static str,
    /// Untruncated text behind the copy affordance, where copying is worth
    /// offering (a path, a whole digest, the full command line).
    pub copy: Option<String>,
}

fn plain(label: &'static str, value: String) -> DetailRow {
    DetailRow {
        label,
        value,
        note: "",
        copy: None,
    }
}

/// Everything needed to judge whether this really is the process you think
/// it is, in the order WFC shows it.
///
/// A row whose value the daemon could not fill in is dropped rather than
/// rendered empty - a column of "unknown" teaches the user to stop reading
/// the table. `Checksum` is the exception: its absence is itself the
/// finding, because it says the rule you are about to write cannot be
/// pinned to this binary.
pub fn detail_rows(ev: &proto::PromptEvent) -> Vec<DetailRow> {
    let mut rows = Vec::with_capacity(11);

    if let Some(p) = ev.process.as_ref() {
        if !p.exe.is_empty() {
            rows.push(plain(PROGRAM_LABEL, convert::process_display(p)));
            rows.push(DetailRow {
                label: "Path",
                value: p.exe.clone(),
                note: "",
                copy: Some(p.exe.clone()),
            });
        }

        // The command line only earns a row when it says something the path
        // did not: `/usr/bin/curl` invoked as bare `curl` is noise, the
        // arguments it was invoked *with* are the point.
        let cmdline = p.cmdline.join(" ");
        if !cmdline.is_empty() && cmdline != p.exe && cmdline != convert::process_display(p) {
            rows.push(DetailRow {
                label: "Command line",
                value: format::ellipsize(&cmdline, CMDLINE_MAX_CHARS),
                note: "",
                copy: Some(cmdline),
            });
        }

        if p.pid != 0 || p.ppid != 0 {
            rows.push(plain("Process", process_line(p)));
        }

        // uid is optional in the proto precisely so an unattributed flow
        // never renders as uid 0, i.e. as root. No attribution, no row.
        if p.uid.is_some() {
            rows.push(plain("User", convert::uid_label(p.uid)));
        }

        if !p.cwd.is_empty() {
            rows.push(plain("Working dir", p.cwd.clone()));
        }

        rows.push(if p.sha256.is_empty() {
            DetailRow {
                label: "Checksum",
                value: "-".to_string(),
                note: "(not hashed)",
                copy: None,
            }
        } else {
            DetailRow {
                label: "Checksum",
                value: format::truncate_sha(&p.sha256),
                note: "",
                copy: Some(p.sha256.clone()),
            }
        });

        // Where this binary came from, and whether it still matches what
        // the distribution installed. Always shown, like Checksum: "not
        // from a package" and "MODIFIED since install" are exactly the
        // answers worth seeing before you allow anything.
        rows.push(plain("Package", convert::provenance_label(p)));
    }

    if let Some(c) = ev.connection.as_ref() {
        let src = format::socket_display(&c.src_ip, c.src_port);
        if !src.is_empty() {
            rows.push(plain("Source", src));
        }

        let remote = format::remote_display(&c.dst_host, &c.dst_ip, c.dst_port);
        if !remote.is_empty() {
            rows.push(plain("Remote", remote));
        }

        if !matches!(
            proto::Protocol::try_from(c.protocol).unwrap_or(proto::Protocol::Unspecified),
            proto::Protocol::Unspecified
        ) {
            rows.push(plain(
                "Protocol",
                convert::protocol_label(c.protocol).to_string(),
            ));
        }

        if c.timestamp_unix_ms > 0 {
            rows.push(plain(
                "Started",
                format::format_local_clock_ms(c.timestamp_unix_ms),
            ));
        }
    }

    rows
}

/// `"pid 4242 (parent pid 1310)"`.
///
/// WFC names the parent program; the proto carries only `ppid`, so the
/// number is all we can honestly show. Inventing a path by reading
/// `/proc/<ppid>` from the UI would be a lie the moment the parent exited.
fn process_line(p: &proto::ProcessInfo) -> String {
    if p.ppid == 0 {
        format!("pid {}", p.pid)
    } else {
        format!("pid {} (parent pid {})", p.pid, p.ppid)
    }
}

/// WFC's title line: what happened, and when, on the user's own clock.
pub fn heading(ev: &proto::PromptEvent) -> String {
    let conn = ev.connection.as_ref();
    let what = match conn.map(|c| c.direction) {
        Some(d) if d == proto::Direction::Inbound as i32 => "Incoming connection",
        _ => "Outgoing connection",
    };
    match conn.map(|c| c.timestamp_unix_ms).filter(|t| *t > 0) {
        Some(ts) => format!("{what} - {}", format::format_local_clock_ms(ts)),
        None => what.to_string(),
    }
}

/// Basename used in the action wording ("Always allow curl to connect").
pub fn program_label(ev: &proto::PromptEvent) -> String {
    ev.process
        .as_ref()
        .filter(|p| !p.exe.is_empty())
        .map(convert::process_display)
        .unwrap_or_else(|| "this program".to_string())
}

/// The four answers a card offers, in render order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptAction {
    /// Allow, forever, for this executable.
    AllowProgram,
    /// Block, forever, for this executable.
    BlockProgram,
    /// Block this flow and ask again next time.
    BlockOnce,
    /// Allow this flow and ask again next time.
    AllowOnce,
}

/// A fully-formed answer: exactly the triple `SubmitVerdict` carries.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub action: proto::Action,
    pub duration: proto::Duration,
    pub scope: Option<proto::RuleScope>,
}

/// The verdict a choice submits, or `None` when the daemon gave us nothing
/// to scope a program rule on.
///
/// Two invariants live here rather than in the view, so no button and no
/// keyboard shortcut can route around them:
///
/// * `Once` never carries a scope. The daemon answers a persisted `Once`
///   verdict with `invalid_argument`, which the user would see as the
///   prompt simply not working.
/// * a program rule needs a real `exe_path`. An empty one is not a narrow
///   rule, it is a rule that matches every program on the machine.
pub fn verdict_for(choice: PromptAction, ev: &proto::PromptEvent) -> Option<Verdict> {
    let (action, program_scoped) = match choice {
        PromptAction::AllowProgram => (proto::Action::Allow, true),
        PromptAction::BlockProgram => (proto::Action::Deny, true),
        PromptAction::BlockOnce => (proto::Action::Deny, false),
        PromptAction::AllowOnce => (proto::Action::Allow, false),
    };

    if !program_scoped {
        return Some(Verdict {
            action,
            duration: proto::Duration::Once,
            scope: None,
        });
    }

    Some(Verdict {
        action,
        duration: proto::Duration::Always,
        scope: Some(exe_scope(ev)?),
    })
}

/// Scope matching just the executable.
fn exe_scope(ev: &proto::PromptEvent) -> Option<proto::RuleScope> {
    let p = ev.process.as_ref()?;
    if p.exe.is_empty() {
        return None;
    }
    Some(proto::RuleScope {
        exe_path: p.exe.clone(),
        exe_sha256: String::new(),
        parent_exe: String::new(),
        uid: 0,
        has_uid: false,
        dst_host: String::new(),
        dst_net: String::new(),
        dst_port: 0,
        has_dst_port: false,
        protocol: 0,
        has_protocol: false,
    })
}

/// First line of an action row - the decision.
pub fn action_title(choice: PromptAction) -> &'static str {
    match choice {
        PromptAction::AllowProgram => "Allow this program",
        PromptAction::BlockProgram => "Block this program",
        PromptAction::BlockOnce => "Block for now",
        PromptAction::AllowOnce => "Allow once",
    }
}

/// Second line - the consequence, in the same words the rule will have.
pub fn action_consequence(choice: PromptAction, program: &str) -> String {
    match choice {
        PromptAction::AllowProgram => format!("Always allow {program} to connect"),
        PromptAction::BlockProgram => format!("Always block {program} from connecting"),
        PromptAction::BlockOnce => "Deny this connection only and ask again next time".to_string(),
        PromptAction::AllowOnce => {
            "Permit this connection only and ask again next time".to_string()
        }
    }
}

// --- Rendering ----------------------------------------------------------

type ButtonStyle = fn(&iced::Theme, iced::widget::button::Status) -> iced::widget::button::Style;

fn prompt_card(
    card: &PromptCard,
    timeout_action: i32,
    timeout_secs: u32,
    now_ms: i64,
) -> Element<'_, Message> {
    let ev = &card.event;
    let program = program_label(ev);

    let header = text(heading(ev)).size(16);
    let countdown = countdown_row(card, timeout_action, timeout_secs, now_ms);

    let table = column(
        detail_rows(ev)
            .into_iter()
            .map(detail_row)
            .collect::<Vec<_>>(),
    )
    .spacing(3);

    let customize = button(text("Customize this rule before creating it").size(11))
        .padding([2, 4])
        .on_press(Message::CustomizePromptRule(ev.prompt_id.clone()))
        .style(crate::theme::link_button);

    let actions = column![
        action_row(
            PromptAction::AllowProgram,
            ev,
            &program,
            iced::widget::button::success,
            true
        ),
        action_row(
            PromptAction::BlockProgram,
            ev,
            &program,
            iced::widget::button::danger,
            true
        ),
        action_row(
            PromptAction::BlockOnce,
            ev,
            &program,
            iced::widget::button::secondary,
            true
        ),
        action_row(
            PromptAction::AllowOnce,
            ev,
            &program,
            crate::theme::action_secondary,
            false
        ),
    ]
    .spacing(6);

    // Without an exe path the two program rows are dead: say why, once,
    // rather than leaving the user clicking a button that does nothing.
    let unscopable: Element<'_, Message> = if verdict_for(PromptAction::AllowProgram, ev).is_some()
    {
        Space::new().into()
    } else {
        text(
            "No executable path for this flow - a \"this program\" rule would have an empty \
             program and match everything, so only the one-off answers are available.",
        )
        .size(10)
        .color(crate::theme::BURGUNDY_DARK)
        .into()
    };

    container(column![header, countdown, table, customize, actions, unscopable].spacing(9))
        .padding(12)
        .style(crate::theme::panel)
        .into()
}

fn detail_row<'a>(r: DetailRow) -> Element<'a, Message> {
    let emphasised = r.label == PROGRAM_LABEL;
    let value = text(r.value)
        .size(if emphasised { 14 } else { 11 })
        .font(if emphasised {
            Font::DEFAULT
        } else {
            Font::MONOSPACE
        });

    let note: Element<'a, Message> = if r.note.is_empty() {
        Space::new().into()
    } else {
        text(r.note)
            .size(10)
            .color(crate::theme::PARCHMENT_MUTED)
            .into()
    };

    let copy: Element<'a, Message> = match r.copy {
        Some(full) => copy_button(full),
        None => Space::new().into(),
    };

    row![
        container(text(r.label).size(11).color(crate::theme::PARCHMENT_MUTED))
            .width(Length::Fixed(LABEL_WIDTH)),
        value,
        note,
        copy,
    ]
    .spacing(6)
    .align_y(iced::Alignment::Center)
    .into()
}

/// A full-width choice: what it does on line one, what it persists on line
/// two. `prominent` is the difference between one of the three decisions
/// and the subordinate "Allow once" beneath them.
fn action_row<'a>(
    choice: PromptAction,
    ev: &proto::PromptEvent,
    program: &str,
    style: ButtonStyle,
    prominent: bool,
) -> Element<'a, Message> {
    let press = verdict_for(choice, ev).map(|v| Message::SubmitVerdict {
        prompt_id: ev.prompt_id.clone(),
        action: v.action,
        scope: v.scope,
        duration: v.duration,
    });

    let (title_size, sub_size) = if prominent { (14, 11) } else { (12, 10) };
    let padding: iced::Padding = if prominent {
        [9u16, 12u16].into()
    } else {
        [5u16, 10u16].into()
    };

    button(
        column![
            text(action_title(choice)).size(title_size),
            text(action_consequence(choice, program)).size(sub_size),
        ]
        .spacing(1),
    )
    .width(Length::Fill)
    .padding(padding)
    .on_press_maybe(press)
    .style(style)
    .into()
}

fn countdown_row<'a>(
    card: &PromptCard,
    timeout_action: i32,
    timeout_secs: u32,
    now_ms: i64,
) -> Element<'a, Message> {
    let Some(left) = format::remaining_secs(card.deadline_unix_ms, now_ms) else {
        return text("no deadline - waiting for your answer")
            .size(10)
            .into();
    };

    let fraction = format::countdown_fraction(card.deadline_unix_ms, now_ms, timeout_secs);
    let style = if left <= URGENT_SECS {
        crate::theme::countdown_bar_urgent
    } else {
        crate::theme::countdown_bar
    };

    column![
        progress_bar(0.0..=1.0, fraction)
            .length(Length::Fill)
            .girth(Length::Fixed(4.0))
            .style(style),
        text(format!(
            "daemon {} automatically in {}",
            format::fallback_verb(timeout_action),
            format::format_countdown(left)
        ))
        .size(10),
    ]
    .spacing(3)
    .into()
}

fn copy_button<'a>(value: String) -> Element<'a, Message> {
    if value.is_empty() {
        return Space::new().into();
    }
    button(text("copy").size(9))
        .padding([1, 5])
        .on_press(Message::CopyText(value))
        .style(crate::theme::subtle_icon)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process() -> proto::ProcessInfo {
        proto::ProcessInfo {
            pid: 4242,
            ppid: 1310,
            uid: Some(1000),
            gid: Some(1000),
            exe: "/usr/bin/curl".into(),
            cmdline: vec!["curl".into(), "-sS".into(), "https://example.com".into()],
            cwd: "/home/user".into(),
            sha256: "a".repeat(64),
            package: String::new(),
            provenance: 0,
        }
    }

    fn connection() -> proto::ConnectionInfo {
        proto::ConnectionInfo {
            id: "c1".into(),
            timestamp_unix_ms: 1_700_000_000_000,
            protocol: proto::Protocol::Tcp as i32,
            direction: proto::Direction::Outbound as i32,
            src_ip: "10.0.0.2".into(),
            src_port: 54321,
            dst_ip: "93.184.216.34".into(),
            dst_port: 443,
            dst_host: "example.com".into(),
        }
    }

    fn event() -> proto::PromptEvent {
        proto::PromptEvent {
            prompt_id: "p1".into(),
            connection: Some(connection()),
            process: Some(process()),
            deadline_unix_ms: 1_700_000_015_000,
        }
    }

    fn labels(ev: &proto::PromptEvent) -> Vec<&'static str> {
        detail_rows(ev).into_iter().map(|r| r.label).collect()
    }

    fn value_of(ev: &proto::PromptEvent, label: &str) -> Option<String> {
        detail_rows(ev)
            .into_iter()
            .find(|r| r.label == label)
            .map(|r| r.value)
    }

    #[test]
    fn a_full_event_renders_every_row_in_wfc_order() {
        assert_eq!(
            labels(&event()),
            vec![
                "Program",
                "Path",
                "Command line",
                "Process",
                "User",
                "Working dir",
                "Checksum",
                "Package",
                "Source",
                "Remote",
                "Protocol",
                "Started",
            ]
        );
        let ev = event();
        assert_eq!(value_of(&ev, "Program").unwrap(), "curl");
        assert_eq!(value_of(&ev, "Path").unwrap(), "/usr/bin/curl");
        assert_eq!(
            value_of(&ev, "Process").unwrap(),
            "pid 4242 (parent pid 1310)"
        );
        assert_eq!(value_of(&ev, "User").unwrap(), "1000");
        assert_eq!(value_of(&ev, "Working dir").unwrap(), "/home/user");
        assert_eq!(value_of(&ev, "Source").unwrap(), "10.0.0.2:54321");
        assert_eq!(value_of(&ev, "Protocol").unwrap(), "tcp");
    }

    #[test]
    fn remote_prefers_the_hostname_the_daemon_resolved() {
        let ev = event();
        assert_eq!(
            value_of(&ev, "Remote").unwrap(),
            "example.com (93.184.216.34):443"
        );

        let bare = proto::PromptEvent {
            connection: Some(proto::ConnectionInfo {
                dst_host: String::new(),
                ..connection()
            }),
            ..event()
        };
        assert_eq!(value_of(&bare, "Remote").unwrap(), "93.184.216.34:443");
    }

    #[test]
    fn rows_the_daemon_could_not_fill_in_are_dropped() {
        let sparse = proto::PromptEvent {
            process: Some(proto::ProcessInfo {
                ppid: 0,
                uid: None,
                gid: None,
                cmdline: Vec::new(),
                cwd: String::new(),
                sha256: String::new(),
                package: String::new(),
                provenance: 0,
                ..process()
            }),
            connection: Some(proto::ConnectionInfo {
                src_ip: String::new(),
                src_port: 0,
                protocol: proto::Protocol::Unspecified as i32,
                timestamp_unix_ms: 0,
                ..connection()
            }),
            ..event()
        };
        // Checksum survives: its absence is the finding, not a gap.
        assert_eq!(
            labels(&sparse),
            vec!["Program", "Path", "Process", "Checksum", "Package", "Remote"]
        );
        let checksum = detail_rows(&sparse)
            .into_iter()
            .find(|r| r.label == "Checksum")
            .unwrap();
        assert_eq!(checksum.value, "-");
        assert_eq!(checksum.note, "(not hashed)");
        assert!(checksum.copy.is_none(), "nothing to copy");
        // ppid 0 means no parent to name.
        assert_eq!(value_of(&sparse, "Process").unwrap(), "pid 4242");
    }

    #[test]
    fn an_unattributed_uid_is_omitted_rather_than_shown_as_root() {
        let anon = proto::PromptEvent {
            process: Some(proto::ProcessInfo {
                uid: None,
                ..process()
            }),
            ..event()
        };
        assert!(!labels(&anon).contains(&"User"));
        assert!(
            !detail_rows(&anon).iter().any(|r| r.value == "0"),
            "unknown attribution must never render as uid 0"
        );

        // An actual root process still says so.
        let root = proto::PromptEvent {
            process: Some(proto::ProcessInfo {
                uid: Some(0),
                ..process()
            }),
            ..event()
        };
        assert_eq!(value_of(&root, "User").unwrap(), "0");
    }

    #[test]
    fn a_command_line_that_only_repeats_the_program_is_dropped() {
        let echoed = proto::PromptEvent {
            process: Some(proto::ProcessInfo {
                cmdline: vec!["curl".into()],
                ..process()
            }),
            ..event()
        };
        assert!(!labels(&echoed).contains(&"Command line"));

        let full_path = proto::PromptEvent {
            process: Some(proto::ProcessInfo {
                cmdline: vec!["/usr/bin/curl".into()],
                ..process()
            }),
            ..event()
        };
        assert!(!labels(&full_path).contains(&"Command line"));

        assert_eq!(
            value_of(&event(), "Command line").unwrap(),
            "curl -sS https://example.com"
        );
    }

    #[test]
    fn long_values_are_clipped_but_stay_copyable_in_full() {
        let long: String = std::iter::repeat_n("--flag", 60)
            .collect::<Vec<_>>()
            .join(" ");
        let ev = proto::PromptEvent {
            process: Some(proto::ProcessInfo {
                cmdline: vec![long.clone()],
                ..process()
            }),
            ..event()
        };
        let cmd = detail_rows(&ev)
            .into_iter()
            .find(|r| r.label == "Command line")
            .unwrap();
        assert_eq!(cmd.value.chars().count(), CMDLINE_MAX_CHARS + 3);
        assert!(cmd.value.ends_with("..."));
        assert_eq!(cmd.copy.as_deref(), Some(long.as_str()), "copy is verbatim");

        let sha = detail_rows(&ev)
            .into_iter()
            .find(|r| r.label == "Checksum")
            .unwrap();
        assert_eq!(sha.value, format!("{}...", "a".repeat(16)));
        assert_eq!(sha.copy.as_deref(), Some("a".repeat(64).as_str()));
    }

    #[test]
    fn an_event_without_a_process_still_describes_the_connection() {
        let ev = proto::PromptEvent {
            process: None,
            ..event()
        };
        assert_eq!(labels(&ev), vec!["Source", "Remote", "Protocol", "Started"]);
        assert!(detail_rows(&proto::PromptEvent::default()).is_empty());
    }

    #[test]
    fn the_heading_names_the_direction_and_the_local_time() {
        let h = heading(&event());
        assert!(h.starts_with("Outgoing connection - "), "{h}");
        assert_eq!(h.len(), "Outgoing connection - ".len() + 8, "{h}");

        let inbound = proto::PromptEvent {
            connection: Some(proto::ConnectionInfo {
                direction: proto::Direction::Inbound as i32,
                ..connection()
            }),
            ..event()
        };
        assert!(heading(&inbound).starts_with("Incoming connection - "));

        // No timestamp: still a title, just no clock.
        let undated = proto::PromptEvent {
            connection: Some(proto::ConnectionInfo {
                timestamp_unix_ms: 0,
                ..connection()
            }),
            ..event()
        };
        assert_eq!(heading(&undated), "Outgoing connection");
        assert_eq!(
            heading(&proto::PromptEvent::default()),
            "Outgoing connection"
        );
    }

    #[test]
    fn program_label_falls_back_to_a_pronoun() {
        assert_eq!(program_label(&event()), "curl");
        assert_eq!(
            program_label(&proto::PromptEvent::default()),
            "this program"
        );
        assert_eq!(
            action_consequence(PromptAction::AllowProgram, &program_label(&event())),
            "Always allow curl to connect"
        );
    }

    const ALL: [PromptAction; 4] = [
        PromptAction::AllowProgram,
        PromptAction::BlockProgram,
        PromptAction::BlockOnce,
        PromptAction::AllowOnce,
    ];

    #[test]
    fn each_action_maps_to_its_documented_verdict() {
        let ev = event();
        let v = verdict_for(PromptAction::AllowProgram, &ev).unwrap();
        assert_eq!(v.action, proto::Action::Allow);
        assert_eq!(v.duration, proto::Duration::Always);
        assert_eq!(v.scope.unwrap().exe_path, "/usr/bin/curl");

        let v = verdict_for(PromptAction::BlockProgram, &ev).unwrap();
        assert_eq!(v.action, proto::Action::Deny);
        assert_eq!(v.duration, proto::Duration::Always);
        assert_eq!(v.scope.unwrap().exe_path, "/usr/bin/curl");

        let v = verdict_for(PromptAction::BlockOnce, &ev).unwrap();
        assert_eq!(v.action, proto::Action::Deny);
        assert_eq!(v.duration, proto::Duration::Once);

        let v = verdict_for(PromptAction::AllowOnce, &ev).unwrap();
        assert_eq!(v.action, proto::Action::Allow);
        assert_eq!(v.duration, proto::Duration::Once);
    }

    #[test]
    fn once_never_carries_a_scope() {
        // The daemon rejects a persisted Once verdict with invalid_argument,
        // which the user would experience as the prompt not working.
        for choice in ALL {
            for ev in [event(), proto::PromptEvent::default()] {
                let Some(v) = verdict_for(choice, &ev) else {
                    continue;
                };
                if v.duration == proto::Duration::Once {
                    assert!(v.scope.is_none(), "{choice:?} persisted a Once verdict");
                }
            }
        }
    }

    #[test]
    fn a_program_scope_is_never_empty_and_never_a_wildcard() {
        // An empty exe_path is not a narrow rule, it is a rule that matches
        // every program on the machine.
        let no_exe = proto::PromptEvent {
            process: Some(proto::ProcessInfo {
                exe: String::new(),
                ..process()
            }),
            ..event()
        };
        for ev in [no_exe, proto::PromptEvent::default()] {
            assert!(verdict_for(PromptAction::AllowProgram, &ev).is_none());
            assert!(verdict_for(PromptAction::BlockProgram, &ev).is_none());
            // The one-off answers stay available - they need no scope.
            assert!(verdict_for(PromptAction::BlockOnce, &ev).is_some());
            assert!(verdict_for(PromptAction::AllowOnce, &ev).is_some());
        }
    }

    #[test]
    fn a_program_scope_constrains_nothing_but_the_program() {
        let scope = verdict_for(PromptAction::AllowProgram, &event())
            .unwrap()
            .scope
            .unwrap();
        assert_eq!(scope.exe_path, "/usr/bin/curl");
        assert!(!scope.has_uid);
        assert!(!scope.has_dst_port);
        assert!(!scope.has_protocol);
        assert!(scope.dst_host.is_empty());
        assert!(scope.dst_net.is_empty());
        assert!(scope.exe_sha256.is_empty());
    }

    #[test]
    fn every_action_is_worded_as_a_decision_plus_a_consequence() {
        for choice in ALL {
            assert!(!action_title(choice).is_empty());
            let c = action_consequence(choice, "curl");
            assert!(!c.is_empty(), "{choice:?}");
            assert!(c != action_title(choice), "{choice:?} repeats itself");
        }
        assert_eq!(
            action_consequence(PromptAction::BlockProgram, "curl"),
            "Always block curl from connecting"
        );
    }
}
