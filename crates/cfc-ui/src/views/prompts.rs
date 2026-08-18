//! The prompt queue: one card per flow the daemon is holding open.
//!
//! Every card carries the daemon's own deadline, so the countdown here is
//! the same clock the daemon will act on - not a guess.

use cfc_client::{convert, proto};
use iced::widget::{
    button, column, container, pick_list, progress_bar, row, scrollable, text, Space,
};
use iced::{Element, Length};

use crate::views::rules::DurationOption;
use crate::{format, Message, PromptCard};

/// Below this many seconds the countdown turns amber.
const URGENT_SECS: i64 = 5;

pub fn view<'a>(
    prompts: &'a [PromptCard],
    status: Option<&'a proto::StatusResponse>,
    now_ms: i64,
) -> Element<'a, Message> {
    if prompts.is_empty() {
        return container(
            column![
                text("No pending prompts").size(18),
                text("Outbound flows without a matching rule will appear here for you to allow or deny.").size(12),
                text("Keyboard: A allow / D deny the newest, Shift for the selected scope.").size(11),
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

    container(scrollable(column(cards).spacing(10).padding(8)).height(Length::Fill))
        .padding(8)
        .into()
}

/// Scope matching just the executable. Public because the keyboard path
/// (Shift+A / Shift+D) persists with exactly this scope.
pub fn exe_scope(ev: &proto::PromptEvent) -> Option<proto::RuleScope> {
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

/// Scope matching this executable talking to this destination. Prefers a
/// domain-scoped rule when the daemon resolved a hostname, which is what
/// the user actually meant by "allow this app to reach example.com".
fn exe_and_dst_scope(ev: &proto::PromptEvent) -> Option<proto::RuleScope> {
    let p = ev.process.as_ref()?;
    let c = ev.connection.as_ref()?;
    let (dst_host, dst_net) = if c.dst_host.is_empty() {
        (String::new(), format::host_cidr(&c.dst_ip))
    } else {
        (c.dst_host.clone(), String::new())
    };
    if dst_host.is_empty() && dst_net.is_empty() {
        return None;
    }
    Some(proto::RuleScope {
        exe_path: p.exe.clone(),
        exe_sha256: String::new(),
        parent_exe: String::new(),
        uid: 0,
        has_uid: false,
        dst_host,
        dst_net,
        dst_port: c.dst_port,
        has_dst_port: true,
        protocol: c.protocol,
        has_protocol: true,
    })
}

fn prompt_card(
    card: &PromptCard,
    timeout_action: i32,
    timeout_secs: u32,
    now_ms: i64,
) -> Element<'_, Message> {
    let ev = &card.event;
    let conn = ev.connection.as_ref();
    let proc = ev.process.as_ref();

    let process_line = proc
        .map(convert::process_display)
        .unwrap_or_else(|| "unknown process".into());
    let pid = proc.map(|p| p.pid).unwrap_or(0);
    let cmdline = proc.map(|p| p.cmdline.join(" ")).unwrap_or_default();

    let target_line = conn
        .map(|c| format::dest_display(&c.dst_host, &c.dst_ip, c.dst_port))
        .unwrap_or_else(|| "?".into());
    let proto_line = conn
        .map(|c| convert::protocol_label(c.protocol).to_string())
        .unwrap_or_default();

    let header = row![
        text(format!("{process_line} (pid {pid})")).size(15),
        Space::new().width(Length::Fill),
        text(format!("{proto_line} {target_line}")).size(13),
        button(
            text(if card.details_open {
                "details ▾"
            } else {
                "details ▸"
            })
            .size(10)
        )
        .padding([2, 6])
        .on_press(Message::TogglePromptDetails(ev.prompt_id.clone()))
        .style(crate::theme::subtle_icon),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center);

    let cmd_row: Element<'_, Message> = if cmdline.is_empty() {
        Space::new().into()
    } else {
        text(cmdline).size(11).into()
    };

    let countdown = countdown_row(card, timeout_action, timeout_secs, now_ms);

    let details: Element<'_, Message> = if card.details_open {
        details_block(ev)
    } else {
        Space::new().into()
    };

    let persistable = card.persistable();
    let prompt_id = &ev.prompt_id;

    let duration_pick = pick_list(
        [
            DurationOption::Once,
            DurationOption::UntilRestart,
            DurationOption::Always,
        ],
        Some(DurationOption::from(card.duration)),
        {
            let id = prompt_id.clone();
            move |d| Message::PromptDuration {
                prompt_id: id.clone(),
                duration: d.into(),
            }
        },
    )
    .text_size(12)
    .padding([2, 6]);

    // "Once" answers this flow only: the daemon rejects a persisted Once
    // rule outright, so the scope buttons must not be reachable.
    let scope_hint: Element<'_, Message> = if persistable {
        text("scope buttons save a rule").size(10).into()
    } else {
        text("\"Once\" answers this flow only - no rule is saved")
            .size(10)
            .into()
    };

    let dst_label = conn
        .map(|c| format::dest_key(&c.dst_host, &c.dst_ip))
        .unwrap_or_else(|| "destination".into());

    let allow_once = plain_button(
        "Allow",
        prompt_id,
        proto::Action::Allow,
        iced::widget::button::secondary,
    );
    let allow_exe = scoped_button(
        "Allow this app",
        prompt_id,
        proto::Action::Allow,
        exe_scope(ev),
        card.duration,
        persistable,
        iced::widget::button::primary,
    );
    let allow_exe_dst = scoped_button(
        &format!("Allow app → {dst_label}"),
        prompt_id,
        proto::Action::Allow,
        exe_and_dst_scope(ev),
        card.duration,
        persistable,
        iced::widget::button::primary,
    );
    let deny_once = plain_button(
        "Deny",
        prompt_id,
        proto::Action::Deny,
        iced::widget::button::secondary,
    );
    let deny_exe = scoped_button(
        "Deny this app",
        prompt_id,
        proto::Action::Deny,
        exe_scope(ev),
        card.duration,
        persistable,
        iced::widget::button::danger,
    );

    let buttons = row![
        duration_pick,
        allow_once,
        allow_exe,
        allow_exe_dst,
        Space::new().width(Length::Fill),
        deny_once,
        deny_exe,
    ]
    .spacing(6)
    .align_y(iced::Alignment::Center);

    container(column![header, cmd_row, countdown, details, buttons, scope_hint].spacing(8))
        .padding(10)
        .style(crate::theme::panel)
        .into()
}

type ButtonStyle = fn(&iced::Theme, iced::widget::button::Status) -> iced::widget::button::Style;

/// Answers this flow and nothing else. Always available - a scope-less
/// verdict is always `Once`, which the daemon never tries to persist.
fn plain_button<'a>(
    label: &str,
    prompt_id: &str,
    action: proto::Action,
    style: ButtonStyle,
) -> Element<'a, Message> {
    button(text(label.to_string()).size(12))
        .padding([4, 10])
        .on_press(Message::SubmitVerdict {
            prompt_id: prompt_id.to_string(),
            action,
            scope: None,
            duration: proto::Duration::Once,
        })
        .style(style)
        .into()
}

/// Answers and saves a rule. Disabled when the chosen duration is `Once`
/// (unpersistable) or when the daemon gave us nothing to scope on, so the
/// user can never provoke the daemon's invalid_argument.
fn scoped_button<'a>(
    label: &str,
    prompt_id: &str,
    action: proto::Action,
    scope: Option<proto::RuleScope>,
    duration: proto::Duration,
    persistable: bool,
    style: ButtonStyle,
) -> Element<'a, Message> {
    let press = match (persistable, scope) {
        (true, Some(scope)) => Some(Message::SubmitVerdict {
            prompt_id: prompt_id.to_string(),
            action,
            scope: Some(scope),
            duration,
        }),
        _ => None,
    };
    button(text(label.to_string()).size(12))
        .padding([4, 10])
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

/// Everything needed to judge whether this really is the process you think
/// it is. Collapsed by default so the card stays scannable.
fn details_block(ev: &proto::PromptEvent) -> Element<'_, Message> {
    let Some(p) = ev.process.as_ref() else {
        return text("no process attribution for this flow").size(11).into();
    };

    let exe = if p.exe.is_empty() {
        "unknown".to_string()
    } else {
        p.exe.clone()
    };
    let cwd = if p.cwd.is_empty() {
        "unknown".to_string()
    } else {
        p.cwd.clone()
    };

    let sha_row = row![
        text(format!("sha256   {}", format::truncate_sha(&p.sha256))).size(11),
        copy_button(&p.sha256),
    ]
    .spacing(6)
    .align_y(iced::Alignment::Center);

    let exe_row = row![
        text(format!("exe      {exe}")).size(11),
        copy_button(&p.exe),
    ]
    .spacing(6)
    .align_y(iced::Alignment::Center);

    container(
        column![
            exe_row,
            // uid is optional in the proto precisely so an unattributed
            // flow does not render as root.
            text(format!("uid      {}", convert::uid_label(p.uid))).size(11),
            text(format!("cwd      {cwd}")).size(11),
            text(format!("ppid     {}", p.ppid)).size(11),
            sha_row,
        ]
        .spacing(2),
    )
    .padding([6, 8])
    .into()
}

fn copy_button<'a>(value: &str) -> Element<'a, Message> {
    if value.is_empty() {
        return Space::new().into();
    }
    button(text("copy").size(9))
        .padding([1, 5])
        .on_press(Message::CopyText(value.to_string()))
        .style(crate::theme::subtle_icon)
        .into()
}
