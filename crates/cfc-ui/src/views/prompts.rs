use cfc_client::{convert, proto};
use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Element, Length};

use crate::{Message, PromptCard};

pub fn view<'a>(prompts: &'a [PromptCard]) -> Element<'a, Message> {
    if prompts.is_empty() {
        return container(
            column![
                text("No pending prompts").size(18),
                text("Outbound flows without a matching rule will appear here for you to allow or deny.").size(12),
            ]
            .spacing(8),
        )
        .padding(16)
        .width(Length::Fill)
        .height(Length::Fill)
        .into();
    }

    let cards: Vec<Element<'a, Message>> = prompts.iter().map(prompt_card).collect();

    container(scrollable(column(cards).spacing(10).padding(8)).height(Length::Fill))
        .padding(8)
        .into()
}

fn prompt_card(card: &PromptCard) -> Element<'_, Message> {
    let ev = &card.event;
    let conn = ev.connection.as_ref();
    let proc = ev.process.as_ref();

    let process_line = proc
        .map(convert::process_display)
        .unwrap_or_else(|| "unknown process".into());
    let pid = proc.map(|p| p.pid).unwrap_or(0);
    let cmdline = proc.map(|p| p.cmdline.join(" ")).unwrap_or_default();

    let target_line = conn
        .map(|c| format!("{}:{}", c.dst_ip, c.dst_port))
        .unwrap_or_else(|| "?".into());
    let proto_line = conn
        .map(|c| convert::protocol_label(c.protocol).to_string())
        .unwrap_or_default();

    let header = row![
        text(format!("{process_line} (pid {pid})")).size(15),
        Space::new().width(Length::Fill),
        text(format!("{proto_line} {target_line}")).size(13),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center);

    let cmd_row = if cmdline.is_empty() {
        container(text(""))
    } else {
        container(text(cmdline).size(11))
    };

    let prompt_id = ev.prompt_id.clone();
    let exe_scope: Option<proto::RuleScope> = proc.map(|p| proto::RuleScope {
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
    });
    let exe_and_dst_scope: Option<proto::RuleScope> = match (proc, conn) {
        (Some(p), Some(c)) => Some(proto::RuleScope {
            exe_path: p.exe.clone(),
            exe_sha256: String::new(),
            parent_exe: String::new(),
            uid: 0,
            has_uid: false,
            dst_host: String::new(),
            dst_net: format!("{}/32", c.dst_ip),
            dst_port: c.dst_port,
            has_dst_port: true,
            protocol: c.protocol,
            has_protocol: true,
        }),
        _ => None,
    };

    let pid1 = prompt_id.clone();
    let pid2 = prompt_id.clone();
    let pid3 = prompt_id.clone();
    let pid4 = prompt_id.clone();
    let pid5 = prompt_id;

    let allow_once = button(text("Allow once").size(12))
        .padding([4, 10])
        .on_press(Message::SubmitVerdict {
            prompt_id: pid1,
            action: proto::Action::Allow,
            scope: None,
            duration: proto::Duration::Once,
        })
        .style(iced::widget::button::secondary);

    let allow_exe = button(text("Allow this app").size(12))
        .padding([4, 10])
        .on_press(Message::SubmitVerdict {
            prompt_id: pid2,
            action: proto::Action::Allow,
            scope: exe_scope.clone(),
            duration: proto::Duration::Always,
        })
        .style(iced::widget::button::primary);

    let allow_exe_dst = button(text("Allow this app for this dst").size(12))
        .padding([4, 10])
        .on_press(Message::SubmitVerdict {
            prompt_id: pid3,
            action: proto::Action::Allow,
            scope: exe_and_dst_scope,
            duration: proto::Duration::Always,
        })
        .style(iced::widget::button::primary);

    let deny_once = button(text("Deny once").size(12))
        .padding([4, 10])
        .on_press(Message::SubmitVerdict {
            prompt_id: pid4,
            action: proto::Action::Deny,
            scope: None,
            duration: proto::Duration::Once,
        })
        .style(iced::widget::button::secondary);

    let deny_exe = button(text("Deny this app").size(12))
        .padding([4, 10])
        .on_press(Message::SubmitVerdict {
            prompt_id: pid5,
            action: proto::Action::Deny,
            scope: exe_scope,
            duration: proto::Duration::Always,
        })
        .style(iced::widget::button::danger);

    let buttons = row![
        allow_once,
        allow_exe,
        allow_exe_dst,
        Space::new().width(Length::Fill),
        deny_once,
        deny_exe,
    ]
    .spacing(6);

    container(column![header, cmd_row, buttons].spacing(8))
        .padding(10)
        .into()
}
