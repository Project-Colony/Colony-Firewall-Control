use cfc_client::{convert, proto};
use iced::widget::{
    button, column, container, pick_list, row, scrollable, text, text_input, Space,
};
use iced::{Element, Length};

use crate::{Message, RuleEditor};

pub fn view<'a>(
    rules: &'a [proto::RuleInfo],
    filter: &'a str,
    editor: Option<&'a RuleEditor>,
) -> Element<'a, Message> {
    let body: Element<'a, Message> = if let Some(ed) = editor {
        editor_view(ed)
    } else {
        list_view(rules, filter)
    };

    container(body)
        .padding(8)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn rule_matches_filter(r: &proto::RuleInfo, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let n = needle.to_ascii_lowercase();
    if r.name.to_ascii_lowercase().contains(&n) {
        return true;
    }
    if let Some(s) = r.scope.as_ref() {
        if s.exe_path.to_ascii_lowercase().contains(&n) {
            return true;
        }
        if s.dst_host.to_ascii_lowercase().contains(&n) {
            return true;
        }
        if s.dst_net.to_ascii_lowercase().contains(&n) {
            return true;
        }
    }
    false
}

fn list_view<'a>(rules: &'a [proto::RuleInfo], filter: &'a str) -> Element<'a, Message> {
    let filtered: Vec<&proto::RuleInfo> = rules
        .iter()
        .filter(|r| rule_matches_filter(r, filter))
        .collect();

    let toolbar = row![
        button(text("+ Add rule").size(12))
            .padding([4, 12])
            .on_press(Message::OpenEditor)
            .style(iced::widget::button::primary),
        text_input("Search by name / exe / host", filter)
            .on_input(Message::RulesFilterChanged)
            .padding(4)
            .size(12)
            .width(Length::Fixed(260.0)),
        Space::new().width(Length::Fill),
        text(if filter.is_empty() {
            format!("{} rules", rules.len())
        } else {
            format!("{}/{} rules", filtered.len(), rules.len())
        })
        .size(11),
    ]
    .spacing(8)
    .padding(6)
    .align_y(iced::Alignment::Center);

    if rules.is_empty() {
        return column![
            toolbar,
            container(
                column![
                    text("No rules yet").size(18),
                    text("Click \"+ Add rule\" or answer a prompt with a persist option.").size(12),
                ]
                .spacing(8),
            )
            .padding(16),
        ]
        .spacing(6)
        .into();
    }

    if filtered.is_empty() {
        return column![
            toolbar,
            container(text(format!("No rules match \"{filter}\"")).size(13)).padding(16),
        ]
        .spacing(6)
        .into();
    }

    let header = row![
        text("on").size(11).width(Length::Fixed(40.0)),
        text("action").size(11).width(Length::Fixed(60.0)),
        text("duration").size(11).width(Length::Fixed(90.0)),
        text("summary").size(11).width(Length::Fill),
        text("hits").size(11).width(Length::Fixed(50.0)),
        text("").width(Length::Fixed(130.0)),
    ]
    .spacing(6)
    .padding(6);

    let rows: Vec<Element<'a, Message>> = filtered.iter().map(|r| rule_row(r)).collect();

    column![
        toolbar,
        header,
        scrollable(column(rows).spacing(2).padding([0, 6])).height(Length::Fill),
    ]
    .spacing(4)
    .into()
}

fn rule_row(r: &proto::RuleInfo) -> Element<'_, Message> {
    let id_for_toggle = r.id.clone();
    let id_for_edit = r.id.clone();
    let id_for_delete = r.id.clone();
    let toggle_label = if r.enabled { "on" } else { "off" };
    let toggle_style = if r.enabled {
        iced::widget::button::primary
    } else {
        iced::widget::button::secondary
    };

    row![
        button(text(toggle_label).size(11))
            .padding([2, 6])
            .on_press(Message::ToggleRuleEnabled(id_for_toggle))
            .style(toggle_style)
            .width(Length::Fixed(40.0)),
        text(convert::action_label(r.action))
            .size(12)
            .width(Length::Fixed(60.0)),
        text(convert::duration_label(r.duration))
            .size(12)
            .width(Length::Fixed(90.0)),
        text(convert::rule_summary(r)).size(12).width(Length::Fill),
        text(r.hit_count.to_string())
            .size(12)
            .width(Length::Fixed(50.0)),
        button(text("Edit").size(11))
            .padding([2, 8])
            .on_press(Message::EditExistingRule(id_for_edit))
            .style(iced::widget::button::secondary),
        button(text("Delete").size(11))
            .padding([2, 8])
            .on_press(Message::DeleteRule(id_for_delete))
            .style(iced::widget::button::danger),
    ]
    .spacing(6)
    .padding(4)
    .align_y(iced::Alignment::Center)
    .into()
}

fn editor_view(ed: &RuleEditor) -> Element<'_, Message> {
    let title = row![
        text(if ed.editing_id.is_some() {
            "Edit rule"
        } else {
            "New rule"
        })
        .size(18),
        Space::new().width(Length::Fill),
        button(text("Cancel").size(12))
            .padding([4, 10])
            .on_press(Message::CloseEditor)
            .style(iced::widget::button::secondary),
        button(text("Save").size(12))
            .padding([4, 12])
            .on_press(Message::SaveRule)
            .style(iced::widget::button::primary),
    ]
    .spacing(8)
    .padding(6)
    .align_y(iced::Alignment::Center);

    let name_field = labeled_input("Name", &ed.name, Message::EditorName, "ui-added");

    let action_pick = pick_list(
        [
            ActionOption::Allow,
            ActionOption::Deny,
            ActionOption::Reject,
        ],
        Some(ActionOption::from(ed.action)),
        |a| Message::EditorAction(a.into()),
    );
    let duration_pick = pick_list(
        [
            DurationOption::Once,
            DurationOption::UntilRestart,
            DurationOption::Always,
        ],
        Some(DurationOption::from(ed.duration)),
        |d| Message::EditorDuration(d.into()),
    );
    let protocol_pick = pick_list(
        [
            ProtoOption::Any,
            ProtoOption::Tcp,
            ProtoOption::Udp,
            ProtoOption::Icmp,
        ],
        Some(ProtoOption::from(ed.protocol)),
        |p| Message::EditorProtocol(p.into()),
    );

    let policy_row = row![
        labeled(action_pick.into(), "Action", 200.0),
        labeled(duration_pick.into(), "Duration", 200.0),
        labeled(protocol_pick.into(), "Protocol", 200.0),
    ]
    .spacing(12);

    let scope_intro = text("At least one match below is required:").size(11);
    let exe_field = labeled_input(
        "Executable path",
        &ed.exe,
        Message::EditorExe,
        "/usr/bin/curl",
    );
    let host_field = labeled_input(
        "Destination host",
        &ed.dst_host,
        Message::EditorDstHost,
        "example.com",
    );
    let net_field = labeled_input(
        "Destination CIDR",
        &ed.dst_net,
        Message::EditorDstNet,
        "10.0.0.0/8",
    );
    let port_field = labeled_input(
        "Destination port",
        &ed.dst_port,
        Message::EditorDstPort,
        "443",
    );

    let validation: Element<'_, Message> = match &ed.validation {
        Some(msg) => container(text(msg.clone()).size(11)).padding(4).into(),
        None => Space::new().into(),
    };

    container(scrollable(
        column![
            title,
            name_field,
            policy_row,
            scope_intro,
            exe_field,
            host_field,
            net_field,
            port_field,
            validation,
        ]
        .spacing(10)
        .padding(8),
    ))
    .into()
}

fn labeled_input<'a>(
    label: &'a str,
    value: &str,
    on_change: impl Fn(String) -> Message + 'a,
    placeholder: &'a str,
) -> Element<'a, Message> {
    column![
        text(label).size(11),
        text_input(placeholder, value)
            .on_input(on_change)
            .padding(6)
            .size(13),
    ]
    .spacing(3)
    .into()
}

fn labeled<'a>(field: Element<'a, Message>, label: &'a str, width: f32) -> Element<'a, Message> {
    container(
        column![text(label).size(11), field]
            .spacing(3)
            .width(Length::Fixed(width)),
    )
    .into()
}

/// Wraps Option<proto::Protocol> so iced's pick_list can show "Any".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoOption {
    Any,
    Tcp,
    Udp,
    Icmp,
}

impl From<Option<proto::Protocol>> for ProtoOption {
    fn from(v: Option<proto::Protocol>) -> Self {
        match v {
            None => ProtoOption::Any,
            Some(proto::Protocol::Tcp) => ProtoOption::Tcp,
            Some(proto::Protocol::Udp) => ProtoOption::Udp,
            Some(proto::Protocol::Icmp) => ProtoOption::Icmp,
            _ => ProtoOption::Any,
        }
    }
}

impl From<ProtoOption> for Option<proto::Protocol> {
    fn from(v: ProtoOption) -> Self {
        match v {
            ProtoOption::Any => None,
            ProtoOption::Tcp => Some(proto::Protocol::Tcp),
            ProtoOption::Udp => Some(proto::Protocol::Udp),
            ProtoOption::Icmp => Some(proto::Protocol::Icmp),
        }
    }
}

impl std::fmt::Display for ProtoOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProtoOption::Any => "Any",
            ProtoOption::Tcp => "TCP",
            ProtoOption::Udp => "UDP",
            ProtoOption::Icmp => "ICMP",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionOption {
    Allow,
    Deny,
    Reject,
}

impl From<proto::Action> for ActionOption {
    fn from(v: proto::Action) -> Self {
        match v {
            proto::Action::Deny => ActionOption::Deny,
            proto::Action::Reject => ActionOption::Reject,
            _ => ActionOption::Allow,
        }
    }
}

impl From<ActionOption> for proto::Action {
    fn from(v: ActionOption) -> Self {
        match v {
            ActionOption::Allow => proto::Action::Allow,
            ActionOption::Deny => proto::Action::Deny,
            ActionOption::Reject => proto::Action::Reject,
        }
    }
}

impl std::fmt::Display for ActionOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ActionOption::Allow => "Allow",
            ActionOption::Deny => "Deny",
            ActionOption::Reject => "Reject",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurationOption {
    Once,
    UntilRestart,
    Always,
}

impl From<proto::Duration> for DurationOption {
    fn from(v: proto::Duration) -> Self {
        match v {
            proto::Duration::Once => DurationOption::Once,
            proto::Duration::UntilRestart => DurationOption::UntilRestart,
            _ => DurationOption::Always,
        }
    }
}

impl From<DurationOption> for proto::Duration {
    fn from(v: DurationOption) -> Self {
        match v {
            DurationOption::Once => proto::Duration::Once,
            DurationOption::UntilRestart => proto::Duration::UntilRestart,
            DurationOption::Always => proto::Duration::Always,
        }
    }
}

impl std::fmt::Display for DurationOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DurationOption::Once => "Once",
            DurationOption::UntilRestart => "Until restart",
            DurationOption::Always => "Always",
        })
    }
}
