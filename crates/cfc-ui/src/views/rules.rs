use cfc_client::{convert, proto};
use iced::widget::{
    button, column, container, pick_list, row, scrollable, text, text_input, Space,
};
use iced::{Element, Length};
use std::cmp::Ordering;

use crate::{format, Message, RuleEditor, DELETE_CONFIRM_MS};

/// Which column the list is ordered by, and in which direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RuleSort {
    /// Busiest rules first - the useful default when auditing.
    #[default]
    HitsDesc,
    HitsAsc,
    CreatedDesc,
    CreatedAsc,
    NameAsc,
    NameDesc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Hits,
    Created,
    Name,
}

impl RuleSort {
    pub fn key(self) -> SortKey {
        match self {
            RuleSort::HitsDesc | RuleSort::HitsAsc => SortKey::Hits,
            RuleSort::CreatedDesc | RuleSort::CreatedAsc => SortKey::Created,
            RuleSort::NameAsc | RuleSort::NameDesc => SortKey::Name,
        }
    }

    /// Result of clicking `key`'s header: same column flips direction, a
    /// new column starts at its most useful direction.
    pub fn toggled(self, key: SortKey) -> RuleSort {
        match (key, self) {
            (SortKey::Hits, RuleSort::HitsDesc) => RuleSort::HitsAsc,
            (SortKey::Hits, _) => RuleSort::HitsDesc,
            (SortKey::Created, RuleSort::CreatedDesc) => RuleSort::CreatedAsc,
            (SortKey::Created, _) => RuleSort::CreatedDesc,
            (SortKey::Name, RuleSort::NameAsc) => RuleSort::NameDesc,
            (SortKey::Name, _) => RuleSort::NameAsc,
        }
    }

    fn arrow(self, key: SortKey) -> &'static str {
        if self.key() != key {
            return "";
        }
        match self {
            RuleSort::HitsDesc | RuleSort::CreatedDesc | RuleSort::NameDesc => " ▼",
            RuleSort::HitsAsc | RuleSort::CreatedAsc | RuleSort::NameAsc => " ▲",
        }
    }
}

/// Total order over rules. Ties always break on id so the table never
/// reshuffles between refreshes.
pub fn compare_rules(a: &proto::RuleInfo, b: &proto::RuleInfo, sort: RuleSort) -> Ordering {
    let primary = match sort {
        RuleSort::HitsDesc => b.hit_count.cmp(&a.hit_count),
        RuleSort::HitsAsc => a.hit_count.cmp(&b.hit_count),
        RuleSort::CreatedDesc => b.created_at_unix_ms.cmp(&a.created_at_unix_ms),
        RuleSort::CreatedAsc => a.created_at_unix_ms.cmp(&b.created_at_unix_ms),
        RuleSort::NameAsc => a
            .name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase()),
        RuleSort::NameDesc => b
            .name
            .to_ascii_lowercase()
            .cmp(&a.name.to_ascii_lowercase()),
    };
    primary.then_with(|| a.id.cmp(&b.id))
}

pub struct ListArgs<'a> {
    pub rules: &'a [proto::RuleInfo],
    pub filter: &'a str,
    pub editor: Option<&'a RuleEditor>,
    pub sort: RuleSort,
    /// Rule id whose Delete button is armed, and when it was armed.
    pub pending_delete: Option<&'a (String, i64)>,
    pub now_ms: i64,
}

pub fn view(args: ListArgs<'_>) -> Element<'_, Message> {
    let body: Element<'_, Message> = match args.editor {
        Some(ed) => editor_view(ed),
        None => list_view(args),
    };

    container(body)
        .padding(8)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

pub fn rule_matches_filter(r: &proto::RuleInfo, needle: &str) -> bool {
    let n = needle.trim().to_ascii_lowercase();
    if n.is_empty() {
        return true;
    }
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

fn list_view(args: ListArgs<'_>) -> Element<'_, Message> {
    let ListArgs {
        rules,
        filter,
        sort,
        pending_delete,
        now_ms,
        ..
    } = args;

    let mut filtered: Vec<&proto::RuleInfo> = rules
        .iter()
        .filter(|r| rule_matches_filter(r, filter))
        .collect();
    filtered.sort_by(|a, b| compare_rules(a, b, sort));

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
        text(if filter.trim().is_empty() {
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
        text("action").size(11).width(Length::Fixed(56.0)),
        text("duration").size(11).width(Length::Fixed(84.0)),
        sort_header("name / scope", SortKey::Name, sort, Length::Fill),
        sort_header("created", SortKey::Created, sort, Length::Fixed(110.0)),
        sort_header("hits", SortKey::Hits, sort, Length::Fixed(54.0)),
        text("").width(Length::Fixed(140.0)),
    ]
    .spacing(6)
    .padding([0, 6])
    .align_y(iced::Alignment::Center);

    let rows: Vec<Element<'_, Message>> = filtered
        .iter()
        .map(|r| rule_row(r, pending_delete, now_ms))
        .collect();

    column![
        toolbar,
        header,
        scrollable(column(rows).spacing(2).padding([0, 6])).height(Length::Fill),
    ]
    .spacing(4)
    .into()
}

fn sort_header<'a>(
    label: &'a str,
    key: SortKey,
    sort: RuleSort,
    width: Length,
) -> Element<'a, Message> {
    button(text(format!("{label}{}", sort.arrow(key))).size(11))
        .padding([4, 4])
        .width(width)
        .on_press(Message::RulesSortBy(sort.toggled(key)))
        .style(crate::theme::column_header)
        .into()
}

fn rule_row<'a>(
    r: &'a proto::RuleInfo,
    pending_delete: Option<&(String, i64)>,
    now_ms: i64,
) -> Element<'a, Message> {
    let toggle_label = if r.enabled { "on" } else { "off" };
    let toggle_style = if r.enabled {
        iced::widget::button::primary
    } else {
        iced::widget::button::secondary
    };

    // Two-step delete: the first click arms this row, a second click
    // within DELETE_CONFIRM_MS actually removes the rule.
    let armed = pending_delete
        .is_some_and(|(id, at)| *id == r.id && now_ms.saturating_sub(*at) <= DELETE_CONFIRM_MS);
    let delete_label = if armed { "Confirm?" } else { "Delete" };

    row![
        button(text(toggle_label).size(11))
            .padding([2, 6])
            .on_press(Message::ToggleRuleEnabled(r.id.clone()))
            .style(toggle_style)
            .width(Length::Fixed(40.0)),
        text(convert::action_label(r.action))
            .size(12)
            .width(Length::Fixed(56.0)),
        text(convert::duration_label(r.duration))
            .size(12)
            .width(Length::Fixed(84.0)),
        column![
            text(if r.name.is_empty() {
                "(unnamed)".to_string()
            } else {
                r.name.clone()
            })
            .size(12),
            text(convert::rule_summary(r)).size(10),
        ]
        .spacing(1)
        .width(Length::Fill),
        text(format::format_unix_ms(r.created_at_unix_ms))
            .size(11)
            .width(Length::Fixed(110.0)),
        text(r.hit_count.to_string())
            .size(12)
            .width(Length::Fixed(54.0)),
        button(text("Edit").size(11))
            .padding([2, 8])
            .on_press(Message::EditExistingRule(r.id.clone()))
            .style(iced::widget::button::secondary),
        button(text(delete_label).size(11))
            .padding([2, 8])
            .on_press(Message::DeleteRule(r.id.clone()))
            .style(if armed {
                iced::widget::button::danger
            } else {
                iced::widget::button::secondary
            }),
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
        text("Esc cancel · Enter save").size(10),
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
    // Once is intentionally absent: the daemon rejects a persisted Once
    // rule, so offering it here would only produce an error.
    let duration_pick = pick_list(
        [DurationOption::UntilRestart, DurationOption::Always],
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
        Some(msg) => container(text(msg.clone()).size(11))
            .padding(6)
            .width(Length::Fill)
            .style(crate::theme::banner_err)
            .into(),
        None => Space::new().into(),
    };

    // This rule restricts more than the fields above can show. Saving keeps
    // those predicates, but the user should know they are there rather than
    // read the visible fields as the whole rule.
    let carried: Element<'_, Message> = if ed.carried_scope.is_set() {
        container(
            text(format!(
                "also restricted to {} - kept on save, edit with cfc",
                ed.carried_scope.summary()
            ))
            .size(11),
        )
        .padding(6)
        .width(Length::Fill)
        .style(crate::theme::banner_warn)
        .into()
    } else {
        Space::new().into()
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
            carried,
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
            .on_submit(Message::SaveRule)
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

/// Shared with the prompt cards, which offer the same three choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationOption {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, name: &str, hits: u64, created: i64) -> proto::RuleInfo {
        proto::RuleInfo {
            id: id.into(),
            name: name.into(),
            enabled: true,
            action: proto::Action::Allow as i32,
            duration: proto::Duration::Always as i32,
            scope: Some(proto::RuleScope {
                exe_path: "/usr/bin/curl".into(),
                exe_sha256: String::new(),
                parent_exe: String::new(),
                uid: 0,
                has_uid: false,
                dst_host: "example.com".into(),
                dst_net: String::new(),
                dst_port: 443,
                has_dst_port: true,
                protocol: proto::Protocol::Tcp as i32,
                has_protocol: true,
            }),
            created_at_unix_ms: created,
            hit_count: hits,
        }
    }

    fn sorted(rules: &[proto::RuleInfo], sort: RuleSort) -> Vec<&str> {
        let mut v: Vec<&proto::RuleInfo> = rules.iter().collect();
        v.sort_by(|a, b| compare_rules(a, b, sort));
        v.iter().map(|r| r.id.as_str()).collect()
    }

    #[test]
    fn hits_and_created_sort_both_directions() {
        let rules = vec![
            rule("a", "alpha", 5, 100),
            rule("b", "bravo", 50, 50),
            rule("c", "charlie", 0, 300),
        ];
        assert_eq!(sorted(&rules, RuleSort::HitsDesc), ["b", "a", "c"]);
        assert_eq!(sorted(&rules, RuleSort::HitsAsc), ["c", "a", "b"]);
        assert_eq!(sorted(&rules, RuleSort::CreatedDesc), ["c", "a", "b"]);
        assert_eq!(sorted(&rules, RuleSort::CreatedAsc), ["b", "a", "c"]);
    }

    #[test]
    fn name_sort_is_case_insensitive() {
        let rules = vec![
            rule("1", "Zebra", 0, 0),
            rule("2", "apple", 0, 0),
            rule("3", "Mango", 0, 0),
        ];
        assert_eq!(sorted(&rules, RuleSort::NameAsc), ["2", "3", "1"]);
        assert_eq!(sorted(&rules, RuleSort::NameDesc), ["1", "3", "2"]);
    }

    #[test]
    fn ties_break_on_id_so_the_table_is_stable() {
        let rules = vec![rule("z", "same", 7, 1), rule("a", "same", 7, 1)];
        assert_eq!(sorted(&rules, RuleSort::HitsDesc), ["a", "z"]);
        assert_eq!(sorted(&rules, RuleSort::CreatedDesc), ["a", "z"]);
    }

    #[test]
    fn clicking_a_header_flips_only_its_own_column() {
        assert_eq!(RuleSort::HitsDesc.toggled(SortKey::Hits), RuleSort::HitsAsc);
        assert_eq!(RuleSort::HitsAsc.toggled(SortKey::Hits), RuleSort::HitsDesc);
        // Switching columns starts at the most useful direction.
        assert_eq!(
            RuleSort::HitsAsc.toggled(SortKey::Created),
            RuleSort::CreatedDesc
        );
        assert_eq!(RuleSort::HitsDesc.toggled(SortKey::Name), RuleSort::NameAsc);
        assert_eq!(RuleSort::NameAsc.toggled(SortKey::Name), RuleSort::NameDesc);
    }

    #[test]
    fn default_sort_is_busiest_first() {
        assert_eq!(RuleSort::default(), RuleSort::HitsDesc);
        assert_eq!(RuleSort::default().key(), SortKey::Hits);
    }

    #[test]
    fn arrow_only_marks_the_active_column() {
        assert_eq!(RuleSort::HitsDesc.arrow(SortKey::Hits), " ▼");
        assert_eq!(RuleSort::HitsAsc.arrow(SortKey::Hits), " ▲");
        assert_eq!(RuleSort::HitsDesc.arrow(SortKey::Name), "");
    }

    #[test]
    fn filter_matches_name_exe_and_destination() {
        let r = rule("1", "let curl out", 0, 0);
        assert!(rule_matches_filter(&r, ""));
        assert!(rule_matches_filter(&r, "   "));
        assert!(rule_matches_filter(&r, "CURL"));
        assert!(rule_matches_filter(&r, "/usr/bin"));
        assert!(rule_matches_filter(&r, "example.com"));
        assert!(!rule_matches_filter(&r, "firefox"));
    }
}
