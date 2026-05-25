//! Colony Firewall Control - UI entry point.

mod streams;
mod theme;
mod views;

use cfc_client::{proto, Client};
use iced::widget::{button, column, container, row, text, Space};
use iced::{Element, Length, Subscription, Task};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

const SOCKET_PATH: &str = "/run/colony-firewall/cfc.sock";
const LIVE_CAP: usize = 500;

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,cfc_ui=info")),
        )
        .init();

    iced::application(App::new, App::update, App::view)
        .title(App::title)
        .theme(App::theme)
        .subscription(App::subscription)
        .run()
}

pub struct App {
    pub socket_path: PathBuf,
    pub tab: Tab,
    pub daemon: DaemonState,
    pub rules: Vec<proto::RuleInfo>,
    pub live: VecDeque<LiveEntry>,
    pub prompts: Vec<PromptCard>,
    pub status: Option<proto::StatusResponse>,
    pub last_error: Option<String>,
    pub editor: Option<RuleEditor>,
}

#[derive(Debug, Clone)]
pub struct RuleEditor {
    pub name: String,
    pub action: proto::Action,
    pub duration: proto::Duration,
    pub exe: String,
    pub dst_host: String,
    pub dst_net: String,
    pub dst_port: String,
    pub protocol: Option<proto::Protocol>,
    pub validation: Option<String>,
}

impl Default for RuleEditor {
    fn default() -> Self {
        Self {
            name: String::new(),
            action: proto::Action::Allow,
            duration: proto::Duration::Always,
            exe: String::new(),
            dst_host: String::new(),
            dst_net: String::new(),
            dst_port: String::new(),
            protocol: None,
            validation: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LiveEntry {
    pub event: proto::ConnectionEvent,
}

#[derive(Debug, Clone)]
pub struct PromptCard {
    pub event: proto::PromptEvent,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Prompts,
    Rules,
    Live,
    Stats,
}

#[derive(Debug, Clone)]
pub enum DaemonState {
    Connecting,
    Connected,
    Failed(String),
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
    Reconnect,
    HandshakeDone(Result<HandshakeData, String>),
    RulesLoaded(Result<Vec<proto::RuleInfo>, String>),
    DeleteRule(String),
    RuleDeleted(Result<(String, bool), String>),
    StatusLoaded(Result<proto::StatusResponse, String>),
    StatusTick,
    LiveEvent(proto::ConnectionEvent),
    LiveStreamEnded(String),
    PromptEvent(proto::PromptEvent),
    PromptStreamEnded(String),
    SubmitVerdict {
        prompt_id: String,
        action: proto::Action,
        scope: Option<proto::RuleScope>,
        duration: proto::Duration,
    },
    VerdictSubmitted(Result<(String, bool), String>),
    OpenEditor,
    CloseEditor,
    EditorName(String),
    EditorAction(proto::Action),
    EditorDuration(proto::Duration),
    EditorExe(String),
    EditorDstHost(String),
    EditorDstNet(String),
    EditorDstPort(String),
    EditorProtocol(Option<proto::Protocol>),
    SaveRule,
    RuleSaved(Result<String, String>),
}

#[derive(Debug, Clone)]
pub struct HandshakeData {
    pub status: proto::StatusResponse,
    pub rules: Vec<proto::RuleInfo>,
}

impl App {
    fn new() -> (Self, Task<Message>) {
        let app = Self {
            socket_path: PathBuf::from(SOCKET_PATH),
            tab: Tab::Prompts,
            daemon: DaemonState::Connecting,
            rules: Vec::new(),
            live: VecDeque::with_capacity(LIVE_CAP),
            prompts: Vec::new(),
            status: None,
            last_error: None,
            editor: None,
        };
        let socket = app.socket_path.clone();
        (
            app,
            Task::perform(handshake(socket), Message::HandshakeDone),
        )
    }

    fn title(&self) -> String {
        "Colony Firewall Control".to_string()
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::TabSelected(t) => {
                self.tab = t;
                Task::none()
            }
            Message::Reconnect => {
                self.daemon = DaemonState::Connecting;
                self.last_error = None;
                let socket = self.socket_path.clone();
                Task::perform(handshake(socket), Message::HandshakeDone)
            }
            Message::HandshakeDone(Ok(data)) => {
                self.daemon = DaemonState::Connected;
                self.status = Some(data.status);
                self.rules = data.rules;
                self.last_error = None;
                info!("connected to daemon");
                Task::none()
            }
            Message::HandshakeDone(Err(e)) => {
                self.daemon = DaemonState::Failed(e.clone());
                self.last_error = Some(e);
                Task::none()
            }
            Message::RulesLoaded(Ok(rules)) => {
                self.rules = rules;
                Task::none()
            }
            Message::RulesLoaded(Err(e)) => {
                self.last_error = Some(e);
                Task::none()
            }
            Message::DeleteRule(id) => {
                let socket = self.socket_path.clone();
                Task::perform(delete_rule(socket, id), Message::RuleDeleted)
            }
            Message::RuleDeleted(Ok((id, true))) => {
                self.rules.retain(|r| r.id != id);
                Task::none()
            }
            Message::RuleDeleted(Ok((_, false))) => Task::none(),
            Message::RuleDeleted(Err(e)) => {
                self.last_error = Some(e);
                Task::none()
            }
            Message::StatusLoaded(Ok(s)) => {
                self.status = Some(s);
                Task::none()
            }
            Message::StatusLoaded(Err(_)) => Task::none(),
            Message::StatusTick => {
                if matches!(self.daemon, DaemonState::Connected) {
                    let socket = self.socket_path.clone();
                    Task::perform(fetch_status(socket), Message::StatusLoaded)
                } else {
                    Task::none()
                }
            }
            Message::LiveEvent(ev) => {
                self.live.push_front(LiveEntry { event: ev });
                while self.live.len() > LIVE_CAP {
                    self.live.pop_back();
                }
                Task::none()
            }
            Message::LiveStreamEnded(e) => {
                self.last_error = Some(format!("live stream ended: {e}"));
                Task::none()
            }
            Message::PromptEvent(ev) => {
                notify_prompt(&ev);
                self.prompts.push(PromptCard { event: ev });
                Task::none()
            }
            Message::PromptStreamEnded(e) => {
                self.last_error = Some(format!("prompt stream ended: {e}"));
                Task::none()
            }
            Message::SubmitVerdict {
                prompt_id,
                action,
                scope,
                duration,
            } => {
                self.prompts.retain(|p| p.event.prompt_id != prompt_id);
                let socket = self.socket_path.clone();
                Task::perform(
                    submit_verdict(socket, prompt_id, action, scope, duration),
                    Message::VerdictSubmitted,
                )
            }
            Message::VerdictSubmitted(Ok(_)) => Task::none(),
            Message::VerdictSubmitted(Err(e)) => {
                self.last_error = Some(e);
                Task::none()
            }
            Message::OpenEditor => {
                self.editor = Some(RuleEditor::default());
                Task::none()
            }
            Message::CloseEditor => {
                self.editor = None;
                Task::none()
            }
            Message::EditorName(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.name = s;
                }
                Task::none()
            }
            Message::EditorAction(a) => {
                if let Some(ed) = &mut self.editor {
                    ed.action = a;
                }
                Task::none()
            }
            Message::EditorDuration(d) => {
                if let Some(ed) = &mut self.editor {
                    ed.duration = d;
                }
                Task::none()
            }
            Message::EditorExe(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.exe = s;
                }
                Task::none()
            }
            Message::EditorDstHost(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_host = s;
                }
                Task::none()
            }
            Message::EditorDstNet(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_net = s;
                }
                Task::none()
            }
            Message::EditorDstPort(s) => {
                if let Some(ed) = &mut self.editor {
                    ed.dst_port = s;
                }
                Task::none()
            }
            Message::EditorProtocol(p) => {
                if let Some(ed) = &mut self.editor {
                    ed.protocol = p;
                }
                Task::none()
            }
            Message::SaveRule => {
                let Some(editor) = &mut self.editor else {
                    return Task::none();
                };
                match build_rule_from_editor(editor) {
                    Ok(rule) => {
                        editor.validation = None;
                        let socket = self.socket_path.clone();
                        Task::perform(upsert_rule(socket, rule), Message::RuleSaved)
                    }
                    Err(e) => {
                        editor.validation = Some(e);
                        Task::none()
                    }
                }
            }
            Message::RuleSaved(Ok(_)) => {
                self.editor = None;
                let socket = self.socket_path.clone();
                Task::perform(fetch_rules(socket), Message::RulesLoaded)
            }
            Message::RuleSaved(Err(e)) => {
                if let Some(ed) = &mut self.editor {
                    ed.validation = Some(e.clone());
                }
                self.last_error = Some(e);
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let status_text = match &self.daemon {
            DaemonState::Connecting => "Connecting...".to_string(),
            DaemonState::Connected => "Connected".to_string(),
            DaemonState::Failed(e) => format!("Disconnected: {e}"),
        };

        let header = row![
            text("Colony Firewall Control").size(22),
            Space::new().width(Length::Fill),
            text(status_text).size(12),
            reconnect_button(&self.daemon),
        ]
        .padding(12)
        .spacing(12)
        .align_y(iced::Alignment::Center);

        let tabs = row![
            tab_button("Prompts", Tab::Prompts, self.tab, self.prompts.len()),
            tab_button_simple("Rules", Tab::Rules, self.tab),
            tab_button_simple("Live", Tab::Live, self.tab),
            tab_button_simple("Stats", Tab::Stats, self.tab),
        ]
        .spacing(8)
        .padding([0, 12]);

        let body: Element<'_, Message> = match self.tab {
            Tab::Prompts => views::prompts::view(&self.prompts),
            Tab::Rules => views::rules::view(&self.rules, self.editor.as_ref()),
            Tab::Live => views::live::view(&self.live),
            Tab::Stats => views::stats::view(self.status.as_ref()),
        };

        let footer: Element<'_, Message> = if let Some(err) = &self.last_error {
            container(text(format!("error: {err}")).size(11))
                .padding(6)
                .into()
        } else {
            container(text("")).into()
        };

        container(column![header, tabs, body, footer].spacing(8))
            .padding(8)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn theme(&self) -> iced::Theme {
        theme::parchment()
    }

    fn subscription(&self) -> Subscription<Message> {
        let mut subs = Vec::new();

        if matches!(self.daemon, DaemonState::Connected) {
            subs.push(iced::time::every(Duration::from_secs(2)).map(|_| Message::StatusTick));
            subs.push(streams::live_subscription(self.socket_path.clone()));
            subs.push(streams::prompts_subscription(self.socket_path.clone()));
        }

        Subscription::batch(subs)
    }
}

fn tab_button<'a>(label: &'a str, this: Tab, current: Tab, badge: usize) -> Element<'a, Message> {
    let display = if badge > 0 {
        format!("{label} ({badge})")
    } else {
        label.to_string()
    };
    let is_active = this == current;
    let btn = button(text(display))
        .on_press(Message::TabSelected(this))
        .padding([6, 14]);
    if is_active {
        btn.style(iced::widget::button::primary).into()
    } else {
        btn.style(iced::widget::button::secondary).into()
    }
}

fn tab_button_simple<'a>(label: &'a str, this: Tab, current: Tab) -> Element<'a, Message> {
    tab_button(label, this, current, 0)
}

fn reconnect_button(state: &DaemonState) -> Element<'_, Message> {
    match state {
        DaemonState::Connected | DaemonState::Connecting => container(text("")).into(),
        DaemonState::Failed(_) => button(text("Reconnect"))
            .on_press(Message::Reconnect)
            .padding([4, 10])
            .style(iced::widget::button::primary)
            .into(),
    }
}

async fn handshake(path: PathBuf) -> Result<HandshakeData, String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    let status = client.status().await.map_err(|e| e.to_string())?;
    let rules = client.list_rules().await.map_err(|e| e.to_string())?;
    Ok(HandshakeData { status, rules })
}

async fn fetch_status(path: PathBuf) -> Result<proto::StatusResponse, String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    client.status().await.map_err(|e| e.to_string())
}

async fn delete_rule(path: PathBuf, id: String) -> Result<(String, bool), String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    let ok = client.delete_rule(&id).await.map_err(|e| e.to_string())?;
    Ok((id, ok))
}

async fn fetch_rules(path: PathBuf) -> Result<Vec<proto::RuleInfo>, String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    client.list_rules().await.map_err(|e| e.to_string())
}

async fn upsert_rule(path: PathBuf, rule: proto::RuleInfo) -> Result<String, String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    client.upsert_rule(rule).await.map_err(|e| e.to_string())
}

fn build_rule_from_editor(ed: &RuleEditor) -> Result<proto::RuleInfo, String> {
    let name = if ed.name.trim().is_empty() {
        "ui-added".to_string()
    } else {
        ed.name.trim().to_string()
    };

    let dst_port = if ed.dst_port.trim().is_empty() {
        None
    } else {
        Some(
            ed.dst_port
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("\"{}\" is not a valid port", ed.dst_port))?,
        )
    };

    let dst_net = ed.dst_net.trim();
    if !dst_net.is_empty() {
        dst_net
            .parse::<ipnet::IpNet>()
            .map_err(|e| format!("dst-net invalid: {e}"))?;
    }

    // Need at least one scope predicate, else the rule would match everything.
    let scope_empty = ed.exe.trim().is_empty()
        && ed.dst_host.trim().is_empty()
        && dst_net.is_empty()
        && dst_port.is_none()
        && ed.protocol.is_none();
    if scope_empty {
        return Err(
            "rule must restrict at least one of: exe, dst-host, dst-net, dst-port, protocol".into(),
        );
    }

    let scope = proto::RuleScope {
        exe_path: ed.exe.trim().to_string(),
        exe_sha256: String::new(),
        parent_exe: String::new(),
        uid: 0,
        has_uid: false,
        dst_host: ed.dst_host.trim().to_string(),
        dst_net: dst_net.to_string(),
        dst_port: dst_port.map(u32::from).unwrap_or(0),
        has_dst_port: dst_port.is_some(),
        protocol: ed.protocol.map(|p| p as i32).unwrap_or(0),
        has_protocol: ed.protocol.is_some(),
    };

    Ok(proto::RuleInfo {
        id: String::new(),
        name,
        enabled: true,
        action: ed.action as i32,
        duration: ed.duration as i32,
        scope: Some(scope),
        created_at_unix_ms: 0,
        hit_count: 0,
    })
}

async fn submit_verdict(
    path: PathBuf,
    prompt_id: String,
    action: proto::Action,
    scope: Option<proto::RuleScope>,
    duration: proto::Duration,
) -> Result<(String, bool), String> {
    let mut client = Client::connect(&path).await.map_err(|e| e.to_string())?;
    let accepted = client
        .submit_verdict(&prompt_id, action, duration, scope)
        .await
        .map_err(|e| e.to_string())?;
    Ok((prompt_id, accepted))
}

fn notify_prompt(ev: &proto::PromptEvent) {
    let (process_name, pid) = match ev.process.as_ref() {
        Some(p) => (cfc_client::convert::process_display(p), p.pid),
        None => ("unknown".to_string(), 0),
    };
    let target = match ev.connection.as_ref() {
        Some(c) => format!("{}:{}", c.dst_ip, c.dst_port),
        None => "?".to_string(),
    };
    let body = format!("{process_name} (pid {pid}) -> {target}");
    let _ = notify_rust::Notification::new()
        .summary("Colony Firewall: new connection")
        .body(&body)
        .icon("network-firewall")
        .timeout(notify_rust::Timeout::Milliseconds(8000))
        .show();
}
