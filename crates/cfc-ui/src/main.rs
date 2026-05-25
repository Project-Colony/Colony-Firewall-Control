//! Colony Firewall Control - UI entry point.

mod theme;
mod views;

use iced::widget::{column, container, row, text, Space};
use iced::{Element, Length, Task};

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    iced::application(App::title, App::update, App::view)
        .theme(App::theme)
        .run_with(App::new)
}

#[derive(Debug, Default)]
struct App {
    tab: Tab,
    status_text: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Prompts,
    Rules,
    Live,
    Stats,
}

#[derive(Debug, Clone)]
enum Message {
    TabSelected(Tab),
    DaemonStatus(Result<String, String>),
}

impl App {
    fn new() -> (Self, Task<Message>) {
        let app = Self {
            tab: Tab::Prompts,
            status_text: "Not connected to daemon".to_string(),
        };
        (app, Task::none())
    }

    fn title(&self) -> String {
        "Colony Firewall Control".to_string()
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::TabSelected(t) => self.tab = t,
            Message::DaemonStatus(Ok(s)) => self.status_text = s,
            Message::DaemonStatus(Err(e)) => {
                self.status_text = format!("daemon error: {e}")
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let header = row![
            text("Colony Firewall Control").size(22),
            Space::with_width(Length::Fill),
            text(&self.status_text).size(12),
        ]
        .padding(12)
        .spacing(12)
        .align_y(iced::Alignment::Center);

        let tabs = row![
            tab_button("Prompts", Tab::Prompts, self.tab),
            tab_button("Rules", Tab::Rules, self.tab),
            tab_button("Live", Tab::Live, self.tab),
            tab_button("Stats", Tab::Stats, self.tab),
        ]
        .spacing(8)
        .padding([0, 12]);

        let body: Element<'_, Message> = match self.tab {
            Tab::Prompts => views::prompts::view(),
            Tab::Rules => views::rules::view(),
            Tab::Live => views::live::view(),
            Tab::Stats => views::stats::view(),
        };

        container(column![header, tabs, body].spacing(12))
            .padding(8)
            .into()
    }

    fn theme(&self) -> iced::Theme {
        theme::parchment()
    }
}

fn tab_button<'a>(label: &'a str, this: Tab, current: Tab) -> Element<'a, Message> {
    let is_active = this == current;
    let btn = iced::widget::button(text(label))
        .on_press(Message::TabSelected(this))
        .padding([6, 14]);
    if is_active {
        btn.style(iced::widget::button::primary).into()
    } else {
        btn.style(iced::widget::button::secondary).into()
    }
}
