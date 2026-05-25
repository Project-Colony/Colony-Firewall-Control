//! iced Subscriptions that connect to the daemon's gRPC streams and emit
//! Messages into the App.

use crate::Message;
use cfc_client::Client;
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use iced::stream;
use iced::Subscription;
use std::hash::Hash;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct SubKey {
    pub kind: SubKind,
    pub path: PathBuf,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum SubKind {
    Live,
    Prompts,
}

pub fn live_subscription(path: PathBuf) -> Subscription<Message> {
    Subscription::run_with(
        SubKey {
            kind: SubKind::Live,
            path,
        },
        build_stream,
    )
}

pub fn prompts_subscription(path: PathBuf) -> Subscription<Message> {
    Subscription::run_with(
        SubKey {
            kind: SubKind::Prompts,
            path,
        },
        build_stream,
    )
}

fn build_stream(key: &SubKey) -> impl Stream<Item = Message> {
    let path = key.path.clone();
    let kind = key.kind;
    match kind {
        SubKind::Live => {
            Box::pin(live_stream(path)) as std::pin::Pin<Box<dyn Stream<Item = Message> + Send>>
        }
        SubKind::Prompts => {
            Box::pin(prompts_stream(path)) as std::pin::Pin<Box<dyn Stream<Item = Message> + Send>>
        }
    }
}

fn live_stream(path: PathBuf) -> impl Stream<Item = Message> + Send {
    stream::channel(256, move |mut output: mpsc::Sender<Message>| async move {
        loop {
            let mut client = match Client::connect(&path).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = output
                        .send(Message::LiveStreamEnded(format!("connect: {e}")))
                        .await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            let mut stream = match client.stream_connections("cfc-ui".into()).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = output
                        .send(Message::LiveStreamEnded(format!("subscribe: {e}")))
                        .await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => {
                        if output.send(Message::LiveEvent(ev)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = output.send(Message::LiveStreamEnded(e.to_string())).await;
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

fn prompts_stream(path: PathBuf) -> impl Stream<Item = Message> + Send {
    stream::channel(64, move |mut output: mpsc::Sender<Message>| async move {
        loop {
            let mut client = match Client::connect(&path).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = output
                        .send(Message::PromptStreamEnded(format!("connect: {e}")))
                        .await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            let mut stream = match client.stream_prompts("cfc-ui".into()).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = output
                        .send(Message::PromptStreamEnded(format!("subscribe: {e}")))
                        .await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => {
                        if output.send(Message::PromptEvent(ev)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = output.send(Message::PromptStreamEnded(e.to_string())).await;
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}
