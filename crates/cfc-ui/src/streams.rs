//! iced Subscriptions over cfc-client's self-reconnecting gRPC streams.
//!
//! Reconnection itself - connect, subscribe, exponential backoff capped at
//! `cfc_client::RECONNECT_MAX`, and reporting the connection lifecycle -
//! lives in cfc-client so the CLI and the GUI behave identically. All that
//! is left here is mapping [`StreamItem`] onto App [`Message`]s.

use crate::Message;
use cfc_client::{proto, StreamItem};
use futures::{stream, Stream, StreamExt};
use iced::Subscription;
use std::hash::Hash;
use std::path::PathBuf;

/// How this client names itself to the daemon's subscriber bookkeeping.
const CLIENT_ID: &str = "cfc-ui";

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

fn map_live(item: StreamItem<proto::ConnectionEvent>) -> Message {
    match item {
        StreamItem::Connected => Message::StreamConnected,
        StreamItem::Event(ev) => Message::LiveEvent(ev),
        StreamItem::Disconnected(err) => Message::LiveStreamEnded(err.to_string()),
    }
}

fn map_prompts(item: StreamItem<proto::PromptEvent>) -> Message {
    match item {
        StreamItem::Connected => Message::StreamConnected,
        StreamItem::Event(ev) => Message::PromptEvent(ev),
        StreamItem::Disconnected(err) => Message::PromptStreamEnded(err.to_string()),
    }
}

/// The resilient streams drive their pump from a `tokio::spawn`, so building
/// one is deferred to the first poll: by then iced is polling us from inside
/// its executor and a runtime is guaranteed to be in context.
fn live_stream(path: PathBuf) -> impl Stream<Item = Message> + Send {
    stream::once(async move {
        cfc_client::stream_connections_resilient(path, CLIENT_ID.to_string()).map(map_live)
    })
    .flatten()
}

/// See [`live_stream`] for why construction is deferred.
fn prompts_stream(path: PathBuf) -> impl Stream<Item = Message> + Send {
    stream::once(async move {
        cfc_client::stream_prompts_resilient(path, CLIENT_ID.to_string()).map(map_prompts)
    })
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfc_client::ClientError;

    #[test]
    fn live_items_map_onto_the_ui_messages() {
        assert!(matches!(
            map_live(StreamItem::Connected),
            Message::StreamConnected
        ));
        assert!(matches!(
            map_live(StreamItem::Event(proto::ConnectionEvent::default())),
            Message::LiveEvent(_)
        ));
        match map_live(StreamItem::Disconnected(ClientError::StreamClosed)) {
            Message::LiveStreamEnded(e) => assert!(e.contains("stream closed"), "{e}"),
            other => panic!("expected LiveStreamEnded, got {other:?}"),
        }
    }

    #[test]
    fn prompt_items_map_onto_the_ui_messages() {
        assert!(matches!(
            map_prompts(StreamItem::Connected),
            Message::StreamConnected
        ));
        assert!(matches!(
            map_prompts(StreamItem::Event(proto::PromptEvent::default())),
            Message::PromptEvent(_)
        ));
        match map_prompts(StreamItem::Disconnected(ClientError::StreamClosed)) {
            Message::PromptStreamEnded(e) => assert!(e.contains("stream closed"), "{e}"),
            other => panic!("expected PromptStreamEnded, got {other:?}"),
        }
    }

    /// Both feeds share the one `stream_trouble` flag, so a reconnect on
    /// either must be able to clear it - the same message on purpose.
    #[test]
    fn both_feeds_report_reconnection_with_the_same_message() {
        assert!(matches!(
            map_live(StreamItem::Connected),
            Message::StreamConnected
        ));
        assert!(matches!(
            map_prompts(StreamItem::Connected),
            Message::StreamConnected
        ));
    }
}
