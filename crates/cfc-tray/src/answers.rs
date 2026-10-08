//! Answers to the tray's prompt notifications, taken only from the
//! notification server.
//!
//! `ActionInvoked` is a signal, and any program on the session bus may emit
//! one with any notification id, broadcast or sent straight to the tray.
//! notify-rust's `wait_for_action` matched it with no sender, so a program
//! could press "Always allow app" on its own prompt through the tray, which
//! the daemon trusts. Here the server's unique name is looked up once (a
//! method reply, which no other client can forge), the bus is asked for
//! that sender's signals only, and every message's sender is checked again,
//! since a signal addressed to the tray reaches it whatever it subscribed to.
//!
//! The server itself is still trusted: a same-user program that replaces it
//! answers for the user (see docs/HARDENING.md).

use crate::model::KEY_CLOSED;
use tokio_stream::StreamExt as _;
use zbus::message::Type;
use zbus::names::{OwnedUniqueName, UniqueName};
use zbus::{Message, MessageStream};

const SERVER: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

/// Signals of the notification server that owned its name at subscription.
pub struct Answers {
    owner: OwnedUniqueName,
    stream: MessageStream,
}

impl Answers {
    /// Subscribes on `conn`. Call it before showing the bubble, so a click
    /// that comes before the wait starts is queued, not lost.
    pub async fn subscribe(conn: &zbus::Connection) -> zbus::Result<Self> {
        let owner = zbus::fdo::DBusProxy::new(conn)
            .await?
            .get_name_owner(SERVER.try_into()?)
            .await?;
        let rule = zbus::MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(owner.as_ref())?
            .path(PATH)?
            .interface(SERVER)?
            .build();
        let stream = MessageStream::for_match_rule(rule, conn, None).await?;
        Ok(Self { owner, stream })
    }

    /// The action key picked on notification `id`, or [`KEY_CLOSED`] once
    /// it closed. `None` when the bus connection ended first.
    pub async fn next_for(&mut self, id: u32) -> Option<String> {
        while let Some(message) = self.stream.next().await {
            if let Some(key) = message.ok().and_then(|m| answer(&m, &self.owner, id)) {
                return Some(key);
            }
        }
        None
    }
}

/// What `message` says about notification `id`, if it comes from `owner`.
fn answer(message: &Message, owner: &UniqueName<'_>, id: u32) -> Option<String> {
    let header = message.header();
    if header.message_type() != Type::Signal || header.sender() != Some(owner) {
        return None;
    }
    match header.member()?.as_str() {
        "ActionInvoked" => {
            let (nid, key): (u32, String) = message.body().deserialize().ok()?;
            (nid == id).then_some(key)
        }
        "NotificationClosed" => {
            let (nid, _reason): (u32, u32) = message.body().deserialize().ok()?;
            (nid == id).then(|| KEY_CLOSED.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead as _;
    use std::process::{Child, Command, Stdio};
    use zbus::connection::Builder;
    use zbus::names::BusName;

    /// A private session bus, killed on drop.
    struct Bus {
        child: Child,
        address: String,
        _dir: tempfile::TempDir,
    }

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn private_bus() -> Option<Bus> {
        let dir = tempfile::tempdir().ok()?;
        let mut child = Command::new("dbus-daemon")
            .arg("--session")
            .arg("--nofork")
            .arg("--print-address=1")
            .arg(format!(
                "--address=unix:path={}",
                dir.path().join("bus").display()
            ))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut address = String::new();
        std::io::BufReader::new(child.stdout.take()?)
            .read_line(&mut address)
            .ok()?;
        let address = address.trim().to_string();
        let bus = Bus {
            child,
            address,
            _dir: dir,
        };
        (!bus.address.is_empty()).then_some(bus)
    }

    async fn connect(bus: &Bus) -> zbus::Connection {
        Builder::address(bus.address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap()
    }

    async fn emit(
        from: &zbus::Connection,
        to: Option<BusName<'_>>,
        member: &str,
        body: &(u32, &str),
    ) {
        from.emit_signal(to, PATH, SERVER, member, body)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn only_the_notification_server_answers() {
        let Some(bus) = private_bus() else {
            eprintln!("skipped: dbus-daemon is not available");
            return;
        };
        let server = Builder::address(bus.address.as_str())
            .unwrap()
            .name(SERVER)
            .unwrap()
            .build()
            .await
            .unwrap();
        let tray = connect(&bus).await;
        let intruder = connect(&bus).await;
        let mut answers = Answers::subscribe(&tray).await.unwrap();

        // Forged, broadcast and addressed to the tray, with the right id.
        let tray_name = BusName::from(tray.unique_name().unwrap().clone());
        emit(&intruder, None, "ActionInvoked", &(7, "allow")).await;
        emit(
            &intruder,
            Some(tray_name.clone()),
            "ActionInvoked",
            &(7, "allow"),
        )
        .await;
        let closed: (u32, u32) = (7, 2);
        intruder
            .emit_signal(Some(tray_name), PATH, SERVER, "NotificationClosed", &closed)
            .await
            .unwrap();
        // A round trip on the intruder's connection: the bus has routed
        // everything it sent before this reply, so the forgeries come first.
        zbus::fdo::DBusProxy::new(&intruder)
            .await
            .unwrap()
            .get_id()
            .await
            .unwrap();

        // The server: another bubble first, then this one.
        emit(&server, None, "ActionInvoked", &(8, "allow")).await;
        emit(&server, None, "ActionInvoked", &(7, "deny")).await;
        assert_eq!(answers.next_for(7).await.as_deref(), Some("deny"));

        server
            .emit_signal(
                None::<BusName<'_>>,
                PATH,
                SERVER,
                "NotificationClosed",
                &closed,
            )
            .await
            .unwrap();
        assert_eq!(answers.next_for(7).await.as_deref(), Some(KEY_CLOSED));
    }

    #[tokio::test]
    async fn no_notification_server_is_an_error() {
        let Some(bus) = private_bus() else {
            eprintln!("skipped: dbus-daemon is not available");
            return;
        };
        assert!(Answers::subscribe(&connect(&bus).await).await.is_err());
    }
}
