//! Minimal `sd_notify(3)` client. std only -- no new dependencies.
//!
//! systemd passes the notification socket in `$NOTIFY_SOCKET` when the
//! unit is `Type=notify`. When the variable is unset (not running under
//! systemd, or a plain `Type=simple` unit), every call is a successful
//! no-op, so callers notify unconditionally and never gate on environment.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Sends the given state lines (e.g. `["READY=1"]`) joined with `\n` as a
/// single datagram to `$NOTIFY_SOCKET`. Abstract-namespace sockets (a
/// leading `@`) are supported. No-op `Ok` when the variable is unset.
pub fn notify(msgs: &[&str]) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    if msgs.is_empty() {
        return Ok(());
    }
    let payload = msgs.join("\n");
    let sock = UnixDatagram::unbound()?;
    match path.as_bytes().strip_prefix(b"@") {
        Some(abstract_name) => {
            let addr = SocketAddr::from_abstract_name(abstract_name)?;
            sock.send_to_addr(payload.as_bytes(), &addr)?;
        }
        None => {
            sock.send_to(payload.as_bytes(), &path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    /// `NOTIFY_SOCKET` is process-global; serialize the tests touching it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn unset_socket_is_a_successful_noop() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("NOTIFY_SOCKET");
        notify(&["READY=1"]).expect("must no-op Ok without NOTIFY_SOCKET");
    }

    #[test]
    fn delivers_joined_payload_to_path_socket() {
        let _guard = ENV_LOCK.lock().unwrap();
        // sun_path caps socket paths at ~108 bytes; fall back to /tmp when
        // the ambient temp dir (e.g. a deep $TMPDIR) would overflow it.
        let mut dir = std::env::temp_dir();
        if dir.as_os_str().len() > 60 {
            dir = std::path::PathBuf::from("/tmp");
        }
        let path = dir.join(format!("cfc-sd-notify-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let receiver = UnixDatagram::bind(&path).expect("binding temp notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        std::env::set_var("NOTIFY_SOCKET", &path);
        let sent = notify(&["READY=1", "STATUS=up"]);
        std::env::remove_var("NOTIFY_SOCKET");
        sent.expect("notify should send");

        let mut buf = [0u8; 64];
        let n = receiver.recv(&mut buf).expect("datagram should arrive");
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=up");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delivers_to_abstract_socket() {
        let _guard = ENV_LOCK.lock().unwrap();
        let name = format!("cfc-sd-notify-abstract-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&addr).expect("binding abstract socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        std::env::set_var("NOTIFY_SOCKET", format!("@{name}"));
        let sent = notify(&["WATCHDOG=1"]);
        std::env::remove_var("NOTIFY_SOCKET");
        sent.expect("notify should send");

        let mut buf = [0u8; 64];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
    }
}
