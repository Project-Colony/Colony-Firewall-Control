//! Administrator authorization through polkit.
//!
//! Pause, resume and rule import change the whole firewall at once, and an
//! Allow rule that names no program opens it for every program, so even the
//! official app and tray must have them confirmed by an administrator:
//! the daemon asks polkit's `CheckAuthorization` for the calling process,
//! with user interaction allowed, and the user's polkit agent shows its
//! password dialog. The shipped policy
//! (`pkg/org.projectcolony.firewall.policy`) asks every time for pause and
//! resume (`auth_admin`: any same-user program can click the tray's menu
//! over D-Bus, so a kept authorization would let it pause unseen) and keeps
//! an import or allow-every-program authorization a few minutes
//! (`auth_admin_keep`). Root never gets here, and neither do prompt answers
//! or edits of rules that name a program or deny.
//!
//! One fresh system-bus connection per call: these calls are rare, and a
//! connection kept open would be one more thing to babysit across D-Bus
//! restarts.

use crate::ipc::PeerId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use zbus::zvariant::Value;

/// Pause or resume filtering (`SetPaused`, both directions).
pub const PAUSE: &str = "org.projectcolony.firewall.pause";
/// Import, replace or bundle-install rules (`ApplyRules`).
pub const IMPORT_RULES: &str = "org.projectcolony.firewall.import-rules";
/// Store an enabled Allow rule that names no program (`UpsertRule`, or a
/// prompt answer customized into one), which lets every program through.
pub const GENERIC_ALLOW: &str = "org.projectcolony.firewall.allow-every-program";
/// How long the daemon waits for the user to answer the dialog. Clients wait
/// longer (`cfc_client::INTERACTIVE_TIMEOUT`), so this answer reaches them.
pub const TIMEOUT: Duration = Duration::from_secs(120);

const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
/// `CheckAuthorizationFlags.AllowUserInteraction`.
const ALLOW_USER_INTERACTION: u32 = 1;

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait Authority {
    fn check_authorization(
        &self,
        subject: &(&str, HashMap<&str, Value<'_>>),
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;

    fn cancel_check_authorization(&self, cancellation_id: &str) -> zbus::Result<()>;
}

/// Asks polkit whether `peer` may perform `action`, letting its agent ask
/// the user. `Err` carries the reason the client shows.
pub async fn check(peer: PeerId, action: &'static str) -> Result<(), String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let (Some(pid), Some(start_time)) = (
        peer.pid.and_then(|pid| u32::try_from(pid).ok()),
        peer.starttime,
    ) else {
        return Err("the caller's process could not be identified for polkit".into());
    };
    let unreachable = |e: zbus::Error| {
        format!(
            "this needs administrator authorization, but the system D-Bus is unreachable \
             ({e}); use sudo cfc instead"
        )
    };
    let bus = zbus::connection::Builder::system()
        .map_err(unreachable)?
        .method_timeout(TIMEOUT + Duration::from_secs(10))
        .build()
        .await
        .map_err(unreachable)?;
    let authority = AuthorityProxy::builder(&bus)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(|e| call_error(&e))?;
    let subject = (
        "unix-process",
        HashMap::from([
            ("pid", Value::from(pid)),
            // Clock ticks since boot, the same field 22 polkit reads.
            ("start-time", Value::from(start_time)),
            ("uid", Value::from(peer.uid as i32)),
        ]),
    );
    let cancellation = format!("cfc-{pid}-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    let call = authority.check_authorization(
        &subject,
        action,
        HashMap::new(),
        ALLOW_USER_INTERACTION,
        &cancellation,
    );
    match tokio::time::timeout(TIMEOUT, call).await {
        Ok(Ok((authorized, challenge, details))) => outcome(authorized, challenge, &details),
        Ok(Err(e)) => Err(call_error(&e)),
        Err(_) => {
            // Close the dialog the user did not answer.
            let _ = authority.cancel_check_authorization(&cancellation).await;
            Err(format!(
                "authorization timed out after {} s",
                TIMEOUT.as_secs()
            ))
        }
    }
}

/// What a `CheckAuthorization` answer means for the caller.
fn outcome(
    authorized: bool,
    challenge: bool,
    details: &HashMap<String, String>,
) -> Result<(), String> {
    if authorized {
        Ok(())
    } else if details.get("polkit.dismissed").map(String::as_str) == Some("true") {
        Err("authorization dialog dismissed".into())
    } else if challenge {
        Err(
            "no polkit authentication agent answered in your session (start one, e.g. \
             hyprpolkitagent or polkit-gnome) or use sudo cfc"
                .into(),
        )
    } else {
        Err("not authorized by polkit policy".into())
    }
}

fn call_error(e: &zbus::Error) -> String {
    let unknown = match e {
        zbus::Error::MethodError(name, ..) => name.as_str() == SERVICE_UNKNOWN,
        zbus::Error::FDO(fdo) => matches!(**fdo, zbus::fdo::Error::ServiceUnknown(_)),
        _ => false,
    };
    if unknown {
        "polkit is not installed or not running; use sudo cfc instead".into()
    } else {
        format!("polkit check failed: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `<defaults>` the shipped policy file gives `action`.
    fn shipped_defaults(action: &str) -> Vec<&'static str> {
        const POLICY: &str = include_str!("../../../pkg/org.projectcolony.firewall.policy");
        let block = POLICY
            .split("<action id=\"")
            .find(|block| block.starts_with(&format!("{action}\"")))
            .unwrap_or_else(|| panic!("{action} is not in the shipped policy"));
        ["allow_any", "allow_inactive", "allow_active"]
            .iter()
            .map(|key| {
                block
                    .split(&format!("<{key}>"))
                    .nth(1)
                    .and_then(|rest| rest.split('<').next())
                    .unwrap_or_else(|| panic!("{action} has no {key}"))
            })
            .collect()
    }

    #[test]
    fn pause_asks_every_time_and_an_import_is_kept() {
        assert_eq!(shipped_defaults(PAUSE), ["auth_admin"; 3]);
        assert_eq!(shipped_defaults(IMPORT_RULES), ["auth_admin_keep"; 3]);
        assert_eq!(shipped_defaults(GENERIC_ALLOW), ["auth_admin_keep"; 3]);
    }

    #[test]
    fn outcome_mapping() {
        let none = HashMap::new();
        assert_eq!(outcome(true, false, &none), Ok(()));
        assert_eq!(
            outcome(true, true, &none),
            Ok(()),
            "authorized wins over a stale challenge flag"
        );
        let dismissed = HashMap::from([("polkit.dismissed".to_string(), "true".to_string())]);
        assert_eq!(
            outcome(false, true, &dismissed).unwrap_err(),
            "authorization dialog dismissed"
        );
        let no_agent = outcome(false, true, &none).unwrap_err();
        assert!(no_agent.starts_with("no polkit authentication agent answered"));
        assert!(no_agent.contains("sudo cfc"));
        assert_eq!(
            outcome(false, false, &none).unwrap_err(),
            "not authorized by polkit policy"
        );
    }

    #[test]
    fn service_unknown_maps_to_not_installed() {
        let message = zbus::message::Message::method_call("/", "CheckAuthorization")
            .unwrap()
            .build(&())
            .unwrap();
        let unknown = zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(SERVICE_UNKNOWN).unwrap(),
            None,
            message.clone(),
        );
        assert!(call_error(&unknown).starts_with("polkit is not installed"));
        let fdo = zbus::Error::FDO(Box::new(zbus::fdo::Error::ServiceUnknown("x".into())));
        assert!(call_error(&fdo).starts_with("polkit is not installed"));
        let other = zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from("org.freedesktop.DBus.Error.AccessDenied")
                .unwrap(),
            None,
            message,
        );
        assert!(call_error(&other).starts_with("polkit check failed"));
    }

    /// By hand, as a user with a polkit agent: expects a dialog. Without an
    /// agent: expects the "no polkit authentication agent" message.
    #[tokio::test]
    #[ignore = "asks the real polkit on the system bus"]
    async fn live_check_against_the_system_bus() {
        let pid = std::process::id();
        let peer = PeerId {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            pid: Some(pid as i32),
            starttime: crate::process_resolve::read_starttime(pid),
            sock_ino: None,
        };
        println!("{:?}", check(peer, PAUSE).await);
    }
}
