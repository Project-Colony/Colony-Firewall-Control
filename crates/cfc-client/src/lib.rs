//! Colony Firewall Control - shared client.
//!
//! Wraps the tonic-generated `FirewallClient` with a Unix-domain-socket
//! transport. Used by `cfc-ui` and `cfc-cli`.

use anyhow::Context;
use cfc_proto::v1::firewall_client::FirewallClient;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub mod convert;

pub use cfc_proto::v1 as proto;

/// First reconnect delay used by the resilient streams.
pub const RECONNECT_INITIAL: Duration = Duration::from_millis(250);
/// Upper bound on the reconnect delay. Exponential backoff stops here.
pub const RECONNECT_MAX: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The socket path does not exist: the daemon has never started, or it
    /// is configured with a different `--socket`.
    #[error(
        "socket {path} does not exist - is colony-firewalld running? \
         (systemctl status colony-firewalld)"
    )]
    SocketMissing { path: PathBuf },

    /// The socket exists but this uid cannot open it. Since the daemon
    /// creates it 0660 root:colony-firewall, this is a group-membership
    /// problem far more often than anything else.
    #[error(
        "permission denied on {path} - add your user to the colony-firewall group \
         (sudo usermod -aG colony-firewall $USER) then log out and back in, or run as root. \
         The group gives read access and lets the Colony Firewall app and tray connect; \
         firewall changes come from the app, the tray or sudo cfc"
    )]
    PermissionDenied { path: PathBuf },

    /// The daemon refused the request (PERMISSION_DENIED). The text is the
    /// daemon's own reason, made display-safe, and is shown as it is: it
    /// already says what to do (use the app or tray, or sudo).
    #[error("{0}")]
    Denied(String),

    /// The socket inode is there but nothing is listening: a crashed or
    /// SIGKILLed daemon leaves exactly this behind.
    #[error(
        "stale socket at {path} - the daemon crashed or was killed; \
         restart it (sudo systemctl restart colony-firewalld)"
    )]
    StaleSocket { path: PathBuf },

    #[error("connecting to {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("rpc: {0}")]
    Rpc(tonic::Status),

    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),

    /// The daemon closed a subscription stream without an error. Normal
    /// during a restart, fatal for a one-shot (non-following) consumer.
    #[error("stream closed by the daemon")]
    StreamClosed,
}

impl From<tonic::Status> for ClientError {
    fn from(status: tonic::Status) -> Self {
        if status.code() == tonic::Code::PermissionDenied {
            ClientError::Denied(convert::display_safe(status.message()))
        } else {
            ClientError::Rpc(status)
        }
    }
}

impl ClientError {
    /// True when the daemon could not be reached at all, as opposed to the
    /// daemon answering with an error. Callers use this to distinguish
    /// "not running / no access" from "your request was bad".
    pub fn is_unreachable(&self) -> bool {
        match self {
            ClientError::SocketMissing { .. }
            | ClientError::PermissionDenied { .. }
            | ClientError::StaleSocket { .. }
            | ClientError::Connect { .. }
            | ClientError::Transport(_) => true,
            ClientError::Rpc(status) => status.code() == tonic::Code::Unavailable,
            ClientError::StreamClosed | ClientError::Denied(_) => false,
        }
    }
}

/// Turns a connect-time `io::Error` into an error a user can act on.
///
/// The three kinds below are the whole first-run failure surface of a
/// root-owned 0660 socket, and tonic's boxed transport error renders all
/// three identically, so they are mapped explicitly.
fn io_to_client_error(path: &Path, err: &std::io::Error) -> ClientError {
    let path = path.to_path_buf();
    match err.kind() {
        ErrorKind::NotFound => ClientError::SocketMissing { path },
        ErrorKind::PermissionDenied => ClientError::PermissionDenied { path },
        ErrorKind::ConnectionRefused => ClientError::StaleSocket { path },
        _ => ClientError::Connect {
            path,
            source: Box::new(std::io::Error::new(err.kind(), err.to_string())),
        },
    }
}

/// Walks an error's source chain for an `io::Error`, so a transport error
/// that merely wraps ENOENT still produces the actionable message.
fn transport_to_client_error(
    path: &Path,
    err: Box<dyn std::error::Error + Send + Sync + 'static>,
) -> ClientError {
    let mut cursor: Option<&(dyn std::error::Error + 'static)> = Some(err.as_ref());
    while let Some(e) = cursor {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            return io_to_client_error(path, io);
        }
        cursor = e.source();
    }
    ClientError::Connect {
        path: path.to_path_buf(),
        source: err,
    }
}

#[derive(Clone)]
pub struct Client {
    inner: FirewallClient<Channel>,
}

/// What came back from answering a prompt.
///
/// `accepted` and `rule_persisted` are separate questions and were previously
/// conflated: the first says the verdict reached a waiting connection, the
/// second says a standing rule was written. A storage failure leaves the first
/// true and the second false, and a client that reports "Rule created" on the
/// strength of `accepted` alone tells the user something untrue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictOutcome {
    /// The verdict reached a prompt that was still waiting.
    pub accepted: bool,
    /// Whether a standing rule was asked for and stored.
    ///
    /// `None` means the daemon did not say - either no rule was asked for, or
    /// it is a build predating `persisted_rule_id`. That third state is not
    /// pedantry: a package upgrade leaves new client binaries talking to the
    /// still-running old daemon until it is restarted, and treating silence as
    /// failure would report every successful "Allow always" as lost. Clients
    /// must complain only on `Some(false)`.
    pub rule_persisted: Option<bool>,
    /// Why the rule could not be stored, when one was asked for and failed.
    /// Display-safe, like `persist_note`.
    pub persist_error: Option<String>,
    /// Something true about the rule that WAS stored, worth showing: today,
    /// that it was hash-bound (a replaced binary will prompt again), or that
    /// a promised binding fell through and the rule follows the path. Never
    /// a failure - `persist_error` owns those.
    pub persist_note: Option<String>,
}

/// Per-request deadline of [`Client::connect`].
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-request deadline of [`Client::connect_interactive`]: longer than the
/// daemon's 120 s wait for a polkit password dialog, so the daemon's own
/// answer (authorized, dismissed, timed out) always arrives first.
pub const INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(150);

impl Client {
    /// Connects with the 5 s per-request deadline every ordinary call uses.
    pub async fn connect(socket_path: impl AsRef<Path>) -> Result<Self, ClientError> {
        Self::connect_with_timeout(socket_path, REQUEST_TIMEOUT).await
    }

    /// Connects for a request that may wait on an administrator password
    /// (pause, resume, import, an Allow rule for every program): the daemon
    /// asks polkit and polkit asks the user.
    pub async fn connect_interactive(socket_path: impl AsRef<Path>) -> Result<Self, ClientError> {
        Self::connect_with_timeout(socket_path, INTERACTIVE_TIMEOUT).await
    }

    async fn connect_with_timeout(
        socket_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let path = socket_path.as_ref().to_path_buf();
        let connect_path = path.clone();

        // Pre-flight: connect once ourselves so the raw io::ErrorKind is
        // visible. Inside `connect_with_connector` it is boxed by tonic and
        // ENOENT / EACCES / ECONNREFUSED become indistinguishable.
        match UnixStream::connect(&path).await {
            Ok(stream) => drop(stream),
            Err(e) => return Err(io_to_client_error(&path, &e)),
        }

        let endpoint = Endpoint::try_from("http://localhost")
            .context("building endpoint")
            .map_err(|e| ClientError::Connect {
                path: path.clone(),
                source: e.into(),
            })?
            .timeout(timeout);

        let channel = endpoint
            .connect_with_connector(service_fn(move |_: Uri| {
                let p = connect_path.clone();
                async move {
                    let stream = UnixStream::connect(p).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| transport_to_client_error(&path, Box::new(e)))?;

        Ok(Self {
            inner: FirewallClient::new(channel),
        })
    }

    pub fn raw(&mut self) -> &mut FirewallClient<Channel> {
        &mut self.inner
    }

    pub async fn status(&mut self) -> Result<proto::StatusResponse, ClientError> {
        let resp = self.inner.get_status(proto::StatusRequest {}).await?;
        Ok(resp.into_inner())
    }

    pub async fn list_rules(&mut self) -> Result<Vec<proto::RuleInfo>, ClientError> {
        let resp = self.inner.list_rules(proto::ListRulesRequest {}).await?;
        Ok(resp.into_inner().rules)
    }

    pub async fn upsert_rule(&mut self, rule: proto::RuleInfo) -> Result<String, ClientError> {
        let resp = self
            .inner
            .upsert_rule(proto::UpsertRuleRequest { rule: Some(rule) })
            .await?;
        Ok(resp.into_inner().id)
    }

    pub async fn apply_rules(
        &mut self,
        rules: Vec<proto::RuleInfo>,
        replace: bool,
    ) -> Result<proto::ApplyRulesResponse, ClientError> {
        Ok(self
            .inner
            .apply_rules(proto::ApplyRulesRequest { rules, replace })
            .await?
            .into_inner())
    }

    pub async fn delete_rule(&mut self, id: &str) -> Result<bool, ClientError> {
        let resp = self
            .inner
            .delete_rule(proto::DeleteRuleRequest { id: id.to_string() })
            .await?;
        Ok(resp.into_inner().deleted)
    }

    /// Queries the persisted verdict log, newest first. The daemon owns
    /// both the default page size and the maximum, so a `limit` of 0 means
    /// "the daemon's default" and a large one is clamped server-side.
    pub async fn list_events(
        &mut self,
        req: proto::ListEventsRequest,
    ) -> Result<Vec<proto::Event>, ClientError> {
        let resp = self.inner.list_events(req).await?;
        Ok(resp.into_inner().events)
    }

    /// Pauses or resumes enforcement. `duration_secs = 0` asks the daemon
    /// to use its configured default; the daemon clamps the value and
    /// reports the effective deadline in `resume_at_unix_ms`, so callers
    /// must read it from the response rather than assume one.
    pub async fn set_paused(
        &mut self,
        paused: bool,
        duration_secs: u32,
    ) -> Result<proto::SetPausedResponse, ClientError> {
        let resp = self
            .inner
            .set_paused(proto::SetPausedRequest {
                paused,
                duration_secs,
            })
            .await?;
        Ok(resp.into_inner())
    }

    pub async fn submit_verdict(
        &mut self,
        prompt_id: &str,
        action: proto::Action,
        duration: proto::Duration,
        persist_scope: Option<proto::RuleScope>,
    ) -> Result<VerdictOutcome, ClientError> {
        let wanted_rule = persist_scope.is_some();
        let req = proto::VerdictRequest {
            prompt_id: prompt_id.to_string(),
            action: action as i32,
            duration: duration as i32,
            persist_scope,
        };
        let resp = self.inner.submit_verdict(req).await?.into_inner();
        let said_something = !resp.persisted_rule_id.is_empty() || !resp.persist_error.is_empty();
        Ok(VerdictOutcome {
            accepted: resp.accepted,
            rule_persisted: match (wanted_rule, said_something) {
                (false, _) => None,
                // A daemon that answers neither field is one that does not know
                // about them; silence is not a failure report.
                (true, false) => None,
                (true, true) => Some(!resp.persisted_rule_id.is_empty()),
            },
            // Escaped once here for every front end: both can quote a path
            // whose name a local user chose.
            persist_error: (!resp.persist_error.is_empty())
                .then(|| convert::display_safe(&resp.persist_error)),
            persist_note: (!resp.persist_note.is_empty())
                .then(|| convert::display_safe(&resp.persist_note)),
        })
    }

    pub async fn stream_connections(
        &mut self,
        client_id: String,
    ) -> Result<tonic::Streaming<proto::ConnectionEvent>, ClientError> {
        let resp = self
            .inner
            .stream_connections(proto::SubscribeRequest { client_id })
            .await?;
        Ok(resp.into_inner())
    }

    pub async fn stream_prompts(
        &mut self,
        client_id: String,
    ) -> Result<tonic::Streaming<proto::PromptEvent>, ClientError> {
        let resp = self
            .inner
            .stream_prompts(proto::SubscribeRequest { client_id })
            .await?;
        Ok(resp.into_inner())
    }
}

// ---------------------------------------------------------------------------
// Official client prologue
// ---------------------------------------------------------------------------

/// Makes this process recognisable to the daemon as the installed Colony
/// Firewall app or tray. The first statement of their `main`, before any
/// thread, runtime, D-Bus or display connection exists; never called by the
/// CLI.
///
/// 1. Closes every inherited descriptor above stderr, so no control-socket
///    connection opened by whoever exec'd this binary survives into it. The
///    daemon accepts a connection only when the official process itself holds
///    it, which closes the "connect, write a request, then exec the app"
///    route.
/// 2. Marks the process non-dumpable. The kernel then gives the files under
///    `/proc/<pid>` to root, which is the marker the daemon checks, and
///    same-user `ptrace`, `/proc/<pid>/mem` and `pidfd_getfd` are refused
///    for the rest of the process's life. Not before: a parent that traced
///    this process from `exec` had until now, which only Yama
///    `ptrace_scope >= 2` prevents.
///
/// A failure is returned for the caller to log once logging is up. The app
/// keeps working, read-only: the daemon refuses its changes with a reason.
pub fn seal_official_process() -> std::io::Result<()> {
    close_inherited_fds()?;
    // SAFETY: prctl(PR_SET_DUMPABLE) takes plain integers and touches no
    // memory of ours.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn close_inherited_fds() -> std::io::Result<()> {
    // SAFETY: close_range(2) only closes descriptors; nothing in this
    // single-threaded prologue owns one above stderr yet.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOSYS) {
        return Err(error);
    }
    // Kernels before 5.9: list first, then close, so the directory handle is
    // not closed under the iteration.
    let open: Vec<i32> = std::fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd >= 3)
        .collect();
    for fd in open {
        // SAFETY: as above; EBADF for the listing's own, now closed, handle
        // is harmless.
        unsafe { libc::close(fd) };
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Resilient (self-reconnecting) subscriptions
// ---------------------------------------------------------------------------

/// One item of a resilient subscription.
///
/// The connection lifecycle is part of the stream rather than hidden, so a
/// consumer can tell "nothing is happening" from "we lost the daemon", and
/// the stream itself never ends while a consumer is listening.
#[derive(Debug)]
pub enum StreamItem<T> {
    /// A subscription was (re)established. Emitted before any event.
    Connected,
    Event(T),
    /// The subscription was lost. A reconnect attempt follows.
    Disconnected(ClientError),
}

/// Next backoff delay: doubling, capped at [`RECONNECT_MAX`].
pub fn next_backoff(current: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > RECONNECT_MAX {
        RECONNECT_MAX
    } else {
        doubled
    }
}

/// A server-streaming subscription that [`stream_resilient`] can re-establish.
pub trait ResilientSubscription: Sized + Send + 'static {
    fn subscribe(
        client: &mut Client,
        client_id: String,
    ) -> impl std::future::Future<Output = Result<tonic::Streaming<Self>, ClientError>> + Send;
}

impl ResilientSubscription for proto::ConnectionEvent {
    async fn subscribe(
        client: &mut Client,
        client_id: String,
    ) -> Result<tonic::Streaming<Self>, ClientError> {
        client.stream_connections(client_id).await
    }
}

impl ResilientSubscription for proto::PromptEvent {
    async fn subscribe(
        client: &mut Client,
        client_id: String,
    ) -> Result<tonic::Streaming<Self>, ClientError> {
        client.stream_prompts(client_id).await
    }
}

enum PumpOutcome {
    /// The consumer dropped the stream; stop entirely.
    ConsumerGone,
    /// The subscription ended; reconnect after a backoff. `connected` says
    /// whether we got as far as a live subscription, which decides whether
    /// the backoff resets.
    Lost { err: ClientError, connected: bool },
}

/// Connect, subscribe, and forward events until something breaks.
async fn pump_once<T: ResilientSubscription>(
    path: &Path,
    client_id: &str,
    tx: &tokio::sync::mpsc::Sender<StreamItem<T>>,
) -> PumpOutcome {
    let mut client = match Client::connect(path).await {
        Ok(c) => c,
        Err(err) => {
            return PumpOutcome::Lost {
                err,
                connected: false,
            }
        }
    };
    let mut stream = match T::subscribe(&mut client, client_id.to_string()).await {
        Ok(s) => s,
        Err(err) => {
            return PumpOutcome::Lost {
                err,
                connected: false,
            }
        }
    };
    if tx.send(StreamItem::Connected).await.is_err() {
        return PumpOutcome::ConsumerGone;
    }
    loop {
        // Watch the consumer too: a dropped stream must unsubscribe now, not
        // when the next event fails to send. Until then the daemon counts it
        // as a listener and holds a prompt for it for the full timeout.
        let message = tokio::select! {
            _ = tx.closed() => return PumpOutcome::ConsumerGone,
            message = stream.message() => message,
        };
        match message {
            Ok(Some(ev)) => {
                if tx.send(StreamItem::Event(ev)).await.is_err() {
                    return PumpOutcome::ConsumerGone;
                }
            }
            Ok(None) => {
                return PumpOutcome::Lost {
                    err: ClientError::StreamClosed,
                    connected: true,
                }
            }
            Err(status) => {
                return PumpOutcome::Lost {
                    err: status.into(),
                    connected: true,
                }
            }
        }
    }
}

/// A subscription that survives daemon restarts.
///
/// Connect, subscribe, forward; on any failure emit
/// [`StreamItem::Disconnected`] and retry with exponential backoff capped
/// at [`RECONNECT_MAX`]. The returned stream ends only when dropped.
pub fn stream_resilient<T: ResilientSubscription>(
    socket_path: impl AsRef<Path>,
    client_id: String,
) -> impl Stream<Item = StreamItem<T>> {
    let path = socket_path.as_ref().to_path_buf();
    let (tx, rx) = tokio::sync::mpsc::channel(256);
    tokio::spawn(async move {
        let mut backoff = RECONNECT_INITIAL;
        loop {
            match pump_once::<T>(&path, &client_id, &tx).await {
                PumpOutcome::ConsumerGone => return,
                PumpOutcome::Lost { err, connected } => {
                    // A subscription that actually came up resets the
                    // backoff, so one daemon restart does not leave a
                    // long-lived consumer waiting the maximum delay.
                    if connected {
                        backoff = RECONNECT_INITIAL;
                    }
                    if tx.send(StreamItem::Disconnected(err)).await.is_err() {
                        return;
                    }
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = next_backoff(backoff);
        }
    });
    ReceiverStream::new(rx)
}

/// [`stream_resilient`] for the live connection feed.
pub fn stream_connections_resilient(
    socket_path: impl AsRef<Path>,
    client_id: String,
) -> impl Stream<Item = StreamItem<proto::ConnectionEvent>> {
    stream_resilient::<proto::ConnectionEvent>(socket_path, client_id)
}

/// [`stream_resilient`] for the prompt feed.
pub fn stream_prompts_resilient(
    socket_path: impl AsRef<Path>,
    client_id: String,
) -> impl Stream<Item = StreamItem<proto::PromptEvent>> {
    stream_resilient::<proto::PromptEvent>(socket_path, client_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enoent_names_the_daemon() {
        let err = io_to_client_error(
            Path::new("/run/cfc.sock"),
            &std::io::Error::from(ErrorKind::NotFound),
        );
        assert!(matches!(err, ClientError::SocketMissing { .. }));
        let msg = err.to_string();
        assert!(msg.contains("/run/cfc.sock"), "{msg}");
        assert!(msg.contains("colony-firewalld"), "{msg}");
        assert!(err.is_unreachable());
    }

    #[test]
    fn eacces_names_the_group() {
        let err = io_to_client_error(
            Path::new("/run/cfc.sock"),
            &std::io::Error::from(ErrorKind::PermissionDenied),
        );
        assert!(matches!(err, ClientError::PermissionDenied { .. }));
        let msg = err.to_string();
        assert!(msg.contains("colony-firewall group"), "{msg}");
        assert!(msg.contains("usermod"), "{msg}");
    }

    #[test]
    fn econnrefused_says_stale() {
        let err = io_to_client_error(
            Path::new("/run/cfc.sock"),
            &std::io::Error::from(ErrorKind::ConnectionRefused),
        );
        assert!(matches!(err, ClientError::StaleSocket { .. }));
        assert!(err.to_string().contains("stale socket"));
    }

    #[test]
    fn unknown_io_kind_falls_back_to_connect() {
        let err = io_to_client_error(
            Path::new("/run/cfc.sock"),
            &std::io::Error::from(ErrorKind::AddrInUse),
        );
        assert!(matches!(err, ClientError::Connect { .. }));
        assert!(err.is_unreachable());
    }

    #[test]
    fn transport_error_unwraps_to_the_inner_io_kind() {
        // tonic boxes the connector's io::Error; the chain walk must still
        // find it.
        #[derive(Debug)]
        struct Wrapper(std::io::Error);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "transport error")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let err = transport_to_client_error(
            Path::new("/run/cfc.sock"),
            Box::new(Wrapper(std::io::Error::from(ErrorKind::PermissionDenied))),
        );
        assert!(matches!(err, ClientError::PermissionDenied { .. }));
    }

    #[test]
    fn rpc_errors_are_not_unreachable_unless_unavailable() {
        assert!(!ClientError::Rpc(tonic::Status::not_found("nope")).is_unreachable());
        assert!(ClientError::Rpc(tonic::Status::unavailable("bye")).is_unreachable());
        assert!(!ClientError::StreamClosed.is_unreachable());
    }

    #[test]
    fn permission_denied_status_becomes_denied_with_the_daemon_message() {
        let err: ClientError =
            tonic::Status::permission_denied("read-only access: use sudo\u{1b}[2J").into();
        match &err {
            ClientError::Denied(message) => {
                assert!(message.starts_with("read-only access: use sudo"));
                assert!(!message.contains('\u{1b}'), "display-safe: {message}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        assert_eq!(err.to_string(), "read-only access: use sudo\\u{1b}[2J");
        assert!(!err.is_unreachable());
        let err: ClientError = tonic::Status::internal("boom").into();
        assert!(matches!(err, ClientError::Rpc(_)));
    }

    #[test]
    fn seal_official_process_closes_inherited_fds_and_sets_non_dumpable() {
        // In a forked child: the prologue closes every descriptor of the
        // process it runs in, which would break the test harness.
        // SAFETY: the child only makes raw syscalls (close_range succeeds on
        // every kernel CI runs, so the allocating fallback is not reached)
        // and leaves with _exit.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let code = unsafe {
                if libc::dup2(1, 57) != 57 {
                    libc::_exit(10);
                }
                if seal_official_process().is_err() {
                    libc::_exit(11);
                }
                if libc::fcntl(57, libc::F_GETFD) != -1 {
                    libc::_exit(12);
                }
                if libc::fcntl(2, libc::F_GETFD) == -1 {
                    libc::_exit(13);
                }
                if libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 {
                    libc::_exit(14);
                }
                0
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waiting on our own child with a valid out-pointer.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child died: {status}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "child check failed");
    }

    #[tokio::test]
    async fn connect_interactive_outlives_five_seconds() {
        use cfc_proto::v1::firewall_server::{Firewall, FirewallServer};
        use tonic::{Request, Response, Status};

        // A daemon that takes 6 s to answer SetPaused, as one waiting on a
        // polkit dialog does. Only SetPaused is reached.
        struct Slow;
        #[tonic::async_trait]
        impl Firewall for Slow {
            type StreamPromptsStream = tokio_stream::Empty<Result<proto::PromptEvent, Status>>;
            type StreamConnectionsStream =
                tokio_stream::Empty<Result<proto::ConnectionEvent, Status>>;
            async fn set_paused(
                &self,
                req: Request<proto::SetPausedRequest>,
            ) -> Result<Response<proto::SetPausedResponse>, Status> {
                tokio::time::sleep(Duration::from_secs(6)).await;
                Ok(Response::new(proto::SetPausedResponse {
                    paused: req.into_inner().paused,
                    resume_at_unix_ms: 0,
                }))
            }
            async fn stream_prompts(
                &self,
                _: Request<proto::SubscribeRequest>,
            ) -> Result<Response<Self::StreamPromptsStream>, Status> {
                unreachable!()
            }
            async fn submit_verdict(
                &self,
                _: Request<proto::VerdictRequest>,
            ) -> Result<Response<proto::VerdictResponse>, Status> {
                unreachable!()
            }
            async fn list_rules(
                &self,
                _: Request<proto::ListRulesRequest>,
            ) -> Result<Response<proto::ListRulesResponse>, Status> {
                unreachable!()
            }
            async fn upsert_rule(
                &self,
                _: Request<proto::UpsertRuleRequest>,
            ) -> Result<Response<proto::UpsertRuleResponse>, Status> {
                unreachable!()
            }
            async fn apply_rules(
                &self,
                _: Request<proto::ApplyRulesRequest>,
            ) -> Result<Response<proto::ApplyRulesResponse>, Status> {
                unreachable!()
            }
            async fn delete_rule(
                &self,
                _: Request<proto::DeleteRuleRequest>,
            ) -> Result<Response<proto::DeleteRuleResponse>, Status> {
                unreachable!()
            }
            async fn stream_connections(
                &self,
                _: Request<proto::SubscribeRequest>,
            ) -> Result<Response<Self::StreamConnectionsStream>, Status> {
                unreachable!()
            }
            async fn get_status(
                &self,
                _: Request<proto::StatusRequest>,
            ) -> Result<Response<proto::StatusResponse>, Status> {
                unreachable!()
            }
            async fn list_events(
                &self,
                _: Request<proto::ListEventsRequest>,
            ) -> Result<Response<proto::ListEventsResponse>, Status> {
                unreachable!()
            }
        }

        let dir = std::env::temp_dir().join(format!("cfc-client-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("slow.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(FirewallServer::new(Slow))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener)),
        );

        let mut quick = Client::connect(&socket).await.unwrap();
        let err = quick.set_paused(true, 0).await.unwrap_err();
        assert!(
            matches!(&err, ClientError::Rpc(status) if status.code() == tonic::Code::Cancelled
                || status.code() == tonic::Code::DeadlineExceeded),
            "the 5 s client gives up first: {err:?}"
        );
        let mut patient = Client::connect_interactive(&socket).await.unwrap();
        assert!(patient.set_paused(true, 0).await.unwrap().paused);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backoff_doubles_and_saturates() {
        let mut d = RECONNECT_INITIAL;
        let mut seen = vec![d];
        for _ in 0..10 {
            d = next_backoff(d);
            seen.push(d);
        }
        assert!(seen.windows(2).all(|w| w[1] >= w[0]));
        assert_eq!(*seen.last().unwrap(), RECONNECT_MAX);
        assert_eq!(next_backoff(RECONNECT_MAX), RECONNECT_MAX);
        assert_eq!(
            next_backoff(Duration::from_millis(250)),
            Duration::from_millis(500)
        );
    }
}
