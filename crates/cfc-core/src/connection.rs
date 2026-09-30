//! Connection: a single network flow intercepted by the daemon.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub protocol: Protocol,
    pub direction: Direction,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub dst_host: Option<String>,
    /// Whether a reverse lookup was forward-confirmed against `dst_ip`.
    /// This is diagnostic metadata: it does not establish the application's
    /// intended hostname or enumerate aliases, and never authorizes policy.
    #[serde(default)]
    pub dst_host_verified: bool,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
}

impl Connection {
    pub fn new(
        protocol: Protocol,
        direction: Direction,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            protocol,
            direction,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            dst_host: None,
            dst_host_verified: false,
            pid: None,
            uid: None,
        }
    }

    /// Attach the owning pid and (if attributed) uid. `uid` stays `None`
    /// when the process could not be attributed rather than defaulting to 0.
    pub fn with_process(mut self, pid: u32, uid: Option<u32>) -> Self {
        self.pid = Some(pid);
        self.uid = uid;
        self
    }

    /// Attaches a name that has *not* been confirmed against the address.
    /// See [`Self::dst_host_verified`].
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.dst_host = Some(host.into());
        self.dst_host_verified = false;
        self
    }

    /// Attaches a name and says whether it was confirmed against the address.
    pub fn with_host_verified(mut self, host: impl Into<String>, verified: bool) -> Self {
        self.dst_host = Some(host.into());
        self.dst_host_verified = verified;
        self
    }
}
