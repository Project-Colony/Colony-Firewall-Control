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
    /// Whether [`Self::dst_host`] was confirmed to belong to [`Self::dst_ip`],
    /// rather than merely asserted by something on the wire.
    ///
    /// The daemon learns names two ways and they are not equally
    /// trustworthy. A reverse lookup is forward-confirmed - the name must
    /// resolve back to this address, so claiming one means controlling that
    /// name's forward zone. A name lifted out of an observed DNS response is
    /// whatever the packet said: nothing correlates such a response to a
    /// query this host sent, so any peer that answers from source port 53 can
    /// assert any name for any address.
    ///
    /// What that costs an unconfirmed name is the power to *admit*, and only
    /// that: see [`crate::Rule::permits_on_an_unverified_name`]. It may still
    /// refuse, so a `deny --dst-host` keeps working exactly as before, and it
    /// is still attached to the flow either way - it is what the live feed,
    /// the log and the prompt show, and it is right nearly always.
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
