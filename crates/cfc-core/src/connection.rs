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
            pid: None,
            uid: None,
        }
    }

    pub fn with_process(mut self, pid: u32, uid: u32) -> Self {
        self.pid = Some(pid);
        self.uid = Some(uid);
        self
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.dst_host = Some(host.into());
        self
    }
}
