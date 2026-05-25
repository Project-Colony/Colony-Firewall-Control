//! Rule: a persisted decision policy that maps Connection -> Verdict.
//!
//! Loosely modeled on opensnitch's rule format, simplified for v0.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Duration {
    Once,
    UntilRestart,
    Always,
    Seconds(u32),
}

/// What this rule matches on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleScope {
    pub exe_path: Option<PathBuf>,
    pub exe_sha256: Option<String>,
    pub parent_exe: Option<PathBuf>,
    pub uid: Option<u32>,
    pub dst_host: Option<String>,
    pub dst_net: Option<IpNet>,
    pub dst_port: Option<u16>,
    pub protocol: Option<crate::Protocol>,
}

impl RuleScope {
    pub fn any() -> Self {
        Self {
            exe_path: None,
            exe_sha256: None,
            parent_exe: None,
            uid: None,
            dst_host: None,
            dst_net: None,
            dst_port: None,
            protocol: None,
        }
    }

    pub fn matches(&self, conn: &crate::Connection, proc: &crate::Process) -> bool {
        if let Some(p) = &self.exe_path {
            if &proc.exe != p {
                return false;
            }
        }
        if let Some(h) = &self.exe_sha256 {
            match &proc.sha256 {
                Some(s) if s == h => {}
                _ => return false,
            }
        }
        if let Some(u) = self.uid {
            if proc.uid != u {
                return false;
            }
        }
        if let Some(h) = &self.dst_host {
            match &conn.dst_host {
                Some(d) if d == h => {}
                _ => return false,
            }
        }
        if let Some(net) = self.dst_net {
            if !net.contains(&conn.dst_ip) {
                return false;
            }
        }
        if let Some(port) = self.dst_port {
            if conn.dst_port != port {
                return false;
            }
        }
        if let Some(proto) = self.protocol {
            if conn.protocol != proto {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: uuid::Uuid,
    pub name: String,
    pub enabled: bool,
    pub action: Action,
    pub duration: Duration,
    pub scope: RuleScope,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub hit_count: u64,
}

impl Rule {
    pub fn new(name: impl Into<String>, action: Action, scope: RuleScope) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            enabled: true,
            action,
            duration: Duration::Always,
            scope,
            created_at: chrono::Utc::now(),
            hit_count: 0,
        }
    }
}

/// In-memory snapshot of all rules; the daemon walks this in priority order.
#[derive(Debug, Default, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn lookup(&self, conn: &crate::Connection, proc: &crate::Process) -> Option<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.enabled)
            .find(|r| r.scope.matches(conn, proc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Connection, Direction, Process, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn mk_conn() -> Connection {
        Connection::new(
            Protocol::Tcp,
            Direction::Outbound,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            54321,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            443,
        )
    }

    fn mk_proc(exe: &str) -> Process {
        Process {
            pid: 100,
            ppid: Some(1),
            uid: 1000,
            gid: 1000,
            exe: PathBuf::from(exe),
            cmdline: vec![exe.to_string()],
            cwd: None,
            sha256: None,
            started_at: None,
        }
    }

    #[test]
    fn empty_set_returns_none() {
        let set = RuleSet::default();
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");
        assert!(set.lookup(&conn, &proc).is_none());
    }

    #[test]
    fn matches_by_exe_only() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        let rule = Rule::new("curl", Action::Allow, scope);

        let set = RuleSet {
            rules: vec![rule.clone()],
        };
        let conn = mk_conn();

        assert!(set.lookup(&conn, &mk_proc("/usr/bin/curl")).is_some());
        assert!(set.lookup(&conn, &mk_proc("/usr/bin/wget")).is_none());
    }

    #[test]
    fn matches_by_dst_port_only() {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(443);
        let rule = Rule::new("https", Action::Allow, scope);

        let set = RuleSet { rules: vec![rule] };
        let proc = mk_proc("/usr/bin/curl");
        let mut conn = mk_conn();

        assert!(set.lookup(&conn, &proc).is_some());
        conn.dst_port = 80;
        assert!(set.lookup(&conn, &proc).is_none());
    }

    #[test]
    fn matches_by_cidr() {
        let mut scope = RuleScope::any();
        scope.dst_net = Some("10.0.0.0/8".parse().unwrap());
        let rule = Rule::new("rfc1918-10", Action::Deny, scope);

        let set = RuleSet { rules: vec![rule] };
        let proc = mk_proc("/usr/bin/curl");
        let mut conn = mk_conn();

        conn.dst_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(set.lookup(&conn, &proc).is_some());

        conn.dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(set.lookup(&conn, &proc).is_none());
    }

    #[test]
    fn multiple_predicates_must_all_match() {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        scope.dst_port = Some(443);
        scope.protocol = Some(Protocol::Tcp);
        let rule = Rule::new("curl-https-tcp", Action::Allow, scope);

        let set = RuleSet { rules: vec![rule] };
        let proc = mk_proc("/usr/bin/curl");

        // All three match -> hit.
        let mut conn = mk_conn();
        assert!(set.lookup(&conn, &proc).is_some());

        // Wrong port -> miss.
        conn.dst_port = 80;
        assert!(set.lookup(&conn, &proc).is_none());

        // Wrong proto -> miss.
        conn.dst_port = 443;
        conn.protocol = Protocol::Udp;
        assert!(set.lookup(&conn, &proc).is_none());

        // Wrong exe -> miss.
        conn.protocol = Protocol::Tcp;
        assert!(set.lookup(&conn, &mk_proc("/usr/bin/python")).is_none());
    }

    #[test]
    fn disabled_rules_skipped() {
        let mut scope = RuleScope::any();
        scope.dst_port = Some(443);
        let mut rule = Rule::new("https", Action::Allow, scope);
        rule.enabled = false;

        let set = RuleSet { rules: vec![rule] };
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");
        assert!(set.lookup(&conn, &proc).is_none());
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut scope_a = RuleScope::any();
        scope_a.dst_port = Some(443);
        let allow = Rule::new("allow-https", Action::Allow, scope_a);

        let mut scope_b = RuleScope::any();
        scope_b.exe_path = Some(PathBuf::from("/usr/bin/curl"));
        let deny = Rule::new("deny-curl", Action::Deny, scope_b);

        let set = RuleSet {
            rules: vec![allow, deny],
        };
        let conn = mk_conn();
        let proc = mk_proc("/usr/bin/curl");

        let hit = set.lookup(&conn, &proc).expect("should match first rule");
        assert_eq!(hit.action, Action::Allow);
        assert_eq!(hit.name, "allow-https");
    }

    #[test]
    fn uid_predicate() {
        let mut scope = RuleScope::any();
        scope.uid = Some(1000);
        let rule = Rule::new("uid-1000", Action::Allow, scope);

        let set = RuleSet { rules: vec![rule] };
        let conn = mk_conn();

        assert!(set.lookup(&conn, &mk_proc("/anything")).is_some());

        let mut other = mk_proc("/anything");
        other.uid = 2000;
        assert!(set.lookup(&conn, &other).is_none());
    }
}
