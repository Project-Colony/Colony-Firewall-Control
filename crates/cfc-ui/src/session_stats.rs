//! Session-scoped aggregation over the live connection stream.
//!
//! The daemon only exposes global counters, but "which app talks the most"
//! and "where does it talk to" are computable from the feed we are already
//! subscribed to. These numbers cover this UI session only - they reset
//! when the window is closed, and they are labelled as such in the view.

use cfc_client::proto;
use std::collections::HashMap;

use crate::format;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub total: u64,
    pub allowed: u64,
    pub denied: u64,
}

impl Counts {
    fn record(&mut self, verdict: i32) {
        self.total = self.total.saturating_add(1);
        match proto::Action::try_from(verdict).unwrap_or(proto::Action::Unspecified) {
            proto::Action::Allow => self.allowed = self.allowed.saturating_add(1),
            // A reject is a deny that answers the peer; both are "blocked"
            // as far as a top-N breakdown is concerned.
            proto::Action::Deny | proto::Action::Reject => {
                self.denied = self.denied.saturating_add(1)
            }
            proto::Action::Unspecified => {}
        }
    }
}

#[derive(Debug, Default)]
pub struct SessionStats {
    apps: HashMap<String, Counts>,
    dests: HashMap<String, Counts>,
    events: u64,
}

impl SessionStats {
    pub fn record(&mut self, ev: &proto::ConnectionEvent) {
        self.events = self.events.saturating_add(1);

        let app = match ev.process.as_ref() {
            Some(p) if !p.exe.is_empty() => p.exe.clone(),
            _ => "unknown".to_string(),
        };
        self.apps.entry(app).or_default().record(ev.verdict);

        if let Some(c) = ev.connection.as_ref() {
            let dest = format::dest_key(&c.dst_host, &c.dst_ip);
            self.dests.entry(dest).or_default().record(ev.verdict);
        }
    }

    pub fn events(&self) -> u64 {
        self.events
    }

    pub fn top_apps(&self, n: usize) -> Vec<(&str, Counts)> {
        top_n(&self.apps, n)
    }

    pub fn top_dests(&self, n: usize) -> Vec<(&str, Counts)> {
        top_n(&self.dests, n)
    }
}

/// Highest `total` first; ties break on the key so the table does not
/// reshuffle between frames.
fn top_n(map: &HashMap<String, Counts>, n: usize) -> Vec<(&str, Counts)> {
    let mut v: Vec<(&str, Counts)> = map.iter().map(|(k, c)| (k.as_str(), *c)).collect();
    v.sort_by(|a, b| b.1.total.cmp(&a.1.total).then_with(|| a.0.cmp(b.0)));
    v.truncate(n);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(exe: &str, host: &str, ip: &str, verdict: proto::Action) -> proto::ConnectionEvent {
        proto::ConnectionEvent {
            connection: Some(proto::ConnectionInfo {
                id: String::new(),
                timestamp_unix_ms: 0,
                protocol: proto::Protocol::Tcp as i32,
                direction: proto::Direction::Outbound as i32,
                src_ip: "10.0.0.2".into(),
                src_port: 5000,
                dst_ip: ip.into(),
                dst_port: 443,
                dst_host: host.into(),
            }),
            process: Some(proto::ProcessInfo {
                pid: 1,
                ppid: 0,
                uid: None,
                gid: None,
                exe: exe.into(),
                cmdline: vec![],
                cwd: String::new(),
                sha256: String::new(),
            }),
            verdict: verdict as i32,
            rule_id: String::new(),
        }
    }

    #[test]
    fn counts_split_allowed_and_denied() {
        let mut s = SessionStats::default();
        s.record(&ev(
            "/usr/bin/curl",
            "a.test",
            "1.1.1.1",
            proto::Action::Allow,
        ));
        s.record(&ev(
            "/usr/bin/curl",
            "a.test",
            "1.1.1.1",
            proto::Action::Deny,
        ));
        s.record(&ev(
            "/usr/bin/curl",
            "a.test",
            "1.1.1.1",
            proto::Action::Reject,
        ));
        let apps = s.top_apps(10);
        assert_eq!(apps.len(), 1);
        assert_eq!(
            apps[0].1,
            Counts {
                total: 3,
                allowed: 1,
                denied: 2
            }
        );
        assert_eq!(s.events(), 3);
    }

    #[test]
    fn unspecified_verdict_counts_toward_total_only() {
        let mut s = SessionStats::default();
        s.record(&ev("/bin/x", "", "9.9.9.9", proto::Action::Unspecified));
        assert_eq!(
            s.top_apps(1)[0].1,
            Counts {
                total: 1,
                allowed: 0,
                denied: 0
            }
        );
    }

    #[test]
    fn top_n_is_ordered_by_total_then_key() {
        let mut s = SessionStats::default();
        for _ in 0..3 {
            s.record(&ev("/bin/b", "b.test", "2.2.2.2", proto::Action::Allow));
        }
        s.record(&ev("/bin/a", "a.test", "1.1.1.1", proto::Action::Allow));
        s.record(&ev("/bin/c", "c.test", "3.3.3.3", proto::Action::Allow));

        let apps = s.top_apps(10);
        assert_eq!(apps[0].0, "/bin/b");
        // Equal totals: deterministic, alphabetical.
        assert_eq!(apps[1].0, "/bin/a");
        assert_eq!(apps[2].0, "/bin/c");
    }

    #[test]
    fn top_n_truncates() {
        let mut s = SessionStats::default();
        for i in 0..25 {
            s.record(&ev(
                &format!("/bin/app{i:02}"),
                &format!("h{i:02}.test"),
                "1.1.1.1",
                proto::Action::Allow,
            ));
        }
        assert_eq!(s.top_apps(10).len(), 10);
        assert_eq!(s.top_dests(10).len(), 10);
    }

    #[test]
    fn destinations_key_on_hostname_then_ip() {
        let mut s = SessionStats::default();
        s.record(&ev(
            "/bin/x",
            "example.com",
            "1.2.3.4",
            proto::Action::Allow,
        ));
        s.record(&ev("/bin/x", "", "5.6.7.8", proto::Action::Allow));
        let dests = s.top_dests(10);
        let keys: Vec<&str> = dests.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"example.com"));
        assert!(keys.contains(&"5.6.7.8"));
    }

    #[test]
    fn missing_process_is_attributed_to_unknown() {
        let mut s = SessionStats::default();
        let mut e = ev("", "h", "1.1.1.1", proto::Action::Allow);
        e.process = None;
        s.record(&e);
        assert_eq!(s.top_apps(1)[0].0, "unknown");
    }
}
