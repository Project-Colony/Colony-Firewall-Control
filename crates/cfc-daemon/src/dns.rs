//! Reverse DNS cache.
//!
//! For every observed connection, we kick off a non-blocking PTR lookup so
//! that subsequent observations of the same destination IP can be displayed
//! with a hostname instead of just an address.
//!
//! Crucially, the daemon must skip its OWN outgoing DNS packets in the
//! NFQUEUE worker (via `is_self()`) - otherwise the resolver's queries
//! would themselves be intercepted, deadlocking the resolver on a verdict
//! the daemon hasn't produced yet.
//!
//! # Why the forward confirmation matters
//!
//! A PTR record is published by whoever controls the IP's reverse zone -
//! i.e. by the operator of the address the traffic is going to, which for
//! outbound filtering is exactly the party we may be trying to keep the
//! user away from. Taken at face value, a hostile server could name itself
//! `api.github.com` and satisfy a `dst_host` allow rule.
//!
//! So every PTR answer is forward-confirmed (FCrDNS): we resolve the name
//! we got back to its A/AAAA set and keep it only if that set contains the
//! IP we started from. That makes the name as trustworthy as the forward
//! zone of the claimed domain, instead of as trustworthy as the reverse
//! zone of an arbitrary IP. Unconfirmed names are discarded, so a rule
//! never matches on them.
//!
//! This is a mitigation, not a guarantee: hostnames are still resolved
//! after the fact and cached, and an attacker who controls both zones can
//! still self-consistently name themselves. `dst_host` remains best-effort
//! metadata - see docs/HARDENING.md.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CACHE_TTL_SECS: u64 = 300;
const NEGATIVE_TTL_SECS: u64 = 60;
const CACHE_MAX_ENTRIES: usize = 4096;

#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<Inner>,
}

struct Inner {
    cache: RwLock<HashMap<IpAddr, Entry>>,
    daemon_pid: u32,
}

struct Entry {
    hostname: Option<String>,
    inserted: Instant,
    in_flight: bool,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                cache: RwLock::new(HashMap::new()),
                daemon_pid: std::process::id(),
            }),
        }
    }

    /// True when a pid refers to the daemon itself. Used to skip the
    /// daemon's own DNS queries in NFQUEUE.
    pub fn is_self(&self, pid: u32) -> bool {
        pid == self.inner.daemon_pid
    }

    /// Returns the cached hostname for `ip` if any is known and fresh.
    pub fn lookup_cached(&self, ip: IpAddr) -> Option<String> {
        let cache = self.inner.cache.read();
        let entry = cache.get(&ip)?;
        if entry.in_flight {
            return None;
        }
        let ttl = if entry.hostname.is_some() {
            CACHE_TTL_SECS
        } else {
            NEGATIVE_TTL_SECS
        };
        if entry.inserted.elapsed() > Duration::from_secs(ttl) {
            return None;
        }
        entry.hostname.clone()
    }

    /// Fire-and-forget reverse lookup. The next call to `lookup_cached(ip)`
    /// after the response will return the hostname.
    pub fn enqueue_lookup(&self, ip: IpAddr) {
        {
            let cache = self.inner.cache.read();
            if let Some(entry) = cache.get(&ip) {
                let ttl = if entry.hostname.is_some() {
                    CACHE_TTL_SECS
                } else {
                    NEGATIVE_TTL_SECS
                };
                if entry.in_flight || entry.inserted.elapsed() <= Duration::from_secs(ttl) {
                    return;
                }
            }
        }

        // Reserve the slot so concurrent observations don't double-spawn.
        {
            let mut cache = self.inner.cache.write();
            if cache.len() >= CACHE_MAX_ENTRIES {
                // Evict the oldest entry to keep the map bounded.
                if let Some((&oldest_key, _)) = cache.iter().min_by_key(|(_, e)| e.inserted) {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(
                ip,
                Entry {
                    hostname: None,
                    inserted: Instant::now(),
                    in_flight: true,
                },
            );
        }

        let inner = self.inner.clone();
        tokio::spawn(async move {
            // `dns_lookup` is sync (getnameinfo/getaddrinfo); move to a
            // blocking thread so the tokio runtime stays responsive.
            let hostname = tokio::task::spawn_blocking(move || {
                let name = dns_lookup::lookup_addr(&ip)
                    .ok()
                    // libc may return the input IP as a string if no PTR
                    // record exists. Treat that as a negative result.
                    .filter(|h| *h != ip.to_string())?;
                forward_confirm(&name, ip).then_some(name)
            })
            .await
            .unwrap_or(None);

            inner.cache.write().insert(
                ip,
                Entry {
                    hostname,
                    inserted: Instant::now(),
                    in_flight: false,
                },
            );
        });
    }
}

/// Forward-confirms a PTR answer: resolves `name` and reports whether the
/// result set contains `ip`. A failed forward lookup counts as unconfirmed,
/// so a name is only ever trusted on positive evidence.
///
/// Comparison is done on canonical form so a v4-mapped forward answer
/// (`::ffff:a.b.c.d`) still confirms an IPv4 destination.
fn forward_confirm(name: &str, ip: IpAddr) -> bool {
    match dns_lookup::lookup_host(name) {
        Ok(addrs) => {
            let confirmed = addrs_contain(&addrs, ip);
            if !confirmed {
                tracing::debug!(
                    %ip,
                    name,
                    "PTR name failed forward confirmation; discarding"
                );
            }
            confirmed
        }
        Err(e) => {
            tracing::debug!(%ip, name, "forward confirmation lookup failed: {e}");
            false
        }
    }
}

/// Whether a forward-lookup result set covers `ip`, comparing canonical
/// forms so a v4-mapped answer (`::ffff:a.b.c.d`) confirms an IPv4
/// destination.
fn addrs_contain(addrs: &[IpAddr], ip: IpAddr) -> bool {
    let want = ip.to_canonical();
    addrs.iter().any(|a| a.to_canonical() == want)
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_confirmation_requires_the_original_ip() {
        let want: IpAddr = "93.184.216.34".parse().unwrap();
        let other: IpAddr = "203.0.113.7".parse().unwrap();

        assert!(addrs_contain(&[other, want], want));
        // A name that resolves elsewhere (or nowhere) is not confirmation.
        assert!(!addrs_contain(&[other], want));
        assert!(!addrs_contain(&[], want));
    }

    #[test]
    fn forward_confirmation_accepts_v4_mapped_answers() {
        let want: IpAddr = "93.184.216.34".parse().unwrap();
        let mapped: IpAddr = "::ffff:93.184.216.34".parse().unwrap();

        assert!(addrs_contain(&[mapped], want));
        assert!(addrs_contain(&[want], mapped));
    }

    #[test]
    fn is_self_matches_pid() {
        let cache = DnsCache::new();
        assert!(cache.is_self(std::process::id()));
        assert!(!cache.is_self(std::process::id() + 1));
    }

    #[test]
    fn empty_cache_returns_none() {
        let cache = DnsCache::new();
        assert!(cache.lookup_cached("8.8.8.8".parse().unwrap()).is_none());
    }
}
