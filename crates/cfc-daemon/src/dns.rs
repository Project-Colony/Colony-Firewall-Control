//! IP -> hostname cache, with two sources of very different trustworthiness.
//!
//! The names in here are what `dst_host` rules match on and what the UI shows
//! next to a destination address. Where a name came from therefore matters
//! more than the name itself.
//!
//! Crucially, the daemon must skip its OWN outgoing DNS packets in the
//! NFQUEUE worker (via `is_self()`) - otherwise the resolver's queries
//! would themselves be intercepted, deadlocking the resolver on a verdict
//! the daemon hasn't produced yet.
//!
//! # Source 1: PTR + forward confirmation (always available)
//!
//! For every observed connection, we kick off a non-blocking PTR lookup so
//! that subsequent observations of the same destination IP can be displayed
//! with a hostname instead of just an address.
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
//!
//! # Source 2: observed answers (only with the eBPF layer)
//!
//! When `cgroup_skb/ingress` is attached (see [`crate::ebpf`]), the daemon
//! sees the DNS *responses* the machine actually receives and lifts the
//! `A`/`AAAA` records straight out of them. [`DnsCache::observe_answer`]
//! stores those with a higher trust level than anything the PTR path
//! produces, and [`DnsCache::lookup_cached`] prefers them.
//!
//! **Why that is a security win.** An observed answer is *first-hand*: this
//! host asked a resolver for `example.com`, and the resolver said `93.184.…`.
//! The mapping comes from the forward zone of the name, which is the party
//! that owns the name, and it arrives *before* the connection it explains. A
//! PTR answer is second-hand in the worst possible way - it is published by
//! the owner of the destination address, i.e. by the server we may be trying
//! to keep the user away from, and it is fetched *after* the fact. Observed
//! answers close the "hostile server names itself `api.github.com`" hole
//! outright, because the destination no longer gets a vote in what it is
//! called.
//!
//! **What it does not close.** The hook reads packets off the wire, before the
//! resolver's own transaction-id and port checks. Anything that arrives from
//! source port 53 and parses as a response is observed, including a spoofed or
//! injected one that the resolving library will go on to reject. So an
//! attacker who can land forged UDP packets on an open socket can still poison
//! this cache - the same attacker, note, who can also forge the forward lookup
//! FCrDNS relies on. The rule stands: `dst_host` is best-effort metadata and a
//! convenience for *deny* rules, never the boundary an allow rule leans on.
//!
//! Both sources feed one map keyed by IP, so a later PTR result can never
//! displace a live observed answer, and an observed answer always displaces a
//! PTR one.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CACHE_TTL_SECS: u64 = 300;
const NEGATIVE_TTL_SECS: u64 = 60;
const CACHE_MAX_ENTRIES: usize = 4096;

/// Floor and ceiling applied to the TTL of an observed answer.
///
/// The record's own TTL is honoured in between. The floor keeps a
/// deliberately-tiny TTL (CDNs routinely publish 30s, and 0 is legal) from
/// making the entry useless for the connection it was about to explain; the
/// ceiling keeps a hostile or absurd TTL from pinning a name in the cache
/// forever.
const OBSERVED_MIN_TTL_SECS: u64 = 60;
const OBSERVED_MAX_TTL_SECS: u64 = 3600;

/// Where a cached name came from. Ordered: higher is more trustworthy, and
/// the ordering is what [`Entry::supersedes`] is written in terms of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// Reverse lookup of the destination address, forward-confirmed. The
    /// destination's owner had a say in this name.
    Ptr,
    /// Lifted from a DNS response this host actually received. The name's own
    /// zone said so, before the connection happened.
    Observed,
}

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
    trust: Trust,
    /// How long this entry stays valid. For PTR results that is the fixed
    /// positive/negative TTL; for observed answers it is the record's own TTL,
    /// clamped.
    ttl: Duration,
}

impl Entry {
    fn is_fresh(&self, now: Instant) -> bool {
        !self.in_flight && now.saturating_duration_since(self.inserted) <= self.ttl
    }

    /// Whether a new entry at `trust` may replace this one.
    ///
    /// A fresh observed answer outranks everything, including a later PTR
    /// result for the same address; anything else is replaceable. An in-flight
    /// placeholder is never protected, or a lookup that raced an observation
    /// could deadlock the slot.
    fn supersedes(&self, trust: Trust, now: Instant) -> bool {
        trust >= self.trust || !self.is_fresh(now)
    }
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
    ///
    /// Allocation on the packet path is one `String` clone, the same as
    /// before; nothing here parses or looks anything up.
    pub fn lookup_cached(&self, ip: IpAddr) -> Option<String> {
        self.lookup_at(ip, Instant::now())
    }

    /// [`Self::lookup_cached`] with the clock injected, so expiry is testable
    /// without sleeping through a TTL.
    fn lookup_at(&self, ip: IpAddr, now: Instant) -> Option<String> {
        let cache = self.inner.cache.read();
        let entry = cache.get(&ip)?;
        entry
            .is_fresh(now)
            .then(|| entry.hostname.clone())
            .flatten()
    }

    /// The trust level backing the currently cached name for `ip`, if any.
    /// Diagnostics and tests; the packet path does not care.
    pub fn cached_trust(&self, ip: IpAddr) -> Option<Trust> {
        let cache = self.inner.cache.read();
        let entry = cache.get(&ip)?;
        (entry.is_fresh(Instant::now()) && entry.hostname.is_some()).then_some(entry.trust)
    }

    /// Records an `A`/`AAAA` record lifted out of a DNS response this host
    /// received, with `ttl` in seconds as the record carried it.
    ///
    /// This is first-hand evidence (see the module docs) and outranks any PTR
    /// result for the same address, present or future. Called from the
    /// `DNS_PACKETS` ring-buffer consumer, never from the packet path.
    pub fn observe_answer(&self, ip: IpAddr, name: &str, ttl: u32) {
        self.observe_answer_at(ip, name, ttl, Instant::now());
    }

    /// [`Self::observe_answer`] with the clock injected. See [`Self::lookup_at`].
    fn observe_answer_at(&self, ip: IpAddr, name: &str, ttl: u32, now: Instant) {
        // Trailing dots and case are presentation details of the wire format;
        // rules and the UI compare bare lowercase names.
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return;
        }
        let ttl =
            Duration::from_secs(u64::from(ttl).clamp(OBSERVED_MIN_TTL_SECS, OBSERVED_MAX_TTL_SECS));

        let mut cache = self.inner.cache.write();
        if let Some(existing) = cache.get(&ip) {
            // Only a *newer* observation replaces an observed entry; the
            // point is to keep the freshest answer, and several names
            // legitimately resolve to one CDN address.
            if !existing.supersedes(Trust::Observed, now) {
                return;
            }
        }
        evict_if_full(&mut cache);
        tracing::trace!(%ip, name, ttl_secs = ttl.as_secs(), "observed DNS answer");
        cache.insert(
            ip,
            Entry {
                hostname: Some(name),
                inserted: now,
                in_flight: false,
                trust: Trust::Observed,
                ttl,
            },
        );
    }

    /// Fire-and-forget reverse lookup. The next call to `lookup_cached(ip)`
    /// after the response will return the hostname.
    ///
    /// A no-op when a fresh entry already exists, which now includes an
    /// observed answer: with the eBPF layer running, most destinations are
    /// already named by the time a packet reaches this point and the daemon
    /// stops emitting PTR queries for them altogether.
    pub fn enqueue_lookup(&self, ip: IpAddr) {
        let now = Instant::now();
        {
            let cache = self.inner.cache.read();
            if let Some(entry) = cache.get(&ip) {
                if entry.in_flight || entry.is_fresh(now) {
                    return;
                }
            }
        }

        // Reserve the slot so concurrent observations don't double-spawn.
        {
            let mut cache = self.inner.cache.write();
            // Re-check under the write lock: an observation may have landed
            // between the two, and the placeholder would throw it away.
            if let Some(entry) = cache.get(&ip) {
                if entry.in_flight || entry.is_fresh(Instant::now()) {
                    return;
                }
            }
            evict_if_full(&mut cache);
            cache.insert(
                ip,
                Entry {
                    hostname: None,
                    inserted: Instant::now(),
                    in_flight: true,
                    trust: Trust::Ptr,
                    ttl: Duration::from_secs(NEGATIVE_TTL_SECS),
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

            record_ptr_result(&inner, ip, hostname, Instant::now());
        });
    }
}

/// Files a completed PTR + forward-confirmation lookup.
///
/// `hostname` is `None` for "no PTR record, or it failed confirmation", which
/// is cached negatively so the lookup is not retried on every packet.
///
/// A free function taking `&Inner` because the spawned task owns an `Arc`, and
/// a private one because the *only* legitimate producer is that task - the
/// trust ordering below is what stops a late PTR answer from overwriting a
/// live observed one, and it must not be bypassable.
fn record_ptr_result(inner: &Inner, ip: IpAddr, hostname: Option<String>, now: Instant) {
    let mut cache = inner.cache.write();
    // An answer observed on the wire while this lookup was in flight is
    // better than the result we just got; do not clobber it.
    if let Some(existing) = cache.get(&ip) {
        if !existing.supersedes(Trust::Ptr, now) {
            return;
        }
    }
    let ttl = Duration::from_secs(if hostname.is_some() {
        CACHE_TTL_SECS
    } else {
        NEGATIVE_TTL_SECS
    });
    cache.insert(
        ip,
        Entry {
            hostname,
            inserted: now,
            in_flight: false,
            trust: Trust::Ptr,
            ttl,
        },
    );
}

/// Keeps the map bounded by dropping the oldest entry. Called with the write
/// lock held, just before an insert that would grow it.
fn evict_if_full(cache: &mut HashMap<IpAddr, Entry>) {
    if cache.len() < CACHE_MAX_ENTRIES {
        return;
    }
    if let Some((&oldest, _)) = cache.iter().min_by_key(|(_, e)| e.inserted) {
        cache.remove(&oldest);
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
            // dns-lookup 3.x returns an iterator where 2.x returned a Vec.
            // Collected rather than threading the iterator through: this runs
            // once per PTR confirmation on the blocking resolver task, and the
            // result set is a handful of addresses.
            let addrs: Vec<IpAddr> = addrs.collect();
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

    // -- trust precedence ---------------------------------------------------

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Files a PTR result exactly as the completed lookup task would, without
    /// needing a resolver.
    fn insert_ptr(cache: &DnsCache, addr: IpAddr, name: Option<&str>, now: Instant) {
        record_ptr_result(&cache.inner, addr, name.map(str::to_string), now);
    }

    #[test]
    fn an_observed_answer_is_returned_and_marked_observed() {
        let cache = DnsCache::new();
        let now = Instant::now();
        cache.observe_answer_at(ip("93.184.216.34"), "example.com", 300, now);
        assert_eq!(
            cache.lookup_at(ip("93.184.216.34"), now).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            cache.cached_trust(ip("93.184.216.34")),
            Some(Trust::Observed)
        );
    }

    #[test]
    fn observed_answers_are_normalized() {
        let cache = DnsCache::new();
        let now = Instant::now();
        // Wire format carries a trailing dot and preserves query case.
        cache.observe_answer_at(ip("1.2.3.4"), "API.GitHub.com.", 300, now);
        assert_eq!(
            cache.lookup_at(ip("1.2.3.4"), now).as_deref(),
            Some("api.github.com")
        );
        // An empty name is not a name.
        cache.observe_answer_at(ip("5.6.7.8"), ".", 300, now);
        assert!(cache.lookup_at(ip("5.6.7.8"), now).is_none());
    }

    #[test]
    fn an_observation_beats_an_existing_ptr_name() {
        // The whole point: a destination that named itself via PTR loses to
        // what the resolver actually answered for the name.
        let cache = DnsCache::new();
        let now = Instant::now();
        insert_ptr(&cache, ip("203.0.113.7"), Some("api.github.com"), now);
        assert_eq!(cache.cached_trust(ip("203.0.113.7")), Some(Trust::Ptr));

        cache.observe_answer_at(ip("203.0.113.7"), "tracker.example.net", 300, now);
        assert_eq!(
            cache.lookup_at(ip("203.0.113.7"), now).as_deref(),
            Some("tracker.example.net")
        );
        assert_eq!(cache.cached_trust(ip("203.0.113.7")), Some(Trust::Observed));
    }

    #[test]
    fn a_ptr_result_never_displaces_a_fresh_observation() {
        let cache = DnsCache::new();
        let now = Instant::now();
        cache.observe_answer_at(ip("93.184.216.34"), "example.com", 300, now);
        // A PTR lookup for the same address completes later, claiming
        // something else. The destination's reverse zone does not get to
        // rename a host we watched the resolver answer for.
        insert_ptr(&cache, ip("93.184.216.34"), Some("evil.example"), now);
        assert_eq!(
            cache.lookup_at(ip("93.184.216.34"), now).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            cache.cached_trust(ip("93.184.216.34")),
            Some(Trust::Observed)
        );
    }

    #[test]
    fn a_negative_ptr_result_cannot_erase_an_observation_either() {
        let cache = DnsCache::new();
        let now = Instant::now();
        cache.observe_answer_at(ip("93.184.216.34"), "example.com", 300, now);
        insert_ptr(&cache, ip("93.184.216.34"), None, now);
        assert_eq!(
            cache.lookup_at(ip("93.184.216.34"), now).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn ptr_is_still_used_when_nothing_was_observed() {
        let cache = DnsCache::new();
        let now = Instant::now();
        insert_ptr(&cache, ip("203.0.113.9"), Some("mail.example.org"), now);
        assert_eq!(
            cache.lookup_at(ip("203.0.113.9"), now).as_deref(),
            Some("mail.example.org")
        );
        assert_eq!(cache.cached_trust(ip("203.0.113.9")), Some(Trust::Ptr));
    }

    #[test]
    fn observed_entries_expire_on_the_records_own_ttl() {
        let cache = DnsCache::new();
        let now = Instant::now();
        cache.observe_answer_at(ip("93.184.216.34"), "example.com", 120, now);
        assert!(cache
            .lookup_at(ip("93.184.216.34"), now + Duration::from_secs(119))
            .is_some());
        assert!(
            cache
                .lookup_at(ip("93.184.216.34"), now + Duration::from_secs(121))
                .is_none(),
            "the record's 120s TTL is honoured, not the 300s PTR one"
        );
    }

    #[test]
    fn absurd_record_ttls_are_clamped_at_both_ends() {
        let cache = DnsCache::new();
        let now = Instant::now();
        // A 0-TTL answer must still be usable for the connection it explains.
        cache.observe_answer_at(ip("1.1.1.1"), "one.one.one.one", 0, now);
        assert!(cache
            .lookup_at(ip("1.1.1.1"), now + Duration::from_secs(59))
            .is_some());
        assert!(cache
            .lookup_at(ip("1.1.1.1"), now + Duration::from_secs(61))
            .is_none());

        // A ten-year TTL must not pin a name in the cache.
        cache.observe_answer_at(ip("8.8.8.8"), "dns.google", u32::MAX, now);
        assert!(cache
            .lookup_at(ip("8.8.8.8"), now + Duration::from_secs(3599))
            .is_some());
        assert!(cache
            .lookup_at(ip("8.8.8.8"), now + Duration::from_secs(3601))
            .is_none());
    }

    #[test]
    fn a_stale_observation_is_replaced_by_a_ptr_result() {
        let cache = DnsCache::new();
        let now = Instant::now();
        cache.observe_answer_at(ip("93.184.216.34"), "example.com", 60, now);
        let later = now + Duration::from_secs(61);
        insert_ptr(&cache, ip("93.184.216.34"), Some("edge.example.net"), later);
        assert_eq!(
            cache.lookup_at(ip("93.184.216.34"), later).as_deref(),
            Some("edge.example.net"),
            "once the observation is stale, PTR may take the slot again"
        );
        assert_eq!(
            cache.cached_trust(ip("93.184.216.34")),
            Some(Trust::Ptr),
            "and the trust level drops back with it"
        );
    }

    #[test]
    fn a_newer_observation_replaces_an_older_one() {
        let cache = DnsCache::new();
        let now = Instant::now();
        cache.observe_answer_at(ip("93.184.216.34"), "example.com", 300, now);
        cache.observe_answer_at(ip("93.184.216.34"), "www.example.com", 300, now);
        assert_eq!(
            cache.lookup_at(ip("93.184.216.34"), now).as_deref(),
            Some("www.example.com"),
            "several names share a CDN address; keep the freshest answer"
        );
    }

    #[test]
    fn the_cache_stays_bounded_under_a_flood_of_observations() {
        let cache = DnsCache::new();
        let now = Instant::now();
        for i in 0..CACHE_MAX_ENTRIES + 64 {
            let addr = IpAddr::from(std::net::Ipv6Addr::from(i as u128));
            cache.observe_answer_at(addr, &format!("h{i}.example"), 300, now);
        }
        assert!(cache.inner.cache.read().len() <= CACHE_MAX_ENTRIES);
    }
}
