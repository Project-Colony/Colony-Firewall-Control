//! Hostname enrichment with separate policy identity and display decoration.
//!
//! Policy names come only from PTR lookups whose forward A/AAAA lookup contains
//! the original address. They remain asynchronous, cached, best-effort metadata;
//! neither a hostname Allow nor Deny rule provides domain isolation.
//!
//! The eBPF ingress hook also observes UDP DNS-shaped responses. Those records
//! are not tied to a resolver transaction, so they remain diagnostics only and
//! cannot replace a confirmed policy name. The diagnostic cache prefers fresh
//! observations; [`DnsCache::cached_named`] reads the independent policy cache.
//!
//! At most eight resolver jobs run or wait at once. A permit is acquired before
//! spawning and remains held until the blocking libc resolver returns. Full
//! capacity drops enrichment work immediately. Explicit Deny/Reject decisions
//! do not start new lookups. The daemon's own resolver traffic must be exempted
//! in NFQUEUE to avoid waiting for its own verdict.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CACHE_TTL_SECS: u64 = 300;
const NEGATIVE_TTL_SECS: u64 = 60;
const CACHE_MAX_ENTRIES: usize = 4096;
const LOOKUP_MAX_IN_FLIGHT: usize = 8;

/// Floor and ceiling applied to the TTL of an observed answer.
///
/// The record's own TTL is honoured in between. The floor keeps a
/// deliberately-tiny TTL (CDNs routinely publish 30s, and 0 is legal) from
/// making the entry useless for the connection it was about to explain; the
/// ceiling keeps a hostile or absurd TTL from pinning a name in the cache
/// forever.
const OBSERVED_MIN_TTL_SECS: u64 = 60;
const OBSERVED_MAX_TTL_SECS: u64 = 3600;

/// Display source preference, used by [`Entry::supersedes`]. This ordering does
/// not grant policy trust; observed names are excluded from policy identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// Reverse lookup of the destination address, forward-confirmed. The
    /// destination's owner had a say in this name.
    Ptr,
    /// Lifted from an uncorrelated DNS-shaped response received by this host.
    Observed,
}

#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<Inner>,
}

struct Inner {
    cache: RwLock<HashMap<IpAddr, Entry>>,
    policy: RwLock<HashMap<IpAddr, Entry>>,
    lookups: Arc<tokio::sync::Semaphore>,
    daemon_pid: u32,
}

#[derive(Clone)]
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
    /// Fresh observations have display preference over PTR. This does not
    /// affect the separate policy cache. Expired entries are replaceable.
    fn supersedes(&self, trust: Trust, now: Instant) -> bool {
        trust >= self.trust || !self.is_fresh(now)
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                cache: RwLock::new(HashMap::new()),
                policy: RwLock::new(HashMap::new()),
                lookups: Arc::new(tokio::sync::Semaphore::new(LOOKUP_MAX_IN_FLIGHT)),
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

    /// The confirmed policy name for `ip`, in one read. Display-only observed
    /// responses never enter this cache.
    ///
    /// Confirmed means a reverse lookup that passed forward confirmation: the
    /// name resolved back to this address, so asserting it takes control of
    /// that name's forward zone. A name lifted out of an observed response is
    /// not confirmed - nothing ties such a response to a query this host sent
    /// - and only decorates the flow. See `Connection::dst_host_verified`.
    pub fn cached_named(&self, ip: IpAddr) -> Option<(String, bool)> {
        let cache = self.inner.policy.read();
        let entry = cache.get(&ip)?;
        if !entry.is_fresh(Instant::now()) {
            return None;
        }
        Some((entry.hostname.clone()?, true))
    }

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
    /// A no-op when fresh policy identity or an in-flight PTR lookup already
    /// exists. Display observations do not suppress policy enrichment.
    pub fn enqueue_lookup(&self, ip: IpAddr) {
        let now = Instant::now();
        {
            let cache = self.inner.policy.read();
            if let Some(entry) = cache.get(&ip) {
                if entry.in_flight || entry.is_fresh(now) {
                    return;
                }
            }
        }

        // Bound both running lookups and work waiting for a blocking thread.
        // Never queue a task waiting for a permit on this packet path.
        let Ok(permit) = self.inner.lookups.clone().try_acquire_owned() else {
            return;
        };

        // Reserve the slot so concurrent connections do not double-spawn.
        {
            let mut cache = self.inner.policy.write();
            // Re-check under the write lock: another connection may already
            // have reserved or completed this policy lookup.
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
                // Keep the permit in the blocking job even if its async waiter
                // is cancelled while libc is still resolving.
                let _permit = permit;
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
    let entry = Entry {
        ttl: Duration::from_secs(if hostname.is_some() {
            CACHE_TTL_SECS
        } else {
            NEGATIVE_TTL_SECS
        }),
        hostname,
        inserted: now,
        in_flight: false,
        trust: Trust::Ptr,
    };
    {
        let mut policy = inner.policy.write();
        // A completion cannot recreate an evicted reservation.
        if !policy.contains_key(&ip) {
            return;
        }
        policy.insert(ip, entry.clone());
    }
    let mut cache = inner.cache.write();
    if cache
        .get(&ip)
        .is_some_and(|old| !old.supersedes(Trust::Ptr, now))
    {
        return;
    }
    if !cache.contains_key(&ip) {
        evict_if_full(&mut cache);
    }
    cache.insert(ip, entry);
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
    fn uncorrelated_observations_cannot_replace_policy_identity() {
        let cache = DnsCache::new();
        let addr = ip("203.0.113.7");
        insert_ptr(&cache, addr, Some("blocked.example"), Instant::now());
        cache.observe_answer(addr, "untrusted.example", 300);
        assert_eq!(
            cache.lookup_cached(addr).as_deref(),
            Some("untrusted.example")
        );
        assert_eq!(
            cache.cached_named(addr),
            Some(("blocked.example".into(), true))
        );
    }

    #[test]
    fn an_observation_alone_has_no_policy_identity() {
        let cache = DnsCache::new();
        let addr = ip("203.0.113.8");
        cache.observe_answer(addr, "untrusted.example", 300);
        assert_eq!(cache.cached_named(addr), None);
    }

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
    ///
    /// Including the reservation, because that is half of what the real path
    /// does: `enqueue_lookup` always inserts an `in_flight` placeholder before
    /// it spawns, and `record_ptr_result` now only ever *updates* a key that
    /// placeholder created. A helper that skipped the reservation would test a
    /// sequence that cannot happen.
    fn insert_ptr(cache: &DnsCache, addr: IpAddr, name: Option<&str>, now: Instant) {
        reserve(cache, addr, now);
        record_ptr_result(&cache.inner, addr, name.map(str::to_string), now);
    }

    /// The `in_flight` placeholder `enqueue_lookup` reserves before spawning.
    ///
    /// Non-clobbering, exactly as the real one is: `enqueue_lookup` returns
    /// early when an entry is already there, so a reservation can never throw
    /// away an observation. A helper that overwrote would have made every
    /// trust-ordering test below pass for the wrong reason.
    fn reserve(cache: &DnsCache, addr: IpAddr, now: Instant) {
        let entry = Entry {
            hostname: None,
            inserted: now,
            in_flight: true,
            trust: Trust::Ptr,
            ttl: Duration::from_secs(NEGATIVE_TTL_SECS),
        };
        cache
            .inner
            .policy
            .write()
            .entry(addr)
            .or_insert(entry.clone());
        cache.inner.cache.write().entry(addr).or_insert(entry);
    }

    #[test]
    fn saturated_lookups_do_not_spawn_or_reserve_another_job() {
        let cache = DnsCache::new();
        let _permits: Vec<_> = (0..8)
            .map(|_| cache.inner.lookups.clone().try_acquire_owned().unwrap())
            .collect();
        // No runtime and no network: saturation must return before spawning.
        cache.enqueue_lookup(ip("203.0.113.9"));
        assert!(cache.inner.policy.read().is_empty());
    }

    #[test]
    fn a_ptr_result_whose_reservation_was_evicted_is_dropped() {
        // The bound. `evict_if_full` removes one entry per insert, so a
        // completing lookup that re-created its own evicted key added one back
        // - the map ratcheted upward for as long as new destinations kept
        // arriving. A completion with nothing to update has nothing to say.
        let cache = DnsCache::new();
        let now = Instant::now();
        let addr = ip("198.51.100.7");
        record_ptr_result(&cache.inner, addr, Some("orphan.example".to_string()), now);
        assert_eq!(
            cache.lookup_at(addr, now),
            None,
            "a result nobody reserved must not create an entry"
        );
        assert_eq!(cache.cached_trust(addr), None);

        // With the reservation in place it lands, as it always did.
        reserve(&cache, addr, now);
        record_ptr_result(&cache.inner, addr, Some("real.example".to_string()), now);
        assert_eq!(cache.lookup_at(addr, now).as_deref(), Some("real.example"));
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
        // Diagnostic naming prefers a fresh observation; policy identity does
        // not use this preference.
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
        // something else. Display preference does not alter policy identity.
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
