//! Runtime counters shared across daemon components.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct Stats {
    inner: Arc<StatsInner>,
}

struct StatsInner {
    started: Instant,
    connections_total: AtomicU64,
    connections_allowed: AtomicU64,
    connections_denied: AtomicU64,
    prompts_pending: AtomicU64,
    paused: AtomicBool,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StatsInner {
                started: Instant::now(),
                connections_total: AtomicU64::new(0),
                connections_allowed: AtomicU64::new(0),
                connections_denied: AtomicU64::new(0),
                prompts_pending: AtomicU64::new(0),
                paused: AtomicBool::new(false),
            }),
        }
    }

    pub fn record_allow(&self) {
        self.inner.connections_total.fetch_add(1, Ordering::Relaxed);
        self.inner
            .connections_allowed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_deny(&self) {
        self.inner.connections_total.fetch_add(1, Ordering::Relaxed);
        self.inner
            .connections_denied
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn prompts_inc(&self) {
        self.inner.prompts_pending.fetch_add(1, Ordering::Relaxed);
    }

    pub fn prompts_dec(&self) {
        self.inner.prompts_pending.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.inner.started.elapsed().as_secs()
    }

    pub fn connections_total(&self) -> u64 {
        self.inner.connections_total.load(Ordering::Relaxed)
    }

    pub fn connections_allowed(&self) -> u64 {
        self.inner.connections_allowed.load(Ordering::Relaxed)
    }

    pub fn connections_denied(&self) -> u64 {
        self.inner.connections_denied.load(Ordering::Relaxed)
    }

    pub fn prompts_pending(&self) -> u64 {
        self.inner.prompts_pending.load(Ordering::Relaxed)
    }

    pub fn is_paused(&self) -> bool {
        self.inner.paused.load(Ordering::Relaxed)
    }

    pub fn set_paused(&self, paused: bool) {
        self.inner.paused.store(paused, Ordering::Relaxed);
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}
