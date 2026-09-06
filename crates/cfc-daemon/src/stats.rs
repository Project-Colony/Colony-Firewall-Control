//! Runtime counters shared across daemon components.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
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
    /// Incremented each time `set_paused` is called. Used so the
    /// auto-unpause timer can be invalidated if the user toggles in the
    /// meantime.
    pause_generation: AtomicU64,
    /// Last answer from the nftables probe: see [`TablePresence`].
    ///
    /// Starts `Unknown` and stays there on any host where `nft` cannot be
    /// asked, which is what keeps a failed probe from reading as "the
    /// firewall is gone".
    nft_table: AtomicU8,
}

/// What the periodic nftables probe last found.
///
/// Three states, not two, and the third is the point: "could not ask" has to
/// be distinguishable from "asked, and the table is not there". Reporting the
/// second when the first happened would call a healthy machine unprotected
/// every time a fork failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TablePresence {
    /// Never probed, or the probe could not run.
    Unknown,
    /// `table inet colony_firewall` is loaded.
    Present,
    /// It is not. Nothing reaches the queue; nothing is being filtered.
    Absent,
}

impl TablePresence {
    fn as_u8(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Present => 1,
            Self::Absent => 2,
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Present,
            2 => Self::Absent,
            _ => Self::Unknown,
        }
    }
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
                pause_generation: AtomicU64::new(0),
                nft_table: AtomicU8::new(TablePresence::Unknown.as_u8()),
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

    /// Records what the nftables probe found.
    pub fn set_nft_table(&self, presence: TablePresence) {
        self.inner
            .nft_table
            .store(presence.as_u8(), Ordering::Relaxed);
    }

    /// The probe's last answer.
    pub fn nft_table(&self) -> TablePresence {
        TablePresence::from_u8(self.inner.nft_table.load(Ordering::Relaxed))
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

    /// Sets the paused flag and bumps the generation. Returns the new
    /// generation so callers can check whether the state has changed
    /// before doing follow-up work (e.g. an auto-unpause timer).
    pub fn set_paused(&self, paused: bool) -> u64 {
        self.inner.paused.store(paused, Ordering::Relaxed);
        self.inner.pause_generation.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn pause_generation(&self) -> u64 {
        self.inner.pause_generation.load(Ordering::Relaxed)
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}
