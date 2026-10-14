//! The daemon's background housekeeping: the hit-count flush and rule
//! expiry, the provenance index warmer, the nftables presence probe, the
//! systemd watchdog heartbeat, and the SIGHUP policy reload.
//!
//! `main` starts each of these once; none of them decides a verdict.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use crate::{config, decision, ebpf, nfqueue, provenance, sd_notify, stats, storage};

/// How stale the NFQUEUE worker's activity stamp may get before the
/// watchdog task considers the worker wedged and withholds the systemd
/// heartbeat. The worker's loop never blocks for more than a few
/// milliseconds at a time (see `nfqueue`'s module docs), so any staleness
/// on this scale is a real wedge. Combined with WatchdogSec=30 in the unit,
/// this bounds wedged-daemon detection at roughly 90 seconds.
const WORKER_STALL_MS: i64 = 60_000;

/// How often to ask nftables whether the table that feeds NFQUEUE is loaded.
///
/// One minute: it is a fork and an exec, and it bounds how long `cfc status`
/// may be stale.
const NFT_PRESENCE_INTERVAL: Duration = Duration::from_secs(60);

/// How often the provenance index is checked for staleness and rebuilt.
///
/// See [`spawn_provenance_warmer`]. Not a hot path: the check is one `stat`
/// of the package database directory, and a rebuild only happens when its
/// mtime moved.
const PROVENANCE_WARM_INTERVAL: Duration = Duration::from_secs(120);

/// Periodic maintenance: flush hit-count deltas so the persisted
/// rule.hit_count reflects recent matches even if the daemon crashes,
/// and prune expired Seconds-duration rules (lookup already skips them;
/// this reclaims the rows while the daemon runs).
pub fn spawn_hit_flush(
    engine: decision::Engine,
    store: storage::RuleStore,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.tick().await; // skip immediate fire
        loop {
            tick.tick().await;
            // The whole tick: a rule write between the drain and the merge
            // would count the drained hits twice (see `lock_mutations`).
            let _mutation = engine.lock_mutations();
            let deltas = engine.drain_hits();
            if !deltas.is_empty() {
                if let Err(e) = store.merge_hit_counts(&deltas) {
                    tracing::warn!("hit-count flush failed: {e}");
                }
            }
            // Only scan when there is something to find. `purge_expired`
            // reads every row and JSON-deserializes it; the in-memory rule
            // set already knows whether any rule has a deadline that has
            // passed, and on a machine whose rules are all `always` - which
            // is every machine most of the time - the answer is no.
            let now_ms = chrono::Utc::now().timestamp_millis();
            let any_expired = engine.snapshot().rules.iter().any(|r| r.is_expired(now_ms));
            if !any_expired {
                continue;
            }
            // Something's deadline has passed. Rebuild the kernel's rule table
            // before dropping the rows: expiry is not a rule edit, so nothing
            // else would tell it.
            engine.notify_rules_expired();
            match store.purge_expired(now_ms) {
                Ok(n) if n > 0 => tracing::debug!(removed = n, "purged expired rules"),
                Ok(_) => {}
                Err(e) => tracing::warn!("expired-rule purge failed: {e}"),
            }
            // Persisted events are pruned to [events] max_rows by the
            // event-writer task (ipc::spawn_event_pipeline), which owns
            // that table's whole lifecycle.
        }
    })
}

/// Package-index warmer.
///
/// The datapath refuses to build the provenance index - building it reads
/// every installed package's file list, and the packet worker is one
/// thread, so a build there stops every flow on the machine for a tenth of
/// a second. Something else has to do it, and this is that something: if
/// nothing called it, provenance would simply never resolve.
///
/// On the blocking pool, not a worker, for the same reason. The first run
/// is immediate so a fresh daemon has provenance within a second; after
/// that it is a poll, because the trigger is the package database's mtime
/// changing under us and there is no cheap way to be told about that. Two
/// minutes is chosen against what it costs to be wrong: a binary first seen
/// after a package transaction shows provenance unknown for at most that
/// long, in a field that decorates an event and decides nothing.
pub fn spawn_provenance_warmer() {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(PROVENANCE_WARM_INTERVAL);
        loop {
            tick.tick().await;
            if tokio::task::spawn_blocking(provenance::warm).await.is_err() {
                tracing::debug!("provenance warm task panicked; retrying next tick");
            }
        }
    });
}

/// Is the ruleset that feeds us still loaded?
///
/// `cfc status`'s `enforcing` used to be "have we ever seen a packet", and
/// a counter that only goes up: after the first packet it said yes for the
/// daemon's whole life, including after `nft flush ruleset` or a firewall
/// reload took the table away and the machine stopped being filtered. The
/// README points people at that field, and at `cfc --json status | jq
/// .enforcing` for scripts, so the one indicator failed in the direction of
/// false confidence.
///
/// A packet counter cannot tell "nothing is filtered" from "nothing is
/// happening" - an idle laptop looks identical to an unprotected one. So
/// ask nftables instead. Once a minute, on the blocking pool because it is
/// a fork and an exec. An error leaves the previous answer standing: "could
/// not ask" must never render as "the firewall is gone".
pub fn spawn_nft_presence_probe(stats: stats::Stats) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(NFT_PRESENCE_INTERVAL);
        loop {
            tick.tick().await;
            match tokio::task::spawn_blocking(ebpf::nft_table_loaded).await {
                Ok(Ok(present)) => stats.set_nft_table(if present {
                    stats::TablePresence::Present
                } else {
                    stats::TablePresence::Absent
                }),
                Ok(Err(e)) => tracing::debug!("could not ask nftables for its table: {e:#}"),
                Err(e) => tracing::debug!("the nftables probe did not run: {e}"),
            }
        }
    });
}

/// Watchdog heartbeat. sd_notify::notify() no-ops without
/// $NOTIFY_SOCKET, so this runs harmlessly outside systemd too. The
/// worker stamps `last_activity` once per loop iteration and no
/// iteration blocks for more than a few milliseconds, so a stamp older
/// than WORKER_STALL_MS means it wedged: withhold WATCHDOG=1 so
/// systemd's WatchdogSec kills and restarts the daemon.
pub fn spawn_watchdog(last_activity: Arc<AtomicI64>, dry_run: bool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            let stamp = last_activity.load(Ordering::Relaxed);
            let healthy = dry_run || nfqueue::unix_ms() - stamp < WORKER_STALL_MS;
            if healthy {
                if let Err(e) = sd_notify::notify(&["WATCHDOG=1"]) {
                    tracing::warn!("sd_notify WATCHDOG=1 failed: {e}");
                }
            } else {
                tracing::error!(
                    stalled_ms = nfqueue::unix_ms() - stamp,
                    "NFQUEUE worker unresponsive; withholding watchdog heartbeat"
                );
            }
        }
    });
}

/// SIGHUP handler: re-reads the config file and swaps the shared default
/// policy in place.
///
/// - On read/parse errors the running policy is kept: a bad edit must
///   never take down or degrade a live firewall.
/// - Only `profile` / `[default_policy]` hot-reload. `[nfqueue]`
///   (queue_num, queue_max_len, fail_open), `[storage]` and the IPC
///   socket path are bound at startup and require a restart to change.
pub fn reload_policy(path: &std::path::Path, policy: &decision::SharedPolicy) {
    match config::Config::load_or_default(path) {
        Ok(new_cfg) => {
            let old = {
                let mut guard = policy
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::mem::replace(&mut *guard, new_cfg.default_policy)
            };
            info!(
                profile = new_cfg.profile.as_deref().unwrap_or("<none>"),
                old = ?old,
                new = ?new_cfg.default_policy,
                "default policy reloaded"
            );
        }
        Err(e) => {
            error!("config reload failed; keeping current policy: {e:#}");
        }
    }
}
