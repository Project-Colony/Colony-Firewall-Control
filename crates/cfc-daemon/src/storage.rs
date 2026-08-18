//! Rule and event persistence via SQLite.
//!
//! Schema versioning: `PRAGMA user_version` tracks the schema version.
//! Version 0 means "fresh database" or "pre-versioning database" (the old
//! layout that only had the `rules` table); both are upgraded to version 1
//! by [`migrate`]. All DDL uses `IF NOT EXISTS`, so the fresh path and the
//! pre-versioning upgrade path are the same statements.

use anyhow::Context;
use cfc_core::{Duration as RuleDuration, Rule, RuleSet};
use parking_lot::Mutex;
use rusqlite::Connection;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Highest schema version this build understands.
const SCHEMA_VERSION: i64 = 1;

#[derive(Clone)]
pub struct RuleStore {
    conn: Arc<Mutex<Connection>>,
    /// Number of rule rows skipped by the most recent `snapshot()` because
    /// their JSON failed to deserialize. Rows are preserved on disk.
    skipped: Arc<AtomicUsize>,
}

/// One row of the `events` table: a persisted verdict/audit record.
///
/// `id` is assigned by the database; it is ignored by [`RuleStore::insert_events`]
/// and populated by [`RuleStore::query_events`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventRow {
    pub id: i64,
    pub ts_unix_ms: i64,
    pub proto: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub dst_host: Option<String>,
    pub exe: Option<String>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub action: String,
    pub source: String,
    pub rule_id: Option<String>,
}

/// Optional filters for [`RuleStore::query_events`]. All fields are ANDed.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Keep events whose `exe` contains this substring.
    pub exe_contains: Option<String>,
    /// Keep events with exactly this `action`.
    pub action: Option<String>,
    /// Keep events with `ts_unix_ms >= since_ts_unix_ms`.
    pub since_ts_unix_ms: Option<i64>,
}

impl RuleStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).context("opening sqlite")?;
        let store = Self::from_conn(conn)?;

        // "Until restart" and "once" rules must not survive a daemon restart;
        // open() runs at daemon start, so purging here implements that
        // honestly. Expired timed rules are swept here too (and periodically
        // by the flush task once wave 2 wires it up).
        let transient = store.purge_transient().context("purging transient rules")?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let expired = store
            .purge_expired(now_ms)
            .context("purging expired rules")?;
        if transient + expired > 0 {
            tracing::info!(
                transient,
                expired,
                "purged transient/expired rules at startup"
            );
        }
        Ok(store)
    }

    fn from_conn(conn: Connection) -> anyhow::Result<Self> {
        migrate(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            skipped: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn snapshot(&self) -> anyhow::Result<RuleSet> {
        let conn = self.conn.lock();
        // Deterministic load order. `created_at` lives inside the JSON blob
        // (the table has no timestamp column), so order by `id`: stable
        // across restarts, and the in-memory sort handles priority ordering.
        let mut stmt =
            conn.prepare("SELECT id, data FROM rules WHERE enabled = 1 ORDER BY id ASC")?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((id, json))
        })?;
        let mut rules = Vec::new();
        let mut skipped_ids = Vec::new();
        for r in rows {
            let (id, json) = r?;
            match serde_json::from_str::<Rule>(&json) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    tracing::error!(rule_id = %id, "rule failed to deserialize, skipping (row preserved): {e}");
                    skipped_ids.push(id);
                }
            }
        }
        if !skipped_ids.is_empty() {
            tracing::error!(
                count = skipped_ids.len(),
                ids = ?skipped_ids,
                "{} rule(s) could not be loaded; rows are preserved on disk",
                skipped_ids.len()
            );
        }
        self.skipped.store(skipped_ids.len(), Ordering::Relaxed);
        Ok(RuleSet { rules })
    }

    /// Number of rule rows the most recent [`snapshot`](Self::snapshot) call
    /// skipped because their JSON failed to deserialize. Rows are never
    /// deleted for failing to parse; this count lets callers surface the
    /// problem (e.g. in `status`) instead of losing data silently.
    pub fn skipped_rules(&self) -> usize {
        self.skipped.load(Ordering::Relaxed)
    }

    pub fn upsert(&self, rule: &Rule) -> anyhow::Result<()> {
        let json = serde_json::to_string(rule)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO rules(id, enabled, data) VALUES(?1, ?2, ?3) \
             ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled, data = excluded.data",
            rusqlite::params![rule.id.to_string(), rule.enabled as i64, json],
        )?;
        Ok(())
    }

    pub fn delete(&self, id: uuid::Uuid) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "DELETE FROM rules WHERE id = ?1",
            rusqlite::params![id.to_string()],
        )?;
        Ok(n > 0)
    }

    /// Deletes rules whose duration is `UntilRestart` or `Once`. Called at
    /// [`open`](Self::open), i.e. at daemon start, which is what makes
    /// "until restart" mean what it says. Returns the number deleted.
    pub fn purge_transient(&self) -> anyhow::Result<usize> {
        self.purge_where(|rule| {
            matches!(
                rule.duration,
                RuleDuration::Once | RuleDuration::UntilRestart
            )
        })
    }

    /// Deletes `Seconds(n)` rules whose lifetime has elapsed as of
    /// `now_unix_ms`. Called once at open; wave 2's periodic flush task will
    /// call it on a timer. Returns the number deleted.
    pub fn purge_expired(&self, now_unix_ms: i64) -> anyhow::Result<usize> {
        self.purge_where(|rule| rule.is_expired(now_unix_ms))
    }

    /// Deletes every rule matching `pred` in one transaction. Rows whose JSON
    /// fails to parse are left untouched (same policy as `snapshot()`).
    /// Duration lives inside the JSON blob, so each row is parsed in Rust
    /// rather than relying on sqlite's JSON1 extension.
    fn purge_where(&self, pred: impl Fn(&Rule) -> bool) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let doomed: Vec<String> = {
            let mut stmt = tx.prepare("SELECT id, data FROM rules")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut ids = Vec::new();
            for r in rows {
                let (id, json) = r?;
                if let Ok(rule) = serde_json::from_str::<Rule>(&json) {
                    if pred(&rule) {
                        ids.push(id);
                    }
                }
            }
            ids
        };
        for id in &doomed {
            tx.execute("DELETE FROM rules WHERE id = ?1", rusqlite::params![id])?;
        }
        tx.commit()?;
        Ok(doomed.len())
    }

    /// Merges per-rule hit increments into the persisted JSON `data` blob.
    /// Skips rules that have been deleted since the increment was recorded.
    pub fn merge_hit_counts(
        &self,
        increments: &std::collections::HashMap<uuid::Uuid, u64>,
    ) -> anyhow::Result<()> {
        if increments.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        for (id, extra) in increments {
            let id_str = id.to_string();
            let mut stmt = tx.prepare("SELECT data FROM rules WHERE id = ?1")?;
            let row: Option<String> = stmt
                .query_row(rusqlite::params![&id_str], |row| row.get(0))
                .ok();
            let Some(json) = row else { continue };
            let mut rule: Rule = match serde_json::from_str(&json) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("skipping hit merge for {id}: bad JSON: {e}");
                    continue;
                }
            };
            rule.hit_count = rule.hit_count.saturating_add(*extra);
            let new_json = serde_json::to_string(&rule)?;
            tx.execute(
                "UPDATE rules SET data = ?2 WHERE id = ?1",
                rusqlite::params![id_str, new_json],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Inserts a batch of verdict events in a single transaction.
    /// `EventRow::id` is ignored; the database assigns ids.
    pub fn insert_events(&self, batch: &[EventRow]) -> anyhow::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events(ts_unix_ms, proto, src_ip, src_port, dst_ip, dst_port, \
                 dst_host, exe, pid, uid, action, source, rule_id) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )?;
            for e in batch {
                stmt.execute(rusqlite::params![
                    e.ts_unix_ms,
                    e.proto,
                    e.src_ip,
                    e.src_port,
                    e.dst_ip,
                    e.dst_port,
                    e.dst_host,
                    e.exe,
                    e.pid,
                    e.uid,
                    e.action,
                    e.source,
                    e.rule_id,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Returns events newest-first, applying `filter`, then `limit`/`offset`.
    pub fn query_events(
        &self,
        limit: u32,
        offset: u32,
        filter: EventFilter,
    ) -> anyhow::Result<Vec<EventRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT id, ts_unix_ms, proto, src_ip, src_port, dst_ip, dst_port, dst_host, \
             exe, pid, uid, action, source, rule_id \
             FROM events \
             WHERE (?1 IS NULL OR instr(exe, ?1) > 0) \
               AND (?2 IS NULL OR action = ?2) \
               AND (?3 IS NULL OR ts_unix_ms >= ?3) \
             ORDER BY ts_unix_ms DESC, id DESC \
             LIMIT ?4 OFFSET ?5",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![
                filter.exe_contains,
                filter.action,
                filter.since_ts_unix_ms,
                limit,
                offset,
            ],
            |row| {
                Ok(EventRow {
                    id: row.get(0)?,
                    ts_unix_ms: row.get(1)?,
                    proto: row.get(2)?,
                    src_ip: row.get(3)?,
                    src_port: row.get(4)?,
                    dst_ip: row.get(5)?,
                    dst_port: row.get(6)?,
                    dst_host: row.get(7)?,
                    exe: row.get(8)?,
                    pid: row.get(9)?,
                    uid: row.get(10)?,
                    action: row.get(11)?,
                    source: row.get(12)?,
                    rule_id: row.get(13)?,
                })
            },
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Deletes the oldest events beyond `max_rows`, keeping the newest.
    /// Returns the number deleted.
    pub fn prune_events(&self, max_rows: u32) -> anyhow::Result<usize> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "DELETE FROM events WHERE id IN ( \
                 SELECT id FROM events ORDER BY ts_unix_ms DESC, id DESC \
                 LIMIT -1 OFFSET ?1 \
             )",
            rusqlite::params![max_rows],
        )?;
        Ok(n)
    }
}

/// Brings the database up to [`SCHEMA_VERSION`], one version at a time, so
/// future migrations slot in as new match arms.
fn migrate(conn: &Connection) -> anyhow::Result<()> {
    loop {
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .context("reading user_version")?;
        match version {
            // Fresh database, or a pre-versioning one that already has the
            // `rules` table: the v1 DDL is all IF NOT EXISTS, so both are
            // handled by the same statements.
            0 => {
                conn.execute_batch(SCHEMA_V1).context("applying schema v1")?;
                conn.pragma_update(None, "user_version", 1)
                    .context("setting user_version=1")?;
            }
            SCHEMA_VERSION => return Ok(()),
            v => anyhow::bail!(
                "database schema version {v} is newer than this daemon supports (max {SCHEMA_VERSION})"
            ),
        }
    }
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_unix_ms INTEGER NOT NULL,
    proto TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    dst_host TEXT,
    exe TEXT,
    pid INTEGER,
    uid INTEGER,
    action TEXT NOT NULL,
    source TEXT NOT NULL,
    rule_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_unix_ms);
"#;

#[cfg(test)]
impl RuleStore {
    /// Test-only: in-memory store. Runs migrations but not the startup purges,
    /// so tests control purge timing explicitly.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().context("opening sqlite :memory:")?;
        Self::from_conn(conn)
    }

    fn user_version(&self) -> i64 {
        self.conn
            .lock()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfc_core::{Action, Rule, RuleScope};
    use std::path::PathBuf;

    fn sample_rule(name: &str) -> Rule {
        let mut scope = RuleScope::any();
        scope.exe_path = Some(PathBuf::from(format!("/usr/bin/{name}")));
        scope.dst_port = Some(443);
        Rule::new(name, Action::Allow, scope)
    }

    fn rule_with_duration(name: &str, duration: RuleDuration) -> Rule {
        let mut rule = sample_rule(name);
        rule.duration = duration;
        rule
    }

    fn temp_db_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cfc-storage-test-{tag}-{}.db",
            uuid::Uuid::new_v4()
        ))
    }

    fn sample_event(ts: i64, exe: &str, action: &str) -> EventRow {
        EventRow {
            id: 0,
            ts_unix_ms: ts,
            proto: Some("tcp".into()),
            src_ip: Some("192.168.1.10".into()),
            src_port: Some(54321),
            dst_ip: Some("1.2.3.4".into()),
            dst_port: Some(443),
            dst_host: Some("example.com".into()),
            exe: Some(exe.into()),
            pid: Some(100),
            uid: Some(1000),
            action: action.into(),
            source: "rule".into(),
            rule_id: None,
        }
    }

    #[test]
    fn empty_store_returns_empty_set() {
        let store = RuleStore::open_in_memory().unwrap();
        let snap = store.snapshot().unwrap();
        assert!(snap.rules.is_empty());
        assert_eq!(store.skipped_rules(), 0);
    }

    #[test]
    fn upsert_then_snapshot_roundtrips() {
        let store = RuleStore::open_in_memory().unwrap();
        let rule = sample_rule("curl");
        store.upsert(&rule).unwrap();

        let snap = store.snapshot().unwrap();
        assert_eq!(snap.rules.len(), 1);
        assert_eq!(snap.rules[0].id, rule.id);
        assert_eq!(snap.rules[0].name, "curl");
        assert_eq!(snap.rules[0].action, Action::Allow);
    }

    #[test]
    fn upsert_idempotent_by_id() {
        let store = RuleStore::open_in_memory().unwrap();
        let mut rule = sample_rule("curl");
        store.upsert(&rule).unwrap();

        rule.name = "curl-renamed".into();
        store.upsert(&rule).unwrap();

        let snap = store.snapshot().unwrap();
        assert_eq!(snap.rules.len(), 1);
        assert_eq!(snap.rules[0].name, "curl-renamed");
    }

    #[test]
    fn delete_removes_rule() {
        let store = RuleStore::open_in_memory().unwrap();
        let rule = sample_rule("curl");
        store.upsert(&rule).unwrap();

        assert!(store.delete(rule.id).unwrap());
        assert!(store.snapshot().unwrap().rules.is_empty());

        // Second delete is a no-op.
        assert!(!store.delete(rule.id).unwrap());
    }

    #[test]
    fn disabled_rules_excluded_from_snapshot() {
        let store = RuleStore::open_in_memory().unwrap();
        let mut rule = sample_rule("curl");
        rule.enabled = false;
        store.upsert(&rule).unwrap();
        assert!(store.snapshot().unwrap().rules.is_empty());
    }

    #[test]
    fn multiple_rules_persist() {
        let store = RuleStore::open_in_memory().unwrap();
        for name in ["curl", "wget", "firefox"] {
            store.upsert(&sample_rule(name)).unwrap();
        }
        let snap = store.snapshot().unwrap();
        assert_eq!(snap.rules.len(), 3);
    }

    #[test]
    fn migration_sets_user_version_and_open_is_idempotent() {
        let path = temp_db_path("migrate");

        let store = RuleStore::open(&path).unwrap();
        assert_eq!(store.user_version(), 1);
        store.upsert(&sample_rule("curl")).unwrap();
        drop(store);

        // Second open must not error, must keep version 1, must keep data.
        let store = RuleStore::open(&path).unwrap();
        assert_eq!(store.user_version(), 1);
        assert_eq!(store.snapshot().unwrap().rules.len(), 1);
        drop(store);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn pre_versioning_db_migrates_to_v1() {
        let path = temp_db_path("prever");

        // Simulate the old, unversioned layout: rules table only, version 0.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS rules ( \
                     id TEXT PRIMARY KEY, \
                     enabled INTEGER NOT NULL DEFAULT 1, \
                     data TEXT NOT NULL \
                 ); \
                 CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);",
            )
            .unwrap();
            let rule = sample_rule("curl");
            conn.execute(
                "INSERT INTO rules(id, enabled, data) VALUES(?1, 1, ?2)",
                rusqlite::params![rule.id.to_string(), serde_json::to_string(&rule).unwrap()],
            )
            .unwrap();
        }

        let store = RuleStore::open(&path).unwrap();
        assert_eq!(store.user_version(), 1);
        // Old data survives, and the events table now exists.
        assert_eq!(store.snapshot().unwrap().rules.len(), 1);
        store
            .insert_events(&[sample_event(1000, "/usr/bin/curl", "Allow")])
            .unwrap();
        assert_eq!(
            store
                .query_events(10, 0, EventFilter::default())
                .unwrap()
                .len(),
            1
        );
        drop(store);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn future_schema_version_is_rejected() {
        let path = temp_db_path("future");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", 99).unwrap();
        }
        assert!(RuleStore::open(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn purge_transient_removes_once_and_until_restart() {
        let store = RuleStore::open_in_memory().unwrap();
        store
            .upsert(&rule_with_duration("once", RuleDuration::Once))
            .unwrap();
        store
            .upsert(&rule_with_duration("restart", RuleDuration::UntilRestart))
            .unwrap();
        store
            .upsert(&rule_with_duration("always", RuleDuration::Always))
            .unwrap();
        store
            .upsert(&rule_with_duration("timed", RuleDuration::Seconds(3600)))
            .unwrap();

        assert_eq!(store.purge_transient().unwrap(), 2);

        let snap = store.snapshot().unwrap();
        let names: Vec<&str> = snap.rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(snap.rules.len(), 2);
        assert!(names.contains(&"always"));
        assert!(names.contains(&"timed"));

        // Idempotent.
        assert_eq!(store.purge_transient().unwrap(), 0);
    }

    #[test]
    fn purge_expired_removes_only_expired_seconds_rules() {
        let store = RuleStore::open_in_memory().unwrap();

        let mut expired = rule_with_duration("expired", RuleDuration::Seconds(10));
        expired.created_at = chrono::Utc::now() - chrono::Duration::seconds(60);
        store.upsert(&expired).unwrap();

        let alive = rule_with_duration("alive", RuleDuration::Seconds(3600));
        store.upsert(&alive).unwrap();

        store
            .upsert(&rule_with_duration("always", RuleDuration::Always))
            .unwrap();

        let now_ms = chrono::Utc::now().timestamp_millis();
        assert_eq!(store.purge_expired(now_ms).unwrap(), 1);

        let snap = store.snapshot().unwrap();
        let names: Vec<&str> = snap.rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(snap.rules.len(), 2);
        assert!(names.contains(&"alive"));
        assert!(names.contains(&"always"));
    }

    #[test]
    fn open_purges_transient_rules_at_startup() {
        let path = temp_db_path("startup-purge");

        let store = RuleStore::open(&path).unwrap();
        store
            .upsert(&rule_with_duration("restart", RuleDuration::UntilRestart))
            .unwrap();
        store
            .upsert(&rule_with_duration("always", RuleDuration::Always))
            .unwrap();
        drop(store);

        // "Restart" the daemon: reopen the same database.
        let store = RuleStore::open(&path).unwrap();
        let snap = store.snapshot().unwrap();
        assert_eq!(snap.rules.len(), 1);
        assert_eq!(snap.rules[0].name, "always");
        drop(store);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn snapshot_counts_corrupted_rows_without_deleting_them() {
        let store = RuleStore::open_in_memory().unwrap();
        store.upsert(&sample_rule("curl")).unwrap();

        // Insert a raw row with JSON that no longer matches the Rule format.
        store
            .conn
            .lock()
            .execute(
                "INSERT INTO rules(id, enabled, data) VALUES('bad-row', 1, '{\"not\": \"a rule\"}')",
                [],
            )
            .unwrap();

        let snap = store.snapshot().unwrap();
        assert_eq!(snap.rules.len(), 1);
        assert_eq!(store.skipped_rules(), 1);

        // The corrupt row must still be on disk (not deleted).
        let count: i64 = store
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM rules WHERE id = 'bad-row'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // A clean snapshot resets the count.
        store
            .conn
            .lock()
            .execute("DELETE FROM rules WHERE id = 'bad-row'", [])
            .unwrap();
        store.snapshot().unwrap();
        assert_eq!(store.skipped_rules(), 0);
    }

    #[test]
    fn events_insert_query_roundtrip() {
        let store = RuleStore::open_in_memory().unwrap();
        let batch = vec![
            sample_event(1000, "/usr/bin/curl", "Allow"),
            sample_event(2000, "/usr/bin/wget", "Deny"),
            sample_event(3000, "/usr/bin/curl", "Deny"),
            sample_event(4000, "/usr/bin/firefox", "Allow"),
        ];
        store.insert_events(&batch).unwrap();

        // Newest first, no filter.
        let all = store.query_events(10, 0, EventFilter::default()).unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].ts_unix_ms, 4000);
        assert_eq!(all[3].ts_unix_ms, 1000);
        // Round-trip of all fields (ignore the DB-assigned id).
        let mut got = all[3].clone();
        got.id = 0;
        assert_eq!(got, batch[0]);

        // Limit + offset paginate.
        let page = store.query_events(2, 1, EventFilter::default()).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].ts_unix_ms, 3000);
        assert_eq!(page[1].ts_unix_ms, 2000);

        // Filter by exe substring.
        let curls = store
            .query_events(
                10,
                0,
                EventFilter {
                    exe_contains: Some("curl".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(curls.len(), 2);

        // Filter by action.
        let denies = store
            .query_events(
                10,
                0,
                EventFilter {
                    action: Some("Deny".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(denies.len(), 2);

        // Filter by since_ts.
        let recent = store
            .query_events(
                10,
                0,
                EventFilter {
                    since_ts_unix_ms: Some(3000),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(recent.len(), 2);

        // Combined filters AND together.
        let combo = store
            .query_events(
                10,
                0,
                EventFilter {
                    exe_contains: Some("curl".into()),
                    action: Some("Deny".into()),
                    since_ts_unix_ms: Some(2000),
                },
            )
            .unwrap();
        assert_eq!(combo.len(), 1);
        assert_eq!(combo[0].ts_unix_ms, 3000);
    }

    #[test]
    fn prune_events_keeps_newest() {
        let store = RuleStore::open_in_memory().unwrap();
        let batch: Vec<EventRow> = (1..=5)
            .map(|i| sample_event(i * 1000, "/usr/bin/curl", "Allow"))
            .collect();
        store.insert_events(&batch).unwrap();

        assert_eq!(store.prune_events(2).unwrap(), 3);

        let left = store.query_events(10, 0, EventFilter::default()).unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(left[0].ts_unix_ms, 5000);
        assert_eq!(left[1].ts_unix_ms, 4000);

        // Pruning below the cap is a no-op.
        assert_eq!(store.prune_events(10).unwrap(), 0);
    }

    #[test]
    fn insert_events_empty_batch_is_noop() {
        let store = RuleStore::open_in_memory().unwrap();
        store.insert_events(&[]).unwrap();
        assert!(store
            .query_events(10, 0, EventFilter::default())
            .unwrap()
            .is_empty());
    }
}
