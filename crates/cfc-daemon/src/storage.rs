//! Rule persistence via SQLite.

use anyhow::Context;
use cfc_core::{Rule, RuleSet};
use parking_lot::Mutex;
use rusqlite::Connection;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct RuleStore {
    conn: Arc<Mutex<Connection>>,
}

impl RuleStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).context("opening sqlite")?;
        conn.execute_batch(SCHEMA).context("applying schema")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn snapshot(&self) -> anyhow::Result<RuleSet> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT data FROM rules WHERE enabled = 1")?;
        let rows = stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?;
        let mut rules = Vec::new();
        for r in rows {
            let json = r?;
            match serde_json::from_str::<Rule>(&json) {
                Ok(rule) => rules.push(rule),
                Err(e) => tracing::warn!("skipping malformed rule: {e}"),
            }
        }
        Ok(RuleSet { rules })
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
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
"#;

#[cfg(test)]
impl RuleStore {
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().context("opening sqlite :memory:")?;
        conn.execute_batch(SCHEMA).context("applying schema")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
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

    #[test]
    fn empty_store_returns_empty_set() {
        let store = RuleStore::open_in_memory().unwrap();
        let snap = store.snapshot().unwrap();
        assert!(snap.rules.is_empty());
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
}
