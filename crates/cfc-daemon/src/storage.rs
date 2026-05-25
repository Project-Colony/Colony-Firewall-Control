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
