//! SQLite alert storage.
//!
//! One table, one writer. The schema and the reasoning behind it are documented in
//! `docs/development/database.md`. Every statement is parameterised; no packet payload is stored.

use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};

use crate::alert::{Alert, Severity};

/// Default database file, created on first run if missing.
pub const DEFAULT_DATABASE_PATH: &str = "stomper.db";

/// Largest page of alerts a caller may request in one query.
pub const MAX_QUERY_LIMIT: i64 = 500;

/// The whole schema. Re-running it is a no-op, so it doubles as the migration step.
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT    NOT NULL,
        category    TEXT    NOT NULL,
        severity    TEXT    NOT NULL,
        source      TEXT,
        destination TEXT,
        details     TEXT    NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] sqlx::Error),
    #[error("stored alert {id} has an unreadable {field}")]
    InvalidRow { id: i64, field: &'static str },
}

/// Handle to the alert database. Cloning shares the same connection pool.
#[derive(Clone)]
pub struct AlertStore {
    pool: SqlitePool,
}

impl AlertStore {
    /// Opens (creating if needed) the database at `path` and applies the schema.
    pub async fn open(path: &str) -> Result<Self, DbError> {
        Self::connect(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
        .await
    }

    /// Opens a private in-memory database, so tests never touch a real file.
    #[cfg(test)]
    pub async fn in_memory() -> Result<Self, DbError> {
        Self::connect(SqliteConnectOptions::new().filename(":memory:")).await
    }

    /// A single connection keeps writes serialised, avoids SQLite lock contention, and lets the
    /// in-memory database survive between calls. Alert volume does not need more.
    async fn connect(options: SqliteConnectOptions) -> Result<Self, DbError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        sqlx::raw_sql(SCHEMA).execute(&pool).await?;
        Ok(Self { pool })
    }

    /// Stores one alert and returns its new row id.
    pub async fn insert(&self, alert: &Alert) -> Result<i64, DbError> {
        let result = sqlx::query(
            "INSERT INTO alerts (timestamp, category, severity, source, destination, details)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(alert.timestamp.to_rfc3339())
        .bind(&alert.category)
        .bind(alert.severity.as_str())
        .bind(alert.source.as_deref())
        .bind(alert.destination.as_deref())
        .bind(&alert.details)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Returns the most recent alerts, newest first. `limit` is clamped to [`MAX_QUERY_LIMIT`].
    pub async fn recent(&self, limit: i64) -> Result<Vec<Alert>, DbError> {
        let rows = sqlx::query(
            "SELECT id, timestamp, category, severity, source, destination, details
             FROM alerts ORDER BY id DESC LIMIT ?",
        )
        .bind(limit.clamp(1, MAX_QUERY_LIMIT))
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(row_to_alert).collect()
    }

    /// Returns one alert by row id.
    pub async fn by_id(&self, id: i64) -> Result<Option<Alert>, DbError> {
        let row = sqlx::query(
            "SELECT id, timestamp, category, severity, source, destination, details
             FROM alerts WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(row_to_alert).transpose()
    }

    /// Counts stored alerts per severity, for the dashboard summary.
    pub async fn summary(&self) -> Result<AlertSummary, DbError> {
        let rows = sqlx::query("SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity")
            .fetch_all(&self.pool)
            .await?;

        let mut summary = AlertSummary::default();
        for row in &rows {
            let count: i64 = row.try_get("count")?;
            summary.total += count;
            match Severity::parse(row.try_get("severity")?) {
                Some(Severity::Low) => summary.low += count,
                Some(Severity::Medium) => summary.medium += count,
                Some(Severity::High) => summary.high += count,
                // A severity written by another build still counts toward the total.
                None => {}
            }
        }
        Ok(summary)
    }
}

/// Stored alert counts, grouped by severity.
#[derive(Debug, Default, Clone, Serialize)]
pub struct AlertSummary {
    pub total: i64,
    pub low: i64,
    pub medium: i64,
    pub high: i64,
}

fn row_to_alert(row: &SqliteRow) -> Result<Alert, DbError> {
    let id: i64 = row.try_get("id")?;
    let timestamp: String = row.try_get("timestamp")?;
    let severity: String = row.try_get("severity")?;

    Ok(Alert {
        id: Some(id),
        timestamp: chrono::DateTime::parse_from_rfc3339(&timestamp)
            .map_err(|_| DbError::InvalidRow {
                id,
                field: "timestamp",
            })?
            .into(),
        category: row.try_get("category")?,
        severity: Severity::parse(&severity).ok_or(DbError::InvalidRow {
            id,
            field: "severity",
        })?,
        source: row.try_get("source")?,
        destination: row.try_get("destination")?,
        details: row.try_get("details")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::test_support::sample_alert;

    fn alert(category: &str, severity: Severity) -> Alert {
        sample_alert(
            category,
            severity,
            "64 distinct destination sockets contacted; ports 22, 80",
        )
    }

    #[tokio::test]
    async fn stored_alert_round_trips() {
        let store = AlertStore::in_memory().await.expect("open store");
        let stored = alert("Port Scan", Severity::Medium);

        let id = store.insert(&stored).await.expect("insert");
        let loaded = store.by_id(id).await.expect("query").expect("row exists");

        assert_eq!(loaded.id, Some(id));
        assert_eq!(loaded.category, stored.category);
        assert_eq!(loaded.severity, stored.severity);
        assert_eq!(loaded.source, stored.source);
        assert_eq!(loaded.destination, None);
        assert_eq!(loaded.details, stored.details);
        assert_eq!(loaded.timestamp, stored.timestamp);
    }

    #[tokio::test]
    async fn recent_returns_newest_first_and_respects_the_limit() {
        let store = AlertStore::in_memory().await.expect("open store");
        for _ in 0..3 {
            store
                .insert(&alert("Port Scan", Severity::Medium))
                .await
                .expect("insert");
        }
        let last = store
            .insert(&alert("SYN Flood", Severity::High))
            .await
            .expect("insert");

        let recent = store.recent(2).await.expect("query");

        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id, Some(last));
        assert_eq!(recent[0].category, "SYN Flood");
    }

    #[tokio::test]
    async fn missing_alert_is_not_an_error() {
        let store = AlertStore::in_memory().await.expect("open store");

        assert!(store.by_id(404).await.expect("query").is_none());
    }

    #[tokio::test]
    async fn summary_counts_each_severity() {
        let store = AlertStore::in_memory().await.expect("open store");
        store
            .insert(&alert("Port Scan", Severity::Medium))
            .await
            .expect("insert");
        store
            .insert(&alert("SYN Flood", Severity::High))
            .await
            .expect("insert");
        store
            .insert(&alert("SYN Flood", Severity::High))
            .await
            .expect("insert");

        let summary = store.summary().await.expect("query");

        assert_eq!(summary.total, 3);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.high, 2);
    }
}
