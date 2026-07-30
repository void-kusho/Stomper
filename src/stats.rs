//! Shared in-memory runtime counters.
//!
//! Capture and the alert manager write these counters; the API reads them. They live only for the
//! current run - only alerts are persisted.

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Process-wide counters shared through an `Arc`.
pub struct Stats {
    /// Interface the capture worker is reading from.
    interface: String,
    /// Path of the SQLite database backing alert storage.
    database: String,
    started_at: DateTime<Utc>,
    packets_captured: AtomicU64,
    bytes_captured: AtomicU64,
    parse_errors: AtomicU64,
    packets_dropped_queue_full: AtomicU64,
    alerts_generated: AtomicU64,
}

impl Stats {
    pub fn new(interface: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            database: database.into(),
            started_at: Utc::now(),
            packets_captured: AtomicU64::new(0),
            bytes_captured: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            packets_dropped_queue_full: AtomicU64::new(0),
            alerts_generated: AtomicU64::new(0),
        }
    }

    /// Records one successfully parsed frame of `raw_len` bytes.
    pub fn record_packet(&self, raw_len: usize) {
        self.packets_captured.fetch_add(1, Ordering::Relaxed);
        self.bytes_captured
            .fetch_add(raw_len as u64, Ordering::Relaxed);
    }

    /// Records one frame the parser rejected.
    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one parsed packet dropped because the detection queue was full.
    pub fn record_queue_drop(&self) {
        self.packets_dropped_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one alert accepted by the alert manager.
    pub fn record_alert(&self) {
        self.alerts_generated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let uptime_seconds = (Utc::now() - self.started_at).as_seconds_f64().max(0.0);
        let packets_captured = self.packets_captured.load(Ordering::Relaxed);
        StatsSnapshot {
            interface: self.interface.clone(),
            database: self.database.clone(),
            started_at: self.started_at,
            uptime_seconds,
            packets_captured,
            bytes_captured: self.bytes_captured.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            packets_dropped_queue_full: self.packets_dropped_queue_full.load(Ordering::Relaxed),
            alerts_generated: self.alerts_generated.load(Ordering::Relaxed),
            packets_per_second: if uptime_seconds > 0.0 {
                packets_captured as f64 / uptime_seconds
            } else {
                0.0
            },
        }
    }
}

/// A consistent-enough view of [`Stats`] for one API response or one shutdown summary.
#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub interface: String,
    pub database: String,
    pub started_at: DateTime<Utc>,
    pub uptime_seconds: f64,
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub parse_errors: u64,
    pub packets_dropped_queue_full: u64,
    pub alerts_generated: u64,
    pub packets_per_second: f64,
}
