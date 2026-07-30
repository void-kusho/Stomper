//! Alert manager.
//!
//! Detector [`Activity`] values become [`Alert`] records here. The manager task owns one bounded
//! channel: it consumes alerts, persists them through [`AlertStore`], prints them to the console,
//! and bumps the shared counters. Alert volume is much lower than packet volume, so a single task
//! is enough and keeps insert order equal to detection order.

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::db::AlertStore;
use crate::detection::Activity;
use crate::stats::Stats;

/// Capacity of the bounded channel between the detection task and the alert manager.
const ALERT_QUEUE_CAPACITY: usize = 64;

/// Timestamp layout shared by the console alert and the dashboard table.
pub(crate) const ALERT_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

/// Console/database name of a port scan alert.
pub const CATEGORY_PORT_SCAN: &str = "Port Scan";
/// Console/database name of a SYN flood alert.
pub const CATEGORY_SYN_FLOOD: &str = "SYN Flood";

/// How serious an alert is. Stored and served as its string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        }
    }

    /// Parses the stored string form. Returns `None` for anything this build does not know.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Low" => Some(Self::Low),
            "Medium" => Some(Self::Medium),
            "High" => Some(Self::High),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One recorded detection. Contains no packet payload; only addresses, counts, and a summary.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    /// Database row id. `None` until the alert has been stored.
    pub id: Option<i64>,
    /// When the packet that triggered detection was captured, in UTC.
    pub timestamp: DateTime<Utc>,
    /// Attack name, e.g. [`CATEGORY_PORT_SCAN`].
    pub category: String,
    pub severity: Severity,
    /// Attacking address, when the detector can attribute one.
    pub source: Option<String>,
    /// Targeted address, when the detector can attribute one.
    pub destination: Option<String>,
    /// Supporting evidence: counts, ports, observed sources.
    pub details: String,
}

impl Alert {
    /// Builds an alert from a detection, timestamped with the packet that triggered it.
    pub fn from_activity(activity: &Activity, observed_at: SystemTime) -> Self {
        let timestamp = DateTime::<Utc>::from(observed_at);
        match activity {
            Activity::SingleSourceScan {
                src,
                destinations,
                ports,
            } => Self {
                id: None,
                timestamp,
                category: CATEGORY_PORT_SCAN.to_string(),
                severity: Severity::Medium,
                source: Some(src.to_string()),
                destination: None,
                details: format!(
                    "{destinations} distinct destination sockets contacted; ports {}",
                    join(ports)
                ),
            },
            Activity::SynFlood {
                dst,
                syn_count,
                sources,
            } => Self {
                id: None,
                timestamp,
                category: CATEGORY_SYN_FLOOD.to_string(),
                severity: Severity::High,
                source: Some(join(sources)),
                destination: Some(dst.to_string()),
                details: format!(
                    "{syn_count} bare SYN packets from {} sources",
                    sources.len()
                ),
            },
        }
    }
}

/// Console form, as specified by `docs/testing.md` section 6.
impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "[{} UTC] ALERT: {} Detected",
            self.timestamp.format(ALERT_TIME_FORMAT),
            self.category
        )?;
        writeln!(f, "  Source:      {}", optional(&self.source))?;
        writeln!(f, "  Destination: {}", optional(&self.destination))?;
        writeln!(f, "  Severity:    {}", self.severity)?;
        write!(f, "  Details:     {}", self.details)
    }
}

/// Spawns the alert manager and returns the sender the detection task writes to. The task drains
/// its queue and exits once every sender is dropped, so a clean shutdown is "stop capture, drop the
/// sender, then await this handle".
pub fn spawn_manager(
    store: AlertStore,
    stats: Arc<Stats>,
) -> (mpsc::Sender<Alert>, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(ALERT_QUEUE_CAPACITY);
    (tx, tokio::spawn(run(store, stats, rx)))
}

async fn run(store: AlertStore, stats: Arc<Stats>, mut rx: mpsc::Receiver<Alert>) {
    while let Some(alert) = rx.recv().await {
        // A storage failure must not silence the console alert, so report and keep going.
        if let Err(e) = store.insert(&alert).await {
            eprintln!("Failed to store alert: {e}");
        }
        stats.record_alert();
        println!("{alert}");
    }
}

fn join<T: fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(T::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders a missing address as a dash, for both the console form and the dashboard.
pub(crate) fn optional(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("-")
}

/// Alert fixtures shared by the `alert`, `db`, and `api` tests, so the struct's field set is
/// written out once.
#[cfg(test)]
pub(crate) mod test_support {
    use std::time::{Duration, SystemTime};

    use chrono::{DateTime, Utc};

    use super::{Alert, Severity};

    /// 2025-07-23 10:35:14 UTC, fixed so tests never depend on the clock.
    const TEST_UNIX_SECONDS: i64 = 1_753_266_914;

    pub fn observed_at() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(TEST_UNIX_SECONDS as u64)
    }

    pub fn sample_alert(category: &str, severity: Severity, details: &str) -> Alert {
        Alert {
            id: None,
            timestamp: DateTime::<Utc>::from_timestamp(TEST_UNIX_SECONDS, 0)
                .expect("valid timestamp"),
            category: category.to_string(),
            severity,
            source: Some("192.168.1.50".to_string()),
            destination: None,
            details: details.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::observed_at;
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn scan_activity() -> Activity {
        Activity::SingleSourceScan {
            src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            destinations: 64,
            ports: vec![22, 80, 443],
        }
    }

    fn flood_activity() -> Activity {
        Activity::SynFlood {
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80),
            syn_count: 256,
            sources: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))],
        }
    }

    #[test]
    fn port_scan_maps_to_medium_severity_with_evidence() {
        let alert = Alert::from_activity(&scan_activity(), observed_at());

        assert_eq!(alert.category, CATEGORY_PORT_SCAN);
        assert_eq!(alert.severity, Severity::Medium);
        assert_eq!(alert.source.as_deref(), Some("192.168.1.50"));
        assert!(alert.details.contains("64 distinct destination sockets"));
        assert!(alert.details.contains("22, 80, 443"));
    }

    #[test]
    fn syn_flood_maps_to_high_severity_with_target() {
        let alert = Alert::from_activity(&flood_activity(), observed_at());

        assert_eq!(alert.category, CATEGORY_SYN_FLOOD);
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.destination.as_deref(), Some("192.168.1.1:80"));
        assert!(alert.details.contains("256 bare SYN packets"));
    }

    /// The console block must carry every field listed in `docs/testing.md` section 6.
    #[test]
    fn console_form_contains_required_fields() {
        let rendered = Alert::from_activity(&scan_activity(), observed_at()).to_string();

        assert!(rendered.contains("2025-07-23 10:35:14 UTC"));
        assert!(rendered.contains("ALERT: Port Scan Detected"));
        assert!(rendered.contains("Source:      192.168.1.50"));
        assert!(rendered.contains("Destination: -"));
        assert!(rendered.contains("Severity:    Medium"));
    }

    /// Detection -> channel -> manager -> SQLite, the path `main` wires up.
    #[tokio::test]
    async fn manager_stores_every_queued_alert_then_exits() {
        let store = AlertStore::in_memory().await.expect("open store");
        let stats = Arc::new(Stats::new("eth0", "memory"));

        let (tx, task) = spawn_manager(store.clone(), Arc::clone(&stats));

        for activity in [scan_activity(), flood_activity()] {
            tx.send(Alert::from_activity(&activity, observed_at()))
                .await
                .expect("queue alert");
        }

        // Dropping the last sender is what tells the manager to drain and stop.
        drop(tx);
        task.await.expect("manager task");

        let stored = store.recent(10).await.expect("query");
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].category, CATEGORY_SYN_FLOOD);
        assert_eq!(stored[1].category, CATEGORY_PORT_SCAN);
        assert!(stored.iter().all(|alert| alert.id.is_some()));
        assert_eq!(stats.snapshot().alerts_generated, 2);
    }

    #[test]
    fn severity_round_trips_through_its_stored_form() {
        for severity in [Severity::Low, Severity::Medium, Severity::High] {
            assert_eq!(Severity::parse(severity.as_str()), Some(severity));
        }
        assert_eq!(Severity::parse("Critical"), None);
    }
}
