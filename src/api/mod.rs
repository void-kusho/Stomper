use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tokio::{net::TcpListener, sync::RwLock};

use crate::capture::{ParsedPacket, TransportHeader};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");
const DASHBOARD_CSS: &str = include_str!("dashboard.css");
const DASHBOARD_JS: &str = include_str!("dashboard.js");
const DEFAULT_ALERT_LIMIT: u32 = 20;
const MAX_ALERT_LIMIT: u32 = 100;

const RECENT_ALERTS_SQL: &str = r#"
    SELECT id, occurred_at_ms, attack_type, severity,
           source_ip, destination_ip, details
    FROM alerts
    ORDER BY occurred_at_ms DESC, id DESC
    LIMIT ?
"#;

pub type SharedStatistics = Arc<RwLock<TrafficStatistics>>;
pub type SharedStatus = Arc<RwLock<RuntimeStatus>>;

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrafficStatistics {
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub alerts_detected: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub other_packets: u64,
}

impl TrafficStatistics {
    pub fn observe_packet(&mut self, packet: &ParsedPacket) {
        self.packets_captured = self.packets_captured.saturating_add(1);
        self.bytes_captured = self.bytes_captured.saturating_add(packet.raw_len as u64);

        match &packet.transport {
            Some(TransportHeader::Tcp(_)) => self.tcp_packets = self.tcp_packets.saturating_add(1),
            Some(TransportHeader::Udp(_)) => self.udp_packets = self.udp_packets.saturating_add(1),
            Some(TransportHeader::Icmp(_)) => {
                self.icmp_packets = self.icmp_packets.saturating_add(1)
            }
            Some(TransportHeader::Unknown(_)) | None => {
                self.other_packets = self.other_packets.saturating_add(1)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub capture_active: bool,
    pub interface: Option<String>,
    pub started_at_ms: i64,
}

pub struct ApiState {
    pool: SqlitePool,
    statistics: SharedStatistics,
    status: SharedStatus,
}

impl Clone for ApiState {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            statistics: Arc::clone(&self.statistics),
            status: Arc::clone(&self.status),
        }
    }
}

impl ApiState {
    pub fn new(pool: SqlitePool, statistics: SharedStatistics, status: SharedStatus) -> Self {
        Self {
            pool,
            statistics,
            status,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AlertSummary {
    pub id: i64,
    pub occurred_at_ms: i64,
    pub attack_type: String,
    pub severity: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub details: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RecentAlertsQuery {
    limit: Option<u32>,
}

#[derive(Serialize)]
struct ErrorMessage {
    error: &'static str,
}

struct ApiError(sqlx::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        eprintln!("API database query failed: {}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorMessage {
                error: "Unable to load alerts",
            }),
        )
            .into_response()
    }
}

pub fn shared_statistics() -> SharedStatistics {
    Arc::new(RwLock::new(TrafficStatistics::default()))
}

pub fn shared_status() -> SharedStatus {
    Arc::new(RwLock::new(RuntimeStatus {
        capture_active: false,
        interface: None,
        started_at_ms: now_ms(),
    }))
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/dashboard.css", get(dashboard_css))
        .route("/dashboard.js", get(dashboard_js))
        .route("/api/alerts/recent", get(recent_alerts))
        .route("/api/statistics", get(statistics))
        .route("/api/status", get(status))
        .with_state(state)
}

pub async fn serve(port: u16, state: ApiState) -> std::io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    axum::serve(listener, router(state)).await
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn dashboard_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css")], DASHBOARD_CSS)
}

async fn dashboard_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        DASHBOARD_JS,
    )
}

async fn recent_alerts(
    State(state): State<ApiState>,
    Query(query): Query<RecentAlertsQuery>,
) -> Result<Json<Vec<AlertSummary>>, ApiError> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ALERT_LIMIT)
        .clamp(1, MAX_ALERT_LIMIT) as i64;

    let rows = sqlx::query(RECENT_ALERTS_SQL)
        .bind(limit)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError)?;

    let alerts = rows
        .into_iter()
        .map(|row| AlertSummary {
            id: row.get("id"),
            occurred_at_ms: row.get("occurred_at_ms"),
            attack_type: row.get("attack_type"),
            severity: row.get("severity"),
            source_ip: row.get("source_ip"),
            destination_ip: row.get("destination_ip"),
            details: row.get("details"),
        })
        .collect();

    Ok(Json(alerts))
}

async fn statistics(State(state): State<ApiState>) -> Json<TrafficStatistics> {
    Json(state.statistics.read().await.clone())
}

async fn status(State(state): State<ApiState>) -> Json<RuntimeStatus> {
    Json(state.status.read().await.clone())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Ipv4Header, ParsedPacket};
    use std::net::Ipv4Addr;

    #[test]
    fn statistics_count_packet_protocol_and_bytes() {
        let mut statistics = TrafficStatistics::default();
        statistics.observe_packet(&ParsedPacket {
            timestamp: SystemTime::UNIX_EPOCH,
            ethernet: None,
            ipv4: Some(Ipv4Header {
                src_ip: Ipv4Addr::LOCALHOST,
                dst_ip: Ipv4Addr::LOCALHOST,
                protocol: 17,
                ttl: 64,
                total_length: 28,
                identification: 0,
                version: 4,
                ihl: 5,
                dscp: 0,
                ecn: 0,
                flags: 0,
                fragment_offset: 0,
            }),
            ipv6: None,
            transport: Some(TransportHeader::Udp(crate::capture::UdpHeader {
                src_port: 1,
                dst_port: 2,
                length: 8,
                checksum: 0,
            })),
            raw_len: 42,
        });

        assert_eq!(statistics.packets_captured, 1);
        assert_eq!(statistics.bytes_captured, 42);
        assert_eq!(statistics.udp_packets, 1);
//! Local JSON API.
//!
//! Axum serves alert history from SQLite and traffic statistics from the shared in-memory
//! counters. It binds to loopback only: there is no authentication, no TLS, and no remote access.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::alert::Alert;
use crate::db::{AlertStore, AlertSummary, DbError};
use crate::stats::{Stats, StatsSnapshot};

/// Loopback address the API listens on.
pub const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);

/// Alerts returned when the caller does not ask for a specific page size.
const DEFAULT_ALERT_LIMIT: i64 = 50;

/// A running API server.
pub struct ApiServer {
    /// Address actually bound, which matters when the caller asked for port 0.
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl ApiServer {
    /// Stops serving. In-flight requests are cut off; nothing durable is lost because the API only
    /// reads.
    pub fn stop(self) {
        self.task.abort();
    }
}

/// Binds the listener, then serves in the background. Binding eagerly means a port clash is
/// reported during startup instead of disappearing into a task.
pub async fn serve(
    bind: SocketAddr,
    store: AlertStore,
    stats: Arc<Stats>,
) -> Result<ApiServer, std::io::Error> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let router = router(AppState { store, stats });

    Ok(ApiServer {
        addr,
        task: tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                eprintln!("API server stopped: {e}");
            }
        }),
    })
}

#[derive(Clone)]
struct AppState {
    store: AlertStore,
    stats: Arc<Stats>,
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/{id}", get(get_alert))
        .route("/api/stats", get(get_stats))
        .route("/api/status", get(get_status))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct AlertQuery {
    /// Page size. Defaults to [`DEFAULT_ALERT_LIMIT`]; the store clamps the upper bound.
    limit: Option<i64>,
}

/// Traffic statistics plus the stored alert breakdown.
#[derive(Debug, Serialize)]
struct StatsResponse {
    traffic: StatsSnapshot,
    alerts: AlertSummary,
}

/// Whether the process is healthy, and the counters that show it.
#[derive(Debug, Serialize)]
struct StatusResponse {
    healthy: bool,
    #[serde(flatten)]
    traffic: StatsSnapshot,
}

async fn list_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertQuery>,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let limit = query.limit.unwrap_or(DEFAULT_ALERT_LIMIT);
    Ok(Json(state.store.recent(limit).await?))
}

async fn get_alert(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Alert>, ApiError> {
    state
        .store
        .by_id(id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

async fn get_stats(State(state): State<AppState>) -> Result<Json<StatsResponse>, ApiError> {
    Ok(Json(StatsResponse {
        traffic: state.stats.snapshot(),
        alerts: state.store.summary().await?,
    }))
}

/// Reaching this handler at all proves the runtime is up; the database is checked separately.
async fn get_status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        healthy: true,
        traffic: state.stats.snapshot(),
    })
}

enum ApiError {
    Db(DbError),
    NotFound,
}

impl From<DbError> for ApiError {
    fn from(error: DbError) -> Self {
        Self::Db(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Db(error) => {
                eprintln!("API database error: {error}");
                (StatusCode::INTERNAL_SERVER_ERROR, "database error").into_response()
            }
            Self::NotFound => (StatusCode::NOT_FOUND, "alert not found").into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Severity, test_support::sample_alert};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn alert(details: &str) -> Alert {
        sample_alert(crate::alert::CATEGORY_PORT_SCAN, Severity::Medium, details)
    }

    /// Minimal HTTP/1.1 GET, so the routes can be exercised without a client dependency.
    async fn get(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("send request");

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read response");
        response
    }

    #[tokio::test]
    async fn serves_stored_alerts_and_runtime_status() {
        let store = AlertStore::in_memory().await.expect("open store");
        let id = store
            .insert(&alert("64 destinations"))
            .await
            .expect("insert");
        let stats = Arc::new(Stats::new("eth0", "memory"));
        stats.record_packet(64);

        let server = serve("127.0.0.1:0".parse().expect("valid address"), store, stats)
            .await
            .expect("bind");
        let addr = server.addr;

        let alerts = get(addr, "/api/alerts?limit=10").await;
        assert!(alerts.contains("\"category\":\"Port Scan\""));
        assert!(alerts.contains("\"severity\":\"Medium\""));

        let one = get(addr, &format!("/api/alerts/{id}")).await;
        assert!(one.starts_with("HTTP/1.1 200 OK"));

        let missing = get(addr, "/api/alerts/9999").await;
        assert!(missing.starts_with("HTTP/1.1 404 Not Found"));

        let status = get(addr, "/api/status").await;
        assert!(status.contains("\"healthy\":true"));
        assert!(status.contains("\"packets_captured\":1"));

        let stats_body = get(addr, "/api/stats").await;
        assert!(stats_body.contains("\"total\":1"));

        server.stop();
    }
}
