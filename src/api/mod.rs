//! Local dashboard and JSON API.
//!
//! Axum serves alert history from SQLite and traffic statistics from the shared in-memory
//! counters. It binds to loopback only: there is no authentication, no TLS, and no remote access.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::alert::{ALERT_TIME_FORMAT, Alert, optional};
use crate::db::{AlertStore, AlertSummary, DbError};
use crate::stats::{Stats, StatsSnapshot};

/// Loopback address the dashboard listens on.
pub const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);

/// Alerts returned when the caller does not ask for a specific page size.
const DEFAULT_ALERT_LIMIT: i64 = 50;

/// A running dashboard server.
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
        .route("/", get(dashboard))
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

async fn dashboard(State(state): State<AppState>) -> Result<Html<String>, ApiError> {
    let stats = state.stats.snapshot();
    let summary = state.store.summary().await?;
    let alerts = state.store.recent(DEFAULT_ALERT_LIMIT).await?;

    Ok(Html(render_dashboard(&stats, &summary, &alerts)))
}

fn render_dashboard(stats: &StatsSnapshot, summary: &AlertSummary, alerts: &[Alert]) -> String {
    let rows = if alerts.is_empty() {
        "<tr><td colspan=\"6\" class=\"empty\">No alerts recorded yet.</td></tr>".to_string()
    } else {
        alerts.iter().map(render_row).collect()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>Stomper</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #10131a; color: #e6e8ee; }}
h1 {{ margin: 0 0 .25rem; font-size: 1.4rem; }}
p.sub {{ margin: 0 0 1.5rem; color: #8b93a7; font-size: .85rem; }}
.cards {{ display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.5rem; }}
.card {{ background: #191d27; border: 1px solid #262c3a; border-radius: 6px; padding: .75rem 1rem; min-width: 9rem; }}
.card span {{ display: block; color: #8b93a7; font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; }}
.card strong {{ font-size: 1.25rem; font-weight: 600; }}
table {{ border-collapse: collapse; width: 100%; font-size: .85rem; }}
th, td {{ text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #262c3a; vertical-align: top; }}
th {{ color: #8b93a7; font-weight: 600; text-transform: uppercase; font-size: .72rem; }}
td.empty {{ color: #8b93a7; text-align: center; padding: 2rem; }}
.sev-High {{ color: #ff6b6b; }} .sev-Medium {{ color: #ffb454; }} .sev-Low {{ color: #6bd6a0; }}
</style>
</head>
<body>
<h1>Stomper</h1>
<p class="sub">Interface {interface} &middot; database {database} &middot; up {uptime:.0}s &middot; refreshes every 5s</p>
<div class="cards">
  <div class="card"><span>Packets</span><strong>{packets}</strong></div>
  <div class="card"><span>Packets/s</span><strong>{rate:.0}</strong></div>
  <div class="card"><span>Bytes</span><strong>{bytes}</strong></div>
  <div class="card"><span>Dropped (queue full)</span><strong>{dropped}</strong></div>
  <div class="card"><span>Parse errors</span><strong>{parse_errors}</strong></div>
  <div class="card"><span>Alerts</span><strong>{total} <small>({high} high / {medium} medium / {low} low)</small></strong></div>
</div>
<table>
<thead><tr><th>#</th><th>Time (UTC)</th><th>Attack</th><th>Severity</th><th>Source &rarr; Destination</th><th>Details</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"#,
        interface = escape(&stats.interface),
        database = escape(&stats.database),
        uptime = stats.uptime_seconds,
        packets = stats.packets_captured,
        rate = stats.packets_per_second,
        bytes = stats.bytes_captured,
        dropped = stats.packets_dropped_queue_full,
        parse_errors = stats.parse_errors,
        total = summary.total,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
        rows = rows,
    )
}

fn render_row(alert: &Alert) -> String {
    format!(
        "<tr><td>{id}</td><td>{time}</td><td>{category}</td><td class=\"sev-{severity}\">{severity}</td><td>{source} &rarr; {destination}</td><td>{details}</td></tr>",
        id = alert.id.unwrap_or_default(),
        time = alert.timestamp.format(ALERT_TIME_FORMAT),
        category = escape(&alert.category),
        severity = alert.severity.as_str(),
        source = escape(optional(&alert.source)),
        destination = escape(optional(&alert.destination)),
        details = escape(&alert.details),
    )
}

/// Addresses and evidence come from captured traffic, so everything rendered is escaped.
fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }
    escaped
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

    #[test]
    fn rendered_alerts_are_html_escaped() {
        let row = render_row(&alert("<script>alert(1)</script>"));

        assert!(!row.contains("<script>"));
        assert!(row.contains("&lt;script&gt;"));
    }

    #[test]
    fn empty_history_renders_a_placeholder_row() {
        let stats = Stats::new("eth0", "stomper.db").snapshot();

        let page = render_dashboard(&stats, &AlertSummary::default(), &[]);

        assert!(page.contains("No alerts recorded yet."));
        assert!(page.contains("eth0"));
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

        let dashboard = get(addr, "/").await;
        assert!(dashboard.starts_with("HTTP/1.1 200 OK"));
        assert!(dashboard.contains("64 destinations"));

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
