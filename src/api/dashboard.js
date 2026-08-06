const number = new Intl.NumberFormat();
const rows = document.querySelector("#alert-rows");
const status = document.querySelector("#status");
const refreshButton = document.querySelector("#refresh");

function formatBytes(bytes) {
  if (bytes < 1024) return `${number.format(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

function formatDuration(seconds) {
  const totalSeconds = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const remainder = totalSeconds % 60;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${remainder}s`;
  return `${remainder}s`;
}

function renderStatistics(stats) {
  document.querySelector("#packets").textContent = number.format(stats.packets_captured);
  document.querySelector("#bytes").textContent = formatBytes(stats.bytes_captured);
  document.querySelector("#alerts").textContent = number.format(stats.alerts_detected);
  document.querySelector("#protocols").textContent =
    `TCP ${number.format(stats.tcp_packets)} / UDP ${number.format(stats.udp_packets)} / ` +
    `ICMP ${number.format(stats.icmp_packets)} / Other ${number.format(stats.other_packets)}`;
}

function renderRuntime(runtime) {
  const captureStatus = document.querySelector("#capture-status");
  captureStatus.textContent = runtime.capture_active ? "Capturing" : "Standby";
  captureStatus.dataset.active = runtime.capture_active;
  document.querySelector("#interface").textContent = runtime.interface || "No interface";
  const startedAt = new Date(runtime.started_at_ms).valueOf();
  document.querySelector("#uptime").textContent = Number.isNaN(startedAt)
    ? "--"
    : formatDuration((Date.now() - startedAt) / 1000);
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = value || "--";
  row.append(cell);
}

function renderAlertMessage(message, isError = false) {
  rows.replaceChildren();
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 6;
  cell.className = isError ? "empty error" : "empty";
  cell.textContent = message;
  row.append(cell);
  rows.append(row);
}

function renderAlerts(alerts) {
  rows.replaceChildren();
  if (!alerts.length) {
    renderAlertMessage("No alerts have been recorded.");
    return;
  }

  for (const alert of alerts) {
    const row = document.createElement("tr");
    const severityCell = document.createElement("td");
    const severity = document.createElement("span");
    const occurredAt = new Date(alert.occurred_at_ms);

    severity.className = "severity";
    severity.dataset.level = alert.severity.toLowerCase();
    severity.textContent = alert.severity;
    severityCell.append(severity);

    appendCell(row, Number.isNaN(occurredAt.valueOf()) ? "Unknown" : occurredAt.toLocaleString());
    row.append(severityCell);
    appendCell(row, alert.attack_type);
    appendCell(row, alert.source_ip);
    appendCell(row, alert.destination_ip);
    appendCell(row, alert.details);
    rows.append(row);
  }
}

async function getJson(url) {
  const response = await fetch(url, {
    cache: "no-store",
    headers: { Accept: "application/json" }
  });
  if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
  return response.json();
}

async function refresh() {
  if (refreshButton.disabled) return;
  refreshButton.disabled = true;
  status.textContent = "Refreshing...";
  status.dataset.state = "";

  const [statistics, alerts, runtime] = await Promise.allSettled([
    getJson("/api/statistics"),
    getJson("/api/alerts/recent?limit=20"),
    getJson("/api/status")
  ]);
  const unavailable = [];

  if (statistics.status === "fulfilled") {
    renderStatistics(statistics.value);
  } else {
    unavailable.push("traffic summary");
  }

  if (alerts.status === "fulfilled") {
    renderAlerts(alerts.value);
  } else {
    renderAlertMessage("Recent alerts are temporarily unavailable.", true);
    unavailable.push("alerts");
  }

  if (runtime.status === "fulfilled") {
    renderRuntime(runtime.value);
  } else {
    unavailable.push("capture status");
  }

  if (unavailable.length) {
    status.textContent = `${unavailable.join(", ")} unavailable`;
    status.dataset.state = "error";
  } else {
    status.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    status.dataset.state = "ok";
  }

  refreshButton.disabled = false;
}

refreshButton.addEventListener("click", refresh);
refresh();
window.setInterval(refresh, 5000);
