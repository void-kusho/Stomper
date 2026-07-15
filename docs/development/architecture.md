# Stomper Architecture

## Overview

Stomper is a network intrusion detection system (IDS) written in Rust. It captures live traffic, detects suspicious activity (port scans, SYN floods, signature matches, anomalies), and surfaces alerts through a web dashboard.

The system follows a **modular pipeline architecture** with independent components connected via channels and a shared database. Each component can be developed, tested, and scaled independently.

---

## High-Level Architecture

```mermaid
flowchart TB
    subgraph Network["Network"]
        NIC["Network Interface"]
    end

    subgraph Stomper["Stomper IDS"]
        PC["Packet Capture"]
        DE["Detection Engine"]
        AM["Alert Manager"]
        DB[("SQLite Database")]
        API["REST API (Axum)"]
        UI["Web Dashboard"]
        CFG[("Config / Rules<br/>JSON/YAML")]
    end

    subgraph Admin["Administrator"]
        ADMIN["Security Admin"]
    end

    NIC -->|"live traffic"| PC
    PC -->|"raw packets"| DE
    DE -->|"alerts"| AM
    AM -->|"persist"| DB
    DB -->|"query"| API
    API -->|"JSON"| UI
    UI --> ADMIN
    CFG -.->|"rules"| DE
    CFG -.->|"settings"| PC
```

---

## Component Architecture

```mermaid
flowchart LR
    subgraph Capture["Capture Layer"]
        PC["pcap/pnet<br/>Packet Sniffer"]
        PP["Packet Parser<br/>(Ethernet/IP/TCP/UDP)"]
    end

    subgraph Detection["Detection Layer"]
        PS["Port Scan<br/>Detector"]
        SF["SYN Flood<br/>Detector"]
        SD["Signature<br/>Detector"]
        AD["Anomaly<br/>Detector"]
    end

    subgraph Alerting["Alert Layer"]
        AM["Alert Manager"]
        AL["Alert Logger<br/>(SQLite)"]
        AN["Notifier<br/>(Console / Log / Webhook)"]
    end

    subgraph UI_Layer["Presentation Layer"]
        API["REST API<br/>(Axum)"]
        DASH["Web Dashboard<br/>(HTML + HTMX)"]
    end

    subgraph Config["Configuration"]
        CFG["Rule Engine<br/>(Serde / YAML+JSON)"]
    end

    PC --> PP
    PP --> PS
    PP --> SF
    PP --> SD
    PP --> AD
    PS --> AM
    SF --> AM
    SD --> AM
    AD --> AM
    AM --> AL
    AM --> AN
    AL --> API
    API --> DASH
    CFG -.-> SD
    CFG -.-> AD
```

---

## Data Flow

```mermaid
sequenceDiagram
    participant NIC as Network Interface
    participant PC as Packet Capture
    participant DE as Detection Engine
    participant AM as Alert Manager
    participant DB as SQLite
    participant API as REST API
    participant UI as Dashboard

    loop Every packet
        NIC->>PC: raw frame
        PC->>PC: parse headers
        PC->>DE: parsed packet
        DE->>DE: analyze (port scan, SYN flood, signatures, anomalies)
        alt Suspicious activity detected
            DE->>AM: alert event
            AM->>DB: INSERT alert
            AM->>AM: console / log output
        end
    end

    UI->>API: GET /api/alerts
    API->>DB: SELECT alerts
    DB-->>API: alert rows
    API-->>UI: JSON response
    UI->>UI: render dashboard

    UI->>API: GET /api/stats
    API->>DB: SELECT stats
    DB-->>API: statistics
    API-->>UI: JSON response
```

---

## Module Structure

```
src/
├── main.rs                 # Entry point, wires components together
├── capture/                # Packet capture & parsing
│   ├── mod.rs
│   ├── sniffer.rs          # pcap/pnet interface binding
│   └── parser.rs           # Ethernet/IP/TCP/UDP header parsing
├── detection/              # Intrusion detection engine
│   ├── mod.rs
│   ├── port_scan.rs        # Port scan detection logic
│   ├── syn_flood.rs        # SYN flood detection logic
│   ├── signature.rs        # Signature-based matching
│   └── anomaly.rs          # Behavioral / statistical anomalies
├── alert/                  # Alert management
│   ├── mod.rs
│   ├── manager.rs          # Alert lifecycle, dedup, throttling
│   ├── storage.rs          # SQLite read/write via rusqlite/sqlx
│   └── notifier.rs         # Console, log file, webhook/email sinks
├── api/                    # REST API & dashboard
│   ├── mod.rs
│   ├── routes.rs           # Axum route handlers
│   ├── dashboard.rs        # Dashboard HTML rendering
│   └── response.rs         # JSON response types
├── config/                 # Configuration & rules
│   ├── mod.rs
│   ├── settings.rs         # App-wide configuration
│   └── rules.rs            # Rule parsing (Serde, YAML/JSON)
└── db/                     # Database layer
    ├── mod.rs
    ├── migrations.rs       # Schema setup
    └── models.rs           # Row types
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Language | Rust (edition 2024) | Memory-safe systems programming |
| Packet Capture | `pcap` / `pnet` | Live network interface binding and packet parsing |
| Async Runtime | `Tokio` | Concurrent non-blocking packet processing |
| Web Framework | `Axum` | REST API and HTTP dashboard server |
| Database | `SQLite` via `rusqlite` / `sqlx` | Persistent alert and event storage |
| Serialization | `Serde` | JSON/YAML config and rule file parsing |
| Dashboard | HTML + HTMX | Lightweight web UI (no heavy JS framework) |
| Testing | Built-in `#[test]` | Unit and integration tests |

---

## Key Design Decisions

- **Pipeline concurrency**: The capture, detection, and alert stages run on separate Tokio tasks connected by channels. This prevents backpressure from dropping packets when analysis is slow.
- **Open/Closed Principle**: New detection modules (e.g., brute-force, DNS tunneling) can be added without modifying existing code — each implements a common `Detector` trait.
- **Configuration hot-reload**: Rule files are watched for changes and reloaded without restarting the process, allowing live tuning.
- **SQLite for simplicity**: A serverless database avoids operational overhead while supporting structured alert queries for the dashboard.
