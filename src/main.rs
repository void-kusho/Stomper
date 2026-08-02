mod alert;
mod api;
mod capture;
mod db;
mod detection;
mod stats;

use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;

use crate::alert::Alert;
use crate::capture::{CaptureConfig, ParsedPacket, Sniffer, TransportHeader, start_capture};
use crate::db::AlertStore;
use crate::detection::DetectorState;
use crate::stats::Stats;

/// Bounded queue between capture and detection. A full queue drops the newest packet and bumps
/// `packets_dropped_queue_full`, keeping memory bounded and the loss visible.
const PACKET_QUEUE_CAPACITY: usize = 256;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let devices = Sniffer::list_interfaces()?;
    let Some(device) = devices
        .iter()
        .find(|d| !d.name.starts_with("lo"))
        .or(devices.first())
    else {
        eprintln!("No network interfaces found");
        return Ok(());
    };

    println!(
        "  Interface: {} ({})",
        device.name,
        device.desc.as_deref().unwrap_or("no description")
    );

    // Storage, counters, and the API come up before capture so the first alert already has
    // somewhere to go.
    let store = AlertStore::open(db::DEFAULT_DATABASE_PATH).await?;
    let stats = Arc::new(Stats::new(&device.name, db::DEFAULT_DATABASE_PATH));

    let api = api::serve(api::DEFAULT_BIND, store.clone(), Arc::clone(&stats)).await?;
    println!("  API: http://{}/api/status", api.addr);

    let config = CaptureConfig {
        interface: device.name.clone(),
        ..Default::default()
    };
    let (packet_tx, packet_rx) = mpsc::channel::<ParsedPacket>(PACKET_QUEUE_CAPACITY);

    let capture = match start_capture(config, packet_tx, Arc::clone(&stats)).await {
        Ok(handle) => handle,
        Err(e) => {
            let msg = format!("{e}");
            eprintln!("  Error: {msg}");
            if msg.contains("CAP_NET_RAW") {
                eprintln!(
                    "  Hint: run with 'sudo' or set 'sudo setcap cap_net_raw+ep target/debug/stomper'"
                );
            }
            return Ok(());
        }
    };

    let detection_task = tokio::spawn(run_detection(packet_rx, store, Arc::clone(&stats)));

    println!("  Press Ctrl-C to stop");
    println!();
    print_header();

    tokio::signal::ctrl_c().await?;
    println!();
    println!("  Stopping...");

    // Shut down capture first, then drain remaining packets through detection.
    capture.shutdown().await;
    let _ = detection_task.await;
    api.stop();

    print_summary(&stats);

    Ok(())
}

/// Single detection task: keeps packet order for the stateful detectors and turns every detection
/// into an alert. Ends when capture closes the queue.
///
/// The alert pipeline is: packet -> `DetectorState` -> `Activity` -> `Alert` -> SQLite + console.
/// Because detection is stateful (scan/flood windows), this task must process packets in order,
/// so it is the only consumer of the queue. Capture is a separate task feeding this one, which
/// decouples packet loss (a full queue drops the newest packet) from detection latency.
async fn run_detection(
    mut rx: mpsc::Receiver<ParsedPacket>,
    store: AlertStore,
    stats: Arc<Stats>,
) {
    let mut detector = DetectorState::default();
    let mut count = 0u64;

    while let Some(packet) = rx.recv().await {
        count += 1;
        print_packet(count, &packet);

        // A single packet can trigger more than one detector (e.g. a SYN is also a port-scan
        // probe), so each packet may produce zero, one, or several activities.
        for activity in detector.log_packet(&packet) {
            let alert = Alert::from_activity(&activity, packet.timestamp);
            // The insert is awaited inline: with only one writer it keeps ordering simple, at
            // the cost of stalling packet processing while the alert is persisted. Alerts are
            // also written exactly as emitted - there is no dedup/coalescing, so a long scan
            // can generate a large number of near-identical rows.
            if let Err(e) = store.insert(&alert).await {
                eprintln!("Failed to store alert: {e}");
            }
            stats.record_alert();
            // Console output is the operator's real-time view; the API serves the same data
            // from the database for dashboards.
            println!("{alert}");
        }
    }
}

fn print_summary(stats: &Stats) {
    let snapshot = stats.snapshot();
    println!();
    println!(
        "  Captured {} packets in {:.1}s ({:.0} pkts/s), {} alerts, {} dropped",
        snapshot.packets_captured,
        snapshot.uptime_seconds,
        snapshot.packets_per_second,
        snapshot.alerts_generated,
        snapshot.packets_dropped_queue_full,
    );
}

fn print_header() {
    println!(
        " {:>6}  {:>12}  {:>5}  {:>5}  Info",
        "Pkt#", "Time", "Proto", "Size"
    );
    println!(" {}", "-".repeat(75));
}

fn print_packet(count: u64, pkt: &ParsedPacket) {
    let ts = format_timestamp(pkt.timestamp);
    let (proto, info) = format_info(pkt);
    println!(
        " {:>6}  {:>12}  {:>5}  {:>5}B  {}",
        count, ts, proto, pkt.raw_len, info
    );
}

fn format_timestamp(ts: SystemTime) -> String {
    DateTime::<Utc>::from(ts).format("%H:%M:%S%.3f").to_string()
}

fn format_info(pkt: &ParsedPacket) -> (&'static str, String) {
    let src = pkt
        .ipv4
        .as_ref()
        .map(|ip| ip.src_ip.to_string())
        .or_else(|| pkt.ipv6.as_ref().map(|ip| ip.src_ip.to_string()))
        .unwrap_or_else(|| {
            pkt.ethernet
                .as_ref()
                .map(|e| mac_str(&e.src_mac))
                .unwrap_or_else(|| "?.?.?.?".into())
        });

    let dst = pkt
        .ipv4
        .as_ref()
        .map(|ip| ip.dst_ip.to_string())
        .or_else(|| pkt.ipv6.as_ref().map(|ip| ip.dst_ip.to_string()))
        .unwrap_or_else(|| {
            pkt.ethernet
                .as_ref()
                .map(|e| mac_str(&e.dst_mac))
                .unwrap_or_else(|| "?.?.?.?".into())
        });

    match &pkt.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            let mut f = String::with_capacity(6);
            if tcp.flags.syn {
                f.push('S');
            }
            if tcp.flags.ack {
                f.push('A');
            }
            if tcp.flags.fin {
                f.push('F');
            }
            if tcp.flags.rst {
                f.push('R');
            }
            if tcp.flags.psh {
                f.push('P');
            }
            if tcp.flags.urg {
                f.push('U');
            }
            if f.is_empty() {
                f.push('.');
            }
            (
                "TCP",
                format!(
                    "{}:{} → {}:{} [{}]",
                    src, tcp.src_port, dst, tcp.dst_port, f
                ),
            )
        }
        Some(TransportHeader::Udp(udp)) => (
            "UDP",
            format!("{}:{} → {}:{}", src, udp.src_port, dst, udp.dst_port),
        ),
        Some(TransportHeader::Icmp(icmp)) => {
            let desc = icmp_desc(icmp.icmp_type, icmp.code);
            ("ICMP", format!("{} → {}  {}", src, dst, desc))
        }
        Some(TransportHeader::Unknown(p)) => ("IP", format!("proto={p}  {} → {}", src, dst)),
        None => (
            "ETH",
            format!(
                "{} → {}  ethertype=0x{:04x}",
                src,
                dst,
                pkt.ethernet.as_ref().map(|e| e.ethertype).unwrap_or(0)
            ),
        ),
    }
}

fn mac_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn icmp_desc(typ: u8, code: u8) -> String {
    let name = match typ {
        0 => "Echo Reply",
        3 => match code {
            0 => "Net Unreachable",
            1 => "Host Unreachable",
            2 => "Proto Unreachable",
            3 => "Port Unreachable",
            _ => "Dest Unreachable",
        },
        5 => "Redirect",
        8 => "Echo Request",
        11 => match code {
            0 => "TTL Exceeded",
            _ => "Time Exceeded",
        },
        _ => return format!("type={typ} code={code}"),
    };
    name.to_string()
}
