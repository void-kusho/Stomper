mod capture;
mod detection;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use capture::{start_capture, CaptureConfig, ParsedPacket, Sniffer, TransportHeader};

use crate::detection::DetectorState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let devices = Sniffer::list_interfaces()?;
    if devices.is_empty() {
        eprintln!("No network interfaces found");
        return Ok(());
    }

    let device = devices
        .iter()
        .find(|d| !d.name.starts_with("lo"))
        .unwrap_or(&devices[0]);

    println!("  Interface: {} ({})", device.name,
             device.desc.as_deref().unwrap_or("no description"));

    let config = CaptureConfig {
        interface: device.name.clone(),
        ..Default::default()
    };

    let (tx, mut rx) = mpsc::channel::<ParsedPacket>(256);

    let handle = match start_capture(config, tx).await {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("{e}");
            eprintln!("  Error: {msg}");
            if msg.contains("CAP_NET_RAW") {
                eprintln!("  Hint: run with 'sudo' or set 'sudo setcap cap_net_raw+ep target/debug/stomper'");
            }
            return Ok(());
        }
    };

    println!("  Duration: 30 seconds");
    println!();
    print_header();

    let timeout = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(timeout);

    let mut count = 0u64;
    let start = SystemTime::now();

    let mut detector = DetectorState::default();

    loop {
        tokio::select! {
            packet = rx.recv() => {
                match packet {
                    Some(pkt) => {
                        count += 1;
                        print_packet(count, &pkt);
                        for activity in detector.log_packet(pkt) {
                            println!("Activity detected: {activity:?}");
                        }
                    }
                    None => {
                        eprintln!("Capture channel closed unexpectedly");
                        break;
                    }
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    handle.abort();

    let elapsed = start.elapsed().unwrap_or(Duration::from_secs(30));
    let rate = count as f64 / elapsed.as_secs_f64();
    println!();
    println!("  Captured {count} packets in {:.1}s ({:.0} pkts/s)", elapsed.as_secs_f64(), rate);

    Ok(())
}

fn print_header() {
    println!(
        " {:>6}  {:>12}  {:>5}  {:>5}  {}",
        "Pkt#", "Time", "Proto", "Size", "Info"
    );
    println!(" {}", "-".repeat(75));
}

fn print_packet(count: u64, pkt: &ParsedPacket) {
    let ts = format_timestamp(pkt.timestamp);
    let (proto, info) = format_info(pkt);
    println!(" {:>6}  {:>12}  {:>5}  {:>5}B  {}", count, ts, proto, pkt.raw_len, info);
}

fn format_timestamp(ts: SystemTime) -> String {
    let since_epoch = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs_of_day = since_epoch.as_secs() % 86400;
    let h = secs_of_day / 3600;
    let m = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    let ms = since_epoch.subsec_millis();
    format!("{h:02}:{m:02}:{s:02}.{ms:03}")
}

fn format_info(pkt: &ParsedPacket) -> (&'static str, String) {
    let src = pkt.ipv4.as_ref().map(|ip| ip.src_ip.to_string())
        .or_else(|| pkt.ipv6.as_ref().map(|ip| ip.src_ip.to_string()))
        .unwrap_or_else(|| {
            pkt.ethernet.as_ref().map(|e| mac_str(&e.src_mac))
                .unwrap_or_else(|| "?.?.?.?".into())
        });

    let dst = pkt.ipv4.as_ref().map(|ip| ip.dst_ip.to_string())
        .or_else(|| pkt.ipv6.as_ref().map(|ip| ip.dst_ip.to_string()))
        .unwrap_or_else(|| {
            pkt.ethernet.as_ref().map(|e| mac_str(&e.dst_mac))
                .unwrap_or_else(|| "?.?.?.?".into())
        });

    match &pkt.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            let mut f = String::with_capacity(6);
            if tcp.flags.syn { f.push('S'); }
            if tcp.flags.ack { f.push('A'); }
            if tcp.flags.fin { f.push('F'); }
            if tcp.flags.rst { f.push('R'); }
            if tcp.flags.psh { f.push('P'); }
            if tcp.flags.urg { f.push('U'); }
            if f.is_empty() { f.push('.'); }
            ("TCP", format!("{}:{} → {}:{} [{}]", src, tcp.src_port, dst, tcp.dst_port, f))
        }
        Some(TransportHeader::Udp(udp)) => {
            ("UDP", format!("{}:{} → {}:{}", src, udp.src_port, dst, udp.dst_port))
        }
        Some(TransportHeader::Icmp(icmp)) => {
            let desc = icmp_desc(icmp.icmp_type, icmp.code);
            ("ICMP", format!("{} → {}  {}", src, dst, desc))
        }
        Some(TransportHeader::Unknown(p)) => {
            ("IP", format!("proto={p}  {} → {}", src, dst))
        }
        None => {
            ("ETH", format!("{} → {}  ethertype=0x{:04x}",
                src, dst,
                pkt.ethernet.as_ref().map(|e| e.ethertype).unwrap_or(0)))
        }
    }
}

fn mac_str(mac: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
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
    format!("{name}")
}
