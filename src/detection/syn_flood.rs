use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use crate::{
    capture::{ParsedPacket, TransportHeader},
    detection::{Activity, evidence_sample, src_dst_ip},
};

/// One observed bare SYN, kept only long enough to age out of `SynFloodState::syn_flood_interval`.
struct SynRecord {
    at: SystemTime,
    src: IpAddr,
}

pub struct SynFloodState {
    /// Time interval within which a large number of SYNs is considered an attack.
    syn_flood_interval: Duration,
    /// Amount of SYNs considered a large number for the time interval.
    syn_flood_packet_count_threshold: usize,
    /// Maps destinations to SYN occurrences, tagged with a timestamp. Detecting a SYN flood is just
    /// watching for more than `syn_flood_packet_count_threshold` packets within a time period of
    /// `syn_flood_interval`.
    history: HashMap<SocketAddr, Vec<SynRecord>>,
}

impl SynFloodState {
    pub fn new(syn_flood_interval: Duration, syn_flood_packet_count_threshold: usize) -> Self {
        Self {
            syn_flood_interval,
            syn_flood_packet_count_threshold,
            history: HashMap::new(),
        }
    }

    pub fn log_packet(&mut self, packet: &ParsedPacket) -> Option<Activity> {
        // Remove outdated packets from history.
        let now = packet.timestamp;
        self.history.retain(|_, records| {
            records.retain(|record| record.at + self.syn_flood_interval >= now);
            !records.is_empty()
        });

        let tcp = match packet.transport.as_ref()? {
            TransportHeader::Tcp(x) => x,
            _ => return None,
        };
        // Only bare SYNs count, SYN-ACK replies aren't attack traffic.
        if !tcp.flags.syn || tcp.flags.ack {
            return None;
        }

        let (src_ip, dst_ip) = src_dst_ip(packet)?;
        let dst = SocketAddr::new(dst_ip, tcp.dst_port);
        let entry = self.history.entry(dst).or_default();
        entry.push(SynRecord {
            at: packet.timestamp,
            src: src_ip,
        });

        // Run detection rule. Clear history on detection so we don't flood with flood detections.
        if entry.len() < self.syn_flood_packet_count_threshold {
            return None;
        }
        let syn_count = entry.len();
        let sources = evidence_sample(entry.iter().map(|record| record.src));
        self.history.remove(&dst);
        Some(Activity::SynFlood {
            dst,
            syn_count,
            sources,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{ParsedPacket, TcpFlags, TransportHeader, UdpHeader};
    use crate::detection::test_support::{tcp_packet, test_time};
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    // These tests exercise the detection rule itself, so the exact threshold values don't matter
    // as long as they're used consistently below.
    const TEST_SYN_FLOOD_INTERVAL: Duration = Duration::from_secs(1);
    const TEST_SYN_FLOOD_PACKET_COUNT_THRESHOLD: usize = 256;

    fn test_state() -> SynFloodState {
        SynFloodState::new(
            TEST_SYN_FLOOD_INTERVAL,
            TEST_SYN_FLOOD_PACKET_COUNT_THRESHOLD,
        )
    }

    fn make_syn_packet(timestamp: SystemTime) -> ParsedPacket {
        tcp_packet(
            timestamp,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            80,
            TcpFlags {
                syn: true,
                ack: false,
                ..Default::default()
            },
        )
    }

    #[test]
    fn test_syn_flood_below_threshold() {
        let mut detector = test_state();
        let now = test_time();

        for i in 0..(TEST_SYN_FLOOD_PACKET_COUNT_THRESHOLD - 1) {
            let pkt = make_syn_packet(now + Duration::from_millis(i as u64));
            assert!(detector.log_packet(&pkt).is_none());
        }
    }

    #[test]
    fn test_syn_flood_detected_at_threshold() {
        let mut detector = test_state();
        let now = test_time();

        for i in 0..TEST_SYN_FLOOD_PACKET_COUNT_THRESHOLD {
            let pkt = make_syn_packet(now + Duration::from_millis(i as u64));

            let result = detector.log_packet(&pkt);

            if i == TEST_SYN_FLOOD_PACKET_COUNT_THRESHOLD - 1 {
                assert!(matches!(result, Some(Activity::SynFlood { .. })));
            } else {
                assert!(result.is_none());
            }
        }
    }

    #[test]
    fn test_syn_ack_not_detected() {
        let mut detector = test_state();

        let mut pkt = make_syn_packet(test_time());

        if let Some(TransportHeader::Tcp(ref mut tcp)) = pkt.transport {
            tcp.flags.ack = true;
        }

        assert!(detector.log_packet(&pkt).is_none());
    }

    #[test]
    fn test_history_cleared_after_detection() {
        let mut detector = test_state();
        let now = test_time();

        let mut detected = None;

        for i in 0..TEST_SYN_FLOOD_PACKET_COUNT_THRESHOLD {
            let pkt = make_syn_packet(now + Duration::from_millis(i as u64));
            detected = detector.log_packet(&pkt);
        }

        assert!(matches!(detected, Some(Activity::SynFlood { .. })));
        assert!(detector.history.is_empty());
    }

    #[test]
    fn test_old_packets_expire() {
        let mut detector = test_state();

        let base = test_time();

        let packet_count = (TEST_SYN_FLOOD_PACKET_COUNT_THRESHOLD * 3) / 4;

        // First batch of packets.
        for _ in 0..packet_count {
            let pkt = make_syn_packet(base);
            assert!(detector.log_packet(&pkt).is_none());
        }

        // Advance beyond the expiration interval.
        let later = base + TEST_SYN_FLOOD_INTERVAL + Duration::from_millis(1);

        // Second batch should not combine with the expired first batch.
        for _ in 0..packet_count {
            let pkt = make_syn_packet(later);
            assert!(detector.log_packet(&pkt).is_none());
        }

        // One more packet still should not trigger detection.
        let pkt = make_syn_packet(later);
        assert!(detector.log_packet(&pkt).is_none());
    }

    #[test]
    fn test_udp_not_detected() {
        let mut detector = test_state();

        let mut pkt = make_syn_packet(test_time());

        pkt.transport = Some(TransportHeader::Udp(UdpHeader {
            src_port: 50000,
            dst_port: 80,
            length: 8,
            checksum: 0,
        }));

        assert!(detector.log_packet(&pkt).is_none());
    }
}
