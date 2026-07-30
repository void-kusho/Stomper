use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use crate::{
    capture::{ParsedPacket, TransportHeader},
    detection::{Activity, src_dst_ip},
};

/// Time interval within which a large number of SYNs is considered an attack.
pub const SYN_FLOOD_INTERVAL: Duration = Duration::from_secs(1);
/// Amount of SYNs considered a large number for the time interval.
pub const SYN_FLOOD_PACKET_COUNT_THRESHOLD: usize = 256;

#[derive(Default)]
pub struct SynFloodState {
    /// Maps destinations to SYN occurrences, tagged with a timestamp. Detecting a SYN flood is just
    /// watching for more than [`SYN_FLOOD_PACKET_COUNT_THRESHOLD`] packets within a time period of
    /// [`SYN_FLOOD_INTERVAL`].
    history: HashMap<SocketAddr, Vec<SystemTime>>,
}

impl SynFloodState {
    pub fn log_packet(&mut self, packet: &ParsedPacket) -> Option<Activity> {
        // Remove outdated packets from history.
        let now = packet.timestamp;
        self.history.retain(|_, timestamps| {
            timestamps.retain(|ts| *ts + SYN_FLOOD_INTERVAL >= now);
            !timestamps.is_empty()
        });

        let tcp = match packet.transport.as_ref()? {
            TransportHeader::Tcp(x) => x,
            _ => return None,
        };
        // Only bare SYNs count, SYN-ACK replies aren't attack traffic.
        if !tcp.flags.syn || tcp.flags.ack {
            return None;
        }

        let (_, dst_ip) = src_dst_ip(packet)?;
        let dst = SocketAddr::new(dst_ip, tcp.dst_port);
        let entry = self.history.entry(dst).or_default();
        entry.push(packet.timestamp);

        // Run detection rule. Clear history on detection so we don't flood with flood detections.
        (entry.len() >= SYN_FLOOD_PACKET_COUNT_THRESHOLD).then(|| {
            self.history.remove(&dst);
            Activity::SynFlood { dst }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{
        Ipv4Header, ParsedPacket, TcpFlags, TcpHeader, TransportHeader, UdpHeader,
    };
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    /// Common fixed timestamp for all tests.
    const TEST_TIME_OFFSET: Duration = Duration::from_secs(1000);

    fn test_time() -> SystemTime {
        SystemTime::UNIX_EPOCH + TEST_TIME_OFFSET
    }

    fn make_syn_packet(timestamp: SystemTime) -> ParsedPacket {
        ParsedPacket {
            timestamp,
            ethernet: None,
            ipv4: Some(Ipv4Header {
                src_ip: Ipv4Addr::new(192, 168, 1, 100),
                dst_ip: Ipv4Addr::new(192, 168, 1, 1),
                protocol: 6,
                ttl: 64,
                total_length: 40,
                identification: 0,
                version: 4,
                ihl: 5,
                dscp: 0,
                ecn: 0,
                flags: 0,
                fragment_offset: 0,
            }),
            ipv6: None,
            transport: Some(TransportHeader::Tcp(TcpHeader {
                src_port: 50000,
                dst_port: 80,
                sequence_number: 0,
                acknowledgment_number: 0,
                data_offset: 20,
                flags: TcpFlags {
                    syn: true,
                    ack: false,
                    ..Default::default()
                },
                window_size: 1024,
                checksum: 0,
                urgent_pointer: 0,
            })),
            raw_len: 54,
        }
    }

    #[test]
    fn test_syn_flood_below_threshold() {
        let mut detector = SynFloodState::default();
        let now = test_time();

        for i in 0..(SYN_FLOOD_PACKET_COUNT_THRESHOLD - 1) {
            let pkt = make_syn_packet(now + Duration::from_millis(i as u64));
            assert!(detector.log_packet(&pkt).is_none());
        }
    }

    #[test]
    fn test_syn_flood_detected_at_threshold() {
        let mut detector = SynFloodState::default();
        let now = test_time();

        for i in 0..SYN_FLOOD_PACKET_COUNT_THRESHOLD {
            let pkt = make_syn_packet(now + Duration::from_millis(i as u64));

            let result = detector.log_packet(&pkt);

            if i == SYN_FLOOD_PACKET_COUNT_THRESHOLD - 1 {
                assert!(matches!(result, Some(Activity::SynFlood { .. })));
            } else {
                assert!(result.is_none());
            }
        }
    }

    #[test]
    fn test_syn_ack_not_detected() {
        let mut detector = SynFloodState::default();

        let mut pkt = make_syn_packet(test_time());

        if let Some(TransportHeader::Tcp(ref mut tcp)) = pkt.transport {
            tcp.flags.ack = true;
        }

        assert!(detector.log_packet(&pkt).is_none());
    }

    #[test]
    fn test_history_cleared_after_detection() {
        let mut detector = SynFloodState::default();
        let now = test_time();

        let mut detected = None;

        for i in 0..SYN_FLOOD_PACKET_COUNT_THRESHOLD {
            let pkt = make_syn_packet(now + Duration::from_millis(i as u64));
            detected = detector.log_packet(&pkt);
        }

        assert!(matches!(detected, Some(Activity::SynFlood { .. })));
        assert!(detector.history.is_empty());
    }

    #[test]
    fn test_old_packets_expire() {
        let mut detector = SynFloodState::default();

        let base = test_time();

        let packet_count = (SYN_FLOOD_PACKET_COUNT_THRESHOLD * 3) / 4;

        // First batch of packets.
        for _ in 0..packet_count {
            let pkt = make_syn_packet(base);
            assert!(detector.log_packet(&pkt).is_none());
        }

        // Advance beyond the expiration interval.
        let later = base + SYN_FLOOD_INTERVAL + Duration::from_millis(1);

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
        let mut detector = SynFloodState::default();

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
