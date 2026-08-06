use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use crate::{
    capture::{ParsedPacket, TransportHeader},
    detection::{Activity, evidence_sample, src_dst_ip},
};

/// Port scan detection measures distinct packet destinations within a time frame. This constant
/// specifies the interval within which a scan will be considered to have occurred.
pub const MAX_SCAN_INTERVAL: Duration = Duration::from_secs(10);
/// How many distinct destinations need to be logged from the same source in order to consider the
/// activity a port scan.
pub const SCAN_PACKET_COUNT_THRESHOLD: usize = 64;

#[derive(Default)]
pub struct SingleSourceScanState {
    /// Maps source IPs to the destination socket addresses they've sent packets to, as well as the
    /// timestamp for the latest packet. We can remove entries from the inner hashmap when the
    /// latest packet has aged out according to [`MAX_SCAN_INTERVAL`].
    history: HashMap<IpAddr, HashMap<SocketAddr, SystemTime>>,
}

impl SingleSourceScanState {
    pub fn log_packet(&mut self, packet: &ParsedPacket) -> Option<Activity> {
        // Remove outdated packets from history
        let now = packet.timestamp;
        self.history.retain(|_, inner| {
            inner.retain(|_, ts| *ts + MAX_SCAN_INTERVAL >= now);
            !inner.is_empty()
        });

        // Append history for source address
        let (src_ip, dst_ip) = src_dst_ip(packet)?;
        let dst_port = match packet.transport.as_ref()? {
            TransportHeader::Tcp(x) => x.dst_port,
            TransportHeader::Udp(x) => x.dst_port,
            _ => return None,
        };
        let dst = SocketAddr::new(dst_ip, dst_port);
        let source_entry = self.history.entry(src_ip).or_default();
        source_entry.insert(dst, packet.timestamp);

        // Run detection rule, only need to check most recent source (other runs will test other
        // sources). Clear history on detection so we don't flood with scan detections.
        if source_entry.len() < SCAN_PACKET_COUNT_THRESHOLD {
            return None;
        }
        let destinations = source_entry.len();
        let ports = evidence_sample(source_entry.keys().map(SocketAddr::port));
        self.history.remove(&src_ip);
        Some(Activity::SingleSourceScan {
            src: src_ip,
            destinations,
            ports,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::TcpFlags;
    use crate::detection::{MAX_EVIDENCE_ITEMS, test_support::tcp_packet, test_support::test_time};
    use std::net::Ipv4Addr;

    const SCANNER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    const TARGET: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    /// One connection attempt from `src` to `TARGET:port`, at `timestamp`.
    fn probe(timestamp: SystemTime, src: Ipv4Addr, port: u16) -> ParsedPacket {
        tcp_packet(
            timestamp,
            src,
            TARGET,
            port,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
        )
    }

    #[test]
    fn scan_below_threshold_is_not_detected() {
        let mut detector = SingleSourceScanState::default();
        let now = test_time();

        for port in 0..(SCAN_PACKET_COUNT_THRESHOLD - 1) {
            let packet = probe(now, SCANNER, port as u16);
            assert!(detector.log_packet(&packet).is_none());
        }
    }

    #[test]
    fn scan_is_detected_at_the_threshold_with_capped_port_evidence() {
        let mut detector = SingleSourceScanState::default();
        let now = test_time();
        let mut detected = None;

        for port in 0..SCAN_PACKET_COUNT_THRESHOLD {
            detected = detector.log_packet(&probe(now, SCANNER, port as u16));
        }

        let Some(Activity::SingleSourceScan {
            src,
            destinations,
            ports,
        }) = detected
        else {
            panic!("expected a port scan detection");
        };
        assert_eq!(src, IpAddr::V4(SCANNER));
        assert_eq!(destinations, SCAN_PACKET_COUNT_THRESHOLD);
        assert_eq!(ports.len(), MAX_EVIDENCE_ITEMS);
        assert!(ports.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(detector.history.is_empty());
    }

    /// Repeating one destination is a retry, not reconnaissance.
    #[test]
    fn repeated_probes_to_one_destination_are_not_a_scan() {
        let mut detector = SingleSourceScanState::default();
        let now = test_time();

        for i in 0..(SCAN_PACKET_COUNT_THRESHOLD * 2) {
            let packet = probe(now + Duration::from_millis(i as u64), SCANNER, 443);
            assert!(detector.log_packet(&packet).is_none());
        }
    }

    #[test]
    fn destinations_from_different_sources_do_not_combine() {
        let mut detector = SingleSourceScanState::default();
        let now = test_time();

        for port in 0..SCAN_PACKET_COUNT_THRESHOLD {
            let src = Ipv4Addr::new(192, 168, 1, 50 + (port % 2) as u8);
            assert!(detector.log_packet(&probe(now, src, port as u16)).is_none());
        }
    }

    #[test]
    fn old_destinations_expire() {
        let mut detector = SingleSourceScanState::default();
        let base = test_time();
        let half = SCAN_PACKET_COUNT_THRESHOLD / 2;

        for port in 0..half {
            assert!(
                detector
                    .log_packet(&probe(base, SCANNER, port as u16))
                    .is_none()
            );
        }

        // Past the window, so the first batch can no longer contribute to a detection.
        let later = base + MAX_SCAN_INTERVAL + Duration::from_millis(1);
        for port in half..SCAN_PACKET_COUNT_THRESHOLD {
            assert!(
                detector
                    .log_packet(&probe(later, SCANNER, port as u16))
                    .is_none()
            );
        }
    }
}
