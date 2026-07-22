use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use crate::capture::{ParsedPacket, TransportHeader};

/// Port scan detection measures distinct packet destinations within a time frame. This constant
/// specifies the interval within which a scan will be considered to have occurred.
pub const MAX_SCAN_INTERVAL: Duration = Duration::from_secs(10);
/// How many distinct destinations need to be logged from the same source in order to consider the
/// activity a port scan.
pub const SCAN_PACKET_COUNT_THRESHOLD: usize = 64;

#[derive(Default)]
pub struct DetectorState {
    single_source_scan: SingleSourceScanState,
}

impl DetectorState {
    pub fn log_packet(&mut self, packet: ParsedPacket) -> Vec<Activity> {
        self.single_source_scan
            .log_packet(packet)
            .into_iter()
            .collect()
    }
}

#[derive(Debug)]
pub enum Activity {
    /// Detected a port scan from a single source, meaning there were a large number of connection
    /// attempts from one source socket address to many destination socket addresses in a short
    /// amount of time.
    SingleSourceScan {
        /// The source from which the scan originated.
        src: IpAddr,
    },
}

#[derive(Default)]
struct SingleSourceScanState {
    /// Maps source IPs to the destination socket addresses they've sent packets to, as well as the
    /// timestamp for the latest packet. We can remove entries from the inner hashmap when the
    /// latest packet has aged out according to [`MAX_SCAN_INTERVAL`].
    history: HashMap<IpAddr, HashMap<SocketAddr, SystemTime>>,
}

impl SingleSourceScanState {
    fn log_packet(&mut self, packet: ParsedPacket) -> Option<Activity> {
        // Remove outdated packets from history
        let now = SystemTime::now();
        self.history.retain(|_, inner| {
            inner.retain(|_, ts| *ts + MAX_SCAN_INTERVAL >= now);
            !inner.is_empty()
        });

        // Append history for source address
        let (src_ip, dst_ip) = packet
            .ipv4
            .map(|x| (IpAddr::V4(x.src_ip), IpAddr::V4(x.dst_ip)))
            .or_else(|| {
                packet
                    .ipv6
                    .map(|x| (IpAddr::V6(x.src_ip), (IpAddr::V6(x.dst_ip))))
            })?;
        let dst_port = match packet.transport? {
            TransportHeader::Tcp(x) => x.dst_port,
            TransportHeader::Udp(x) => x.dst_port,
            _ => return None,
        };
        let dst = SocketAddr::new(dst_ip, dst_port);
        let source_entry = self.history.entry(src_ip).or_default();
        source_entry.insert(dst, packet.timestamp);

        // Run detection rule, only need to check most recent source (other runs will test other
        // sources). Clear history on detection so we don't flood with scan detections.
        (source_entry.len() >= SCAN_PACKET_COUNT_THRESHOLD).then(|| {
            self.history.remove(&src_ip);
            Activity::SingleSourceScan { src: src_ip }
        })
    }
}
