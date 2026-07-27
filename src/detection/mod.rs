mod port_scan;
mod syn_flood;

use port_scan::SingleSourceScanState;
use syn_flood::SynFloodState;

use std::net::{IpAddr, SocketAddr};

use crate::capture::ParsedPacket;

#[derive(Default)]
pub struct DetectorState {
    single_source_scan: SingleSourceScanState,
    syn_flood: SynFloodState,
}

impl DetectorState {
    pub fn log_packet(&mut self, packet: &ParsedPacket) -> Vec<Activity> {
        self.single_source_scan
            .log_packet(packet)
            .into_iter()
            .chain(self.syn_flood.log_packet(packet))
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
    /// Detected a SYN flood, meaning a large number of bare SYN packets landed on a single
    /// destination socket in a short amount of time.
    SynFlood {
        /// The destination being flooded.
        dst: SocketAddr,
    },
}

/// Extracts the (source, destination) IP pair from a packet, regardless of IP version.
fn src_dst_ip(packet: &ParsedPacket) -> Option<(IpAddr, IpAddr)> {
    packet
        .ipv4
        .as_ref()
        .map(|x| (IpAddr::V4(x.src_ip), IpAddr::V4(x.dst_ip)))
        .or_else(|| {
            packet
                .ipv6
                .as_ref()
                .map(|x| (IpAddr::V6(x.src_ip), IpAddr::V6(x.dst_ip)))
        })
}
