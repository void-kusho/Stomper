pub(crate) mod port_scan;
pub(crate) mod syn_flood;

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

/// Upper bound on how many sample values (ports, source addresses) an [`Activity`] carries as
/// evidence. Alerts only need enough detail for an operator to recognise the attack, not the full
/// detector state.
pub const MAX_EVIDENCE_ITEMS: usize = 8;

#[derive(Debug)]
pub enum Activity {
    /// Detected a port scan from a single source, meaning there were a large number of connection
    /// attempts from one source socket address to many destination socket addresses in a short
    /// amount of time.
    SingleSourceScan {
        /// The source from which the scan originated.
        src: IpAddr,
        /// How many distinct destination sockets the source contacted within the window.
        destinations: usize,
        /// Sample of the destination ports that were contacted, ascending.
        ports: Vec<u16>,
    },
    /// Detected a SYN flood, meaning a large number of bare SYN packets landed on a single
    /// destination socket in a short amount of time.
    SynFlood {
        /// The destination being flooded.
        dst: SocketAddr,
        /// How many bare SYNs landed on the destination within the window.
        syn_count: usize,
        /// Sample of the source addresses the SYNs came from, ascending. Flood sources are often
        /// spoofed, so this is evidence rather than attribution.
        sources: Vec<IpAddr>,
    },
}

/// Collects up to [`MAX_EVIDENCE_ITEMS`] sorted, distinct values for use as alert evidence.
fn evidence_sample<T: Ord>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut sample: Vec<T> = values.into_iter().collect();
    sample.sort_unstable();
    sample.dedup();
    sample.truncate(MAX_EVIDENCE_ITEMS);
    sample
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

/// Packet fixtures shared by the detector tests, so each detector describes only the traffic
/// pattern it cares about.
#[cfg(test)]
pub(super) mod test_support {
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use crate::capture::{Ipv4Header, ParsedPacket, TcpFlags, TcpHeader, TransportHeader};

    /// Fixed base time, so tests never depend on the clock.
    pub fn test_time() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1000)
    }

    /// A minimal IPv4/TCP packet: enough header for the detectors, nothing else.
    pub fn tcp_packet(
        timestamp: SystemTime,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        flags: TcpFlags,
    ) -> ParsedPacket {
        ParsedPacket {
            timestamp,
            ethernet: None,
            ipv4: Some(Ipv4Header {
                src_ip,
                dst_ip,
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
                dst_port,
                sequence_number: 0,
                acknowledgment_number: 0,
                data_offset: 20,
                flags,
                window_size: 1024,
                checksum: 0,
                urgent_pointer: 0,
            })),
            raw_len: 54,
        }
    }
}
