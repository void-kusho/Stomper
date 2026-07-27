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
        let now = SystemTime::now();
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
