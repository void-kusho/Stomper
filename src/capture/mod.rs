pub mod parser;
pub mod sniffer;

#[expect(unused_imports)]
pub use parser::{
    EthernetHeader, IcmpHeader, Ipv4Header, Ipv6Header, ParsedPacket, TcpFlags, TcpHeader,
    TransportHeader, UdpHeader,
};
pub use sniffer::{CaptureConfig, Sniffer};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unsupported link type: {0:?}")]
    UnsupportedLinkType(pcap::Linktype),
    #[error("packet too short: needed {needed} bytes, got {got}")]
    PacketTooShort { needed: usize, got: usize },
}

pub async fn start_capture(
    config: CaptureConfig,
    tx: mpsc::Sender<ParsedPacket>,
) -> Result<JoinHandle<()>, CaptureError> {
    let sniffer = Sniffer::new(&config)?;
    Ok(sniffer.start(tx))
}
