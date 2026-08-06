pub mod parser;
pub mod sniffer;

#[expect(unused_imports)]
pub use parser::{
    EthernetHeader, IcmpHeader, Ipv4Header, Ipv6Header, ParsedPacket, TcpFlags, TcpHeader,
    TransportHeader, UdpHeader,
};
pub use sniffer::{CaptureConfig, Sniffer};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::stats::Stats;

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

/// Owns the running capture worker. Dropping it does not stop capture; call
/// [`CaptureHandle::shutdown`] so the packet sender is released and downstream tasks can drain.
pub struct CaptureHandle {
    task: JoinHandle<()>,
    stop_flag: Arc<AtomicBool>,
}

impl CaptureHandle {
    /// Asks the capture loop to finish, then waits for it. The loop notices within one pcap read
    /// timeout.
    pub async fn shutdown(self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Err(e) = self.task.await {
            eprintln!("Capture worker ended abnormally: {e}");
        }
    }
}

pub async fn start_capture(
    config: CaptureConfig,
    tx: mpsc::Sender<ParsedPacket>,
    stats: Arc<Stats>,
) -> Result<CaptureHandle, CaptureError> {
    let sniffer = Sniffer::new(&config)?;
    let stop_flag = Arc::new(AtomicBool::new(false));

    Ok(CaptureHandle {
        task: sniffer.start(tx, stats, Arc::clone(&stop_flag)),
        stop_flag,
    })
}
