use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pcap::Device;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::CaptureError;
use super::ParsedPacket;
use super::parser;
use crate::stats::Stats;

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: String,
    pub promiscuous: bool,
    pub snaplen: i32,
    pub timeout: i32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            promiscuous: true,
            snaplen: 65535,
            timeout: 1000,
        }
    }
}

pub struct Sniffer {
    capture: pcap::Capture<pcap::Active>,
    link_type: pcap::Linktype,
}

impl Sniffer {
    pub fn new(config: &CaptureConfig) -> Result<Self, CaptureError> {
        let cap = pcap::Capture::from_device(config.interface.as_str())?
            .promisc(config.promiscuous)
            .snaplen(config.snaplen)
            .timeout(config.timeout)
            .open()?;

        let link_type = cap.get_datalink();

        Ok(Self {
            capture: cap,
            link_type,
        })
    }

    pub fn list_interfaces() -> Result<Vec<Device>, CaptureError> {
        Ok(Device::list()?)
    }

    /// Runs the capture loop on a blocking worker until `shutdown` is set or the receiver goes
    /// away. The pcap read timeout bounds how long a stop request waits.
    pub fn start(
        self,
        tx: mpsc::Sender<ParsedPacket>,
        stats: Arc<Stats>,
        shutdown: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let mut cap = self.capture;
        let link_type = self.link_type;

        tokio::task::spawn_blocking(move || {
            while !shutdown.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(packet) => {
                        let ts = packet.header.ts;
                        // The `.into()` calls are redundant on Linux but required on Windows,
                        // where libpcap's timeval fields are i32 (see ISSUE-001 in docs/testing.md).
                        let parsed = parser::parse_packet(
                            packet.data,
                            link_type,
                            ts.tv_sec.into(),
                            ts.tv_usec.into(),
                        );

                        match parsed {
                            Ok(pkt) => {
                                stats.record_packet(pkt.raw_len);
                                // Overload drops the newest packet rather than stalling capture,
                                // which keeps memory bounded and the loss visible in /api/status.
                                match tx.try_send(pkt) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        stats.record_queue_drop()
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                                }
                            }
                            Err(e) => {
                                stats.record_parse_error();
                                eprintln!("Packet parse error: {e}");
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(e) => {
                        eprintln!("Capture error: {e}");
                        break;
                    }
                }
            }
        })
    }
}
