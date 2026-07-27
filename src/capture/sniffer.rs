use pcap::Device;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::parser;
use super::CaptureError;
use super::ParsedPacket;

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

    pub fn start(self, tx: mpsc::Sender<ParsedPacket>) -> JoinHandle<()> {
        let mut cap = self.capture;
        let link_type = self.link_type;

        tokio::task::spawn_blocking(move || {
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        let ts = packet.header.ts;
                        let parsed = parser::parse_packet(
                            packet.data,
                            link_type,
                            ts.tv_sec.into(),
                            ts.tv_usec.into(),
                        );

                        match parsed {
                            Ok(pkt) => {
                                if tx.blocking_send(pkt).is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
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
