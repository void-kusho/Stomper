#![expect(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use pcap::Linktype;

use pnet_packet::ethernet::{EthernetPacket, EtherTypes};
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;

use super::CaptureError;

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub timestamp: SystemTime,
    pub ethernet: Option<EthernetHeader>,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub transport: Option<TransportHeader>,
    pub raw_len: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub total_length: u16,
    pub identification: u16,
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub flags: u8,
    pub fragment_offset: u16,
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload_length: u16,
    pub flow_label: u32,
    pub traffic_class: u8,
}

#[derive(Debug, Clone)]
pub enum TransportHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    Unknown(u8),
}

#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
}

const ETHERNET_HEADER_LEN: usize = 14;

const IPV6_EXT_HOP_BY_HOP: u8 = 0;
const IPV6_EXT_ROUTING: u8 = 43;
const IPV6_EXT_FRAGMENT: u8 = 44;
const IPV6_EXT_AUTH: u8 = 51;
const IPV6_ESP: u8 = 50;
const IPV6_EXT_DEST_OPTS: u8 = 60;

fn tv_to_systemtime(tv_sec: i64, tv_usec: i64) -> SystemTime {
    UNIX_EPOCH + Duration::new(tv_sec as u64, (tv_usec as u32) * 1000)
}

pub fn parse_packet(
    data: &[u8],
    link_type: Linktype,
    tv_sec: i64,
    tv_usec: i64,
) -> Result<ParsedPacket, CaptureError> {
    let timestamp = tv_to_systemtime(tv_sec, tv_usec);

    match link_type {
        Linktype::ETHERNET => parse_ethernet(data, timestamp),
        _ => Err(CaptureError::UnsupportedLinkType(link_type)),
    }
}

fn parse_ethernet(data: &[u8], timestamp: SystemTime) -> Result<ParsedPacket, CaptureError> {
    let eth = EthernetPacket::new(data).ok_or(CaptureError::PacketTooShort {
        needed: ETHERNET_HEADER_LEN,
        got: data.len(),
    })?;

    let ethernet = EthernetHeader {
        dst_mac: eth.get_destination().octets(),
        src_mac: eth.get_source().octets(),
        ethertype: eth.get_ethertype().0,
    };

    let captured_len = data.len();

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => parse_ipv4(eth.payload(), timestamp, ethernet, captured_len),
        EtherTypes::Ipv6 => parse_ipv6(eth.payload(), timestamp, ethernet, captured_len),
        _ => Ok(ParsedPacket {
            timestamp,
            ethernet: Some(ethernet),
            ipv4: None,
            ipv6: None,
            transport: None,
            raw_len: captured_len,
        }),
    }
}

fn parse_ipv4(
    data: &[u8],
    timestamp: SystemTime,
    ethernet: EthernetHeader,
    captured_len: usize,
) -> Result<ParsedPacket, CaptureError> {
    let ip = Ipv4Packet::new(data).ok_or(CaptureError::PacketTooShort {
        needed: Ipv4Packet::minimum_packet_size(),
        got: data.len(),
    })?;

    let ihl = ip.get_header_length();
    let header_len = (ihl as usize) * 4;
    if header_len > data.len() {
        return Err(CaptureError::Parse(format!(
            "IPv4 header length {header_len} exceeds packet size {}",
            data.len()
        )));
    }

    let ipv4 = Ipv4Header {
        src_ip: ip.get_source(),
        dst_ip: ip.get_destination(),
        protocol: ip.get_next_level_protocol().0,
        ttl: ip.get_ttl(),
        total_length: ip.get_total_length(),
        identification: ip.get_identification(),
        version: ip.get_version(),
        ihl,
        dscp: ip.get_dscp(),
        ecn: ip.get_ecn(),
        flags: ip.get_flags(),
        fragment_offset: ip.get_fragment_offset(),
    };

    let transport = parse_transport(ip.payload(), ip.get_next_level_protocol().0);

    Ok(ParsedPacket {
        timestamp,
        ethernet: Some(ethernet),
        ipv4: Some(ipv4),
        ipv6: None,
        transport,
        raw_len: captured_len,
    })
}

fn parse_ipv6(
    data: &[u8],
    timestamp: SystemTime,
    ethernet: EthernetHeader,
    captured_len: usize,
) -> Result<ParsedPacket, CaptureError> {
    let ip = Ipv6Packet::new(data).ok_or(CaptureError::PacketTooShort {
        needed: Ipv6Packet::minimum_packet_size(),
        got: data.len(),
    })?;

    let ipv6 = Ipv6Header {
        src_ip: ip.get_source(),
        dst_ip: ip.get_destination(),
        next_header: ip.get_next_header().0,
        hop_limit: ip.get_hop_limit(),
        payload_length: ip.get_payload_length(),
        flow_label: ip.get_flow_label(),
        traffic_class: ip.get_traffic_class(),
    };

    let (final_protocol, transport_payload) =
        skip_ipv6_ext_headers(ip.payload(), ip.get_next_header().0);

    let transport = if final_protocol == u8::MAX {
        None
    } else {
        parse_transport(transport_payload, final_protocol)
    };

    Ok(ParsedPacket {
        timestamp,
        ethernet: Some(ethernet),
        ipv4: None,
        ipv6: Some(ipv6),
        transport,
        raw_len: captured_len,
    })
}

fn skip_ipv6_ext_headers<'a>(mut data: &'a [u8], mut next_header: u8) -> (u8, &'a [u8]) {
    loop {
        match next_header {
            IPV6_EXT_HOP_BY_HOP | IPV6_EXT_ROUTING | IPV6_EXT_DEST_OPTS => {
                if data.len() < 2 {
                    return (next_header, data);
                }
                let ext_len_bytes = data[1] as usize;
                let total_len = (ext_len_bytes + 1) * 8;
                if total_len > data.len() {
                    return (next_header, data);
                }
                next_header = data[0];
                data = &data[total_len..];
            }
            IPV6_EXT_FRAGMENT => {
                if data.len() < 8 {
                    return (next_header, data);
                }
                let frag_off = (u16::from_be_bytes([data[2], data[3]]) >> 3) & 0x1FFF;
                let m_flag = (data[3] & 0x01) != 0;
                next_header = data[0];
                data = &data[8..];
                if frag_off != 0 || m_flag {
                    return (u8::MAX, data);
                }
            }
            IPV6_EXT_AUTH => {
                if data.len() < 4 {
                    return (next_header, data);
                }
                let ah_len = data[1] as usize;
                let total_len = (ah_len + 2) * 4;
                if total_len > data.len() {
                    return (next_header, data);
                }
                next_header = data[0];
                data = &data[total_len..];
            }
            IPV6_ESP => {
                return (u8::MAX, data);
            }
            _ => return (next_header, data),
        }
    }
}

fn parse_transport(data: &[u8], protocol: u8) -> Option<TransportHeader> {
    match protocol {
        6 => parse_tcp(data).map(TransportHeader::Tcp),
        17 => parse_udp(data).map(TransportHeader::Udp),
        1 | 58 => parse_icmp(data).map(TransportHeader::Icmp),
        _ => Some(TransportHeader::Unknown(protocol)),
    }
}

fn parse_tcp(data: &[u8]) -> Option<TcpHeader> {
    let tcp = TcpPacket::new(data)?;

    let raw_flags = tcp.get_flags();
    let ns = (tcp.packet().get(12).copied().unwrap_or(0) & 0x01) != 0;
    let flags = TcpFlags {
        fin: raw_flags & 0x01 != 0,
        syn: raw_flags & 0x02 != 0,
        rst: raw_flags & 0x04 != 0,
        psh: raw_flags & 0x08 != 0,
        ack: raw_flags & 0x10 != 0,
        urg: raw_flags & 0x20 != 0,
        ece: raw_flags & 0x40 != 0,
        cwr: raw_flags & 0x80 != 0,
        ns,
    };

    Some(TcpHeader {
        src_port: tcp.get_source(),
        dst_port: tcp.get_destination(),
        sequence_number: tcp.get_sequence(),
        acknowledgment_number: tcp.get_acknowledgement(),
        data_offset: tcp.get_data_offset() * 4,
        flags,
        window_size: tcp.get_window(),
        checksum: tcp.get_checksum(),
        urgent_pointer: tcp.get_urgent_ptr(),
    })
}

fn parse_udp(data: &[u8]) -> Option<UdpHeader> {
    let udp = UdpPacket::new(data)?;

    Some(UdpHeader {
        src_port: udp.get_source(),
        dst_port: udp.get_destination(),
        length: udp.get_length(),
        checksum: udp.get_checksum(),
    })
}

fn parse_icmp(data: &[u8]) -> Option<IcmpHeader> {
    let icmp = IcmpPacket::new(data)?;

    Some(IcmpHeader {
        icmp_type: icmp.get_icmp_type().0,
        code: icmp.get_icmp_code().0,
        checksum: icmp.get_checksum(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ethernet_too_short() {
        let result = parse_ethernet(&[0u8; 10], UNIX_EPOCH);
        assert!(result.is_err());
        match result {
            Err(CaptureError::PacketTooShort { needed, got }) => {
                assert_eq!(needed, 14);
                assert_eq!(got, 10);
            }
            _ => panic!("expected PacketTooShort error"),
        }
    }

    #[test]
    fn test_parse_ethernet_ipv4() {
        let mut buf = vec![0u8; 14 + 20];
        buf[12] = 0x08;
        buf[13] = 0x00;
        buf[14] = 0x45;
        buf[15] = 0x00;
        buf[16..20].copy_from_slice(&[0x00, 0x28, 0x00, 0x00]);

        let result = parse_ethernet(&buf, UNIX_EPOCH);
        assert!(result.is_ok());
        let pkt = result.unwrap();
        assert!(pkt.ethernet.is_some());
        assert_eq!(pkt.ethernet.unwrap().ethertype, 0x0800);
        assert!(pkt.ipv4.is_some());
        assert_eq!(pkt.raw_len, buf.len());
    }

    #[test]
    fn test_parse_ipv4_header() {
        let data = [
            0x45,            // version=4, ihl=5
            0x00,            // dscp=0, ecn=0
            0x00, 0x34,      // total_length=52
            0x12, 0x34,      // identification=0x1234
            0x40, 0x00,      // flags=DF, fragment_offset=0
            0x40,            // ttl=64
            0x06,            // protocol=TCP
            0x00, 0x00,      // checksum
            0xC0, 0xA8, 0x01, 0x01, // src=192.168.1.1
            0xC0, 0xA8, 0x01, 0x02, // dst=192.168.1.2
        ];
        let eth = EthernetHeader {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            ethertype: 0x0800,
        };
        let result = parse_ipv4(&data, UNIX_EPOCH, eth, 14 + data.len());
        assert!(result.is_ok());
        let pkt = result.unwrap();
        let ip = pkt.ipv4.unwrap();
        assert_eq!(ip.src_ip.to_string(), "192.168.1.1");
        assert_eq!(ip.dst_ip.to_string(), "192.168.1.2");
        assert_eq!(ip.protocol, 6);
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.version, 4);
        assert_eq!(ip.ihl, 5);
        assert_eq!(ip.total_length, 52);
        assert_eq!(ip.identification, 0x1234);
        assert_eq!(ip.flags, 2);
        assert_eq!(ip.fragment_offset, 0);
    }

    #[test]
    fn test_parse_ipv4_invalid_ihl() {
        let data = [
            0x47,            // version=4, ihl=7 (28 bytes), data only 20 bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let eth = EthernetHeader {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            ethertype: 0x0800,
        };
        let result = parse_ipv4(&data, UNIX_EPOCH, eth, 34);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv6_header() {
        let mut data = vec![0u8; 40];
        data[0] = 0x60;
        data[1] = 0x00;
        data[4] = 0x00;
        data[5] = 0x14;
        data[6] = 17;
        data[7] = 64;
        data[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        data[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        let eth = EthernetHeader {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            ethertype: 0x86DD,
        };
        let result = parse_ipv6(&data, UNIX_EPOCH, eth, 14 + data.len());
        assert!(result.is_ok());
        let pkt = result.unwrap();
        let ip = pkt.ipv6.unwrap();
        assert_eq!(ip.src_ip.to_string(), "2001:db8::1");
        assert_eq!(ip.dst_ip.to_string(), "2001:db8::2");
        assert_eq!(ip.next_header, 17);
        assert_eq!(ip.hop_limit, 64);
        assert_eq!(ip.payload_length, 20);
    }

    #[test]
    fn test_parse_tcp() {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x00;
        buf[1] = 0x50;
        buf[2] = 0x1A;
        buf[3] = 0x0B;
        buf[12] = 0x50;
        buf[13] = 0x02;
        buf[14] = 0xFF;
        buf[15] = 0xFF;

        let tcp = parse_tcp(&buf);
        assert!(tcp.is_some());
        let tcp = tcp.unwrap();
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.dst_port, 6667);
        assert!(tcp.flags.syn);
        assert!(!tcp.flags.ack);
        assert_eq!(tcp.window_size, 65535);
    }

    #[test]
    fn test_parse_tcp_all_flags() {
        let mut buf = vec![0u8; 20];
        buf[12] = 0x51; // data_offset=5, NS=1
        buf[13] = 0xFF; // all flags

        let tcp = parse_tcp(&buf).unwrap();
        assert!(tcp.flags.fin);
        assert!(tcp.flags.syn);
        assert!(tcp.flags.rst);
        assert!(tcp.flags.psh);
        assert!(tcp.flags.ack);
        assert!(tcp.flags.urg);
        assert!(tcp.flags.ece);
        assert!(tcp.flags.cwr);
        assert!(tcp.flags.ns);
    }

    #[test]
    fn test_parse_tcp_too_short() {
        assert!(parse_tcp(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_udp() {
        let mut buf = vec![0u8; 8];
        buf[0] = 0x00;
        buf[1] = 0x35;
        buf[2] = 0x00;
        buf[3] = 0x50;

        let udp = parse_udp(&buf);
        assert!(udp.is_some());
        let udp = udp.unwrap();
        assert_eq!(udp.src_port, 53);
        assert_eq!(udp.dst_port, 80);
    }

    #[test]
    fn test_parse_udp_too_short() {
        assert!(parse_udp(&[0u8; 4]).is_none());
    }

    #[test]
    fn test_parse_icmp() {
        let buf = [0x08, 0x00, 0xF7, 0xFF];
        let icmp = parse_icmp(&buf);
        assert!(icmp.is_some());
        let icmp = icmp.unwrap();
        assert_eq!(icmp.icmp_type, 8);
        assert_eq!(icmp.code, 0);
    }

    #[test]
    fn test_parse_icmp_too_short() {
        assert!(parse_icmp(&[0u8; 2]).is_none());
    }

    #[test]
    fn test_parse_transport_unknown() {
        let result = parse_transport(&[], 42);
        assert!(result.is_some());
        match result.unwrap() {
            TransportHeader::Unknown(42) => {}
            _ => panic!("expected Unknown transport"),
        }
    }

    #[test]
    fn test_parse_transport_icmpv6() {
        let buf = [0x80, 0x00, 0x00, 0x00];
        let result = parse_transport(&buf, 58);
        assert!(result.is_some());
        match result.unwrap() {
            TransportHeader::Icmp(icmp) => {
                assert_eq!(icmp.icmp_type, 128);
                assert_eq!(icmp.code, 0);
            }
            _ => panic!("expected Icmp transport"),
        }
    }

    #[test]
    fn test_skip_ipv6_no_extensions() {
        let data = b"payload";
        let (proto, rest) = skip_ipv6_ext_headers(data, 6);
        assert_eq!(proto, 6);
        assert_eq!(rest, data as &[u8]);
    }

    #[test]
    fn test_skip_ipv6_hop_by_hop() {
        let mut ext = vec![0u8; 16];
        ext[0] = 6;
        ext[1] = 1;

        let payload = b"payload";

        let mut full = ext.clone();
        full.extend_from_slice(payload);

        let (proto, rest) = skip_ipv6_ext_headers(&full, IPV6_EXT_HOP_BY_HOP);
        assert_eq!(proto, 6);
        assert_eq!(rest, payload as &[u8]);
    }

    #[test]
    fn test_skip_ipv6_multiple_extensions() {
        let mut hop = vec![0u8; 16];
        hop[0] = IPV6_EXT_ROUTING;
        hop[1] = 1;

        let mut route = vec![0u8; 16];
        route[0] = 6;
        route[1] = 1;

        let payload = b"payload";

        let mut full = Vec::new();
        full.extend_from_slice(&hop);
        full.extend_from_slice(&route);
        full.extend_from_slice(payload);

        let (proto, rest) = skip_ipv6_ext_headers(&full, IPV6_EXT_HOP_BY_HOP);
        assert_eq!(proto, 6);
        assert_eq!(rest, payload as &[u8]);
    }

    #[test]
    fn test_skip_ipv6_fragment_non_zero() {
        let mut frag = vec![0u8; 8];
        frag[0] = 6;
        frag[2] = 0x01;
        frag[3] = 0x00;

        let payload = b"payload";
        let mut full = frag.clone();
        full.extend_from_slice(payload);

        let (proto, _) = skip_ipv6_ext_headers(&full, IPV6_EXT_FRAGMENT);
        assert_eq!(proto, u8::MAX);
    }

    #[test]
    fn test_skip_ipv6_fragment_first() {
        let mut frag = vec![0u8; 8];
        frag[0] = 6;
        frag[2] = 0x00;
        frag[3] = 0x00;

        let payload = b"payload";
        let mut full = frag.clone();
        full.extend_from_slice(payload);

        let (proto, _) = skip_ipv6_ext_headers(&full, IPV6_EXT_FRAGMENT);
        assert_eq!(proto, 6);
    }

    #[test]
    fn test_skip_ipv6_auth() {
        let mut ah = vec![0u8; 12];
        ah[0] = 17;
        ah[1] = 1;

        let payload = b"payload";
        let mut full = ah.clone();
        full.extend_from_slice(payload);

        let (proto, rest) = skip_ipv6_ext_headers(&full, IPV6_EXT_AUTH);
        assert_eq!(proto, 17);
        assert_eq!(rest, payload as &[u8]);
    }

    #[test]
    fn test_skip_ipv6_esp() {
        let esp = vec![0u8; 8];

        let payload = b"payload";
        let mut full = esp.clone();
        full.extend_from_slice(payload);

        let (proto, _) = skip_ipv6_ext_headers(&full, IPV6_ESP);
        assert_eq!(proto, u8::MAX);
    }

    #[test]
    fn test_full_parse_ethernet_ipv4_tcp() {
        let mut frame = vec![0u8; 14 + 20 + 20];
        // Ethernet: dst ff:ff:ff:ff:ff:ff, src 00:11:22:33:44:55, type IPv4
        frame[0..6].fill(0xFF);
        frame[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame[12] = 0x08;
        frame[13] = 0x00;
        // IPv4
        frame[14] = 0x45;
        frame[16] = 0x00;
        frame[17] = 0x28;
        frame[22] = 0x40;
        frame[23] = 0x06;
        frame[26] = 0xC0;
        frame[27] = 0xA8;
        frame[28] = 0x01;
        frame[29] = 0x01;
        frame[30] = 0xC0;
        frame[31] = 0xA8;
        frame[32] = 0x01;
        frame[33] = 0x02;
        // TCP
        frame[34] = 0x00;
        frame[35] = 0x50;
        frame[36] = 0x1F;
        frame[37] = 0x90;
        frame[46] = 0x50;
        frame[47] = 0x18;
        frame[48] = 0x10;
        frame[49] = 0x00;

        let eth = Linktype::ETHERNET;
        let result = parse_packet(&frame, eth, 0, 0);
        assert!(result.is_ok());
        let pkt = result.unwrap();
        assert_eq!(pkt.raw_len, frame.len());

        let eth_hdr = pkt.ethernet.unwrap();
        assert!(eth_hdr.src_mac[5] == 0x55);

        let ip = pkt.ipv4.unwrap();
        assert_eq!(ip.src_ip.to_string(), "192.168.1.1");
        assert_eq!(ip.dst_ip.to_string(), "192.168.1.2");

        let tcp = match pkt.transport.unwrap() {
            TransportHeader::Tcp(t) => t,
            _ => panic!("expected TCP"),
        };
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.dst_port, 8080);
        assert!(tcp.flags.ack);
        assert!(tcp.flags.psh);
    }

    #[test]
    fn test_unsupported_link_type() {
        let result = parse_packet(&[], Linktype::NULL, 0, 0);
        assert!(result.is_err());
        match result {
            Err(CaptureError::UnsupportedLinkType(_)) => {}
            _ => panic!("expected UnsupportedLinkType"),
        }
    }

    #[test]
    fn test_tv_to_systemtime() {
        let ts = tv_to_systemtime(1_000_000, 500_000);
        let since_epoch = ts.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(since_epoch.as_secs(), 1_000_000);
        assert_eq!(since_epoch.subsec_nanos(), 500_000_000);
    }
}
