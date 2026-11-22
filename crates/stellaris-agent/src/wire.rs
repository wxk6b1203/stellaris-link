//! On-wire IP packet framing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use stellaris_types::NetworkId;

pub const HEADER_LEN: usize = 16;
pub const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeshHeader {
    pub version: u8,
    pub flags: u8,
    pub ttl: u8,
    pub network_hash: u32,
    pub flow_hash: u32,
}

impl MeshHeader {
    pub fn new(network: NetworkId, ttl: u8, flow_hash: u32) -> Self {
        Self {
            version: VERSION,
            flags: 0,
            ttl,
            network_hash: network_hash(network),
            flow_hash,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.version;
        out[1] = self.flags;
        out[2] = self.ttl;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.network_hash.to_be_bytes());
        out[8..12].copy_from_slice(&self.flow_hash.to_be_bytes());
        // 12..16 reserved
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let version = bytes[0];
        if version != VERSION {
            return None;
        }
        Some(Self {
            version,
            flags: bytes[1],
            ttl: bytes[2],
            network_hash: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
            flow_hash: u32::from_be_bytes(bytes[8..12].try_into().ok()?),
        })
    }
}

pub fn network_hash(network: NetworkId) -> u32 {
    let bytes = network.0.as_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ttl: u8,
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl PacketInfo {
    pub fn parse(packet: &[u8]) -> Option<Self> {
        match packet.first()? >> 4 {
            4 => parse_v4(packet),
            6 => parse_v6(packet),
            _ => None,
        }
    }
}

fn parse_v4(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let protocol = packet[9];
    let ttl = packet[8];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let (src_port, dst_port) = ports(packet, ihl, protocol);
    Some(PacketInfo {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        ttl,
        protocol,
        src_port,
        dst_port,
    })
}

fn parse_v6(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 40 {
        return None;
    }
    let protocol = packet[6];
    let ttl = packet[7];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    let (src_port, dst_port) = ports(packet, 40, protocol);
    Some(PacketInfo {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        ttl,
        protocol,
        src_port,
        dst_port,
    })
}

fn ports(packet: &[u8], offset: usize, protocol: u8) -> (Option<u16>, Option<u16>) {
    if !matches!(protocol, 6 | 17) || packet.len() < offset + 4 {
        return (None, None);
    }
    let src = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let dst = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    (Some(src), Some(dst))
}

/// Stable 5-tuple flow hash (FNV-1a).
pub fn flow_hash(info: &PacketInfo) -> u32 {
    let mut hash = 0x811c9dc5u32;
    let mut write = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
    };
    match info.src {
        IpAddr::V4(ip) => write(&ip.octets()),
        IpAddr::V6(ip) => write(&ip.octets()),
    }
    match info.dst {
        IpAddr::V4(ip) => write(&ip.octets()),
        IpAddr::V6(ip) => write(&ip.octets()),
    }
    write(&[info.protocol]);
    write(&info.src_port.unwrap_or(0).to_be_bytes());
    write(&info.dst_port.unwrap_or(0).to_be_bytes());
    hash
}

/// Set the DSCP field (IPv4 TOS / IPv6 traffic class), preserving ECN.
pub fn set_dscp(packet: &mut [u8], dscp: u8) -> bool {
    if dscp > 63 {
        return false;
    }
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            packet[1] = (packet[1] & 0x03) | ((dscp & 0x3f) << 2);
            recompute_ipv4_checksum(packet);
            true
        }
        Some(6) if packet.len() >= 40 => {
            let ecn = packet[1] & 0x3f;
            packet[0] = (packet[0] & 0xf0) | ((dscp >> 2) & 0x0f);
            packet[1] = ((dscp & 0x03) << 6) | ecn;
            true
        }
        _ => false,
    }
}

pub fn dscp(packet: &[u8]) -> Option<u8> {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => Some(packet[1] >> 2),
        Some(6) if packet.len() >= 40 => Some(((packet[0] & 0x0f) << 2) | (packet[1] >> 6)),
        _ => None,
    }
}

fn recompute_ipv4_checksum(packet: &mut [u8]) {
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl || ihl < 20 {
        return;
    }
    packet[10] = 0;
    packet[11] = 0;
    let mut sum = 0u32;
    for chunk in packet[..ihl].chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

/// Clamp the TCP MSS option to the overlay MTU. Returns true if modified.
pub fn clamp_tcp_mss(packet: &mut [u8], mtu: u16) -> bool {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 || packet.len() < ihl + 20 || packet[9] != 6 {
                return false;
            }
            let max = mtu.saturating_sub(40);
            clamp_tcp(packet, ihl, max, true)
        }
        Some(6) if packet.len() >= 60 => {
            if packet[6] != 6 {
                return false;
            }
            let max = mtu.saturating_sub(60);
            clamp_tcp(packet, 40, max, false)
        }
        _ => false,
    }
}

fn clamp_tcp(packet: &mut [u8], offset: usize, max_mss: u16, v4: bool) -> bool {
    if packet.len() < offset + 20 {
        return false;
    }
    let data_offset = (packet[offset + 12] >> 4) as usize * 4;
    if data_offset < 20 || packet.len() < offset + data_offset {
        return false;
    }
    let mut pos = offset + 20;
    let end = offset + data_offset;
    let mut mss_pos = None;
    while pos < end {
        let kind = packet[pos];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            pos += 1;
            continue;
        }
        if pos + 1 >= end {
            break;
        }
        let len = packet[pos + 1] as usize;
        if len < 2 || pos + len > end {
            break;
        }
        if kind == 2 && len == 4 {
            mss_pos = Some(pos + 2);
            break;
        }
        pos += len;
    }
    let Some(mss_pos) = mss_pos else {
        return false;
    };
    let mss = u16::from_be_bytes([packet[mss_pos], packet[mss_pos + 1]]);
    if mss <= max_mss {
        return false;
    }
    packet[mss_pos..mss_pos + 2].copy_from_slice(&max_mss.to_be_bytes());
    packet[offset + 16] = 0;
    packet[offset + 17] = 0;
    let tcp_len = packet.len() - offset;
    let mut sum = 0u32;
    if v4 {
        for chunk in packet[12..20].chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        sum += 6;
        sum += tcp_len as u32;
    } else {
        for chunk in packet[8..40].chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        sum += (tcp_len as u32) >> 16;
        sum += (tcp_len as u32) & 0xffff;
        sum += 6;
    }
    let mut i = offset;
    while i + 1 < packet.len() {
        sum += u16::from_be_bytes([packet[i], packet[i + 1]]) as u32;
        i += 2;
    }
    if i < packet.len() {
        sum += u16::from_be_bytes([packet[i], 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[offset + 16..offset + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    true
}

/// Decrement IPv4 TTL / IPv6 hop limit in place. Returns false if it would reach 0.
pub fn decrement_ttl(packet: &mut [u8]) -> bool {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            if packet[8] <= 1 {
                return false;
            }
            packet[8] -= 1;
            // IPv4 header checksum.
            packet[10] = 0;
            packet[11] = 0;
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if packet.len() >= ihl {
                let mut sum = 0u32;
                for chunk in packet[..ihl].chunks(2) {
                    let word = if chunk.len() == 2 {
                        u16::from_be_bytes([chunk[0], chunk[1]])
                    } else {
                        u16::from_be_bytes([chunk[0], 0])
                    };
                    sum += word as u32;
                }
                while sum >> 16 != 0 {
                    sum = (sum & 0xffff) + (sum >> 16);
                }
                let checksum = !(sum as u16);
                packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            true
        }
        Some(6) if packet.len() >= 40 => {
            if packet[7] <= 1 {
                return false;
            }
            packet[7] -= 1;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8];
        p[0] = 0x45;
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 7, 0, 1]);
        p[16..20].copy_from_slice(&[10, 7, 0, 2]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p[22..24].copy_from_slice(&80u16.to_be_bytes());
        p
    }

    #[test]
    fn header_roundtrip() {
        let h = MeshHeader::new(NetworkId::new(), 64, 0xdeadbeef);
        let encoded = h.encode();
        assert_eq!(MeshHeader::decode(&encoded).unwrap(), h);
        assert!(MeshHeader::decode(&encoded[..10]).is_none());
    }

    #[test]
    fn parse_v4() {
        let p = v4_packet();
        let info = PacketInfo::parse(&p).unwrap();
        assert_eq!(info.src, "10.7.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(info.dst, "10.7.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(info.src_port, Some(1234));
        assert_eq!(info.dst_port, Some(80));
        assert_eq!(info.protocol, 6);
    }

    #[test]
    fn ttl_decrement_checksum() {
        let mut p = v4_packet();
        assert!(decrement_ttl(&mut p));
        assert_eq!(p[8], 63);
        assert_ne!(u16::from_be_bytes([p[10], p[11]]), 0);
    }

    #[test]
    fn dscp_roundtrip_and_checksum() {
        let mut p = v4_packet();
        assert!(set_dscp(&mut p, 46));
        assert_eq!(dscp(&p), Some(46));
        assert_ne!(u16::from_be_bytes([p[10], p[11]]), 0);
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert!(set_dscp(&mut v6, 46));
        assert_eq!(dscp(&v6), Some(46));
    }
    #[test]
    fn clamps_ipv4_tcp_mss() {
        let mut p = vec![0u8; 44];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&44u16.to_be_bytes());
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20 + 12] = 6 << 4;
        p[40] = 2;
        p[41] = 4;
        p[42..44].copy_from_slice(&1460u16.to_be_bytes());
        assert!(clamp_tcp_mss(&mut p, 1200));
        assert_eq!(u16::from_be_bytes([p[42], p[43]]), 1160);
        assert!(!clamp_tcp_mss(&mut p, 1200));
    }

    #[test]
    fn clamps_ipv6_tcp_mss() {
        let mut p = vec![0u8; 64];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&24u16.to_be_bytes());
        p[6] = 6;
        p[40 + 12] = 6 << 4;
        p[60] = 2;
        p[61] = 4;
        p[62..64].copy_from_slice(&1460u16.to_be_bytes());
        assert!(clamp_tcp_mss(&mut p, 1200));
        assert_eq!(u16::from_be_bytes([p[62], p[63]]), 1140);
    }
}
