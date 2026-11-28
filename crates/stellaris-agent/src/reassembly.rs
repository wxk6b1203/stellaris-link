//! Bounded IPv4/IPv6 fragment reassembly for overlay packets.
//!
//! Fragments are reassembled before ACL/transit decisions so rules see the
//! complete L4 header and kernels never receive partial datagrams. Limits are
//! deliberately small: this is an overlay datapath, not a general router.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use stellaris_types::NodeId;

/// Fragments older than this are discarded.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ENTRIES: usize = 256;
const MAX_ENTRIES_PER_PEER: usize = 32;
const MAX_BUFFERED_BYTES: usize = 8 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 128;
const MAX_REASSEMBLED: usize = 65_535;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    from: NodeId,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not a fragment (or a complete atomic packet): pass through unchanged.
    Pass,
    /// Fragment stored; wait for the rest.
    Buffered,
    /// Reassembled packet, ready for the normal dataplane path.
    Complete(Vec<u8>),
    /// Malformed/expired/over-limit fragment.
    Dropped(&'static str),
}

struct Entry {
    fragments: BTreeMap<usize, Vec<u8>>,
    total_payload: Option<usize>,
    header: Option<Vec<u8>>,
    ipv6: bool,
    last: Instant,
}

impl Entry {
    fn coverage(&self, total: usize) -> bool {
        let mut end = 0usize;
        for (start, data) in &self.fragments {
            if *start > end {
                return false;
            }
            end = end.max(start + data.len());
        }
        end >= total
    }

    fn assemble(&self, total: usize) -> Option<Vec<u8>> {
        if !self.coverage(total) {
            return None;
        }
        let mut payload = vec![0u8; total];
        let mut written = vec![false; total];
        for (start, data) in &self.fragments {
            for (i, byte) in data.iter().enumerate() {
                let pos = start + i;
                if pos >= total {
                    continue;
                }
                // First fragment wins on overlap (IPv4 policy); IPv6 overlap
                // is rejected before we get here.
                if !written[pos] {
                    payload[pos] = *byte;
                    written[pos] = true;
                }
            }
        }
        let mut header = self.header.clone()?;
        if self.ipv6 {
            let total_len = header.len() + total;
            if total_len > usize::from(u16::MAX) {
                return None;
            }
            header[4..6].copy_from_slice(&(total_len as u16).to_be_bytes());
            let mut packet = header;
            packet.extend_from_slice(&payload);
            Some(packet)
        } else {
            let total_len = header.len() + total;
            if total_len > usize::from(u16::MAX) {
                return None;
            }
            header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            header[6..8].copy_from_slice(&0u16.to_be_bytes()); // clear MF/offset
            // The first fragment carries a valid header checksum; zero it
            // before recomputing over the reassembled header (including
            // IPv4 options).
            header[10..12].copy_from_slice(&[0, 0]);
            let header_len = header.len();
            let mut packet = header;
            packet.extend_from_slice(&payload);
            let checksum = ipv4_checksum(&packet[..header_len]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            Some(packet)
        }
    }
}

pub struct Reassembler {
    entries: HashMap<Key, Entry>,
    timeout: Duration,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(DEFAULT_TIMEOUT)
    }
}

impl Reassembler {
    pub fn new(timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            timeout,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Feed one inner IP packet (without the mesh header).
    pub fn process(&mut self, from: NodeId, packet: &[u8], now: Instant) -> Outcome {
        self.expire(now);
        match packet.first().map(|b| b >> 4) {
            Some(4) => self.process_v4(from, packet, now),
            Some(6) => self.process_v6(from, packet, now),
            _ => Outcome::Dropped("bad ip version"),
        }
    }

    fn expire(&mut self, now: Instant) {
        let timeout = self.timeout;
        self.entries
            .retain(|_, e| now.duration_since(e.last) < timeout);
    }

    fn process_v4(&mut self, from: NodeId, packet: &[u8], now: Instant) -> Outcome {
        if packet.len() < 20 {
            return Outcome::Dropped("short ipv4");
        }
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        if ihl < 20 || packet.len() < ihl {
            return Outcome::Dropped("bad ihl");
        }
        let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        let id = u16::from_be_bytes([packet[4], packet[5]]);
        let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
        let more = flags_offset & 0x2000 != 0;
        let offset = usize::from(flags_offset & 0x1fff) * 8;
        if !more && offset == 0 {
            return Outcome::Pass;
        }
        // Every fragment's IPv4 total-length field describes that fragment,
        // not the original datagram; the full length is inferred from the
        // last fragment's offset + payload.
        if total < ihl || total > packet.len() || ihl > packet.len() {
            return Outcome::Dropped("bad ipv4 length");
        }
        // The IP total-length field covers only this fragment; trim Ethernet
        // padding instead of reassembling it as payload.
        let payload = &packet[ihl..total];
        if !payload.len().is_multiple_of(8) && more {
            return Outcome::Dropped("unaligned fragment");
        }
        if offset.saturating_add(payload.len()) > MAX_REASSEMBLED {
            return Outcome::Dropped("fragment past end");
        }
        let key = Key {
            from,
            src: IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )),
            dst: IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
            protocol: packet[9],
            id: u32::from(id),
        };
        self.insert(
            key,
            payload,
            offset,
            more,
            None,
            packet[..ihl].to_vec(),
            false,
            now,
        )
    }

    fn process_v6(&mut self, from: NodeId, packet: &[u8], now: Instant) -> Outcome {
        if packet.len() < 40 {
            return Outcome::Dropped("short ipv6");
        }
        let mut next_header = packet[6];
        let mut cursor = 40usize;
        let mut next_field = 6usize;
        for _ in 0..8 {
            match next_header {
                44 => {
                    if packet.len() < cursor + 8 {
                        return Outcome::Dropped("short fragment header");
                    }
                    let fragment_next = packet[cursor];
                    let frag = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
                    let offset = usize::from(frag >> 3) * 8;
                    let more = frag & 1 != 0;
                    if !more && offset == 0 {
                        // Atomic fragment: no reassembly required and the
                        // kernel can consume it as-is.
                        return Outcome::Pass;
                    }
                    let payload = &packet[cursor + 8..];
                    if more && !payload.len().is_multiple_of(8) {
                        return Outcome::Dropped("unaligned ipv6 fragment");
                    }
                    if offset.saturating_add(payload.len()) > MAX_REASSEMBLED {
                        return Outcome::Dropped("fragment past end");
                    }
                    let mut header = packet[..cursor].to_vec();
                    header[next_field] = fragment_next; // drop fragment header
                    let key = Key {
                        from,
                        src: IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(&packet[8..24]).unwrap(),
                        )),
                        dst: IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
                        )),
                        protocol: fragment_next,
                        id: u32::from_be_bytes([
                            packet[cursor + 4],
                            packet[cursor + 5],
                            packet[cursor + 6],
                            packet[cursor + 7],
                        ]),
                    };
                    // RFC 8200: overlapping fragments are invalid. Reject any
                    // overlap, not just an identical start offset.
                    let end = offset + payload.len();
                    if let Some(entry) = self.entries.get(&key) {
                        for (start, data) in &entry.fragments {
                            if offset < start + data.len() && *start < end {
                                return Outcome::Dropped("overlapping ipv6 fragment");
                            }
                        }
                    }
                    return self.insert(key, payload, offset, more, None, header, true, now);
                }
                0 | 43 | 60 => {
                    if packet.len() < cursor + 2 {
                        return Outcome::Dropped("short ipv6 extension header");
                    }
                    let length = (usize::from(packet[cursor + 1]) + 1) * 8;
                    if length == 0 || cursor + length > packet.len() {
                        return Outcome::Dropped("bad ipv6 extension length");
                    }
                    next_field = cursor;
                    next_header = packet[cursor];
                    cursor += length;
                }
                51 => {
                    if packet.len() < cursor + 2 {
                        return Outcome::Dropped("short ipv6 ah header");
                    }
                    let length = (usize::from(packet[cursor + 1]) + 2) * 4;
                    if cursor + length > packet.len() {
                        return Outcome::Dropped("bad ipv6 ah length");
                    }
                    next_field = cursor;
                    next_header = packet[cursor];
                    cursor += length;
                }
                _ => return Outcome::Pass,
            }
        }
        Outcome::Dropped("too many ipv6 extension headers")
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        key: Key,
        payload: &[u8],
        offset: usize,
        more: bool,
        declared_total: Option<usize>,
        header: Vec<u8>,
        ipv6: bool,
        now: Instant,
    ) -> Outcome {
        if payload.is_empty() && !more {
            return Outcome::Dropped("empty fragment");
        }
        let existing = self.entries.contains_key(&key);
        if !existing {
            if self.entries.len() >= MAX_ENTRIES {
                return Outcome::Dropped("reassembly table full");
            }
            if self
                .entries
                .keys()
                .filter(|candidate| candidate.from == key.from)
                .count()
                >= MAX_ENTRIES_PER_PEER
            {
                return Outcome::Dropped("too many reassembly entries for peer");
            }
        }
        let buffered: usize = self
            .entries
            .values()
            .flat_map(|entry| entry.fragments.values())
            .map(Vec::len)
            .sum();
        if buffered.saturating_add(payload.len()) > MAX_BUFFERED_BYTES {
            return Outcome::Dropped("reassembly byte limit reached");
        }
        let entry = self.entries.entry(key.clone()).or_insert_with(|| Entry {
            fragments: BTreeMap::new(),
            total_payload: None,
            header: None,
            ipv6,
            last: now,
        });
        entry.last = now;
        if entry.fragments.len() >= MAX_FRAGMENTS {
            return Outcome::Dropped("too many fragments");
        }
        if offset == 0 {
            entry.header = Some(header);
            if let Some(total) = declared_total {
                entry.total_payload = Some(total);
            }
        }
        if !more {
            entry.total_payload = Some(offset + payload.len());
        }
        if let Some(existing) = entry.total_payload
            && offset + payload.len() > existing
        {
            return Outcome::Dropped("fragment past end");
        }
        entry
            .fragments
            .entry(offset)
            .or_insert_with(|| payload.to_vec());
        let Some(total) = entry.total_payload else {
            return Outcome::Buffered;
        };
        if total > MAX_REASSEMBLED {
            self.entries.remove(&key);
            return Outcome::Dropped("reassembled too large");
        }
        let Some(packet) = entry.assemble(total) else {
            return Outcome::Buffered;
        };
        self.entries.remove(&key);
        Outcome::Complete(packet)
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_fragment(id: u16, offset: usize, more: bool, payload: &[u8], total: usize) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        let _ = total;
        let total_len = 20 + payload.len();
        p[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        p[4..6].copy_from_slice(&id.to_be_bytes());
        let mut flags = (offset / 8) as u16;
        if more {
            flags |= 0x2000;
        }
        p[6..8].copy_from_slice(&flags.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[10..12].copy_from_slice(&0xdeadu16.to_be_bytes()); // stale header checksum
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p.extend_from_slice(payload);
        p
    }

    fn v6_fragment(id: u32, offset: usize, more: bool, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[6] = 44;
        p[7] = 64;
        p[8..24].copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        p[40] = 17; // UDP
        let mut frag = ((offset / 8) as u16) << 3;
        if more {
            frag |= 1;
        }
        p[42..44].copy_from_slice(&frag.to_be_bytes());
        p[44..48].copy_from_slice(&id.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn node() -> NodeId {
        NodeId::new([1u8; 32])
    }

    #[test]
    fn reassembles_ipv4_out_of_order() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        let first = v4_fragment(7, 0, true, &[0u8; 8], 16);
        let last = v4_fragment(7, 8, false, &[0u8; 8], 16);
        assert_eq!(r.process(node(), &last, now), Outcome::Buffered);
        match r.process(node(), &first, now) {
            Outcome::Complete(packet) => {
                assert_eq!(packet.len(), 20 + 16);
                assert_eq!(packet[6..8], [0, 0]);
                assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 36);
                assert_eq!(ipv4_checksum(&packet[..20]), 0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ipv4_non_fragment_passes_through() {
        let mut r = Reassembler::default();
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(r.process(node(), &p, Instant::now()), Outcome::Pass);
    }

    #[test]
    fn ipv6_reassembles_and_drops_overlap() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        assert_eq!(
            r.process(node(), &v6_fragment(9, 0, true, &[1u8; 8]), now),
            Outcome::Buffered
        );
        assert_eq!(
            r.process(node(), &v6_fragment(9, 8, true, &[4u8; 8]), now),
            Outcome::Buffered
        );
        assert_eq!(
            r.process(node(), &v6_fragment(9, 8, true, &[5u8; 8]), now),
            Outcome::Dropped("overlapping ipv6 fragment")
        );
        match r.process(node(), &v6_fragment(9, 16, false, &[3u8; 8]), now) {
            Outcome::Complete(packet) => {
                assert_eq!(packet.len(), 40 + 24);
                assert_eq!(packet[6], 17);
                assert_eq!(&packet[40..48], &[1u8; 8]);
                assert_eq!(&packet[48..56], &[4u8; 8]);
                assert_eq!(&packet[56..64], &[3u8; 8]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn incomplete_entries_expire() {
        let now = Instant::now();
        let mut r = Reassembler::new(Duration::from_millis(10));
        assert_eq!(
            r.process(node(), &v4_fragment(1, 0, true, &[0u8; 8], 16), now),
            Outcome::Buffered
        );
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.process(
                node(),
                &v4_fragment(2, 0, true, &[0u8; 8], 16),
                now + Duration::from_millis(20)
            ),
            Outcome::Buffered
        );
        // The first entry expired during process().
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn malformed_fragments_are_dropped() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        assert_eq!(
            r.process(node(), &[0x45], now),
            Outcome::Dropped("short ipv4")
        );
        assert_eq!(
            r.process(node(), &[0x70], now),
            Outcome::Dropped("bad ip version")
        );
    }
    #[test]
    fn per_peer_reassembly_quota_is_enforced() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        let a = node();
        let b = NodeId::new([2u8; 32]);
        for id in 0..MAX_ENTRIES_PER_PEER as u32 {
            let frag = v4_fragment(id as u16, 0, true, &[0u8; 8], 16);
            assert_eq!(r.process(a, &frag, now), Outcome::Buffered);
        }
        let over = v4_fragment(999, 0, true, &[0u8; 8], 16);
        assert_eq!(
            r.process(a, &over, now),
            Outcome::Dropped("too many reassembly entries for peer")
        );
        // A different peer is unaffected by the first peer's quota.
        assert_eq!(r.process(b, &over, now), Outcome::Buffered);
    }
    #[test]
    fn ipv4_total_length_trims_link_padding() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        let mut first = v4_fragment(11, 0, true, &[1u8; 8], 16);
        first.extend_from_slice(&[0xaa; 4]); // Ethernet padding beyond total_length
        assert_eq!(r.process(node(), &first, now), Outcome::Buffered);
        let last = v4_fragment(11, 8, false, &[2u8; 8], 16);
        match r.process(node(), &last, now) {
            Outcome::Complete(packet) => {
                assert_eq!(packet.len(), 20 + 16);
                assert_eq!(&packet[20..28], &[1u8; 8]);
                assert_eq!(&packet[28..36], &[2u8; 8]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ipv4_options_are_included_in_the_reassembled_checksum() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        let fragment = |offset: usize, more: bool, payload: &[u8]| {
            let mut p = vec![0u8; 24];
            p[0] = 0x46; // IHL = 6 (24 bytes)
            let total = 24 + payload.len();
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p[4..6].copy_from_slice(&77u16.to_be_bytes());
            let mut flags = (offset / 8) as u16;
            if more {
                flags |= 0x2000;
            }
            p[6..8].copy_from_slice(&flags.to_be_bytes());
            p[8] = 64;
            p[9] = 17;
            p[12..16].copy_from_slice(&[10, 0, 0, 1]);
            p[16..20].copy_from_slice(&[10, 0, 0, 2]);
            p[20..24].copy_from_slice(&[1, 1, 1, 0]); // options
            p.extend_from_slice(payload);
            p
        };
        assert_eq!(
            r.process(node(), &fragment(0, true, &[3u8; 8]), now),
            Outcome::Buffered
        );
        match r.process(node(), &fragment(8, false, &[4u8; 8]), now) {
            Outcome::Complete(packet) => {
                assert_eq!(packet.len(), 24 + 16);
                assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 40);
                assert_eq!(ipv4_checksum(&packet[..24]), 0);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ipv6_fragment_after_an_extension_header_is_reassembled() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        let fragment = |offset: usize, more: bool, payload: &[u8]| {
            let ext = [44u8, 0, 0, 0, 0, 0, 0, 0]; // Hop-by-Hop -> Fragment
            let mut p = vec![0u8; 40 + ext.len() + 8 + payload.len()];
            p[0] = 0x60;
            let payload_len = ext.len() + 8 + payload.len();
            p[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
            p[6] = 0; // Hop-by-Hop
            p[7] = 64;
            p[8..24].copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
            p[24..40].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
            p[40..48].copy_from_slice(&ext);
            let frag = 48;
            p[frag] = 17; // UDP after the fragment header
            let mut field = ((offset / 8) as u16) << 3;
            if more {
                field |= 1;
            }
            p[frag + 2..frag + 4].copy_from_slice(&field.to_be_bytes());
            p[frag + 4..frag + 8].copy_from_slice(&0x1234u32.to_be_bytes());
            p[56..].copy_from_slice(payload);
            p
        };
        assert_eq!(
            r.process(node(), &fragment(0, true, &[7u8; 8]), now),
            Outcome::Buffered
        );
        match r.process(node(), &fragment(8, false, &[8u8; 8]), now) {
            Outcome::Complete(packet) => {
                assert_eq!(packet.len(), 40 + 8 + 16);
                assert_eq!(packet[6], 0);
                assert_eq!(packet[40], 17);
                assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 48 + 16);
                assert_eq!(&packet[48..56], &[7u8; 8]);
                assert_eq!(&packet[56..64], &[8u8; 8]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ipv6_partial_overlap_and_unaligned_fragments_are_rejected() {
        let now = Instant::now();
        let mut r = Reassembler::default();
        assert_eq!(
            r.process(node(), &v6_fragment(5, 0, true, &[1u8; 16]), now),
            Outcome::Buffered
        );
        assert_eq!(
            r.process(node(), &v6_fragment(5, 8, true, &[2u8; 16]), now),
            Outcome::Dropped("overlapping ipv6 fragment")
        );
        assert_eq!(
            r.process(node(), &v6_fragment(6, 0, true, &[0u8; 7]), now),
            Outcome::Dropped("unaligned ipv6 fragment")
        );
    }
}
