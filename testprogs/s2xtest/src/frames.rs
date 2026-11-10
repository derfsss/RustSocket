//! Test frames: s2xtest's own payloads (EtherType 0x88B5, IEEE 802's local
//! experimental type) and IPv4 / IPv6 packets with TCP or UDP, with their
//! checksums right or deliberately wrong.

use alloc::vec;
use alloc::vec::Vec;

/// IEEE 802 local experimental EtherType: nobody else on the link reads it.
pub const ETYPE: u32 = 0x88B5;
pub const ETYPE_IPV4: u32 = 0x0800;
pub const ETYPE_IPV6: u32 = 0x86DD;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// A test payload: "S2X", the test id, the sequence number, then a
/// pattern that depends on both (so a frame's bytes can be checked).
pub fn payload(id: u8, seq: u16, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len.max(6)];
    p[0] = b'S';
    p[1] = b'2';
    p[2] = b'X';
    p[3] = id;
    p[4] = (seq >> 8) as u8;
    p[5] = seq as u8;
    for (i, b) in p.iter_mut().enumerate().skip(6) {
        *b = (i as u16).wrapping_mul(7).wrapping_add(seq) as u8 ^ id;
    }
    p
}

/// (test id, sequence number) of a payload whose pattern is intact.
pub fn parse(p: &[u8]) -> Option<(u8, u16)> {
    if p.len() < 6 || &p[..3] != b"S2X" {
        return None;
    }
    let id = p[3];
    let seq = (p[4] as u16) << 8 | p[5] as u16;
    for (i, &b) in p.iter().enumerate().skip(6) {
        if b != (i as u16).wrapping_mul(7).wrapping_add(seq) as u8 ^ id {
            return None;
        }
    }
    Some((id, seq))
}

/// One's complement sum of `data` added to `sum` (not folded).
pub fn sum(mut sum: u32, data: &[u8]) -> u32 {
    for c in data.chunks(2) {
        sum += (c[0] as u32) << 8 | *c.get(1).unwrap_or(&0) as u32;
    }
    sum
}

pub fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// The finished checksum of `data` (the complement of the folded sum).
pub fn checksum(data: &[u8]) -> u16 {
    !fold(sum(0, data))
}

pub const SRC4: [u8; 4] = [10, 0, 6, 1];
pub const DST4: [u8; 4] = [10, 0, 6, 2];
pub const SRC6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1];
pub const DST6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 2];

/// The pseudo-header sum (not folded, not complemented) for a transport
/// segment of `len` bytes.
pub fn pseudo(v6: bool, proto: u8, len: usize) -> u32 {
    if v6 {
        let mut s = sum(0, &SRC6);
        s = sum(s, &DST6);
        s += (len as u32) >> 16;
        s += len as u32 & 0xffff;
        s + proto as u32
    } else {
        let mut s = sum(0, &SRC4);
        s = sum(s, &DST4);
        s + proto as u32 + len as u32
    }
}

/// Where the transport checksum lies in a transport header.
pub fn l4_csum_at(proto: u8) -> usize {
    if proto == PROTO_TCP { 16 } else { 6 }
}

/// A transport segment (TCP: 20-byte header, ACK|PSH; UDP: 8 bytes)
/// with `data`, its checksum right.
pub fn transport(v6: bool, proto: u8, sport: u16, dport: u16, seq: u32, data: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    if proto == PROTO_TCP {
        t.extend_from_slice(&seq.to_be_bytes());
        t.extend_from_slice(&1u32.to_be_bytes());
        t.push(5 << 4);
        t.push(0x18);
        t.extend_from_slice(&8192u16.to_be_bytes());
        t.extend_from_slice(&[0, 0, 0, 0]);
    } else {
        t.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        t.extend_from_slice(&[0, 0]);
    }
    t.extend_from_slice(data);
    let at = l4_csum_at(proto);
    let mut c = !fold(sum(pseudo(v6, proto, t.len()), &t));
    if proto == PROTO_UDP && c == 0 {
        c = 0xffff;
    }
    t[at..at + 2].copy_from_slice(&c.to_be_bytes());
    t
}

/// An IPv4 packet (20-byte header, its checksum right) around `l4`.
pub fn ipv4(proto: u8, id: u16, l4: &[u8]) -> Vec<u8> {
    let total = 20 + l4.len();
    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes());
    ip.extend_from_slice(&[0x40, 0, 64, proto, 0, 0]);
    ip.extend_from_slice(&SRC4);
    ip.extend_from_slice(&DST4);
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(l4);
    ip
}

/// An IPv6 packet around `l4`.
pub fn ipv6(next: u8, l4: &[u8]) -> Vec<u8> {
    let mut ip = vec![0x60u8, 0, 0, 0];
    ip.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    ip.push(next);
    ip.push(64);
    ip.extend_from_slice(&SRC6);
    ip.extend_from_slice(&DST6);
    ip.extend_from_slice(l4);
    ip
}

/// Whether an IPv4 packet's header checksum is right.
pub fn ipv4_ok(p: &[u8]) -> bool {
    p.len() >= 20 && fold(sum(0, &p[..((p[0] & 15) as usize) * 4])) == 0xffff
}

/// Whether the transport checksum of an IP packet (v4 or v6, no IPv6
/// extension headers) is right; None if it is not TCP/UDP or too short.
pub fn l4_ok(p: &[u8]) -> Option<bool> {
    let (v6, proto, off) = match p.first()? >> 4 {
        4 => (false, *p.get(9)?, ((p[0] & 15) as usize) * 4),
        6 => (true, *p.get(6)?, 40),
        _ => return None,
    };
    // The packet's own length (a short frame arrives padded).
    let total = if v6 { 40 + u16::from_be_bytes([p[4], p[5]]) as usize } else { u16::from_be_bytes([p[2], p[3]]) as usize };
    if proto != PROTO_TCP && proto != PROTO_UDP || total > p.len() || total < off + 8 {
        return None;
    }
    let t = &p[off..total];
    Some(fold(sum(pseudo(v6, proto, t.len()), t)) == 0xffff)
}
