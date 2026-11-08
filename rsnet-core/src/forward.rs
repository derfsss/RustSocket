//! IP forwarding (ip.forwarding, RoadshowControl / SBTC_IP_FORWARDING),
//! as Roadshow 1.15 routes, measured with two QEMU machines on a shared
//! segment (Roadshow as router, a LAN host behind it, the "map" rule of
//! Roadshow's own example ipnat.rules):
//! off by default, and then a datagram for another host is dropped without
//! a word; on, it goes out of the interface the routing table picks with
//! its TTL one lower (ping replies arrive with 254), and one whose TTL
//! runs out is answered with ICMP time exceeded from the receiving
//! interface's address (traceroute's first hop is the router).
//!
//! The link hands such a datagram over (Link::receive, after the "in"
//! rules and NAT); the stack process sends it on (`Forwarder::run`)
//! through the outgoing link's own send, so the "out" rules and NAT apply
//! (4.4BSD's ip_forward through ip_output). No route: ICMP host
//! unreachable; too big for the outgoing interface with DF set: ICMP
//! fragmentation needed (without DF: dropped, as no fragmenting is done
//! here). The next hop's Ethernet address comes from the interface's ARP
//! table; when it is not there an ARP request goes out (again each
//! second) and the datagram waits up to 5 s (then ICMP host unreachable,
//! as BSD's ARP gives up). A datagram that leaves by the interface it came in on, from a
//! host on that interface's network, by a route that is not the default
//! one, gets an ICMP host redirect to its next hop first while
//! ip.sendredirects is 1 (4.4BSD's ip_forward; Roadshow's, measured: "redirect
//! 192.0.2.1 to host 10.0.6.4" from the router, TTL 255), and is
//! forwarded still. Roadshow fragments no forwarded datagram either: one
//! larger than the outgoing interface's MTU got no answer through it.

use alloc::vec::Vec;

use crate::link::Link;

/// How long a datagram waits for its next hop's ARP answer, and how often
/// the request goes out meanwhile (4.4BSD's arp_maxtries 5, one a second).
const ARP_WAIT_US: u64 = 5_000_000;
pub const ARP_AGAIN_US: u64 = 1_000_000;

/// Is `dst` one of ours, or not unicast (so not to be forwarded)?
pub fn not_forwarded(local: &[[u8; 4]], dst: [u8; 4]) -> bool {
    dst[0] >= 224 || dst == [255; 4] || dst[0] == 0 || dst[0] == 127 || local.contains(&dst)
}

/// A datagram waiting for its next hop's Ethernet address: the outgoing
/// slot, the next hop, the frame (its Ethernet header replaced when sent),
/// the receiving slot and the source's Ethernet address (for an ICMP error),
/// and the deadline.
pub struct Waiting {
    pub out: usize,
    pub hop: [u8; 4],
    pub frame: Vec<u8>,
    pub from: usize,
    pub deadline: u64,
    /// When the ARP request goes out again.
    pub again: u64,
}

/// The Internet checksum of `b`.
fn cksum(b: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut k = 0;
    while k + 1 < b.len() {
        sum += u16::from_be_bytes([b[k], b[k + 1]]) as u32;
        k += 2;
    }
    if k < b.len() {
        sum += (b[k] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The IP header's checksum made again.
pub fn fix_header(ip: &mut [u8]) {
    let hl = ((ip[0] & 15) as usize * 4).min(ip.len());
    ip[10] = 0;
    ip[11] = 0;
    let c = cksum(&ip[..hl]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
}

/// An ICMP error (`kind`, `code`, and `rest`: the four bytes after the
/// checksum, the next hop's MTU for "fragmentation needed", the gateway
/// for a redirect) about datagram `ip`, from `src` back to its sender, as
/// an Ethernet frame from `mac` to `to_mac`: the header and 8 bytes quoted,
/// TTL 255 and the datagram's DF flag (4.4BSD's icmp_error and
/// icmp_reflect; Roadshow's redirect, measured). None about an ICMP error,
/// a fragment past the first, or a datagram from a non-unicast source.
pub fn icmp_error(ip: &[u8], kind: u8, code: u8, rest: [u8; 4], src: [u8; 4], mac: [u8; 6], to_mac: [u8; 6]) -> Option<Vec<u8>> {
    if ip.len() < 20 {
        return None;
    }
    let hl = (ip[0] & 15) as usize * 4;
    let off = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    let from = [ip[12], ip[13], ip[14], ip[15]];
    if off != 0 || from[0] >= 224 || from == [0; 4] || ip.len() < hl {
        return None;
    }
    if ip[9] == 1 && ip.len() > hl && matches!(ip[hl], 3 | 4 | 5 | 11 | 12) {
        return None;
    }
    let quote = &ip[..(hl + 8).min(ip.len())];
    let mut icmp = Vec::with_capacity(8 + quote.len());
    icmp.extend_from_slice(&[kind, code, 0, 0]);
    icmp.extend_from_slice(&rest);
    icmp.extend_from_slice(quote);
    let c = cksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let total = 20 + icmp.len();
    let mut f = Vec::with_capacity(14 + total);
    f.extend_from_slice(&to_mac);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&[0x08, 0x00]);
    let mut h = [0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    h[6] = ip[6] & 0x40;
    h[8] = 255;
    h[9] = 1;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&from);
    fix_header(&mut h);
    f.extend_from_slice(&h);
    f.extend_from_slice(&icmp);
    if f.len() < 60 {
        f.resize(60, 0);
    }
    Some(f)
}

/// An ARP request for `hop` from `link` (our address `me` on it).
pub fn arp_request(link: &mut Link, me: [u8; 4], hop: [u8; 4]) {
    let mut f = Vec::with_capacity(60);
    f.extend_from_slice(&[0xff; 6]);
    f.extend_from_slice(&link.mac);
    f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    f.extend_from_slice(&link.mac);
    f.extend_from_slice(&me);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&hop);
    f.resize(60, 0);
    link.send(&f);
}

/// `ip` (a frame's datagram) sent to `mac` out of `link`, through its
/// filtered send (the "out" rules, NAT).
pub fn send_to(link: &mut Link, mac: [u8; 6], ip: &[u8]) -> bool {
    let mut f = Vec::with_capacity(14 + ip.len());
    f.extend_from_slice(&mac);
    f.extend_from_slice(&link.mac);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(ip);
    if f.len() < 60 {
        f.resize(60, 0);
    }
    link.send(&f)
}

/// The answer to an ICMP time stamp request (type 13) in `frame` to one
/// of `local`, as Roadshow gives it (testprogs/rstcp/c/tsprobe.c:
/// type 14, the originate time echoed, receive and transmit
/// the same, milliseconds since midnight, TTL 255): the reply frame, from
/// `mac` back to the sender. None for anything else.
pub fn timestamp_reply(frame: &[u8], local: &[[u8; 4]], mac: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < 34 || frame[12] != 0x08 || frame[13] != 0x00 || frame[14] >> 4 != 4 || frame[23] != 1 {
        return None;
    }
    let ip = &frame[14..];
    let hl = (ip[0] & 15) as usize * 4;
    let total = (u16::from_be_bytes([ip[2], ip[3]]) as usize).min(ip.len());
    let off = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff;
    let dst = [ip[16], ip[17], ip[18], ip[19]];
    if off != 0 || total < hl + 20 || ip[hl] != 13 || ip[hl + 1] != 0 || !local.contains(&dst) {
        return None;
    }
    let t = amigaos4::timer::sys_time();
    let ms = ((t.secs % 86_400) * 1000 + t.micros / 1000).to_be_bytes();
    let mut icmp = [0u8; 20];
    icmp.copy_from_slice(&ip[hl..hl + 20]);
    icmp[0] = 14;
    icmp[2] = 0;
    icmp[3] = 0;
    icmp[12..16].copy_from_slice(&ms);
    icmp[16..20].copy_from_slice(&ms);
    let c = cksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut f = Vec::with_capacity(60);
    f.extend_from_slice(&frame[6..12]);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&[0x08, 0x00]);
    let mut h = [0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&40u16.to_be_bytes());
    h[8] = 255;
    h[9] = 1;
    h[12..16].copy_from_slice(&dst);
    h[16..20].copy_from_slice(&ip[12..16]);
    fix_header(&mut h);
    f.extend_from_slice(&h);
    f.extend_from_slice(&icmp);
    f.resize(60, 0);
    Some(f)
}

/// An ICMP redirect (type 5, codes 0-3) in `frame` to one of `local`:
/// (the destination it is about, the new gateway, who sent it).
pub fn redirect_of(frame: &[u8], local: &[[u8; 4]]) -> Option<([u8; 4], [u8; 4], [u8; 4])> {
    if frame.len() < 34 || frame[12] != 0x08 || frame[13] != 0x00 || frame[23] != 1 {
        return None;
    }
    let ip = &frame[14..];
    let hl = (ip[0] & 15) as usize * 4;
    let to = [ip[16], ip[17], ip[18], ip[19]];
    if ip.len() < hl + 8 + 20 || ip[hl] != 5 || ip[hl + 1] > 3 || !local.contains(&to) {
        return None;
    }
    let gw = [ip[hl + 4], ip[hl + 5], ip[hl + 6], ip[hl + 7]];
    let q = &ip[hl + 8..];
    Some(([q[16], q[17], q[18], q[19]], gw, [ip[12], ip[13], ip[14], ip[15]]))
}

/// Whether the datagram may wait for ARP still.
pub fn expired(w: &Waiting, now: u64) -> bool {
    now >= w.deadline
}

/// The deadline for a datagram that starts waiting now.
pub fn deadline(now: u64) -> u64 {
    now + ARP_WAIT_US
}
