//! Protocol counters for GetNetworkStatistics (NETSTATUS_ip, _tcp, _udp,
//! _icmp), counted from each frame's headers as it passes the PHY
//! (smoltcp keeps none). The tables have BSD's layout as Roadshow's autodoc
//! gives it (the amigaos4 crate's IPSTAT/TCPSTAT/UDPSTAT field lists, which
//! netprof reads from Roadshow). What a header shows is counted: packets and
//! bytes in and out, TCP data / pure ACK / control segments, UDP datagrams,
//! ICMP types, IP version errors; connection events (attempts, accepts,
//! established, closed) come from the socket layer. Retransmissions,
//! retransmission timeouts and duplicate ACKs come from counters in
//! smoltcp (perfhook::count); the rest of smoltcp's inside view
//! (duplicate and out-of-order data, checksum failures) stays 0.

use core::sync::atomic::{AtomicU32, Ordering};

/// ICMP_MAXTYPE + 1.
const ICMP_TYPES: usize = 19;

pub const IP_WORDS: usize = 24;
pub const TCP_WORDS: usize = 52;
pub const UDP_WORDS: usize = 9;
/// icps_error, oldshort, oldicmp, outhist[19], badcode, tooshort, checksum,
/// badlen, reflect, inhist[19].
pub const ICMP_WORDS: usize = 3 + ICMP_TYPES + 5 + ICMP_TYPES;

pub static IP: [AtomicU32; IP_WORDS] = [const { AtomicU32::new(0) }; IP_WORDS];
pub static TCP: [AtomicU32; TCP_WORDS] = [const { AtomicU32::new(0) }; TCP_WORDS];
pub static UDP: [AtomicU32; UDP_WORDS] = [const { AtomicU32::new(0) }; UDP_WORDS];
pub static ICMP: [AtomicU32; ICMP_WORDS] = [const { AtomicU32::new(0) }; ICMP_WORDS];

// ipstat
const IPS_TOTAL: usize = 0;
const IPS_FRAGMENTS: usize = 6;
const IPS_DELIVERED: usize = 13;
const IPS_LOCALOUT: usize = 14;
const IPS_OFRAGMENTS: usize = 18;
const IPS_BADVERS: usize = 22;
// tcpstat
pub const TCPS_CONNATTEMPT: usize = 0;
pub const TCPS_ACCEPTS: usize = 1;
pub const TCPS_CONNECTS: usize = 2;
pub const TCPS_CLOSED: usize = 5;
const TCPS_REXMTTIMEO: usize = 10;
const TCPS_SNDREXMITPACK: usize = 18;
const TCPS_SNDREXMITBYTE: usize = 19;
const TCPS_RCVDUPACK: usize = 41;
const TCPS_SNDTOTAL: usize = 15;
const TCPS_SNDPACK: usize = 16;
const TCPS_SNDBYTE: usize = 17;
const TCPS_SNDACKS: usize = 20;
const TCPS_SNDCTRL: usize = 24;
const TCPS_RCVTOTAL: usize = 25;
const TCPS_RCVPACK: usize = 26;
const TCPS_RCVBYTE: usize = 27;
const TCPS_RCVACKPACK: usize = 43;
// udpstat
const UDPS_IPACKETS: usize = 0;
const UDPS_OPACKETS: usize = 8;
// icmpstat
const ICPS_OUTHIST: usize = 3;
const ICPS_REFLECT: usize = 3 + ICMP_TYPES + 4;
const ICPS_INHIST: usize = 3 + ICMP_TYPES + 5;

fn add(t: &[AtomicU32], i: usize, n: u32) {
    t[i].fetch_add(n, Ordering::Relaxed);
}

/// A TCP connection event (TCPS_* index).
pub fn tcp_event(i: usize) {
    add(&TCP, i, 1);
}

/// Count one Ethernet frame (`rx`: received, else sent).
pub fn frame(f: &[u8], rx: bool) {
    if f.len() < 14 + 20 || f[12] != 0x08 || f[13] != 0x00 {
        return;
    }
    let ip = &f[14..];
    if rx {
        add(&IP, IPS_TOTAL, 1);
    } else {
        add(&IP, IPS_LOCALOUT, 1);
    }
    if ip[0] >> 4 != 4 {
        if rx {
            add(&IP, IPS_BADVERS, 1);
        }
        return;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if frag & 0x3FFF != 0 {
        add(&IP, if rx { IPS_FRAGMENTS } else { IPS_OFRAGMENTS }, 1);
    }
    if rx {
        add(&IP, IPS_DELIVERED, 1);
    }
    // The header must be whole; the body is cut to what the frame holds.
    if ihl < 20 || total < ihl || ip.len() < ihl {
        return;
    }
    let body = &ip[ihl..total.min(ip.len())];
    match ip[9] {
        6 if body.len() >= 20 => {
            let off = ((body[12] >> 4) as usize) * 4;
            let flags = body[13];
            let payload = body.len().saturating_sub(off) as u32;
            if rx {
                add(&TCP, TCPS_RCVTOTAL, 1);
                if payload > 0 {
                    add(&TCP, TCPS_RCVPACK, 1);
                    add(&TCP, TCPS_RCVBYTE, payload);
                } else if flags & 0x10 != 0 {
                    add(&TCP, TCPS_RCVACKPACK, 1);
                }
            } else {
                add(&TCP, TCPS_SNDTOTAL, 1);
                if payload > 0 {
                    add(&TCP, TCPS_SNDPACK, 1);
                    add(&TCP, TCPS_SNDBYTE, payload);
                } else if flags & 0x07 != 0 {
                    // SYN, FIN or RST.
                    add(&TCP, TCPS_SNDCTRL, 1);
                } else {
                    add(&TCP, TCPS_SNDACKS, 1);
                }
            }
        }
        17 => add(&UDP, if rx { UDPS_IPACKETS } else { UDPS_OPACKETS }, 1),
        1 if !body.is_empty() => {
            let t = body[0] as usize;
            if t < ICMP_TYPES {
                add(&ICMP, if rx { ICPS_INHIST } else { ICPS_OUTHIST } + t, 1);
            }
            // An echo reply sent is a response to a request.
            if !rx && t == 0 {
                add(&ICMP, ICPS_REFLECT, 1);
            }
        }
        _ => {}
    }
}

/// A copy of a table as big-endian LONGs (the caller's layout).
pub fn snapshot(t: &[AtomicU32]) -> alloc::vec::Vec<u8> {
    if core::ptr::eq(t, &TCP[..]) {
        sync_smoltcp();
    }
    t.iter().flat_map(|c| c.load(Ordering::Relaxed).to_be_bytes()).collect()
}

/// The loss counters smoltcp keeps (perfhook::count) into tcpstat.
fn sync_smoltcp() {
    use smoltcp::perfhook::count;
    for (i, c) in [
        (TCPS_REXMTTIMEO, &count::RTO),
        (TCPS_SNDREXMITPACK, &count::REXMIT_PACK),
        (TCPS_SNDREXMITBYTE, &count::REXMIT_BYTE),
        (TCPS_RCVDUPACK, &count::DUPACK),
    ] {
        TCP[i].store(c.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}
