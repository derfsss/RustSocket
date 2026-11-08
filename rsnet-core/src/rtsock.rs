//! Routing sockets (socket(PF_ROUTE, SOCK_RAW, family)) and the ARP table
//! as routes: what Roadshow's arp and route-style tools use. A program
//! writes an rt_msghdr message (Roadshow's layout, measured: 74 bytes,
//! pack(2), then the sockaddrs named by rtm_addrs, each rounded up to a
//! LONG) and reads the answer back from the same socket: RTM_GET fills in
//! the route or ARP entry, RTM_ADD / RTM_DELETE / RTM_CHANGE act on the
//! routing table or, for a link-level gateway (AF_LINK) or RTF_LLINFO, on
//! the ARP table (smoltcp's neighbor cache: the vendored smoltcp's
//! accessors). A failure sets rtm_errno and the write's errno.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, Ipv4Address};

use crate::sock::Net;

/// rt_msghdr (Roadshow's order: msglen, version, type, index, flags,
/// addrs, pid, seq, errno, use, inits, rmx).
pub mod hdr {
    pub const MSGLEN: usize = 0;
    pub const VERSION: usize = 2;
    pub const TYPE: usize = 3;
    pub const INDEX: usize = 4;
    pub const FLAGS: usize = 6;
    pub const ADDRS: usize = 10;
    pub const PID: usize = 14;
    pub const SEQ: usize = 18;
    pub const ERRNO: usize = 22;
    pub const SIZE: usize = 74;
}

pub const RTM_ADD: u8 = 1;
pub const RTM_DELETE: u8 = 2;
pub const RTM_CHANGE: u8 = 3;
pub const RTM_GET: u8 = 4;

pub const RTA_DST: u32 = 0x1;
pub const RTA_GATEWAY: u32 = 0x2;
pub const RTA_NETMASK: u32 = 0x4;
pub const RTA_IFP: u32 = 0x10;

pub const RTF_UP: u32 = 0x1;
pub const RTF_GATEWAY: u32 = 0x2;
pub const RTF_HOST: u32 = 0x4;
pub const RTF_DONE: u32 = 0x40;
pub const RTF_LLINFO: u32 = 0x400;
pub const RTF_STATIC: u32 = 0x800;

const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;
/// IFT_ETHER.
const IFT_ETHER: u8 = 6;

const EINVAL: i32 = 22;
const ESRCH: i32 = 3;
const ENETUNREACH: i32 = 51;

/// An ARP entry kept this far in the future is static (arp -s).
const STATIC_SECS: i64 = 100 * 365 * 24 * 3600;

/// One ARP table entry: (slot, IPv4 address, MAC, static).
pub type Neighbor = (usize, [u8; 4], [u8; 6], bool);

/// Every interface's ARP entries that are still valid at `now`.
pub fn neighbors(nets: &[Net], now: Instant) -> Vec<Neighbor> {
    let mut v = Vec::new();
    for (k, n) in nets.iter().enumerate() {
        for (ip, hw, exp) in n.iface.neighbors() {
            // IPv4 and Ethernet only in this build (proto-ipv4, medium-ethernet).
            let (IpAddress::Ipv4(a), HardwareAddress::Ethernet(m)) = (ip, hw);
            if exp < now {
                continue;
            }
            v.push((k, a.octets(), m.0, exp.total_micros() / 1_000_000 - now.total_micros() / 1_000_000 > STATIC_SECS / 2));
        }
    }
    v
}

/// LONG-rounded sockaddr length (BSD's ROUNDUP).
fn roundup(len: usize) -> usize {
    if len == 0 { 4 } else { (len + 3) & !3 }
}

/// A sockaddr_in.
pub fn sa_in(a: [u8; 4]) -> Vec<u8> {
    let mut s = vec![0u8; 16];
    s[0] = 16;
    s[1] = AF_INET;
    s[4..8].copy_from_slice(&a);
    s
}

/// A sockaddr_dl for interface slot `k` (index k + 1) with MAC `m`
/// (None: no link address yet).
pub fn sa_dl(k: usize, m: Option<[u8; 6]>) -> Vec<u8> {
    let mut s = vec![0u8; 20];
    s[0] = 20;
    s[1] = AF_LINK;
    s[2..4].copy_from_slice(&((k + 1) as u16).to_be_bytes());
    s[4] = IFT_ETHER;
    s[5] = 0; // sdl_nlen
    if let Some(m) = m {
        s[6] = 6; // sdl_alen
        s[8..14].copy_from_slice(&m);
    }
    s
}

/// The sockaddrs of a message, by RTA_* bit.
struct Addrs {
    dst: Option<[u8; 4]>,
    gw_in: Option<[u8; 4]>,
    gw_link: Option<(u16, Option<[u8; 6]>)>,
    mask: Option<[u8; 4]>,
}

fn parse(msg: &[u8]) -> Option<(u8, u32, u32, Addrs)> {
    if msg.len() < hdr::SIZE {
        return None;
    }
    let ty = msg[hdr::TYPE];
    let flags = u32::from_be_bytes(msg[hdr::FLAGS..hdr::FLAGS + 4].try_into().ok()?);
    let addrs = u32::from_be_bytes(msg[hdr::ADDRS..hdr::ADDRS + 4].try_into().ok()?);
    let mut a = Addrs { dst: None, gw_in: None, gw_link: None, mask: None };
    let mut at = hdr::SIZE;
    for bit in 0..8 {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let len = *msg.get(at)? as usize;
        let fam = *msg.get(at + 1).unwrap_or(&0);
        let sa = msg.get(at..at + len.max(2)).unwrap_or(&[]);
        let ip = |s: &[u8]| (s.len() >= 8).then(|| [s[4], s[5], s[6], s[7]]);
        match 1u32 << bit {
            RTA_DST => a.dst = ip(sa),
            RTA_GATEWAY if fam == AF_LINK && sa.len() >= 8 => {
                let idx = u16::from_be_bytes([sa[2], sa[3]]);
                let (nlen, alen) = (sa[5] as usize, sa[6] as usize);
                let mac = (alen == 6 && sa.len() >= 8 + nlen + 6).then(|| {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(&sa[8 + nlen..8 + nlen + 6]);
                    m
                });
                a.gw_link = Some((idx, mac));
            }
            RTA_GATEWAY => a.gw_in = ip(sa),
            // A netmask may come shortened (sa_len below 8): the rest is 0.
            RTA_NETMASK => {
                let mut m = [0u8; 4];
                for (i, b) in m.iter_mut().enumerate() {
                    *b = *sa.get(4 + i).unwrap_or(&0);
                }
                a.mask = Some(m);
            }
            _ => {}
        }
        at += roundup(len);
    }
    Some((ty, flags, addrs, a))
}

fn prefix_of(m: [u8; 4]) -> u8 {
    u32::from_be_bytes(m).leading_ones() as u8
}

/// The answer to one message written to a routing socket: the reply
/// message, and the errno for the write (0: success).
pub fn handle(msg: &[u8], nets: &mut [Net], routes: &mut crate::route::Table, now: Instant) -> (Vec<u8>, i32) {
    let Some((ty, flags, _, a)) = parse(msg) else { return (msg.to_vec(), EINVAL) };
    let mut out_addrs: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut out_flags = flags;
    let mut index = 0u16;
    let err = match ty {
        RTM_GET => {
            let Some(dst) = a.dst else { return reply(msg, ty, flags, 0, &[], EINVAL) };
            let arp = neighbors(nets, now).into_iter().find(|n| n.1 == dst);
            match (arp, routes.select(nets, dst)) {
                (Some((k, ip, m, st)), _) => {
                    out_flags = RTF_UP | RTF_HOST | RTF_LLINFO | RTF_DONE | if st { RTF_STATIC } else { 0 };
                    index = (k + 1) as u16;
                    out_addrs.push((RTA_DST, sa_in(ip)));
                    out_addrs.push((RTA_GATEWAY, sa_dl(k, Some(m))));
                    out_addrs.push((RTA_IFP, sa_dl(k, None)));
                    0
                }
                (None, Some(k)) => {
                    // The route that would carry it; on a connected subnet
                    // its gateway is the interface's link (no address yet).
                    let r = routes.all(nets).into_iter().filter(|r| r.slot == Some(k) && crate::route::contains(r.dst, r.prefix, dst)).max_by_key(|r| r.prefix);
                    index = (k + 1) as u16;
                    match r {
                        Some(r) => {
                            out_flags = r.flags | RTF_DONE;
                            out_addrs.push((RTA_DST, sa_in(r.dst)));
                            out_addrs.push((RTA_GATEWAY, match r.gateway {
                                Some(g) => sa_in(g),
                                None => sa_dl(k, None),
                            }));
                            out_addrs.push((RTA_NETMASK, sa_in(u32::to_be_bytes(if r.prefix == 0 { 0 } else { u32::MAX << (32 - r.prefix as u32) }))));
                            out_addrs.push((RTA_IFP, sa_dl(k, None)));
                            0
                        }
                        None => ESRCH,
                    }
                }
                (None, None) => ESRCH,
            }
        }
        RTM_ADD | RTM_CHANGE if a.gw_link.is_some() || flags & RTF_LLINFO != 0 => {
            // An ARP entry (arp -s): on the interface the link address
            // names, else the one whose subnet holds the address.
            match (a.dst, a.gw_link.and_then(|g| g.1)) {
                (Some(dst), Some(m)) => {
                    let k = a.gw_link.map(|g| g.0 as usize).filter(|&i| i >= 1 && i <= nets.len()).map(|i| i - 1).or_else(|| routes.select(nets, dst));
                    match k {
                        Some(k) => {
                            let ip = IpAddress::Ipv4(Ipv4Address::new(dst[0], dst[1], dst[2], dst[3]));
                            let exp = now + smoltcp::time::Duration::from_secs(STATIC_SECS as u64);
                            nets[k].iface.neighbor_fill(ip, HardwareAddress::Ethernet(EthernetAddress(m)), exp);
                            0
                        }
                        None => ENETUNREACH,
                    }
                }
                _ => EINVAL,
            }
        }
        RTM_DELETE if flags & RTF_LLINFO != 0 || a.gw_link.is_some() || neighbors(nets, now).iter().any(|n| Some(n.1) == a.dst) => {
            // An ARP entry (arp -d).
            match a.dst {
                Some(dst) => {
                    let ip = IpAddress::Ipv4(Ipv4Address::new(dst[0], dst[1], dst[2], dst[3]));
                    let mut found = false;
                    for n in nets.iter_mut() {
                        found |= n.iface.neighbor_remove(&ip);
                    }
                    if found { 0 } else { ESRCH }
                }
                None => EINVAL,
            }
        }
        RTM_ADD | RTM_DELETE | RTM_CHANGE => {
            let Some(dst) = a.dst else { return reply(msg, ty, flags, 0, &[], EINVAL) };
            let prefix = if flags & RTF_HOST != 0 { 32 } else { a.mask.map(prefix_of).unwrap_or(32) };
            let r = match ty {
                RTM_ADD => a.gw_in.map(|g| routes.add(nets, dst, prefix, g)).unwrap_or(Err(EINVAL)),
                RTM_DELETE => routes.delete(dst, prefix),
                _ => a.gw_in.map(|g| routes.change(nets, dst, prefix, g)).unwrap_or(Err(EINVAL)),
            };
            match r {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        _ => EINVAL,
    };
    if ty != RTM_GET || err != 0 {
        // Writes are answered with the request itself (and its result).
        let mut m = msg.to_vec();
        m[hdr::ERRNO..hdr::ERRNO + 4].copy_from_slice(&err.to_be_bytes());
        if err == 0 {
            let f = flags | RTF_DONE;
            m[hdr::FLAGS..hdr::FLAGS + 4].copy_from_slice(&f.to_be_bytes());
        }
        return (m, err);
    }
    reply(msg, ty, out_flags, index, &out_addrs, 0)
}

/// A reply: the request's header (pid, seq kept) with `flags`, the
/// interface index, rtm_errno and the sockaddrs given.
fn reply(msg: &[u8], ty: u8, flags: u32, index: u16, addrs: &[(u32, Vec<u8>)], err: i32) -> (Vec<u8>, i32) {
    let mut m = msg[..hdr::SIZE.min(msg.len())].to_vec();
    m.resize(hdr::SIZE, 0);
    m[hdr::VERSION] = 3;
    m[hdr::TYPE] = ty;
    m[hdr::INDEX..hdr::INDEX + 2].copy_from_slice(&index.to_be_bytes());
    m[hdr::FLAGS..hdr::FLAGS + 4].copy_from_slice(&flags.to_be_bytes());
    let mut bits = 0u32;
    let mut sorted: Vec<&(u32, Vec<u8>)> = addrs.iter().collect();
    sorted.sort_by_key(|x| x.0);
    for (bit, sa) in sorted {
        bits |= bit;
        let at = m.len();
        m.extend_from_slice(sa);
        m.resize(at + roundup(sa.len()), 0);
    }
    m[hdr::ADDRS..hdr::ADDRS + 4].copy_from_slice(&bits.to_be_bytes());
    m[hdr::ERRNO..hdr::ERRNO + 4].copy_from_slice(&err.to_be_bytes());
    // rmx_expire (rt_metrics at 34, the fourth LONG): non-zero for an ARP
    // entry that expires (arp shows 0 as "permanent").
    if flags & RTF_LLINFO != 0 && flags & RTF_STATIC == 0 {
        m[46..50].copy_from_slice(&60u32.to_be_bytes());
    }
    let len = m.len() as u16;
    m[hdr::MSGLEN..hdr::MSGLEN + 2].copy_from_slice(&len.to_be_bytes());
    (m, err)
}

/// One routing socket: the messages waiting to be read.
#[derive(Default)]
pub struct RouteSock {
    pub queue: VecDeque<Vec<u8>>,
}
