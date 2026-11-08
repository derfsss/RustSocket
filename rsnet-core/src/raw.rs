//! Raw IP sockets (socket(AF_INET, SOCK_RAW, protocol)): what ping and
//! traceroute use. BSD semantics: a sent datagram is the protocol's
//! message and the stack puts the IPv4 header in front (unless IP_HDRINCL:
//! then the program gives the whole packet); a received one is the whole IP
//! packet, header included, and its sender is the header's source. One
//! smoltcp raw socket per interface takes a copy of every packet of the
//! protocol (smoltcp still handles the packet itself, so the stack goes on
//! answering pings while ping runs, as Roadshow does).

use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::raw;
use smoltcp::wire::{IpProtocol, IpVersion};

use crate::sock::Net;

/// IPPROTO_RAW: send-only, the program always gives the header.
pub const IPPROTO_RAW: u8 = 255;

/// One raw socket of a program.
pub struct RawEntry {
    pub proto: u8,
    /// One smoltcp raw socket per interface slot.
    pub socks: Vec<SocketHandle>,
    /// bind's address (the source of what is sent), connect's peer.
    pub bound: Option<[u8; 4]>,
    pub peer: Option<[u8; 4]>,
    /// IP_TTL (None: ip.defttl), IP_HDRINCL.
    pub ttl: Option<u8>,
    pub hdrincl: bool,
    /// The IP identification of the next datagram.
    pub id: u16,
}

pub fn new_socket(proto: u8) -> raw::Socket<'static> {
    let tx = raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; 8], vec![0u8; 8 * 1024]);
    if proto == IPPROTO_RAW {
        // Sends any protocol (smoltcp drops a sent packet whose protocol
        // is not the socket's), receives nothing, as BSD's IPPROTO_RAW: no
        // receive room, so smoltcp drops the copies it would hand it.
        let rx = raw::PacketBuffer::new(vec![], vec![]);
        return raw::Socket::new(Some(IpVersion::Ipv4), None, rx, tx);
    }
    let rx = raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; 16], vec![0u8; 16 * 1024]);
    raw::Socket::new(Some(IpVersion::Ipv4), Some(IpProtocol::from(proto)), rx, tx)
}

impl RawEntry {
    pub fn new(proto: u8, nets: &mut [Net], seed: u16) -> Self {
        let socks = nets.iter_mut().map(|n| n.sockets.add(new_socket(proto))).collect();
        RawEntry { proto, socks, bound: None, peer: None, ttl: None, hdrincl: proto == IPPROTO_RAW, id: seed }
    }

    /// The interface slot with a packet waiting, if any.
    pub fn pending(&self, nets: &mut [Net]) -> Option<usize> {
        self.socks.iter().enumerate().position(|(k, &h)| nets[k].sockets.get::<raw::Socket>(h).can_recv())
    }

    /// The next waiting packet's length.
    pub fn next_len(&self, nets: &mut [Net]) -> usize {
        match self.pending(nets) {
            Some(k) => nets[k].sockets.get_mut::<raw::Socket>(self.socks[k]).peek().map(|p| p.len()).unwrap_or(0),
            None => 0,
        }
    }

    /// The datagram to send to `dst` from `src`: the IPv4 header (unless
    /// the program gave it: then its checksum, total length and an empty
    /// source are filled in) and `data`.
    pub fn packet(&mut self, data: &[u8], src: [u8; 4], dst: [u8; 4], default_ttl: u8) -> Option<Vec<u8>> {
        let mut p;
        if self.hdrincl {
            if data.len() < 20 {
                return None;
            }
            p = data.to_vec();
            let total = p.len() as u16;
            p[2..4].copy_from_slice(&total.to_be_bytes());
            if p[12..16] == [0; 4] {
                p[12..16].copy_from_slice(&src);
            }
        } else {
            let total = 20 + data.len();
            if total > 65535 {
                return None;
            }
            p = vec![0u8; 20];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            self.id = self.id.wrapping_add(1);
            p[4..6].copy_from_slice(&self.id.to_be_bytes());
            p[8] = self.ttl.unwrap_or(default_ttl);
            p[9] = self.proto;
            p[12..16].copy_from_slice(&src);
            p[16..20].copy_from_slice(&dst);
            p.extend_from_slice(data);
        }
        let ihl = ((p[0] & 0x0F) as usize * 4).max(20).min(p.len());
        p[10] = 0;
        p[11] = 0;
        let sum = checksum(&p[..ihl]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        Some(p)
    }
}

/// The Internet checksum of `b`.
pub fn checksum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while s > 0xFFFF {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}
