//! `rstcp raw [library] [host]`: raw ICMP sockets (what ping and traceroute
//! use): an echo request to QEMU's host side through SOCK_RAW/IPPROTO_ICMP,
//! the reply read with its IP header, IP_TTL read back, and a UDP datagram
//! with TTL 1 drawing an ICMP time-exceeded (traceroute's first hop) when
//! the host is a router away (otherwise skipped).

use alloc::vec::Vec;
use core::ffi::c_void;

use amigaos4::bsdsocket::SocketLib;
use amigaos4::sys::SocketIFace;

use super::Tally;

fn checksum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while s > 0xFFFF {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

fn sockaddr(a: [u8; 4]) -> [u8; 16] {
    let mut s = [0u8; 16];
    s[0] = 16;
    s[1] = 2;
    s[4..8].copy_from_slice(&a);
    s
}

pub fn run(lib: &SocketLib, host: [u8; 4], t: &mut Tally) {
    let i: *mut SocketIFace = lib.iface();
    // SAFETY: plain calls with buffers of the sizes given.
    unsafe {
        let s = ((*i).socket)(i, 2, 3, 1);
        t.check(s >= 0, format_args!("raw: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = {} (errno {})", s, ((*i).Errno)(i)));
        if s < 0 {
            return;
        }
        let timeout: [u32; 2] = [2, 0];
        ((*i).setsockopt)(i, s, 0xffff, 0x1006, timeout.as_ptr() as *mut c_void, 8);
        let mut pkt: Vec<u8> = alloc::vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
        pkt.extend_from_slice(b"rustsocket raw ping");
        let c = checksum(&pkt);
        pkt[2..4].copy_from_slice(&c.to_be_bytes());
        let to = sockaddr(host);
        let n = ((*i).sendto)(i, s, pkt.as_ptr() as *mut c_void, pkt.len() as i32, 0, to.as_ptr() as *mut c_void, 16);
        t.check(n == pkt.len() as i32, format_args!("raw: sendto an echo request: {} (errno {})", n, ((*i).Errno)(i)));
        let mut buf = [0u8; 256];
        let mut from = [0u8; 16];
        let mut flen: u32 = 16;
        let mut got = -1;
        let t0 = super::us();
        // The first packet back may be our own request's copy on a looped
        // path; read until the reply or the timeout.
        for _ in 0..4 {
            got = ((*i).recvfrom)(i, s, buf.as_mut_ptr() as *mut c_void, buf.len() as i32, 0, from.as_mut_ptr() as *mut c_void, &mut flen);
            if got < 28 || buf[20] == 0 {
                break;
            }
        }
        let ms = (super::us() - t0) / 1000;
        let ok = got >= 28 && buf[0] >> 4 == 4 && buf[9] == 1 && buf[20] == 0 && buf[24..26] == [0x12, 0x34] && from[4..8] == host;
        t.check(
            ok,
            format_args!(
                "raw: recvfrom the echo reply with its IP header: {} bytes in {} ms (errno {}), proto {}, type {}, id {:02x}{:02x}, from {:?}",
                got, ms, ((*i).Errno)(i), buf[9], buf[20], buf[24], buf[25], &from[4..8]
            ),
        );
        let mut ttl: u32 = 0;
        let mut tl: u32 = 4;
        let set: u32 = 7;
        ((*i).setsockopt)(i, s, 0, 4, &set as *const u32 as *mut c_void, 4);
        ((*i).getsockopt)(i, s, 0, 4, &mut ttl as *mut u32 as *mut c_void, &mut tl);
        t.check(ttl == 7, format_args!("raw: IP_TTL 7 read back: {}", ttl));
        ((*i).CloseSocket)(i, s);
    }
}
