//! The IP filter hook (SocketBaseTagList SBTC_IP_FILTER_HOOK, API version 1
//! as Roadshow reports it): called for every IPv4 datagram an interface
//! receives (before the stack sees it) and sends, with an IPFilterMsg and
//! the datagram as an mbuf chain (mbuf.rs). A non-zero result or a NULL
//! ifm_Packet drops it; a different ifm_Packet replaces it.
//!
//! As measured on Roadshow (`rstcp ipf`): ifm_Size 24,
//! ifm_IPLength the header's length, the datagram in one M_PKTHDR mbuf
//! (pkthdr.len = the IP total length).
//!
//! ifm_Interface points to a small BSD-style struct ifnet per interface:
//! if_name (char *) at 0, if_index (UWORD) at 20, if_unit (WORD) at 22;
//! the rest is zero (Roadshow's own is not documented).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::mbuf;

pub const API_VERSION: u32 = 1;

static HOOK: AtomicU32 = AtomicU32::new(0);

pub fn hook() -> u32 {
    HOOK.load(Ordering::Acquire)
}

pub fn set_hook(h: u32) {
    HOOK.store(h, Ordering::Release);
}

/// The fake ifnet records, one per slot, kept while the stack runs.
static IFNETS: AtomicU32 = AtomicU32::new(0);

/// The library's last Close, after the stack has stopped: the ifnet
/// records and the hook go (no opener is left to have set one or to keep
/// a record's pointer).
pub fn free() {
    HOOK.store(0, Ordering::Release);
    let t = IFNETS.swap(0, Ordering::AcqRel) as *mut [[u32; 32]; crate::stack::MAX_SLOTS];
    if !t.is_null() {
        // SAFETY: the Box set_ifnet made, taken out of the static once.
        drop(unsafe { Box::from_raw(t) });
    }
}

/// Make (once) or name slot `slot`'s ifnet: `name` NUL-terminated.
pub fn set_ifnet(slot: u8, name: &str) {
    if slot as usize >= crate::stack::MAX_SLOTS {
        return;
    }
    let mut t = IFNETS.load(Ordering::Acquire) as *mut [[u32; 32]; crate::stack::MAX_SLOTS];
    if t.is_null() {
        let b = Box::into_raw(Box::new([[0u32; 32]; crate::stack::MAX_SLOTS]));
        match IFNETS.compare_exchange(0, b as u32, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => t = b,
            Err(other) => {
                // SAFETY: ours, never shared.
                drop(unsafe { Box::from_raw(b) });
                t = other as *mut _;
            }
        }
    }
    // SAFETY: the table made above (freed only by `free`, at the last
    // Close); the name goes in words 8.. (32 bytes) of the record.
    unsafe {
        let r = &mut (*t)[slot as usize];
        let base = r.as_mut_ptr() as *mut u8;
        core::ptr::write_bytes(base, 0, 128);
        let n = name.len().min(15);
        core::ptr::copy_nonoverlapping(name.as_ptr(), base.add(32), n);
        core::ptr::write_unaligned(base as *mut u32, base.add(32) as u32);
        core::ptr::write_unaligned(base.add(20) as *mut u16, slot as u16 + 1);
        let unit = name.bytes().rev().take_while(|b| b.is_ascii_digit()).count();
        let u = name[name.len() - unit..].parse::<u16>().unwrap_or(0);
        core::ptr::write_unaligned(base.add(22) as *mut u16, u);
    }
}

/// The ifnet of the interface named `name`, if one has it (the IP filter's
/// rules name their interface).
pub fn ifnet_by_name(name: &[u8]) -> Option<u32> {
    let t = IFNETS.load(Ordering::Acquire) as *mut [[u32; 32]; crate::stack::MAX_SLOTS];
    if t.is_null() {
        return None;
    }
    (0..crate::stack::MAX_SLOTS).find_map(|k| {
        // SAFETY: the table set_ifnet made; the name is in bytes 32..48,
        // NUL-terminated.
        let r = unsafe { core::slice::from_raw_parts((*t)[k].as_ptr() as *const u8, 128) };
        let n = &r[32..48];
        let l = n.iter().position(|&c| c == 0).unwrap_or(16);
        // Roadshow's ipf ignores case ("LOOPBACK" names its loopback).
        (l > 0 && n[..l].eq_ignore_ascii_case(name)).then(|| r.as_ptr() as u32)
    })
}

/// The name (16 bytes, NUL-padded) of the interface whose ifnet is `ifp`;
/// zeros for anything else.
pub fn ifnet_name(ifp: u32) -> [u8; 16] {
    let mut n = [0u8; 16];
    let t = IFNETS.load(Ordering::Acquire) as *mut [[u32; 32]; crate::stack::MAX_SLOTS];
    if t.is_null() {
        return n;
    }
    for k in 0..crate::stack::MAX_SLOTS {
        // SAFETY: the table set_ifnet made; a record is 128 bytes, its
        // name in bytes 32..48.
        let r = unsafe { core::slice::from_raw_parts((*t)[k].as_ptr() as *const u8, 128) };
        if r.as_ptr() as u32 == ifp {
            n.copy_from_slice(&r[32..48]);
            break;
        }
    }
    n
}

/// The interface slot whose ifnet is `ifp`.
pub fn slot_of(ifp: u32) -> Option<u8> {
    (0..crate::stack::MAX_SLOTS as u8).find(|&k| ifp != 0 && ifnet(k) == ifp)
}

/// Interface `slot`'s ifnet (0 when it has none).
pub fn ifnet(slot: u8) -> u32 {
    let t = IFNETS.load(Ordering::Acquire) as *mut [[u32; 32]; crate::stack::MAX_SLOTS];
    if t.is_null() || slot as usize >= crate::stack::MAX_SLOTS {
        return 0;
    }
    // SAFETY: the table set_ifnet made.
    unsafe { (*t)[slot as usize].as_ptr() as u32 }
}

/// An Ethernet frame of `len` bytes in `buf` (room for the largest frame):
/// run the IP filter (ipfil.rs: ipf's rules), then the hook, on its IPv4
/// datagram. The frame's new length (a replaced datagram is written in
/// place), or None to drop it.
///
/// `reply` (on receive) takes a frame to send back for a blocked one
/// (return-rst, return-icmp).
pub fn filter(slot: u8, buf: &mut [u8], len: usize, rx: bool, reply: Option<&mut Option<Vec<u8>>>) -> Option<usize> {
    if len < 34 || buf[12] != 0x08 || buf[13] != 0x00 {
        return Some(len);
    }
    let on = crate::ipfil::running();
    // NAT (ipnat.rs): what comes in is translated before the rules.
    if on && rx {
        crate::ipnat::nat_in(ifnet(slot), &mut buf[14..len], crate::ipfil::now());
    }
    let mut answer = None;
    if !crate::ipfil::check(ifnet(slot), &buf[..14], &buf[14..len], !rx, &mut answer) {
        // return-rst / return-icmp: back to the sender's Ethernet address
        // (not to a broadcast or multicast one).
        if let (Some(ip), Some(reply)) = (answer, reply) {
            if buf[0] & 1 == 0 {
                let mut f = Vec::with_capacity(14 + ip.len());
                f.extend_from_slice(&buf[6..12]);
                f.extend_from_slice(&buf[0..6]);
                f.extend_from_slice(&[0x08, 0x00]);
                f.extend_from_slice(&ip);
                if f.len() < 60 {
                    f.resize(60, 0);
                }
                *reply = Some(f);
            }
        }
        return None;
    }
    // ... and what goes out after them.
    if on && !rx {
        crate::ipnat::nat_out(ifnet(slot), &mut buf[14..len], crate::ipfil::now());
    }
    let h = hook();
    if h == 0 {
        return Some(len);
    }
    let ip = &buf[14..len];
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let total = (u16::from_be_bytes([ip[2], ip[3]]) as usize).min(ip.len());
    if ip[0] >> 4 != 4 || ihl < 20 || total < ihl {
        return Some(len);
    }
    let m = mbuf::from_bytes(&ip[..total], ifnet(slot))?;
    // struct IPFilterMsg: size, ip, ip length, interface, direction, packet.
    let mut msg: [u32; 6] = [24, mbuf::data(m) as u32, ihl as u32, ifnet(slot), if rx { 0 } else { 1 }, m as u32];
    let r = crate::monitor::call(h, msg.as_mut_ptr() as *mut core::ffi::c_void);
    let p = msg[5] as mbuf::M;
    if r != 0 || p == 0 {
        mbuf::freem(p);
        return None;
    }
    if p == m {
        mbuf::freem(m);
        return Some(len);
    }
    // A replacement: its bytes after our Ethernet header.
    let bytes: Vec<u8> = mbuf::to_vec(p);
    mbuf::freem(p);
    let n = 14 + bytes.len();
    if n > buf.len() || bytes.len() < 20 {
        return None;
    }
    buf[14..n].copy_from_slice(&bytes);
    // Ethernet's minimum: what is short is padded with zeros.
    Some(if n < 60 {
        buf[n..60].fill(0);
        60
    } else {
        n
    })
}
