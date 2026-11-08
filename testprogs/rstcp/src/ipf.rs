//! `rstcp ipf [library] [host]`: the IP filter hook (SBTC_IP_FILTER_HOOK)
//! and the mbuf calls it uses, measured on Roadshow and compared: the
//! IPFilterMsg, the packet's mbuf chain, dropping by result and by a NULL
//! packet, and mbuf_get/gethdr/free/freem/copym/copydata/copyback/prepend/
//! cat/adj/pullup run inside the hook on a copy of a packet.

use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use alloc::vec::Vec;

use amigaos4::bsdsocket::SocketLib;
use amigaos4::hook::Hook;
use amigaos4::sys::SocketIFace;

use super::{Out, Tally};
use core::fmt::Write;

static IFACE: AtomicU32 = AtomicU32::new(0);
/// 0: watch; 1: refuse incoming ICMP (EACCES); 2: NULL the outgoing ICMP
/// packet; 3: replace the incoming reply with a changed copy (its
/// identifier byte flipped and back: the same bytes, through the calls).
static MODE: AtomicU32 = AtomicU32::new(0);
static SEEN_IN: AtomicU32 = AtomicU32::new(0);
static SEEN_OUT: AtomicU32 = AtomicU32::new(0);
/// The first ICMP packet's facts: size, IP length, direction, first
/// mbuf's flags, pkthdr.len, chain length, mbufs, IP total, copydata ok.
static FACTS: [AtomicI32; 9] = [const { AtomicI32::new(-1) }; 9];
/// The mbuf calls' checks, a bit each (set when right).
static CALLS: AtomicU32 = AtomicU32::new(0);
static CALLS_DONE: AtomicU32 = AtomicU32::new(0);
/// Details of the mbuf checks: gl, l3, l4, pullup's first m_len (-1:
/// NULL), the original's first word before and after.
static DBG: [AtomicI32; 6] = [const { AtomicI32::new(-9) }; 6];

fn rd32(p: u32, at: u32) -> u32 {
    // SAFETY: inside an mbuf the stack gave the hook.
    unsafe { u32::from_be(core::ptr::read_unaligned((p + at) as *const u32)) }
}
fn rd16(p: u32, at: u32) -> u16 {
    // SAFETY: as rd32.
    unsafe { u16::from_be(core::ptr::read_unaligned((p + at) as *const u16)) }
}

/// The chain's (mbufs, total m_len).
fn chain(mut m: u32) -> (i32, i32) {
    let (mut n, mut len) = (0, 0);
    while m != 0 && n < 1000 {
        n += 1;
        len += rd32(m, 12) as i32;
        m = rd32(m, 0);
    }
    (n, len)
}

/// The mbuf calls on a copy of packet `m`.
unsafe fn calls(i: *mut SocketIFace, m: *mut c_void, total: usize) -> u32 {
    let mut ok = 0u32;
    let mut want = alloc::vec![0u8; total];
    let r = ((*i).mbuf_copydata)(i, m, 0, total as i32, want.as_mut_ptr() as *mut c_void);
    let c = ((*i).mbuf_copym)(i, m, 0, 1_000_000_000);
    let mut got = alloc::vec![0u8; total];
    if !c.is_null() {
        ((*i).mbuf_copydata)(i, c, 0, total as i32, got.as_mut_ptr() as *mut c_void);
    }
    ok |= ((r == 0 || r == total as i32) && !c.is_null() && got == want) as u32; // bit 0: copym + copydata
    // prepend 8 bytes, then adj them off again.
    let p = ((*i).mbuf_prepend)(i, c, 8);
    let (n1, l1) = chain(p as u32);
    let a = ((*i).mbuf_adj)(i, p, 8);
    let (_, l2) = chain(p as u32);
    ok |= ((!p.is_null() && l1 == total as i32 + 8 && l2 == total as i32) as u32) << 1; // bit 1: prepend + adj
    let _ = (n1, a);
    // trim 4 from the tail (negative adj).
    ((*i).mbuf_adj)(i, p, -4);
    let (_, l3) = chain(p as u32);
    ok |= ((l3 == total as i32 - 4) as u32) << 2; // bit 2: adj from the end
    // copyback: write 4 bytes at 0 and read them back.
    let mark = [0xde_u8, 0xad, 0xbe, 0xef];
    let cb = ((*i).mbuf_copyback)(i, p, 0, 4, mark.as_ptr() as *mut c_void);
    let mut back = [0u8; 4];
    ((*i).mbuf_copydata)(i, p, 0, 4, back.as_mut_ptr() as *mut c_void);
    ok |= ((back == mark) as u32) << 3; // bit 3: copyback
    let _ = cb;
    // a new mbuf with 16 bytes, cat'ed on.
    let g = ((*i).mbuf_get)(i);
    let h = ((*i).mbuf_gethdr)(i);
    ok |= ((!g.is_null() && !h.is_null() && rd16(h as u32, 18) & 2 != 0 && rd16(g as u32, 18) & 2 == 0) as u32) << 4; // bit 4: get/gethdr flags
    if !g.is_null() {
        let zeros = [7u8; 16];
        ((*i).mbuf_copyback)(i, g, 0, 16, zeros.as_ptr() as *mut c_void);
        let (_, gl) = chain(g as u32);
        ((*i).mbuf_cat)(i, p, g);
        let (_, l4) = chain(p as u32);
        DBG[0].store(gl, Ordering::Relaxed);
        DBG[1].store(l3, Ordering::Relaxed);
        DBG[2].store(l4, Ordering::Relaxed);
        ok |= ((gl == 16 && l4 == l3 + 16) as u32) << 5; // bit 5: copyback into an empty mbuf + cat
    }
    // pullup 40 bytes into the first mbuf.
    let pu = ((*i).mbuf_pullup)(i, p, 40);
    DBG[3].store(if pu.is_null() { -1 } else { rd32(pu as u32, 12) as i32 }, Ordering::Relaxed);
    ok |= ((!pu.is_null() && rd32(pu as u32, 12) >= 40) as u32) << 6; // bit 6: pullup
    let next = ((*i).mbuf_free)(i, h);
    ok |= (next.is_null() as u32) << 7; // bit 7: free returns the next (none)
    if !pu.is_null() {
        ((*i).mbuf_freem)(i, pu);
    }
    ok
}

fn hook(_o: *mut c_void, msg: *mut c_void) -> u32 {
    let i = IFACE.load(Ordering::Relaxed) as *mut SocketIFace;
    let ifm = msg as u32;
    let ip = rd32(ifm, 4);
    // SAFETY: the IP header the stack points to.
    let proto = unsafe { *((ip + 9) as *const u8) };
    if proto != 1 {
        return 0;
    }
    let dir = rd32(ifm, 16);
    let m = rd32(ifm, 20);
    if dir == 0 { &SEEN_IN } else { &SEEN_OUT }.fetch_add(1, Ordering::Relaxed);
    let total = rd16(ip, 2) as usize;
    if FACTS[0].load(Ordering::Relaxed) == -1 {
        let (n, len) = chain(m);
        let mut buf = alloc::vec![0u8; total];
        // SAFETY: a call on the library's interface with a buffer of `total`.
        unsafe { ((*i).mbuf_copydata)(i, m as *mut c_void, 0, total as i32, buf.as_mut_ptr() as *mut c_void) };
        // SAFETY: the IP header, 20 bytes at least.
        let head = unsafe { core::slice::from_raw_parts(ip as *const u8, 20) };
        let vals = [rd32(ifm, 0) as i32, rd32(ifm, 8) as i32, dir as i32, rd16(m, 18) as i32, rd32(m, 24) as i32, len, n, total as i32, (buf[..20] == *head) as i32];
        for (f, v) in FACTS.iter().zip(vals) {
            f.store(v, Ordering::Relaxed);
        }
    }
    // SAFETY: the type byte follows the IP header.
    let icmp_type = unsafe { *((ip + 4 * (*(ip as *const u8) as u32 & 15)) as *const u8) };
    if dir == 0 && icmp_type == 0 && CALLS_DONE.swap(1, Ordering::Relaxed) == 0 {
        DBG[4].store(rd32(ip, 0) as i32, Ordering::Relaxed);
        // SAFETY: the calls on a copy; the packet itself is read only.
        CALLS.store(unsafe { calls(i, m as *mut c_void, total) }, Ordering::Relaxed);
        DBG[5].store(rd32(ip, 0) as i32, Ordering::Relaxed);
    }
    match MODE.load(Ordering::Relaxed) {
        1 if dir == 0 => 13,
        2 if dir == 1 => {
            // SAFETY: the message's ifm_Packet: freed here, then NULL.
            unsafe {
                ((*i).mbuf_freem)(i, m as *mut c_void);
                core::ptr::write_unaligned((ifm + 20) as *mut u32, 0);
            }
            0
        }
        3 if dir == 0 && icmp_type == 0 => {
            // SAFETY: a copy put in place of the packet, the old one freed.
            unsafe {
                let c = ((*i).mbuf_copym)(i, m as *mut c_void, 0, 1_000_000_000);
                if !c.is_null() {
                    ((*i).mbuf_freem)(i, m as *mut c_void);
                    core::ptr::write_unaligned((ifm + 20) as *mut u32, (c as u32).to_be());
                }
            }
            0
        }
        _ => 0,
    }
}

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

/// An echo through a raw socket: whether its reply came within a second.
fn ping(i: *mut SocketIFace, host: [u8; 4], seq: u16) -> bool {
    // SAFETY: plain calls with buffers of their sizes.
    unsafe {
        let s = ((*i).socket)(i, 2, 3, 1);
        let tv: [u32; 2] = [1, 0];
        ((*i).setsockopt)(i, s, 0xffff, 0x1006, tv.as_ptr() as *mut c_void, 8);
        let mut p = alloc::vec![8u8, 0, 0, 0, 0x69, 0x70, (seq >> 8) as u8, seq as u8, 1, 2, 3, 4];
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
        let mut to = [0u8; 16];
        to[0] = 16;
        to[1] = 2;
        to[4..8].copy_from_slice(&host);
        ((*i).sendto)(i, s, p.as_ptr() as *mut c_void, p.len() as i32, 0, to.as_ptr() as *mut c_void, 16);
        let mut buf = [0u8; 128];
        let mut got = false;
        for _ in 0..3 {
            let n = ((*i).recv)(i, s, buf.as_mut_ptr() as *mut c_void, 128, 0);
            if n < 0 {
                break;
            }
            if n >= 28 && buf[20] == 0 && buf[24] == 0x69 && buf[27] == seq as u8 {
                got = true;
                break;
            }
        }
        ((*i).CloseSocket)(i, s);
        got
    }
}

pub fn run(lib: &SocketLib, host: [u8; 4], t: &mut Tally) {
    let i = lib.iface();
    IFACE.store(i as u32, Ordering::Relaxed);
    let version = lib.get_base_value(58);
    let before = lib.get_base_value(62);
    say!("ipf: SBTC_IPF_API_VERSION {:?}, SBTC_IP_FILTER_HOOK {:?}", version, before);
    // The undocumented ipf_* device calls: implemented or not?
    for minor in [0, 1, 2, 3] {
        // SAFETY: plain calls on an open interface.
        let (r, e) = unsafe { (((*i).ipf_open)(i, minor), ((*i).Errno)(i)) };
        // SAFETY: as above.
        let w = if r >= 0 { unsafe { ((*i).ipf_log_data_waiting)(i, r) } } else { -2 };
        say!("ipf: ipf_open({}) = {} errno {}; log_data_waiting {}", minor, r, e, w);
        if r >= 0 {
            // SAFETY: as above.
            unsafe { ((*i).ipf_close)(i, r) };
        }
    }
    let Ok(h) = Hook::new(hook) else {
        t.check(false, format_args!("ipf: no hook"));
        return;
    };
    let set = lib.set_base_value(62, h.as_ptr() as u32);
    let now = lib.get_base_value(62);
    t.check(set.is_ok() && now.as_ref().ok() == Some(&(h.as_ptr() as u32)), format_args!("ipf: hook installed {:?}, read back {:?}", set.is_ok(), now.map(|v| v == h.as_ptr() as u32)));
    let ok = ping(i, host, 1);
    let facts: Vec<i32> = FACTS.iter().map(|f| f.load(Ordering::Relaxed)).collect();
    say!("ipf: first ICMP packet: ifm_Size {} ifm_IPLength {} direction {} m_flags {:#x} pkthdr.len {} chain len {} mbufs {} IP total {} copydata = ifm_IP {}", facts[0], facts[1], facts[2], facts[3], facts[4], facts[5], facts[6], facts[7], facts[8]);
    t.check(ok && SEEN_IN.load(Ordering::Relaxed) >= 1 && SEEN_OUT.load(Ordering::Relaxed) >= 1, format_args!("ipf: ping passes; hook saw {} in, {} out", SEEN_IN.load(Ordering::Relaxed), SEEN_OUT.load(Ordering::Relaxed)));
    t.check(facts[5] == facts[7] && facts[4] == facts[7] && facts[8] == 1 && facts[3] & 2 != 0, format_args!("ipf: the chain holds the whole packet, M_PKTHDR set"));
    let c = CALLS.load(Ordering::Relaxed);
    say!("ipf: mbuf calls in the hook: {:#010b} (bits: copym+copydata, prepend+adj, adj tail, copyback, get/gethdr, cat, pullup, free)", c);
    let d: Vec<i32> = DBG.iter().map(|f| f.load(Ordering::Relaxed)).collect();
    say!("ipf: detail: copyback into m_get {} bytes, chain {} then {} after cat, pullup first m_len {}, packet word {:#x} -> {:#x}", d[0], d[1], d[2], d[3], d[4], d[5]);
    t.check(c == 0xff, format_args!("ipf: all eight mbuf checks ({:#x})", c));
    MODE.store(1, Ordering::Relaxed);
    let refused = !ping(i, host, 2);
    MODE.store(2, Ordering::Relaxed);
    let nulled = !ping(i, host, 3);
    MODE.store(3, Ordering::Relaxed);
    let replaced = ping(i, host, 4);
    MODE.store(0, Ordering::Relaxed);
    t.check(refused && nulled && replaced, format_args!("ipf: a refused reply drops it {}, a NULL packet drops it {}, a replaced copy passes {}", refused, nulled, replaced));
    let _ = lib.set_base_value(62, 0);
    let n = SEEN_IN.load(Ordering::Relaxed);
    let back = ping(i, host, 5);
    t.check(back && SEEN_IN.load(Ordering::Relaxed) == n && lib.get_base_value(62).ok() == Some(0), format_args!("ipf: hook removed: ping passes, not called"));
}
