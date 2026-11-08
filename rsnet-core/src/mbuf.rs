//! mbufs as the SDK's sys/mbuf.h lays them out (pack(2), MSIZE 128,
//! aligned to MSIZE so dtom() works, 2048-byte clusters) and the BSD 4.4
//! routines the library offers as mbuf_* (for IP filter hooks).
//!
//! Copies are deep (clusters are not shared): a hook that changes a copy
//! never changes the packet it copied, as the autodoc's "make a copy,
//! release the old packet" asks. Roadshow's mbuf_copym shared the data
//! (a write to the copy changed the packet) and its
//! mbuf_cat did not lengthen the chain; rustsocket does what the autodoc
//! and BSD say.
//!
//! Every pointer here is an mbuf this module made (a hook gets them from
//! the packet or the calls).

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::ptr::{read_unaligned as rd, write_unaligned as wr};

pub const MSIZE: usize = 128;
pub const MCLBYTES: usize = 2048;
const M_HDR: usize = 20;
pub const MLEN: usize = MSIZE - M_HDR;
pub const MHLEN: usize = MLEN - 8;
pub const M_EXT: u16 = 0x0001;
pub const M_PKTHDR: u16 = 0x0002;
const M_COPYFLAGS: u16 = 0x0002 | 0x0004 | 0x0100 | 0x0200;
pub const M_COPYALL: i32 = 1_000_000_000;
const MT_DATA: u16 = 1;

// Field offsets.
const NEXT: usize = 0;
const NEXTPKT: usize = 4;
const DATA: usize = 8;
const LEN: usize = 12;
const TYPE: usize = 16;
const FLAGS: usize = 18;
const RCVIF: usize = 20;
const PKTLEN: usize = 24;
const EXT_BUF: usize = 28;
const EXT_FREE: usize = 32;
const EXT_SIZE: usize = 36;
const DAT: usize = 20;
const PKTDAT: usize = 28;

pub type M = usize;

fn g32(m: M, at: usize) -> u32 {
    // SAFETY: an mbuf of ours (MSIZE bytes).
    unsafe { rd((m + at) as *const u32) }
}
fn s32(m: M, at: usize, v: u32) {
    // SAFETY: as g32.
    unsafe { wr((m + at) as *mut u32, v) }
}
fn g16(m: M, at: usize) -> u16 {
    // SAFETY: as g32.
    unsafe { rd((m + at) as *const u16) }
}
fn s16(m: M, at: usize, v: u16) {
    // SAFETY: as g32.
    unsafe { wr((m + at) as *mut u16, v) }
}

pub fn next(m: M) -> M {
    g32(m, NEXT) as M
}
pub fn len(m: M) -> usize {
    g32(m, LEN) as usize
}
pub fn data(m: M) -> usize {
    g32(m, DATA) as usize
}
pub fn flags(m: M) -> u16 {
    g16(m, FLAGS)
}
fn set_len(m: M, n: usize) {
    s32(m, LEN, n as u32);
}
fn set_data(m: M, p: usize) {
    s32(m, DATA, p as u32);
}

/// The data area's start and size.
fn area(m: M) -> (usize, usize) {
    let f = flags(m);
    if f & M_EXT != 0 {
        (g32(m, EXT_BUF) as usize, g32(m, EXT_SIZE) as usize)
    } else if f & M_PKTHDR != 0 {
        (m + PKTDAT, MHLEN)
    } else {
        (m + DAT, MLEN)
    }
}

fn leading(m: M) -> usize {
    data(m) - area(m).0
}
fn trailing(m: M) -> usize {
    let (a, n) = area(m);
    a + n - (data(m) + len(m))
}

/// m_get / m_gethdr: a zeroed mbuf.
pub fn get(hdr: bool) -> Option<M> {
    // SAFETY: a non-zero size and power-of-two alignment.
    let m = unsafe { alloc_zeroed(Layout::from_size_align(MSIZE, MSIZE).ok()?) } as M;
    if m == 0 {
        return None;
    }
    s16(m, TYPE, MT_DATA);
    if hdr {
        s16(m, FLAGS, M_PKTHDR);
        set_data(m, m + PKTDAT);
    } else {
        set_data(m, m + DAT);
    }
    Some(m)
}

/// Give `m` a cluster (M_EXT, 2048 bytes).
fn clget(m: M) -> bool {
    let Ok(l) = Layout::from_size_align(MCLBYTES, 4) else { return false };
    // SAFETY: a non-zero layout.
    let c = unsafe { alloc_zeroed(l) } as usize;
    if c == 0 {
        return false;
    }
    s32(m, EXT_BUF, c as u32);
    s32(m, EXT_FREE, 0);
    s32(m, EXT_SIZE, MCLBYTES as u32);
    s16(m, FLAGS, flags(m) | M_EXT);
    set_data(m, c);
    true
}

/// m_free: free one mbuf; the next in its chain.
pub fn free(m: M) -> M {
    if m == 0 {
        return 0;
    }
    let n = next(m);
    if flags(m) & M_EXT != 0 && g32(m, EXT_FREE) == 0 {
        let size = g32(m, EXT_SIZE) as usize;
        if let Ok(l) = Layout::from_size_align(size.max(1), 4) {
            // SAFETY: a cluster clget made with this size.
            unsafe { dealloc(g32(m, EXT_BUF) as *mut u8, l) };
        }
    }
    // SAFETY: an mbuf `get` made.
    unsafe { dealloc(m as *mut u8, Layout::from_size_align_unchecked(MSIZE, MSIZE)) };
    n
}

/// m_freem: free a whole chain.
pub fn freem(mut m: M) {
    while m != 0 {
        m = free(m);
    }
}

/// The chain's length (sum of m_len).
pub fn total(mut m: M) -> usize {
    let mut n = 0;
    while m != 0 {
        n += len(m);
        m = next(m);
    }
    n
}

/// A packet-header chain holding `bytes` (one mbuf, with a cluster when
/// it does not fit): the IP filter's packet.
pub fn from_bytes(bytes: &[u8], rcvif: u32) -> Option<M> {
    let m = get(true)?;
    if bytes.len() > MHLEN && (bytes.len() > MCLBYTES || !clget(m)) {
        free(m);
        return None;
    }
    // SAFETY: the data area holds `bytes`.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), data(m) as *mut u8, bytes.len()) };
    set_len(m, bytes.len());
    s32(m, PKTLEN, bytes.len() as u32);
    s32(m, RCVIF, rcvif);
    Some(m)
}

/// m_copydata: `n` bytes from `off` into `out`; false when the chain is
/// shorter.
pub fn copydata(mut m: M, mut off: usize, mut n: usize, mut out: *mut u8) -> bool {
    while m != 0 && off >= len(m) {
        off -= len(m);
        m = next(m);
    }
    while n > 0 {
        if m == 0 {
            return false;
        }
        let k = (len(m) - off).min(n);
        // SAFETY: inside the mbuf's data, into the caller's buffer.
        unsafe {
            core::ptr::copy_nonoverlapping((data(m) + off) as *const u8, out, k);
            out = out.add(k);
        }
        n -= k;
        off = 0;
        m = next(m);
    }
    true
}

/// m_copym: a new chain with `n` bytes (M_COPYALL: to the end) from `off`.
pub fn copym(m: M, off: usize, n: i32) -> Option<M> {
    let have = total(m);
    if off > have {
        return None;
    }
    let n = if n == M_COPYALL || n as usize > have - off { have - off } else { n.max(0) as usize };
    let mut buf = alloc::vec![0u8; n];
    if !copydata(m, off, n, buf.as_mut_ptr()) {
        return None;
    }
    let hdr = off == 0 && flags(m) & M_PKTHDR != 0;
    let c = build(&buf, hdr)?;
    if hdr {
        s16(c, FLAGS, (flags(c) & !M_COPYFLAGS) | (flags(m) & M_COPYFLAGS));
        s32(c, RCVIF, g32(m, RCVIF));
    }
    Some(c)
}

/// A chain holding `bytes` (clusters for anything over MINCLSIZE).
fn build(bytes: &[u8], hdr: bool) -> Option<M> {
    let first = get(hdr)?;
    let (mut m, mut rest) = (first, bytes);
    loop {
        if rest.len() > area(m).1 && !clget(m) {
            freem(first);
            return None;
        }
        let k = rest.len().min(area(m).1);
        // SAFETY: the area holds k bytes.
        unsafe { core::ptr::copy_nonoverlapping(rest.as_ptr(), data(m) as *mut u8, k) };
        set_len(m, k);
        rest = &rest[k..];
        if rest.is_empty() {
            break;
        }
        let Some(n) = get(false) else {
            freem(first);
            return None;
        };
        s32(m, NEXT, n as u32);
        m = n;
    }
    if hdr {
        s32(first, PKTLEN, bytes.len() as u32);
    }
    Some(first)
}

/// m_copyback: write `n` bytes at `off`, extending the chain (zeros in
/// any gap); false when out of memory.
pub fn copyback(m0: M, mut off: usize, n: usize, src: *const u8) -> bool {
    let mut m = m0;
    let mut done = 0usize;
    let mut grown = 0usize;
    while off > len(m) {
        off -= len(m);
        if next(m) == 0 {
            // Fill the gap with zeros in this mbuf's room, then new ones.
            let room = trailing(m);
            let z = room.min(off);
            // SAFETY: inside the area.
            unsafe { core::ptr::write_bytes((data(m) + len(m)) as *mut u8, 0, z) };
            set_len(m, len(m) + z);
            grown += z;
            off -= z;
            if off == 0 {
                break;
            }
            let Some(nm) = get(false) else { return false };
            s32(m, NEXT, nm as u32);
        }
        m = next(m);
    }
    while done < n {
        // Bytes that land in data already there, then room after it.
        let over = (len(m) - off).min(n - done);
        // SAFETY: inside the mbuf's data, from the caller's buffer.
        unsafe { core::ptr::copy_nonoverlapping(src.add(done), (data(m) + off) as *mut u8, over) };
        done += over;
        off += over;
        if done < n && off == len(m) {
            let room = trailing(m).min(n - done);
            // SAFETY: inside the area, after the data.
            unsafe { core::ptr::copy_nonoverlapping(src.add(done), (data(m) + off) as *mut u8, room) };
            set_len(m, len(m) + room);
            grown += room;
            done += room;
            off += room;
        }
        if done < n {
            if next(m) == 0 {
                let Some(nm) = get(false) else { return false };
                if n - done > MLEN {
                    clget(nm);
                }
                s32(m, NEXT, nm as u32);
            }
            m = next(m);
            off = 0;
        }
    }
    if flags(m0) & M_PKTHDR != 0 {
        let t = total(m0);
        s32(m0, PKTLEN, t as u32);
    }
    let _ = grown;
    true
}

/// m_prepend: room for `n` bytes before the data (a new mbuf in front when
/// there is none); the chain's new head, or None (the chain is freed).
pub fn prepend(m: M, n: usize) -> Option<M> {
    if leading(m) >= n {
        set_data(m, data(m) - n);
        set_len(m, len(m) + n);
        if flags(m) & M_PKTHDR != 0 {
            s32(m, PKTLEN, g32(m, PKTLEN) + n as u32);
        }
        return Some(m);
    }
    let hdr = flags(m) & M_PKTHDR != 0;
    let Some(h) = get(hdr) else {
        freem(m);
        return None;
    };
    if n > area(h).1 {
        free(h);
        freem(m);
        return None;
    }
    if hdr {
        // The packet header moves to the new first mbuf.
        s16(h, FLAGS, (flags(h) & !M_COPYFLAGS) | (flags(m) & M_COPYFLAGS));
        s32(h, RCVIF, g32(m, RCVIF));
        s32(h, PKTLEN, g32(m, PKTLEN) + n as u32);
        // `m` keeps its data where it is: still in m_pktdat if it was a
        // plain header mbuf (only the flag goes).
        s16(m, FLAGS, flags(m) & !M_COPYFLAGS);
    }
    // Put the room at the end of the new mbuf's area (as M_ALIGN would).
    let (a, size) = area(h);
    set_data(h, a + size - n);
    set_len(h, n);
    s32(h, NEXT, m as u32);
    Some(h)
}

/// m_cat: append chain `n` to chain `m` (copied into `m`'s last mbuf when
/// it fits, n then freed).
pub fn cat(m: M, mut n: M) {
    let mut last = m;
    while next(last) != 0 {
        last = next(last);
    }
    while n != 0 {
        if flags(last) & M_EXT == 0 && trailing(last) >= len(n) {
            // SAFETY: room after the last mbuf's data.
            unsafe { core::ptr::copy_nonoverlapping(data(n) as *const u8, (data(last) + len(last)) as *mut u8, len(n)) };
            set_len(last, len(last) + len(n));
            n = free(n);
        } else {
            s32(last, NEXT, n as u32);
            break;
        }
    }
    if flags(m) & M_PKTHDR != 0 {
        let t = total(m);
        s32(m, PKTLEN, t as u32);
    }
}

/// m_adj: drop `req` bytes from the front (positive) or the end
/// (negative).
pub fn adj(m0: M, req: i32) {
    if req >= 0 {
        let mut left = req as usize;
        let mut m = m0;
        while m != 0 && left > 0 {
            let k = len(m).min(left);
            set_data(m, data(m) + k);
            set_len(m, len(m) - k);
            left -= k;
            m = next(m);
        }
    } else {
        let mut keep = total(m0).saturating_sub(req.unsigned_abs() as usize);
        let mut m = m0;
        while m != 0 {
            let k = len(m).min(keep);
            set_len(m, k);
            keep -= k;
            m = next(m);
        }
    }
    if flags(m0) & M_PKTHDR != 0 {
        let t = total(m0);
        s32(m0, PKTLEN, t as u32);
    }
}

/// m_pullup: the first `n` bytes made contiguous in the first mbuf; the
/// new head, or None (the chain is freed) when the chain is shorter or
/// `n` exceeds MHLEN.
pub fn pullup(m: M, n: usize) -> Option<M> {
    if len(m) >= n {
        return Some(m);
    }
    if n > MHLEN || total(m) < n {
        freem(m);
        return None;
    }
    let mut buf = alloc::vec![0u8; n];
    copydata(m, 0, n, buf.as_mut_ptr());
    let hdr = flags(m) & M_PKTHDR != 0;
    let Some(h) = get(hdr) else {
        freem(m);
        return None;
    };
    if hdr {
        s16(h, FLAGS, (flags(h) & !M_COPYFLAGS) | (flags(m) & M_COPYFLAGS));
        s32(h, RCVIF, g32(m, RCVIF));
        s32(h, PKTLEN, g32(m, PKTLEN));
    }
    // SAFETY: the new mbuf's area holds n <= MHLEN bytes.
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), data(h) as *mut u8, n) };
    set_len(h, n);
    // Take the n bytes off the old chain's front; its emptied mbufs go.
    let mut rest = m;
    let mut left = n;
    while rest != 0 && left > 0 {
        let k = len(rest).min(left);
        set_data(rest, data(rest) + k);
        set_len(rest, len(rest) - k);
        left -= k;
        if len(rest) == 0 {
            rest = free(rest);
        }
    }
    s32(h, NEXT, rest as u32);
    let _ = NEXTPKT;
    Some(h)
}

/// The chain's bytes, flattened.
pub fn to_vec(m: M) -> alloc::vec::Vec<u8> {
    let n = total(m);
    let mut v = alloc::vec![0u8; n];
    copydata(m, 0, n, v.as_mut_ptr());
    v
}
