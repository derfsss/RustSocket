//! Receive-side scaling (S2XCAP_RSS): set queues with S2X_CONFIGURE,
//! read batches per queue, and every frame's hash, hash type and queue
//! checked against a Toeplitz hash computed here.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, null_mut};

use amigaos4::sana2::*;
use amigaos4::sana2ext as x;

use crate::frames::{self, ETYPE_IPV4, PROTO_TCP, PROTO_UDP};
use crate::tests::T;
use crate::{Batch, Ctx, ItemSet, Opener};

/// The key the test sets (Microsoft's verification key).
pub const KEY: [u8; 40] = [
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb,
    0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
];

/// The Toeplitz hash of `input` under `key` (Microsoft's RSS
/// specification).
pub fn toeplitz(key: &[u8; 40], input: &[u8]) -> u32 {
    let mut h = 0u32;
    let mut window = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
    let mut next = 4;
    for &b in input {
        for bit in (0..8).rev() {
            if b >> bit & 1 != 0 {
                h ^= window;
            }
            let kb = key.get(next).copied().unwrap_or(0);
            window = (window << 1) | ((kb >> bit) & 1) as u32;
        }
        next += 1;
    }
    h
}

/// The verification suite's first IPv4 case (the I210 datasheet
/// 7.1.2.10.3.1): 66.9.149.187:2794 -> 161.142.100.80:1766, TCP hash
/// 0x51ccc178, IP-only hash 0x323e8fc2.
pub fn self_check() -> bool {
    let src = [66, 9, 149, 187];
    let dst = [161, 142, 100, 80];
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&src);
    tcp.extend_from_slice(&dst);
    tcp.extend_from_slice(&2794u16.to_be_bytes());
    tcp.extend_from_slice(&1766u16.to_be_bytes());
    toeplitz(&KEY, &tcp) == 0x51cc_c178 && toeplitz(&KEY, &tcp[..8]) == 0x323e_8fc2
}

/// S2XSET_RSS on opener `o`: (io_Error, s2xc_Failed set) and the values
/// written back (hash types, queues).
fn set_rss(ctx: &mut Ctx, o: &Opener, flags: u32, types: u32, queues: u16, key: Option<&mut [u8; 40]>, table: Option<&mut [u8; 128]>) -> (Option<(i8, u32)>, bool, u32, u16) {
    let mut item = Box::new(x::S2XSetRSS {
        s2xsr_Header: x::S2XItem::new(x::S2XSET_RSS, core::mem::size_of::<x::S2XSetRSS>()),
        s2xsr_HashTypes: types,
        s2xsr_Queues: queues,
        s2xsr_TableSize: 128,
        s2xsr_Key: key.map_or(null_mut(), |k| k.as_mut_ptr()),
        s2xsr_Table: table.map_or(null_mut(), |t| t.as_mut_ptr()),
    });
    let mut c = Box::new(x::S2XConfigure {
        s2xc_Size: core::mem::size_of::<x::S2XConfigure>() as u32,
        s2xc_Flags: flags,
        s2xc_Items: x::MinList { mlh_Head: null_mut(), mlh_Tail: null_mut(), mlh_TailPred: null_mut() },
        s2xc_Failed: null_mut(),
    });
    // SAFETY: boxed list and item, linked once.
    unsafe {
        x::MinList::init(addr_of_mut!(c.s2xc_Items));
        x::MinList::add_tail(addr_of_mut!(c.s2xc_Items), addr_of_mut!(*item) as *mut MinNode);
    }
    let mut q = ctx.clone_req(&o.req, 16);
    q.set(x::S2X_CONFIGURE, 0);
    q.r.set_stat_data(addr_of_mut!(*c) as *mut c_void);
    ctx.send(&q);
    let res = ctx.wait(&q, 5000);
    ctx.free(q);
    // SAFETY: our own structures, read after the reply.
    let failed = unsafe { !addr_of!(c.s2xc_Failed).read_unaligned().is_null() };
    (res, failed, item.s2xsr_HashTypes, item.s2xsr_Queues)
}

/// Wait until links are up again (a change resets the card).
fn links(t: &mut T) {
    for o in [&*t.a, &*t.b] {
        let mut q = t.ctx.clone_req(&o.req, 16);
        q.set(S2_ONEVENT, 0);
        q.r.set_wire_error(S2EVENT_CONNECT);
        t.ctx.send(&q);
        let _ = t.ctx.wait(&q, 8000);
        t.ctx.free(q);
    }
}

pub fn run(t: &mut T, types: u32, max_q: u16, want_q: u16) {
    t.ctx.check("rss.toeplitz", self_check(), "s2xtest's own Toeplitz hash against the verification suite's first IPv4 case".into());
    let nq = want_q.min(max_q).max(2);
    if max_q < 2 {
        t.ctx.skip("rss", "fewer than two receive queues");
        return;
    }
    // An even spread over nq queues, the test's key.
    let mut key = KEY;
    let mut table = [0u8; 128];
    for (i, e) in table.iter_mut().enumerate() {
        *e = (i % nq as usize) as u8;
    }
    let use_types = types & (x::S2XRSS_UDPV4 | x::S2XRSS_TCPV4 | x::S2XRSS_IPV4);
    let (res, failed, wt, wq) = set_rss(t.ctx, t.b, 0, use_types, nq, Some(&mut key), Some(&mut table.clone()));
    t.ctx.check("rss.set", res == Some((0, 0)) && !failed && wq == nq && wt == use_types, format!("{} queues, types 0x{:x}: {:?}, written back {} queues types 0x{:x}", nq, use_types, res, wq, wt));
    links(t);
    // A read with S2XCF_READ gives the same key and table back.
    let mut k2 = [0u8; 40];
    let mut t2 = [0xFFu8; 128];
    let (r2, _, rt, rq) = set_rss(t.ctx, t.b, x::S2XCF_READ, 0, 0, Some(&mut k2), Some(&mut t2));
    t.ctx.check("rss.read", r2 == Some((0, 0)) && rq == nq && rt == use_types && k2 == KEY && t2 == table, format!("{:?}: {} queues, types 0x{:x}, key back {}, table back {}", r2, rq, rt, k2 == KEY, t2 == table));
    // One read batch per queue, with RSS items; flows on A.
    let items = ItemSet { rss: true, ..ItemSet::default() };
    let mut batches: Vec<Batch> = Vec::new();
    for q in 0..nq {
        let mut b = Batch::new(t.ctx, &t.b.req, 16.min(t.offer.max_frames as usize), crate::NORMAL_BUF, items);
        b.set_queue(q as u32);
        b.post_read(t.ctx, ETYPE_IPV4, 0);
        batches.push(b);
    }
    t.ctx.sleep(20);
    let id = t.ctx.next_id();
    // Two openers of one port (no peer): no frames come back; the frame
    // checks are skipped.
    let same_port = t.a.unit == t.b.unit;
    let flows = if same_port { 0 } else { 32usize };
    let mut sent = Vec::new();
    for f in 0..flows {
        let proto = if f % 2 == 0 { PROTO_UDP } else { PROTO_TCP };
        let sport = 10000 + 37 * f as u16;
        let l4 = frames::transport(false, proto, sport, 5555, 1, &frames::payload(id, f as u16, 40));
        let pkt = frames::ipv4(proto, 0x500 + f as u16, &l4);
        let _ = t.send_one(ETYPE_IPV4, &pkt);
        sent.push((proto, sport));
    }
    // Collect: (queue, flow, hash, type).
    let mut got: Vec<(usize, usize, u32, u32)> = Vec::new();
    let mut waited = 0;
    while got.len() < flows && waited < 3000 {
        let mut any = false;
        for (q, b) in batches.iter_mut().enumerate() {
            if t.ctx.poll(&b.req) {
                any = true;
                for i in 0..(b.done() as usize).min(b.freqs.len()) {
                    let bytes = b.freqs[i].bytes();
                    if bytes.len() >= 28 {
                        let off = 20 + if bytes[9] == PROTO_TCP { 20 } else { 8 };
                        if let Some((fid, f)) = bytes.get(off..).and_then(frames::parse) {
                            if fid == id {
                                // SAFETY: our own boxed item.
                                let (h, ty) = b.rss[i].as_ref().map_or((0, 0), |r| unsafe { (addr_of!(r.s2xfr_Hash).read_unaligned(), addr_of!(r.s2xfr_HashType).read_unaligned()) });
                                got.push((q, f as usize, h, ty));
                            }
                        }
                    }
                }
                b.post_read(t.ctx, ETYPE_IPV4, 0);
            }
        }
        if !any {
            t.ctx.sleep(10);
            waited += 10;
        }
    }
    let mut per_q = alloc::vec![0usize; nq as usize];
    let mut bad = Vec::new();
    for &(q, f, h, ty) in &got {
        per_q[q] += 1;
        let (proto, sport) = sent[f];
        let mut input = Vec::new();
        input.extend_from_slice(&frames::SRC4);
        input.extend_from_slice(&frames::DST4);
        let (want_ty, hashed_ports) = match proto {
            PROTO_UDP if use_types & x::S2XRSS_UDPV4 != 0 => (x::S2XRSS_UDPV4, true),
            PROTO_TCP if use_types & x::S2XRSS_TCPV4 != 0 => (x::S2XRSS_TCPV4, true),
            _ if use_types & x::S2XRSS_IPV4 != 0 => (x::S2XRSS_IPV4, false),
            _ => (0, false),
        };
        if hashed_ports {
            input.extend_from_slice(&sport.to_be_bytes());
            input.extend_from_slice(&5555u16.to_be_bytes());
        }
        let want_h = toeplitz(&KEY, &input);
        let want_q = if want_ty == 0 { 0 } else { table[(want_h & 0x7F) as usize] as usize };
        if ty != want_ty || (want_ty != 0 && h != want_h) || q != want_q {
            bad.push(format!("flow {}: queue {} (want {}), hash 0x{:08x} (want 0x{:08x}), type 0x{:x} (want 0x{:x})", f, q, want_q, h, want_h, ty, want_ty));
        }
    }
    let spread = per_q.iter().filter(|&&n| n > 0).count();
    if same_port {
        t.ctx.skip("rss.frames", "one port: it does not receive its own frames");
        t.ctx.skip("rss.spread", "one port");
    } else {
    t.ctx.check("rss.frames", got.len() == flows && bad.is_empty(), format!("{} of {} flows received, per queue {:?}{}", got.len(), flows, per_q, if bad.is_empty() { alloc::string::String::new() } else { format!(": {:?}", &bad[..bad.len().min(3)]) }));
    t.ctx.check("rss.spread", spread >= 2, format!("{} of {} queues received frames ({:?})", spread, nq, per_q));
    }
    // Turning RSS off while a batch is posted on queue 1: S2ERR_BAD_STATE.
    let (r3, f3, _, _) = set_rss(t.ctx, t.b, 0, 0, 1, None, None);
    t.ctx.check("rss.badstate", matches!(r3, Some((e, _)) if e == S2ERR_BAD_STATE) && f3, format!("one queue with a batch posted on queue 1: {:?}, s2xc_Failed set {}", r3, f3));
    for b in batches {
        b.free(t.ctx);
    }
    // Off: everything on queue 0 again; a batch on queue 1 is refused.
    let (r4, _, _, q4) = set_rss(t.ctx, t.b, 0, 0, 1, None, None);
    links(t);
    let mut b1 = Batch::new(t.ctx, &t.b.req, 2, crate::NORMAL_BUF, ItemSet::default());
    b1.set_queue(1);
    b1.post_read(t.ctx, ETYPE_IPV4, 0);
    let r5 = t.ctx.wait(&b1.req, 1000);
    b1.free(t.ctx);
    t.ctx.check("rss.off", r4 == Some((0, 0)) && q4 == 1 && matches!(r5, Some((e, _)) if e != 0), format!("one queue: {:?} ({} written back); a read batch on queue 1 afterwards: {:?}", r4, q4, r5));
    let _ = (frames::ETYPE, Ctx::sleep);
}
