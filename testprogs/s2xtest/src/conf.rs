//! S2X_CONFIGURE: reading, refusals (unknown and private types, values
//! outside the capability, the MTU with a receive request posted), changes
//! with write-back and S2EVENT_CONFIGCHANGED, and a jumbo MTU end to end.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, null_mut};

use amigaos4::device::cmd::{CMD_READ, CMD_WRITE};
use amigaos4::sana2::*;
use amigaos4::sana2ext as x;

use crate::frames::{self, ETYPE};
use crate::tests::T;
use crate::{Ctx, Opener, Req};

/// One S2X_CONFIGURE request's structure and items (boxed: the driver
/// sees their addresses).
struct Conf {
    hdr: Box<x::S2XConfigure>,
    mtu: Option<Box<x::S2XSetMTU>>,
    modr: Option<Box<x::S2XSetModeration>>,
    flow: Option<Box<x::S2XSetFlowControl>>,
    odd: Vec<Box<x::S2XSetMTU>>,
}

impl Conf {
    fn new(flags: u32) -> Conf {
        let mut hdr = Box::new(x::S2XConfigure {
            s2xc_Size: core::mem::size_of::<x::S2XConfigure>() as u32,
            s2xc_Flags: flags,
            s2xc_Items: x::MinList { mlh_Head: null_mut(), mlh_Tail: null_mut(), mlh_TailPred: null_mut() },
            s2xc_Failed: 0x1234 as *mut x::S2XItem,
        });
        // SAFETY: a boxed list that stays put.
        unsafe { x::MinList::init(addr_of_mut!(hdr.s2xc_Items)) };
        Conf { hdr, mtu: None, modr: None, flow: None, odd: Vec::new() }
    }
    fn link(&mut self, n: *mut MinNode) {
        // SAFETY: boxed items, linked once.
        unsafe { x::MinList::add_tail(addr_of_mut!(self.hdr.s2xc_Items), n) };
    }
    fn mtu(mut self, v: u32) -> Self {
        let mut it = Box::new(x::S2XSetMTU { s2xsm_Header: x::S2XItem::new(x::S2XSET_MTU, core::mem::size_of::<x::S2XSetMTU>()), s2xsm_MTU: v, s2xsm_Reserved: 0 });
        self.link(addr_of_mut!(*it) as *mut MinNode);
        self.mtu = Some(it);
        self
    }
    fn moderation(mut self, rx: u32, tx: u32) -> Self {
        let mut it = Box::new(x::S2XSetModeration { s2xso_Header: x::S2XItem::new(x::S2XSET_MODERATION, core::mem::size_of::<x::S2XSetModeration>()), s2xso_RxMicros: rx, s2xso_TxMicros: tx });
        self.link(addr_of_mut!(*it) as *mut MinNode);
        self.modr = Some(it);
        self
    }
    fn flow(mut self, m: u32) -> Self {
        let mut it = Box::new(x::S2XSetFlowControl { s2xsf_Header: x::S2XItem::new(x::S2XSET_FLOWCONTROL, core::mem::size_of::<x::S2XSetFlowControl>()), s2xsf_Modes: m, s2xsf_Reserved: 0 });
        self.link(addr_of_mut!(*it) as *mut MinNode);
        self.flow = Some(it);
        self
    }
    /// An item of type `ty` the driver does not know (MTU-sized).
    fn odd(mut self, ty: u32) -> Self {
        let mut it = Box::new(x::S2XSetMTU { s2xsm_Header: x::S2XItem::new(ty, core::mem::size_of::<x::S2XSetMTU>()), s2xsm_MTU: 1500, s2xsm_Reserved: 0 });
        self.link(addr_of_mut!(*it) as *mut MinNode);
        self.odd.push(it);
        self
    }
    fn failed(&self) -> *mut x::S2XItem {
        // SAFETY: our own structure, read after the reply.
        unsafe { addr_of!(self.hdr.s2xc_Failed).read_unaligned() }
    }
    fn mtu_v(&self) -> u32 {
        self.mtu.as_ref().map_or(0, |m| m.s2xsm_MTU)
    }
    fn mod_v(&self) -> (u32, u32) {
        self.modr.as_ref().map_or((0, 0), |m| (m.s2xso_RxMicros, m.s2xso_TxMicros))
    }
    fn flow_v(&self) -> u32 {
        self.flow.as_ref().map_or(0, |f| f.s2xsf_Modes)
    }
    fn ptr<I>(b: &Option<Box<I>>) -> *mut x::S2XItem {
        b.as_ref().map_or(null_mut(), |i| &**i as *const I as *mut x::S2XItem)
    }
}

/// Send `c` on opener `o` (DoIO-like, 5 s bound); (io_Error, wire).
fn configure(ctx: &mut Ctx, o: &Opener, c: &mut Conf) -> Option<(i8, u32)> {
    let mut q = ctx.clone_req(&o.req, 16);
    q.set(x::S2X_CONFIGURE, 0);
    q.r.set_stat_data(addr_of_mut!(*c.hdr) as *mut c_void);
    ctx.send(&q);
    let res = ctx.wait(&q, 5000);
    ctx.free(q);
    res
}

/// The unit's MTU from S2_DEVICEQUERY.
fn device_mtu(ctx: &mut Ctx, o: &Opener) -> u32 {
    let mut q = ctx.clone_req(&o.req, 16);
    let mut dq: Sana2DeviceQuery = unsafe { core::mem::zeroed() };
    dq.SizeAvailable = core::mem::size_of::<Sana2DeviceQuery>() as u32;
    q.set(S2_DEVICEQUERY, 0);
    q.r.set_stat_data(&mut dq as *mut Sana2DeviceQuery as *mut c_void);
    let (e, _) = ctx.do_io(&q);
    ctx.free(q);
    if e == 0 { dq.MTU } else { 0 }
}

/// An S2_ONEVENT for `mask`, posted.
fn post_event(ctx: &mut Ctx, o: &Opener, mask: u32) -> Req {
    let mut q = ctx.clone_req(&o.req, 16);
    q.set(S2_ONEVENT, 0);
    q.r.set_wire_error(mask);
    ctx.send(&q);
    q
}

pub fn run(t: &mut T) {
    let offer = t.offer;
    // Reading: every item filled with the setting in force.
    let mut rd = Conf::new(x::S2XCF_READ).mtu(0).moderation(0xFFFF_FFFF, 0xFFFF_FFFF).flow(0xFFFF_FFFF);
    let res = configure(t.ctx, t.b, &mut rd);
    let dmtu = device_mtu(t.ctx, t.b);
    let (mrx, mtx) = rd.mod_v();
    let fl = rd.flow_v();
    let mod_ok = offer.moderation.map_or(true, |(max, _)| mrx <= max && mtx <= max);
    let flow_ok = offer.flow.map_or(true, |m| fl & !m == 0);
    let ok = res == Some((0, 0)) && rd.failed().is_null() && rd.mtu_v() == dmtu && dmtu != 0 && mod_ok && flow_ok;
    t.ctx.check("conf.read", ok, format!("{:?}: MTU {} (S2_DEVICEQUERY {}), moderation {}/{} us, flow 0x{:x}, s2xc_Failed {:p}", res, rd.mtu_v(), dmtu, mrx, mtx, fl, rd.failed()));
    let (orig_rx, orig_flow) = (mrx, fl);
    // Unknown and private types are refused, with nothing changed.
    for (name, ty) in [("conf.unknown", 0x2077u32), ("conf.private", x::S2XITEM_PRIVATE | 0x2001)] {
        let mut c = Conf::new(0).moderation(orig_rx + 7, orig_rx + 7).odd(ty);
        let res = configure(t.ctx, t.b, &mut c);
        let failed = c.failed();
        let want = &*c.odd[0] as *const x::S2XSetMTU as *mut x::S2XItem;
        let mut after = Conf::new(x::S2XCF_READ).moderation(0, 0);
        let _ = configure(t.ctx, t.b, &mut after);
        let unchanged = after.mod_v().0 == orig_rx;
        t.ctx.check(name, matches!(res, Some((e, _)) if e == S2ERR_NOT_SUPPORTED) && failed == want && unchanged, format!("type 0x{:x} after a moderation item: {:?}, s2xc_Failed points at it {}, moderation unchanged {}", ty, res, failed == want, unchanged));
    }
    // Values outside the capability.
    if let Some((_, max)) = offer.mtu {
        let mut c = Conf::new(0).mtu(max + 1);
        let res = configure(t.ctx, t.b, &mut c);
        // Outside the range: S2ERR_BAD_ARGUMENT. While another opener (a
        // stack) has reads posted the MTU also breaks the posted-reads
        // rule, and the spec does not say which refusal comes first, so
        // S2ERR_BAD_STATE is right too.
        t.ctx.check("conf.range.mtu", matches!(res, Some((e, _)) if e == S2ERR_BAD_ARGUMENT || e == S2ERR_BAD_STATE) && c.failed() == Conf::ptr(&c.mtu), format!("MTU {} (max {}): {:?}", max + 1, max, res));
    }
    if let Some((max, _)) = offer.moderation {
        if max < u32::MAX / 8 {
            let mut c = Conf::new(0).moderation(max + 1, max + 1);
            let res = configure(t.ctx, t.b, &mut c);
            t.ctx.check("conf.range.moderation", matches!(res, Some((e, _)) if e == S2ERR_BAD_ARGUMENT) && c.failed() == Conf::ptr(&c.modr), format!("{} us (max {}): {:?}", max + 1, max, res));
        }
    }
    if let Some(modes) = offer.flow {
        let bad = !(modes | 0) & 0x8000_0000;
        let mut c = Conf::new(0).flow(modes | bad);
        let res = configure(t.ctx, t.b, &mut c);
        t.ctx.check("conf.range.flow", matches!(res, Some((e, _)) if e == S2ERR_BAD_ARGUMENT) && c.failed() == Conf::ptr(&c.flow), format!("modes 0x{:x} (offered 0x{:x}): {:?}", modes | bad, modes, res));
    }
    // The MTU with a receive request posted: S2ERR_BAD_STATE.
    if offer.mtu.is_some() {
        let reads = t.post_reads(1, ETYPE, 0);
        t.ctx.sleep(10);
        let mut c = Conf::new(0).mtu(dmtu);
        let res = configure(t.ctx, t.b, &mut c);
        let still = !t.ctx.poll(&reads[0]);
        t.ctx.check("conf.badstate", matches!(res, Some((e, _)) if e == S2ERR_BAD_STATE) && c.failed() == Conf::ptr(&c.mtu) && still, format!("S2XSET_MTU with a CMD_READ posted: {:?}, the read still posted {}", res, still));
        let _ = t.take(reads, 0, 0);
    }
    // Moderation: a change written back (rounded to the card's step),
    // read back the same, CONFIGCHANGED sent; then the old value again.
    if let Some((max, _)) = offer.moderation {
        let want = 100.min(max);
        let ev = post_event(t.ctx, t.b, S2EVENT_CONFIGCHANGED);
        t.ctx.sleep(10);
        let mut c = Conf::new(0).moderation(want, want);
        let res = configure(t.ctx, t.b, &mut c);
        let applied = c.mod_v();
        let event = t.ctx.wait(&ev, 1000);
        t.ctx.free(ev);
        let mut rb = Conf::new(x::S2XCF_READ).moderation(0, 0);
        let _ = configure(t.ctx, t.b, &mut rb);
        let ok = res == Some((0, 0)) && applied.0 <= max && applied.0.abs_diff(want) <= want / 2 + 1 && rb.mod_v() == applied && matches!(event, Some((0, w)) if w & S2EVENT_CONFIGCHANGED != 0);
        t.ctx.check("conf.moderation", ok, format!("asked {} us: {:?}, applied {:?}, read back {:?}, S2EVENT_CONFIGCHANGED {:?}", want, res, applied, rb.mod_v(), event));
        let mut back = Conf::new(0).moderation(orig_rx, orig_rx);
        let _ = configure(t.ctx, t.b, &mut back);
    }
    // Flow control: the current modes again (no change), then forced both
    // ways if offered (no AUTO), read back, then the old setting.
    if let Some(modes) = offer.flow {
        let mut same = Conf::new(0).flow(orig_flow);
        let r1 = configure(t.ctx, t.b, &mut same);
        let forced = modes & (x::S2XFC_RX | x::S2XFC_TX);
        let mut c = Conf::new(0).flow(forced);
        let r2 = configure(t.ctx, t.b, &mut c);
        let mut rb = Conf::new(x::S2XCF_READ).flow(0);
        let _ = configure(t.ctx, t.b, &mut rb);
        let ok = r1 == Some((0, 0)) && r2 == Some((0, 0)) && c.flow_v() == forced && rb.flow_v() == forced;
        t.ctx.check("conf.flow", ok, format!("same 0x{:x}: {:?}; forced 0x{:x}: {:?}, written back 0x{:x}, read back 0x{:x}", orig_flow, r1, forced, r2, c.flow_v(), rb.flow_v()));
        let mut back = Conf::new(0).flow(orig_flow);
        let _ = configure(t.ctx, t.b, &mut back);
    }
    // A jumbo MTU on both units, end to end, then back.
    if let Some((_, max)) = offer.mtu {
        if max >= 9000 {
            jumbo(t, 9000, dmtu);
        } else {
            t.ctx.skip("conf.mtu", "S2XCAP_MTU below 9000");
        }
    }
}

/// Set `mtu` on A and B (no reads posted), check S2_DEVICEQUERY and the
/// event, post a read on B at once (during any link reset), send a frame
/// of the full size and one byte more, then set `old` back.
fn jumbo(t: &mut T, mtu: u32, old: u32) {
    let id = t.ctx.next_id();
    let ev = post_event(t.ctx, t.b, S2EVENT_CONFIGCHANGED);
    t.ctx.sleep(10);
    let mut ca = Conf::new(0).mtu(mtu);
    let ra = configure(t.ctx, t.a, &mut ca);
    let mut cb = Conf::new(0).mtu(mtu);
    let rb = configure(t.ctx, t.b, &mut cb);
    // Another opener (a stack) with reads posted: the driver must refuse
    // with S2ERR_BAD_STATE (checked as conf.badstate), so the jumbo checks
    // cannot run. Put back a unit that did change and skip.
    let busy = |r: Option<(i8, u32)>| matches!(r, Some((e, _)) if e == S2ERR_BAD_STATE);
    if busy(ra) || busy(rb) {
        let _ = t.ctx.wait(&ev, 200);
        t.ctx.free(ev);
        for (o, r) in [(&*t.a, ra), (&*t.b, rb)] {
            if r == Some((0, 0)) {
                let mut back = Conf::new(0).mtu(old);
                let _ = configure(t.ctx, o, &mut back);
            }
        }
        t.ctx.skip("conf.mtu", "S2ERR_BAD_STATE: another opener has reads posted");
        return;
    }
    // A read posted straight away must stay queued over the link reset.
    let mut big = t.ctx.clone_req(&t.b.req, mtu as usize + 64);
    big.set(CMD_READ, 0);
    big.r.set_packet_type(ETYPE);
    t.ctx.send(&big);
    let event = t.ctx.wait(&ev, 1000);
    t.ctx.free(ev);
    let (ma, mb) = (device_mtu(t.ctx, t.a), device_mtu(t.ctx, t.b));
    t.ctx.check("conf.mtu.set", ra == Some((0, 0)) && rb == Some((0, 0)) && ca.mtu_v() == mtu && cb.mtu_v() == mtu && ma == mtu && mb == mtu && matches!(event, Some((0, w)) if w & S2EVENT_CONFIGCHANGED != 0), format!("A {:?} B {:?}, written back {}/{}, S2_DEVICEQUERY {}/{}, event {:?}", ra, rb, ca.mtu_v(), cb.mtu_v(), ma, mb, event));
    // The links come back (S2EVENT_CONNECT, answered at once when up).
    for o in [&*t.a, &*t.b] {
        let c = post_event(t.ctx, o, S2EVENT_CONNECT);
        let _ = t.ctx.wait(&c, 8000);
        t.ctx.free(c);
    }
    // Two openers of one port (no peer): a card does not receive its own
    // frames, so the frame checks are skipped.
    let same_port = t.a.unit == t.b.unit;
    let early = t.ctx.poll(&big);
    let data = frames::payload(id, 1, mtu as usize);
    let mut w = t.ctx.clone_req(&t.a.req, mtu as usize + 64);
    let bmac = t.b.mac;
    w.set_write(CMD_WRITE, 0, ETYPE, &bmac, &data);
    let (we, _) = t.ctx.do_io(&w);
    let got = t.ctx.wait(&big, 2000);
    let right = got == Some((0, 0)) && big.bytes() == &data[..];
    if same_port {
        t.ctx.skip("conf.mtu.frame", "one port: it does not receive its own frames");
    } else {
    t.ctx.check("conf.mtu.frame", !early && we == 0 && right, format!("read posted during the reset still waiting {}; {} bytes sent: write error {}, read {:?}, bytes right {}", !early, data.len(), we, got, right));
    }
    let over = frames::payload(id, 2, mtu as usize + 1);
    w.set_write(CMD_WRITE, 0, ETYPE, &bmac, &over);
    let (oe, _) = t.ctx.do_io(&w);
    t.ctx.check("conf.mtu.over", oe != 0, format!("{} bytes (MTU {}): write error {}", over.len(), mtu, oe));
    t.ctx.free(w);
    t.ctx.free(big);
    let mut ba = Conf::new(0).mtu(old);
    let ra = configure(t.ctx, t.a, &mut ba);
    let mut bb = Conf::new(0).mtu(old);
    let rb = configure(t.ctx, t.b, &mut bb);
    for o in [&*t.a, &*t.b] {
        let c = post_event(t.ctx, o, S2EVENT_CONNECT);
        let _ = t.ctx.wait(&c, 8000);
        t.ctx.free(c);
    }
    let (ma, mb) = (device_mtu(t.ctx, t.a), device_mtu(t.ctx, t.b));
    let reads = t.post_reads(1, ETYPE, 0);
    t.ctx.sleep(10);
    let e = t.send_one(ETYPE, &frames::payload(id, 3, 200));
    let g = t.take(reads, 1, 2000);
    let back = g.first().map_or(false, |g| g.err == 0 && frames::parse(&g.bytes) == Some((id, 3)));
    t.ctx.check("conf.mtu.back", ra == Some((0, 0)) && rb == Some((0, 0)) && ma == old && mb == old && (same_port || (e == 0 && back)), format!("MTU {} again: A {:?} B {:?}, S2_DEVICEQUERY {}/{}, a normal frame afterwards {} (one port: not checked {})", old, ra, rb, ma, mb, back, same_port));
}

/// Settings read only (S2XCF_READ), for a unit a stack is using: the MTU
/// as S2_DEVICEQUERY says, moderation and flow control within the
/// capability, s2xc_Failed left NULL. Nothing is changed.
pub fn read_only(ctx: &mut Ctx, o: &Opener, offer: crate::Offer) {
    if offer.features & (x::S2XF_MTU | x::S2XF_MODERATION | x::S2XF_FLOWCONTROL) == 0 {
        ctx.skip("conf.read", "no setting capability");
        return;
    }
    let mut rd = Conf::new(x::S2XCF_READ).mtu(0).moderation(0xFFFF_FFFF, 0xFFFF_FFFF).flow(0xFFFF_FFFF);
    let res = configure(ctx, o, &mut rd);
    let dmtu = device_mtu(ctx, o);
    let (mrx, mtx) = rd.mod_v();
    let fl = rd.flow_v();
    let mod_ok = offer.moderation.map_or(true, |(max, _)| mrx <= max && mtx <= max);
    let flow_ok = offer.flow.map_or(true, |m| fl & !m == 0);
    let ok = res == Some((0, 0)) && rd.failed().is_null() && rd.mtu_v() == dmtu && dmtu != 0 && mod_ok && flow_ok;
    ctx.check("conf.read", ok, format!("{:?}: MTU {} (S2_DEVICEQUERY {}), moderation {}/{} us, flow 0x{:x}, s2xc_Failed {:p}", res, rd.mtu_v(), dmtu, mrx, mtx, fl, rd.failed()));
}
