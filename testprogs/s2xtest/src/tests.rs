//! The checks: discovery (S2X_QUERY), batches, the dispatch rule, abort,
//! refusal, receive checksums.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use amigaos4::device::cmd::{CMD_READ, CMD_WRITE, NSCMD_DEVICEQUERY};
use amigaos4::device::ioerr::IOERR_ABORTED;
use amigaos4::sana2::*;
use amigaos4::sana2ext as x;

use crate::frames::{self, ETYPE, ETYPE_IPV4, ETYPE_IPV6, PROTO_TCP, PROTO_UDP};
use crate::{Batch, Ctx, ItemSet, Offer, Opener, Req, NORMAL_BUF, PRIVATE_ITEM};

/// Capability names for need=.
const NAMES: [(&str, u32); 8] = [
    ("batch", x::S2XF_BATCH),
    ("rxcsum", x::S2XF_RXCHECKSUM),
    ("txcsum", x::S2XF_TXCHECKSUM),
    ("segment", x::S2XF_SEGMENT),
    ("mtu", x::S2XF_MTU),
    ("moderation", x::S2XF_MODERATION),
    ("flow", x::S2XF_FLOWCONTROL),
    ("rss", x::S2XF_RSS),
];

/// Read a field of a packed item.
macro_rules! rd {
    ($p:expr, $f:ident) => {
        // SAFETY: an item of the driver's read-only capability list (valid
        // until CloseDevice) or one of ours.
        unsafe { core::ptr::addr_of!((*$p).$f).read_unaligned() }
    };
}

/// S2X_QUERY and the capability list. Returns what the driver offers
/// (`ok` false: plain SANA-II, or the answer is unusable).
pub fn query(ctx: &mut Ctx, a: &Opener, need: &[String]) -> Offer {
    let mut offer = Offer::default();
    // NSCMD_DEVICEQUERY lists S2X_QUERY.
    let mut q = ctx.clone_req(&a.req, 16);
    let mut res = [0u32; 4];
    q.set(NSCMD_DEVICEQUERY, 0);
    q.r.io().set_data(res.as_mut_ptr() as *mut u8);
    q.r.io().set_length(16);
    let (e, _) = ctx.do_io(&q);
    let mut cmds: Vec<u16> = Vec::new();
    if e == 0 && res[3] != 0 {
        let p = res[3] as usize as *const u16;
        for i in 0..256 {
            // SAFETY: the driver's 0-terminated command list (bounded walk).
            let c = unsafe { p.add(i).read_unaligned() };
            if c == 0 {
                break;
            }
            cmds.push(c);
        }
    }
    let listed = cmds.contains(&x::S2X_QUERY);
    if !listed {
        if need.is_empty() {
            ctx.skip("query", "NSCMD_DEVICEQUERY does not list S2X_QUERY: plain SANA-II, nothing to check");
        } else {
            ctx.check("query.cmdlist", false, format!("need={:?}, but NSCMD_DEVICEQUERY (error {}, {} commands) lists no S2X_QUERY", need, e, cmds.len()));
        }
        ctx.free(q);
        return offer;
    }
    let mut ans: x::S2XQuery = unsafe { core::mem::zeroed() };
    ans.s2xq_Size = core::mem::size_of::<x::S2XQuery>() as u32;
    q.set(x::S2X_QUERY, 0);
    q.r.set_stat_data(&mut ans as *mut x::S2XQuery as *mut c_void);
    let (e, w) = ctx.do_io(&q);
    let magic = ans.s2xq_Magic;
    let version = ans.s2xq_Version;
    let caps = ans.s2xq_Capabilities;
    let ok = e == 0 && magic == x::S2X_MAGIC && version >= 1 && !caps.is_null();
    ctx.check(
        "query.answer",
        ok,
        format!("error {} wire {}, magic 0x{:08x}, version {}, revision {}, features 0x{:08x}, list {:p}", e, w, magic, version, { ans.s2xq_Revision }, { ans.s2xq_Features }, caps),
    );
    if !ok {
        ctx.free(q);
        return offer;
    }
    offer.features = ans.s2xq_Features;
    // The items.
    let mut bits = 0u32;
    let mut n = 0;
    let mut sizes_ok = true;
    let mut text = String::new();
    // SAFETY: the driver's list, read only, valid until CloseDevice.
    for it in unsafe { x::items(caps) } {
        n += 1;
        let ty = rd!(it, s2xi_Type);
        let size = rd!(it, s2xi_Size) as usize;
        let need_size = match ty {
            x::S2XCAP_BATCH => core::mem::size_of::<x::S2XCapBatch>(),
            x::S2XCAP_RXCHECKSUM | x::S2XCAP_TXCHECKSUM => core::mem::size_of::<x::S2XCapChecksum>(),
            x::S2XCAP_SEGMENT => core::mem::size_of::<x::S2XCapSegment>(),
            x::S2XCAP_MTU => core::mem::size_of::<x::S2XCapMTU>(),
            x::S2XCAP_MODERATION => core::mem::size_of::<x::S2XCapModeration>(),
            x::S2XCAP_FLOWCONTROL => core::mem::size_of::<x::S2XCapFlowControl>(),
            x::S2XCAP_RSS => core::mem::size_of::<x::S2XCapRSS>(),
            _ => core::mem::size_of::<x::S2XItem>(),
        };
        if size < need_size {
            sizes_ok = false;
            text.push_str(&format!(" [type 0x{:x} only {} bytes]", ty, size));
            continue;
        }
        if (1..32).contains(&ty) {
            bits |= 1 << ty;
        }
        match ty {
            x::S2XCAP_BATCH => {
                let p = it as *const x::S2XCapBatch;
                offer.max_frames = rd!(p, s2xcb_MaxFrames);
                text.push_str(&format!(" batch(max {})", offer.max_frames));
            }
            x::S2XCAP_RXCHECKSUM | x::S2XCAP_TXCHECKSUM => {
                let p = it as *const x::S2XCapChecksum;
                let v = rd!(p, s2xcc_Protocols);
                if ty == x::S2XCAP_RXCHECKSUM {
                    offer.rx_csum = Some(v);
                    text.push_str(&format!(" rxcsum(0x{:x})", v));
                } else {
                    offer.tx_csum = Some(v);
                    text.push_str(&format!(" txcsum(0x{:x})", v));
                }
            }
            x::S2XCAP_SEGMENT => {
                let p = it as *const x::S2XCapSegment;
                offer.segment = Some((rd!(p, s2xcs_Protocols), rd!(p, s2xcs_MaxSize), rd!(p, s2xcs_MaxSegments), rd!(p, s2xcs_MinSegSize)));
                text.push_str(&format!(" segment{:?}", offer.segment.unwrap()));
            }
            x::S2XCAP_MTU => {
                let p = it as *const x::S2XCapMTU;
                offer.mtu = Some((rd!(p, s2xcm_MinMTU), rd!(p, s2xcm_MaxMTU)));
                text.push_str(&format!(" mtu{:?}", offer.mtu.unwrap()));
            }
            x::S2XCAP_MODERATION => {
                let p = it as *const x::S2XCapModeration;
                offer.moderation = Some((rd!(p, s2xco_MaxMicros), rd!(p, s2xco_Flags)));
                text.push_str(&format!(" moderation{:?}", offer.moderation.unwrap()));
            }
            x::S2XCAP_FLOWCONTROL => {
                let p = it as *const x::S2XCapFlowControl;
                offer.flow = Some(rd!(p, s2xcf_Modes));
                text.push_str(&format!(" flow(0x{:x})", offer.flow.unwrap()));
            }
            x::S2XCAP_RSS => {
                let p = it as *const x::S2XCapRSS;
                offer.rss = Some((rd!(p, s2xcr_HashTypes), rd!(p, s2xcr_MaxQueues), rd!(p, s2xcr_KeySize), rd!(p, s2xcr_TableSize), rd!(p, s2xcr_MaxTxQueues)));
                text.push_str(&format!(" rss{:?}", offer.rss.unwrap()));
            }
            _ => text.push_str(&format!(" unknown(0x{:x})", ty)),
        }
    }
    ctx.check("query.items", n > 0 && sizes_ok, format!("{} items:{}", n, text));
    ctx.check("query.features", bits == offer.features & 0xFFFF_FFFE, format!("s2xq_Features 0x{:08x}, items give 0x{:08x}", offer.features, bits));
    // The commands each capability needs, listed.
    let batch_ok = bits & x::S2XF_BATCH == 0 || (cmds.contains(&x::S2X_READBATCH) && cmds.contains(&x::S2X_WRITEBATCH));
    let conf = bits & (x::S2XF_MTU | x::S2XF_MODERATION | x::S2XF_FLOWCONTROL | x::S2XF_RSS);
    let conf_ok = conf == 0 || cmds.contains(&x::S2X_CONFIGURE);
    ctx.check("query.cmdlist", batch_ok && conf_ok, format!("{} commands; READBATCH {}, WRITEBATCH {}, CONFIGURE {}", cmds.len(), cmds.contains(&x::S2X_READBATCH), cmds.contains(&x::S2X_WRITEBATCH), cmds.contains(&x::S2X_CONFIGURE)));
    // Every frame item rides on a batch; segmentation needs TX checksums.
    let frame_caps = bits & (x::S2XF_RXCHECKSUM | x::S2XF_TXCHECKSUM | x::S2XF_SEGMENT | x::S2XF_RSS);
    let mut dep = frame_caps == 0 || bits & x::S2XF_BATCH != 0;
    if let Some((p, ..)) = offer.segment {
        dep &= offer.tx_csum.map_or(false, |t| t & p == p);
    }
    if bits & x::S2XF_BATCH != 0 {
        dep &= offer.max_frames >= 1;
    }
    ctx.check("query.depends", dep, format!("features 0x{:x}, batch max {}, segment {:?}, txcsum {:?}", bits, offer.max_frames, offer.segment, offer.tx_csum));
    // A shorter answer: whole fields up to s2xq_Size, nothing after.
    let mut short = [0xEEu8; 32];
    short[..4].copy_from_slice(&8u32.to_ne_bytes());
    q.set(x::S2X_QUERY, 0);
    q.r.set_stat_data(short.as_mut_ptr() as *mut c_void);
    let (e2, _) = ctx.do_io(&q);
    let m2 = u32::from_ne_bytes([short[4], short[5], short[6], short[7]]);
    let rest = short[8..].iter().all(|&b| b == 0xEE);
    ctx.check("query.short", e2 == 0 && m2 == x::S2X_MAGIC && rest, format!("s2xq_Size 8: error {}, magic 0x{:08x}, bytes after 8 untouched {}", e2, m2, rest));
    // The list is the same for the whole open.
    let mut again: x::S2XQuery = unsafe { core::mem::zeroed() };
    again.s2xq_Size = core::mem::size_of::<x::S2XQuery>() as u32;
    q.set(x::S2X_QUERY, 0);
    q.r.set_stat_data(&mut again as *mut x::S2XQuery as *mut c_void);
    let _ = ctx.do_io(&q);
    ctx.check("query.stable", again.s2xq_Capabilities == caps && { again.s2xq_Features } == offer.features, format!("second answer list {:p} features 0x{:x}", { again.s2xq_Capabilities }, { again.s2xq_Features }));
    ctx.free(q);
    let mut missing = Vec::new();
    for w in need {
        match NAMES.iter().find(|(n, _)| n == w) {
            Some((_, bit)) if bits & bit == 0 => missing.push(w.clone()),
            Some(_) => {}
            None => missing.push(format!("{} (unknown name)", w)),
        }
    }
    if !need.is_empty() {
        ctx.check("query.need", missing.is_empty(), format!("need {:?}; missing {:?}", need, missing));
    }
    offer.ok = true;
    offer
}

/// A received frame as the test sees it.
pub(crate) struct Got {
    pub err: i8,
    pub ptype: u32,
    src: [u8; 6],
    dst: [u8; 6],
    pub len: u32,
    flags: u8,
    pub bytes: Vec<u8>,
}

fn got_of(r: &Req) -> Got {
    Got {
        err: r.error(),
        ptype: r.r.packet_type(),
        src: r.r.src_mac(),
        dst: r.r.dst_mac(),
        len: r.r.data_length(),
        flags: r.r.io().flags(),
        bytes: r.bytes().to_vec(),
    }
}

pub struct T<'a> {
    pub ctx: &'a mut Ctx,
    pub a: &'a mut Opener,
    pub b: &'a mut Opener,
    pub offer: Offer,
    pub only: Vec<String>,
}

impl T<'_> {
    fn wants(&self, name: &str) -> bool {
        self.only.is_empty() || self.only.iter().any(|o| name.starts_with(o.as_str()))
    }

    pub fn run_all(&mut self, _need: &[String]) {
        if !self.offer.ok {
            return;
        }
        if self.offer.features & x::S2XF_BATCH == 0 {
            self.ctx.skip("batch", "no S2XCAP_BATCH");
        } else {
            let tests: [(&str, fn(&mut Self)); 11] = [
                ("batch.write", Self::batch_write),
                ("batch.read", Self::batch_read),
                ("batch.raw", Self::batch_raw),
                ("batch.full", Self::batch_full),
                ("dispatch.order", Self::dispatch_order),
                ("dispatch.batchfirst", Self::dispatch_batch_first),
                ("dispatch.openers", Self::dispatch_openers),
                ("abort.read", Self::abort_read),
                ("abort.write", Self::abort_write),
                ("write.refuse", Self::write_refuse),
                ("bad", Self::bad),
            ];
            for (name, f) in tests {
                if self.wants(name) {
                    f(self);
                    // Frames left over wait at most 100 ms in the driver.
                    self.ctx.sleep(250);
                }
            }
        }
        if self.wants("rxcsum") {
            match self.offer.rx_csum {
                Some(p) => self.rx_checksum(p),
                None => self.ctx.skip("rxcsum", "no S2XCAP_RXCHECKSUM"),
            }
        }
        if self.wants("txcsum") {
            match self.offer.tx_csum {
                Some(p) => self.tx_checksum(p),
                None => self.ctx.skip("txcsum", "no S2XCAP_TXCHECKSUM"),
            }
        }
        if self.wants("tso") {
            match self.offer.segment {
                Some((p, max, _, min)) => crate::tso::run(self, p, max, min),
                None => self.ctx.skip("tso", "no S2XCAP_SEGMENT"),
            }
        }
        if self.wants("rss") {
            match self.offer.rss {
                Some((types, maxq, ..)) => crate::rss::run(self, types, maxq, 2),
                None => self.ctx.skip("rss", "no S2XCAP_RSS"),
            }
        }
        if self.wants("conf") {
            if self.offer.features & (x::S2XF_MTU | x::S2XF_MODERATION | x::S2XF_FLOWCONTROL) == 0 {
                self.ctx.skip("conf", "no setting capability (MTU, moderation, flow control)");
            } else {
                crate::conf::run(self);
            }
        }
    }

    // ---- helpers ----

    /// `n` CMD_READs of `ptype` posted on B.
    pub(crate) fn post_reads(&mut self, n: usize, ptype: u32, flags: u8) -> Vec<Req> {
        let mut v = Vec::new();
        for _ in 0..n {
            let mut r = self.ctx.clone_req(&self.b.req, NORMAL_BUF);
            r.set(CMD_READ, flags);
            r.r.set_packet_type(ptype);
            self.ctx.send(&r);
            v.push(r);
        }
        v
    }

    /// Wait until `want` of `reads` are back (at most `ms`), take what came
    /// (in posting order), and abort and free the rest.
    pub(crate) fn take(&mut self, reads: Vec<Req>, want: usize, ms: u32) -> Vec<Got> {
        {
            let refs: Vec<&Req> = reads.iter().collect();
            let _ = self.ctx.wait_n(&refs, want, ms);
        }
        let mut out = Vec::new();
        for r in reads {
            if self.ctx.poll(&r) {
                out.push(got_of(&r));
            }
            self.ctx.free(r);
        }
        out
    }

    /// A sends one frame with CMD_WRITE (DoIO); its io_Error.
    pub(crate) fn send_one(&mut self, ptype: u32, data: &[u8]) -> i8 {
        let mut w = self.ctx.clone_req(&self.a.req, NORMAL_BUF);
        let bmac = self.b.mac;
        w.set_write(CMD_WRITE, 0, ptype, &bmac, data);
        let (e, _) = self.ctx.do_io(&w);
        self.ctx.free(w);
        e
    }

    /// A write batch on A of `payloads` (test frames to B).
    fn write_batch(&mut self, payloads: &[Vec<u8>]) -> Batch {
        let mut wb = Batch::new(self.ctx, &self.a.req, payloads.len(), NORMAL_BUF, ItemSet::default());
        let bmac = self.b.mac;
        for (i, p) in payloads.iter().enumerate() {
            wb.freqs[i].set_write(CMD_WRITE, 0, ETYPE, &bmac, p);
        }
        wb
    }

    /// Check frames received for test `id`: sequence numbers 0..n in order.
    fn seqs(got: &[Got], id: u8) -> (Vec<u16>, usize) {
        let mut seqs = Vec::new();
        let mut stray = 0;
        for g in got {
            match frames::parse(&g.bytes) {
                Some((i, s)) if i == id => seqs.push(s),
                _ => stray += 1,
            }
        }
        (seqs, stray)
    }

    fn in_order(seqs: &[u16], n: usize) -> bool {
        seqs.len() == n && seqs.iter().enumerate().all(|(i, &s)| s as usize == i)
    }

    // ---- batches ----

    /// A write batch of 8 frames arrives at B whole and in order.
    fn batch_write(&mut self) {
        let id = self.ctx.next_id();
        let n = 8.min(self.offer.max_frames as usize);
        let reads = self.post_reads(n, ETYPE, 0);
        self.ctx.sleep(20);
        let payloads: Vec<Vec<u8>> = (0..n).map(|i| frames::payload(id, i as u16, 60 + i * 150)).collect();
        let mut wb = self.write_batch(&payloads);
        wb.post_write(self.ctx);
        let res = self.ctx.wait(&wb.req, 2000);
        let done = wb.done();
        let ferrs = wb.freqs.iter().filter(|f| f.error() != 0).count();
        let got = self.take(reads, n, 2000);
        let (seqs, stray) = Self::seqs(&got, id);
        let lens_ok = got.iter().zip(payloads.iter()).all(|(g, p)| g.bytes == *p && g.len as usize == p.len());
        let ok = res == Some((0, 0)) && done == n as u32 && ferrs == 0 && Self::in_order(&seqs, n) && lens_ok;
        self.ctx.check("batch.write", ok, format!("{} frames: reply {:?}, s2xb_Done {}, frame errors {}; B got {:?} ({} stray), bytes right {}", n, res, done, ferrs, seqs, stray, lens_ok));
        wb.free(self.ctx);
    }

    /// Collect frames of test `id` through read batch `rb` (posted again
    /// after each reply) until `n` came or `ms` passed. Returns (frames in
    /// order, Done of each reply, field problems).
    fn collect_batch(&mut self, rb: &mut Batch, flags: u8, n: usize, ms: u32) -> (Vec<Got>, Vec<u32>, Vec<String>) {
        let mut all = Vec::new();
        let mut dones = Vec::new();
        let mut bad = Vec::new();
        let mut waited = 0;
        while all.len() < n && waited < ms {
            match self.ctx.wait(&rb.req, 50) {
                None => waited += 50,
                Some((e, w)) => {
                    let d = rb.done();
                    dones.push(d);
                    if e != 0 {
                        bad.push(format!("batch error {} wire {}", e, w));
                    }
                    if d == 0 || d as usize > rb.freqs.len() {
                        bad.push(format!("s2xb_Done {}", d));
                    }
                    for i in 0..(d as usize).min(rb.freqs.len()) {
                        all.push(got_of(&rb.freqs[i]));
                    }
                    if all.len() < n {
                        rb.post_read(self.ctx, ETYPE, flags);
                    }
                }
            }
        }
        (all, dones, bad)
    }

    /// One read batch of 16 takes the 5 frames of a write batch (in one or
    /// more replies), each frame's request filled as CMD_READ would be.
    fn batch_read(&mut self) {
        let id = self.ctx.next_id();
        let n = 5;
        let cap = 16.min(self.offer.max_frames as usize);
        let mut rb = Batch::new(self.ctx, &self.b.req, cap, NORMAL_BUF, ItemSet::default());
        rb.post_read(self.ctx, ETYPE, 0);
        self.ctx.sleep(20);
        let payloads: Vec<Vec<u8>> = (0..n).map(|i| frames::payload(id, i as u16, 100 + i * 7)).collect();
        let mut wb = self.write_batch(&payloads);
        wb.post_write(self.ctx);
        let wres = self.ctx.wait(&wb.req, 2000);
        let (got, dones, mut bad) = self.collect_batch(&mut rb, 0, n, 2000);
        let (amac, bmac) = (self.a.mac, self.b.mac);
        for (i, g) in got.iter().enumerate() {
            let want = payloads.get(i);
            if g.err != 0 || g.ptype != ETYPE || g.src != amac || g.dst != bmac || Some(&g.bytes) != want || g.len as usize != g.bytes.len() || g.flags & (SANA2IOF_BCAST | SANA2IOF_MCAST) != 0 {
                bad.push(format!("frame {}: error {} type 0x{:x} src {} dst {} len {} flags 0x{:x}", i, g.err, g.ptype, crate::mac(&g.src), crate::mac(&g.dst), g.len, g.flags));
            }
        }
        let (seqs, stray) = Self::seqs(&got, id);
        let ok = wres == Some((0, 0)) && Self::in_order(&seqs, n) && bad.is_empty();
        self.ctx.check("batch.read", ok, format!("write {:?}; {} frames in replies with s2xb_Done {:?}: {:?} ({} stray) {:?}", wres, got.len(), dones, seqs, stray, bad));
        wb.free(self.ctx);
        rb.free(self.ctx);
    }

    /// SANA2IOF_RAW on a read batch: every frame comes with its Ethernet
    /// header.
    fn batch_raw(&mut self) {
        let id = self.ctx.next_id();
        let n = 3;
        let mut rb = Batch::new(self.ctx, &self.b.req, 8.min(self.offer.max_frames as usize), NORMAL_BUF, ItemSet::default());
        rb.post_read(self.ctx, ETYPE, SANA2IOF_RAW);
        self.ctx.sleep(20);
        let payloads: Vec<Vec<u8>> = (0..n).map(|i| frames::payload(id, i as u16, 80)).collect();
        let mut wb = self.write_batch(&payloads);
        wb.post_write(self.ctx);
        let _ = self.ctx.wait(&wb.req, 2000);
        let (got, dones, mut bad) = self.collect_batch(&mut rb, SANA2IOF_RAW, n, 2000);
        let (amac, bmac) = (self.a.mac, self.b.mac);
        let mut seqs = Vec::new();
        for (i, g) in got.iter().enumerate() {
            let b = &g.bytes;
            let hdr_ok = b.len() == 14 + 80 && b[..6] == bmac && b[6..12] == amac && b[12..14] == (ETYPE as u16).to_be_bytes();
            if !hdr_ok || g.len as usize != b.len() {
                bad.push(format!("frame {}: {} bytes, header right {}", i, b.len(), hdr_ok));
            }
            if b.len() > 14 {
                if let Some((fid, s)) = frames::parse(&b[14..]) {
                    if fid == id {
                        seqs.push(s);
                    }
                }
            }
        }
        let ok = Self::in_order(&seqs, n) && bad.is_empty();
        self.ctx.check("batch.raw", ok, format!("{} frames (Done {:?}): {:?} {:?}", got.len(), dones, seqs, bad));
        wb.free(self.ctx);
        rb.free(self.ctx);
    }

    /// A read batch of 4 never reports more than 4; 10 frames come through
    /// it, reposted, in order.
    fn batch_full(&mut self) {
        let id = self.ctx.next_id();
        let n = 10.min(self.offer.max_frames as usize);
        let mut rb = Batch::new(self.ctx, &self.b.req, 4, NORMAL_BUF, ItemSet::default());
        rb.post_read(self.ctx, ETYPE, 0);
        self.ctx.sleep(20);
        let payloads: Vec<Vec<u8>> = (0..n).map(|i| frames::payload(id, i as u16, 64)).collect();
        let mut wb = self.write_batch(&payloads);
        wb.post_write(self.ctx);
        let _ = self.ctx.wait(&wb.req, 2000);
        let (got, dones, bad) = self.collect_batch(&mut rb, 0, n, 3000);
        let (seqs, stray) = Self::seqs(&got, id);
        // Frames that came while no batch was posted wait in the driver
        // (up to its hold time); none may be lost while one is posted
        // again at once.
        let ok = Self::in_order(&seqs, n) && bad.is_empty() && dones.iter().all(|&d| (1..=4).contains(&d));
        self.ctx.check("batch.full", ok, format!("{} frames, replies with s2xb_Done {:?}: {:?} ({} stray) {:?}", got.len(), dones, seqs, stray, bad));
        wb.free(self.ctx);
        rb.free(self.ctx);
    }

    // ---- which request gets a frame ----

    /// CMD_READ r1, then a read batch, then CMD_READ r2, posted in that
    /// order: three frames sent one at a time go to r1, the batch, r2.
    fn dispatch_order(&mut self) {
        let id = self.ctx.next_id();
        let mut r1 = self.post_reads(1, ETYPE, 0);
        self.ctx.sleep(10);
        let mut rb = Batch::new(self.ctx, &self.b.req, 4.min(self.offer.max_frames as usize), NORMAL_BUF, ItemSet::default());
        rb.post_read(self.ctx, ETYPE, 0);
        self.ctx.sleep(10);
        let mut r2 = self.post_reads(1, ETYPE, 0);
        self.ctx.sleep(10);
        let mut seen = [None, None, None];
        let e0 = self.send_one(ETYPE, &frames::payload(id, 0, 64));
        if self.ctx.wait(&r1[0], 1000).is_some() {
            seen[0] = frames::parse(r1[0].bytes()).map(|p| p.1);
        }
        let e1 = self.send_one(ETYPE, &frames::payload(id, 1, 64));
        let mut bdone = 0;
        if self.ctx.wait(&rb.req, 1000).is_some() {
            bdone = rb.done();
            if bdone >= 1 {
                seen[1] = frames::parse(rb.freqs[0].bytes()).map(|p| p.1);
            }
        }
        let e2 = self.send_one(ETYPE, &frames::payload(id, 2, 64));
        if self.ctx.wait(&r2[0], 1000).is_some() {
            seen[2] = frames::parse(r2[0].bytes()).map(|p| p.1);
        }
        let ok = e0 == 0 && e1 == 0 && e2 == 0 && seen == [Some(0), Some(1), Some(2)] && bdone == 1;
        self.ctx.check("dispatch.order", ok, format!("r1, batch, r2 posted in that order got frames {:?} (batch s2xb_Done {}; write errors {} {} {})", seen, bdone, e0, e1, e2));
        for r in r1.drain(..).chain(r2.drain(..)) {
            self.ctx.free(r);
        }
        rb.free(self.ctx);
    }

    /// A read batch posted before a CMD_READ gets the first frame.
    fn dispatch_batch_first(&mut self) {
        let id = self.ctx.next_id();
        let mut rb = Batch::new(self.ctx, &self.b.req, 4.min(self.offer.max_frames as usize), NORMAL_BUF, ItemSet::default());
        rb.post_read(self.ctx, ETYPE, 0);
        self.ctx.sleep(10);
        let mut r1 = self.post_reads(1, ETYPE, 0);
        self.ctx.sleep(10);
        let _ = self.send_one(ETYPE, &frames::payload(id, 0, 64));
        let mut first = None;
        if self.ctx.wait(&rb.req, 1000).is_some() && rb.done() >= 1 {
            first = frames::parse(rb.freqs[0].bytes()).map(|p| p.1);
        }
        let r1_waits = !self.ctx.poll(&r1[0]);
        let _ = self.send_one(ETYPE, &frames::payload(id, 1, 64));
        let second = if self.ctx.wait(&r1[0], 1000).is_some() { frames::parse(r1[0].bytes()).map(|p| p.1) } else { None };
        let ok = first == Some(0) && r1_waits && second == Some(1);
        self.ctx.check("dispatch.batchfirst", ok, format!("batch then r1 posted: batch got {:?}, r1 still waiting {}, then r1 got {:?}", first, r1_waits, second));
        for r in r1.drain(..) {
            self.ctx.free(r);
        }
        rb.free(self.ctx);
    }

    /// Two openers on B (a read batch and a CMD_READ): each gets the frame.
    fn dispatch_openers(&mut self) {
        let id = self.ctx.next_id();
        let unit = self.b.unit;
        let b2 = match self.ctx.open(unit) {
            Ok(o) => o,
            Err(e) => {
                self.ctx.check("dispatch.openers", false, format!("second OpenDevice on unit {}: error {}", unit, e));
                return;
            }
        };
        let mut rb = Batch::new(self.ctx, &self.b.req, 4.min(self.offer.max_frames as usize), NORMAL_BUF, ItemSet::default());
        rb.post_read(self.ctx, ETYPE, 0);
        let mut r2 = self.ctx.clone_req(&b2.req, NORMAL_BUF);
        r2.set(CMD_READ, 0);
        r2.r.set_packet_type(ETYPE);
        self.ctx.send(&r2);
        self.ctx.sleep(10);
        let _ = self.send_one(ETYPE, &frames::payload(id, 7, 64));
        let a = if self.ctx.wait(&rb.req, 1000).is_some() && rb.done() >= 1 { frames::parse(rb.freqs[0].bytes()) } else { None };
        let b = if self.ctx.wait(&r2, 1000).is_some() { frames::parse(r2.bytes()) } else { None };
        self.ctx.check("dispatch.openers", a == Some((id, 7)) && b == Some((id, 7)), format!("opener 1 (read batch) got {:?}, opener 2 (CMD_READ) got {:?}", a, b));
        self.ctx.free(r2);
        rb.free(self.ctx);
        self.ctx.close(b2);
    }

    // ---- abort ----

    /// An idle read batch, aborted: IOERR_ABORTED, s2xb_Done 0.
    fn abort_read(&mut self) {
        let mut rb = Batch::new(self.ctx, &self.b.req, 4.min(self.offer.max_frames as usize), NORMAL_BUF, ItemSet::default());
        rb.post_read(self.ctx, 0x88B6, 0);
        self.ctx.sleep(50);
        let pending = !self.ctx.poll(&rb.req);
        let res = self.ctx.abort(&rb.req);
        let done = rb.done();
        let ok = pending && matches!(res, Some((e, _)) if e == IOERR_ABORTED) && done == 0;
        self.ctx.check("abort.read", ok, format!("pending before {}, after AbortIO {:?}, s2xb_Done {}", pending, res, done));
        rb.free(self.ctx);
    }

    /// A write batch of the most frames, aborted at once: either it was all
    /// taken (no error, s2xb_Done = Count) or it came back IOERR_ABORTED;
    /// either way B receives exactly s2xb_Done frames.
    fn abort_write(&mut self) {
        let id = self.ctx.next_id();
        let n = self.offer.max_frames.min(64) as usize;
        let reads = self.post_reads(n, ETYPE, 0);
        self.ctx.sleep(20);
        let payloads: Vec<Vec<u8>> = (0..n).map(|i| frames::payload(id, i as u16, 1000)).collect();
        let mut wb = self.write_batch(&payloads);
        wb.post_write(self.ctx);
        let res = self.ctx.abort(&wb.req);
        let done = wb.done();
        let got = self.take(reads, done as usize, 1500);
        self.ctx.sleep(300);
        let (seqs, stray) = Self::seqs(&got, id);
        let branch = match res {
            Some((0, _)) => "all taken before the abort",
            Some((e, _)) if e == IOERR_ABORTED => "aborted part-way",
            _ => "unexpected",
        };
        let ok = matches!(res, Some((0, _))) && done as usize == n || matches!(res, Some((e, _)) if e == IOERR_ABORTED) && (done as usize) <= n;
        let ok = ok && Self::in_order(&seqs, done as usize);
        self.ctx.check("abort.write", ok, format!("{} frames, AbortIO at once: {:?} ({}), s2xb_Done {}; B got {} frames ({} stray)", n, res, branch, done, seqs.len(), stray));
        wb.free(self.ctx);
    }

    // ---- refusal ----

    /// A write batch whose fourth frame is too long: the first three go,
    /// the fourth has the error and so does the batch, the last two are
    /// untouched, and B gets exactly three frames.
    fn write_refuse(&mut self) {
        let id = self.ctx.next_id();
        let n = 6.min(self.offer.max_frames as usize);
        if n < 6 {
            self.ctx.skip("write.refuse", "batches of fewer than 6 frames");
            return;
        }
        let reads = self.post_reads(n, ETYPE, 0);
        self.ctx.sleep(20);
        let mtu = self.b.mtu.max(self.a.mtu) as usize;
        let payloads: Vec<Vec<u8>> = (0..n).map(|i| frames::payload(id, i as u16, if i == 3 { (mtu + 100).min(NORMAL_BUF) } else { 200 })).collect();
        let mut wb = self.write_batch(&payloads);
        for f in wb.freqs[4..].iter_mut() {
            f.r.io().set_error(0x55);
            f.r.set_wire_error(0xDEAD_BEEF);
        }
        wb.post_write(self.ctx);
        let res = self.ctx.wait(&wb.req, 2000);
        let done = wb.done();
        let errs: Vec<(i8, u32)> = wb.freqs.iter().map(|f| (f.error(), f.r.wire_error())).collect();
        let got = self.take(reads, 3, 1500);
        self.ctx.sleep(300);
        let (seqs, stray) = Self::seqs(&got, id);
        let berr = res.map(|r| r.0).unwrap_or(0);
        let ok = berr != 0
            && done == 3
            && errs[..3].iter().all(|&(e, _)| e == 0)
            && errs[3].0 == berr
            && errs[4..].iter().all(|&(e, w)| e == 0x55 && w == 0xDEAD_BEEF)
            && Self::in_order(&seqs, 3);
        self.ctx.check("write.refuse", ok, format!("frame 3 of {} bytes (MTU {}): reply {:?}, s2xb_Done {}, frame errors {:?}; B got {:?} ({} stray)", payloads[3].len(), mtu, res, done, errs, seqs, stray));
        wb.free(self.ctx);
    }

    /// Malformed batches are refused (and come back at once).
    fn bad(&mut self) {
        // ios2_StatData NULL, both commands.
        for (cmd, what) in [(x::S2X_READBATCH, "read"), (x::S2X_WRITEBATCH, "write")] {
            let mut r = self.ctx.clone_req(&self.b.req, 16);
            r.set(cmd, 0);
            r.r.set_packet_type(ETYPE);
            r.r.set_stat_data(core::ptr::null_mut());
            self.ctx.send(&r);
            let res = self.ctx.wait(&r, 1000);
            self.ctx.check(&format!("bad.null.{}", what), matches!(res, Some((e, _)) if e != 0), format!("{} batch with ios2_StatData NULL: {:?}", what, res));
            self.ctx.free(r);
        }
        let max = self.offer.max_frames as usize;
        // s2xb_Count 0, a queue that does not exist, s2xb_Size too small.
        let cases: [(&str, u32, u32, u32); 3] = [("bad.count0", 0, 0, 0), ("bad.queue", 1, 99, 0), ("bad.size", 1, 0, 8)];
        for (name, count, queue, size) in cases {
            let mut rb = Batch::new(self.ctx, &self.b.req, 2.min(max), NORMAL_BUF, ItemSet::default());
            rb.set_count(count);
            rb.set_queue(queue);
            if size != 0 {
                rb.hdr.s2xb_Size = size;
            }
            rb.post_read(self.ctx, ETYPE, 0);
            let res = self.ctx.wait(&rb.req, 1000);
            self.ctx.check(name, matches!(res, Some((e, _)) if e != 0), format!("read batch (Count {}, Queue {}, Size {}): {:?}", count, queue, if size != 0 { size } else { rb.hdr.s2xb_Size }, res));
            rb.free(self.ctx);
        }
        // More frames than s2xcb_MaxFrames: the spec does not say; report.
        if max < 256 {
            let mut rb = Batch::new(self.ctx, &self.b.req, max + 1, NORMAL_BUF, ItemSet::default());
            rb.post_read(self.ctx, 0x88B6, 0);
            let res = self.ctx.wait(&rb.req, 200);
            let detail = match res {
                Some((e, w)) => format!("refused at once: error {} wire {}", e, w),
                None => "accepted (pending)".into(),
            };
            self.ctx.info("bad.overmax", format!("read batch of {} frames (MaxFrames {}): {}", max + 1, max, detail));
            rb.free(self.ctx);
        }
    }

    // ---- receive checksums ----

    fn rx_checksum(&mut self, protos: u32) {
        struct Case {
            name: &'static str,
            v6: bool,
            proto: u8,
            /// 0 right, 1 transport checksum wrong, 2 IPv4 header checksum
            /// wrong, 3 UDP checksum 0 (not used), 4 an IPv4 first fragment (MF).
            fault: u8,
        }
        let cases = [
            Case { name: "rxcsum.v4.udp", v6: false, proto: PROTO_UDP, fault: 0 },
            Case { name: "rxcsum.v4.udp.bad", v6: false, proto: PROTO_UDP, fault: 1 },
            Case { name: "rxcsum.v4.tcp", v6: false, proto: PROTO_TCP, fault: 0 },
            Case { name: "rxcsum.v4.tcp.bad", v6: false, proto: PROTO_TCP, fault: 1 },
            Case { name: "rxcsum.v4.ip.bad", v6: false, proto: PROTO_UDP, fault: 2 },
            Case { name: "rxcsum.v6.udp", v6: true, proto: PROTO_UDP, fault: 0 },
            Case { name: "rxcsum.v6.udp.bad", v6: true, proto: PROTO_UDP, fault: 1 },
            Case { name: "rxcsum.v6.tcp", v6: true, proto: PROTO_TCP, fault: 0 },
            Case { name: "rxcsum.v6.tcp.bad", v6: true, proto: PROTO_TCP, fault: 1 },
            Case { name: "rxcsum.v4.udp.zero", v6: false, proto: PROTO_UDP, fault: 3 },
            Case { name: "rxcsum.v4.frag", v6: false, proto: PROTO_UDP, fault: 4 },
        ];
        let items = ItemSet { checksum: true, private: true, ..ItemSet::default() };
        for (k, c) in cases.iter().enumerate() {
            let id = self.ctx.next_id();
            let data = frames::payload(id, k as u16, 40);
            let mut l4 = frames::transport(c.v6, c.proto, 4000 + k as u16, 5000, 1000, &data);
            let at = frames::l4_csum_at(c.proto);
            if c.fault == 1 {
                l4[at] ^= 0x55;
            }
            if c.fault == 3 {
                l4[at] = 0;
                l4[at + 1] = 0;
            }
            let mut pkt = if c.v6 { frames::ipv6(c.proto, &l4) } else { frames::ipv4(c.proto, 0x100 + k as u16, &l4) };
            if c.fault == 2 {
                pkt[10] ^= 0x33;
            }
            if c.fault == 4 {
                // More fragments: the transport checksum covers a whole
                // datagram, so no L4 result may come for this part.
                pkt[6] |= 0x20;
                pkt[10] = 0;
                pkt[11] = 0;
                let c = frames::checksum(&pkt[..20]);
                pkt[10..12].copy_from_slice(&c.to_be_bytes());
            }
            let ety = if c.v6 { ETYPE_IPV6 } else { ETYPE_IPV4 };
            let mut rb = Batch::new(self.ctx, &self.b.req, 2.min(self.offer.max_frames as usize), NORMAL_BUF, items);
            rb.post_read(self.ctx, ety, 0);
            self.ctx.sleep(10);
            let e = self.send_one(ety, &pkt);
            let res = self.ctx.wait(&rb.req, 1000);
            let mut flags = None;
            let mut bytes_ok = false;
            let mut private_ok = false;
            if res.is_some() && rb.done() >= 1 {
                flags = Some(rb.csum_flags(0));
                let b = rb.freqs[0].bytes();
                bytes_ok = b.len() >= pkt.len() && b[..pkt.len()] == pkt[..];
                if let Some(p) = &rb.private[0] {
                    private_ok = { p.s2xfr_Hash } == 0x1234_5678 && { p.s2xfr_HashType } == 0x9ABC_DEF0 && { p.s2xfr_Header.s2xi_Type } == PRIVATE_ITEM;
                }
            }
            let Some(f) = flags else {
                self.ctx.check(c.name, false, format!("nothing received (write error {}, batch {:?})", e, res));
                rb.free(self.ctx);
                continue;
            };
            let l4bit = match (c.v6, c.proto) {
                (false, PROTO_TCP) => x::S2XCSUM_TCPV4,
                (false, _) => x::S2XCSUM_UDPV4,
                (true, PROTO_TCP) => x::S2XCSUM_TCPV6,
                (true, _) => x::S2XCSUM_UDPV6,
            };
            let ip_claimed = !c.v6 && protos & x::S2XCSUM_IPV4 != 0;
            let l4_claimed = protos & l4bit != 0;
            let ipf = f & (x::S2XCS_IP_GOOD | x::S2XCS_IP_BAD);
            let l4f = f & (x::S2XCS_L4_GOOD | x::S2XCS_L4_BAD);
            let ip_ok = if c.v6 {
                ipf == 0
            } else if !ip_claimed {
                true
            } else if c.fault == 2 {
                ipf == x::S2XCS_IP_BAD
            } else {
                ipf == x::S2XCS_IP_GOOD
            };
            let l4_ok = match c.fault {
                // A bad IPv4 header: the transport result is not checked.
                2 | 3 => l4f != x::S2XCS_L4_BAD || c.fault == 2,
                // A fragment: never an L4 result.
                4 => l4f == 0,
                _ if !l4_claimed => true,
                1 => l4f == x::S2XCS_L4_BAD,
                _ => l4f == x::S2XCS_L4_GOOD,
            };
            let unclaimed = (!c.v6 && !ip_claimed) || !l4_claimed;
            let detail = format!(
                "flags 0x{:x} (IP {}, L4 {}), protocols claimed IP {} L4 {}, bytes right {}, private item untouched {}",
                f,
                match ipf { x::S2XCS_IP_GOOD => "good", x::S2XCS_IP_BAD => "bad", 0 => "not checked", _ => "good+bad" },
                match l4f { x::S2XCS_L4_GOOD => "good", x::S2XCS_L4_BAD => "bad", 0 => "not checked", _ => "good+bad" },
                ip_claimed, l4_claimed, bytes_ok, private_ok
            );
            if c.fault == 4 {
                // Never an L4 result on a fragment, claimed or not.
                self.ctx.check(c.name, l4_ok && ip_ok && bytes_ok && private_ok, detail);
            } else if c.fault == 3 {
                // UDP over IPv4 without a checksum: either "not checked" or
                // good is right; only "bad" would be wrong.
                self.ctx.check(c.name, l4f != x::S2XCS_L4_BAD && ip_ok && bytes_ok && private_ok, detail);
            } else if unclaimed && ip_ok && l4_ok {
                self.ctx.info(c.name, detail);
            } else {
                self.ctx.check(c.name, ip_ok && l4_ok && bytes_ok && private_ok, detail);
            }
            rb.free(self.ctx);
        }
        // A frame with no checksum item still arrives (nothing to fill).
        let id = self.ctx.next_id();
        let l4 = frames::transport(false, PROTO_UDP, 4100, 5000, 0, &frames::payload(id, 0, 40));
        let pkt = frames::ipv4(PROTO_UDP, 0x200, &l4);
        let mut rb = Batch::new(self.ctx, &self.b.req, 2.min(self.offer.max_frames as usize), NORMAL_BUF, ItemSet::default());
        rb.post_read(self.ctx, ETYPE_IPV4, 0);
        self.ctx.sleep(10);
        let _ = self.send_one(ETYPE_IPV4, &pkt);
        let res = self.ctx.wait(&rb.req, 1000);
        let ok = res == Some((0, 0)) && rb.done() >= 1 && rb.freqs[0].bytes().get(..pkt.len()) == Some(&pkt[..]);
        self.ctx.check("rxcsum.noitem", ok, format!("frame without items: {:?}, s2xb_Done {}", res, rb.done()));
        rb.free(self.ctx);
        // A non-IP frame: nothing checked.
        let id = self.ctx.next_id();
        let mut rb = Batch::new(self.ctx, &self.b.req, 2.min(self.offer.max_frames as usize), NORMAL_BUF, ItemSet { checksum: true, ..ItemSet::default() });
        rb.post_read(self.ctx, ETYPE, 0);
        self.ctx.sleep(10);
        let _ = self.send_one(ETYPE, &frames::payload(id, 0, 64));
        let res = self.ctx.wait(&rb.req, 1000);
        let got = res.is_some() && rb.done() >= 1;
        self.ctx.check("rxcsum.nonip", got && rb.csum_flags(0) == 0, format!("EtherType 0x{:04x}: received {}, flags 0x{:x}", ETYPE, got, if got { rb.csum_flags(0) } else { 0 }));
        rb.free(self.ctx);
        let _ = (ETYPE_IPV6, frames::ipv4_ok, frames::l4_ok);
    }

    // ---- transmit checksums ----

    /// Write batches whose frames ask the driver for checksums (the IPv4
    /// header's zeroed, the transport field holding the pseudo-header sum,
    /// as the spec says); B reads them with plain CMD_READs and checks
    /// every checksum in software, and the rest of each packet byte for
    /// byte.
    fn tx_checksum(&mut self, protos: u32) {
        struct Case {
            name: &'static str,
            v6: bool,
            /// 6/17 TCP/UDP; 1 ICMP (a sum the card's TCP/UDP model does
            /// not fit: Start at the ICMP header, Offset 2, no
            /// pseudo-header).
            proto: u8,
            fill_ip: bool,
            fill_l4: bool,
            raw: bool,
            need: u32,
            /// Payload bytes (None: the usual size). Small frames (under the
            /// 60-byte minimum) catch padding that leaks into the packet.
            dlen: Option<usize>,
        }
        let cases = [
            Case { name: "txcsum.v4.udp", v6: false, proto: PROTO_UDP, fill_ip: true, fill_l4: true, raw: false, need: x::S2XCSUM_IPV4 | x::S2XCSUM_UDPV4, dlen: None },
            Case { name: "txcsum.v4.tcp", v6: false, proto: PROTO_TCP, fill_ip: true, fill_l4: true, raw: false, need: x::S2XCSUM_IPV4 | x::S2XCSUM_TCPV4, dlen: None },
            Case { name: "txcsum.v4.iponly", v6: false, proto: PROTO_UDP, fill_ip: true, fill_l4: false, raw: false, need: x::S2XCSUM_IPV4, dlen: None },
            Case { name: "txcsum.v4.l4only", v6: false, proto: PROTO_TCP, fill_ip: false, fill_l4: true, raw: false, need: x::S2XCSUM_TCPV4, dlen: None },
            Case { name: "txcsum.v6.udp", v6: true, proto: PROTO_UDP, fill_ip: false, fill_l4: true, raw: false, need: x::S2XCSUM_UDPV6, dlen: None },
            Case { name: "txcsum.v6.tcp", v6: true, proto: PROTO_TCP, fill_ip: false, fill_l4: true, raw: false, need: x::S2XCSUM_TCPV6, dlen: None },
            Case { name: "txcsum.v4.tcp.raw", v6: false, proto: PROTO_TCP, fill_ip: true, fill_l4: true, raw: true, need: x::S2XCSUM_IPV4 | x::S2XCSUM_TCPV4, dlen: None },
            Case { name: "txcsum.v4.icmp", v6: false, proto: 1, fill_ip: true, fill_l4: true, raw: false, need: x::S2XCSUM_IPV4, dlen: None },
            // Short RAW frames, as a stack sends its pure ACKs and pings.
            Case { name: "txcsum.v4.ack.raw", v6: false, proto: PROTO_TCP, fill_ip: true, fill_l4: true, raw: true, need: x::S2XCSUM_IPV4 | x::S2XCSUM_TCPV4, dlen: Some(0) },
            Case { name: "txcsum.v4.ack.l4only.raw", v6: false, proto: PROTO_TCP, fill_ip: false, fill_l4: true, raw: true, need: x::S2XCSUM_TCPV4, dlen: Some(0) },
            Case { name: "txcsum.v4.ack.iponly.raw", v6: false, proto: PROTO_TCP, fill_ip: true, fill_l4: false, raw: true, need: x::S2XCSUM_IPV4, dlen: Some(0) },
            Case { name: "txcsum.v4.udp.small.raw", v6: false, proto: PROTO_UDP, fill_ip: true, fill_l4: true, raw: true, need: x::S2XCSUM_IPV4 | x::S2XCSUM_UDPV4, dlen: Some(4) },
            Case { name: "txcsum.v4.icmp.iponly.raw", v6: false, proto: 1, fill_ip: true, fill_l4: false, raw: true, need: x::S2XCSUM_IPV4, dlen: Some(56) },
            Case { name: "txcsum.v6.ack.raw", v6: true, proto: PROTO_TCP, fill_ip: false, fill_l4: true, raw: true, need: x::S2XCSUM_TCPV6, dlen: Some(0) },
        ];
        for (k, c) in cases.iter().enumerate() {
            if protos & c.need != c.need {
                self.ctx.skip(c.name, "protocol not in S2XCAP_TXCHECKSUM");
                continue;
            }
            let id = self.ctx.next_id();
            let data = match c.dlen {
                Some(0) => Vec::new(),
                Some(n) => frames::payload(id, k as u16, n.max(6))[..n].to_vec(),
                None => frames::payload(id, k as u16, 120 + k * 33),
            };
            // The packet as it must arrive (every checksum right) ...
            let l4 = if c.proto == 1 {
                let mut m = alloc::vec![8u8, 0, 0, 0, 0x12, 0x34, 0, k as u8];
                m.extend_from_slice(&data);
                let s = frames::checksum(&m);
                m[2..4].copy_from_slice(&s.to_be_bytes());
                m
            } else {
                frames::transport(c.v6, c.proto, 6000 + k as u16, 7000, 5000, &data)
            };
            let good = if c.v6 { frames::ipv6(c.proto, &l4) } else { frames::ipv4(c.proto, 0x300 + k as u16, &l4) };
            // ... and as it is handed to the driver.
            let iphl = if c.v6 { 40 } else { 20 };
            let mut sent = good.clone();
            if c.fill_ip {
                sent[10] = 0;
                sent[11] = 0;
            }
            let (start, offset) = if c.proto == 1 { (iphl, 2) } else { (iphl, frames::l4_csum_at(c.proto)) };
            if c.fill_l4 {
                let v = if c.proto == 1 { 0 } else { frames::fold(frames::pseudo(c.v6, c.proto, l4.len())) };
                sent[start + offset..start + offset + 2].copy_from_slice(&v.to_be_bytes());
            }
            let ety = if c.v6 { ETYPE_IPV6 } else { ETYPE_IPV4 };
            let (amac, bmac) = (self.a.mac, self.b.mac);
            let mut wire = Vec::new();
            if c.raw {
                wire.extend_from_slice(&bmac);
                wire.extend_from_slice(&amac);
                wire.extend_from_slice(&(ety as u16).to_be_bytes());
            }
            let hl = wire.len();
            wire.extend_from_slice(&sent);
            let reads = self.post_reads(1, ety, 0);
            self.ctx.sleep(10);
            let mut wb = Batch::new(self.ctx, &self.a.req, 1, NORMAL_BUF, ItemSet { checksum: true, ..ItemSet::default() });
            wb.freqs[0].set_write(CMD_WRITE, if c.raw { SANA2IOF_RAW } else { 0 }, ety, &bmac, &wire);
            let flags = if c.fill_ip { x::S2XCS_FILL_IP } else { 0 } | if c.fill_l4 { x::S2XCS_FILL_L4 } else { 0 };
            wb.set_csum(0, flags, (hl + start) as u16, offset as u16);
            wb.post_write(self.ctx);
            let res = self.ctx.wait(&wb.req, 1000);
            let got = self.take(reads, 1, 1000);
            let Some(g) = got.first() else {
                self.ctx.check(c.name, false, format!("nothing received (write {:?})", res));
                wb.free(self.ctx);
                continue;
            };
            let b = &g.bytes;
            let ip_ok = c.v6 || frames::ipv4_ok(b);
            let l4_ok = if c.proto == 1 {
                b.len() >= good.len() && frames::checksum(&b[20..good.len()]) == 0
            } else {
                frames::l4_ok(b) == Some(true)
            };
            let same = b.len() >= good.len() && b[..good.len()] == good[..];
            let ok = res == Some((0, 0)) && ip_ok && l4_ok && same;
            self.ctx.check(c.name, ok, format!("write {:?}; received {} bytes: IP header checksum right {}, {} checksum right {}, packet as expected {}", res, b.len(), ip_ok, if c.proto == 1 { "ICMP" } else { "transport" }, l4_ok, same));
            wb.free(self.ctx);
            self.ctx.sleep(20);
        }
        // A request that does not fit the frame (the result would lie
        // past its end): the spec does not say what happens; report it.
        let id = self.ctx.next_id();
        let data = frames::payload(id, 0, 80);
        let reads = self.post_reads(1, ETYPE, 0);
        let mut wb = Batch::new(self.ctx, &self.a.req, 1, NORMAL_BUF, ItemSet { checksum: true, ..ItemSet::default() });
        let bmac = self.b.mac;
        wb.freqs[0].set_write(CMD_WRITE, 0, ETYPE, &bmac, &data);
        wb.set_csum(0, x::S2XCS_FILL_L4, 70, 20);
        wb.post_write(self.ctx);
        let res = self.ctx.wait(&wb.req, 1000);
        let got = self.take(reads, 1, 500);
        self.ctx.info("txcsum.outside", format!("FILL_L4 with the result past the frame's end: write {:?}, frame error {}, B received {}", res, wb.freqs[0].error(), got.len()));
        wb.free(self.ctx);
    }
}
