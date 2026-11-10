//! s2xtest: a conformance test for SANA-II drivers that offer the
//! unofficial SANA-II extensions (sana2ext, docs/devices/sana2ext.md in the
//! amigaos4 crate). It drives two units of one driver joined by one link
//! (a cable between two ports, or two QEMU cards on one network): unit A
//! sends, unit B receives, so every check sees what really went over the
//! wire.
//!
//!   s2xtest <device> <unit A> <unit B> [only=a,b,...] [need=batch,rxcsum,...]
//!
//! Each capability the driver lists in S2X_QUERY is checked; what it does
//! not list is skipped (or fails, if named in need=). Every check prints
//! PASS, FAIL, SKIP or INFO; the tool returns 0 when nothing failed. Every
//! check needs a positive count of what it read: a check that receives
//! nothing fails by name.

#![no_std]
#![no_main]

extern crate alloc;

mod frames;
mod conf;
mod tso;
mod rss;
mod echo;
mod tests;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use core::ffi::c_void;
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut, null_mut};

use amigaos4::allocator::SharedExecAllocator;
use amigaos4::device::cmd::NSCMD_DEVICEQUERY;
use amigaos4::port::AmigaMsgPort;
use amigaos4::sana2::*;
use amigaos4::sana2ext as x;
use amigaos4::sys::{self, TagItem};
use amigaos4::timer::{AmigaTimer, TimerUnit, TimerVal};

// Batches, frames and items are handed to the driver: shared memory.
#[global_allocator]
static ALLOCATOR: SharedExecAllocator = SharedExecAllocator;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    amigaos4::panic::default_panic_handler(info)
}

pub struct Out;
impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut buf = [0u8; 128];
        for chunk in s.as_bytes().chunks(buf.len() - 1) {
            buf[..chunk.len()].copy_from_slice(chunk);
            buf[chunk.len()] = 0;
            // SAFETY: a NUL-terminated buffer on the stack.
            unsafe { sys::dos_put_str(buf.as_ptr() as _) };
        }
        Ok(())
    }
}
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {{ let _ = core::fmt::Write::write_fmt(&mut $crate::Out, format_args!("{}\n", format_args!($($arg)*))); }};
}

// ---- The stack side of buffer management ----
//
// A buffer cookie is a pointer to a Buf: its bytes and how many are used.

pub struct Buf {
    pub len: u32,
    pub data: Vec<u8>,
}

unsafe fn copy_to(to: *mut c_void, from: *const u8, n: u32) -> u32 {
    let b = to as *mut Buf;
    if b.is_null() || n as usize > (*b).data.len() {
        return 0;
    }
    core::ptr::copy_nonoverlapping(from, (*b).data.as_mut_ptr(), n as usize);
    (*b).len = n;
    1
}
unsafe fn copy_from(to: *mut u8, from: *const c_void, n: u32) -> u32 {
    let b = from as *const Buf;
    if b.is_null() || n as usize > (*b).data.len() {
        return 0;
    }
    core::ptr::copy_nonoverlapping((*b).data.as_ptr(), to, n as usize);
    1
}
unsafe extern "C" fn tag_copy_to(to: *mut c_void, from: *mut c_void, n: u32) -> u32 {
    copy_to(to, from as *const u8, n)
}
unsafe extern "C" fn tag_copy_from(to: *mut c_void, from: *mut c_void, n: u32) -> u32 {
    copy_from(to as *mut u8, from, n)
}

// ---- Requests ----

pub const NORMAL_BUF: usize = 2048;

pub struct Req {
    pub r: S2Req,
    pub buf: Box<Buf>,
    /// False from `send` until `wait` sees it back: a request still out
    /// must not be deleted.
    pub back: Cell<bool>,
}

impl Req {
    pub fn cookie(&mut self) -> *mut c_void {
        &mut *self.buf as *mut Buf as *mut c_void
    }
    /// The bytes the driver copied in (a read) or the stack set (a write).
    pub fn bytes(&self) -> &[u8] {
        &self.buf.data[..self.buf.len as usize]
    }
    /// Command, flags, cleared errors, and ios2_Data = this request's buffer.
    pub fn set(&mut self, cmd: u16, flags: u8) {
        let c = self.cookie();
        let io = self.r.io();
        io.set_command(cmd);
        io.set_flags(flags);
        io.set_error(0);
        self.r.set_wire_error(0);
        self.r.set_data(c);
    }
    /// A write of `data` (ios2_DataLength set too).
    pub fn set_write(&mut self, cmd: u16, flags: u8, ptype: u32, dst: &[u8; 6], data: &[u8]) {
        self.set(cmd, flags);
        self.buf.data[..data.len()].copy_from_slice(data);
        self.buf.len = data.len() as u32;
        self.r.set_packet_type(ptype);
        self.r.set_dst_mac(dst);
        self.r.set_data_length(data.len() as u32);
    }
    pub fn error(&self) -> i8 {
        self.r.io().error()
    }
}

/// One opener of a unit: its request (the base every copy is made from),
/// its station address and MTU.
pub struct Opener {
    pub req: Req,
    pub unit: u32,
    pub mac: [u8; 6],
    pub mtu: u32,
}

static COPY_TAGS: [TagItem; 3] = [
    TagItem { ti_Tag: S2_COPY_TO_BUFF, ti_Data: 0 },
    TagItem { ti_Tag: S2_COPY_FROM_BUFF, ti_Data: 0 },
    TagItem { ti_Tag: sys::TAG_DONE, ti_Data: 0 },
];

pub struct Ctx {
    pub port: AmigaMsgPort,
    pub timer: AmigaTimer,
    pub devname: Vec<u8>,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    /// Next test id (byte 3 of every test frame), so frames left over from
    /// one check are never taken for another's.
    pub id: u8,
}

impl Ctx {
    pub fn check(&mut self, name: &str, ok: bool, detail: String) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        let word = if ok { "PASS" } else { "FAIL" };
        say!("{} {}: {}", word, name, detail);
        amigaos4::serial_println!("s2xtest {} {}: {}", word, name, detail);
    }
    pub fn skip(&mut self, name: &str, why: &str) {
        self.skipped += 1;
        say!("SKIP {}: {}", name, why);
        amigaos4::serial_println!("s2xtest SKIP {}: {}", name, why);
    }
    pub fn info(&mut self, name: &str, detail: String) {
        say!("INFO {}: {}", name, detail);
        amigaos4::serial_println!("s2xtest INFO {}: {}", name, detail);
    }
    pub fn next_id(&mut self) -> u8 {
        self.id = self.id.wrapping_add(1).max(1);
        self.id
    }

    pub fn sleep(&mut self, ms: u32) {
        let _ = self.timer.delay(TimerVal::from_millis(ms));
    }

    /// A new request on our port, unopened, with a buffer of `size` bytes.
    pub fn new_req(&self, size: usize) -> Req {
        // SAFETY: plain exec calls.
        unsafe {
            let ior = sys::exec_create_iorequest(self.port.as_ptr(), 88);
            let r = S2Req::from_raw(ior).expect("CreateIORequest failed");
            Req { r, buf: Box::new(Buf { len: 0, data: vec![0; size] }), back: Cell::new(true) }
        }
    }

    /// A copy of an opened request (device, unit, buffer management).
    pub fn clone_req(&self, base: &Req, size: usize) -> Req {
        let n = self.new_req(size);
        // SAFETY: both are 88-byte requests; the reply port is ours in both.
        unsafe { core::ptr::copy_nonoverlapping(base.r.raw() as *const u8, n.r.raw() as *mut u8, 88) };
        n
    }

    /// Delete a request that is back (or leak it if it is still out).
    pub fn free(&mut self, req: Req) {
        if self.retire(&req) {
            // SAFETY: a request of ours that is not in flight.
            unsafe { sys::exec_delete_iorequest(req.r.as_ptr()) };
        } else {
            core::mem::forget(req);
        }
    }

    pub fn open(&mut self, unit: u32) -> Result<Opener, i8> {
        let req = self.new_req(NORMAL_BUF);
        let mut tags = [TagItem { ti_Tag: COPY_TAGS[0].ti_Tag, ti_Data: 0 }, TagItem { ti_Tag: COPY_TAGS[1].ti_Tag, ti_Data: 0 }, TagItem { ti_Tag: sys::TAG_DONE, ti_Data: 0 }];
        tags[0].ti_Data = tag_copy_to as *const () as usize as u32;
        tags[1].ti_Data = tag_copy_from as *const () as usize as u32;
        let tags = Box::leak(Box::new(tags));
        req.r.set_buffer_management(tags.as_ptr() as *mut c_void);
        // SAFETY: an 88-byte request and a NUL-terminated name.
        let e = unsafe { sys::exec_open_device(self.devname.as_ptr() as _, unit, req.r.as_ptr(), 0) };
        if e != 0 {
            // SAFETY: never opened.
            unsafe { sys::exec_delete_iorequest(req.r.as_ptr()) };
            return Err(e as i8);
        }
        Ok(Opener { req, unit, mac: [0; 6], mtu: 1500 })
    }

    pub fn close(&mut self, o: Opener) {
        // SAFETY: an opened request, back.
        unsafe {
            sys::exec_close_device(o.req.r.as_ptr());
            sys::exec_delete_iorequest(o.req.r.as_ptr());
        }
    }

    pub fn do_io(&self, req: &Req) -> (i8, u32) {
        // SAFETY: an opened request.
        unsafe { sys::exec_do_io(req.r.as_ptr()) };
        (req.r.io().error(), req.r.wire_error())
    }

    /// Start a request with its io_Flags as set (BeginIO; SendIO would
    /// clear them).
    pub fn send(&self, req: &Req) {
        req.back.set(false);
        // SAFETY: an opened request.
        unsafe { sys::exec_begin_io(req.r.as_ptr()) };
    }

    /// Whether a sent request is back (and take it off the port if so).
    pub fn poll(&self, req: &Req) -> bool {
        if req.back.get() {
            return true;
        }
        // SAFETY: a sent request.
        unsafe {
            if !sys::exec_check_io(req.r.as_ptr()).is_null() {
                sys::exec_wait_io(req.r.as_ptr());
                req.back.set(true);
                return true;
            }
        }
        false
    }

    /// Wait for a sent request, at most `ms`. None: it did not come back.
    pub fn wait(&mut self, req: &Req, ms: u32) -> Option<(i8, u32)> {
        let mut waited = 0;
        loop {
            if self.poll(req) {
                return Some((req.r.io().error(), req.r.wire_error()));
            }
            if waited >= ms {
                return None;
            }
            self.sleep(5);
            waited += 5;
        }
    }

    /// Wait until `n` of `reqs` are back, at most `ms`; how many are.
    pub fn wait_n(&mut self, reqs: &[&Req], n: usize, ms: u32) -> usize {
        let mut waited = 0;
        loop {
            let got = reqs.iter().filter(|r| self.poll(r)).count();
            if got >= n || waited >= ms {
                return got;
            }
            self.sleep(5);
            waited += 5;
        }
    }

    pub fn abort(&mut self, req: &Req) -> Option<(i8, u32)> {
        if req.back.get() {
            return Some((req.r.io().error(), req.r.wire_error()));
        }
        // SAFETY: a sent request.
        unsafe { sys::exec_abort_io(req.r.as_ptr()) };
        self.wait(req, 2000)
    }

    /// Make a request safe to delete: abort it if it is out, wait 2 s.
    pub fn retire(&mut self, req: &Req) -> bool {
        if !req.back.get() {
            let _ = self.abort(req);
        }
        req.back.get()
    }
}

// ---- Batches ----

/// Frame items a test batch carries.
#[derive(Clone, Copy, Default)]
pub struct ItemSet {
    pub checksum: bool,
    pub segment: bool,
    pub rss: bool,
    /// An item of a private type no driver knows (it must be skipped).
    pub private: bool,
}

/// A batch the test owns: the batch request, the S2XBatch, its frames,
/// each frame's request and items. Allocated once, reposted as needed.
pub struct Batch {
    pub req: Req,
    pub hdr: Box<x::S2XBatch>,
    pub frames: Vec<Box<x::S2XFrame>>,
    pub freqs: Vec<Req>,
    pub csum: Vec<Option<Box<x::S2XFrameChecksum>>>,
    pub seg: Vec<Option<Box<x::S2XFrameSegment>>>,
    pub rss: Vec<Option<Box<x::S2XFrameRSS>>>,
    pub private: Vec<Option<Box<x::S2XFrameRSS>>>,
}

pub const PRIVATE_ITEM: u32 = x::S2XITEM_PRIVATE | 0x5A5A;

impl Batch {
    pub fn new(ctx: &Ctx, base: &Req, n: usize, bufsize: usize, items: ItemSet) -> Batch {
        let mut hdr = Box::new(x::S2XBatch {
            s2xb_Size: core::mem::size_of::<x::S2XBatch>() as u32,
            s2xb_Count: n as u32,
            s2xb_Frames: x::MinList { mlh_Head: null_mut(), mlh_Tail: null_mut(), mlh_TailPred: null_mut() },
            s2xb_Done: 0,
            s2xb_Queue: 0,
        });
        let list = addr_of_mut!(hdr.s2xb_Frames);
        // SAFETY: a list in a box that stays put.
        unsafe { x::MinList::init(list) };
        let mut b = Batch {
            req: ctx.clone_req(base, 16),
            hdr,
            frames: Vec::new(),
            freqs: Vec::new(),
            csum: Vec::new(),
            seg: Vec::new(),
            rss: Vec::new(),
            private: Vec::new(),
        };
        for _ in 0..n {
            let fr = ctx.clone_req(base, bufsize);
            let mut f = Box::new(x::S2XFrame {
                s2xf_Node: MinNode { mln_Succ: null_mut(), mln_Pred: null_mut() },
                s2xf_Req: fr.r.raw(),
                s2xf_Items: x::MinList { mlh_Head: null_mut(), mlh_Tail: null_mut(), mlh_TailPred: null_mut() },
                s2xf_Size: core::mem::size_of::<x::S2XFrame>() as u32,
                s2xf_Reserved: 0,
            });
            let il = addr_of_mut!(f.s2xf_Items);
            // SAFETY: boxed frames and items, linked once, never moved.
            unsafe {
                x::MinList::init(il);
                let mut c = None;
                if items.checksum {
                    let mut it = Box::new(x::S2XFrameChecksum {
                        s2xfc_Header: x::S2XItem::new(x::S2XFRAME_CHECKSUM, core::mem::size_of::<x::S2XFrameChecksum>()),
                        s2xfc_Flags: 0,
                        s2xfc_Start: 0,
                        s2xfc_Offset: 0,
                    });
                    x::MinList::add_tail(il, addr_of_mut!(*it) as *mut MinNode);
                    c = Some(it);
                }
                let mut s = None;
                if items.segment {
                    let mut it = Box::new(x::S2XFrameSegment {
                        s2xfs_Header: x::S2XItem::new(x::S2XFRAME_SEGMENT, core::mem::size_of::<x::S2XFrameSegment>()),
                        s2xfs_Protocol: 0,
                        s2xfs_SegSize: 0,
                        s2xfs_HdrLen: 0,
                    });
                    x::MinList::add_tail(il, addr_of_mut!(*it) as *mut MinNode);
                    s = Some(it);
                }
                let mut r = None;
                if items.rss {
                    let mut it = Box::new(x::S2XFrameRSS {
                        s2xfr_Header: x::S2XItem::new(x::S2XFRAME_RSS, core::mem::size_of::<x::S2XFrameRSS>()),
                        s2xfr_Hash: 0,
                        s2xfr_HashType: 0,
                    });
                    x::MinList::add_tail(il, addr_of_mut!(*it) as *mut MinNode);
                    r = Some(it);
                }
                let mut p = None;
                if items.private {
                    let mut it = Box::new(x::S2XFrameRSS {
                        s2xfr_Header: x::S2XItem::new(PRIVATE_ITEM, core::mem::size_of::<x::S2XFrameRSS>()),
                        s2xfr_Hash: 0x1234_5678,
                        s2xfr_HashType: 0x9ABC_DEF0,
                    });
                    x::MinList::add_tail(il, addr_of_mut!(*it) as *mut MinNode);
                    p = Some(it);
                }
                x::MinList::add_tail(list, addr_of_mut!(*f) as *mut MinNode);
                b.csum.push(c);
                b.seg.push(s);
                b.rss.push(r);
                b.private.push(p);
            }
            b.frames.push(f);
            b.freqs.push(fr);
        }
        b
    }

    pub fn done(&self) -> u32 {
        // SAFETY: our own boxed structure (read after the reply).
        unsafe { addr_of!(self.hdr.s2xb_Done).read_unaligned() }
    }

    pub fn set_count(&mut self, n: u32) {
        // SAFETY: as `done`.
        unsafe { addr_of_mut!(self.hdr.s2xb_Count).write_unaligned(n) };
    }

    pub fn set_queue(&mut self, q: u32) {
        // SAFETY: as `done`.
        unsafe { addr_of_mut!(self.hdr.s2xb_Queue).write_unaligned(q) };
    }

    /// The receive checksum result of frame `i` (0 without an item).
    pub fn csum_flags(&self, i: usize) -> u32 {
        match &self.csum[i] {
            // SAFETY: our own boxed item.
            Some(c) => unsafe { addr_of!(c.s2xfc_Flags).read_unaligned() },
            None => 0,
        }
    }

    /// Set a send-side checksum request on frame `i`.
    pub fn set_csum(&mut self, i: usize, flags: u32, start: u16, offset: u16) {
        if let Some(c) = self.csum[i].as_mut() {
            // SAFETY: our own boxed item.
            unsafe {
                addr_of_mut!(c.s2xfc_Flags).write_unaligned(flags);
                addr_of_mut!(c.s2xfc_Start).write_unaligned(start);
                addr_of_mut!(c.s2xfc_Offset).write_unaligned(offset);
            }
        }
    }

    /// Post as a read batch for `ptype` (io_Flags `flags`).
    pub fn post_read(&mut self, ctx: &mut Ctx, ptype: u32, flags: u8) {
        // SAFETY: as `done`.
        unsafe { addr_of_mut!(self.hdr.s2xb_Done).write_unaligned(0xFFFF_FFFF) };
        for i in 0..self.freqs.len() {
            let fr = &mut self.freqs[i];
            fr.set(0, 0);
            fr.buf.len = 0;
            fr.r.set_data_length(0);
            fr.r.io().set_error(0x55);
            if let Some(c) = self.csum[i].as_mut() {
                // SAFETY: our own boxed item.
                unsafe { addr_of_mut!(c.s2xfc_Flags).write_unaligned(0) };
            }
            if let Some(r) = self.rss[i].as_mut() {
                // SAFETY: our own boxed item.
                unsafe {
                    addr_of_mut!(r.s2xfr_Hash).write_unaligned(0);
                    addr_of_mut!(r.s2xfr_HashType).write_unaligned(0);
                }
            }
        }
        self.req.set(x::S2X_READBATCH, flags);
        self.req.r.set_packet_type(ptype);
        self.req.r.set_stat_data(addr_of_mut!(*self.hdr) as *mut c_void);
        ctx.send(&self.req);
    }

    /// Post as a write batch (frames set with `Req::set_write` first).
    pub fn post_write(&mut self, ctx: &mut Ctx) {
        // SAFETY: as `done`.
        unsafe { addr_of_mut!(self.hdr.s2xb_Done).write_unaligned(0xFFFF_FFFF) };
        self.req.set(x::S2X_WRITEBATCH, 0);
        self.req.r.set_stat_data(addr_of_mut!(*self.hdr) as *mut c_void);
        ctx.send(&self.req);
    }

    pub fn free(self, ctx: &mut Ctx) {
        let Batch { req, freqs, .. } = self;
        let back = ctx.retire(&req);
        ctx.free(req);
        if back {
            for f in freqs {
                ctx.free(f);
            }
        } else {
            // Still the driver's: leak everything it may touch.
            core::mem::forget(freqs);
        }
    }
}

// ---- What the driver offers ----

#[derive(Default, Clone, Copy)]
pub struct Offer {
    pub ok: bool,
    pub features: u32,
    pub max_frames: u32,
    pub rx_csum: Option<u32>,
    pub tx_csum: Option<u32>,
    pub segment: Option<(u32, u32, u16, u16)>,
    pub mtu: Option<(u32, u32)>,
    pub moderation: Option<(u32, u32)>,
    pub flow: Option<u32>,
    /// HashTypes, MaxQueues, KeySize, TableSize, MaxTxQueues.
    pub rss: Option<(u32, u16, u16, u16, u16)>,
}

fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut it = s.split('.');
    for o in out.iter_mut() {
        *o = it.next()?.parse().ok()?;
    }
    if it.next().is_some() { None } else { Some(out) }
}

pub fn mac(m: &[u8]) -> String {
    alloc::format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// Configure a unit with its factory address and wait for its link.
pub fn bring_up(ctx: &mut Ctx, o: &mut Opener) -> Result<(), String> {
    let mut q = ctx.clone_req(&o.req, 16);
    q.set(S2_GETSTATIONADDRESS, 0);
    let (e, w) = ctx.do_io(&q);
    if e != 0 {
        ctx.free(q);
        return Err(alloc::format!("S2_GETSTATIONADDRESS error {} wire {}", e, w));
    }
    let factory = q.r.dst_mac();
    q.set(S2_CONFIGINTERFACE, 0);
    q.r.set_src_mac(&factory);
    let (e, w) = ctx.do_io(&q);
    if e != 0 && !(e == S2ERR_BAD_STATE && w == S2WERR_IS_CONFIGURED) {
        ctx.free(q);
        return Err(alloc::format!("S2_CONFIGINTERFACE error {} wire {}", e, w));
    }
    q.set(S2_ONLINE, 0);
    let _ = ctx.do_io(&q);
    q.set(S2_GETSTATIONADDRESS, 0);
    let _ = ctx.do_io(&q);
    o.mac = q.r.src_mac();
    let mut dq: Sana2DeviceQuery = unsafe { core::mem::zeroed() };
    dq.SizeAvailable = core::mem::size_of::<Sana2DeviceQuery>() as u32;
    q.set(S2_DEVICEQUERY, 0);
    q.r.set_stat_data(&mut dq as *mut Sana2DeviceQuery as *mut c_void);
    if ctx.do_io(&q).0 == 0 {
        o.mtu = dq.MTU;
    }
    // The link: S2EVENT_CONNECT (answered at once when it is up).
    q.set(S2_ONEVENT, 0);
    q.r.set_wire_error(S2EVENT_CONNECT);
    ctx.send(&q);
    let up = ctx.wait(&q, 8000).is_some();
    ctx.free(q);
    if !up {
        return Err("no link (S2EVENT_CONNECT did not come in 8 s)".into());
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn rust_main(args: *const u8, arglen: i32) -> i32 {
    // SAFETY: the Shell's argument string.
    let text = unsafe { core::slice::from_raw_parts(args, arglen.max(0) as usize) };
    let text = core::str::from_utf8(text).unwrap_or("");
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() < 3 {
        say!("usage: s2xtest <device> <unit A> <unit B or -> [only=name,...] [need=batch,rxcsum,...] [echo=U,MYIP,GWIP[,PORT]]");
        return 10;
    }
    let name = words[0];
    // Unit B "-": no peer (one port, e.g. on real hardware with a stack
    // using it): discovery, settings read only, and echo= if given.
    let (Ok(ua), ub) = (words[1].parse::<u32>(), if words[2] == "-" { Ok(None) } else { words[2].parse::<u32>().map(Some) }) else {
        say!("s2xtest: the units must be numbers (unit B may be -)");
        return 10;
    };
    let Ok(ub) = ub else {
        say!("s2xtest: the units must be numbers (unit B may be -)");
        return 10;
    };
    let list = |k: &str| -> Vec<String> {
        words.iter().find_map(|w| w.strip_prefix(k)).map(|v| v.split(',').map(String::from).collect()).unwrap_or_default()
    };
    let only = list("only=");
    let need = list("need=");
    // echo=U,MYIP,GWIP: checksum offload against a real stack on unit U.
    let echo = words.iter().find_map(|w| w.strip_prefix("echo=")).and_then(|v| {
        let p: Vec<&str> = v.split(',').collect();
        Some((p.first()?.parse::<u32>().ok()?, parse_ip(p.get(1)?)?, parse_ip(p.get(2)?)?, p.get(3).and_then(|s| s.parse::<u16>().ok()).unwrap_or(4530)))
    });
    let mut devname: Vec<u8> = name.as_bytes().to_vec();
    devname.push(0);
    let port = match AmigaMsgPort::new() {
        Ok(p) => p,
        Err(_) => return 20,
    };
    let timer = match AmigaTimer::open(TimerUnit::MicroHz) {
        Ok(t) => t,
        Err(_) => return 20,
    };
    let mut ctx = Ctx { port, timer, devname, passed: 0, failed: 0, skipped: 0, id: 0 };
    let mut a = match ctx.open(ua) {
        Ok(o) => o,
        Err(e) => {
            ctx.check("open", false, alloc::format!("unit {}: OpenDevice error {}", ua, e));
            return 20;
        }
    };
    let mut txcsum = false;
    let mut rxcsum = false;
    match ub {
        None => {
            say!("s2xtest: {} unit {}, no peer", name, ua);
            match bring_up(&mut ctx, &mut a) {
                Ok(()) => ctx.check("open", true, alloc::format!("{} MTU {}, link up", mac(&a.mac), a.mtu)),
                Err(e) => ctx.check("open", false, e),
            }
            if ctx.failed == 0 {
                let offer = tests::query(&mut ctx, &a, &need);
                txcsum = offer.tx_csum.is_some();
                rxcsum = offer.rx_csum.is_some();
                if offer.ok {
                    conf::read_only(&mut ctx, &a, offer);
                }
            }
            ctx.close(a);
        }
        Some(ub) => {
            say!("s2xtest: {} units {} (A, sends) and {} (B, receives)", name, ua, ub);
            let mut b = match ctx.open(ub) {
                Ok(o) => o,
                Err(e) => {
                    ctx.check("open", false, alloc::format!("unit {}: OpenDevice error {}", ub, e));
                    ctx.close(a);
                    return 20;
                }
            };
            let up = bring_up(&mut ctx, &mut a).and_then(|_| bring_up(&mut ctx, &mut b));
            match up {
                Ok(()) => ctx.check("open", true, alloc::format!("A {} MTU {}, B {} MTU {}, links up", mac(&a.mac), a.mtu, mac(&b.mac), b.mtu)),
                Err(e) => ctx.check("open", false, e),
            }
            if ctx.failed == 0 {
                let offer = tests::query(&mut ctx, &a, &need);
                txcsum = offer.tx_csum.is_some();
                rxcsum = offer.rx_csum.is_some();
                let mut t = tests::T { ctx: &mut ctx, a: &mut a, b: &mut b, offer, only };
                t.run_all(&need);
            }
            ctx.close(a);
            ctx.close(b);
        }
    }
    if let Some((unit, my, gw, port)) = echo {
        if txcsum {
            echo::run(&mut ctx, unit, my, gw, port, rxcsum);
        } else {
            ctx.skip("echo", "no S2XCAP_TXCHECKSUM");
        }
    }
    say!("s2xtest: {} passed, {} failed, {} skipped", ctx.passed, ctx.failed, ctx.skipped);
    amigaos4::serial_println!("s2xtest: {} passed, {} failed, {} skipped", ctx.passed, ctx.failed, ctx.skipped);
    let _ = NSCMD_DEVICEQUERY;
    if ctx.failed == 0 { 0 } else { 20 }
}
