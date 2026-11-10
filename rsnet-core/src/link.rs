//! One SANA-II unit opened as a stack would: raw Ethernet frames.
//!
//! The opener sequence is s2test's (testprogs/s2test): OpenDevice with the
//! buffer-management copy functions as tags (68k-callable EmuTraps, as
//! Roadshow passes them; the cookie in ios2_Data is a
//! [`Buf`] of ours), S2_DEVICEQUERY for the MTU, S2_GETSTATIONADDRESS for
//! the MAC, S2_CONFIGINTERFACE (a unit someone else configured is fine).
//!
//! Reads and writes are raw (SANA2IOF_RAW: the whole frame with its
//! Ethernet header, which is what smoltcp's Ethernet medium wants). They are
//! started with BeginIO, since SendIO and DoIO clear io_Flags and the RAW
//! flag with them. A raw read still matches its ios2_PacketType, so there is
//! a pool of pending reads per type; each read is re-posted as soon as it
//! comes back, since a device with no read pending holds or drops frames
//! (virtionet.device holds them up to 100 ms).
//!
//! Writes are synchronous (BeginIO then WaitIO); virtionet.device sends in
//! the caller's task anyway.
//!
//! No frame is copied here: a read that comes back hands its buffer to the
//! receive queue and is posted again with a spare one (from [`Pool`]; the
//! buffer goes back there when smoltcp has read it), and smoltcp writes a
//! frame to send straight into the write request's buffer
//! ([`Link::send_with`]).
//!
//! A driver that has the unofficial SANA-II extensions (`amigaos4::sana2ext`:
//! NSCMD_DEVICEQUERY lists S2X_QUERY, which answers with the magic) is
//! used through batches instead: S2X_READBATCH requests, several per packet
//! type and no CMD_READ for those types (the spec's dispatch rule), each
//! carrying several frames with their own requests and buffers (allocated
//! once, the buffers swapped as above), and one S2X_WRITEBATCH per run of
//! queued frames. A frame the card checked carries its checksum result
//! (S2XFRAME_CHECKSUM) to smoltcp, which then skips that check
//! ([`Buf::trust`]); a bad one is dropped and counted. Any other answer
//! from the driver means plain SANA-II, as before.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut, null_mut};

use amigaos4::device::cmd::{CMD_READ, CMD_WRITE, NSCMD_DEVICEQUERY};
use amigaos4::device::ioerr::IOERR_ABORTED;
use amigaos4::port::AmigaMsgPort;
use amigaos4::sana2::*;
use amigaos4::sana2ext::{self as s2x, MinList, S2XBatch, S2XFrame, S2XFrameChecksum, S2XItem, S2XQuery};
use amigaos4::sys::{self, TagItem};

use crate::s2xlogic::{self, Caps, ReadNext, RxCsum};

/// Room for a frame: the Ethernet header, a 1500-byte MTU and spare.
pub const FRAME_MAX: usize = 1600;
/// sizeof(struct IOSana2Req).
const IOS2_SIZE: u32 = 88;
/// Reads kept pending for IPv4 and for ARP.
const IPV4_READS: usize = 32;
const ARP_READS: usize = 4;
/// The reads a link keeps posted (every one is re-posted as it comes back).
pub const READS: u32 = (IPV4_READS + ARP_READS) as u32;
/// With read batches: the frames posted for IPv4 and for ARP, and the
/// most frames one batch carries for each (the driver may allow fewer).
/// Several batches per type, so the driver has room while the stack takes
/// one that came back.
const IPV4_BATCH_FRAMES: usize = 128;
const IPV4_PER_BATCH: usize = 32;
const ARP_BATCH_FRAMES: usize = 8;
const ARP_PER_BATCH: usize = 4;
/// The most frames one write batch carries.
const TX_PER_BATCH: usize = 64;
/// Frames received but not yet taken by smoltcp, at most.
const RX_QUEUE_MAX: usize = 256;
/// Frames waiting for flush(), at most: past it they are written at once.
const TX_QUEUE_MAX: usize = 256;

/// A buffer-management cookie: the frame and its length.
#[repr(C)]
pub struct Buf {
    len: u32,
    data: [u8; FRAME_MAX],
    /// A received frame's s2xlogic TRUST_ bits: the checks the card made
    /// that smoltcp may skip (0: smoltcp verifies everything).
    pub(crate) trust: u8,
}

impl Buf {
    fn new() -> Box<Self> {
        Box::new(Buf { len: 0, data: [0; FRAME_MAX], trust: 0 })
    }

    /// The frame it holds.
    pub fn frame(&self) -> &[u8] {
        &self.data[..(self.len as usize).min(FRAME_MAX)]
    }

    /// The whole buffer and the frame's length, to change the frame (the
    /// IP filter hook's replacement).
    pub(crate) fn parts(&mut self) -> (&mut [u8], &mut u32) {
        (&mut self.data[..], &mut self.len)
    }
}

/// Spare receive buffers: a received frame's buffer comes back here once
/// smoltcp has read it (the stack process's only task uses it).
#[derive(Clone, Default)]
pub struct Pool(Rc<RefCell<Vec<Box<Buf>>>>);

impl Pool {
    fn take(&self) -> Box<Buf> {
        let mut b = self.0.borrow_mut().pop().unwrap_or_else(Buf::new);
        b.trust = 0;
        b
    }

    /// Hand a buffer back for the next read.
    pub fn give(&self, b: Box<Buf>) {
        self.0.borrow_mut().push(b);
    }
}

// The OpenDevice copy functions, native: (to, from, n) -> BOOL. The device
// calls them in its own task or the caller's, with our cookie on one side.
unsafe extern "C" fn copy_to_buff(to: *mut c_void, from: *mut c_void, n: u32) -> u32 {
    let b = to as *mut Buf;
    if b.is_null() || n as usize > FRAME_MAX {
        return 0;
    }
    // SAFETY: `to` is the cookie of one of our requests (a live Buf) and
    // `from` holds `n` bytes (the device's contract); n fits.
    unsafe {
        core::ptr::copy_nonoverlapping(from as *const u8, (*b).data.as_mut_ptr(), n as usize);
        (*b).len = n;
    }
    1
}

unsafe extern "C" fn copy_from_buff(to: *mut c_void, from: *mut c_void, n: u32) -> u32 {
    let b = from as *const Buf;
    // SAFETY: `from` is the cookie of our write request (a live Buf).
    if b.is_null() || n > unsafe { (*b).len } {
        return 0;
    }
    // SAFETY: as above; `to` has room for `n` bytes (the device's contract)
    // and the Buf holds `n`.
    unsafe { core::ptr::copy_nonoverlapping((*b).data.as_ptr(), to as *mut u8, n as usize) };
    1
}

/// exec/emulation.h's struct EmuTrap: a 68k-callable entry into PPC code
/// (TRAPINST, TRAPTYPE, then the function, which gets the 68k registers).
#[repr(C, packed(2))]
struct EmuTrap {
    instruction: u32,
    kind: u16,
    function: unsafe extern "C" fn(*mut u32) -> u32,
}

const TRAPINST: u32 = 0x4ef8_0000;
const TRAPTYPE: u16 = 0x0004;
/// Longword indexes of D0, A0 and A1 in the 68k register array (REG68K_*).
const D0: usize = 0;
const A0: usize = 8;
const A1: usize = 9;

// The copy functions as SANA-II's 68k convention calls them (A0 to, A1
// from, D0 length). The OpenDevice tags hold these traps, as Roadshow's do:
// p50x0_eth.device (the X5000's onboard Ethernet, 52.6) calls the tag
// functions through IExec->EmulateTags, and a plain PPC function pointer
// got none of its arguments (testprogs/rstcp/c/s2probe on the X5000:
// every write failed with S2WERR_BUFF_ERROR, no frame left).
// A driver that checks IsNative (virtionet.device) emulates the trap too.
unsafe extern "C" fn trap_to_buff(regs: *mut u32) -> u32 {
    // SAFETY: the emulator's 68k register array (16 longwords and more).
    unsafe { copy_to_buff(*regs.add(A0) as usize as *mut c_void, *regs.add(A1) as usize as *mut c_void, *regs.add(D0)) }
}

unsafe extern "C" fn trap_from_buff(regs: *mut u32) -> u32 {
    // SAFETY: as above.
    unsafe { copy_from_buff(*regs.add(A0) as usize as *mut c_void, *regs.add(A1) as usize as *mut c_void, *regs.add(D0)) }
}

static TRAP_TO_BUFF: EmuTrap = EmuTrap { instruction: TRAPINST, kind: TRAPTYPE, function: trap_to_buff };
static TRAP_FROM_BUFF: EmuTrap = EmuTrap { instruction: TRAPINST, kind: TRAPTYPE, function: trap_from_buff };

/// One IOSana2Req of ours and its buffer.
struct Req {
    r: S2Req,
    buf: Box<Buf>,
    /// The packet type a read waits for (0 for other requests).
    ptype: u32,
}

impl Req {
    fn new(port: &AmigaMsgPort) -> Result<Self, String> {
        // SAFETY: a live port of this task; an IOSana2Req-sized request.
        let ior = unsafe { sys::exec_create_iorequest(port.as_ptr(), IOS2_SIZE) };
        // SAFETY: a fresh 88-byte request (or NULL, refused here).
        let r = unsafe { S2Req::from_raw(ior) }.ok_or_else(|| String::from("CreateIORequest failed"))?;
        Ok(Self { r, buf: Buf::new(), ptype: 0 })
    }

    fn cookie(&mut self) -> *mut c_void {
        &mut *self.buf as *mut Buf as *mut c_void
    }

    /// Ready the request for `cmd` with `flags` and our cookie as ios2_Data.
    fn set(&mut self, cmd: u16, flags: u8) {
        let c = self.cookie();
        let io = self.r.io();
        io.set_command(cmd);
        io.set_flags(flags);
        io.set_error(0);
        self.r.set_wire_error(0);
        self.r.set_data(c);
    }

    /// DeleteIORequest (the request is not in flight).
    fn delete(&self) {
        // SAFETY: our request, back from the device (or never sent).
        unsafe { sys::exec_delete_iorequest(self.r.as_ptr()) };
    }
}

/// One frame of a batch: its S2XFrame, its checksum item and its own
/// request (an opened copy of the base request) with its buffer. Boxed:
/// the lists point into it.
struct Slot {
    frame: S2XFrame,
    csum: S2XFrameChecksum,
    req: Req,
}

/// A read or write batch: its own request, the S2XBatch (boxed: the list
/// points into it) and its frames, all allocated once and reused.
struct Batch {
    req: Req,
    batch: Box<S2XBatch>,
    slots: Vec<Box<Slot>>,
    /// The packet type a read batch waits for (0 for the write batch).
    ptype: u32,
    /// Link each frame's S2XFRAME_CHECKSUM item.
    csum_item: bool,
    /// Sent and not yet back.
    in_flight: bool,
    /// The driver refused the command: no longer used.
    dead: bool,
}

impl Batch {
    fn new(port: &AmigaMsgPort, base: &Req, frames: usize, ptype: u32, csum_item: bool) -> Result<Self, String> {
        let req = Link::copy_of(port, base)?;
        let batch = Box::new(S2XBatch {
            s2xb_Size: size_of::<S2XBatch>() as u32,
            s2xb_Count: 0,
            s2xb_Frames: MinList { mlh_Head: null_mut(), mlh_Tail: null_mut(), mlh_TailPred: null_mut() },
            s2xb_Done: 0,
            s2xb_Queue: 0,
        });
        let mut b = Batch { req, batch, slots: Vec::with_capacity(frames), ptype, csum_item, in_flight: false, dead: false };
        for _ in 0..frames {
            let r = match Link::copy_of(port, base) {
                Ok(r) => r,
                Err(e) => {
                    b.delete();
                    return Err(e);
                }
            };
            b.slots.push(Box::new(Slot {
                frame: S2XFrame {
                    s2xf_Node: MinNode { mln_Succ: null_mut(), mln_Pred: null_mut() },
                    s2xf_Req: null_mut(),
                    s2xf_Items: MinList { mlh_Head: null_mut(), mlh_Tail: null_mut(), mlh_TailPred: null_mut() },
                    s2xf_Size: size_of::<S2XFrame>() as u32,
                    s2xf_Reserved: 0,
                },
                csum: S2XFrameChecksum { s2xfc_Header: S2XItem::new(s2x::S2XFRAME_CHECKSUM, size_of::<S2XFrameChecksum>()), s2xfc_Flags: 0, s2xfc_Start: 0, s2xfc_Offset: 0 },
                req: r,
            }));
        }
        Ok(b)
    }

    /// Link the first `count` frames (each with its items) into the batch
    /// and ready the batch's request for `cmd`. The frames' own requests
    /// are set by the caller. The lists are built again every time: the
    /// driver owned them while the batch was out.
    fn arm(&mut self, count: usize, cmd: u16) {
        let list = addr_of_mut!(self.batch.s2xb_Frames);
        // SAFETY: the boxed batch and slots do not move while linked; the
        // batch is not in flight (ours to change).
        unsafe {
            MinList::init(list);
            for s in self.slots[..count].iter_mut() {
                let s: &mut Slot = s;
                s.frame.s2xf_Req = s.req.r.raw();
                s.frame.s2xf_Size = size_of::<S2XFrame>() as u32;
                let items = addr_of_mut!(s.frame.s2xf_Items);
                MinList::init(items);
                if self.csum_item {
                    s.csum.s2xfc_Flags = 0;
                    s.csum.s2xfc_Start = 0;
                    s.csum.s2xfc_Offset = 0;
                    MinList::add_tail(items, addr_of_mut!(s.csum.s2xfc_Header.s2xi_Node));
                }
                MinList::add_tail(list, addr_of_mut!(s.frame.s2xf_Node));
            }
        }
        self.batch.s2xb_Size = size_of::<S2XBatch>() as u32;
        self.batch.s2xb_Count = count as u32;
        self.batch.s2xb_Done = 0;
        self.batch.s2xb_Queue = 0;
        self.req.set(cmd, SANA2IOF_RAW);
        self.req.r.set_data(null_mut());
        self.req.r.set_data_length(0);
        self.req.r.set_packet_type(self.ptype);
        self.req.r.set_stat_data(&mut *self.batch as *mut S2XBatch as *mut c_void);
    }

    /// The batch's io_Error and s2xb_Done once it is back.
    fn result(&self) -> (i8, u32) {
        (self.req.r.io().error(), self.batch.s2xb_Done)
    }

    /// Send it (BeginIO: the RAW flag stays).
    fn begin(&mut self) {
        self.in_flight = true;
        // SAFETY: our opened request copy, armed, not in flight; the batch
        // and every frame it lists stay put until it is back.
        unsafe { sys::exec_begin_io(self.req.r.as_ptr()) };
    }

    /// Delete every request (none in flight).
    fn delete(&self) {
        for s in &self.slots {
            s.req.delete();
        }
        self.req.delete();
    }
}

/// The driver's NSCMD_DEVICEQUERY answer lists S2X_QUERY, which answers
/// with the magic: its capabilities (sanitised); else all zero.
fn discover(base: &mut Req) -> Caps {
    // NSCMD_DEVICEQUERY uses io_Data / io_Length (an IOStdReq's fields,
    // over ios2_PacketType and ios2_SrcAddr here, set again before use).
    let mut res = Box::new([0u32; 4]);
    base.set(NSCMD_DEVICEQUERY, 0);
    let io = base.r.io();
    io.set_length(16);
    io.set_data(res.as_mut_ptr() as *mut u8);
    io.set_actual(0);
    // SAFETY: our opened request, not in use; `res` is 16 bytes and lives
    // across the call.
    unsafe { sys::exec_do_io(base.r.as_ptr()) };
    if io.error() != 0 || res[1] < 16 {
        return Caps::default();
    }
    // SupportedCommands: a pointer (offset 12), a 0-terminated list.
    // SAFETY: the 16-byte answer holds it at offset 12.
    let cmds = unsafe { core::ptr::read_unaligned((res.as_ptr() as *const u8).add(12) as *const *const u16) };
    if cmds.is_null() {
        return Caps::default();
    }
    // SAFETY: the driver's static list, 0-terminated (looked at for 512
    // entries at most).
    let listed = s2xlogic::supports((0..512).map(|i| unsafe { cmds.add(i).read_unaligned() }), s2x::S2X_QUERY);
    if !listed {
        return Caps::default();
    }
    let mut q = Box::new(S2XQuery { s2xq_Size: size_of::<S2XQuery>() as u32, s2xq_Magic: 0, s2xq_Version: 0, s2xq_Revision: 0, s2xq_Features: 0, s2xq_Capabilities: core::ptr::null() });
    base.set(s2x::S2X_QUERY, 0);
    base.r.set_stat_data(&mut *q as *mut S2XQuery as *mut c_void);
    // SAFETY: our opened request; `q` is a sized S2XQuery alive across it.
    unsafe { sys::exec_do_io(base.r.as_ptr()) };
    base.r.set_stat_data(null_mut());
    if base.r.io().error() != 0 || q.s2xq_Magic != s2x::S2X_MAGIC {
        return Caps::default();
    }
    let mut c = Caps { present: true, version: q.s2xq_Version, revision: q.s2xq_Revision, features: q.s2xq_Features, ..Caps::default() };
    let list = q.s2xq_Capabilities;
    if !list.is_null() {
        // SAFETY: the driver's read-only capability list, valid until
        // CloseDevice; every node starts an item (the spec); `find` only
        // returns items at least as large as the structure read.
        unsafe {
            if let Some(b) = s2x::find::<s2x::S2XCapBatch>(list, s2x::S2XCAP_BATCH) {
                c.batch_frames = addr_of!((*b).s2xcb_MaxFrames).read_unaligned();
            }
            if let Some(x) = s2x::find::<s2x::S2XCapChecksum>(list, s2x::S2XCAP_RXCHECKSUM) {
                c.rx_csum = addr_of!((*x).s2xcc_Protocols).read_unaligned();
            }
            if let Some(x) = s2x::find::<s2x::S2XCapChecksum>(list, s2x::S2XCAP_TXCHECKSUM) {
                c.tx_csum = addr_of!((*x).s2xcc_Protocols).read_unaligned();
            }
            if let Some(x) = s2x::find::<s2x::S2XCapSegment>(list, s2x::S2XCAP_SEGMENT) {
                c.seg_protocols = addr_of!((*x).s2xcs_Protocols).read_unaligned();
                c.seg_max_size = addr_of!((*x).s2xcs_MaxSize).read_unaligned();
                c.seg_max_segments = addr_of!((*x).s2xcs_MaxSegments).read_unaligned();
                c.seg_min_seg = addr_of!((*x).s2xcs_MinSegSize).read_unaligned();
            }
            if let Some(x) = s2x::find::<s2x::S2XCapMTU>(list, s2x::S2XCAP_MTU) {
                c.mtu_min = addr_of!((*x).s2xcm_MinMTU).read_unaligned();
                c.mtu_max = addr_of!((*x).s2xcm_MaxMTU).read_unaligned();
            }
            if let Some(x) = s2x::find::<s2x::S2XCapModeration>(list, s2x::S2XCAP_MODERATION) {
                c.moderation = true;
                c.mod_max_us = addr_of!((*x).s2xco_MaxMicros).read_unaligned();
                c.mod_flags = addr_of!((*x).s2xco_Flags).read_unaligned();
            }
            if let Some(x) = s2x::find::<s2x::S2XCapFlowControl>(list, s2x::S2XCAP_FLOWCONTROL) {
                c.flow_control = true;
                c.fc_modes = addr_of!((*x).s2xcf_Modes).read_unaligned();
            }
            if let Some(x) = s2x::find::<s2x::S2XCapRSS>(list, s2x::S2XCAP_RSS) {
                c.rss_hash = addr_of!((*x).s2xcr_HashTypes).read_unaligned();
                c.rss_queues = addr_of!((*x).s2xcr_MaxQueues).read_unaligned();
                c.rss_tx_queues = addr_of!((*x).s2xcr_MaxTxQueues).read_unaligned();
                c.rss_key = addr_of!((*x).s2xcr_KeySize).read_unaligned();
                c.rss_table = addr_of!((*x).s2xcr_TableSize).read_unaligned();
            }
        }
    }
    c.sanitize();
    c
}

/// What has gone through the link.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinkStats {
    pub rx_frames: u32,
    pub tx_frames: u32,
    /// Reads that came back with an error (other than an abort).
    pub rx_errors: u32,
    pub tx_errors: u32,
    /// Frames received while smoltcp had RX_QUEUE_MAX waiting.
    pub rx_dropped: u32,
    /// Bytes of the frames counted in rx_frames / tx_frames (Ethernet
    /// header included).
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Frames the link keeps posted for reading (plain reads, or the
    /// frames of its read batches).
    pub reads_posted: u32,
    /// Read batches that came back and the frames they carried (frames
    /// per batch: the one divided by the other); the same for writes.
    pub rx_batches: u32,
    pub rx_batch_frames: u32,
    pub tx_batches: u32,
    pub tx_batch_frames: u32,
    /// Received frames whose checksums the card checked and smoltcp
    /// skipped (at least one of IPv4 header, TCP/UDP), and frames the card
    /// found bad (dropped; also counted in rx_errors).
    pub rx_csum_ok: u32,
    pub rx_csum_bad: u32,
}

/// An opened SANA-II unit with its reads pending.
pub struct Link {
    port: AmigaMsgPort,
    /// The opened request; its copies (same device, unit, buffer
    /// management) do the work. Closed last.
    base: Req,
    reads: Vec<Req>,
    /// Read batches (extensions only): several per packet type.
    rx_batches: Vec<Batch>,
    /// The write batch (extensions only), and whether it is still used.
    tx_batch: Option<Batch>,
    tx_batch_on: bool,
    /// What the driver offers (all zero: plain SANA-II).
    pub caps: Caps,
    write: Req,
    /// The buffer-management tags, read by OpenDevice.
    _tags: Box<[TagItem; 3]>,
    pub mac: [u8; 6],
    pub mtu: u32,
    /// From S2_DEVICEQUERY: bits per second, the SANA-II hardware type,
    /// the address size in bits.
    pub bps: u32,
    pub hw_type: u32,
    pub addr_bits: u32,
    pub(crate) rx: VecDeque<Box<Buf>>,
    /// Frames sent while the stack held its lock, written by flush() once
    /// it has let go (the device's reply to each write is waited for).
    tx: VecDeque<Box<Buf>>,
    pub(crate) pool: Pool,
    pub stats: LinkStats,
    /// The stack's interface slot (the packet filter's tap names it).
    pub slot: u8,
    closed: bool,
    /// Every address of the stack (forward.rs: what is not for us).
    pub(crate) local: Vec<[u8; 4]>,
    /// Datagrams to forward (whole frames), for the stack process.
    pub(crate) fwd: Vec<Vec<u8>>,
    /// ICMP redirects that came in: (destination, new gateway, sender).
    pub(crate) redirects: Vec<([u8; 4], [u8; 4], [u8; 4])>,
}

impl Link {
    /// Open `unit` of `device` (e.g. "networks/virtionet.device": exec's
    /// OpenDevice does not search DEVS:Networks/), configure it with its
    /// factory address and post the reads.
    /// `mac`: the hardware address to configure the unit with
    /// (IFA_HardwareAddress), else its factory address.
    pub fn open(device: &str, unit: u32, mac: Option<[u8; 6]>) -> Result<Self, String> {
        let port = AmigaMsgPort::new().map_err(|e| alloc::format!("message port: {}", e))?;
        let tags = Box::new([
            TagItem { ti_Tag: S2_COPY_TO_BUFF, ti_Data: &TRAP_TO_BUFF as *const EmuTrap as usize as u32 },
            TagItem { ti_Tag: S2_COPY_FROM_BUFF, ti_Data: &TRAP_FROM_BUFF as *const EmuTrap as usize as u32 },
            TagItem { ti_Tag: sys::TAG_DONE, ti_Data: 0 },
        ]);
        let mut name = Vec::from(device.as_bytes());
        name.push(0);
        let base = Req::new(&port)?;
        base.r.set_buffer_management(tags.as_ptr() as *mut c_void);
        // SAFETY: an 88-byte request on our port and a NUL-terminated name.
        let e = unsafe { sys::exec_open_device(name.as_ptr() as _, unit, base.r.as_ptr(), 0) };
        if e != 0 {
            // SAFETY: never opened.
            unsafe { sys::exec_delete_iorequest(base.r.as_ptr()) };
            return Err(alloc::format!("OpenDevice {} unit {}: error {}", device, unit, e as i8));
        }
        let write = match Self::copy_of(&port, &base) {
            Ok(w) => w,
            Err(e) => {
                // SAFETY: the request opened above, closed and deleted once.
                unsafe {
                    sys::exec_close_device(base.r.as_ptr());
                    sys::exec_delete_iorequest(base.r.as_ptr());
                }
                return Err(e);
            }
        };
        let mut link = Self {
            port,
            base,
            reads: Vec::new(),
            rx_batches: Vec::new(),
            tx_batch: None,
            tx_batch_on: false,
            caps: Caps::default(),
            write,
            _tags: tags,
            mac: mac.unwrap_or([0; 6]),
            mtu: 1500,
            bps: 0,
            hw_type: 0,
            addr_bits: 48,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            pool: Pool::default(),
            stats: LinkStats::default(),
            slot: 0,
            closed: false,
            local: Vec::new(),
            fwd: Vec::new(),
            redirects: Vec::new(),
        };
        // From here, dropping `link` closes the device.
        link.query()?;
        link.caps = discover(&mut link.base);
        if link.caps.batches() {
            link.report_caps(device, unit);
            let max = link.caps.batch_frames;
            let csum = link.caps.rx_csum != 0;
            for (ptype, want, prefer) in [(0x0800u32, IPV4_BATCH_FRAMES, IPV4_PER_BATCH), (0x0806, ARP_BATCH_FRAMES, ARP_PER_BATCH)] {
                let (n, per) = s2xlogic::plan_reads(want, max, prefer);
                for _ in 0..n {
                    let b = Batch::new(&link.port, &link.base, per, ptype, csum)?;
                    link.rx_batches.push(b);
                }
            }
            let per = TX_PER_BATCH.min(max as usize).max(1);
            link.tx_batch = Some(Batch::new(&link.port, &link.base, per, 0, false)?);
            link.tx_batch_on = true;
            for k in 0..link.rx_batches.len() {
                link.post_batch(k);
            }
        } else {
            for (ptype, n) in [(0x0800u32, IPV4_READS), (0x0806, ARP_READS)] {
                link.add_reads(ptype, n)?;
            }
        }
        link.stats.reads_posted = link.reads.len() as u32 + link.rx_batches.iter().map(|b| b.slots.len() as u32).sum::<u32>();
        Ok(link)
    }

    /// `n` more plain reads for `ptype`, posted.
    fn add_reads(&mut self, ptype: u32, n: usize) -> Result<(), String> {
        for _ in 0..n {
            let mut r = Self::copy_of(&self.port, &self.base)?;
            r.ptype = ptype;
            self.reads.push(r);
            let k = self.reads.len() - 1;
            self.post(k);
        }
        Ok(())
    }

    /// One line on the debug log: what the driver offers.
    fn report_caps(&self, device: &str, unit: u32) {
        let c = &self.caps;
        amigaos4::serial_println!(
            "rsnet: {} unit {}: SANA-II extensions version {} revision {}: batches of {} frames, rx checksums {:#x}, tx checksums {:#x}, segmentation {:#x} (up to {} bytes), MTU {}-{}, RSS {} queues",
            device, unit, c.version, c.revision, c.batch_frames, c.rx_csum, c.tx_csum, c.seg_protocols, c.seg_max_size, c.mtu_min, c.mtu_max, c.rss_queues
        );
    }

    /// Post read batch `k` again: every frame with its own buffer, the
    /// checksum items cleared.
    fn post_batch(&mut self, k: usize) {
        let b = &mut self.rx_batches[k];
        let ptype = b.ptype;
        for s in b.slots.iter_mut() {
            s.req.set(CMD_READ, SANA2IOF_RAW);
            s.req.r.set_packet_type(ptype);
            s.req.r.set_data_length(FRAME_MAX as u32);
        }
        let n = b.slots.len();
        b.arm(n, s2x::S2X_READBATCH);
        b.begin();
    }

    /// Read batch `k` came back: its frames into the queue (checksum
    /// results applied), then posted again.
    fn take_batch(&mut self, k: usize) {
        let caps = self.caps;
        let b = &mut self.rx_batches[k];
        b.in_flight = false;
        let (err, done) = b.result();
        let (filled, next) = s2xlogic::read_outcome(b.slots.len(), done, err);
        for s in b.slots[..filled].iter_mut() {
            if s.req.r.io().error() != 0 {
                self.stats.rx_errors += 1;
                continue;
            }
            let n = (s.req.buf.len as usize).min(FRAME_MAX);
            let flags = if b.csum_item { s.csum.s2xfc_Flags } else { 0 };
            // The frame's buffer goes to the queue, a spare one takes its
            // place (set as the cookie when the batch is posted again).
            let mut full = core::mem::replace(&mut s.req.buf, self.pool.take());
            full.len = n as u32;
            match s2xlogic::rx_csum(flags, caps.rx_csum, full.frame()) {
                RxCsum::Bad => {
                    self.stats.rx_csum_bad += 1;
                    self.stats.rx_errors += 1;
                    self.pool.give(full);
                    continue;
                }
                RxCsum::Trust(t) => {
                    full.trust = t;
                    if t != 0 {
                        self.stats.rx_csum_ok += 1;
                    }
                }
            }
            self.rx.push_back(full);
            self.stats.rx_frames += 1;
            self.stats.rx_bytes += n as u64;
        }
        self.stats.rx_batches += 1;
        self.stats.rx_batch_frames += filled as u32;
        #[cfg(feature = "perf")]
        crate::perf::batch_taken(filled as u32);
        match next {
            ReadNext::Repost { error } => {
                if error {
                    self.stats.rx_errors += 1;
                }
                if !self.closed {
                    self.post_batch(k);
                }
            }
            ReadNext::Stop => {}
            ReadNext::Fallback => {
                // The driver said S2X_QUERY yet refuses the batch: plain
                // reads for this packet type in its place.
                let b = &mut self.rx_batches[k];
                b.dead = true;
                let (ptype, n) = (b.ptype, b.slots.len().min(IPV4_READS));
                if self.stats.rx_errors < 8 {
                    amigaos4::serial_println!("rsnet: S2X_READBATCH refused (io_Error {}): plain reads for type {:#06x}", err, ptype);
                }
                if !self.closed && self.add_reads(ptype, n).is_ok() {
                    self.stats.reads_posted = self.reads.len() as u32 + self.rx_batches.iter().filter(|b| !b.dead).map(|b| b.slots.len() as u32).sum::<u32>();
                }
            }
        }
    }

    /// A new request on `port` copied from `base` (device, unit, buffer
    /// management), with a buffer of its own.
    fn copy_of(port: &AmigaMsgPort, base: &Req) -> Result<Req, String> {
        let n = Req::new(port)?;
        // SAFETY: both are 88-byte requests whose reply port is ours.
        unsafe { core::ptr::copy_nonoverlapping(base.r.raw() as *const u8, n.r.raw() as *mut u8, IOS2_SIZE as usize) };
        Ok(n)
    }

    /// A synchronous command on the base request: (io_Error, ios2_WireError).
    /// S2_ONLINE / S2_OFFLINE (IFA_DownGoesOffline): true when the device
    /// took it.
    pub fn set_online(&mut self, on: bool) -> bool {
        self.do_io(if on { S2_ONLINE } else { S2_OFFLINE }).0 == 0
    }

    fn do_io(&mut self, cmd: u16) -> (i8, u32) {
        self.base.set(cmd, 0);
        // SAFETY: our opened request, not in use.
        unsafe { sys::exec_do_io(self.base.r.as_ptr()) };
        (self.base.r.io().error(), self.base.r.wire_error())
    }

    fn query(&mut self) -> Result<(), String> {
        let mut q = [0u8; 34];
        q[0..4].copy_from_slice(&34u32.to_be_bytes());
        self.base.r.set_stat_data(q.as_mut_ptr() as *mut c_void);
        self.base.set(S2_DEVICEQUERY, 0);
        self.base.r.set_stat_data(q.as_mut_ptr() as *mut c_void);
        // SAFETY: our opened request; q is a 34-byte Sana2DeviceQuery with
        // its size field set, alive across the call.
        unsafe { sys::exec_do_io(self.base.r.as_ptr()) };
        if self.base.r.io().error() != 0 {
            return Err(alloc::format!("S2_DEVICEQUERY: error {}", self.base.r.io().error()));
        }
        let mtu = u32::from_be_bytes([q[18], q[19], q[20], q[21]]);
        self.addr_bits = u16::from_be_bytes([q[16], q[17]]) as u32;
        self.bps = u32::from_be_bytes([q[22], q[23], q[24], q[25]]);
        self.hw_type = u32::from_be_bytes([q[26], q[27], q[28], q[29]]);
        if mtu >= 576 && mtu as usize + 14 <= FRAME_MAX {
            self.mtu = mtu;
        }
        let (e, w) = self.do_io(S2_GETSTATIONADDRESS);
        if e != 0 {
            return Err(alloc::format!("S2_GETSTATIONADDRESS: error {} wire {}", e, w));
        }
        let factory = self.base.r.dst_mac();
        let current = self.base.r.src_mac();
        let want = if self.mac != [0; 6] { self.mac } else { factory };
        self.base.set(S2_CONFIGINTERFACE, 0);
        self.base.r.set_src_mac(&want);
        // SAFETY: our opened request.
        unsafe { sys::exec_do_io(self.base.r.as_ptr()) };
        let (e, w) = (self.base.r.io().error(), self.base.r.wire_error());
        self.mac = if e == 0 {
            want
        } else if e == S2ERR_BAD_STATE && w == S2WERR_IS_CONFIGURED {
            // Configured before (an earlier run, or another opener): it
            // keeps the address it was given then.
            current
        } else {
            return Err(alloc::format!("S2_CONFIGINTERFACE: error {} wire {}", e, w));
        };
        Ok(())
    }

    /// Start read `k` again.
    fn post(&mut self, k: usize) {
        let r = &mut self.reads[k];
        r.set(CMD_READ, SANA2IOF_RAW);
        r.r.set_packet_type(r.ptype);
        r.r.set_data_length(FRAME_MAX as u32);
        // SAFETY: our opened request copy, not in flight; BeginIO keeps the
        // RAW flag (SendIO would clear it).
        unsafe { sys::exec_begin_io(r.r.as_ptr()) };
    }

    /// The signal of the port the reads come back to.
    pub fn signal_mask(&self) -> u32 {
        self.port.signal_mask()
    }

    /// Take the reads that have come back: frames into the queue, the reads
    /// posted again. A re-posted read can come back inside this call (a
    /// driver with frames waiting answers it at once): an X5000 with an
    /// I210 took ~1,000 frames in one call, and every frame past
    /// RX_QUEUE_MAX was dropped (~8% under two downloads). So this stops at
    /// RX_QUEUE_MAX and leaves the other replies on the port for the next
    /// pass, after smoltcp has emptied the queue; the port's signal is set
    /// again so that pass comes at once (the stack sleeps on it, and the
    /// replies left behind raise no new signal).
    pub fn poll(&mut self) {
        #[cfg(feature = "perf")]
        let (q0, mut taken, mut dropped) = (self.rx.len(), 0u32, 0u32);
        loop {
            if self.rx.len() >= RX_QUEUE_MAX {
                // SAFETY: SetSignal on the calling task's own signal bits.
                unsafe { sys::exec_set_signal(self.port.signal_mask(), self.port.signal_mask()) };
                break;
            }
            let Some(m) = self.port.get_raw() else { break };
            let Some(k) = self.reads.iter().position(|r| r.r.as_ptr() as *mut sys::Message == m) else {
                if let Some(k) = self.rx_batches.iter().position(|b| b.req.r.as_ptr() as *mut sys::Message == m) {
                    #[cfg(feature = "perf")]
                    let before = self.stats.rx_frames;
                    self.take_batch(k);
                    #[cfg(feature = "perf")]
                    {
                        taken += self.stats.rx_frames - before;
                    }
                }
                continue;
            };
            let err = self.reads[k].r.io().error();
            if err == 0 {
                #[cfg(feature = "perf")]
                {
                    taken += 1;
                }
                let n = (self.reads[k].buf.len as usize).min(FRAME_MAX);
                if self.rx.len() < RX_QUEUE_MAX {
                    // The read takes a spare buffer; its own goes to the queue.
                    let mut full = core::mem::replace(&mut self.reads[k].buf, self.pool.take());
                    full.trust = 0;
                    self.rx.push_back(full);
                    self.stats.rx_frames += 1;
                    self.stats.rx_bytes += n as u64;
                } else {
                    self.stats.rx_dropped += 1;
                    #[cfg(feature = "perf")]
                    {
                        dropped += 1;
                    }
                }
            } else if err == IOERR_ABORTED {
                continue;
            } else {
                self.stats.rx_errors += 1;
            }
            if !self.closed {
                self.post(k);
            }
        }
        #[cfg(feature = "perf")]
        crate::perf::link_poll(q0 as u32, taken, dropped);
    }

    /// Take `frame` in as if the device had just read it (a datagram the IP
    /// filter's auth program let go: ipfil.rs SIOCAUTHR).
    pub(crate) fn inject(&mut self, frame: &[u8]) {
        let n = frame.len().min(FRAME_MAX);
        let mut b = self.pool.take();
        b.data[..n].copy_from_slice(&frame[..n]);
        b.len = n as u32;
        self.rx.push_front(b);
    }

    /// Whether `frame` came to us for another host to be forwarded: IPv4,
    /// to our Ethernet address, for none of our addresses, while
    /// ip.forwarding is on (forward.rs).
    pub(crate) fn to_forward(&self, frame: &[u8]) -> bool {
        if frame.len() < 34 || frame[12] != 0x08 || frame[13] != 0x00 || frame[0] & 1 != 0 || frame[14] >> 4 != 4 {
            return false;
        }
        if crate::settings::SETTINGS.get(crate::settings::Setting::IpForwarding) == 0 {
            return false;
        }
        !crate::forward::not_forwarded(&self.local, [frame[30], frame[31], frame[32], frame[33]])
    }

    /// Send one whole Ethernet frame (raw), waiting until the device has it.
    pub fn send(&mut self, frame: &[u8]) -> bool {
        let n = frame.len();
        self.send_with(n, |b| b.copy_from_slice(frame)).1
    }

    /// Send a frame of `len` bytes that `fill` writes into the write
    /// request's buffer, waiting until the device has it: `fill`'s result
    /// and whether it went. A frame shorter than its Ethernet header or
    /// longer than FRAME_MAX is not sent (`fill` runs on a scratch buffer).
    pub fn send_with<R>(&mut self, len: usize, fill: impl FnOnce(&mut [u8]) -> R) -> (R, bool) {
        self.send_inner(len, fill, true)
    }

    /// Send one whole frame without the IP filter (a datagram its "to" /
    /// "dup-to" rule routes: ipfil.rs).
    pub(crate) fn send_unfiltered(&mut self, frame: &[u8]) -> bool {
        self.send_inner(frame.len(), |b| b.copy_from_slice(frame), false).1
    }

    fn send_inner<R>(&mut self, len: usize, fill: impl FnOnce(&mut [u8]) -> R, filter: bool) -> (R, bool) {
        if len < 14 || len > FRAME_MAX {
            self.stats.tx_errors += 1;
            return (fill(&mut alloc::vec![0u8; len]), false);
        }
        let mut b = self.pool.take();
        let r = fill(&mut b.data[..len]);
        // The IP filter hook may drop or replace it.
        let len = if filter {
            match crate::ipf::filter(self.slot, &mut b.data[..], len, false, None) {
                Some(n) => n,
                None => {
                    self.pool.give(b);
                    return (r, false);
                }
            }
        } else {
            len
        };
        let frame = &b.data[..len];
        // A monitoring hook (MHT_Packet) may drop it.
        if !crate::monitor::frame(frame, false) {
            self.pool.give(b);
            return (r, false);
        }
        crate::bpf::tap(self.slot, frame, false);
        // Written by flush(), after the stack has let go of its lock: the
        // wait for each write's reply (1.7-5.3 us a frame on an X5000) was
        // spent holding it.
        b.len = len as u32;
        self.tx.push_back(b);
        if self.tx.len() >= TX_QUEUE_MAX {
            self.flush();
        }
        (r, true)
    }

    /// Write the frames waiting in order, each waited for. A refused write
    /// is dropped and counted (TCP sends it again).
    pub fn flush(&mut self) {
        if self.tx_batch_on {
            self.flush_batches();
        }
        while let Some(b) = self.tx.pop_front() {
            let len = b.len as usize;
            let old = core::mem::replace(&mut self.write.buf, b);
            self.pool.give(old);
            self.write_one(len);
        }
    }

    /// Write the frames waiting as S2X_WRITEBATCHes, each waited for. The
    /// frame a batch refuses is dropped and counted as a refused write is;
    /// those after it (untouched, the spec says) go in the next batch. A
    /// batch that takes nothing and refuses nothing leaves the frames to
    /// plain writes (for good when the driver does not know the command).
    fn flush_batches(&mut self) {
        while !self.tx.is_empty() {
            let Some(tb) = self.tx_batch.as_mut() else { return };
            let n = self.tx.len().min(tb.slots.len());
            for s in tb.slots[..n].iter_mut() {
                let Some(b) = self.tx.pop_front() else { break };
                let len = b.len as usize;
                let old = core::mem::replace(&mut s.req.buf, b);
                self.pool.give(old);
                let frame = &s.req.buf.data[..len];
                let ptype = u16::from_be_bytes([frame[12], frame[13]]) as u32;
                let mut dst = [0u8; 6];
                dst.copy_from_slice(&frame[0..6]);
                s.req.set(CMD_WRITE, SANA2IOF_RAW);
                s.req.r.set_data_length(len as u32);
                s.req.r.set_packet_type(ptype);
                s.req.r.set_dst_mac(&dst);
            }
            tb.arm(n, s2x::S2X_WRITEBATCH);
            let perf_t = crate::perf::now();
            tb.begin();
            // SAFETY: the batch just sent; WaitIO takes its reply off our
            // port (reads' replies stay queued for poll()).
            unsafe { sys::exec_wait_io(tb.req.r.as_ptr()) };
            crate::perf::add(crate::perf::TX_WAIT, perf_t);
            tb.in_flight = false;
            let (err, done) = tb.result();
            let frame_err = if (done as usize) < n { tb.slots[done as usize].req.r.io().error() } else { 0 };
            let o = s2xlogic::write_outcome(n, done, err, frame_err);
            for s in tb.slots[..o.sent].iter() {
                self.stats.tx_frames += 1;
                self.stats.tx_bytes += s.req.buf.len as u64;
            }
            self.stats.tx_batches += 1;
            self.stats.tx_batch_frames += o.sent as u32;
            if o.refused {
                if self.stats.tx_errors < 8 {
                    let s = &tb.slots[o.sent];
                    amigaos4::serial_println!("rsnet: write refused in a batch: io_Error {} wire error {} ({} bytes)", frame_err, s.req.r.wire_error(), s.req.buf.len);
                }
                self.stats.tx_errors += 1;
            }
            // The untouched ones back to the front, in order.
            for s in tb.slots[o.resend_from..n].iter_mut().rev() {
                let b = core::mem::replace(&mut s.req.buf, self.pool.take());
                self.tx.push_front(b);
            }
            if o.plain {
                if o.give_up {
                    amigaos4::serial_println!("rsnet: S2X_WRITEBATCH refused (io_Error {}): plain writes", err);
                    self.tx_batch_on = false;
                }
                // flush() writes what is left one by one.
                return;
            }
        }
    }

    fn write_one(&mut self, len: usize) {
        let err = self.write_now(len);
        if err == 0 {
            return;
        }
        // A refused write is dropped and counted; TCP sends it again.
        // p50x0_eth.device on the X5000 refuses writes with
        // S2ERR_TX_FAILURE (11) when sends run at line rate with more than
        // 64 KB in flight (7-12 per 256 MB send). Holding the frame and
        // trying it again, after 1 ms sleeps or in a 2 ms loop, wedged the
        // driver: every later write was refused and the machine's network
        // stopped, in 2 boots of 2. Dropping always recovers.
        if self.stats.tx_errors < 8 {
            amigaos4::serial_println!("rsnet: write refused: io_Error {} wire error {} ({} bytes)", err as i8, self.write.r.wire_error(), len);
        }
        self.stats.tx_errors += 1;
    }

    /// Write the `len` bytes in the write request's buffer and wait for the
    /// device: io_Error (0: it has the frame, counted).
    fn write_now(&mut self, len: usize) -> i8 {
        let frame = &self.write.buf.data[..len];
        let ptype = u16::from_be_bytes([frame[12], frame[13]]) as u32;
        let mut dst = [0u8; 6];
        dst.copy_from_slice(&frame[0..6]);
        self.write.buf.len = len as u32;
        self.write.set(CMD_WRITE, SANA2IOF_RAW);
        self.write.r.set_data_length(len as u32);
        self.write.r.set_packet_type(ptype);
        self.write.r.set_dst_mac(&dst);
        // SAFETY: our opened request copy, not in flight. WaitIO takes the
        // reply off our port (a read's reply that arrives meanwhile stays
        // queued for poll()).
        unsafe {
            let perf_t = crate::perf::now();
            sys::exec_begin_io(self.write.r.as_ptr());
            sys::exec_wait_io(self.write.r.as_ptr());
            crate::perf::add(crate::perf::TX_WAIT, perf_t);
        }
        let err = self.write.r.io().error();
        if err == 0 {
            self.stats.tx_frames += 1;
            self.stats.tx_bytes += len as u64;
        }
        err
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        // What the last pass sent goes out first.
        self.flush();
        self.closed = true;
        for r in &self.reads {
            // SAFETY: our requests, each in flight or replied: AbortIO on a
            // replied one does nothing, WaitIO takes its reply.
            unsafe {
                sys::exec_abort_io(r.r.as_ptr());
                sys::exec_wait_io(r.r.as_ptr());
            }
        }
        // A read batch is aborted through its own request only; what it
        // filled is let go.
        for b in self.rx_batches.iter_mut().filter(|b| b.in_flight) {
            // SAFETY: our batch request, in flight or replied (as above).
            unsafe {
                sys::exec_abort_io(b.req.r.as_ptr());
                sys::exec_wait_io(b.req.r.as_ptr());
            }
            b.in_flight = false;
        }
        for b in self.rx_batches.iter().chain(self.tx_batch.iter()) {
            b.delete();
        }
        // SAFETY: every copy is back; the base request is the opened one,
        // closed once; then all are deleted.
        unsafe {
            for r in &self.reads {
                sys::exec_delete_iorequest(r.r.as_ptr());
            }
            sys::exec_delete_iorequest(self.write.r.as_ptr());
            sys::exec_close_device(self.base.r.as_ptr());
            sys::exec_delete_iorequest(self.base.r.as_ptr());
        }
    }
}
