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

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ffi::c_void;

use amigaos4::device::cmd::{CMD_READ, CMD_WRITE};
use amigaos4::device::ioerr::IOERR_ABORTED;
use amigaos4::port::AmigaMsgPort;
use amigaos4::sana2::*;
use amigaos4::sys::{self, TagItem};

/// Room for a frame: the Ethernet header, a 1500-byte MTU and spare.
pub const FRAME_MAX: usize = 1600;
/// sizeof(struct IOSana2Req).
const IOS2_SIZE: u32 = 88;
/// Reads kept pending for IPv4 and for ARP.
const IPV4_READS: usize = 32;
const ARP_READS: usize = 4;
/// The reads a link keeps posted (every one is re-posted as it comes back).
pub const READS: u32 = (IPV4_READS + ARP_READS) as u32;
/// Frames received but not yet taken by smoltcp, at most.
const RX_QUEUE_MAX: usize = 256;
/// Frames waiting for flush(), at most: past it they are written at once.
const TX_QUEUE_MAX: usize = 256;

/// A buffer-management cookie: the frame and its length.
#[repr(C)]
pub struct Buf {
    len: u32,
    data: [u8; FRAME_MAX],
}

impl Buf {
    fn new() -> Box<Self> {
        Box::new(Buf { len: 0, data: [0; FRAME_MAX] })
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
        self.0.borrow_mut().pop().unwrap_or_else(Buf::new)
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
}

/// An opened SANA-II unit with its reads pending.
pub struct Link {
    port: AmigaMsgPort,
    /// The opened request; its copies (same device, unit, buffer
    /// management) do the work. Closed last.
    base: Req,
    reads: Vec<Req>,
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
        for (ptype, n) in [(0x0800u32, IPV4_READS), (0x0806, ARP_READS)] {
            for _ in 0..n {
                let mut r = Self::copy_of(&link.port, &link.base)?;
                r.ptype = ptype;
                link.reads.push(r);
            }
        }
        for k in 0..link.reads.len() {
            link.post(k);
        }
        Ok(link)
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
                    let full = core::mem::replace(&mut self.reads[k].buf, self.pool.take());
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
        while let Some(b) = self.tx.pop_front() {
            let len = b.len as usize;
            let old = core::mem::replace(&mut self.write.buf, b);
            self.pool.give(old);
            self.write_one(len);
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
