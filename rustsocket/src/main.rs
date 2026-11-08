//! rustsocket.library: TCP/IP for AmigaOS 4 on smoltcp (rsnet-core),
//! with the interface of Roadshow's bsdsocket.library.
//!
//! The C glue (library_glue.c) gives each opener a "main" interface of its
//! own with an [`Opener`] in front of it; the vectors (vectors.c, generated
//! by tools/gen-socket-vectors.py) are SocketIFace's slots, those not done
//! yet a stub that sets errno ENOSYS. The first Open starts the stack
//! process with lo0 only (AddNetInterface adds the interfaces); the last
//! Close stops it, unless it has interfaces: then it runs on with no
//! opener until NetShutdown takes them away, as Roadshow's does.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

mod basetags;
mod iface;
mod routes;
mod dns;
mod rsdata;
mod ioctl;
mod inet;
mod misc;
mod msgio;
mod netdb;
mod shared;
mod server;
mod tcpdev;
mod bpf;
mod mbuf;
mod ipfil;
use core::ffi::c_void;
use core::panic::PanicInfo;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use amigaos4::allocator::SharedExecAllocator;
use amigaos4::sys::{self, Interface, TagItem};
use alloc::vec::Vec;
use rsnet_core::stack::{Config, Stack};
use rsnet_core::sock::{errno, SockKind, SockOp, SockOpt};

// The library's functions run in the callers' tasks and the stack process:
// the heap is shared. Counted, so the last Close can say what is still
// allocated (a leak shows there; the machine's free memory moves by
// hundreds of KB between runs with caches).
#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Bytes the library and its stack process have allocated and not freed.
static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: SharedExecAllocator's contract, passed through; the counter only
// adds what it returned and subtracts what is given back.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: the caller's layout, as GlobalAlloc::alloc requires.
        let p = unsafe { SharedExecAllocator.alloc(l) };
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        // SAFETY: memory from `alloc` with this layout.
        unsafe { SharedExecAllocator.dealloc(p, l) }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    amigaos4::panic::default_panic_handler(info)
}

/// BSD errno values (netinclude/sys/errno.h).
const EINVAL: i32 = 22;
const ENOSYS: i32 = 78;

extern "C" {
    fn rs_opener_of(i: *mut Interface) -> *mut c_void;
}

/// What each opener's interface carries (its data area, MIT_DataSize).
#[repr(C)]
pub struct Opener {
    magic: u32,
    errno: i32,
    /// Where the opener asked errno to be written too (SetErrnoPtr,
    /// SBTC_ERRNO*PTR), and its size: 1, 2 or 4.
    errno_ptr: *mut u8,
    errno_size: u32,
    /// SBTC_BREAKMASK (default CTRL-C), SBTC_SIGIOMASK, SBTC_SIGURGMASK,
    /// SBTC_SIGEVENTMASK.
    break_mask: u32,
    sigio_mask: u32,
    sigurg_mask: u32,
    sigevent_mask: u32,
    herrno: i32,
    /// The opener's descriptors: fd -> the stack's socket handle (a Box
    /// in the shared heap, freed with the opener).
    fds: *mut Vec<Option<Fd>>,
    /// gethostbyname's answer (a Box in the shared heap, freed with the
    /// opener).
    host: *mut HostEnt,
    /// Inet_NtoA's answer.
    ntoa: [u8; 16],
    /// The netdb answers and *ent walks (a Box in the shared heap, freed
    /// with the opener).
    netdb: *mut netdb::Local,
    /// The stub slots this opener has called (one log line each).
    stubs_seen: [u32; 5],
    /// SBTC_HERRNOLONGPTR: where h_errno is written too.
    herrno_ptr: *mut i32,
    /// SBTC_SIG_ADDRESS_CHANGE_MASK.
    sig_addr_mask: u32,
    /// ipf_set_interrupt_mask: the signals that end a wait in SIOCAUTHW
    /// (IPF_INTR_UNSET: the break mask).
    ipf_intr: u32,
    /// syslog: SBTC_LOGSTAT, SBTC_LOGTAGPTR, SBTC_LOGFACILITY, SBTC_LOGMASK.
    log_stat: u32,
    log_tag: u32,
    log_facility: u32,
    log_mask: u32,
    /// SBTC_FDCALLBACK (deprecated; kept, not called).
    fd_callback: u32,
    /// SBTC_ERROR_HOOK: a Hook called on every errno / h_errno change.
    error_hook: u32,
    /// SBTC_CAN_SHARE_LIBRARY_BASES.
    share_base: u32,
    /// SBTC_IDN_DEFAULT_CHARACTER_SET.
    idn: u32,
    /// SBTC_DTABLESIZE: the descriptor table's size.
    dtable: u32,
}

const OPENER_MAGIC: u32 = 0x5253_4F50; // 'RSOP'

#[no_mangle]
pub extern "C" fn rust_opener_size() -> u32 {
    core::mem::size_of::<Opener>() as u32
}

#[no_mangle]
pub extern "C" fn rust_opener_init(p: *mut c_void) {
    // SAFETY: the glue passes the new interface's data area, of
    // rust_opener_size() bytes, not yet used.
    unsafe {
        (p as *mut Opener).write(Opener {
            magic: OPENER_MAGIC,
            errno: 0,
            errno_ptr: core::ptr::null_mut(),
            errno_size: 0,
            break_mask: sys::SIGBREAKF_CTRL_C,
            sigio_mask: 0,
            sigurg_mask: 0,
            sigevent_mask: 0,
            herrno: 0,
            fds: Box::into_raw(Box::new(Vec::new())),
            host: Box::into_raw(Box::new(HostEnt::empty())),
            ntoa: [0; 16],
            netdb: Box::into_raw(Box::new(netdb::Local::new())),
            stubs_seen: [0; 5],
            herrno_ptr: core::ptr::null_mut(),
            sig_addr_mask: 0,
            ipf_intr: ipfil::IPF_INTR_UNSET,
            log_stat: 0,
            log_tag: 0,
            log_facility: basetags::LOG_USER,
            log_mask: 0xFF,
            fd_callback: 0,
            error_hook: 0,
            share_base: 0,
            idn: 1,
            dtable: basetags::DTABLE_DEFAULT,
        })
    };
}

#[no_mangle]
pub extern "C" fn rust_opener_free(p: *mut c_void) {
    // SAFETY: the opener's data, about to be freed with its interface; its
    // descriptor table is taken once.
    let o = unsafe { &mut *(p as *mut Opener) };
    o.magic = 0;
    // Its packet filter channels close with it.
    bpf::close_all(p as usize);
    if o.sig_addr_mask != 0 {
        if let Some(s) = stack() {
            s.watch_addresses(p as u32, 0, 0);
        }
    }
    if !o.host.is_null() {
        // SAFETY: the Box made by rust_opener_init, taken once.
        drop(unsafe { Box::from_raw(o.host) });
        o.host = core::ptr::null_mut();
    }
    if !o.netdb.is_null() {
        // SAFETY: the Box made by rust_opener_init, taken once.
        drop(unsafe { Box::from_raw(o.netdb) });
        o.netdb = core::ptr::null_mut();
    }
    if o.fds.is_null() {
        return;
    }
    // SAFETY: the Box made by rust_opener_init.
    let fds = unsafe { Box::from_raw(o.fds) };
    o.fds = core::ptr::null_mut();
    // What the opener left open is closed in the stack, unless another
    // descriptor (Dup2Socket, ReleaseCopyOfSocket) still refers to it.
    if let Some(stack) = stack() {
        for f in fds.iter().flatten().filter(|f| !f.reserved) {
            if shared::drop_ref(f.h) {
                let _ = stack.sock(SockOp::Close { h: f.h, result: Ok(()) });
            } else if f.evmask != 0 {
                let _ = stack.sock(SockOp::SetOpt { h: f.h, opt: SockOpt::Events(0, None), result: Ok(()) });
            }
        }
    }
}

/// The first 64 failed calls (not counting EWOULDBLOCK / EINPROGRESS) are
/// logged (they show what a program needs that does not work).
static FAILS_LOGGED: AtomicU32 = AtomicU32::new(0);

/// The calling task's name, for the log.
fn task_name() -> &'static str {
    let t = amigaos4::signal::current_task();
    // SAFETY: the running task, whose struct starts with its Node; the
    // Node's ln_Name is at byte 10 (exec's 2-byte packed layout). The name,
    // when set, is a NUL-terminated string that lives as long as the task.
    unsafe {
        let n = core::ptr::read_unaligned((t as *const u8).add(10) as *const *const u8);
        if n.is_null() {
            return "?";
        }
        core::ffi::CStr::from_ptr(n as *const core::ffi::c_char).to_str().unwrap_or("?")
    }
}

/// The calling opener's data.
fn opener(i: *mut Interface) -> Option<&'static mut Opener> {
    // SAFETY: `i` is one of our main interfaces (the caller called through
    // it), alive during the call; its data area is an Opener.
    let o = unsafe { &mut *(rs_opener_of(i) as *mut Opener) };
    (o.magic == OPENER_MAGIC).then_some(o)
}

impl Opener {
    fn set_herrno(&mut self, e: i32) {
        self.herrno = e;
        if !self.herrno_ptr.is_null() {
            // SAFETY: the opener gave this LONG's address (SBTC_HERRNOLONGPTR).
            unsafe { core::ptr::write_unaligned(self.herrno_ptr, e) };
        }
        basetags::error_hook(self.error_hook, true, e);
    }

    fn set_errno(&mut self, e: i32) {
        self.errno = e;
        basetags::error_hook(self.error_hook, false, e);
        if self.errno_ptr.is_null() {
            return;
        }
        // SAFETY: the opener gave this address and size for errno.
        unsafe {
            match self.errno_size {
                1 => *self.errno_ptr = e as u8,
                2 => core::ptr::write_unaligned(self.errno_ptr as *mut i16, e as i16),
                _ => core::ptr::write_unaligned(self.errno_ptr as *mut i32, e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The stack, shared by every opener
// ---------------------------------------------------------------------------

static STACK: AtomicPtr<Stack> = AtomicPtr::new(core::ptr::null_mut());

/// The running stack (between the first Open and the last Close).
fn stack() -> Option<&'static Stack> {
    let s = STACK.load(Ordering::Acquire);
    // SAFETY: the Box stored by rust_lib_open, freed only by the last
    // Close, after which no opener calls in.
    if s.is_null() { None } else { Some(unsafe { &*s }) }
}

/// The interface list's size: every slot the stack can have.
const MAX_IFACES: usize = rsnet_core::stack::MAX_SLOTS;

/// Expunge asks (with no opener left): must the library stay? Yes while
/// the stack runs on with interfaces (Roadshow's stays until NetShutdown),
/// or a process of ours still runs. A stack left with lo0 only (after
/// NetShutdown took the interfaces away) is stopped here, when the caller
/// is a Process that can wait for it; NetShutdown's RemLibrary is one.
#[no_mangle]
pub extern "C" fn rust_lib_busy() -> i32 {
    if stack().is_some() {
        if has_interfaces() || !amigaos4::dos::is_process() {
            return 1;
        }
        amigaos4::serial_println!("rustsocket.library: expunge with no interface left: the stack stops");
        stop_all();
    }
    (tcpdev::busy() || server::busy()) as i32
}

/// Whether the stack has an interface besides lo0 (added by
/// AddNetInterface or the interface API, not yet removed).
fn has_interfaces() -> bool {
    stack().and_then(|s| s.status()).map(|v| v.iter().any(|st| st.present && !st.loopback)).unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn rust_lib_init() -> i32 {
    amigaos4::serial_println!("rustsocket.library: init");
    0
}

/// Open: `count` openers now. The first starts the stack (in its task,
/// which must be a Process); a failure fails the OpenLibrary.
#[no_mangle]
pub extern "C" fn rust_lib_open(count: u32) -> i32 {
    amigaos4::serial_println!("rustsocket.library: open {} by {}", count, task_name());
    // A later Open, or the first since the last Close left the stack
    // running with its interfaces.
    if count != 1 || START.load(Ordering::Acquire) == STARTED {
        return wait_started();
    }
    START.store(STARTING, Ordering::Release);
    let r = start_stack();
    START.store(if r == 0 { STARTED } else { STOPPED }, Ordering::Release);
    r
}

/// Where the first Open is: the stack may take seconds to start (DHCP),
/// and Open waits (Wait breaks exec's Forbid), so another opener can come
/// in meanwhile; it must not go on before the stack is there.
static START: AtomicU32 = AtomicU32::new(STOPPED);
const STOPPED: u32 = 0;
const STARTING: u32 = 1;
const STARTED: u32 = 2;

/// A later Open: wait (polling every 20 ms) while the first is starting
/// the stack; 0 when it is running, 1 (the Open fails) when it is not.
fn wait_started() -> i32 {
    if START.load(Ordering::Acquire) == STARTING {
        let Ok(mut timer) = amigaos4::timer::AmigaTimer::open(amigaos4::timer::TimerUnit::MicroHz) else { return 1 };
        while START.load(Ordering::Acquire) == STARTING {
            let _ = timer.delay(amigaos4::timer::TimerVal::from_millis(20));
        }
    }
    if stack().is_some() { 0 } else { 1 }
}

/// The first Open's work: start the stack, wait for addresses.
fn start_stack() -> i32 {
    if !amigaos4::dos::is_process() {
        amigaos4::serial_println!("rustsocket.library: the first opener must be a DOS Process");
        return 1;
    }
    // lo0 only: interfaces come as Roadshow's do, from AddNetInterface
    // (S:Network-Startup) through the interface API.
    match Stack::start(Config { units: Vec::new() }) {
        Ok(s) => {
            if !shared::init() {
                amigaos4::serial_println!("rustsocket.library: no mutex for the shared state");
                s.stop();
                return 1;
            }
            STACK.store(Box::into_raw(Box::new(s)), Ordering::Release);
            rsdata::read_env();
            dns::read_name_resolution();
            server::start();
            tcpdev::start();
            0
        }
        Err(e) => {
            amigaos4::serial_println!("rustsocket.library: the stack did not start: {}", e);
            1
        }
    }
}

/// Close: `count` openers left. The last stops the stack and waits until
/// its process has gone (the library may be expunged right after), unless
/// the stack has interfaces: then it runs on with no opener, as Roadshow's
/// does (AddNetInterface opens, adds, configures and closes; its close may
/// be the last one, and must not take the interfaces with the stack).
/// NetShutdown takes the interfaces away; the stack then
/// stops at the expunge (rust_lib_busy) or at a later last Close.
#[no_mangle]
pub extern "C" fn rust_lib_close(count: u32) {
    amigaos4::serial_println!("rustsocket.library: close, {} left, by {}", count, task_name());
    if count != 0 {
        return;
    }
    if has_interfaces() {
        amigaos4::serial_println!("rustsocket.library: no opener left; the stack runs on with its interfaces");
        return;
    }
    stop_all();
}

/// Stop the stack and everything around it (no opener left).
fn stop_all() {
    START.store(STOPPED, Ordering::Release);
    // The superserver goes first: it uses the stack and the shared state;
    // then the TCP: handler lets go of the stack.
    server::stop();
    tcpdev::stop();
    rsnet_core::bpf::free();
    rsnet_core::ipfil::free();
    rsnet_core::ipnat::free();
    // Released sockets nobody obtained are closed before the stack stops.
    let left = shared::take_all();
    if let Some(stack) = stack() {
        for f in left {
            let _ = stack.sock(SockOp::Close { h: f.h, result: Ok(()) });
        }
    }
    let s = STACK.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !s.is_null() {
        // SAFETY: the Box stored by rust_lib_open, taken once (and freed
        // here, so the count below is what is really left).
        let s = *unsafe { Box::from_raw(s) };
        let frames: u32 = s.status().map(|v| v.iter().map(|n| n.link.rx_frames + n.link.tx_frames).sum()).unwrap_or(0);
        s.stop();
        let p = rsnet_core::stack::perf();
        amigaos4::serial_println!(
            "rustsocket.library: stack passes {}, sleeps {}, recv/send in the caller's task {}, sent to the stack {}; frames {}",
            p[0], p[1], p[2], p[3], frames
        );
        free_device_name();
        // The interfaces' ifnet records (no stack, no opener left to call
        // a hook with them).
        rsnet_core::ipf::free();
        amigaos4::serial_println!("rustsocket.library: the stack has stopped; {} bytes still allocated", LIVE.load(Ordering::Relaxed));
    }
}

// ---------------------------------------------------------------------------
// SocketIFace functions
// ---------------------------------------------------------------------------

/// A slot not done yet: errno ENOSYS, its name and the calling task
/// logged once per opener (so each program's first missing call shows).
#[no_mangle]
pub extern "C" fn rs_stub(i: *mut Interface, slot: u32, name: *const u8) -> i32 {
    let (w, b) = ((slot / 32) as usize, 1u32 << (slot % 32));
    let o = opener(i);
    let first = match &o {
        Some(o) if w < o.stubs_seen.len() => o.stubs_seen[w] & b == 0,
        _ => true,
    };
    if first {
        // SAFETY: the generated stub passes a NUL-terminated literal.
        let n = unsafe { core::ffi::CStr::from_ptr(name as *const core::ffi::c_char) }.to_str().unwrap_or("?");
        amigaos4::serial_println!("rustsocket.library: {} (slot {}) is not done yet: ENOSYS (task {})", n, slot, task_name());
    }
    if let Some(o) = o {
        if w < o.stubs_seen.len() {
            o.stubs_seen[w] |= b;
        }
        o.set_errno(ENOSYS);
    }
    -1
}

/// Errno(): the opener's last error.
#[no_mangle]
pub extern "C" fn rs_Errno(i: *mut Interface) -> i32 {
    opener(i).map(|o| o.errno).unwrap_or(0)
}

/// SetErrnoPtr(ptr, size): also write errno there (size 1, 2 or 4).
#[no_mangle]
pub extern "C" fn rs_SetErrnoPtr(i: *mut Interface, ptr: *mut u8, size: i32) {
    if let Some(o) = opener(i) {
        if matches!(size, 1 | 2 | 4) {
            o.errno_ptr = ptr;
            o.errno_size = size as u32;
        } else {
            o.set_errno(EINVAL);
        }
    }
}


// ---------------------------------------------------------------------------
// Sockets: TCP and UDP over the stack process
// ---------------------------------------------------------------------------

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOCK_RAW: i32 = 3;
const PF_ROUTE: i32 = 17;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;
const SOL_SOCKET: i32 = 0xffff;
const ENOPROTOOPT: i32 = 42;
const EMFILE: i32 = 24;
const MSG_PEEK: i32 = 0x2;
const MSG_DONTWAIT: i32 = 0x80;
// sys/filio.h: _IOW/_IOR('f', n, long).
const FIONBIO: u32 = 0x8004_667E;
const FIONREAD: u32 = 0x4004_667F;
const FIOASYNC: u32 = 0x8004_667D;

/// A descriptor: the stack's socket and how the program set it up.
#[derive(Clone, Copy, Default)]
pub struct Fd {
    h: u32,
    nonblock: bool,
    /// SO_RCVTIMEO / SO_SNDTIMEO in microseconds (0: wait as long as it
    /// takes).
    rcvtimeo_us: u64,
    sndtimeo_us: u64,
    /// SOL_SOCKET flag options set and read back (SO_REUSEADDR and the
    /// like; see setsockopt).
    flags: u32,
    /// SO_EVENTMASK.
    evmask: u32,
    /// Dup2Socket(-1, fd): the slot is taken, there is no socket.
    reserved: bool,
    /// IP_TTL as set (0: not set, ip.defttl applies) and IP_HDRINCL, read
    /// back by getsockopt.
    ttl: u8,
    hdrincl: bool,
    /// A routing socket: a message written gets the writer as rtm_pid, as
    /// the kernel fills it in (arp reads until it sees its own).
    route: bool,
}

static TOKEN: AtomicU32 = AtomicU32::new(1);

impl Opener {
    fn fds(&mut self) -> &mut Vec<Option<Fd>> {
        // SAFETY: the opener's table, alive until rust_opener_free.
        unsafe { &mut *self.fds }
    }

    /// Descriptor `fd`'s socket (a reserved slot has none).
    fn fd(&mut self, fd: i32) -> Option<Fd> {
        self.slot(fd).filter(|f| !f.reserved)
    }

    /// Whatever is in slot `fd`.
    fn slot(&mut self, fd: i32) -> Option<Fd> {
        if fd < 0 {
            return None;
        }
        self.fds().get(fd as usize).copied().flatten()
    }

    /// Put `f` in the lowest free slot (or slot `at`, freed first when in
    /// use): the descriptor, or EMFILE / EBADF.
    fn place(&mut self, f: Fd, at: Option<i32>) -> Result<i32, i32> {
        let dtable = self.dtable;
        let fds = self.fds();
        let fd = match at {
            Some(n) if n < 0 || n as u32 >= dtable => return Err(errno::EBADF),
            Some(n) => n as usize,
            None => match fds.iter().position(|f| f.is_none()) {
                Some(k) => k,
                None => fds.len(),
            },
        };
        if fd as u32 >= dtable {
            return Err(EMFILE);
        }
        if fd >= fds.len() {
            fds.resize(fd + 1, None);
        }
        fds[fd] = Some(f);
        Ok(fd as i32)
    }

    /// The lowest free descriptor for a new stack socket `h`; EMFILE (and
    /// the socket closed) when the table is full.
    fn new_fd(&mut self, h: u32) -> Result<i32, i32> {
        match self.place(Fd { h, ..Fd::default() }, None) {
            Ok(fd) => {
                shared::add_ref(h);
                Ok(fd)
            }
            Err(e) => {
                let _ = self.run(false, SockOp::Close { h, result: Ok(()) });
                Err(e)
            }
        }
    }

    /// Let go of slot `fd`: the stack socket closes with its last
    /// descriptor. The close's error, if any.
    fn release_slot(&mut self, fd: i32) -> Result<(), i32> {
        let Some(f) = self.slot(fd) else { return Err(errno::EBADF) };
        self.fds()[fd as usize] = None;
        if f.reserved {
            return Ok(());
        }
        if shared::drop_ref(f.h) {
            match self.run(false, SockOp::Close { h: f.h, result: Ok(()) }) {
                Some(SockOp::Close { result: Err(e), .. }) => return Err(e),
                _ => {}
            }
        } else if f.evmask != 0 {
            // Another descriptor keeps the socket: stop signalling this
            // opener.
            let _ = self.run(false, SockOp::SetOpt { h: f.h, opt: SockOpt::Events(0, None), result: Ok(()) });
        }
        Ok(())
    }

    /// -1 with errno `e`.
    fn fail(&mut self, e: i32) -> i32 {
        self.set_errno(e);
        // EWOULDBLOCK and EINPROGRESS are a non-blocking socket's normal
        // answers, not failures worth a log line.
        if e != errno::EWOULDBLOCK && e != errno::EINPROGRESS && FAILS_LOGGED.fetch_add(1, Ordering::Relaxed) < 64 {
            amigaos4::serial_println!("rustsocket.library: {}: a call failed, errno {}", task_name(), e);
        }
        -1
    }

    /// Run `op` in the stack for this opener: its break mask (CTRL-C by
    /// default) interrupts a wait with EINTR. The answered op, or None if
    /// the stack is gone.
    fn run(&mut self, nonblock: bool, op: SockOp) -> Option<SockOp> {
        self.run_hit(nonblock, op).map(|(op, _)| op)
    }

    /// As `run`; a wait gives up after `timeout_us` (0: no limit) with
    /// EWOULDBLOCK (SO_RCVTIMEO, SO_SNDTIMEO).
    fn run_timed(&mut self, nonblock: bool, timeout_us: u64, op: SockOp) -> Option<SockOp> {
        let stack = stack()?;
        let token = TOKEN.fetch_add(1, Ordering::Relaxed);
        let deadline = (timeout_us != 0).then(|| amigaos4::timer::get_up_time().as_micros() + timeout_us);
        let r = stack.sock_with(token, nonblock, deadline, op, self.break_mask);
        keep_break(r.as_ref().map(|x| x.1).unwrap_or(0));
        r.map(|(op, _)| op)
    }

    /// As `run`, also saying which break signals arrived.
    fn run_hit(&mut self, nonblock: bool, op: SockOp) -> Option<(SockOp, u32)> {
        let stack = stack()?;
        let token = TOKEN.fetch_add(1, Ordering::Relaxed);
        let r = stack.sock_with(token, nonblock, None, op, self.break_mask);
        keep_break(r.as_ref().map(|x| x.1).unwrap_or(0));
        r
    }
}

/// A break signal that ended a wait (EINTR) is set again: the program
/// tests it itself afterwards (autodoc, SocketBaseTagList NOTES), and ping
/// Waits for the timer signal it put in its break mask.
fn keep_break(hit: u32) {
    if hit != 0 {
        // SAFETY: SetSignal only sets the calling task's own signal bits,
        // ones it was just sent.
        unsafe { sys::exec_set_signal(hit, hit) };
    }
}

/// socket(domain, type, protocol): AF_INET with SOCK_STREAM (TCP) or
/// SOCK_DGRAM (UDP).
#[no_mangle]
pub extern "C" fn rs_socket(i: *mut Interface, domain: i32, kind: i32, protocol: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    // PF_ROUTE: a routing socket (arp, route-style tools).
    if domain == PF_ROUTE {
        if kind != SOCK_RAW {
            return o.fail(errno::EPROTONOSUPPORT);
        }
        return match o.run(false, SockOp::Open { kind: SockKind::Route, result: Err(0) }) {
            Some(SockOp::Open { result: Ok(h), .. }) => match o.new_fd(h) {
                Ok(fd) => {
                    if let Some(Some(slot)) = o.fds().get_mut(fd as usize) {
                        slot.route = true;
                    }
                    fd
                }
                Err(e) => o.fail(e),
            },
            Some(SockOp::Open { result: Err(e), .. }) => o.fail(e),
            _ => o.fail(errno::ENOTCONN),
        };
    }
    if domain != AF_INET {
        return o.fail(errno::EAFNOSUPPORT);
    }
    let kind = match (kind, protocol) {
        (SOCK_STREAM, 0 | IPPROTO_TCP) => SockKind::Tcp,
        (SOCK_DGRAM, 0 | IPPROTO_UDP) => SockKind::Udp,
        // A raw socket for any IP protocol but 0 (ping and traceroute:
        // IPPROTO_ICMP; IPPROTO_RAW: send-only, header given).
        (SOCK_RAW, p) if (1..=255).contains(&p) => SockKind::Raw(p as u8),
        _ => return o.fail(errno::EPROTONOSUPPORT),
    };
    match o.run(false, SockOp::Open { kind, result: Err(0) }) {
        Some(SockOp::Open { result: Ok(h), .. }) => match o.new_fd(h) {
            Ok(fd) => fd,
            Err(e) => o.fail(e),
        },
        Some(SockOp::Open { result: Err(e), .. }) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

/// struct sockaddr_in (BSD 4.4: sin_len, sin_family, sin_port, sin_addr).
fn sockaddr_in(name: *const u8, len: u32) -> Option<([u8; 4], u16)> {
    if name.is_null() || len < 8 {
        return None;
    }
    // SAFETY: the caller's sockaddr of `len` (>= 8) bytes.
    let b = unsafe { core::slice::from_raw_parts(name, 8) };
    if b[1] as i32 != AF_INET {
        return None;
    }
    Some(([b[4], b[5], b[6], b[7]], u16::from_be_bytes([b[2], b[3]])))
}

/// Write a sockaddr_in to the caller's `name` (room in *namelen).
fn put_sockaddr(name: *mut u8, namelen: *mut u32, ep: ([u8; 4], u16)) -> bool {
    if name.is_null() || namelen.is_null() {
        return false;
    }
    let mut b = [0u8; 16];
    b[0] = 16;
    b[1] = AF_INET as u8;
    b[2..4].copy_from_slice(&ep.1.to_be_bytes());
    b[4..8].copy_from_slice(&ep.0);
    // SAFETY: the caller's buffer of *namelen bytes and its length.
    unsafe {
        let n = (*namelen as usize).min(16);
        core::ptr::copy_nonoverlapping(b.as_ptr(), name, n);
        *namelen = 16;
    }
    true
}

/// bind(s, name, namelen): port 0 takes a free one.
#[no_mangle]
pub extern "C" fn rs_bind(i: *mut Interface, fd: i32, name: *const u8, len: u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    // struct BindMonitorMsg: size, caller, socket, name, name length.
    let e = monitor_call(rsnet_core::monitor::MHT_BIND, &mut [20, o.log_tag, fd as u32, name as u32, len]);
    if e > 0 {
        return o.fail(e);
    }
    let Some((addr, port)) = sockaddr_in(name, len) else { return o.fail(errno::EAFNOSUPPORT) };
    match o.run(false, SockOp::Bind { h: f.h, addr, port, result: Err(0) }) {
        Some(SockOp::Bind { result: Ok(()), .. }) => 0,
        Some(SockOp::Bind { result: Err(e), .. }) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

/// listen(s, backlog): a bound TCP socket (backlog 1 to 4 connections
/// waiting to be accepted).
#[no_mangle]
pub extern "C" fn rs_listen(i: *mut Interface, fd: i32, backlog: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    match o.run(false, SockOp::Listen { h: f.h, backlog, result: Err(0) }) {
        Some(SockOp::Listen { result: Ok(()), .. }) => 0,
        Some(SockOp::Listen { result: Err(e), .. }) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

/// accept(s, addr, addrlen): the next connection, a new descriptor
/// (blocking, as the new one is: it does not inherit FIONBIO).
#[no_mangle]
pub extern "C" fn rs_accept(i: *mut Interface, fd: i32, name: *mut u8, namelen: *mut u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    match o.run_timed(f.nonblock, f.rcvtimeo_us, SockOp::Accept { h: f.h, result: Err(0) }) {
        Some(SockOp::Accept { result: Ok((h, peer)), .. }) => match o.new_fd(h) {
            Ok(nfd) => {
                if !name.is_null() && !namelen.is_null() {
                    put_sockaddr(name, namelen, peer);
                }
                nfd
            }
            Err(e) => o.fail(e),
        },
        Some(SockOp::Accept { result: Err(e), .. }) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

/// connect(s, name, namelen): TCP blocks until established or refused (a
/// non-blocking socket gives EINPROGRESS and goes on in the background);
/// UDP sets the default peer.
#[no_mangle]
pub extern "C" fn rs_connect(i: *mut Interface, fd: i32, name: *const u8, len: u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    // struct ConnectMonitorMsg: size, caller, socket, name, name length.
    let e = monitor_call(rsnet_core::monitor::MHT_CONNECT, &mut [20, o.log_tag, fd as u32, name as u32, len]);
    if e > 0 {
        return o.fail(e);
    }
    let Some((addr, port)) = sockaddr_in(name, len) else { return o.fail(errno::EAFNOSUPPORT) };
    match o.run_timed(f.nonblock, f.sndtimeo_us, SockOp::Connect { h: f.h, addr, port, result: Err(0) }) {
        Some(SockOp::Connect { result: Ok(()), .. }) => 0,
        Some(SockOp::Connect { result: Err(e), .. }) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

/// The most of one TCP send copied into a message: the socket's transmit
/// buffer (32 KB) twice over.
const SEND_COPY: usize = 64 * 1024;

/// The MHT_Connect / MHT_Bind / MHT_Send hooks, called in the caller's
/// task with `msg`: 0, or the errno the first refusing hook returned.
fn monitor_call(kind: u32, msg: &mut [u32]) -> i32 {
    for h in rsnet_core::monitor::hooks_of(kind) {
        let r = rsnet_core::monitor::call(h, msg.as_mut_ptr() as *mut c_void);
        if r > 0 {
            return r;
        }
    }
    0
}

fn do_send(o: &mut Opener, fd: i32, msg: *const u8, len: i32, flags: i32, to: Option<([u8; 4], u16)>) -> i32 {
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    if len < 0 || (msg.is_null() && len > 0) {
        return o.fail(errno::EINVAL);
    }
    // struct SendMonitorMessage: size, caller, socket, buffer, length,
    // flags, to, to length, msghdr (NULL here).
    let mut sa = [0u8; 16];
    if let Some((a, p)) = to {
        sa[0] = 16;
        sa[1] = 2;
        sa[2..4].copy_from_slice(&p.to_be_bytes());
        sa[4..8].copy_from_slice(&a);
    }
    let (tp, tl) = if to.is_some() { (sa.as_ptr() as u32, 16) } else { (0, 0) };
    let e = monitor_call(rsnet_core::monitor::MHT_SEND, &mut [36, o.log_tag, fd as u32, msg as u32, len as u32, flags as u32, tp, tl, 0]);
    if e > 0 {
        return o.fail(e);
    }
    // TCP with room in the transmit buffer: copied in here, no message.
    if len > 0 && to.is_none() {
        // SAFETY: the caller's buffer of `len` bytes, read in its own task.
        let data = unsafe { core::slice::from_raw_parts(msg, len as usize) };
        if let Some(n) = stack().and_then(|s| s.send_now(f.h, data, o.break_mask)) {
            return n as i32;
        }
    }
    // At most SEND_COPY bytes go in one message (a send may take part of
    // the buffer; the caller sends the rest): copying all of a 5 MB send
    // for each 32 KB the socket took made big sends quadratic.
    let data = if len == 0 {
        Vec::new()
    } else {
        let n = (len as usize).min(if to.is_none() { SEND_COPY } else { len as usize });
        // SAFETY: the caller's buffer of `len` bytes (n <= len), copied in
        // its own task.
        unsafe { core::slice::from_raw_parts(msg, n) }.to_vec()
    };
    let mut data = data;
    if f.route && data.len() >= 18 {
        // rt_msghdr's rtm_pid (offset 14): the writing task.
        let me = amigaos4::signal::current_task() as usize as u32;
        data[14..18].copy_from_slice(&me.to_be_bytes());
    }
    match o.run_timed(f.nonblock || flags & MSG_DONTWAIT != 0, f.sndtimeo_us, SockOp::Send { h: f.h, data, to, result: Err(0) }) {
        Some(SockOp::Send { result: Ok(n), .. }) => n as i32,
        Some(SockOp::Send { result: Err(e), .. }) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

/// send(s, msg, len, flags): what was taken (TCP: blocks while the transmit
/// buffer is full, unless non-blocking; UDP: one datagram to the peer).
#[no_mangle]
pub extern "C" fn rs_send(i: *mut Interface, fd: i32, msg: *const u8, len: i32, flags: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    do_send(o, fd, msg, len, flags, None)
}

/// sendto(s, msg, len, flags, to, tolen).
#[no_mangle]
pub extern "C" fn rs_sendto(i: *mut Interface, fd: i32, msg: *const u8, len: i32, flags: i32, to: *const u8, tolen: u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let dest = if to.is_null() {
        None
    } else {
        match sockaddr_in(to, tolen) {
            Some(d) => Some(d),
            None => return o.fail(errno::EAFNOSUPPORT),
        }
    };
    do_send(o, fd, msg, len, flags, dest)
}

fn do_recv(o: &mut Opener, fd: i32, buf: *mut u8, len: i32, flags: i32, from: *mut u8, fromlen: *mut u32) -> i32 {
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    if len < 0 || (buf.is_null() && len > 0) {
        return o.fail(errno::EINVAL);
    }
    // TCP with bytes queued: copied out here, no message (recvfrom's
    // address and MSG_PEEK take the stack's way).
    if len > 0 && from.is_null() && flags & MSG_PEEK == 0 {
        // SAFETY: the caller's buffer of `len` bytes, written in its own
        // task.
        let out = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };
        if let Some(n) = stack().and_then(|s| s.recv_now(f.h, out, o.break_mask)) {
            return n as i32;
        }
    }
    let op = SockOp::Recv { h: f.h, max: len as usize, peek: flags & MSG_PEEK != 0, result: Err(0) };
    match o.run_timed(f.nonblock || flags & MSG_DONTWAIT != 0, f.rcvtimeo_us, op) {
        Some(SockOp::Recv { result: Ok((data, sender)), .. }) => {
            let n = data.len().min(len as usize);
            // SAFETY: the caller's buffer of `len` bytes, written in its own
            // task.
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), buf, n) };
            if let Some(ep) = sender {
                if !from.is_null() && !fromlen.is_null() {
                    put_sockaddr(from, fromlen, ep);
                }
            }
            n as i32
        }
        Some(SockOp::Recv { result: Err(e), .. }) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

/// recv(s, buf, len, flags): what has arrived, up to len (blocks until
/// something has, unless non-blocking); TCP: 0 at the end of the stream;
/// UDP: one datagram, cut to len. MSG_PEEK leaves it queued; MSG_DONTWAIT
/// does not wait.
#[no_mangle]
pub extern "C" fn rs_recv(i: *mut Interface, fd: i32, buf: *mut u8, len: i32, flags: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    do_recv(o, fd, buf, len, flags, core::ptr::null_mut(), core::ptr::null_mut())
}

/// recvfrom(s, buf, len, flags, from, fromlen).
#[no_mangle]
pub extern "C" fn rs_recvfrom(i: *mut Interface, fd: i32, buf: *mut u8, len: i32, flags: i32, from: *mut u8, fromlen: *mut u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    do_recv(o, fd, buf, len, flags, from, fromlen)
}

/// CloseSocket(d).
#[no_mangle]
pub extern "C" fn rs_CloseSocket(i: *mut Interface, fd: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    match o.release_slot(fd) {
        Ok(()) => 0,
        Err(e) => o.fail(e),
    }
}

/// ReleaseSocket's id that asks for a new one.
const UNIQUE_ID: i32 = -1;

/// Ids handed out for UNIQUE_ID start here, above what programs pick.
static NEXT_ID: AtomicU32 = AtomicU32::new(0x1000);

/// Keep descriptor `f` under `id` (UNIQUE_ID: a new one) for an
/// ObtainSocket: the id, or EINVAL when `id` is taken.
fn keep_released(f: Fd, id: i32) -> Result<i32, i32> {
    let Some(mut sh) = shared::lock() else { return Err(errno::EINVAL) };
    let id = if id == UNIQUE_ID {
        loop {
            let n = (NEXT_ID.fetch_add(1, Ordering::Relaxed) & 0x7fff_ffff) as i32;
            if n != UNIQUE_ID && !sh.released.iter().any(|(k, _)| *k == n) {
                break n;
            }
        }
    } else if id < 0 || sh.released.iter().any(|(k, _)| *k == id) {
        return Err(errno::EINVAL);
    } else {
        id
    };
    // A released socket signals nobody until it is obtained.
    sh.released.push((id, Fd { evmask: 0, ..f }));
    Ok(id)
}

/// ReleaseSocket(fd, id): take descriptor `fd` out of this opener's table
/// and keep it under `id` (UNIQUE_ID: a new id) for another opener's
/// ObtainSocket. The id, or -1 (EBADF; EINVAL when `id` is taken).
#[no_mangle]
pub extern "C" fn rs_ReleaseSocket(i: *mut Interface, fd: i32, id: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    match keep_released(f, id) {
        Ok(id) => {
            o.fds()[fd as usize] = None;
            if f.evmask != 0 {
                let _ = o.run(false, SockOp::SetOpt { h: f.h, opt: SockOpt::Events(0, None), result: Ok(()) });
            }
            id
        }
        Err(e) => o.fail(e),
    }
}

/// ReleaseCopyOfSocket(fd, id): as ReleaseSocket, but `fd` stays this
/// opener's too (the socket closes with the last of the two).
#[no_mangle]
pub extern "C" fn rs_ReleaseCopyOfSocket(i: *mut Interface, fd: i32, id: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    match keep_released(f, id) {
        Ok(id) => {
            shared::add_ref(f.h);
            id
        }
        Err(e) => o.fail(e),
    }
}

/// ObtainSocket(id, domain, type, protocol): the socket released under
/// `id`, as a new descriptor of this opener. -1 with EWOULDBLOCK when no
/// socket has that id.
#[no_mangle]
pub extern "C" fn rs_ObtainSocket(i: *mut Interface, id: i32, _domain: i32, _kind: i32, _protocol: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let f = {
        let Some(mut sh) = shared::lock() else { return o.fail(errno::EWOULDBLOCK) };
        let Some(k) = sh.released.iter().position(|(n, _)| *n == id) else {
            drop(sh);
            return o.fail(errno::EWOULDBLOCK);
        };
        sh.released.swap_remove(k).1
    };
    match o.place(f, None) {
        Ok(fd) => fd,
        Err(e) => {
            // No room: it goes back, for another try.
            if let Some(mut sh) = shared::lock() {
                sh.released.push((id, f));
            }
            o.fail(e)
        }
    }
}

/// Dup2Socket(old, new): descriptor `new` (-1: the lowest free) for the
/// socket of `old`; `new` is closed first if in use. old = -1 reserves
/// `new` without a socket. The new descriptor, or -1.
#[no_mangle]
pub extern "C" fn rs_Dup2Socket(i: *mut Interface, old: i32, new: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let f = if old == -1 {
        if new < 0 {
            return o.fail(errno::EBADF);
        }
        Fd { reserved: true, ..Fd::default() }
    } else {
        match o.fd(old) {
            Some(f) => Fd { evmask: 0, ..f },
            None => return o.fail(errno::EBADF),
        }
    };
    if new == old {
        return new;
    }
    if new >= 0 && o.slot(new).is_some() {
        let _ = o.release_slot(new);
    }
    match o.place(f, (new >= 0).then_some(new)) {
        Ok(fd) => {
            if !f.reserved {
                shared::add_ref(f.h);
            }
            fd
        }
        Err(e) => o.fail(e),
    }
}

/// getdtablesize(): the size of each opener's descriptor table.
#[no_mangle]
pub extern "C" fn rs_getdtablesize(i: *mut Interface) -> i32 {
    opener(i).map(|o| o.dtable).unwrap_or(basetags::DTABLE_DEFAULT) as i32
}

/// gethostname(name, namelen): ENV:HOSTNAME, else "amiga", NUL-terminated
/// when it fits.
#[no_mangle]
pub extern "C" fn rs_gethostname(i: *mut Interface, name: *mut u8, namelen: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    if name.is_null() || namelen <= 0 {
        return o.fail(errno::EINVAL);
    }
    let host = amigaos4::dos::get_var("HOSTNAME", amigaos4::dos::VarScope::Global)
        .ok()
        .flatten()
        .unwrap_or_else(|| alloc::string::String::from("amiga"));
    let b = host.as_bytes();
    let n = b.len().min(namelen as usize - 1);
    // SAFETY: the caller's buffer of `namelen` bytes; n + 1 <= namelen.
    unsafe {
        core::ptr::copy_nonoverlapping(b.as_ptr(), name, n);
        *name.add(n) = 0;
    }
    0
}

/// shutdown(s, how).
#[no_mangle]
pub extern "C" fn rs_shutdown(i: *mut Interface, fd: i32, how: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    match o.run(false, SockOp::Shutdown { h: f.h, how, result: Err(0) }) {
        Some(SockOp::Shutdown { result: Ok(()), .. }) => 0,
        Some(SockOp::Shutdown { result: Err(e), .. }) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

fn info(o: &mut Opener, fd: i32, take_error: bool) -> Result<rsnet_core::sock::SockInfo, i32> {
    let f = o.fd(fd).ok_or(errno::EBADF)?;
    match o.run(false, SockOp::Info { h: f.h, take_error, result: Err(0) }) {
        Some(SockOp::Info { result, .. }) => result,
        _ => Err(errno::ENOTCONN),
    }
}

/// getsockname(s, name, namelen).
#[no_mangle]
pub extern "C" fn rs_getsockname(i: *mut Interface, fd: i32, name: *mut u8, namelen: *mut u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    match info(o, fd, false) {
        Ok(inf) => {
            if put_sockaddr(name, namelen, inf.local.unwrap_or(([0; 4], 0))) { 0 } else { o.fail(errno::EINVAL) }
        }
        Err(e) => o.fail(e),
    }
}

/// getpeername(s, name, namelen): ENOTCONN when not connected.
#[no_mangle]
pub extern "C" fn rs_getpeername(i: *mut Interface, fd: i32, name: *mut u8, namelen: *mut u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    match info(o, fd, false) {
        Ok(inf) => match inf.remote {
            Some(ep) => {
                if put_sockaddr(name, namelen, ep) { 0 } else { o.fail(errno::EINVAL) }
            }
            None => o.fail(errno::ENOTCONN),
        },
        Err(e) => o.fail(e),
    }
}

/// IoctlSocket(s, request, argp): FIONBIO, FIONREAD, FIOASYNC (accepted,
/// no SIGIO yet).
#[no_mangle]
pub extern "C" fn rs_IoctlSocket(i: *mut Interface, fd: i32, req: u32, argp: *mut i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    if o.fd(fd).is_none() {
        return o.fail(errno::EBADF);
    }
    if argp.is_null() {
        return o.fail(errno::EINVAL);
    }
    match req {
        FIONBIO => {
            // SAFETY: the caller's long.
            let on = unsafe { *argp } != 0;
            if let Some(Some(f)) = o.fds().get_mut(fd as usize) {
                f.nonblock = on;
            }
            0
        }
        FIONREAD => match info(o, fd, false) {
            Ok(inf) => {
                // SAFETY: the caller's long.
                unsafe { *argp = inf.readable as i32 };
                0
            }
            Err(e) => o.fail(e),
        },
        FIOASYNC => 0,
        // The interface and other socket requests (ioctl.rs).
        _ => match ioctl::ioctl(o, req, argp as *mut u8) {
            Some(r) => r,
            None => o.fail(errno::EINVAL),
        },
    }
}

/// SOL_SOCKET options kept as flags and read back (their values are their
/// bits): SO_DEBUG, SO_REUSEADDR, SO_KEEPALIVE, SO_DONTROUTE,
/// SO_BROADCAST, SO_USELOOPBACK, SO_OOBINLINE, SO_REUSEPORT.
const FLAG_OPTS: i32 = 0x0001 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0100 | 0x0200;
const SO_KEEPALIVE: i32 = 0x0008;
const SO_LINGER: i32 = 0x0080;
const SO_SNDBUF: i32 = 0x1001;
const SO_RCVBUF: i32 = 0x1002;
const SO_SNDLOWAT: i32 = 0x1003;
const SO_RCVLOWAT: i32 = 0x1004;
const SO_SNDTIMEO: i32 = 0x1005;
const SO_RCVTIMEO: i32 = 0x1006;
const SO_ERROR: i32 = 0x1007;
const SO_TYPE: i32 = 0x1008;
const SO_ACCEPTCONN: i32 = 0x0002;
const SO_EVENTMASK: i32 = 0x2001;
const TCP_NODELAY: i32 = 0x01;
const TCP_MAXSEG: i32 = 0x02;
const IPPROTO_IP: i32 = 0;
const IP_TOS: i32 = 3;
const IP_TTL: i32 = 4;
const IP_HDRINCL: i32 = 2;

/// An option's value as the caller gave it: `len` bytes at `value`.
fn opt_bytes<'a>(value: *const u8, len: u32) -> Option<&'a [u8]> {
    if value.is_null() || len == 0 {
        return None;
    }
    // SAFETY: the caller's option of `len` bytes.
    Some(unsafe { core::slice::from_raw_parts(value, len as usize) })
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]]))
}

/// setsockopt(s, level, name, value, len). Applied: SO_RCVTIMEO and
/// SO_SNDTIMEO (a struct timeval: waits give up with EWOULDBLOCK),
/// SO_KEEPALIVE, SO_LINGER (a zero time resets the connection on close),
/// SO_EVENTMASK (GetSocketEvents), TCP_NODELAY. Kept and read back: the
/// flag options. Accepted with no effect: SO_SNDBUF / SO_RCVBUF (the
/// buffers are fixed, 64 KB in / 32 KB out per TCP socket), the low-water
/// marks, IP_TOS, IP_TTL.
#[no_mangle]
pub extern "C" fn rs_setsockopt(i: *mut Interface, fd: i32, level: i32, name: i32, value: *const u8, len: u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    let Some(v) = opt_bytes(value, len) else { return o.fail(errno::EINVAL) };
    let int = be32(v, 0);
    let stack_opt = |o: &mut Opener, opt: SockOpt| -> i32 {
        match o.run(false, SockOp::SetOpt { h: f.h, opt, result: Ok(()) }) {
            Some(SockOp::SetOpt { result: Err(e), .. }) => o.fail(e),
            _ => 0,
        }
    };
    let set_fd = |o: &mut Opener, g: Fd| {
        if let Some(Some(slot)) = o.fds().get_mut(fd as usize) {
            *slot = g;
        }
    };
    match (level, name) {
        (SOL_SOCKET, SO_RCVTIMEO | SO_SNDTIMEO) => {
            let (Some(sec), Some(usec)) = (be32(v, 0), be32(v, 4)) else { return o.fail(errno::EINVAL) };
            let us = sec as u64 * 1_000_000 + usec as u64;
            set_fd(o, if name == SO_RCVTIMEO { Fd { rcvtimeo_us: us, ..f } } else { Fd { sndtimeo_us: us, ..f } });
            0
        }
        (SOL_SOCKET, SO_LINGER) => {
            let (Some(on), Some(secs)) = (be32(v, 0), be32(v, 4)) else { return o.fail(errno::EINVAL) };
            stack_opt(o, SockOpt::LingerAbort(on != 0 && secs == 0))
        }
        (SOL_SOCKET, SO_EVENTMASK) => {
            let Some(mask) = int else { return o.fail(errno::EINVAL) };
            let target = (o.sigevent_mask != 0).then(|| amigaos4::signal::SignalTarget::new(amigaos4::signal::current_task(), o.sigevent_mask));
            set_fd(o, Fd { evmask: mask, ..f });
            stack_opt(o, SockOpt::Events(mask, target))
        }
        (SOL_SOCKET, n) if n & !FLAG_OPTS == 0 && n.count_ones() == 1 => {
            let Some(on) = int.map(|x| x != 0) else { return o.fail(errno::EINVAL) };
            set_fd(o, Fd { flags: if on { f.flags | n as u32 } else { f.flags & !(n as u32) }, ..f });
            if n == SO_KEEPALIVE {
                stack_opt(o, SockOpt::KeepAlive(on))
            } else {
                0
            }
        }
        (IPPROTO_IP, IP_TTL) => {
            // An int, or a single byte as some programs pass it.
            let Some(t) = int.or_else(|| v.first().map(|&b| b as u32)) else { return o.fail(errno::EINVAL) };
            if !(1..=255).contains(&t) {
                return o.fail(errno::EINVAL);
            }
            set_fd(o, Fd { ttl: t as u8, ..f });
            stack_opt(o, SockOpt::Ttl(t as u8))
        }
        (IPPROTO_IP, IP_HDRINCL) => {
            let Some(on) = int.map(|x| x != 0) else { return o.fail(errno::EINVAL) };
            set_fd(o, Fd { hdrincl: on, ..f });
            stack_opt(o, SockOpt::HdrIncl(on))
        }
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF | SO_SNDLOWAT | SO_RCVLOWAT) | (IPPROTO_IP, IP_TOS) => {
            if int.is_none() {
                return o.fail(errno::EINVAL);
            }
            0
        }
        (IPPROTO_TCP, TCP_NODELAY) => {
            let Some(on) = int.map(|x| x != 0) else { return o.fail(errno::EINVAL) };
            stack_opt(o, SockOpt::NoDelay(on))
        }
        _ => o.fail(ENOPROTOOPT),
    }
}

/// getsockopt(s, level, name, value, len): SO_ERROR (a background
/// connect's result, cleared), SO_TYPE, SO_ACCEPTCONN, the options
/// setsockopt takes (SO_SNDBUF / SO_RCVBUF say the real buffer sizes),
/// TCP_MAXSEG, IP_TOS, IP_TTL.
#[no_mangle]
pub extern "C" fn rs_getsockopt(i: *mut Interface, fd: i32, level: i32, name: i32, value: *mut u8, len: *mut u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(f) = o.fd(fd) else { return o.fail(errno::EBADF) };
    if value.is_null() || len.is_null() {
        return o.fail(errno::EINVAL);
    }
    // SAFETY: the caller's length.
    let room = unsafe { *len } as usize;
    let mut out = [0u8; 8];
    let mut n = 4;
    let mut put = |a: u32, b: Option<u32>| {
        out[..4].copy_from_slice(&a.to_be_bytes());
        if let Some(b) = b {
            out[4..].copy_from_slice(&b.to_be_bytes());
            n = 8;
        }
    };
    let needs_info = matches!((level, name), (SOL_SOCKET, SO_ERROR | SO_TYPE | SO_ACCEPTCONN | SO_KEEPALIVE | SO_LINGER | SO_SNDBUF | SO_RCVBUF) | (IPPROTO_TCP, TCP_NODELAY));
    let inf = if needs_info {
        match info(o, fd, name == SO_ERROR && level == SOL_SOCKET) {
            Ok(inf) => Some(inf),
            Err(e) => return o.fail(e),
        }
    } else {
        None
    };
    match (level, name) {
        (SOL_SOCKET, SO_ERROR) => put(inf.as_ref().unwrap().error as u32, None),
        (SOL_SOCKET, SO_TYPE) => put(
            match inf.as_ref().unwrap().kind {
                Some(SockKind::Udp) => SOCK_DGRAM as u32,
                Some(SockKind::Raw(_)) => SOCK_RAW as u32,
                _ => SOCK_STREAM as u32,
            },
            None,
        ),
        (SOL_SOCKET, SO_ACCEPTCONN) => put(inf.as_ref().unwrap().listening as u32, None),
        (SOL_SOCKET, SO_KEEPALIVE) => put(inf.as_ref().unwrap().keepalive as u32, None),
        (SOL_SOCKET, SO_LINGER) => put(inf.as_ref().unwrap().linger_abort as u32, Some(0)),
        (SOL_SOCKET, SO_SNDBUF) => put(inf.as_ref().unwrap().tx_buffer as u32, None),
        (SOL_SOCKET, SO_RCVBUF) => put(inf.as_ref().unwrap().rx_buffer as u32, None),
        (SOL_SOCKET, SO_SNDLOWAT | SO_RCVLOWAT) => put(1, None),
        (SOL_SOCKET, SO_RCVTIMEO | SO_SNDTIMEO) => {
            let us = if name == SO_RCVTIMEO { f.rcvtimeo_us } else { f.sndtimeo_us };
            put((us / 1_000_000) as u32, Some((us % 1_000_000) as u32));
        }
        (SOL_SOCKET, SO_EVENTMASK) => put(f.evmask, None),
        (SOL_SOCKET, n) if n & !FLAG_OPTS == 0 && n.count_ones() == 1 => put((f.flags & n as u32 != 0) as u32, None),
        (IPPROTO_TCP, TCP_NODELAY) => put(inf.as_ref().unwrap().nodelay as u32, None),
        (IPPROTO_TCP, TCP_MAXSEG) => put(1460, None),
        (IPPROTO_IP, IP_TOS) => put(0, None),
        (IPPROTO_IP, IP_TTL) => put(if f.ttl != 0 { f.ttl as u32 } else { rsnet_core::settings::SETTINGS.ttl() as u32 }, None),
        (IPPROTO_IP, IP_HDRINCL) => put(f.hdrincl as u32, None),
        _ => return o.fail(ENOPROTOOPT),
    }
    if room < n {
        return o.fail(errno::EINVAL);
    }
    // SAFETY: the caller's buffer of `room` >= n bytes and its length.
    unsafe {
        core::ptr::copy_nonoverlapping(out.as_ptr(), value, n);
        *len = n as u32;
    }
    0
}

/// SetSocketSignals(intr, io, urgent): the old way to set the break,
/// SIGIO and SIGURG masks.
#[no_mangle]
pub extern "C" fn rs_SetSocketSignals(i: *mut Interface, intr: u32, io: u32, urgent: u32) {
    if let Some(o) = opener(i) {
        o.break_mask = intr;
        o.sigio_mask = io;
        o.sigurg_mask = urgent;
    }
}

/// GetSocketEvents(&events): a descriptor of this opener with SO_EVENTMASK
/// events pending, and those events (taken); -1 when none has any.
#[no_mangle]
pub extern "C" fn rs_GetSocketEvents(i: *mut Interface, events: *mut u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let watched: Vec<(i32, u32)> = o.fds().iter().enumerate().filter_map(|(k, f)| f.filter(|f| !f.reserved && f.evmask != 0).map(|f| (k as i32, f.h))).collect();
    if watched.is_empty() {
        return -1;
    }
    let hs = watched.iter().map(|&(_, h)| h).collect();
    match o.run(false, SockOp::TakeEvents { hs, result: None }) {
        Some(SockOp::TakeEvents { result: Some((h, ev)), .. }) => {
            if !events.is_null() {
                // SAFETY: the caller's ULONG.
                unsafe { *events = ev };
            }
            watched.iter().find(|&&(_, wh)| wh == h).map(|&(fd, _)| fd).unwrap_or(-1)
        }
        _ => -1,
    }
}

/// fd_set: 32-bit words, descriptor n is bit n % 32 of word n / 32.
fn fd_isset(set: *const u32, n: usize) -> bool {
    // SAFETY: the caller's fd_set covering nfds descriptors.
    !set.is_null() && unsafe { *set.add(n / 32) } & (1 << (n % 32)) != 0
}

fn fd_clear_all(set: *mut u32, nfds: usize) {
    if !set.is_null() {
        for w in 0..nfds.div_ceil(32) {
            // SAFETY: as fd_isset.
            unsafe { *set.add(w) = 0 };
        }
    }
}

fn fd_set(set: *mut u32, n: usize) {
    if !set.is_null() {
        // SAFETY: as fd_isset.
        unsafe { *set.add(n / 32) |= 1 << (n % 32) };
    }
}

/// WaitSelect(nfds, readfds, writefds, exceptfds, timeout, sigmask): wait
/// until one of the sockets can be read (or accepted from) or written, the
/// timeout passes, or one of *sigmask's signals (then 0, with *sigmask =
/// what arrived) or the break mask (then -1, EINTR) comes. Exceptions are
/// never reported.
#[no_mangle]
pub extern "C" fn rs_WaitSelect(i: *mut Interface, nfds: i32, rd: *mut u32, wr: *mut u32, ex: *mut u32, timeout: *const u32, sigmask: *mut u32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let n = nfds.clamp(0, o.dtable as i32) as usize;
    let (mut reads, mut writes) = (Vec::new(), Vec::new());
    let mut map = Vec::new();
    for fd in 0..n {
        let (r, w) = (fd_isset(rd, fd), fd_isset(wr, fd));
        if !r && !w {
            continue;
        }
        let Some(f) = o.fd(fd as i32) else { return o.fail(errno::EBADF) };
        if r {
            reads.push(f.h);
        }
        if w {
            writes.push(f.h);
        }
        map.push((fd, f.h));
    }
    let until_us = if timeout.is_null() {
        None
    } else {
        // SAFETY: the caller's struct timeval { long tv_sec, tv_usec }.
        let (s, us) = unsafe { (*timeout as u64, *timeout.add(1) as u64) };
        Some(amigaos4::timer::get_up_time().as_micros() + s * 1_000_000 + us)
    };
    // SAFETY: the caller's signal mask, if given.
    let wanted = if sigmask.is_null() { 0 } else { unsafe { *sigmask } };
    let Some(stack) = stack() else { return o.fail(errno::ENOTCONN) };
    let token = TOKEN.fetch_add(1, Ordering::Relaxed);
    let r = stack.sock_with(token, false, None, SockOp::Select { reads, writes, until_us, result: Err(0) }, wanted | o.break_mask);
    let set_sig = |v: u32| {
        if !sigmask.is_null() {
            // SAFETY: as above.
            unsafe { *sigmask = v };
        }
    };
    match r {
        Some((SockOp::Select { result: Ok((r, w)), .. }, hit)) => {
            fd_clear_all(rd, n);
            fd_clear_all(wr, n);
            fd_clear_all(ex, n);
            let mut count = 0;
            for &(fd, h) in &map {
                if r.contains(&h) {
                    fd_set(rd, fd);
                    count += 1;
                }
                if w.contains(&h) {
                    fd_set(wr, fd);
                    count += 1;
                }
            }
            set_sig(hit & wanted);
            count
        }
        Some((SockOp::Select { result: Err(errno::EINTR), .. }, hit)) => {
            fd_clear_all(rd, n);
            fd_clear_all(wr, n);
            fd_clear_all(ex, n);
            if hit & o.break_mask != 0 {
                set_sig(0);
                keep_break(hit & o.break_mask);
                o.fail(errno::EINTR)
            } else {
                set_sig(hit & wanted);
                0
            }
        }
        Some((SockOp::Select { result: Err(e), .. }, _)) => o.fail(e),
        _ => o.fail(errno::ENOTCONN),
    }
}

// ---------------------------------------------------------------------------
// Names: gethostbyname through smoltcp's DNS socket
// ---------------------------------------------------------------------------

/// struct hostent (netinclude/netdb.h) and what it points to: one per
/// opener, overwritten by its next lookup (as BSD's static one is).
#[repr(C)]
pub struct HostEnt {
    h_name: *const u8,
    h_aliases: *const *const u8,
    h_addrtype: i32,
    h_length: i32,
    h_addr_list: *const *const u8,
    /// The names (official, then aliases), NUL-terminated one after another.
    pool: [u8; HOSTENT_POOL],
    aliases: [*const u8; HOSTENT_MAX + 1],
    addrs: [[u8; 4]; HOSTENT_MAX],
    addr_list: [*const u8; HOSTENT_MAX + 1],
}

/// BSD's MAXALIASES / MAXADDRS, and room for the names.
const HOSTENT_MAX: usize = 35;
const HOSTENT_POOL: usize = 1024;

impl HostEnt {
    pub fn empty() -> Self {
        HostEnt {
            h_name: core::ptr::null(),
            h_aliases: core::ptr::null(),
            h_addrtype: AF_INET,
            h_length: 4,
            h_addr_list: core::ptr::null(),
            pool: [0; HOSTENT_POOL],
            aliases: [core::ptr::null(); HOSTENT_MAX + 1],
            addrs: [[0; 4]; HOSTENT_MAX],
            addr_list: [core::ptr::null(); HOSTENT_MAX + 1],
        }
    }

    /// Fill in an answer (official name, aliases, addresses; as many as
    /// fit) and point the fields at the copies.
    fn set_answer(&mut self, a: &rsnet_core::resolver::Answer) -> *mut HostEnt {
        let mut at = 0usize;
        let mut put = |pool: &mut [u8; HOSTENT_POOL], s: &str| -> Option<usize> {
            let n = s.len().min(255);
            if at + n + 1 > HOSTENT_POOL {
                return None;
            }
            pool[at..at + n].copy_from_slice(&s.as_bytes()[..n]);
            pool[at + n] = 0;
            let start = at;
            at += n + 1;
            Some(start)
        };
        let name = put(&mut self.pool, &a.name).unwrap_or(0);
        let mut nal = 0;
        let mut offs = [0usize; HOSTENT_MAX];
        for x in a.aliases.iter().take(HOSTENT_MAX) {
            match put(&mut self.pool, x) {
                Some(o) => {
                    offs[nal] = o;
                    nal += 1;
                }
                None => break,
            }
        }
        for k in 0..=HOSTENT_MAX {
            self.aliases[k] = if k < nal { self.pool[offs[k]..].as_ptr() } else { core::ptr::null() };
        }
        let nad = a.addrs.len().min(HOSTENT_MAX);
        for k in 0..nad {
            self.addrs[k] = a.addrs[k];
        }
        for k in 0..=HOSTENT_MAX {
            self.addr_list[k] = if k < nad { self.addrs[k].as_ptr() } else { core::ptr::null() };
        }
        self.h_name = self.pool[name..].as_ptr();
        self.h_aliases = self.aliases.as_ptr();
        self.h_addrtype = AF_INET;
        self.h_length = 4;
        self.h_addr_list = self.addr_list.as_ptr();
        self as *mut HostEnt
    }
}

/// gethostbyname(name): the opener's hostent, or NULL with h_errno set
/// (HOST_NOT_FOUND, TRY_AGAIN, NO_RECOVERY). A dotted address is itself.
/// Waits for DNS (its break mask interrupts: TRY_AGAIN, errno EINTR).
#[no_mangle]
pub extern "C" fn rs_gethostbyname(i: *mut Interface, name: *const u8) -> *mut HostEnt {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    if name.is_null() {
        o.set_herrno(rsnet_core::sock::herrno::HOST_NOT_FOUND);
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's NUL-terminated name.
    let bytes = unsafe { core::ffi::CStr::from_ptr(name as *const core::ffi::c_char) }.to_bytes();
    let Ok(text) = core::str::from_utf8(bytes) else {
        o.set_herrno(rsnet_core::sock::herrno::HOST_NOT_FOUND);
        return core::ptr::null_mut();
    };
    match netdb::lookup_name(o, text) {
        // h_errno stays as it was, as Roadshow leaves it on success
        // (still 1 from an earlier failure, say).
        Ok(ans) => {
            // SAFETY: the opener's hostent, made with it.
            unsafe { (*o.host).set_answer(&ans) }
        }
        Err((h, hit)) => {
            o.set_herrno(h);
            if hit != 0 {
                o.set_errno(errno::EINTR);
            }
            core::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Interfaces and statistics: what netprof and Roadshow's tools read
// ---------------------------------------------------------------------------

/// The interfaces are named rs0, rs1, ... in Config order.
const ENXIO: i32 = 6;

/// "rs<n>" (any case) as n.
/// The slot of the present interface called `name` in `all` (names are
/// case-insensitive, as Roadshow's).
fn iface_index(all: &[rsnet_core::stack::Status], name: &[u8]) -> Option<usize> {
    all.iter().position(|st| st.present && st.name.as_bytes().eq_ignore_ascii_case(name))
}

const IFQ_BASE: u32 = sys::TAG_USER + 1900;
const IFQ_DEVICE_NAME: u32 = IFQ_BASE + 1;
const IFQ_DEVICE_UNIT: u32 = IFQ_BASE + 2;
const IFQ_HARDWARE_ADDRESS_SIZE: u32 = IFQ_BASE + 3;
const IFQ_HARDWARE_ADDRESS: u32 = IFQ_BASE + 4;
const IFQ_MTU: u32 = IFQ_BASE + 5;
const IFQ_BPS: u32 = IFQ_BASE + 6;
const IFQ_HARDWARE_TYPE: u32 = IFQ_BASE + 7;
const IFQ_PACKETS_RECEIVED: u32 = IFQ_BASE + 8;
const IFQ_PACKETS_SENT: u32 = IFQ_BASE + 9;
const IFQ_BAD_DATA: u32 = IFQ_BASE + 10;
const IFQ_OVERRUNS: u32 = IFQ_BASE + 11;
const IFQ_UNKNOWN_TYPES: u32 = IFQ_BASE + 12;
const IFQ_LAST_START: u32 = IFQ_BASE + 13;
const IFQ_ADDRESS: u32 = IFQ_BASE + 14;
const IFQ_DESTINATION_ADDRESS: u32 = IFQ_BASE + 15;
const IFQ_BROADCAST_ADDRESS: u32 = IFQ_BASE + 16;
const IFQ_NET_MASK: u32 = IFQ_BASE + 17;
const IFQ_METRIC: u32 = IFQ_BASE + 18;
const IFQ_STATE: u32 = IFQ_BASE + 19;
const IFQ_ADDRESS_BIND_TYPE: u32 = IFQ_BASE + 20;
const IFQ_ADDRESS_LEASE_EXPIRES: u32 = IFQ_BASE + 21;
const IFQ_PRIMARY_DNS: u32 = IFQ_BASE + 22;
const IFQ_SECONDARY_DNS: u32 = IFQ_BASE + 23;
const IFQ_NUM_READ_REQUESTS: u32 = IFQ_BASE + 24;
const IFQ_MAX_READ_REQUESTS: u32 = IFQ_BASE + 25;
const IFQ_NUM_WRITE_REQUESTS: u32 = IFQ_BASE + 26;
const IFQ_MAX_WRITE_REQUESTS: u32 = IFQ_BASE + 27;
const IFQ_GET_BYTES_IN: u32 = IFQ_BASE + 28;
const IFQ_GET_BYTES_OUT: u32 = IFQ_BASE + 29;
const IFQ_GET_DEBUG_MODE: u32 = IFQ_BASE + 30;
const IFQ_GET_SANA2_COPY_STATS: u32 = IFQ_BASE + 31;
const IFQ_NUM_READ_REQUESTS_PENDING: u32 = IFQ_BASE + 32;
const IFQ_NUM_WRITE_REQUESTS_PENDING: u32 = IFQ_BASE + 33;
const IFQ_HARDWARE_MTU: u32 = IFQ_BASE + 34;
const IFQ_OUTPUT_DROPS: u32 = IFQ_BASE + 35;
const IFQ_INPUT_DROPS: u32 = IFQ_BASE + 36;
const IFQ_OUTPUT_ERRORS: u32 = IFQ_BASE + 37;
const IFQ_INPUT_ERRORS: u32 = IFQ_BASE + 38;
const IFQ_OUTPUT_MULTICASTS: u32 = IFQ_BASE + 39;
const IFQ_INPUT_MULTICASTS: u32 = IFQ_BASE + 40;
const IFQ_IP_DROPS: u32 = IFQ_BASE + 41;
const IFQ_ARP_DROPS: u32 = IFQ_BASE + 42;
const SM_DOWN: i32 = 2;
const SM_UP: i32 = 3;

const NETWORKSTATUS_VERSION: i32 = 1;
const NETSTATUS_TCP_SOCKETS: i32 = 9;
const NETSTATUS_UDP_SOCKETS: i32 = 10;

/// struct Node and struct List (exec/nodes.h, exec/lists.h; pack 2).
#[repr(C, packed(2))]
struct ExecNode {
    succ: *mut ExecNode,
    pred: *mut ExecNode,
    kind: u8,
    pri: i8,
    name: *const u8,
}

#[repr(C, packed(2))]
struct ExecList {
    head: *mut ExecNode,
    tail: *mut ExecNode,
    tail_pred: *mut ExecNode,
    kind: u8,
    pad: u8,
}

/// What ObtainInterfaceList hands out: a list of one node per interface,
/// and the names; freed by ReleaseInterfaceList.
#[repr(C)]
pub struct IfaceList {
    list: ExecList,
    nodes: [ExecNode; MAX_IFACES],
    names: [[u8; 16]; MAX_IFACES],
}

/// ObtainInterfaceList(): the interfaces as an exec List of named nodes.
#[no_mangle]
pub extern "C" fn rs_ObtainInterfaceList(i: *mut Interface) -> *mut IfaceList {
    let Some(_) = opener(i) else { return core::ptr::null_mut() };
    // Roadshow's list leaves the loopback interface out (lo0 still answers
    // QueryInterfaceTagList).
    let present: Vec<alloc::string::String> =
        stack().and_then(|s| s.status()).map(|v| v.into_iter().filter(|st| st.present && !st.loopback).map(|st| st.name).collect()).unwrap_or_default();
    let n = present.len().min(MAX_IFACES);
    const EMPTY: ExecNode = ExecNode { succ: core::ptr::null_mut(), pred: core::ptr::null_mut(), kind: 0, pri: 0, name: core::ptr::null() };
    let mut b = Box::new(IfaceList {
        list: ExecList { head: core::ptr::null_mut(), tail: core::ptr::null_mut(), tail_pred: core::ptr::null_mut(), kind: 0, pad: 0 },
        nodes: [EMPTY; MAX_IFACES],
        names: [[0; 16]; MAX_IFACES],
    });
    for (k, name) in present.iter().take(n).enumerate() {
        let l = name.len().min(15);
        b.names[k][..l].copy_from_slice(&name.as_bytes()[..l]);
    }
    let p = Box::into_raw(b);
    // SAFETY: our new block; the list links point inside it (it does not
    // move: a Box until ReleaseInterfaceList). An exec list: lh_Head the
    // first node (or &lh_Tail when empty), each node's ln_Succ the next (the
    // last one's &lh_Tail), ln_Pred the one before (the first's the list),
    // lh_TailPred the last node (or the list when empty).
    unsafe {
        let l = core::ptr::addr_of_mut!((*p).list);
        let nodes = core::ptr::addr_of_mut!((*p).nodes) as *mut ExecNode;
        let tail_node = core::ptr::addr_of_mut!((*l).tail) as *mut ExecNode;
        core::ptr::addr_of_mut!((*l).tail).write_unaligned(core::ptr::null_mut());
        if n == 0 {
            core::ptr::addr_of_mut!((*l).head).write_unaligned(tail_node);
            core::ptr::addr_of_mut!((*l).tail_pred).write_unaligned(l as *mut ExecNode);
        } else {
            core::ptr::addr_of_mut!((*l).head).write_unaligned(nodes);
            core::ptr::addr_of_mut!((*l).tail_pred).write_unaligned(nodes.add(n - 1));
            for k in 0..n {
                let node = nodes.add(k);
                let succ = if k + 1 < n { nodes.add(k + 1) } else { tail_node };
                let pred = if k == 0 { l as *mut ExecNode } else { nodes.add(k - 1) };
                core::ptr::addr_of_mut!((*node).succ).write_unaligned(succ);
                core::ptr::addr_of_mut!((*node).pred).write_unaligned(pred);
                let name = (core::ptr::addr_of!((*p).names) as *const [u8; 16]).add(k) as *const u8;
                core::ptr::addr_of_mut!((*node).name).write_unaligned(name);
            }
        }
    }
    p
}

/// ReleaseInterfaceList(list).
#[no_mangle]
pub extern "C" fn rs_ReleaseInterfaceList(_i: *mut Interface, list: *mut IfaceList) {
    if !list.is_null() {
        // SAFETY: a block from rs_ObtainInterfaceList, given back once.
        drop(unsafe { Box::from_raw(list) });
    }
}

/// The interface's device name for IFQ_DeviceName: made at the first
/// query, valid until the last Close (the device does not change while the
/// stack runs).
static DEVICE_NAME: [AtomicPtr<Vec<u8>>; MAX_IFACES] = [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_IFACES];

fn device_name_ptr(k: usize, name: &str) -> *const u8 {
    let slot = &DEVICE_NAME[k.min(MAX_IFACES - 1)];
    let cur = slot.load(Ordering::Acquire);
    if !cur.is_null() {
        // SAFETY: a Vec stored below, freed only at the last Close.
        return unsafe { (*cur).as_ptr() };
    }
    let mut v = Vec::from(name.as_bytes());
    v.push(0);
    let new = Box::into_raw(Box::new(v));
    match slot.compare_exchange(core::ptr::null_mut(), new, Ordering::AcqRel, Ordering::Acquire) {
        // SAFETY: just stored.
        Ok(_) => unsafe { (*new).as_ptr() },
        Err(won) => {
            // SAFETY: ours, never published; `won` was stored by another
            // caller and lives until the last Close.
            unsafe {
                drop(Box::from_raw(new));
                (*won).as_ptr()
            }
        }
    }
}

/// At the last Close: the device name goes.
fn free_device_name() {
    for slot in &DEVICE_NAME {
        let cur = slot.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !cur.is_null() {
            // SAFETY: stored by device_name_ptr, taken once.
            drop(unsafe { Box::from_raw(cur) });
        }
    }
}

fn prefix_mask(len: u8) -> [u8; 4] {
    let m: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len.min(32) as u32) };
    m.to_be_bytes()
}

fn put_sockaddr_at(data: u32, ep: ([u8; 4], u16)) {
    let mut len: u32 = 16;
    put_sockaddr(data as *mut u8, &mut len, ep);
}

/// QueryInterfaceTagList(name, tags): each tag's ti_Data points to where
/// its answer goes. -1 (ENXIO) for an unknown interface, -1 (EINVAL) for a
/// tag this stack does not answer.
#[no_mangle]
pub extern "C" fn rs_QueryInterfaceTagList(i: *mut Interface, name: *const u8, tags: *mut TagItem) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    if name.is_null() {
        return o.fail(ENXIO);
    }
    // SAFETY: the caller's NUL-terminated name.
    let n = unsafe { core::ffi::CStr::from_ptr(name as *const core::ffi::c_char) }.to_bytes();
    let Some(all) = stack().and_then(|s| s.status()) else { return o.fail(ENXIO) };
    let Some(k) = iface_index(&all, n) else { return o.fail(ENXIO) };
    let Some(st) = all.into_iter().nth(k) else { return o.fail(ENXIO) };
    let mut t = tags;
    loop {
        if t.is_null() {
            return 0;
        }
        // SAFETY: the caller's TAG_DONE-ended list (TAG_MORE/IGNORE/SKIP
        // followed as utility.library does).
        let (tag, data) = unsafe { ((*t).ti_Tag, (*t).ti_Data) };
        match tag {
            sys::TAG_DONE => return 0,
            sys::TAG_IGNORE => {
                // SAFETY: as above.
                t = unsafe { t.add(1) };
                continue;
            }
            sys::TAG_MORE => {
                t = data as *mut TagItem;
                continue;
            }
            sys::TAG_SKIP => {
                // SAFETY: as above.
                t = unsafe { t.add(1 + data as usize) };
                continue;
            }
            _ => {}
        }
        if data == 0 {
            return o.fail(EINVAL);
        }
        let long = |v: u32| {
            // SAFETY: a LONG * / ULONG * tag's destination.
            unsafe { *(data as *mut u32) = v };
        };
        let quad = |v: u64| {
            // SAFETY: an SBQUAD_T * destination: { sbq_High, sbq_Low }.
            unsafe {
                *(data as *mut u32) = (v >> 32) as u32;
                *(data as *mut u32).add(1) = v as u32;
            }
        };
        let (addr, plen) = st.address.unwrap_or(([0; 4], 0));
        match tag {
            IFQ_DEVICE_NAME => {
                // SAFETY: a STRPTR * destination.
                unsafe { *(data as *mut *const u8) = device_name_ptr(k, &st.device) };
            }
            IFQ_DEVICE_UNIT => long(st.unit),
            IFQ_HARDWARE_ADDRESS_SIZE => long(st.addr_bits),
            IFQ_HARDWARE_ADDRESS => {
                // SAFETY: a buffer of the hardware address's size.
                unsafe { core::ptr::copy_nonoverlapping(st.mac.as_ptr(), data as *mut u8, 6) };
            }
            IFQ_MTU => long(st.mtu),
            IFQ_HARDWARE_MTU => long(if st.hw_mtu != 0 { st.hw_mtu } else { st.mtu }),
            IFQ_BPS => long(st.bps),
            IFQ_HARDWARE_TYPE => long(st.hw_type),
            IFQ_PACKETS_RECEIVED => long(st.link.rx_frames),
            IFQ_PACKETS_SENT => long(st.link.tx_frames),
            IFQ_BAD_DATA | IFQ_OVERRUNS | IFQ_UNKNOWN_TYPES | IFQ_OUTPUT_DROPS | IFQ_IP_DROPS | IFQ_ARP_DROPS | IFQ_OUTPUT_MULTICASTS | IFQ_INPUT_MULTICASTS => long(0),
            // struct timeval: when it was added.
            IFQ_LAST_START => {
                long(st.started.0);
                // SAFETY: a struct timeval *: tv_micro follows tv_secs.
                unsafe { *(data as *mut u32).add(1) = st.started.1 };
            }
            // IFABT_Dynamic while the interface keeps the address its
            // BeginInterfaceConfig lease gave, IFABT_Static for any other
            // (also once taken down), IFABT_Unknown before one.
            IFQ_ADDRESS_BIND_TYPE => long(match (st.address, st.lease) {
                (None, _) => 0,
                (Some((a, _)), Some((l, _))) if a == l => 2,
                _ => 1,
            }),
            // struct DateStamp: when the dynamic address's lease ends;
            // zeros for a static one or a lease that never ends.
            IFQ_ADDRESS_LEASE_EXPIRES => {
                let ds = match (st.address, st.lease) {
                    (Some((a, _)), Some((l, end))) if a == l && end != u64::MAX => {
                        let left = end.saturating_sub(amigaos4::timer::get_up_time().as_micros()) / 1_000_000;
                        rsnet_core::aam::expiry(left.min(u32::MAX as u64) as u32)
                    }
                    _ => sys::DateStamp::default(),
                };
                // SAFETY: a struct DateStamp * (three LONGs).
                unsafe { (data as *mut sys::DateStamp).write_unaligned(ds) };
            }
            IFQ_GET_DEBUG_MODE => long(st.debug as u32),
            // struct SANA2CopyStats: one byte-copy call per frame each way.
            IFQ_GET_SANA2_COPY_STATS => {
                let v = [0, 0, st.link.rx_frames, st.link.tx_frames, 0];
                // SAFETY: a struct SANA2CopyStats * (five ULONGs).
                unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), data as *mut u32, 5) };
            }
            IFQ_INPUT_DROPS => long(st.link.rx_dropped),
            IFQ_INPUT_ERRORS => long(st.link.rx_errors),
            IFQ_OUTPUT_ERRORS => long(st.link.tx_errors),
            IFQ_ADDRESS => put_sockaddr_at(data, (addr, 0)),
            IFQ_NET_MASK => put_sockaddr_at(data, (prefix_mask(plen), 0)),
            IFQ_BROADCAST_ADDRESS => {
                let m = prefix_mask(plen);
                let computed = [addr[0] | !m[0], addr[1] | !m[1], addr[2] | !m[2], addr[3] | !m[3]];
                put_sockaddr_at(data, (st.broadcast.unwrap_or(computed), 0));
            }
            // Only point-to-point interfaces have one (none here); Roadshow
            // fails the query too (ShowNetStatus then prints no peer line).
            IFQ_DESTINATION_ADDRESS => return o.fail(EINVAL),
            IFQ_PRIMARY_DNS => put_sockaddr_at(data, (st.dns.first().copied().unwrap_or([0; 4]), 0)),
            IFQ_SECONDARY_DNS => put_sockaddr_at(data, (st.dns.get(1).copied().unwrap_or([0; 4]), 0)),
            IFQ_METRIC => long(st.metric),
            // Down once ConfigureNetInterface DOWN took it down (Roadshow's
            // "Link status = Down").
            IFQ_STATE => long(if st.address.is_some() && st.up { SM_UP } else { SM_DOWN } as u32),
            IFQ_NUM_READ_REQUESTS | IFQ_MAX_READ_REQUESTS | IFQ_NUM_READ_REQUESTS_PENDING => long(rsnet_core::link::READS),
            IFQ_NUM_WRITE_REQUESTS | IFQ_MAX_WRITE_REQUESTS => long(1),
            IFQ_NUM_WRITE_REQUESTS_PENDING => long(0),
            IFQ_GET_BYTES_IN => quad(st.link.rx_bytes),
            IFQ_GET_BYTES_OUT => quad(st.link.tx_bytes),
            _ => return o.fail(EINVAL),
        }
        // SAFETY: as above.
        t = unsafe { t.add(1) };
    }
}

/// struct protocol_connection_data (pack 2), 24 bytes.
#[repr(C, packed(2))]
struct ConnData {
    foreign_address: u32,
    foreign_port: u16,
    local_address: u32,
    local_port: u16,
    receive_queue_size: u32,
    send_queue_size: u32,
    tcp_state: i32,
}
const _: () = assert!(core::mem::size_of::<ConnData>() == 24);

/// GetNetworkStatistics(type, version, dest, size): the counter tables
/// (rsnet_core::stats; igmp, mb, mrt and rt are kept at 0: no multicast
/// routing, no mbufs, no redirects here) and the TCP and UDP socket lists.
/// A NULL dest asks for the size; at most `size` bytes are copied.
#[no_mangle]
pub extern "C" fn rs_GetNetworkStatistics(i: *mut Interface, kind: i32, version: i32, dest: *mut u8, size: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    if version != NETWORKSTATUS_VERSION {
        return o.fail(EINVAL);
    }
    use rsnet_core::stats;
    let table: Option<Vec<u8>> = match kind {
        0 => Some(stats::snapshot(&stats::ICMP)),
        // struct igmpstat (9 LONGs), mbstat (7), mrtstat (8), rtstat (5 WORDs).
        1 => Some(alloc::vec![0u8; 9 * 4]),
        2 => Some(stats::snapshot(&stats::IP)),
        3 => Some(alloc::vec![0u8; 7 * 4]),
        4 => Some(alloc::vec![0u8; 8 * 4]),
        5 => Some(alloc::vec![0u8; 5 * 2]),
        6 => Some(stats::snapshot(&stats::TCP)),
        7 => Some(stats::snapshot(&stats::UDP)),
        _ => None,
    };
    if let Some(t) = table {
        if dest.is_null() {
            return t.len() as i32;
        }
        let n = t.len().min(size.max(0) as usize);
        // SAFETY: the caller's buffer of `size` bytes.
        unsafe { core::ptr::copy_nonoverlapping(t.as_ptr(), dest, n) };
        return n as i32;
    }
    let k = match kind {
        NETSTATUS_TCP_SOCKETS => SockKind::Tcp,
        NETSTATUS_UDP_SOCKETS => SockKind::Udp,
        _ => return o.fail(EINVAL),
    };
    let list = match o.run(false, SockOp::List { kind: k, result: Vec::new() }) {
        Some(SockOp::List { result, .. }) => result,
        _ => return o.fail(errno::ENOTCONN),
    };
    let need = list.len() * 24;
    if dest.is_null() {
        return need as i32;
    }
    let room = (size.max(0) as usize) / 24;
    let n = list.len().min(room);
    for (k, c) in list.iter().take(n).enumerate() {
        let d = ConnData {
            foreign_address: u32::from_be_bytes(c.remote.0),
            foreign_port: c.remote.1,
            local_address: u32::from_be_bytes(c.local.0),
            local_port: c.local.1,
            receive_queue_size: c.recv_queue,
            send_queue_size: c.send_queue,
            tcp_state: c.tcp_state,
        };
        // SAFETY: the caller's buffer of `size` bytes holds `room` entries.
        unsafe { core::ptr::write_unaligned((dest as *mut ConnData).add(k), d) };
    }
    (n * 24) as i32
}
