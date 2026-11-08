//! The "TCP:" device (Roadshow's tcp-handler.doc): DOS files that are
//! network connections.
//!
//! - `TCP:host/port`, `TCP:HOST=h/PORT=p` (SERVICE= and service names for
//!   the port): a connection to that host;
//! - `TCP:port` or `TCP:service`: wait for one connection on that port;
//! - `TCP:OBTAIN=n`: a socket released under id n (ReleaseSocket, or the
//!   superserver for a DOS server).
//!
//! Packets: FINDINPUT/FINDOUTPUT/FINDUPDATE, END, READ, WRITE, WAIT_CHAR,
//! IS_FILESYSTEM, STACK (characters pushed back). As Roadshow
//! (testprogs/rstcp/c/tcpdos.c): such files are not interactive,
//! a failed open says ERROR_OBJECT_NOT_FOUND.
//!
//! Like the superserver, a process of the library's own, not an opener.
//! It adds the device when it starts unless something called TCP is
//! already there. At the last Close (`stop`) it closes its sockets, takes
//! the device away and stops using the stack before `stop` returns; files
//! still open are answered (READ 0, WRITE -1) until their END, and only
//! then does the process end. The library is not expunged while it is
//! there (`busy`, asked by the glue's Expunge).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use amigaos4::sys::{self, DosPacket, Message};
use rsnet_core::sock::{errno, SockKind, SockOp};

use super::{shared, stack};

const NAME: &str = "rustsocket TCP-Handler";
const CTRL_C: u32 = sys::SIGBREAKF_CTRL_C;

const ACTION_WAIT_CHAR: i32 = 20;
const ACTION_FINDUPDATE: i32 = 1004;
const ACTION_FINDINPUT: i32 = 1005;
const ACTION_FINDOUTPUT: i32 = 1006;
const ACTION_END: i32 = 1007;
const ACTION_IS_FILESYSTEM: i32 = 1027;
const ACTION_READ: i32 = 82;
const ACTION_WRITE: i32 = 87;
const ACTION_STACK: i32 = 2002;

const ERROR_NO_FREE_STORE: i32 = 103;
const ERROR_OBJECT_NOT_FOUND: i32 = 205;
const ERROR_ACTION_NOT_KNOWN: i32 = 209;
const DOSTRUE: i32 = -1;

const LDF_WRITE: u32 = 1 << 1;
const LDF_READ: u32 = 1 << 0;
const LDF_DEVICES: u32 = 1 << 2;
const LDF_ALL: u32 = (1 << 2) | (1 << 3) | (1 << 4);
const DLT_DEVICE: i32 = 0;

// FileHandle fields (dos/dosextens.h).
const FH_INTERACTIVE: usize = 4;
const FH_ARG1: usize = 36;

/// The running handler's task (0: none); `stop` signals it.
static CURRENT: AtomicU32 = AtomicU32::new(0);
/// Set by the handler once it no longer calls the stack (after `stop`).
static DETACHED: AtomicU32 = AtomicU32::new(0);
static TOKEN: AtomicU32 = AtomicU32::new(0x6000_0000);

/// Start the handler (the stack is running).
pub fn start() {
    DETACHED.store(0, Ordering::Release);
    let b = match amigaos4::dos::process::ProcessBuilder::new(NAME) {
        Ok(b) => b.priority(1).stack(32768),
        Err(_) => return,
    };
    if let Err(e) = b.spawn_detached(run) {
        amigaos4::serial_println!("rustsocket.library: the TCP: handler did not start: {}", e);
    }
}

/// The last Close: the handler lets go of the stack before this returns.
pub fn stop() {
    let t = CURRENT.load(Ordering::Acquire);
    if t == 0 {
        return;
    }
    let Ok(mut timer) = amigaos4::timer::AmigaTimer::open(amigaos4::timer::TimerUnit::MicroHz) else { return };
    for _ in 0..500 {
        if DETACHED.load(Ordering::Acquire) != 0 || CURRENT.load(Ordering::Acquire) != t {
            return;
        }
        // SAFETY: the handler's own task, which clears CURRENT only after
        // it has let go of the stack and before it ends.
        unsafe { sys::exec_signal(t as *mut sys::Task, CTRL_C) };
        let _ = timer.delay(amigaos4::timer::TimerVal::from_millis(10));
    }
    amigaos4::serial_println!("rustsocket.library: the TCP: handler did not let go of the stack");
}

/// Whether a handler process is still there (the library must stay).
pub fn busy() -> bool {
    let name = alloc::format!("{}\0", NAME);
    // SAFETY: FindTask with a NUL-terminated name (the glue calls this
    // from Expunge, under exec's Forbid).
    !unsafe { sys::exec_find_task(name.as_ptr()) }.is_null()
}

enum State {
    Open,
    /// TCP:port: waiting for a connection on this listener.
    Accepting(u32),
    /// A connect under way.
    Connecting,
}

struct File {
    id: u32,
    /// The stack socket (None once detached).
    h: Option<u32>,
    state: State,
    /// The FIND packet answered when the connection is there.
    find: Option<*mut DosPacket>,
    /// READ / WAIT_CHAR packets waiting for data (WAIT_CHAR: deadline).
    reads: VecDeque<(*mut DosPacket, Option<u64>)>,
    pushback: Vec<u8>,
}

fn op(nonblock: bool, o: SockOp, brk: u32) -> Option<(SockOp, u32)> {
    stack()?.sock_with(TOKEN.fetch_add(1, Ordering::Relaxed), nonblock, None, o, brk)
}

fn reply(p: *mut DosPacket, r1: i32, r2: i32) {
    // SAFETY: a packet DOS sent us, answered once.
    unsafe { sys::dos_reply_pkt(p, r1, r2) };
}

fn arg(p: *mut DosPacket, n: usize) -> i32 {
    // SAFETY: a packet DOS sent us: dp_Arg1.. follow dp_Res2 (offset 20).
    unsafe { core::ptr::read_unaligned((p as *const u8).add(20 + 4 * (n - 1)) as *const i32) }
}

/// FIND's name: a BSTR (or, from some callers, a C string), without the
/// device part.
fn find_name(a: i32) -> String {
    // SAFETY: DOS passes a BSTR (a BPTR to a length byte and the
    // characters); a C string is told by its having no length byte that
    // matches (checked against the first NUL).
    unsafe {
        let b = ((a as u32) << 2) as *const u8;
        let len = *b as usize;
        let s = core::slice::from_raw_parts(b.add(1), len);
        let raw = if !s.contains(&0) && s.contains(&b':') {
            s.to_vec()
        } else {
            let c = a as u32 as *const u8;
            let n = (0..512).position(|k| *c.add(k) == 0).unwrap_or(0);
            core::slice::from_raw_parts(c, n).to_vec()
        };
        let t = String::from_utf8_lossy(&raw).into_owned();
        match t.split_once(':') {
            Some((_, rest)) => String::from(rest),
            None => t,
        }
    }
}

/// The address of `host`: dotted, the hosts file, then DNS.
fn resolve(host: &str) -> Option<[u8; 4]> {
    if let Some(a) = super::inet::parse(host.as_bytes()) {
        return Some(a.to_be_bytes());
    }
    if let Some(a) = super::netdb::host_address(host) {
        return Some(a);
    }
    let ask = rsnet_core::resolver::Ask::Name(String::from(host));
    match op(false, SockOp::Resolve { ask, state: Default::default(), result: Err(0) }, CTRL_C) {
        Some((SockOp::Resolve { result: Ok(a), .. }, _)) => a.addrs.first().copied(),
        _ => None,
    }
}

fn port_of(s: &str) -> Option<u16> {
    super::netdb::service_port(s, "tcp")
}

/// Parse the name: Obtain(id), Connect(host, port) or Listen(port).
enum Target {
    Obtain(i32),
    Connect(String, u16),
    Listen(u16),
}

fn target(name: &str) -> Option<Target> {
    let (mut host, mut port, mut obtain) = (None, None, None);
    let mut positional = Vec::new();
    for part in name.split('/').filter(|s| !s.is_empty()) {
        match part.split_once('=') {
            Some((k, v)) => match k.to_ascii_uppercase().as_str() {
                "H" | "HOST" => host = Some(String::from(v)),
                "P" | "PORT" | "S" | "SERVICE" => port = Some(String::from(v)),
                "O" | "OBTAIN" => obtain = v.parse::<i32>().ok(),
                _ => return None,
            },
            None => positional.push(String::from(part)),
        }
    }
    if let Some(id) = obtain {
        return Some(Target::Obtain(id));
    }
    let mut pos = positional.into_iter();
    if host.is_none() && port.is_none() {
        let first = pos.next()?;
        match pos.next() {
            Some(p) => {
                host = Some(first);
                port = Some(p);
            }
            None => port = Some(first),
        }
    } else if host.is_some() && port.is_none() {
        port = pos.next();
    } else if host.is_none() {
        host = pos.next();
    }
    let p = port_of(&port?)?;
    Some(match host {
        Some(h) => Target::Connect(h, p),
        None => Target::Listen(p),
    })
}

/// A new stack socket of ours (one descriptor-like reference).
fn new_sock() -> Option<u32> {
    match op(false, SockOp::Open { kind: SockKind::Tcp, result: Err(0) }, 0) {
        Some((SockOp::Open { result: Ok(h), .. }, _)) => {
            shared::add_ref(h);
            Some(h)
        }
        _ => None,
    }
}

fn release(h: u32) {
    if shared::drop_ref(h) {
        let _ = op(false, SockOp::Close { h, result: Ok(()) }, 0);
    }
}

struct Handler {
    files: Vec<File>,
    next_id: u32,
}

impl Handler {
    fn file(&mut self, id: i32) -> Option<&mut File> {
        self.files.iter_mut().find(|f| f.id == id as u32)
    }

    /// FINDINPUT/OUTPUT/UPDATE.
    fn find(&mut self, p: *mut DosPacket) {
        let fh = ((arg(p, 1) as u32) << 2) as usize;
        let name = find_name(arg(p, 3));
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut f = File { id, h: None, state: State::Open, find: None, reads: VecDeque::new(), pushback: Vec::new() };
        let set_fh = || {
            // SAFETY: the FileHandle DOS gave with the packet.
            unsafe {
                core::ptr::write_unaligned((fh + FH_ARG1) as *mut u32, id);
                core::ptr::write_unaligned((fh + FH_INTERACTIVE) as *mut i32, 0);
            }
        };
        match target(&name) {
            Some(Target::Obtain(n)) => {
                let got = shared::lock().and_then(|mut sh| {
                    let k = sh.released.iter().position(|(i, _)| *i == n)?;
                    Some(sh.released.swap_remove(k).1)
                });
                match got {
                    Some(fd) => {
                        f.h = Some(fd.h);
                        set_fh();
                        self.files.push(f);
                        reply(p, DOSTRUE, 0);
                    }
                    None => reply(p, 0, ERROR_OBJECT_NOT_FOUND),
                }
            }
            Some(Target::Connect(host, port)) => {
                let Some(addr) = resolve(&host) else { return reply(p, 0, ERROR_OBJECT_NOT_FOUND) };
                let Some(h) = new_sock() else { return reply(p, 0, ERROR_NO_FREE_STORE) };
                match op(true, SockOp::Connect { h, addr, port, result: Err(0) }, 0) {
                    Some((SockOp::Connect { result: Ok(()), .. }, _)) => {
                        f.h = Some(h);
                        set_fh();
                        self.files.push(f);
                        reply(p, DOSTRUE, 0);
                    }
                    Some((SockOp::Connect { result: Err(e), .. }, _)) if e == errno::EINPROGRESS || e == errno::EWOULDBLOCK => {
                        f.h = Some(h);
                        f.state = State::Connecting;
                        f.find = Some(p);
                        set_fh();
                        self.files.push(f);
                    }
                    _ => {
                        release(h);
                        reply(p, 0, ERROR_OBJECT_NOT_FOUND);
                    }
                }
            }
            Some(Target::Listen(port)) => {
                let Some(l) = new_sock() else { return reply(p, 0, ERROR_NO_FREE_STORE) };
                let ok = matches!(op(false, SockOp::Bind { h: l, addr: [0; 4], port, result: Err(0) }, 0), Some((SockOp::Bind { result: Ok(()), .. }, _)))
                    && matches!(op(false, SockOp::Listen { h: l, backlog: 1, result: Err(0) }, 0), Some((SockOp::Listen { result: Ok(()), .. }, _)));
                if !ok {
                    release(l);
                    return reply(p, 0, ERROR_OBJECT_NOT_FOUND);
                }
                f.state = State::Accepting(l);
                f.find = Some(p);
                set_fh();
                self.files.push(f);
            }
            None => {
                amigaos4::serial_println!("rustsocket TCP: cannot make sense of \"{}\"", name);
                reply(p, 0, ERROR_OBJECT_NOT_FOUND);
            }
        }
    }

    fn end(&mut self, p: *mut DosPacket) {
        let id = arg(p, 1) as u32;
        if let Some(k) = self.files.iter().position(|f| f.id == id) {
            let f = self.files.swap_remove(k);
            for (r, _) in f.reads {
                reply(r, -1, ERROR_OBJECT_NOT_FOUND);
            }
            if let State::Accepting(l) = f.state {
                release(l);
            }
            if let Some(h) = f.h {
                release(h);
            }
        }
        reply(p, DOSTRUE, 0);
    }

    fn write(&mut self, p: *mut DosPacket) {
        let (buf, len) = (arg(p, 2) as usize, arg(p, 3).max(0) as usize);
        let Some(h) = self.file(arg(p, 1)).and_then(|f| f.h) else { return reply(p, -1, ERROR_OBJECT_NOT_FOUND) };
        // SAFETY: the caller's buffer of `len` bytes.
        let data = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
        let mut sent = 0;
        while sent < len {
            match op(false, SockOp::Send { h, data: data[sent..].to_vec(), to: None, result: Err(0) }, 0) {
                Some((SockOp::Send { result: Ok(n), .. }, _)) if n > 0 => sent += n,
                _ => break,
            }
        }
        if sent == len || sent > 0 { reply(p, sent as i32, 0) } else { reply(p, -1, ERROR_OBJECT_NOT_FOUND) }
    }

    /// Answer what can be answered of file `k`'s waiting reads.
    fn serve(&mut self, k: usize, readable: bool, now: u64) {
        let f = &mut self.files[k];
        while let Some(&(p, deadline)) = f.reads.front() {
            let is_wait = deadline.is_some();
            if !f.pushback.is_empty() {
                f.reads.pop_front();
                if is_wait {
                    reply(p, DOSTRUE, 0);
                } else {
                    let n = (arg(p, 3).max(0) as usize).min(f.pushback.len());
                    // SAFETY: the caller's buffer.
                    unsafe { core::ptr::copy_nonoverlapping(f.pushback.as_ptr(), arg(p, 2) as usize as *mut u8, n) };
                    f.pushback.drain(..n);
                    reply(p, n as i32, 0);
                }
                continue;
            }
            let Some(h) = f.h else {
                f.reads.pop_front();
                reply(p, if is_wait { 0 } else { 0 }, 0);
                continue;
            };
            if is_wait {
                if readable {
                    f.reads.pop_front();
                    reply(p, DOSTRUE, 0);
                    continue;
                }
                if deadline.is_some_and(|d| now >= d) {
                    f.reads.pop_front();
                    reply(p, 0, 0);
                    continue;
                }
                break;
            }
            if !readable {
                break;
            }
            let max = arg(p, 3).max(0) as usize;
            match op(true, SockOp::Recv { h, max, peek: false, result: Err(0) }, 0) {
                Some((SockOp::Recv { result: Ok((d, _)), .. }, _)) => {
                    f.reads.pop_front();
                    // SAFETY: the caller's buffer of `max` >= d.len() bytes.
                    unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), arg(p, 2) as usize as *mut u8, d.len()) };
                    reply(p, d.len() as i32, 0);
                    // One read per readiness: the next waits for the next.
                    break;
                }
                Some((SockOp::Recv { result: Err(e), .. }, _)) if e == errno::EWOULDBLOCK => break,
                _ => {
                    f.reads.pop_front();
                    reply(p, -1, ERROR_OBJECT_NOT_FOUND);
                }
            }
        }
    }

    fn packet(&mut self, p: *mut DosPacket, detached: bool) {
        // SAFETY: a packet DOS sent us: dp_Type at 8.
        let action = unsafe { core::ptr::read_unaligned((p as *const u8).add(8) as *const i32) };
        match action {
            ACTION_FINDINPUT | ACTION_FINDOUTPUT | ACTION_FINDUPDATE if !detached => self.find(p),
            ACTION_FINDINPUT | ACTION_FINDOUTPUT | ACTION_FINDUPDATE => reply(p, 0, ERROR_OBJECT_NOT_FOUND),
            ACTION_END => self.end(p),
            ACTION_READ => match self.files.iter().position(|f| f.id == arg(p, 1) as u32) {
                Some(k) => self.files[k].reads.push_back((p, None)),
                None => reply(p, -1, ERROR_OBJECT_NOT_FOUND),
            },
            ACTION_WRITE if !detached => self.write(p),
            ACTION_WRITE => reply(p, -1, ERROR_OBJECT_NOT_FOUND),
            ACTION_WAIT_CHAR => {
                // dp_Arg1 the timeout in microseconds; the file is the one
                // named by dp_Arg2 if it is ours, else the only one.
                let timeout = arg(p, 1).max(0) as u64;
                let k = self.files.iter().position(|f| f.id == arg(p, 2) as u32).or((self.files.len() == 1).then_some(0));
                match k {
                    Some(k) => {
                        let until = amigaos4::timer::get_up_time().as_micros() + timeout;
                        self.files[k].reads.push_back((p, Some(until)));
                    }
                    None => reply(p, 0, 0),
                }
            }
            ACTION_STACK => match self.file(arg(p, 1)) {
                Some(f) => {
                    let n = arg(p, 3).max(0) as usize;
                    // SAFETY: the caller's characters, pushed back in front.
                    let s = unsafe { core::slice::from_raw_parts(arg(p, 2) as usize as *const u8, n) };
                    let mut v = s.to_vec();
                    v.extend_from_slice(&f.pushback);
                    f.pushback = v;
                    reply(p, n as i32, 0);
                }
                None => reply(p, -1, ERROR_OBJECT_NOT_FOUND),
            },
            ACTION_IS_FILESYSTEM => reply(p, 0, 0),
            _ => reply(p, 0, ERROR_ACTION_NOT_KNOWN),
        }
    }

    /// Let go of the stack: sockets closed, waiting opens refused, reads
    /// answered with the end of the stream.
    fn detach(&mut self) {
        for f in self.files.iter_mut() {
            if let Some(p) = f.find.take() {
                reply(p, 0, ERROR_OBJECT_NOT_FOUND);
            }
            if let State::Accepting(l) = f.state {
                release(l);
            }
            f.state = State::Open;
            if let Some(h) = f.h.take() {
                release(h);
            }
        }
        self.files.retain(|f| f.find.is_none());
        // Answer reads queued so far (end of stream).
        for k in 0..self.files.len() {
            self.serve(k, false, u64::MAX);
        }
    }
}

/// The device: added unless something named TCP exists. The entry, or
/// null.
fn add_device(port: *mut sys::MsgPort) -> *mut sys::DosList {
    // SAFETY: DOS list calls: looked up under a read lock, added with the
    // list unlocked (AddDosEntry locks it itself).
    unsafe {
        let dl = sys::dos_lock_dos_list(LDF_ALL | LDF_READ);
        let there = !sys::dos_find_dos_entry(dl, b"TCP\0".as_ptr(), LDF_ALL).is_null();
        sys::dos_un_lock_dos_list(LDF_ALL | LDF_READ);
        if there {
            amigaos4::serial_println!("rustsocket.library: TCP: is already there; not added");
            return core::ptr::null_mut();
        }
        let e = sys::dos_make_dos_entry(b"TCP\0".as_ptr(), DLT_DEVICE);
        if e.is_null() {
            return e;
        }
        core::ptr::write_unaligned((e as *mut u8).add(8) as *mut u32, port as u32);
        if sys::dos_add_dos_entry(e) == 0 {
            sys::dos_free_dos_entry(e);
            return core::ptr::null_mut();
        }
        e
    }
}

fn remove_device(e: *mut sys::DosList) {
    if e.is_null() {
        return;
    }
    // SAFETY: our entry, removed under the write lock, then freed.
    unsafe {
        sys::dos_lock_dos_list(LDF_DEVICES | LDF_WRITE);
        sys::dos_rem_dos_entry(e);
        sys::dos_un_lock_dos_list(LDF_DEVICES | LDF_WRITE);
        sys::dos_free_dos_entry(e);
    }
}

fn run() {
    let me = amigaos4::signal::current_task() as u32;
    let Ok(port) = amigaos4::port::AmigaMsgPort::new() else { return };
    let dev = add_device(port.as_ptr());
    // No device of ours (something called TCP was there first, such as
    // Roadshow's handler): nothing can reach this process, so it ends now
    // and the last Close need not wait for it (testprogs/rstcp/c/lastclose.c).
    if dev.is_null() {
        return;
    }
    CURRENT.store(me, Ordering::Release);
    let pmask = port.signal_mask();
    let mut h = Handler { files: Vec::new(), next_id: 1 };
    let mut detached = false;
    let mut dev = dev;
    loop {
        // Packets first.
        while let Some(m) = port.get_raw() {
            // SAFETY: a DOS packet's message: ln_Name (offset 10) is the
            // packet.
            let p = unsafe { core::ptr::read_unaligned((m as *const u8).add(10) as *const usize) } as *mut DosPacket;
            let _: *mut Message = m;
            h.packet(p, detached);
        }
        if !detached && amigaos4::signal::take(CTRL_C) != 0 {
            remove_device(dev);
            dev = core::ptr::null_mut();
            h.detach();
            detached = true;
            DETACHED.store(1, Ordering::Release);
        }
        if detached {
            for k in 0..h.files.len() {
                h.serve(k, false, u64::MAX);
            }
            if h.files.is_empty() {
                break;
            }
            amigaos4::signal::wait(pmask);
            continue;
        }
        let now = amigaos4::timer::get_up_time().as_micros();
        // Pushback or due WAIT_CHARs first.
        for k in 0..h.files.len() {
            h.serve(k, false, now);
        }
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        let mut until = now + 1_000_000;
        for f in &h.files {
            match f.state {
                State::Accepting(l) => reads.push(l),
                State::Connecting => writes.extend(f.h),
                State::Open => {
                    if !f.reads.is_empty() {
                        reads.extend(f.h);
                    }
                    for &(_, d) in &f.reads {
                        if let Some(d) = d {
                            until = until.min(d);
                        }
                    }
                }
            }
        }
        let (r, w) = if reads.is_empty() && writes.is_empty() {
            let got = amigaos4::signal::wait(pmask | CTRL_C);
            if got & CTRL_C != 0 {
                // Wait took it: set it again for the check above (else
                // the last Close's stop never sees the handler let go).
                // SAFETY: the signal came to us.
                unsafe { sys::exec_set_signal(CTRL_C, CTRL_C) };
            }
            continue;
        } else {
            match op(false, SockOp::Select { reads, writes, until_us: Some(until), result: Err(0) }, pmask | CTRL_C) {
                Some((SockOp::Select { result: Ok(rw), .. }, _)) => rw,
                Some((_, hit)) => {
                    if hit & CTRL_C != 0 {
                        // SAFETY: the signal came to us: set it again for the
                        // check at the top.
                        unsafe { sys::exec_set_signal(CTRL_C, CTRL_C) };
                    }
                    (Vec::new(), Vec::new())
                }
                None => (Vec::new(), Vec::new()),
            }
        };
        let now = amigaos4::timer::get_up_time().as_micros();
        for k in 0..h.files.len() {
            let f = &mut h.files[k];
            match f.state {
                State::Accepting(l) if r.contains(&l) => {
                    if let Some((SockOp::Accept { result: Ok((c, _)), .. }, _)) = op(true, SockOp::Accept { h: l, result: Err(0) }, 0) {
                        shared::add_ref(c);
                        release(l);
                        f.h = Some(c);
                        f.state = State::Open;
                        if let Some(p) = f.find.take() {
                            reply(p, DOSTRUE, 0);
                        }
                    }
                }
                State::Connecting if f.h.is_some_and(|x| w.contains(&x)) => {
                    let hh = f.h.unwrap();
                    let err = match op(true, SockOp::Info { h: hh, take_error: true, result: Err(0) }, 0) {
                        Some((SockOp::Info { result: Ok(i), .. }, _)) => i.error,
                        _ => errno::ECONNREFUSED,
                    };
                    let p = f.find.take();
                    if err == 0 {
                        f.state = State::Open;
                        if let Some(p) = p {
                            reply(p, DOSTRUE, 0);
                        }
                    } else {
                        f.h = None;
                        release(hh);
                        if let Some(p) = p {
                            reply(p, 0, ERROR_OBJECT_NOT_FOUND);
                        }
                        // The file never opened: no END will come.
                        f.state = State::Open;
                        f.id = 0;
                    }
                }
                _ => {}
            }
            let readable = h.files[k].h.is_some_and(|x| r.contains(&x));
            h.serve(k, readable, now);
        }
        h.files.retain(|f| f.id != 0);
    }
    drop(port);
    CURRENT.store(0, Ordering::Release);
}
