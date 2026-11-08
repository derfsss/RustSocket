//! The Internet superserver (DEVS:Internet/servers) and the server API
//! (ProcessIsServer, ObtainServerSocket).
//!
//! As Roadshow: a process of the library's own (not an opener, so it does
//! not keep the stack alive) reads DEVS:Internet/servers and takes up a
//! change to it at once (Roadshow answers on a service enabled after boot
//! without a restart; here the file's date and size are looked at every
//! second). Each active line listens on its service's port (netdb's
//! services file): STREAM over TCP, any other type over UDP.
//!
//! - `internal`: echo, discard, chargen, daytime and time, answered in the
//!   superserver itself, in Roadshow's formats (as measured on Roadshow):
//!   chargen's ring starts at the space, 72 characters
//!   and CR LF a line, one line per datagram; daytime is ctime's
//!   "Sat Nov 07 04:46:10 2026" plus CR LF; time is the Amiga clock as is.
//! - a program: each connection (STREAM) or the socket itself (other types,
//!   until the program closes it: WAIT) goes to a new CLI process, found in
//!   C: and the PATH directories, whose ObtainServerSocket claims it. The
//!   process is made one priority below the superserver, recorded, and only
//!   then given its own (PRI), so it cannot ask before it is known (a new
//!   process may otherwise run before CreateNewProc has returned).
//! - MAXHITS: at most that many programs started a minute, 1500 by
//!   default (roadshow.doc 7.1.2.8); more connections are closed.
//! - DOS: the program's Input() and Output() are the connection, two
//!   "TCP:OBTAIN=" files on it (tcpdev.rs); Output() is interactive, as
//!   Roadshow's is. ProcessIsServer is TRUE for it, ObtainServerSocket -1.
//! - INACTIVE switches a line off; PATH (a directive line, or a keyword in
//!   a line) adds drawers to look for the program in.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use amigaos4::sys::{self, TagItem, TAG_DONE, TAG_USER};
use rsnet_core::sock::{errno, SockKind, SockOp};

use super::{shared, Fd};

const NAME: &str = "rustsocket superserver";
const SERVERS: &str = "DEVS:Internet/servers";
const CTRL_C: u32 = sys::SIGBREAKF_CTRL_C;
/// How many started programs ProcessIsServer remembers.
const KEEP: usize = 64;

const NP_SEGLIST: u32 = TAG_USER + 1001;
const NP_FREESEGLIST: u32 = TAG_USER + 1002;
const NP_CLI: u32 = TAG_USER + 1018;
const NP_COMMANDNAME: u32 = TAG_USER + 1020;
const NP_ARGUMENTS: u32 = TAG_USER + 1021;
const NT_PROCESS: u8 = 13;

#[derive(Clone, PartialEq)]
enum Prog {
    Internal,
    Command(String),
}

#[derive(Clone, PartialEq)]
struct Entry {
    name: String,
    port: u16,
    stream: bool,
    wait: bool,
    dos: bool,
    pri: i8,
    stack: u32,
    maxhits: u32,
    paths: Vec<String>,
    prog: Prog,
}

/// The servers file: its entries and PATH directories.
fn parse(text: &str) -> (Vec<Entry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut paths = Vec::new();
    for line in text.lines() {
        let w: Vec<&str> = line.split('#').next().unwrap_or("").split_whitespace().collect();
        let Some(&name) = w.first() else { continue };
        if name.eq_ignore_ascii_case("path") {
            paths.extend(w[1..].iter().map(|s| String::from(*s)));
            continue;
        }
        let mut e = Entry { name: String::from(name), port: 0, stream: true, wait: false, dos: false, pri: 0, stack: 0, maxhits: 1500, paths: Vec::new(), prog: Prog::Internal };
        let mut inactive = false;
        let mut k = 1;
        // A keyword's value: KEY=n or KEY n.
        let value = |k: &mut usize, tok: &str| -> Option<i64> {
            if let Some((_, v)) = tok.split_once('=') {
                return v.parse().ok();
            }
            *k += 1;
            w.get(*k)?.parse().ok()
        };
        while k < w.len() {
            let tok = w[k];
            let key = tok.split('=').next().unwrap_or("").to_ascii_uppercase();
            match key.as_str() {
                "STREAM" => e.stream = true,
                "DGRAM" | "DATAGRAM" | "SEQPACKET" | "SEQUENCEDPACKET" | "RAW" => e.stream = false,
                "WAIT" => e.wait = true,
                "INACTIVE" => inactive = true,
                "PATH" => {
                    // Drawers (they name a volume or a path) up to the next
                    // keyword or the program.
                    while let Some(t) = w.get(k + 1) {
                        if !(t.contains(':') || t.contains('/')) || t.contains('=') {
                            break;
                        }
                        e.paths.push(String::from(*t));
                        k += 1;
                    }
                }
                "DOS" => e.dos = true,
                "PRI" | "PRIORITY" => e.pri = value(&mut k, tok).unwrap_or(0).clamp(-128, 127) as i8,
                "MAXHITS" => e.maxhits = value(&mut k, tok).unwrap_or(0).max(0) as u32,
                "STACK" | "STACKSIZE" => e.stack = value(&mut k, tok).unwrap_or(0).max(0) as u32,
                _ => {
                    let rest = w[k..].join(" ");
                    if !rest.eq_ignore_ascii_case("internal") {
                        e.prog = Prog::Command(rest);
                    }
                    break;
                }
            }
            k += 1;
        }
        if inactive {
            continue;
        }
        match super::netdb::service_port(&e.name, if e.stream { "tcp" } else { "udp" }) {
            Some(p) => {
                e.port = p;
                entries.push(e);
            }
            None => amigaos4::serial_println!("rustsocket superserver: {}: no such service", e.name),
        }
    }
    (entries, paths)
}

// ---------------------------------------------------------------------------
// Start and stop (the library's first Open and last Close)
// ---------------------------------------------------------------------------

/// Start the superserver (the stack is running).
pub fn start() {
    let b = match amigaos4::dos::process::ProcessBuilder::new(NAME) {
        Ok(b) => b.priority(0).stack(32768),
        Err(_) => return,
    };
    if let Err(e) = b.spawn_detached(run) {
        amigaos4::serial_println!("rustsocket.library: the superserver did not start: {}", e);
    }
}

/// Stop it and wait until it has gone (before the stack stops).
pub fn stop() {
    let name = alloc::format!("{}\0", NAME);
    let Ok(mut timer) = amigaos4::timer::AmigaTimer::open(amigaos4::timer::TimerUnit::MicroHz) else { return };
    for _ in 0..500 {
        // SAFETY: FindTask by a NUL-terminated name; Signal to the task it
        // found, which is ours and leaves only after its loop has ended.
        let t = unsafe { sys::exec_find_task(name.as_ptr()) };
        if t.is_null() {
            return;
        }
        // SAFETY: as above.
        unsafe { sys::exec_signal(t, CTRL_C) };
        let _ = timer.delay(amigaos4::timer::TimerVal::from_millis(10));
    }
    amigaos4::serial_println!("rustsocket.library: the superserver did not stop");
}

/// Whether the superserver process is still there.
pub fn busy() -> bool {
    let name = alloc::format!("{}\0", NAME);
    // SAFETY: FindTask with a NUL-terminated name.
    !unsafe { sys::exec_find_task(name.as_ptr()) }.is_null()
}

// ---------------------------------------------------------------------------
// The server API
// ---------------------------------------------------------------------------

/// `p`'s process ID, or the caller's (p NULL); None for a plain Task.
fn pid_of(p: *mut sys::Process) -> Option<u32> {
    // SAFETY: FindTask(NULL) is the caller; a Task's Node type is the byte
    // at 8 (exec's packed layout); GetPID on a Process.
    unsafe {
        let p = if p.is_null() { sys::exec_find_task(core::ptr::null()) as *mut sys::Process } else { p };
        if *(p as *const u8).add(8) != NT_PROCESS {
            return None;
        }
        Some(sys::dos_get_pid(p, sys::GPID_PROCESS))
    }
}

/// ProcessIsServer(process): whether the superserver started it.
#[no_mangle]
pub extern "C" fn rs_ProcessIsServer(_i: *mut sys::Interface, p: *mut sys::Process) -> i32 {
    let Some(pid) = pid_of(p) else { return 0 };
    shared::lock().is_some_and(|sh| sh.servers.iter().any(|&(n, _)| n == pid)) as i32
}

/// ObtainServerSocket(): the socket the superserver gave this process, once;
/// -1 when there is none or it was claimed.
#[no_mangle]
pub extern "C" fn rs_ObtainServerSocket(i: *mut sys::Interface) -> i32 {
    let Some(pid) = pid_of(core::ptr::null_mut()) else { return -1 };
    let id = {
        let Some(mut sh) = shared::lock() else { return -1 };
        let Some(e) = sh.servers.iter_mut().find(|e| e.0 == pid && e.1.is_some()) else { return -1 };
        e.1.take()
    };
    match id {
        Some(id) => super::rs_ObtainSocket(i, id, 2, 0, 0),
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// The superserver process
// ---------------------------------------------------------------------------

static TOKEN: AtomicU32 = AtomicU32::new(0x4000_0000);

/// Run `op` in the stack; CTRL-C ends a wait. None when the stack is gone.
fn op(nonblock: bool, op: SockOp) -> Option<(SockOp, u32)> {
    super::stack()?.sock_with(TOKEN.fetch_add(1, Ordering::Relaxed), nonblock, None, op, CTRL_C)
}

fn close(h: u32) {
    let _ = op(false, SockOp::Close { h, result: Ok(()) });
}

/// A listening socket for `e` (TCP: listening; UDP: bound).
fn listen(e: &Entry) -> Option<u32> {
    let kind = if e.stream { SockKind::Tcp } else { SockKind::Udp };
    let Some((SockOp::Open { result: Ok(h), .. }, _)) = op(false, SockOp::Open { kind, result: Err(0) }) else { return None };
    let ok = matches!(op(false, SockOp::Bind { h, addr: [0; 4], port: e.port, result: Err(0) }), Some((SockOp::Bind { result: Ok(()), .. }, _)))
        && (!e.stream || matches!(op(false, SockOp::Listen { h, backlog: 5, result: Err(0) }), Some((SockOp::Listen { result: Ok(()), .. }, _))));
    if ok {
        Some(h)
    } else {
        amigaos4::serial_println!("rustsocket superserver: {} (port {}): cannot listen", e.name, e.port);
        close(h);
        None
    }
}

struct Service {
    e: Entry,
    /// Our socket; None while a WAIT program has it (`given`).
    h: Option<u32>,
    given: Option<u32>,
    /// Programs started in the current minute: (minute start, count).
    hits: (u64, u32),
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Echo,
    Discard,
    Chargen,
}

struct Conn {
    h: u32,
    kind: Kind,
    /// chargen: the stream's byte position.
    pos: u64,
}

fn internal(name: &str) -> Option<&'static str> {
    ["echo", "discard", "chargen", "daytime", "time"].into_iter().find(|n| n.eq_ignore_ascii_case(name))
}

/// The file's date and size, to see a change.
fn stamp() -> Option<(i32, i32, i32, u64)> {
    let m = amigaos4::dos::fs::metadata(SERVERS).ok()?;
    Some((m.date.ds_Days, m.date.ds_Minute, m.date.ds_Tick, m.size.unwrap_or(0)))
}

fn run() {
    let mut services: Vec<Service> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut conns: Vec<Conn> = Vec::new();
    let mut seen: Option<Option<(i32, i32, i32, u64)>> = None;
    // name_resolution as read when the stack started (dns.rs).
    let mut resolv_seen = super::dns::name_resolution_stamp();
    loop {
        // DEVS:Internet/name_resolution changed: read it again.
        let resolv_now = super::dns::name_resolution_stamp();
        if resolv_now != resolv_seen {
            resolv_seen = resolv_now;
            super::dns::read_name_resolution();
        }
        // The file changed (or first pass): listen anew.
        let now_stamp = stamp();
        if seen != Some(now_stamp) {
            seen = Some(now_stamp);
            let (entries, p) = match now_stamp {
                Some(_) => amigaos4::dos::fs::File::read_to_vec(SERVERS).map(|d| parse(&String::from_utf8_lossy(&d))).unwrap_or_default(),
                None => (Vec::new(), Vec::new()),
            };
            paths = p;
            // Keep the services whose line stayed the same.
            let mut keep = Vec::new();
            for s in services.drain(..) {
                if entries.contains(&s.e) {
                    keep.push(s);
                } else if let Some(h) = s.h {
                    close(h);
                }
            }
            for e in entries {
                if keep.iter().any(|s| s.e == e) {
                    continue;
                }
                if matches!(e.prog, Prog::Internal) && internal(&e.name).is_none() {
                    amigaos4::serial_println!("rustsocket superserver: {}: no such internal service", e.name);
                    continue;
                }
                let h = listen(&e);
                amigaos4::serial_println!("rustsocket superserver: {} {} port {}{}", e.name, if e.stream { "stream" } else { "dgram" }, e.port, if h.is_some() { "" } else { " (failed)" });
                keep.push(Service { e, h, given: None, hits: (0, 0) });
            }
            services = keep;
        }
        // A WAIT program's socket came back closed: listen again.
        for s in services.iter_mut() {
            if let Some(g) = s.given {
                if !matches!(op(true, SockOp::Info { h: g, take_error: false, result: Err(0) }), Some((SockOp::Info { result: Ok(_), .. }, _))) {
                    s.given = None;
                    s.h = listen(&s.e);
                }
            }
        }
        let mut reads: Vec<u32> = services.iter().filter_map(|s| s.h).collect();
        reads.extend(conns.iter().map(|c| c.h));
        let writes: Vec<u32> = conns.iter().filter(|c| c.kind == Kind::Chargen).map(|c| c.h).collect();
        let until = amigaos4::timer::get_up_time().as_micros() + 1_000_000;
        let (r, w) = match op(false, SockOp::Select { reads, writes, until_us: Some(until), result: Err(0) }) {
            None => break,
            Some((_, hit)) if hit & CTRL_C != 0 => break,
            Some((SockOp::Select { result: Ok(rw), .. }, _)) => rw,
            Some(_) => {
                // A socket went away under us (NetShutdown): start over.
                for c in conns.drain(..) {
                    close(c.h);
                }
                for s in services.drain(..) {
                    if let Some(h) = s.h {
                        close(h);
                    }
                }
                seen = None;
                continue;
            }
        };
        for s in services.iter_mut() {
            let Some(h) = s.h else { continue };
            if r.contains(&h) {
                ready(s, h, &paths, &mut conns);
            }
        }
        conns.retain_mut(|c| serve(c, r.contains(&c.h), w.contains(&c.h)));
    }
    for c in conns {
        close(c.h);
    }
    for s in services {
        if let Some(h) = s.h {
            close(h);
        }
    }
}

/// A listening socket has something: a connection or a datagram.
fn ready(s: &mut Service, h: u32, paths: &[String], conns: &mut Vec<Conn>) {
    if let Prog::Command(cmd) = &s.e.prog {
        let cmd = cmd.clone();
        // The socket for the program: the connection, or (datagrams) the
        // service's own socket until the program closes it.
        let ch = if s.e.stream {
            match op(true, SockOp::Accept { h, result: Err(0) }) {
                Some((SockOp::Accept { result: Ok((ch, _)), .. }, _)) => ch,
                _ => return,
            }
        } else {
            h
        };
        let now = amigaos4::timer::get_up_time().as_micros();
        if now - s.hits.0 >= 60_000_000 {
            s.hits = (now, 0);
        }
        if s.e.maxhits != 0 && s.hits.1 >= s.e.maxhits {
            amigaos4::serial_println!("rustsocket superserver: {}: MAXHITS {} reached this minute", s.e.name, s.e.maxhits);
        } else if if s.e.dos { dos_hand_over(ch, &cmd, paths, &s.e) } else { hand_over(ch, &cmd, paths, &s.e) } {
            s.hits.1 += 1;
            if !s.e.stream {
                s.h = None;
                s.given = Some(h);
            }
            return;
        }
        if s.e.stream {
            close(ch);
        } else {
            // Take the datagram that is waiting, so it does not come back.
            let _ = op(true, SockOp::Recv { h, max: 0, peek: false, result: Err(0) });
        }
        return;
    }
    let name = internal(&s.e.name).unwrap_or("");
    if s.e.stream {
        let Some((SockOp::Accept { result: Ok((ch, _)), .. }, _)) = op(true, SockOp::Accept { h, result: Err(0) }) else { return };
        match name {
            "daytime" | "time" => {
                let _ = op(true, SockOp::Send { h: ch, data: answer(name), to: None, result: Err(0) });
                close(ch);
            }
            _ => conns.push(Conn { h: ch, kind: if name == "echo" { Kind::Echo } else if name == "chargen" { Kind::Chargen } else { Kind::Discard }, pos: 0 }),
        }
        return;
    }
    let Some((SockOp::Recv { result: Ok((data, Some(from))), .. }, _)) = op(true, SockOp::Recv { h, max: 2048, peek: false, result: Err(0) }) else { return };
    let reply = match name {
        "echo" => data,
        "discard" => return,
        "chargen" => chargen(0, 74),
        _ => answer(name),
    };
    let _ = op(true, SockOp::Send { h, data: reply, to: Some(from), result: Err(0) });
}

/// One internal connection's turn: false when it is done (closed).
fn serve(c: &mut Conn, readable: bool, writable: bool) -> bool {
    if readable {
        match op(true, SockOp::Recv { h: c.h, max: 4096, peek: false, result: Err(0) }) {
            Some((SockOp::Recv { result: Ok((data, _)), .. }, _)) if data.is_empty() => {
                close(c.h);
                return false;
            }
            Some((SockOp::Recv { result: Ok((data, _)), .. }, _)) => {
                if c.kind == Kind::Echo {
                    let _ = op(true, SockOp::Send { h: c.h, data, to: None, result: Err(0) });
                }
            }
            Some((SockOp::Recv { result: Err(e), .. }, _)) if e == errno::EWOULDBLOCK => {}
            _ => {
                close(c.h);
                return false;
            }
        }
    }
    if writable && c.kind == Kind::Chargen {
        match op(true, SockOp::Send { h: c.h, data: chargen(c.pos, 74 * 14), to: None, result: Err(0) }) {
            Some((SockOp::Send { result: Ok(n), .. }, _)) => c.pos += n as u64,
            Some((SockOp::Send { result: Err(e), .. }, _)) if e == errno::EWOULDBLOCK => {}
            _ => {
                close(c.h);
                return false;
            }
        }
    }
    true
}

/// `len` bytes of the chargen stream from byte `pos`: line L is the 95
/// printable characters from the space, rotated by L, cut to 72, and CR LF.
fn chargen(pos: u64, len: usize) -> Vec<u8> {
    (pos..pos + len as u64)
        .map(|b| {
            let (line, col) = (b / 74, b % 74);
            match col {
                72 => b'\r',
                73 => b'\n',
                _ => b' ' + ((line + col) % 95) as u8,
            }
        })
        .collect()
}

/// daytime's and time's answers from the Amiga clock.
fn answer(name: &str) -> Vec<u8> {
    let mut ds = sys::DateStamp { ds_Days: 0, ds_Minute: 0, ds_Tick: 0 };
    // SAFETY: DateStamp fills the struct given.
    unsafe { sys::dos_date_stamp(&mut ds) };
    let secs = ds.ds_Minute as u64 * 60 + ds.ds_Tick as u64 / 50;
    let unix_days = ds.ds_Days as i64 + 2922;
    if name == "time" {
        // RFC 868: seconds since 1900.
        let t = (unix_days as u64 * 86400 + secs + 2_208_988_800) as u32;
        return t.to_be_bytes().to_vec();
    }
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let z = unix_days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    // 1970-01-01 was a Thursday.
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    alloc::format!("{} {} {:02} {:02}:{:02}:{:02} {}\r\n", DAYS[unix_days.rem_euclid(7) as usize], MONTHS[(m - 1) as usize], d, secs / 3600, secs / 60 % 60, secs % 60, y).into_bytes()
}

/// Give socket `h` to a new process running `cmd`: true when it started.
fn hand_over(h: u32, cmd: &str, paths: &[String], e: &Entry) -> bool {
    shared::add_ref(h);
    let Ok(id) = super::keep_released(Fd { h, ..Fd::default() }, super::UNIQUE_ID) else {
        shared::drop_ref(h);
        return false;
    };
    match launch(cmd, paths, e, Some(id), None) {
        Some(pid) => {
            amigaos4::serial_println!("rustsocket superserver: {}: started \"{}\" (process {})", e.name, cmd, pid);
            true
        }
        None => {
            amigaos4::serial_println!("rustsocket superserver: {}: cannot start \"{}\"", e.name, cmd);
            if let Some(mut sh) = shared::lock() {
                sh.released.retain(|(n, _)| *n != id);
            }
            shared::drop_ref(h);
            false
        }
    }
}

/// Give connection `h` to a new process running `cmd` as its Input() and
/// Output(): two TCP:OBTAIN= files on it.
fn dos_hand_over(h: u32, cmd: &str, paths: &[String], e: &Entry) -> bool {
    let mut ids = [0i32; 2];
    for id in ids.iter_mut() {
        shared::add_ref(h);
        match super::keep_released(Fd { h, ..Fd::default() }, super::UNIQUE_ID) {
            Ok(n) => *id = n,
            Err(_) => {
                shared::drop_ref(h);
                return false;
            }
        }
    }
    let open = |id: i32, mode: i32| {
        let name = alloc::format!("TCP:OBTAIN={}\0", id);
        // SAFETY: Open with a NUL-terminated name.
        unsafe { sys::dos_open(name.as_ptr(), mode) }
    };
    let input = open(ids[0], sys::MODE_OLDFILE);
    let output = open(ids[1], sys::MODE_NEWFILE);
    if input != 0 && output != 0 {
        // SAFETY: the FileHandle Open made: fh_Interactive (Roadshow's DOS
        // servers see an interactive Output()).
        unsafe { core::ptr::write_unaligned(((output << 2) + 4) as *mut i32, -1) };
        if let Some(pid) = launch(cmd, paths, e, None, Some((input, output))) {
            amigaos4::serial_println!("rustsocket superserver: {}: started DOS server \"{}\" (process {})", e.name, cmd, pid);
            return true;
        }
    }
    amigaos4::serial_println!("rustsocket superserver: {}: cannot start DOS server \"{}\"", e.name, cmd);
    // SAFETY: the files Open made (closing one drops its reference).
    unsafe {
        if input != 0 {
            sys::dos_close(input);
        }
        if output != 0 {
            sys::dos_close(output);
        }
    }
    // Ids nobody obtained go, with their references.
    if let Some(mut sh) = shared::lock() {
        for id in ids {
            if let Some(k) = sh.released.iter().position(|(n, _)| *n == id) {
                sh.released.swap_remove(k);
                drop(sh);
                shared::drop_ref(h);
                sh = match shared::lock() {
                    Some(g) => g,
                    None => return false,
                };
            }
        }
    }
    false
}

/// Load the command (C:, the line's PATH, the PATH directives, then as
/// named) and start it as a CLI process; it is recorded (with socket id
/// `id` for ObtainServerSocket) before it runs. `io`: its Input() and
/// Output() (closed by DOS when it ends).
fn launch(cmd: &str, paths: &[String], e: &Entry, id: Option<i32>, io: Option<(u32, u32)>) -> Option<u32> {
    let (prog, args) = match cmd.split_once(char::is_whitespace) {
        Some((p, a)) => (p, a.trim_start()),
        None => (cmd, ""),
    };
    let mut tries: Vec<String> = Vec::new();
    if !prog.contains(':') {
        tries.push(alloc::format!("C:{}", prog));
        for p in e.paths.iter().chain(paths) {
            let sep = if p.ends_with(':') || p.ends_with('/') { "" } else { "/" };
            tries.push(alloc::format!("{}{}{}", p, sep, prog));
        }
    }
    tries.push(String::from(prog));
    let seg = tries.iter().find_map(|t| {
        let c = alloc::format!("{}\0", t);
        // SAFETY: LoadSeg with a NUL-terminated name.
        let s = unsafe { sys::dos_load_seg(c.as_ptr()) };
        (s != 0).then_some(s)
    })?;
    let base = prog.rsplit([':', '/']).next().unwrap_or(prog);
    let name = alloc::format!("{}\0", base);
    let argv = alloc::format!("{}\n\0", args);
    // SAFETY: FindTask(NULL) is this process.
    let me = unsafe { sys::exec_find_task(core::ptr::null()) };
    // SAFETY: the running task's priority is the byte at 9.
    let my_pri = unsafe { *(me as *const i8).add(9) };
    let mut tags = alloc::vec![
        TagItem { ti_Tag: NP_SEGLIST, ti_Data: seg },
        TagItem { ti_Tag: NP_FREESEGLIST, ti_Data: 1 },
        TagItem { ti_Tag: sys::NP_NAME, ti_Data: name.as_ptr() as u32 },
        TagItem { ti_Tag: NP_COMMANDNAME, ti_Data: name.as_ptr() as u32 },
        TagItem { ti_Tag: NP_ARGUMENTS, ti_Data: argv.as_ptr() as u32 },
        TagItem { ti_Tag: NP_CLI, ti_Data: 1 },
        TagItem { ti_Tag: sys::NP_STACK_SIZE, ti_Data: if e.stack >= 4096 { e.stack } else { 65536 } },
        TagItem { ti_Tag: sys::NP_PRIORITY, ti_Data: (my_pri as i32 - 1) as u32 },
    ];
    // A DOS server's streams (else DOS's defaults, NIL:).
    if let Some((input, output)) = io {
        tags.push(TagItem { ti_Tag: sys::NP_INPUT, ti_Data: input });
        tags.push(TagItem { ti_Tag: sys::NP_OUTPUT, ti_Data: output });
    }
    tags.push(TagItem { ti_Tag: TAG_DONE, ti_Data: 0 });
    // SAFETY: a TAG_DONE-ended list; DOS copies the name, command name
    // and arguments (dostags.h), and frees the seglist at the end.
    let proc = unsafe { sys::dos_create_new_proc(tags.as_ptr()) };
    if proc.is_null() {
        // SAFETY: the seglist LoadSeg gave, not handed on.
        unsafe { ((*sys::IDOS).UnLoadSeg)(sys::IDOS, seg) };
        return None;
    }
    // SAFETY: the process just made, which has not run yet (it is below
    // us): recorded, then given its own priority.
    let pid = unsafe { sys::dos_get_pid(proc, sys::GPID_PROCESS) };
    if let Some(mut sh) = shared::lock() {
        if sh.servers.len() >= KEEP {
            let k = sh.servers.iter().position(|e| e.1.is_none()).unwrap_or(0);
            sh.servers.remove(k);
        }
        sh.servers.push((pid, id));
    }
    // SAFETY: as above.
    unsafe { sys::exec_set_task_pri(proc as *mut sys::Task, e.pri) };
    Some(pid)
}
