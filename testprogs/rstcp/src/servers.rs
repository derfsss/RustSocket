//! The Internet superserver (DEVS:Internet/servers) and the server API.
//!
//! `rstcp servers [library] [host]`: a client of the built-in services on
//! `host` (127.0.0.1 by default): echo, discard, chargen, daytime and time
//! over TCP and UDP, and port 79 (service finger) whose servers line
//! starts `rstcp server`. Run it on each stack with the same servers
//! file and compare what it prints. The file needs echo, discard,
//! chargen, daytime and time as internal services (stream, and dgram
//! wait), `finger stream <path>rstcp server bsdsocket.library` and, for
//! c/tcpdos, `systat stream dos <path>rstcp dosserver bsdsocket.library`,
//! where <path> is where rstcp is installed.
//!
//! `rstcp server [library]`: what the superserver starts: it checks
//! ProcessIsServer and ObtainServerSocket (a second call gives -1), reads
//! a line and answers "server ok <checks>" on the socket.

use core::ffi::c_void;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use amigaos4::bsdsocket::SocketLib;
use amigaos4::sys::SocketIFace;

use super::Tally;

fn sa(a: [u8; 4], port: u16) -> [u8; 16] {
    let mut s = [0u8; 16];
    s[0] = 16;
    s[1] = 2;
    s[2..4].copy_from_slice(&port.to_be_bytes());
    s[4..8].copy_from_slice(&a);
    s
}

fn timeout(i: *mut SocketIFace, s: i32, secs: u32) {
    let tv: [u32; 2] = [secs, 0];
    // SAFETY: SO_RCVTIMEO with a timeval.
    unsafe { ((*i).setsockopt)(i, s, 0xffff, 0x1006, tv.as_ptr() as *mut c_void, 8) };
}

/// Connect to `port` over TCP, send `out`, read until the end, a timeout
/// or `max` bytes; None when the connect fails.
fn tcp(i: *mut SocketIFace, host: [u8; 4], port: u16, out: &[u8], max: usize, shut: bool) -> Option<Vec<u8>> {
    // SAFETY: plain calls with buffers of their sizes.
    unsafe {
        let s = ((*i).socket)(i, 2, 1, 0);
        timeout(i, s, 3);
        let to = sa(host, port);
        if ((*i).connect)(i, s, to.as_ptr() as *mut c_void, 16) != 0 {
            ((*i).CloseSocket)(i, s);
            return None;
        }
        if !out.is_empty() {
            ((*i).send)(i, s, out.as_ptr() as *mut c_void, out.len() as i32, 0);
        }
        if shut {
            ((*i).shutdown)(i, s, 1);
        }
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        while got.len() < max {
            let n = ((*i).recv)(i, s, buf.as_mut_ptr() as *mut c_void, buf.len().min(max - got.len()) as i32, 0);
            if n <= 0 {
                break;
            }
            got.extend_from_slice(&buf[..n as usize]);
        }
        ((*i).CloseSocket)(i, s);
        Some(got)
    }
}

/// One UDP datagram to `port` and the answer (empty: none in 2 s).
fn udp(i: *mut SocketIFace, host: [u8; 4], port: u16, out: &[u8]) -> Vec<u8> {
    // SAFETY: plain calls with buffers of their sizes.
    unsafe {
        let s = ((*i).socket)(i, 2, 2, 0);
        timeout(i, s, 2);
        let to = sa(host, port);
        ((*i).sendto)(i, s, out.as_ptr() as *mut c_void, out.len() as i32, 0, to.as_ptr() as *mut c_void, 16);
        let mut buf = [0u8; 1024];
        let n = ((*i).recv)(i, s, buf.as_mut_ptr() as *mut c_void, buf.len() as i32, 0);
        ((*i).CloseSocket)(i, s);
        buf[..n.max(0) as usize].to_vec()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace('\r', "\\r").replace('\n', "\\n")
}

/// RFC 868 time: seconds since 1900, as a date (UTC by the RFC).
fn time_text(b: &[u8]) -> String {
    if b.len() != 4 {
        return alloc::format!("{} bytes", b.len());
    }
    let t = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
    let unix = t.saturating_sub(2_208_988_800);
    let (days, secs) = (unix / 86400, unix % 86400);
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    alloc::format!("{} = {:04}-{:02}-{:02} {:02}:{:02}:{:02}", t, y, m, d, secs / 3600, secs / 60 % 60, secs % 60)
}

pub fn run(lib: &SocketLib, host: [u8; 4], t: &mut Tally) {
    let i = lib.iface();
    let echo = tcp(i, host, 7, b"hello superserver\r\n", 19, false);
    t.check(echo.as_deref() == Some(b"hello superserver\r\n"), format_args!("servers: tcp echo ({:?})", echo.as_deref().map(text)));
    let discard = tcp(i, host, 9, b"gone\r\n", 64, true);
    t.check(discard.as_deref() == Some(b""), format_args!("servers: tcp discard ({:?})", discard.as_deref().map(text)));
    let chargen = tcp(i, host, 19, b"", 148, false);
    let cg = chargen.clone().unwrap_or_default();
    t.check(cg.len() == 148 && cg.starts_with(b" !\"#$%&'()*+,-./0123456789") && cg[72..74] == *b"\r\n", format_args!("servers: tcp chargen ({:?})", text(&cg[..cg.len().min(74)])));
    let daytime = tcp(i, host, 13, b"", 128, false);
    t.check(daytime.as_ref().is_some_and(|d| d.len() > 8), format_args!("servers: tcp daytime ({:?})", daytime.as_deref().map(text)));
    let time = tcp(i, host, 37, b"", 16, false);
    t.check(time.as_ref().is_some_and(|d| d.len() == 4), format_args!("servers: tcp time ({})", time.as_deref().map(time_text).unwrap_or_default()));

    let ue = udp(i, host, 7, b"udp echo");
    t.check(ue == b"udp echo", format_args!("servers: udp echo ({:?})", text(&ue)));
    let uc = udp(i, host, 19, b"x");
    t.check(!uc.is_empty() && uc.starts_with(b" !\"#$%"), format_args!("servers: udp chargen ({} bytes: {:?})", uc.len(), text(&uc[..uc.len().min(74)])));
    let ud = udp(i, host, 13, b"x");
    t.check(ud.len() > 8, format_args!("servers: udp daytime ({:?})", text(&ud)));
    let ut = udp(i, host, 37, b"x");
    t.check(ut.len() == 4, format_args!("servers: udp time ({})", time_text(&ut)));

    // The program entry, twice (a new process each time).
    for k in 0..2 {
        let p = tcp(i, host, 79, b"ping\n", 128, false);
        t.check(p.as_deref().is_some_and(|b| b.starts_with(b"server ok 4/4")), format_args!("servers: rstcp server, connection {} ({:?})", k + 1, p.as_deref().map(text)));
    }
}

/// Started by the superserver as a DOS server: one line from Input(),
/// answered on Output() (both are the connection).
pub fn dosserver(lib: Option<&SocketLib>) -> i32 {
    let mut buf = [0u8; 128];
    let mut n = 0usize;
    // SAFETY: the process's own streams; one byte at a time up to a newline.
    unsafe {
        let input = amigaos4::sys::dos_input();
        let output = amigaos4::sys::dos_output();
        while n < buf.len() {
            if amigaos4::sys::dos_read(input, buf.as_mut_ptr().add(n) as *mut c_void, 1) != 1 {
                break;
            }
            n += 1;
            if buf[n - 1] == b'\n' {
                break;
            }
        }
        let line = String::from_utf8_lossy(&buf[..n]).trim_end().to_owned();
        let is_server = lib.map(|l| ((*l.iface()).ProcessIsServer)(l.iface(), core::ptr::null_mut()) != 0);
        let reply = alloc::format!("dos ok {} (interactive in {} out {}, ProcessIsServer {:?})\n", line, amigaos4::sys::dos_is_interactive(input), amigaos4::sys::dos_is_interactive(output), is_server);
        amigaos4::serial_println!("rstcp dosserver: {}", reply.trim_end());
        amigaos4::sys::dos_write(output, reply.as_ptr() as *const c_void, reply.len() as i32);
    }
    0
}

/// Started by the superserver: the server API's view, answered on the
/// socket (the program's own output goes to NIL:).
pub fn server(lib: &SocketLib) -> i32 {
    let i = lib.iface();
    // SAFETY: plain calls on an open interface.
    unsafe {
        let is = ((*i).ProcessIsServer)(i, core::ptr::null_mut()) != 0;
        let s = ((*i).ObtainServerSocket)(i);
        let again = ((*i).ObtainServerSocket)(i);
        let me = amigaos4::sys::exec_find_task(core::ptr::null()) as *mut amigaos4::sys::Process;
        let is_me = ((*i).ProcessIsServer)(i, me) != 0;
        let ok = [is, s >= 0, again == -1, is_me].iter().filter(|&&b| b).count();
        amigaos4::serial_println!("rstcp server: ProcessIsServer {} socket {} again {} by pointer {}", is, s, again, is_me);
        if s < 0 {
            return 20;
        }
        let mut buf = [0u8; 64];
        timeout(i, s, 3);
        let n = ((*i).recv)(i, s, buf.as_mut_ptr() as *mut c_void, 64, 0);
        let line = alloc::format!("server ok {}/4 is {} socket {} again {} by-pointer {} read {}\r\n", ok, is, s, again, is_me, n);
        ((*i).send)(i, s, line.as_ptr() as *mut c_void, line.len() as i32, 0);
        ((*i).CloseSocket)(i, s);
        if ok == 4 { 0 } else { 10 }
    }
}
