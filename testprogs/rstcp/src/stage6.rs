//! Socket API checks: socket options that take effect, descriptor sharing
//! (Dup2Socket, ReleaseCopyOfSocket), sendmsg / recvmsg, socket events,
//! the network databases and getaddrinfo / getnameinfo, and the small
//! calls. Every
//! connection is over lo0 (127.0.0.1), so nothing outside is needed but DNS
//! for one getaddrinfo.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_void, CStr};

use amigaos4::bsdsocket::{SockAddrIn, SocketLib};
use amigaos4::error::AmigaError;
use amigaos4::sys::SocketIFace;

use super::{us, Tally};

const EBADF: i32 = 9;
const EWOULDBLOCK: i32 = 35;
const SOL_SOCKET: i32 = 0xffff;
const IPPROTO_TCP: i32 = 6;

fn cstr(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: a NUL-terminated string from the library.
    String::from_utf8_lossy(unsafe { CStr::from_ptr(p as *const core::ffi::c_char) }.to_bytes()).into_owned()
}

/// A connected TCP pair over lo0: (client, server, listener).
fn pair(lib: &SocketLib) -> Option<(i32, i32, i32)> {
    let l = lib.socket(2, 1, 0).ok()?;
    lib.bind(l, &SockAddrIn::v4([127, 0, 0, 1], 0)).ok()?;
    lib.listen(l, 2).ok()?;
    let port = lib.local_addr(l).ok()?.sin_port;
    let c = lib.socket(2, 1, 0).ok()?;
    lib.connect(c, &SockAddrIn::v4([127, 0, 0, 1], port)).ok()?;
    let (s, _) = lib.accept(l).ok()?;
    Some((c, s, l))
}

fn opt8(i: *mut SocketIFace, fd: i32, level: i32, name: i32) -> (i32, u32, [u32; 2]) {
    let mut v = [0u32; 2];
    let mut len: u32 = 8;
    // SAFETY: an 8-byte buffer and its length.
    let r = unsafe { ((*i).getsockopt)(i, fd, level, name, v.as_mut_ptr() as *mut c_void, &mut len) };
    (r, len, v)
}

fn set8(i: *mut SocketIFace, fd: i32, level: i32, name: i32, a: u32, b: Option<u32>) -> i32 {
    let v = [a, b.unwrap_or(0)];
    // SAFETY: a 4- or 8-byte value.
    unsafe { ((*i).setsockopt)(i, fd, level, name, v.as_ptr() as *mut c_void, if b.is_some() { 8 } else { 4 }) }
}


/// The parts whose bits are set in `mask`: 1 options, 2 sharing, 4 msgio,
/// 8 events, 0x10 netdb, 0x20 small (`rstcp api mask=N`).
pub fn run_parts(lib: &SocketLib, lib_name: &str, t: &mut Tally, mask: u32) {
    let i = lib.iface();
    let parts: [(u32, &str, fn(&SocketLib, &str, *mut SocketIFace, &mut Tally)); 6] = [
        (1, "options", |l, _, i, t| options(l, i, t)),
        (2, "sharing", |l, n, i, t| sharing(l, n, i, t)),
        (4, "msgio", |l, _, i, t| msgio(l, i, t)),
        (8, "events", |l, _, i, t| events(l, i, t)),
        (0x10, "netdb", |l, _, i, t| netdb(l, i, t)),
        (0x20, "small", |l, _, i, t| small(l, i, t)),
    ];
    for (bit, name, f) in parts {
        if mask & bit != 0 {
            let _ = core::fmt::Write::write_fmt(&mut super::Out, format_args!("info: stage 6 {}
", name));
            f(lib, lib_name, i, t);
        }
    }
}

fn options(lib: &SocketLib, i: *mut SocketIFace, t: &mut Tally) {
    let Some((c, s, l)) = pair(lib) else {
        t.check(false, format_args!("6: options: a TCP pair over lo0"));
        return;
    };
    // SO_RCVTIMEO 300 ms: a recv with nothing coming gives EWOULDBLOCK.
    let r = set8(i, s, SOL_SOCKET, 0x1006, 0, Some(300_000));
    let back = opt8(i, s, SOL_SOCKET, 0x1006);
    let t0 = us();
    let got = lib.recv(s, &mut [0u8; 8], 0);
    let ms = (us() - t0) / 1000;
    t.check(
        r == 0 && back == (0, 8, [0, 300_000]) && matches!(got, Err(AmigaError::IoError(EWOULDBLOCK))) && (250..2000).contains(&ms),
        format_args!("6: SO_RCVTIMEO 300 ms: read back {:?}; recv gave {:?} after {} ms", back, got, ms),
    );
    let _ = set8(i, s, SOL_SOCKET, 0x1006, 0, Some(0));
    // The socket still works after the timeout.
    let ok = lib.send(c, b"after", 0) == Ok(5);
    let mut b = [0u8; 5];
    t.check(ok && lib.recv(s, &mut b, 0) == Ok(5) && &b == b"after", format_args!("6: the socket works after a receive timeout"));
    let ka = (set8(i, c, SOL_SOCKET, 0x0008, 1, None), opt8(i, c, SOL_SOCKET, 0x0008).2[0]);
    let nd0 = opt8(i, c, IPPROTO_TCP, 0x01).2[0];
    let nd = (set8(i, c, IPPROTO_TCP, 0x01, 0, None), opt8(i, c, IPPROTO_TCP, 0x01).2[0]);
    let ra = (set8(i, c, SOL_SOCKET, 0x0004, 1, None), opt8(i, c, SOL_SOCKET, 0x0004).2[0], opt8(i, c, SOL_SOCKET, 0x0020).2[0]);
    // SO_SNDBUF: Roadshow's default tcp.sendspace is 32 KB, rustsocket's
    // 64 KB; either passes, so the suite runs against both.
    let bufs = (opt8(i, c, SOL_SOCKET, 0x1001).2[0], opt8(i, c, SOL_SOCKET, 0x1002).2[0]);
    t.check(
        ka == (0, 1) && nd0 == 1 && nd == (0, 0) && ra == (0, 1, 0) && matches!(bufs, (32768 | 65536, 65536)),
        format_args!("6: SO_KEEPALIVE {:?}, TCP_NODELAY default {} then {:?}, SO_REUSEADDR/SO_BROADCAST {:?}, SO_SNDBUF/SO_RCVBUF {:?}", ka, nd0, nd, ra, bufs),
    );
    let bad = set8(i, c, 0xffff, 0x7777, 1, None);
    t.check(bad == -1 && lib.errno() == 42, format_args!("6: an unknown option gives ENOPROTOOPT ({} {})", bad, lib.errno()));
    // SO_LINGER {1, 0}: CloseSocket resets; the peer reads an error, not
    // the end of the stream.
    let lg = set8(i, c, SOL_SOCKET, 0x0080, 1, Some(0));
    let lgb = opt8(i, c, SOL_SOCKET, 0x0080).2;
    let _ = lib.close(c);
    let r = lib.recv(s, &mut [0u8; 4], 0);
    t.check(lg == 0 && lgb == [1, 0] && matches!(r, Err(AmigaError::IoError(54))), format_args!("6: SO_LINGER {{1, 0}} resets on close: the peer's recv gives ECONNRESET ({:?})", r));
    let _ = lib.close(s);
    let _ = lib.close(l);
}

fn sharing(lib: &SocketLib, lib_name: &str, i: *mut SocketIFace, t: &mut Tally) {
    let Some((c, s, l)) = pair(lib) else {
        t.check(false, format_args!("6: sharing: a TCP pair over lo0"));
        return;
    };
    // SAFETY: an open interface.
    let d = unsafe { ((*i).Dup2Socket)(i, c, -1) };
    let _ = lib.close(c);
    let sent = lib.send(d, b"dup!", 0);
    let mut b = [0u8; 4];
    let got = lib.recv(s, &mut b, 0);
    t.check(d >= 0 && d != c && sent == Ok(4) && got == Ok(4) && &b == b"dup!", format_args!("6: Dup2Socket(c, -1) = {}; c closed, the copy still sends ({:?} {:?})", d, sent, got));
    // SAFETY: as above.
    let d20 = unsafe { ((*i).Dup2Socket)(i, d, 20) };
    let _ = lib.close(d);
    let _ = lib.send(d20, b"x", 0);
    let _ = lib.close(d20);
    let end = lib.recv(s, &mut b, 0);
    let end2 = if end == Ok(1) { lib.recv(s, &mut b, 0) } else { end.clone() };
    t.check(d20 == 20 && end2 == Ok(0), format_args!("6: Dup2Socket(d, 20); closing the last copy ends the stream ({} {:?})", d20, end2));
    // SAFETY: as above.
    let r = unsafe { ((*i).Dup2Socket)(i, -1, 21) };
    let rr = lib.recv(21, &mut b, 0);
    t.check(r == 21 && matches!(rr, Err(AmigaError::IoError(EBADF))) && lib.close(21).is_ok(), format_args!("6: Dup2Socket(-1, 21) reserves 21 (recv gives {:?}; it closes)", rr));
    let _ = lib.close(s);
    let _ = lib.close(l);

    // ReleaseCopyOfSocket: both openers hold it, it lives until both close.
    let Some((c, s, l)) = pair(lib) else { return };
    let Ok(b2) = SocketLib::open_named(lib_name, 1) else {
        t.check(false, format_args!("6: a second opener"));
        return;
    };
    // SAFETY: as above.
    let id = unsafe { ((*i).ReleaseCopyOfSocket)(i, c, -1) };
    let i2 = b2.iface();
    // SAFETY: the second opener's interface.
    let c2 = unsafe { ((*i2).ObtainSocket)(i2, id, 2, 1, 0) };
    let _ = lib.close(c);
    let sent = b2.send(c2, b"copy", 0);
    let got = lib.recv(s, &mut b, 0);
    t.check(id >= 0 && c2 >= 0 && sent == Ok(4) && got == Ok(4), format_args!("6: ReleaseCopyOfSocket: the original closed, the other opener's copy still sends (id {}, fd {}, {:?})", id, c2, sent));
    drop(b2);
    let end = lib.recv(s, &mut b, 0);
    t.check(end == Ok(0), format_args!("6: the copy's opener closing ends the stream ({:?})", end));
    let _ = lib.close(s);
    let _ = lib.close(l);
}

#[repr(C)]
struct IoVec {
    base: *mut u8,
    len: u32,
}

#[repr(C)]
struct MsgHdr {
    name: *mut u8,
    namelen: u32,
    iov: *mut IoVec,
    iovlen: u32,
    control: *mut u8,
    controllen: u32,
    flags: i32,
}

fn msgio(lib: &SocketLib, i: *mut SocketIFace, t: &mut Tally) {
    let Some((c, s, l)) = pair(lib) else { return };
    let (mut a, mut b, mut d) = (*b"one ", *b"two ", *b"three");
    let mut iov = [IoVec { base: a.as_mut_ptr(), len: 4 }, IoVec { base: b.as_mut_ptr(), len: 4 }, IoVec { base: d.as_mut_ptr(), len: 5 }];
    let mut m = MsgHdr { name: core::ptr::null_mut(), namelen: 0, iov: iov.as_mut_ptr(), iovlen: 3, control: core::ptr::null_mut(), controllen: 0, flags: 0 };
    // SAFETY: a msghdr of three pieces.
    let n = unsafe { ((*i).sendmsg)(i, c, &mut m as *mut MsgHdr as *mut c_void, 0) };
    let (mut x, mut y) = ([0u8; 6], [0u8; 7]);
    let mut riov = [IoVec { base: x.as_mut_ptr(), len: 6 }, IoVec { base: y.as_mut_ptr(), len: 7 }];
    let mut rm = MsgHdr { name: core::ptr::null_mut(), namelen: 0, iov: riov.as_mut_ptr(), iovlen: 2, control: core::ptr::null_mut(), controllen: 99, flags: 0 };
    let mut got = 0;
    let t0 = us();
    while got < 13 && us() - t0 < 2_000_000 {
        // SAFETY: as above; later reads land after what came before.
        let r = unsafe { ((*i).recvmsg)(i, s, &mut rm as *mut MsgHdr as *mut c_void, 0) };
        if r <= 0 {
            break;
        }
        got += r;
        if got < 13 {
            // Spread the rest after what arrived.
            let k = got as usize;
            riov = if k < 6 {
                [IoVec { base: x[k..].as_mut_ptr(), len: (6 - k) as u32 }, IoVec { base: y.as_mut_ptr(), len: 7 }]
            } else {
                [IoVec { base: y[k - 6..].as_mut_ptr(), len: (13 - k) as u32 }, IoVec { base: core::ptr::null_mut(), len: 0 }]
            };
            rm.iov = riov.as_mut_ptr();
        }
    }
    t.check(n == 13 && got == 13 && &x == b"one tw" && &y == b"o three" && rm.controllen == 0, format_args!("6: sendmsg of 3 pieces ({}), recvmsg into 2 ({}): {:?} {:?}", n, got, String::from_utf8_lossy(&x), String::from_utf8_lossy(&y)));
    let _ = lib.close(c);
    let _ = lib.close(s);
    let _ = lib.close(l);

    // UDP over lo0 with msg_name both ways.
    let (Ok(u1), Ok(u2)) = (lib.socket(2, 2, 0), lib.socket(2, 2, 0)) else { return };
    let _ = lib.bind(u1, &SockAddrIn::v4([127, 0, 0, 1], 0));
    let _ = lib.bind(u2, &SockAddrIn::v4([127, 0, 0, 1], 0));
    let (p1, p2) = (lib.local_addr(u1).map(|a| a.sin_port).unwrap_or(0), lib.local_addr(u2).map(|a| a.sin_port).unwrap_or(0));
    let mut to = SockAddrIn::v4([127, 0, 0, 1], p2);
    let mut data = *b"datagram";
    let mut v = [IoVec { base: data.as_mut_ptr(), len: 8 }];
    let mut m = MsgHdr { name: &mut to as *mut SockAddrIn as *mut u8, namelen: 16, iov: v.as_mut_ptr(), iovlen: 1, control: core::ptr::null_mut(), controllen: 0, flags: 0 };
    // SAFETY: as above.
    let n = unsafe { ((*i).sendmsg)(i, u1, &mut m as *mut MsgHdr as *mut c_void, 0) };
    let mut from = SockAddrIn::v4([0; 4], 0);
    let mut buf = [0u8; 16];
    let mut rv = [IoVec { base: buf.as_mut_ptr(), len: 16 }];
    let mut rm = MsgHdr { name: &mut from as *mut SockAddrIn as *mut u8, namelen: 16, iov: rv.as_mut_ptr(), iovlen: 1, control: core::ptr::null_mut(), controllen: 0, flags: 0 };
    let _ = set8(i, u2, SOL_SOCKET, 0x1006, 2, Some(0));
    // SAFETY: as above.
    let r = unsafe { ((*i).recvmsg)(i, u2, &mut rm as *mut MsgHdr as *mut c_void, 0) };
    t.check(n == 8 && r == 8 && &buf[..8] == b"datagram" && from.ip() == [127, 0, 0, 1] && from.sin_port == p1, format_args!("6: UDP sendmsg to msg_name ({}), recvmsg gives the sender {:?}:{} ({})", n, from.ip(), from.sin_port, r));
    let _ = lib.close(u1);
    let _ = lib.close(u2);
}

fn events(lib: &SocketLib, i: *mut SocketIFace, t: &mut Tally) {
    let Ok(sig) = amigaos4::signal::Signal::alloc() else {
        t.check(false, format_args!("6: events: no free signal"));
        return;
    };
    let ok = lib.set_base_value(4, sig.mask()).is_ok();
    let Some((c, s, l)) = pair(lib) else { return };
    let m = set8(i, s, SOL_SOCKET, 0x2001, 0x08 | 0x40, None);
    sig.clear();
    let _ = lib.send(c, b"ev", 0);
    let got = amigaos4::signal::wait(sig.mask() | amigaos4::sys::SIGBREAKF_CTRL_C);
    let mut ev = 0u32;
    // SAFETY: an open interface and a ULONG.
    let fd = unsafe { ((*i).GetSocketEvents)(i, &mut ev) };
    // SAFETY: as above.
    let none = unsafe { ((*i).GetSocketEvents)(i, &mut ev) };
    t.check(ok && m == 0 && got & sig.mask() != 0 && fd == s && none == -1, format_args!("6: SO_EVENTMASK FD_READ: signalled ({:#x}), GetSocketEvents gives fd {} (want {}), then none ({})", got, fd, s, none));
    let _ = lib.recv(s, &mut [0u8; 2], 0);
    let _ = lib.close(c);
    let got = amigaos4::signal::wait(sig.mask() | amigaos4::sys::SIGBREAKF_CTRL_C);
    // SAFETY: as above.
    let fd = unsafe { ((*i).GetSocketEvents)(i, &mut ev) };
    t.check(got & sig.mask() != 0 && fd == s && ev & 0x40 != 0, format_args!("6: the peer closing gives FD_CLOSE (events {:#x})", ev));
    let _ = lib.set_base_value(4, 0);
    let _ = lib.close(s);
    let _ = lib.close(l);
}

#[repr(C)]
struct AddrInfo {
    ai_flags: i32,
    ai_family: i32,
    ai_socktype: i32,
    ai_protocol: i32,
    ai_addrlen: u32,
    ai_addr: *mut u8,
    ai_canonname: *mut u8,
    ai_next: *mut AddrInfo,
}

/// getaddrinfo's answers as (socktype, ip, port), and the first canonname.
fn gai(i: *mut SocketIFace, node: Option<&[u8]>, serv: Option<&[u8]>, flags: i32, socktype: i32) -> (i32, Vec<(i32, [u8; 4], u16)>, String) {
    let hints = AddrInfo { ai_flags: flags, ai_family: 0, ai_socktype: socktype, ai_protocol: 0, ai_addrlen: 0, ai_addr: core::ptr::null_mut(), ai_canonname: core::ptr::null_mut(), ai_next: core::ptr::null_mut() };
    let mut res: *mut AddrInfo = core::ptr::null_mut();
    let n = node.map_or(core::ptr::null_mut(), |b| b.as_ptr() as *mut u8);
    let s = serv.map_or(core::ptr::null_mut(), |b| b.as_ptr() as *mut u8);
    // SAFETY: NUL-terminated strings, hints, a result pointer.
    let r = unsafe { ((*i).getaddrinfo)(i, n, s, &hints as *const AddrInfo as *mut c_void, &mut res as *mut *mut AddrInfo as *mut *mut c_void) };
    let mut out = Vec::new();
    let mut canon = String::new();
    let mut p = res;
    while !p.is_null() {
        // SAFETY: the list getaddrinfo made.
        let a = unsafe { &*p };
        // SAFETY: its 16-byte sockaddr_in.
        let sa = unsafe { core::slice::from_raw_parts(a.ai_addr, 16) };
        out.push((a.ai_socktype, [sa[4], sa[5], sa[6], sa[7]], u16::from_be_bytes([sa[2], sa[3]])));
        if canon.is_empty() {
            canon = cstr(a.ai_canonname);
        }
        p = a.ai_next;
    }
    // SAFETY: the list getaddrinfo made, freed once.
    unsafe { ((*i).freeaddrinfo)(i, res as *mut c_void) };
    (r, out, canon)
}

fn netdb(lib: &SocketLib, i: *mut SocketIFace, t: &mut Tally) {
    let _ = lib;
    // SAFETY: an open interface; NUL-terminated literals; the answers are
    // the opener's structs (read before the next call).
    unsafe {
        let sv = ((*i).getservbyname)(i, b"http\0".as_ptr() as *mut u8, b"tcp\0".as_ptr() as *mut u8) as *const u32;
        let sp = if sv.is_null() { -1 } else { *sv.add(2) as i32 };
        let sn = ((*i).getservbyport)(i, 22, b"tcp\0".as_ptr() as *mut u8) as *const u32;
        let sname = if sn.is_null() { String::new() } else { cstr(*sn as *const u8) };
        let pr = ((*i).getprotobyname)(i, b"udp\0".as_ptr() as *mut u8) as *const u32;
        let pn = if pr.is_null() { -1 } else { *pr.add(2) as i32 };
        let pb = ((*i).getprotobynumber)(i, 6) as *const u32;
        let pname = if pb.is_null() { String::new() } else { cstr(*pb as *const u8) };
        t.check(sp == 80 && sname == "ssh" && pn == 17 && pname == "tcp", format_args!("6: getservbyname(http) {}, getservbyport(22) {:?}, getprotobyname(udp) {}, getprotobynumber(6) {:?}", sp, sname, pn, pname));
        ((*i).setservent)(i, 0);
        let mut n = 0;
        while !((*i).getservent)(i).is_null() && n < 10_000 {
            n += 1;
        }
        ((*i).endservent)(i);
        ((*i).setprotoent)(i, 0);
        let mut np = 0;
        while !((*i).getprotoent)(i).is_null() && np < 10_000 {
            np += 1;
        }
        t.check(n > 20 && np > 10, format_args!("6: getservent walks {} services, getprotoent {} protocols", n, np));
        let h = lib.iface();
        let he = ((*h).gethostbyname)(h, b"localhost\0".as_ptr() as *mut u8) as *const u32;
        let la = if he.is_null() { [0; 4] } else { let l = *(he.add(4)) as *const *const u8; let a = *l; [*a, *a.add(1), *a.add(2), *a.add(3)] };
        let addr = [127u8, 0, 0, 1];
        let ba = ((*h).gethostbyaddr)(h, addr.as_ptr() as *mut u8, 4, 2) as *const u32;
        let bn = if ba.is_null() { String::new() } else { cstr(*ba as *const u8) };
        let mut hbuf = [0u32; 5];
        let mut store = [0u8; 128];
        let mut herr = 99i32;
        let r = ((*h).gethostbyname_r)(h, b"localhost\0".as_ptr() as *mut u8, hbuf.as_mut_ptr() as *mut c_void, store.as_mut_ptr() as *mut c_void, 128, &mut herr) as *const u32;
        let rn = if r.is_null() { String::new() } else { cstr(*r as *const u8) };
        t.check(la == [127, 0, 0, 1] && bn == "localhost" && !r.is_null() && herr == 0 && rn == "localhost", format_args!("6: gethostbyname(localhost) {:?} (hosts file), gethostbyaddr(127.0.0.1) {:?}, gethostbyname_r {:?} h_errno {}", la, bn, rn, herr));
    }
    let a = gai(i, Some(b"localhost\0"), Some(b"http\0"), 2, 1);
    let b = gai(i, Some(b"10.0.4.2\0"), Some(b"4500\0"), 0, 0);
    let c = gai(i, None, Some(b"8080\0"), 1, 2);
    let d = gai(i, Some(b"github.com\0"), None, 0, 1);
    let e = gai(i, Some(b"no.such.host.invalid\0"), None, 0, 1);
    let f = gai(i, Some(b"localhost\0"), Some(b"nosuchservice\0"), 0, 1);
    t.check(
        a.0 == 0 && a.1 == [(1, [127, 0, 0, 1], 80)] && a.2 == "localhost"
            && b.0 == 0 && b.1 == [(1, [10, 0, 4, 2], 4500), (2, [10, 0, 4, 2], 4500)]
            && c.0 == 0 && c.1 == [(2, [0, 0, 0, 0], 8080)]
            && d.0 == 0 && d.1.len() == 1 && d.1[0].1 != [0; 4]
            && e.0 == -2 && f.0 == -8,
        format_args!("6: getaddrinfo: localhost/http {:?}, 10.0.4.2/4500 {:?}, passive udp {:?}, github.com {:?}, unknown host {}, unknown service {}", a, b, c, d, e.0, f.0),
    );
    // SAFETY: as above.
    let msg = cstr(unsafe { ((*i).gai_strerror)(i, -2) } as *const u8);
    let sa = SockAddrIn::v4([127, 0, 0, 1], 80);
    let (mut host, mut serv) = ([0u8; 64], [0u8; 32]);
    // SAFETY: a sockaddr and two buffers.
    let r = unsafe { ((*i).getnameinfo)(i, &sa as *const SockAddrIn as *mut c_void, 16, host.as_mut_ptr(), 64, serv.as_mut_ptr(), 32, 0) };
    let (hn, sn) = (cstr(host.as_ptr()), cstr(serv.as_ptr()));
    // SAFETY: as above.
    let r2 = unsafe { ((*i).getnameinfo)(i, &sa as *const SockAddrIn as *mut c_void, 16, host.as_mut_ptr(), 64, serv.as_mut_ptr(), 32, 1 | 2) };
    let (hn2, sn2) = (cstr(host.as_ptr()), cstr(serv.as_ptr()));
    t.check(!msg.is_empty() && r == 0 && hn == "localhost" && (sn == "http" || sn == "www") && r2 == 0 && hn2 == "127.0.0.1" && sn2 == "80", format_args!("6: gai_strerror {:?}; getnameinfo {:?}/{:?}, numeric {:?}/{:?}", msg, hn, sn, hn2, sn2));
}

fn small(lib: &SocketLib, i: *mut SocketIFace, t: &mut Tally) {
    let _ = lib;
    // SAFETY: an open interface; literals.
    unsafe {
        let id = ((*i).gethostid)(i);
        let local = ((*i).In_LocalAddr)(i, u32::from_be_bytes(super::host_side(i)));
        let far = ((*i).In_LocalAddr)(i, 0x0808_0808);
        // BSD's in_canforward, as Roadshow (canfwd.c): 8.8.8.8 yes, 127.0.0.1 no.
        let fwd = ((*i).In_CanForward)(i, 0x0808_0808) != 0 && ((*i).In_CanForward)(i, 0x7f00_0001) == 0;
        let dt = ((*i).getdtablesize)(i);
        t.check(id != 0 && local != 0 && far == 0 && fwd && dt == 256, format_args!("6: gethostid {:#x}, In_LocalAddr(QEMU's host side) {}, (8.8.8.8) {}, In_CanForward {}, getdtablesize {}", id, local, far, fwd, dt));
        ((*i).SetDefaultDomainName)(i, b"example.test\0".as_ptr() as *mut u8);
        let mut b = [0u8; 32];
        let ok = ((*i).GetDefaultDomainName)(i, b.as_mut_ptr(), 32);
        let dn = cstr(b.as_ptr());
        ((*i).SetDefaultDomainName)(i, core::ptr::null_mut());
        let cleared = ((*i).GetDefaultDomainName)(i, b.as_mut_ptr(), 32);
        t.check(ok != 0 && dn == "example.test" && cleared == 0, format_args!("6: Set/GetDefaultDomainName {:?}, cleared {}", dn, cleared));
        let args: [u32; 2] = [b"vsyslog\0".as_ptr() as u32, 42];
        ((*i).vsyslog)(i, 6, b"rstcp stage 6: %s %ld (on the serial log)\0".as_ptr() as *mut u8, args.as_ptr() as *mut c_void);
    }
}
