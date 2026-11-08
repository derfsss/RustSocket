//! Handoff checks: ReleaseSocket / ObtainSocket between two openers, as a
//! server hands each accepted connection to a worker process, and
//! gethostname, the address helpers and a connection over lo0. A second
//! opener of bsdsocket.library is the client,
//! through QEMU's forward of 10.0.3.2:4510 back to this guest's 4510 (see
//! stage3).

use amigaos4::bsdsocket::{SockAddrIn, SocketLib};
use amigaos4::error::AmigaError;

use super::Tally;

const UNIQUE_ID: i32 = -1;
const EBADF: i32 = 9;
const EINVAL: i32 = 22;
const EWOULDBLOCK: i32 = 35;

fn release(lib: &SocketLib, fd: i32, id: i32) -> Result<i32, i32> {
    let i = lib.iface();
    // SAFETY: an open library interface; ReleaseSocket takes a descriptor
    // and an id.
    let r = unsafe { ((*i).ReleaseSocket)(i, fd, id) };
    if r < 0 { Err(lib.errno()) } else { Ok(r) }
}

fn obtain(lib: &SocketLib, id: i32) -> Result<i32, i32> {
    let i = lib.iface();
    // SAFETY: as in release; AF_INET (2), SOCK_STREAM (1), protocol 0.
    let r = unsafe { ((*i).ObtainSocket)(i, id, 2, 1, 0) };
    if r < 0 { Err(lib.errno()) } else { Ok(r) }
}

/// The address helpers (Inet_NtoA, inet_addr and the rest).
fn helpers(lib: &SocketLib, t: &mut Tally) {
    let i = lib.iface();
    // SAFETY: an open library interface; NUL-terminated literals; Inet_NtoA
    // returns the opener's NUL-terminated buffer.
    unsafe {
        let addr = |s: &[u8]| ((*i).inet_addr)(i, s.as_ptr() as *mut u8);
        let a = [addr(b"10.0.4.2\0"), addr(b"0x7f.1\0"), addr(b"10.0.258\0"), addr(b"1.2.3.256\0"), addr(b"junk\0")];
        t.check(a == [0x0A00_0402, 0x7F00_0001, 0x0A00_0102, 0xffff_ffff, 0xffff_ffff], format_args!("5: inet_addr of 10.0.4.2, 0x7f.1, 10.0.258, 1.2.3.256, junk ({:x?})", a));
        let p = ((*i).Inet_NtoA)(i, 0xC0A8_00FF);
        let s = if p.is_null() { "" } else { core::ffi::CStr::from_ptr(p as *const core::ffi::c_char).to_str().unwrap_or("?") };
        t.check(s == "192.168.0.255", format_args!("5: Inet_NtoA(0xC0A800FF) = {:?}", s));
        let mut v = 0u32;
        let ok = ((*i).inet_aton)(i, b"127.0.0.1\0".as_ptr() as *mut u8, &mut v as *mut u32 as *mut core::ffi::c_void);
        let bad = ((*i).inet_aton)(i, b"1..2\0".as_ptr() as *mut u8, &mut v as *mut u32 as *mut core::ffi::c_void);
        t.check(ok == 1 && bad == 0, format_args!("5: inet_aton 127.0.0.1 -> 1, 1..2 -> 0 ({} {})", ok, bad));
        let mut b = [0u8; 4];
        let r1 = ((*i).inet_pton)(i, 2, b"10.0.2.15\0".as_ptr() as *mut u8, b.as_mut_ptr() as *mut core::ffi::c_void);
        let r2 = ((*i).inet_pton)(i, 2, b"10.0.2\0".as_ptr() as *mut u8, b.as_mut_ptr() as *mut core::ffi::c_void);
        let mut out = [0u8; 16];
        let q = ((*i).inet_ntop)(i, 2, [10u8, 0, 2, 15].as_ptr() as *mut core::ffi::c_void, out.as_mut_ptr(), 16);
        let back = if q.is_null() { "" } else { core::ffi::CStr::from_ptr(q as *const core::ffi::c_char).to_str().unwrap_or("?") };
        t.check(r1 == 1 && b == [10, 0, 2, 15] && r2 == 0 && back == "10.0.2.15", format_args!("5: inet_pton/inet_ntop ({} {:?} {} {:?})", r1, b, r2, back));
        let lna = ((*i).Inet_LnaOf)(i, 0x8001_0203);
        let net = ((*i).Inet_NetOf)(i, 0x8001_0203);
        let mk = ((*i).Inet_MakeAddr)(i, 0x8001, 0x0203);
        t.check(lna == 0x0203 && net == 0x8001 && mk == 0x8001_0203, format_args!("5: class B 128.1.2.3: LnaOf {:x}, NetOf {:x}, MakeAddr {:x}", lna, net, mk));
    }
}

/// lo0: a listener on 127.0.0.1, a connection to it, data both ways (how
/// curl makes its socketpair).
fn loopback(lib: &SocketLib, t: &mut Tally) {
    let lo = SockAddrIn::v4([127, 0, 0, 1], 0);
    let Ok(l) = lib.socket(2, 1, 0) else {
        t.check(false, format_args!("5: lo0: socket"));
        return;
    };
    let port = lib.bind(l, &lo).and_then(|_| lib.listen(l, 1)).and_then(|_| lib.local_addr(l));
    let Ok(at) = port else {
        t.check(false, format_args!("5: lo0: listen on 127.0.0.1 ({:?})", port.err()));
        let _ = lib.close(l);
        return;
    };
    let c = lib.socket(2, 1, 0).unwrap_or(-1);
    let conn = lib.connect(c, &SockAddrIn::v4([127, 0, 0, 1], at.sin_port));
    let acc = lib.accept(l);
    let mut ok = conn.is_ok() && acc.is_ok();
    if let Ok((s, peer)) = acc {
        ok &= peer.ip() == [127, 0, 0, 1];
        ok &= lib.send(c, b"wake", 0) == Ok(4);
        let mut b = [0u8; 4];
        ok &= lib.recv(s, &mut b, 0) == Ok(4) && &b == b"wake";
        ok &= lib.send(s, b"back", 0) == Ok(4);
        ok &= lib.recv(c, &mut b, 0) == Ok(4) && &b == b"back";
        let _ = lib.close(s);
    }
    t.check(ok, format_args!("5: lo0: connect to a listener on 127.0.0.1:{}, accept, data both ways ({:?})", at.sin_port, conn.err()));
    let _ = lib.close(c);
    let _ = lib.close(l);
}

pub fn run(lib: &SocketLib, lib_name: &str, t: &mut Tally) {
    helpers(lib, t);
    loopback(lib, t);
    let rs = match SocketLib::open(4) {
        Ok(l) => l,
        Err(e) => {
            t.check(false, format_args!("5: open Roadshow's bsdsocket.library (the client): {}", e));
            return;
        }
    };
    let rs = &rs;
    // gethostname.
    let mut name = [0xffu8; 64];
    let i = lib.iface();
    // SAFETY: a buffer of 64 bytes.
    let r = unsafe { ((*i).gethostname)(i, name.as_mut_ptr(), 64) };
    let len = name.iter().position(|&b| b == 0);
    t.check(r == 0 && matches!(len, Some(n) if n > 0), format_args!("5: gethostname gives a terminated name ({}, {:?})", r, len.map(|n| core::str::from_utf8(&name[..n]).unwrap_or("?"))));

    let b = match SocketLib::open_named(lib_name, 1) {
        Ok(l) => l,
        Err(e) => {
            t.check(false, format_args!("5: a second opener: {}", e));
            return;
        }
    };
    let l = match lib.socket(2, 1, 0) {
        Ok(fd) => fd,
        Err(e) => {
            t.check(false, format_args!("5: socket: {}", e));
            return;
        }
    };
    let listening = lib.bind(l, &SockAddrIn::v4([0; 4], 4510)).and_then(|_| lib.listen(l, 2));
    if let Err(e) = listening {
        t.check(false, format_args!("5: listen on 4510: {}", e));
        let _ = lib.close(l);
        return;
    }
    let to = SockAddrIn::v4([10, 0, 3, 2], super::fwd());
    let mut c1 = match rs.tcp_connect(&to) {
        Ok(c) => c,
        Err(e) => {
            t.check(false, format_args!("5: Roadshow connects: {}", e));
            let _ = lib.close(l);
            return;
        }
    };
    let Ok((fd, _)) = lib.accept(l) else {
        t.check(false, format_args!("5: accept"));
        let _ = lib.close(l);
        return;
    };

    // Release with a new id; the descriptor leaves this opener.
    let id = release(lib, fd, UNIQUE_ID);
    t.check(matches!(id, Ok(n) if n >= 0), format_args!("5: ReleaseSocket(fd, UNIQUE_ID) gives an id ({:?})", id));
    let gone = lib.recv(fd, &mut [0u8; 4], 0x40 /* MSG_DONTWAIT */);
    t.check(matches!(gone, Err(AmigaError::IoError(EBADF))), format_args!("5: the released descriptor is gone from its opener: EBADF ({:?})", gone));
    let none = obtain(&b, 0x7fff_0000);
    t.check(none == Err(EWOULDBLOCK), format_args!("5: ObtainSocket of an id nobody released: EWOULDBLOCK ({:?})", none));

    // The other opener obtains it and talks through it.
    let Ok(id) = id else { return };
    let got = obtain(&b, id);
    t.check(got.is_ok(), format_args!("5: the second opener obtains the socket ({:?})", got));
    let again = obtain(&b, id);
    t.check(again == Err(EWOULDBLOCK), format_args!("5: the same id cannot be obtained twice ({:?})", again));
    if let Ok(bfd) = got {
        let a = c1.write_all(b"ping").is_ok();
        let mut buf = [0u8; 4];
        let mut n = 0;
        while n < 4 {
            match b.recv(bfd, &mut buf[n..], 0) {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
        }
        let w = b.send(bfd, b"pong", 0) == Ok(4);
        let mut back = [0u8; 4];
        let r = c1.read_exact(&mut back).is_ok();
        t.check(a && n == 4 && &buf == b"ping" && w && r && &back == b"pong", format_args!("5: data both ways through the obtained socket ({:?} {:?})", &buf[..n], back));
        let _ = b.close(bfd);
    }
    drop(c1);

    // An explicit id; taking it again is EINVAL. This one is left released:
    // the last CloseLibrary must close it (0 bytes still allocated).
    if let Ok(mut c2) = rs.tcp_connect(&to) {
        let _ = c2.write_all(b"x");
        if let Ok((fd2, _)) = lib.accept(l) {
            let r = release(lib, fd2, 77);
            t.check(r == Ok(77), format_args!("5: ReleaseSocket(fd, 77) keeps id 77 ({:?})", r));
            if let Ok((fd3, _)) = rs.tcp_connect(&to).and_then(|c3| {
                let a = lib.accept(l);
                drop(c3);
                a
            }) {
                let dup = release(lib, fd3, 77);
                t.check(dup == Err(EINVAL), format_args!("5: releasing a second socket under id 77 gives EINVAL ({:?})", dup));
                let _ = lib.close(fd3);
            }
        } else {
            t.check(false, format_args!("5: accept of the second connection"));
        }
        drop(c2);
    }
    let _ = lib.close(l);
    drop(b);
}
