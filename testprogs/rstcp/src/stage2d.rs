//! Socket checks: non-blocking descriptors, WaitSelect, Ctrl-C, names,
//! options, shutdown, MSG_PEEK. Calls the library through the raw
//! interface where the crate has no wrapper.

use core::ffi::c_void;

use amigaos4::bsdsocket::{SockAddrIn, SocketLib};
use amigaos4::error::AmigaError;
use amigaos4::signal::{self, SignalTarget};
use amigaos4::sys;

use super::{us, Tally};

const EINTR: i32 = 4;
const EWOULDBLOCK: i32 = 35;
const EINPROGRESS: i32 = 36;
const ENOTCONN: i32 = 57;
const ENOPROTOOPT: i32 = 42;
const FIONBIO: u32 = 0x8004_667E;
const FIONREAD: u32 = 0x4004_667F;
const MSG_PEEK: i32 = 0x2;

fn ioctl(lib: &SocketLib, fd: i32, req: u32, v: &mut i32) -> i32 {
    let i = lib.iface();
    // SAFETY: the library's interface; `v` is a long for the request.
    unsafe { ((*i).IoctlSocket)(i, fd, req, v as *mut i32 as _) }
}

/// WaitSelect on one descriptor: (result, readable, writable, signals left
/// in the mask).
pub(super) fn select(lib: &SocketLib, fd: i32, read: bool, write: bool, timeout_ms: Option<u32>, sigs: u32) -> (i32, bool, bool, u32) {
    let mut rd = [0u32; 2];
    let mut wr = [0u32; 2];
    let bit = 1u32 << (fd % 32);
    if read {
        rd[fd as usize / 32] = bit;
    }
    if write {
        wr[fd as usize / 32] = bit;
    }
    let tv = timeout_ms.map(|ms| [ms / 1000, (ms % 1000) * 1000]);
    let tvp = tv.as_ref().map(|t| t.as_ptr() as *mut c_void).unwrap_or(core::ptr::null_mut());
    let mut mask = sigs;
    let maskp = if sigs != 0 { &mut mask as *mut u32 } else { core::ptr::null_mut() };
    let i = lib.iface();
    // SAFETY: the library's interface; fd_sets of 64 descriptors, a
    // struct timeval and a signal mask on this stack.
    let r = unsafe { ((*i).WaitSelect)(i, fd + 1, rd.as_mut_ptr() as _, wr.as_mut_ptr() as _, core::ptr::null_mut(), tvp, maskp) };
    (r, rd[fd as usize / 32] & bit != 0, wr[fd as usize / 32] & bit != 0, mask)
}

fn peer_name(lib: &SocketLib, fd: i32) -> Result<SockAddrIn, i32> {
    let mut a = SockAddrIn::default();
    let mut len: u32 = 16;
    let i = lib.iface();
    // SAFETY: `a` has room for a sockaddr_in.
    let r = unsafe { ((*i).getpeername)(i, fd, &mut a as *mut _ as *mut c_void, &mut len) };
    if r < 0 { Err(lib.errno()) } else { Ok(a) }
}

fn signal_self(mask: u32) {
    // SAFETY: this task, signalling itself.
    unsafe { SignalTarget::new(signal::current_task(), mask).send() };
}

/// Read until the end of the stream with WaitSelect between reads (the
/// descriptor is non-blocking); the bytes and how many were wrong (the
/// pattern continues from offset `start`).
fn drain(lib: &SocketLib, fd: i32, start: u64) -> Result<(u64, u64), &'static str> {
    let mut buf = [0u8; 8192];
    let (mut got, mut wrong) = (0u64, 0u64);
    loop {
        let (r, rd, _, _) = select(lib, fd, true, false, Some(5000), 0);
        if r < 0 {
            return Err("WaitSelect failed");
        }
        if r == 0 || !rd {
            return Err("WaitSelect timed out");
        }
        match lib.recv(fd, &mut buf, 0) {
            Ok(0) => return Ok((got, wrong)),
            Ok(n) => {
                for (k, &b) in buf[..n].iter().enumerate() {
                    if b != ((start + got + k as u64) % 251) as u8 {
                        wrong += 1;
                    }
                }
                got += n as u64;
            }
            Err(AmigaError::IoError(EWOULDBLOCK)) => {}
            Err(_) => return Err("recv failed"),
        }
    }
}

pub fn run(lib: &SocketLib, host: [u8; 4], t: &mut Tally) {
    let peer = SockAddrIn::v4(host, 4500);

    // Non-blocking connect, then WaitSelect for writable and SO_ERROR.
    let Ok(fd) = lib.socket(2, 1, 0) else {
        t.check(false, format_args!("2d: socket"));
        return;
    };
    let mut on = 1;
    t.check(ioctl(lib, fd, FIONBIO, &mut on) == 0, format_args!("2d: IoctlSocket FIONBIO"));
    let r = lib.connect(fd, &peer);
    t.check(matches!(r, Err(AmigaError::IoError(EINPROGRESS))), format_args!("2d: non-blocking connect gives EINPROGRESS ({:?})", r));
    let (r, _, wr, _) = select(lib, fd, false, true, Some(5000), 0);
    let err = lib.get_opt(fd, 0xffff, 0x1007);
    t.check(r == 1 && wr && err == Ok(0), format_args!("2d: WaitSelect says writable once connected, SO_ERROR 0 ({} {} {:?})", r, wr, err));
    let p = peer_name(lib, fd);
    let me = lib.local_addr(fd);
    t.check(
        matches!(&p, Ok(a) if a.ip() == host && a.sin_port == 4500) && matches!(&me, Ok(a) if a.sin_port != 0 && a.ip() != [0; 4]),
        format_args!("2d: getpeername {:?} and getsockname {:?}", p.as_ref().map(|a| (a.ip(), a.sin_port)), me.as_ref().map(|a| (a.ip(), a.sin_port))),
    );
    t.check(lib.get_opt(fd, 0xffff, 0x1008) == Ok(1), format_args!("2d: SO_TYPE is SOCK_STREAM"));
    t.check(lib.set_opt(fd, 6, 1, 1).is_ok(), format_args!("2d: setsockopt TCP_NODELAY"));
    let r = lib.set_opt(fd, 0xffff, 0x7777, 1);
    t.check(matches!(r, Err(AmigaError::IoError(ENOPROTOOPT))), format_args!("2d: an unknown option gives ENOPROTOOPT ({:?})", r));

    // Nothing to read yet (the host waits for a command): EWOULDBLOCK, and
    // WaitSelect for reading times out.
    let r = lib.recv(fd, &mut [0u8; 16], 0);
    t.check(matches!(r, Err(AmigaError::IoError(EWOULDBLOCK))), format_args!("2d: non-blocking recv with nothing queued gives EWOULDBLOCK ({:?})", r));
    let t0 = us();
    let (r, rd, _, _) = select(lib, fd, true, false, Some(300), 0);
    let ms = (us() - t0) / 1000;
    t.check(r == 0 && !rd && (250..1000).contains(&ms), format_args!("2d: WaitSelect with a 300 ms timeout returns 0 after {} ms", ms));

    // A signal in WaitSelect's mask ends the wait: 0, the mask says which.
    signal_self(sys::SIGBREAKF_CTRL_E);
    let t0 = us();
    let (r, _, _, left) = select(lib, fd, true, false, None, sys::SIGBREAKF_CTRL_E);
    t.check(
        r == 0 && left == sys::SIGBREAKF_CTRL_E && us() - t0 < 1_000_000,
        format_args!("2d: CTRL-E in WaitSelect's mask ends it at once ({} mask {:#x})", r, left),
    );

    // Data: FIONREAD, MSG_PEEK, then everything with WaitSelect.
    let _ = lib.send(fd, b"NETPROF 1 SEND 100000\n", 0);
    let (r, rd, _, _) = select(lib, fd, true, false, Some(5000), 0);
    let mut n = 0;
    let fr = ioctl(lib, fd, FIONREAD, &mut n);
    t.check(r == 1 && rd && fr == 0 && n > 0, format_args!("2d: readable after the request; FIONREAD {}", n));
    let mut a = [0u8; 4];
    let mut b = [0u8; 4];
    let p = lib.recv(fd, &mut a, MSG_PEEK);
    let q = lib.recv(fd, &mut b, 0);
    t.check(p == Ok(4) && q == Ok(4) && a == b && a == [0, 1, 2, 3], format_args!("2d: MSG_PEEK then recv see the same bytes ({:?} {:?})", a, b));
    let d = drain(lib, fd, 4);
    t.check(d == Ok((99996, 0)), format_args!("2d: the rest through WaitSelect: {:?} (of 99996)", d));
    let _ = lib.close(fd);

    // Ctrl-C interrupts a blocking recv with EINTR.
    match lib.socket(2, 1, 0) {
        Ok(fd) => {
            let c = lib.connect(fd, &peer);
            signal_self(sys::SIGBREAKF_CTRL_C);
            let t0 = us();
            let r = lib.recv(fd, &mut [0u8; 16], 0);
            t.check(
                c.is_ok() && matches!(r, Err(AmigaError::IoError(EINTR))) && us() - t0 < 1_000_000,
                format_args!("2d: CTRL-C interrupts a blocking recv with EINTR ({:?})", r),
            );
            // The break signal is still set after EINTR (Roadshow and
            // rustsocket alike: `rstcp sigs`); a program clears it itself
            // before it goes on. The socket still works afterwards.
            // SAFETY: SetSignal on this task's own CTRL-C bit.
            unsafe { sys::exec_set_signal(0, sys::SIGBREAKF_CTRL_C) };
            let _ = lib.send(fd, b"NETPROF 1 SEND 5000\n", 0);
            let mut got = 0;
            let mut buf = [0u8; 2048];
            while let Ok(n) = lib.recv(fd, &mut buf, 0) {
                if n == 0 {
                    break;
                }
                got += n;
            }
            t.check(got == 5000, format_args!("2d: the socket works after EINTR ({} of 5000)", got));
            let _ = lib.close(fd);
        }
        Err(e) => t.check(false, format_args!("2d: socket: {}", e)),
    }
    signal::take(sys::SIGBREAKF_CTRL_C);

    // shutdown(SHUT_WR) after the request: the host still sends.
    match lib.socket(2, 1, 0) {
        Ok(fd) => {
            let c = lib.connect(fd, &peer);
            let _ = lib.send(fd, b"NETPROF 1 SEND 20000\n", 0);
            let s = lib.shutdown(fd, 1);
            let mut got = 0;
            let mut buf = [0u8; 4096];
            while let Ok(n) = lib.recv(fd, &mut buf, 0) {
                if n == 0 {
                    break;
                }
                got += n;
            }
            let w = lib.send(fd, b"x", 0);
            t.check(
                c.is_ok() && s.is_ok() && got == 20000 && w.is_err(),
                format_args!("2d: shutdown(1): {} of 20000 still arrive, a send after it fails ({:?})", got, w),
            );
            let _ = lib.close(fd);
        }
        Err(e) => t.check(false, format_args!("2d: socket: {}", e)),
    }

    // A socket never connected.
    if let Ok(fd) = lib.socket(2, 1, 0) {
        let p = peer_name(lib, fd);
        let r = lib.recv(fd, &mut [0u8; 4], 0);
        t.check(
            p.as_ref().err() == Some(&ENOTCONN) && matches!(r, Err(AmigaError::IoError(ENOTCONN))),
            format_args!("2d: getpeername and recv on an unconnected socket give ENOTCONN ({:?} {:?})", p.err(), r),
        );
        let _ = lib.close(fd);
    }
}
