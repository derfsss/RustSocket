//! `rstcp calls [library] [host]`: free memory around repeated calls of one
//! kind, the library open all the time, to find a per-call leak.

use alloc::vec;

use amigaos4::bsdsocket::{SockAddrIn, SocketLib};
use amigaos4::sys;

use super::stage2d::select;
use super::Out;
use core::fmt::Write;

fn free() -> i64 {
    // SAFETY: AvailMem reads exec's counters.
    unsafe { sys::exec_avail_mem(sys::MEMF_ANY) as i64 }
}

pub fn run(lib: &SocketLib, host: [u8; 4]) {
    let peer = SockAddrIn::v4(host, 4500);
    // Warm up: the stack's first socket, DHCP, the first connect.
    if let Ok(mut s) = lib.tcp_connect(&peer) {
        let _ = s.write_all(b"NETPROF 1 SEND 1000\n");
        let mut b = [0u8; 2048];
        while let Ok(n) = s.read(&mut b) {
            if n == 0 {
                break;
            }
        }
    }
    let fd = lib.socket(2, 1, 0).unwrap_or(-1);

    let row = |what: &str, n: u32, f: &mut dyn FnMut()| {
        let a = free();
        for _ in 0..n {
            f();
        }
        let b = free();
        say!("calls: {:<34} {:>5} calls: free {:+} bytes ({:+} per call)", what, n, b - a, (b - a) / n as i64);
        amigaos4::serial_println!("rstcp calls: {} {} calls: free {:+} bytes", what, n, b - a);
    };

    row("getsockopt SO_TYPE (Info)", 2000, &mut || {
        let _ = lib.get_opt(fd, 0xffff, 0x1008);
    });
    row("WaitSelect, 0 timeout (Select)", 2000, &mut || {
        let _ = select(lib, fd, true, false, Some(0), 0);
    });
    row("socket + CloseSocket (Open, Close)", 500, &mut || {
        if let Ok(s) = lib.socket(2, 1, 0) {
            let _ = lib.close(s);
        }
    });
    row("UDP socket + CloseSocket", 500, &mut || {
        if let Ok(s) = lib.socket(2, 2, 0) {
            let _ = lib.close(s);
        }
    });
    row("connect + SEND 1000 + read + close", 100, &mut || {
        if let Ok(mut s) = lib.tcp_connect(&peer) {
            let _ = s.write_all(b"NETPROF 1 SEND 1000\n");
            let mut b = [0u8; 2048];
            while let Ok(n) = s.read(&mut b) {
                if n == 0 {
                    break;
                }
            }
        }
    });
    // Many small recvs on one connection.
    if let Ok(mut s) = lib.tcp_connect(&peer) {
        let _ = s.write_all(b"NETPROF 1 SEND 400000\n");
        let mut b = vec![0u8; 200];
        row("recv of 200 bytes", 2000, &mut || {
            let _ = s.read(&mut b);
        });
    }
    let _ = lib.close(fd);
    let a = free();
    say!("calls: free now {} (after the rows)", a);
}
