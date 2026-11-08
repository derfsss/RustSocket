//! rstcp: rustsocket's checks, through the amigaos4 crate's net module
//! and the raw SocketIFace (docs/roadshow-compat.md has what they
//! cover). The same checks run against Roadshow and against rustsocket,
//! each installed as bsdsocket.library, so the two can be compared.
//!
//!   rstcp [library] [host] [download bytes] [upload bytes] [nostage3|lan] [fwd=N]
//!       the main suite (90 checks). fwd=N: the host port that QEMU's user
//!       network forwards to this guest's TCP port 4510 (N+1 to UDP 4511);
//!       default 4510. A second run in the same boot fails one check by
//!       design (descriptor id 77 is taken).
//!   rstcp calls [library] [host]   memory around repeated calls
//!   rstcp multi [library]          two interfaces at once (needs a third
//!                                  virtio-net card, unit 2)
//!   rstcp iface [library]          the interface API (needs the same card)
//!   rstcp raw [library] [host]     raw sockets
//!   rstcp sigs [library]           break signals and EINTR
//!   rstcp monitor [library] [host] the monitoring hooks
//!   rstcp bpf [library] [host]     the packet filter
//!   rstcp ipf [library] [host]     the IP filter hook and mbufs
//!   rstcp servers [library] [host] the superserver (see servers.rs for the
//!                                  servers file it needs)
//!   rstcp server / dosserver [library]  what the superserver starts
//!   rstcp api [library] [mask=N]   the socket API and SocketBaseTagList
//!                                  checks alone
//!
//! Defaults: bsdsocket.library, 10.0.3.2 (QEMU's host side on the first
//! virtio card's network; 127.0.0.1 for servers), 1048576 down, 262144 up.
//! The PC runs tools/netprof-host (port 4500; `netprof-host 4500
//! 127.0.0.1` is enough): "NETPROF 1 SEND n" sends n bytes (byte o is
//! o % 251) and closes; "NETPROF 1 RECV n" reads n bytes of the same
//! pattern and answers "DONE n microseconds wrong". Prints PASS/FAIL; rc 0
//! when all pass.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use core::fmt::{self, Write};
use core::panic::PanicInfo;

use amigaos4::allocator::SharedExecAllocator;
use amigaos4::bsdsocket::{SockAddrIn, SocketLib};
use amigaos4::error::AmigaError;
use amigaos4::sys;
use amigaos4::timer::get_up_time;

#[global_allocator]
static ALLOCATOR: SharedExecAllocator = SharedExecAllocator;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    amigaos4::panic::default_panic_handler(info)
}

pub(crate) struct Out;
impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut buf = [0u8; 128];
        for chunk in s.as_bytes().chunks(buf.len() - 1) {
            buf[..chunk.len()].copy_from_slice(chunk);
            buf[chunk.len()] = 0;
            // SAFETY: a NUL-terminated buffer on the stack.
            unsafe { sys::dos_put_str(buf.as_ptr() as _) };
        }
        Ok(())
    }
}
macro_rules! say {
    ($($arg:tt)*) => {{ let _ = writeln!(Out, $($arg)*); }};
}

mod stage2d;
mod stage3;
mod calls;
mod multi;
mod handoff;
mod stage6;
mod stage7;
mod iface;
mod raw;
mod sigs;
mod monitor;
mod servers;
mod bpf;
mod ipf;

struct Tally(u32, u32);
impl Tally {
    fn check(&mut self, ok: bool, what: fmt::Arguments) {
        if ok { self.0 += 1 } else { self.1 += 1 }
        say!("{} {}", if ok { "PASS" } else { "FAIL" }, what);
        amigaos4::serial_println!("rstcp {} {}", if ok { "PASS" } else { "FAIL" }, what);
    }
}

fn us() -> u64 {
    get_up_time().as_micros()
}

fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut o = [0u8; 4];
    let mut it = s.split('.');
    for b in &mut o {
        *b = it.next()?.parse().ok()?;
    }
    it.next().is_none().then_some(o)
}

fn mbps(bytes: u64, micros: u64) -> f64 {
    bytes as f64 / micros.max(1) as f64
}

/// The host port QEMU forwards to this guest's TCP 4510 (fwd=N).
static FWD: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(4510);

/// QEMU's host side on the network of this guest's first interface
/// (gethostid's a.b.c.2): where forwarded connections come from.
pub fn host_side(i: *mut amigaos4::sys::SocketIFace) -> [u8; 4] {
    // SAFETY: a plain call on an open interface.
    let id = unsafe { ((*i).gethostid)(i) }.to_be_bytes();
    [id[0], id[1], id[2], 2]
}

/// The forwarded TCP port; UDP is one above.
pub fn fwd() -> u16 {
    FWD.load(core::sync::atomic::Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_main(args: *const u8, arglen: i32) -> i32 {
    // SAFETY: the Shell's argument string, `arglen` bytes.
    let text = unsafe { core::slice::from_raw_parts(args, arglen.max(0) as usize) };
    let text = core::str::from_utf8(text).unwrap_or("");
    if let Some(n) = text.split_whitespace().find_map(|s| s.strip_prefix("fwd=")).and_then(|n| n.parse().ok()) {
        FWD.store(n, core::sync::atomic::Ordering::Relaxed);
    }
    let positional = |s: &&str| !s.starts_with("fwd=");
    let mut w = text.split_whitespace().filter(positional);
    let first = text.split_whitespace().find(positional);
    let calls = first == Some("calls");
    let multi = first == Some("multi");
    let ifacemode = first == Some("iface");
    let rawmode = first == Some("raw");
    let sigsmode = first == Some("sigs");
    let monmode = first == Some("monitor");
    let srvmode = first == Some("servers");
    let servermode = first == Some("server");
    let dosservermode = first == Some("dosserver");
    let bpfmode = first == Some("bpf");
    let ipfmode = first == Some("ipf");
    // "api [library] [mask=N]": the socket API checks (stage6.rs) and the
    // SocketBaseTagList checks (stage7.rs) alone, parts chosen by the bits
    // of N (stage6::run_parts; bit 6 = all of stage7.rs), to find a part
    // quickly.
    let apimode = first == Some("api");
    if calls || multi || ifacemode || rawmode || sigsmode || monmode || srvmode || servermode || bpfmode || ipfmode || dosservermode || apimode {
        w.next();
    }
    let lib_name = String::from(w.next().unwrap_or("bsdsocket.library"));
    let host = w.next().and_then(parse_ip).unwrap_or(if srvmode { [127, 0, 0, 1] } else { [10, 0, 3, 2] });
    let down: u64 = w.next().and_then(|s| s.parse().ok()).unwrap_or(1 << 20);
    let up: u64 = w.next().and_then(|s| s.parse().ok()).unwrap_or(1 << 18);
    // "nostage3": the library alone, without the listener, UDP, DNS,
    // handoff and API checks, to measure its memory.
    // "lan": a real network: the API and SocketBaseTagList checks run, the
    // listener, UDP, DNS and handoff checks (they need QEMU's forward back
    // to this guest) do not.
    let mode = w.next();
    let stage3 = mode != Some("nostage3") && mode != Some("lan");
    let api = mode != Some("nostage3");
    let mut t = Tally(0, 0);

    let t_open = us();
    let lib = match SocketLib::open_named(&lib_name, 1) {
        Ok(l) => l,
        Err(e) => {
            t.check(false, format_args!("open {}: {}", lib_name, e));
            return 20;
        }
    };
    let peer = SockAddrIn::v4(host, 4500);
    if calls {
        calls::run(&lib, host);
        drop(lib);
        return 0;
    }
    if dosservermode {
        let r = servers::dosserver(Some(&lib));
        drop(lib);
        return r;
    }
    if ipfmode {
        ipf::run(&lib, host, &mut t);
        drop(lib);
        say!("rstcp ipf: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    if bpfmode {
        bpf::run(&lib, host, &mut t);
        drop(lib);
        say!("rstcp bpf: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    if servermode {
        let r = servers::server(&lib);
        drop(lib);
        return r;
    }
    if srvmode {
        servers::run(&lib, host, &mut t);
        drop(lib);
        say!("rstcp servers: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    if monmode {
        monitor::run(&lib, host, &mut t);
        drop(lib);
        say!("rstcp monitor: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    if apimode {
        let mask = text.split_whitespace().find_map(|s| s.strip_prefix("mask=")).and_then(|n| n.parse().ok()).unwrap_or(0x7fu32);
        stage6::run_parts(&lib, &lib_name, &mut t, mask);
        // Bit 6: all of the SocketBaseTagList checks; bits 8-12: their
        // parts (stage7::run_parts).
        let parts7 = if mask & 0x40 != 0 { 0x1f } else { (mask >> 8) & 0x1f };
        if parts7 != 0 {
            stage7::run_parts(&lib, &mut t, parts7);
        }
        drop(lib);
        say!("rstcp api: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    if sigsmode {
        sigs::run(&lib, &mut t);
        drop(lib);
        say!("rstcp sigs: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    if rawmode {
        raw::run(&lib, host, &mut t);
        drop(lib);
        say!("rstcp raw: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    if ifacemode {
        iface::run(&lib, &mut t);
        drop(lib);
        say!("rstcp iface: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    if multi {
        multi::run(&lib, &mut t);
        drop(lib);
        say!("rstcp multi: {}/{} passed", t.0, t.0 + t.1);
        return if t.1 == 0 { 0 } else { 20 };
    }
    say!("info: OpenLibrary (the stack started) took {} ms", (us() - t_open) / 1000);
    let t_conn = us();

    // Download.
    match lib.tcp_connect(&peer) {
        Ok(mut s) => {
            say!("info: the first connect took {} ms", (us() - t_conn) / 1000);
            let req = alloc::format!("NETPROF 1 SEND {}\n", down);
            let sent = s.write_all(req.as_bytes());
            let t0 = us();
            let mut buf = vec![0u8; 16384];
            let (mut got, mut wrong) = (0u64, 0u64);
            let mut err = None;
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        for (k, &b) in buf[..n].iter().enumerate() {
                            if b != ((got + k as u64) % 251) as u8 {
                                wrong += 1;
                            }
                        }
                        got += n as u64;
                    }
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            let dt = us() - t0;
            say!("info: download: {} bytes in {} ms ({:.2} MB/s)", got, dt / 1000, mbps(got, dt));
            t.check(
                sent.is_ok() && err.is_none() && got == down && wrong == 0,
                format_args!("download: {} of {} bytes, {} wrong, end of stream at the end ({:?})", got, down, wrong, err),
            );
        }
        Err(e) => t.check(false, format_args!("download: connect to {}.{}.{}.{}:4500: {}", host[0], host[1], host[2], host[3], e)),
    }

    // Upload.
    match lib.tcp_connect(&peer) {
        Ok(mut s) => {
            let req = alloc::format!("NETPROF 1 RECV {}\n", up);
            let mut ok = s.write_all(req.as_bytes()).is_ok();
            let block: alloc::vec::Vec<u8> = (0..(1usize << 16) + 251).map(|i| (i % 251) as u8).collect();
            let t0 = us();
            let mut off = 0u64;
            while ok && off < up {
                let n = ((up - off) as usize).min(1 << 16);
                let start = (off % 251) as usize;
                ok = s.write_all(&block[start..start + n]).is_ok();
                off += n as u64;
            }
            let mut answer = vec![0u8; 128];
            let mut len = 0;
            while ok && len < answer.len() {
                match s.read(&mut answer[len..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        len += n;
                        if answer[..len].contains(&b'\n') {
                            break;
                        }
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            let dt = us() - t0;
            let line = String::from_utf8_lossy(&answer[..len]).into_owned();
            let f: alloc::vec::Vec<&str> = line.split_whitespace().collect();
            let wrong = f.get(3).and_then(|v| v.parse::<u64>().ok());
            let host_bytes = f.get(1).and_then(|v| v.parse::<u64>().ok());
            say!("info: upload: {} bytes in {} ms ({:.2} MB/s); host: {:?}", up, dt / 1000, mbps(up, dt), line.trim());
            t.check(
                ok && f.first() == Some(&"DONE") && host_bytes == Some(up) && wrong == Some(0),
                format_args!("upload: the host read {:?} bytes, {:?} wrong", host_bytes, wrong),
            );
        }
        Err(e) => t.check(false, format_args!("upload: connect: {}", e)),
    }

    // A port nobody listens on.
    let t_ref = us();
    let r = lib.tcp_connect(&SockAddrIn::v4(host, 4501));
    say!("info: the refused connect took {} ms", (us() - t_ref) / 1000);
    t.check(
        matches!(r, Err(AmigaError::IoError(61)) | Err(AmigaError::IoError(60))),
        format_args!("connect to a closed port fails: refused, or timed out on QEMU's user network ({:?})", r.as_ref().err()),
    );
    drop(r);

    // Errors on descriptors.
    let r = lib.recv(99, &mut [0u8; 4], 0);
    t.check(matches!(r, Err(AmigaError::IoError(9))), format_args!("recv on a descriptor never opened gives EBADF ({:?})", r));

    // Many connections, one after another (descriptors reused, sockets
    // freed in the stack).
    let mut ok = 0;
    let t_many = us();
    for _ in 0..20 {
        if let Ok(mut s) = lib.tcp_connect(&peer) {
            let _ = s.write_all(b"NETPROF 1 SEND 1000\n");
            let mut buf = [0u8; 2048];
            let mut got = 0;
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got += n;
            }
            if got == 1000 {
                ok += 1;
            }
        }
    }
    t.check(ok == 20, format_args!("20 short connections in a row: {}/20 complete in {} ms", ok, (us() - t_many) / 1000));

    stage2d::run(&lib, host, &mut t);
    if stage3 {
        stage3::run(&lib, &mut t);
        handoff::run(&lib, &lib_name, &mut t);
    }
    if api {
        // "lan" leaves out the descriptor sharing checks: on Roadshow 1.15
        // on real hardware they crashed rstcp; they run alone as
        // `rstcp api mask=2`.
        stage6::run_parts(&lib, &lib_name, &mut t, if stage3 { 0x3f } else { 0x3d });
        stage7::run(&lib, &mut t);
    }

    let t_close = us();
    drop(lib);
    say!("info: CloseLibrary (the stack stopped) took {} ms", (us() - t_close) / 1000);
    say!("rstcp: {}/{} passed", t.0, t.0 + t.1);
    if t.1 == 0 { 0 } else { 20 }
}
