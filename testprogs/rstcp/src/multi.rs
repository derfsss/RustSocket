//! `rstcp multi [library]`: the library on two interfaces at once:
//! VIRTIONET (virtio-net unit 0, 10.0.3.0/24, added at start-up by
//! AddNetInterface in S:Network-Startup) and "m2" (a third virtio-net
//! card, unit 2, on a QEMU user network of its own, 10.0.5.0/24)
//! added here at run time and given its address by DHCP through the
//! address allocation message (iface.rs's helpers), as AddNetInterface
//! does. netprof-host on the PC answers on both networks (10.0.3.2:4500
//! and 10.0.5.2:4500; `netprof-host 4500 127.0.0.1` is enough, slirp hands
//! the guests' connections to the PC's loopback). m2 is removed at the end.

use alloc::vec::Vec;
use core::ffi::c_void;

use amigaos4::bsdsocket::{SockAddrIn, SocketLib};
use amigaos4::port::AmigaMsgPort;
use amigaos4::timer::Waiter;

use super::iface::{create, errno, get, wait_reply, AAMR_SUCCESS, AAM_ADDRESS, AAM_RESULT};
use super::Tally;

fn fetch(lib: &SocketLib, host: [u8; 4], n: usize) -> (Result<usize, &'static str>, Option<SockAddrIn>) {
    let Ok(mut s) = lib.tcp_connect(&SockAddrIn::v4(host, 4500)) else { return (Err("connect"), None) };
    let me = s.sock.local_addr().ok();
    if s.write_all(alloc::format!("NETPROF 1 SEND {}\n", n).as_bytes()).is_err() {
        return (Err("send"), me);
    }
    let mut buf = alloc::vec![0u8; 8192];
    let (mut got, mut wrong) = (0usize, 0usize);
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => {
                wrong += buf[..k].iter().enumerate().filter(|(i, &b)| b != ((got + i) % 251) as u8).count();
                got += k;
            }
            Err(_) => return (Err("recv"), me),
        }
    }
    (if wrong == 0 { Ok(got) } else { Err("wrong bytes") }, me)
}

/// Add m2 on unit 2 and configure it by DHCP: its address, or None.
fn add_second(lib: &SocketLib, t: &mut Tally) -> Option<[u8; 4]> {
    let i = lib.iface();
    let (Ok(port), Ok(mut timer)) = (AmigaMsgPort::new(), Waiter::new()) else {
        t.check(false, format_args!("multi: no port or timer"));
        return None;
    };
    // SAFETY: NUL-terminated names and an empty tag list.
    let r = unsafe { ((*i).AddInterfaceTagList)(i, b"m2\0".as_ptr() as *mut u8, b"virtionet.device\0".as_ptr() as *mut u8, 2, core::ptr::null_mut()) };
    if r != 0 {
        t.check(false, format_args!("multi: AddInterfaceTagList m2 on unit 2 (needs a third virtio-net card): {} errno {}", r, errno(i)));
        return None;
    }
    let (c, m) = create(i, 2, b"m2\0", &port);
    if c != 0 || m == 0 {
        t.check(false, format_args!("multi: CreateAddrAllocMessage: CAAME {}", c));
        return None;
    }
    // SAFETY: our message from CreateAddrAllocMessage.
    unsafe { ((*i).BeginInterfaceConfig)(i, m as *mut c_void) };
    let back = wait_reply(&port, &mut timer, m, 20000);
    let res = get(m, AAM_RESULT) as i32;
    let a = get(m, AAM_ADDRESS).to_be_bytes();
    // SAFETY: our message, back from the stack.
    unsafe { ((*i).DeleteAddrAllocMessage)(i, m as *mut c_void) };
    t.check(back && res == AAMR_SUCCESS && a == [10, 0, 5, 15], format_args!("multi: m2 added on unit 2, DHCP gave {:?} (result {})", a, res));
    (back && res == AAMR_SUCCESS).then_some(a)
}

pub fn run(lib: &SocketLib, t: &mut Tally) {
    let Some(_) = add_second(lib, t) else { return };
    let names = lib.interfaces().unwrap_or_default();
    let addrs: Vec<([u8; 4], [u8; 4])> = names.iter().map(|n| lib.interface_ipv4(n).unwrap_or(([0; 4], [0; 4]))).collect();
    t.check(
        names.len() == 2 && addrs.iter().all(|(a, _)| a[0] == 10 && a[3] == 15),
        format_args!("multi: two interfaces with addresses: {:?} {:?}", names, addrs),
    );

    // Out of each interface by route.
    for host in [[10, 0, 3, 2], [10, 0, 5, 2]] {
        let (r, me) = fetch(lib, host, 200_000);
        let local = me.map(|a| a.ip());
        t.check(
            r == Ok(200_000) && local == Some([host[0], host[1], host[2], 15]),
            format_args!("multi: 200000 bytes from {:?}:4500, every byte checked, from local {:?} ({:?})", host, local, r),
        );
    }

    // Both at once: two connections open, read in turns.
    let a = lib.tcp_connect(&SockAddrIn::v4([10, 0, 3, 2], 4500));
    let b = lib.tcp_connect(&SockAddrIn::v4([10, 0, 5, 2], 4500));
    let mut ok = false;
    if let (Ok(mut a), Ok(mut b)) = (a, b) {
        let _ = a.write_all(b"NETPROF 1 SEND 300000\n");
        let _ = b.write_all(b"NETPROF 1 SEND 300000\n");
        let mut buf = alloc::vec![0u8; 4096];
        let (mut ga, mut gb, mut ea, mut eb) = (0usize, 0usize, false, false);
        while !(ea && eb) {
            if !ea {
                match a.read(&mut buf) {
                    Ok(0) | Err(_) => ea = true,
                    Ok(k) => ga += k,
                }
            }
            if !eb {
                match b.read(&mut buf) {
                    Ok(0) | Err(_) => eb = true,
                    Ok(k) => gb += k,
                }
            }
        }
        ok = ga == 300_000 && gb == 300_000;
        t.check(ok, format_args!("multi: two connections at once, one on each interface: {} and {} of 300000", ga, gb));
    } else {
        t.check(ok, format_args!("multi: two connections at once: a connect failed"));
    }

    // DNS still answers.
    let r = lib.resolve("github.com");
    t.check(matches!(&r, Ok(v) if !v.is_empty()), format_args!("multi: gethostbyname(github.com) with two interfaces: {:?}", r));

    // m2 goes again.
    let i = lib.iface();
    // SAFETY: a NUL-terminated name.
    let r = unsafe { ((*i).RemoveInterface)(i, b"m2\0".as_ptr() as *mut u8, 1) };
    t.check(r == 1 && lib.interfaces().map(|v| v.len()).unwrap_or(0) == 1, format_args!("multi: m2 removed ({})", r));
}
