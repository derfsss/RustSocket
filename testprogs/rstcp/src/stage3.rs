//! Listener, UDP and DNS checks. A second opener of bsdsocket.library is
//! the other end: it connects to QEMU's host side, 10.0.3.2, at the fwd=N
//! port (default 4510), which QEMU's user network forwards back to this
//! guest's port 4510 (and N+1 to UDP 4511). So the peer the library under
//! test sees is QEMU's host side on its own network.

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use amigaos4::bsdsocket::{SockAddrIn, SocketLib};
use amigaos4::error::AmigaError;
use amigaos4::net::Socket;

use super::stage2d::select;
use super::{us, Tally};

const EWOULDBLOCK: i32 = 35;
const ROADSHOW_TO_RUSTSOCKET: [u8; 4] = [10, 0, 3, 2];

fn ip(a: &SockAddrIn) -> [u8; 4] {
    a.ip()
}

/// Wait up to `ms` for the client's socket to be readable.
fn rs_ready(rs: &SocketLib, s: &Socket<'_>, ms: u64) -> bool {
    matches!(rs.wait(&[s], &[], 0, Some(Duration::from_millis(ms))), Ok(r) if r.readable.first() == Some(&true))
}

fn pattern(off: u64, n: usize) -> Vec<u8> {
    (0..n).map(|k| ((off + k as u64) % 251) as u8).collect()
}

pub fn run(lib: &SocketLib, t: &mut Tally) {
    let rs = match SocketLib::open(4) {
        Ok(l) => l,
        Err(e) => {
            t.check(false, format_args!("3: open Roadshow's bsdsocket.library (the client): {}", e));
            return;
        }
    };
    listener(lib, &rs, t);
    udp(lib, &rs, t);
    dns(lib, &rs, t);
}

fn listener(lib: &SocketLib, rs: &SocketLib, t: &mut Tally) {
    let at = SockAddrIn::v4([0; 4], 4510);
    let l = match lib.tcp_listen(&at, 2) {
        Ok(l) => l,
        Err(e) => {
            t.check(false, format_args!("3: listen on 4510: {}", e));
            return;
        }
    };
    let me = l.local_addr();
    t.check(matches!(&me, Ok(a) if a.sin_port == 4510), format_args!("3: the listener's getsockname port 4510 ({:?})", me.as_ref().map(|a| (a.ip(), a.sin_port))));
    let _ = l.sock.set_nonblocking(true);
    let r = lib.accept(l.sock.fd());
    t.check(matches!(r, Err(AmigaError::IoError(EWOULDBLOCK))), format_args!("3: non-blocking accept with nobody waiting gives EWOULDBLOCK ({:?})", r.as_ref().err()));
    let _ = l.sock.set_nonblocking(false);

    // A connection from the client.
    let to = SockAddrIn::v4(ROADSHOW_TO_RUSTSOCKET, super::fwd());
    let t0 = us();
    let client = match rs.tcp_connect(&to) {
        Ok(c) => c,
        Err(e) => {
            t.check(false, format_args!("3: Roadshow connects to 10.0.3.2:4510 (QEMU forwards it to rustsocket): {}", e));
            return;
        }
    };
    let (r, rd, _, _) = select(lib, l.sock.fd(), true, false, Some(5000), 0);
    t.check(r == 1 && rd, format_args!("3: WaitSelect: the listener is readable once a connection waits ({} ms)", (us() - t0) / 1000));
    let (mut server, peer) = match l.accept() {
        Ok(x) => x,
        Err(e) => {
            t.check(false, format_args!("3: accept: {}", e));
            return;
        }
    };
    let host = super::host_side(lib.iface());
    t.check(ip(&peer) == host, format_args!("3: accept gives the peer {:?}:{} (QEMU's {:?})", ip(&peer), peer.sin_port, host));
    let mut client = client;

    // 256 KB each way, in 16 KB steps (one task drives both ends).
    const STEP: usize = 16 * 1024;
    const TOTAL: u64 = 256 * 1024;
    let mut buf = vec![0u8; STEP];
    let (mut wrong, mut moved) = (0u64, 0u64);
    let t0 = us();
    let mut ok = true;
    while ok && moved < TOTAL {
        ok = client.write_all(&pattern(moved, STEP)).is_ok();
        let mut got = 0;
        while ok && got < STEP {
            match server.read(&mut buf[..STEP - got]) {
                Ok(0) | Err(_) => ok = false,
                Ok(n) => {
                    let want = pattern(moved + got as u64, n);
                    wrong += buf[..n].iter().zip(&want).filter(|(a, b)| a != b).count() as u64;
                    got += n;
                }
            }
        }
        moved += got as u64;
    }
    let up_ms = (us() - t0) / 1000;
    t.check(ok && moved == TOTAL && wrong == 0, format_args!("3: Roadshow -> rustsocket: {} of {} bytes, {} wrong, {} ms", moved, TOTAL, wrong, up_ms));
    let (mut wrong, mut moved) = (0u64, 0u64);
    let t0 = us();
    let mut ok = true;
    while ok && moved < TOTAL {
        ok = server.write_all(&pattern(moved, STEP)).is_ok();
        let mut got = 0;
        while ok && got < STEP {
            if !rs_ready(rs, &client.sock, 5000) {
                ok = false;
                break;
            }
            match client.read(&mut buf[..STEP - got]) {
                Ok(0) | Err(_) => ok = false,
                Ok(n) => {
                    let want = pattern(moved + got as u64, n);
                    wrong += buf[..n].iter().zip(&want).filter(|(a, b)| a != b).count() as u64;
                    got += n;
                }
            }
        }
        moved += got as u64;
    }
    let down_ms = (us() - t0) / 1000;
    t.check(ok && moved == TOTAL && wrong == 0, format_args!("3: rustsocket -> Roadshow: {} of {} bytes, {} wrong, {} ms", moved, TOTAL, wrong, down_ms));
    drop(client);
    let mut one = [0u8; 4];
    let r = server.read(&mut one);
    t.check(r == Ok(0), format_args!("3: the accepted connection sees the end of the stream when Roadshow closes ({:?})", r));
    drop(server);

    // A second connection from the same listener (its pool refilled).
    match rs.tcp_connect(&to) {
        Ok(mut c) => {
            let ok = match l.accept() {
                Ok((mut s, _)) => {
                    let a = c.write_all(b"ping").is_ok();
                    let mut b = [0u8; 4];
                    let r1 = s.read_exact(&mut b).is_ok() && &b == b"ping";
                    let w = s.write_all(b"pong").is_ok();
                    let r2 = rs_ready(rs, &c.sock, 3000) && c.read_exact(&mut b).is_ok() && &b == b"pong";
                    a && r1 && w && r2
                }
                Err(_) => false,
            };
            t.check(ok, format_args!("3: a second accept on the same listener, ping/pong"));
        }
        Err(e) => t.check(false, format_args!("3: second connect: {}", e)),
    }

    // A connection waiting when the listener closes is reset.
    match rs.tcp_connect(&to) {
        Ok(mut c) => {
            let (r, rd, _, _) = select(lib, l.sock.fd(), true, false, Some(3000), 0);
            drop(l);
            let ready = rs_ready(rs, &c.sock, 5000);
            let mut b = [0u8; 4];
            let r2 = if ready { Some(c.read(&mut b)) } else { None };
            t.check(
                r == 1 && rd && matches!(r2, Some(Ok(0)) | Some(Err(_))),
                format_args!("3: closing the listener ends a connection not yet accepted (Roadshow reads {:?})", r2),
            );
        }
        Err(e) => t.check(false, format_args!("3: third connect: {}", e)),
    }
}

fn udp(lib: &SocketLib, rs: &SocketLib, t: &mut Tally) {
    let u = match lib.udp_bind(&SockAddrIn::v4([0; 4], 4511)) {
        Ok(u) => u,
        Err(e) => {
            t.check(false, format_args!("3: UDP bind 4511: {}", e));
            return;
        }
    };
    let r = match rs.udp_bind(&SockAddrIn::v4([0; 4], 0)) {
        Ok(r) => r,
        Err(e) => {
            t.check(false, format_args!("3: Roadshow UDP socket: {}", e));
            return;
        }
    };
    let to = SockAddrIn::v4(ROADSHOW_TO_RUSTSOCKET, super::fwd() + 1);
    let _ = r.send_to(b"hello rustsocket", &to);
    let (n, rd, _, _) = select(lib, u.sock.fd(), true, false, Some(3000), 0);
    let mut buf = [0u8; 64];
    let got = if n == 1 && rd { u.recv_from(&mut buf).ok() } else { None };
    let from = got.map(|(_, a)| a);
    t.check(
        matches!(got, Some((16, a)) if ip(&a) == super::host_side(lib.iface())) && &buf[..16] == b"hello rustsocket",
        format_args!("3: UDP from Roadshow arrives with its sender ({:?})", got.map(|(n, a)| (n, ip(&a), a.sin_port))),
    );
    let Some(from) = from else { return };

    // The answer goes back through QEMU to the client's socket.
    let s = u.send_to(b"hello roadshow", &from);
    let back = if rs_ready(rs, &r.sock, 3000) { r.recv_from(&mut buf).ok() } else { None };
    t.check(
        s == Ok(14) && matches!(back, Some((14, _))) && &buf[..14] == b"hello roadshow",
        format_args!("3: a UDP answer to the sender reaches Roadshow ({:?})", back.map(|(n, a)| (n, ip(&a), a.sin_port))),
    );

    // A datagram longer than the buffer is cut; the next one is whole.
    let _ = r.send_to(&[7u8; 100], &to);
    let _ = r.send_to(b"next", &to);
    let mut small = [0u8; 10];
    let (_, rd, _, _) = select(lib, u.sock.fd(), true, false, Some(3000), 0);
    let a = if rd { u.recv_from(&mut small).ok().map(|(n, _)| n) } else { None };
    let (_, rd, _, _) = select(lib, u.sock.fd(), true, false, Some(3000), 0);
    let b = if rd { u.recv_from(&mut buf).ok().map(|(n, _)| n) } else { None };
    t.check(
        a == Some(10) && small == [7u8; 10] && b == Some(4) && &buf[..4] == b"next",
        format_args!("3: a 100-byte datagram into 10 bytes is cut to 10, the next comes whole ({:?} {:?})", a, b),
    );

    // Connected: only the peer's datagrams. First show that a second
    // client socket arrives from another port (so the filter has
    // something to tell apart through QEMU's forward).
    let r2 = rs.udp_bind(&SockAddrIn::v4([0; 4], 0));
    let mut other = None;
    if let Ok(r2) = &r2 {
        let _ = r2.send_to(b"other", &to);
        let (_, rd, _, _) = select(lib, u.sock.fd(), true, false, Some(3000), 0);
        if rd {
            other = u.recv_from(&mut buf).ok().map(|(_, a)| a);
        }
    }
    t.check(
        matches!(&other, Some(a) if a.sin_port != from.sin_port),
        format_args!("3: a second sender arrives from another port ({:?} vs {})", other.as_ref().map(|a| (ip(a), a.sin_port)), from.sin_port),
    );
    let c = u.connect(&from);
    if let Ok(r2) = &r2 {
        let _ = r2.send_to(b"intruder", &to);
    }
    // Let the intruder's datagram arrive first.
    let _ = select(lib, u.sock.fd(), true, false, Some(300), 0);
    let _ = r.send_to(b"friend", &to);
    let mut got = None;
    for _ in 0..3 {
        let (_, rd, _, _) = select(lib, u.sock.fd(), true, false, Some(2000), 0);
        if !rd {
            break;
        }
        if let Ok((n, _)) = u.recv_from(&mut buf) {
            got = Some(Vec::from(&buf[..n]));
            break;
        }
    }
    let peer2 = r2.as_ref().ok().and_then(|s| s.sock.local_addr().ok()).map(|a| a.sin_port);
    t.check(
        c.is_ok() && got.as_deref() == Some(&b"friend"[..]),
        format_args!(
            "3: a connected UDP socket ignores another sender (got {:?}; Roadshow ports {} and {:?})",
            got.as_deref().map(|g| core::str::from_utf8(g).unwrap_or("?")),
            from.sin_port,
            peer2
        ),
    );
}

fn dns(lib: &SocketLib, rs: &SocketLib, t: &mut Tally) {
    let r = lib.resolve("10.0.4.2");
    t.check(matches!(&r, Ok(v) if v.first() == Some(&[10, 0, 4, 2])), format_args!("3: gethostbyname of a dotted address is itself ({:?})", r));

    let name = "github.com";
    let t0 = us();
    let a = lib.resolve(name);
    let ms = (us() - t0) / 1000;
    let b = rs.resolve(name);
    t.check(
        matches!(&a, Ok(v) if !v.is_empty()) && b.is_ok(),
        format_args!("3: gethostbyname({}) = {:?} in {} ms (Roadshow: {:?}; needs the PC online)", name, a, ms, b),
    );

    let t0 = us();
    let r = lib.resolve("no-such-host.invalid");
    let ms = (us() - t0) / 1000;
    let mut herr: u32 = 0;
    let h = lib.get_base_value(7);
    if let Ok(v) = h {
        herr = v;
    }
    t.check(
        matches!(r, Err(AmigaError::HostNotFound)) && herr == 1,
        format_args!("3: an unknown name gives NULL and h_errno HOST_NOT_FOUND ({:?}, h_errno {}, {} ms)", r.err(), herr, ms),
    );
}
