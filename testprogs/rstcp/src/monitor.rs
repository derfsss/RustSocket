//! `rstcp monitor [library] [host]`: the network monitoring hooks
//! (AddNetMonitorHookTagList / RemoveNetMonitorHook): a connect hook that
//! refuses with EACCES, a bind hook that counts, a send hook that refuses,
//! an ICMP hook that sees an echo reply and then drops one, a packet hook
//! that counts frames both ways.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicI32, Ordering};

use amigaos4::bsdsocket::SocketLib;
use amigaos4::hook::Hook;
use amigaos4::sys::SocketIFace;

use super::Tally;

static SEEN: [AtomicU32; 7] = [const { AtomicU32::new(0) }; 7];
static ANSWER: [AtomicI32; 7] = [const { AtomicI32::new(0) }; 7];

fn checksum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while s > 0xFFFF {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

fn sa(a: [u8; 4], port: u16) -> [u8; 16] {
    let mut s = [0u8; 16];
    s[0] = 16;
    s[1] = 2;
    s[2..4].copy_from_slice(&port.to_be_bytes());
    s[4..8].copy_from_slice(&a);
    s
}

/// One echo request through a raw socket; whether its reply came within
/// a second.
fn ping(i: *mut SocketIFace, host: [u8; 4], seq: u16) -> bool {
    // SAFETY: plain calls with buffers of their sizes.
    unsafe {
        let s = ((*i).socket)(i, 2, 3, 1);
        let tv: [u32; 2] = [1, 0];
        ((*i).setsockopt)(i, s, 0xffff, 0x1006, tv.as_ptr() as *mut c_void, 8);
        let mut p = alloc::vec![8u8, 0, 0, 0, 0x77, 0x77, (seq >> 8) as u8, seq as u8, 1, 2, 3, 4];
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
        let to = sa(host, 0);
        ((*i).sendto)(i, s, p.as_ptr() as *mut c_void, p.len() as i32, 0, to.as_ptr() as *mut c_void, 16);
        let mut buf = [0u8; 128];
        let mut got = false;
        for _ in 0..3 {
            let n = ((*i).recv)(i, s, buf.as_mut_ptr() as *mut c_void, 128, 0);
            if n < 0 {
                break;
            }
            if n >= 28 && buf[20] == 0 && buf[24] == 0x77 {
                got = true;
                break;
            }
        }
        ((*i).CloseSocket)(i, s);
        got
    }
}

pub fn run(lib: &SocketLib, host: [u8; 4], t: &mut Tally) {
    let i = lib.iface();
    let mk = |k: usize| {
        Hook::new(move |_o: *mut c_void, _m: *mut c_void| {
            SEEN[k].fetch_add(1, Ordering::Relaxed);
            ANSWER[k].load(Ordering::Relaxed) as u32
        })
    };
    let (Ok(h_connect), Ok(h_bind), Ok(h_send), Ok(h_icmp), Ok(h_packet)) = (mk(3), mk(6), mk(4), mk(0), mk(5)) else {
        t.check(false, format_args!("monitor: no hooks"));
        return;
    };
    // SAFETY: plain calls; the hooks live until the end of this function
    // and are removed before.
    unsafe {
        let add = |kind: i32, h: &dyn Fn() -> *mut amigaos4::sys::Hook| ((*i).AddNetMonitorHookTagList)(i, kind, h(), core::ptr::null_mut());
        let r = add(3, &|| h_connect.as_ptr()) | add(6, &|| h_bind.as_ptr()) | add(4, &|| h_send.as_ptr()) | add(0, &|| h_icmp.as_ptr()) | add(5, &|| h_packet.as_ptr());
        let bad = ((*i).AddNetMonitorHookTagList)(i, 9, h_bind.as_ptr(), core::ptr::null_mut());
        t.check(r == 0 && bad == -1 && ((*i).Errno)(i) == 22, format_args!("monitor: five hooks added; type 9 EINVAL ({})", bad));

        // connect refused by the hook with EACCES, then allowed.
        ANSWER[3].store(13, Ordering::Relaxed);
        let s = ((*i).socket)(i, 2, 1, 0);
        let to = sa(host, 4500);
        let c1 = ((*i).connect)(i, s, to.as_ptr() as *mut c_void, 16);
        let e1 = ((*i).Errno)(i);
        ANSWER[3].store(0, Ordering::Relaxed);
        let c2 = ((*i).connect)(i, s, to.as_ptr() as *mut c_void, 16);
        t.check(c1 == -1 && e1 == 13 && c2 == 0 && SEEN[3].load(Ordering::Relaxed) == 2, format_args!("monitor: MHT_Connect refuses with EACCES ({} {}), then lets it through ({})", c1, e1, c2));

        // send refused by the hook.
        ANSWER[4].store(1, Ordering::Relaxed);
        let n1 = ((*i).send)(i, s, b"x".as_ptr() as *mut c_void, 1, 0);
        let e3 = ((*i).Errno)(i);
        ANSWER[4].store(0, Ordering::Relaxed);
        t.check(n1 == -1 && e3 == 1, format_args!("monitor: MHT_Send refuses with EPERM ({} {})", n1, e3));
        ((*i).CloseSocket)(i, s);

        // bind seen.
        let u = ((*i).socket)(i, 2, 2, 0);
        let any = sa([0; 4], 0);
        ((*i).bind)(i, u, any.as_ptr() as *mut c_void, 16);
        ((*i).CloseSocket)(i, u);
        t.check(SEEN[6].load(Ordering::Relaxed) == 1, format_args!("monitor: MHT_Bind saw the bind ({})", SEEN[6].load(Ordering::Relaxed)));

        // ICMP: an echo reply seen, then dropped.
        let p0 = SEEN[5].load(Ordering::Relaxed);
        let ok = ping(i, host, 1);
        let seen_icmp = SEEN[0].load(Ordering::Relaxed);
        ANSWER[0].store(-2, Ordering::Relaxed);
        let dropped = !ping(i, host, 2);
        ANSWER[0].store(0, Ordering::Relaxed);
        let back = ping(i, host, 3);
        t.check(ok && seen_icmp >= 1 && dropped && back, format_args!("monitor: MHT_ICMP sees the reply ({}), MA_Drop drops it ({}), then it passes again ({})", seen_icmp, dropped, back));
        t.check(SEEN[5].load(Ordering::Relaxed) > p0 + 4, format_args!("monitor: MHT_Packet saw frames both ways ({})", SEEN[5].load(Ordering::Relaxed) - p0));

        for h in [h_connect.as_ptr(), h_bind.as_ptr(), h_send.as_ptr(), h_icmp.as_ptr(), h_packet.as_ptr()] {
            ((*i).RemoveNetMonitorHook)(i, h);
        }
        let before = SEEN[0].load(Ordering::Relaxed);
        ping(i, host, 4);
        t.check(SEEN[0].load(Ordering::Relaxed) == before, format_args!("monitor: removed hooks are not called"));
    }
}
