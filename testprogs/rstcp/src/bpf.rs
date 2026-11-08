//! `rstcp bpf [library] [host]`: the packet filter (bpf_open .. bpf_ioctl)
//! as Roadshow has it, run on Roadshow and on rustsocket and compared:
//! the channel count, buffer size, link type, a filter that keeps ICMP
//! only, the headers bpf_read gives (sizes, alignment), statistics, a
//! frame sent with bpf_write coming back, the notify signal, errors.

use core::ffi::c_void;

use alloc::vec::Vec;

use amigaos4::bsdsocket::SocketLib;
use amigaos4::sys::SocketIFace;

use super::{Out, Tally};
use core::fmt::Write;

const fn ior(g: u8, n: u8, len: u32) -> u32 {
    0x4000_0000 | (len & 0x1fff) << 16 | (g as u32) << 8 | n as u32
}
const fn iow(g: u8, n: u8, len: u32) -> u32 {
    0x8000_0000 | (len & 0x1fff) << 16 | (g as u32) << 8 | n as u32
}
const BIOCGBLEN: u32 = ior(b'B', 102, 4);
const BIOCSBLEN: u32 = 0xC000_0000 | 4 << 16 | (b'B' as u32) << 8 | 102;
const BIOCSETF: u32 = iow(b'B', 103, 8);
const BIOCFLUSH: u32 = 0x2000_0000 | (b'B' as u32) << 8 | 104;
const BIOCGDLT: u32 = ior(b'B', 106, 4);
const BIOCGETIF: u32 = ior(b'B', 107, 32);
const BIOCSETIF: u32 = iow(b'B', 108, 32);
const BIOCSRTIMEOUT: u32 = iow(b'B', 109, 8);
const BIOCGSTATS: u32 = ior(b'B', 111, 8);
const BIOCIMMEDIATE: u32 = iow(b'B', 112, 4);
const BIOCVERSION: u32 = ior(b'B', 113, 4);
const FIONREAD: u32 = ior(b'f', 127, 4);
const SIOCGIFADDR: u32 = 0xC000_0000 | 32 << 16 | (b'i' as u32) << 8 | 33;

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

/// One echo request through a raw socket (the reply is not waited for).
fn ping(i: *mut SocketIFace, host: [u8; 4], seq: u16) {
    // SAFETY: plain calls with buffers of their sizes.
    unsafe {
        let s = ((*i).socket)(i, 2, 3, 1);
        let mut p = alloc::vec![8u8, 0, 0, 0, 0x62, 0x70, (seq >> 8) as u8, seq as u8, 1, 2, 3, 4];
        let c = checksum(&p);
        p[2..4].copy_from_slice(&c.to_be_bytes());
        let mut to = [0u8; 16];
        to[0] = 16;
        to[1] = 2;
        to[4..8].copy_from_slice(&host);
        ((*i).sendto)(i, s, p.as_ptr() as *mut c_void, p.len() as i32, 0, to.as_ptr() as *mut c_void, 16);
        let mut buf = [0u8; 128];
        let tv: [u32; 2] = [1, 0];
        ((*i).setsockopt)(i, s, 0xffff, 0x1006, tv.as_ptr() as *mut c_void, 8);
        ((*i).recv)(i, s, buf.as_mut_ptr() as *mut c_void, 128, 0);
        ((*i).CloseSocket)(i, s);
    }
}

/// The packets in one bpf_read buffer: (caplen, datalen, hdrlen, frame).
fn packets(buf: &[u8]) -> Vec<(u32, u32, u16, Vec<u8>)> {
    let mut v = Vec::new();
    let mut p = 0usize;
    while p + 18 <= buf.len() {
        let caplen = u32::from_be_bytes(buf[p + 8..p + 12].try_into().unwrap());
        let datalen = u32::from_be_bytes(buf[p + 12..p + 16].try_into().unwrap());
        let hdrlen = u16::from_be_bytes([buf[p + 16], buf[p + 17]]);
        let start = p + hdrlen as usize;
        if hdrlen < 18 || start + caplen as usize > buf.len() {
            break;
        }
        v.push((caplen, datalen, hdrlen, buf[start..start + caplen as usize].to_vec()));
        p = (start + caplen as usize + 3) & !3;
    }
    v
}

pub fn run(lib: &SocketLib, host: [u8; 4], t: &mut Tally) {
    let i = lib.iface();
    let channels = lib.get_base_value(40).unwrap_or(0);
    let name = lib.interfaces().ok().and_then(|v| v.into_iter().find(|n| n != "lo0")).unwrap_or_default();
    say!("bpf: SBTC_NUM_PACKET_FILTER_CHANNELS {}, interface {}", channels, name);
    // SAFETY: plain calls with buffers of the sizes the requests name.
    unsafe {
        let ioctl = |h: i32, req: u32, arg: *mut u8| ((*i).bpf_ioctl)(i, h, req, arg as *mut c_void);
        let errno = || ((*i).Errno)(i);
        let h = ((*i).bpf_open)(i, -1);
        let e_open = errno();
        t.check(channels > 0 && h > 0, format_args!("bpf: open(-1) = {} (errno {})", h, e_open));
        if h <= 0 {
            return;
        }
        let again = ((*i).bpf_open)(i, h);
        let e_again = errno();
        t.check(again == -1, format_args!("bpf: open({}) again = {} errno {} (ENXIO 6: a handle is not a channel number)", h, again, e_again));
        let mut ver = [0u8; 4];
        let mut blen = [0u8; 4];
        let mut dlt = [0u8; 4];
        let rv = ioctl(h, BIOCVERSION, ver.as_mut_ptr());
        let rb = ioctl(h, BIOCGBLEN, blen.as_mut_ptr());
        let rd = ioctl(h, BIOCGDLT, dlt.as_mut_ptr());
        let e_dlt = errno();
        say!("bpf: BIOCVERSION {} {}.{}, BIOCGBLEN {} {}, BIOCGDLT before SETIF {} {} errno {}", rv, u16::from_be_bytes([ver[0], ver[1]]), u16::from_be_bytes([ver[2], ver[3]]), rb, u32::from_be_bytes(blen), rd, u32::from_be_bytes(dlt), e_dlt);
        let mut sblen = 100_000u32.to_be_bytes();
        let rs = ioctl(h, BIOCSBLEN, sblen.as_mut_ptr());
        say!("bpf: BIOCSBLEN 100000 -> {} {}", rs, u32::from_be_bytes(sblen));
        let mut sblen = 4096u32.to_be_bytes();
        let rs = ioctl(h, BIOCSBLEN, sblen.as_mut_ptr());
        let mut nread = [0u8; 4];
        let rn = ioctl(h, FIONREAD, nread.as_mut_ptr());
        let e_n = errno();
        say!("bpf: BIOCSBLEN 4096 -> {} {}; FIONREAD before SETIF {} errno {}", rs, u32::from_be_bytes(sblen), rn, e_n);

        let mut ifr = [0u8; 32];
        ifr[..name.len().min(15)].copy_from_slice(&name.as_bytes()[..name.len().min(15)]);
        let rsi = ioctl(h, BIOCSETIF, ifr.as_mut_ptr());
        t.check(rsi == 0, format_args!("bpf: BIOCSETIF {} = {} (errno {})", name, rsi, errno()));
        let mut gif = [0u8; 32];
        let rgi = ioctl(h, BIOCGETIF, gif.as_mut_ptr());
        let gname = core::str::from_utf8(&gif[..gif[..16].iter().position(|&b| b == 0).unwrap_or(16)]).unwrap_or("?");
        t.check(rgi == 0 && gname == name, format_args!("bpf: BIOCGETIF = {} {:?}", rgi, gname));
        let rd = ioctl(h, BIOCGDLT, dlt.as_mut_ptr());
        t.check(rd == 0 && u32::from_be_bytes(dlt) == 1, format_args!("bpf: BIOCGDLT = {} {} (DLT_EN10MB 1)", rd, u32::from_be_bytes(dlt)));
        let rb = ioctl(h, BIOCGBLEN, blen.as_mut_ptr());
        let blen = u32::from_be_bytes(blen) as usize;
        say!("bpf: BIOCGBLEN after SETIF {} {}", rb, blen);
        let mut sa = [0u8; 32];
        let ra = ioctl(h, SIOCGIFADDR, sa.as_mut_ptr());
        say!("bpf: SIOCGIFADDR {} family {} addr {}.{}.{}.{}", ra, sa[17], sa[20], sa[21], sa[22], sa[23]);

        // ICMP only: ldh [12]; jeq 0x800; ldb [23]; jeq 1; ret 65535; ret 0.
        let prog: [[u8; 8]; 6] = [
            [0x00, 0x28, 0, 0, 0, 0, 0, 12],
            [0x00, 0x15, 0, 3, 0, 0, 0x08, 0x00],
            [0x00, 0x30, 0, 0, 0, 0, 0, 23],
            [0x00, 0x15, 0, 1, 0, 0, 0, 1],
            [0x00, 0x06, 0, 0, 0, 0, 0xff, 0xff],
            [0x00, 0x06, 0, 0, 0, 0, 0, 0],
        ];
        let mut bp = [0u8; 8];
        bp[..4].copy_from_slice(&6u32.to_be_bytes());
        bp[4..].copy_from_slice(&(prog.as_ptr() as u32).to_be_bytes());
        let rf = ioctl(h, BIOCSETF, bp.as_mut_ptr());
        let mut one = 1u32.to_be_bytes();
        let ri = ioctl(h, BIOCIMMEDIATE, one.as_mut_ptr());
        let mut tv = [0u8; 8];
        tv[..4].copy_from_slice(&2u32.to_be_bytes());
        let rt = ioctl(h, BIOCSRTIMEOUT, tv.as_mut_ptr());
        t.check(rf == 0 && ri == 0 && rt == 0, format_args!("bpf: BIOCSETF {} BIOCIMMEDIATE {} BIOCSRTIMEOUT {}", rf, ri, rt));

        ping(i, host, 1);
        let waiting = ((*i).bpf_data_waiting)(i, h);
        let rn = ioctl(h, FIONREAD, nread.as_mut_ptr());
        say!("bpf: data_waiting {} FIONREAD {} {}", waiting, rn, u32::from_be_bytes(nread));
        let short = ((*i).bpf_read)(i, h, alloc::vec![0u8; 64].as_mut_ptr() as *mut c_void, 64);
        t.check(short == -1 && errno() == 22, format_args!("bpf: read with the wrong length = {} errno {} (EINVAL)", short, errno()));
        let mut buf = alloc::vec![0u32; blen.max(64) / 4];
        let mut got = Vec::new();
        for _ in 0..3 {
            let n = ((*i).bpf_read)(i, h, buf.as_mut_ptr() as *mut c_void, blen as i32);
            if n <= 0 {
                say!("bpf: read {} errno {}", n, errno());
                break;
            }
            let bytes = core::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize);
            got.extend(packets(bytes));
            if got.iter().any(|p| p.3.len() > 34 && p.3[34] == 0) {
                break;
            }
        }
        for (k, p) in got.iter().enumerate() {
            say!("bpf: packet {} caplen {} datalen {} hdrlen {} icmp type {} ({}) {:02x?}->{:02x?}", k, p.0, p.1, p.2, p.3.get(34).copied().unwrap_or(255), if p.3.get(34) == Some(&0) { "reply" } else { "request" }, &p.3[6..12], &p.3[..6]);
        }
        let reply = got.iter().find(|p| p.3.len() >= 42 && p.3[34] == 0).map(|p| p.3.clone());
        t.check(reply.is_some() && got.iter().all(|p| p.3[23] == 1), format_args!("bpf: read {} ICMP packets, the reply among them, nothing else", got.len()));
        let mut st = [0u8; 8];
        ioctl(h, BIOCGSTATS, st.as_mut_ptr());
        say!("bpf: BIOCGSTATS recv {} drop {}", u32::from_be_bytes(st[..4].try_into().unwrap()), u32::from_be_bytes(st[4..].try_into().unwrap()));

        // An ARP request for the host side sent with bpf_write (built from
        // the reply's addresses: ours are its destination); its answer must
        // come back through an accept-all filter.
        if let Some(r) = reply {
            let mut f = alloc::vec![0xffu8; 6];
            f.extend_from_slice(&r[..6]);
            f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 1]);
            f.extend_from_slice(&r[..6]);
            f.extend_from_slice(&r[30..34]);
            f.extend_from_slice(&[0; 6]);
            f.extend_from_slice(&r[26..30]);
            let all: [[u8; 8]; 1] = [[0x00, 0x06, 0, 0, 0, 0, 0xff, 0xff]];
            let mut bp = [0u8; 8];
            bp[..4].copy_from_slice(&1u32.to_be_bytes());
            bp[4..].copy_from_slice(&(all.as_ptr() as u32).to_be_bytes());
            ioctl(h, BIOCSETF, bp.as_mut_ptr());
            ioctl(h, BIOCFLUSH, core::ptr::null_mut());
            let sig = ((*i).bpf_set_notify_mask)(i, h, amigaos4::sys::SIGBREAKF_CTRL_F);
            amigaos4::sys::exec_set_signal(0, amigaos4::sys::SIGBREAKF_CTRL_F);
            let w = ((*i).bpf_write)(i, h, f.as_ptr() as *mut c_void, f.len() as i32);
            let mut back = false;
            for _ in 0..12 {
                let n = ((*i).bpf_read)(i, h, buf.as_mut_ptr() as *mut c_void, blen as i32);
                if n <= 0 {
                    break;
                }
                let bytes = core::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize);
                for p in packets(bytes) {
                    say!("bpf: after write: caplen {} ethertype {:02x?} {:02x?}->{:02x?}", p.0, &p.3[12..14], &p.3[6..12], &p.3[..6]);
                }
                if packets(bytes).iter().any(|p| p.3.len() >= 42 && p.3[12..14] == [8, 6] && p.3[20..22] == [0, 2] && p.3[28..32] == r[26..30]) {
                    back = true;
                    break;
                }
            }
            let notified = amigaos4::sys::exec_set_signal(0, amigaos4::sys::SIGBREAKF_CTRL_F) & amigaos4::sys::SIGBREAKF_CTRL_F != 0;
            t.check(w == f.len() as i32 && back, format_args!("bpf: bpf_write (ARP request) {} of {}: the answer came back {}", w, f.len(), back));
            t.check(sig == 0 && notified, format_args!("bpf: notify mask {} signalled {}", sig, notified));
        }
        let rc = ((*i).bpf_close)(i, h);
        let rc2 = ((*i).bpf_close)(i, h);
        let e_close = errno();
        t.check(rc == 0 && rc2 == -1, format_args!("bpf: close {}, again {} errno {} (EPERM 1, as Roadshow)", rc, rc2, e_close));
    }
}
