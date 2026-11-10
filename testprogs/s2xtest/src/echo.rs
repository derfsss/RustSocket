//! echo=U,MYIP,GWIP[,PORT]: transmit checksum offload against a real IP stack
//! (QEMU's user network, or a router). Unit U is brought up as MYIP, the
//! gateway's address is found by ARP, then frames written RAW in write
//! batches, with checksum requests, must be answered: ICMP echo with
//! FILL_IP only (two sizes), TCP SYN (a 54-byte frame, under the Ethernet
//! minimum) with FILL_IP + FILL_L4, FILL_L4 only, FILL_IP only, and with
//! no request, to TCP port PORT of the gateway (default 4530; it should be
//! one something listens on: the SYN must be answered quickly, and QEMU's
//! slirp is slow to refuse a closed one) (the baseline: if that one gets no answer the check itself
//! does not work there). A stack drops a frame whose checksums are wrong,
//! so an answer proves them right.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use amigaos4::device::cmd::{CMD_READ, CMD_WRITE};
use amigaos4::sana2::*;
use amigaos4::sana2ext as x;

use crate::frames::{checksum, fold, sum};
use crate::{bring_up, Batch, Ctx, ItemSet, Opener, Req, NORMAL_BUF};

fn ip4(src: [u8; 4], dst: [u8; 4], proto: u8, id: u16, l4: &[u8]) -> Vec<u8> {
    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes());
    ip.extend_from_slice(&[0x40, 0, 64, proto, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(l4);
    ip
}

fn pseudo4(src: [u8; 4], dst: [u8; 4], proto: u8, len: usize) -> u32 {
    sum(sum(0, &src), &dst) + proto as u32 + len as u32
}

/// Post `n` CMD_READs of `ptype` on `o`.
fn reads(ctx: &mut Ctx, o: &Opener, n: usize, ptype: u32) -> Vec<Req> {
    (0..n)
        .map(|_| {
            let mut r = ctx.clone_req(&o.req, NORMAL_BUF);
            r.set(CMD_READ, 0);
            r.r.set_packet_type(ptype);
            ctx.send(&r);
            r
        })
        .collect()
}

/// The first of `rs` (back within `ms`) whose bytes `f` accepts; all freed.
fn find(ctx: &mut Ctx, rs: Vec<Req>, ms: u32, f: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    let mut waited = 0;
    let mut hit = None;
    while hit.is_none() && waited < ms {
        for r in rs.iter() {
            if ctx.poll(r) && f(r.bytes()) {
                hit = Some(r.bytes().to_vec());
                break;
            }
        }
        if hit.is_none() {
            ctx.sleep(10);
            waited += 10;
        }
    }
    for r in rs {
        ctx.free(r);
    }
    hit
}

/// Write one RAW frame in a write batch, with checksum flags `flags`
/// (Start/Offset from the Ethernet header).
fn send_raw(ctx: &mut Ctx, o: &Opener, frame: &[u8], flags: u32, start: u16, offset: u16) -> Option<(i8, u32)> {
    let mut wb = Batch::new(ctx, &o.req, 1, NORMAL_BUF, ItemSet { checksum: true, ..ItemSet::default() });
    let dst = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];
    wb.freqs[0].set_write(CMD_WRITE, SANA2IOF_RAW, 0x0800, &dst, frame);
    wb.set_csum(0, flags, start, offset);
    wb.post_write(ctx);
    let res = ctx.wait(&wb.req, 1000);
    wb.free(ctx);
    res
}

/// A read batch for IPv4 on `o` with checksum items, posted.
fn post_batch(ctx: &mut Ctx, o: &Opener) -> Batch {
    let mut b = Batch::new(ctx, &o.req, 16, NORMAL_BUF, ItemSet { checksum: true, ..ItemSet::default() });
    b.post_read(ctx, 0x0800, 0);
    b
}

/// The first IPv4 frame `b` receives (reposted while others come, `ms` at
/// most) that `f` accepts, with its receive checksum result; `b` freed.
fn find_batch(ctx: &mut Ctx, mut b: Batch, ms: u32, f: impl Fn(&[u8]) -> bool) -> Option<(Vec<u8>, u32)> {
    let mut waited = 0;
    let mut hit = None;
    while hit.is_none() && waited < ms {
        if ctx.poll(&b.req) {
            for i in 0..(b.done() as usize).min(b.freqs.len()) {
                if f(b.freqs[i].bytes()) {
                    hit = Some((b.freqs[i].bytes().to_vec(), b.csum_flags(i)));
                    break;
                }
            }
            if hit.is_none() {
                b.post_read(ctx, 0x0800, 0);
            }
        } else {
            ctx.sleep(10);
            waited += 10;
        }
    }
    b.free(ctx);
    hit
}

pub fn run(ctx: &mut Ctx, devname_unit: u32, my: [u8; 4], gw: [u8; 4], port: u16, rxcsum: bool) {
    let mut o = match ctx.open(devname_unit) {
        Ok(o) => o,
        Err(e) => {
            ctx.check("echo.open", false, format!("unit {}: OpenDevice error {}", devname_unit, e));
            return;
        }
    };
    if let Err(e) = bring_up(ctx, &mut o) {
        ctx.check("echo.open", false, e);
        ctx.close(o);
        return;
    }
    // ARP for the gateway.
    let mut arp = vec![0u8, 1, 8, 0, 6, 4, 0, 1];
    arp.extend_from_slice(&o.mac);
    arp.extend_from_slice(&my);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&gw);
    let mut gmac = None;
    for _ in 0..3 {
        let rs = reads(ctx, &o, 4, 0x0806);
        let mut w = ctx.clone_req(&o.req, NORMAL_BUF);
        w.set_write(S2_BROADCAST, 0, 0x0806, &[0xff; 6], &arp);
        let _ = ctx.do_io(&w);
        ctx.free(w);
        if let Some(b) = find(ctx, rs, 1000, |b| b.len() >= 28 && b[7] == 2 && b[14..18] == gw) {
            gmac = Some([b[8], b[9], b[10], b[11], b[12], b[13]]);
            break;
        }
    }
    let Some(gmac) = gmac else {
        ctx.check("echo.arp", false, format!("no ARP answer from {}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]));
        ctx.close(o);
        return;
    };
    ctx.check("echo.arp", true, format!("gateway {}", crate::mac(&gmac)));
    let eth = |ip: &[u8]| -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&gmac);
        f.extend_from_slice(&o.mac);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(ip);
        f
    };
    let mut rx_icmp: Option<u32> = None;
    let mut rx_tcp: Option<u32> = None;
    // ICMP echo, FILL_IP only (the stack computes the ICMP checksum).
    for (k, size) in [56usize, 1400].into_iter().enumerate() {
        let mut m = vec![8u8, 0, 0, 0, 0x5a, 0x17, 0, k as u8];
        m.extend((0..size).map(|i| (i * 13 + k) as u8));
        let c = checksum(&m);
        m[2..4].copy_from_slice(&c.to_be_bytes());
        let mut ip = ip4(my, gw, 1, 0x700 + k as u16, &m);
        ip[10] = 0;
        ip[11] = 0;
        let rb = post_batch(ctx, &o);
        let res = send_raw(ctx, &o, &eth(&ip), x::S2XCS_FILL_IP, 0, 0);
        let got = find_batch(ctx, rb, 2000, |b| b.len() >= 28 && b[9] == 1 && b[20] == 0 && b[24..26] == [0x5a, 0x17] && b[27] == k as u8);
        ctx.check(&format!("echo.icmp{}.iponly", size), res == Some((0, 0)) && got.is_some(), format!("{} data bytes, FILL_IP: write {:?}, echo reply {}", size, res, got.is_some()));
        if let Some((_, f)) = got {
            rx_icmp.get_or_insert(f);
        }
    }
    // TCP SYN, 54 bytes on the wire before padding.
    let cases: [(&str, u32); 4] = [
        ("echo.syn.none", 0),
        ("echo.syn.both", x::S2XCS_FILL_IP | x::S2XCS_FILL_L4),
        ("echo.syn.l4only", x::S2XCS_FILL_L4),
        ("echo.syn.iponly", x::S2XCS_FILL_IP),
    ];
    for (k, (name, flags)) in cases.into_iter().enumerate() {
        let sport = 40000 + 97 * k as u16 + (ctx.next_id() as u16);
        let seq = 0x1000_0000u32 + k as u32 * 0x100;
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&port.to_be_bytes());
        t.extend_from_slice(&seq.to_be_bytes());
        t.extend_from_slice(&0u32.to_be_bytes());
        t.extend_from_slice(&[5 << 4, 0x02, 0x40, 0x00, 0, 0, 0, 0]);
        let full = !fold(sum(pseudo4(my, gw, 6, t.len()), &t));
        t[16..18].copy_from_slice(&full.to_be_bytes());
        if flags & x::S2XCS_FILL_L4 != 0 {
            // The pseudo-header sum in the field, as the spec says.
            let ps = fold(pseudo4(my, gw, 6, t.len()));
            t[16..18].copy_from_slice(&ps.to_be_bytes());
        }
        let mut ip = ip4(my, gw, 6, 0x800 + k as u16, &t);
        if flags & x::S2XCS_FILL_IP != 0 {
            ip[10] = 0;
            ip[11] = 0;
        }
        let rb = post_batch(ctx, &o);
        let res = send_raw(ctx, &o, &eth(&ip), flags, 34, 16);
        // Any TCP answer from the gateway to our port that acknowledges
        // the SYN (SYN+ACK, or RST+ACK from a closed port).
        let want_ack = seq.wrapping_add(1).to_be_bytes();
        let got = find_batch(ctx, rb, 3000, |b| b.len() >= 40 && b[9] == 6 && b[22..24] == sport.to_be_bytes() && b[28..32] == want_ack && b[33] & 0x10 != 0);
        let what = got.as_ref().map(|(b, _)| match b[33] & 0x17 {
            0x12 => "SYN+ACK",
            0x14 => "RST+ACK",
            _ => "ACK",
        });
        ctx.check(name, res == Some((0, 0)) && got.is_some(), format!("TCP SYN (54 bytes), flags 0x{:x}: write {:?}, answer {:?}", flags, res, what));
        if let Some((b, f)) = got {
            rx_tcp.get_or_insert(f);
            if b[33] & 0x02 != 0 {
                // A SYN+ACK: reset the half-open connection.
                let mut r = Vec::new();
                r.extend_from_slice(&sport.to_be_bytes());
                r.extend_from_slice(&port.to_be_bytes());
                r.extend_from_slice(&seq.wrapping_add(1).to_be_bytes());
                r.extend_from_slice(&0u32.to_be_bytes());
                r.extend_from_slice(&[5 << 4, 0x04, 0, 0, 0, 0, 0, 0]);
                let c = !fold(sum(pseudo4(my, gw, 6, r.len()), &r));
                r[16..18].copy_from_slice(&c.to_be_bytes());
                let _ = send_raw(ctx, &o, &eth(&ip4(my, gw, 6, 0x900, &r)), 0, 0, 0);
            }
        }
    }
    // The answers' receive checksum results (real frames from another
    // stack: their checksums are right).
    if rxcsum {
        let good = |f: Option<u32>, want: u32| f == Some(want);
        ctx.check("echo.rx.icmp", good(rx_icmp, x::S2XCS_IP_GOOD), format!("ICMP echo reply: checksum result {:?} (want IP good, L4 not checked)", rx_icmp));
        ctx.check("echo.rx.tcp", good(rx_tcp, x::S2XCS_IP_GOOD | x::S2XCS_L4_GOOD), format!("TCP answer: checksum result {:?} (want IP good, L4 good)", rx_tcp));
    }
    ctx.close(o);
}
