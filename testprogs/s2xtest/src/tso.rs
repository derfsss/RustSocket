//! TCP segmentation (S2XCAP_SEGMENT): one large send on A, the segments
//! as B receives them (plain CMD_READs), each checked in software.

use alloc::format;
use alloc::vec::Vec;
use core::ptr::addr_of_mut;

use amigaos4::device::cmd::CMD_WRITE;
use amigaos4::sana2::*;
use amigaos4::sana2ext as x;

use crate::frames::{self, ETYPE_IPV4, ETYPE_IPV6, PROTO_TCP};
use crate::tests::T;
use crate::{Batch, ItemSet};

const BIG_BUF: usize = 66000;

/// Send `payload` as one segmented TCP send (MSS `mss`) on A; the
/// segments B received, as (IP packet bytes) in arrival order; and the
/// write's result.
fn send_tso(t: &mut T, v6: bool, raw: bool, payload: &[u8], mss: u16, seq: u32) -> (Option<(i8, u32)>, Vec<Vec<u8>>, usize) {
    let mut l4 = frames::transport(v6, PROTO_TCP, 9000, 9001, seq, payload);
    // The pseudo-header sum with a length of 0 (the card adds each
    // segment's), in the checksum field.
    let ps = frames::fold(frames::pseudo(v6, PROTO_TCP, 0));
    l4[16..18].copy_from_slice(&ps.to_be_bytes());
    let mut ip = if v6 { frames::ipv6(PROTO_TCP, &l4) } else { frames::ipv4(PROTO_TCP, 0x4000, &l4) };
    if !v6 {
        ip[10] = 0;
        ip[11] = 0;
    }
    let iphl = if v6 { 40 } else { 20 };
    let ety = if v6 { ETYPE_IPV6 } else { ETYPE_IPV4 };
    let (amac, bmac) = (t.a.mac, t.b.mac);
    let mut data = Vec::new();
    if raw {
        data.extend_from_slice(&bmac);
        data.extend_from_slice(&amac);
        data.extend_from_slice(&(ety as u16).to_be_bytes());
    }
    let hl = data.len();
    data.extend_from_slice(&ip);
    let n = payload.len().div_ceil(mss as usize);
    let reads = t.post_reads(n + 2, ety, 0);
    t.ctx.sleep(20);
    let mut wb = Batch::new(t.ctx, &t.a.req, 1, BIG_BUF, ItemSet { checksum: true, segment: true, ..ItemSet::default() });
    wb.freqs[0].set_write(CMD_WRITE, if raw { SANA2IOF_RAW } else { 0 }, ety, &bmac, &data);
    let flags = x::S2XCS_FILL_L4 | if v6 { 0 } else { x::S2XCS_FILL_IP };
    wb.set_csum(0, flags, (hl + iphl) as u16, 16);
    if let Some(s) = wb.seg[0].as_mut() {
        // SAFETY: our own boxed item.
        unsafe {
            addr_of_mut!(s.s2xfs_Protocol).write_unaligned(if v6 { x::S2XCSUM_TCPV6 } else { x::S2XCSUM_TCPV4 });
            addr_of_mut!(s.s2xfs_SegSize).write_unaligned(mss);
            addr_of_mut!(s.s2xfs_HdrLen).write_unaligned((hl + iphl + 20) as u16);
        }
    }
    wb.post_write(t.ctx);
    let res = t.ctx.wait(&wb.req, 2000);
    let got = t.take(reads, n, 3000);
    t.ctx.sleep(200);
    wb.free(t.ctx);
    let segs = got.into_iter().filter(|g| g.err == 0).map(|g| g.bytes).collect();
    (res, segs, n)
}

/// Check segments of one send: count, checksums, lengths, sequence
/// numbers, IP ids, and the payload put back together.
fn check_segments(v6: bool, segs: &[Vec<u8>], payload: &[u8], mss: usize, seq: u32, n: usize) -> (bool, alloc::string::String) {
    let iphl = if v6 { 40 } else { 20 };
    let mut joined = Vec::new();
    let mut bad = Vec::new();
    let mut ids = Vec::new();
    for (i, s) in segs.iter().enumerate() {
        if s.len() < iphl + 20 {
            bad.push(format!("segment {}: {} bytes", i, s.len()));
            continue;
        }
        let total = if v6 { 40 + u16::from_be_bytes([s[4], s[5]]) as usize } else { u16::from_be_bytes([s[2], s[3]]) as usize };
        let doff = ((s[iphl + 12] >> 4) as usize) * 4;
        let plen = total.saturating_sub(iphl + doff);
        let tseq = u32::from_be_bytes([s[iphl + 4], s[iphl + 5], s[iphl + 6], s[iphl + 7]]);
        let want_len = if i + 1 < n { mss } else { payload.len() - mss * (n - 1) };
        if !v6 {
            ids.push(u16::from_be_bytes([s[4], s[5]]));
            if !frames::ipv4_ok(s) {
                bad.push(format!("segment {}: IPv4 header checksum wrong", i));
            }
        }
        if frames::l4_ok(s) != Some(true) {
            bad.push(format!("segment {}: TCP checksum wrong", i));
        }
        if plen != want_len || total > s.len() {
            bad.push(format!("segment {}: payload {} bytes, expected {}", i, plen, want_len));
        }
        if tseq != seq.wrapping_add((i * mss) as u32) {
            bad.push(format!("segment {}: sequence {} expected {}", i, tseq, seq.wrapping_add((i * mss) as u32)));
        }
        if total <= s.len() && iphl + doff <= total {
            joined.extend_from_slice(&s[iphl + doff..total]);
        }
    }
    let ids_ok = v6 || ids.windows(2).all(|w| w[0] != w[1]);
    if !ids_ok {
        bad.push(format!("IP ids repeat: {:?}", ids));
    }
    let same = joined == payload;
    let ok = segs.len() == n && bad.is_empty() && same;
    (ok, format!("{} of {} segments, payload back together {}{}", segs.len(), n, same, if bad.is_empty() { alloc::string::String::new() } else { format!(", {:?}", &bad[..bad.len().min(4)]) }))
}

pub fn run(t: &mut T, protos: u32, max: u32, min_seg: u16) {
    let mtu = t.a.mtu.min(t.b.mtu) as usize;
    struct Case {
        name: &'static str,
        v6: bool,
        raw: bool,
        len: usize,
    }
    let cases = [
        Case { name: "tso.v4", v6: false, raw: false, len: 20000 },
        Case { name: "tso.v6", v6: true, raw: false, len: 12000 },
        Case { name: "tso.v4.raw", v6: false, raw: true, len: 8000 },
        Case { name: "tso.v4.one", v6: false, raw: false, len: 700 },
        Case { name: "tso.v4.max", v6: false, raw: false, len: (max as usize).saturating_sub(40).min(64000) },
    ];
    for (k, c) in cases.iter().enumerate() {
        let need = if c.v6 { x::S2XCSUM_TCPV6 } else { x::S2XCSUM_TCPV4 };
        if protos & need != need {
            t.ctx.skip(c.name, "protocol not in S2XCAP_SEGMENT");
            continue;
        }
        let mss = mtu - if c.v6 { 60 } else { 40 };
        if (mss as u16) < min_seg {
            t.ctx.skip(c.name, "MTU too small for the smallest segment");
            continue;
        }
        let id = t.ctx.next_id();
        let payload = frames::payload(id, k as u16, c.len);
        let seq = 100_000 * (k as u32 + 1);
        let (res, segs, n) = send_tso(t, c.v6, c.raw, &payload, mss as u16, seq);
        let (ok, detail) = check_segments(c.v6, &segs, &payload, mss, seq, n);
        t.ctx.check(c.name, res == Some((0, 0)) && ok, format!("{} bytes, MSS {}: write {:?}; {}", c.len, mss, res, detail));
    }
    // A segment size that would make frames longer than the MTU: the spec
    // says nothing; report what the driver does.
    let id = t.ctx.next_id();
    let payload = frames::payload(id, 9, 4000);
    let (res, segs, _) = send_tso(t, false, false, &payload, (mtu + 200) as u16, 7);
    t.ctx.info("tso.overmtu", format!("MSS {} with MTU {}: write {:?}, B received {} frames", mtu + 200, mtu, res, segs.len()));
}
