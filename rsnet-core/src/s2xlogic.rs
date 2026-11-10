//! The SANA-II extensions' decisions that need no device, so they can be
//! tested on the host (rsnet-core/host-tests): what a driver's capabilities
//! allow, how many read batches to post, what a returned read or write
//! batch means, and what a receive checksum result lets the stack skip.
//! The link (link.rs) does the device work around them.
//!
//! The extensions are the crate's `amigaos4::sana2ext` (unofficial, version
//! 1; the rules are in the crate's docs/devices/sana2ext.md).

use amigaos4::device::ioerr::{IOERR_ABORTED, IOERR_NOCMD};
use amigaos4::sana2::S2ERR_NOT_SUPPORTED;
use amigaos4::sana2ext::*;

/// What a driver offers (its S2X_QUERY answer and capability items); all
/// zero: plain SANA-II.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// S2X_QUERY succeeded with the right magic.
    pub present: bool,
    /// s2xq_Version / s2xq_Revision / s2xq_Features.
    pub version: u16,
    pub revision: u16,
    pub features: u32,
    /// S2XCAP_BATCH: frames one batch may carry (0: no batches).
    pub batch_frames: u32,
    /// S2XCAP_RXCHECKSUM / S2XCAP_TXCHECKSUM: S2XCSUM_ protocols.
    pub rx_csum: u32,
    pub tx_csum: u32,
    /// S2XCAP_SEGMENT: protocols (0: none), largest send, most segments,
    /// smallest segment size.
    pub seg_protocols: u32,
    pub seg_max_size: u32,
    pub seg_max_segments: u16,
    pub seg_min_seg: u16,
    /// S2XCAP_MTU (0, 0: not offered).
    pub mtu_min: u32,
    pub mtu_max: u32,
    /// S2XCAP_MODERATION: longest interval (us) and S2XMOD_ bits; offered
    /// when `moderation` is set.
    pub moderation: bool,
    pub mod_max_us: u32,
    pub mod_flags: u32,
    /// S2XCAP_FLOWCONTROL: S2XFC_ modes; offered when `flow_control` is set.
    pub flow_control: bool,
    pub fc_modes: u32,
    /// S2XCAP_RSS: hash types, receive and transmit queues, key and table
    /// sizes (rss_queues 0: not offered).
    pub rss_hash: u32,
    pub rss_queues: u16,
    pub rss_tx_queues: u16,
    pub rss_key: u16,
    pub rss_table: u16,
}

impl Caps {
    /// Whether the batch commands may be used.
    pub fn batches(&self) -> bool {
        self.present && self.batch_frames > 0
    }

    /// Drop what the spec says cannot stand alone: every frame item rides
    /// on a batch, so without batches there are no checksums, segmentation
    /// or RSS; segmentation needs transmit checksums for its protocols
    /// (TCP over IPv4 also needs the IPv4 header's).
    pub fn sanitize(&mut self) {
        if !self.present || self.version < 1 {
            *self = Caps::default();
            return;
        }
        if self.batch_frames == 0 {
            self.rx_csum = 0;
            self.tx_csum = 0;
            self.seg_protocols = 0;
            self.rss_queues = 0;
        }
        let mut seg = 0;
        if self.seg_protocols & S2XCSUM_TCPV4 != 0 && self.tx_csum & (S2XCSUM_TCPV4 | S2XCSUM_IPV4) == (S2XCSUM_TCPV4 | S2XCSUM_IPV4) {
            seg |= S2XCSUM_TCPV4;
        }
        if self.seg_protocols & S2XCSUM_TCPV6 != 0 && self.tx_csum & S2XCSUM_TCPV6 != 0 {
            seg |= S2XCSUM_TCPV6;
        }
        self.seg_protocols = seg;
        if self.mtu_max < self.mtu_min {
            self.mtu_min = 0;
            self.mtu_max = 0;
        }
    }
}

/// Whether `cmd` is in a 0-terminated NSCMD_DEVICEQUERY command list.
pub fn supports(cmds: impl IntoIterator<Item = u16>, cmd: u16) -> bool {
    cmds.into_iter().take_while(|&c| c != 0).any(|c| c == cmd)
}

/// Read batches to post for `want` frames of one packet type: (batches,
/// frames per batch), each batch at most `prefer` frames and at most what
/// the driver allows.
pub fn plan_reads(want: usize, max_frames: u32, prefer: usize) -> (usize, usize) {
    let per = prefer.min(max_frames as usize).max(1);
    let want = want.max(1);
    (want.div_ceil(per), per)
}

/// What to do with a read batch that came back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadNext {
    /// Post it again (`error`: the batch's own io_Error was not 0).
    Repost { error: bool },
    /// Aborted (the link is closing): leave it.
    Stop,
    /// The driver does not take the command after all: plain CMD_READs
    /// for this packet type instead.
    Fallback,
}

/// A read batch of `count` frames came back with `done` and io_Error
/// `err`: the frames filled (list order, from the first) and what next.
pub fn read_outcome(count: usize, done: u32, err: i8) -> (usize, ReadNext) {
    let filled = (done as usize).min(count);
    let next = match err {
        0 => ReadNext::Repost { error: false },
        IOERR_ABORTED => ReadNext::Stop,
        IOERR_NOCMD | S2ERR_NOT_SUPPORTED if filled == 0 => ReadNext::Fallback,
        _ => ReadNext::Repost { error: true },
    };
    (filled, next)
}

/// What a write batch's reply means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteOutcome {
    /// Frames the driver took, from the first.
    pub sent: usize,
    /// The frame after them was refused (it has the error): dropped and
    /// counted, as a refused CMD_WRITE is.
    pub refused: bool,
    /// The first frame to send again (the rest of the batch is untouched);
    /// `count` when none.
    pub resend_from: usize,
    /// The batch made no progress and refused no frame: write these frames
    /// one by one with CMD_WRITE.
    pub plain: bool,
    /// ... and stop using write batches on this link (the driver does not
    /// take the command).
    pub give_up: bool,
}

/// A write batch of `count` frames came back with `done` and io_Error
/// `err`; `frame_err` is io_Error of frame `done` (when done < count).
pub fn write_outcome(count: usize, done: u32, err: i8, frame_err: i8) -> WriteOutcome {
    let sent = (done as usize).min(count);
    let mut o = WriteOutcome { sent, refused: false, resend_from: count, plain: false, give_up: false };
    if sent == count {
        return o;
    }
    if err != 0 && frame_err != 0 {
        // The spec's refusal: frame `done` has the error, the rest are
        // untouched.
        o.refused = true;
        o.resend_from = sent + 1;
        return o;
    }
    // Fewer taken and no frame refused: send the rest again, unless
    // nothing went at all (a loop otherwise).
    o.resend_from = sent;
    if sent == 0 {
        o.plain = true;
        o.give_up = matches!(err, IOERR_NOCMD | S2ERR_NOT_SUPPORTED);
    }
    o
}

/// smoltcp may skip the IPv4 header checksum of this frame.
pub const TRUST_IP: u8 = 1;
/// smoltcp may skip the TCP or UDP checksum of this frame.
pub const TRUST_L4: u8 = 2;

/// A received frame's checksum result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxCsum {
    /// The card found a bad checksum: drop it.
    Bad,
    /// TRUST_ bits: which checks smoltcp may skip (0: verify as usual).
    Trust(u8),
}

/// The card's S2XFRAME_CHECKSUM result `flags` for an Ethernet `frame`
/// (raw reads: the offsets are the link header's), with the driver's
/// receive protocols `protocols`. A check is skipped only for a protocol
/// the driver says it checks, and the L4 one only for a datagram that is
/// not a fragment (the card cannot check a fragment's TCP or UDP sum, and
/// smoltcp checks the reassembled one).
pub fn rx_csum(flags: u32, protocols: u32, frame: &[u8]) -> RxCsum {
    if flags & (S2XCS_IP_BAD | S2XCS_L4_BAD) != 0 {
        return RxCsum::Bad;
    }
    if flags & (S2XCS_IP_GOOD | S2XCS_L4_GOOD) == 0 || frame.len() < 34 || frame[12] != 0x08 || frame[13] != 0x00 {
        return RxCsum::Trust(0);
    }
    let ip = &frame[14..];
    if ip[0] >> 4 != 4 || ip[0] & 0x0f < 5 {
        return RxCsum::Trust(0);
    }
    let mut t = 0;
    if flags & S2XCS_IP_GOOD != 0 && protocols & S2XCSUM_IPV4 != 0 {
        t |= TRUST_IP;
    }
    let fragment = u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0;
    let l4 = match ip[9] {
        6 => S2XCSUM_TCPV4,
        17 => S2XCSUM_UDPV4,
        _ => 0,
    };
    if flags & S2XCS_L4_GOOD != 0 && !fragment && l4 != 0 && protocols & l4 != 0 {
        t |= TRUST_L4;
    }
    RxCsum::Trust(t)
}

/// The checksums the stack leaves to the card on send, from the driver's
/// transmit protocols: the IPv4 header and TCP over IPv4. UDP is not
/// among them: smoltcp fragments a large datagram itself, and the card
/// cannot sum a datagram over its fragments.
pub fn tx_offload(c: &Caps) -> u32 {
    if !c.batches() {
        return 0;
    }
    c.tx_csum & (S2XCSUM_IPV4 | S2XCSUM_TCPV4)
}

/// What the card is asked to fill in one frame (an S2XFRAME_CHECKSUM
/// item on send): S2XCS_FILL_ bits (0: nothing), and for FILL_L4 where the
/// sum starts and where the result goes (from Start), counted from the
/// first byte of the frame as copied (the Ethernet header: raw writes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxFill {
    pub flags: u32,
    pub start: u16,
    pub offset: u16,
}

/// The 16-bit ones' complement sum of `data` added to `sum`, folded.
fn sum16(mut sum: u32, data: &[u8]) -> u32 {
    let mut c = data.chunks_exact(2);
    for w in &mut c {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    if let [b] = c.remainder() {
        sum += (*b as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

/// The IPv4 pseudo-header's sum (addresses, protocol, `len`), folded,
/// not complemented: what goes in the checksum field for the card.
pub fn pseudo_sum(src: [u8; 4], dst: [u8; 4], proto: u8, len: u16) -> u16 {
    let s = sum16(0, &src);
    let s = sum16(s, &dst);
    sum16(s + proto as u32 + len as u32, &[]) as u16
}

/// Ready an Ethernet `frame` the stack built (its offloaded checksums
/// left 0) for the card: the IPv4 header's sum field 0 for FILL_IP; for
/// TCP over IPv4 (not a fragment, nothing after the datagram) the
/// pseudo-header sum in the TCP checksum field for FILL_L4. Runs after
/// the IP filter and NAT, which may change addresses and ports: what the
/// card sums is the frame as it goes out. `offload`: tx_offload's bits.
pub fn tx_plan(frame: &mut [u8], offload: u32) -> TxFill {
    let mut f = TxFill::default();
    if offload == 0 || frame.len() < 34 || frame[12] != 0x08 || frame[13] != 0x00 {
        return f;
    }
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    if frame[14] >> 4 != 4 || ihl < 20 || frame.len() < 14 + ihl {
        return f;
    }
    if offload & S2XCSUM_IPV4 != 0 {
        frame[24] = 0;
        frame[25] = 0;
        f.flags |= S2XCS_FILL_IP;
    }
    let total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let fragment = u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0;
    if offload & S2XCSUM_TCPV4 != 0 && frame[23] == 6 && !fragment && total >= ihl + 20 && 14 + total == frame.len() {
        let start = 14 + ihl;
        let len = (total - ihl) as u16;
        let src = [frame[26], frame[27], frame[28], frame[29]];
        let dst = [frame[30], frame[31], frame[32], frame[33]];
        frame[start + 16..start + 18].copy_from_slice(&pseudo_sum(src, dst, 6, len).to_be_bytes());
        f.flags |= S2XCS_FILL_L4;
        f.start = start as u16;
        f.offset = 16;
    }
    f
}

/// Do what `fill` asked of the card, in software: for a frame that goes
/// out as a plain CMD_WRITE after all (the driver turned a batch down).
pub fn tx_software(frame: &mut [u8], fill: TxFill) {
    if fill.flags & S2XCS_FILL_IP != 0 && frame.len() >= 34 {
        let ihl = (((frame[14] & 0x0f) as usize) * 4).clamp(20, frame.len() - 14);
        frame[24] = 0;
        frame[25] = 0;
        let s = !(sum16(0, &frame[14..14 + ihl]) as u16);
        frame[24..26].copy_from_slice(&s.to_be_bytes());
    }
    let (start, at) = (fill.start as usize, fill.start as usize + fill.offset as usize);
    if fill.flags & S2XCS_FILL_L4 != 0 && at + 2 <= frame.len() {
        // The field holds the pseudo-header sum: summing from Start to the
        // end takes it in, as the card does.
        let mut s = !(sum16(0, &frame[start..]) as u16);
        if s == 0 && frame.get(23) == Some(&17) {
            s = 0xffff;
        }
        frame[at..at + 2].copy_from_slice(&s.to_be_bytes());
    }
}

/// The largest MTU a link takes (a driver's S2_DEVICEQUERY or an MTU
/// change), as Sana2DeviceQuery's MTU: packet data without the link header.
pub const MTU_MAX: u32 = 16000;

/// The receive and send buffer size for `mtu`: the Ethernet header, the
/// MTU and room for a VLAN tag and the card's spare bytes; never below
/// the 1500-byte MTU's.
pub fn frame_size(mtu: u32) -> usize {
    (mtu.min(MTU_MAX) as usize + 14 + 86).max(1600)
}

/// The unit's settings as the driver reported them (S2X_CONFIGURE with
/// S2XCF_READ, and the values it wrote back after a change). A setting
/// the driver does not offer stays None.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HwSettings {
    pub mtu: Option<u32>,
    /// Microseconds between interrupts, receive and send (0: off).
    pub moderation: Option<(u32, u32)>,
    /// S2XFC_ modes (0: off).
    pub flow_control: Option<u32>,
}

/// What an IFA_LimitMTU / IFC_LimitMTU value asks of a link whose driver
/// MTU is `hw`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtuPlan {
    /// Use this MTU, the driver's staying as it is (Roadshow's meaning:
    /// a limit at most the driver's).
    Limit(u32),
    /// Change the driver's MTU to this (S2XSET_MTU), then use it: a larger
    /// MTU than the driver's, which only a driver with S2XCAP_MTU can do.
    Hardware(u32),
}

/// The plan for `want` (at least 68, IPv4's least).
pub fn mtu_plan(c: &Caps, hw: u32, want: u32) -> MtuPlan {
    let want = want.max(68);
    if want <= hw {
        return MtuPlan::Limit(want);
    }
    if !c.present || c.mtu_max <= hw {
        return MtuPlan::Limit(hw);
    }
    let m = want.min(c.mtu_max).min(MTU_MAX).max(c.mtu_min);
    if m > hw { MtuPlan::Hardware(m) } else { MtuPlan::Limit(hw) }
}

/// "Leave the driver's own value": the stack options' default.
pub const DRIVER_DEFAULT: i32 = -1;

/// The S2XSET_MODERATION values for the stack options `rx` / `tx`
/// (microseconds; DRIVER_DEFAULT: leave), the current ones `cur`: None
/// when there is nothing to change. Values past the driver's longest
/// interval are cut to it; without S2XMOD_TX the receive value applies to
/// both (the spec), so the send one follows it.
pub fn moderation_change(c: &Caps, rx: i32, tx: i32, cur: Option<(u32, u32)>) -> Option<(u32, u32)> {
    if !c.moderation || (rx < 0 && tx < 0) {
        return None;
    }
    let (cr, ct) = cur.unwrap_or((0, 0));
    let clamp = |v: i32, keep: u32| if v < 0 { keep } else { (v as u32).min(c.mod_max_us) };
    let r = clamp(rx, cr);
    let t = if c.mod_flags & S2XMOD_TX != 0 { clamp(tx, ct) } else { r };
    if cur == Some((r, t)) {
        return None;
    }
    Some((r, t))
}

/// The S2XSET_FLOWCONTROL modes for the stack option `v` (S2XFC_ bits;
/// DRIVER_DEFAULT: leave), the current ones `cur`: None when there is
/// nothing to change. Modes the card does not have are left out.
pub fn flow_control_change(c: &Caps, v: i32, cur: Option<u32>) -> Option<u32> {
    if !c.flow_control || v < 0 {
        return None;
    }
    let m = v as u32 & c.fc_modes;
    if cur == Some(m) {
        return None;
    }
    Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn frame(proto: u8, frag: u16) -> Vec<u8> {
        let mut f = alloc::vec![0u8; 60];
        f[12] = 0x08;
        f[14] = 0x45;
        f[20..22].copy_from_slice(&frag.to_be_bytes());
        f[23] = proto;
        f
    }

    const ALL: u32 = S2XCSUM_IPV4 | S2XCSUM_TCPV4 | S2XCSUM_UDPV4;

    #[test]
    fn rx_good_tcp_udp() {
        let g = S2XCS_IP_GOOD | S2XCS_L4_GOOD;
        assert_eq!(rx_csum(g, ALL, &frame(6, 0)), RxCsum::Trust(TRUST_IP | TRUST_L4));
        assert_eq!(rx_csum(g, ALL, &frame(17, 0x4000)), RxCsum::Trust(TRUST_IP | TRUST_L4), "DF is not a fragment");
        assert_eq!(rx_csum(S2XCS_IP_GOOD, ALL, &frame(6, 0)), RxCsum::Trust(TRUST_IP));
    }

    #[test]
    fn rx_not_trusted() {
        let g = S2XCS_IP_GOOD | S2XCS_L4_GOOD;
        assert_eq!(rx_csum(0, ALL, &frame(6, 0)), RxCsum::Trust(0), "not checked");
        assert_eq!(rx_csum(g, ALL, &frame(1, 0)), RxCsum::Trust(TRUST_IP), "ICMP is always verified");
        assert_eq!(rx_csum(g, ALL, &frame(6, 0x2000)), RxCsum::Trust(TRUST_IP), "more fragments");
        assert_eq!(rx_csum(g, ALL, &frame(17, 0x0010)), RxCsum::Trust(TRUST_IP), "a later fragment");
        assert_eq!(rx_csum(g, S2XCSUM_IPV4 | S2XCSUM_UDPV4, &frame(6, 0)), RxCsum::Trust(TRUST_IP), "TCP not offered");
        assert_eq!(rx_csum(g, S2XCSUM_TCPV4, &frame(6, 0)), RxCsum::Trust(TRUST_L4), "IPv4 header not offered");
        let mut arp = frame(6, 0);
        arp[13] = 0x06;
        assert_eq!(rx_csum(g, ALL, &arp), RxCsum::Trust(0));
        let mut v6 = frame(6, 0);
        v6[14] = 0x65;
        assert_eq!(rx_csum(g, ALL, &v6), RxCsum::Trust(0));
        assert_eq!(rx_csum(g, ALL, &frame(6, 0)[..30]), RxCsum::Trust(0), "short");
    }

    #[test]
    fn rx_bad_dropped() {
        assert_eq!(rx_csum(S2XCS_IP_BAD, ALL, &frame(6, 0)), RxCsum::Bad);
        assert_eq!(rx_csum(S2XCS_IP_GOOD | S2XCS_L4_BAD, ALL, &frame(17, 0)), RxCsum::Bad);
        assert_eq!(rx_csum(S2XCS_L4_BAD, 0, &frame(17, 0)), RxCsum::Bad, "the card's verdict, offered or not");
    }

    #[test]
    fn caps_sanitize() {
        let mut c = Caps { present: true, version: 1, batch_frames: 0, rx_csum: ALL, tx_csum: ALL, seg_protocols: S2XCSUM_TCPV4, rss_queues: 4, ..Caps::default() };
        c.sanitize();
        assert!(!c.batches());
        assert_eq!((c.rx_csum, c.tx_csum, c.seg_protocols, c.rss_queues), (0, 0, 0, 0));
        let mut c = Caps { present: true, version: 1, batch_frames: 64, tx_csum: S2XCSUM_TCPV4, seg_protocols: S2XCSUM_TCPV4, ..Caps::default() };
        c.sanitize();
        assert_eq!(c.seg_protocols, 0, "TSO over IPv4 needs the IPv4 header sum too");
        let mut c = Caps { present: true, version: 1, batch_frames: 64, tx_csum: ALL, seg_protocols: S2XCSUM_TCPV4 | S2XCSUM_TCPV6, ..Caps::default() };
        c.sanitize();
        assert_eq!(c.seg_protocols, S2XCSUM_TCPV4);
        let mut c = Caps { present: true, version: 0, batch_frames: 64, ..Caps::default() };
        c.sanitize();
        assert_eq!(c, Caps::default());
        let mut c = Caps { present: true, version: 1, batch_frames: 8, mtu_min: 9000, mtu_max: 1500, ..Caps::default() };
        c.sanitize();
        assert!(c.batches());
        assert_eq!((c.mtu_min, c.mtu_max), (0, 0));
    }

    #[test]
    fn command_list() {
        let l = [0x0002u16, 0x0003, S2X_QUERY, 0, S2X_READBATCH];
        assert!(supports(l, S2X_QUERY));
        assert!(!supports(l, S2X_READBATCH), "after the terminator");
        assert!(!supports([0u16; 0], S2X_QUERY));
    }

    #[test]
    fn reads_plan() {
        assert_eq!(plan_reads(64, 64, 16), (4, 16));
        assert_eq!(plan_reads(64, 8, 16), (8, 8));
        assert_eq!(plan_reads(64, 1, 16), (64, 1));
        assert_eq!(plan_reads(4, 64, 4), (1, 4));
        assert_eq!(plan_reads(10, 4, 16), (3, 4));
        assert_eq!(plan_reads(0, 0, 16), (1, 1));
    }

    #[test]
    fn read_batches() {
        assert_eq!(read_outcome(16, 5, 0), (5, ReadNext::Repost { error: false }));
        assert_eq!(read_outcome(16, 99, 0), (16, ReadNext::Repost { error: false }), "Done past Count");
        assert_eq!(read_outcome(16, 3, IOERR_ABORTED), (3, ReadNext::Stop));
        assert_eq!(read_outcome(16, 0, IOERR_NOCMD), (0, ReadNext::Fallback));
        assert_eq!(read_outcome(16, 0, S2ERR_NOT_SUPPORTED), (0, ReadNext::Fallback));
        assert_eq!(read_outcome(16, 2, IOERR_NOCMD), (2, ReadNext::Repost { error: true }));
        assert_eq!(read_outcome(16, 0, 10), (0, ReadNext::Repost { error: true }));
    }

    /// An Ethernet + IPv4 + TCP frame with `payload` bytes and correct
    /// checksums, summed the plain way (an independent reference).
    fn tcp_frame(payload: usize, frag: u16) -> Vec<u8> {
        tcp_frame_from(payload, frag, [192, 168, 0, 26])
    }

    fn tcp_frame_from(payload: usize, frag: u16, src: [u8; 4]) -> Vec<u8> {
        let total = 20 + 20 + payload;
        let mut f = alloc::vec![0u8; 14 + total];
        f[12] = 0x08;
        f[14] = 0x45;
        f[16..18].copy_from_slice(&(total as u16).to_be_bytes());
        f[18..20].copy_from_slice(&0x1234u16.to_be_bytes());
        f[20..22].copy_from_slice(&frag.to_be_bytes());
        f[22] = 64;
        f[23] = 6;
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&[192, 168, 0, 156]);
        let t = 34;
        f[t..t + 2].copy_from_slice(&4620u16.to_be_bytes());
        f[t + 2..t + 4].copy_from_slice(&80u16.to_be_bytes());
        f[t + 4..t + 8].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
        f[t + 12] = 0x50;
        f[t + 13] = 0x18;
        f[t + 14..t + 16].copy_from_slice(&0xffffu16.to_be_bytes());
        for (i, b) in f[t + 20..].iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        // Reference sums: word by word, carries folded at the end.
        let words = |d: &[u8]| -> u32 { d.chunks(2).map(|w| ((w[0] as u32) << 8) | *w.get(1).unwrap_or(&0) as u32).sum() };
        let fold = |mut s: u32| {
            while s >> 16 != 0 {
                s = (s & 0xffff) + (s >> 16);
            }
            !(s as u16)
        };
        let ip = fold(words(&f[14..34]));
        f[24..26].copy_from_slice(&ip.to_be_bytes());
        let mut ph = Vec::new();
        ph.extend_from_slice(&f[26..34]);
        ph.extend_from_slice(&[0, 6]);
        ph.extend_from_slice(&((total - 20) as u16).to_be_bytes());
        let tcp = fold(words(&ph) + words(&f[t..]));
        f[t + 16..t + 18].copy_from_slice(&tcp.to_be_bytes());
        f
    }

    /// What the card does with an S2XFRAME_CHECKSUM item (virtio-net's
    /// model), for the tests: the same as tx_software.
    fn card(frame: &mut [u8], fill: TxFill) {
        tx_software(frame, fill);
    }

    #[test]
    fn tx_checksum_offload() {
        for payload in [0usize, 1, 2, 3, 1460] {
            let good = tcp_frame(payload, 0x4000);
            let mut f = good.clone();
            // As smoltcp leaves it with the sums off: both fields 0.
            f[24..26].fill(0);
            f[50..52].fill(0);
            let fill = tx_plan(&mut f, S2XCSUM_IPV4 | S2XCSUM_TCPV4);
            assert_eq!(fill, TxFill { flags: S2XCS_FILL_IP | S2XCS_FILL_L4, start: 34, offset: 16 });
            let ph = pseudo_sum([192, 168, 0, 26], [192, 168, 0, 156], 6, (20 + payload) as u16);
            assert_eq!(u16::from_be_bytes([f[50], f[51]]), ph, "pseudo-header sum in the field");
            card(&mut f, fill);
            assert_eq!(f, good, "payload {}", payload);
        }
    }


    #[test]
    fn tx_checksum_after_nat() {
        // NAT rewrote the source address after smoltcp built the frame and
        // adjusted the zero fields incrementally (garbage now): the plan
        // sums the frame as it goes out.
        let good = tcp_frame_from(100, 0, [10, 0, 0, 1]);
        let mut f = good.clone();
        f[24..26].copy_from_slice(&[0x12, 0x34]);
        f[50..52].copy_from_slice(&[0x56, 0x78]);
        let fill = tx_plan(&mut f, S2XCSUM_IPV4 | S2XCSUM_TCPV4);
        card(&mut f, fill);
        assert_eq!(f, good);
    }

    #[test]
    fn tx_checksum_not_offloaded() {
        let mut f = tcp_frame(10, 0);
        let keep = f.clone();
        assert_eq!(tx_plan(&mut f, 0), TxFill::default());
        assert_eq!(tx_plan(&mut f, S2XCSUM_UDPV4), TxFill::default(), "UDP only: nothing for TCP");
        assert_eq!(f, keep);
        let mut frag = tcp_frame(10, 0x2000);
        assert_eq!(tx_plan(&mut frag, S2XCSUM_IPV4 | S2XCSUM_TCPV4).flags, S2XCS_FILL_IP, "fragment: header only");
        let mut padded = tcp_frame(0, 0);
        padded.extend_from_slice(&[0; 6]);
        assert_eq!(tx_plan(&mut padded, S2XCSUM_IPV4 | S2XCSUM_TCPV4).flags, S2XCS_FILL_IP, "padding after the datagram");
        let mut only_tcp = tcp_frame(10, 0);
        let fill = tx_plan(&mut only_tcp, S2XCSUM_TCPV4);
        assert_eq!(fill.flags, S2XCS_FILL_L4);
        assert_eq!(&only_tcp[24..26], &keep[24..26], "IPv4 header sum left alone");
        let mut udp = tcp_frame(10, 0);
        udp[23] = 17;
        assert_eq!(tx_plan(&mut udp, S2XCSUM_IPV4 | S2XCSUM_TCPV4).flags, S2XCS_FILL_IP);
        let mut arp = tcp_frame(10, 0);
        arp[13] = 6;
        assert_eq!(tx_plan(&mut arp, S2XCSUM_IPV4 | S2XCSUM_TCPV4), TxFill::default());
        let c = Caps { present: true, version: 1, batch_frames: 8, tx_csum: S2XCSUM_IPV4 | S2XCSUM_TCPV4 | S2XCSUM_UDPV4, ..Caps::default() };
        assert_eq!(tx_offload(&c), S2XCSUM_IPV4 | S2XCSUM_TCPV4);
        assert_eq!(tx_offload(&Caps { batch_frames: 0, ..c }), 0);
    }

    #[test]
    fn mtu_plans() {
        let jumbo = Caps { present: true, version: 1, mtu_min: 68, mtu_max: 9000, ..Caps::default() };
        let plain = Caps::default();
        assert_eq!(mtu_plan(&plain, 1500, 1400), MtuPlan::Limit(1400));
        assert_eq!(mtu_plan(&plain, 1500, 9000), MtuPlan::Limit(1500), "plain SANA-II: at most the driver's");
        assert_eq!(mtu_plan(&plain, 1500, 10), MtuPlan::Limit(68));
        assert_eq!(mtu_plan(&jumbo, 1500, 9000), MtuPlan::Hardware(9000));
        assert_eq!(mtu_plan(&jumbo, 1500, 20000), MtuPlan::Hardware(9000), "cut to the driver's most");
        assert_eq!(mtu_plan(&jumbo, 9000, 1500), MtuPlan::Limit(1500), "lower: a limit, the card keeps 9000");
        assert_eq!(mtu_plan(&jumbo, 9000, 9000), MtuPlan::Limit(9000));
        let odd = Caps { mtu_min: 2000, mtu_max: 4000, ..jumbo };
        assert_eq!(mtu_plan(&odd, 1500, 1600), MtuPlan::Hardware(2000), "raised to the driver's least");
        assert_eq!(frame_size(1500), 1600);
        assert_eq!(frame_size(9000), 9100);
        assert_eq!(frame_size(60000), MTU_MAX as usize + 100);
    }

    #[test]
    fn moderation_and_flow_control() {
        let c = Caps { present: true, version: 1, moderation: true, mod_max_us: 1000, mod_flags: S2XMOD_RX | S2XMOD_TX, flow_control: true, fc_modes: S2XFC_RX | S2XFC_TX, ..Caps::default() };
        assert_eq!(moderation_change(&c, -1, -1, Some((50, 50))), None, "both left to the driver");
        assert_eq!(moderation_change(&c, 100, -1, Some((50, 20))), Some((100, 20)));
        assert_eq!(moderation_change(&c, 5000, 0, Some((50, 20))), Some((1000, 0)), "cut to the longest");
        assert_eq!(moderation_change(&c, 50, 20, Some((50, 20))), None, "no change");
        let rx_only = Caps { mod_flags: S2XMOD_RX, ..c };
        assert_eq!(moderation_change(&rx_only, 100, 7, Some((50, 50))), Some((100, 100)), "send follows receive");
        assert_eq!(moderation_change(&Caps { moderation: false, ..c }, 100, 100, None), None);
        assert_eq!(flow_control_change(&c, -1, Some(3)), None);
        assert_eq!(flow_control_change(&c, 0, Some(3)), Some(0));
        assert_eq!(flow_control_change(&c, 7, Some(0)), Some(S2XFC_RX | S2XFC_TX), "auto not offered");
        assert_eq!(flow_control_change(&c, 3, Some(3)), None);
        assert_eq!(flow_control_change(&Caps { flow_control: false, ..c }, 3, None), None);
    }

    #[test]
    fn write_batches() {
        let all = write_outcome(8, 8, 0, 0);
        assert_eq!((all.sent, all.refused, all.resend_from, all.plain), (8, false, 8, false));
        let r = write_outcome(8, 3, 11, 11);
        assert_eq!((r.sent, r.refused, r.resend_from, r.plain), (3, true, 4, false), "frame 3 refused, 4..8 again");
        let r = write_outcome(8, 7, 11, 11);
        assert_eq!((r.sent, r.refused, r.resend_from), (7, true, 8), "the last one refused");
        let r = write_outcome(8, 0, 11, 11);
        assert_eq!((r.sent, r.refused, r.resend_from, r.plain), (0, true, 1, false));
        let r = write_outcome(8, 5, 0, 0);
        assert_eq!((r.sent, r.refused, r.resend_from, r.plain), (5, false, 5, false), "short without error: the rest again");
        let r = write_outcome(8, 0, IOERR_NOCMD, 0);
        assert_eq!((r.sent, r.resend_from, r.plain, r.give_up), (0, 0, true, true));
        let r = write_outcome(8, 0, 4, 0);
        assert_eq!((r.plain, r.give_up), (true, false), "no progress, no frame error");
    }
}
