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
