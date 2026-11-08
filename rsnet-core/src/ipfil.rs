//! IP Filter 3.4.21's kernel side, as Roadshow has it: the rule lists that
//! ipf loads (ipf_ioctl on minor IPL_LOGIPF), the statistics ipfstat shows,
//! keep state, keep frags, accounting rules and rule groups, run on every
//! IPv4 datagram an interface receives or sends once ipf -E has switched it
//! on (ipf.rs calls [`check`] before the IP_FILTER_HOOK).
//!
//! The ABI is the SDK's netinet/ip_fil.h (pack(2), big-endian bitfields:
//! a frentry is 252 bytes) and what Roadshow 1.15 answers, measured with
//! testprogs/rstcp/c/ipfprobe.c and ipf's own messages:
//! handles 0x60000000 + minor; a rule is kept as the caller's frentry with
//! fr_next / fr_grp / fr_ref / fr_ifa / fr_hits / fr_bytes / fr_cksum
//! filled in (fr_cksum = the 32-bit sum of the words from fr_ip up to
//! fr_cksum), so a tool can walk the lists from SIOCGETFS's pointers;
//! duplicate add EEXIST, missing remove or group ESRCH; f_defpass
//! FR_PASS|FR_NOMATCH; an unknown interface name gives fr_ifa -1 (re-read by
//! SIOCFRSYN, ipf -y).
//!
//! The matching follows 3.4.21's fr_scanlist / fr_tcpudpchk / fr_makefrip
//! (the masked fr_ip words, FR_NOTSRCIP / FR_NOTDSTIP, port comparisons,
//! TCP flags, ICMP type/code, skip, quick, group heads). Keep state is
//! simpler than 3.4's: a flow's addresses and ports (ICMP queries by id),
//! TCP by its flags only (no sequence-window check), and ICMP errors that
//! carry a known flow's header.
//!
//! The log (ipmon reads it: ipf_ioctl FIONREAD, then ipf_log_read) holds
//! records as Roadshow writes them (measured with ipfprobe log 0):
//! struct iplog (24 bytes: 'IPLM', count 1, Unix seconds and microseconds,
//! ipl_dsize = the whole record, next 0), struct ipflog (36: the interface
//! name without a unit number, fl_plen, fl_hlen, fl_loglevel (0xffff by
//! default), fl_rule 0-based in its list, fl_group, fl_flags the pass
//! flags, fl_lflags 0), then the datagram's IP header with its checksum
//! field 0 (as BSD's ip_input leaves it) and the transport header (TCP 20,
//! UDP 8, ICMP 28, an ICMP error 36 bytes, at most what there is), and
//! with "log body" up to 128 bytes more. 8192 bytes per minor (IPLLOGSIZE);
//! a record that does not fit is a log failure. Unlike Roadshow, opening a
//! minor is never refused: there, once a program has read the log, the
//! minor stays "busy" for everyone until the next boot (ipf_close never
//! lets go).
//!
//! A blocked datagram that came in under "return-rst" (TCP, not short, not
//! itself a reset) is answered with a reset, and under "return-icmp" with
//! an ICMP unreachable of the rule's code quoting its header and 8 bytes
//! (3.4's send_reset / send_icmp_err): [`check`] hands the reply back for
//! the interface to send. As in 3.4, ipfstat's "ICMP replies" is fr_ret of
//! the input statistics, "TCP RSTs sent" fr_ret of the output ones.
//!
//! Auth (3.4's ip_auth.c, measured on Roadshow with
//! testprogs/rstcp/c/authprobe.c): a
//! datagram that meets an "auth" rule is held (32 at most, 300 s) instead
//! of passed or blocked; SIOCAUTHW on minor IPL_LOGAUTH hands the oldest
//! one out as struct frauth (96 bytes: fra_age in half-seconds left,
//! fra_index, fra_pass, struct fr_info), waiting while none is held (the
//! opener's break signals end the wait with EINTR and stay set); SIOCAUTHR
//! takes the program's verdict in fra_pass and sends the datagram on again
//! (fra_info.fin_out: out of its interface, else into the stack), where
//! [`check`] finds the verdict (fr_checkauth: same fin_id and fr_info up to
//! fin_icode) before any rule. fr_authstat is 40 bytes (4-byte counters):
//! hits, miss (each datagram checked while one is held that is not its
//! answer, or a preauth rule with no auth rule to match), nospace, added,
//! sendfail, sendok, queok, quefail, expire, the auth rule list. "preauth"
//! rules look up the rules a program adds with SIOCADAFR on IPL_LOGAUTH.
//! Every IPL_LOGAUTH command answers EIO while the filter is off, as on
//! Roadshow. Unlike Roadshow, a program already waiting in SIOCAUTHW is
//! woken when a datagram is held (Roadshow's sleeps on until its break,
//! though the datagram is queued), and ipf -D empties the queue.
//!
//! "to <if>[:ip]" sends a datagram a rule passes out of that interface
//! instead (to ip, else to its destination, by the interface's ARP table
//! or its router), "dup-to" sends a copy that way too (3.4's
//! ipfr_fastroute, measured on Roadshow: two datagrams arrive for each
//! dup-to send, and each "to" or dup copy counts as a fastroute success in
//! friostat's f_froute). The datagram or copy leaves without the filter's
//! rules (as 3.4 sends it straight to the interface); an interface name no
//! interface has stays -1 and the datagram goes the normal way. Names are
//! looked up as Roadshow's ipf does: case does not matter, and the
//! loopback interface is "loopback" (stack.rs). "fastroute" without "to"
//! counts the datagram as fastrouted and lets it go the normal way
//! (forwarding goes by the routing table: forward.rs).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use amigaos4::sync::{Mutex, MutexGuard};

// ---------------------------------------------------------------------------
// The SDK's numbers
// ---------------------------------------------------------------------------

pub const IPL_LOGIPF: u32 = 0;
pub const IPL_LOGNAT: u32 = 1;
pub const IPL_LOGSTATE: u32 = 2;
pub const IPL_LOGAUTH: u32 = 3;

pub const SIOCADAFR: u32 = 0x8004_723C;
pub const SIOCRMAFR: u32 = 0x8004_723D;
pub const SIOCSETFF: u32 = 0x8004_723E;
pub const SIOCGETFF: u32 = 0x4004_723F;
pub const SIOCGETFS: u32 = 0xC004_7240;
pub const SIOCIPFFL: u32 = 0xC004_7241;
pub const SIOCIPFFB: u32 = 0x4004_7242;
pub const SIOCADIFR: u32 = 0x8004_7243;
pub const SIOCRMIFR: u32 = 0x8004_7244;
pub const SIOCSWAPA: u32 = 0x4004_7245;
pub const SIOCINAFR: u32 = 0x8004_7246;
pub const SIOCINIFR: u32 = 0x8004_7247;
pub const SIOCFRENB: u32 = 0x8004_7248;
pub const SIOCFRSYN: u32 = 0x8004_7249;
pub const SIOCFRZST: u32 = 0xC004_724A;
pub const SIOCZRLST: u32 = 0xC004_724B;
pub const SIOCATHST: u32 = 0xC004_724E;
pub const SIOCGFRST: u32 = 0xC004_7253;
/// ip_nat.h: _IOWR('r', 62, struct natstat *).
pub const SIOCGNATS: u32 = 0xC004_723E;

const FR_BLOCK: u32 = 0x1;
const FR_PASS: u32 = 0x2;
const FR_OUTQUE: u32 = 0x4;
const FR_INQUE: u32 = 0x8;
const FR_LOG: u32 = 0x10;
const FR_LOGB: u32 = 0x11;
const FR_LOGP: u32 = 0x12;
const FR_LOGMASK: u32 = 0x13;
const FR_LOGBODY: u32 = 0x20;
const FR_LOGFIRST: u32 = 0x40;
const FR_RETRST: u32 = 0x80;
const FR_RETICMP: u32 = 0x100;
const FR_NOMATCH: u32 = 0x200;
const FR_ACCOUNT: u32 = 0x400;
const FR_KEEPFRAG: u32 = 0x800;
const FR_KEEPSTATE: u32 = 0x1000;
const FR_INACTIVE: u32 = 0x2000;
const FR_QUICK: u32 = 0x4000;
const FR_NOTSRCIP: u32 = 0x80000;
const FR_NOTDSTIP: u32 = 0x100000;
const FR_LOGORBLOCK: u32 = 0x40000;
const FR_DONTCACHE: u32 = 0x800000;
const FR_AUTH: u32 = 0x200000;
const FR_FASTROUTE: u32 = 0x8000;
const FR_DUP: u32 = 0x20000;
const FR_PREAUTH: u32 = 0x400000;
const FF_LOGPASS: u32 = 0x1000_0000;
const FF_LOGBLOCK: u32 = 0x2000_0000;
const FF_LOGNOMATCH: u32 = 0x4000_0000;
const FF_LOGGING: u32 = 0x7000_0000;
/// sys/filio.h: how many log bytes wait (ipmon polls it).
pub const FIONREAD: u32 = 0x4004_667F;
/// IPLLOGSIZE: the log's size per minor.
const LOGSIZE: usize = 8192;
const IPL_MAGIC: u32 = 0x4950_4C4D;
/// 1978-01-01 (the Amiga's epoch) in Unix seconds.
const AMIGA_EPOCH: u32 = 252_460_800;

/// fi_fl bits (the packet's, in the second nibble of fr_ip's first word).
const FI_OPTIONS: u8 = 0x1;
const FI_TCPUDP: u8 = 0x2;
const FI_FRAG: u8 = 0x4;
const FI_SHORT: u8 = 0x8;

const FR_EQUAL: u32 = 1;
const FR_NEQUAL: u32 = 2;
const FR_LESST: u32 = 3;
const FR_GREATERT: u32 = 4;
const FR_LESSTE: u32 = 5;
const FR_GREATERTE: u32 = 6;
const FR_OUTRANGE: u32 = 7;
const FR_INRANGE: u32 = 8;

pub const ENXIO: i32 = 6;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EINVAL: i32 = 22;
pub const ESRCH: i32 = 3;
pub const EIO: i32 = 5;
pub const EINTR: i32 = 4;

/// ip_fil.h: _IOWR('r', 76 / 77, struct frauth_t *).
pub const SIOCAUTHW: u32 = 0xC004_724C;
pub const SIOCAUTHR: u32 = 0xC004_724D;
/// ip_auth.h: FR_NUMAUTH; struct frauth; struct fr_info and the part of it
/// fr_checkauth compares (FI_CSIZE, up to fin_icode).
const FR_NUMAUTH: usize = 32;
pub const FRAUTH: usize = 96;
const FRINFO: usize = 84;
const FI_CSIZE: usize = 57;
/// fr_defaultauthage: 600 half-seconds, for a held datagram and a preauth
/// rule alike.
const AUTH_AGE: i32 = 600;
const AUTH_US: u64 = 300_000_000;

/// struct frentry and its fields' offsets.
pub const FRENTRY: usize = 252;
const O_NEXT: usize = 0;
const O_GRP: usize = 4;
const O_REF: usize = 8;
const O_IFA: usize = 12;
const O_OIFA: usize = 16;
const O_HITS: usize = 20;
const O_BYTES: usize = 24;
const O_IP: usize = 28;
const O_MIP: usize = 72;
const O_ICMPM: usize = 116;
const O_ICMP: usize = 118;
const O_TCPFM: usize = 120;
const O_TCPF: usize = 121;
const O_SCMP: usize = 122;
const O_SPORT: usize = 126;
const O_STOP: usize = 128;
const O_DCMP: usize = 130;
const O_DPORT: usize = 134;
const O_DTOP: usize = 136;
const O_GROUP: usize = 138;
const O_GRHEAD: usize = 142;
const O_FLAGS: usize = 146;
const O_SKIP: usize = 150;
const O_LOGLEVEL: usize = 154;
const O_ICODE: usize = 166;
const O_IFNAME: usize = 167;
const O_OIFNAME: usize = 183;
const O_TIF_IFP: usize = 200;
const O_TIF_IP: usize = 204;
const O_TIF_NAME: usize = 208;
const O_DIF_IFP: usize = 224;
const O_DIF_IP: usize = 228;
const O_DIF_NAME: usize = 232;
const O_CKSUM: usize = 248;
/// struct friostat: 348 bytes; struct frgroup: 16.
pub const FRIOSTAT: usize = 348;
const FRGROUP: usize = 16;
/// struct ipfrstat (SIOCGFRST), struct ips_stat (state SIOCGETFS), struct
/// natstat, struct fr_authstat: the sizes Roadshow's tools read.
pub const IPFRSTAT: usize = 32;
pub const IPS_STAT: usize = 60;
pub const NATSTAT: usize = 76;
pub const AUTHSTAT: usize = 40;

/// The version string SIOCGETFS reports (ipf -V's "Kernel:").
const VERSION: &[u8] = b"IP Filter: v3.4.21";

/// Timeouts, in seconds (3.4's, which count half-seconds).
const TCP_SYN_S: u64 = 120;
const TCP_IDLE_S: u64 = 5 * 24 * 3600;
const TCP_HALFCLOSED_S: u64 = 120;
const TCP_CLOSED_S: u64 = 60;
const TCP_RESET_S: u64 = 30;
const UDP_S: u64 = 120;
const ICMP_S: u64 = 60;
const FRAG_S: u64 = 60;
/// 3.4's IPSTATE_MAX and IPFT_SIZE-ish limits.
const STATE_MAX: usize = 4013;
const FRAG_MAX: usize = 257;

// ---------------------------------------------------------------------------
// Big-endian byte access
// ---------------------------------------------------------------------------

fn g16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn g32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn p32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_be_bytes());
}

fn p16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_be_bytes());
}

/// A NUL-terminated name in 16 bytes.
fn name16(b: &[u8], o: usize) -> &[u8] {
    let s = &b[o..o + 16];
    let n = s.iter().position(|&c| c == 0).unwrap_or(16);
    &s[..n]
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// One frentry in C memory, kept for the tools to walk (MEMF_SHARED: the
/// library's allocator).
struct Mem(NonNull<[u8; FRENTRY]>);

impl Mem {
    fn new(b: &[u8; FRENTRY]) -> Mem {
        Mem(NonNull::from(Box::leak(Box::new(*b))))
    }

    fn addr(&self) -> u32 {
        self.0.as_ptr() as usize as u32
    }

    fn bytes(&mut self) -> &mut [u8; FRENTRY] {
        // SAFETY: ours (made by `new`, freed by Drop), used under the
        // engine's mutex.
        unsafe { self.0.as_mut() }
    }

    /// Add `n` to the big-endian counter at `o` (fr_hits, fr_bytes) while
    /// the rule is only borrowed: through the raw pointer, no reference to
    /// the C copy being live.
    fn bump(&self, o: usize, n: u32) {
        // SAFETY: our allocation of FRENTRY bytes, o + 4 <= FRENTRY; only
        // touched under the engine's mutex.
        unsafe {
            let q = (self.0.as_ptr() as *mut u8).add(o);
            let mut b = [0u8; 4];
            core::ptr::copy_nonoverlapping(q, b.as_mut_ptr(), 4);
            let v = u32::from_be_bytes(b).wrapping_add(n).to_be_bytes();
            core::ptr::copy_nonoverlapping(v.as_ptr(), q, 4);
        }
    }
}

impl Drop for Mem {
    fn drop(&mut self) {
        // SAFETY: made by Box::leak in `new`, freed once here.
        drop(unsafe { Box::from_raw(self.0.as_ptr()) });
    }
}

// SAFETY: the memory is only touched under the engine's mutex.
unsafe impl Send for Mem {}

/// A rule: its stored frentry and the fields the matcher reads.
struct Rule {
    mem: Mem,
    /// The caller's bytes from fr_ip on (fr_cksum set): what a remove or
    /// SIOCZRLST compares with.
    orig: Box<[u8; FRENTRY - O_IP]>,
    cksum: u32,
    ip: [u32; 5],
    mask: [u32; 5],
    icmpm: u16,
    icmp: u16,
    tcpfm: u8,
    tcpf: u8,
    scmp: u32,
    sport: u16,
    stop: u16,
    dcmp: u32,
    dport: u16,
    dtop: u16,
    group: u32,
    grhead: u32,
    flags: u32,
    skip: u32,
    loglevel: u16,
    icode: u8,
    ifname: [u8; 16],
    oifname: [u8; 16],
    ifa: u32,
    /// fr_tif and fr_dif once looked up: (ifnet or 0 / -1, fd_ip).
    tif: (u32, u32),
    dif: (u32, u32),
}

impl Rule {
    /// From a caller's frentry: fr_cksum computed, the rest as given.
    fn new(user: &[u8; FRENTRY]) -> Rule {
        let mut b = *user;
        p32(&mut b, O_CKSUM, 0);
        let mut sum = 0u32;
        let mut o = O_IP;
        while o < O_CKSUM {
            sum = sum.wrapping_add(g32(&b, o));
            o += 4;
        }
        p32(&mut b, O_CKSUM, sum);
        let mut orig = Box::new([0u8; FRENTRY - O_IP]);
        orig.copy_from_slice(&b[O_IP..]);
        // fr_ip's words: v/fl/tos/ttl/p, src (i6[0]), dst, optmsk, secmsk/auth.
        let words = |b: &[u8; FRENTRY], base: usize| [g32(b, base), g32(b, base + 4), g32(b, base + 20), g32(b, base + 36), g32(b, base + 40)];
        let (ip, mask) = (words(&b, O_IP), words(&b, O_MIP));
        let mut ifname = [0u8; 16];
        ifname.copy_from_slice(&b[O_IFNAME..O_IFNAME + 16]);
        let mut oifname = [0u8; 16];
        oifname.copy_from_slice(&b[O_OIFNAME..O_OIFNAME + 16]);
        // The kernel's own fields start clear.
        for o in [O_NEXT, O_GRP, O_IFA, O_OIFA, O_HITS, O_BYTES, O_TIF_IFP, O_DIF_IFP] {
            p32(&mut b, o, 0);
        }
        p32(&mut b, O_REF, 1);
        Rule {
            ip,
            mask,
            icmpm: g16(&b, O_ICMPM),
            icmp: g16(&b, O_ICMP),
            tcpfm: b[O_TCPFM],
            tcpf: b[O_TCPF],
            scmp: g32(&b, O_SCMP),
            sport: g16(&b, O_SPORT),
            stop: g16(&b, O_STOP),
            dcmp: g32(&b, O_DCMP),
            dport: g16(&b, O_DPORT),
            dtop: g16(&b, O_DTOP),
            group: g32(&b, O_GROUP),
            grhead: g32(&b, O_GRHEAD),
            flags: g32(&b, O_FLAGS),
            skip: g32(&b, O_SKIP),
            loglevel: g32(&b, O_LOGLEVEL) as u16,
            icode: b[O_ICODE],
            ifname,
            oifname,
            ifa: 0,
            tif: (0, 0),
            dif: (0, 0),
            cksum: sum,
            orig,
            mem: Mem::new(&b),
        }
    }

    fn same(&self, other: &Rule) -> bool {
        self.cksum == other.cksum && self.orig[..] == other.orig[..]
    }

    /// Look the interface names up again (at add and SIOCFRSYN): 0 for
    /// none, the interface's ifnet, or -1 for a name no interface has.
    fn resolve(&mut self) {
        let look = |n: &[u8; 16]| -> u32 {
            let s = name16(n, 0);
            if s.is_empty() {
                0
            } else {
                crate::ipf::ifnet_by_name(s).unwrap_or(u32::MAX)
            }
        };
        self.ifa = look(&self.ifname);
        let oifa = look(&self.oifname);
        let tif = {
            let b = *self.mem.bytes();
            let mut n = [0u8; 16];
            n.copy_from_slice(&b[O_TIF_NAME..O_TIF_NAME + 16]);
            let t = look(&n);
            n.copy_from_slice(&b[O_DIF_NAME..O_DIF_NAME + 16]);
            (t, look(&n))
        };
        let ifa = self.ifa;
        // FR_DUP only when the dup-to interface is there (3.4's frrequest).
        let real = |p: u32| p != 0 && p != u32::MAX;
        self.flags = (self.flags & !FR_DUP) | if real(tif.1) { FR_DUP } else { 0 };
        let flags = self.flags;
        let b = self.mem.bytes();
        p32(b, O_IFA, ifa);
        p32(b, O_OIFA, oifa);
        p32(b, O_TIF_IFP, tif.0);
        p32(b, O_DIF_IFP, tif.1);
        p32(b, O_FLAGS, flags);
        self.tif = (tif.0, g32(b, O_TIF_IP));
        self.dif = (tif.1, g32(b, O_DIF_IP));
        // fr_cksum as Roadshow keeps it: over the looked-up rule.
        p32(b, O_CKSUM, 0);
        let mut sum = 0u32;
        let mut o = O_IP;
        while o < O_CKSUM {
            sum = sum.wrapping_add(g32(b, o));
            o += 4;
        }
        p32(b, O_CKSUM, sum);
    }

    /// The list a rule goes on: 0 in, 1 out, 2 accounting in, 3 accounting
    /// out; and its group table (0 in, 1 out, 2 accounting).
    fn kind(&self) -> (usize, usize) {
        let out = (self.flags & FR_INQUE == 0) as usize;
        if self.flags & FR_ACCOUNT != 0 {
            (2 + out, 2)
        } else {
            (out, out)
        }
    }
}

/// A group: its number, the table it is in, the head rule (an address in
/// some list) and its own rules; and its struct frgroup.
struct Group {
    num: u32,
    table: usize,
    head: u32,
    rules: Vec<Rule>,
    mem: NonNull<[u8; FRGROUP]>,
}

impl Group {
    fn new(num: u32, table: usize, head: u32) -> Group {
        Group { num, table, head, rules: Vec::new(), mem: NonNull::from(Box::leak(Box::new([0u8; FRGROUP]))) }
    }

    fn addr(&self) -> u32 {
        self.mem.as_ptr() as usize as u32
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        // SAFETY: made by Box::leak in `new`, freed once here.
        drop(unsafe { Box::from_raw(self.mem.as_ptr()) });
    }
}

// SAFETY: as Mem.
unsafe impl Send for Group {}

#[derive(Default)]
struct Set {
    lists: [Vec<Rule>; 4],
    groups: Vec<Group>,
}

impl Set {
    fn group(&self, table: usize, num: u32) -> Option<usize> {
        self.groups.iter().position(|g| g.table == table && g.num == num)
    }

    /// Chain the C copies: fr_next along each list, a head's fr_grp to its
    /// group's first rule, fr_ref, and the frgroup records (fg_num,
    /// fg_next, fg_head, fg_start).
    fn relink(&mut self) {
        fn chain(rules: &mut [Rule]) {
            let addrs: Vec<u32> = rules.iter().map(|r| r.mem.addr()).collect();
            for (k, r) in rules.iter_mut().enumerate() {
                let next = addrs.get(k + 1).copied().unwrap_or(0);
                let b = r.mem.bytes();
                p32(b, O_NEXT, next);
                p32(b, O_GRP, 0);
                p32(b, O_REF, 1);
            }
        }
        for l in self.lists.iter_mut() {
            chain(l);
        }
        let heads: Vec<(u32, u32, u32)> = self
            .groups
            .iter_mut()
            .map(|g| {
                chain(&mut g.rules);
                (g.head, g.rules.first().map(|r| r.mem.addr()).unwrap_or(0), g.rules.len() as u32)
            })
            .collect();
        for (head, first, n) in heads {
            for l in self.lists.iter_mut().chain(self.groups.iter_mut().map(|g| &mut g.rules)) {
                if let Some(r) = l.iter_mut().find(|r| r.mem.addr() == head) {
                    let b = r.mem.bytes();
                    p32(b, O_GRP, first);
                    p32(b, O_REF, 1 + n);
                }
            }
        }
        for t in 0..3 {
            let addrs: Vec<u32> = self.groups.iter().filter(|g| g.table == t).map(|g| g.addr()).collect();
            let mut k = 0;
            for g in self.groups.iter_mut().filter(|g| g.table == t) {
                let next = addrs.get(k + 1).copied().unwrap_or(0);
                k += 1;
                let (num, head) = (g.num, g.head);
                // SAFETY: the group's own record (Group::new).
                let m = unsafe { g.mem.as_mut() };
                p32(m, 0, num);
                p32(m, 4, next);
                p32(m, 8, head);
                // fg_start: the address of the head's fr_grp.
                p32(m, 12, if head != 0 { head + O_GRP as u32 } else { 0 });
            }
        }
    }

    fn first_group(&self, table: usize) -> u32 {
        self.groups.iter().find(|g| g.table == table).map(|g| g.addr()).unwrap_or(0)
    }

    /// Remove every rule (and group) of the lists in `which` (indexes into
    /// `lists`): how many rules went.
    fn flush(&mut self, which: &[usize]) -> u32 {
        let mut n = 0;
        for &k in which {
            n += self.lists[k].len() as u32;
            self.lists[k].clear();
            let table = if k >= 2 { 2 } else { k };
            self.groups.retain(|g| {
                if g.table == table {
                    n += g.rules.len() as u32;
                    false
                } else {
                    true
                }
            });
        }
        n
    }
}

// ---------------------------------------------------------------------------
// The packet summary (fr_info)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct Fin {
    ifp: u32,
    /// fr_ip's words: v/fl/tos/ttl/p, src, dst, optmsk, secmsk/auth.
    w: [u32; 5],
    data: [u16; 2],
    hlen: u16,
    tcpf: u8,
    p: u8,
    fl: u8,
    /// The fragment offset in bytes; the total and data lengths; the id.
    off: u16,
    plen: u16,
    dlen: u16,
    id: u16,
    /// 0 in, 1 out.
    out: usize,
    rule: u32,
    group: u32,
    fr: u32,
    /// The matched rule's fr_loglevel (0xffff: none).
    loglevel: u16,
    icode: u8,
    /// A look ahead ([`blocks`]): nothing is counted, logged or kept.
    dry: bool,
    /// The matched rule's fr_tif and fr_dif (Rule::tif, Rule::dif).
    dest: [(u32, u32); 2],
}

impl Fin {
    /// struct fr_info as SIOCAUTHW hands it out (84 bytes): `dp` and `mp`
    /// point into the held frame. fin_off is the IP header's offset field.
    fn fr_info(&self, dp: u32, mp: u32) -> [u8; FRINFO] {
        let mut b = [0u8; FRINFO];
        p32(&mut b, 0, self.ifp);
        p32(&mut b, 4, self.w[0]);
        p32(&mut b, 8, self.w[1]);
        p32(&mut b, 24, self.w[2]);
        p32(&mut b, 40, self.w[3]);
        p32(&mut b, 44, self.w[4]);
        p16(&mut b, 48, self.data[0]);
        p16(&mut b, 50, self.data[1]);
        b[52] = self.out as u8;
        p16(&mut b, 54, self.hlen);
        b[56] = self.tcpf;
        b[57] = self.icode;
        p16(&mut b, 58, self.rule as u16);
        p32(&mut b, 60, self.group);
        p32(&mut b, 64, self.fr);
        p32(&mut b, 68, dp);
        p16(&mut b, 72, self.dlen);
        p16(&mut b, 74, self.id);
        p32(&mut b, 76, mp);
        p16(&mut b, 80, self.plen);
        p16(&mut b, 82, self.off >> 3);
        b
    }

    fn src(&self) -> u32 {
        self.w[1]
    }

    fn dst(&self) -> u32 {
        self.w[2]
    }
}

/// IP options -> fi_optmsk (3.4's ipopts table) and the security option's
/// class -> fi_secmsk.
const IPOPTS: [(u8, u32); 19] = [
    (1, 0x1),
    (7, 0x2),
    (10, 0x4),
    (11, 0x8),
    (12, 0x10),
    (15, 0x20),
    (68, 0x40),
    (82, 0x80),
    (130, 0x100),
    (131, 0x200),
    (133, 0x400),
    (134, 0x800),
    (136, 0x1000),
    (137, 0x2000),
    (147, 0x4000),
    (142, 0x8000),
    (144, 0x10000),
    (145, 0x20000),
    (205, 0x40000),
];
const SECCLASS: [(u8, u16); 8] = [(0x01, 0x01), (0x3d, 0x02), (0x5a, 0x04), (0x66, 0x08), (0x96, 0x10), (0xab, 0x20), (0xcc, 0x40), (0xf1, 0x80)];

/// fr_makefrip: the summary of an IPv4 datagram, or None for one too
/// broken to look at (it is passed as it is).
fn makefrip(ifp: u32, ip: &[u8], out: usize) -> Option<Fin> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let hl = ((ip[0] & 15) as usize) * 4;
    let len = (g16(ip, 2) as usize).min(ip.len());
    if hl < 20 || len < hl {
        return None;
    }
    let offf = g16(ip, 6);
    let off = (offf & 0x1fff) << 3;
    let p = ip[9];
    let mut fin = Fin { ifp, out, rule: u32::MAX, loglevel: 0xffff, hlen: hl as u16, p, off, plen: len as u16, dlen: (len - hl) as u16, id: g16(ip, 4), ..Fin::default() };
    let mut fl = 0u8;
    if offf & 0x3fff != 0 {
        fl |= FI_FRAG;
    }
    let (mut optmsk, mut secmsk, mut auth) = (0u32, 0u16, 0u16);
    if hl > 20 {
        fl |= FI_OPTIONS;
        let mut k = 20;
        while k < hl {
            let opt = ip[k];
            if opt == 0 {
                break;
            }
            let ol = if opt == 1 { 1 } else if k + 1 < hl { (ip[k + 1] as usize).max(2) } else { break };
            if let Some(&(_, bit)) = IPOPTS.iter().find(|&&(o, _)| o == opt) {
                optmsk |= bit;
            }
            if opt == 130 && ol >= 4 && k + 3 < hl {
                if let Some(&(_, s)) = SECCLASS.iter().find(|&&(c, _)| c == ip[k + 2]) {
                    secmsk |= s;
                }
                auth = ip[k + 3] as u16;
            }
            k += ol;
        }
    }
    let d = &ip[hl..len];
    let dl = d.len();
    match p {
        6 => {
            fl |= FI_TCPUDP;
            if (off == 0 && dl < 20) || (off != 0 && off < 20) {
                fl |= FI_SHORT;
            }
            if off == 0 && dl >= 4 {
                fin.data = [g16(d, 0), g16(d, 2)];
            }
            if off == 0 && dl >= 14 {
                fin.tcpf = d[13];
            }
        }
        17 => {
            fl |= FI_TCPUDP;
            if (off == 0 && dl < 8) || (off != 0 && off < 8) {
                fl |= FI_SHORT;
            }
            if off == 0 && dl >= 4 {
                fin.data = [g16(d, 0), g16(d, 2)];
            }
        }
        1 => {
            let min = if off == 0 && dl >= 1 && (d[0] == 0 || d[0] == 8) { 8 } else { 28 };
            if (off == 0 && dl < min) || (off != 0 && off < 28) {
                fl |= FI_SHORT;
            }
            if off == 0 && dl > 1 {
                fin.data[0] = g16(d, 0);
            }
        }
        _ => {}
    }
    fin.fl = fl;
    fin.w = [
        (4u32 << 28) | ((fl as u32) << 24) | ((ip[1] as u32) << 16) | ((ip[8] as u32) << 8) | p as u32,
        g32(ip, 12),
        g32(ip, 16),
        optmsk,
        ((secmsk as u32) << 16) | auth as u32,
    ];
    Some(fin)
}

fn portcheck(frp: u16, op: u32, po: u16, top: u16) -> bool {
    match op {
        FR_EQUAL => po == frp,
        FR_NEQUAL => po != frp,
        FR_LESST => po < frp,
        FR_GREATERT => po > frp,
        FR_LESSTE => po <= frp,
        FR_GREATERTE => po >= frp,
        FR_OUTRANGE => po < frp || po > top,
        FR_INRANGE => po > frp && po < top,
        _ => true,
    }
}

/// fr_tcpudpchk.
fn tcpudpchk(fr: &Rule, fin: &Fin) -> bool {
    let mut ok = true;
    if fr.dcmp != 0 {
        ok &= portcheck(fr.dport, fr.dcmp, fin.data[1], fr.dtop);
    }
    if ok && fr.scmp != 0 {
        ok &= portcheck(fr.sport, fr.scmp, fin.data[0], fr.stop);
    }
    if ok && fin.p == 6 {
        if fin.fl & FI_SHORT != 0 {
            return fr.tcpf | fr.tcpfm == 0;
        }
        if fr.tcpfm != 0 && fr.tcpf != fin.tcpf & fr.tcpfm {
            ok = false;
        }
    }
    ok
}

// ---------------------------------------------------------------------------
// State and fragments
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tcp {
    Syn,
    Open,
    /// FIN seen from these sides (bit 0: the side that made the state).
    Closing(u8),
    Reset,
}

struct State {
    p: u8,
    /// The flow as its first packet had it: a -> b.
    a: u32,
    b: u32,
    ap: u16,
    bp: u16,
    /// ICMP: the query's type, id and sequence number (3.4 keeps a state
    /// per query: ping -c 2 keeps two).
    itype: u8,
    id: u16,
    seq: u16,
    pass: u32,
    tcp: Tcp,
    until: u64,
}

impl State {
    /// Some(forward?) when `fin` is of this flow.
    fn matches(&self, p: u8, src: u32, dst: u32, sp: u16, dp: u16) -> Option<bool> {
        if self.p != p {
            return None;
        }
        if self.a == src && self.b == dst && self.ap == sp && self.bp == dp {
            Some(true)
        } else if self.a == dst && self.b == src && self.ap == dp && self.bp == sp {
            Some(false)
        } else {
            None
        }
    }
}

struct Frag {
    src: u32,
    dst: u32,
    id: u16,
    p: u8,
    pass: u32,
    until: u64,
}

/// The reply type of an ICMP query (echo, timestamp, information, mask).
fn icmp_reply(t: u8) -> Option<u8> {
    match t {
        8 => Some(0),
        13 => Some(14),
        15 => Some(16),
        17 => Some(18),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The log
// ---------------------------------------------------------------------------

/// The records waiting in each minor's log, and who to signal on new ones
/// (ipf_set_notify_mask: task, signals).
#[derive(Default)]
struct Logs {
    recs: [VecDeque<Vec<u8>>; 4],
    bytes: [usize; 4],
    notify: [(u32, u32); 4],
}

impl Logs {
    fn add(&mut self, minor: usize, rec: Vec<u8>) -> bool {
        if self.bytes[minor] + rec.len() > LOGSIZE {
            return false;
        }
        self.bytes[minor] += rec.len();
        self.recs[minor].push_back(rec);
        let (task, mask) = self.notify[minor];
        if task != 0 && mask != 0 {
            // SAFETY: the task that asked for these signals
            // (ipf_set_notify_mask), which clears them before it goes.
            unsafe { amigaos4::sys::exec_signal(task as usize as *mut amigaos4::sys::Task, mask) };
        }
        true
    }

    /// Whole records, as many as fit in `max` bytes.
    fn read(&mut self, minor: usize, max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(r) = self.recs[minor].front() {
            if out.len() + r.len() > max {
                break;
            }
            let r = self.recs[minor].pop_front().unwrap();
            self.bytes[minor] -= r.len();
            out.extend_from_slice(&r);
        }
        out
    }

    fn flush(&mut self, minor: usize) -> usize {
        let n = self.bytes[minor];
        self.recs[minor].clear();
        self.bytes[minor] = 0;
        n
    }
}

/// ipflog(): a record of datagram `ip` (summary `fin`) with pass flags
/// `flags` into the IPL_LOGIPF log.
fn ipllog(logs: &mut Logs, fin: &Fin, ip: &[u8], flags: u32) -> bool {
    let iphl = fin.hlen as usize;
    let dlen = fin.dlen as usize;
    let mut hlen = iphl;
    if fin.off == 0 {
        hlen += match fin.p {
            6 => dlen.min(20),
            17 => dlen.min(8),
            1 if dlen >= 1 && matches!(ip[iphl], 3 | 4 | 5 | 11 | 12) => dlen.min(36),
            1 => dlen.min(28),
            _ => 0,
        };
    }
    let total = (fin.plen as usize).min(ip.len());
    let hlen = hlen.min(total);
    let plen = if flags & FR_LOGBODY != 0 { (total - hlen).min(128) } else { 0 };
    let dsize = (24 + 36 + hlen + plen + 3) & !3;
    let now = amigaos4::timer::sys_time();
    let mut r = Vec::with_capacity(dsize);
    for v in [IPL_MAGIC, 1, now.secs.wrapping_add(AMIGA_EPOCH), now.micros, dsize as u32, 0] {
        r.extend_from_slice(&v.to_be_bytes());
    }
    r.extend_from_slice(&crate::ipf::ifnet_name(fin.ifp));
    r.push(plen as u8);
    r.push(hlen as u8);
    r.extend_from_slice(&fin.loglevel.to_be_bytes());
    for v in [fin.rule, fin.group, flags, 0] {
        r.extend_from_slice(&v.to_be_bytes());
    }
    let at = r.len();
    r.extend_from_slice(&ip[..hlen + plen]);
    // The header's checksum as BSD's ip_input leaves it: 0.
    if hlen >= 12 {
        r[at + 10] = 0;
        r[at + 11] = 0;
    }
    r.resize(dsize, 0);
    logs.add(IPL_LOGIPF as usize, r)
}

/// fr_scanlist over `rules` (a list, or a group of set `set`): the pass
/// flags. A pure "log" rule logs here (and counts fr_pkl).
fn scan(set: &Set, rules: &[Rule], pass_in: u32, fin: &mut Fin, ip: &[u8], logs: &mut Logs, stats: &mut [[u32; ST_WORDS]; 2]) -> u32 {
    let mut pass = pass_in;
    let mut skip = 0u32;
    let mut logged = false;
    fin.fr = 0;
    let out = fin.out;
    for (n, fr) in rules.iter().enumerate() {
        if skip > 0 {
            skip -= 1;
            continue;
        }
        if fr.ifa != 0 && fr.ifa != fin.ifp {
            continue;
        }
        if fin.w[0] & fr.mask[0] != fr.ip[0] {
            continue;
        }
        if ((fin.w[1] & fr.mask[1]) != fr.ip[1]) ^ (fr.flags & FR_NOTSRCIP != 0) {
            continue;
        }
        if ((fin.w[2] & fr.mask[2]) != fr.ip[2]) ^ (fr.flags & FR_NOTDSTIP != 0) {
            continue;
        }
        if fin.w[3] & fr.mask[3] != fr.ip[3] || fin.w[4] & fr.mask[4] != fr.ip[4] {
            continue;
        }
        if fin.fl & FI_TCPUDP != 0 {
            if !tcpudpchk(fr, fin) {
                continue;
            }
        } else if fr.icmpm != 0 || fr.icmp != 0 {
            if fin.p != 1 || fin.off != 0 || fin.dlen < 2 || fin.data[0] & fr.icmpm != fr.icmp {
                continue;
            }
        }
        let mut passt = fr.flags;
        fin.fr = fr.mem.addr();
        fin.dest = [fr.tif, fr.dif];
        fin.rule = n as u32;
        fin.group = fr.group;
        fin.loglevel = fr.loglevel;
        if !fin.dry && passt & FR_LOGMASK == FR_LOG {
            if !ipllog(logs, fin, ip, passt) {
                if passt & FR_LOGORBLOCK != 0 {
                    passt |= FR_BLOCK | FR_QUICK;
                }
                stats[out][ST_SKIP] = stats[out][ST_SKIP].wrapping_add(1);
            }
            stats[out][ST_PKL] = stats[out][ST_PKL].wrapping_add(1);
            logged = true;
        }
        skip = fr.skip;
        if skip == 0 && passt & FR_LOGMASK != FR_LOG {
            pass = passt;
        }
        if passt & FR_ACCOUNT != 0 {
            if !fin.dry {
                fr.mem.bump(O_HITS, 1);
                fr.mem.bump(O_BYTES, fin.plen as u32);
            }
        } else {
            if !fin.dry {
                fr.mem.bump(O_HITS, 1);
            }
            fin.icode = fr.icode;
        }
        if fr.grhead != 0 {
            let (_, table) = fr.kind();
            if let Some(g) = set.group(table, fr.grhead) {
                pass = scan(set, &set.groups[g].rules, pass, fin, ip, logs, stats);
                if fin.fr == 0 {
                    fin.rule = n as u32;
                    fin.group = fr.group;
                    fin.loglevel = fr.loglevel;
                    fin.fr = fr.mem.addr();
                    fin.dest = [fr.tif, fr.dif];
                }
                if pass & FR_DONTCACHE != 0 {
                    logged = true;
                }
            }
        }
        if pass & FR_QUICK != 0 {
            break;
        }
    }
    if logged {
        pass |= FR_DONTCACHE;
    }
    pass
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Cached {
    key: (u32, [u32; 5], [u16; 2], u16, u8),
    pass: u32,
    fr: u32,
    rule: u32,
    group: u32,
    loglevel: u16,
    dest: [(u32, u32); 2],
}

/// filterstats' words.
const ST_PASS: usize = 0;
const ST_BLOCK: usize = 1;
const ST_NOM: usize = 2;
const ST_SHORT: usize = 3;
const ST_PPKL: usize = 4;
const ST_BPKL: usize = 5;
const ST_NPKL: usize = 6;
const ST_PKL: usize = 7;
const ST_SKIP: usize = 8;
const ST_RET: usize = 9;
const ST_ACCT: usize = 10;
const ST_BNFR: usize = 11;
const ST_NFR: usize = 12;
const ST_CFR: usize = 13;
const ST_BADS: usize = 14;
const ST_ADS: usize = 15;
const ST_CHIT: usize = 16;
const ST_WORDS: usize = 24;

#[derive(Default)]
struct StateStats {
    hits: u32,
    miss: u32,
    max: u32,
    tcp: u32,
    udp: u32,
    icmp: u32,
    nomem: u32,
    expire: u32,
    fin: u32,
}

#[derive(Default)]
struct FragStats {
    exists: u32,
    nomem: u32,
    new: u32,
    hits: u32,
    expire: u32,
}

pub struct Engine {
    sets: [Set; 2],
    active: usize,
    /// SIOCSETFF's FF_LOG* flags.
    flags: u32,
    stats: [[u32; ST_WORDS]; 2],
    cache: [[Option<Cached>; 8]; 2],
    states: Vec<State>,
    sstats: StateStats,
    frags: Vec<Frag>,
    fstats: FragStats,
    logs: Logs,
    auth: Auth,
    /// f_froute: datagrams "to" / "dup-to" sent, and failed.
    froute: [u32; 2],
    /// What "to" / "dup-to" hand the stack process to send.
    routed: Vec<Routed>,
}

impl Engine {
    fn new() -> Engine {
        Engine {
            sets: Default::default(),
            active: 0,
            flags: 0,
            stats: [[0; ST_WORDS]; 2],
            cache: [[None; 8]; 2],
            states: Vec::new(),
            sstats: StateStats::default(),
            frags: Vec::new(),
            fstats: FragStats::default(),
            logs: Logs::default(),
            auth: Auth::new(),
            froute: [0; 2],
            routed: Vec::new(),
        }
    }

    fn uncache(&mut self) {
        self.cache = [[None; 8]; 2];
    }

    fn expire(&mut self, now: u64) {
        let before = self.states.len();
        self.states.retain(|s| s.until > now);
        self.sstats.expire += (before - self.states.len()) as u32;
        let before = self.frags.len();
        self.frags.retain(|f| f.until > now);
        self.fstats.expire += (before - self.frags.len()) as u32;
        self.auth.expire(now);
    }

    /// fr_checkstate: the pass flags of the flow `fin` belongs to.
    fn check_state(&mut self, fin: &Fin, ip: &[u8], now: u64) -> Option<u32> {
        if self.states.is_empty() {
            self.sstats.miss += 1;
            return None;
        }
        let (src, dst) = (fin.src(), fin.dst());
        let hit = match fin.p {
            6 | 17 if fin.fl & FI_TCPUDP != 0 && fin.off == 0 && fin.dlen >= 4 => {
                let found = self.states.iter().position(|s| s.matches(fin.p, src, dst, fin.data[0], fin.data[1]).is_some());
                found.map(|k| {
                    let fwd = self.states[k].matches(fin.p, src, dst, fin.data[0], fin.data[1]) == Some(true);
                    let s = &mut self.states[k];
                    if fin.p == 6 {
                        let f = fin.tcpf;
                        let side = if fwd { 1u8 } else { 2 };
                        s.tcp = if f & 0x04 != 0 {
                            Tcp::Reset
                        } else if f & 0x01 != 0 {
                            match s.tcp {
                                Tcp::Closing(m) => Tcp::Closing(m | side),
                                _ => Tcp::Closing(side),
                            }
                        } else if s.tcp == Tcp::Syn && !fwd && f & 0x10 != 0 {
                            Tcp::Open
                        } else {
                            s.tcp
                        };
                        s.until = now
                            + 1_000_000
                                * match s.tcp {
                                    Tcp::Syn => TCP_SYN_S,
                                    Tcp::Open => TCP_IDLE_S,
                                    Tcp::Closing(3) => TCP_CLOSED_S,
                                    Tcp::Closing(_) => TCP_HALFCLOSED_S,
                                    Tcp::Reset => TCP_RESET_S,
                                };
                    } else {
                        s.until = now + UDP_S * 1_000_000;
                    }
                    s.pass
                })
            }
            1 if fin.off == 0 && fin.dlen >= 8 => {
                let d = &ip[fin.hlen as usize..];
                let (t, id, seq) = (d[0], g16(d, 4), g16(d, 6));
                if let Some(k) = self.states.iter().position(|s| {
                    s.p == 1
                        && s.id == id
                        && s.seq == seq
                        && ((s.a == src && s.b == dst && s.itype == t) || (s.a == dst && s.b == src && icmp_reply(s.itype) == Some(t)))
                }) {
                    self.states[k].until = now + ICMP_S * 1_000_000;
                    Some(self.states[k].pass)
                } else if matches!(t, 3 | 4 | 5 | 11 | 12) && d.len() >= 8 + 20 + 8 {
                    // An error about a flow of ours: the datagram it quotes.
                    let q = &d[8..];
                    let qh = ((q[0] & 15) as usize) * 4;
                    if q.len() >= qh + 8 && qh >= 20 {
                        let (qp, qs, qd) = (q[9], g32(q, 12), g32(q, 16));
                        let (sp, dp) = (g16(q, qh), g16(q, qh + 2));
                        self.states
                            .iter()
                            .find(|s| match qp {
                                6 | 17 => s.matches(qp, qs, qd, sp, dp).is_some(),
                                1 => s.p == 1 && ((s.a == qs && s.b == qd) || (s.a == qd && s.b == qs)) && s.id == g16(q, qh + 4) && s.seq == g16(q, qh + 6),
                                _ => false,
                            })
                            .map(|s| s.pass)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
        match hit {
            Some(p) => {
                self.sstats.hits += 1;
                // Only the first packet of a flow is logged "first".
                Some(if p & FR_LOGFIRST != 0 { p & !(FR_LOGFIRST | FR_LOG) } else { p })
            }
            None => {
                self.sstats.miss += 1;
                None
            }
        }
    }

    /// fr_addstate.
    fn add_state(&mut self, fin: &Fin, ip: &[u8], pass: u32, now: u64) -> bool {
        if fin.fl & (FI_SHORT) != 0 || fin.off != 0 || self.states.len() >= STATE_MAX {
            if self.states.len() >= STATE_MAX {
                self.sstats.max += 1;
            }
            return false;
        }
        let (a, b) = (fin.src(), fin.dst());
        let mut s = State { p: fin.p, a, b, ap: 0, bp: 0, itype: 0, id: 0, seq: 0, pass, tcp: Tcp::Open, until: 0 };
        match fin.p {
            6 | 17 if fin.fl & FI_TCPUDP != 0 => {
                s.ap = fin.data[0];
                s.bp = fin.data[1];
                if fin.p == 6 {
                    let f = fin.tcpf;
                    s.tcp = if f & 0x04 != 0 {
                        Tcp::Reset
                    } else if f & 0x12 == 0x02 {
                        Tcp::Syn
                    } else {
                        Tcp::Open
                    };
                    s.until = now + 1_000_000 * if s.tcp == Tcp::Syn { TCP_SYN_S } else { TCP_IDLE_S };
                    self.sstats.tcp += 1;
                } else {
                    s.until = now + UDP_S * 1_000_000;
                    self.sstats.udp += 1;
                }
            }
            1 => {
                let d = &ip[fin.hlen as usize..];
                if d.len() < 8 || icmp_reply(d[0]).is_none() {
                    return false;
                }
                s.itype = d[0];
                s.id = g16(d, 4);
                s.seq = g16(d, 6);
                s.until = now + ICMP_S * 1_000_000;
                self.sstats.icmp += 1;
            }
            _ => return false,
        }
        self.states.push(s);
        true
    }

    fn known_frag(&mut self, fin: &Fin) -> Option<u32> {
        let (src, dst) = (fin.src(), fin.dst());
        let f = self.frags.iter().find(|f| f.src == src && f.dst == dst && f.id == fin.id && f.p == fin.p)?;
        self.fstats.hits += 1;
        Some(f.pass)
    }

    fn new_frag(&mut self, fin: &Fin, pass: u32, now: u64) -> bool {
        let (src, dst) = (fin.src(), fin.dst());
        if self.frags.iter().any(|f| f.src == src && f.dst == dst && f.id == fin.id && f.p == fin.p) {
            self.fstats.exists += 1;
            return false;
        }
        if self.frags.len() >= FRAG_MAX {
            self.fstats.nomem += 1;
            return false;
        }
        self.frags.push(Frag { src, dst, id: fin.id, p: fin.p, pass, until: now + FRAG_S * 1_000_000 });
        self.fstats.new += 1;
        true
    }

    /// fr_check: does the datagram go on.
    fn check(&mut self, ifp: u32, eth: &[u8], ip: &[u8], out: usize, now: u64, reply: &mut Option<Vec<u8>>, dry: bool) -> bool {
        let Some(mut fin) = makefrip(ifp, ip, out) else { return true };
        self.expire(now);
        fin.dry = dry;
        let st = |e: &mut Engine, k: usize| {
            if !dry {
                e.stats[out][k] = e.stats[out][k].wrapping_add(1);
            }
        };
        if fin.fl & FI_SHORT != 0 {
            st(self, ST_SHORT);
        }
        let set = self.active;
        // An answer from the auth program (SIOCAUTHR) decides before any
        // rule, and the datagram is not counted again.
        let apass = self.auth.check(&fin, dry);
        // Accounting rules count every datagram.
        if apass.is_none() && !self.sets[set].lists[2 + out].is_empty() {
            let mut f2 = fin;
            if scan(&self.sets[set], &self.sets[set].lists[2 + out], FR_NOMATCH, &mut f2, ip, &mut self.logs, &mut self.stats) & FR_ACCOUNT != 0 {
                st(self, ST_ACCT);
            }
        }
        let key = (fin.ifp, fin.w, fin.data, fin.hlen, fin.tcpf);
        let slot = (ifp as usize >> 7) & 7;
        let mut from_rules = false;
        let pass = if let Some((p, fr)) = apass {
            fin.fr = fr;
            if !dry && p & FR_KEEPSTATE != 0 {
                let k = if self.add_state(&fin, ip, p, now) { ST_ADS } else { ST_BADS };
                st(self, k);
            }
            p
        } else if let Some(c) = self.cache[out][slot].filter(|c| c.key == key) {
            from_rules = true;
            st(self, ST_CHIT);
            if c.fr != 0 && !dry {
                self.bump_hits(c.fr);
            }
            fin.fr = c.fr;
            fin.rule = c.rule;
            fin.group = c.group;
            fin.loglevel = c.loglevel;
            fin.dest = c.dest;
            c.pass
        } else if let Some(p) = if fin.fl & FI_FRAG != 0 && fin.off != 0 { self.known_frag(&fin) } else { None } {
            p
        } else if let Some(p) = self.check_state(&fin, ip, now) {
            p
        } else {
            from_rules = true;
            let pass = scan(&self.sets[set], &self.sets[set].lists[out], FR_PASS | FR_NOMATCH, &mut fin, ip, &mut self.logs, &mut self.stats);
            if !dry && pass & (FR_KEEPSTATE | FR_DONTCACHE) == 0 {
                self.cache[out][slot] = Some(Cached { key, pass, fr: fin.fr, rule: fin.rule, group: fin.group, loglevel: fin.loglevel, dest: fin.dest });
            }
            if pass & FR_NOMATCH != 0 {
                st(self, ST_NOM);
            }
            if !dry && pass & FR_KEEPFRAG != 0 {
                if fin.fl & FI_FRAG != 0 {
                    let k = if self.new_frag(&fin, pass, now) { ST_NFR } else { ST_BNFR };
                    st(self, k);
                } else {
                    st(self, ST_CFR);
                }
            }
            if !dry && pass & FR_KEEPSTATE != 0 {
                let k = if self.add_state(&fin, ip, pass, now) { ST_ADS } else { ST_BADS };
                st(self, k);
            }
            pass
        };
        // "preauth": the rules the auth program added decide; none that
        // matches leaves neither pass nor block (dropped, not counted).
        let mut pass = pass;
        if from_rules && pass & FR_PREAUTH != 0 {
            let (fr, rule, group) = (fin.fr, fin.rule, fin.group);
            let p = scan(&self.sets[set], &self.auth.pre, 0, &mut fin, ip, &mut self.logs, &mut self.stats);
            (fin.fr, fin.rule, fin.group) = (fr, rule, group);
            if !dry {
                self.auth.st[if p != 0 { AS_HITS } else { AS_MISS }] += 1;
            }
            pass = p;
        }
        // "auth": held for the auth program, neither passed nor blocked. A
        // look ahead lets it go on (a socket's send is not refused).
        if pass & FR_AUTH != 0 {
            if dry {
                return true;
            }
            self.auth.hold(&fin, eth, ip, now);
            return false;
        }
        // The log: no match (ipf -l nomatch), a "pass log" / "block log"
        // rule, or ipf -l pass / block.
        let ff = self.flags;
        let what = if ff & FF_LOGNOMATCH != 0 && pass & FR_NOMATCH != 0 {
            pass |= FF_LOGNOMATCH;
            Some(ST_NPKL)
        } else if pass & FR_LOGMASK == FR_LOGP || (pass & FR_PASS != 0 && ff & FF_LOGPASS != 0) {
            if pass & FR_LOGMASK != FR_LOGP {
                pass |= FF_LOGPASS;
            }
            Some(ST_PPKL)
        } else if pass & FR_LOGMASK == FR_LOGB || (pass & FR_BLOCK != 0 && ff & FF_LOGBLOCK != 0) {
            if pass & FR_LOGMASK != FR_LOGB {
                pass |= FF_LOGBLOCK;
            }
            Some(ST_BPKL)
        } else {
            None
        };
        if let Some(k) = what.filter(|_| !dry) {
            st(self, k);
            if !ipllog(&mut self.logs, &fin, ip, pass) {
                st(self, ST_SKIP);
                if pass & (FR_PASS | FR_LOGORBLOCK) == FR_PASS | FR_LOGORBLOCK {
                    pass ^= FR_PASS | FR_BLOCK;
                }
            }
        }
        if pass & FR_PASS != 0 {
            st(self, ST_PASS);
            // to / dup-to / fastroute (3.4's ipfr_fastroute), for what a
            // rule passed.
            if from_rules && !dry && fin.fr != 0 {
                let real = |p: u32| p != 0 && p != u32::MAX;
                let [tif, dif] = fin.dest;
                let gone = real(tif.0);
                if gone {
                    self.route(tif, &fin, eth, ip);
                } else if pass & FR_FASTROUTE != 0 && out == 0 {
                    self.froute[0] = self.froute[0].wrapping_add(1);
                }
                if pass & FR_DUP != 0 && real(dif.0) {
                    self.route(dif, &fin, eth, ip);
                }
                if gone {
                    return false;
                }
            }
            true
        } else {
            if pass & FR_BLOCK != 0 {
                st(self, ST_BLOCK);
                // A reply to what came in (3.4 counts ICMP replies in the
                // input statistics' fr_ret, resets in the output ones').
                if out == 0 && !dry {
                    if pass & FR_RETICMP != 0 {
                        if let Some(r) = icmp_unreach(ip, &fin) {
                            *reply = Some(r);
                            self.stats[0][ST_RET] = self.stats[0][ST_RET].wrapping_add(1);
                        }
                    } else if pass & FR_RETRST != 0 && fin.fl & FI_SHORT == 0 {
                        if let Some(r) = tcp_reset(ip, &fin) {
                            *reply = Some(r);
                            self.stats[1][ST_RET] = self.stats[1][ST_RET].wrapping_add(1);
                        }
                    }
                }
            }
            false
        }
    }

    /// A cached match counts as a hit on its rule again.
    fn bump_hits(&mut self, addr: u32) {
        let set = self.active;
        let s = &mut self.sets[set];
        for l in s.lists.iter_mut().chain(s.groups.iter_mut().map(|g| &mut g.rules)) {
            if let Some(r) = l.iter_mut().find(|r| r.mem.addr() == addr) {
                r.mem.bump(O_HITS, 1);
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // ioctls
    // -----------------------------------------------------------------------

    /// SIOCADAFR & co: add (at the end, or at position fr_hits for an
    /// insert) or remove a rule in set `set`.
    fn request(&mut self, user: &[u8; FRENTRY], set: usize, add: bool, insert: bool) -> Result<(), i32> {
        let mut r = Rule::new(user);
        if r.flags & (FR_INQUE | FR_OUTQUE) == 0 {
            return Err(EINVAL);
        }
        let (list, table) = r.kind();
        let s = &mut self.sets[set];
        let target: &mut Vec<Rule> = if r.group != 0 {
            match s.group(table, r.group) {
                Some(g) => &mut s.groups[g].rules,
                None => return Err(ESRCH),
            }
        } else {
            &mut s.lists[list]
        };
        let at = target.iter().position(|x| x.same(&r));
        if add {
            if at.is_some() {
                return Err(EEXIST);
            }
            if r.grhead != 0 && s.group(table, r.grhead).is_some() {
                return Err(EEXIST);
            }
            r.resolve();
            let (grhead, addr) = (r.grhead, r.mem.addr());
            let target: &mut Vec<Rule> = if r.group != 0 {
                let g = s.group(table, r.group).unwrap();
                &mut s.groups[g].rules
            } else {
                &mut s.lists[list]
            };
            let pos = if insert { (g32(user, O_HITS) as usize).min(target.len()) } else { target.len() };
            target.insert(pos, r);
            if grhead != 0 {
                s.groups.push(Group::new(grhead, table, addr));
            }
        } else {
            let Some(k) = at else { return Err(ESRCH) };
            let gone = target.remove(k);
            if gone.grhead != 0 {
                if let Some(g) = s.group(table, gone.grhead) {
                    if !s.groups[g].rules.is_empty() {
                        // Its group still has rules: put it back.
                        let target: &mut Vec<Rule> = if gone.group != 0 {
                            let gg = s.group(table, gone.group).unwrap();
                            &mut s.groups[gg].rules
                        } else {
                            &mut s.lists[list]
                        };
                        target.insert(k, gone);
                        return Err(EBUSY);
                    }
                    s.groups.remove(g);
                }
            }
        }
        s.relink();
        self.uncache();
        Ok(())
    }

    /// SIOCZRLST: the rule's hits and bytes into the caller's copy, then 0.
    fn zero_rule(&mut self, user: &mut [u8; FRENTRY]) -> Result<(), i32> {
        let r = Rule::new(user);
        let (list, table) = r.kind();
        let set = if r.flags & FR_INACTIVE != 0 { 1 - self.active } else { self.active };
        let s = &mut self.sets[set];
        let rules: &mut Vec<Rule> = if r.group != 0 {
            match s.group(table, r.group) {
                Some(g) => &mut s.groups[g].rules,
                None => return Err(ESRCH),
            }
        } else {
            &mut s.lists[list]
        };
        let Some(x) = rules.iter_mut().find(|x| x.same(&r)) else { return Err(ESRCH) };
        let b = x.mem.bytes();
        let (h, n) = (g32(b, O_HITS), g32(b, O_BYTES));
        p32(b, O_HITS, 0);
        p32(b, O_BYTES, 0);
        p32(user, O_HITS, h);
        p32(user, O_BYTES, n);
        Ok(())
    }

    /// SIOCIPFFL: flush the in (FR_INQUE) and/or out (FR_OUTQUE) lists of
    /// the active set (or the inactive one, FR_INACTIVE): how many rules.
    fn flush(&mut self, how: u32) -> u32 {
        let set = if how & FR_INACTIVE != 0 { 1 - self.active } else { self.active };
        let mut which = Vec::new();
        if how & FR_INQUE != 0 {
            which.extend([0, 2]);
        }
        if how & FR_OUTQUE != 0 {
            which.extend([1, 3]);
        }
        let n = self.sets[set].flush(&which);
        self.sets[set].relink();
        self.uncache();
        n
    }

    fn sync(&mut self) {
        for s in self.sets.iter_mut() {
            for l in s.lists.iter_mut().chain(s.groups.iter_mut().map(|g| &mut g.rules)) {
                for r in l.iter_mut() {
                    r.resolve();
                }
            }
        }
        self.uncache();
    }

    /// struct friostat.
    fn friostat(&self, running: bool) -> [u8; FRIOSTAT] {
        let mut b = [0u8; FRIOSTAT];
        for d in 0..2 {
            for k in 0..ST_WORDS {
                p32(&mut b, d * 96 + k * 4, self.stats[d][k]);
            }
        }
        let first = |s: &Set, k: usize| s.lists[k].first().map(|r| r.mem.addr()).unwrap_or(0);
        for set in 0..2 {
            let s = &self.sets[set];
            p32(&mut b, 192 + set * 4, first(s, 0));
            p32(&mut b, 200 + set * 4, first(s, 1));
            p32(&mut b, 208 + set * 4, first(s, 2));
            p32(&mut b, 216 + set * 4, first(s, 3));
            for t in 0..3 {
                p32(&mut b, 260 + (t * 2 + set) * 4, s.first_group(t));
            }
        }
        // f_auth: Roadshow reports -1 (no authentication list).
        p32(&mut b, 256, u32::MAX);
        p32(&mut b, 284, self.froute[0]);
        p32(&mut b, 288, self.froute[1]);
        p32(&mut b, 292, FR_PASS | FR_NOMATCH);
        b[296] = self.active as u8;
        b[297] = running as u8;
        // f_logging: the log is there.
        b[298] = 1;
        b[299..299 + VERSION.len()].copy_from_slice(VERSION);
        b
    }

    /// struct ipfrstat.
    fn ipfrstat(&self) -> [u8; IPFRSTAT] {
        let mut b = [0u8; IPFRSTAT];
        let f = &self.fstats;
        for (k, v) in [f.exists, f.nomem, f.new, f.hits, f.expire, self.frags.len() as u32].into_iter().enumerate() {
            p32(&mut b, k * 4, v);
        }
        b
    }

    /// struct ips_stat.
    fn ips_stat(&self) -> [u8; IPS_STAT] {
        let mut b = [0u8; IPS_STAT];
        let s = &self.sstats;
        let active = self.states.len() as u32;
        for (k, v) in [s.hits, s.miss, s.max, s.tcp, s.udp, s.icmp, s.nomem, s.expire, s.fin, active, 0, 0, active].into_iter().enumerate() {
            p32(&mut b, k * 4, v);
        }
        b
    }

    fn flush_states(&mut self, how: u32) -> u32 {
        let before = self.states.len();
        if how == 0 {
            self.states.clear();
        } else {
            // 1: what is not an established TCP flow.
            self.states.retain(|s| s.p == 6 && s.tcp == Tcp::Open);
        }
        (before - self.states.len()) as u32
    }
}

// ---------------------------------------------------------------------------
// The engine's lock, the fast path and the ioctl entry
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// to / dup-to (3.4's ipfr_fastroute)
// ---------------------------------------------------------------------------

/// A datagram "to" or "dup-to" sends out of interface `ifp` to `hop` (0:
/// its destination `dst`): the frame it came in (its Ethernet header is
/// replaced).
pub struct Routed {
    pub ifp: u32,
    pub hop: u32,
    pub dst: u32,
    pub frame: Vec<u8>,
}

/// Set when "to" / "dup-to" queued a datagram.
static ROUTED: AtomicBool = AtomicBool::new(false);

impl Engine {
    /// Queue the datagram (or a copy) for interface `d.0`, next hop `d.1`.
    fn route(&mut self, d: (u32, u32), fin: &Fin, eth: &[u8], ip: &[u8]) {
        let mut frame = Vec::with_capacity(14 + ip.len());
        frame.extend_from_slice(eth);
        frame.resize(14, 0);
        frame.extend_from_slice(ip);
        self.routed.push(Routed { ifp: d.0, hop: d.1, dst: fin.dst(), frame });
        ROUTED.store(true, Ordering::Release);
    }
}

/// The datagrams "to" / "dup-to" queued since the last call (the stack
/// process sends them and reports each with [`froute_done`]).
pub fn take_routed() -> Vec<Routed> {
    if !ROUTED.swap(false, Ordering::AcqRel) {
        return Vec::new();
    }
    match lock() {
        Some(mut e) => core::mem::take(&mut e.routed),
        None => Vec::new(),
    }
}

/// One "to" / "dup-to" datagram sent (f_froute[0]) or not ([1]).
pub fn froute_done(ok: bool) {
    if let Some(mut e) = lock() {
        let k = (!ok) as usize;
        e.froute[k] = e.froute[k].wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Auth (3.4's ip_auth.c)
// ---------------------------------------------------------------------------

/// fr_authstat's counters, in order.
const AS_HITS: usize = 0;
const AS_MISS: usize = 1;
const AS_NOSPACE: usize = 2;
const AS_ADDED: usize = 3;
const AS_SENDOK: usize = 5;
const AS_QUEOK: usize = 6;
const AS_EXPIRE: usize = 8;

/// One slot of the queue: fr_auth[i] and fr_authpkts[i].
struct Held {
    /// Its own slot while held; -2 once answered (until the datagram comes
    /// round again), -1 when free.
    index: i32,
    pass: u32,
    info: [u8; FRINFO],
    since: u64,
    /// The whole frame (Ethernet header and datagram) until it is answered.
    frame: Option<Vec<u8>>,
}

impl Held {
    fn free() -> Held {
        Held { index: -1, pass: 0, info: [0; FRINFO], since: 0, frame: None }
    }
}

/// A datagram an auth program let go (SIOCAUTHR): the stack sends it out
/// of interface `ifp` (`out`) or takes it in there again.
pub struct Released {
    pub ifp: u32,
    pub out: bool,
    pub frame: Vec<u8>,
}

struct Auth {
    q: Vec<Held>,
    start: usize,
    end: usize,
    next: usize,
    used: usize,
    st: [u32; 9],
    /// The preauth rules (fae_list) and when each was added.
    pre: Vec<Rule>,
    pre_since: Vec<u64>,
    /// Tasks waiting in SIOCAUTHW: (task, signal mask).
    waiters: Vec<(u32, u32)>,
    released: Vec<Released>,
}

impl Auth {
    fn new() -> Auth {
        Auth {
            q: (0..FR_NUMAUTH).map(|_| Held::free()).collect(),
            start: 0,
            end: 0,
            next: 0,
            used: 0,
            st: [0; 9],
            pre: Vec::new(),
            pre_since: Vec::new(),
            waiters: Vec::new(),
            released: Vec::new(),
        }
    }

    fn signal(to: (u32, u32)) {
        if to.0 != 0 && to.1 != 0 {
            // SAFETY: a task that registered itself under the engine lock
            // and takes itself off under it before it goes.
            unsafe { amigaos4::sys::exec_signal(to.0 as usize as *mut amigaos4::sys::Task, to.1) };
        }
    }

    /// Slot `i` became free: move the start past free slots (3.4's loop).
    fn advance(&mut self, mut i: usize) {
        if i != self.start {
            return;
        }
        while self.q[i].index == -1 {
            i = (i + 1) % FR_NUMAUTH;
            self.start = i;
            if i == self.end {
                break;
            }
        }
        if self.start == self.end {
            self.next = 0;
            self.start = 0;
            self.end = 0;
        }
    }

    /// fr_checkauth: the program's answer for `fin`, and the rule it was
    /// held by, when it is a datagram coming round again.
    fn check(&mut self, fin: &Fin, dry: bool) -> Option<(u32, u32)> {
        if self.used == 0 {
            return None;
        }
        let me = fin.fr_info(0, 0);
        let mut i = self.start;
        while i != self.end {
            let h = &self.q[i];
            if h.index == -2 && g16(&h.info, 74) == fin.id && h.info[..FI_CSIZE] == me[..FI_CSIZE] {
                let mut pass = h.pass;
                // No feedback loop.
                if pass == 0 || pass & FR_AUTH != 0 {
                    pass = FR_BLOCK;
                }
                let fr = g32(&h.info, 64);
                if !dry {
                    self.st[AS_HITS] += 1;
                    self.q[i].index = -1;
                    self.used -= 1;
                    self.advance(i);
                }
                return Some((pass, fr));
            }
            i = (i + 1) % FR_NUMAUTH;
        }
        if !dry {
            self.st[AS_MISS] += 1;
        }
        None
    }

    /// fr_newauth: hold the frame (its Ethernet header `eth`, datagram
    /// `ip`) and wake the waiting programs.
    fn hold(&mut self, fin: &Fin, eth: &[u8], ip: &[u8], now: u64) -> bool {
        if eth.len() != 14 || self.start > self.end || self.used == FR_NUMAUTH {
            self.st[AS_NOSPACE] += 1;
            return false;
        }
        self.st[AS_ADDED] += 1;
        self.used += 1;
        let i = self.end;
        self.end = (self.end + 1) % FR_NUMAUTH;
        let mut frame = Vec::with_capacity(14 + ip.len());
        frame.extend_from_slice(eth);
        frame.extend_from_slice(ip);
        let at = frame.as_ptr() as usize as u32;
        let info = fin.fr_info(at + 14 + fin.hlen as u32, at);
        self.q[i] = Held { index: i as i32, pass: 0, info, since: now, frame: Some(frame) };
        for &w in &self.waiters {
            Auth::signal(w);
        }
        true
    }

    /// fr_authexpire: held datagrams and preauth rules older than 300 s.
    fn expire(&mut self, now: u64) {
        for h in self.q.iter_mut() {
            if h.frame.is_some() && now.saturating_sub(h.since) >= AUTH_US {
                h.frame = None;
                h.index = -1;
                self.st[AS_EXPIRE] += 1;
                self.used -= 1;
            }
        }
        let mut k = 0;
        while k < self.pre.len() {
            if now.saturating_sub(self.pre_since[k]) >= AUTH_US {
                self.pre.remove(k);
                self.pre_since.remove(k);
                self.st[AS_EXPIRE] += 1;
            } else {
                k += 1;
            }
        }
    }

    /// The next held datagram's struct frauth for SIOCAUTHW (past slots
    /// that expired), or None.
    fn take(&mut self, now: u64) -> Option<[u8; FRAUTH]> {
        while self.next != self.end && self.q[self.next].frame.is_none() {
            self.next = (self.next + 1) % FR_NUMAUTH;
        }
        if self.next == self.end {
            return None;
        }
        let h = &self.q[self.next];
        let mut b = [0u8; FRAUTH];
        let age = AUTH_AGE - (now.saturating_sub(h.since) / 500_000) as i32;
        p32(&mut b, 0, age as u32);
        p32(&mut b, 4, h.index as u32);
        p32(&mut b, 8, h.pass);
        b[12..].copy_from_slice(&h.info);
        self.next = (self.next + 1) % FR_NUMAUTH;
        Some(b)
    }

    /// SIOCAUTHR: the program's verdict on a datagram it was handed.
    fn answer(&mut self, user: &[u8; FRAUTH]) -> Result<(), i32> {
        let i = g32(user, 4) as i32;
        if i < 0 || i as usize >= FR_NUMAUTH || g16(&self.q[i as usize].info, 74) != g16(user, 12 + 74) {
            return Err(EINVAL);
        }
        let h = &mut self.q[i as usize];
        let frame = h.frame.take();
        h.index = -2;
        h.pass = g32(user, 8);
        let ifp = g32(&h.info, 0);
        let Some(frame) = frame else { return Err(EINVAL) };
        let out = user[12 + 52] != 0;
        self.st[if out { AS_SENDOK } else { AS_QUEOK }] += 1;
        self.released.push(Released { ifp, out, frame });
        RELEASED.store(true, Ordering::Release);
        Ok(())
    }

    /// SIOCADAFR / SIOCRMAFR on IPL_LOGAUTH (fr_preauthcmd): a preauth rule.
    fn request(&mut self, user: &[u8; FRENTRY], add: bool) -> Result<(), i32> {
        let mut r = Rule::new(user);
        if r.flags & (FR_INQUE | FR_OUTQUE) == 0 {
            return Err(EINVAL);
        }
        let at = self.pre.iter().position(|x| x.same(&r));
        match (add, at) {
            (true, Some(_)) => Err(EEXIST),
            (true, None) => {
                r.resolve();
                self.pre.push(r);
                self.pre_since.push(now_us());
                Ok(())
            }
            (false, Some(k)) => {
                self.pre.remove(k);
                self.pre_since.remove(k);
                Ok(())
            }
            (false, None) => Err(ESRCH),
        }
    }

    /// struct fr_authstat (SIOCATHST): the counters, then fas_faelist.
    fn stat(&self) -> [u8; AUTHSTAT] {
        let mut b = [0u8; AUTHSTAT];
        for (k, v) in self.st.iter().enumerate() {
            p32(&mut b, 4 * k, *v);
        }
        p32(&mut b, 36, self.pre.first().map(|r| r.mem.addr()).unwrap_or(0));
        b
    }

    /// fr_authunload (ipf -D): held datagrams and preauth rules gone; the
    /// waiting programs woken (they find the filter off).
    fn unload(&mut self) {
        for h in self.q.iter_mut() {
            *h = Held::free();
        }
        (self.start, self.end, self.next, self.used) = (0, 0, 0, 0);
        self.pre.clear();
        self.pre_since.clear();
        for &w in &self.waiters {
            Auth::signal(w);
        }
    }
}

/// SIOCAUTHW for task `task`: the next held datagram's struct frauth, or
/// None after registering `mask` to be signalled when one is held (0: take
/// the task off the waiters). EIO while the filter is off.
pub fn auth_wait(task: u32, mask: u32) -> Result<Option<[u8; FRAUTH]>, i32> {
    let Some(mut e) = lock() else { return Err(EIO) };
    e.auth.waiters.retain(|w| w.0 != task);
    if !RUNNING.load(Ordering::Acquire) {
        return Err(EIO);
    }
    let now = now_us();
    e.expire(now);
    let got = e.auth.take(now);
    if got.is_none() && mask != 0 {
        e.auth.waiters.push((task, mask));
    }
    Ok(got)
}

/// Set when SIOCAUTHR let a datagram go, so the stack's loop takes the
/// engine lock only then (the caller wakes the stack: Stack::wake).
static RELEASED: AtomicBool = AtomicBool::new(false);

/// The datagrams auth programs let go since the last call.
pub fn take_released() -> Vec<Released> {
    if !RELEASED.swap(false, Ordering::AcqRel) {
        return Vec::new();
    }
    match lock() {
        Some(mut e) => core::mem::take(&mut e.auth.released),
        None => Vec::new(),
    }
}

static ENGINE: AtomicPtr<Mutex<Engine>> = AtomicPtr::new(core::ptr::null_mut());
/// ipf -E / -D (SIOCFRENB): off at start, as on Roadshow.
static RUNNING: AtomicBool = AtomicBool::new(false);

fn lock() -> Option<MutexGuard<'static, Engine>> {
    let mut p = ENGINE.load(Ordering::Acquire);
    if p.is_null() {
        let m = Box::into_raw(Box::new(Mutex::new(Engine::new()).ok()?));
        p = match ENGINE.compare_exchange(core::ptr::null_mut(), m, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => m,
            Err(other) => {
                // SAFETY: ours, never shared.
                drop(unsafe { Box::from_raw(m) });
                other
            }
        };
    }
    // SAFETY: the Box stored above, freed only by `free` at the library's
    // last Close, after which nobody calls in.
    unsafe { &*p }.lock().ok()
}

/// The library's last Close: the rules and the engine go.
pub fn free() {
    RUNNING.store(false, Ordering::Release);
    let p = ENGINE.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !p.is_null() {
        // SAFETY: made by `lock`; nobody calls in any more.
        drop(unsafe { Box::from_raw(p) });
    }
}

fn now_us() -> u64 {
    amigaos4::timer::get_up_time().as_micros()
}

/// Is the filter on (ipf -E)? NAT works only then, as on Roadshow.
pub fn running() -> bool {
    RUNNING.load(Ordering::Acquire)
}

/// Microseconds of up time (the state and NAT clocks).
pub fn now() -> u64 {
    now_us()
}

/// A natlog record (ipnat.rs) as an iplog record for minor IPL_LOGNAT:
/// the header (dsize 58: 24 + 34, not rounded, as Roadshow's), then it.
fn nat_record(rec: &[u8; crate::ipnat::NATLOG]) -> Vec<u8> {
    let now = amigaos4::timer::sys_time();
    let mut r = Vec::with_capacity(24 + rec.len());
    for v in [IPL_MAGIC, 1, now.secs.wrapping_add(AMIGA_EPOCH), now.micros, (24 + rec.len()) as u32, 0] {
        r.extend_from_slice(&v.to_be_bytes());
    }
    r.extend_from_slice(rec);
    r
}

/// The NAT's log records (ipnat.rs, sent with its lock let go).
pub fn nat_log(recs: Vec<[u8; crate::ipnat::NATLOG]>) {
    if recs.is_empty() {
        return;
    }
    if let Some(mut e) = lock() {
        for rec in recs {
            let r = nat_record(&rec);
            e.logs.add(IPL_LOGNAT as usize, r);
        }
    }
}

/// The filter on one IPv4 datagram of interface `ifp` (its ifnet): false to
/// drop it. Nothing happens until ipf -E.
///
/// A blocked datagram that came in may leave a reply in `reply` (an IPv4
/// datagram: return-rst, return-icmp) for the interface to send.
///
/// `eth` is the frame's Ethernet header (14 bytes), kept with a datagram an
/// "auth" rule holds; without it such a datagram is dropped (nospace).
pub fn check(ifp: u32, eth: &[u8], ip: &[u8], out: bool, reply: &mut Option<Vec<u8>>) -> bool {
    if !RUNNING.load(Ordering::Acquire) {
        return true;
    }
    match lock() {
        Some(mut e) => e.check(ifp, eth, ip, out as usize, now_us(), reply, false),
        None => true,
    }
}

/// Would the filter block datagram `ip` leaving interface `ifp`? Nothing
/// is counted, logged or kept. A socket's send asks first, so that the
/// sender gets EHOSTUNREACH as from Roadshow's ip_output (then it calls
/// [`check`] for the counters and the log, and does not send).
pub fn blocks(ifp: u32, ip: &[u8]) -> bool {
    if !RUNNING.load(Ordering::Acquire) {
        return false;
    }
    match lock() {
        Some(mut e) => !e.check(ifp, &[], ip, 1, now_us(), &mut None, true),
        None => false,
    }
}

/// A blocked datagram a socket was about to send: counted and logged as
/// leaving `ifp`; true when it was indeed blocked.
pub fn refuse(ifp: u32, ip: &[u8]) -> bool {
    blocks(ifp, ip) && !check(ifp, &[], ip, true, &mut None)
}

/// The datagram a UDP send would make (for [`refuse`]): header and payload.
pub fn udp_datagram(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, data: &[u8]) -> Vec<u8> {
    let mut d = ip_header(u32::from_be_bytes(src), u32::from_be_bytes(dst), 17, 8 + data.len()).to_vec();
    d.extend_from_slice(&sport.to_be_bytes());
    d.extend_from_slice(&dport.to_be_bytes());
    d.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(data);
    d
}

/// The SYN a TCP connect would send first (for [`refuse`]): a 20-byte
/// header with SYN alone.
pub fn tcp_syn(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
    let mut d = ip_header(u32::from_be_bytes(src), u32::from_be_bytes(dst), 6, 20).to_vec();
    d.extend_from_slice(&sport.to_be_bytes());
    d.extend_from_slice(&dport.to_be_bytes());
    d.extend_from_slice(&[0; 8]);
    d.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
    d
}

/// The Internet checksum of `b`, starting from `sum`.
fn cksum(b: &[u8], mut sum: u32) -> u16 {
    let mut k = 0;
    while k + 1 < b.len() {
        sum += u16::from_be_bytes([b[k], b[k + 1]]) as u32;
        k += 2;
    }
    if k < b.len() {
        sum += (b[k] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 header from `src` to `dst` for `len` bytes of protocol `p`.
fn ip_header(src: u32, dst: u32, p: u8, len: usize) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&((20 + len) as u16).to_be_bytes());
    h[8] = crate::settings::SETTINGS.ttl();
    h[9] = p;
    h[12..16].copy_from_slice(&src.to_be_bytes());
    h[16..20].copy_from_slice(&dst.to_be_bytes());
    let c = cksum(&h, 0);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h
}

/// send_reset: a TCP reset answering `ip` (none to a reset).
fn tcp_reset(ip: &[u8], fin: &Fin) -> Option<Vec<u8>> {
    let hl = fin.hlen as usize;
    let t = ip.get(hl..fin.plen as usize)?;
    if fin.p != 6 || fin.off != 0 || t.len() < 20 || t[13] & 0x04 != 0 {
        return None;
    }
    let toff = ((t[12] >> 4) as usize * 4).max(20).min(t.len());
    let flags = t[13];
    let mut r = [0u8; 20];
    r[0..2].copy_from_slice(&t[2..4]);
    r[2..4].copy_from_slice(&t[0..2]);
    if flags & 0x10 != 0 {
        // ACK: the reset takes the acknowledged sequence number.
        r[4..8].copy_from_slice(&t[8..12]);
        r[13] = 0x04;
    } else {
        let mut ack = u32::from_be_bytes([t[4], t[5], t[6], t[7]]).wrapping_add((t.len() - toff) as u32);
        if flags & 0x02 != 0 {
            ack = ack.wrapping_add(1);
        }
        if flags & 0x01 != 0 {
            ack = ack.wrapping_add(1);
        }
        r[8..12].copy_from_slice(&ack.to_be_bytes());
        r[13] = 0x14;
    }
    r[12] = 5 << 4;
    let (src, dst) = (fin.dst(), fin.src());
    let mut pseudo = 0u32;
    for w in [src >> 16, src & 0xffff, dst >> 16, dst & 0xffff, 6, 20] {
        pseudo += w;
    }
    let c = cksum(&r, pseudo);
    r[16..18].copy_from_slice(&c.to_be_bytes());
    let mut d = ip_header(src, dst, 6, 20).to_vec();
    d.extend_from_slice(&r);
    Some(d)
}

/// send_icmp_err: an ICMP unreachable (the rule's code) quoting `ip`'s
/// header and 8 bytes; none for an ICMP error itself.
fn icmp_unreach(ip: &[u8], fin: &Fin) -> Option<Vec<u8>> {
    let hl = fin.hlen as usize;
    let total = (fin.plen as usize).min(ip.len());
    if fin.p == 1 && fin.off == 0 && total > hl && !matches!(ip[hl], 0 | 8 | 13 | 14 | 15 | 16 | 17 | 18) {
        return None;
    }
    let quote = &ip[..(hl + 8).min(total)];
    let mut m = alloc::vec![0u8; 8];
    m[0] = 3;
    m[1] = fin.icode;
    m.extend_from_slice(quote);
    let c = cksum(&m, 0);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    let mut d = ip_header(fin.dst(), fin.src(), 1, m.len()).to_vec();
    d.extend_from_slice(&m);
    Some(d)
}

/// ipf_log_read: whole records from minor `minor`'s log, as many as fit in
/// `max` bytes (none when the first does not fit).
pub fn log_read(minor: u32, max: usize) -> Result<Vec<u8>, i32> {
    let mut e = lock().ok_or(EIO)?;
    Ok(e.logs.read(minor as usize & 3, max))
}

/// The bytes waiting in minor `minor`'s log.
pub fn log_waiting(minor: u32) -> usize {
    lock().map(|e| e.logs.bytes[minor as usize & 3]).unwrap_or(0)
}

/// ipf_set_notify_mask: signal `mask` to `task` when a record arrives (0
/// stops it).
pub fn set_notify(minor: u32, task: u32, mask: u32) {
    if let Some(mut e) = lock() {
        e.logs.notify[minor as usize & 3] = if mask != 0 { (task, mask) } else { (0, 0) };
    }
}

/// Read a caller's struct at the pointer `data` points to (the ioctls whose
/// argument is a struct pointer take a pointer to it).
///
/// # Safety
/// `data` points to a pointer to at least N readable bytes.
unsafe fn read_via<const N: usize>(data: *mut u8) -> [u8; N] {
    // SAFETY: the caller's contract.
    unsafe {
        let p = read_u32(data) as usize as *const u8;
        let mut b = [0u8; N];
        core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), N);
        b
    }
}

/// # Safety
/// `data` points to a pointer to at least `b.len()` writable bytes.
unsafe fn write_via(data: *mut u8, b: &[u8]) {
    // SAFETY: the caller's contract.
    unsafe {
        let p = read_u32(data) as usize as *mut u8;
        core::ptr::copy_nonoverlapping(b.as_ptr(), p, b.len());
    }
}

/// # Safety
/// `data` points to 4 readable bytes.
unsafe fn read_u32(data: *mut u8) -> u32 {
    let mut b = [0u8; 4];
    // SAFETY: the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(data as *const u8, b.as_mut_ptr(), 4) };
    u32::from_be_bytes(b)
}

/// # Safety
/// `data` points to 4 writable bytes.
unsafe fn write_u32(data: *mut u8, v: u32) {
    // SAFETY: the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(v.to_be_bytes().as_ptr(), data, 4) }
}

/// ipf_ioctl on minor `minor`: Ok(0) or the errno.
///
/// # Safety
/// `data` is what the command says it is (a pointer to a value, or to a
/// pointer to a struct), as ipf, ipfstat, ipmon and ipnat pass it.
pub unsafe fn ioctl(minor: u32, cmd: u32, data: *mut u8) -> Result<i32, i32> {
    // Roadshow: every auth command EIO while the filter is off.
    if minor == IPL_LOGAUTH && !RUNNING.load(Ordering::Acquire) {
        return Err(EIO);
    }
    let Some(mut e) = lock() else { return Err(EIO) };
    let e = &mut *e;
    // SAFETY (for every access below): the caller's contract on `data`.
    unsafe {
        match (minor, cmd) {
            (IPL_LOGIPF, SIOCADAFR | SIOCRMAFR | SIOCADIFR | SIOCRMIFR | SIOCINAFR | SIOCINIFR) => {
                let user = read_via::<FRENTRY>(data);
                let set = if matches!(cmd, SIOCADIFR | SIOCRMIFR | SIOCINIFR) { 1 - e.active } else { e.active };
                let add = !matches!(cmd, SIOCRMAFR | SIOCRMIFR);
                e.request(&user, set, add, matches!(cmd, SIOCINAFR | SIOCINIFR))?;
            }
            (IPL_LOGIPF, SIOCSETFF) => e.flags = read_u32(data) & FF_LOGGING,
            (IPL_LOGIPF, SIOCGETFF) => write_u32(data, e.flags),
            (IPL_LOGIPF, SIOCGETFS) => write_via(data, &e.friostat(RUNNING.load(Ordering::Acquire))),
            (IPL_LOGIPF, SIOCFRZST) => {
                write_via(data, &e.friostat(RUNNING.load(Ordering::Acquire)));
                e.stats = [[0; ST_WORDS]; 2];
            }
            (IPL_LOGIPF, SIOCIPFFL) => {
                let n = e.flush(read_u32(data));
                write_u32(data, n);
            }
            (IPL_LOGIPF, SIOCIPFFB) => {
                let n = e.logs.flush(IPL_LOGIPF as usize);
                write_u32(data, n as u32);
            }
            (0..=3, FIONREAD) => write_u32(data, e.logs.bytes[minor as usize] as u32),
            (IPL_LOGIPF, SIOCSWAPA) => {
                write_u32(data, e.active as u32);
                e.active = 1 - e.active;
                e.uncache();
            }
            (IPL_LOGIPF, SIOCFRENB) => {
                let on = read_u32(data) != 0;
                if on && RUNNING.load(Ordering::Acquire) {
                    return Err(EBUSY);
                }
                e.uncache();
                RUNNING.store(on, Ordering::Release);
                if !on {
                    // fr_authunload; a waiting SIOCAUTHW wakes to EIO.
                    e.auth.unload();
                    // ip_natunload (the NAT has its own lock); its NL_FLUSH
                    // records into the log here, as this lock is held.
                    for rec in crate::ipnat::unload() {
                        e.logs.add(IPL_LOGNAT as usize, nat_record(&rec));
                    }
                }
            }
            (IPL_LOGIPF, SIOCFRSYN) => e.sync(),
            (IPL_LOGIPF, SIOCZRLST) => {
                let mut user = read_via::<FRENTRY>(data);
                e.zero_rule(&mut user)?;
                write_via(data, &user);
            }
            (IPL_LOGIPF, SIOCGFRST) => write_via(data, &e.ipfrstat()),
            (IPL_LOGSTATE, SIOCGETFS) => write_via(data, &e.ips_stat()),
            (IPL_LOGSTATE, SIOCIPFFL) => {
                let n = e.flush_states(read_u32(data));
                e.uncache();
                write_u32(data, n);
            }
            (IPL_LOGNAT, _) => {
                // The NAT has its own lock (ipnat.rs).
                return crate::ipnat::ioctl(cmd, data, RUNNING.load(Ordering::Acquire));
            }
            (IPL_LOGAUTH, SIOCATHST) => write_via(data, &e.auth.stat()),
            (IPL_LOGAUTH, SIOCAUTHR) => {
                let user = read_via::<FRAUTH>(data);
                e.auth.answer(&user)?;
            }
            (IPL_LOGAUTH, SIOCADAFR | SIOCRMAFR) => {
                let user = read_via::<FRENTRY>(data);
                e.auth.request(&user, cmd == SIOCADAFR)?;
            }
            _ => return Err(EINVAL),
        }
    }
    Ok(0)
}
