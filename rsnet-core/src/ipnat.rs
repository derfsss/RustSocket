//! IP Filter 3.4.21's NAT (ipnat, minor IPL_LOGNAT): "rdr" redirects what
//! comes in, "map" (with portmap ranges or "portmap auto") rewrites the
//! source of what goes out, "bimap" both, each translated flow kept as a
//! session; on every IPv4 datagram while the filter runs (ipf -E): inbound
//! before the rules, outbound after them, as 3.4's fr_check calls
//! ip_natin / ip_natout. Addresses and ports are rewritten and the IP, TCP
//! and UDP checksums made again.
//!
//! The ABI is the SDK's netinet/ip_nat.h (pack(2): ipnat_t 140 bytes, nat_t
//! 116, natstat_t 84), filled in as Roadshow 1.15 does (measured with
//! testprogs/rstcp/c/ipfprobe.c nat): a rule keeps the caller's ipnat_t
//! with in_next / in_ifp / in_space / in_use / in_hits / in_nextip /
//! in_pnext set; a session is a nat_t (addresses and ports inside, outside
//! and the other end, nat_dir, nat_p, nat_flags the rule's protocol flags,
//! nat_ptr, packets and bytes, the interface name) chained from
//! ns_instances, so ipnat -l lists rules and sessions as on Roadshow; table
//! sizes 127. Like Roadshow, the NAT ioctls answer EIO while the filter is
//! off.
//!
//! Also as 3.4.21 (measured on Roadshow): in_space and in_nextip set up as its SIOCADNAT
//! does; "map-block" hands out each inside address's block of ports
//! (nat_new: in_ippip / in_ppip as the ipnat tool computed them, so a
//! map-block whose inside and outside masks are equal gets in_ppip 0 from
//! the tool and never maps: "bad nat" for every datagram, on Roadshow too);
//! "rdr ... -> ip1,ip2" (IPN_SPLIT, round-robin) alternates between the two
//! addresses; "-> ifname/32" (0/32) takes the interface's address; a
//! "proxy" rule needs a proxy the kernel knows, and Roadshow's knows "ftp"
//! over TCP only (any other: ENOENT); a rule removed or flushed (ipnat -C)
//! while sessions use it stays until they end (IPN_DELETE), and ipnat -C
//! leaves the sessions; a new outbound session takes one from its rule's
//! in_space and an ended one gives one back (nat_new, nat_delete); ipf -D
//! unloads the NAT (rules and sessions; the counters stay).
//!
//! NAT logging: as 3.4's nat_log,
//! a struct natlog (34 bytes: the other end's, outside and inside
//! addresses, their ports, the type, the rule's index in the list or -1,
//! packets, bytes, protocol) in an iplog record on minor IPL_LOGNAT for
//! each new session (its rule's in_redir), each expired one (NL_EXPIRE)
//! and each flushed one (NL_FLUSH, ipnat -F and ipf -D); Roadshow writes
//! the same record for a new map session. The records go to the filter's
//! log (ipfil.rs) once the NAT's lock is let go.
//!
//! Not done: the FTP proxy's own work (rewriting PORT / 227 addresses when
//! the map changes them, and the proxy state ipnat -l prints under its
//! session: Roadshow's data connections are ordinary map sessions, which
//! rustsocket makes too), the headers quoted inside ICMP errors.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

use amigaos4::sync::{Mutex, MutexGuard};

pub const SIOCADNAT: u32 = 0x8004_723C;
pub const SIOCRMNAT: u32 = 0x8004_723D;
pub const SIOCGNATS: u32 = 0xC004_723E;
pub const SIOCGNATL: u32 = 0xC004_723F;
pub const SIOCIPFFL: u32 = 0xC004_7241;

const IPNAT: usize = 140;
const NAT: usize = 116;
const NATSTAT: usize = 84;
/// ipnat_t: what a duplicate is compared over (IPN_CMPSIZ, from in_flags).
const IN_FLAGS: usize = 48;

const NAT_MAP: u32 = 1;
const NAT_REDIRECT: u32 = 2;
const NAT_MAPBLK: u32 = 4;
const IPN_TCP: u32 = 1;
const IPN_UDP: u32 = 2;
const IPN_AUTOPORTMAP: u32 = 0x10;
const IPN_IPRANGE: u32 = 0x20;
const IPN_SPLIT: u32 = 0x80;
const IPN_DELETE: u32 = 0x4;
/// 3.4's USABLE_PORTS and MAPBLK_MINPORT.
const USABLE_PORTS: u32 = 65535 - 1023;
/// ip_nat.h: NL_FLUSH, NL_EXPIRE; struct natlog's size (pack(2)).
const NL_FLUSH: u16 = 0xfffe;
const NL_EXPIRE: u16 = 0xffff;
pub const NATLOG: usize = 34;
const MAPBLK_MINPORT: u32 = 1024;
const IPN_NOTSRC: u32 = 0x80000;
const IPN_NOTDST: u32 = 0x100000;
const TABLE_SIZE: u32 = 127;

const EIO: i32 = 5;
const ESRCH: i32 = 3;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOENT: i32 = 2;

/// The proxies Roadshow's kernel knows (appr_lookup): FTP over TCP only
/// (measured: rcmd, raudio, ipsec, netbios and ftp/udp give ENOENT). A
/// rule's in_apr points here.
static APR_FTP: [u8; 20] = *b"ftp\0\0\0\0\0\0\0\0\0\0\0\0\0\x06\0\0\0";

const TCP_IDLE_S: u64 = 5 * 24 * 3600;
const TCP_CLOSE_S: u64 = 60;
/// 3.4's fr_defnatage (600 s) for anything but TCP, fr_defnaticmpage (3 s)
/// for ICMP.
const UDP_S: u64 = 600;
const OTHER_S: u64 = 600;
const ICMP_S: u64 = 3;

fn g16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn g32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn p16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_be_bytes());
}

fn p32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_be_bytes());
}

/// A record in C memory that tools read (MEMF_SHARED, the library's
/// allocator).
struct CMem<const N: usize>(NonNull<[u8; N]>);

impl<const N: usize> CMem<N> {
    fn new(b: [u8; N]) -> Self {
        CMem(NonNull::from(Box::leak(Box::new(b))))
    }

    fn addr(&self) -> u32 {
        self.0.as_ptr() as usize as u32
    }

    fn b(&mut self) -> &mut [u8; N] {
        // SAFETY: ours (made by `new`, freed by Drop), used under the NAT
        // mutex.
        unsafe { self.0.as_mut() }
    }
}

impl<const N: usize> Drop for CMem<N> {
    fn drop(&mut self) {
        // SAFETY: made by Box::leak in `new`, freed once here.
        drop(unsafe { Box::from_raw(self.0.as_ptr()) });
    }
}

// SAFETY: only touched under the NAT mutex.
unsafe impl<const N: usize> Send for CMem<N> {}

struct Rule {
    mem: CMem<IPNAT>,
    orig: [u8; IPNAT - IN_FLAGS],
    redir: u32,
    flags: u32,
    ifname: [u8; 16],
    ifa: u32,
    pmin: u16,
    pmax: u16,
    inip: u32,
    inmsk: u32,
    outip: u32,
    outmsk: u32,
    srcip: u32,
    srcmsk: u32,
    p: u8,
    /// in_tuc's port comparisons (source, destination): op, port, top.
    scmp: (u32, u16, u16),
    dcmp: (u32, u16, u16),
    /// The next address and port a map hands out; the target port of a rdr.
    nextip: u32,
    pnext: u16,
    hits: u32,
    /// map-block: inside addresses per outside one, ports per inside one
    /// (in_ippip, in_ppip, as the ipnat tool set them); in_space.
    ippip: u32,
    ppip: u32,
    space: u32,
    /// The proxy's port (in_dport) when the rule names one.
    proxy: bool,
}

impl Rule {
    fn new(user: &[u8; IPNAT]) -> Rule {
        let mut b = *user;
        let mut orig = [0u8; IPNAT - IN_FLAGS];
        orig.copy_from_slice(&b[IN_FLAGS..]);
        let mut ifname = [0u8; 16];
        ifname.copy_from_slice(&b[106..122]);
        for o in [0, 4, 8, 12, 16, 20, 24, 28, 32, 36] {
            p32(&mut b, o, 0);
        }
        Rule {
            redir: g32(&b, 102),
            flags: g32(&b, 48),
            ifname,
            ifa: 0,
            pmin: g16(&b, 56),
            pmax: g16(&b, 58),
            inip: g32(&b, 60),
            inmsk: g32(&b, 64),
            outip: g32(&b, 68),
            outmsk: g32(&b, 72),
            srcip: g32(&b, 76),
            srcmsk: g32(&b, 80),
            p: b[138],
            scmp: (g32(&b, 86), g16(&b, 90), g16(&b, 92)),
            dcmp: (g32(&b, 94), g16(&b, 98), g16(&b, 100)),
            nextip: g32(&b, 40),
            pnext: g16(&b, 44),
            hits: 0,
            ippip: g16(&b, 46) as u32,
            ppip: g16(&b, 54) as u32,
            space: 0,
            proxy: false,
            orig,
            mem: CMem::new(b),
        }
    }

    fn resolve(&mut self) {
        let n = self.ifname.iter().position(|&c| c == 0).unwrap_or(16);
        self.ifa = if n == 0 { 0 } else { crate::ipf::ifnet_by_name(&self.ifname[..n]).unwrap_or(u32::MAX) };
        let ifa = self.ifa;
        p32(self.mem.b(), 20, ifa);
    }

    /// SIOCADNAT's in_space, in_nextip and in_pnext (3.4.21's formulas).
    fn setup(&mut self) {
        let map = self.redir & NAT_MAP != 0;
        let mut space = if self.redir & NAT_MAPBLK != 0 {
            USABLE_PORTS.wrapping_mul(!self.outmsk)
        } else if self.flags & IPN_AUTOPORTMAP != 0 {
            USABLE_PORTS.wrapping_mul(!self.inmsk)
        } else if self.flags & IPN_IPRANGE != 0 {
            self.outmsk.wrapping_sub(self.outip)
        } else if self.flags & IPN_SPLIT != 0 {
            2
        } else {
            !self.outmsk
        };
        if space != 0 {
            space = if self.flags & IPN_IPRANGE != 0 { space + 1 } else { space - 1 };
        } else {
            space = 1;
        }
        self.nextip = if self.outmsk != u32::MAX && self.outmsk != 0 && self.flags & (IPN_IPRANGE | IPN_SPLIT) == 0 {
            self.outip.wrapping_add(1)
        } else if self.flags & IPN_SPLIT != 0 && self.redir & NAT_REDIRECT != 0 {
            self.inip
        } else {
            self.outip
        };
        if map {
            self.pnext = self.pmin;
            if self.pmax >= self.pmin {
                space = space.wrapping_mul((self.pmax - self.pmin) as u32 + 1);
                let i = self.inmsk;
                if i != 0 && i != u32::MAX {
                    let j = space.wrapping_mul((!i).wrapping_add(1));
                    space = if j >= space { j } else { u32::MAX };
                }
            }
            if self.flags & (IPN_TCP | IPN_UDP) == 0 {
                let j = space.wrapping_mul(256);
                space = if j >= space { j } else { u32::MAX };
            }
        }
        self.space = space;
    }

    /// The datagram's protocol is one this rule takes (IPN_TCP / IPN_UDP,
    /// or in_p).
    fn proto_ok(&self, p: u8) -> bool {
        let tu = self.flags & (IPN_TCP | IPN_UDP);
        if tu != 0 {
            return (p == 6 && tu & IPN_TCP != 0) || (p == 17 && tu & IPN_UDP != 0);
        }
        self.p == 0 || self.p == p
    }

    /// in_tuc: the "port" comparisons after from / to (3.4's
    /// fr_tcpudpchk ops), for TCP and UDP.
    fn tuc_ok(&self, p: u8, sp: u16, dp: u16) -> bool {
        if p != 6 && p != 17 {
            return self.scmp.0 == 0 && self.dcmp.0 == 0;
        }
        let ok = |(op, port, top): (u32, u16, u16), v: u16| match op {
            1 => v == port,
            2 => v != port,
            3 => v < port,
            4 => v > port,
            5 => v <= port,
            6 => v >= port,
            7 => v < port || v > top,
            8 => v > port && v < top,
            _ => true,
        };
        ok(self.scmp, sp) && ok(self.dcmp, dp)
    }

    /// Ports are translated (a portmap, or a rdr's port range).
    fn ports(&self, p: u8) -> bool {
        (p == 6 || p == 17) && (self.pmin != 0 || self.flags & IPN_AUTOPORTMAP != 0)
    }
}

struct Session {
    mem: CMem<NAT>,
    rule: u32,
    p: u8,
    inip: u32,
    inport: u16,
    outip: u32,
    outport: u16,
    oip: u32,
    oport: u16,
    fin: u8,
    until: u64,
}

#[derive(Default)]
struct Nat {
    rules: Vec<Rule>,
    /// Rules removed or flushed while sessions use them (IPN_DELETE):
    /// kept, off the list, until their last session ends.
    dead: Vec<Rule>,
    /// natlog records waiting for the filter's log (ipfil::nat_log).
    logq: Vec<[u8; NATLOG]>,
    sessions: Vec<Session>,
    mapped: [u32; 2],
    added: u32,
    expire: u32,
    memfail: u32,
    badnat: u32,
}

/// Zeroed hash tables for natstat's pointers (127 entries each: ipnat
/// reads the sizes, the lists come from ns_list and ns_instances).
static TABLES: AtomicPtr<[u32; 4 * TABLE_SIZE as usize]> = AtomicPtr::new(core::ptr::null_mut());

fn tables() -> u32 {
    let mut p = TABLES.load(Ordering::Acquire);
    if p.is_null() {
        let b = Box::into_raw(Box::new([0u32; 4 * TABLE_SIZE as usize]));
        p = match TABLES.compare_exchange(core::ptr::null_mut(), b, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => b,
            Err(other) => {
                // SAFETY: ours, never shared.
                drop(unsafe { Box::from_raw(b) });
                other
            }
        };
    }
    p as usize as u32
}

impl Nat {
    /// Take rule `k` off the list (SIOCRMNAT, ipnat -C): freed, or kept
    /// while sessions use it.
    fn unlist(&mut self, k: usize) {
        let mut r = self.rules.remove(k);
        let addr = r.mem.addr();
        if self.sessions.iter().any(|s| s.rule == addr) {
            r.flags |= IPN_DELETE;
            let f = r.flags;
            p32(r.mem.b(), 48, f);
            p32(r.mem.b(), 0, 0);
            self.dead.push(r);
        }
    }

    fn relink(&mut self) {
        let used: Vec<u32> = self.sessions.iter().map(|s| s.rule).collect();
        self.dead.retain(|r| used.contains(&r.mem.addr()));
        let addrs: Vec<u32> = self.rules.iter().map(|r| r.mem.addr()).collect();
        for (k, r) in self.rules.iter_mut().enumerate() {
            let next = addrs.get(k + 1).copied().unwrap_or(0);
            p32(r.mem.b(), 0, next);
        }
        let saddrs: Vec<u32> = self.sessions.iter().map(|s| s.mem.addr()).collect();
        for (k, s) in self.sessions.iter_mut().enumerate() {
            let next = saddrs.get(k + 1).copied().unwrap_or(0);
            p32(s.mem.b(), 72, next);
        }
        let counts: Vec<(u32, u32)> = self.rules.iter().map(|r| (r.mem.addr(), self.sessions.iter().filter(|s| s.rule == r.mem.addr()).count() as u32)).collect();
        for (r, (_, n)) in self.rules.iter_mut().zip(counts) {
            let (hits, nextip, pnext, space) = (r.hits, r.nextip, r.pnext, r.space);
            let b = r.mem.b();
            p32(b, 28, space);
            p32(b, 32, n);
            p32(b, 36, hits);
            p32(b, 40, nextip);
            p16(b, 44, pnext);
        }
    }

    fn expire(&mut self, now: u64) {
        let n = self.drop_sessions(|s| s.until > now, NL_EXPIRE);
        if n != 0 {
            self.expire += n;
            self.relink();
        }
    }

    /// Drop the sessions `keep` refuses (nat_delete: each gives its rule
    /// one in_space back): how many.
    fn drop_sessions(&mut self, keep: impl Fn(&Session) -> bool, kind: u16) -> u32 {
        let gone: Vec<u32> = self.sessions.iter().filter(|s| !keep(s)).map(|s| s.rule).collect();
        if gone.is_empty() {
            return 0;
        }
        let logs: Vec<[u8; NATLOG]> = self.sessions.iter().filter(|s| !keep(s)).map(|s| self.natlog(s, kind)).collect();
        self.logq.extend(logs);
        self.sessions.retain(|s| keep(s));
        for a in &gone {
            if let Some(r) = self.rules.iter_mut().chain(self.dead.iter_mut()).find(|r| r.mem.addr() == *a) {
                r.space = r.space.wrapping_add(1);
            }
        }
        gone.len() as u32
    }

    fn natstat(&self) -> [u8; NATSTAT] {
        let mut b = [0u8; NATSTAT];
        p32(&mut b, 0, self.mapped[0]);
        p32(&mut b, 4, self.mapped[1]);
        p32(&mut b, 8, (self.rules.len() + self.dead.len()) as u32);
        p32(&mut b, 12, self.added);
        p32(&mut b, 16, self.expire);
        p32(&mut b, 20, self.sessions.len() as u32);
        p32(&mut b, 32, self.memfail);
        p32(&mut b, 36, self.badnat);
        let t = tables();
        let size = TABLE_SIZE * 4;
        p32(&mut b, 40, t);
        p32(&mut b, 44, t + size);
        p32(&mut b, 48, t + 2 * size);
        p32(&mut b, 52, self.rules.first().map(|r| r.mem.addr()).unwrap_or(0));
        for o in [60, 64, 68, 72] {
            p32(&mut b, o, TABLE_SIZE);
        }
        p32(&mut b, 76, self.sessions.first().map(|s| s.mem.addr()).unwrap_or(0));
        b
    }

    fn add_session(&mut self, k: usize, dir: u32, p: u8, inside: (u32, u16), outside: (u32, u16), other: (u32, u16), ifp: u32, now: u64) {
        let r = &mut self.rules[k];
        r.hits += 1;
        if dir == 0 && r.space > 0 {
            r.space -= 1;
        }
        let mut m = [0u8; NAT];
        p32(&mut m, 4, r.flags & (IPN_TCP | IPN_UDP));
        p32(&mut m, 32, inside.0);
        p32(&mut m, 36, outside.0);
        p32(&mut m, 40, other.0);
        p16(&mut m, 52, other.1);
        p16(&mut m, 54, inside.1);
        p16(&mut m, 56, outside.1);
        m[62] = p;
        p32(&mut m, 64, r.mem.addr());
        p32(&mut m, 92, ifp);
        p32(&mut m, 96, dir);
        m[100..116].copy_from_slice(&crate::ipf::ifnet_name(ifp));
        let rule = r.mem.addr();
        // Newest first, as Roadshow lists them (ns_instances).
        self.sessions.insert(0, Session {
            mem: CMem::new(m),
            rule,

            p,
            inip: inside.0,
            inport: inside.1,
            outip: outside.0,
            outport: outside.1,
            oip: other.0,
            oport: other.1,
            fin: 0,
            until: now + 1_000_000 * timeout(p, 0),
        });
        self.added += 1;
        let kind = self.rules[k].redir as u16;
        let rec = self.natlog(&self.sessions[0], kind);
        self.logq.push(rec);
        self.relink();
    }

    /// struct natlog for session `s` (3.4's nat_log): the other end's,
    /// outside and inside addresses and ports, the type, the rule's index
    /// in the list (-1: none there), packets, bytes, protocol.
    fn natlog(&self, s: &Session, kind: u16) -> [u8; NATLOG] {
        let mut b = [0u8; NATLOG];
        p32(&mut b, 0, s.oip);
        p32(&mut b, 4, s.outip);
        p32(&mut b, 8, s.inip);
        p16(&mut b, 12, s.oport);
        p16(&mut b, 14, s.outport);
        p16(&mut b, 16, s.inport);
        p16(&mut b, 18, kind);
        let rule = self.rules.iter().position(|r| r.mem.addr() == s.rule).map(|k| k as u32).unwrap_or(u32::MAX);
        p32(&mut b, 20, rule);
        // SAFETY: the session's own nat_t copy (NAT bytes).
        let m = unsafe { &*s.mem.0.as_ptr() };
        p32(&mut b, 24, g32(m, 44));
        p32(&mut b, 28, g32(m, 48));
        b[32] = s.p;
        b
    }
}

fn timeout(p: u8, fin: u8) -> u64 {
    match p {
        6 if fin != 0 => TCP_CLOSE_S,
        6 => TCP_IDLE_S,
        17 => UDP_S,
        1 => ICMP_S,
        _ => OTHER_S,
    }
}

static NATS: AtomicPtr<Mutex<Nat>> = AtomicPtr::new(core::ptr::null_mut());

fn lock() -> Option<MutexGuard<'static, Nat>> {
    let mut p = NATS.load(Ordering::Acquire);
    if p.is_null() {
        let m = Box::into_raw(Box::new(Mutex::new(Nat::default()).ok()?));
        p = match NATS.compare_exchange(core::ptr::null_mut(), m, Ordering::AcqRel, Ordering::Acquire) {
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

/// The library's last Close.
pub fn free() {
    let p = NATS.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !p.is_null() {
        // SAFETY: made by `lock`; nobody calls in any more.
        drop(unsafe { Box::from_raw(p) });
    }
    let t = TABLES.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !t.is_null() {
        // SAFETY: made by `tables`; nobody reads it any more.
        drop(unsafe { Box::from_raw(t) });
    }
}

/// The checksums of an IPv4 datagram made again after a rewrite (TCP and
/// UDP only in the first fragment; a UDP checksum of 0 stays 0).
fn fix_sums(ip: &mut [u8]) {
    let hl = ((ip[0] & 15) as usize) * 4;
    let len = (g16(ip, 2) as usize).min(ip.len());
    ip[10] = 0;
    ip[11] = 0;
    let c = sum(&ip[..hl], 0);
    p16(ip, 10, c);
    let off = g16(ip, 6) & 0x1fff;
    if off != 0 || len <= hl {
        return;
    }
    let p = ip[9];
    let seg = len - hl;
    let o = match p {
        6 if seg >= 20 => 16,
        17 if seg >= 8 && g16(ip, hl + 6) != 0 => 6,
        _ => return,
    };
    p16(ip, hl + o, 0);
    let mut pseudo = 0u32;
    for w in [g16(ip, 12), g16(ip, 14), g16(ip, 16), g16(ip, 18)] {
        pseudo += w as u32;
    }
    pseudo += p as u32 + seg as u32;
    let mut c = sum(&ip[hl..len], pseudo);
    if p == 17 && c == 0 {
        c = 0xffff;
    }
    p16(ip, hl + o, c);
}

fn sum(b: &[u8], mut s: u32) -> u16 {
    let mut k = 0;
    while k + 1 < b.len() {
        s += g16(b, k) as u32;
        k += 2;
    }
    if k < b.len() {
        s += (b[k] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// The fields NAT looks at: protocol, addresses, ports (0 for what has
/// none or for a later fragment), the header length.
fn fields(ip: &[u8]) -> Option<(u8, u32, u32, u16, u16, usize)> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let hl = ((ip[0] & 15) as usize) * 4;
    let len = (g16(ip, 2) as usize).min(ip.len());
    if hl < 20 || len < hl {
        return None;
    }
    let p = ip[9];
    let first = g16(ip, 6) & 0x1fff == 0;
    let (sp, dp) = if (p == 6 || p == 17) && first && len >= hl + 4 { (g16(ip, hl), g16(ip, hl + 2)) } else { (0, 0) };
    Some((p, g32(ip, 12), g32(ip, 16), sp, dp, hl))
}

fn set_src(ip: &mut [u8], a: u32, port: Option<u16>, hl: usize) {
    p32(ip, 12, a);
    if let Some(pt) = port {
        p16(ip, hl, pt);
    }
}

fn set_dst(ip: &mut [u8], a: u32, port: Option<u16>, hl: usize) {
    p32(ip, 16, a);
    if let Some(pt) = port {
        p16(ip, hl + 2, pt);
    }
}

fn tcp_fin(ip: &[u8], p: u8, hl: usize) -> bool {
    p == 6 && ip.len() >= hl + 14 && ip[hl + 13] & 0x05 != 0
}

/// ip_natin: a datagram that came in on `ifp`; true when rewritten.
pub fn nat_in(ifp: u32, ip: &mut [u8], now: u64) -> bool {
    let (r, logs) = {
        let Some(mut n) = lock() else { return false };
        let r = nat_in_locked(&mut n, ifp, ip, now);
        (r, core::mem::take(&mut n.logq))
    };
    crate::ipfil::nat_log(logs);
    r
}

fn nat_in_locked(n: &mut Nat, ifp: u32, ip: &mut [u8], now: u64) -> bool {
    if n.rules.is_empty() && n.sessions.is_empty() {
        return false;
    }
    n.expire(now);
    let Some((p, src, dst, sp, dp, hl)) = fields(ip) else { return false };
    let ported = sp != 0 || dp != 0;
    // A flow we know: back to its inside address and port.
    if let Some(k) = n.sessions.iter().position(|s| s.p == p && s.outip == dst && s.oip == src && (!ported || (s.outport == dp && s.oport == sp))) {
        let fin = tcp_fin(ip, p, hl);
        let s = &mut n.sessions[k];
        let (inip, inport) = (s.inip, s.inport);
        if fin {
            s.fin = 1;
        }
        s.until = now + 1_000_000 * timeout(p, s.fin);
        bump(s, ip);
        set_dst(ip, inip, ported.then_some(inport), hl);
        fix_sums(ip);
        n.mapped[0] += 1;
        return true;
    }
    // A redirect (or the inbound half of a bimap).
    let found = n.rules.iter().position(|r| {
        r.redir & NAT_REDIRECT != 0
            && (r.ifa == 0 || r.ifa == ifp)
            && r.proto_ok(p)
            && (((dst & r.outmsk) == r.outip) != (r.flags & IPN_NOTDST != 0))
            && (r.srcmsk == 0 || (((src & r.srcmsk) == r.srcip) != (r.flags & IPN_NOTSRC != 0)))
            && (!r.ports(p) || r.redir & NAT_MAP != 0 || (dp >= r.pmin && dp <= r.pmax.max(r.pmin)))
            && r.tuc_ok(p, sp, dp)
    });
    let Some(k) = found else { return false };
    let r = &mut n.rules[k];
    let bimap = r.redir & NAT_MAP != 0;
    let newip = if bimap {
        r.inip | (dst & !r.inmsk)
    } else if r.flags & IPN_SPLIT != 0 {
        // "-> ip1,ip2": in turn (in_nip; the second address is in_inmsk).
        let a = r.nextip;
        r.nextip = if a == r.inip { r.inmsk } else { r.inip };
        a
    } else {
        r.inip
    };
    let newport = if !bimap && r.ports(p) && r.pnext != 0 { r.pnext.wrapping_add(dp - r.pmin) } else { dp };
    n.add_session(k, 1, p, (newip, newport), (dst, dp), (src, sp), ifp, now);

    bump(&mut n.sessions[0], ip);
    set_dst(ip, newip, ported.then_some(newport), hl);
    fix_sums(ip);
    n.mapped[0] += 1;
    true
}

/// ip_natout: a datagram going out on `ifp` that the rules passed; true
/// when rewritten.
pub fn nat_out(ifp: u32, ip: &mut [u8], now: u64) -> bool {
    let (r, logs) = {
        let Some(mut n) = lock() else { return false };
        let r = nat_out_locked(&mut n, ifp, ip, now);
        (r, core::mem::take(&mut n.logq))
    };
    crate::ipfil::nat_log(logs);
    r
}

fn nat_out_locked(n: &mut Nat, ifp: u32, ip: &mut [u8], now: u64) -> bool {
    if n.rules.is_empty() && n.sessions.is_empty() {
        return false;
    }
    n.expire(now);
    let Some((p, src, dst, sp, dp, hl)) = fields(ip) else { return false };
    let ported = sp != 0 || dp != 0;
    if let Some(k) = n.sessions.iter().position(|s| s.p == p && s.inip == src && s.oip == dst && (!ported || (s.inport == sp && s.oport == dp))) {
        let fin = tcp_fin(ip, p, hl);
        let s = &mut n.sessions[k];
        let (outip, outport) = (s.outip, s.outport);
        if fin {
            s.fin = 1;
        }
        s.until = now + 1_000_000 * timeout(p, s.fin);
        bump(s, ip);
        set_src(ip, outip, ported.then_some(outport), hl);
        fix_sums(ip);
        n.mapped[1] += 1;
        return true;
    }
    let found = n.rules.iter().position(|r| {
        r.redir & (NAT_MAP | NAT_MAPBLK) != 0
            && (r.ifa == 0 || r.ifa == ifp)
            && r.proto_ok(p)
            && (((src & r.inmsk) == r.inip) != (r.flags & IPN_NOTSRC != 0))
            && (r.srcmsk == 0 || (((dst & r.srcmsk) == r.srcip) != (r.flags & IPN_NOTDST != 0)))
            && r.tuc_ok(p, sp, dp)
    });
    let Some(k) = found else { return false };
    if n.rules[k].redir & NAT_MAPBLK != 0 {
        // nat_new's map-block: the inside address's own block of ports.
        let r = &n.rules[k];
        let tcpudp = p == 6 || p == 17;
        let inb = src & !r.inmsk;
        let mut got = None;
        let mut l = 0u32;
        while r.ippip != 0 && l < r.ppip && (l == 0 || tcpudp) && !(l > 0 && r.outmsk == u32::MAX && r.pnext == 0) {
            let a = ((inb / r.ippip) & !r.outmsk).wrapping_add(r.outip);
            let port = if tcpudp { ((sp as u32 + l) % r.ppip + r.ppip * (inb % r.ippip) + MAPBLK_MINPORT) as u16 } else { sp };
            if !n.sessions.iter().any(|s| s.p == p && s.outip == a && s.outport == port && s.oip == dst && s.oport == dp) {
                got = Some((a, port));
                break;
            }
            l += 1;
        }
        let Some((newip, newport)) = got else {
            n.badnat += 1;
            return false;
        };
        n.add_session(k, 0, p, (src, sp), (newip, newport), (dst, dp), ifp, now);
        bump(&mut n.sessions[0], ip);
        set_src(ip, newip, ported.then_some(newport), hl);
        fix_sums(ip);
        n.mapped[1] += 1;
        return true;
    }
    // The outside ends in use, so a portmap hands out a free port.
    let used: Vec<(u32, u16)> = n.sessions.iter().filter(|s| s.p == p).map(|s| (s.outip, s.outport)).collect();
    let r = &mut n.rules[k];
    let bimap = r.redir & NAT_REDIRECT != 0;
    // The new address: one of the range (0/32: keep the interface's own,
    // which is the source here), the next in turn.
    let newip = if r.outip == 0 && r.outmsk == u32::MAX {
        src
    } else if bimap {
        r.outip | (src & !r.outmsk)
    } else if r.outmsk == u32::MAX {
        r.outip
    } else {
        let lo = r.outip & r.outmsk;
        let span = !r.outmsk;
        let mut a = if r.nextip & r.outmsk == lo { r.nextip } else { lo + 1 };
        if a & span == 0 || a & span == span {
            a = lo + 1;
        }
        let mut next = a + 1;
        if next & span == span {
            next = lo + 1;
        }
        r.nextip = next;
        a
    };
    let newport = if r.ports(p) && !bimap && r.flags & IPN_AUTOPORTMAP != 0 {
        // "portmap auto": nat_new's block per inside address, from the
        // ipnat tool's in_ippip / in_ppip (Roadshow: 10.0.6.2 port 1035
        // -> 1555 for 10.0.6.0/24 -> one address).
        let (ippip, ppip) = (r.ippip.max(1), r.ppip.max(1));
        let mut pt = sp;
        for l in 0..ppip {
            let c = ((sp as u32 + l) % ppip + ppip * (src % ippip) + MAPBLK_MINPORT) as u16;
            if !used.contains(&(newip, c)) {
                pt = c;
                break;
            }
        }
        pt
    } else if r.ports(p) && !bimap {
        let (lo, hi) = (r.pmin, r.pmax.max(r.pmin));
        let mut pt = if r.pnext >= lo && r.pnext <= hi { r.pnext } else { lo };
        // A port no session of this address uses.
        for _ in 0..=(hi - lo) as u32 {
            if !used.contains(&(newip, pt)) {
                break;
            }
            pt = if pt >= hi { lo } else { pt + 1 };
        }
        r.pnext = if pt >= hi { lo } else { pt + 1 };
        pt
    } else {
        sp
    };
    if r.nextip == 0 {
        r.nextip = newip;
    }
    n.add_session(k, 0, p, (src, sp), (newip, newport), (dst, dp), ifp, now);

    bump(&mut n.sessions[0], ip);
    set_src(ip, newip, ported.then_some(newport), hl);
    fix_sums(ip);
    n.mapped[1] += 1;
    true
}

/// A session's packet and byte counters.
fn bump(s: &mut Session, ip: &[u8]) {
    let len = g16(ip, 2) as u32;
    let b = s.mem.b();
    let pk = g32(b, 44).wrapping_add(1);
    let by = g32(b, 48).wrapping_add(len);
    p32(b, 44, pk);
    p32(b, 48, by);
}

/// ipf -D (3.4's ip_natunload): every session and rule gone; the counters
/// stay. The NL_FLUSH records, for the caller (which holds the filter's
/// lock) to log.
pub fn unload() -> Vec<[u8; NATLOG]> {
    let Some(mut n) = lock() else { return Vec::new() };
    n.drop_sessions(|_| false, NL_FLUSH);
    n.rules.clear();
    n.dead.clear();
    n.relink();
    core::mem::take(&mut n.logq)
}

/// ipf_ioctl on IPL_LOGNAT.
///
/// # Safety
/// `data` is what the command takes (a pointer to a pointer to the struct,
/// or to a value), as ipnat passes it.
pub unsafe fn ioctl(cmd: u32, data: *mut u8, running: bool) -> Result<i32, i32> {
    if !running {
        return Err(EIO);
    }
    let (r, logs) = {
        let mut n = lock().ok_or(EIO)?;
        // SAFETY: the caller's contract on `data`.
        let r = unsafe { ioctl_locked(&mut n, cmd, data) };
        (r, core::mem::take(&mut n.logq))
    };
    crate::ipfil::nat_log(logs);
    r
}

/// The NAT ioctls under the NAT's lock.
///
/// # Safety
/// As [`ioctl`].
unsafe fn ioctl_locked(n: &mut Nat, cmd: u32, data: *mut u8) -> Result<i32, i32> {
    // SAFETY: the caller's contract on `data`.
    let via = unsafe { u32::from_be_bytes(core::ptr::read_unaligned(data as *const [u8; 4])) } as usize as *mut u8;
    match cmd {
        SIOCADNAT | SIOCRMNAT => {
            let mut user = [0u8; IPNAT];
            // SAFETY: the caller's ipnat_t (140 bytes).
            unsafe { core::ptr::copy_nonoverlapping(via, user.as_mut_ptr(), IPNAT) };
            let mut r = Rule::new(&user);
            let at = n.rules.iter().position(|x| x.orig[..] == r.orig[..]);
            if cmd == SIOCADNAT {
                if at.is_some() {
                    return Err(EEXIST);
                }
                if r.redir & (NAT_MAP | NAT_REDIRECT | NAT_MAPBLK) == 0 {
                    return Err(EINVAL);
                }
                r.resolve();
                // A proxy the kernel knows (appr_lookup), else ENOENT.
                let label = &r.mem.b()[122..138];
                if label[0] != 0 {
                    let l = label.iter().position(|&c| c == 0).unwrap_or(16);
                    if &label[..l] != b"ftp" || r.p != 6 {
                        return Err(ENOENT);
                    }
                    r.proxy = true;
                    let apr = APR_FTP.as_ptr() as usize as u32;
                    p32(r.mem.b(), 24, apr);
                }
                r.setup();
                n.rules.push(r);
            } else {
                let Some(k) = at else { return Err(ESRCH) };
                n.unlist(k);
            }
            n.relink();
        }
        SIOCGNATS => {
            let b = n.natstat();
            // SAFETY: the caller's natstat_t (84 bytes).
            unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), via, NATSTAT) };
        }
        SIOCGNATL => {
            // struct natlookup: nl_inip, nl_outip, nl_realip, nl_flags,
            // nl_inport, nl_outport, nl_realport: the real end of a
            // redirected connection.
            let mut l = [0u8; 26];
            // SAFETY: the caller's natlookup_t.
            unsafe { core::ptr::copy_nonoverlapping(via, l.as_mut_ptr(), 26) };
            let (inip, outip, inport, outport) = (g32(&l, 0), g32(&l, 4), g16(&l, 16), g16(&l, 18));
            let s = n.sessions.iter().find(|s| s.oip == inip && s.oport == inport && s.inip == outip && s.inport == outport).ok_or(ESRCH)?;
            p32(&mut l, 8, s.outip);
            p16(&mut l, 20, s.outport);
            // SAFETY: as above.
            unsafe { core::ptr::copy_nonoverlapping(l.as_ptr(), via, 26) };
        }
        SIOCIPFFL => {
            // ipnat -F (0): the sessions; -C (1): the rules too.
            // SAFETY: the caller's int.
            let how = unsafe { u32::from_be_bytes(core::ptr::read_unaligned(data as *const [u8; 4])) };
            let count = if how == 1 {
                let c = n.rules.len() as u32;
                while !n.rules.is_empty() {
                    n.unlist(0);
                }
                c
            } else {
                n.drop_sessions(|_| false, NL_FLUSH)
            };
            n.relink();
            // SAFETY: as above.
            unsafe { core::ptr::write_unaligned(data as *mut [u8; 4], count.to_be_bytes()) };
        }
        _ => return Err(EINVAL),
    }
    Ok(0)
}
