//! Stack-wide settings: Roadshow's named options (ObtainRoadshowData /
//! ChangeRoadshowData, RoadshowControl, ENV:Roadshow/<area>/<name>) and the
//! SocketBaseTagList globals that are the same values (SBTC_UDP_CHECKSUM,
//! SBTC_IP_FORWARDING, SBTC_IP_DEFAULT_TTL, the SBTC_ICMP_* reactions).
//!
//! The names and defaults are Roadshow 1.15's (RoadshowControl's listing on
//! QEMU's AmigaOne). What each does here:
//! - taking effect: ip.defttl (new sockets' TTL), tcp.recvspace and
//!   tcp.sendspace (new TCP sockets' buffers; the receive buffer then
//!   grows with the connection's rate up to tcp.recvspace.max, an option
//!   of rustsocket's own, default 1 MB, and the send buffer likewise up to
//!   tcp.sendspace.max, default 64 KB = no growth), udp.recvspace and
//!   udp.sendspace (new UDP sockets' buffers), task.controller.priority (the
//!   stack process's priority);
//! - ip.forwarding 0 or 1 (forward.rs);
//! - fixed to what smoltcp does, refusing other values:
//!   udp.cksum 1, icmp.maskrepl 0, icmp.processecho 0 (answered),
//!   (icmp.procesststamp: 0 answers time stamp requests (link.rs, as
//!   Roadshow's default), 1 and 2 leave them unanswered);
//! - kept, no effect yet: the rest.

use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

/// An ICMP request is answered.
pub const IR_PROCESS: u32 = 0;
/// An ICMP request is not answered but goes to raw sockets.
pub const IR_IGNORE: u32 = 1;
/// An ICMP request is dropped.
pub const IR_DROP: u32 = 2;

/// What values an option takes.
#[derive(Clone, Copy)]
enum Rule {
    /// Any value in this range.
    Range(i32, i32),
    /// Only this value (what this stack does).
    Only(i32),
}

/// One option: Roadshow's name, its value here at start, what it takes.
pub struct Opt {
    pub name: &'static str,
    pub default: i32,
    rule: Rule,
}

const fn opt(name: &'static str, default: i32, rule: Rule) -> Opt {
    Opt { name, default, rule }
}

/// Every option, in RoadshowControl's order.
pub static OPTIONS: [Opt; N_OPTIONS] = [
    opt("bpf.bufsize", 4096, Rule::Range(0, 1 << 20)),
    opt("icmp.maskrepl", 0, Rule::Only(0)),
    opt("icmp.processecho", 0, Rule::Only(0)),
    opt("icmp.procesststamp", 0, Rule::Range(0, 2)),
    opt("ip.defttl", 64, Rule::Range(1, 255)),
    opt("ip.forwarding", 0, Rule::Range(0, 1)),
    opt("ip.sendredirects", 1, Rule::Range(0, 1)),
    opt("ip.subnetsarelocal", 0, Rule::Range(0, 1)),
    opt("tcp.do_rfc1323", 1, Rule::Range(0, 1)),
    opt("tcp.do_timestamps", 0, Rule::Range(0, 1)),
    opt("tcp.do_win_scale", 0, Rule::Range(0, 1)),
    opt("tcp.mssdflt", 1460, Rule::Range(64, 65535)),
    opt("tcp.recvspace", 65536, Rule::Range(2048, 1 << 20)),
    // Not Roadshow's: the ceiling a TCP connection's receive buffer grows
    // to (auto-tuning, sock.rs tune_rx); tcp.recvspace is where it starts.
    opt("tcp.recvspace.max", 1 << 20, Rule::Range(2048, 16 << 20)),
    opt("tcp.rttdflt", 3, Rule::Range(1, 600)),
    // 64 KB, not Roadshow's 32 KB: on an AmigaOne X5000, LAN send went
    // from 85 to 115 MB/s (gigabit's line rate) with it, in 6 of 6 runs
    // (48 KB gave 104, 96 KB stalled now and then).
    opt("tcp.sendspace", 65536, Rule::Range(2048, 1 << 20)),
    // Not Roadshow's: the ceiling a TCP connection's send buffer grows to
    // (auto-tuning, sock.rs tune_tx); tcp.sendspace is where it starts.
    // 64 KB, i.e. off: in 12 alternating internet uploads from an X5000
    // a 1 MB ceiling gave no gain (3.53 against 3.77 MB/s, 5 of 6 pairs
    // lost in the second set).
    opt("tcp.sendspace.max", 65536, Rule::Range(2048, 16 << 20)),
    opt("tcp.use_mssdflt_for_remote", 0, Rule::Range(0, 1)),
    opt("tcp.random", 0, Rule::Range(0, 1)),
    opt("udp.cksum", 1, Rule::Only(1)),
    opt("udp.recvspace", 41600, Rule::Range(2048, 1 << 20)),
    opt("udp.sendspace", 9216, Rule::Range(2048, 1 << 20)),
    opt("task.controller.priority", 0, Rule::Range(-128, 127)),
    opt("if.receive.useclusters", 1, Rule::Range(0, 1)),
    opt("if.minclustersize", 208, Rule::Range(0, 2048)),
];

const N_OPTIONS: usize = 25;

static VALUES: [AtomicI32; N_OPTIONS] = {
    let mut v = [const { AtomicI32::new(0) }; N_OPTIONS];
    let mut i = 0;
    while i < N_OPTIONS {
        v[i] = AtomicI32::new(OPTIONS[i].default);
        i += 1;
    }
    v
};

/// Why a change was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// No option of that name.
    Unknown,
    /// A value the option does not take here.
    Value,
}

fn index(name: &str) -> Option<usize> {
    OPTIONS.iter().position(|o| o.name.len() == name.len() && o.name.eq_ignore_ascii_case(name))
}

/// `index(name)`, remembered in `cell` after the first look (0xFF: not yet).
/// The stack reads some settings for every frame and every pass, and the
/// search compares names case-insensitively.
fn index_cached(cell: &AtomicU8, name: &str) -> Option<usize> {
    let c = cell.load(Ordering::Relaxed);
    if c != 0xff {
        return Some(c as usize);
    }
    let i = index(name)?;
    cell.store(i as u8, Ordering::Relaxed);
    Some(i)
}

/// `val` through a cached index.
fn val_c(cell: &AtomicU8, name: &str, d: i32) -> i32 {
    index_cached(cell, name).map(|i| VALUES[i].load(Ordering::Relaxed)).unwrap_or(d)
}

/// A cache cell for index_cached.
const NOT_YET: AtomicU8 = AtomicU8::new(0xff);

/// The value of option `name` (case-insensitive).
pub fn get(name: &str) -> Option<i32> {
    index(name).map(|i| VALUES[i].load(Ordering::Relaxed))
}

/// Change option `name` (case-insensitive).
pub fn set(name: &str, v: i32) -> Result<(), Refused> {
    let i = index(name).ok_or(Refused::Unknown)?;
    let ok = match OPTIONS[i].rule {
        Rule::Range(lo, hi) => (lo..=hi).contains(&v),
        Rule::Only(x) => v == x,
    };
    if !ok {
        return Err(Refused::Value);
    }
    VALUES[i].store(v, Ordering::Relaxed);
    Ok(())
}

/// The SocketBaseTagList settings, by their Roadshow names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Setting {
    UdpChecksum,
    IpForwarding,
    IpDefaultTtl,
    IcmpMaskReply,
    IcmpSendRedirects,
    IcmpProcessEcho,
    IcmpProcessTstamp,
}

impl Setting {
    fn name(self) -> &'static str {
        match self {
            Setting::UdpChecksum => "udp.cksum",
            Setting::IpForwarding => "ip.forwarding",
            Setting::IpDefaultTtl => "ip.defttl",
            Setting::IcmpMaskReply => "icmp.maskrepl",
            Setting::IcmpSendRedirects => "ip.sendredirects",
            Setting::IcmpProcessEcho => "icmp.processecho",
            Setting::IcmpProcessTstamp => "icmp.procesststamp",
        }
    }
}

/// The settings as the stack reads them.
pub struct Settings;

pub static SETTINGS: Settings = Settings;

impl Settings {
    pub fn get(&self, s: Setting) -> u32 {
        static CELLS: [AtomicU8; 7] = [NOT_YET; 7];
        val_c(&CELLS[s as usize], s.name(), 0) as u32
    }

    /// Change a setting; false when the stack cannot do what `v` asks.
    pub fn set(&self, s: Setting, v: u32) -> bool {
        set(s.name(), v as i32).is_ok()
    }

    /// The hop limit for new sockets.
    pub fn ttl(&self) -> u8 {
        static C: AtomicU8 = NOT_YET;
        val_c(&C, "ip.defttl", 64).clamp(1, 255) as u8
    }

    /// New TCP sockets' receive and send buffers, in bytes.
    pub fn tcp_space(&self) -> (usize, usize) {
        static R: AtomicU8 = NOT_YET;
        static S: AtomicU8 = NOT_YET;
        (val_c(&R, "tcp.recvspace", 65536) as usize, val_c(&S, "tcp.sendspace", 65536) as usize)
    }

    /// The size a TCP connection's receive buffer may grow to (never below
    /// tcp.recvspace).
    pub fn tcp_recv_max(&self) -> usize {
        static R: AtomicU8 = NOT_YET;
        static M: AtomicU8 = NOT_YET;
        let start = val_c(&R, "tcp.recvspace", 65536) as usize;
        (val_c(&M, "tcp.recvspace.max", 1 << 20) as usize).max(start)
    }

    /// The size a TCP connection's send buffer may grow to (never below
    /// tcp.sendspace).
    pub fn tcp_send_max(&self) -> usize {
        static S: AtomicU8 = NOT_YET;
        static M: AtomicU8 = NOT_YET;
        let start = val_c(&S, "tcp.sendspace", 65536) as usize;
        (val_c(&M, "tcp.sendspace.max", 65536) as usize).max(start)
    }

    /// New UDP sockets' receive and send buffers, in bytes.
    pub fn udp_space(&self) -> (usize, usize) {
        static R: AtomicU8 = NOT_YET;
        static S: AtomicU8 = NOT_YET;
        (val_c(&R, "udp.recvspace", 41600) as usize, val_c(&S, "udp.sendspace", 9216) as usize)
    }

    /// The stack process's priority.
    pub fn stack_priority(&self) -> i8 {
        static C: AtomicU8 = NOT_YET;
        val_c(&C, "task.controller.priority", 0).clamp(-128, 127) as i8
    }
}
