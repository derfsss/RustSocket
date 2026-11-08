//! The Berkeley Packet Filter (bpf_open .. bpf_ioctl): channels bound to an
//! interface see every frame it receives (the link reads IPv4 and ARP) and
//! sends, through a filter program, into a buffer the program reads.
//!
//! As Roadshow (measured with `rstcp bpf`):
//! 8 channels, handles 0x70000000 + channel, a 4096-byte buffer by default
//! (BIOCSBLEN: 32..32768), 18-byte headers (pack(2) bpf_hdr), each record
//! starting on a 4-byte boundary, sent frames captured too, statistics
//! counting the packets the filter kept.
//!
//! The table lives in the library's heap behind one mutex; the stack
//! process taps frames into it (`tap`, a quick no-op while no channel is
//! bound), the library's callers read and configure it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use amigaos4::sync::{Mutex, MutexGuard};

pub const CHANNELS: usize = 8;
pub const HANDLE_BASE: i32 = 0x7000_0000;
pub const DEFAULT_BLEN: usize = 4096;
pub const MIN_BLEN: usize = 32;
pub const MAX_BLEN: usize = 0x8000;
pub const MAX_INSNS: usize = 512;
const HDR: usize = 18;

/// One filter instruction (struct bpf_insn).
#[derive(Clone, Copy)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

pub struct Chan {
    /// The opener that owns it (its interface data).
    pub owner: usize,
    /// The interface slot it listens on (BIOCSETIF).
    pub slot: Option<u8>,
    pub blen: usize,
    pub buf: Vec<u8>,
    pub recv: u32,
    pub drop: u32,
    pub immediate: bool,
    /// BIOCSRTIMEOUT (0: none).
    pub timeout_us: u64,
    /// None: keep every packet whole.
    pub filter: Option<Vec<Insn>>,
    /// bpf_set_notify_mask: (task, signals), sent on new data.
    pub notify: (u32, u32),
    /// bpf_set_interrupt_mask.
    pub interrupt: u32,
    /// A bpf_read waiting: (task, signal).
    pub reader: (u32, u32),
}

impl Chan {
    pub fn new(owner: usize) -> Chan {
        Chan { owner, slot: None, blen: DEFAULT_BLEN, buf: Vec::new(), recv: 0, drop: 0, immediate: false, timeout_us: 0, filter: None, notify: (0, 0), interrupt: 0, reader: (0, 0) }
    }

    /// BIOCFLUSH.
    pub fn flush(&mut self) {
        self.buf.clear();
        self.recv = 0;
        self.drop = 0;
    }

    /// The buffer holds no room for another full frame: a reader that is not
    /// immediate is woken.
    pub fn full(&self) -> bool {
        self.buf.len() + 3 + HDR + 1514 > self.blen
    }
}

pub type Table = [Option<Chan>; CHANNELS];

static TABLE: AtomicPtr<Mutex<Table>> = AtomicPtr::new(core::ptr::null_mut());
/// Channels bound to an interface: the tap does nothing while 0.
static BOUND: AtomicU32 = AtomicU32::new(0);

/// The table, locked (made at first use); None if no mutex could be had.
pub fn lock() -> Option<MutexGuard<'static, Table>> {
    let mut p = TABLE.load(Ordering::Acquire);
    if p.is_null() {
        let m = Box::into_raw(Box::new(Mutex::new([const { None }; CHANNELS]).ok()?));
        p = match TABLE.compare_exchange(core::ptr::null_mut(), m, Ordering::AcqRel, Ordering::Acquire) {
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

/// Count the channels bound to an interface again (after a change).
pub fn recount(t: &Table) {
    BOUND.store(t.iter().flatten().filter(|c| c.slot.is_some()).count() as u32, Ordering::Release);
}

/// The library's last Close: the table goes.
pub fn free() {
    BOUND.store(0, Ordering::Release);
    let p = TABLE.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !p.is_null() {
        // SAFETY: the Box stored by `lock`, taken once.
        drop(unsafe { Box::from_raw(p) });
    }
}

/// Check a filter program as BSD does: known codes, jumps that land inside,
/// scratch memory in range, ending in a return.
pub fn valid(p: &[Insn]) -> bool {
    if p.is_empty() || p.len() > MAX_INSNS {
        return false;
    }
    for (pc, i) in p.iter().enumerate() {
        let ok = match i.code & 0x07 {
            0x00 | 0x01 => match i.code & 0xe0 {
                0x60 => i.k < 16,
                0x00 | 0x20 | 0x40 | 0x80 | 0xa0 => true,
                _ => false,
            },
            0x02 | 0x03 => i.k < 16,
            0x04 => !(i.code & 0xf0 == 0x30 && i.code & 0x08 == 0 && i.k == 0) && i.code & 0xf0 <= 0x80,
            0x05 => {
                if i.code & 0xf0 == 0x00 {
                    (pc + 1).checked_add(i.k as usize).is_some_and(|t| t < p.len())
                } else {
                    i.code & 0xf0 <= 0x40 && pc + 1 + (i.jt as usize) < p.len() && pc + 1 + (i.jf as usize) < p.len()
                }
            }
            0x06 => true,
            _ => i.code & 0xf8 == 0x00 || i.code & 0xf8 == 0x80,
        };
        if !ok {
            return false;
        }
    }
    p[p.len() - 1].code & 0x07 == 0x06
}

fn load(p: &[u8], at: u32, n: usize) -> Option<u32> {
    let at = at as usize;
    let b = p.get(at..at.checked_add(n)?)?;
    Some(b.iter().fold(0u32, |a, &x| (a << 8) | x as u32))
}

/// Run filter `prog` on frame `p`: how many bytes to keep (0: drop). A
/// load beyond the frame ends it with 0, as BSD's filter does.
pub fn run(prog: &[Insn], p: &[u8]) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut m = [0u32; 16];
    let mut pc = 0usize;
    while let Some(i) = prog.get(pc) {
        pc += 1;
        let k = i.k;
        let size = match i.code & 0x18 {
            0x00 => 4,
            0x08 => 2,
            _ => 1,
        };
        match i.code & 0x07 {
            0x00 => {
                a = match i.code & 0xe0 {
                    0x00 => k,
                    0x20 => match load(p, k, size) {
                        Some(v) => v,
                        None => return 0,
                    },
                    0x40 => match load(p, x.wrapping_add(k), size) {
                        Some(v) => v,
                        None => return 0,
                    },
                    0x60 => m[k as usize & 15],
                    0x80 => p.len() as u32,
                    _ => return 0,
                }
            }
            0x01 => {
                x = match i.code & 0xe0 {
                    0x00 => k,
                    0x60 => m[k as usize & 15],
                    0x80 => p.len() as u32,
                    // BPF_MSH: 4 * (P[k:1] & 0xf), the IP header length.
                    0xa0 => match p.get(k as usize) {
                        Some(&b) => ((b & 0x0f) as u32) * 4,
                        None => return 0,
                    },
                    _ => return 0,
                }
            }
            0x02 => m[k as usize & 15] = a,
            0x03 => m[k as usize & 15] = x,
            0x04 => {
                let v = if i.code & 0x08 != 0 { x } else { k };
                a = match i.code & 0xf0 {
                    0x00 => a.wrapping_add(v),
                    0x10 => a.wrapping_sub(v),
                    0x20 => a.wrapping_mul(v),
                    0x30 => {
                        if v == 0 {
                            return 0;
                        }
                        a / v
                    }
                    0x40 => a | v,
                    0x50 => a & v,
                    0x60 => a.checked_shl(v).unwrap_or(0),
                    0x70 => a.checked_shr(v).unwrap_or(0),
                    0x80 => a.wrapping_neg(),
                    _ => return 0,
                }
            }
            0x05 => {
                let v = if i.code & 0x08 != 0 { x } else { k };
                let take = match i.code & 0xf0 {
                    0x00 => {
                        pc += k as usize;
                        continue;
                    }
                    0x10 => a == v,
                    0x20 => a > v,
                    0x30 => a >= v,
                    0x40 => a & v != 0,
                    _ => return 0,
                };
                pc += if take { i.jt } else { i.jf } as usize;
            }
            0x06 => {
                return match i.code & 0x18 {
                    0x10 => a,
                    _ => k,
                };
            }
            _ => {
                if i.code & 0xf8 == 0 {
                    x = a;
                } else {
                    a = x;
                }
            }
        }
    }
    0
}

/// A frame on interface `slot`, received (`rx`) or sent: into every
/// channel listening there whose filter keeps it.
pub fn tap(slot: u8, f: &[u8], _rx: bool) {
    if BOUND.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(mut t) = lock() else { return };
    let now = amigaos4::timer::sys_time();
    for c in t.iter_mut().flatten() {
        if c.slot != Some(slot) {
            continue;
        }
        let keep = match &c.filter {
            Some(p) => run(p, f),
            None => u32::MAX,
        };
        if keep == 0 {
            continue;
        }
        c.recv = c.recv.wrapping_add(1);
        let cap = (keep as usize).min(f.len());
        let start = (c.buf.len() + 3) & !3;
        if start + HDR + cap > c.blen {
            c.drop = c.drop.wrapping_add(1);
        } else {
            c.buf.resize(start, 0);
            c.buf.extend_from_slice(&now.secs.to_be_bytes());
            c.buf.extend_from_slice(&now.micros.to_be_bytes());
            c.buf.extend_from_slice(&(cap as u32).to_be_bytes());
            c.buf.extend_from_slice(&(f.len() as u32).to_be_bytes());
            c.buf.extend_from_slice(&(HDR as u16).to_be_bytes());
            c.buf.extend_from_slice(&f[..cap]);
        }
        // SAFETY: tasks the channel's owner named, signalled with signals
        // they asked for (a reader clears its entry before it goes).
        unsafe {
            if c.notify.0 != 0 && c.notify.1 != 0 {
                amigaos4::sys::exec_signal(c.notify.0 as *mut amigaos4::sys::Task, c.notify.1);
            }
            if c.reader.0 != 0 && (c.immediate || c.full()) {
                amigaos4::sys::exec_signal(c.reader.0 as *mut amigaos4::sys::Task, c.reader.1);
            }
        }
    }
}
