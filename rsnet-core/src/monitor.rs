//! Network monitoring hooks (AddNetMonitorHookTagList,
//! RemoveNetMonitorHook): the packet-path types are called here, in the
//! stack process, on each frame as it reaches smoltcp or leaves it:
//! MHT_Packet (in and out), MHT_ICMP, MHT_UDP and MHT_TCP_Connect (an
//! incoming SYN without ACK). The library calls the MHT_Connect, MHT_Bind
//! and MHT_Send hooks itself, in the caller's task (`hooks_of`).
//!
//! What a hook returns: MA_Continue (0) lets the data go on; MA_Drop and
//! MA_DropWithReset drop it (no reset is sent: the remote times out), as
//! does MA_Ignore here (smoltcp cannot skip its own processing and still
//! hand the packet to raw sockets). The table is a fixed set of atomic
//! slots, so the stack reads it without a lock.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

pub const MHT_ICMP: u32 = 0;
pub const MHT_UDP: u32 = 1;
pub const MHT_TCP_CONNECT: u32 = 2;
pub const MHT_CONNECT: u32 = 3;
pub const MHT_SEND: u32 = 4;
pub const MHT_PACKET: u32 = 5;
pub const MHT_BIND: u32 = 6;

const SLOTS: usize = 32;

/// (type + 1, hook): 0 in the first marks a free slot.
static TYPES: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];
static HOOKS: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];

/// Add a hook of `kind`: false when the table is full.
pub fn add(kind: u32, hook: u32) -> bool {
    for k in 0..SLOTS {
        if TYPES[k].compare_exchange(0, u32::MAX, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            HOOKS[k].store(hook, Ordering::Release);
            TYPES[k].store(kind + 1, Ordering::Release);
            return true;
        }
    }
    false
}

/// Remove every registration of `hook`.
pub fn remove(hook: u32) {
    for k in 0..SLOTS {
        if HOOKS[k].load(Ordering::Acquire) == hook && TYPES[k].load(Ordering::Acquire) != 0 {
            TYPES[k].store(0, Ordering::Release);
            HOOKS[k].store(0, Ordering::Release);
        }
    }
}

/// The hooks of `kind`, in the order they were added (slot order).
pub fn hooks_of(kind: u32) -> impl Iterator<Item = u32> {
    (0..SLOTS).filter_map(move |k| (TYPES[k].load(Ordering::Acquire) == kind + 1).then(|| HOOKS[k].load(Ordering::Acquire))).filter(|&h| h != 0)
}

fn any(kind: u32) -> bool {
    (0..SLOTS).any(|k| TYPES[k].load(Ordering::Relaxed) == kind + 1)
}

/// Call `hook` with `msg`; its LONG result.
pub fn call(hook: u32, msg: *mut c_void) -> i32 {
    // SAFETY: a Hook a program installed with AddNetMonitorHookTagList (it
    // removes it before it closes the library); reserved is NULL.
    unsafe { amigaos4::sys::utility_call_hook_pkt(hook as *mut amigaos4::sys::Hook, core::ptr::null_mut(), msg) as i32 }
}

/// Whether every hook of `kind` lets the message through.
fn pass(kind: u32, msg: *mut c_void) -> bool {
    hooks_of(kind).all(|h| call(h, msg) == 0)
}

/// An Ethernet frame reaching the stack (`rx`) or leaving it: false when a
/// hook drops it.
pub fn frame(f: &[u8], rx: bool) -> bool {
    if any(MHT_PACKET) {
        // struct PacketMonitorMessage: size, direction, link layer data and
        // size, payload and size.
        let mut m = [24u32, if rx { 0 } else { 1 }, f.as_ptr() as u32, 14.min(f.len()) as u32, f.as_ptr().wrapping_add(14) as u32, f.len().saturating_sub(14) as u32];
        if !pass(MHT_PACKET, m.as_mut_ptr() as *mut c_void) {
            return false;
        }
    }
    if !rx || f.len() < 34 || f[12] != 0x08 || f[13] != 0 {
        return true;
    }
    let ip = &f[14..];
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    if ihl < 20 || ip.len() < ihl + 8 {
        return true;
    }
    let kind = match ip[9] {
        1 => MHT_ICMP,
        17 => MHT_UDP,
        // A SYN without ACK: a connection being asked for.
        6 if ip.len() >= ihl + 14 && ip[ihl + 13] & 0x12 == 0x02 => MHT_TCP_CONNECT,
        _ => return true,
    };
    if !any(kind) {
        return true;
    }
    // ICMP/UDP/TCPConnect monitor messages: size, &source, &destination,
    // the protocol header.
    let mut m = [16u32, ip.as_ptr().wrapping_add(12) as u32, ip.as_ptr().wrapping_add(16) as u32, ip.as_ptr().wrapping_add(ihl) as u32];
    pass(kind, m.as_mut_ptr() as *mut c_void)
}
