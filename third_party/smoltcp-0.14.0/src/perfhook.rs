//! rustsocket.library's timing of smoltcp's own phases (VirtioRust patch;
//! feature `rsnet-perf`, off by default). Timebase ticks (PPC `mftb`, low
//! 32 bits) and calls per slot; rsnet-core's perf report takes
//! and clears them. Without the feature every call compiles to nothing.

/// A received frame, from the device's token to the end of its handling.
pub const INGRESS: usize = 0;
/// TcpRepr::parse (the TCP checksum check is in it).
pub const TCP_PARSE: usize = 1;
/// Finding the socket that accepts a segment, and its processing.
pub const TCP_SOCKETS: usize = 2;
/// tcp::Socket::process alone.
pub const TCP_PROCESS: usize = 3;
/// The egress loop of Interface::poll.
pub const EGRESS: usize = 4;
pub const N: usize = 5;
pub const NAMES: [&str; N] = ["smoltcp: frame in", "smoltcp:  TCP parse+checksum", "smoltcp:  TCP socket search+process", "smoltcp:   TCP process", "smoltcp: egress"];

#[cfg(feature = "rsnet-perf")]
mod on {
    use core::sync::atomic::{AtomicU32, Ordering};

    static TICKS: [AtomicU32; super::N] = [const { AtomicU32::new(0) }; super::N];
    static CALLS: [AtomicU32; super::N] = [const { AtomicU32::new(0) }; super::N];

    #[inline(always)]
    #[allow(unsafe_code)]
    pub fn now() -> u32 {
        let v: u32;
        // SAFETY: reads the time base, no side effects.
        unsafe { core::arch::asm!("mftb {0}", out(reg) v, options(nomem, nostack)) };
        v
    }

    #[inline(always)]
    pub fn add(i: usize, since: u32) {
        TICKS[i].fetch_add(now().wrapping_sub(since), Ordering::Relaxed);
        CALLS[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Ticks and calls of slot `i`, cleared.
    pub fn take(i: usize) -> (u32, u32) {
        (TICKS[i].swap(0, Ordering::Relaxed), CALLS[i].swap(0, Ordering::Relaxed))
    }
}

#[cfg(not(feature = "rsnet-perf"))]
mod on {
    #[inline(always)]
    pub fn now() -> u32 {
        0
    }
    #[inline(always)]
    pub fn add(_i: usize, _since: u32) {}
    pub fn take(_i: usize) -> (u32, u32) {
        (0, 0)
    }
}

pub use on::{add, now, take};

/// TCP loss counters for rustsocket's tcpstat (always on: one atomic add
/// per event, and only on loss), so netprof's "retx" column shows real
/// retransmissions.
pub mod count {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// Retransmission timeouts (tcps_rexmttimeo).
    pub static RTO: AtomicU32 = AtomicU32::new(0);
    /// Segments sent again, and their bytes (tcps_sndrexmitpack, _byte).
    pub static REXMIT_PACK: AtomicU32 = AtomicU32::new(0);
    pub static REXMIT_BYTE: AtomicU32 = AtomicU32::new(0);
    /// Duplicate ACKs received (tcps_rcvdupack).
    pub static DUPACK: AtomicU32 = AtomicU32::new(0);

    #[inline]
    pub fn inc(c: &AtomicU32, n: u32) {
        c.fetch_add(n, Ordering::Relaxed);
    }
}
