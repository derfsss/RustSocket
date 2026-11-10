//! Where the stack's time goes (feature `perf`): timebase ticks
//! summed per phase, and a report every 10 s on the serial/debug log while
//! frames flow. Without the feature every call here compiles to nothing.
//!
//! The phases: the stack process waiting for the Core lock, a whole pass
//! with it held, the link's SANA-II reply handling (Link::poll), smoltcp's
//! poll (with the frames it sends), the wait for each write's reply
//! (Link::send_inner), the stack's sleep; and in the caller's task, the
//! wait for the lock and the work under it (recv_now / send_now).

#[cfg(feature = "perf")]
mod on {
    use core::sync::atomic::{AtomicU32, Ordering};

    pub const STACK_LOCK: usize = 0;
    pub const PASS: usize = 1;
    pub const LINK_POLL: usize = 2;
    pub const IFACE_POLL: usize = 3;
    pub const TX_WAIT: usize = 4;
    pub const SLEEP: usize = 5;
    pub const CALLER_LOCK: usize = 6;
    pub const CALLER_WORK: usize = 7;
    pub const ROUND2: usize = 8;
    pub const LO_POLL: usize = 9;
    pub const PROGRESS: usize = 10;
    pub const DELAYS: usize = 11;
    const N: usize = 12;
    const NAMES: [&str; N] = ["stack lock wait", "stack pass", " link poll", " smoltcp poll", "  write wait", "stack sleep", "caller lock wait", "caller work", " second round", " lo0 polls", " socks.progress", " sleep set-up"];

    static TICKS: [AtomicU32; N] = [const { AtomicU32::new(0) }; N];
    static CALLS: [AtomicU32; N] = [const { AtomicU32::new(0) }; N];
    /// The last report: timebase (low 32 bits) and up time in ms. Only the
    /// stack process reports.
    static LAST_TB: AtomicU32 = AtomicU32::new(0);
    static LAST_MS: AtomicU32 = AtomicU32::new(0);

    #[inline]
    pub fn now() -> u64 {
        amigaos4::arch::timebase()
    }

    static LP_POLLS: AtomicU32 = AtomicU32::new(0);
    static LP_TAKEN: AtomicU32 = AtomicU32::new(0);
    static LP_TAKEN_MAX: AtomicU32 = AtomicU32::new(0);
    static LP_Q0_MAX: AtomicU32 = AtomicU32::new(0);
    static LP_DROP_POLLS: AtomicU32 = AtomicU32::new(0);
    static LP_DROPPED: AtomicU32 = AtomicU32::new(0);

    /// One Link::poll: the queue length it found, the frames it took, the
    /// frames it dropped.
    pub fn link_poll(q0: u32, taken: u32, dropped: u32) {
        LP_POLLS.fetch_add(1, Ordering::Relaxed);
        LP_TAKEN.fetch_add(taken, Ordering::Relaxed);
        LP_TAKEN_MAX.fetch_max(taken, Ordering::Relaxed);
        LP_Q0_MAX.fetch_max(q0, Ordering::Relaxed);
        if dropped > 0 {
            LP_DROP_POLLS.fetch_add(1, Ordering::Relaxed);
            LP_DROPPED.fetch_add(dropped, Ordering::Relaxed);
        }
    }

    static RB_BATCHES: AtomicU32 = AtomicU32::new(0);
    static RB_FRAMES: AtomicU32 = AtomicU32::new(0);
    static RB_MAX: AtomicU32 = AtomicU32::new(0);
    static RB_EMPTY: AtomicU32 = AtomicU32::new(0);

    /// One read batch came back with `frames` filled.
    pub fn batch_taken(frames: u32) {
        RB_BATCHES.fetch_add(1, Ordering::Relaxed);
        RB_FRAMES.fetch_add(frames, Ordering::Relaxed);
        RB_MAX.fetch_max(frames, Ordering::Relaxed);
        if frames == 0 {
            RB_EMPTY.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The SANA-II extension counters of one link (totals since it was
    /// added), after each report.
    pub fn link_s2x(slot: u8, s: &crate::link::LinkStats) {
        if s.rx_batches == 0 && s.tx_batches == 0 {
            return;
        }
        amigaos4::serial_println!(
            "rsnet perf:   if {}: rx batches {} frames {} ({:.1}/batch), tx batches {} frames {} ({:.1}/batch), rx csum skipped {} bad {}, tx csum offloaded {}, tso {} sends {} segments {} cut here, rss hashed {} per queue {:?}",
            slot, s.rx_batches, s.rx_batch_frames, s.rx_batch_frames as f64 / s.rx_batches.max(1) as f64,
            s.tx_batches, s.tx_batch_frames, s.tx_batch_frames as f64 / s.tx_batches.max(1) as f64, s.rx_csum_ok, s.rx_csum_bad, s.tx_csum_offloaded, s.tso_sends, s.tso_segments, s.tso_soft, s.rx_rss_hashed, s.rx_queue_frames
        );
    }

    #[inline]
    pub fn add(i: usize, since: u64) {
        let d = now().wrapping_sub(since) as u32;
        TICKS[i].fetch_add(d, Ordering::Relaxed);
        CALLS[i].fetch_add(1, Ordering::Relaxed);
    }

    /// From the stack loop: every 10 s of timebase, print the shares of
    /// the elapsed time and the calls, then start again. `frames` are the
    /// frames received and sent since the last report.
    pub fn report(frames_in: u64, frames_out: u64) -> bool {
        // The span in wall time (timer.device) and in timebase ticks: their
        // ratio is the timebase's rate, so no GetCPUInfo is needed.
        let ms = (amigaos4::timer::get_up_time().as_micros() / 1000) as u32;
        let t = now() as u32;
        let last_ms = LAST_MS.load(Ordering::Relaxed);
        if last_ms == 0 {
            LAST_MS.store(ms, Ordering::Relaxed);
            LAST_TB.store(t, Ordering::Relaxed);
            for i in 0..N {
                TICKS[i].store(0, Ordering::Relaxed);
                CALLS[i].store(0, Ordering::Relaxed);
            }
            return true;
        }
        let wall_ms = ms.wrapping_sub(last_ms);
        if wall_ms < 10_000 {
            return false;
        }
        let span = t.wrapping_sub(LAST_TB.load(Ordering::Relaxed)) as u64;
        LAST_MS.store(ms, Ordering::Relaxed);
        LAST_TB.store(t, Ordering::Relaxed);
        let secs = wall_ms as f64 / 1000.0;
        let speed = (span as f64 / secs) as u64;
        amigaos4::serial_println!("rsnet perf: {:.1} s, frames in {} ({:.0}/s), out {} ({:.0}/s)", secs, frames_in, frames_in as f64 / secs, frames_out, frames_out as f64 / secs);
        for i in 0..N {
            let ticks = TICKS[i].swap(0, Ordering::Relaxed) as f64;
            let calls = CALLS[i].swap(0, Ordering::Relaxed);
            let us_per = if calls > 0 { ticks / speed as f64 * 1e6 / calls as f64 } else { 0.0 };
            let per_frame = if frames_in > 0 { ticks / speed as f64 * 1e6 / frames_in as f64 } else { 0.0 };
            amigaos4::serial_println!("rsnet perf:   {:<17} {:5.1}%  {:9} calls  {:7.2} us/call  {:6.2} us per frame in", NAMES[i], 100.0 * ticks / span as f64, calls, us_per, per_frame);
        }
        // Link::poll: how many replied reads one call took (a driver with a
        // backlog answers a re-posted read at once, inside the same call),
        // the queue it found, and what it dropped at RX_QUEUE_MAX.
        let polls = LP_POLLS.swap(0, Ordering::Relaxed);
        let taken = LP_TAKEN.swap(0, Ordering::Relaxed);
        amigaos4::serial_println!(
            "rsnet perf:   link polls {}, frames taken {} ({:.1}/poll, most {} in one), queue at entry most {}, polls that dropped {}, frames dropped {}",
            polls, taken, if polls > 0 { taken as f64 / polls as f64 } else { 0.0 },
            LP_TAKEN_MAX.swap(0, Ordering::Relaxed), LP_Q0_MAX.swap(0, Ordering::Relaxed),
            LP_DROP_POLLS.swap(0, Ordering::Relaxed), LP_DROPPED.swap(0, Ordering::Relaxed)
        );
        // Read batches (SANA-II extensions): frames each carried.
        let batches = RB_BATCHES.swap(0, Ordering::Relaxed);
        if batches > 0 {
            let frames = RB_FRAMES.swap(0, Ordering::Relaxed);
            amigaos4::serial_println!(
                "rsnet perf:   read batches {}, frames {} ({:.1}/batch, most {}, empty {})",
                batches, frames, frames as f64 / batches as f64, RB_MAX.swap(0, Ordering::Relaxed), RB_EMPTY.swap(0, Ordering::Relaxed)
            );
        }
        // smoltcp's own phases (its rsnet-perf feature, same time base).
        for i in 0..smoltcp::perfhook::N {
            let (ticks, calls) = smoltcp::perfhook::take(i);
            let ticks = ticks as f64;
            let us_per = if calls > 0 { ticks / speed as f64 * 1e6 / calls as f64 } else { 0.0 };
            let per_frame = if frames_in > 0 { ticks / speed as f64 * 1e6 / frames_in as f64 } else { 0.0 };
            amigaos4::serial_println!("rsnet perf:   {:<36} {:9} calls  {:7.2} us/call  {:6.2} us per frame in", smoltcp::perfhook::NAMES[i], calls, us_per, per_frame);
        }
        true
    }

}

#[cfg(feature = "perf")]
pub use on::*;

#[cfg(not(feature = "perf"))]
mod off {
    pub const STACK_LOCK: usize = 0;
    pub const PASS: usize = 1;
    pub const LINK_POLL: usize = 2;
    pub const IFACE_POLL: usize = 3;
    pub const TX_WAIT: usize = 4;
    pub const SLEEP: usize = 5;
    pub const CALLER_LOCK: usize = 6;
    pub const CALLER_WORK: usize = 7;
    pub const ROUND2: usize = 8;
    pub const LO_POLL: usize = 9;
    pub const PROGRESS: usize = 10;
    pub const DELAYS: usize = 11;
    #[inline(always)]
    pub fn now() -> u64 {
        0
    }
    #[inline(always)]
    pub fn add(_i: usize, _since: u64) {}
    #[inline(always)]
    pub fn report(_frames_in: u64, _frames_out: u64) -> bool {
        false
    }
    #[inline(always)]
    pub fn link_s2x(_slot: u8, _s: &crate::link::LinkStats) {}
}

#[cfg(not(feature = "perf"))]
pub use off::*;
