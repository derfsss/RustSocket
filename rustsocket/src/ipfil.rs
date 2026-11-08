//! The IP filter calls (ipf_open, ipf_close, ipf_ioctl, ipf_log_read,
//! ipf_log_data_waiting, ipf_set_notify_mask, ipf_set_interrupt_mask) that
//! Roadshow's ipf, ipfstat, ipmon and ipnat use; the filter itself is
//! rsnet-core's ipfil.rs.
//!
//! As Roadshow 1.15 answers them (testprogs/rstcp/c/ipfprobe.c):
//! ipf_open(minor) for minors 0-3 (IPL_LOGIPF, IPL_LOGNAT,
//! IPL_LOGSTATE, IPL_LOGAUTH) gives the handle 0x60000000 + minor, the same
//! every time, other minors ENXIO; ipf_close answers -1 EBUSY; a call on
//! anything but a handle ENXIO; an unknown ioctl EINVAL; ipf_log_read of 0
//! bytes EINVAL; ipf_log_data_waiting 1 when records wait (FIONREAD gives
//! their bytes); ipf_log_read gives whole records only and does not wait.
//! SIOCAUTHW waits for a held datagram (authprobe.c); a break
//! signal ends the wait with EINTR and stays set.

use amigaos4::sys::Interface;
use rsnet_core::ipfil;

use super::opener;

const HANDLE_BASE: i32 = 0x6000_0000;
/// Opener::ipf_intr before ipf_set_interrupt_mask: use the break mask.
pub const IPF_INTR_UNSET: u32 = u32::MAX;
const MINORS: i32 = 4;

/// The minor a handle names.
fn minor(h: i32) -> Result<u32, i32> {
    let k = h.wrapping_sub(HANDLE_BASE);
    if (0..MINORS).contains(&k) {
        Ok(k as u32)
    } else {
        Err(ipfil::ENXIO)
    }
}

fn answer(i: *mut Interface, r: Result<i32, i32>) -> i32 {
    match r {
        Ok(v) => {
            if let Some(o) = opener(i) {
                o.set_errno(0);
            }
            v
        }
        Err(e) => match opener(i) {
            Some(o) => o.fail(e),
            None => -1,
        },
    }
}

/// ipf_open(minor): its handle.
#[no_mangle]
pub extern "C" fn rs_ipf_open(i: *mut Interface, channel: i32) -> i32 {
    let r = if (0..MINORS).contains(&channel) { Ok(HANDLE_BASE + channel) } else { Err(ipfil::ENXIO) };
    answer(i, r)
}

/// ipf_close(handle): Roadshow answers -1 EBUSY.
#[no_mangle]
pub extern "C" fn rs_ipf_close(i: *mut Interface, h: i32) -> i32 {
    let r = minor(h).and(Err(ipfil::EBUSY));
    answer(i, r)
}

/// ipf_ioctl(handle, command, data).
#[no_mangle]
pub extern "C" fn rs_ipf_ioctl(i: *mut Interface, h: i32, cmd: u32, data: *mut u8) -> i32 {
    let r = minor(h).and_then(|m| {
        if data.is_null() {
            return Err(ipfil::EINVAL);
        }
        if m == ipfil::IPL_LOGAUTH && cmd == ipfil::SIOCAUTHW {
            return auth_wait(i, data);
        }
        // SAFETY: the caller passes what the command takes (a value, or a
        // pointer to a struct), as the IP Filter tools do.
        let r = unsafe { ipfil::ioctl(m, cmd, data) };
        if r.is_ok() && m == ipfil::IPL_LOGAUTH && cmd == ipfil::SIOCAUTHR {
            // The released datagram goes out from the stack process.
            if let Some(s) = super::stack() {
                s.wake();
            }
        }
        r
    });
    answer(i, r)
}

/// SIOCAUTHW: wait until a datagram is held, then hand its struct frauth
/// through the caller's pointer.
fn auth_wait(i: *mut Interface, data: *mut u8) -> Result<i32, i32> {
    let intr = match opener(i) {
        Some(o) if o.ipf_intr != IPF_INTR_UNSET => o.ipf_intr,
        Some(o) => o.break_mask,
        None => return Err(ipfil::EINVAL),
    };
    let sig = amigaos4::signal::Signal::alloc().map_err(|_| ipfil::EIO)?;
    let task = amigaos4::signal::current_task() as u32;
    let r = loop {
        match ipfil::auth_wait(task, sig.mask()) {
            Err(e) => break Err(e),
            Ok(Some(b)) => {
                // SAFETY: `data` holds the caller's frauth pointer (the
                // tools' convention, as the other struct ioctls); 96 bytes.
                unsafe {
                    let p = (data as *const *mut u8).read_unaligned();
                    if p.is_null() {
                        break Err(ipfil::EINVAL);
                    }
                    core::ptr::copy_nonoverlapping(b.as_ptr(), p, b.len());
                }
                break Ok(0);
            }
            Ok(None) => {}
        }
        let got = amigaos4::signal::wait(sig.mask() | intr);
        if got & intr != 0 {
            let _ = ipfil::auth_wait(task, 0);
            // As Roadshow: the break stays set for the program to see.
            // SAFETY: sets only the caller's own signal bits it was sent.
            unsafe { amigaos4::sys::exec_set_signal(got & intr, got & intr) };
            break Err(ipfil::EINTR);
        }
    };
    // A hold may have signalled after the wait ended: drop it.
    sig.take();
    r
}

/// ipf_log_read(handle, buffer, length): whole log records, as many as
/// fit; 0 when none waits.
#[no_mangle]
pub extern "C" fn rs_ipf_log_read(i: *mut Interface, h: i32, buf: *mut u8, len: i32) -> i32 {
    let r = minor(h).and_then(|m| {
        if len <= 0 || buf.is_null() {
            return Err(ipfil::EINVAL);
        }
        let recs = ipfil::log_read(m, len as usize)?;
        // SAFETY: the caller's buffer of `len` bytes; recs.len() <= len.
        unsafe { core::ptr::copy_nonoverlapping(recs.as_ptr(), buf, recs.len()) };
        Ok(recs.len() as i32)
    });
    answer(i, r)
}

/// ipf_log_data_waiting(handle): 1 when log records wait (Roadshow's
/// answer), else 0.
#[no_mangle]
pub extern "C" fn rs_ipf_log_data_waiting(i: *mut Interface, h: i32) -> i32 {
    let r = minor(h).map(|m| (ipfil::log_waiting(m) > 0) as i32);
    answer(i, r)
}

/// ipf_set_notify_mask(handle, signals): the calling task gets them when
/// a log record arrives.
#[no_mangle]
pub extern "C" fn rs_ipf_set_notify_mask(i: *mut Interface, h: i32, mask: u32) -> i32 {
    let r = minor(h).map(|m| {
        // SAFETY: FindTask(NULL), the calling task.
        let me = unsafe { amigaos4::sys::exec_find_task(core::ptr::null_mut()) } as usize as u32;
        ipfil::set_notify(m, me, mask);
        0
    });
    answer(i, r)
}

/// ipf_set_interrupt_mask(handle, signals): the signals that end a wait in
/// SIOCAUTHW (until then the break mask, CTRL-C by default).
#[no_mangle]
pub extern "C" fn rs_ipf_set_interrupt_mask(i: *mut Interface, h: i32, mask: u32) -> i32 {
    let r = minor(h).map(|_| {
        if let Some(o) = opener(i) {
            o.ipf_intr = mask;
        }
        0
    });
    answer(i, r)
}
