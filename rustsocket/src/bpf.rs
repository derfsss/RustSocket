//! The packet filter calls (bpf_open, bpf_close, bpf_read, bpf_write,
//! bpf_set_notify_mask, bpf_set_interrupt_mask, bpf_ioctl,
//! bpf_data_waiting); the channels and the tap are rsnet-core's bpf.rs.

use alloc::vec::Vec;

use amigaos4::sys::{self, Interface};
use rsnet_core::bpf::{self, Chan, Insn, CHANNELS, HANDLE_BASE, MAX_BLEN, MIN_BLEN};

use super::{opener, stack, Opener};

const EPERM: i32 = 1;
const EINTR: i32 = 4;
const ENXIO: i32 = 6;
const EBUSY: i32 = 16;
const EINVAL: i32 = 22;
const EIO: i32 = 5;

const FIONREAD: u32 = 0x4004_667F;
const BIOCGBLEN: u32 = 0x4004_4266;
const BIOCSBLEN: u32 = 0xC004_4266;
const BIOCSETF: u32 = 0x8008_4267;
const BIOCFLUSH: u32 = 0x2000_4268;
const BIOCPROMISC: u32 = 0x2000_4269;
const BIOCGDLT: u32 = 0x4004_426A;
const BIOCGETIF: u32 = 0x4020_426B;
const BIOCSETIF: u32 = 0x8020_426C;
const BIOCSRTIMEOUT: u32 = 0x8008_426D;
const BIOCGRTIMEOUT: u32 = 0x4008_426E;
const BIOCGSTATS: u32 = 0x4008_426F;
const BIOCIMMEDIATE: u32 = 0x8004_4270;
const BIOCVERSION: u32 = 0x4004_4271;

fn me(o: &mut Opener) -> usize {
    o as *mut Opener as usize
}

/// The channel a handle names, if this opener owns it: Ok(index), or the
/// errno (ENXIO: no such channel; EPERM: not ours or not open, as Roadshow
/// answers a second bpf_close).
fn index(t: &bpf::Table, owner: usize, h: i32) -> Result<usize, i32> {
    let k = h.wrapping_sub(HANDLE_BASE);
    if !(0..CHANNELS as i32).contains(&k) {
        return Err(ENXIO);
    }
    match &t[k as usize] {
        Some(c) if c.owner == owner => Ok(k as usize),
        _ => Err(EPERM),
    }
}

/// Run `f` on channel `h` of this opener: its result, or -1 with errno.
fn with<R>(i: *mut Interface, h: i32, f: impl FnOnce(&mut Chan) -> Result<R, i32>) -> Result<R, i32> {
    let Some(o) = opener(i) else { return Err(EINVAL) };
    let owner = me(o);
    let Some(mut t) = bpf::lock() else { return Err(EIO) };
    let k = index(&t, owner, h)?;
    let r = f(t[k].as_mut().unwrap());
    bpf::recount(&t);
    r
}

fn answer(i: *mut Interface, r: Result<i32, i32>) -> i32 {
    match r {
        // Roadshow clears errno when a packet filter call succeeds.
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

/// bpf_open(channel): a channel (-1: the first free); its handle.
#[no_mangle]
pub extern "C" fn rs_bpf_open(i: *mut Interface, channel: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let owner = me(o);
    let r = (|| {
        let mut t = bpf::lock().ok_or(EIO)?;
        let k = if channel == -1 {
            t.iter().position(|c| c.is_none()).ok_or(EBUSY)?
        } else if (0..CHANNELS as i32).contains(&channel) {
            channel as usize
        } else {
            return Err(ENXIO);
        };
        if t[k].is_some() {
            return Err(EBUSY);
        }
        t[k] = Some(Chan::new(owner));
        Ok(HANDLE_BASE + k as i32)
    })();
    answer(i, r)
}

/// bpf_close(handle).
#[no_mangle]
pub extern "C" fn rs_bpf_close(i: *mut Interface, h: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let owner = me(o);
    let r = (|| {
        let mut t = bpf::lock().ok_or(EIO)?;
        let k = index(&t, owner, h)?;
        t[k] = None;
        bpf::recount(&t);
        Ok(0)
    })();
    answer(i, r)
}

/// The opener goes (CloseLibrary): its channels close with it.
pub fn close_all(owner: usize) {
    if let Some(mut t) = bpf::lock() {
        for c in t.iter_mut() {
            if c.as_ref().is_some_and(|c| c.owner == owner) {
                *c = None;
            }
        }
        bpf::recount(&t);
    }
}

/// bpf_data_waiting(handle): 1 when bpf_read has something, else 0.
#[no_mangle]
pub extern "C" fn rs_bpf_data_waiting(i: *mut Interface, h: i32) -> i32 {
    let r = with(i, h, |c| Ok(!c.buf.is_empty() as i32));
    answer(i, r)
}

/// bpf_set_notify_mask(handle, mask): signal the caller on new data.
#[no_mangle]
pub extern "C" fn rs_bpf_set_notify_mask(i: *mut Interface, h: i32, mask: u32) -> i32 {
    let task = amigaos4::signal::current_task() as u32;
    let r = with(i, h, |c| {
        c.notify = (task, mask);
        Ok(0)
    });
    answer(i, r)
}

/// bpf_set_interrupt_mask(handle, mask): signals that end a bpf_read.
#[no_mangle]
pub extern "C" fn rs_bpf_set_interrupt_mask(i: *mut Interface, h: i32, mask: u32) -> i32 {
    let r = with(i, h, |c| {
        c.interrupt = mask;
        Ok(0)
    });
    answer(i, r)
}

/// bpf_read(handle, buffer, len): the packets gathered, `len` must be the
/// buffer size. Waits for data (immediate), a full buffer or the timeout;
/// the interrupt mask ends it with EINTR.
#[no_mangle]
pub extern "C" fn rs_bpf_read(i: *mut Interface, h: i32, out: *mut u8, len: i32) -> i32 {
    let r = read(i, h, out, len);
    answer(i, r)
}

fn read(i: *mut Interface, h: i32, out: *mut u8, len: i32) -> Result<i32, i32> {
    let (blen, timeout_us, interrupt) = with(i, h, |c| {
        if c.slot.is_none() || len < 0 || len as usize != c.blen {
            return Err(EINVAL);
        }
        Ok((c.blen, c.timeout_us, c.interrupt))
    })?;
    if out.is_null() {
        return Err(EINVAL);
    }
    let sig = amigaos4::signal::Signal::alloc().map_err(|_| EIO)?;
    let task = amigaos4::signal::current_task() as u32;
    let mut timer = None;
    if timeout_us != 0 {
        let mut t = amigaos4::timer::AmigaTimer::open(amigaos4::timer::TimerUnit::MicroHz).map_err(|_| EIO)?;
        t.start(amigaos4::timer::TimerVal::from_micros(timeout_us));
        timer = Some(t);
    }
    let tmask = timer.as_ref().map(|t| t.signal_mask()).unwrap_or(0);
    let mut timed_out = false;
    let r = loop {
        let step = with(i, h, |c| {
            if !c.buf.is_empty() && (c.immediate || c.full() || timed_out) {
                let n = c.buf.len().min(blen);
                // SAFETY: the caller's buffer of `len` (= blen) bytes.
                unsafe { core::ptr::copy_nonoverlapping(c.buf.as_ptr(), out, n) };
                c.buf.clear();
                c.reader = (0, 0);
                return Ok(Some(n as i32));
            }
            if timed_out {
                c.reader = (0, 0);
                return Ok(Some(0));
            }
            c.reader = (task, sig.mask());
            Ok(None)
        });
        match step {
            Err(e) => break Err(e),
            Ok(Some(n)) => break Ok(n),
            Ok(None) => {}
        }
        let got = amigaos4::signal::wait(sig.mask() | interrupt | tmask);
        if got & interrupt != 0 {
            let _ = with(i, h, |c| {
                c.reader = (0, 0);
                Ok(())
            });
            // As a socket call's break: the program tests it itself after.
            // SAFETY: sets only the caller's own signal bits it was sent.
            unsafe { sys::exec_set_signal(got & interrupt, got & interrupt) };
            break Err(EINTR);
        }
        if got & tmask != 0 {
            timed_out = true;
        }
    };
    if let Some(mut t) = timer {
        t.abort();
    }
    // A tap may have signalled after the entry was cleared: drop it.
    sig.take();
    r
}

/// bpf_write(handle, data, len): one whole frame out of the interface.
#[no_mangle]
pub extern "C" fn rs_bpf_write(i: *mut Interface, h: i32, data: *const u8, len: i32) -> i32 {
    let r = (|| {
        let slot = with(i, h, |c| c.slot.ok_or(EINVAL))?;
        if data.is_null() || len < 14 {
            return Err(EINVAL);
        }
        // SAFETY: the caller's frame of `len` bytes.
        let frame = unsafe { core::slice::from_raw_parts(data, len as usize) }.to_vec();
        stack().ok_or(ENXIO)?.bpf_write(slot, frame).map(|n| n as i32)
    })();
    answer(i, r)
}

fn put(arg: *mut u8, at: usize, v: u32) {
    // SAFETY: the caller's argument, of the size its request names.
    unsafe { core::ptr::write_unaligned(arg.add(at) as *mut u32, v.to_be()) };
}

fn get(arg: *const u8, at: usize) -> u32 {
    // SAFETY: as put.
    u32::from_be(unsafe { core::ptr::read_unaligned(arg.add(at) as *const u32) })
}

/// The interface slot named in an ifreq, and its name.
fn slot_of(name: &[u8]) -> Option<u8> {
    let n = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
    let all = stack()?.status()?;
    all.iter().position(|s| s.present && s.name.as_bytes().eq_ignore_ascii_case(n) && s.name != "lo0").map(|k| k as u8)
}

/// bpf_ioctl(handle, request, arg).
#[no_mangle]
pub extern "C" fn rs_bpf_ioctl(i: *mut Interface, h: i32, req: u32, arg: *mut u8) -> i32 {
    let r = ioctl(i, h, req, arg);
    answer(i, r)
}

fn ioctl(i: *mut Interface, h: i32, req: u32, arg: *mut u8) -> Result<i32, i32> {
    let needs_arg = !matches!(req, BIOCFLUSH | BIOCPROMISC);
    if needs_arg && arg.is_null() {
        return Err(EINVAL);
    }
    match req {
        BIOCSETIF => {
            // SAFETY: the caller's struct ifreq: the name is its first 16
            // bytes.
            let name = unsafe { core::slice::from_raw_parts(arg, 16) }.to_vec();
            let slot = slot_of(&name).ok_or(ENXIO)?;
            with(i, h, |c| {
                c.slot = Some(slot);
                c.flush();
                c.buf.reserve(c.blen);
                Ok(0)
            })
        }
        BIOCGETIF => {
            let slot = with(i, h, |c| c.slot.ok_or(EINVAL))?;
            let all = stack().and_then(|s| s.status()).unwrap_or_default();
            let name = all.get(slot as usize).map(|s| s.name.clone()).ok_or(ENXIO)?;
            // SAFETY: the caller's struct ifreq (32 bytes).
            unsafe {
                core::ptr::write_bytes(arg, 0, 16);
                core::ptr::copy_nonoverlapping(name.as_ptr(), arg, name.len().min(15));
            }
            Ok(0)
        }
        _ => with(i, h, |c| {
            match req {
                FIONREAD => put(arg, 0, c.buf.len() as u32),
                BIOCGBLEN => put(arg, 0, c.blen as u32),
                BIOCSBLEN => {
                    if c.slot.is_some() {
                        return Err(EINVAL);
                    }
                    c.blen = (get(arg, 0) as usize).clamp(MIN_BLEN, MAX_BLEN);
                    put(arg, 0, c.blen as u32);
                }
                BIOCSETF => {
                    let n = get(arg, 0) as usize;
                    let p = get(arg, 4) as *const u8;
                    if n == 0 || p.is_null() {
                        c.filter = None;
                    } else {
                        if n > bpf::MAX_INSNS {
                            return Err(EINVAL);
                        }
                        // SAFETY: the caller's array of `n` 8-byte insns.
                        let raw = unsafe { core::slice::from_raw_parts(p, n * 8) };
                        let prog: Vec<Insn> = raw
                            .chunks(8)
                            .map(|w| Insn { code: u16::from_be_bytes([w[0], w[1]]), jt: w[2], jf: w[3], k: u32::from_be_bytes([w[4], w[5], w[6], w[7]]) })
                            .collect();
                        if !bpf::valid(&prog) {
                            return Err(EINVAL);
                        }
                        c.filter = Some(prog);
                    }
                    c.flush();
                }
                BIOCFLUSH => c.flush(),
                // virtio-net on QEMU sees only frames for this host and
                // broadcasts; the device is not switched (nothing to gain).
                BIOCPROMISC => {}
                BIOCGDLT => {
                    if c.slot.is_none() {
                        return Err(EINVAL);
                    }
                    put(arg, 0, 1);
                }
                BIOCSRTIMEOUT => c.timeout_us = get(arg, 0) as u64 * 1_000_000 + get(arg, 4) as u64,
                BIOCGRTIMEOUT => {
                    put(arg, 0, (c.timeout_us / 1_000_000) as u32);
                    put(arg, 4, (c.timeout_us % 1_000_000) as u32);
                }
                BIOCGSTATS => {
                    put(arg, 0, c.recv);
                    put(arg, 4, c.drop);
                }
                BIOCIMMEDIATE => c.immediate = get(arg, 0) != 0,
                BIOCVERSION => put(arg, 0, 0x0001_0001),
                _ => return Err(EINVAL),
            }
            Ok(0)
        }),
    }
}
