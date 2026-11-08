//! The RoadshowData API: ObtainRoadshowData, ChangeRoadshowData,
//! ReleaseRoadshowData (RoadshowControl's), over the stack's named options
//! (rsnet_core::settings), and ENV:Roadshow/<area>/<name> read when the
//! stack starts (RoadshowControl SAVE writes them to ENVARC:).
//!
//! The list handed out is a snapshot: one exec List of RoadshowDataNodes
//! (rdn_MinNode, rdn_Name, rdn_Flags, rdn_Type, rdn_Length, rdn_Data: 24
//! bytes, pack(2)), each pointing to its LONG; ChangeRoadshowData changes
//! the option and the snapshot's value. One opener at a time may hold
//! write access; a second writer waits for the first to release it.

use alloc::boxed::Box;

use amigaos4::sys::Interface;
use rsnet_core::settings::{self, Refused, OPTIONS};

use super::{opener, shared};

const EINVAL: i32 = 22;
const EACCES: i32 = 13;
const ENOENT: i32 = 2;
const ENOSPC: i32 = 28;

const ORD_WRITE_ACCESS: i32 = 1;
const RDNT_INTEGER: u16 = 0;

/// Block layout: List (16), nodes (24 each), names (32 each), values (4).
const LIST: usize = 16;
const NODE: usize = 24;
const NAME: usize = 32;

/// ObtainRoadshowData(access): the options, or NULL with errno.
#[no_mangle]
pub extern "C" fn rs_ObtainRoadshowData(i: *mut Interface, access: i32) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    if access != 0 && access != ORD_WRITE_ACCESS {
        o.fail(EINVAL);
        return core::ptr::null_mut();
    }
    let n = OPTIONS.len();
    let total = LIST + n * (NODE + NAME + 4);
    let words = total.div_ceil(4);
    let block: Box<[u32]> = alloc::vec![0u32; words].into_boxed_slice();
    let base = Box::into_raw(block) as *mut u32 as usize;
    let put = |at: usize, x: u32| {
        // SAFETY: inside our block of `words` LONGs.
        unsafe { core::ptr::write_unaligned((base + at) as *mut u32, x) }
    };
    let node = |k: usize| base + LIST + k * NODE;
    let tail = (base + 4) as u32;
    put(0, node(0) as u32);
    put(8, node(n - 1) as u32);
    for (k, opt) in OPTIONS.iter().enumerate() {
        let name_at = base + LIST + n * NODE + k * NAME;
        let value_at = base + LIST + n * (NODE + NAME) + k * 4;
        // SAFETY: a 32-byte name slot (the names are shorter) and the
        // value's LONG, inside the block.
        unsafe {
            core::ptr::copy_nonoverlapping(opt.name.as_ptr(), name_at as *mut u8, opt.name.len().min(NAME - 1));
            core::ptr::write_unaligned(value_at as *mut i32, settings::get(opt.name).unwrap_or(opt.default));
        }
        let at = node(k) - base;
        put(at, if k + 1 < n { node(k + 1) as u32 } else { tail });
        put(at + 4, if k == 0 { base as u32 } else { node(k - 1) as u32 });
        put(at + 8, name_at as u32);
        // rdn_Flags (0: changeable) and rdn_Type (RDNT_Integer).
        put(at + 12, RDNT_INTEGER as u32);
        put(at + 16, 4);
        put(at + 20, value_at as u32);
    }
    let write = access == ORD_WRITE_ACCESS;
    // Access follows an exec semaphore's rules, as Roadshow's does
    // (testprogs/rstcp/c/rdprobe): write access
    // waits while anyone holds a list, unless only this task holds write
    // access (a read list of its own blocks it too: "rdprobe rw" never
    // returns); read access waits while another task holds write access.
    // Roadshow's wait keeps its stack task busy; this one sleeps 1/50 s
    // between looks.
    // SAFETY: FindTask(NULL), this task.
    let me = unsafe { amigaos4::sys::exec_find_task(core::ptr::null()) } as usize;
    let mut sh = loop {
        let Some(sh) = shared::lock() else {
            // SAFETY: just made, not handed out.
            drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(base as *mut u32, words)) });
            o.fail(EINVAL);
            return core::ptr::null_mut();
        };
        let other_writer = sh.rd_writers.iter().any(|&(_, t)| t != me);
        if !other_writer && (!write || sh.rd_readers.is_empty()) {
            break sh;
        }
        drop(sh);
        // SAFETY: Delay(1), 1/50 s; RoadshowData's callers are Processes.
        unsafe { amigaos4::sys::dos_delay(1) };
    };
    if write {
        sh.rd_writers.push((base, me));
    } else {
        sh.rd_readers.push((base, me));
    }
    sh.rd_lists.push((base, words));
    base as *mut u8
}

/// ChangeRoadshowData(list, name, length, data): TRUE, or FALSE with errno.
#[no_mangle]
pub extern "C" fn rs_ChangeRoadshowData(i: *mut Interface, list: *mut u8, name: *const u8, length: u32, data: *const u8) -> i32 {
    let Some(o) = opener(i) else { return 0 };
    let fail = |o: &mut super::Opener, e: i32| {
        o.fail(e);
        0
    };
    let (known, writer) = match shared::lock() {
        Some(sh) => (sh.rd_lists.iter().any(|&(p, _)| p == list as usize), sh.rd_writers.iter().any(|&(p, _)| p == list as usize)),
        None => (false, false),
    };
    if !known || name.is_null() {
        return fail(o, EINVAL);
    }
    if !writer {
        return fail(o, EACCES);
    }
    // SAFETY: the caller's NUL-terminated name.
    let Ok(n) = unsafe { core::ffi::CStr::from_ptr(name as *const core::ffi::c_char) }.to_str() else { return fail(o, ENOENT) };
    let Some(k) = OPTIONS.iter().position(|opt| opt.name.eq_ignore_ascii_case(n)) else { return fail(o, ENOENT) };
    if length != 4 || data.is_null() {
        return fail(o, ENOSPC);
    }
    // SAFETY: the caller's 4-byte value.
    let v = unsafe { core::ptr::read_unaligned(data as *const i32) };
    match settings::set(OPTIONS[k].name, v) {
        Ok(()) => {
            let value_at = list as usize + LIST + OPTIONS.len() * (NODE + NAME) + k * 4;
            // SAFETY: the snapshot's value for option k (the list is ours).
            unsafe { core::ptr::write_unaligned(value_at as *mut i32, v) };
            1
        }
        Err(Refused::Unknown) => fail(o, ENOENT),
        // A value this stack cannot do (roadshow-compat.md).
        Err(Refused::Value) => fail(o, EINVAL),
    }
}

/// ReleaseRoadshowData(list).
#[no_mangle]
pub extern "C" fn rs_ReleaseRoadshowData(_i: *mut Interface, list: *mut u8) {
    if list.is_null() {
        return;
    }
    let Some(mut sh) = shared::lock() else { return };
    let Some(k) = sh.rd_lists.iter().position(|&(p, _)| p == list as usize) else { return };
    let (p, words) = sh.rd_lists.swap_remove(k);
    sh.rd_writers.retain(|&(l, _)| l != p);
    sh.rd_readers.retain(|&(l, _)| l != p);
    drop(sh);
    // SAFETY: a block from rs_ObtainRoadshowData, listed once.
    drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(p as *mut u32, words)) });
}

/// ENV:Roadshow/<area>/<rest of the name> for each option (e.g.
/// ENV:Roadshow/tcp/recvspace), when the stack starts.
pub fn read_env() {
    for opt in OPTIONS.iter() {
        let Some((area, rest)) = opt.name.split_once('.') else { continue };
        let var = alloc::format!("Roadshow/{}/{}", area, rest);
        let Ok(Some(v)) = amigaos4::dos::get_var(&var, amigaos4::dos::VarScope::Global) else { continue };
        match v.trim().parse::<i32>() {
            Ok(x) => {
                if settings::set(opt.name, x).is_err() {
                    amigaos4::serial_println!("rustsocket.library: ENV:{} = {} is not taken here", var, x);
                }
            }
            Err(_) => amigaos4::serial_println!("rustsocket.library: ENV:{}: not a number", var),
        }
    }
}
