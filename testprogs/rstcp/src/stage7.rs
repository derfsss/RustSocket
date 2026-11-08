//! SocketBaseTagList checks. Every Roadshow tool
//! asks the library about itself through it before anything else. Checks
//! queries by value (the answer goes into the tag's ti_Data) and by
//! reference, the error strings, the release string, the system status,
//! a stack-wide setting, the descriptor table size, the h_errno pointer,
//! the byte counters and the error and log hooks. A setting rustsocket
//! cannot honour must be refused; that check runs only on rustsocket
//! (Roadshow forwards datagrams).

use alloc::string::String;
use core::ffi::{c_void, CStr};
use core::sync::atomic::{AtomicU32, Ordering};

use amigaos4::bsdsocket::SocketLib;
use amigaos4::hook::Hook;
use amigaos4::sys::{SocketIFace, TagItem, TAG_DONE, TAG_USER};

use super::Tally;

const SBTF_REF: u32 = 0x8000;
const SBTF_SET: u32 = 1;
const ERRNOSTRPTR: u32 = 14;
const LOGMASK: u32 = 13;
const HERRNOLONGPTR: u32 = 25;
const DTABLESIZE: u32 = 8;
const RELEASESTRPTR: u32 = 29;
const IP_FORWARDING: u32 = 43;
const IP_DEFAULT_TTL: u32 = 44;
const HAVE_ADDRESS_CONVERSION_API: u32 = 60;
const LOG_HOOK: u32 = 55;
const SYSTEM_STATUS: u32 = 56;
const GET_BYTES_RECEIVED: u32 = 64;
const ERROR_HOOK: u32 = 68;

fn getval(c: u32) -> u32 {
    TAG_USER | (c << 1)
}
fn getref(c: u32) -> u32 {
    TAG_USER | SBTF_REF | (c << 1)
}
fn setval(c: u32) -> u32 {
    TAG_USER | (c << 1) | SBTF_SET
}

fn tags(i: *mut SocketIFace, t: &mut [TagItem]) -> i32 {
    // SAFETY: a TAG_DONE-ended list the call may update.
    unsafe { ((*i).SocketBaseTagList)(i, t.as_mut_ptr()) }
}

fn one(i: *mut SocketIFace, tag: u32, data: u32) -> (i32, u32) {
    let mut t = [TagItem { ti_Tag: tag, ti_Data: data }, TagItem { ti_Tag: TAG_DONE, ti_Data: 0 }];
    let r = tags(i, &mut t);
    (r, t[0].ti_Data)
}

fn cstr(p: u32) -> String {
    if p == 0 {
        return String::new();
    }
    // SAFETY: a NUL-terminated string from the library.
    String::from_utf8_lossy(unsafe { CStr::from_ptr(p as *const core::ffi::c_char) }.to_bytes()).into_owned()
}

static HOOK_CODE: AtomicU32 = AtomicU32::new(0);
static HOOK_CALLS: AtomicU32 = AtomicU32::new(0);
static LOG_PRI: AtomicU32 = AtomicU32::new(99);

pub fn run(lib: &SocketLib, t: &mut Tally) {
    run_parts(lib, t, 0x1f);
}

/// The parts whose bits are set: 1 base tags, 2 HERRNOLONGPTR lookup,
/// 4 ERROR_HOOK, 8 LOG_HOOK + LOGMASK, 0x10 RoadshowData
/// (`rstcp api mask=N`: these are N's bits 8-12).
pub fn run_parts(lib: &SocketLib, t: &mut Tally, m: u32) {
    let i = lib.iface();
    if m & 1 != 0 {
        base(lib, t);
    }
    if m & 2 != 0 {
        lookup(i, t);
    }
    if m & 4 != 0 {
        error_hook(i, t);
    }
    if m & 8 != 0 {
        log_hook(i, t);
    }
    if m & 0x10 != 0 {
        roadshow_data(i, t);
    }
}

fn base(lib: &SocketLib, t: &mut Tally) {
    let i = lib.iface();

    let (r, s) = one(i, getval(ERRNOSTRPTR), 61);
    t.check(r == 0 && cstr(s) == "Connection refused", format_args!("ERRNOSTRPTR by value, 61: {} {:?}", r, cstr(s)));
    let mut code: u32 = 22;
    let (r, _) = one(i, getref(ERRNOSTRPTR), &mut code as *mut u32 as u32);
    t.check(r == 0 && cstr(code) == "Invalid argument", format_args!("ERRNOSTRPTR by reference, 22: {} {:?}", r, cstr(code)));

    let (r, rel) = one(i, getval(RELEASESTRPTR), 0);
    let release = cstr(rel);
    let ours = release.contains("rustsocket");
    t.check(r == 0 && !release.is_empty(), format_args!("RELEASESTRPTR: {:?}", release));

    let (r, st) = one(i, getval(SYSTEM_STATUS), 0);
    // SBSYSSTAT_Interfaces | SBSYSSTAT_BCast_Interfaces: the run has an address.
    t.check(r == 0 && st & 5 == 5, format_args!("SYSTEM_STATUS: {} 0x{:x}", r, st));

    let (r, v) = one(i, getval(HAVE_ADDRESS_CONVERSION_API), 0);
    t.check(r == 0 && v == 1, format_args!("HAVE_ADDRESS_CONVERSION_API: {} {}", r, v));

    let (_, ttl0) = one(i, getval(IP_DEFAULT_TTL), 0);
    let (r1, _) = one(i, setval(IP_DEFAULT_TTL), 32);
    let (_, ttl1) = one(i, getval(IP_DEFAULT_TTL), 0);
    let _ = one(i, setval(IP_DEFAULT_TTL), ttl0);
    t.check(ttl0 == 64 && r1 == 0 && ttl1 == 32, format_args!("IP_DEFAULT_TTL: {} -> set 32 ({}) -> {}", ttl0, r1, ttl1));
    if ours {
        // Forwarding can be switched on, as on Roadshow (RoadshowControl
        // SET ip.forwarding=1), and off again.
        let (r, _) = one(i, setval(IP_FORWARDING), 1);
        let (_, on) = one(i, getval(IP_FORWARDING), 0);
        let (r0, _) = one(i, setval(IP_FORWARDING), 0);
        let (_, off) = one(i, getval(IP_FORWARDING), 0);
        t.check(r == 0 && on == 1 && r0 == 0 && off == 0, format_args!("IP_FORWARDING: on ({}) -> {}, off ({}) -> {}", r, on, r0, off));
    }

    let (r, _) = one(i, setval(DTABLESIZE), 512);
    // SAFETY: a plain call.
    let n = unsafe { ((*i).getdtablesize)(i) };
    t.check(r == 0 && n == 512, format_args!("DTABLESIZE set 512: {}, getdtablesize {}", r, n));

    let mut bytes = [0u32; 2];
    let (r, _) = one(i, getref(GET_BYTES_RECEIVED), bytes.as_mut_ptr() as u32);
    t.check(r == 0 && (bytes[0] != 0 || bytes[1] != 0), format_args!("GET_BYTES_RECEIVED: {} {}", r, ((bytes[0] as u64) << 32) | bytes[1] as u64));
}

fn lookup(i: *mut SocketIFace, t: &mut Tally) {
    // h_errno through the program's own variable.
    let mut herr: i32 = -7;
    let (r, _) = one(i, setval(HERRNOLONGPTR), &mut herr as *mut i32 as u32);
    // SAFETY: a NUL-terminated name.
    let h = unsafe { ((*i).gethostbyname)(i, b"no-such-host.invalid\0".as_ptr() as *mut u8) };
    t.check(r == 0 && h.is_null() && herr > 0, format_args!("HERRNOLONGPTR: {}, lookup of no-such-host.invalid set h_errno to {}", r, herr));
    let _ = one(i, setval(HERRNOLONGPTR), 0);
}

fn error_hook(i: *mut SocketIFace, t: &mut Tally) {
    // The error hook sees errno change.
    match Hook::new(|_obj: *mut c_void, msg: *mut c_void| {
        // SAFETY: an ErrorHookMsg: size, action, code.
        let m = unsafe { core::slice::from_raw_parts(msg as *const u32, 3) };
        if m[0] >= 12 && m[1] == 1 {
            HOOK_CODE.store(m[2], Ordering::Relaxed);
        }
        HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }) {
        Ok(hook) => {
            let (r, _) = one(i, setval(ERROR_HOOK), hook.as_ptr() as u32);
            // SAFETY: closing a descriptor that is not open: EBADF.
            let c = unsafe { ((*i).CloseSocket)(i, 4000) };
            let _ = one(i, setval(ERROR_HOOK), 0);
            let code = HOOK_CODE.load(Ordering::Relaxed);
            t.check(r == 0 && c == -1 && code == 9, format_args!("ERROR_HOOK: {}, CloseSocket(4000) {}, hook saw errno {} ({} calls)", r, c, code, HOOK_CALLS.load(Ordering::Relaxed)));
        }
        Err(e) => t.check(false, format_args!("ERROR_HOOK: no hook: {}", e)),
    }
}

fn log_hook(i: *mut SocketIFace, t: &mut Tally) {
    // The log hook takes syslog's messages; LOGMASK filters them first.
    match Hook::new(|_obj: *mut c_void, msg: *mut c_void| {
        // SAFETY: a LogHookMessage: size, priority, ...
        let m = unsafe { core::slice::from_raw_parts(msg as *const u32, 2) };
        LOG_PRI.store(m[1], Ordering::Relaxed);
        0
    }) {
        Ok(hook) => {
            let (r, _) = one(i, setval(LOG_HOOK), hook.as_ptr() as u32);
            let args = [0u32; 2];
            // LOG_DEBUG (7) masked out first, then let through.
            let _ = one(i, setval(LOGMASK), 0x7F);
            // SAFETY: a format with no conversions and an argument array.
            unsafe { ((*i).vsyslog)(i, 7, b"rstcp: masked\0".as_ptr() as *mut u8, args.as_ptr() as *mut c_void) };
            let masked = LOG_PRI.load(Ordering::Relaxed);
            let _ = one(i, setval(LOGMASK), 0xFF);
            // SAFETY: as above.
            unsafe { ((*i).vsyslog)(i, 6, b"rstcp: through the log hook\0".as_ptr() as *mut u8, args.as_ptr() as *mut c_void) };
            let seen = LOG_PRI.load(Ordering::Relaxed);
            let _ = one(i, setval(LOG_HOOK), 0);
            t.check(r == 0 && masked == 99 && seen == 6, format_args!("LOG_HOOK + LOGMASK: {}, masked message {}, LOG_INFO message priority {}", r, if masked == 99 { "not seen" } else { "SEEN" }, seen));
        }
        Err(e) => t.check(false, format_args!("LOG_HOOK: no hook: {}", e)),
    }
}

/// The RoadshowData API (RoadshowControl's): read and write lists, write
/// access for one at a time, the refusals; the TTL changed and put back.
fn roadshow_data(i: *mut SocketIFace, t: &mut Tally) {
    // SAFETY: plain calls; the lists are given back; names are
    // NUL-terminated, values 4 bytes.
    unsafe {
        let errno = || ((*i).Errno)(i);
        // Write access first, then read: Roadshow's access is an exec
        // semaphore's (measured with c/rdprobe): a task holding a
        // read list that asks for write access waits for ever.
        let wl = ((*i).ObtainRoadshowData)(i, 1);
        let rl = ((*i).ObtainRoadshowData)(i, 0);
        t.check(!rl.is_null() && !wl.is_null(), format_args!("RoadshowData: read and write lists"));
        let mut v: i32 = 32;
        let vp = &mut v as *mut i32 as *mut c_void;
        let ro = ((*i).ChangeRoadshowData)(i, rl, b"ip.defttl\0".as_ptr() as *mut u8, 4, vp);
        let e_ro = errno();
        let ok = ((*i).ChangeRoadshowData)(i, wl, b"IP.DefTTL\0".as_ptr() as *mut u8, 4, vp);
        let mut q = [TagItem { ti_Tag: getval(IP_DEFAULT_TTL), ti_Data: 0 }, TagItem { ti_Tag: TAG_DONE, ti_Data: 0 }];
        tags(i, &mut q);
        let ttl = q[0].ti_Data;
        let unknown = ((*i).ChangeRoadshowData)(i, wl, b"no.such\0".as_ptr() as *mut u8, 4, vp);
        let e_unknown = errno();
        let short = ((*i).ChangeRoadshowData)(i, wl, b"ip.defttl\0".as_ptr() as *mut u8, 2, vp);
        let e_short = errno();
        let mut on: i32 = 1;
        let fwd = ((*i).ChangeRoadshowData)(i, wl, b"ip.forwarding\0".as_ptr() as *mut u8, 4, &mut on as *mut i32 as *mut c_void);
        let mut back: i32 = 64;
        ((*i).ChangeRoadshowData)(i, wl, b"ip.defttl\0".as_ptr() as *mut u8, 4, &mut back as *mut i32 as *mut c_void);
        let mut off: i32 = 0;
        ((*i).ChangeRoadshowData)(i, wl, b"ip.forwarding\0".as_ptr() as *mut u8, 4, &mut off as *mut i32 as *mut c_void);
        ((*i).ReleaseRoadshowData)(i, rl);
        ((*i).ReleaseRoadshowData)(i, wl);
        t.check(
            ro == 0 && e_ro == 13 && ok != 0 && ttl == 32 && unknown == 0 && e_unknown == 2 && short == 0 && e_short == 28 && fwd != 0,
            format_args!(
                "RoadshowData: read list EACCES ({} {}), ip.defttl set on the write list ({}) -> SBTC TTL {}, unknown ENOENT ({}), 2 bytes ENOSPC ({}), ip.forwarding 1 taken ({})",
                ro, e_ro, ok, ttl, e_unknown, e_short, fwd
            ),
        );
        let again = ((*i).ObtainRoadshowData)(i, 1);
        t.check(!again.is_null(), format_args!("RoadshowData: write access free again after the release"));
        ((*i).ReleaseRoadshowData)(i, again);
    }
}
