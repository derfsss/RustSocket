//! SocketBaseTagList: every SBTC code of SDK 54.25's
//! netinclude/libraries/bsdsocket.h, as Roadshow's autodoc describes it.
//!
//! A query by value writes its answer into the TagItem's ti_Data, a query
//! by reference into the LONG ti_Data points to. The SBTC_HAVE_* answers
//! say what rustsocket really has: an API whose calls are still stubs
//! answers FALSE, so Roadshow's tools report it as missing instead of
//! failing half way.

use core::ffi::c_void;

use amigaos4::sys::{self, Interface, TagItem};
use rsnet_core::settings::{Setting, SETTINGS};

use super::{opener, shared, stack, Opener};

const SBTF_REF: u32 = 0x8000;
const SBTF_SET: u32 = 1;

pub const SBTC_BREAKMASK: u32 = 1;
pub const SBTC_SIGIOMASK: u32 = 2;
pub const SBTC_SIGURGMASK: u32 = 3;
pub const SBTC_SIGEVENTMASK: u32 = 4;
pub const SBTC_ERRNO: u32 = 6;
pub const SBTC_HERRNO: u32 = 7;
pub const SBTC_DTABLESIZE: u32 = 8;
pub const SBTC_FDCALLBACK: u32 = 9;
pub const SBTC_LOGSTAT: u32 = 10;
pub const SBTC_LOGTAGPTR: u32 = 11;
pub const SBTC_LOGFACILITY: u32 = 12;
pub const SBTC_LOGMASK: u32 = 13;
pub const SBTC_ERRNOSTRPTR: u32 = 14;
pub const SBTC_HERRNOSTRPTR: u32 = 15;
pub const SBTC_IOERRNOSTRPTR: u32 = 16;
pub const SBTC_S2ERRNOSTRPTR: u32 = 17;
pub const SBTC_S2WERRNOSTRPTR: u32 = 18;
pub const SBTC_ERRNOBYTEPTR: u32 = 21;
pub const SBTC_ERRNOWORDPTR: u32 = 22;
pub const SBTC_ERRNOLONGPTR: u32 = 24;
pub const SBTC_HERRNOLONGPTR: u32 = 25;
pub const SBTC_RELEASESTRPTR: u32 = 29;
pub const SBTC_NUM_PACKET_FILTER_CHANNELS: u32 = 40;
pub const SBTC_HAVE_ROUTING_API: u32 = 41;
pub const SBTC_UDP_CHECKSUM: u32 = 42;
pub const SBTC_IP_FORWARDING: u32 = 43;
pub const SBTC_IP_DEFAULT_TTL: u32 = 44;
pub const SBTC_ICMP_MASK_REPLY: u32 = 45;
pub const SBTC_ICMP_SEND_REDIRECTS: u32 = 46;
pub const SBTC_HAVE_INTERFACE_API: u32 = 47;
pub const SBTC_ICMP_PROCESS_ECHO: u32 = 48;
pub const SBTC_ICMP_PROCESS_TSTAMP: u32 = 49;
pub const SBTC_HAVE_MONITORING_API: u32 = 50;
pub const SBTC_CAN_SHARE_LIBRARY_BASES: u32 = 51;
pub const SBTC_LOG_FILE_NAME: u32 = 52;
pub const SBTC_HAVE_STATUS_API: u32 = 53;
pub const SBTC_HAVE_DNS_API: u32 = 54;
pub const SBTC_LOG_HOOK: u32 = 55;
pub const SBTC_SYSTEM_STATUS: u32 = 56;
pub const SBTC_SIG_ADDRESS_CHANGE_MASK: u32 = 57;
pub const SBTC_IPF_API_VERSION: u32 = 58;
pub const SBTC_HAVE_LOCAL_DATABASE_API: u32 = 59;
pub const SBTC_HAVE_ADDRESS_CONVERSION_API: u32 = 60;
pub const SBTC_HAVE_KERNEL_MEMORY_API: u32 = 61;
pub const SBTC_IP_FILTER_HOOK: u32 = 62;
pub const SBTC_HAVE_SERVER_API: u32 = 63;
pub const SBTC_GET_BYTES_RECEIVED: u32 = 64;
pub const SBTC_GET_BYTES_SENT: u32 = 65;
pub const SBTC_IDN_DEFAULT_CHARACTER_SET: u32 = 66;
pub const SBTC_HAVE_ROADSHOWDATA_API: u32 = 67;
pub const SBTC_ERROR_HOOK: u32 = 68;
pub const SBTC_HAVE_GETHOSTADDR_R_API: u32 = 69;

const SBSYSSTAT_INTERFACES: u32 = 1 << 0;
const SBSYSSTAT_BCAST_INTERFACES: u32 = 1 << 2;
const SBSYSSTAT_RESOLVER: u32 = 1 << 3;
const SBSYSSTAT_ROUTES: u32 = 1 << 4;
const SBSYSSTAT_DEFAULT_ROUTE: u32 = 1 << 5;

/// IDNCS_ASCII and IDNCS_ISO_8859_LATIN_1.
const IDNCS_LATIN_1: u32 = 1;

/// LOG_USER (sys/syslog.h: facility 1, shifted by 3).
pub const LOG_USER: u32 = 1 << 3;

/// Roadshow's default descriptor table size.
pub const DTABLE_DEFAULT: u32 = 256;
/// The most a program may ask for.
pub const DTABLE_MAX: u32 = 4096;

/// ErrorHookMsg's actions.
const EHMA_SET_ERRNO: u32 = 1;
const EHMA_SET_H_ERRNO: u32 = 2;

extern "C" {
    fn rs_release_string() -> *const u8;
}

/// The answer to each SBTC_HAVE_* query.
fn have(code: u32) -> Option<u32> {
    Some(match code {
        SBTC_HAVE_INTERFACE_API | SBTC_HAVE_STATUS_API | SBTC_HAVE_LOCAL_DATABASE_API | SBTC_HAVE_ADDRESS_CONVERSION_API
        | SBTC_HAVE_GETHOSTADDR_R_API | SBTC_HAVE_ROUTING_API | SBTC_HAVE_DNS_API | SBTC_HAVE_ROADSHOWDATA_API
        | SBTC_HAVE_MONITORING_API | SBTC_HAVE_SERVER_API => 1,
        SBTC_HAVE_KERNEL_MEMORY_API => 1,
        _ => return None,
    })
}

fn setting(code: u32) -> Option<Setting> {
    Some(match code {
        SBTC_UDP_CHECKSUM => Setting::UdpChecksum,
        SBTC_IP_FORWARDING => Setting::IpForwarding,
        SBTC_IP_DEFAULT_TTL => Setting::IpDefaultTtl,
        SBTC_ICMP_MASK_REPLY => Setting::IcmpMaskReply,
        SBTC_ICMP_SEND_REDIRECTS => Setting::IcmpSendRedirects,
        SBTC_ICMP_PROCESS_ECHO => Setting::IcmpProcessEcho,
        SBTC_ICMP_PROCESS_TSTAMP => Setting::IcmpProcessTstamp,
        _ => return None,
    })
}

/// SBTC_SYSTEM_STATUS: what GetNetStatus reports.
fn system_status() -> u32 {
    let Some(all) = stack().and_then(|s| s.status()) else { return 0 };
    let mut st = 0;
    // "Network interfaces" does not take in the loopback interface (autodoc).
    for n in all.iter().filter(|n| n.present && !n.loopback) {
        if n.address.is_some() {
            // Every interface rustsocket runs is an Ethernet one.
            st |= SBSYSSTAT_INTERFACES | SBSYSSTAT_BCAST_INTERFACES | SBSYSSTAT_ROUTES;
        }


    }
    if stack().and_then(|s| s.name_servers()).map(|v| !v.is_empty()).unwrap_or(false) {
        st |= SBSYSSTAT_RESOLVER;
    }
    if let Some(r) = stack().and_then(|s| s.routes()) {
        if r.iter().any(|r| r.gateway.is_some()) {
            st |= SBSYSSTAT_ROUTES;
        }
        if r.iter().any(|r| r.prefix == 0) {
            st |= SBSYSSTAT_DEFAULT_ROUTE;
        }
    }
    st
}

/// The bytes every interface received (`rx`) or sent.
fn bytes(rx: bool) -> u64 {
    stack()
        .and_then(|s| s.status())
        .map(|v| v.iter().map(|n| if rx { n.link.rx_bytes } else { n.link.tx_bytes }).sum())
        .unwrap_or(0)
}

/// What one tag did.
enum Done {
    Ok,
    /// Not done: the call stops at this tag.
    Fail,
}

/// SocketBaseTagList(tags): 0, or the 1-based index of the tag that
/// failed.
#[no_mangle]
pub extern "C" fn rs_SocketBaseTagList(i: *mut Interface, tags: *mut TagItem) -> i32 {
    let Some(o) = opener(i) else { return 1 };
    let mut t = tags;
    let mut n = 0i32;
    loop {
        n += 1;
        // SAFETY: the caller's TAG_DONE-ended list; TAG_MORE/IGNORE/SKIP
        // follow utility.library's rules.
        let (tag, data) = unsafe { ((*t).ti_Tag, (*t).ti_Data) };
        match tag {
            sys::TAG_DONE => return 0,
            sys::TAG_IGNORE => {
                // SAFETY: as above.
                t = unsafe { t.add(1) };
                continue;
            }
            sys::TAG_MORE => {
                t = data as *mut TagItem;
                if t.is_null() {
                    return 0;
                }
                continue;
            }
            sys::TAG_SKIP => {
                // SAFETY: as above.
                t = unsafe { t.add(1 + data as usize) };
                continue;
            }
            _ => {}
        }
        if tag & sys::TAG_USER == 0 {
            return n;
        }
        let code = (tag >> 1) & 0x3FFF;
        let set = tag & SBTF_SET != 0;
        let by_ref = tag & SBTF_REF != 0;
        if by_ref && data == 0 {
            return n;
        }
        if let Done::Fail = one(o, t, code, set, by_ref, data) {
            amigaos4::serial_println!("rustsocket.library: SocketBaseTagList code {} ({}) refused", code, if set { "set" } else { "get" });
            return n;
        }
        // SAFETY: as above.
        t = unsafe { t.add(1) };
    }
}

fn one(o: &mut Opener, t: *mut TagItem, code: u32, set: bool, by_ref: bool, data: u32) -> Done {
    // SAFETY: a by-reference tag's data is the address of a LONG (checked
    // non-NULL by the caller); a by-value one is ti_Data itself.
    let value = || if by_ref { unsafe { *(data as *const u32) } } else { data };
    let put = |v: u32| {
        if by_ref {
            // SAFETY: as above.
            unsafe { *(data as *mut u32) = v };
        } else {
            // SAFETY: the caller's tag, which a by-value query updates in
            // place (bsdsocket.h: "Modify either Tag->ti_Data ...").
            unsafe { (*t).ti_Data = v };
        }
    };
    // Either side of a plain per-opener value.
    let rw = |f: &mut u32| {
        if set {
            *f = value();
        } else {
            put(*f);
        }
        Done::Ok
    };
    match code {
        SBTC_BREAKMASK => rw(&mut o.break_mask),
        SBTC_SIGIOMASK => rw(&mut o.sigio_mask),
        SBTC_SIGURGMASK => rw(&mut o.sigurg_mask),
        SBTC_SIGEVENTMASK => rw(&mut o.sigevent_mask),
        SBTC_SIG_ADDRESS_CHANGE_MASK => {
            if set {
                o.sig_addr_mask = value();
                // The stack signals the calling task on every address change.
                if let Some(s) = stack() {
                    s.watch_addresses(o as *const Opener as u32, amigaos4::signal::current_task() as usize, o.sig_addr_mask);
                }
            } else {
                put(o.sig_addr_mask);
            }
            Done::Ok
        }
        SBTC_LOGSTAT => rw(&mut o.log_stat),
        SBTC_LOGTAGPTR => rw(&mut o.log_tag),
        SBTC_LOGFACILITY => rw(&mut o.log_facility),
        SBTC_LOGMASK => rw(&mut o.log_mask),
        SBTC_FDCALLBACK => rw(&mut o.fd_callback),
        SBTC_ERROR_HOOK => rw(&mut o.error_hook),
        SBTC_CAN_SHARE_LIBRARY_BASES => rw(&mut o.share_base),
        SBTC_IDN_DEFAULT_CHARACTER_SET => {
            if set {
                // An unknown set behaves as ASCII (autodoc).
                o.idn = if value() == IDNCS_LATIN_1 { IDNCS_LATIN_1 } else { 0 };
            } else {
                put(o.idn);
            }
            Done::Ok
        }
        SBTC_ERRNO => {
            if set {
                o.set_errno(value() as i32);
            } else {
                put(o.errno as u32);
            }
            Done::Ok
        }
        SBTC_HERRNO => {
            if set {
                o.set_herrno(value() as i32);
            } else {
                put(o.herrno as u32);
            }
            Done::Ok
        }
        SBTC_ERRNOBYTEPTR | SBTC_ERRNOWORDPTR | SBTC_ERRNOLONGPTR if set => {
            o.errno_ptr = value() as *mut u8;
            o.errno_size = match code {
                SBTC_ERRNOBYTEPTR => 1,
                SBTC_ERRNOWORDPTR => 2,
                _ => 4,
            };
            Done::Ok
        }
        SBTC_HERRNOLONGPTR if set => {
            o.herrno_ptr = value() as *mut i32;
            Done::Ok
        }
        SBTC_DTABLESIZE => {
            if set {
                let want = value();
                // It may grow, never below the descriptors in use.
                if want == 0 || want > DTABLE_MAX || (want as usize) < o.fds().len() {
                    return Done::Fail;
                }
                o.dtable = want;
            } else {
                put(o.dtable);
            }
            Done::Ok
        }
        SBTC_ERRNOSTRPTR | SBTC_HERRNOSTRPTR | SBTC_IOERRNOSTRPTR | SBTC_S2ERRNOSTRPTR | SBTC_S2WERRNOSTRPTR if !set => {
            let c = value() as i32;
            let s = match code {
                SBTC_ERRNOSTRPTR => errno_str(c),
                SBTC_HERRNOSTRPTR => herrno_str(c),
                SBTC_IOERRNOSTRPTR => ioerr_str(c),
                SBTC_S2ERRNOSTRPTR => s2err_str(c),
                _ => s2werr_str(c),
            };
            put(s.as_ptr() as u32);
            Done::Ok
        }
        SBTC_RELEASESTRPTR if !set => {
            // SAFETY: the glue's static string.
            put(unsafe { rs_release_string() } as u32);
            Done::Ok
        }
        SBTC_SYSTEM_STATUS if !set => {
            put(system_status());
            Done::Ok
        }
        SBTC_GET_BYTES_RECEIVED | SBTC_GET_BYTES_SENT if !set && by_ref => {
            let b = bytes(code == SBTC_GET_BYTES_RECEIVED);
            // SAFETY: an SBQUAD_T { sbq_High, sbq_Low } by reference
            // (autodoc: "must be passed by reference").
            unsafe {
                *(data as *mut u32) = (b >> 32) as u32;
                *(data as *mut u32).add(1) = b as u32;
            }
            Done::Ok
        }
        SBTC_NUM_PACKET_FILTER_CHANNELS if !set => {
            put(rsnet_core::bpf::CHANNELS as u32);
            Done::Ok
        }
        SBTC_LOG_FILE_NAME => {
            let Some(mut sh) = shared::lock() else { return Done::Fail };
            if set {
                let p = value() as *const u8;
                sh.log_file.clear();
                if !p.is_null() {
                    // SAFETY: the caller's NUL-terminated name; copied, at
                    // most 510 characters (autodoc).
                    let s = unsafe { core::ffi::CStr::from_ptr(p as *const core::ffi::c_char) }.to_bytes();
                    sh.log_file.extend_from_slice(&s[..s.len().min(510)]);
                }
                sh.log_file.push(0);
            } else {
                if sh.log_file.last() != Some(&0) {
                    sh.log_file.push(0);
                }
                put(sh.log_file.as_ptr() as u32);
            }
            Done::Ok
        }
        SBTC_LOG_HOOK => {
            let Some(mut sh) = shared::lock() else { return Done::Fail };
            if set {
                sh.log_hook = value();
            } else {
                put(sh.log_hook);
            }
            Done::Ok
        }
        _ => {
            if let Some(v) = have(code) {
                if set {
                    return Done::Fail;
                }
                put(v);
                return Done::Ok;
            }
            if let Some(s) = setting(code) {
                if set {
                    return if SETTINGS.set(s, value()) { Done::Ok } else { Done::Fail };
                }
                put(SETTINGS.get(s));
                return Done::Ok;
            }
            match code {
                // The IP filter hook (rsnet-core ipf.rs).
                SBTC_IPF_API_VERSION if !set => {
                    put(rsnet_core::ipf::API_VERSION);
                    Done::Ok
                }
                SBTC_IP_FILTER_HOOK => {
                    if set {
                        rsnet_core::ipf::set_hook(value());
                    } else {
                        put(rsnet_core::ipf::hook());
                    }
                    Done::Ok
                }
                _ => Done::Fail,
            }
        }
    }
}

/// Call an opener's SBTC_ERROR_HOOK for a new errno or h_errno.
pub fn error_hook(hook: u32, herrno: bool, code: i32) {
    if hook == 0 {
        return;
    }
    let mut msg = [12u32, if herrno { EHMA_SET_H_ERRNO } else { EHMA_SET_ERRNO }, code as u32];
    // SAFETY: the Hook the opener installed (it keeps it valid while
    // installed); the message is the documented 12-byte ErrorHookMsg.
    unsafe { sys::utility_call_hook_pkt(hook as *mut sys::Hook, core::ptr::null_mut(), msg.as_mut_ptr() as *mut c_void) };
}

/// Hand a log message to the SBTC_LOG_HOOK, if one is installed: true
/// when it took it.
pub fn log_hook(priority: i32, tag: *const u8, text: &[u8]) -> bool {
    let hook = shared::lock().map(|s| s.log_hook).unwrap_or(0);
    if hook == 0 {
        return false;
    }
    let mut line = alloc::vec::Vec::with_capacity(text.len() + 1);
    line.extend_from_slice(text);
    line.push(0);
    let mut ds = sys::DateStamp::default();
    // SAFETY: DateStamp fills the structure.
    unsafe { sys::dos_date_stamp(&mut ds) };
    // struct LogHookMessage: lhm_Size, lhm_Priority, lhm_Date (3 LONGs),
    // lhm_Tag, lhm_ID, lhm_Message.
    let mut m = [0u32, priority as u32, ds.ds_Days as u32, ds.ds_Minute as u32, ds.ds_Tick as u32, tag as u32, 0, line.as_ptr() as u32];
    m[0] = core::mem::size_of_val(&m) as u32;
    // SAFETY: the hook installed with SBTC_LOG_HOOK; the message and the
    // text live until it returns (read-only to it).
    unsafe { sys::utility_call_hook_pkt(hook as *mut sys::Hook, core::ptr::null_mut(), m.as_mut_ptr() as *mut c_void) };
    true
}

/// strerror for the stack's errno values (netinclude/sys/errno.h).
/// The errno strings, as Roadshow's library gives them (testprogs/rstcp/c/
/// errstr.c dumps both): BSD's, but "No error", "Object not
/// found", "Object exists", "Cannot" for "Can't", "RPC program not avail",
/// and "Unknown error: <n>" past 79.
pub fn errno_str(e: i32) -> &'static [u8] {
    match e {
        0 => b"No error\0",
        1 => b"Operation not permitted\0",
        2 => b"Object not found\0",
        3 => b"No such process\0",
        4 => b"Interrupted system call\0",
        5 => b"Input/output error\0",
        6 => b"Device not configured\0",
        7 => b"Argument list too long\0",
        8 => b"Exec format error\0",
        9 => b"Bad file descriptor\0",
        10 => b"No child processes\0",
        11 => b"Resource deadlock avoided\0",
        12 => b"Cannot allocate memory\0",
        13 => b"Permission denied\0",
        14 => b"Bad address\0",
        15 => b"Block device required\0",
        16 => b"Device busy\0",
        17 => b"Object exists\0",
        18 => b"Cross-device link\0",
        19 => b"Operation not supported by device\0",
        20 => b"Not a directory\0",
        21 => b"Is a directory\0",
        22 => b"Invalid argument\0",
        23 => b"Too many open files in system\0",
        24 => b"Too many open files\0",
        25 => b"Inappropriate ioctl for device\0",
        26 => b"Text file busy\0",
        27 => b"File too large\0",
        28 => b"No space left on device\0",
        29 => b"Illegal seek\0",
        30 => b"Read-only file system\0",
        31 => b"Too many links\0",
        32 => b"Broken pipe\0",
        33 => b"Numerical argument out of domain\0",
        34 => b"Result too large\0",
        35 => b"Resource temporarily unavailable\0",
        36 => b"Operation now in progress\0",
        37 => b"Operation already in progress\0",
        38 => b"Socket operation on non-socket\0",
        39 => b"Destination address required\0",
        40 => b"Message too long\0",
        41 => b"Protocol wrong type for socket\0",
        42 => b"Protocol not available\0",
        43 => b"Protocol not supported\0",
        44 => b"Socket type not supported\0",
        45 => b"Operation not supported\0",
        46 => b"Protocol family not supported\0",
        47 => b"Address family not supported by protocol family\0",
        48 => b"Address already in use\0",
        49 => b"Cannot assign requested address\0",
        50 => b"Network is down\0",
        51 => b"Network is unreachable\0",
        52 => b"Network dropped connection on reset\0",
        53 => b"Software caused connection abort\0",
        54 => b"Connection reset by peer\0",
        55 => b"No buffer space available\0",
        56 => b"Socket is already connected\0",
        57 => b"Socket is not connected\0",
        58 => b"Cannot send after socket shutdown\0",
        59 => b"Too many references: cannot splice\0",
        60 => b"Operation timed out\0",
        61 => b"Connection refused\0",
        62 => b"Too many levels of symbolic links\0",
        63 => b"File name too long\0",
        64 => b"Host is down\0",
        65 => b"No route to host\0",
        66 => b"Directory not empty\0",
        67 => b"Too many processes\0",
        68 => b"Too many users\0",
        69 => b"Disc quota exceeded\0",
        70 => b"Stale NFS file handle\0",
        71 => b"Too many levels of remote in path\0",
        72 => b"RPC struct is bad\0",
        73 => b"RPC version wrong\0",
        74 => b"RPC program not avail\0",
        75 => b"Program version wrong\0",
        76 => b"Bad procedure for program\0",
        77 => b"No locks available\0",
        78 => b"Function not implemented\0",
        79 => b"Inappropriate file type or format\0",
        _ => unknown("Unknown error: ", e),
    }
}

/// `prefix` and the number (NUL-terminated), in one of a few buffers used
/// in turn: the string stays valid until that many more have been asked
/// for. Roadshow names the number in its "unknown" texts.
fn unknown(prefix: &str, e: i32) -> &'static [u8] {
    use core::sync::atomic::{AtomicUsize, Ordering};
    const N: usize = 16;
    static mut BUFS: [[u8; 48]; N] = [[0; 48]; N];
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let k = NEXT.fetch_add(1, Ordering::Relaxed) % N;
    let text = alloc::format!("{}{}\0", prefix, e);
    // SAFETY: buffer k is handed to one caller at a time (the index
    // rotates); its 48 bytes hold the longest such text (39 with the NUL).
    unsafe {
        let b = &mut *core::ptr::addr_of_mut!(BUFS[k]);
        b[..text.len()].copy_from_slice(text.as_bytes());
        &b[..text.len()]
    }
}

/// The resolver's h_errno values (netinclude/netdb.h).
pub fn herrno_str(e: i32) -> &'static [u8] {
    match e {
        0 => b"No error\0",
        1 => b"Unknown host\0",
        2 => b"Host name lookup failure\0",
        3 => b"Unknown server error\0",
        4 => b"No address associated with name\0",
        _ => b"Unknown resolver error\0",
    }
}

/// exec's IOERR_* values (exec/errors.h).
fn ioerr_str(e: i32) -> &'static [u8] {
    // Roadshow numbers these as positive values (1 = IOERR_OPENFAIL).
    match e {
        0 => b"No error\0",
        1 => b"Device/unit failed to open\0",
        2 => b"Request terminated early\0",
        3 => b"Command not supported by device\0",
        4 => b"Not a valid length\0",
        5 => b"Invalid address\0",
        6 => b"Device opens OK, but requested unit is busy\0",
        7 => b"Hardware failed self-test\0",
        _ => unknown("Unknown I/O error ", e),
    }
}

/// SANA-II S2ERR_* values (devices/sana2.h), in Roadshow's words.
fn s2err_str(e: i32) -> &'static [u8] {
    match e {
        0 => b"No error\0",
        1 => b"Resource allocation failure\0",
        3 => b"Bad argument\0",
        4 => b"Inappropriate state\0",
        5 => b"Bad address\0",
        6 => b"Maximum transmission unit exceeded\0",
        8 => b"Command not supported by hardware\0",
        9 => b"Software error detected\0",
        10 => b"Driver is offline\0",
        11 => b"Transmission attempt failed\0",
        _ => unknown("Unknown SANA-II error ", e),
    }
}

/// SANA-II S2WERR_* values (devices/sana2.h), in Roadshow's words (its
/// 12 ends in a tab).
fn s2werr_str(e: i32) -> &'static [u8] {
    match e {
        0 => b"No specific information available\0",
        1 => b"Unit not configured\0",
        2 => b"Unit is currently online\0",
        3 => b"Unit is currently offline\0",
        4 => b"Protocol already tracked\0",
        5 => b"Protocol not tracked\0",
        6 => b"Buffer management function returned error\0",
        7 => b"Source address problem\0",
        8 => b"Destination address problem\0",
        9 => b"Broadcast address problem\0",
        10 => b"Multicast address problem\0",
        11 => b"Multicast address list is full\0",
        12 => b"Unsupported event class\t\0",
        13 => b"StatData failed sanity check\0",
        15 => b"Attempt to configure twice\0",
        16 => b"NULL pointer detected\0",
        17 => b"Transmission failed - too many retries\0",
        18 => b"Driver fixable hardware error\0",
        19 => b"Unit currently not connected\0",
        20 => b"Unit currently connected\0",
        21 => b"Invalid option rejected\0",
        22 => b"Mandatory option missing\0",
        23 => b"Could not log in\0",
        _ => unknown("Unknown SANA-II wire error ", e),
    }
}
