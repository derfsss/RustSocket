//! Small calls of the socket interface: gethostid, In_LocalAddr,
//! In_CanForward, the default domain name, syslog.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_void, CStr};

use amigaos4::sys::Interface;

use super::{opener, shared, stack};

/// The interfaces' (address, prefix length) pairs, configured ones only;
/// 127.0.0.1/8 (lo0) last.
fn addresses() -> Vec<([u8; 4], u8)> {
    let mut v: Vec<([u8; 4], u8)> =
        stack().and_then(|s| s.status()).map(|st| st.iter().filter(|x| x.present && !x.loopback).filter_map(|x| x.address).collect()).unwrap_or_default();
    v.push(([127, 0, 0, 1], 8));
    v
}

/// gethostid(): the first interface's address (0 before DHCP).
#[no_mangle]
pub extern "C" fn rs_gethostid(_i: *mut Interface) -> u32 {
    addresses().first().filter(|(a, _)| a[0] != 127).map(|(a, _)| u32::from_be_bytes(*a)).unwrap_or(0)
}

/// In_LocalAddr(address): TRUE when `address` is on one of the interfaces'
/// networks.
#[no_mangle]
pub extern "C" fn rs_In_LocalAddr(_i: *mut Interface, address: u32) -> i32 {
    addresses().iter().any(|&(a, p)| {
        let mask = if p == 0 { 0 } else { u32::MAX << (32 - p as u32) };
        u32::from_be_bytes(a) & mask == address & mask
    }) as i32
}

/// In_CanForward(address): 4.4BSD's in_canforward, by the address alone
/// (not ip.forwarding), as Roadshow answers (testprogs/rstcp/c/canfwd.c):
/// FALSE for multicast and class E (224 and up), class A
/// network 0 and the loopback network; TRUE for the rest.
#[no_mangle]
pub extern "C" fn rs_In_CanForward(_i: *mut Interface, address: u32) -> i32 {
    let top = (address >> 24) as u8;
    (top < 224 && top != 0 && top != 127) as i32
}

/// GetDefaultDomainName(buffer, size): TRUE and the name (NUL-terminated,
/// cut to fit), FALSE when none is set.
#[no_mangle]
pub extern "C" fn rs_GetDefaultDomainName(_i: *mut Interface, buffer: *mut u8, size: i32) -> i32 {
    let Some(sh) = shared::lock() else { return 0 };
    if sh.domain.is_empty() || buffer.is_null() || size <= 0 {
        return 0;
    }
    let b = sh.domain.as_bytes();
    let n = b.len().min(size as usize - 1);
    // SAFETY: the caller's buffer of `size` bytes; n + 1 <= size.
    unsafe {
        core::ptr::copy_nonoverlapping(b.as_ptr(), buffer, n);
        *buffer.add(n) = 0;
    }
    1
}

/// SetDefaultDomainName(name): NULL or "" clears it.
#[no_mangle]
pub extern "C" fn rs_SetDefaultDomainName(_i: *mut Interface, name: *const u8) {
    let Some(mut sh) = shared::lock() else { return };
    sh.domain = if name.is_null() {
        String::new()
    } else {
        // SAFETY: the caller's NUL-terminated name.
        String::from_utf8_lossy(unsafe { CStr::from_ptr(name as *const core::ffi::c_char) }.to_bytes()).into_owned()
    };
}

/// One 32-bit argument of a linear varargs array.
///
/// # Safety
/// `args` holds at least `k + 1` words.
unsafe fn arg(args: *const u32, k: usize) -> u32 {
    // SAFETY: the caller's guarantee.
    unsafe { core::ptr::read_unaligned(args.add(k)) }
}

/// C printf on `format` with linear 32-bit `args`: %d %i %u %x %X %o %c %s
/// %p %%, the l and h length letters, flags "-0 +#", a width and a
/// precision (numbers or *). %m is the opener's errno. Floating point is
/// not formatted (its words are skipped).
fn format(format: &[u8], args: *const u32, errno: i32) -> String {
    let mut out = String::new();
    let mut k = 0usize;
    let mut i = 0;
    let next = |k: &mut usize| -> u32 {
        if args.is_null() {
            return 0;
        }
        // SAFETY: syslog's caller passes one argument per conversion.
        let v = unsafe { arg(args, *k) };
        *k += 1;
        v
    };
    while i < format.len() {
        let c = format[i];
        i += 1;
        if c != b'%' {
            out.push(c as char);
            continue;
        }
        let (mut left, mut zero) = (false, false);
        while i < format.len() && b"-0 +#".contains(&format[i]) {
            match format[i] {
                b'-' => left = true,
                b'0' => zero = true,
                _ => {}
            }
            i += 1;
        }
        let mut width = 0usize;
        if i < format.len() && format[i] == b'*' {
            width = next(&mut k) as i32 as usize;
            i += 1;
        }
        while i < format.len() && format[i].is_ascii_digit() {
            width = width * 10 + (format[i] - b'0') as usize;
            i += 1;
        }
        let mut prec: Option<usize> = None;
        if i < format.len() && format[i] == b'.' {
            i += 1;
            let mut p = 0usize;
            if i < format.len() && format[i] == b'*' {
                p = next(&mut k) as usize;
                i += 1;
            }
            while i < format.len() && format[i].is_ascii_digit() {
                p = p * 10 + (format[i] - b'0') as usize;
                i += 1;
            }
            prec = Some(p);
        }
        while i < format.len() && b"lhzt".contains(&format[i]) {
            i += 1;
        }
        let Some(&conv) = format.get(i) else { break };
        i += 1;
        let text: String = match conv {
            b'%' => String::from("%"),
            b'd' | b'i' => alloc::format!("{}", next(&mut k) as i32),
            b'u' => alloc::format!("{}", next(&mut k)),
            b'x' => alloc::format!("{:x}", next(&mut k)),
            b'X' => alloc::format!("{:X}", next(&mut k)),
            b'o' => alloc::format!("{:o}", next(&mut k)),
            b'p' => alloc::format!("0x{:08x}", next(&mut k)),
            b'c' => String::from((next(&mut k) as u8) as char),
            b's' => {
                let p = next(&mut k) as usize as *const core::ffi::c_char;
                if p.is_null() {
                    String::from("(null)")
                } else {
                    // SAFETY: a %s argument is a NUL-terminated string.
                    let b = unsafe { CStr::from_ptr(p) }.to_bytes();
                    let b = &b[..prec.map_or(b.len(), |p| p.min(b.len()))];
                    String::from_utf8_lossy(b).into_owned()
                }
            }
            b'm' => alloc::format!("errno {}", errno),
            b'e' | b'f' | b'g' | b'E' | b'G' => {
                next(&mut k);
                next(&mut k);
                String::from("?")
            }
            _ => String::new(),
        };
        let pad = width.saturating_sub(text.chars().count());
        if left {
            out.push_str(&text);
            out.extend(core::iter::repeat_n(' ', pad));
        } else {
            let fill = if zero && conv != b's' { '0' } else { ' ' };
            out.extend(core::iter::repeat_n(fill, pad));
            out.push_str(&text);
        }
    }
    out
}

/// AddNetMonitorHookTagList(type, hook, tags): 0, or -1 (EINVAL: a type
/// not known, EFAULT: no hook, ENOMEM: the table is full).
#[no_mangle]
pub extern "C" fn rs_AddNetMonitorHookTagList(i: *mut Interface, kind: i32, hook: *mut c_void, _tags: *const c_void) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    if !(0..=6).contains(&kind) {
        return o.fail(22);
    }
    if hook.is_null() {
        return o.fail(14);
    }
    if rsnet_core::monitor::add(kind as u32, hook as u32) { 0 } else { o.fail(12) }
}

/// RemoveNetMonitorHook(hook).
#[no_mangle]
pub extern "C" fn rs_RemoveNetMonitorHook(_i: *mut Interface, hook: *mut c_void) {
    if !hook.is_null() {
        rsnet_core::monitor::remove(hook as u32);
    }
}

/// vsyslog(level, format, args): the message goes to the serial log, with
/// its level (LOG_EMERG 0 .. LOG_DEBUG 7) and the opener's task name.
#[no_mangle]
pub extern "C" fn rs_vsyslog(i: *mut Interface, level: i32, fmt: *const u8, args: *const u32) {
    if fmt.is_null() {
        return;
    }
    let Some(o) = opener(i) else { return };
    let pri = level & 7;
    // SBTC_LOGMASK: LOG_MASK(pri) = 1 << pri.
    if o.log_mask & (1 << pri) == 0 {
        return;
    }
    // SAFETY: the caller's NUL-terminated format.
    let f = unsafe { CStr::from_ptr(fmt as *const core::ffi::c_char) }.to_bytes();
    let text = format(f, args, o.errno);
    let text = text.trim_end();
    let tag = o.log_tag as *const u8;
    if super::basetags::log_hook(pri, tag, text.as_bytes()) {
        return;
    }
    let who = if tag.is_null() {
        super::task_name()
    } else {
        // SAFETY: SBTC_LOGTAGPTR: the opener's NUL-terminated tag.
        unsafe { CStr::from_ptr(tag as *const core::ffi::c_char) }.to_str().unwrap_or("?")
    };
    amigaos4::serial_println!("syslog <{}> {}: {}", pri, who, text);
}
