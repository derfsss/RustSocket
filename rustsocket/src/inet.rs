//! The address helpers of the socket interface: text <-> IPv4 address and
//! the old class A/B/C splits. Addresses are u32 in network order, which on
//! this big-endian CPU is the plain value (10.0.4.2 = 0x0A000402).

use core::ffi::CStr;

use amigaos4::sys::Interface;

use super::{opener, Opener};

const INADDR_NONE: u32 = 0xffff_ffff;
const AF_INET: i32 = 2;

/// One part of a dotted address, C style: 0x.. hex, 0.. octal, else
/// decimal. The value and the rest of the text.
fn part(s: &[u8]) -> Option<(u32, &[u8])> {
    let (radix, mut i) = match s {
        [b'0', b'x' | b'X', ..] => (16, 2),
        [b'0', _, ..] => (8, 1),
        _ => (10, 0),
    };
    let start = i;
    let mut v: u64 = 0;
    while i < s.len() {
        let d = match s[i] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' => (c - b'a' + 10) as u64,
            c @ b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => break,
        };
        if d >= radix {
            return None;
        }
        v = v * radix + d;
        if v > u32::MAX as u64 {
            return None;
        }
        i += 1;
    }
    // "0" alone (octal with no digits after it) is 0; "0x" alone is not.
    if i == start && !(radix == 8 && start == 1) {
        return None;
    }
    Some((v as u32, &s[i..]))
}

/// inet_aton's parse: a, a.b, a.b.c or a.b.c.d (the last part fills the
/// rest of the address).
pub fn parse(text: &[u8]) -> Option<u32> {
    let mut parts = [0u32; 4];
    let mut n = 0;
    let mut s = text;
    loop {
        let (v, rest) = part(s)?;
        parts[n] = v;
        n += 1;
        match rest {
            [] => break,
            [b'.', more @ ..] if n < 4 => s = more,
            [c, ..] if c.is_ascii_whitespace() => break,
            _ => return None,
        }
    }
    let [a, b, c, d] = parts;
    match n {
        1 => Some(a),
        2 if a <= 0xff && b <= 0xff_ffff => Some(a << 24 | b),
        3 if a <= 0xff && b <= 0xff && c <= 0xffff => Some(a << 24 | b << 16 | c),
        4 if a <= 0xff && b <= 0xff && c <= 0xff && d <= 0xff => Some(a << 24 | b << 16 | c << 8 | d),
        _ => None,
    }
}

/// a.b.c.d into `out` (16 bytes), NUL-terminated; its length.
pub fn format(ip: u32, out: &mut [u8; 16]) -> usize {
    let mut n = 0;
    for (k, b) in ip.to_be_bytes().iter().enumerate() {
        if k > 0 {
            out[n] = b'.';
            n += 1;
        }
        let mut v = *b;
        let mut digits = [0u8; 3];
        let mut m = 0;
        loop {
            digits[m] = b'0' + v % 10;
            m += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while m > 0 {
            m -= 1;
            out[n] = digits[m];
            n += 1;
        }
    }
    out[n] = 0;
    n
}

/// The bytes of a C string, or None for NULL.
fn text<'a>(p: *const u8) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller's NUL-terminated string.
    Some(unsafe { CStr::from_ptr(p as *const core::ffi::c_char) }.to_bytes())
}

/// Class A/B/C: the network part's mask.
fn class_mask(ip: u32) -> u32 {
    if ip & 0x8000_0000 == 0 {
        0xff00_0000
    } else if ip & 0xc000_0000 == 0x8000_0000 {
        0xffff_0000
    } else {
        0xffff_ff00
    }
}

/// Inet_NtoA(in): the address as text, in the opener's buffer (valid until
/// its next call).
#[no_mangle]
pub extern "C" fn rs_Inet_NtoA(i: *mut Interface, ip: u32) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Opener { ntoa, .. } = o;
    format(ip, ntoa);
    ntoa.as_mut_ptr()
}

/// inet_addr(cp): the address, or INADDR_NONE.
#[no_mangle]
pub extern "C" fn rs_inet_addr(_i: *mut Interface, cp: *const u8) -> u32 {
    text(cp).and_then(parse).unwrap_or(INADDR_NONE)
}

/// inet_aton(cp, addr): 1 and *addr set, or 0.
#[no_mangle]
pub extern "C" fn rs_inet_aton(_i: *mut Interface, cp: *const u8, addr: *mut u32) -> i32 {
    match text(cp).and_then(parse) {
        Some(v) => {
            if !addr.is_null() {
                // SAFETY: the caller's struct in_addr.
                unsafe { core::ptr::write_unaligned(addr, v) };
            }
            1
        }
        None => 0,
    }
}

/// inet_network(cp): as inet_addr (the parts right-aligned the same way).
#[no_mangle]
pub extern "C" fn rs_inet_network(_i: *mut Interface, cp: *const u8) -> u32 {
    text(cp).and_then(parse).unwrap_or(INADDR_NONE)
}

/// Inet_LnaOf(in): the host part, by class.
#[no_mangle]
pub extern "C" fn rs_Inet_LnaOf(_i: *mut Interface, ip: u32) -> u32 {
    ip & !class_mask(ip)
}

/// Inet_NetOf(in): the network part, by class, shifted down.
#[no_mangle]
pub extern "C" fn rs_Inet_NetOf(_i: *mut Interface, ip: u32) -> u32 {
    let m = class_mask(ip);
    (ip & m) >> m.trailing_zeros()
}

/// Inet_MakeAddr(net, host): the address of `host` on network `net`.
#[no_mangle]
pub extern "C" fn rs_Inet_MakeAddr(_i: *mut Interface, net: u32, host: u32) -> u32 {
    if net < 128 {
        net << 24 | host & 0x00ff_ffff
    } else if net < 65536 {
        net << 16 | host & 0xffff
    } else if net < 16_777_216 {
        net << 8 | host & 0xff
    } else {
        net | host
    }
}

/// inet_ntop(af, src, dst, size): AF_INET only; dst, or NULL (errno
/// EAFNOSUPPORT, or ENOSPC when it does not fit).
#[no_mangle]
pub extern "C" fn rs_inet_ntop(i: *mut Interface, af: i32, src: *const u8, dst: *mut u8, size: i32) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    if af != AF_INET {
        o.fail(super::errno::EAFNOSUPPORT);
        return core::ptr::null_mut();
    }
    if src.is_null() || dst.is_null() {
        o.fail(super::errno::EINVAL);
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's 4-byte struct in_addr.
    let ip = unsafe { core::ptr::read_unaligned(src as *const u32) };
    let mut buf = [0u8; 16];
    let n = format(ip, &mut buf);
    if size < 0 || n + 1 > size as usize {
        o.fail(28); // ENOSPC
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's buffer of `size` bytes; n + 1 <= size.
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, n + 1) };
    dst
}

/// inet_pton(af, src, dst): AF_INET only, dotted quad only: 1, 0 when the
/// text is not one, -1 (EAFNOSUPPORT) for another family.
#[no_mangle]
pub extern "C" fn rs_inet_pton(i: *mut Interface, af: i32, src: *const u8, dst: *mut u8) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    if af != AF_INET {
        return o.fail(super::errno::EAFNOSUPPORT);
    }
    let Some(t) = text(src) else { return 0 };
    // inet_pton takes exactly four decimal parts.
    let quad = t.split(|&c| c == b'.').count() == 4
        && t.split(|&c| c == b'.').all(|p| !p.is_empty() && p.len() <= 3 && p.iter().all(u8::is_ascii_digit) && (p.len() == 1 || p[0] != b'0'));
    match parse(t) {
        Some(v) if quad && !dst.is_null() => {
            // SAFETY: the caller's 4-byte struct in_addr.
            unsafe { core::ptr::write_unaligned(dst as *mut u32, v) };
            1
        }
        _ => 0,
    }
}
