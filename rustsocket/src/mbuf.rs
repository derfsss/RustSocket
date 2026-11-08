//! The kernel memory calls (mbuf_*), for IP filter hooks: BSD 4.4's m_*
//! routines on rsnet-core's mbufs (mbuf.rs there).

use core::ffi::c_void;

use amigaos4::sys::Interface;
use rsnet_core::mbuf as m;

fn ptr(v: Option<m::M>) -> *mut c_void {
    v.unwrap_or(0) as *mut c_void
}

/// mbuf_get(): an mbuf.
#[no_mangle]
pub extern "C" fn rs_mbuf_get(_i: *mut Interface) -> *mut c_void {
    ptr(m::get(false))
}

/// mbuf_gethdr(): an mbuf with a packet header.
#[no_mangle]
pub extern "C" fn rs_mbuf_gethdr(_i: *mut Interface) -> *mut c_void {
    ptr(m::get(true))
}

/// mbuf_free(mbuf): the next mbuf of its chain.
#[no_mangle]
pub extern "C" fn rs_mbuf_free(_i: *mut Interface, b: *mut c_void) -> *mut c_void {
    m::free(b as m::M) as *mut c_void
}

/// mbuf_freem(chain).
#[no_mangle]
pub extern "C" fn rs_mbuf_freem(_i: *mut Interface, b: *mut c_void) {
    m::freem(b as m::M);
}

/// mbuf_copym(chain, offset, length): a copy, or NULL.
#[no_mangle]
pub extern "C" fn rs_mbuf_copym(_i: *mut Interface, b: *mut c_void, off: i32, len: i32) -> *mut c_void {
    if b.is_null() || off < 0 || len < 0 {
        return core::ptr::null_mut();
    }
    ptr(m::copym(b as m::M, off as usize, len))
}

/// mbuf_copydata(chain, offset, length, out): 0, or -1 when the chain is
/// shorter.
#[no_mangle]
pub extern "C" fn rs_mbuf_copydata(_i: *mut Interface, b: *mut c_void, off: i32, len: i32, out: *mut u8) -> i32 {
    if b.is_null() || out.is_null() || off < 0 || len < 0 {
        return -1;
    }
    if m::copydata(b as m::M, off as usize, len as usize, out) { 0 } else { -1 }
}

/// mbuf_copyback(chain, offset, length, data): 0, or -1 (no memory).
#[no_mangle]
pub extern "C" fn rs_mbuf_copyback(_i: *mut Interface, b: *mut c_void, off: i32, len: i32, data: *const u8) -> i32 {
    if b.is_null() || data.is_null() || off < 0 || len < 0 {
        return -1;
    }
    if m::copyback(b as m::M, off as usize, len as usize, data) { 0 } else { -1 }
}

/// mbuf_prepend(chain, length): the new head, or NULL (chain freed).
#[no_mangle]
pub extern "C" fn rs_mbuf_prepend(_i: *mut Interface, b: *mut c_void, len: i32) -> *mut c_void {
    if b.is_null() || len < 0 {
        return core::ptr::null_mut();
    }
    ptr(m::prepend(b as m::M, len as usize))
}

/// mbuf_cat(first, second): 0.
#[no_mangle]
pub extern "C" fn rs_mbuf_cat(_i: *mut Interface, a: *mut c_void, b: *mut c_void) -> i32 {
    if a.is_null() || b.is_null() {
        return -1;
    }
    m::cat(a as m::M, b as m::M);
    0
}

/// mbuf_adj(chain, length): 0.
#[no_mangle]
pub extern "C" fn rs_mbuf_adj(_i: *mut Interface, b: *mut c_void, len: i32) -> i32 {
    if b.is_null() {
        return -1;
    }
    m::adj(b as m::M, len);
    0
}

/// mbuf_pullup(chain, length): the new head, or NULL (chain freed).
#[no_mangle]
pub extern "C" fn rs_mbuf_pullup(_i: *mut Interface, b: *mut c_void, len: i32) -> *mut c_void {
    if b.is_null() || len < 0 {
        return core::ptr::null_mut();
    }
    ptr(m::pullup(b as m::M, len as usize))
}
