//! sendmsg / recvmsg: scatter-gather over send and recv. No ancillary
//! data: msg_controllen comes back 0.

use alloc::vec;
use alloc::vec::Vec;

use amigaos4::sys::Interface;

use super::{do_recv, do_send, opener, sockaddr_in};

/// struct msghdr (sys/socket.h).
#[repr(C)]
pub struct MsgHdr {
    name: *mut u8,
    namelen: u32,
    iov: *const IoVec,
    iovlen: u32,
    control: *mut u8,
    controllen: u32,
    flags: i32,
}

/// struct iovec (sys/uio.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoVec {
    base: *mut u8,
    len: u32,
}

/// The most iovec entries taken (BSD's UIO_MAXIOV is 1024).
const MAX_IOV: u32 = 1024;
const EMSGSIZE: i32 = 40;

/// The caller's iovec array.
fn iovecs<'a>(m: &MsgHdr) -> Option<&'a [IoVec]> {
    if m.iovlen > MAX_IOV || (m.iov.is_null() && m.iovlen > 0) {
        return None;
    }
    if m.iovlen == 0 {
        return Some(&[]);
    }
    // SAFETY: the caller's array of iovlen entries.
    Some(unsafe { core::slice::from_raw_parts(m.iov, m.iovlen as usize) })
}

/// sendmsg(s, msg, flags): the iovec pieces sent as one buffer (to
/// msg_name, if given).
#[no_mangle]
pub extern "C" fn rs_sendmsg(i: *mut Interface, fd: i32, msg: *const MsgHdr, flags: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    if msg.is_null() {
        return o.fail(super::errno::EINVAL);
    }
    // SAFETY: the caller's msghdr.
    let m = unsafe { &*msg };
    let Some(iov) = iovecs(m) else { return o.fail(EMSGSIZE) };
    let to = if m.name.is_null() {
        None
    } else {
        match sockaddr_in(m.name, m.namelen) {
            Some(d) => Some(d),
            None => return o.fail(super::errno::EAFNOSUPPORT),
        }
    };
    let total: usize = iov.iter().map(|v| v.len as usize).sum();
    if total > i32::MAX as usize {
        return o.fail(super::errno::EINVAL);
    }
    let mut buf = Vec::with_capacity(total);
    for v in iov {
        if v.len == 0 {
            continue;
        }
        if v.base.is_null() {
            return o.fail(super::errno::EINVAL);
        }
        // SAFETY: the caller's piece of len bytes.
        buf.extend_from_slice(unsafe { core::slice::from_raw_parts(v.base, v.len as usize) });
    }
    do_send(o, fd, buf.as_ptr(), buf.len() as i32, flags, to)
}

/// recvmsg(s, msg, flags): received into one buffer and spread over the
/// iovec pieces; msg_name gets the sender (UDP).
#[no_mangle]
pub extern "C" fn rs_recvmsg(i: *mut Interface, fd: i32, msg: *mut MsgHdr, flags: i32) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    if msg.is_null() {
        return o.fail(super::errno::EINVAL);
    }
    // SAFETY: the caller's msghdr, written back below.
    let m = unsafe { &mut *msg };
    let Some(iov) = iovecs(m) else { return o.fail(EMSGSIZE) };
    let total: usize = iov.iter().map(|v| v.len as usize).sum();
    if total > i32::MAX as usize {
        return o.fail(super::errno::EINVAL);
    }
    let mut buf = vec![0u8; total];
    let (from, mut fromlen) = (m.name, m.namelen);
    let fromlen_ptr = if from.is_null() { core::ptr::null_mut() } else { &mut fromlen as *mut u32 };
    let n = do_recv(o, fd, buf.as_mut_ptr(), total as i32, flags, from, fromlen_ptr);
    if n < 0 {
        return n;
    }
    let mut left = &buf[..n as usize];
    for v in iov {
        if left.is_empty() {
            break;
        }
        let k = left.len().min(v.len as usize);
        if k > 0 && !v.base.is_null() {
            // SAFETY: the caller's piece of len >= k bytes.
            unsafe { core::ptr::copy_nonoverlapping(left.as_ptr(), v.base, k) };
        }
        left = &left[k..];
    }
    if !from.is_null() {
        m.namelen = fromlen;
    }
    m.controllen = 0;
    m.flags = 0;
    n
}
