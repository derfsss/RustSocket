//! Roadshow's `struct AddressAllocationMessage` (SDK 54.25
//! netinclude/libraries/bsdsocket.h, `#pragma pack(2)`): what
//! BeginInterfaceConfig hands the stack and the stack fills in and replies
//! when DHCP has finished. The offsets were measured with the SDK's own
//! compiler (offsetof); the structure is 142 bytes.
//!
//! The message belongs to the caller. The stack keeps only its address while
//! the request runs and gives it back with ReplyMsg from the stack process.

use alloc::vec::Vec;

/// Field offsets.
pub mod off {
    /// struct Message: mn_Node (14 bytes), mn_ReplyPort, mn_Length.
    pub const REPLY_PORT: usize = 14;
    pub const RESULT: usize = 24;
    pub const VERSION: usize = 28;
    pub const PROTOCOL: usize = 32;
    pub const INTERFACE_NAME: usize = 36;
    pub const TIMEOUT: usize = 52;
    pub const LEASE_TIME: usize = 56;
    pub const REQUESTED_ADDRESS: usize = 60;
    pub const CLIENT_IDENTIFIER: usize = 64;
    pub const ADDRESS: usize = 68;
    pub const SERVER_ADDRESS: usize = 72;
    pub const SUBNET_MASK: usize = 76;
    pub const NAK_MESSAGE: usize = 80;
    pub const NAK_MESSAGE_SIZE: usize = 84;
    pub const ROUTER_TABLE: usize = 88;
    pub const ROUTER_TABLE_SIZE: usize = 92;
    pub const DNS_TABLE: usize = 96;
    pub const DNS_TABLE_SIZE: usize = 100;
    pub const STATIC_ROUTE_TABLE: usize = 104;
    pub const STATIC_ROUTE_TABLE_SIZE: usize = 108;
    pub const HOST_NAME: usize = 112;
    pub const HOST_NAME_SIZE: usize = 116;
    pub const DOMAIN_NAME: usize = 120;
    pub const DOMAIN_NAME_SIZE: usize = 124;
    pub const BOOTP_MESSAGE: usize = 128;
    pub const BOOTP_MESSAGE_SIZE: usize = 132;
    pub const LEASE_EXPIRES: usize = 136;
    pub const UNICAST: usize = 140;
    pub const SIZE: usize = 142;
}

/// aam_Result values.
pub const AAMR_SUCCESS: i32 = 0;
pub const AAMR_ABORTED: i32 = 1;
pub const AAMR_INTERFACE_NOT_KNOWN: i32 = 2;
pub const AAMR_INTERFACE_WRONG_TYPE: i32 = 3;
pub const AAMR_ADDRESS_KNOWN: i32 = 4;
pub const AAMR_VERSION_UNKNOWN: i32 = 5;
pub const AAMR_NO_MEMORY: i32 = 6;
pub const AAMR_TIMEOUT: i32 = 7;
pub const AAMR_BUSY: i32 = 11;
pub const AAMR_IGNORED: i32 = -1;

/// AAM_VERSION and AAM_VERSION_MINIMUM.
pub const AAM_VERSION: u32 = 2;
pub const AAM_VERSION_MINIMUM: u32 = 1;

/// aam_Protocol values.
pub const AAMP_BOOTP: u32 = 0;
pub const AAMP_DHCP: u32 = 1;

/// What DHCP gave, for the reply.
#[derive(Default, Clone, Debug)]
pub struct Lease {
    pub address: [u8; 4],
    pub mask: [u8; 4],
    pub server: [u8; 4],
    pub routers: Vec<[u8; 4]>,
    pub dns: Vec<[u8; 4]>,
    pub host_name: Option<Vec<u8>>,
    pub domain_name: Option<Vec<u8>>,
    /// Seconds; None when the server gave none; u32::MAX for infinite.
    pub lease_secs: Option<u32>,
    /// The server's reply, for aam_BOOTPMessage.
    pub packet: Option<Vec<u8>>,
}

/// # Safety
/// `aam` points to a live AddressAllocationMessage.
pub unsafe fn get(aam: usize, o: usize) -> u32 {
    // SAFETY: inside the caller's message (the caller's contract); fields
    // are 2-byte aligned (pack(2)), so read unaligned.
    unsafe { core::ptr::read_unaligned((aam + o) as *const u32) }
}

/// # Safety
/// As [`get`].
pub unsafe fn put(aam: usize, o: usize, v: u32) {
    // SAFETY: as in get.
    unsafe { core::ptr::write_unaligned((aam + o) as *mut u32, v) }
}

/// The interface name in the message (at most 15 characters).
///
/// # Safety
/// As [`get`].
pub unsafe fn name(aam: usize) -> Vec<u8> {
    // SAFETY: the 16-byte aam_InterfaceName array (the caller's contract).
    let b = unsafe { core::slice::from_raw_parts((aam + off::INTERFACE_NAME) as *const u8, 16) };
    b.iter().take_while(|&&c| c != 0).copied().collect()
}

/// Copy up to `size` entries into the table at field `table` (size at
/// `size_field`), zero the rest.
///
/// # Safety
/// As [`get`]; the table points to the caller's `size` LONGs or is NULL.
unsafe fn fill_table(aam: usize, table: usize, size_field: usize, v: &[[u8; 4]]) {
    // SAFETY: the caller's contract.
    let (p, n) = unsafe { (get(aam, table) as *mut u32, get(aam, size_field) as i32) };
    if p.is_null() || n <= 0 {
        return;
    }
    for i in 0..n as usize {
        let x = v.get(i).map(|a| u32::from_be_bytes(*a)).unwrap_or(0);
        // SAFETY: entry i of the caller's table of n.
        unsafe { core::ptr::write_unaligned(p.add(i), x) };
    }
}

/// Copy a string into the buffer at field `buf` (size at `size_field`),
/// NUL-terminated and cut to fit.
///
/// # Safety
/// As [`get`]; the buffer is the caller's `size` bytes or NULL.
unsafe fn fill_string(aam: usize, buf: usize, size_field: usize, s: Option<&[u8]>) {
    // SAFETY: the caller's contract.
    let (p, n) = unsafe { (get(aam, buf) as *mut u8, get(aam, size_field) as i32) };
    let Some(s) = s else { return };
    if p.is_null() || n <= 0 {
        return;
    }
    let l = s.len().min(n as usize - 1);
    // SAFETY: l + 1 <= n bytes of the caller's buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), p, l);
        *p.add(l) = 0;
    }
}

/// Fill in `result` (and the lease's data on success) and reply the
/// message. Called from the stack process.
///
/// # Safety
/// `aam` points to a live AddressAllocationMessage that was handed to
/// BeginInterfaceConfig and has a reply port; it is not used after this.
pub unsafe fn complete(aam: usize, result: i32, lease: Option<&Lease>) {
    // SAFETY: the caller's contract for every access below.
    unsafe {
        put(aam, off::RESULT, result as u32);
        // "The allocation process will eventually reset
        // 'aam_RequestedAddress' to zero."
        put(aam, off::REQUESTED_ADDRESS, 0);
        if let Some(l) = lease {
            put(aam, off::ADDRESS, u32::from_be_bytes(l.address));
            put(aam, off::SERVER_ADDRESS, u32::from_be_bytes(l.server));
            put(aam, off::SUBNET_MASK, u32::from_be_bytes(l.mask));
            fill_table(aam, off::ROUTER_TABLE, off::ROUTER_TABLE_SIZE, &l.routers);
            fill_table(aam, off::DNS_TABLE, off::DNS_TABLE_SIZE, &l.dns);
            // Static routes (options 33 / 121) are not passed on yet.
            fill_table(aam, off::STATIC_ROUTE_TABLE, off::STATIC_ROUTE_TABLE_SIZE, &[]);
            fill_string(aam, off::HOST_NAME, off::HOST_NAME_SIZE, l.host_name.as_deref());
            fill_string(aam, off::DOMAIN_NAME, off::DOMAIN_NAME_SIZE, l.domain_name.as_deref());
            let (bp, bn) = (get(aam, off::BOOTP_MESSAGE) as *mut u8, get(aam, off::BOOTP_MESSAGE_SIZE) as i32);
            if let (Some(pkt), false) = (&l.packet, bp.is_null() || bn <= 0) {
                core::ptr::copy_nonoverlapping(pkt.as_ptr(), bp, pkt.len().min(bn as usize));
            }
            let ds = get(aam, off::LEASE_EXPIRES) as *mut amigaos4::sys::DateStamp;
            if !ds.is_null() {
                *ds = match l.lease_secs {
                    Some(s) if s != u32::MAX => expiry(s),
                    _ => amigaos4::sys::DateStamp::default(),
                };
            }
        }
        amigaos4::sys::exec_reply_msg(aam as *mut amigaos4::sys::Message);
    }
}

/// Now plus `secs`, as a DateStamp (the caller must be a Process).
pub fn expiry(secs: u32) -> amigaos4::sys::DateStamp {
    let mut ds = amigaos4::sys::DateStamp::default();
    // SAFETY: DateStamp fills the structure (the stack is a Process).
    unsafe { amigaos4::sys::dos_date_stamp(&mut ds) };
    let ticks = ds.ds_Tick as u64 + (secs as u64 % 60) * 50;
    let minutes = ds.ds_Minute as u64 + secs as u64 / 60 + ticks / 3000;
    ds.ds_Tick = (ticks % 3000) as i32;
    ds.ds_Days += (minutes / 1440) as i32;
    ds.ds_Minute = (minutes % 1440) as i32;
    ds
}
