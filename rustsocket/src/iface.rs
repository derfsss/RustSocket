//! The interface API: AddInterfaceTagList,
//! ConfigureInterfaceTagList, RemoveInterface, and the address allocation
//! messages (CreateAddrAllocMessageA, DeleteAddrAllocMessage,
//! BeginInterfaceConfig, AbortInterfaceConfig), as Roadshow's autodoc
//! describes them. The stack does the work (rsnet_core::stack); DHCP for a
//! message runs in the stack process, which fills the message in and
//! replies it (rsnet_core::aam).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use amigaos4::sys::{self, Interface, TagItem};
use rsnet_core::aam;
use rsnet_core::sock::parse_dotted;

use super::{opener, shared, stack};

const EINVAL: i32 = 22;
const ENXIO: i32 = 6;

const IFA_BASE: u32 = sys::TAG_USER + 1700;
const IFA_IP_TYPE: u32 = IFA_BASE + 1;
const IFA_ARP_TYPE: u32 = IFA_BASE + 2;
const IFA_POINT_TO_POINT: u32 = IFA_BASE + 7;
const IFA_DOWN_GOES_OFFLINE: u32 = IFA_BASE + 10;
const IFA_HARDWARE_ADDRESS: u32 = IFA_BASE + 14;
const IFA_LIMIT_MTU: u32 = IFA_BASE + 16;

const IFC_BASE: u32 = sys::TAG_USER + 1800;
const IFC_ADDRESS: u32 = IFC_BASE + 1;
const IFC_NET_MASK: u32 = IFC_BASE + 2;
const IFC_DESTINATION_ADDRESS: u32 = IFC_BASE + 3;
const IFC_BROADCAST_ADDRESS: u32 = IFC_BASE + 4;
const IFC_METRIC: u32 = IFC_BASE + 5;
const IFC_ADD_ALIAS_ADDRESS: u32 = IFC_BASE + 6;
const IFC_DELETE_ALIAS_ADDRESS: u32 = IFC_BASE + 7;
const IFC_STATE: u32 = IFC_BASE + 8;
const IFC_RELEASE_ADDRESS: u32 = IFC_BASE + 14;
const IFC_SET_DEBUG_MODE: u32 = IFC_BASE + 15;
const IFC_COMPLETE: u32 = IFC_BASE + 16;
const IFC_LIMIT_MTU: u32 = IFC_BASE + 17;

/// IFC_State values.
const SM_OFFLINE: u32 = 0;
const SM_ONLINE: u32 = 1;
const SM_DOWN: u32 = 2;
const SM_UP: u32 = 3;

const CAAMTA_BASE: u32 = sys::TAG_USER + 2000;
const CAAMTA_TIMEOUT: u32 = CAAMTA_BASE + 1;
const CAAMTA_LEASE_TIME: u32 = CAAMTA_BASE + 2;
const CAAMTA_REQUESTED_ADDRESS: u32 = CAAMTA_BASE + 3;
const CAAMTA_CLIENT_IDENTIFIER: u32 = CAAMTA_BASE + 4;
const CAAMTA_NAK_MESSAGE_SIZE: u32 = CAAMTA_BASE + 5;
const CAAMTA_ROUTER_TABLE_SIZE: u32 = CAAMTA_BASE + 6;
const CAAMTA_DNS_TABLE_SIZE: u32 = CAAMTA_BASE + 7;
const CAAMTA_STATIC_ROUTE_TABLE_SIZE: u32 = CAAMTA_BASE + 8;
const CAAMTA_HOST_NAME_SIZE: u32 = CAAMTA_BASE + 9;
const CAAMTA_DOMAIN_NAME_SIZE: u32 = CAAMTA_BASE + 10;
const CAAMTA_BOOTP_MESSAGE_SIZE: u32 = CAAMTA_BASE + 11;
const CAAMTA_RECORD_LEASE_EXPIRATION: u32 = CAAMTA_BASE + 12;
const CAAMTA_REPLY_PORT: u32 = CAAMTA_BASE + 13;
const CAAMTA_REQUEST_UNICAST: u32 = CAAMTA_BASE + 14;

const CAAME_SUCCESS: i32 = 0;
const CAAME_INVALID_RESULT_PTR: i32 = 1;
const CAAME_NOT_ENOUGH_MEMORY: i32 = 2;
const CAAME_INVALID_VERSION: i32 = 3;
const CAAME_INVALID_PROTOCOL: i32 = 4;
const CAAME_INVALID_INTERFACE_NAME: i32 = 5;
const CAAME_INTERFACE_NOT_FOUND: i32 = 6;
const CAAME_INVALID_CLIENT_IDENTIFIER: i32 = 7;
const CAAME_CLIENT_IDENTIFIER_TOO_SHORT: i32 = 8;
const CAAME_CLIENT_IDENTIFIER_TOO_LONG: i32 = 9;

/// exec's NT_MESSAGE.
const NT_MESSAGE: u8 = 5;

/// A caller's NUL-terminated string, or None for NULL.
fn cstr<'a>(p: *const u8) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string the caller passed.
    Some(unsafe { core::ffi::CStr::from_ptr(p as *const core::ffi::c_char) }.to_bytes())
}

/// Walk a tag list (TAG_MORE / IGNORE / SKIP followed); `f` returns false to
/// stop with an error.
fn each_tag(tags: *const TagItem, mut f: impl FnMut(u32, u32) -> bool) -> bool {
    let mut t = tags;
    loop {
        if t.is_null() {
            return true;
        }
        // SAFETY: the caller's TAG_DONE-ended list.
        let (tag, data) = unsafe { ((*t).ti_Tag, (*t).ti_Data) };
        match tag {
            sys::TAG_DONE => return true,
            sys::TAG_IGNORE => {}
            sys::TAG_MORE => {
                t = data as *const TagItem;
                continue;
            }
            sys::TAG_SKIP => {
                // SAFETY: as above.
                t = unsafe { t.add(data as usize) };
            }
            _ => {
                if !f(tag, data) {
                    return false;
                }
            }
        }
        // SAFETY: as above.
        t = unsafe { t.add(1) };
    }
}

/// A dotted-decimal address string.
fn address(p: u32) -> Option<[u8; 4]> {
    parse_dotted(core::str::from_utf8(cstr(p as *const u8)?).ok()?.trim())
}

/// A net mask as a prefix length (contiguous masks only).
fn prefix_of(mask: [u8; 4]) -> Option<u8> {
    let m = u32::from_be_bytes(mask);
    let len = m.leading_ones();
    (m.checked_shl(len).unwrap_or(0) == 0).then_some(len as u8)
}

/// The class's natural prefix length, for an address given without a mask.
fn natural_prefix(a: [u8; 4]) -> u8 {
    match a[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    }
}

/// AddInterfaceTagList(name, device, unit, tags): 0, or -1 with errno.
/// A device name with no path is looked for in DEVS:Networks/ first, as
/// Roadshow does.
#[no_mangle]
pub extern "C" fn rs_AddInterfaceTagList(i: *mut Interface, name: *const u8, device: *const u8, unit: i32, tags: *const TagItem) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let (Some(n), Some(d)) = (cstr(name), cstr(device)) else { return o.fail(EINVAL) };
    let (Ok(n), Ok(d)) = (core::str::from_utf8(n), core::str::from_utf8(d)) else { return o.fail(EINVAL) };
    let (mut bad, mut mac, mut down_offline, mut mtu) = (false, None, false, None);
    each_tag(tags, |tag, data| {
        // Only what this stack does is accepted: IP and ARP on their usual
        // packet types, a broadcast (Ethernet) interface. The hardware
        // address, "down goes offline" and the MTU limit act (as on
        // Roadshow); the request counts, copy mode, filter
        // mode, init delay, multicast, offline reports, the link status
        // command and debug mode are taken and not acted on
        // (roadshow-compat.md).
        bad |= match tag {
            IFA_IP_TYPE => data != 2048,
            IFA_ARP_TYPE => data != 2054,
            IFA_POINT_TO_POINT => data != 0,
            IFA_DOWN_GOES_OFFLINE => {
                down_offline = data != 0;
                false
            }
            IFA_LIMIT_MTU => {
                mtu = Some(data);
                false
            }
            // struct InterfaceHardwareAddress: iha_Length (bits),
            // iha_Address; an Ethernet address only.
            IFA_HARDWARE_ADDRESS => {
                let p = data as usize as *const u32;
                if p.is_null() {
                    true
                } else {
                    // SAFETY: the caller's InterfaceHardwareAddress.
                    let (bits, at) = unsafe { (p.read_unaligned(), p.add(1).read_unaligned() as usize as *const u8) };
                    if bits != 48 || at.is_null() {
                        true
                    } else {
                        let mut m = [0u8; 6];
                        // SAFETY: iha_Address holds iha_Length bits.
                        unsafe { core::ptr::copy_nonoverlapping(at, m.as_mut_ptr(), 6) };
                        mac = Some(m);
                        false
                    }
                }
            }
            _ => false,
        };
        !bad
    });
    if bad {
        return o.fail(EINVAL);
    }
    let Some(s) = stack() else { return o.fail(ENXIO) };
    if let Err(e) = s.add_iface(n, d, unit as u32, mac, down_offline) {
        return o.fail(e);
    }
    if let Some(m) = mtu {
        let opts = rsnet_core::stack::IfaceOpts { mtu: Some(m), ..Default::default() };
        if let Err(e) = s.iface_opts(n, opts) {
            return o.fail(e);
        }
    }
    0
}

/// ConfigureInterfaceTagList(name, tags): 0, or -1 with errno.
#[no_mangle]
pub extern "C" fn rs_ConfigureInterfaceTagList(i: *mut Interface, name: *const u8, tags: *const TagItem) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(n) = cstr(name).and_then(|n| core::str::from_utf8(n).ok()) else { return o.fail(EINVAL) };
    let (mut addr_str, mut mask, mut up, mut release, mut complete, mut bad) = (0u32, None, None, false, false, false);
    let mut opts = rsnet_core::stack::IfaceOpts::default();
    let mut aliases: alloc::vec::Vec<([u8; 4], bool)> = alloc::vec::Vec::new();
    each_tag(tags, |tag, data| {
        match tag {
            IFC_ADDRESS => addr_str = data,
            IFC_NET_MASK => match address(data).and_then(prefix_of) {
                Some(p) => mask = Some(p),
                None => bad = true,
            },
            // Point-to-point interfaces are not supported.
            IFC_DESTINATION_ADDRESS => bad = true,
            IFC_STATE => match data {
                SM_UP | SM_ONLINE => up = Some(true),
                SM_DOWN | SM_OFFLINE => up = Some(false),
                _ => bad = true,
            },
            IFC_RELEASE_ADDRESS => release = data != 0,
            IFC_COMPLETE => complete = data != 0,
            IFC_BROADCAST_ADDRESS => match address(data) {
                Some(a) => opts.broadcast = Some(a),
                None => bad = true,
            },
            IFC_METRIC => opts.metric = Some(data),
            IFC_SET_DEBUG_MODE => opts.debug = Some(data != 0),
            IFC_LIMIT_MTU => opts.mtu = Some(data),
            IFC_ADD_ALIAS_ADDRESS | IFC_DELETE_ALIAS_ADDRESS => match address(data) {
                Some(a) => aliases.push((a, tag == IFC_ADD_ALIAS_ADDRESS)),
                None => bad = true,
            },
            // Peer address and DNS from PPP, associated route/DNS, the
            // link status command: taken, not acted on (no point-to-point
            // interfaces here; roadshow-compat.md).
            _ => {}
        }
        !bad
    });
    // A host name or an address (resolved as gethostbyname does).
    let addr = if addr_str == 0 {
        None
    } else {
        match cstr(addr_str as *const u8).and_then(|s| core::str::from_utf8(s).ok()).and_then(|s| super::netdb::lookup_host(o, s.trim()).ok()) {
            Some((a, _)) => Some(a),
            None => return o.fail(EINVAL),
        }
    };
    if bad || (mask.is_some() && addr.is_none()) {
        return o.fail(EINVAL);
    }
    let Some(s) = stack() else { return o.fail(ENXIO) };
    let address = addr.map(|a| (a, mask.unwrap_or_else(|| natural_prefix(a))));
    if let Err(e) = s.config_iface(n, address, up, release) {
        return o.fail(e);
    }
    if opts.mtu.is_some() || opts.metric.is_some() || opts.debug.is_some() || opts.broadcast.is_some() {
        if let Err(e) = s.iface_opts(n, opts) {
            return o.fail(e);
        }
    }
    for a in aliases {
        let one = rsnet_core::stack::IfaceOpts { alias: Some(a), ..Default::default() };
        if let Err(e) = s.iface_opts(n, one) {
            return o.fail(e);
        }
    }
    if complete {
        super::routes::read_routes_file(o);
    }
    0
}

/// RemoveInterface(name, force): TRUE, or FALSE with errno.
#[no_mangle]
pub extern "C" fn rs_RemoveInterface(i: *mut Interface, name: *const u8, force: i32) -> i32 {
    let Some(o) = opener(i) else { return 0 };
    let Some(n) = cstr(name).and_then(|n| core::str::from_utf8(n).ok()) else {
        o.fail(EINVAL);
        return 0;
    };
    let Some(s) = stack() else {
        o.fail(ENXIO);
        return 0;
    };
    match s.remove_iface(n, force != 0) {
        Ok(()) => 1,
        Err(e) => {
            o.fail(e);
            0
        }
    }
}

/// Whether interface `name` exists.
fn known(name: &[u8]) -> bool {
    stack().and_then(|s| s.status()).map(|v| v.iter().any(|st| st.present && st.name.as_bytes().eq_ignore_ascii_case(name))).unwrap_or(false)
}

/// CreateAddrAllocMessageA(version, protocol, name, result_ptr, tags):
/// one block holding the message and every buffer the tags asked for,
/// recorded so DeleteAddrAllocMessage frees only these. CAAME_* result.
#[no_mangle]
pub extern "C" fn rs_CreateAddrAllocMessageA(_i: *mut Interface, version: i32, protocol: i32, name: *const u8, result: *mut usize, tags: *const TagItem) -> i32 {
    if result.is_null() {
        return CAAME_INVALID_RESULT_PTR;
    }
    if !(aam::AAM_VERSION_MINIMUM as i32..=aam::AAM_VERSION as i32).contains(&version) {
        return CAAME_INVALID_VERSION;
    }
    if protocol as u32 != aam::AAMP_BOOTP && protocol as u32 != aam::AAMP_DHCP {
        return CAAME_INVALID_PROTOCOL;
    }
    let Some(n) = cstr(name).filter(|n| !n.is_empty() && n.len() <= 15) else { return CAAME_INVALID_INTERFACE_NAME };
    if !known(n) {
        return CAAME_INTERFACE_NOT_FOUND;
    }
    let (mut timeout, mut lease, mut requested, mut unicast, mut port) = (10u32, 0u32, 0u32, 0u32, 0u32);
    let (mut nak, mut routers, mut dns, mut statics, mut host, mut domain, mut bootp, mut expires) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, false);
    let mut cid: Option<Vec<u8>> = None;
    let mut err = CAAME_SUCCESS;
    each_tag(tags, |tag, data| {
        let size = (data as i32).max(0) as usize;
        match tag {
            // Kept as given (Roadshow keeps 7 in the message); the
            // 10-second minimum applies when the configuration runs.
            CAAMTA_TIMEOUT => timeout = data,
            CAAMTA_LEASE_TIME => lease = data,
            CAAMTA_REQUESTED_ADDRESS => requested = data,
            CAAMTA_CLIENT_IDENTIFIER => match cstr(data as *const u8) {
                None => err = CAAME_INVALID_CLIENT_IDENTIFIER,
                Some(c) if c.is_empty() => err = CAAME_INVALID_CLIENT_IDENTIFIER,
                Some(c) if c.len() < 2 => err = CAAME_CLIENT_IDENTIFIER_TOO_SHORT,
                Some(c) if c.len() > 255 => err = CAAME_CLIENT_IDENTIFIER_TOO_LONG,
                Some(c) => cid = Some(Vec::from(c)),
            },
            CAAMTA_NAK_MESSAGE_SIZE => nak = size,
            CAAMTA_ROUTER_TABLE_SIZE => routers = size,
            CAAMTA_DNS_TABLE_SIZE => dns = size,
            CAAMTA_STATIC_ROUTE_TABLE_SIZE => statics = size,
            CAAMTA_HOST_NAME_SIZE => host = size,
            CAAMTA_DOMAIN_NAME_SIZE => domain = size,
            CAAMTA_BOOTP_MESSAGE_SIZE => bootp = size,
            CAAMTA_RECORD_LEASE_EXPIRATION => expires = data != 0,
            CAAMTA_REPLY_PORT => port = data,
            CAAMTA_REQUEST_UNICAST => unicast = (data != 0) as u32,
            _ => {}
        }
        err == CAAME_SUCCESS
    });
    if err != CAAME_SUCCESS {
        return err;
    }
    // The block: the message (142 bytes, padded to 144), then the tables
    // (4-byte entries) and byte buffers, each 4-byte aligned.
    let up4 = |x: usize| (x + 3) & !3;
    let mut at = 144usize;
    let mut take = |len: usize| {
        let o = at;
        at += up4(len);
        o
    };
    let o_routers = take(routers * 4);
    let o_dns = take(dns * 4);
    let o_statics = take(statics * 4);
    let o_nak = take(nak);
    let o_host = take(host);
    let o_domain = take(domain);
    let o_bootp = take(bootp);
    let o_expires = take(if expires { 12 } else { 0 });
    let o_cid = take(cid.as_ref().map(|c| c.len() + 1).unwrap_or(0));
    let total = at;
    let Some(mut sh) = shared::lock() else { return CAAME_NOT_ENOUGH_MEMORY };
    let block: Box<[u32]> = alloc::vec![0u32; total / 4].into_boxed_slice();
    let base = Box::into_raw(block) as *mut u32 as usize;
    sh.alloc_msgs.push((base, total / 4));
    drop(sh);
    let ptr = |o: usize, len: usize| if len == 0 { 0 } else { (base + o) as u32 };
    // SAFETY: our new zeroed block of `total` bytes; every offset is inside.
    unsafe {
        *((base + 8) as *mut u8) = NT_MESSAGE;
        core::ptr::write_unaligned((base + aam::off::REPLY_PORT) as *mut u32, port);
        core::ptr::write_unaligned((base + 18) as *mut u16, aam::off::SIZE as u16);
        aam::put(base, aam::off::VERSION, version as u32);
        aam::put(base, aam::off::PROTOCOL, protocol as u32);
        core::ptr::copy_nonoverlapping(n.as_ptr(), (base + aam::off::INTERFACE_NAME) as *mut u8, n.len());
        aam::put(base, aam::off::TIMEOUT, timeout);
        aam::put(base, aam::off::LEASE_TIME, lease);
        aam::put(base, aam::off::REQUESTED_ADDRESS, requested);
        if let Some(c) = &cid {
            core::ptr::copy_nonoverlapping(c.as_ptr(), (base + o_cid) as *mut u8, c.len());
            aam::put(base, aam::off::CLIENT_IDENTIFIER, (base + o_cid) as u32);
        }
        aam::put(base, aam::off::NAK_MESSAGE, ptr(o_nak, nak));
        aam::put(base, aam::off::NAK_MESSAGE_SIZE, nak as u32);
        aam::put(base, aam::off::ROUTER_TABLE, ptr(o_routers, routers));
        aam::put(base, aam::off::ROUTER_TABLE_SIZE, routers as u32);
        aam::put(base, aam::off::DNS_TABLE, ptr(o_dns, dns));
        aam::put(base, aam::off::DNS_TABLE_SIZE, dns as u32);
        aam::put(base, aam::off::STATIC_ROUTE_TABLE, ptr(o_statics, statics));
        aam::put(base, aam::off::STATIC_ROUTE_TABLE_SIZE, statics as u32);
        aam::put(base, aam::off::HOST_NAME, ptr(o_host, host));
        aam::put(base, aam::off::HOST_NAME_SIZE, host as u32);
        aam::put(base, aam::off::DOMAIN_NAME, ptr(o_domain, domain));
        aam::put(base, aam::off::DOMAIN_NAME_SIZE, domain as u32);
        aam::put(base, aam::off::BOOTP_MESSAGE, ptr(o_bootp, bootp));
        aam::put(base, aam::off::BOOTP_MESSAGE_SIZE, bootp as u32);
        aam::put(base, aam::off::LEASE_EXPIRES, ptr(o_expires, if expires { 12 } else { 0 }));
        core::ptr::write_unaligned((base + aam::off::UNICAST) as *mut u16, unicast as u16);
        *result = base;
    }
    CAAME_SUCCESS
}

/// DeleteAddrAllocMessage(message): frees a message CreateAddrAllocMessageA
/// made (NULL, or anything else, is left alone).
#[no_mangle]
pub extern "C" fn rs_DeleteAddrAllocMessage(_i: *mut Interface, m: *mut c_void) {
    if m.is_null() {
        return;
    }
    let Some(mut sh) = shared::lock() else { return };
    let Some(k) = sh.alloc_msgs.iter().position(|&(p, _)| p == m as usize) else { return };
    let (p, words) = sh.alloc_msgs.swap_remove(k);
    drop(sh);
    // SAFETY: the block made by rs_CreateAddrAllocMessageA with this length,
    // taken out of the record once.
    drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(p as *mut u32, words)) });
}

/// BeginInterfaceConfig(message): DHCP in the stack, which replies the
/// message when it is done; refused requests are replied at once.
#[no_mangle]
pub extern "C" fn rs_BeginInterfaceConfig(_i: *mut Interface, m: *mut c_void) {
    if m.is_null() {
        return;
    }
    let m = m as usize;
    // SAFETY: the caller's AddressAllocationMessage (autodoc contract).
    let (port, version, protocol) = unsafe {
        (core::ptr::read_unaligned((m + aam::off::REPLY_PORT) as *const u32), aam::get(m, aam::off::VERSION), aam::get(m, aam::off::PROTOCOL))
    };
    if port == 0 {
        // Nowhere to reply it to.
        return;
    }
    let reply = |r: i32| {
        // SAFETY: the caller's message, with a reply port.
        unsafe { aam::complete(m, r, None) }
    };
    if !(aam::AAM_VERSION_MINIMUM..=aam::AAM_VERSION).contains(&version) {
        return reply(aam::AAMR_VERSION_UNKNOWN);
    }
    if protocol != aam::AAMP_DHCP {
        // BOOTP and the link-local protocols are not done yet.
        return reply(aam::AAMR_IGNORED);
    }
    // SAFETY: as above.
    let (name, timeout, lease, cid) = unsafe { (aam::name(m), aam::get(m, aam::off::TIMEOUT), aam::get(m, aam::off::LEASE_TIME), aam::get(m, aam::off::CLIENT_IDENTIFIER)) };
    let cid = cstr(cid as *const u8).map(Vec::from).unwrap_or_default();
    let Some(s) = stack() else { return reply(aam::AAMR_NO_MEMORY) };
    let name = String::from_utf8_lossy(&name).into_owned();
    let r = s.begin_config(&name, m, timeout.max(10), lease, cid);
    if r != rsnet_core::stack::BEGIN_PENDING {
        reply(r);
    }
}

/// AbortInterfaceConfig(message): the stack replies it (AAMR_Aborted) if
/// its request still runs.
#[no_mangle]
pub extern "C" fn rs_AbortInterfaceConfig(_i: *mut Interface, m: *mut c_void) {
    if let (false, Some(s)) = (m.is_null(), stack()) {
        s.abort_config(m as usize);
    }
}
