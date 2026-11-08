//! The routing API: AddRouteTagList, DeleteRouteTagList,
//! ChangeRouteTagList, GetRouteInfo, FreeRouteInfo, and DEVS:Internet/routes,
//! read once when an interface's configuration is complete (IFC_Complete),
//! as Roadshow's autodoc says. The table itself is in the stack
//! (rsnet_core::route).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use amigaos4::sys::{self, Interface, TagItem};
use rsnet_core::route::Route;
use rsnet_core::stack::RouteOp;

use super::{netdb, opener, shared, stack, Opener};

const EINVAL: i32 = 22;
const ENXIO: i32 = 6;
const EHOSTUNREACH: i32 = 65;

const RTA_BASE: u32 = sys::TAG_USER + 1600;
const RTA_DESTINATION: u32 = RTA_BASE + 1;
const RTA_GATEWAY: u32 = RTA_BASE + 2;
const RTA_DEFAULT_GATEWAY: u32 = RTA_BASE + 3;
const RTA_DESTINATION_HOST: u32 = RTA_BASE + 4;
const RTA_DESTINATION_NET: u32 = RTA_BASE + 5;

/// Roadshow's struct rt_msghdr (net/route.h, pack(2)): offsets measured
/// with the SDK compiler. Not BSD's order.
mod rtm {
    pub const MSGLEN: usize = 0;
    pub const VERSION: usize = 2;
    pub const TYPE: usize = 3;
    pub const INDEX: usize = 4;
    pub const FLAGS: usize = 6;
    pub const ADDRS: usize = 10;
    pub const SIZE: usize = 74;
    pub const RTM_VERSION: u8 = 3;
    pub const RTM_GET: u8 = 4;
    pub const RTA_DST: u32 = 1;
    pub const RTA_GATEWAY: u32 = 2;
    pub const RTA_NETMASK: u32 = 4;
}

/// What a destination tag means.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Either,
    Host,
    Net,
}

/// A destination as (network, prefix length), BSD's way: a host route is
/// /32; a network route covers the natural class, widened to every octet
/// given that is not zero; a plain destination is a network when its
/// address has nothing beyond that, else a host.
fn destination(a: [u8; 4], kind: Kind) -> ([u8; 4], u8) {
    let natural = match a[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    };
    let last = a.iter().rposition(|&b| b != 0).map(|i| (i as u8 + 1) * 8).unwrap_or(0);
    let net = natural.max(last.min(24)).min(32);
    match kind {
        Kind::Host => (a, 32),
        Kind::Net => (a, net),
        Kind::Either => {
            if last <= net {
                (a, net)
            } else {
                (a, 32)
            }
        }
    }
}

/// A host name or address string.
fn resolve(o: &mut Opener, p: u32) -> Option<[u8; 4]> {
    if p == 0 {
        return None;
    }
    // SAFETY: the caller's NUL-terminated string.
    let s = unsafe { core::ffi::CStr::from_ptr(p as *const core::ffi::c_char) }.to_str().ok()?.trim();
    netdb::lookup_host(o, s).ok().map(|(a, _)| a)
}

/// The tags of a route call.
#[derive(Default)]
struct Args {
    dst: Option<([u8; 4], u8)>,
    gateway: Option<[u8; 4]>,
    default: Option<[u8; 4]>,
    bad: bool,
}

fn args(o: &mut Opener, tags: *const TagItem) -> Args {
    let mut a = Args::default();
    let mut t = tags;
    loop {
        if t.is_null() {
            return a;
        }
        // SAFETY: the caller's TAG_DONE-ended list.
        let (tag, data) = unsafe { ((*t).ti_Tag, (*t).ti_Data) };
        match tag {
            sys::TAG_DONE => return a,
            sys::TAG_MORE => {
                t = data as *const TagItem;
                continue;
            }
            // SAFETY: as above.
            sys::TAG_SKIP => t = unsafe { t.add(data as usize) },
            RTA_DESTINATION | RTA_DESTINATION_HOST | RTA_DESTINATION_NET => {
                let kind = match tag {
                    RTA_DESTINATION_HOST => Kind::Host,
                    RTA_DESTINATION_NET => Kind::Net,
                    _ => Kind::Either,
                };
                match resolve(o, data) {
                    Some(d) => a.dst = Some(destination(d, kind)),
                    None => a.bad = true,
                }
            }
            RTA_GATEWAY => match resolve(o, data) {
                Some(g) => a.gateway = Some(g),
                None => a.bad = true,
            },
            RTA_DEFAULT_GATEWAY => match resolve(o, data) {
                Some(g) => a.default = Some(g),
                None => a.bad = true,
            },
            _ => {}
        }
        // SAFETY: as above.
        t = unsafe { t.add(1) };
    }
}

fn run(o: &mut Opener, op: RouteOp) -> i32 {
    let Some(s) = stack() else { return o.fail(ENXIO) };
    match s.route(op) {
        Ok(()) => 0,
        Err(51) => o.fail(EHOSTUNREACH),
        Err(e) => o.fail(e),
    }
}

/// AddRouteTagList(tags): 0, or -1 with errno.
#[no_mangle]
pub extern "C" fn rs_AddRouteTagList(i: *mut Interface, tags: *const TagItem) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let a = args(o, tags);
    let op = match (a.bad, a.default, a.dst, a.gateway) {
        (false, Some(g), None, None) => RouteOp::Add { dst: [0; 4], prefix: 0, gateway: g },
        (false, None, Some((dst, prefix)), Some(g)) => RouteOp::Add { dst, prefix, gateway: g },
        // A destination with no gateway (a route straight to an
        // interface, for point-to-point links) is not supported.
        _ => return o.fail(EINVAL),
    };
    run(o, op)
}

/// DeleteRouteTagList(tags): 0, or -1 with errno (ESRCH: no such route).
#[no_mangle]
pub extern "C" fn rs_DeleteRouteTagList(i: *mut Interface, tags: *const TagItem) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let a = args(o, tags);
    let op = match (a.bad, a.default, a.dst) {
        (false, Some(_), None) => RouteOp::Delete { dst: [0; 4], prefix: 0 },
        (false, None, Some((dst, prefix))) => RouteOp::Delete { dst, prefix },
        _ => return o.fail(EINVAL),
    };
    run(o, op)
}

/// ChangeRouteTagList(tags): a route's new gateway.
#[no_mangle]
pub extern "C" fn rs_ChangeRouteTagList(i: *mut Interface, tags: *const TagItem) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let a = args(o, tags);
    let op = match (a.bad, a.default, a.dst, a.gateway) {
        (false, Some(g), None, None) => RouteOp::Change { dst: [0; 4], prefix: 0, gateway: g },
        (false, None, Some((dst, prefix)), Some(g)) => RouteOp::Change { dst, prefix, gateway: g },
        _ => return o.fail(EINVAL),
    };
    run(o, op)
}

fn sockaddr_in(out: &mut [u8], a: [u8; 4]) {
    out[0] = 16;
    out[1] = 2; // AF_INET
    out[4..8].copy_from_slice(&a);
}

/// GetRouteInfo(address_family, flags): a copy of the routing table, one
/// rt_msghdr per route (destination, gateway and net mask after it), ended
/// by an entry whose rtm_msglen is 0. FreeRouteInfo gives it back.
#[no_mangle]
pub extern "C" fn rs_GetRouteInfo(i: *mut Interface, family: i32, flags: i32) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    // AF_UNSPEC or AF_INET.
    if family != 0 && family != 2 {
        o.fail(EINVAL);
        return core::ptr::null_mut();
    }
    let Some(all) = stack().and_then(|s| s.routes()) else {
        o.fail(ENXIO);
        return core::ptr::null_mut();
    };
    let want = flags as u32;
    let mut bytes: Vec<u8> = Vec::new();
    // As Roadshow lists them: the routes through gateways, then the
    // loopback host route; connected subnets are not listed.
    let lo = Route { dst: [127, 0, 0, 1], prefix: 32, gateway: Some([127, 0, 0, 1]), flags: rsnet_core::route::RTF_UP | rsnet_core::route::RTF_HOST, slot: Some(0), auto: None };
    for r in all.iter().filter(|r| r.gateway.is_some()).chain(core::iter::once(&lo)).filter(|r| r.flags & want == want) {
        entry(&mut bytes, r, None);
    }
    // The ARP table, as host routes with a link-level gateway (arp -a).
    use rsnet_core::rtsock::{RTF_HOST, RTF_LLINFO, RTF_STATIC, RTF_UP};
    for (k, ip, mac, st) in stack().and_then(|s| s.neighbors()).unwrap_or_default() {
        let f = RTF_UP | RTF_HOST | RTF_LLINFO | if st { RTF_STATIC } else { 0 };
        if f & want == want {
            llinfo_entry(&mut bytes, k, ip, mac, f);
        }
    }
    bytes.resize(bytes.len() + rtm::SIZE, 0);
    // Whole LONGs, so the block can be kept and freed as such.
    let words = bytes.len().div_ceil(4);
    let mut block: Box<[u32]> = alloc::vec![0u32; words].into_boxed_slice();
    // SAFETY: the block holds `words * 4 >= bytes.len()` bytes.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), block.as_mut_ptr() as *mut u8, bytes.len()) };
    let p = Box::into_raw(block) as *mut u32 as usize;
    match shared::lock() {
        Some(mut sh) => sh.route_infos.push((p, words)),
        None => {
            // SAFETY: just made, not handed out.
            drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(p as *mut u32, words)) });
            o.fail(ENXIO);
            return core::ptr::null_mut();
        }
    }
    p as *mut u8
}

fn entry(out: &mut Vec<u8>, r: &Route, own: Option<[u8; 4]>) {
    let start = out.len();
    out.resize(start + rtm::SIZE, 0);
    let gw = r.gateway.or(own);
    let mut addrs = rtm::RTA_DST | rtm::RTA_NETMASK;
    if gw.is_some() {
        addrs |= rtm::RTA_GATEWAY;
    }
    let mut sa = [0u8; 16];
    sockaddr_in(&mut sa, r.dst);
    out.extend_from_slice(&sa);
    if let Some(g) = gw {
        let mut sa = [0u8; 16];
        sockaddr_in(&mut sa, g);
        out.extend_from_slice(&sa);
    }
    let m: u32 = if r.prefix == 0 { 0 } else { u32::MAX << (32 - r.prefix as u32) };
    let mut sa = [0u8; 16];
    sockaddr_in(&mut sa, m.to_be_bytes());
    out.extend_from_slice(&sa);
    let len = (out.len() - start) as u16;
    let h = &mut out[start..start + rtm::SIZE];
    h[rtm::MSGLEN..rtm::MSGLEN + 2].copy_from_slice(&len.to_be_bytes());
    h[rtm::VERSION] = rtm::RTM_VERSION;
    h[rtm::TYPE] = rtm::RTM_GET;
    h[rtm::INDEX..rtm::INDEX + 2].copy_from_slice(&(r.slot.map(|k| k + 1).unwrap_or(0) as u16).to_be_bytes());
    h[rtm::FLAGS..rtm::FLAGS + 4].copy_from_slice(&r.flags.to_be_bytes());
    h[rtm::ADDRS..rtm::ADDRS + 4].copy_from_slice(&addrs.to_be_bytes());
}

/// An ARP entry in GetRouteInfo's table: destination, then a sockaddr_dl
/// gateway with the MAC.
fn llinfo_entry(out: &mut Vec<u8>, k: usize, ip: [u8; 4], mac: [u8; 6], flags: u32) {
    let start = out.len();
    out.resize(start + rtm::SIZE, 0);
    out.extend_from_slice(&rsnet_core::rtsock::sa_in(ip));
    out.extend_from_slice(&rsnet_core::rtsock::sa_dl(k, Some(mac)));
    let len = (out.len() - start) as u16;
    let h = &mut out[start..start + rtm::SIZE];
    h[rtm::MSGLEN..rtm::MSGLEN + 2].copy_from_slice(&len.to_be_bytes());
    h[rtm::VERSION] = rtm::RTM_VERSION;
    h[rtm::TYPE] = rtm::RTM_GET;
    h[rtm::INDEX..rtm::INDEX + 2].copy_from_slice(&((k + 1) as u16).to_be_bytes());
    h[rtm::FLAGS..rtm::FLAGS + 4].copy_from_slice(&flags.to_be_bytes());
    h[rtm::ADDRS..rtm::ADDRS + 4].copy_from_slice(&(rtm::RTA_DST | rtm::RTA_GATEWAY).to_be_bytes());
    // rmx_expire (rt_metrics at 34, the fourth LONG): non-zero for an entry
    // that expires (arp shows 0 as "permanent").
    if flags & rsnet_core::rtsock::RTF_STATIC == 0 {
        h[46..50].copy_from_slice(&60u32.to_be_bytes());
    }
}

/// FreeRouteInfo(table): a table from GetRouteInfo (anything else is left
/// alone).
#[no_mangle]
pub extern "C" fn rs_FreeRouteInfo(_i: *mut Interface, table: *mut u8) {
    if table.is_null() {
        return;
    }
    let Some(mut sh) = shared::lock() else { return };
    let Some(k) = sh.route_infos.iter().position(|&(p, _)| p == table as usize) else { return };
    let (p, words) = sh.route_infos.swap_remove(k);
    drop(sh);
    // SAFETY: a block from rs_GetRouteInfo with this length, listed once.
    drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(p as *mut u32, words)) });
}

/// DEVS:Internet/routes, the first time an interface's configuration is
/// complete: each line as AddNetRoute's arguments (DST=, HOSTDST=,
/// NETDST=, VIA=, DEFAULT=; "KEY value" or "KEY=value"). Lines that fail
/// are logged and skipped.
pub fn read_routes_file(o: &mut Opener) {
    {
        let Some(mut sh) = shared::lock() else { return };
        if sh.routes_file_read {
            return;
        }
        sh.routes_file_read = true;
    }
    let Some(lines) = netdb::lines("routes") else { return };
    for words in lines {
        let mut kv: Vec<(String, String)> = Vec::new();
        let mut w = words.iter();
        while let Some(x) = w.next() {
            match x.split_once('=') {
                Some((k, v)) => kv.push((k.to_ascii_uppercase(), String::from(v))),
                None => {
                    let v = w.next().cloned().unwrap_or_default();
                    kv.push((x.to_ascii_uppercase(), v));
                }
            }
        }
        let get = |names: &[&str]| kv.iter().find(|(k, _)| names.contains(&k.as_str())).map(|(_, v)| v.clone());
        let addr = |o: &mut Opener, s: Option<String>| s.and_then(|s| netdb::lookup_host(o, s.trim()).ok()).map(|(a, _)| a);
        let op = if let Some(g) = addr(o, get(&["DEFAULT", "DEFAULTGATEWAY"])) {
            Some(RouteOp::Add { dst: [0; 4], prefix: 0, gateway: g })
        } else {
            let dst = addr(o, get(&["DST", "DESTINATION"]))
                .map(|d| destination(d, Kind::Either))
                .or_else(|| addr(o, get(&["HOSTDST", "HOSTDESTINATION"])).map(|d| destination(d, Kind::Host)))
                .or_else(|| addr(o, get(&["NETDST", "NETDESTINATION"])).map(|d| destination(d, Kind::Net)));
            match (dst, addr(o, get(&["VIA", "GATEWAY"]))) {
                (Some((dst, prefix)), Some(g)) => Some(RouteOp::Add { dst, prefix, gateway: g }),
                _ => None,
            }
        };
        let r = match (op, stack()) {
            (Some(op), Some(s)) => s.route(op),
            _ => Err(EINVAL),
        };
        if let Err(e) = r {
            amigaos4::serial_println!("rustsocket.library: DEVS:Internet/routes: {:?}: errno {}", words, e);
        }
    }
}
