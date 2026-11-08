//! The DNS API: AddDomainNameServer,
//! RemoveDomainNameServer, ObtainDomainNameServerList,
//! ReleaseDomainNameServerList (prototypes and struct DomainNameServerNode
//! in SDK 54.25 netinclude; the autodoc has no pages for them), and the
//! `nameserver` lines of DEVS:Internet/name_resolution, read when the stack
//! starts. The list itself is in the stack (Socks::name_servers).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use amigaos4::sys::Interface;

use super::{netdb, opener, shared, stack, Opener};

const EINVAL: i32 = 22;
const ENXIO: i32 = 6;

/// The address string's address (a dotted address or a host name).
fn address(o: &mut Opener, p: *const u8) -> Option<[u8; 4]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller's NUL-terminated string.
    let s = unsafe { core::ffi::CStr::from_ptr(p as *const core::ffi::c_char) }.to_str().ok()?.trim();
    netdb::lookup_host(o, s).ok().map(|(a, _)| a)
}

/// AddDomainNameServer(address): 0, or -1 with errno.
#[no_mangle]
pub extern "C" fn rs_AddDomainNameServer(i: *mut Interface, a: *const u8) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(a) = address(o, a) else { return o.fail(EINVAL) };
    match stack().map(|s| s.add_name_server(a, false)) {
        Some(Ok(())) => 0,
        Some(Err(e)) => o.fail(e),
        None => o.fail(ENXIO),
    }
}

/// RemoveDomainNameServer(address): 0, or -1 with errno (ENOENT: not there).
#[no_mangle]
pub extern "C" fn rs_RemoveDomainNameServer(i: *mut Interface, a: *const u8) -> i32 {
    let Some(o) = opener(i) else { return -1 };
    let Some(a) = address(o, a) else { return o.fail(EINVAL) };
    match stack().map(|s| s.remove_name_server(a)) {
        Some(Ok(())) => 0,
        Some(Err(e)) => o.fail(e),
        None => o.fail(ENXIO),
    }
}

/// Layout of the block ObtainDomainNameServerList hands out: an exec List
/// (14 bytes, padded to 16), then one DomainNameServerNode per server
/// (dnsn_MinNode 8, dnsn_Size, dnsn_Address, dnsn_UseCount: 20 bytes), then
/// the addresses as text, 16 bytes each.
const LIST: usize = 16;
const NODE: usize = 20;
const TEXT: usize = 16;

/// ObtainDomainNameServerList(): every name server, NULL with errno when
/// none can be made. ReleaseDomainNameServerList gives it back.
#[no_mangle]
pub extern "C" fn rs_ObtainDomainNameServerList(i: *mut Interface) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Some(v) = stack().and_then(|s| s.name_servers()) else {
        o.fail(ENXIO);
        return core::ptr::null_mut();
    };
    let n = v.len();
    let total = LIST + n * (NODE + TEXT);
    let words = total.div_ceil(4);
    let block: Box<[u32]> = alloc::vec![0u32; words].into_boxed_slice();
    let base = Box::into_raw(block) as *mut u32 as usize;
    let put = |at: usize, x: u32| {
        // SAFETY: inside our block of `words` LONGs.
        unsafe { core::ptr::write_unaligned((base + at) as *mut u32, x) }
    };
    let node = |k: usize| base + LIST + k * NODE;
    // The exec List: lh_Head (0), lh_Tail (4, NULL), lh_TailPred (8).
    let tail = (base + 4) as u32;
    put(0, if n == 0 { tail } else { node(0) as u32 });
    put(8, if n == 0 { base as u32 } else { node(n - 1) as u32 });
    for (k, (a, count)) in v.iter().enumerate() {
        let text = alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
        let tp = base + LIST + n * NODE + k * TEXT;
        // SAFETY: the text slot of 16 bytes (at most 15 characters + NUL).
        unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(), tp as *mut u8, text.len()) };
        let at = node(k) - base;
        put(at, if k + 1 < n { node(k + 1) as u32 } else { tail });
        put(at + 4, if k == 0 { base as u32 } else { node(k - 1) as u32 });
        put(at + 8, NODE as u32);
        put(at + 12, tp as u32);
        put(at + 16, *count as u32);
    }
    match shared::lock() {
        Some(mut sh) => sh.dns_lists.push((base, words)),
        None => {
            // SAFETY: just made, not handed out.
            drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(base as *mut u32, words)) });
            o.fail(ENXIO);
            return core::ptr::null_mut();
        }
    }
    base as *mut u8
}

/// ReleaseDomainNameServerList(list): a list from
/// ObtainDomainNameServerList (anything else is left alone).
#[no_mangle]
pub extern "C" fn rs_ReleaseDomainNameServerList(_i: *mut Interface, list: *mut u8) {
    if list.is_null() {
        return;
    }
    let Some(mut sh) = shared::lock() else { return };
    let Some(k) = sh.dns_lists.iter().position(|&(p, _)| p == list as usize) else { return };
    let (p, words) = sh.dns_lists.swap_remove(k);
    drop(sh);
    // SAFETY: a block from rs_ObtainDomainNameServerList, listed once.
    drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(p as *mut u32, words)) });
}

const NAME_RESOLUTION: &str = "DEVS:Internet/name_resolution";

/// DEVS:Internet/name_resolution as Roadshow reads it (roadshow.doc
/// 7.1.2.3): its `nameserver` lines are servers the resolver asks after
/// the listed ones (Roadshow's ShowNetStatus lists them nowhere, at boot or
/// after a change, and an unreachable one does not slow its lookups), its
/// last `domain` or `search` line the search list (six domains, 256
/// characters at most; a `domain` searches only itself, as Roadshow's). Read when the stack starts and again
/// whenever the file changes (the superserver's loop looks once a second;
/// Roadshow takes up a changed search list within seconds).
pub fn read_name_resolution() {
    let lines = netdb::lines("name_resolution").unwrap_or_default();
    let mut servers: Vec<[u8; 4]> = Vec::new();
    let mut search: Vec<String> = Vec::new();
    for w in lines {
        let key = w[0].to_ascii_lowercase();
        match key.as_str() {
            "nameserver" if w.len() >= 2 => match rsnet_core::sock::parse_dotted(&w[1]) {
                Some(a) if !servers.contains(&a) => servers.push(a),
                Some(_) => {}
                None => amigaos4::serial_println!("rustsocket.library: name_resolution: not an address: {}", w[1]),
            },
            "domain" if w.len() >= 2 => search = alloc::vec![w[1].trim_end_matches('.').into()],
            "search" => {
                search.clear();
                let mut total = 0;
                for d in w[1..].iter().take(6) {
                    total += d.len() + 1;
                    if total > 256 {
                        break;
                    }
                    search.push(d.trim_end_matches('.').into());
                }
            }
            _ => {}
        }
    }
    if let Some(mut sh) = shared::lock() {
        sh.search = search;
    }
    if let Some(s) = stack() {
        s.set_file_name_servers(servers);
    }
}

/// name_resolution's date and size, to see a change.
pub fn name_resolution_stamp() -> Option<(i32, i32, i32, u64)> {
    let m = amigaos4::dos::fs::metadata(NAME_RESOLUTION).ok()?;
    Some((m.date.ds_Days, m.date.ds_Minute, m.date.ds_Tick, m.size.unwrap_or(0)))
}
