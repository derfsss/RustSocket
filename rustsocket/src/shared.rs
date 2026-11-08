//! State every opener shares, under one mutex: sockets released for
//! another opener (ReleaseSocket / ReleaseCopyOfSocket -> ObtainSocket),
//! how many descriptors refer to each stack socket (Dup2Socket,
//! ReleaseCopyOfSocket: the socket closes with its last descriptor), and
//! the default domain name.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use amigaos4::sync::{Mutex, MutexGuard};

use super::Fd;

pub struct Shared {
    /// Released sockets waiting for an ObtainSocket: (id, descriptor).
    pub released: Vec<(i32, Fd)>,
    /// Stack socket -> descriptors (in any opener, or released) that refer
    /// to it.
    pub refs: BTreeMap<u32, u32>,
    /// SetDefaultDomainName / GetDefaultDomainName.
    pub domain: String,
    /// The network databases (netdb.rs), read at first use.
    pub db: Option<alloc::sync::Arc<super::netdb::Db>>,
    /// SBTC_LOG_FILE_NAME (NUL-terminated once set) and SBTC_LOG_HOOK.
    pub log_file: Vec<u8>,
    pub log_hook: u32,
    /// The address allocation messages CreateAddrAllocMessageA made: (block,
    /// length in LONGs). DeleteAddrAllocMessage frees only these.
    pub alloc_msgs: Vec<(usize, usize)>,
    /// GetRouteInfo's tables not yet given back: (block, length in LONGs).
    pub route_infos: Vec<(usize, usize)>,
    /// DEVS:Internet/routes has been read (once, at the first IFC_Complete).
    pub routes_file_read: bool,
    /// ObtainDomainNameServerList's lists not yet given back.
    pub dns_lists: Vec<(usize, usize)>,
    /// ObtainRoadshowData's lists not yet given back (block, LONGs).
    pub rd_lists: Vec<(usize, usize)>,
    /// The lists holding write access and read access, with the task
    /// that obtained each (list, task): exec semaphore rules, as Roadshow.
    pub rd_writers: Vec<(usize, usize)>,
    pub rd_readers: Vec<(usize, usize)>,
    /// Programs the superserver started: (process ID, the socket id their
    /// ObtainServerSocket claims; None once claimed).
    pub servers: Vec<(u32, Option<i32>)>,
    /// DEVS:Internet/name_resolution's search list as last read (dns.rs).
    pub search: Vec<String>,
}

static SHARED: AtomicPtr<Mutex<Shared>> = AtomicPtr::new(core::ptr::null_mut());

/// Made by the first Open. False when no mutex could be had.
pub fn init() -> bool {
    let Ok(m) = Mutex::new(Shared { released: Vec::new(), refs: BTreeMap::new(), domain: String::new(), db: None, log_file: Vec::new(), log_hook: 0, alloc_msgs: Vec::new(), route_infos: Vec::new(), routes_file_read: false, dns_lists: Vec::new(), rd_lists: Vec::new(), rd_writers: Vec::new(), rd_readers: Vec::new(), servers: Vec::new(), search: Vec::new() }) else {
        return false;
    };
    SHARED.store(Box::into_raw(Box::new(m)), Ordering::Release);
    true
}

/// The shared state, locked; None between the last Close and the next
/// first Open.
pub fn lock() -> Option<MutexGuard<'static, Shared>> {
    let p = SHARED.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // SAFETY: the Box stored by init, freed only by take_all at the last
    // Close, after which no opener calls in.
    unsafe { &*p }.lock().ok()
}

/// One more descriptor refers to stack socket `h`.
pub fn add_ref(h: u32) {
    if let Some(mut s) = lock() {
        *s.refs.entry(h).or_insert(0) += 1;
    }
}

/// One descriptor fewer refers to `h`: true when it was the last (the
/// stack socket is to be closed).
pub fn drop_ref(h: u32) -> bool {
    let Some(mut s) = lock() else { return true };
    match s.refs.get_mut(&h) {
        Some(n) if *n > 1 => {
            *n -= 1;
            false
        }
        _ => {
            s.refs.remove(&h);
            true
        }
    }
}

/// The last Close: free the state; the released sockets nobody obtained,
/// to be closed.
pub fn take_all() -> Vec<Fd> {
    let p = SHARED.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: the Box stored by init, taken once.
    let m = unsafe { Box::from_raw(p) };
    let sh = m.into_inner();
    // Messages their programs never deleted go with the library's state.
    for &(p, words) in sh.alloc_msgs.iter().chain(sh.route_infos.iter()).chain(sh.dns_lists.iter()).chain(sh.rd_lists.iter()) {
        // SAFETY: blocks made by CreateAddrAllocMessageA with these
        // lengths, listed once.
        drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(p as *mut u32, words)) });
    }
    sh.released.into_iter().map(|(_, f)| f).collect()
}
