//! The network databases and name lookups: services, protocols, networks
//! and hosts from Roadshow's files in DEVS:Internet/ (parsed once per
//! library open; small built-in tables when a file is missing), and the
//! calls on them: getservbyname/port, getprotobyname/number,
//! getnetbyname/addr, the set/get/end*ent walks, gethostbyaddr, the _r
//! variants, getaddrinfo, freeaddrinfo, gai_strerror, getnameinfo.
//! gethostbyname looks in the hosts file before asking DNS.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::CStr;

use amigaos4::sys::Interface;
use rsnet_core::resolver::{Answer, Ask};
use rsnet_core::sock::{herrno, SockOp};

use super::{errno, inet, opener, shared, HostEnt, Opener, AF_INET};

pub struct Serv {
    name: String,
    aliases: Vec<String>,
    port: u16,
    proto: String,
}

pub struct Proto {
    name: String,
    aliases: Vec<String>,
    num: i32,
}

pub struct NetEnt {
    name: String,
    aliases: Vec<String>,
    net: u32,
}

pub struct Host {
    addr: [u8; 4],
    /// The official name first.
    names: Vec<String>,
}

pub struct Db {
    services: Vec<Serv>,
    protocols: Vec<Proto>,
    networks: Vec<NetEnt>,
    hosts: Vec<Host>,
    /// name_resolution's "domain" line.
    domain: Option<String>,
}

/// The words of each line of `DEVS:Internet/<file>` ('#' starts a
/// comment), or None when the file cannot be read.
pub(crate) fn lines(file: &str) -> Option<Vec<Vec<String>>> {
    let path = alloc::format!("DEVS:Internet/{}", file);
    let data = amigaos4::dos::fs::File::read_to_vec(&path).ok()?;
    let text = String::from_utf8_lossy(&data);
    Some(
        text.lines()
            .map(|l| l.split('#').next().unwrap_or(""))
            .map(|l| l.split_whitespace().map(String::from).collect::<Vec<_>>())
            .filter(|w| !w.is_empty())
            .collect(),
    )
}

fn s(x: &str) -> String {
    String::from(x)
}

impl Db {
    fn load() -> Db {
        let services = match lines("services") {
            Some(ls) => ls
                .into_iter()
                .filter_map(|w| {
                    let (port, proto) = w.get(1)?.split_once('/')?;
                    Some(Serv { name: w[0].clone(), aliases: w[2..].to_vec(), port: port.parse().ok()?, proto: s(proto) })
                })
                .collect(),
            None => [("ftp", 21), ("ssh", 22), ("telnet", 23), ("smtp", 25), ("domain", 53), ("http", 80), ("pop3", 110), ("nntp", 119), ("ntp", 123), ("imap", 143), ("https", 443), ("imaps", 993), ("pop3s", 995)]
                .iter()
                .flat_map(|&(n, p)| ["tcp", "udp"].into_iter().map(move |pr| Serv { name: s(n), aliases: Vec::new(), port: p, proto: s(pr) }))
                .collect(),
        };
        let protocols = match lines("protocols") {
            Some(ls) => ls.into_iter().filter_map(|w| Some(Proto { name: w[0].clone(), num: w.get(1)?.parse().ok()?, aliases: w[2..].to_vec() })).collect(),
            None => [("ip", 0, "IP"), ("icmp", 1, "ICMP"), ("tcp", 6, "TCP"), ("udp", 17, "UDP")].iter().map(|&(n, k, a)| Proto { name: s(n), num: k, aliases: alloc::vec![s(a)] }).collect(),
        };
        let networks = match lines("networks") {
            Some(ls) => ls.into_iter().filter_map(|w| Some(NetEnt { name: w[0].clone(), net: network_number(w.get(1)?)?, aliases: w[2..].to_vec() })).collect(),
            None => alloc::vec![NetEnt { name: s("loopback"), aliases: Vec::new(), net: 127 }],
        };
        let mut hosts: Vec<Host> = lines("hosts")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|w| Some(Host { addr: inet::parse(w[0].as_bytes())?.to_be_bytes(), names: w[1..].to_vec() }))
            .filter(|h| !h.names.is_empty())
            .collect();
        if !hosts.iter().any(|h| h.names.iter().any(|n| n.eq_ignore_ascii_case("localhost"))) {
            hosts.push(Host { addr: [127, 0, 0, 1], names: alloc::vec![s("localhost")] });
        }
        let domain = lines("name_resolution").unwrap_or_default().into_iter().find(|w| w[0] == "domain" && w.len() > 1).map(|w| w[1].clone());
        Db { services, protocols, networks, hosts, domain }
    }

    fn host_by_name(&self, name: &str) -> Option<&Host> {
        self.hosts.iter().find(|h| h.names.iter().any(|n| n.eq_ignore_ascii_case(name)))
    }

    fn host_by_addr(&self, a: [u8; 4]) -> Option<&Host> {
        self.hosts.iter().find(|h| h.addr == a)
    }

    fn serv_by_name(&self, name: &str, proto: Option<&str>) -> Option<&Serv> {
        self.services.iter().find(|x| (x.name == name || x.aliases.iter().any(|a| a == name)) && proto.is_none_or(|p| x.proto == p))
    }

    fn serv_by_port(&self, port: u16, proto: Option<&str>) -> Option<&Serv> {
        self.services.iter().find(|x| x.port == port && proto.is_none_or(|p| x.proto == p))
    }
}

/// A networks-file number: up to four dotted parts, right-aligned
/// (127 = 0x7f, 10.1 = 0x0a01).
fn network_number(t: &str) -> Option<u32> {
    let mut v: u32 = 0;
    for p in t.split('.') {
        v = (v << 8) | p.parse::<u8>().ok()? as u32;
    }
    Some(v)
}

/// `name`'s address from the hosts file (the TCP: handler).
pub fn host_address(name: &str) -> Option<[u8; 4]> {
    db()?.host_by_name(name).map(|h| h.addr)
}

/// A service's port by name (or number) and protocol, for the superserver.
pub fn service_port(name: &str, proto: &str) -> Option<u16> {
    if let Ok(n) = name.parse::<u16>() {
        return Some(n);
    }
    db()?.serv_by_name(name, Some(proto)).map(|s| s.port)
}

/// The databases, loaded at first use (until the library's last Close).
pub fn db() -> Option<Arc<Db>> {
    if let Some(d) = shared::lock()?.db.clone() {
        return Some(d);
    }
    // Read the files with the lock let go of (dos.library calls).
    let d = Arc::new(Db::load());
    let mut sh = shared::lock()?;
    if sh.domain.is_empty() {
        if let Some(dn) = &d.domain {
            sh.domain = dn.clone();
        }
    }
    Some(sh.db.get_or_insert(d).clone())
}

// ---------------------------------------------------------------------------
// Per-opener answers (BSD's static structs, one set per opener)
// ---------------------------------------------------------------------------

/// Strings and pointer arrays an answer points into.
#[derive(Default)]
struct Store {
    strings: Vec<Vec<u8>>,
    lists: Vec<Vec<*const u8>>,
}

impl Store {
    fn clear(&mut self) {
        self.strings.clear();
        self.lists.clear();
    }

    fn str(&mut self, t: &str) -> *const u8 {
        let mut b = t.as_bytes().to_vec();
        b.push(0);
        self.strings.push(b);
        self.strings.last().unwrap().as_ptr()
    }

    /// A NULL-terminated array of `items` as C strings.
    fn list(&mut self, items: &[String]) -> *const *const u8 {
        let mut v: Vec<*const u8> = items.iter().map(|t| self.str(t)).collect();
        v.push(core::ptr::null());
        self.lists.push(v);
        self.lists.last().unwrap().as_ptr()
    }
}

#[repr(C)]
struct ServEnt {
    s_name: *const u8,
    s_aliases: *const *const u8,
    s_port: i32,
    s_proto: *const u8,
}

#[repr(C)]
struct ProtoEnt {
    p_name: *const u8,
    p_aliases: *const *const u8,
    p_proto: i32,
}

#[repr(C)]
struct NetEntC {
    n_name: *const u8,
    n_aliases: *const *const u8,
    n_addrtype: i32,
    n_net: u32,
}

/// One opener's answers and its *ent walk positions.
pub struct Local {
    serv: ServEnt,
    serv_store: Store,
    proto: ProtoEnt,
    proto_store: Store,
    net: NetEntC,
    net_store: Store,
    serv_at: usize,
    proto_at: usize,
    net_at: usize,
}

impl Local {
    pub fn new() -> Local {
        Local {
            serv: ServEnt { s_name: core::ptr::null(), s_aliases: core::ptr::null(), s_port: 0, s_proto: core::ptr::null() },
            serv_store: Store::default(),
            proto: ProtoEnt { p_name: core::ptr::null(), p_aliases: core::ptr::null(), p_proto: 0 },
            proto_store: Store::default(),
            net: NetEntC { n_name: core::ptr::null(), n_aliases: core::ptr::null(), n_addrtype: AF_INET, n_net: 0 },
            net_store: Store::default(),
            serv_at: 0,
            proto_at: 0,
            net_at: 0,
        }
    }

    fn put_serv(&mut self, x: &Serv) -> *mut u8 {
        self.serv_store.clear();
        self.serv = ServEnt {
            s_name: self.serv_store.str(&x.name),
            s_aliases: self.serv_store.list(&x.aliases),
            s_port: x.port as i32,
            s_proto: self.serv_store.str(&x.proto),
        };
        &mut self.serv as *mut ServEnt as *mut u8
    }

    fn put_proto(&mut self, x: &Proto) -> *mut u8 {
        self.proto_store.clear();
        self.proto = ProtoEnt { p_name: self.proto_store.str(&x.name), p_aliases: self.proto_store.list(&x.aliases), p_proto: x.num };
        &mut self.proto as *mut ProtoEnt as *mut u8
    }

    fn put_net(&mut self, x: &NetEnt) -> *mut u8 {
        self.net_store.clear();
        self.net = NetEntC { n_name: self.net_store.str(&x.name), n_aliases: self.net_store.list(&x.aliases), n_addrtype: AF_INET, n_net: x.net };
        &mut self.net as *mut NetEntC as *mut u8
    }
}

fn local(o: &mut Opener) -> &mut Local {
    // SAFETY: the opener's Local, made with it and freed with it.
    unsafe { &mut *o.netdb }
}

/// A C string argument (None for NULL or non-UTF-8).
fn arg<'a>(p: *const u8) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller's NUL-terminated string.
    core::str::from_utf8(unsafe { CStr::from_ptr(p as *const core::ffi::c_char) }.to_bytes()).ok()
}

#[no_mangle]
pub extern "C" fn rs_getservbyname(i: *mut Interface, name: *const u8, proto: *const u8) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let (Some(name), Some(d)) = (arg(name), db()) else { return core::ptr::null_mut() };
    match d.serv_by_name(name, arg(proto)) {
        Some(x) => local(o).put_serv(x),
        None => core::ptr::null_mut(),
    }
}

/// getservbyport(port, proto): `port` in network order (the plain value
/// on this CPU).
#[no_mangle]
pub extern "C" fn rs_getservbyport(i: *mut Interface, port: i32, proto: *const u8) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Some(d) = db() else { return core::ptr::null_mut() };
    match d.serv_by_port(port as u16, arg(proto)) {
        Some(x) => local(o).put_serv(x),
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_getprotobyname(i: *mut Interface, name: *const u8) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let (Some(name), Some(d)) = (arg(name), db()) else { return core::ptr::null_mut() };
    match d.protocols.iter().find(|x| x.name.eq_ignore_ascii_case(name) || x.aliases.iter().any(|a| a.eq_ignore_ascii_case(name))) {
        Some(x) => local(o).put_proto(x),
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_getprotobynumber(i: *mut Interface, num: i32) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Some(d) = db() else { return core::ptr::null_mut() };
    match d.protocols.iter().find(|x| x.num == num) {
        Some(x) => local(o).put_proto(x),
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_getnetbyname(i: *mut Interface, name: *const u8) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let (Some(name), Some(d)) = (arg(name), db()) else { return core::ptr::null_mut() };
    match d.networks.iter().find(|x| x.name.eq_ignore_ascii_case(name) || x.aliases.iter().any(|a| a.eq_ignore_ascii_case(name))) {
        Some(x) => local(o).put_net(x),
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_getnetbyaddr(i: *mut Interface, net: u32, kind: i32) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Some(d) = db() else { return core::ptr::null_mut() };
    if kind != AF_INET {
        return core::ptr::null_mut();
    }
    match d.networks.iter().find(|x| x.net == net) {
        Some(x) => local(o).put_net(x),
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_setservent(i: *mut Interface, _stayopen: i32) {
    if let Some(o) = opener(i) {
        local(o).serv_at = 0;
    }
}

#[no_mangle]
pub extern "C" fn rs_endservent(i: *mut Interface) {
    if let Some(o) = opener(i) {
        local(o).serv_at = 0;
    }
}

#[no_mangle]
pub extern "C" fn rs_getservent(i: *mut Interface) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Some(d) = db() else { return core::ptr::null_mut() };
    let l = local(o);
    match d.services.get(l.serv_at) {
        Some(x) => {
            l.serv_at += 1;
            l.put_serv(x)
        }
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_setprotoent(i: *mut Interface, _stayopen: i32) {
    if let Some(o) = opener(i) {
        local(o).proto_at = 0;
    }
}

#[no_mangle]
pub extern "C" fn rs_endprotoent(i: *mut Interface) {
    if let Some(o) = opener(i) {
        local(o).proto_at = 0;
    }
}

#[no_mangle]
pub extern "C" fn rs_getprotoent(i: *mut Interface) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Some(d) = db() else { return core::ptr::null_mut() };
    let l = local(o);
    match d.protocols.get(l.proto_at) {
        Some(x) => {
            l.proto_at += 1;
            l.put_proto(x)
        }
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_setnetent(i: *mut Interface, _stayopen: i32) {
    if let Some(o) = opener(i) {
        local(o).net_at = 0;
    }
}

#[no_mangle]
pub extern "C" fn rs_endnetent(i: *mut Interface) {
    if let Some(o) = opener(i) {
        local(o).net_at = 0;
    }
}

#[no_mangle]
pub extern "C" fn rs_getnetent(i: *mut Interface) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Some(d) = db() else { return core::ptr::null_mut() };
    let l = local(o);
    match d.networks.get(l.net_at) {
        Some(x) => {
            l.net_at += 1;
            l.put_net(x)
        }
        None => core::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

/// A DNS lookup in the stack (resolver.rs). The error is an h_errno, with
/// the break signals that interrupted the wait.
fn resolve(o: &mut Opener, ask: Ask) -> Result<Answer, (i32, u32)> {
    let op = SockOp::Resolve { ask, state: Default::default(), result: Err(0) };
    match o.run_hit(false, op) {
        Some((SockOp::Resolve { result: Ok(a), .. }, _)) => Ok(a),
        Some((SockOp::Resolve { result: Err(h), .. }, hit)) => Err((h, hit)),
        _ => Err((herrno::NO_RECOVERY, 0)),
    }
}

/// A hosts-file entry as an answer: its first name official and no aliases
/// (Roadshow lists none for "127.1 localhost localhost.my.domain", by name
/// or by address: hostprobe, revprobe).
fn host_answer(h: &Host) -> Answer {
    Answer { name: h.names[0].clone(), aliases: Vec::new(), addrs: alloc::vec![h.addr] }
}

/// `name`'s official name, aliases and addresses: a dotted address is
/// itself, then the hosts file, then DNS (every address, the canonical
/// name with the asked one as an alias, as Roadshow's resolver: hostprobe)
/// through name_resolution's search list.
pub fn lookup_name(o: &mut Opener, name: &str) -> Result<Answer, (i32, u32)> {
    if let Some(a) = inet::parse(name.as_bytes()) {
        return Ok(Answer { name: String::from(name), aliases: Vec::new(), addrs: alloc::vec![a.to_be_bytes()] });
    }
    if let Some(h) = db().as_ref().and_then(|d| d.host_by_name(name).map(host_answer)) {
        return Ok(h);
    }
    search(o, name)
}

/// BSD's res_search with ndots 1, as Roadshow answers:
/// a name ending in a dot as it is; a name with a dot as it is first, then
/// with each search domain; a name without one with each search domain
/// first, then as it is. The h_errno when all fail: the as-it-is one's
/// when that came first, else NO_DATA if any domain had the name without
/// an address, else TRY_AGAIN if any server failed, else the last one's.
fn search(o: &mut Opener, name: &str) -> Result<Answer, (i32, u32)> {
    if let Some(n) = name.strip_suffix('.') {
        return resolve(o, Ask::Name(String::from(n)));
    }
    let list = shared::lock().map(|sh| sh.search.clone()).unwrap_or_default();
    let dots = name.matches('.').count();
    let (mut saved, mut tried, mut nodata, mut servfail, mut last) = (None, false, false, false, herrno::HOST_NOT_FOUND);
    if dots >= 1 || list.is_empty() {
        match resolve(o, Ask::Name(String::from(name))) {
            Ok(a) => return Ok(a),
            Err((h, hit)) if hit != 0 => return Err((h, hit)),
            Err((h, _)) => {
                saved = Some(h);
                last = h;
                tried = true;
            }
        }
    }
    for d in &list {
        match resolve(o, Ask::Name(alloc::format!("{}.{}", name, d))) {
            Ok(a) => return Ok(a),
            Err((h, hit)) if hit != 0 => return Err((h, hit)),
            Err((h, _)) => {
                last = h;
                match h {
                    herrno::NO_DATA => nodata = true,
                    herrno::HOST_NOT_FOUND => {}
                    herrno::TRY_AGAIN => servfail = true,
                    _ => break,
                }
            }
        }
    }
    if !tried {
        match resolve(o, Ask::Name(String::from(name))) {
            Ok(a) => return Ok(a),
            Err((h, hit)) if hit != 0 => return Err((h, hit)),
            Err((h, _)) => last = h,
        }
    }
    let h = match saved {
        Some(h) => h,
        None if nodata => herrno::NO_DATA,
        None if servfail => herrno::TRY_AGAIN,
        None => last,
    };
    Err((h, 0))
}

/// `name`'s first address and official name (lookup_name).
pub fn lookup_host(o: &mut Opener, name: &str) -> Result<([u8; 4], String), (i32, u32)> {
    lookup_name(o, name).map(|a| (a.addrs[0], a.name))
}

/// `a`'s name: the hosts file, else DNS (a PTR query, as Roadshow's
/// resolver asks: revprobe.c); the error is an h_errno value.
fn name_of(o: &mut Opener, a: [u8; 4]) -> Result<Answer, i32> {
    if let Some(h) = db().as_ref().and_then(|d| d.host_by_addr(a).map(host_answer)) {
        return Ok(h);
    }
    resolve(o, Ask::Addr(a)).map_err(|e| e.0)
}

/// gethostbyaddr(addr, len, type): from the hosts file, else DNS; else
/// NULL with the lookup's h_errno.
#[no_mangle]
pub extern "C" fn rs_gethostbyaddr(i: *mut Interface, addr: *const u8, len: i32, kind: i32) -> *mut HostEnt {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    if addr.is_null() || len != 4 || kind != AF_INET {
        o.set_herrno(herrno::HOST_NOT_FOUND);
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's 4-byte address.
    let a = unsafe { [*addr, *addr.add(1), *addr.add(2), *addr.add(3)] };
    match name_of(o, a) {
        // h_errno stays as it was: Roadshow leaves it alone on success
        // (revprobe: 1 from the lookup before, after 127.0.0.1's hit).
        Ok(n) => {
            // SAFETY: the opener's hostent, made with it.
            unsafe { (*o.host).set_answer(&n) }
        }
        Err(h) => {
            o.set_herrno(h);
            core::ptr::null_mut()
        }
    }
}

/// Fill the caller's hostent with `name` and `a`, its pointers into
/// `buf` (len bytes): the address, the address list, the alias list, the
/// name. False when it does not fit.
/// Fill the caller's struct hostent from `a`, everything it points at in
/// `buf` (the addresses, the address and alias lists, the names); false
/// when `len` bytes are too few.
fn fill_hostent(he: *mut u8, buf: *mut u8, len: u32, a: &Answer) -> bool {
    let (na, nl) = (a.addrs.len(), a.aliases.len());
    let names: usize = a.name.len() + 1 + a.aliases.iter().map(|x| x.len() + 1).sum::<usize>();
    let need = 4 * na + 4 * (na + 1) + 4 * (nl + 1) + names;
    if he.is_null() || buf.is_null() || (len as usize) < need {
        return false;
    }
    // SAFETY: the caller's struct hostent (5 words) and buffer of `len`
    // >= need bytes; the pointer arrays are written unaligned.
    unsafe {
        let addrs = buf;
        let list = buf.add(4 * na) as *mut *const u8;
        let aliases = buf.add(4 * na + 4 * (na + 1)) as *mut *const u8;
        let mut text = buf.add(4 * na + 4 * (na + 1) + 4 * (nl + 1));
        for (k, x) in a.addrs.iter().enumerate() {
            core::ptr::copy_nonoverlapping(x.as_ptr(), addrs.add(4 * k), 4);
            core::ptr::write_unaligned(list.add(k), addrs.add(4 * k) as *const u8);
        }
        core::ptr::write_unaligned(list.add(na), core::ptr::null());
        let mut put = |s: &str| {
            let at = text;
            core::ptr::copy_nonoverlapping(s.as_ptr(), at, s.len());
            *at.add(s.len()) = 0;
            text = at.add(s.len() + 1);
            at
        };
        let name = put(&a.name);
        for (k, x) in a.aliases.iter().enumerate() {
            let p = put(x);
            core::ptr::write_unaligned(aliases.add(k), p as *const u8);
        }
        core::ptr::write_unaligned(aliases.add(nl), core::ptr::null());
        let w = he as *mut u32;
        core::ptr::write_unaligned(w, name as u32);
        core::ptr::write_unaligned(w.add(1), aliases as u32);
        core::ptr::write_unaligned(w.add(2), AF_INET as u32);
        core::ptr::write_unaligned(w.add(3), 4);
        core::ptr::write_unaligned(w.add(4), list as u32);
    }
    true
}

fn set_herr(p: *mut i32, v: i32) {
    if !p.is_null() {
        // SAFETY: the caller's int.
        unsafe { *p = v };
    }
}

const ERANGE: i32 = 34;
const NETDB_INTERNAL: i32 = -1;

/// gethostbyname_r(name, hostent, buffer, buflen, h_errnop).
#[no_mangle]
pub extern "C" fn rs_gethostbyname_r(i: *mut Interface, name: *const u8, he: *mut u8, buf: *mut u8, len: u32, herr: *mut i32) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    let Some(n) = arg(name) else {
        set_herr(herr, herrno::HOST_NOT_FOUND);
        return core::ptr::null_mut();
    };
    match lookup_name(o, n) {
        Ok(ans) => {
            if fill_hostent(he, buf, len, &ans) {
                set_herr(herr, 0);
                he
            } else {
                o.set_errno(ERANGE);
                set_herr(herr, NETDB_INTERNAL);
                core::ptr::null_mut()
            }
        }
        Err((h, hit)) => {
            if hit != 0 {
                o.set_errno(errno::EINTR);
            }
            set_herr(herr, h);
            core::ptr::null_mut()
        }
    }
}

/// gethostbyaddr_r(addr, len, type, hostent, buffer, buflen, h_errnop):
/// as gethostbyaddr.
#[no_mangle]
pub extern "C" fn rs_gethostbyaddr_r(i: *mut Interface, addr: *const u8, alen: i32, kind: i32, he: *mut u8, buf: *mut u8, len: u32, herr: *mut i32) -> *mut u8 {
    let Some(o) = opener(i) else { return core::ptr::null_mut() };
    if addr.is_null() || alen != 4 || kind != AF_INET {
        set_herr(herr, herrno::HOST_NOT_FOUND);
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's 4-byte address.
    let a = unsafe { [*addr, *addr.add(1), *addr.add(2), *addr.add(3)] };
    match name_of(o, a) {
        Ok(n) if fill_hostent(he, buf, len, &n) => {
            set_herr(herr, 0);
            he
        }
        Ok(_) => {
            o.set_errno(ERANGE);
            set_herr(herr, NETDB_INTERNAL);
            core::ptr::null_mut()
        }
        Err(h) => {
            set_herr(herr, h);
            core::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// getaddrinfo and friends
// ---------------------------------------------------------------------------

const AI_PASSIVE: i32 = 1;
const AI_CANONNAME: i32 = 2;
const AI_NUMERICHOST: i32 = 4;
const AI_NUMERICSERV: i32 = 16;
const AI_MASK: i32 = AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | 8 | AI_NUMERICSERV;
const NI_NUMERICHOST: u32 = 1;
const NI_NUMERICSERV: u32 = 2;
const NI_NOFQDN: u32 = 4;
const NI_NAMEREQD: u32 = 8;
const NI_DGRAM: u32 = 16;

const EAI_BADFLAGS: i32 = -1;
const EAI_NONAME: i32 = -2;
const EAI_AGAIN: i32 = -3;
const EAI_FAIL: i32 = -4;
const EAI_FAMILY: i32 = -6;
const EAI_SOCKTYPE: i32 = -7;
const EAI_SERVICE: i32 = -8;
const EAI_MEMORY: i32 = -10;
const EAI_SYSTEM: i32 = -11;

const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;

/// struct addrinfo (netdb.h).
#[repr(C)]
pub struct AddrInfo {
    ai_flags: i32,
    ai_family: i32,
    ai_socktype: i32,
    ai_protocol: i32,
    ai_addrlen: u32,
    ai_addr: *mut u8,
    ai_canonname: *mut u8,
    ai_next: *mut AddrInfo,
}

/// One answer as allocated: the addrinfo first, so its address is the
/// node's.
#[repr(C)]
struct AiNode {
    ai: AddrInfo,
    sa: [u8; 16],
    name: [u8; 256],
}

/// getaddrinfo(node, service, hints, res): IPv4 answers (one per socket
/// type asked for, or TCP and UDP when none is), from a dotted address,
/// the hosts file or DNS, and a port number or a services-file name.
#[no_mangle]
pub extern "C" fn rs_getaddrinfo(i: *mut Interface, node: *const u8, service: *const u8, hints: *const AddrInfo, res: *mut *mut AddrInfo) -> i32 {
    let Some(o) = opener(i) else { return EAI_SYSTEM };
    if res.is_null() {
        return EAI_SYSTEM;
    }
    // SAFETY: the caller's result pointer.
    unsafe { *res = core::ptr::null_mut() };
    let (flags, family, socktype, protocol) = if hints.is_null() {
        (0, 0, 0, 0)
    } else {
        // SAFETY: the caller's hints.
        let h = unsafe { &*hints };
        (h.ai_flags, h.ai_family, h.ai_socktype, h.ai_protocol)
    };
    if flags & !AI_MASK != 0 {
        return EAI_BADFLAGS;
    }
    if family != 0 && family != AF_INET {
        return EAI_FAMILY;
    }
    let kinds: Vec<(i32, i32)> = match (socktype, protocol) {
        (0, 0) => alloc::vec![(SOCK_STREAM, IPPROTO_TCP), (SOCK_DGRAM, IPPROTO_UDP)],
        (0, IPPROTO_TCP) | (SOCK_STREAM, 0 | IPPROTO_TCP) => alloc::vec![(SOCK_STREAM, IPPROTO_TCP)],
        (0, IPPROTO_UDP) | (SOCK_DGRAM, 0 | IPPROTO_UDP) => alloc::vec![(SOCK_DGRAM, IPPROTO_UDP)],
        (SOCK_STREAM | SOCK_DGRAM, _) => return EAI_SERVICE,
        _ => return EAI_SOCKTYPE,
    };
    let (node, service) = (arg(node), arg(service));
    if node.is_none() && service.is_none() {
        return EAI_NONAME;
    }
    // The port of each kind.
    let mut ports: Vec<(i32, i32, u16)> = Vec::new();
    for &(st, pr) in &kinds {
        let port = match service {
            None => 0,
            Some(sv) => match sv.parse::<u16>() {
                Ok(p) => p,
                Err(_) if flags & AI_NUMERICSERV != 0 => return EAI_NONAME,
                Err(_) => {
                    let proto = if st == SOCK_STREAM { "tcp" } else { "udp" };
                    match db().and_then(|d| d.serv_by_name(sv, Some(proto)).map(|x| x.port)) {
                        Some(p) => p,
                        None => continue,
                    }
                }
            },
        };
        ports.push((st, pr, port));
    }
    if ports.is_empty() {
        return EAI_SERVICE;
    }
    let (addr, canon) = match node {
        None => (if flags & AI_PASSIVE != 0 { [0; 4] } else { [127, 0, 0, 1] }, String::new()),
        Some(n) => match inet::parse(n.as_bytes()) {
            Some(a) => (a.to_be_bytes(), String::from(n)),
            None if flags & AI_NUMERICHOST != 0 => return EAI_NONAME,
            None => match lookup_host(o, n) {
                Ok(x) => x,
                Err((h, hit)) => {
                    if hit != 0 {
                        o.set_errno(errno::EINTR);
                        return EAI_SYSTEM;
                    }
                    return match h {
                        herrno::HOST_NOT_FOUND => EAI_NONAME,
                        herrno::TRY_AGAIN => EAI_AGAIN,
                        _ => EAI_FAIL,
                    };
                }
            },
        },
    };
    // Build the list back to front.
    let mut head: *mut AddrInfo = core::ptr::null_mut();
    for (k, &(st, pr, port)) in ports.iter().enumerate().rev() {
        let mut node = Box::new(AiNode {
            ai: AddrInfo { ai_flags: flags, ai_family: AF_INET, ai_socktype: st, ai_protocol: pr, ai_addrlen: 16, ai_addr: core::ptr::null_mut(), ai_canonname: core::ptr::null_mut(), ai_next: head },
            sa: [0; 16],
            name: [0; 256],
        });
        node.sa[0] = 16;
        node.sa[1] = AF_INET as u8;
        node.sa[2..4].copy_from_slice(&port.to_be_bytes());
        node.sa[4..8].copy_from_slice(&addr);
        node.ai.ai_addr = node.sa.as_mut_ptr();
        // The canonical name goes on the first answer only.
        if k == 0 && flags & AI_CANONNAME != 0 && !canon.is_empty() {
            let n = canon.len().min(255);
            node.name[..n].copy_from_slice(&canon.as_bytes()[..n]);
            node.ai.ai_canonname = node.name.as_mut_ptr();
        }
        head = Box::into_raw(node) as *mut AddrInfo;
    }
    // SAFETY: the caller's result pointer.
    unsafe { *res = head };
    0
}

/// freeaddrinfo(ai): frees a list getaddrinfo made.
#[no_mangle]
pub extern "C" fn rs_freeaddrinfo(_i: *mut Interface, mut ai: *mut AddrInfo) {
    while !ai.is_null() {
        // SAFETY: a node getaddrinfo made with Box (the addrinfo is the
        // AiNode's first field), freed once.
        let node = unsafe { Box::from_raw(ai as *mut AiNode) };
        ai = node.ai.ai_next;
    }
}

/// gai_strerror(code): its message.
#[no_mangle]
pub extern "C" fn rs_gai_strerror(_i: *mut Interface, code: i32) -> *const u8 {
    let t: &'static [u8] = match code {
        0 => b"Success\0",
        EAI_BADFLAGS => b"Invalid value for ai_flags\0",
        EAI_NONAME => b"Name or service is not known\0",
        EAI_AGAIN => b"Temporary failure in name resolution\0",
        EAI_FAIL => b"Non-recoverable failure in name resolution\0",
        -5 => b"No address associated with name\0",
        EAI_FAMILY => b"ai_family not supported\0",
        EAI_SOCKTYPE => b"ai_socktype not supported\0",
        EAI_SERVICE => b"Service not supported for ai_socktype\0",
        -9 => b"Address family for name not supported\0",
        EAI_MEMORY => b"Memory allocation failure\0",
        EAI_SYSTEM => b"System error returned in errno\0",
        -12 => b"Invalid value for hints\0",
        -13 => b"Resolved protocol is unknown\0",
        _ => b"Unknown error\0",
    };
    t.as_ptr()
}

/// Copy `t` NUL-terminated into `out` (room `len`): false when it does
/// not fit.
fn put_str(out: *mut u8, len: u32, t: &str) -> bool {
    if t.len() + 1 > len as usize {
        return false;
    }
    // SAFETY: the caller's buffer of len >= t.len() + 1 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(t.as_ptr(), out, t.len());
        *out.add(t.len()) = 0;
    }
    true
}

/// getnameinfo(sa, salen, host, hostlen, serv, servlen, flags): names from
/// the hosts and services files, numbers otherwise.
#[no_mangle]
pub extern "C" fn rs_getnameinfo(i: *mut Interface, sa: *const u8, salen: u32, host: *mut u8, hostlen: u32, serv: *mut u8, servlen: u32, flags: u32) -> i32 {
    let Some(o) = opener(i) else { return EAI_SYSTEM };
    let Some((a, port)) = super::sockaddr_in(sa, salen) else { return EAI_FAMILY };
    if !host.is_null() && hostlen > 0 {
        let dotted = || alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
        let name = if flags & NI_NUMERICHOST != 0 {
            dotted()
        } else {
            match name_of(o, a) {
                Ok(n) if flags & NI_NOFQDN != 0 => String::from(n.name.split('.').next().unwrap_or(&n.name)),
                Ok(n) => n.name,
                Err(_) if flags & NI_NAMEREQD != 0 => return EAI_NONAME,
                Err(_) => dotted(),
            }
        };
        if !put_str(host, hostlen, &name) {
            return EAI_MEMORY;
        }
    }
    if !serv.is_null() && servlen > 0 {
        let proto = if flags & NI_DGRAM != 0 { "udp" } else { "tcp" };
        let name = if flags & NI_NUMERICSERV != 0 {
            None
        } else {
            db().and_then(|d| d.serv_by_port(port, Some(proto)).map(|x| x.name.clone()))
        };
        let name = name.unwrap_or_else(|| alloc::format!("{}", port));
        if !put_str(serv, servlen, &name) {
            return EAI_MEMORY;
        }
    }
    0
}
