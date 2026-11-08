//! `rstcp iface [library]`: the run-time interface API on a third
//! virtio-net card (virtionet.device unit 2, on a QEMU user network of its
//! own, 10.0.5.0/24: DHCP server and router 10.0.5.2, DNS 10.0.5.3), which
//! no other interface may have open. Adds interface
//! "t2" on it, runs DHCP for it through an address allocation message,
//! sets an address by hand, watches the address-change signal, removes the
//! interface and adds it back, and checks the refusals.

use alloc::vec::Vec;
use core::ffi::c_void;

use amigaos4::bsdsocket::SocketLib;
use amigaos4::port::AmigaMsgPort;
use amigaos4::sys::{SocketIFace, TagItem, TAG_DONE, TAG_USER};
use amigaos4::timer::{Waited, Waiter};

use super::Tally;

const IFC_BASE: u32 = TAG_USER + 1800;
const IFC_ADDRESS: u32 = IFC_BASE + 1;
const IFC_NET_MASK: u32 = IFC_BASE + 2;
const IFC_RELEASE_ADDRESS: u32 = IFC_BASE + 14;
const CAAMTA_BASE: u32 = TAG_USER + 2000;
const CAAMTA_TIMEOUT: u32 = CAAMTA_BASE + 1;
const CAAMTA_ROUTER_TABLE_SIZE: u32 = CAAMTA_BASE + 6;
const CAAMTA_DNS_TABLE_SIZE: u32 = CAAMTA_BASE + 7;
const CAAMTA_RECORD_LEASE_EXPIRATION: u32 = CAAMTA_BASE + 12;
const CAAMTA_REPLY_PORT: u32 = CAAMTA_BASE + 13;
const IFQ_ADDRESS: u32 = TAG_USER + 1900 + 14;
const SIG_ADDRESS_CHANGE_MASK: u32 = 57;
const RTA_BASE: u32 = TAG_USER + 1600;
const RTA_GATEWAY: u32 = RTA_BASE + 2;
const RTA_DESTINATION_HOST: u32 = RTA_BASE + 4;
const RTF_HOST: i32 = 4;

/// Offsets in struct AddressAllocationMessage (rsnet-core aam.rs).
pub(super) const AAM_RESULT: usize = 24;
const AAM_VERSION: usize = 28;
pub(super) const AAM_ADDRESS: usize = 68;
const AAM_SUBNET_MASK: usize = 76;
const AAM_ROUTER_TABLE: usize = 88;
const AAM_DNS_TABLE: usize = 96;
const AAM_LEASE_EXPIRES: usize = 136;

pub(super) const AAMR_SUCCESS: i32 = 0;
const AAMR_ABORTED: i32 = 1;
const AAMR_ADDRESS_KNOWN: i32 = 4;
const AAMR_VERSION_UNKNOWN: i32 = 5;

pub(super) fn get(m: usize, o: usize) -> u32 {
    // SAFETY: inside the library's message block (142 bytes and more).
    unsafe { core::ptr::read_unaligned((m + o) as *const u32) }
}

pub(super) fn errno(i: *mut SocketIFace) -> i32 {
    // SAFETY: a plain call.
    unsafe { ((*i).Errno)(i) }
}

fn configure(i: *mut SocketIFace, tags: &[(u32, u32)]) -> i32 {
    let mut t: Vec<TagItem> = tags.iter().map(|&(a, b)| TagItem { ti_Tag: a, ti_Data: b }).collect();
    t.push(TagItem { ti_Tag: TAG_DONE, ti_Data: 0 });
    // SAFETY: a NUL-terminated name and a TAG_DONE-ended list.
    unsafe { ((*i).ConfigureInterfaceTagList)(i, b"t2\0".as_ptr() as *mut u8, t.as_mut_ptr()) }
}

/// t2's address from QueryInterfaceTagList (0.0.0.0 when it has none).
fn query_address(i: *mut SocketIFace) -> Option<[u8; 4]> {
    let mut sa = [0u8; 16];
    let mut t = [TagItem { ti_Tag: IFQ_ADDRESS, ti_Data: sa.as_mut_ptr() as u32 }, TagItem { ti_Tag: TAG_DONE, ti_Data: 0 }];
    // SAFETY: a 16-byte sockaddr for IFQ_Address.
    let r = unsafe { ((*i).QueryInterfaceTagList)(i, b"t2\0".as_ptr() as *mut u8, t.as_mut_ptr()) };
    (r == 0).then(|| [sa[4], sa[5], sa[6], sa[7]])
}

/// A DHCP message for t2 replying to `port`: (CAAME code, message).
pub(super) fn create(i: *mut SocketIFace, version: i32, name: &[u8], port: &AmigaMsgPort) -> (i32, usize) {
    let mut m: usize = 0;
    let mut t = [
        TagItem { ti_Tag: CAAMTA_TIMEOUT, ti_Data: 15 },
        TagItem { ti_Tag: CAAMTA_ROUTER_TABLE_SIZE, ti_Data: 4 },
        TagItem { ti_Tag: CAAMTA_DNS_TABLE_SIZE, ti_Data: 4 },
        TagItem { ti_Tag: CAAMTA_RECORD_LEASE_EXPIRATION, ti_Data: 1 },
        TagItem { ti_Tag: CAAMTA_REPLY_PORT, ti_Data: port.as_ptr() as u32 },
        TagItem { ti_Tag: TAG_DONE, ti_Data: 0 },
    ];
    // SAFETY: a NUL-terminated name, a result pointer and a tag list.
    let r = unsafe { ((*i).CreateAddrAllocMessageA)(i, version, 1, name.as_ptr() as *mut u8, &mut m as *mut usize as *mut *mut c_void, t.as_mut_ptr()) };
    (r, m)
}

/// Wait up to `ms` for the message to come back to `port`.
pub(super) fn wait_reply(port: &AmigaMsgPort, timer: &mut Waiter, m: usize, ms: u32) -> bool {
    let t0 = super::us();
    loop {
        if let Some(r) = port.get_raw() {
            if r as usize == m {
                return true;
            }
        }
        let left = ms as u64 * 1000;
        let spent = super::us() - t0;
        if spent >= left {
            return false;
        }
        if let Ok(Waited::TimedOut) = timer.wait_ms(port.signal_mask(), ((left - spent) / 1000).max(1) as u32) {
            return port.get_raw().map(|r| r as usize == m).unwrap_or(false);
        }
    }
}

/// The name servers ObtainDomainNameServerList lists: (address, use count).
fn name_servers(i: *mut SocketIFace) -> Vec<(alloc::string::String, i32)> {
    let mut v = Vec::new();
    // SAFETY: a plain call; the list is walked read-only (exec List: lh_Head
    // at 0; nodes: ln_Succ at 0, dnsn_Address at 12, dnsn_UseCount at 16)
    // and given back.
    unsafe {
        let l = ((*i).ObtainDomainNameServerList)(i) as *mut u8;
        if l.is_null() {
            return v;
        }
        let mut n = *(l as *const usize) as *const u8;
        while !(*(n as *const usize) == 0) {
            let a = *(n.add(12) as *const *const u8);
            let c = *(n.add(16) as *const i32);
            let text = core::ffi::CStr::from_ptr(a as *const core::ffi::c_char).to_string_lossy().into_owned();
            v.push((text, c));
            n = *(n as *const usize) as *const u8;
        }
        ((*i).ReleaseDomainNameServerList)(i, l as *mut _);
    }
    v
}

fn route_call(i: *mut SocketIFace, which: u8, tags: &[(u32, u32)]) -> i32 {
    let mut t: Vec<TagItem> = tags.iter().map(|&(a, b)| TagItem { ti_Tag: a, ti_Data: b }).collect();
    t.push(TagItem { ti_Tag: TAG_DONE, ti_Data: 0 });
    // SAFETY: a TAG_DONE-ended list of NUL-terminated strings.
    unsafe {
        match which {
            b'a' => ((*i).AddRouteTagList)(i, t.as_mut_ptr()),
            b'c' => ((*i).ChangeRouteTagList)(i, t.as_mut_ptr()),
            _ => ((*i).DeleteRouteTagList)(i, t.as_mut_ptr()),
        }
    }
}

/// GetRouteInfo(AF_INET, flags): (destination, gateway, flags) of each entry
/// (Roadshow's rt_msghdr: msglen at 0, flags at 6, rtm_addrs at 10, the
/// sockaddrs from 74 on: destination, gateway when RTA_GATEWAY is set).
fn route_table(i: *mut SocketIFace, flags: i32) -> Option<Vec<([u8; 4], [u8; 4], u32)>> {
    let mut v = Vec::new();
    // SAFETY: the table GetRouteInfo hands out, read and given back.
    unsafe {
        let base = ((*i).GetRouteInfo)(i, 2, flags) as *const u8;
        if base.is_null() {
            return None;
        }
        let mut e = base;
        loop {
            let len = u16::from_be_bytes([*e, *e.add(1)]) as usize;
            if len == 0 {
                break;
            }
            let f = u32::from_be_bytes([*e.add(6), *e.add(7), *e.add(8), *e.add(9)]);
            let addrs = u32::from_be_bytes([*e.add(10), *e.add(11), *e.add(12), *e.add(13)]);
            let sa = e.add(74);
            let dst = [*sa.add(4), *sa.add(5), *sa.add(6), *sa.add(7)];
            let gw = if addrs & 2 != 0 { [*sa.add(20), *sa.add(21), *sa.add(22), *sa.add(23)] } else { [0; 4] };
            v.push((dst, gw, f));
            e = e.add(len);
        }
        ((*i).FreeRouteInfo)(i, base as *mut c_void);
    }
    Some(v)
}

const SIOCGIFCONF: u32 = 0xC0086924;
const SIOCGIFADDR: u32 = 0xC0206921;
const SIOCGIFNETMASK: u32 = 0xC0206925;
const SIOCGIFFLAGS: u32 = 0xC0206911;
const SIOCSIFADDR: u32 = 0x8020690C;
const SIOCSIFFLAGS: u32 = 0x80206910;
const SIOCDIFADDR: u32 = 0x80206919;

fn ifreq(name: &[u8]) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..name.len()].copy_from_slice(name);
    r
}

/// The interface ioctls on t2 (address 10.0.5.99/24 at this point).
fn ioctls(i: *mut SocketIFace, t: &mut Tally) {
    // SAFETY: plain calls on a UDP socket; ifreq/ifconf buffers of their
    // sizes.
    unsafe {
        let s = ((*i).socket)(i, 2, 2, 0);
        let mut buf = [0u8; 32 * 8];
        let mut conf = [buf.len() as u32, buf.as_mut_ptr() as u32];
        let r = ((*i).IoctlSocket)(i, s, SIOCGIFCONF, conf.as_mut_ptr() as *mut c_void);
        let n = conf[0] as usize / 32;
        let names: Vec<alloc::string::String> = (0..n)
            .map(|k| {
                let e = &buf[k * 32..k * 32 + 16];
                alloc::string::String::from_utf8_lossy(&e[..e.iter().position(|&b| b == 0).unwrap_or(16)]).into_owned()
            })
            .collect();
        t.check(r == 0 && names.iter().any(|x| x == "t2") && names.iter().any(|x| x == "lo0"), format_args!("ioctl: SIOCGIFCONF {} lists {:?}", r, names));
        let mut q = ifreq(b"t2");
        let r1 = ((*i).IoctlSocket)(i, s, SIOCGIFADDR, q.as_mut_ptr() as *mut c_void);
        let a = [q[20], q[21], q[22], q[23]];
        let mut q2 = ifreq(b"t2");
        let r2 = ((*i).IoctlSocket)(i, s, SIOCGIFNETMASK, q2.as_mut_ptr() as *mut c_void);
        let m = [q2[20], q2[21], q2[22], q2[23]];
        let mut q3 = ifreq(b"t2");
        let r3 = ((*i).IoctlSocket)(i, s, SIOCGIFFLAGS, q3.as_mut_ptr() as *mut c_void);
        let fl = u16::from_be_bytes([q3[16], q3[17]]);
        t.check(
            r1 == 0 && a == [10, 0, 5, 99] && r2 == 0 && m == [255, 255, 255, 0] && r3 == 0 && fl & 0x3 == 0x3,
            format_args!("ioctl: SIOCGIFADDR {:?}, SIOCGIFNETMASK {:?}, SIOCGIFFLAGS {:#x}", a, m, fl),
        );
        let mut w = ifreq(b"t2");
        w[16] = 16;
        w[17] = 2;
        w[20..24].copy_from_slice(&[10, 0, 5, 98]);
        let r4 = ((*i).IoctlSocket)(i, s, SIOCSIFADDR, w.as_mut_ptr() as *mut c_void);
        t.check(r4 == 0 && query_address(i) == Some([10, 0, 5, 98]), format_args!("ioctl: SIOCSIFADDR 10.0.5.98: {} {:?}", r4, query_address(i)));
        let mut d = ifreq(b"t2");
        d[16..18].copy_from_slice(&0u16.to_be_bytes());
        let r5 = ((*i).IoctlSocket)(i, s, SIOCSIFFLAGS, d.as_mut_ptr() as *mut c_void);
        let mut q4 = ifreq(b"t2");
        ((*i).IoctlSocket)(i, s, SIOCGIFFLAGS, q4.as_mut_ptr() as *mut c_void);
        let down = u16::from_be_bytes([q4[16], q4[17]]) & 1 == 0;
        d[16..18].copy_from_slice(&1u16.to_be_bytes());
        ((*i).IoctlSocket)(i, s, SIOCSIFFLAGS, d.as_mut_ptr() as *mut c_void);
        t.check(r5 == 0 && down, format_args!("ioctl: SIOCSIFFLAGS down: {} (down {})", r5, down));
        let mut x = ifreq(b"t2");
        let r6 = ((*i).IoctlSocket)(i, s, SIOCDIFADDR, x.as_mut_ptr() as *mut c_void);
        t.check(r6 == 0 && query_address(i) == Some([0; 4]), format_args!("ioctl: SIOCDIFADDR: {} {:?}", r6, query_address(i)));
        let mut bad = ifreq(b"nosuch");
        let r7 = ((*i).IoctlSocket)(i, s, SIOCGIFADDR, bad.as_mut_ptr() as *mut c_void);
        t.check(r7 == -1 && errno(i) == 6, format_args!("ioctl: an unknown interface is ENXIO: {} {}", r7, errno(i)));
        ((*i).CloseSocket)(i, s);
    }
}

pub fn run(lib: &SocketLib, t: &mut Tally) {
    let i = lib.iface();
    let (Ok(port), Ok(mut timer)) = (AmigaMsgPort::new(), Waiter::new()) else {
        t.check(false, format_args!("iface: no port or timer"));
        return;
    };

    // SAFETY: NUL-terminated names and an empty tag list.
    let r = unsafe { ((*i).AddInterfaceTagList)(i, b"t2\0".as_ptr() as *mut u8, b"virtionet.device\0".as_ptr() as *mut u8, 2, core::ptr::null_mut()) };
    t.check(r == 0, format_args!("iface: AddInterfaceTagList t2 on virtionet.device unit 2 (DEVS:Networks found): {} errno {}", r, errno(i)));
    // SAFETY: as above.
    let again = unsafe { ((*i).AddInterfaceTagList)(i, b"t2\0".as_ptr() as *mut u8, b"virtionet.device\0".as_ptr() as *mut u8, 2, core::ptr::null_mut()) };
    t.check(again == -1 && errno(i) == 17, format_args!("iface: adding t2 again gives EEXIST: {} errno {}", again, errno(i)));
    t.check(query_address(i) == Some([0; 4]), format_args!("iface: a new interface has no address ({:?})", query_address(i)));

    // The address-change signal.
    // SAFETY: AllocSignal(-1) for this task.
    let sig = unsafe { amigaos4::sys::exec_alloc_signal(-1) };
    let sigmask = if sig >= 0 { 1u32 << sig } else { 0 };
    let mut st = [TagItem { ti_Tag: TAG_USER | (SIG_ADDRESS_CHANGE_MASK << 1) | 1, ti_Data: sigmask }, TagItem { ti_Tag: TAG_DONE, ti_Data: 0 }];
    // SAFETY: a TAG_DONE-ended list.
    unsafe { ((*i).SocketBaseTagList)(i, st.as_mut_ptr()) };
    // SAFETY: clears this task's own signal.
    unsafe { amigaos4::sys::exec_set_signal(0, sigmask) };

    // Refusals at creation.
    let (bad_name, _) = create(i, 2, b"nosuchif\0", &port);
    t.check(bad_name == 6, format_args!("iface: CreateAddrAllocMessage for an unknown interface: CAAME {}", bad_name));
    let (bad_ver, _) = create(i, 9, b"t2\0", &port);
    t.check(bad_ver == 3, format_args!("iface: CreateAddrAllocMessage version 9: CAAME {}", bad_ver));

    // DHCP through the message.
    let (c, m) = create(i, 2, b"t2\0", &port);
    t.check(c == 0 && m != 0, format_args!("iface: CreateAddrAllocMessage: CAAME {}", c));
    if c != 0 || m == 0 {
        return;
    }
    let t0 = super::us();
    // SAFETY: our message from CreateAddrAllocMessage.
    unsafe { ((*i).BeginInterfaceConfig)(i, m as *mut c_void) };
    let back = wait_reply(&port, &mut timer, m, 20000);
    let res = get(m, AAM_RESULT) as i32;
    let a = get(m, AAM_ADDRESS).to_be_bytes();
    let mask = get(m, AAM_SUBNET_MASK).to_be_bytes();
    // SAFETY: the tables the message points to (4 entries each) and its
    // DateStamp.
    let (router, dns, days) = unsafe {
        (
            (*(get(m, AAM_ROUTER_TABLE) as *const u32)).to_be_bytes(),
            (*(get(m, AAM_DNS_TABLE) as *const u32)).to_be_bytes(),
            *(get(m, AAM_LEASE_EXPIRES) as *const i32),
        )
    };
    t.check(
        back && res == AAMR_SUCCESS && a == [10, 0, 5, 15] && mask == [255, 255, 255, 0] && router == [10, 0, 5, 2] && dns == [10, 0, 5, 3],
        format_args!(
            "iface: BeginInterfaceConfig: replied {} in {} ms, result {}, address {:?}/{:?}, router {:?}, DNS {:?}, lease expires day {}",
            back, (super::us() - t0) / 1000, res, a, mask, router, dns, days
        ),
    );
    t.check(query_address(i) == Some([10, 0, 5, 15]), format_args!("iface: QueryInterfaceTagList t2 address {:?}", query_address(i)));
    // SAFETY: SetSignal(0, 0) reads this task's signals.
    let got = unsafe { amigaos4::sys::exec_set_signal(0, 0) } & sigmask;
    t.check(sigmask != 0 && got != 0, format_args!("iface: SIG_ADDRESS_CHANGE_MASK signalled after DHCP ({:#x})", got));
    // SAFETY: as above.
    unsafe { amigaos4::sys::exec_set_signal(0, sigmask) };

    // A second request for a configured interface.
    // SAFETY: our message, back from the stack.
    unsafe { ((*i).BeginInterfaceConfig)(i, m as *mut c_void) };
    let back = wait_reply(&port, &mut timer, m, 2000);
    t.check(back && get(m, AAM_RESULT) as i32 == AAMR_ADDRESS_KNOWN, format_args!("iface: BeginInterfaceConfig again: AAMR {} (AddressKnown {})", get(m, AAM_RESULT) as i32, AAMR_ADDRESS_KNOWN));

    // A message of an unknown version.
    // SAFETY: our message; version written back after.
    unsafe {
        core::ptr::write_unaligned((m + AAM_VERSION) as *mut u32, 7);
        ((*i).BeginInterfaceConfig)(i, m as *mut c_void);
    }
    let back = wait_reply(&port, &mut timer, m, 2000);
    t.check(back && get(m, AAM_RESULT) as i32 == AAMR_VERSION_UNKNOWN, format_args!("iface: version 7: AAMR {}", get(m, AAM_RESULT) as i32));
    // SAFETY: as above.
    unsafe { core::ptr::write_unaligned((m + AAM_VERSION) as *mut u32, 2) };

    // The lease's name server is listed as the stack's own (dynamic, use
    // count 1).
    let ns = name_servers(i);
    t.check(ns.iter().any(|(a, c)| a == "10.0.5.3" && *c > 0), format_args!("iface: the lease's name server is listed as dynamic ({:?})", ns));

    // A host route through t2's gateway: add, list, change, delete.
    let r = route_call(i, b'a', &[(RTA_DESTINATION_HOST, b"192.168.88.7\0".as_ptr() as u32), (RTA_GATEWAY, b"10.0.5.2\0".as_ptr() as u32)]);
    let all = route_table(i, 0).unwrap_or_default();
    let hosts = route_table(i, RTF_HOST).unwrap_or_default();
    t.check(
        r == 0 && all.iter().any(|e| e.0 == [192, 168, 88, 7] && e.1 == [10, 0, 5, 2]) && !hosts.is_empty() && hosts.iter().all(|e| e.2 & RTF_HOST as u32 != 0) && hosts.iter().any(|e| e.0 == [192, 168, 88, 7]),
        format_args!("iface: AddRouteTagList host route: {}; GetRouteInfo all {:?}; RTF_HOST only {:?}", r, all, hosts),
    );
    let r = route_call(i, b'c', &[(RTA_DESTINATION_HOST, b"192.168.88.7\0".as_ptr() as u32), (RTA_GATEWAY, b"10.0.5.3\0".as_ptr() as u32)]);
    let after = route_table(i, RTF_HOST).unwrap_or_default();
    t.check(r == 0 && after.iter().any(|e| e.0 == [192, 168, 88, 7] && e.1 == [10, 0, 5, 3]), format_args!("iface: ChangeRouteTagList to gateway 10.0.5.3: {} {:?}", r, after));
    let r1 = route_call(i, b'd', &[(RTA_DESTINATION_HOST, b"192.168.88.7\0".as_ptr() as u32)]);
    let r2 = route_call(i, b'd', &[(RTA_DESTINATION_HOST, b"192.168.88.7\0".as_ptr() as u32)]);
    let e2 = errno(i);
    t.check(r1 == 0 && r2 == -1 && e2 == 3, format_args!("iface: DeleteRouteTagList: {}, again {} errno {} (ESRCH 3)", r1, r2, e2));

    // Give the DHCP address back.
    let r = configure(i, &[(IFC_RELEASE_ADDRESS, 1)]);
    t.check(r == 0 && query_address(i) == Some([0; 4]), format_args!("iface: IFC_ReleaseAddress: {} address {:?}", r, query_address(i)));
    let ns = name_servers(i);
    t.check(!ns.iter().any(|(a, c)| a == "10.0.5.3" && *c > 0), format_args!("iface: after the release the lease's name server is gone ({:?})", ns));

    // Abort: start again, abort at once (DHCP on QEMU may win), and give
    // back what it may have got.
    // SAFETY: our message.
    unsafe {
        ((*i).BeginInterfaceConfig)(i, m as *mut c_void);
        ((*i).AbortInterfaceConfig)(i, m as *mut c_void);
    }
    let back = wait_reply(&port, &mut timer, m, 5000);
    let res = get(m, AAM_RESULT) as i32;
    t.check(back && (res == AAMR_ABORTED || res == AAMR_SUCCESS), format_args!("iface: AbortInterfaceConfig: replied {}, AAMR {}", back, res));
    configure(i, &[(IFC_RELEASE_ADDRESS, 1)]);

    // An address set by hand (IFC_ReleaseAddress leaves it: only a
    // dynamic one is released).
    let r = configure(i, &[(IFC_ADDRESS, b"10.0.5.99\0".as_ptr() as u32), (IFC_NET_MASK, b"255.255.255.0\0".as_ptr() as u32)]);
    t.check(r == 0 && query_address(i) == Some([10, 0, 5, 99]), format_args!("iface: IFC_Address 10.0.5.99: {} address {:?}", r, query_address(i)));
    let r = configure(i, &[(IFC_NET_MASK, b"255.0.255.0\0".as_ptr() as u32), (IFC_ADDRESS, b"10.0.5.98\0".as_ptr() as u32)]);
    t.check(r == -1 && errno(i) == 22, format_args!("iface: a non-contiguous mask is EINVAL: {} errno {}", r, errno(i)));
    // SAFETY: SetSignal(0, 0) reads this task's signals.
    let got = unsafe { amigaos4::sys::exec_set_signal(0, 0) } & sigmask;
    t.check(got != 0, format_args!("iface: SIG_ADDRESS_CHANGE_MASK signalled after IFC_Address ({:#x})", got));

    let r = configure(i, &[(IFC_RELEASE_ADDRESS, 1)]);
    t.check(r == 0 && query_address(i) == Some([10, 0, 5, 99]), format_args!("iface: IFC_ReleaseAddress keeps an address set by hand: {} {:?}", r, query_address(i)));

    ioctls(i, t);

    // Remove, again (gone), add back into the same slot, remove.
    // SAFETY: NUL-terminated names.
    let (r1, r2) = unsafe { (((*i).RemoveInterface)(i, b"t2\0".as_ptr() as *mut u8, 0), ((*i).RemoveInterface)(i, b"t2\0".as_ptr() as *mut u8, 0)) };
    let e2 = errno(i);
    t.check(r1 == 1 && r2 == 0 && e2 == 6, format_args!("iface: RemoveInterface TRUE ({}), again FALSE ({}) ENXIO ({})", r1, r2, e2));
    // SAFETY: as above.
    let r3 = unsafe { ((*i).AddInterfaceTagList)(i, b"t2\0".as_ptr() as *mut u8, b"virtionet.device\0".as_ptr() as *mut u8, 2, core::ptr::null_mut()) };
    let r4 = unsafe { ((*i).RemoveInterface)(i, b"t2\0".as_ptr() as *mut u8, 1) };
    t.check(r3 == 0 && r4 == 1, format_args!("iface: added back ({}) and removed with force ({})", r3, r4));
    // SAFETY: lo0 is not removable.
    let r5 = unsafe { ((*i).RemoveInterface)(i, b"lo0\0".as_ptr() as *mut u8, 1) };
    t.check(r5 == 0, format_args!("iface: RemoveInterface lo0 refused ({}, errno {})", r5, errno(i)));

    // SAFETY: our message, not in use any more; then a pointer that is not
    // one (left alone).
    unsafe {
        ((*i).DeleteAddrAllocMessage)(i, m as *mut c_void);
        let mut x = [0u32; 40];
        ((*i).DeleteAddrAllocMessage)(i, x.as_mut_ptr() as *mut c_void);
    }
    let mut off = [TagItem { ti_Tag: TAG_USER | (SIG_ADDRESS_CHANGE_MASK << 1) | 1, ti_Data: 0 }, TagItem { ti_Tag: TAG_DONE, ti_Data: 0 }];
    // SAFETY: as above; then the signal goes back.
    unsafe {
        ((*i).SocketBaseTagList)(i, off.as_mut_ptr());
        if sig >= 0 {
            amigaos4::sys::exec_free_signal(sig);
        }
    }
}
