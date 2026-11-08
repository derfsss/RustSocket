//! IoctlSocket's interface and socket requests beyond FIONBIO / FIONREAD /
//! FIOASYNC (netinclude/sys/sockio.h; the numbers computed with the SDK
//! compiler): SIOCGIFCONF and the SIOCGIF* queries, SIOCSIFADDR /
//! SIOCSIFNETMASK / SIOCSIFFLAGS / SIOCAIFADDR / SIOCDIFADDR through the
//! stack's interface configuration, and the small socket ones (SIOCATMARK,
//! process group, water marks). struct ifreq: 16-byte name, then a 16-byte
//! union (sockaddr, flags WORD, metric LONG); struct ifconf: ifc_len,
//! ifc_buf; struct ifaliasreq: name, address, broadcast, mask.

use rsnet_core::stack::Status;

use super::{errno, stack, Opener};

const SIOCSIFADDR: u32 = 0x8020690C;
const SIOCGIFADDR: u32 = 0xC0206921;
const SIOCSIFDSTADDR: u32 = 0x8020690E;
const SIOCGIFDSTADDR: u32 = 0xC0206922;
const SIOCSIFFLAGS: u32 = 0x80206910;
const SIOCGIFFLAGS: u32 = 0xC0206911;
const SIOCGIFBRDADDR: u32 = 0xC0206923;
const SIOCSIFBRDADDR: u32 = 0x80206913;
const SIOCGIFCONF: u32 = 0xC0086924;
const SIOCGIFNETMASK: u32 = 0xC0206925;
const SIOCSIFNETMASK: u32 = 0x80206916;
const SIOCGIFMETRIC: u32 = 0xC0206917;
const SIOCSIFMETRIC: u32 = 0x80206918;
const SIOCDIFADDR: u32 = 0x80206919;
const SIOCAIFADDR: u32 = 0x8040691A;
const SIOCADDMULTI: u32 = 0x80206931;
const SIOCDELMULTI: u32 = 0x80206932;
const SIOCATMARK: u32 = 0x40047307;
const SIOCSPGRP: u32 = 0x80047308;
const SIOCGPGRP: u32 = 0x40047309;
const SIOCGHIWAT: u32 = 0x40047301;
const SIOCSHIWAT: u32 = 0x80047300;
const SIOCGLOWAT: u32 = 0x40047303;
const SIOCSLOWAT: u32 = 0x80047302;

const IFF_UP: u16 = 0x1;
const IFF_BROADCAST: u16 = 0x2;
const IFF_LOOPBACK: u16 = 0x8;
const IFF_RUNNING: u16 = 0x40;
const IFF_SIMPLEX: u16 = 0x800;
const IFF_MULTICAST: u16 = 0x8000;

const ENXIO: i32 = 6;
const EADDRNOTAVAIL: i32 = 49;

fn mask(prefix: u8) -> [u8; 4] {
    (if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix as u32) }).to_be_bytes()
}

/// A sockaddr_in at `p`.
///
/// # Safety
/// `p` points to 16 writable bytes.
unsafe fn put_sa(p: *mut u8, a: [u8; 4]) {
    let mut s = [0u8; 16];
    s[0] = 16;
    s[1] = 2;
    s[4..8].copy_from_slice(&a);
    // SAFETY: the caller's contract.
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), p, 16) };
}

/// The address in the sockaddr at `p`.
///
/// # Safety
/// `p` points to 16 readable bytes.
unsafe fn get_sa(p: *const u8) -> [u8; 4] {
    // SAFETY: the caller's contract.
    unsafe { [*p.add(4), *p.add(5), *p.add(6), *p.add(7)] }
}

fn flags(st: &Status) -> u16 {
    let mut f = if st.up { IFF_UP | IFF_RUNNING } else { 0 } | IFF_MULTICAST;
    f |= if st.loopback { IFF_LOOPBACK } else { IFF_BROADCAST | IFF_SIMPLEX };
    f
}

/// The interface an ifreq names, and every interface.
///
/// # Safety
/// `ifr` points to an ifreq.
unsafe fn named(ifr: *const u8) -> Option<(Status, alloc::vec::Vec<Status>)> {
    // SAFETY: the 16-byte ifr_name (the caller's contract).
    let name = unsafe { core::slice::from_raw_parts(ifr, 16) };
    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(16)];
    let all = stack()?.status()?;
    let st = all.iter().find(|s| s.present && s.name.as_bytes().eq_ignore_ascii_case(name))?.clone();
    Some((st, all))
}

/// The requests this module answers: Some(result), None for others.
pub fn ioctl(o: &mut Opener, req: u32, argp: *mut u8) -> Option<i32> {
    let ifr = argp;
    let data = argp.wrapping_add(16);
    let s = stack();
    let r = match req {
        SIOCGIFCONF => {
            // SAFETY: the caller's struct ifconf: ifc_len, ifc_buf.
            let (len, buf) = unsafe { (core::ptr::read_unaligned(argp as *const i32), core::ptr::read_unaligned(argp.add(4) as *const usize) as *mut u8) };
            let all = s.and_then(|s| s.status()).unwrap_or_default();
            let mut used = 0usize;
            for st in all.iter().filter(|s| s.present) {
                if used + 32 > len.max(0) as usize || buf.is_null() {
                    break;
                }
                let mut name = [0u8; 16];
                let l = st.name.len().min(15);
                name[..l].copy_from_slice(&st.name.as_bytes()[..l]);
                // SAFETY: 32 bytes of the caller's buffer of `len`.
                unsafe {
                    core::ptr::copy_nonoverlapping(name.as_ptr(), buf.add(used), 16);
                    put_sa(buf.add(used + 16), st.address.map(|a| a.0).unwrap_or([0; 4]));
                }
                used += 32;
            }
            // SAFETY: as above.
            unsafe { core::ptr::write_unaligned(argp as *mut i32, used as i32) };
            Ok(())
        }
        SIOCGIFADDR | SIOCGIFNETMASK | SIOCGIFBRDADDR | SIOCGIFFLAGS | SIOCGIFMETRIC | SIOCGIFDSTADDR => {
            // SAFETY: the caller's struct ifreq.
            match unsafe { named(ifr) } {
                None => Err(ENXIO),
                Some((st, _)) => {
                    let (a, p) = st.address.unwrap_or(([0; 4], 0));
                    let m = mask(p);
                    // SAFETY: the ifreq's 16-byte union.
                    unsafe {
                        match req {
                            SIOCGIFFLAGS => {
                                core::ptr::write_unaligned(data as *mut u16, flags(&st));
                                Ok(())
                            }
                            SIOCGIFMETRIC => {
                                core::ptr::write_unaligned(data as *mut i32, 0);
                                Ok(())
                            }
                            // No point-to-point interfaces here.
                            SIOCGIFDSTADDR => Err(errno::EINVAL),
                            _ if st.address.is_none() => Err(EADDRNOTAVAIL),
                            SIOCGIFADDR => {
                                put_sa(data, a);
                                Ok(())
                            }
                            SIOCGIFNETMASK => {
                                put_sa(data, m);
                                Ok(())
                            }
                            _ => {
                                put_sa(data, [a[0] | !m[0], a[1] | !m[1], a[2] | !m[2], a[3] | !m[3]]);
                                Ok(())
                            }
                        }
                    }
                }
            }
        }
        SIOCSIFADDR | SIOCSIFNETMASK | SIOCSIFFLAGS | SIOCAIFADDR | SIOCDIFADDR => {
            // SAFETY: the caller's struct ifreq / ifaliasreq.
            match unsafe { named(ifr) } {
                None => Err(ENXIO),
                Some((st, _)) => {
                    let Some(s) = s else { return Some(o.fail(ENXIO)) };
                    let cur = st.address;
                    let natural = |a: [u8; 4]| match a[0] {
                        0..=127 => 8,
                        128..=191 => 16,
                        _ => 24,
                    };
                    // SAFETY: the union's sockaddr / flags (the caller's).
                    let r = unsafe {
                        match req {
                            SIOCSIFADDR => {
                                let a = get_sa(data);
                                s.config_iface(&st.name, Some((a, cur.map(|c| c.1).unwrap_or_else(|| natural(a)))), None, false)
                            }
                            SIOCSIFNETMASK => match cur {
                                Some((a, _)) => s.config_iface(&st.name, Some((a, u32::from_be_bytes(get_sa(data)).leading_ones() as u8)), None, false),
                                None => Err(EADDRNOTAVAIL),
                            },
                            SIOCSIFFLAGS => {
                                let f = core::ptr::read_unaligned(data as *const u16);
                                s.config_iface(&st.name, None, Some(f & IFF_UP != 0), false)
                            }
                            // One address per interface here: an alias
                            // replaces it (ifaliasreq: address at 16, mask
                            // at 48).
                            SIOCAIFADDR => {
                                let a = get_sa(data);
                                let m = get_sa(argp.add(48));
                                let p = if m == [0; 4] { natural(a) } else { u32::from_be_bytes(m).leading_ones() as u8 };
                                s.config_iface(&st.name, Some((a, p)), None, false)
                            }
                            // The address goes ([0; 4] clears it).
                            _ => s.config_iface(&st.name, Some(([0; 4], 0)), None, false),
                        }
                    };
                    r
                }
            }
        }
        // Accepted, kept nowhere (no point-to-point, metric not used).
        SIOCSIFBRDADDR | SIOCSIFMETRIC | SIOCSIFDSTADDR => Ok(()),
        // smoltcp is built without multicast groups.
        SIOCADDMULTI | SIOCDELMULTI => Err(errno::EOPNOTSUPP),
        SIOCATMARK | SIOCGPGRP => {
            // SAFETY: the caller's LONG.
            unsafe { core::ptr::write_unaligned(argp as *mut i32, 0) };
            Ok(())
        }
        SIOCSPGRP | SIOCSHIWAT | SIOCSLOWAT => Ok(()),
        SIOCGHIWAT | SIOCGLOWAT => {
            let v = if req == SIOCGHIWAT { rsnet_core::settings::SETTINGS.tcp_space().1 as i32 } else { 1 };
            // SAFETY: the caller's LONG.
            unsafe { core::ptr::write_unaligned(argp as *mut i32, v) };
            Ok(())
        }
        _ => return None,
    };
    Some(match r {
        Ok(()) => 0,
        Err(e) => o.fail(e),
    })
}
