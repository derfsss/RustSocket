//! The stack's routing table: Roadshow's routes, one
//! table for every interface.
//!
//! An interface with an address gives a connected route to its own subnet
//! (not stored: made from the addresses when asked). The table holds the
//! routes added by hand (AddRouteTagList, DEVS:Internet/routes) and the
//! default routes that DHCP started by [`Stack::start`](crate::stack::Stack::start)
//! installs by itself (the library's own interfaces get theirs from
//! AddNetInterface, as with Roadshow).
//! A packet takes the most specific match; a route through a gateway goes
//! out of the interface whose subnet holds the gateway. smoltcp keeps its
//! own route list per interface: [`Table::program`] rebuilds them from the
//! table whenever the table or an address changes.

use alloc::vec::Vec;

use smoltcp::iface::Route as SmolRoute;
use smoltcp::wire::{IpCidr, Ipv4Address, Ipv4Cidr};

use crate::sock::Net;

pub const RTF_UP: u32 = 0x1;
pub const RTF_GATEWAY: u32 = 0x2;
pub const RTF_HOST: u32 = 0x4;
pub const RTF_STATIC: u32 = 0x800;

/// errno values.
const EEXIST: i32 = 17;
const ESRCH: i32 = 3;
const EINVAL: i32 = 22;
const ENETUNREACH: i32 = 51;

/// One route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub dst: [u8; 4],
    pub prefix: u8,
    /// The gateway; None for a connected route (made from an address).
    pub gateway: Option<[u8; 4]>,
    pub flags: u32,
    /// The interface slot it goes out of (connected: its own; a gateway
    /// route: the one whose subnet holds the gateway, None when no
    /// interface does right now).
    pub slot: Option<usize>,
    /// Installed by DHCP on this slot by itself (the ENV start-up).
    pub auto: Option<usize>,
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32) as u32) }
}

fn net_of(a: [u8; 4], prefix: u8) -> [u8; 4] {
    (u32::from_be_bytes(a) & mask(prefix)).to_be_bytes()
}

pub fn contains(dst: [u8; 4], prefix: u8, a: [u8; 4]) -> bool {
    u32::from_be_bytes(a) & mask(prefix) == u32::from_be_bytes(dst) & mask(prefix)
}

/// The interface (up, with an address) whose subnet holds `a`.
fn connected_slot(nets: &[Net], a: [u8; 4]) -> Option<usize> {
    nets.iter().position(|n| n.up && n.addr().map(|c| contains(c.address().octets(), c.prefix_len(), a)).unwrap_or(false))
}

#[derive(Default)]
pub struct Table {
    list: Vec<Route>,
    /// Changed since the last [`program`](Self::program).
    dirty: bool,
}

impl Table {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a route through `gateway` to `dst`/`prefix` (0/0: the default
    /// route). EEXIST for a duplicate, ENETUNREACH when no interface can
    /// reach the gateway.
    pub fn add(&mut self, nets: &[Net], dst: [u8; 4], prefix: u8, gateway: [u8; 4]) -> Result<(), i32> {
        if prefix > 32 {
            return Err(EINVAL);
        }
        let dst = net_of(dst, prefix);
        if self.list.iter().any(|r| r.auto.is_none() && r.dst == dst && r.prefix == prefix) {
            return Err(EEXIST);
        }
        if connected_slot(nets, gateway).is_none() {
            return Err(ENETUNREACH);
        }
        let mut flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
        if prefix == 32 {
            flags |= RTF_HOST;
        }
        self.list.push(Route { dst, prefix, gateway: Some(gateway), flags, slot: None, auto: None });
        self.dirty = true;
        Ok(())
    }

    /// Delete the route to `dst`/`prefix` (ESRCH when there is none).
    pub fn delete(&mut self, dst: [u8; 4], prefix: u8) -> Result<(), i32> {
        let dst = net_of(dst, prefix);
        let before = self.list.len();
        self.list.retain(|r| !(r.dst == dst && r.prefix == prefix));
        if self.list.len() == before {
            return Err(ESRCH);
        }
        self.dirty = true;
        Ok(())
    }

    /// Change the gateway of the route to `dst`/`prefix`.
    pub fn change(&mut self, nets: &[Net], dst: [u8; 4], prefix: u8, gateway: [u8; 4]) -> Result<(), i32> {
        let dst = net_of(dst, prefix);
        let Some(r) = self.list.iter_mut().find(|r| r.dst == dst && r.prefix == prefix) else { return Err(ESRCH) };
        if connected_slot(nets, gateway).is_none() {
            return Err(ENETUNREACH);
        }
        r.gateway = Some(gateway);
        r.auto = None;
        r.flags |= RTF_STATIC;
        self.dirty = true;
        Ok(())
    }

    /// DHCP's default route for slot `k` (None: its lease went).
    pub fn set_auto(&mut self, k: usize, router: Option<[u8; 4]>) {
        self.list.retain(|r| r.auto != Some(k));
        if let Some(g) = router {
            self.list.push(Route { dst: [0; 4], prefix: 0, gateway: Some(g), flags: RTF_UP | RTF_GATEWAY, slot: None, auto: Some(k) });
        }
        self.dirty = true;
    }

    /// Every route goes (NetShutdown).
    pub fn clear(&mut self) {
        self.list.clear();
        self.dirty = true;
    }

    /// Something else changed (an address): rebuild on the next program.
    pub fn touch(&mut self) {
        self.dirty = true;
    }

    /// Whether a default route is there.
    pub fn has_default(&self) -> bool {
        self.list.iter().any(|r| r.prefix == 0)
    }

    /// The interface to send to `dst` through: the most specific of the
    /// connected routes and the table's (first added wins a tie).
    pub fn select(&self, nets: &[Net], dst: [u8; 4]) -> Option<usize> {
        self.next_hop(nets, dst).map(|h| h.0)
    }

    /// The interface, the next hop (`dst` itself on a connected network,
    /// else the route's gateway) and the route's prefix length (0: the
    /// default route) to send to `dst` through.
    pub fn next_hop(&self, nets: &[Net], dst: [u8; 4]) -> Option<(usize, [u8; 4], u8)> {
        let mut best: Option<(u8, usize, [u8; 4])> = None;
        for (k, n) in nets.iter().enumerate() {
            if let (true, Some(c)) = (n.up, n.addr()) {
                if contains(c.address().octets(), c.prefix_len(), dst) && best.map(|b| c.prefix_len() > b.0).unwrap_or(true) {
                    best = Some((c.prefix_len(), k, dst));
                }
            }
        }
        for r in &self.list {
            if !contains(r.dst, r.prefix, dst) || best.map(|b| r.prefix <= b.0).unwrap_or(false) {
                continue;
            }
            if let Some(g) = r.gateway {
                if let Some(k) = connected_slot(nets, g) {
                    best = Some((r.prefix, k, g));
                }
            }
        }
        best.map(|b| (b.1, b.2, b.0))
    }

    /// Every route, connected ones first (for GetRouteInfo).
    pub fn all(&self, nets: &[Net]) -> Vec<Route> {
        let mut v = Vec::new();
        for (k, n) in nets.iter().enumerate() {
            if let (true, Some(c)) = (n.up, n.addr()) {
                v.push(Route {
                    dst: net_of(c.address().octets(), c.prefix_len()),
                    prefix: c.prefix_len(),
                    gateway: None,
                    flags: RTF_UP | if c.prefix_len() == 32 { RTF_HOST } else { 0 },
                    slot: Some(k),
                    auto: None,
                });
            }
        }
        for r in &self.list {
            let mut r = *r;
            r.slot = r.gateway.and_then(|g| connected_slot(nets, g));
            v.push(r);
        }
        v
    }

    /// Rebuild every interface's smoltcp route list from the table, if
    /// anything changed.
    pub fn program(&mut self, nets: &mut [Net]) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let all = self.all(nets);
        for (k, n) in nets.iter_mut().enumerate() {
            n.iface.routes_mut().update(|t| {
                t.clear();
                for r in all.iter().filter(|r| r.slot == Some(k)) {
                    let Some(g) = r.gateway else { continue };
                    let cidr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(r.dst[0], r.dst[1], r.dst[2], r.dst[3]), r.prefix));
                    let via = Ipv4Address::new(g[0], g[1], g[2], g[3]).into();
                    let _ = t.push(SmolRoute { cidr, via_router: via, preferred_until: None, expires_at: None });
                }
            });
        }
    }
}
