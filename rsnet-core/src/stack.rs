//! The stack process and the handle to it.
//!
//! [`Stack::start`] starts a DOS process that opens each configured SANA-II
//! unit ([`Link`]), makes smoltcp's interface on each with its own socket
//! set, a DHCP socket and an ICMP socket, and then loops: take the replied
//! reads, poll smoltcp, act on DHCP, answer commands, Wait for the links,
//! the command port or the timer smoltcp asks for. Other tasks talk to it
//! with [`Ctl`] messages sent with a reply port; it answers by replying
//! them, filled in. A ping is answered when its echo reply arrives or its
//! time runs out.
//!
//! The interfaces' smoltcp state and the socket table ([`Core`]) sit behind
//! a mutex the stack process holds while it works and lets go of while it
//! sleeps. A TCP recv or send that can be done at once is done by the
//! calling task itself under that lock ([`Stack::recv_now`],
//! [`Stack::send_now`]): one copy between its buffer and smoltcp's, no
//! message, no task switch; it then signals the stack so the window update
//! or the data goes out. Everything else is a message.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use amigaos4::dos::process;
use amigaos4::msg::{Message, Port, Received, Sender};
use amigaos4::signal::{self, SignalTarget};
use amigaos4::sync::Mutex;
use amigaos4::timer::{get_up_time, AmigaTimer, TimerUnit, TimerVal};

use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, Loopback, Medium, TxToken};

use crate::phy::Lo;
use smoltcp::socket::{dhcpv4, icmp};
use smoltcp::time::Instant;
use smoltcp::wire::{DhcpOption, EthernetAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address};

use crate::aam;

use crate::link::{Link, LinkStats};
use crate::sock::Net;

/// What the stack's work costs, counted since the library loaded: passes of
/// the stack process's loop, the times it slept, and the recv/send calls
/// done in the caller's task (each also wakes the stack) against those that
/// went to the stack as a message. [`perf`] reads them.
static PERF: [core::sync::atomic::AtomicU32; 4] = [const { core::sync::atomic::AtomicU32::new(0) }; 4];
const PERF_PASSES: usize = 0;
const PERF_SLEEPS: usize = 1;
const PERF_INLINE: usize = 2;
const PERF_INLINE_MISS: usize = 3;

fn count(i: usize) {
    PERF[i].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// (stack loop passes, sleeps, inline recv/send done, inline recv/send
/// that went to the stack as a message).
pub fn perf() -> [u32; 4] {
    let mut out = [0; 4];
    for (o, p) in out.iter_mut().zip(PERF.iter()) {
        *o = p.load(core::sync::atomic::Ordering::Relaxed);
    }
    out
}

/// One SANA-II unit to add as an interface when the stack starts.
#[derive(Clone, Debug)]
pub struct Unit {
    /// The interface's name (at most 15 characters).
    pub name: String,
    /// e.g. "networks/virtionet.device".
    pub device: String,
    pub unit: u32,
}

/// The interfaces [`Stack::start`] adds (each with DHCP started), through
/// the same commands a running stack takes ([`Stack::add_iface`],
/// [`Stack::start_dhcp`]). May be empty: then only lo0 runs.
#[derive(Clone, Debug)]
pub struct Config {
    pub units: Vec<Unit>,
}

/// Interface slots: lo0 and at most this many SANA-II interfaces.
pub const MAX_SLOTS: usize = 16;

/// The loopback interface's name and slot.
pub const LO_NAME: &str = "lo0";
/// The loopback interface's name to the IP filter (rules, its log, the
/// IP_FILTER_HOOK's ifnet), as Roadshow's ipf has it.
pub const LO_IPF_NAME: &str = "loopback";
pub(crate) const LO: usize = 0;

/// What the stack knows about one interface slot, copied out.
#[derive(Clone, Debug, Default)]
pub struct Status {
    /// The interface's name.
    pub name: String,
    /// lo0.
    pub loopback: bool,
    /// False for a slot whose interface was removed.
    pub present: bool,
    /// Up (taking traffic) or down.
    pub up: bool,
    /// The SANA-II device and unit.
    pub device: String,
    pub unit: u32,
    pub mac: [u8; 6],
    pub mtu: u32,
    /// From the device: bits per second, SANA-II hardware type, address
    /// size in bits.
    pub bps: u32,
    pub hw_type: u32,
    pub addr_bits: u32,
    /// The address and prefix length DHCP gave, if configured.
    pub address: Option<([u8; 4], u8)>,
    pub router: Option<[u8; 4]>,
    pub dns: Vec<[u8; 4]>,
    /// DHCP leases taken since the start.
    pub leases: u32,
    pub link: LinkStats,
    /// When it was added (system time: seconds, microseconds).
    pub started: (u32, u32),
    /// The driver's MTU (`mtu` is the one used, IFC_LimitMTU may lower it).
    pub hw_mtu: u32,
    /// IFC_Metric, IFC_SetDebugMode, IFC_BroadcastAddress as set.
    pub metric: u32,
    pub debug: bool,
    pub broadcast: Option<[u8; 4]>,
    /// IFC_AddAliasAddress: further addresses it answers to.
    pub aliases: Vec<[u8; 4]>,
    /// The lease a BeginInterfaceConfig (DHCP) gave: its address and when
    /// it ends (up time, microseconds; u64::MAX: never). While the
    /// interface keeps that address its binding is dynamic, as Roadshow
    /// reports it; taking the interface down or another address forgets it
    /// (Roadshow then says "Static").
    pub lease: Option<([u8; 4], u64)>,
    /// IFA_DownGoesOffline: S2_OFFLINE when taken down, S2_ONLINE when up.
    pub down_offline: bool,
    /// What the driver offers through the SANA-II extensions (all zero:
    /// plain SANA-II).
    pub s2x: crate::s2xlogic::Caps,
}

/// The interface's addresses: the primary (if any), then its aliases (with
/// the primary's prefix length).
fn set_addrs(iface: &mut Interface, primary: Option<([u8; 4], u8)>, aliases: &[[u8; 4]]) {
    let len = primary.map(|p| p.1).unwrap_or(32);
    let list: Vec<IpCidr> = primary.map(|p| p.0).into_iter().chain(aliases.iter().copied()).map(|a| IpCidr::new(IpAddress::v4(a[0], a[1], a[2], a[3]), len)).collect();
    iface.update_ip_addrs(|v| {
        v.clear();
        for c in list {
            let _ = v.push(c);
        }
    });
}

/// smoltcp's address room (feature iface-max-addr-count-8).
const MAX_ADDRS: usize = 8;

/// What the stack process and the tasks calling it share, behind a mutex:
/// every interface's smoltcp state and the socket table.
pub struct Core {
    nets: Vec<Net>,
    socks: crate::sock::Socks,
    /// The stack process and its command port's signal: a task that changed
    /// a socket wakes it with this (only while `alive`).
    wake: SignalTarget,
    /// Cleared, under the lock, before the stack process ends.
    alive: bool,
    /// Who wants a signal when an interface address changes
    /// (SBTC_SIG_ADDRESS_CHANGE_MASK): (id, task, signal mask).
    watchers: Vec<(u32, usize, u32)>,
}

/// Messages between the stack and the tasks that use it.
pub enum Ctl {
    /// Stack to starter, once: its command port and the shared state, or why
    /// it could not start.
    Ready(Result<(Sender<Ctl>, Arc<Mutex<Core>>), String>),
    /// Filled in by the stack: one Status per slot, lo0 first.
    Status(Vec<Status>),
    /// Add an interface on a SANA-II unit: up, with no address.
    AddIface { name: String, device: String, unit: u32, mac: Option<[u8; 6]>, down_offline: bool, result: Result<(), i32> },
    /// Take an interface away; refused (EBUSY) while a TCP connection runs
    /// over it, unless `force`.
    RemoveIface { name: String, force: bool, result: Result<(), i32> },
    /// Set an interface's address (and prefix length) and/or its state;
    /// `release` gives a DHCP address back first (IFC_ReleaseAddress).
    ConfigIface { name: String, address: Option<([u8; 4], u8)>, up: Option<bool>, release: bool, result: Result<(), i32> },
    /// Start DHCP on an interface, applying what it gives (address, default
    /// route, DNS servers) by itself: for the units given to
    /// [`Stack::start`] (test programs such as rsnet). The library's
    /// interfaces use BeginInterfaceConfig instead.
    StartDhcp { name: String, result: Result<(), i32> },
    /// BeginInterfaceConfig: DHCP for the AddressAllocationMessage at `aam`,
    /// which the stack fills in and replies when done. `result` comes back
    /// as BEGIN_PENDING when the stack took the message, else as the
    /// aam_Result for the caller to reply with at once.
    BeginConfig { name: String, aam: usize, timeout_s: u32, lease_s: u32, client_id: Vec<u8>, result: i32 },
    /// AbortInterfaceConfig: the request with this message, if it still runs.
    AbortConfig { aam: usize },
    /// Add, delete or change a route (AddRouteTagList and the others).
    Route { op: RouteOp, result: Result<(), i32> },
    /// Filled in by the stack: every route, connected ones first.
    Routes(Vec<crate::route::Route>),
    /// Add (`add`; `fixed` from the configuration file) or remove a name
    /// server.
    NameServer { address: [u8; 4], add: bool, fixed: bool, result: Result<(), i32> },
    /// name_resolution's `nameserver` lines, all of them (Socks::file_servers).
    FileNameServers(Vec<[u8; 4]>),
    /// Filled in by the stack: every name server and its use count.
    NameServers(Vec<([u8; 4], i32)>),
    /// Filled in by the stack: every interface's ARP entries.
    Neighbors(Vec<crate::rtsock::Neighbor>),
    /// bpf_write: one whole frame out of interface `slot`.
    BpfWrite { slot: u8, frame: Vec<u8>, result: Result<usize, i32> },
    /// ConfigureInterfaceTagList's other options: MTU limit, metric, debug
    /// mode, broadcast address, an alias added (true) or deleted.
    IfaceOpts { name: String, opts: IfaceOpts, result: Result<(), i32> },
    /// An ICMP echo to `addr`; the stack sets `rtt_us` when the reply comes
    /// (None after `timeout_ms`).
    Ping { addr: [u8; 4], seq: u16, timeout_ms: u32, rtt_us: Option<u64> },
    /// A socket operation for a library opener (see `sock`).
    Sock(crate::sock::SockMsg),
    /// Answer the waiting socket op with this token at once (EINTR); sent
    /// without a reply port.
    Abort(u32),
    /// Close the links and end the process.
    Quit,
}

/// The ICMP identifier the stack's pings use.
const PING_IDENT: u16 = 0x5253;

fn now() -> Instant {
    Instant::from_micros(get_up_time().as_micros() as i64)
}

/// A ping waiting for its reply.
struct PendingPing {
    msg: Received<Ctl>,
    sent: Instant,
    deadline: Instant,
}

/// One interface slot's own parts besides its Net. lo0 is slot 0 (no
/// link); a SANA-II interface keeps its slot for the life of the stack, also
/// once removed (its Net and sockets stay, so no index moves), and an
/// interface added again under the same name takes it back.
struct Side {
    name: String,
    link: Option<Link>,
    /// The DHCP socket, only while DHCP is wanted: smoltcp's starts asking
    /// as soon as its interface is polled.
    dhcp: Option<SocketHandle>,
    /// DHCP installs the default route and DNS servers itself (StartDhcp),
    /// or only the address (BeginConfig: the caller adds the rest).
    dhcp_auto: bool,
    /// A BeginInterfaceConfig request in progress: its message and deadline.
    alloc: Option<(usize, Instant)>,
    /// The DHCP socket's receive buffer and client-identifier option (they
    /// must outlive the socket, which is removed before they are dropped).
    dhcp_buf: Option<Box<[u8]>>,
    dhcp_cid: Option<Box<[u8]>>,
    dhcp_opts: Option<Box<[DhcpOption<'static>]>>,
    ping: Option<SocketHandle>,
    status: Status,
}

impl Side {
    fn empty(status: Status) -> Self {
        Side { name: String::new(), link: None, dhcp: None, dhcp_auto: false, alloc: None, dhcp_buf: None, dhcp_cid: None, dhcp_opts: None, ping: None, status }
    }
}

/// Take interface `k`'s DHCP socket away (and the buffers it used).
fn stop_dhcp(side: &mut Side, net: &mut Net) {
    if let Some(h) = side.dhcp.take() {
        net.sockets.remove(h);
    }
    side.dhcp_opts = None;
    side.dhcp_cid = None;
    side.dhcp_buf = None;
}

/// BeginConfig: start DHCP for an AddressAllocationMessage.
fn begin_config(sides: &mut [Side], nets: &mut [Net], name: &str, aam_ptr: usize, timeout_s: u32, lease_s: u32, client_id: &[u8]) -> i32 {
    let Some(k) = slot_of(sides, name) else { return aam::AAMR_INTERFACE_NOT_KNOWN };
    if k == LO {
        return aam::AAMR_INTERFACE_WRONG_TYPE;
    }
    if sides[k].alloc.is_some() {
        return aam::AAMR_BUSY;
    }
    if sides[k].status.address.is_some() {
        return aam::AAMR_ADDRESS_KNOWN;
    }
    let (side, net) = (&mut sides[k], &mut nets[k]);
    stop_dhcp(side, net);
    let mut d = dhcpv4::Socket::new();
    // The server's reply is kept for the host and domain names and the
    // lease time (aam_HostName, aam_DomainName, aam_LeaseExpires).
    let mut buf: Box<[u8]> = alloc::vec![0u8; 1500].into_boxed_slice();
    let bp: *mut [u8] = &mut *buf;
    // SAFETY: the buffer lives in the Side until stop_dhcp, which removes
    // the socket first.
    d.set_receive_packet_buffer(unsafe { &mut *bp });
    side.dhcp_buf = Some(buf);
    if lease_s != 0 && lease_s != u32::MAX {
        d.set_max_lease_duration(Some(smoltcp::time::Duration::from_secs(lease_s as u64)));
    }
    if client_id.len() >= 2 {
        // Option 61: type 0 (not a hardware address), then the name.
        let mut c = alloc::vec![0u8];
        c.extend_from_slice(&client_id[..client_id.len().min(255)]);
        let c: Box<[u8]> = c.into_boxed_slice();
        let cp: *const [u8] = &*c;
        // SAFETY: as the receive buffer: kept in the Side, dropped after
        // the socket.
        let opts: Box<[DhcpOption<'static>]> = alloc::vec![DhcpOption { kind: 61, data: unsafe { &*cp } }].into_boxed_slice();
        let op: *const [DhcpOption<'static>] = &*opts;
        // SAFETY: as above.
        d.set_outgoing_options(unsafe { &*op });
        side.dhcp_cid = Some(c);
        side.dhcp_opts = Some(opts);
    }
    side.dhcp = Some(net.sockets.add(d));
    side.dhcp_auto = false;
    side.alloc = Some((aam_ptr, now() + smoltcp::time::Duration::from_secs(timeout_s.max(10) as u64)));
    BEGIN_PENDING
}

/// The lease DHCP gave, with what the server's reply carried.
fn lease_of(c: &dhcpv4::Config) -> aam::Lease {
    let mut l = aam::Lease {
        address: c.address.address().octets(),
        mask: u32::to_be_bytes(if c.address.prefix_len() == 0 { 0 } else { u32::MAX << (32 - c.address.prefix_len() as u32) }),
        server: c.server.address.octets(),
        routers: c.router.map(|r| alloc::vec![r.octets()]).unwrap_or_default(),
        dns: c.dns_servers.iter().map(|d| d.octets()).collect(),
        ..aam::Lease::default()
    };
    if let Some(p) = &c.packet {
        for o in p.options() {
            match o.kind {
                12 => l.host_name = Some(Vec::from(o.data)),
                15 => l.domain_name = Some(Vec::from(o.data)),
                51 if o.data.len() == 4 => l.lease_secs = Some(u32::from_be_bytes([o.data[0], o.data[1], o.data[2], o.data[3]])),
                _ => {}
            }
        }
        l.packet = Some(Vec::from(p.into_inner()));
    }
    l
}

/// BeginConfig's `result` when the stack keeps the message.
pub const BEGIN_PENDING: i32 = i32::MIN;

/// A change to the routing table.
#[derive(Clone, Copy, Debug)]
pub enum RouteOp {
    Add { dst: [u8; 4], prefix: u8, gateway: [u8; 4] },
    Delete { dst: [u8; 4], prefix: u8 },
    Change { dst: [u8; 4], prefix: u8, gateway: [u8; 4] },
}

/// ConfigureInterfaceTagList options the stack keeps.
#[derive(Clone, Copy, Debug, Default)]
pub struct IfaceOpts {
    pub mtu: Option<u32>,
    pub metric: Option<u32>,
    pub debug: Option<bool>,
    pub broadcast: Option<[u8; 4]>,
    pub alias: Option<([u8; 4], bool)>,
}

/// IfaceOpts on interface `name`.
fn iface_opts(sides: &mut [Side], nets: &mut [Net], name: &str, o: &IfaceOpts) -> Result<(), i32> {
    let k = slot_of(sides, name).ok_or(err::ENXIO)?;
    let side = &mut sides[k];
    if let Some(m) = o.mtu {
        // Only a smaller one than the driver's (ConfigureNetInterface.doc).
        let hw = if side.status.hw_mtu != 0 { side.status.hw_mtu } else { side.status.mtu };
        let m = m.clamp(68, hw);
        side.status.mtu = m;
        if let Some(l) = side.link.as_mut() {
            l.mtu = m;
        }
    }
    if let Some(m) = o.metric {
        side.status.metric = m;
    }
    if let Some(d) = o.debug {
        side.status.debug = d;
    }
    if let Some(b) = o.broadcast {
        side.status.broadcast = Some(b);
    }
    if let Some((a, add)) = o.alias {
        let had = side.status.aliases.contains(&a);
        if add && !had {
            if side.status.aliases.len() + 1 >= MAX_ADDRS {
                return Err(err::ENOBUFS);
            }
            side.status.aliases.push(a);
        } else if !add && had {
            side.status.aliases.retain(|x| *x != a);
        } else if !add {
            return Err(err::EADDRNOTAVAIL);
        }
        let (primary, aliases) = (side.status.address, side.status.aliases.clone());
        set_addrs(&mut nets[k].iface, primary, &aliases);
    }
    Ok(())
}

/// errno values the interface commands answer with.
mod err {
    pub const EINVAL: i32 = 22;
    pub const ENXIO: i32 = 6;
    pub const ENODEV: i32 = 19;
    pub const EEXIST: i32 = 17;
    pub const EBUSY: i32 = 16;
    pub const ENOBUFS: i32 = 55;
    pub const EPERM: i32 = 1;
    pub const EIO: i32 = 5;
    pub const EADDRNOTAVAIL: i32 = 49;
}

/// The slot of the present interface called `name` (case-insensitive, as
/// Roadshow's names are).
fn slot_of(sides: &[Side], name: &str) -> Option<usize> {
    sides.iter().position(|s| s.status.present && s.name.eq_ignore_ascii_case(name))
}

/// AddIface: open the unit, make its smoltcp interface, take a slot.
fn add_iface(sides: &mut Vec<Side>, nets: &mut Vec<Net>, socks: &mut crate::sock::Socks, seed: &mut u64, name: &str, device: &str, unit: u32, mac: Option<[u8; 6]>, down_offline: bool) -> Result<(), i32> {
    if name.is_empty() || name.len() > 15 {
        return Err(err::EINVAL);
    }
    if slot_of(sides, name).is_some() {
        return Err(err::EEXIST);
    }
    let again = sides.iter().position(|s| !s.status.present && s.name.eq_ignore_ascii_case(name));
    if again.is_none() && sides.len() >= MAX_SLOTS {
        return Err(err::ENOBUFS);
    }
    // A device name with no path is looked for in DEVS:Networks/ first, as
    // Roadshow does; the interface keeps the name it was given.
    let opened = if device.contains(':') || device.contains('/') {
        Link::open(device, unit, mac)
    } else {
        Link::open(&alloc::format!("networks/{}", device), unit, mac).or_else(|_| Link::open(device, unit, mac))
    };
    let mut link = opened.map_err(|_| err::ENODEV)?;
    link.slot = again.unwrap_or(sides.len()) as u8;
    crate::ipf::set_ifnet(link.slot, name);
    let mut config = IfaceConfig::new(EthernetAddress(link.mac).into());
    *seed ^= u64::from_be_bytes([0, 0, link.mac[0], link.mac[1], link.mac[2], link.mac[3], link.mac[4], link.mac[5]]);
    config.random_seed = *seed;
    let iface = Interface::new(config, &mut link, now());
    let status = Status {
        name: String::from(name),
        present: true,
        up: true,
        device: String::from(device),
        unit,
        mac: link.mac,
        mtu: link.mtu,
        hw_mtu: link.mtu,
        started: {
            let t = amigaos4::timer::sys_time();
            (t.secs, t.micros)
        },
        bps: link.bps,
        hw_type: link.hw_type,
        addr_bits: link.addr_bits,
        down_offline,
        s2x: link.caps,
        ..Status::default()
    };
    let k = match again {
        Some(k) => {
            nets[k].iface = iface;
            nets[k].up = true;
            sides[k].link = Some(link);
            sides[k].status = status;
            k
        }
        None => {
            nets.push(Net { iface, sockets: SocketSet::new(vec![]), up: true });
            sides.push(Side { name: String::from(name), link: Some(link), ..Side::empty(status) });
            nets.len() - 1
        }
    };
    if sides[k].ping.is_none() {
        let icmp_rx = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0u8; 2048]);
        let icmp_tx = icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0u8; 2048]);
        let mut ping_sock = icmp::Socket::new(icmp_rx, icmp_tx);
        let _ = ping_sock.bind(icmp::Endpoint::Ident(PING_IDENT));
        sides[k].ping = Some(nets[k].sockets.add(ping_sock));
    }
    socks.add_net(k, nets);
    Ok(())
}

/// Clear interface `k`'s address and DNS servers (its DHCP default route
/// goes with the lease: Table::set_auto).
fn clear_address(side: &mut Side, net: &mut Net) {
    let aliases = side.status.aliases.clone();
    set_addrs(&mut net.iface, None, &aliases);
    side.status.address = None;
    side.status.router = None;
    side.status.dns.clear();
}

/// RemoveIface: the link closes, the slot stays for a later AddIface.
fn remove_iface(sides: &mut [Side], nets: &mut [Net], socks: &mut crate::sock::Socks, name: &str, force: bool) -> Result<(), i32> {
    let k = slot_of(sides, name).ok_or(err::ENXIO)?;
    if k == LO {
        return Err(err::EPERM);
    }
    if !force && socks.in_use(k, nets) {
        return Err(err::EBUSY);
    }
    socks.drop_net(k, nets);
    if let Some((m, _)) = sides[k].alloc.take() {
        // SAFETY: the message BeginInterfaceConfig handed over, still ours.
        unsafe { aam::complete(m, aam::AAMR_ABORTED, None) };
    }
    stop_dhcp(&mut sides[k], &mut nets[k]);
    clear_address(&mut sides[k], &mut nets[k]);
    socks.routes.set_auto(k, None);
    nets[k].up = false;
    sides[k].link = None;
    sides[k].status.present = false;
    sides[k].status.up = false;
    Ok(())
}

/// ConfigIface: an address set by hand replaces DHCP's.
fn config_iface(sides: &mut [Side], nets: &mut [Net], socks: &mut crate::sock::Socks, name: &str, address: Option<([u8; 4], u8)>, up: Option<bool>, release: bool) -> Result<(), i32> {
    let k = slot_of(sides, name).ok_or(err::ENXIO)?;
    if k == LO && (address.is_some() || release) {
        return Err(err::EPERM);
    }
    if release && sides[k].dhcp.is_some() {
        if let Some((m, _)) = sides[k].alloc.take() {
            // SAFETY: the message BeginInterfaceConfig handed over.
            unsafe { aam::complete(m, aam::AAMR_ABORTED, None) };
        }
        stop_dhcp(&mut sides[k], &mut nets[k]);
        clear_address(&mut sides[k], &mut nets[k]);
        // The lease's name servers and default route go with it.
        socks.set_dns(k, &[]);
        socks.routes.set_auto(k, None);
    }
    if let Some((a, len)) = address {
        if len > 32 {
            return Err(err::EINVAL);
        }
        if sides[k].alloc.is_none() {
            stop_dhcp(&mut sides[k], &mut nets[k]);
        }
        // 0.0.0.0: the address goes (SIOCDIFADDR).
        if a == [0; 4] {
            clear_address(&mut sides[k], &mut nets[k]);
            socks.set_dns(k, &[]);
            socks.routes.set_auto(k, None);
            return Ok(());
        }
        let aliases = sides[k].status.aliases.clone();
        set_addrs(&mut nets[k].iface, Some((a, len)), &aliases);
        sides[k].status.address = Some((a, len));
        if sides[k].status.lease.map(|l| l.0) != Some(a) {
            sides[k].status.lease = None;
        }
    }
    if let Some(u) = up {
        nets[k].up = u;
        sides[k].status.up = u;
        if !u {
            sides[k].status.lease = None;
        }
        if sides[k].status.down_offline {
            if let Some(l) = sides[k].link.as_mut() {
                l.set_online(u);
            }
        }
    }
    Ok(())
}

/// StartDhcp: the interface's DHCP socket (once).
fn start_dhcp(sides: &mut [Side], nets: &mut [Net], name: &str) -> Result<(), i32> {
    let k = slot_of(sides, name).ok_or(err::ENXIO)?;
    if k == LO {
        return Err(err::EPERM);
    }
    if sides[k].dhcp.is_none() {
        sides[k].dhcp = Some(nets[k].sockets.add(dhcpv4::Socket::new()));
    }
    sides[k].dhcp_auto = true;
    Ok(())
}

/// Poll lo0 until it settles (each poll moves a packet one step through
/// the loop), 16 rounds at most.
fn poll_lo(net: &mut Net, lo: &mut Lo, t: Instant) {
    for _ in 0..16 {
        if matches!(net.iface.poll(t, lo, &mut net.sockets), PollResult::None) {
            break;
        }
    }
}

/// Forward the datagram in `frame` that came in on interface `k`
/// (forward.rs): TTL, route, MTU, next hop's Ethernet address (waiting for
/// ARP in `waiting` when it is not known yet).
#[allow(clippy::too_many_arguments)]
fn forward_one(sides: &mut [Side], nets: &mut [Net], socks: &mut crate::sock::Socks, neigh: &[crate::rtsock::Neighbor], k: usize, mut frame: Vec<u8>, now_us: u64, waiting: &mut Vec<crate::forward::Waiting>) {
    let total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    if total < 20 || 14 + total > frame.len() {
        return;
    }
    frame.truncate(14 + total);
    if frame[22] <= 1 {
        // Time exceeded in transit, from the receiving interface.
        fwd_icmp(sides, k, &frame, 11, 0, [0; 4]);
        return;
    }
    let dst = [frame[30], frame[31], frame[32], frame[33]];
    let Some((j, hop, prefix)) = socks.routes.next_hop(nets, dst) else {
        fwd_icmp(sides, k, &frame, 3, 1, [0; 4]);
        return;
    };
    let mtu = sides.get(j).map(|s| s.status.mtu as usize).unwrap_or(0);
    if total > mtu {
        // Too big: fragmentation needed when DF is set (no fragmenting
        // here otherwise).
        if frame[20] & 0x40 != 0 {
            let m = (mtu as u16).to_be_bytes();
            fwd_icmp(sides, k, &frame, 3, 4, [0, 0, m[0], m[1]]);
        }
        return;
    }
    frame[22] -= 1;
    crate::forward::fix_header(&mut frame[14..]);
    // Back out of the interface it came in on, from a host there, by a
    // route other than the default: an ICMP host redirect first (BSD).
    if j == k && prefix != 0 && crate::settings::SETTINGS.get(crate::settings::Setting::IcmpSendRedirects) != 0 {
        let src = [frame[26], frame[27], frame[28], frame[29]];
        let near = sides.get(k).and_then(|s| s.status.address).map(|(a, p)| crate::route::contains(a, p, src)).unwrap_or(false);
        if near {
            fwd_icmp(sides, k, &frame, 5, 1, hop);
        }
    }
    let me = sides.get(j).and_then(|s| s.status.address).map(|a| a.0);
    let Some(link) = sides.get_mut(j).and_then(|s| s.link.as_mut()) else { return };
    match neigh.iter().find(|n| n.0 == j && n.1 == hop) {
        Some(n) => {
            crate::forward::send_to(link, n.2, &frame[14..]);
        }
        None => {
            if let Some(me) = me {
                crate::forward::arp_request(link, me, hop);
            }
            waiting.push(crate::forward::Waiting { out: j, hop, frame, from: k, deadline: crate::forward::deadline(now_us), again: now_us + crate::forward::ARP_AGAIN_US });
        }
    }
}

/// An ICMP error about forwarded `frame` back to its sender through
/// interface `k` (its address as the source).
fn fwd_icmp(sides: &mut [Side], k: usize, frame: &[u8], kind: u8, code: u8, rest: [u8; 4]) {
    let Some(side) = sides.get_mut(k) else { return };
    let Some((me, _)) = side.status.address else { return };
    let Some(link) = side.link.as_mut() else { return };
    let mut to = [0u8; 6];
    to.copy_from_slice(&frame[6..12]);
    if let Some(f) = crate::forward::icmp_error(&frame[14..], kind, code, rest, me, link.mac, to) {
        link.send(&f);
    }
}

/// Send datagram `r` ("to" / "dup-to") out of interface `k`: to its next
/// hop if that is on the interface's network, else to its router, by the
/// ARP table (an address not in it is a failure, as an unresolved route).
fn fastroute(side: &mut Side, neigh: &[crate::rtsock::Neighbor], k: usize, r: &crate::ipfil::Routed) -> bool {
    let Some(link) = side.link.as_mut() else { return false };
    if r.frame.len() < 34 {
        return false;
    }
    let dst = if r.hop != 0 { r.hop } else { r.dst };
    let hop = match side.status.address {
        Some((a, p)) if p > 0 && (u32::from_be_bytes(a) ^ dst) >> (32 - p as u32) == 0 => dst.to_be_bytes(),
        _ => match side.status.router {
            Some(g) => g,
            None => return false,
        },
    };
    let Some(n) = neigh.iter().find(|n| n.0 == k && n.1 == hop) else { return false };
    let mut f = Vec::with_capacity(r.frame.len());
    f.extend_from_slice(&n.2);
    f.extend_from_slice(&link.mac);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&r.frame[14..]);
    link.send_unfiltered(&f)
}

/// The stack process's body: lo0 at first; interfaces come by command.
fn run(starter: Sender<Ctl>) {
    let ready = |r: Result<(Sender<Ctl>, Arc<Mutex<Core>>), String>| {
        if let Ok(m) = Message::new(Ctl::Ready(r)) {
            let _ = starter.send(m);
        }
    };
    let port = match Port::<Ctl>::new() {
        Ok(p) => p,
        Err(e) => return ready(Err(alloc::format!("command port: {}", e))),
    };
    let mut timer = match AmigaTimer::open(TimerUnit::MicroHz) {
        Ok(t) => t,
        Err(e) => return ready(Err(alloc::format!("timer.device: {}", e))),
    };
    let mut sides: Vec<Side> = Vec::new();
    let mut nets: Vec<Net> = Vec::new();
    let mut seed = get_up_time().as_micros();

    // lo0, 127.0.0.1/8, slot 0: programs connect to themselves (curl builds
    // its socketpair from a TCP connection to 127.0.0.1).
    let mut lo = Lo(Loopback::new(Medium::Ethernet));
    crate::ipf::set_ifnet(LO as u8, LO_IPF_NAME);
    {
        let mut config = IfaceConfig::new(EthernetAddress([0x02, 0, 0, 0, 0, 1]).into());
        config.random_seed = seed ^ 0x6c6f;
        let mut iface = Interface::new(config, &mut lo, now());
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8));
        });
        nets.push(Net { iface, sockets: SocketSet::new(vec![]), up: true });
        let status = Status {
            name: String::from(LO_NAME),
            loopback: true,
            present: true,
            up: true,
            mtu: 1500,
            address: Some(([127, 0, 0, 1], 8)),
            ..Status::default()
        };
        sides.push(Side { name: String::from(LO_NAME), ..Side::empty(status) });
    }
    let lo_k = LO;

    // NetShutdown's "TCP/IP Control" port (control.rs).
    let mut control = crate::control::Control::new();
    let mut pending: Option<PendingPing> = None;
    // Forwarded datagrams waiting for their next hop's ARP answer.
    let mut fwd_waiting: Vec<crate::forward::Waiting> = Vec::new();
    // Set at the first pass from task.controller.priority.
    let mut priority: i8 = i8::MIN;
    let mut quit: Option<Received<Ctl>> = None;
    // Frames at the last perf report (feature perf).
    let (mut perf_in, mut perf_out) = (0u64, 0u64);
    let socks = crate::sock::Socks::new(seed, nets.len());
    let wake = SignalTarget::new(signal::current_task(), port.signal_mask());
    let core = match Mutex::new(Core { nets, socks, wake, alive: true, watchers: Vec::new() }) {
        Ok(m) => Arc::new(m),
        Err(e) => return ready(Err(alloc::format!("mutex: {}", e))),
    };
    ready(Ok((port.sender(), core.clone())));

    loop {
        // The drivers' replies first, before the lock: the links are this
        // process's own (sides), and taking replies and posting the reads
        // again is mostly the driver's work (a re-posted read is often
        // answered inside BeginIO: the next frame copied in). Under the
        // lock it was 40% of the pass on an X5000 while the program's
        // recv() waited for the lock.
        for side in sides.iter_mut() {
            if let Some(link) = side.link.as_mut() {
                let perf_t = crate::perf::now();
                link.poll();
                crate::perf::add(crate::perf::LINK_POLL, perf_t);
            }
        }
        // Held while working, let go of while sleeping. Never refused: no
        // other code in this task takes it.
        let perf_t = crate::perf::now();
        let Ok(mut guard) = core.lock() else { break };
        crate::perf::add(crate::perf::STACK_LOCK, perf_t);
        let perf_pass = crate::perf::now();
        let Core { nets, socks, watchers, .. } = &mut *guard;
        count(PERF_PASSES);
        // task.controller.priority (RoadshowControl) is the stack's.
        let want = crate::settings::SETTINGS.stack_priority();
        if want != priority {
            // SAFETY: SetTaskPri on this process itself.
            unsafe { amigaos4::sys::exec_set_task_pri(signal::current_task() as _, want) };
            priority = want;
        }
        let t = now();
        let addrs_before: Vec<Option<([u8; 4], u8)>> = sides.iter().map(|s| s.status.address).collect();
        // Datagrams the IP filter's auth program let go: out of their
        // interface, or in on it, through the filter again (ipfil.rs).
        for r in crate::ipfil::take_released() {
            match crate::ipf::slot_of(r.ifp).map(usize::from) {
                Some(k) if k == lo_k => {
                    if let Some(tx) = lo.transmit(t) {
                        tx.consume(r.frame.len(), |b| b.copy_from_slice(&r.frame));
                    }
                }
                Some(k) => {
                    if let Some(link) = sides.get_mut(k).and_then(|s| s.link.as_mut()) {
                        if r.out {
                            link.send(&r.frame);
                        } else {
                            link.inject(&r.frame);
                        }
                    }
                }
                None => {}
            }
        }
        let perf_t = crate::perf::now();
        poll_lo(&mut nets[lo_k], &mut lo, t);
        crate::perf::add(crate::perf::LO_POLL, perf_t);
        let mut dns_changes: Vec<(usize, Vec<[u8; 4]>)> = Vec::new();
        for (k, (side, net)) in sides.iter_mut().zip(nets.iter_mut()).enumerate() {
            let Some(link) = side.link.as_mut() else { continue };
            let perf_t = crate::perf::now();
            net.iface.poll(t, link, &mut net.sockets);
            crate::perf::add(crate::perf::IFACE_POLL, perf_t);
            let dhcp_ev = side.dhcp.and_then(|h| net.sockets.get_mut::<dhcpv4::Socket>(h).poll());
            match dhcp_ev {
                Some(dhcpv4::Event::Configured(c)) if !side.dhcp_auto => {
                    // BeginInterfaceConfig: the address is set here, the
                    // routes by the caller. The lease's name servers are
                    // kept as the stack's own (dynamic) ones, as Roadshow
                    // does; the caller usually adds them as static ones too.
                    let primary = Some((c.address.address().octets(), c.address.prefix_len()));
                    let aliases = side.status.aliases.clone();
                    set_addrs(&mut net.iface, primary, &aliases);
                    side.status.address = primary;
                    side.status.dns = c.dns_servers.iter().map(|d| d.octets()).collect();
                    side.status.leases += 1;
                    dns_changes.push((k, side.status.dns.clone()));
                    if let Some((m, _)) = side.alloc.take() {
                        let lease = lease_of(&c);
                        let end = match lease.lease_secs {
                            Some(s) if s != u32::MAX => get_up_time().as_micros().saturating_add(s as u64 * 1_000_000),
                            _ => u64::MAX,
                        };
                        side.status.lease = Some((lease.address, end));
                        // SAFETY: the message BeginInterfaceConfig handed over.
                        unsafe { aam::complete(m, aam::AAMR_SUCCESS, Some(&lease)) };
                    }
                }
                Some(dhcpv4::Event::Configured(c)) => {
                    let primary = Some((c.address.address().octets(), c.address.prefix_len()));
                    let aliases = side.status.aliases.clone();
                    set_addrs(&mut net.iface, primary, &aliases);
                    socks.routes.set_auto(k, c.router.map(|r| r.octets()));
                    let st = &mut side.status;
                    st.address = Some((c.address.address().octets(), c.address.prefix_len()));
                    st.router = c.router.map(|r| r.octets());
                    st.dns = c.dns_servers.iter().map(|d| d.octets()).collect();
                    st.leases += 1;
                    dns_changes.push((k, st.dns.clone()));
                }
                Some(dhcpv4::Event::Deconfigured) => {
                    net.iface.update_ip_addrs(|a| a.clear());
                    socks.routes.set_auto(k, None);
                    let st = &mut side.status;
                    st.address = None;
                    st.router = None;
                    st.dns.clear();
                    dns_changes.push((k, Vec::new()));
                }
                None => {}
            }

            // Echo replies for the ping in flight.
            let Some(ping) = side.ping else { continue };
            let s = net.sockets.get_mut::<icmp::Socket>(ping);
            while s.can_recv() {
                let Ok((data, _from)) = s.recv() else { break };
                let Ok(pkt) = Icmpv4Packet::new_checked(data) else { continue };
                let Ok(Icmpv4Repr::EchoReply { ident, seq_no, .. }) = Icmpv4Repr::parse(&pkt, &ChecksumCapabilities::default()) else {
                    continue;
                };
                if ident != PING_IDENT {
                    continue;
                }
                if let Some(mut p) = pending.take() {
                    let matches = matches!(&*p.msg, Ctl::Ping { seq, .. } if *seq == seq_no);
                    if matches {
                        if let Ctl::Ping { rtt_us, .. } = &mut *p.msg {
                            *rtt_us = Some((t - p.sent).total_micros());
                        }
                        p.msg.reply();
                    } else {
                        pending = Some(p);
                    }
                }
            }
        }
        // Datagrams for other hosts (ip.forwarding: forward.rs), and the
        // ones still waiting for their next hop's ARP answer.
        let mut fwd_frames: Vec<(usize, Vec<u8>)> = Vec::new();
        for (k, side) in sides.iter_mut().enumerate() {
            if let Some(l) = side.link.as_mut() {
                fwd_frames.extend(l.fwd.drain(..).map(|f| (k, f)));
            }
        }
        if !fwd_frames.is_empty() || !fwd_waiting.is_empty() {
            let neigh = crate::rtsock::neighbors(nets, t);
            let now_us = get_up_time().as_micros();
            for (k, f) in fwd_frames {
                forward_one(&mut sides, nets, socks, &neigh, k, f, now_us, &mut fwd_waiting);
            }
            let mut still = Vec::new();
            for w in core::mem::take(&mut fwd_waiting) {
                let mac = neigh.iter().find(|n| n.0 == w.out && n.1 == w.hop).map(|n| n.2);
                match mac {
                    Some(m) => {
                        if let Some(l) = sides.get_mut(w.out).and_then(|s| s.link.as_mut()) {
                            crate::forward::send_to(l, m, &w.frame[14..]);
                        }
                    }
                    None if crate::forward::expired(&w, now_us) => fwd_icmp(&mut sides, w.from, &w.frame, 3, 1, [0; 4]),
                    None => {
                        let mut w = w;
                        if now_us >= w.again {
                            w.again = now_us + crate::forward::ARP_AGAIN_US;
                            let me = sides.get(w.out).and_then(|s| s.status.address).map(|a| a.0);
                            if let (Some(l), Some(me)) = (sides.get_mut(w.out).and_then(|s| s.link.as_mut()), me) {
                                crate::forward::arp_request(l, me, w.hop);
                            }
                        }
                        still.push(w);
                    }
                }
            }
            fwd_waiting = still;
        }
        // ICMP redirects (4.4BSD's rtredirect, as Roadshow takes them):
        // from the current gateway for the destination,
        // to a gateway on a connected network that is not ours; a host
        // route gets the new gateway, else a host route is added.
        let mut redirects = Vec::new();
        for side in sides.iter_mut() {
            if let Some(l) = side.link.as_mut() {
                redirects.extend(l.redirects.drain(..));
            }
        }
        for (dst, gw, from) in redirects {
            let ours = sides.iter().any(|s| s.status.address.map(|a| a.0) == Some(gw));
            let Some((_, hop, prefix)) = socks.routes.next_hop(nets, dst) else { continue };
            let connected = socks.routes.next_hop(nets, gw).map(|h| h.1 == gw).unwrap_or(false);
            if hop != from || ours || !connected || hop == dst {
                continue;
            }
            let r = if prefix == 32 { socks.routes.change(nets, dst, 32, gw) } else { socks.routes.add(nets, dst, 32, gw) };
            if r.is_err() {
                let _ = socks.routes.add(nets, dst, 32, gw);
            }
        }
        // Every address of the stack, for the links (what is not for us).
        let local: Vec<[u8; 4]> = sides.iter().flat_map(|s| s.status.address.map(|a| a.0).into_iter().chain(s.status.aliases.iter().copied())).collect();
        for side in sides.iter_mut() {
            if let Some(l) = side.link.as_mut() {
                if l.local != local {
                    l.local = local.clone();
                }
            }
        }
        // Datagrams the IP filter routes itself ("to", "dup-to": ipfil.rs).
        let routed = crate::ipfil::take_routed();
        if !routed.is_empty() {
            let neigh = crate::rtsock::neighbors(nets, t);
            let mut round_lo = false;
            for r in routed {
                let ok = match crate::ipf::slot_of(r.ifp).map(usize::from) {
                    Some(k) if k == lo_k => {
                        round_lo = true;
                        match lo.transmit(t) {
                            Some(tx) => {
                                tx.consume(r.frame.len(), |b| b.copy_from_slice(&r.frame));
                                true
                            }
                            None => false,
                        }
                    }
                    Some(k) => sides.get_mut(k).map(|s| fastroute(s, &neigh, k, &r)).unwrap_or(false),
                    None => false,
                };
                crate::ipfil::froute_done(ok);
            }
            if round_lo {
                poll_lo(&mut nets[lo_k], &mut lo, t);
            }
        }
        for (k, dns) in dns_changes {
            socks.set_dns(k, &dns);
        }
        // Address requests whose time ran out.
        for (side, net) in sides.iter_mut().zip(nets.iter_mut()) {
            if let Some((m, deadline)) = side.alloc {
                if t >= deadline {
                    side.alloc = None;
                    stop_dhcp(side, net);
                    // SAFETY: the message BeginInterfaceConfig handed over.
                    unsafe { aam::complete(m, aam::AAMR_TIMEOUT, None) };
                }
            }
        }
        if pending.as_ref().map(|p| t >= p.deadline).unwrap_or(false) {
            if let Some(p) = pending.take() {
                p.msg.reply();
            }
        }

        // Socket ops waiting since an earlier round.
        let perf_t = crate::perf::now();
        let answered = socks.progress(nets);
        crate::perf::add(crate::perf::PROGRESS, perf_t);

        // Commands.
        let mut commands = 0u32;
        while let Ok(Some(mut m)) = port.try_recv() {
            commands += 1;
            if matches!(&*m, Ctl::Sock(_)) {
                socks.command(m, nets);
                continue;
            }
            match &mut *m {
                Ctl::Status(s) => {
                    *s = sides
                        .iter()
                        .map(|side| {
                            let mut st = side.status.clone();
                            if let Some(l) = &side.link {
                                st.link = l.stats;
                            }
                            st
                        })
                        .collect();
                    m.reply();
                }
                Ctl::AddIface { name, device, unit, mac, down_offline, result } => {
                    *result = add_iface(&mut sides, nets, socks, &mut seed, name, device, *unit, *mac, *down_offline);
                    m.reply();
                }
                Ctl::RemoveIface { name, force, result } => {
                    *result = remove_iface(&mut sides, nets, socks, name, *force);
                    m.reply();
                }
                Ctl::ConfigIface { name, address, up, release, result } => {
                    *result = config_iface(&mut sides, nets, socks, name, *address, *up, *release);
                    m.reply();
                }
                Ctl::StartDhcp { name, result } => {
                    *result = start_dhcp(&mut sides, nets, name);
                    m.reply();
                }
                Ctl::BeginConfig { name, aam: msg, timeout_s, lease_s, client_id, result } => {
                    *result = begin_config(&mut sides, nets, name, *msg, *timeout_s, *lease_s, client_id);
                    m.reply();
                }
                Ctl::Route { op, result } => {
                    *result = match *op {
                        RouteOp::Add { dst, prefix, gateway } => socks.routes.add(nets, dst, prefix, gateway),
                        RouteOp::Delete { dst, prefix } => socks.routes.delete(dst, prefix),
                        RouteOp::Change { dst, prefix, gateway } => socks.routes.change(nets, dst, prefix, gateway),
                    };
                    m.reply();
                }
                Ctl::Routes(v) => {
                    *v = socks.routes.all(nets);
                    m.reply();
                }
                Ctl::NameServer { address, add, fixed, result } => {
                    *result = if *add {
                        socks.add_name_server(*address, *fixed);
                        Ok(())
                    } else {
                        socks.remove_name_server(*address)
                    };
                    m.reply();
                }
                Ctl::FileNameServers(v) => {
                    socks.file_servers = core::mem::take(v);
                    m.reply();
                }
                Ctl::NameServers(v) => {
                    *v = socks.name_server_list();
                    m.reply();
                }
                Ctl::Neighbors(v) => {
                    *v = socks.neighbors(nets);
                    m.reply();
                }
                Ctl::IfaceOpts { name, opts, result } => {
                    *result = iface_opts(&mut sides, nets, name, opts);
                    m.reply();
                }
                Ctl::BpfWrite { slot, frame, result } => {
                    *result = match sides.get_mut(*slot as usize).and_then(|s| if s.status.present { s.link.as_mut() } else { None }) {
                        Some(link) if frame.len() >= 14 && frame.len() <= link.mtu as usize + 14 => {
                            let n = frame.len();
                            if link.send_with(n, |b| b.copy_from_slice(frame)).1 { Ok(n) } else { Err(err::EIO) }
                        }
                        Some(_) => Err(err::EINVAL),
                        None => Err(err::ENXIO),
                    };
                    m.reply();
                }
                Ctl::AbortConfig { aam: msg } => {
                    let msg = *msg;
                    // The allocation message is answered BEFORE the caller's
                    // AbortInterfaceConfig returns: the caller may free it
                    // (and its reply port) as soon as that call is back, and
                    // a reply after that wrote into freed memory. On an
                    // X5000 that froze the machine in 5 of 8 boots with a
                    // cable-less unit whose DHCP timed out.
                    for (side, net) in sides.iter_mut().zip(nets.iter_mut()) {
                        if side.alloc.map(|(a, _)| a) == Some(msg) {
                            side.alloc = None;
                            stop_dhcp(side, net);
                            // SAFETY: the message BeginInterfaceConfig handed over.
                            unsafe { aam::complete(msg, aam::AAMR_ABORTED, None) };
                        }
                    }
                    m.reply();
                }
                Ctl::Ping { addr, seq, timeout_ms, .. } => {
                    let k = socks.route_for(nets, *addr);
                    let (Some((k, ping)), None) = (k.and_then(|k| sides.get(k)?.ping.map(|p| (k, p))), pending.as_ref()) else {
                        // One at a time, and only with an address.
                        m.reply();
                        continue;
                    };
                    let (addr, seq, timeout_ms) = (*addr, *seq, *timeout_ms);
                    let payload = [0x52u8; 32];
                    let repr = Icmpv4Repr::EchoRequest { ident: PING_IDENT, seq_no: seq, data: &payload };
                    let s = nets[k].sockets.get_mut::<icmp::Socket>(ping);
                    let dst = IpAddress::Ipv4(Ipv4Address::new(addr[0], addr[1], addr[2], addr[3]));
                    match s.send(repr.buffer_len(), dst) {
                        Ok(buf) => {
                            let mut pkt = Icmpv4Packet::new_unchecked(buf);
                            repr.emit(&mut pkt, &ChecksumCapabilities::default());
                            pending = Some(PendingPing { msg: m, sent: t, deadline: t + smoltcp::time::Duration::from_millis(timeout_ms as u64) });
                        }
                        Err(_) => m.reply(),
                    }
                }
                Ctl::Quit => {
                    quit = Some(m);
                    break;
                }
                Ctl::Abort(token) => {
                    let token = *token;
                    m.reply();
                    socks.abort(token);
                }
                Ctl::Ready(_) | Ctl::Sock(_) => m.reply(),
            }
        }
        if let Some(c) = control.as_mut() {
            if c.poll() {
                // NetShutdown: the network goes down under the programs
                // (their descriptors stay; connections reset).
                let names: Vec<String> = sides.iter().skip(1).filter(|s| s.status.present).map(|s| s.name.clone()).collect();
                for n in names {
                    let _ = remove_iface(&mut sides, nets, socks, &n, true);
                }
                socks.routes.clear();
                socks.name_servers.clear();
                c.finish();
            }
        }
        if quit.is_some() {
            break;
        }
        // Send what the commands queued before sleeping, and answer what
        // that made possible. A pass with no command (frames only, or an
        // inline recv/send's wake: the first round above already polled
        // after those) skips it: on an X5000 this round and its progress
        // cost ~2.4 us of the stack's 17 us per received frame (feature
        // perf).
        if commands > 0 || answered {
            let perf_r2 = crate::perf::now();
            let t2 = now();
            for (side, net) in sides.iter_mut().zip(nets.iter_mut()) {
                if let Some(link) = side.link.as_mut() {
                    net.iface.poll(t2, link, &mut net.sockets);
                }
            }
            crate::perf::add(crate::perf::ROUND2, perf_r2);
            let perf_t = crate::perf::now();
            poll_lo(&mut nets[lo_k], &mut lo, t2);
            crate::perf::add(crate::perf::LO_POLL, perf_t);
            let perf_t = crate::perf::now();
            let _ = socks.progress(nets);
            crate::perf::add(crate::perf::PROGRESS, perf_t);
        }

        let perf_dl = crate::perf::now();
        // Sleep until a frame, a command, or smoltcp's next deadline (a
        // ping's deadline at the latest, and 1 s at most).
        let t = now();
        let mut delay: u64 = 1_000_000;
        let mut mask = port.signal_mask() | timer.signal_mask() | control.as_ref().map(|c| c.signal_mask()).unwrap_or(0);
        let mut queued = false;
        let lo_net = &mut nets[lo_k];
        if let Some(d) = lo_net.iface.poll_delay(t, &lo_net.sockets) {
            delay = delay.min(d.total_micros());
        }
        for (side, net) in sides.iter().zip(nets.iter_mut()) {
            let Some(link) = side.link.as_ref() else { continue };
            if let Some(d) = net.iface.poll_delay(t, &net.sockets) {
                delay = delay.min(d.total_micros());
            }
            mask |= link.signal_mask();
            queued |= !link.rx.is_empty();
        }
        if let Some(until) = socks.next_deadline() {
            delay = delay.min(until.saturating_sub(get_up_time().as_micros()));
        }
        if let Some(p) = &pending {
            delay = delay.min((p.deadline - t).total_micros());
        }
        for (_, deadline) in sides.iter().filter_map(|s| s.alloc) {
            delay = delay.min(if deadline > t { (deadline - t).total_micros() } else { 0 });
        }
        crate::perf::add(crate::perf::DELAYS, perf_dl);
        // An address set or cleared this round: the routes follow, and who
        // asked is told.
        if sides.iter().map(|s| s.status.address).ne(addrs_before.iter().copied()) {
            socks.routes.touch();
            for &(_, task, mask) in watchers.iter() {
                // SAFETY: a task that registered itself and unregisters
                // before it goes (the library, at the opener's end).
                unsafe { amigaos4::sys::exec_signal(task as *mut amigaos4::sys::Task, mask) };
            }
        }
        socks.routes.program(nets);
        crate::perf::add(crate::perf::PASS, perf_pass);
        if cfg!(feature = "perf") {
            let (fi, fo) = sides.iter().filter_map(|s| s.link.as_ref()).fold((0u64, 0u64), |a, l| (a.0 + l.stats.rx_frames as u64, a.1 + l.stats.tx_frames as u64));
            if crate::perf::report(fi.wrapping_sub(perf_in), fo.wrapping_sub(perf_out)) {
                perf_in = fi;
                perf_out = fo;
                for l in sides.iter().filter_map(|s| s.link.as_ref()) {
                    crate::perf::link_s2x(l.slot, &l.stats);
                }
            }
        }
        drop(guard);
        // What this pass sent, written now that the lock is free.
        for side in sides.iter_mut() {
            if let Some(link) = side.link.as_mut() {
                link.flush();
            }
        }
        if !queued {
            timer.start(TimerVal::from_micros(delay.max(1000)));
            count(PERF_SLEEPS);
            let perf_t = crate::perf::now();
            signal::wait(mask);
            crate::perf::add(crate::perf::SLEEP, perf_t);
            if timer.is_done() {
                timer.finish();
            } else {
                timer.abort();
            }
        }
    }

    if let Some(p) = pending.take() {
        p.msg.reply();
    }
    // Shutdown requests are answered as the stack ends.
    drop(control);
    for side in sides.iter_mut() {
        if let Some((m, _)) = side.alloc.take() {
            // SAFETY: the message BeginInterfaceConfig handed over.
            unsafe { aam::complete(m, aam::AAMR_ABORTED, None) };
        }
    }
    if let Ok(mut g) = core.lock() {
        let Core { nets, socks, alive, .. } = &mut *g;
        *alive = false;
        socks.shutdown(nets);
        nets.clear();
    }
    drop(core);
    // Close the links before answering Quit, so the starter knows the units
    // are free once it has the reply.
    drop(sides);
    if let Some(q) = quit {
        q.reply();
    }
}

/// The stack process's task name: one stack at a time; [`Stack::stop`]
/// waits until FindTask no longer finds it.
pub const STACK_TASK: &str = "rsnet stack";

/// The handle to a running stack process. Only a [`Sender`]: `Send` and
/// `Clone`, so a library can keep it for all its openers; each call makes
/// a reply port in the calling task.
#[derive(Clone)]
pub struct Stack {
    to_stack: Sender<Ctl>,
    core: Arc<Mutex<Core>>,
}

impl Stack {
    /// Start the stack process, then add `cfg`'s units and start DHCP on
    /// each, as a running stack's users do. The process is detached: it
    /// belongs to no opener, and ends only on [`stop`](Self::stop). Call
    /// from a Process.
    pub fn start(cfg: Config) -> Result<Self, String> {
        let s = Self::start_empty()?;
        for u in &cfg.units {
            if let Err(e) = s.add_iface(&u.name, &u.device, u.unit, None, false) {
                s.stop();
                return Err(alloc::format!("{}: {} unit {}: errno {}", u.name, u.device, u.unit, e));
            }
            let _ = s.start_dhcp(&u.name);
        }
        Ok(s)
    }

    fn start_empty() -> Result<Self, String> {
        let replies = Port::<Ctl>::new().map_err(|e| alloc::format!("reply port: {}", e))?;
        let starter = replies.sender();
        // 256 KB: smoltcp's Interface holds its fragmentation buffers
        // inline and is built (and moved) on this stack.
        let b = process::ProcessBuilder::new(STACK_TASK).map_err(|e| alloc::format!("stack process: {}", e))?.stack(262144);
        b.spawn_detached(move || run(starter)).map_err(|e| alloc::format!("stack process: {}", e))?;
        loop {
            let m = replies.recv().map_err(|e| alloc::format!("waiting for the stack: {}", e))?;
            if let Ctl::Ready(_) = &*m {
                return match m.into_message().into_inner() {
                    Ctl::Ready(Ok((to_stack, core))) => Ok(Self { to_stack, core }),
                    Ctl::Ready(Err(e)) => {
                        wait_gone();
                        Err(e)
                    }
                    _ => unreachable!(),
                };
            }
        }
    }

    /// Send `c` and wait for it to come back answered (a reply port of the
    /// calling task, for this call).
    fn call(&self, c: Ctl) -> Option<Ctl> {
        let replies = Port::<Ctl>::new().ok()?;
        let m = Message::with_reply(c, &replies).ok()?;
        self.to_stack.send(m).ok()?;
        loop {
            let r = replies.recv().ok()?;
            if r.is_reply() {
                return Some(r.into_message().into_inner());
            }
        }
    }

    /// Add an interface on SANA-II `device` `unit`, named `name`: up, with
    /// no address. errno on failure (EEXIST, ENODEV, ENOBUFS, EINVAL).
    pub fn add_iface(&self, name: &str, device: &str, unit: u32, mac: Option<[u8; 6]>, down_offline: bool) -> Result<(), i32> {
        match self.call(Ctl::AddIface { name: String::from(name), device: String::from(device), unit, mac, down_offline, result: Err(err::ENXIO) }) {
            Some(Ctl::AddIface { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// Remove interface `name` (EBUSY while a connection uses it, unless
    /// `force`; ENXIO when there is none; EPERM for lo0).
    pub fn remove_iface(&self, name: &str, force: bool) -> Result<(), i32> {
        match self.call(Ctl::RemoveIface { name: String::from(name), force, result: Err(err::ENXIO) }) {
            Some(Ctl::RemoveIface { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// Set interface `name`'s address (with its prefix length) and/or
    /// whether it is up.
    pub fn config_iface(&self, name: &str, address: Option<([u8; 4], u8)>, up: Option<bool>, release: bool) -> Result<(), i32> {
        match self.call(Ctl::ConfigIface { name: String::from(name), address, up, release, result: Err(err::ENXIO) }) {
            Some(Ctl::ConfigIface { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// BeginInterfaceConfig: DHCP on `name` for the message at `aam`.
    /// BEGIN_PENDING when the stack keeps the message (it replies it when
    /// done), else the aam_Result to reply it with now.
    pub fn begin_config(&self, name: &str, aam: usize, timeout_s: u32, lease_s: u32, client_id: Vec<u8>) -> i32 {
        match self.call(Ctl::BeginConfig { name: String::from(name), aam, timeout_s, lease_s, client_id, result: aam::AAMR_NO_MEMORY }) {
            Some(Ctl::BeginConfig { result, .. }) => result,
            _ => aam::AAMR_NO_MEMORY,
        }
    }

    /// Add, delete or change a route (errno on failure).
    pub fn route(&self, op: RouteOp) -> Result<(), i32> {
        match self.call(Ctl::Route { op, result: Err(err::ENXIO) }) {
            Some(Ctl::Route { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// Add a name server (`fixed`: from the configuration file).
    pub fn add_name_server(&self, address: [u8; 4], fixed: bool) -> Result<(), i32> {
        match self.call(Ctl::NameServer { address, add: true, fixed, result: Err(err::ENXIO) }) {
            Some(Ctl::NameServer { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// name_resolution's `nameserver` lines (replacing the ones before).
    pub fn set_file_name_servers(&self, servers: Vec<[u8; 4]>) {
        let _ = self.call(Ctl::FileNameServers(servers));
    }

    /// Remove (one use of) a name server.
    pub fn remove_name_server(&self, address: [u8; 4]) -> Result<(), i32> {
        match self.call(Ctl::NameServer { address, add: false, fixed: false, result: Err(err::ENXIO) }) {
            Some(Ctl::NameServer { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// Every interface's ARP entries: (slot, address, MAC, static).
    pub fn neighbors(&self) -> Option<Vec<crate::rtsock::Neighbor>> {
        match self.call(Ctl::Neighbors(Vec::new()))? {
            Ctl::Neighbors(v) => Some(v),
            _ => None,
        }
    }

    /// ConfigureInterfaceTagList's other options on `name`.
    pub fn iface_opts(&self, name: &str, opts: IfaceOpts) -> Result<(), i32> {
        match self.call(Ctl::IfaceOpts { name: String::from(name), opts, result: Err(err::ENXIO) }) {
            Some(Ctl::IfaceOpts { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// bpf_write: send `frame` (Ethernet header and all) out of `slot`.
    pub fn bpf_write(&self, slot: u8, frame: Vec<u8>) -> Result<usize, i32> {
        match self.call(Ctl::BpfWrite { slot, frame, result: Err(err::ENXIO) }) {
            Some(Ctl::BpfWrite { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// Every name server and its use count.
    pub fn name_servers(&self) -> Option<Vec<([u8; 4], i32)>> {
        match self.call(Ctl::NameServers(Vec::new()))? {
            Ctl::NameServers(v) => Some(v),
            _ => None,
        }
    }

    /// Every route, connected ones first.
    pub fn routes(&self) -> Option<Vec<crate::route::Route>> {
        match self.call(Ctl::Routes(Vec::new()))? {
            Ctl::Routes(v) => Some(v),
            _ => None,
        }
    }

    /// AbortInterfaceConfig for the message at `aam`.
    pub fn abort_config(&self, aam: usize) {
        let _ = self.call(Ctl::AbortConfig { aam });
    }

    /// Signal `mask` to `task` whenever an interface address changes,
    /// under `id` (one registration per id; mask 0 removes it).
    pub fn watch_addresses(&self, id: u32, task: usize, mask: u32) {
        if let Ok(mut g) = self.core.lock() {
            g.watchers.retain(|w| w.0 != id);
            if mask != 0 {
                g.watchers.push((id, task, mask));
            }
        }
    }

    /// Start DHCP on interface `name`.
    pub fn start_dhcp(&self, name: &str) -> Result<(), i32> {
        match self.call(Ctl::StartDhcp { name: String::from(name), result: Err(err::ENXIO) }) {
            Some(Ctl::StartDhcp { result, .. }) => result,
            _ => Err(err::ENXIO),
        }
    }

    /// Every slot's status, lo0 first (removed interfaces have
    /// `present == false`).
    pub fn status(&self) -> Option<Vec<Status>> {
        match self.call(Ctl::Status(Vec::new()))? {
            Ctl::Status(s) => Some(s),
            _ => None,
        }
    }

    /// Ping `addr`: the round trip in microseconds, None on no answer in
    /// `timeout_ms` (or before DHCP has given an address).
    pub fn ping(&self, addr: [u8; 4], seq: u16, timeout_ms: u32) -> Option<u64> {
        match self.call(Ctl::Ping { addr, seq, timeout_ms, rtt_us: None })? {
            Ctl::Ping { rtt_us, .. } => rtt_us,
            _ => None,
        }
    }

    /// A socket operation (see `sock::SockOp`), answered by the stack: the
    /// op with its result, or None if the stack is gone.
    pub fn sock(&self, op: crate::sock::SockOp) -> Option<crate::sock::SockOp> {
        self.sock_with(0, false, None, op, 0).map(|(op, _)| op)
    }

    /// As [`sock`](Self::sock) for a library call: `token` names the op,
    /// `nonblock` makes it answer at once, and while it waits any of
    /// `break_mask` (the opener's break or select signals) arriving aborts
    /// it (the stack answers it with EINTR, unless it had its answer
    /// already). Returns the op and which of `break_mask` arrived (left
    /// cleared).
    pub fn sock_with(&self, token: u32, nonblock: bool, deadline_us: Option<u64>, op: crate::sock::SockOp, break_mask: u32) -> Option<(crate::sock::SockOp, u32)> {
        let replies = Port::<Ctl>::new().ok()?;
        let m = Message::with_reply(Ctl::Sock(crate::sock::SockMsg { token, nonblock, deadline_us, op }), &replies).ok()?;
        self.to_stack.send(m).ok()?;
        let mut hit = 0;
        loop {
            if let Ok(Some(r)) = replies.try_recv() {
                if r.is_reply() {
                    return match r.into_message().into_inner() {
                        Ctl::Sock(msg) => Some((msg.op, hit)),
                        _ => None,
                    };
                }
                continue;
            }
            let got = signal::wait(replies.signal_mask() | break_mask);
            if got & break_mask != 0 && hit == 0 {
                hit = got & break_mask;
                if let Ok(a) = Message::new(Ctl::Abort(token)) {
                    let _ = self.to_stack.send(a);
                }
            }
        }
    }

    /// TCP socket `h`'s queued bytes copied into `buf` by the calling task,
    /// if it has any: Some(count), or None when the op must go to the stack
    /// as a message (nothing queued, the end of the stream, not a connected
    /// TCP socket, the stack gone).
    pub fn recv_now(&self, h: u32, buf: &mut [u8], break_mask: u32) -> Option<usize> {
        self.now(break_mask, |c| c.socks.recv_now(h, buf, &mut c.nets))
    }

    /// As much of `data` as TCP socket `h`'s transmit buffer takes now,
    /// copied in by the calling task: Some(count), or None when the op must
    /// go to the stack (no room, not a connected TCP socket, the stack
    /// gone).
    pub fn send_now(&self, h: u32, data: &[u8], break_mask: u32) -> Option<usize> {
        self.now(break_mask, |c| c.socks.send_now(h, data, &mut c.nets))
    }

    /// Run `f` on the shared state under the lock; when it did something,
    /// wake the stack to act on it. A signal in `break_mask` while waiting
    /// for the lock gives up (None) and is raised again, so the message path
    /// the caller falls back to sees it and answers EINTR.
    fn now(&self, break_mask: u32, f: impl FnOnce(&mut Core) -> Option<usize>) -> Option<usize> {
        let perf_t = crate::perf::now();
        // A program may set its break mask to 0: then nothing interrupts.
        let got = if break_mask == 0 {
            self.core.lock().map(Ok)
        } else {
            self.core.lock_or_signal(break_mask)
        };
        let mut g = match got.ok()? {
            Ok(g) => g,
            Err(hit) => {
                // SAFETY: SetSignal only changes the calling task's own
                // signal bits; `hit` are break signals it was sent.
                unsafe { amigaos4::sys::exec_set_signal(hit, hit) };
                return None;
            }
        };
        crate::perf::add(crate::perf::CALLER_LOCK, perf_t);
        let perf_t = crate::perf::now();
        if !g.alive {
            return None;
        }
        let Some(n) = f(&mut g) else {
            count(PERF_INLINE_MISS);
            return None;
        };
        count(PERF_INLINE);
        // SAFETY: `alive` under the lock: the stack process clears it, under
        // this lock, before it ends, and owns its port's signal until then.
        unsafe { g.wake.send() };
        crate::perf::add(crate::perf::CALLER_WORK, perf_t);
        Some(n)
    }

    /// Wake the stack process (it has work outside a message: a datagram
    /// the IP filter's auth program let go).
    pub fn wake(&self) {
        if let Ok(g) = self.core.lock() {
            if g.alive {
                // SAFETY: `alive` under the lock, as in `now`.
                unsafe { g.wake.send() };
            }
        }
    }

    /// Stop the stack: the link closed (Quit is answered after that), then
    /// wait until the process has gone, so its code may be unloaded.
    pub fn stop(self) {
        let _ = self.call(Ctl::Quit);
        wait_gone();
    }
}

/// Wait (up to 10 s) until the stack process has left exec's task lists.
fn wait_gone() {
    let mut name = alloc::vec::Vec::from(STACK_TASK.as_bytes());
    name.push(0);
    for _ in 0..500 {
        // SAFETY: FindTask by a NUL-terminated name only reads the lists.
        if unsafe { amigaos4::sys::exec_find_task(name.as_ptr() as _) }.is_null() {
            return;
        }
        // SAFETY: Delay(1), 1/50 s, from a Process (the callers are).
        unsafe { amigaos4::sys::dos_delay(1) };
    }
}
