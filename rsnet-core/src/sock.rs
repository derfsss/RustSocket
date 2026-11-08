//! Sockets in the stack process, for the library's openers: TCP (streams
//! and listeners), UDP, and DNS lookups.
//!
//! Each [`SockMsg`] arrives as a [`Ctl::Sock`] message from an opener's task,
//! which waits for the reply. An op that can be answered at once is replied
//! at once; one that has to wait (a connect not yet established, a recv
//! with nothing queued, a send with the transmit buffer full, an accept
//! with no connection, a select with nothing ready, a lookup in flight) is
//! kept and tried again after every poll. A non-blocking op never waits:
//! EWOULDBLOCK, or EINPROGRESS for a connect, which then goes on in the
//! background. [`Ctl::Abort`] with the op's token answers a waiting op at
//! once with EINTR (the opener's break or select signals).
//!
//! Data crosses as owned `Vec`s in the shared heap: the opener's library
//! call copies the program's buffer in its own task (a program's memory
//! may be private to it), and the stack copies from and into smoltcp.
//!
//! A listener is a pool of smoltcp sockets listening on one port (a smoltcp
//! socket takes one connection and stops listening): accept takes an
//! established one out of the pool and puts a new listening one in.
//!
//! Several interfaces ([`Net`]: an Interface and its own SocketSet each): a
//! TCP socket is made on the first and moved, before it connects, to the
//! one that routes to its peer; a listener on any address listens on all;
//! a UDP socket has one smoltcp socket per interface, bound alike.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use amigaos4::msg::Received;
use amigaos4::signal::SignalTarget;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::Socket;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv4Cidr};

use crate::stack::Ctl;

/// BSD errno values (netinclude/sys/errno.h).
pub mod errno {
    pub const EINTR: i32 = 4;
    /// The IP filter blocked the datagram on its way out (ipfil.rs).
    pub const EHOSTUNREACH: i32 = 65;
    pub const EBADF: i32 = 9;
    pub const ENOMEM: i32 = 12;
    pub const EINVAL: i32 = 22;
    pub const EPIPE: i32 = 32;
    pub const EWOULDBLOCK: i32 = 35;
    pub const EINPROGRESS: i32 = 36;
    pub const EALREADY: i32 = 37;
    pub const EDESTADDRREQ: i32 = 39;
    pub const EMSGSIZE: i32 = 40;
    pub const EOPNOTSUPP: i32 = 45;
    pub const ENOPROTOOPT: i32 = 42;
    pub const EPROTONOSUPPORT: i32 = 43;
    pub const EAFNOSUPPORT: i32 = 47;
    pub const EADDRINUSE: i32 = 48;
    pub const ENETUNREACH: i32 = 51;
    pub const EISCONN: i32 = 56;
    pub const ENOTCONN: i32 = 57;
    pub const ETIMEDOUT: i32 = 60;
    pub const ECONNREFUSED: i32 = 61;
    pub const ECONNRESET: i32 = 54;
}

/// h_errno values (netinclude/netdb.h).
pub mod herrno {
    pub const HOST_NOT_FOUND: i32 = 1;
    pub const TRY_AGAIN: i32 = 2;
    pub const NO_RECOVERY: i32 = 3;
    pub const NO_DATA: i32 = 4;
}

/// What a socket is made as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockKind {
    Tcp,
    Udp,
    /// SOCK_RAW with this IP protocol (raw.rs).
    Raw(u8),
    /// A routing socket (PF_ROUTE, rtsock.rs).
    Route,
}

/// An IPv4 address and port.
pub type Endpoint = ([u8; 4], u16);

/// What [`SockOp::Info`] reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct SockInfo {
    pub local: Option<Endpoint>,
    pub remote: Option<Endpoint>,
    /// Bytes waiting to be read (FIONREAD): for UDP the next datagram's.
    pub readable: usize,
    /// A background connect's error, cleared by reading it (SO_ERROR).
    pub error: i32,
    pub kind: Option<SockKind>,
    pub listening: bool,
    pub keepalive: bool,
    pub nodelay: bool,
    pub linger_abort: bool,
    /// The receive and transmit buffer sizes (SO_RCVBUF, SO_SNDBUF).
    pub rx_buffer: usize,
    pub tx_buffer: usize,
}

/// One socket as `SockOp::List` reports it (Roadshow's
/// protocol_connection_data).
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnInfo {
    pub local: Endpoint,
    pub remote: Endpoint,
    pub recv_queue: u32,
    pub send_queue: u32,
    /// BSD TCPS_* (netinet/tcp_fsm.h); 0 for UDP.
    pub tcp_state: i32,
}

/// smoltcp's TCP state as BSD's TCPS_* number.
fn tcps(s: tcp::State) -> i32 {
    match s {
        tcp::State::Closed => 0,
        tcp::State::Listen => 1,
        tcp::State::SynSent => 2,
        tcp::State::SynReceived => 3,
        tcp::State::Established => 4,
        tcp::State::CloseWait => 5,
        tcp::State::FinWait1 => 6,
        tcp::State::Closing => 7,
        tcp::State::LastAck => 8,
        tcp::State::FinWait2 => 9,
        tcp::State::TimeWait => 10,
    }
}

/// A socket operation; the stack fills in `result`.
pub enum SockOp {
    /// A new socket: its stack handle.
    Open { kind: SockKind, result: Result<u32, i32> },
    /// The local address and port (port 0: any free one).
    Bind { h: u32, addr: [u8; 4], port: u16, result: Result<(), i32> },
    /// Listen for connections, up to `backlog` (1..=MAX_BACKLOG) at once.
    Listen { h: u32, backlog: i32, result: Result<(), i32> },
    /// A connection from the listener: its handle and peer.
    Accept { h: u32, result: Result<(u32, Endpoint), i32> },
    /// TCP: connect, answered when established or refused. UDP: the
    /// default peer (sends go there, other sources are ignored).
    Connect { h: u32, addr: [u8; 4], port: u16, result: Result<(), i32> },
    /// Queue `data` (UDP: one datagram, to `to` or the default peer);
    /// answered with how much was taken (TCP: at least one byte).
    Send { h: u32, data: Vec<u8>, to: Option<Endpoint>, result: Result<usize, i32> },
    /// Up to `max` bytes and the sender; TCP: an empty Vec at the end of
    /// the stream; UDP: one datagram, cut to `max`. `peek` leaves it queued
    /// (MSG_PEEK).
    Recv { h: u32, max: usize, peek: bool, result: Result<(Vec<u8>, Option<Endpoint>), i32> },
    /// Close (TCP: FIN after what is queued); the handle is gone at once.
    Close { h: u32, result: Result<(), i32> },
    /// shutdown: 0 reads, 1 writes (FIN), 2 both.
    Shutdown { h: u32, how: i32, result: Result<(), i32> },
    /// Addresses, bytes waiting, a background connect's error.
    Info { h: u32, take_error: bool, result: Result<SockInfo, i32> },
    /// Which of `reads` can be read (or accepted from, or are at the end,
    /// or failed) and which of `writes` can be written (or failed), waiting
    /// until one is or the up time reaches `until_us`.
    Select { reads: Vec<u32>, writes: Vec<u32>, until_us: Option<u64>, result: Result<(Vec<u32>, Vec<u32>), i32> },
    /// A DNS lookup (resolver.rs): a name's addresses (a dotted address is
    /// itself) or an address's name; the error is an h_errno value.
    Resolve { ask: crate::resolver::Ask, state: crate::resolver::State, result: Result<crate::resolver::Answer, i32> },
    /// Every socket of `kind`, of all openers (and TCP connections still
    /// closing).
    List { kind: SockKind, result: Vec<ConnInfo> },
    /// setsockopt's options that the stack keeps.
    SetOpt { h: u32, opt: SockOpt, result: Result<(), i32> },
    /// GetSocketEvents: the first of `hs` with events pending, and those
    /// events (cleared by this).
    TakeEvents { hs: Vec<u32>, result: Option<(u32, u32)> },
}

/// The socket options the stack itself applies.
pub enum SockOpt {
    /// SO_KEEPALIVE: probes after a quiet minute; a peer that answers
    /// nothing for five minutes is dropped.
    KeepAlive(bool),
    /// TCP_NODELAY (on by default here).
    NoDelay(bool),
    /// SO_LINGER with a zero time: CloseSocket resets the connection.
    LingerAbort(bool),
    /// SO_EVENTMASK: FD_* events to report, and whom to signal.
    Events(u32, Option<SignalTarget>),
    /// IP_TTL: this socket's datagrams' time to live.
    Ttl(u8),
    /// IP_HDRINCL (raw sockets): the program gives the IP header.
    HdrIncl(bool),
}

/// GetSocketEvents' events (libraries/bsdsocket.h).
pub mod fd_event {
    pub const ACCEPT: u32 = 0x01;
    pub const CONNECT: u32 = 0x02;
    pub const READ: u32 = 0x08;
    pub const WRITE: u32 = 0x10;
    pub const ERROR: u32 = 0x20;
    pub const CLOSE: u32 = 0x40;
}

/// A socket op as the library sends it.
pub struct SockMsg {
    /// Names the op for [`Ctl::Abort`].
    pub token: u32,
    /// The descriptor is non-blocking: never wait.
    pub nonblock: bool,
    /// SO_RCVTIMEO / SO_SNDTIMEO: a waiting op gives up at this up time
    /// (microseconds) with EWOULDBLOCK.
    pub deadline_us: Option<u64>,
    pub op: SockOp,
}

// The buffer sizes of new sockets are Roadshow's options tcp.recvspace,
// tcp.sendspace, udp.recvspace and udp.sendspace (settings.rs).
/// UDP (per interface): datagrams queued each way.
const UDP_RX_PACKETS: usize = 32;
const UDP_TX_PACKETS: usize = 16;
/// A listener's pool is at most this many sockets per interface (each has
/// its buffers).
pub const MAX_BACKLOG: usize = 4;
/// A connect gives up after this. Only while connecting: smoltcp checks
/// its timeout against the last packet received even when nothing waits
/// to be sent, so an established connection that is merely quiet would be
/// aborted (a client whose job ran longer than 20 s lost every reply).
const TIMEOUT_SECS: u64 = 20;

fn up_us() -> u64 {
    amigaos4::timer::get_up_time().as_micros()
}

fn tcp_socket() -> tcp::Socket<'static> {
    let (rx, tx) = crate::settings::SETTINGS.tcp_space();
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; rx]), tcp::SocketBuffer::new(vec![0u8; tx]));
    // The window scale offered in the SYN allows the buffer to grow to the
    // ceiling (tune_rx).
    s.set_rx_buffer_max(crate::settings::SETTINGS.tcp_recv_max());
    s.set_hop_limit(Some(crate::settings::SETTINGS.ttl()));
    s
}

fn udp_socket() -> udp::Socket<'static> {
    let (rs, ts) = crate::settings::SETTINGS.udp_space();
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_RX_PACKETS], vec![0u8; rs]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_TX_PACKETS], vec![0u8; ts]);
    let mut s = udp::Socket::new(rx, tx);
    s.set_hop_limit(Some(crate::settings::SETTINGS.ttl()));
    s
}

fn ep_of(addr: [u8; 4], port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(addr[0], addr[1], addr[2], addr[3])), port)
}

fn endpoint(p: IpEndpoint) -> Option<Endpoint> {
    match p.addr {
        IpAddress::Ipv4(a) => Some((a.octets(), p.port)),
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

/// One interface: smoltcp's Interface and the sockets it polls.
pub struct Net {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    /// Up (set down by the interface's configuration, or removed): a down
    /// interface is never chosen to send through.
    pub up: bool,
}

impl Net {
    pub(crate) fn addr(&self) -> Option<Ipv4Cidr> {
        self.iface.ip_addrs().iter().find_map(|a| match a {
            IpCidr::Ipv4(c) => Some(*c),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }
}

/// Room enough in `s`'s transmit buffer for a send of `len` bytes to go
/// ahead: all of it, or a quarter of the buffer. Without this a sender that
/// runs above the stack's priority wakes for every acknowledged segment and
/// moves one segment per call (a server's workers at priority +1 sent at
/// 0.6 MB/s).
fn send_room(s: &tcp::Socket, len: usize) -> bool {
    let free = s.send_capacity() - s.send_queue();
    free >= len.min(s.send_capacity() / 4)
}

/// SO_KEEPALIVE on a TCP socket: probes after a quiet minute, and a peer
/// that answers nothing for five minutes is dropped. Off: neither.
fn apply_keepalive(s: &mut tcp::Socket, on: bool) {
    if on {
        s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(60)));
        s.set_timeout(Some(smoltcp::time::Duration::from_secs(300)));
    } else {
        s.set_keep_alive(None);
        s.set_timeout(None);
    }
}


/// The interface that has address `a`.
fn owner(nets: &[Net], a: [u8; 4]) -> Option<usize> {
    nets.iter().position(|n| n.addr().map(|c| c.address().octets() == a).unwrap_or(false))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tcp,
    Listener,
    Udp,
}

/// A smoltcp socket: which interface's set, and its handle there.
type At = (usize, SocketHandle);

struct Entry {
    kind: Kind,
    /// TCP: the socket. UDP: unused (see `udp`). Listener: its first pool
    /// socket.
    at: At,
    /// A listener's listening sockets, on every interface it listens on.
    pool: Vec<At>,
    /// UDP: one socket per interface, all bound alike.
    udp: Vec<SocketHandle>,
    /// bind's address (None: any) and port (0: not bound).
    bound: (Option<[u8; 4]>, u16),
    /// A connect has been started in smoltcp and not yet finished.
    connecting: bool,
    /// A connect waiting for an interface with an address (DHCP), and
    /// since when.
    deferred: Option<(IpEndpoint, u64)>,
    /// When the connect was started, or 1 for an accepted connection (a
    /// close after the timeout is ETIMEDOUT, before it a refusal; 0 =
    /// never connected).
    started: u64,
    /// A background connect's error, for SO_ERROR and select.
    error: i32,
    /// The program has shut down reading.
    read_shut: bool,
    /// UDP: the default peer.
    peer: Option<IpEndpoint>,
    keepalive: bool,
    nodelay: bool,
    linger_abort: bool,
    /// The peer's FIN has been seen: a TCP connection that ends Closed
    /// without one was reset (recv gives ECONNRESET once).
    fin_seen: bool,
    /// SO_EVENTMASK's watch.
    ev: Option<Watch>,
    /// A listener's listening sockets per interface (an interface added
    /// later gets as many when the listener is bound to no address).
    backlog: usize,
    /// TCP: the receive buffer's auto-tuning (tune_rx).
    tune: Tune,
}

/// Receive-window auto-tuning, after Linux's dynamic
/// right-sizing: a connection starts with tcp.recvspace. Once per smoothed
/// round trip (or more: the check runs when the program reads), the rate
/// it read at, times the round trip, is the data in flight (the
/// bandwidth-delay product); the buffer is sized to twice that, to the
/// next 4 KB, between tcp.recvspace and tcp.recvspace.max. A window that
/// limits the sender reads at most a buffer per round trip, so the target
/// is then about twice the buffer: it grows until the window no longer
/// limits. It shrinks back:
/// - to tcp.recvspace after 2 s with nothing queued (an idle connection);
/// - to the target after 2 s in which every measurement wanted a quarter
///   of the buffer or less (the transfer slowed down, or the program reads
///   slowly): the advertised window is held to the target first, and the
///   buffer is made that size once what is queued fits (a slow reader's
///   buffer is full; shrinking it at once would drop data). Growth of at
///   least half the buffer when half or more of it is in flight.
/// Doubling on raw bytes per period (counted over periods longer than a
/// round trip) to powers of two took every long download to 1 MB where
/// ~300 KB carries it. Cells: the receive paths hold the entry shared.
#[derive(Default)]
struct Tune {
    /// When the current measurement began (ms of up time; 0: none).
    since_ms: core::cell::Cell<u64>,
    /// Bytes the program read since then.
    bytes: core::cell::Cell<usize>,
    /// When the program last read (ms of up time; 0: never).
    last_ms: core::cell::Cell<u64>,
    /// Since when every measurement wanted a quarter of the buffer or less
    /// (ms of up time; 0: not now).
    low_since: core::cell::Cell<u64>,
    /// The send buffer's (tune_tx): the same four, for what the program
    /// wrote.
    tx_since_ms: core::cell::Cell<u64>,
    tx_bytes: core::cell::Cell<usize>,
    tx_last_ms: core::cell::Cell<u64>,
    tx_low_since: core::cell::Cell<u64>,
    /// The send queue when the measurement began.
    tx_q0: core::cell::Cell<usize>,
}

/// The idle time after which a grown buffer goes back to tcp.recvspace.
const TUNE_IDLE_MS: u64 = 2000;
/// How long a transfer must stay at a quarter of the buffer or less before
/// it shrinks: 4 measurements (~0.14 s) took a dip on the internet path
/// for a slow-down and the buffer went 933 KB -> 233 KB -> back.
const TUNE_LOW_MS: u64 = 2000;

/// The receive buffer's ceiling on a LAN (round trip under 2 ms), below
/// tcp.recvspace.max (see tune_rx).
const LAN_RX_MAX: usize = 512 * 1024;

fn page_up(n: usize) -> usize {
    (n + 4095) & !4095
}

/// Resize `s`'s receive buffer to `want` bytes and log it.
fn resize_rx(s: &mut tcp::Socket<'static>, want: usize, why: core::fmt::Arguments) -> bool {
    let cap = s.recv_capacity();
    let ok = s.resize_rx_buffer(vec![0u8; want]);
    if ok {
        amigaos4::serial_println!("rsnet: TCP receive buffer {} -> {} bytes ({})", cap, want, why);
    }
    ok
}

/// After the program read `n` bytes from `s` (see Tune).
fn tune_rx(t: &Tune, s: &mut tcp::Socket<'static>, n: usize) {
    if n == 0 {
        return;
    }
    let now = up_us() / 1000;
    t.last_ms.set(now);
    // A round trip under 1 ms (a LAN) counts as 1 ms: the stack and the
    // reading program share the CPU, so data waits in the queue until the
    // reader runs and the effective round trip is longer than the wire's.
    // On an AmigaOne X5000 a 64 KB window was full on average and capped
    // receive at 64 MB/s; 256 KB gave 77 MB/s.
    let Some(measured) = s.smoothed_rtt_ms() else { return };
    let rtt = measured.max(1);
    if t.since_ms.get() == 0 {
        t.since_ms.set(now);
        t.bytes.set(0);
    }
    t.bytes.set(t.bytes.get() + n);
    let elapsed = now.saturating_sub(t.since_ms.get());
    if elapsed < rtt as u64 {
        return;
    }
    let bytes = t.bytes.get();
    t.since_ms.set(now);
    t.bytes.set(0);
    let cap = s.recv_capacity();
    let start = crate::settings::SETTINGS.tcp_space().0;
    // The data in flight: the rate read at, times the round trip.
    let in_flight = (bytes as u64 * rtt as u64 / elapsed.max(1)) as usize;
    let mut target = page_up(in_flight * 2);
    // Half the buffer or more in flight: the window may be what limits the
    // sender, so grow by half at least (in 4 KB steps it crept up in 14
    // reallocations).
    if in_flight * 2 >= cap {
        target = target.max(page_up(cap + cap / 2));
    }
    let mut want = target.clamp(start.min(s.rx_buffer_max()), s.rx_buffer_max());
    // On a LAN the window only has to keep the reader fed, and a smaller
    // buffer is still in the cache when the reader copies it out: on the
    // X5000, 512 KB beat 1 MB in 3 of 4 alternating runs (78.3 against 75.2
    // MB/s).
    if measured < 2 {
        want = want.min(LAN_RX_MAX.max(start));
    }
    // The window can only say 65535 << shift; a larger buffer is unused.
    if !s.rx_window_scaled() {
        want = want.min(65535.max(start));
    }
    // More than half the buffer still queued: the program is what is slow
    // (curl --limit-rate reads in bursts that looked like a fast sender);
    // a larger window would only queue more.
    // (Not on a LAN: there a full queue is the reader's scheduling, and a
    // larger window still helped.)
    let reader_slow = measured >= 2 && s.recv_queue() > cap / 2;
    if want > cap && !reader_slow {
        t.low_since.set(0);
        resize_rx(s, want, format_args!("rtt {} ms, {} bytes in flight", rtt, in_flight));
    } else if want > cap {
        // A slow reader: neither grow nor count towards shrinking.
    } else if want * 4 <= cap && cap > start {
        if t.low_since.get() == 0 {
            t.low_since.set(now);
        }
        if now.saturating_sub(t.low_since.get()) >= TUNE_LOW_MS && s.rx_window_limit().is_none() {
            // Offer no more than `want` from now on; the buffer is made
            // smaller once what is queued fits (drain_rx).
            s.set_rx_window_limit(Some(want));
            amigaos4::serial_println!("rsnet: TCP receive window held to {} bytes (slowed: rtt {} ms, {} bytes in flight)", want, rtt, in_flight);
        }
    } else {
        t.low_since.set(0);
        // The rate came back: offer the whole buffer again.
        if s.rx_window_limit().is_some() {
            s.set_rx_window_limit(None);
        }
    }
    drain_rx(t, s);
}

/// A buffer whose window is held (tune_rx) is made that size once what is
/// queued fits in it.
fn drain_rx(t: &Tune, s: &mut tcp::Socket<'static>) {
    let Some(limit) = s.rx_window_limit() else { return };
    if s.recv_queue() <= limit && resize_rx(s, limit, format_args!("drained")) {
        t.low_since.set(0);
    }
}

/// The send buffer's ceiling on a LAN (round trip under 2 ms), below
/// tcp.sendspace.max (see tune_tx): 64 KB, i.e. no growth past the
/// default. On an AmigaOne X5000, 64 KB already sends at gigabit's line
/// rate, and more in flight makes p50x0_eth.device refuse writes
/// (S2ERR_TX_FAILURE; 96 KB: 50 MB/s in some runs).
const LAN_TX_MAX: usize = 64 * 1024;

/// Resize `s`'s send buffer to `want` bytes and log it.
fn resize_tx(s: &mut tcp::Socket<'static>, want: usize, why: core::fmt::Arguments) -> bool {
    let cap = s.send_capacity();
    let ok = s.resize_tx_buffer(vec![0u8; want]);
    if ok {
        amigaos4::serial_println!("rsnet: TCP send buffer {} -> {} bytes ({})", cap, want, why);
    }
    ok
}

/// Send-buffer auto-tuning, tune_rx's for the other way: a
/// connection starts with tcp.sendspace. Once per smoothed round trip, the
/// rate the program wrote at, times the round trip, is the data in flight;
/// the buffer is sized to twice that (growing by half at least while half
/// of it or more is in flight, i.e. while the buffer limits the sender),
/// between tcp.sendspace and tcp.sendspace.max (LAN_TX_MAX on a LAN). The
/// peer's window bounds what is in flight, so the buffer stops at about
/// twice it. It shrinks back after TUNE_LOW_MS at a quarter or less, once
/// what it holds fits, and to tcp.sendspace when idle (tune_idle). Called
/// after the program wrote `n` bytes to `s`.
fn tune_tx(t: &Tune, s: &mut tcp::Socket<'static>, n: usize) {
    if n == 0 {
        return;
    }
    // Not on a LAN (see LAN_TX_MAX); returning before any clock read keeps
    // the caller's send path as it was.
    let Some(measured) = s.smoothed_rtt_ms() else { return };
    if measured < 2 && s.send_capacity() >= LAN_TX_MAX.min(crate::settings::SETTINGS.tcp_send_max()) {
        return;
    }
    let now = up_us() / 1000;
    t.tx_last_ms.set(now);
    let rtt = measured.max(1);
    if t.tx_since_ms.get() == 0 {
        t.tx_since_ms.set(now);
        t.tx_bytes.set(0);
        t.tx_q0.set(s.send_queue() - n);
    }
    t.tx_bytes.set(t.tx_bytes.get() + n);
    let elapsed = now.saturating_sub(t.tx_since_ms.get());
    if elapsed < rtt as u64 {
        return;
    }
    // What left the buffer (acknowledged) in the period: the bytes written
    // less what the queue grew by. The write rate alone counts a larger
    // buffer filling up as speed: on a 6 MB/s upload it "measured" 17 MB/s
    // and grew the buffer to the ceiling.
    let q = s.send_queue();
    let bytes = (t.tx_bytes.get() + t.tx_q0.get()).saturating_sub(q);
    t.tx_since_ms.set(now);
    t.tx_bytes.set(0);
    t.tx_q0.set(q);
    let cap = s.send_capacity();
    let start = crate::settings::SETTINGS.tcp_space().1;
    let mut max = crate::settings::SETTINGS.tcp_send_max();
    if measured < 2 {
        max = max.min(LAN_TX_MAX).max(start);
    }
    let in_flight = (bytes as u64 * rtt as u64 / elapsed.max(1)) as usize;
    let mut target = page_up(in_flight * 2);
    if in_flight * 2 >= cap {
        target = target.max(page_up(cap + cap / 2));
    }
    // What is in flight never exceeds the peer's window: more than twice it
    // is never used (QEMU's slirp offers 65535, unscaled).
    let target = target.min(page_up(s.remote_window() * 2));
    let want = target.clamp(start, max);
    if want > cap {
        t.tx_low_since.set(0);
        resize_tx(s, want, format_args!("rtt {} ms, {} bytes in flight, peer window {}", rtt, in_flight, s.remote_window()));
    } else if want * 4 <= cap && cap > start {
        if t.tx_low_since.get() == 0 {
            t.tx_low_since.set(now);
        }
        if now.saturating_sub(t.tx_low_since.get()) >= TUNE_LOW_MS && s.send_queue() <= want && resize_tx(s, want, format_args!("slowed: rtt {} ms, {} bytes in flight", rtt, in_flight)) {
            t.tx_low_since.set(0);
        }
    } else {
        t.tx_low_since.set(0);
    }
}

/// From the stack's loop: a grown buffer with nothing queued for
/// TUNE_IDLE_MS goes back to tcp.recvspace (see Tune), and a grown send
/// buffer with nothing in it to tcp.sendspace.
fn tune_idle(t: &Tune, s: &mut tcp::Socket<'static>, now_ms: u64) {
    let tx_start = crate::settings::SETTINGS.tcp_space().1;
    let tx_last = t.tx_last_ms.get();
    if tx_last != 0 && s.send_capacity() > tx_start && s.send_queue() == 0 && now_ms.saturating_sub(tx_last) >= TUNE_IDLE_MS && resize_tx(s, tx_start, format_args!("idle {} ms", now_ms - tx_last)) {
        t.tx_since_ms.set(0);
        t.tx_bytes.set(0);
        t.tx_low_since.set(0);
    }
    drain_rx(t, s);
    let start = crate::settings::SETTINGS.tcp_space().0;
    let last = t.last_ms.get();
    if last == 0 || s.recv_capacity() <= start || s.recv_queue() != 0 || now_ms.saturating_sub(last) < TUNE_IDLE_MS {
        return;
    }
    if resize_rx(s, start, format_args!("idle {} ms", now_ms - last)) {
        t.since_ms.set(0);
        t.bytes.set(0);
        t.low_since.set(0);
    }
}

/// One socket's GetSocketEvents state.
struct Watch {
    mask: u32,
    target: Option<SignalTarget>,
    /// Events not yet taken.
    pending: u32,
    /// The conditions true at the last look (events fire on a change).
    seen: u32,
}

impl Entry {
    fn new(kind: Kind, at: At) -> Self {
        Entry {
            kind,
            at,
            pool: Vec::new(),
            udp: Vec::new(),
            bound: (None, 0),
            connecting: false,
            deferred: None,
            started: 0,
            error: 0,
            read_shut: false,
            peer: None,
            keepalive: false,
            nodelay: true,
            linger_abort: false,
            fin_seen: false,
            ev: None,
            backlog: 0,
            tune: Tune::default(),
        }
    }

    fn listen_endpoint(&self) -> IpListenEndpoint {
        IpListenEndpoint {
            addr: self.bound.0.map(|a| IpAddress::Ipv4(Ipv4Address::new(a[0], a[1], a[2], a[3]))),
            port: self.bound.1,
        }
    }
}

fn tcp_of<'a>(nets: &'a mut [Net], at: At) -> &'a mut tcp::Socket<'static> {
    nets[at.0].sockets.get_mut::<tcp::Socket>(at.1)
}

/// The sockets of all openers, on all interfaces.
pub struct Socks {
    socks: BTreeMap<u32, Entry>,
    /// Sockets closed by their opener, kept until smoltcp has finished
    /// with them.
    closing: Vec<At>,
    /// UDP sockets closed with datagrams still queued: kept until they are
    /// sent (BSD has handed a datagram to the interface when sendto
    /// returns) or the up time passes the deadline (a peer that never
    /// answers ARP).
    udp_closing: Vec<(usize, SocketHandle, u64)>,
    waiting: Vec<Received<Ctl>>,
    /// progress's list of handles, kept between passes (no allocation
    /// per call).
    ids: Vec<u32>,
    next: u32,
    /// The last ephemeral ports handed out, TCP and UDP apart (4.4BSD's
    /// inp_lport hint of each protocol's pcb list).
    tcp_port: u16,
    udp_port: u16,
    /// From the start-up seed (raw sockets' ICMP ids).
    seed16: u16,
    /// Each interface's DNS servers from DHCP.
    dns_servers: Vec<Vec<IpAddress>>,
    /// The routing table (route.rs).
    pub routes: crate::route::Table,
    /// The statically configured name servers (AddDomainNameServer,
    /// DEVS:Internet/name_resolution), each with its use count as a negative
    /// number (dnsn_UseCount: "negative values indicate statically-configured
    /// servers"); asked before the ones DHCP gave.
    pub name_servers: Vec<([u8; 4], i32)>,
    /// DEVS:Internet/name_resolution's `nameserver` lines: asked after the
    /// others, listed nowhere (as Roadshow).
    pub file_servers: Vec<[u8; 4]>,
    /// Raw IP sockets (raw.rs), numbered with the others.
    raws: BTreeMap<u32, crate::raw::RawEntry>,
    /// Routing sockets (rtsock.rs), numbered with the others.
    rsocks: BTreeMap<u32, crate::rtsock::RouteSock>,
    /// The DNS client (resolver.rs).
    resolver: crate::resolver::Resolver,
}

impl Socks {
    pub fn new(seed: u64, nets: usize) -> Self {
        Self {
            socks: BTreeMap::new(),
            closing: Vec::new(),
            udp_closing: Vec::new(),
            waiting: Vec::new(),
            ids: Vec::new(),
            next: 1,
            tcp_port: 0,
            udp_port: 0,
            seed16: seed as u16,
            dns_servers: vec![Vec::new(); nets],
            routes: crate::route::Table::new(),
            name_servers: Vec::new(),
            file_servers: Vec::new(),
            raws: BTreeMap::new(),
            rsocks: BTreeMap::new(),
            resolver: crate::resolver::Resolver::default(),
        }
    }

    /// The interface to reach `dst` through (the routing table), for the
    /// stack's own users (ping).
    pub fn route_for(&self, nets: &[Net], dst: [u8; 4]) -> Option<usize> {
        self.routes.select(nets, dst)
    }

    /// A free ephemeral port for TCP or UDP, as 4.4BSD's in_pcbbind hands
    /// them out and Roadshow does (testprogs/rstcp/c/portprobe.c:
    /// 1024 first after boot, then up to 5000 and round again,
    /// each protocol counting on its own): none of that protocol's sockets
    /// is bound to it, nor (TCP) a connection still closing on it.
    fn ephemeral(&mut self, udp: bool, nets: &mut [Net]) -> u16 {
        for _ in 0..=(5000 - 1024) {
            let c = if udp { &mut self.udp_port } else { &mut self.tcp_port };
            *c = c.wrapping_add(1);
            if *c < 1024 || *c > 5000 {
                *c = 1024;
            }
            let p = *c;
            let bound = self.socks.values().any(|e| (e.kind == Kind::Udp) == udp && e.bound.1 == p);
            let closing = !udp && self.closing.iter().any(|&at| tcp_of(nets, at).local_endpoint().map(|l| l.port) == Some(p));
            if !bound && !closing {
                return p;
            }
        }
        // Every one in use: as BSD would loop for ever, take the next.
        if udp { self.udp_port } else { self.tcp_port }
    }

    /// The interface to ask DNS through, and its servers: the configured
    /// name servers (through the interface that routes to the first one
    /// reachable), else the first interface whose DHCP gave some.
    fn dns_choice(&self, nets: &[Net]) -> Option<(usize, Vec<IpAddress>)> {
        let ip = |a: &[u8; 4]| IpAddress::Ipv4(Ipv4Address::new(a[0], a[1], a[2], a[3]));
        let base = if !self.name_servers.is_empty() {
            let k = self.name_servers.iter().find_map(|(a, _)| self.routes.select(nets, *a))?;
            Some((k, self.name_servers.iter().map(|(a, _)| ip(a)).collect::<Vec<_>>()))
        } else {
            self.dns_servers.iter().enumerate().find(|(_, s)| !s.is_empty()).map(|(k, s)| (k, s.clone()))
        };
        // name_resolution's servers: after the listed ones (Roadshow lists
        // them nowhere, and an unreachable one there does not slow its
        // lookups), or alone when there are none.
        match base {
            Some((k, mut servers)) => {
                for a in &self.file_servers {
                    if !servers.contains(&ip(a)) {
                        servers.push(ip(a));
                    }
                }
                Some((k, servers))
            }
            None => {
                let k = self.file_servers.iter().find_map(|a| self.routes.select(nets, *a))?;
                Some((k, self.file_servers.iter().map(ip).collect()))
            }
        }
    }

    /// AddDomainNameServer (and the configuration file's `nameserver`): a
    /// new static server, or one more use of a known one.
    pub fn add_name_server(&mut self, a: [u8; 4], _fixed: bool) {
        match self.name_servers.iter_mut().find(|(x, _)| *x == a) {
            Some((_, n)) => *n -= 1,
            None => self.name_servers.push((a, -1)),
        }
    }

    /// RemoveDomainNameServer: one use fewer; the server goes with its last
    /// use. ENOENT when it is not there.
    pub fn remove_name_server(&mut self, a: [u8; 4]) -> Result<(), i32> {
        let Some(i) = self.name_servers.iter().position(|(x, _)| *x == a) else { return Err(2) };
        if self.name_servers[i].1 < -1 {
            self.name_servers[i].1 += 1;
        } else {
            self.name_servers.remove(i);
        }
        Ok(())
    }

    /// Every name server with its use count: the ones DHCP gave (dynamic,
    /// count 1) first, then the static ones (negative counts), as Roadshow
    /// lists them; a server can be in both.
    pub fn name_server_list(&self) -> Vec<([u8; 4], i32)> {
        let mut v: Vec<([u8; 4], i32)> = Vec::new();
        for s in &self.dns_servers {
            for a in s {
                // IPv4 only in this stack (smoltcp built with proto-ipv4).
                let IpAddress::Ipv4(a) = a;
                let o = a.octets();
                if !v.iter().any(|(x, _)| *x == o) {
                    v.push((o, 1));
                }
            }
        }
        v.extend_from_slice(&self.name_servers);
        v
    }

    /// Interface `k` has been added (a new slot, or a removed one used
    /// again): every UDP socket gets its socket there, bound as on the
    /// others, and every listener bound to no address its listening sockets.
    pub fn add_net(&mut self, k: usize, nets: &mut [Net]) {
        if self.dns_servers.len() <= k {
            self.dns_servers.resize(k + 1, Vec::new());
        }
        for r in self.raws.values_mut() {
            if r.socks.len() == k {
                r.socks.push(nets[k].sockets.add(crate::raw::new_socket(r.proto)));
            }
        }
        for e in self.socks.values_mut() {
            match e.kind {
                Kind::Udp if e.udp.len() == k => {
                    let mut u = udp_socket();
                    if e.bound.1 != 0 {
                        let _ = u.bind(e.listen_endpoint());
                    }
                    e.udp.push(nets[k].sockets.add(u));
                }
                Kind::Listener if e.bound.0.is_none() && !e.pool.iter().any(|a| a.0 == k) => {
                    let lep = e.listen_endpoint();
                    for _ in 0..e.backlog.max(1) {
                        let mut t = tcp_socket();
                        let _ = t.listen(lep);
                        e.pool.push((k, nets[k].sockets.add(t)));
                    }
                }
                _ => {}
            }
        }
    }

    /// Whether a TCP connection runs over interface `k` (RemoveInterface
    /// refuses to take it away without `force`).
    pub fn in_use(&self, k: usize, nets: &mut [Net]) -> bool {
        self.socks.values().any(|e| e.kind == Kind::Tcp && e.at.0 == k && tcp_of(nets, e.at).is_active())
    }

    /// Interface `k` is going: its connections are reset (their programs see
    /// ECONNRESET), its DNS servers dropped. Its sockets stay in its set
    /// (the slot keeps its smoltcp state) and are used again if an interface
    /// of that name is added again.
    pub fn drop_net(&mut self, k: usize, nets: &mut [Net]) {
        for e in self.socks.values() {
            if e.kind == Kind::Tcp && e.at.0 == k {
                tcp_of(nets, e.at).abort();
            }
        }
        self.set_dns(k, &[]);
    }

    /// Interface `k`'s DNS servers from DHCP (empty when its lease is gone).
    pub fn set_dns(&mut self, k: usize, servers: &[[u8; 4]]) {
        self.dns_servers[k] = servers.iter().map(|a| IpAddress::Ipv4(Ipv4Address::new(a[0], a[1], a[2], a[3]))).collect();
    }

    /// TCP socket `h`'s queued bytes into `buf` (in the calling task: the
    /// opener's buffer may be MEMF_PRIVATE): the count, or None when the
    /// Recv op must go to the stack (nothing queued, the end of the stream,
    /// a socket still connecting, not TCP, shut for reading).
    pub fn recv_now(&mut self, h: u32, buf: &mut [u8], nets: &mut [Net]) -> Option<usize> {
        let e = self.socks.get(&h)?;
        if e.kind != Kind::Tcp || e.connecting || e.deferred.is_some() || e.read_shut || buf.is_empty() {
            return None;
        }
        let s = tcp_of(nets, e.at);
        if !s.can_recv() {
            return None;
        }
        let n = s.recv_slice(buf).ok().filter(|&n| n > 0)?;
        tune_rx(&e.tune, s, n);
        Some(n)
    }

    /// As much of `data` as TCP socket `h`'s transmit buffer takes now: the
    /// count, or None when the Send op must go to the stack (no room, the
    /// connection not open for sending, still connecting, not TCP).
    pub fn send_now(&mut self, h: u32, data: &[u8], nets: &mut [Net]) -> Option<usize> {
        let e = self.socks.get(&h)?;
        if e.kind != Kind::Tcp || e.connecting || e.deferred.is_some() || data.is_empty() {
            return None;
        }
        let s = tcp_of(nets, e.at);
        if !s.may_send() || !s.can_send() || !send_room(s, data.len()) {
            return None;
        }
        let n = s.send_slice(data).ok().filter(|&n| n > 0)?;
        tune_tx(&e.tune, s, n);
        Some(n)
    }

    /// A new op from an opener: answered now or kept.
    pub fn command(&mut self, mut m: Received<Ctl>, nets: &mut [Net]) {
        if self.try_msg(&mut m, nets, true) {
            m.reply();
        } else {
            self.waiting.push(m);
        }
    }

    /// Answer the waiting op with `token` at once with EINTR (the opener
    /// was interrupted); nothing if it has been answered already.
    pub fn abort(&mut self, token: u32) {
        if let Some(k) = self.waiting.iter().position(|m| matches!(&**m, Ctl::Sock(s) if s.token == token)) {
            let mut m = self.waiting.swap_remove(k);
            if let Ctl::Sock(s) = &mut *m {
                self.cancel_lookup(&mut s.op);
                fail(&mut s.op, errno::EINTR);
            }
            m.reply();
        }
    }

    fn cancel_lookup(&mut self, op: &mut SockOp) {
        if let SockOp::Resolve { state, .. } = op {
            self.resolver.forget(state.id);
        }
    }

    /// Move an unconnected TCP socket to interface `k`.
    fn move_tcp(nets: &mut [Net], at: At, k: usize) -> At {
        if at.0 == k {
            return at;
        }
        match nets[at.0].sockets.remove(at.1) {
            Socket::Tcp(s) => (k, nets[k].sockets.add(s)),
            // Never: an Entry's TCP handle holds a TCP socket.
            other => (at.0, nets[at.0].sockets.add(other)),
        }
    }

    /// Start a TCP connect on the interface that routes to `remote`; false
    /// when none has an address yet.
    fn start_connect(&mut self, h: u32, remote: IpEndpoint, nets: &mut [Net]) -> Result<bool, i32> {
        let dst = endpoint(remote).map(|e| e.0).unwrap_or([0; 4]);
        let e = &self.socks[&h];
        let k = match e.bound.0 {
            Some(a) => owner(nets, a),
            None => self.routes.select(nets, dst),
        };
        let Some(k) = k else { return Ok(false) };
        crate::stats::tcp_event(crate::stats::TCPS_CONNATTEMPT);
        let (bound_addr, bound) = (e.bound.0, e.bound.1);
        let local = if bound != 0 { bound } else { self.ephemeral(false, nets) };
        // The IP filter's verdict on the SYN now: Roadshow's connect fails
        // at once (EHOSTUNREACH from ip_output through tcp_output) when an
        // "out" rule blocks it.
        let src = bound_addr.or_else(|| nets[k].addr().map(|c| c.address().octets())).unwrap_or([0; 4]);
        let port = endpoint(remote).map(|e| e.1).unwrap_or(0);
        if crate::ipfil::refuse(crate::ipf::ifnet(k as u8), &crate::ipfil::tcp_syn(src, local, dst, port)) {
            return Err(errno::EHOSTUNREACH);
        }
        let e = self.socks.get_mut(&h).unwrap();
        e.at = Self::move_tcp(nets, e.at, k);
        e.bound.1 = local;
        let net = &mut nets[k];
        let s = net.sockets.get_mut::<tcp::Socket>(e.at.1);
        s.set_timeout(Some(smoltcp::time::Duration::from_secs(TIMEOUT_SECS)));
        s.set_nagle_enabled(false);
        let local_ep = match e.bound.0 {
            Some(a) => IpListenEndpoint { addr: Some(IpAddress::Ipv4(Ipv4Address::new(a[0], a[1], a[2], a[3]))), port: local },
            None => IpListenEndpoint { addr: None, port: local },
        };
        s.connect(net.iface.context(), remote, local_ep).map_err(|err| match err {
            tcp::ConnectError::InvalidState => errno::EISCONN,
            tcp::ConnectError::Unaddressable => errno::EINVAL,
        })?;
        e.connecting = true;
        e.started = up_us();
        Ok(true)
    }

    /// Start deferred connects, settle background ones, refill listener
    /// pools, answer the waiting ops that can be answered now, free sockets
    /// smoltcp has finished.
    /// True when a waiting op was answered (what it did may need sending).
    pub fn progress(&mut self, nets: &mut [Net]) -> bool {
        let mut answered = false;
        let now = up_us();
        // The handles in a buffer kept between calls (this runs every pass
        // of the stack: an allocation each time showed on the X5000).
        // One walk over the entries (a map lookup per socket and step cost
        // ~9 us a pass with a server's and the superserver's listeners, on
        // the X5000); deferred connects, which need the whole of
        // Socks, are noted and started after it.
        let mut ids = core::mem::take(&mut self.ids);
        ids.clear();
        for (&h, e) in self.socks.iter_mut() {
            if e.deferred.is_some() {
                ids.push(h);
                continue;
            }
            if e.kind == Kind::Tcp && !e.fin_seen && matches!(tcp_of(nets, e.at).state(), tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait) {
                e.fin_seen = true;
            }
            if e.kind == Kind::Tcp && !e.connecting && e.deferred.is_none() {
                tune_idle(&e.tune, tcp_of(nets, e.at), now / 1000);
            }
            if e.connecting {
                match tcp_of(nets, e.at).state() {
                    tcp::State::Established | tcp::State::CloseWait => {
                        e.connecting = false;
                        tcp_of(nets, e.at).set_timeout(None);
                        crate::stats::tcp_event(crate::stats::TCPS_CONNECTS);
                    }
                    tcp::State::Closed => {
                        e.connecting = false;
                        e.error = closed_error(e.started);
                    }
                    _ => {}
                }
            }
            if e.kind == Kind::Listener {
                // A pool socket whose half-open connection was reset is
                // closed and no longer listening: listen again.
                let lep = e.listen_endpoint();
                for &p in &e.pool {
                    let s = tcp_of(nets, p);
                    if s.state() == tcp::State::Closed {
                        let _ = s.listen(lep);
                    }
                }
            }
        }
        // Connects waiting for a route or an address (the steps above come
        // to them once they are started).
        for &h in ids.iter() {
            let Some((remote, since)) = self.socks.get(&h).and_then(|e| e.deferred) else { continue };
            match self.start_connect(h, remote, nets) {
                Ok(true) => self.socks.get_mut(&h).unwrap().deferred = None,
                Ok(false) => {
                    if now.saturating_sub(since) > TIMEOUT_SECS * 1_000_000 {
                        let e = self.socks.get_mut(&h).unwrap();
                        e.deferred = None;
                        e.error = errno::ENETUNREACH;
                    }
                }
                Err(err) => {
                    let e = self.socks.get_mut(&h).unwrap();
                    e.deferred = None;
                    e.error = err;
                }
            }
        }
        self.ids = ids;
        self.watch_events(nets);
        let mut k = 0;
        while k < self.waiting.len() {
            let mut m = self.waiting.swap_remove(k);
            if self.try_msg(&mut m, nets, false) {
                m.reply();
                answered = true;
            } else if let Ctl::Sock(SockMsg { deadline_us: Some(d), op, .. }) = &mut *m {
                if now >= *d {
                    // SO_RCVTIMEO / SO_SNDTIMEO ran out.
                    let op: &mut SockOp = op;
                    self.cancel_lookup(op);
                    fail(op, errno::EWOULDBLOCK);
                    m.reply();
                } else {
                    self.waiting.push(m);
                    let last = self.waiting.len() - 1;
                    self.waiting.swap(k, last);
                    k += 1;
                }
            } else {
                self.waiting.push(m);
                let last = self.waiting.len() - 1;
                self.waiting.swap(k, last);
                k += 1;
            }
        }
        self.udp_closing.retain(|&(k, u, until)| {
            if nets[k].sockets.get::<udp::Socket>(u).send_queue() == 0 || now >= until {
                nets[k].sockets.remove(u);
                false
            } else {
                true
            }
        });
        self.closing.retain(|&at| {
            let s = nets[at.0].sockets.get::<tcp::Socket>(at.1);
            if matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) {
                nets[at.0].sockets.remove(at.1);
                false
            } else {
                true
            }
        });
        answered
    }

    /// The soonest a waiting select must be answered (its timeout), in up
    /// time microseconds.
    pub fn next_deadline(&self) -> Option<u64> {
        self.waiting
            .iter()
            .filter_map(|m| match &**m {
                Ctl::Sock(SockMsg { op: SockOp::Select { until_us, .. }, deadline_us, .. }) => until_us.or(*deadline_us),
                Ctl::Sock(SockMsg { deadline_us, .. }) => *deadline_us,
                _ => None,
            })
            .min()
    }

    /// Everything closed at once (the stack is stopping): waiting ops
    /// answered with ENOTCONN.
    pub fn shutdown(&mut self, nets: &mut [Net]) {
        for mut m in core::mem::take(&mut self.waiting) {
            if let Ctl::Sock(s) = &mut *m {
                self.cancel_lookup(&mut s.op);
                fail(&mut s.op, errno::ENOTCONN);
            }
            m.reply();
        }
        for (_, e) in core::mem::take(&mut self.socks) {
            match e.kind {
                Kind::Tcp => tcp_of(nets, e.at).abort(),
                Kind::Listener => {
                    for p in e.pool {
                        tcp_of(nets, p).abort();
                    }
                }
                Kind::Udp => {
                    for (k, h) in e.udp.into_iter().enumerate() {
                        nets[k].sockets.get_mut::<udp::Socket>(h).close();
                    }
                }
            }
        }
    }

    /// The pool socket of listener `e` with a connection to hand out.
    fn ready_in_pool(e: &Entry, nets: &[Net]) -> Option<usize> {
        e.pool
            .iter()
            .position(|&(k, p)| matches!(nets[k].sockets.get::<tcp::Socket>(p).state(), tcp::State::Established | tcp::State::CloseWait))
    }

    /// UDP: drop queued datagrams not from the default peer; the interface
    /// whose socket has one that is.
    fn udp_pending(e: &Entry, nets: &mut [Net]) -> Option<usize> {
        for (k, &h) in e.udp.iter().enumerate() {
            let s = nets[k].sockets.get_mut::<udp::Socket>(h);
            loop {
                let from = match s.peek() {
                    Ok((_, meta)) => meta.endpoint,
                    Err(_) => break,
                };
                match e.peer {
                    Some(p) if p != from => {
                        let _ = s.recv();
                    }
                    _ => return Some(k),
                }
            }
        }
        None
    }

    /// SO_EVENTMASK: compare each watched socket's conditions with the
    /// last look; what newly came true is pending, and its owner is
    /// signalled.
    fn watch_events(&mut self, nets: &mut [Net]) {
        let hs: Vec<u32> = self.socks.iter().filter(|(_, e)| e.ev.is_some()).map(|(&h, _)| h).collect();
        for h in hs {
            let now = self.conditions(h, nets);
            let Some(w) = self.socks.get_mut(&h).and_then(|e| e.ev.as_mut()) else { continue };
            let new = now & !w.seen & w.mask;
            w.seen = now;
            if new != 0 {
                let was = w.pending;
                w.pending |= new;
                if was == 0 {
                    if let Some(t) = &w.target {
                        // SAFETY: the target is the opener's task and its
                        // event signal; the library clears the watch
                        // (SO_EVENTMASK 0, or CloseSocket) before the
                        // opener goes away.
                        unsafe { t.send() };
                    }
                }
            }
        }
    }

    /// FD_* conditions of socket `h` now.
    fn conditions(&self, h: u32, nets: &mut [Net]) -> u32 {
        use fd_event::*;
        let Some(e) = self.socks.get(&h) else { return 0 };
        let mut c = 0;
        match e.kind {
            Kind::Listener => {
                if Self::ready_in_pool(e, nets).is_some() {
                    c |= ACCEPT;
                }
            }
            Kind::Udp => {
                if Self::udp_pending(e, nets).is_some() {
                    c |= READ;
                }
                if e.udp.iter().enumerate().all(|(k, &u)| nets[k].sockets.get::<udp::Socket>(u).can_send()) {
                    c |= WRITE;
                }
            }
            Kind::Tcp => {
                let s = tcp_of(nets, e.at);
                let open = !e.connecting && e.deferred.is_none() && e.started != 0;
                if e.error != 0 {
                    c |= ERROR;
                }
                if s.can_recv() {
                    c |= READ;
                }
                if open && s.can_send() {
                    c |= WRITE;
                }
                if open && e.started > 1 {
                    c |= CONNECT;
                }
                if open && !s.may_recv() {
                    c |= CLOSE;
                }
            }
        }
        c
    }

    fn readable(&self, h: u32, nets: &mut [Net]) -> bool {
        if let Some(r) = self.rsocks.get(&h) {
            return !r.queue.is_empty();
        }
        if let Some(r) = self.raws.get(&h) {
            return r.pending(nets).is_some();
        }
        let Some(e) = self.socks.get(&h) else { return true };
        match e.kind {
            Kind::Listener => Self::ready_in_pool(e, nets).is_some(),
            Kind::Udp => Self::udp_pending(e, nets).is_some(),
            Kind::Tcp => {
                let s = tcp_of(nets, e.at);
                e.error != 0 || s.can_recv() || (!e.connecting && e.deferred.is_none() && e.started != 0 && !s.may_recv())
            }
        }
    }

    fn writable(&self, h: u32, nets: &mut [Net]) -> bool {
        if self.raws.contains_key(&h) || self.rsocks.contains_key(&h) {
            return true;
        }
        let Some(e) = self.socks.get(&h) else { return true };
        match e.kind {
            Kind::Listener => false,
            Kind::Udp => e.udp.iter().enumerate().all(|(k, &u)| nets[k].sockets.get::<udp::Socket>(u).can_send()),
            Kind::Tcp => {
                let s = tcp_of(nets, e.at);
                e.error != 0 || (!e.connecting && e.deferred.is_none() && e.started != 0 && (s.can_send() || !s.may_send()))
            }
        }
    }

    /// Try one message: true when its result is set.
    fn try_msg(&mut self, m: &mut Received<Ctl>, nets: &mut [Net], first: bool) -> bool {
        let Ctl::Sock(msg) = &mut **m else { return true };
        let nonblock = msg.nonblock;
        let op = &mut msg.op;
        if self.try_op(op, nets, first, nonblock) {
            return true;
        }
        if nonblock && first {
            if let SockOp::Connect { result, .. } = op {
                // It goes on in the background; select and SO_ERROR tell.
                *result = Err(errno::EINPROGRESS);
            } else {
                self.cancel_lookup(op);
                fail(op, errno::EWOULDBLOCK);
            }
            return true;
        }
        false
    }

    /// Bind a UDP socket that is not yet bound to a free port (on every
    /// interface).
    fn udp_autobind(&mut self, h: u32, nets: &mut [Net]) -> Result<(), i32> {
        if self.socks[&h].bound.1 != 0 {
            return Ok(());
        }
        let port = self.ephemeral(true, nets);
        let e = self.socks.get_mut(&h).unwrap();
        e.bound.1 = port;
        Self::udp_bind_all(e, nets)
    }

    fn udp_bind_all(e: &Entry, nets: &mut [Net]) -> Result<(), i32> {
        let lep = e.listen_endpoint();
        for (k, &u) in e.udp.iter().enumerate() {
            nets[k].sockets.get_mut::<udp::Socket>(u).bind(lep).map_err(|_| errno::EINVAL)?;
        }
        Ok(())
    }

    /// Try one op: true when its result is set.
    /// An op on a routing socket (or opening one): Some(done), else None.
    fn try_route(&mut self, op: &mut SockOp, nets: &mut [Net]) -> Option<bool> {
        if let SockOp::Open { kind: SockKind::Route, result } = op {
            let h = self.next;
            self.next = self.next.wrapping_add(1).max(1);
            self.rsocks.insert(h, crate::rtsock::RouteSock::default());
            *result = Ok(h);
            return Some(true);
        }
        let h = match op {
            SockOp::Bind { h, .. } | SockOp::Listen { h, .. } | SockOp::Accept { h, .. } | SockOp::Connect { h, .. } | SockOp::Send { h, .. }
            | SockOp::Recv { h, .. } | SockOp::Close { h, .. } | SockOp::Shutdown { h, .. } | SockOp::Info { h, .. } | SockOp::SetOpt { h, .. } => *h,
            _ => return None,
        };
        if !self.rsocks.contains_key(&h) {
            return None;
        }
        match op {
            SockOp::Send { data, result, .. } => {
                let now = smoltcp::time::Instant::from_micros(up_us() as i64);
                let (reply, err) = crate::rtsock::handle(data, nets, &mut self.routes, now);
                if let Some(r) = self.rsocks.get_mut(&h) {
                    r.queue.push_back(reply);
                }
                *result = if err == 0 { Ok(data.len()) } else { Err(err) };
            }
            SockOp::Recv { max, peek, result, .. } => {
                let r = self.rsocks.get_mut(&h)?;
                let Some(m) = (if *peek { r.queue.front().cloned() } else { r.queue.pop_front() }) else { return Some(false) };
                *result = Ok((m[..m.len().min(*max)].to_vec(), None));
            }
            SockOp::Close { result, .. } => {
                self.rsocks.remove(&h);
                *result = Ok(());
            }
            SockOp::Info { result, .. } => {
                let readable = self.rsocks[&h].queue.front().map(|m| m.len()).unwrap_or(0);
                *result = Ok(SockInfo {
                    local: None,
                    remote: None,
                    readable,
                    error: 0,
                    kind: Some(SockKind::Route),
                    listening: false,
                    keepalive: false,
                    nodelay: false,
                    linger_abort: false,
                    rx_buffer: 8192,
                    tx_buffer: 8192,
                });
            }
            SockOp::Listen { result, .. } => *result = Err(errno::EOPNOTSUPP),
            SockOp::Accept { result, .. } => *result = Err(errno::EOPNOTSUPP),
            SockOp::Bind { result, .. } | SockOp::Connect { result, .. } | SockOp::Shutdown { result, .. } => *result = Ok(()),
            SockOp::SetOpt { result, .. } => *result = Ok(()),
            _ => return None,
        }
        Some(true)
    }

    /// Every interface's ARP entries.
    pub fn neighbors(&self, nets: &[Net]) -> Vec<crate::rtsock::Neighbor> {
        crate::rtsock::neighbors(nets, smoltcp::time::Instant::from_micros(up_us() as i64))
    }

    /// An op on a raw socket (or opening one): Some(done), else None (not
    /// a raw socket's: the TCP/UDP code takes it).
    fn try_raw(&mut self, op: &mut SockOp, nets: &mut [Net]) -> Option<bool> {
        use crate::raw::RawEntry;
        use smoltcp::socket::raw::Socket as RawSock;
        if let SockOp::Open { kind: SockKind::Raw(p), result } = op {
            let h = self.next;
            self.next = self.next.wrapping_add(1).max(1);
            let e = RawEntry::new(*p, nets, self.seed16.wrapping_mul(31));
            self.raws.insert(h, e);
            *result = Ok(h);
            return Some(true);
        }
        let h = match op {
            SockOp::Bind { h, .. } | SockOp::Listen { h, .. } | SockOp::Accept { h, .. } | SockOp::Connect { h, .. } | SockOp::Send { h, .. }
            | SockOp::Recv { h, .. } | SockOp::Close { h, .. } | SockOp::Shutdown { h, .. } | SockOp::Info { h, .. } | SockOp::SetOpt { h, .. } => *h,
            _ => return None,
        };
        let r = self.raws.get_mut(&h)?;
        match op {
            SockOp::Bind { addr, result, .. } => {
                r.bound = if *addr == [0; 4] { None } else { Some(*addr) };
                *result = Ok(());
            }
            SockOp::Connect { addr, result, .. } => {
                r.peer = if *addr == [0; 4] { None } else { Some(*addr) };
                *result = Ok(());
            }
            SockOp::Listen { result, .. } => *result = Err(errno::EOPNOTSUPP),
            SockOp::Accept { result, .. } => *result = Err(errno::EOPNOTSUPP),
            SockOp::Shutdown { result, .. } => *result = Ok(()),
            SockOp::Send { data, to, result, .. } => {
                let Some(dst) = to.map(|t| t.0).or(r.peer) else {
                    *result = Err(errno::EDESTADDRREQ);
                    return Some(true);
                };
                let Some(k) = self.routes.select(nets, dst) else {
                    *result = Err(errno::ENETUNREACH);
                    return Some(true);
                };
                let src = r.bound.or_else(|| nets[k].addr().map(|c| c.address().octets())).unwrap_or([0; 4]);
                // Raw datagrams go out with MAXTTL unless IP_TTL says otherwise
                // (4.4BSD rip_output; Roadshow's ping requests carry 255).
                let Some(p) = r.packet(data, src, dst, 255) else {
                    *result = Err(errno::EINVAL);
                    return Some(true);
                };
                // The IP filter's verdict now, as Roadshow's ip_output gives
                // it (ping: "sendto: No route to host").
                if crate::ipfil::refuse(crate::ipf::ifnet(k as u8), &p) {
                    *result = Err(errno::EHOSTUNREACH);
                    return Some(true);
                }
                let s = nets[k].sockets.get_mut::<RawSock>(r.socks[k]);
                if p.len() > s.payload_send_capacity() {
                    *result = Err(errno::EMSGSIZE);
                    return Some(true);
                }
                match s.send_slice(&p) {
                    Ok(()) => *result = Ok(data.len()),
                    // Full: wait for room.
                    Err(_) => return Some(false),
                }
            }
            SockOp::Recv { max, peek, result, .. } => {
                let Some(k) = r.pending(nets) else { return Some(false) };
                let s = nets[k].sockets.get_mut::<RawSock>(r.socks[k]);
                let got = if *peek { s.peek().map(|d| d.to_vec()) } else { s.recv().map(|d| d.to_vec()) };
                *result = match got {
                    Ok(mut d) => {
                        let from = if d.len() >= 20 { [d[12], d[13], d[14], d[15]] } else { [0; 4] };
                        d.truncate(*max);
                        Ok((d, Some((from, 0))))
                    }
                    Err(_) => Err(errno::EWOULDBLOCK),
                };
            }
            SockOp::Close { result, .. } => {
                if let Some(r) = self.raws.remove(&h) {
                    for (k, s) in r.socks.into_iter().enumerate() {
                        nets[k].sockets.remove(s);
                    }
                }
                *result = Ok(());
            }
            SockOp::Info { result, .. } => {
                let readable = r.next_len(nets);
                let (rx, tx) = {
                    let s = nets[0].sockets.get::<RawSock>(r.socks[0]);
                    (s.payload_recv_capacity(), s.payload_send_capacity())
                };
                *result = Ok(SockInfo {
                    local: Some((r.bound.unwrap_or([0; 4]), 0)),
                    remote: r.peer.map(|p| (p, 0)),
                    readable,
                    error: 0,
                    kind: Some(SockKind::Raw(r.proto)),
                    listening: false,
                    keepalive: false,
                    nodelay: false,
                    linger_abort: false,
                    rx_buffer: rx,
                    tx_buffer: tx,
                });
            }
            SockOp::SetOpt { opt, result, .. } => {
                match opt {
                    SockOpt::Ttl(t) => r.ttl = Some(*t),
                    SockOpt::HdrIncl(b) => r.hdrincl = *b || r.proto == crate::raw::IPPROTO_RAW,
                    _ => {}
                }
                *result = Ok(());
            }
            _ => return None,
        }
        Some(true)
    }

    fn try_op(&mut self, op: &mut SockOp, nets: &mut [Net], first: bool, nonblock: bool) -> bool {
        if let Some(done) = self.try_route(op, nets) {
            return done;
        }
        if let Some(done) = self.try_raw(op, nets) {
            return done;
        }
        let has_addr = nets.iter().any(|n| n.addr().is_some());
        match op {
            SockOp::Open { kind, result } => {
                let e = match kind {
                    SockKind::Tcp => Entry::new(Kind::Tcp, (0, nets[0].sockets.add(tcp_socket()))),
                    SockKind::Udp => {
                        let udp: Vec<SocketHandle> = nets.iter_mut().map(|n| n.sockets.add(udp_socket())).collect();
                        let mut e = Entry::new(Kind::Udp, (0, udp[0]));
                        e.udp = udp;
                        e
                    }
                    // Opened by try_raw / try_route.
                    SockKind::Raw(_) | SockKind::Route => {
                        *result = Err(errno::EPROTONOSUPPORT);
                        return true;
                    }
                };
                let h = self.next;
                self.next = self.next.wrapping_add(1).max(1);
                self.socks.insert(h, e);
                *result = Ok(h);
                true
            }
            SockOp::Bind { h, addr, port, result } => {
                let Some(e) = self.socks.get(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                if e.bound.1 != 0 || e.kind == Kind::Listener {
                    *result = Err(errno::EINVAL);
                    return true;
                }
                let udp = e.kind == Kind::Udp;
                if *port != 0 && self.socks.values().any(|o| (o.kind == Kind::Udp) == udp && o.bound.1 == *port) {
                    *result = Err(errno::EADDRINUSE);
                    return true;
                }
                let p = if *port == 0 { self.ephemeral(udp, nets) } else { *port };
                let e = self.socks.get_mut(h).unwrap();
                e.bound = (if *addr == [0; 4] { None } else { Some(*addr) }, p);
                if udp && Self::udp_bind_all(e, nets).is_err() {
                    e.bound = (None, 0);
                    *result = Err(errno::EINVAL);
                    return true;
                }
                *result = Ok(());
                true
            }
            SockOp::Listen { h, backlog, result } => {
                let Some(e) = self.socks.get_mut(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                match e.kind {
                    Kind::Udp => {
                        *result = Err(errno::EOPNOTSUPP);
                        return true;
                    }
                    Kind::Listener => {
                        *result = Ok(());
                        return true;
                    }
                    Kind::Tcp => {}
                }
                if e.connecting || e.started != 0 {
                    *result = Err(errno::EINVAL);
                    return true;
                }
                // Unbound: an ephemeral port, as BSD's in_pcbbind (Roadshow
                // too, portprobe "tcp listen unbound").
                if e.bound.1 == 0 {
                    let p = self.ephemeral(false, nets);
                    self.socks.get_mut(h).unwrap().bound.1 = p;
                }
                let e = self.socks.get_mut(h).unwrap();
                let lep = e.listen_endpoint();
                let n = (*backlog).clamp(1, MAX_BACKLOG as i32) as usize;
                // Bound to one address: that interface (the first while it
                // has none yet); else every interface.
                let on: Vec<usize> = match e.bound.0 {
                    Some(a) => vec![owner(nets, a).unwrap_or(0)],
                    None => (0..nets.len()).collect(),
                };
                e.at = Self::move_tcp(nets, e.at, on[0]);
                if tcp_of(nets, e.at).listen(lep).is_err() {
                    *result = Err(errno::EINVAL);
                    return true;
                }
                e.pool.push(e.at);
                e.backlog = n;
                for &k in &on {
                    let have = if k == on[0] { 1 } else { 0 };
                    for _ in have..n {
                        let mut s = tcp_socket();
                        let _ = s.listen(lep);
                        e.pool.push((k, nets[k].sockets.add(s)));
                    }
                }
                e.kind = Kind::Listener;
                *result = Ok(());
                true
            }
            SockOp::Accept { h, result } => {
                let Some(e) = self.socks.get(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                if e.kind != Kind::Listener {
                    *result = Err(errno::EINVAL);
                    return true;
                }
                let Some(i) = Self::ready_in_pool(e, nets) else { return false };
                let e = self.socks.get_mut(h).unwrap();
                let lep = e.listen_endpoint();
                let conn = e.pool.swap_remove(i);
                crate::stats::tcp_event(crate::stats::TCPS_ACCEPTS);
                crate::stats::tcp_event(crate::stats::TCPS_CONNECTS);
                let mut fresh = tcp_socket();
                let _ = fresh.listen(lep);
                let fresh = (conn.0, nets[conn.0].sockets.add(fresh));
                e.pool.push(fresh);
                e.at = e.pool[0];
                let s = tcp_of(nets, conn);
                s.set_timeout(None);
                s.set_nagle_enabled(false);
                let remote = s.remote_endpoint().and_then(endpoint).unwrap_or(([0; 4], 0));
                let id = self.next;
                self.next = self.next.wrapping_add(1).max(1);
                let mut ne = Entry::new(Kind::Tcp, conn);
                // Connected; its port belongs to the listener ("bound" stays
                // empty). It takes the listener's options, as in BSD.
                ne.started = 1;
                if let Some(l) = self.socks.get(h) {
                    ne.keepalive = l.keepalive;
                    ne.nodelay = l.nodelay;
                    ne.linger_abort = l.linger_abort;
                }
                apply_keepalive(tcp_of(nets, conn), ne.keepalive);
                tcp_of(nets, conn).set_nagle_enabled(!ne.nodelay);
                self.socks.insert(id, ne);
                *result = Ok((id, remote));
                true
            }
            SockOp::Connect { h, addr, port, result } => {
                let Some(e) = self.socks.get(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                match e.kind {
                    Kind::Listener => {
                        *result = Err(errno::EISCONN);
                        return true;
                    }
                    Kind::Udp => {
                        if let Err(err) = self.udp_autobind(*h, nets) {
                            *result = Err(err);
                            return true;
                        }
                        let e = self.socks.get_mut(h).unwrap();
                        e.peer = if *addr == [0; 4] && *port == 0 { None } else { Some(ep_of(*addr, *port)) };
                        *result = Ok(());
                        return true;
                    }
                    Kind::Tcp => {}
                }
                if first {
                    if e.connecting || e.deferred.is_some() {
                        *result = Err(errno::EALREADY);
                        return true;
                    }
                    if tcp_of(nets, e.at).state() != tcp::State::Closed {
                        *result = Err(errno::EISCONN);
                        return true;
                    }
                    let remote = ep_of(*addr, *port);
                    self.socks.get_mut(h).unwrap().error = 0;
                    return match self.start_connect(*h, remote, nets) {
                        Ok(true) => false,
                        Ok(false) => {
                            // No interface has an address yet (the stack
                            // has just started): the connect starts when
                            // DHCP gives one.
                            self.socks.get_mut(h).unwrap().deferred = Some((remote, up_us()));
                            false
                        }
                        Err(err) => {
                            *result = Err(err);
                            true
                        }
                    };
                }
                // Waiting: progress() has settled the background state.
                if e.connecting || e.deferred.is_some() {
                    return false;
                }
                let e = self.socks.get_mut(h).unwrap();
                *result = if e.error != 0 { Err(core::mem::take(&mut e.error)) } else { Ok(()) };
                true
            }
            SockOp::Send { h, data, to, result } => {
                let Some(e) = self.socks.get(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                match e.kind {
                    Kind::Listener => {
                        *result = Err(errno::ENOTCONN);
                        true
                    }
                    Kind::Udp => {
                        let Some(dest) = to.map(|(a, p)| ep_of(a, p)).or(e.peer) else {
                            *result = Err(errno::EDESTADDRREQ);
                            return true;
                        };
                        let dst = endpoint(dest).map(|d| d.0).unwrap_or([0; 4]);
                        let k = match e.bound.0 {
                            Some(a) => owner(nets, a),
                            None => self.routes.select(nets, dst),
                        };
                        let Some(k) = k else { return false };
                        if let Err(err) = self.udp_autobind(*h, nets) {
                            *result = Err(err);
                            return true;
                        }
                        let e = &self.socks[&*h];
                        // The IP filter's verdict now, as Roadshow's
                        // ip_output gives it.
                        let src = e.bound.0.or_else(|| nets[k].addr().map(|c| c.address().octets())).unwrap_or([0; 4]);
                        let dg = crate::ipfil::udp_datagram(src, e.bound.1, dst, dest.port, data);
                        if crate::ipfil::refuse(crate::ipf::ifnet(k as u8), &dg) {
                            *result = Err(errno::EHOSTUNREACH);
                            return true;
                        }
                        let s = nets[k].sockets.get_mut::<udp::Socket>(e.udp[k]);
                        if data.len() > s.payload_send_capacity() {
                            *result = Err(errno::EMSGSIZE);
                            return true;
                        }
                        match s.send_slice(data, dest) {
                            Ok(()) => {
                                *result = Ok(data.len());
                                true
                            }
                            Err(udp::SendError::BufferFull) => false,
                            Err(udp::SendError::Unaddressable) => {
                                *result = Err(errno::EINVAL);
                                true
                            }
                        }
                    }
                    Kind::Tcp => {
                        if e.connecting || e.deferred.is_some() {
                            return false;
                        }
                        let started = e.started;
                        let s = tcp_of(nets, e.at);
                        if !s.may_send() {
                            *result = Err(if s.state() == tcp::State::Closed && started == 0 { errno::ENOTCONN } else { errno::EPIPE });
                            return true;
                        }
                        // Blocking: wait for room worth a call (see
                        // send_room); non-blocking: any room.
                        if !s.can_send() || (!nonblock && !send_room(s, data.len())) {
                            return false;
                        }
                        *result = s.send_slice(data).map_err(|_| errno::EPIPE);
                        if let Ok(n) = *result {
                            tune_tx(&e.tune, s, n);
                        }
                        true
                    }
                }
            }
            SockOp::Recv { h, max, peek, result } => {
                let Some(e) = self.socks.get(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                if e.read_shut {
                    *result = Ok((Vec::new(), None));
                    return true;
                }
                match e.kind {
                    Kind::Listener => {
                        *result = Err(errno::ENOTCONN);
                        true
                    }
                    Kind::Udp => {
                        let Some(k) = Self::udp_pending(e, nets) else { return false };
                        let s = nets[k].sockets.get_mut::<udp::Socket>(e.udp[k]);
                        // BSD: a datagram longer than the buffer is cut,
                        // the rest dropped (smoltcp's recv_slice would
                        // drop it all).
                        let r = if *peek { s.peek().map(|(d, m)| (d, m.endpoint)) } else { s.recv().map(|(d, m)| (d, m.endpoint)) };
                        *result = match r {
                            Ok((d, from)) => Ok((d[..d.len().min(*max)].to_vec(), endpoint(from))),
                            Err(_) => Err(errno::EWOULDBLOCK),
                        };
                        true
                    }
                    Kind::Tcp => {
                        if e.connecting || e.deferred.is_some() {
                            return false;
                        }
                        let started = e.started;
                        let s = tcp_of(nets, e.at);
                        let from = s.remote_endpoint().and_then(endpoint);
                        if s.can_recv() {
                            let mut buf = vec![0u8; (*max).min(s.recv_queue()).max(1)];
                            let r = if *peek { s.peek_slice(&mut buf) } else { s.recv_slice(&mut buf) };
                            *result = match r {
                                Ok(n) => {
                                    if !*peek {
                                        tune_rx(&e.tune, s, n);
                                    }
                                    buf.truncate(n);
                                    Ok((buf, from))
                                }
                                Err(_) => Err(errno::ENOTCONN),
                            };
                            return true;
                        }
                        if !s.may_recv() {
                            // The peer has closed (or the connection is
                            // gone): the end of the stream; never connected
                            // is ENOTCONN.
                            let closed = s.state() == tcp::State::Closed;
                            let reset = closed && started != 0 && !e.fin_seen;
                            *result = if closed && started == 0 {
                                Err(errno::ENOTCONN)
                            } else if reset {
                                Err(errno::ECONNRESET)
                            } else {
                                Ok((Vec::new(), from))
                            };
                            if reset {
                                self.socks.get_mut(h).unwrap().fin_seen = true;
                            }
                            return true;
                        }
                        false
                    }
                }
            }
            SockOp::Close { h, result } => {
                match self.socks.remove(h) {
                    Some(e) => {
                        match e.kind {
                            Kind::Tcp => {
                                if e.started != 0 {
                                    crate::stats::tcp_event(crate::stats::TCPS_CLOSED);
                                }
                                if e.linger_abort {
                                    tcp_of(nets, e.at).abort();
                                } else {
                                    tcp_of(nets, e.at).close();
                                }
                                self.closing.push(e.at);
                            }
                            Kind::Listener => {
                                // Connections not yet accepted are reset.
                                for p in e.pool {
                                    tcp_of(nets, p).abort();
                                    self.closing.push(p);
                                }
                            }
                            Kind::Udp => {
                                for (k, u) in e.udp.into_iter().enumerate() {
                                    if nets[k].sockets.get::<udp::Socket>(u).send_queue() > 0 {
                                        self.udp_closing.push((k, u, up_us() + 5_000_000));
                                    } else {
                                        nets[k].sockets.remove(u);
                                    }
                                }
                            }
                        }
                        *result = Ok(());
                    }
                    None => *result = Err(errno::EBADF),
                }
                true
            }
            SockOp::Shutdown { h, how, result } => {
                let Some(e) = self.socks.get_mut(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                if !(0..=2).contains(how) {
                    *result = Err(errno::EINVAL);
                    return true;
                }
                if e.kind != Kind::Tcp || e.started == 0 {
                    *result = Err(errno::ENOTCONN);
                    return true;
                }
                if *how != 1 {
                    e.read_shut = true;
                }
                if *how != 0 {
                    tcp_of(nets, e.at).close();
                }
                *result = Ok(());
                true
            }
            SockOp::SetOpt { h, opt, result } => {
                let Some(e) = self.socks.get_mut(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                let tcp_at = if e.kind == Kind::Tcp { Some(e.at) } else { None };
                match opt {
                    SockOpt::KeepAlive(on) => {
                        e.keepalive = *on;
                        if let Some(at) = tcp_at {
                            apply_keepalive(tcp_of(nets, at), *on);
                        }
                    }
                    SockOpt::NoDelay(on) => {
                        e.nodelay = *on;
                        if let Some(at) = tcp_at {
                            tcp_of(nets, at).set_nagle_enabled(!*on);
                        }
                    }
                    SockOpt::LingerAbort(on) => e.linger_abort = *on,
                    SockOpt::Events(mask, target) => {
                        e.ev = if *mask == 0 { None } else { Some(Watch { mask: *mask, target: target.take(), pending: 0, seen: 0 }) };
                    }
                    // IP_TTL: the socket's own hop limit (TCP: its socket;
                    // UDP: its socket on every interface).
                    SockOpt::Ttl(t) => {
                        let t = Some(*t);
                        if let Some(at) = tcp_at {
                            tcp_of(nets, at).set_hop_limit(t);
                        }
                        if e.kind == Kind::Udp {
                            for (k, &u) in e.udp.iter().enumerate() {
                                nets[k].sockets.get_mut::<udp::Socket>(u).set_hop_limit(t);
                            }
                        }
                    }
                    // Raw sockets only.
                    SockOpt::HdrIncl(_) => {
                        *result = Err(errno::ENOPROTOOPT);
                        return true;
                    }
                }
                *result = Ok(());
                true
            }
            SockOp::TakeEvents { hs, result } => {
                *result = None;
                for &h in hs.iter() {
                    if let Some(w) = self.socks.get_mut(&h).and_then(|e| e.ev.as_mut()) {
                        if w.pending != 0 {
                            *result = Some((h, core::mem::take(&mut w.pending)));
                            break;
                        }
                    }
                }
                true
            }
            SockOp::Info { h, take_error, result } => {
                let Some(e) = self.socks.get(h) else {
                    *result = Err(errno::EBADF);
                    return true;
                };
                let my_addr = nets[e.at.0].addr().map(|c| c.address().octets());
                let bound_local = (e.bound.0.or(my_addr).unwrap_or([0; 4]), e.bound.1);
                let mut inf = SockInfo { listening: e.kind == Kind::Listener, ..SockInfo::default() };
                match e.kind {
                    Kind::Tcp => {
                        inf.kind = Some(SockKind::Tcp);
                        let s = tcp_of(nets, e.at);
                        inf.local = s.local_endpoint().and_then(endpoint).or(if e.bound.1 != 0 { Some(bound_local) } else { None });
                        inf.remote = s.remote_endpoint().and_then(endpoint);
                        inf.readable = s.recv_queue();
                    }
                    Kind::Listener => {
                        inf.kind = Some(SockKind::Tcp);
                        inf.local = Some(bound_local);
                    }
                    Kind::Udp => {
                        inf.kind = Some(SockKind::Udp);
                        inf.local = if e.bound.1 != 0 { Some(bound_local) } else { None };
                        inf.remote = e.peer.and_then(endpoint);
                        inf.readable = match Self::udp_pending(e, nets) {
                            Some(k) => nets[k].sockets.get_mut::<udp::Socket>(e.udp[k]).peek().map(|(d, _)| d.len()).unwrap_or(0),
                            None => 0,
                        };
                    }
                }
                let e = self.socks.get_mut(h).unwrap();
                inf.error = if *take_error { core::mem::take(&mut e.error) } else { e.error };
                inf.keepalive = e.keepalive;
                inf.nodelay = e.nodelay;
                inf.linger_abort = e.linger_abort;
                // The socket's real buffer sizes.
                (inf.rx_buffer, inf.tx_buffer) = match e.kind {
                    Kind::Udp => {
                        let u = nets[0].sockets.get::<udp::Socket>(e.udp[0]);
                        (u.payload_recv_capacity(), u.payload_send_capacity())
                    }
                    _ => {
                        let t = nets[e.at.0].sockets.get::<tcp::Socket>(e.at.1);
                        (t.recv_capacity(), t.send_capacity())
                    }
                };
                *result = Ok(inf);
                true
            }
            SockOp::Select { reads, writes, until_us, result } => {
                if reads.iter().chain(writes.iter()).any(|h| !self.socks.contains_key(h) && !self.raws.contains_key(h) && !self.rsocks.contains_key(h)) {
                    *result = Err(errno::EBADF);
                    return true;
                }
                let r: Vec<u32> = reads.iter().copied().filter(|&h| self.readable(h, nets)).collect();
                let w: Vec<u32> = writes.iter().copied().filter(|&h| self.writable(h, nets)).collect();
                if !r.is_empty() || !w.is_empty() || until_us.map(|u| up_us() >= u).unwrap_or(false) {
                    *result = Ok((r, w));
                    return true;
                }
                false
            }
            SockOp::List { kind, result } => {
                let ep = |p: Option<IpEndpoint>| p.and_then(endpoint).unwrap_or(([0; 4], 0));
                let tcp_info = |at: At, nets: &mut [Net]| {
                    let s = tcp_of(nets, at);
                    ConnInfo {
                        local: ep(s.local_endpoint()),
                        remote: ep(s.remote_endpoint()),
                        recv_queue: s.recv_queue() as u32,
                        send_queue: s.send_queue() as u32,
                        tcp_state: tcps(s.state()),
                    }
                };
                let mut v = Vec::new();
                for e in self.socks.values() {
                    match (*kind, e.kind) {
                        (SockKind::Tcp, Kind::Tcp) => v.push(tcp_info(e.at, nets)),
                        (SockKind::Tcp, Kind::Listener) => v.push(ConnInfo {
                            local: (e.bound.0.unwrap_or([0; 4]), e.bound.1),
                            tcp_state: 1,
                            ..ConnInfo::default()
                        }),
                        (SockKind::Udp, Kind::Udp) => {
                            let (mut rq, mut sq) = (0u32, 0u32);
                            for (k, &u) in e.udp.iter().enumerate() {
                                let s = nets[k].sockets.get::<udp::Socket>(u);
                                rq += s.recv_queue() as u32;
                                sq += s.send_queue() as u32;
                            }
                            v.push(ConnInfo {
                                local: (e.bound.0.unwrap_or([0; 4]), e.bound.1),
                                remote: ep(e.peer),
                                recv_queue: rq,
                                send_queue: sq,
                                tcp_state: 0,
                            });
                        }
                        _ => {}
                    }
                }
                if *kind == SockKind::Tcp {
                    for &at in &self.closing {
                        v.push(tcp_info(at, nets));
                    }
                }
                *result = v;
                true
            }
            SockOp::Resolve { ask, state, result } => {
                use crate::resolver::{Answer, Ask, ROUNDS, WAIT_US};
                if first {
                    if let Ask::Name(n) = &*ask {
                        if let Some(a) = parse_dotted(n) {
                            *result = Ok(Answer { name: n.clone(), aliases: Vec::new(), addrs: vec![a] });
                            return true;
                        }
                        // A name no query can carry (an empty label, a
                        // label over 63 bytes, over 253 in all).
                        if !crate::resolver::valid_name(n) {
                            *result = Err(herrno::HOST_NOT_FOUND);
                            return true;
                        }
                    }
                }
                let Some((k, servers)) = self.dns_choice(nets) else {
                    if first && has_addr {
                        *result = Err(herrno::NO_RECOVERY);
                        return true;
                    }
                    // A lease (and its servers) may still come.
                    return false;
                };
                self.resolver.drain(nets);
                if state.id != 0 {
                    if let Some(r) = self.resolver.take(state.id) {
                        *result = r;
                        return true;
                    }
                }
                let now = up_us();
                if state.id == 0 || now.saturating_sub(state.sent) >= WAIT_US {
                    let n = servers.len().max(1);
                    if state.tries as usize >= n * ROUNDS as usize {
                        self.resolver.forget(state.id);
                        *result = Err(herrno::TRY_AGAIN);
                        return true;
                    }
                    if state.id == 0 {
                        state.id = self.resolver.new_id(ask);
                    }
                    let server = servers[state.tries as usize % n];
                    // A send that did not go counts as a try too, so the
                    // lookup ends (TRY_AGAIN) rather than waiting for ever.
                    let _ = self.resolver.send(nets, k, server, state.id);
                    state.sent = now;
                    state.tries += 1;
                }
                false
            }
        }
    }
}

/// "a.b.c.d" as an address.
pub fn parse_dotted(s: &str) -> Option<[u8; 4]> {
    let mut o = [0u8; 4];
    let mut it = s.split('.');
    for b in &mut o {
        let p = it.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        *b = p.parse().ok()?;
    }
    it.next().is_none().then_some(o)
}

/// Why smoltcp closed a connect: its own timeout (after TIMEOUT_SECS) or a
/// refusal (sooner). QEMU's user network answers a closed host port with
/// nothing, so there it is always the timeout.
fn closed_error(started: u64) -> i32 {
    if up_us().saturating_sub(started) + 500_000 >= TIMEOUT_SECS * 1_000_000 { errno::ETIMEDOUT } else { errno::ECONNREFUSED }
}

fn fail(op: &mut SockOp, e: i32) {
    match op {
        SockOp::Open { result, .. } => *result = Err(e),
        SockOp::Bind { result, .. } => *result = Err(e),
        SockOp::Listen { result, .. } => *result = Err(e),
        SockOp::Accept { result, .. } => *result = Err(e),
        SockOp::Connect { result, .. } => *result = Err(e),
        SockOp::Send { result, .. } => *result = Err(e),
        SockOp::Recv { result, .. } => *result = Err(e),
        SockOp::Close { result, .. } => *result = Err(e),
        SockOp::Shutdown { result, .. } => *result = Err(e),
        SockOp::Info { result, .. } => *result = Err(e),
        SockOp::Select { result, .. } => *result = Err(e),
        SockOp::List { .. } | SockOp::TakeEvents { .. } => {}
        SockOp::SetOpt { result, .. } => *result = Err(e),
        // A lookup's error is an h_errno: an interrupted or refused one is
        // TRY_AGAIN (the library sets errno itself).
        SockOp::Resolve { result, .. } => {
            let _ = e;
            *result = Err(herrno::TRY_AGAIN)
        }
    }
}
