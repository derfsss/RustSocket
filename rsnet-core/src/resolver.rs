//! The stack's DNS client: name -> addresses (A, following CNAMEs) and
//! address -> name (PTR for d.c.b.a.in-addr.arpa), as Roadshow's resolver
//! answers (testprogs/rstcp/c/hostprobe.c and revprobe.c):
//! every address of a name, the canonical name with the asked one as an
//! alias (www.github.com: h_name github.com, alias www.github.com), and
//! "no such name" told from "no address" (HOST_NOT_FOUND / NO_DATA).
//! smoltcp's DNS socket answers with addresses only, so this is a small
//! client of the stack's own on one UDP socket: each lookup has a query id,
//! is sent to the name servers in turn (2 s each, every server twice) and
//! is answered from whatever datagram carries its id. NXDOMAIN is
//! HOST_NOT_FOUND, an answer without the record asked for NO_DATA, a
//! server failure or no answer at all TRY_AGAIN.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};

use crate::sock::{herrno, Net};

/// The local port the lookups go out from (outside the ephemeral range
/// sockets are given, 1024-5000).
const PORT: u16 = 49_200;
/// How long a server has to answer, and the rounds over the servers.
pub const WAIT_US: u64 = 2_000_000;
pub const ROUNDS: u8 = 2;
/// BSD's MAXADDRS / MAXALIASES.
const MAX_ADDRS: usize = 35;
const MAX_ALIASES: usize = 35;

/// What a lookup asks.
#[derive(Clone, Debug)]
pub enum Ask {
    /// The addresses of a name.
    Name(String),
    /// The name of an address.
    Addr([u8; 4]),
}

/// A lookup's answer: the canonical name (or the address's name), the
/// other names it goes by, and the addresses.
#[derive(Clone, Debug, Default)]
pub struct Answer {
    pub name: String,
    pub aliases: Vec<String>,
    pub addrs: Vec<[u8; 4]>,
}

/// A lookup's progress, kept in its op: the query id (0 before the first
/// send), when it was last sent and how often.
#[derive(Clone, Copy, Debug, Default)]
pub struct State {
    pub id: u16,
    pub sent: u64,
    pub tries: u8,
}

/// The stack's resolver: its socket (interface and handle), the lookups in
/// flight (id -> what was asked) and the answers that came for them.
#[derive(Default)]
pub struct Resolver {
    at: Option<(usize, SocketHandle)>,
    next_id: u16,
    pending: BTreeMap<u16, Ask>,
    answers: BTreeMap<u16, Result<Answer, i32>>,
    /// Ids given up (interrupted or out of tries): a late reply is dropped.
    gone: BTreeSet<u16>,
}

impl Resolver {
    /// A new query id (never 0) for `ask`.
    pub fn new_id(&mut self, ask: &Ask) -> u16 {
        loop {
            self.next_id = self.next_id.wrapping_add(1).max(1);
            if !self.pending.contains_key(&self.next_id) {
                break;
            }
        }
        self.gone.remove(&self.next_id);
        self.pending.insert(self.next_id, ask.clone());
        self.next_id
    }

    /// The lookup with `id` is over (answered, given up or interrupted).
    pub fn forget(&mut self, id: u16) {
        if self.pending.remove(&id).is_some() {
            self.gone.insert(id);
        }
        self.answers.remove(&id);
        while self.gone.len() > 64 {
            let first = *self.gone.iter().next().unwrap();
            self.gone.remove(&first);
        }
    }

    /// The answer for `id`, once one came.
    pub fn take(&mut self, id: u16) -> Option<Result<Answer, i32>> {
        let r = self.answers.remove(&id)?;
        self.pending.remove(&id);
        Some(r)
    }

    /// The socket, on interface `k` (made again there if it was on
    /// another one).
    fn socket(&mut self, nets: &mut [Net], k: usize) -> Option<SocketHandle> {
        if let Some((sk, h)) = self.at {
            if sk == k {
                return Some(h);
            }
            nets[sk].sockets.remove(h);
            self.at = None;
        }
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 2048]);
        let mut s = udp::Socket::new(rx, tx);
        s.bind(PORT).ok()?;
        let h = nets[k].sockets.add(s);
        self.at = Some((k, h));
        Some(h)
    }

    /// Send query `id` to `server` through interface `k`: true when it went
    /// into the socket.
    pub fn send(&mut self, nets: &mut [Net], k: usize, server: IpAddress, id: u16) -> bool {
        let Some(ask) = self.pending.get(&id) else { return false };
        let Some(q) = query(id, ask) else { return false };
        let Some(h) = self.socket(nets, k) else { return false };
        nets[k].sockets.get_mut::<udp::Socket>(h).send_slice(&q, IpEndpoint::new(server, 53)).is_ok()
    }

    /// Read what came in and keep the answers for lookups in flight.
    pub fn drain(&mut self, nets: &mut [Net]) {
        let Some((k, h)) = self.at else { return };
        let s = nets[k].sockets.get_mut::<udp::Socket>(h);
        let mut buf = [0u8; 1500];
        while let Ok((n, _)) = s.recv_slice(&mut buf) {
            let p = &buf[..n];
            if p.len() < 12 {
                continue;
            }
            let id = u16::from_be_bytes([p[0], p[1]]);
            if let Some(ask) = self.pending.get(&id) {
                if let Some(r) = answer(p, ask) {
                    self.answers.insert(id, r);
                }
            }
        }
    }
}

/// Whether `name` can be asked: labels of 1 to 63 bytes, 253 in all (a
/// final dot ignored).
pub fn valid_name(name: &str) -> bool {
    labels(name).is_some()
}

/// `name`'s labels (a final dot ignored): None for an empty or oversized
/// name or label.
fn labels(name: &str) -> Option<Vec<&str>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let v: Vec<&str> = name.split('.').collect();
    v.iter().all(|l| !l.is_empty() && l.len() <= 63).then_some(v)
}

/// The query for `ask`: header (RD), one question (A or PTR, class IN).
fn query(id: u16, ask: &Ask) -> Option<Vec<u8>> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    let push = |q: &mut Vec<u8>, l: &str| {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    };
    let kind = match ask {
        Ask::Name(n) => {
            for l in labels(n)? {
                push(&mut q, l);
            }
            1u8
        }
        Ask::Addr(a) => {
            for b in a.iter().rev() {
                push(&mut q, &alloc::format!("{}", b));
            }
            push(&mut q, "in-addr");
            push(&mut q, "arpa");
            12
        }
    };
    q.extend_from_slice(&[0, 0, kind, 0, 1]);
    Some(q)
}

/// A reply to `ask`: the answer, or an h_errno; None when it is not a
/// reply at all.
fn answer(p: &[u8], ask: &Ask) -> Option<Result<Answer, i32>> {
    if p[2] & 0x80 == 0 {
        return None;
    }
    match p[3] & 0x0f {
        0 => {}
        3 => return Some(Err(herrno::HOST_NOT_FOUND)),
        _ => return Some(Err(herrno::TRY_AGAIN)),
    }
    let qd = u16::from_be_bytes([p[4], p[5]]);
    let an = u16::from_be_bytes([p[6], p[7]]);
    let mut at = 12;
    for _ in 0..qd {
        at = skip_name(p, at)? + 4;
    }
    // The answer records: (owner, type, data offset, length).
    let mut recs: Vec<(String, u16, usize, usize)> = Vec::new();
    for _ in 0..an {
        let owner = read_name(p, at).unwrap_or_default();
        at = skip_name(p, at)?;
        let rr = p.get(at..at + 10)?;
        let kind = u16::from_be_bytes([rr[0], rr[1]]);
        let len = u16::from_be_bytes([rr[8], rr[9]]) as usize;
        let data = at + 10;
        if data + len > p.len() {
            return None;
        }
        recs.push((owner, kind, data, len));
        at = data + len;
    }
    match ask {
        Ask::Addr(a) => {
            let name = recs.iter().find(|r| r.1 == 12).and_then(|r| read_name(p, r.2));
            Some(match name {
                Some(n) => Ok(Answer { name: n, aliases: Vec::new(), addrs: vec![*a] }),
                None => Err(herrno::NO_DATA),
            })
        }
        Ask::Name(asked) => {
            // Follow the CNAME chain from the asked name; the names before
            // the canonical one are its aliases.
            let mut name = String::from(asked.strip_suffix('.').unwrap_or(asked));
            let mut aliases: Vec<String> = Vec::new();
            for _ in 0..16 {
                let next = recs.iter().find(|r| r.1 == 5 && r.0.eq_ignore_ascii_case(&name)).and_then(|r| read_name(p, r.2));
                match next {
                    Some(n) if !aliases.iter().any(|x| x.eq_ignore_ascii_case(&n)) => {
                        if aliases.len() < MAX_ALIASES {
                            aliases.push(core::mem::replace(&mut name, n));
                        } else {
                            name = n;
                        }
                    }
                    _ => break,
                }
            }
            let addrs: Vec<[u8; 4]> = recs
                .iter()
                .filter(|r| r.1 == 1 && r.3 == 4 && r.0.eq_ignore_ascii_case(&name))
                .map(|r| [p[r.2], p[r.2 + 1], p[r.2 + 2], p[r.2 + 3]])
                .take(MAX_ADDRS)
                .collect();
            Some(if addrs.is_empty() { Err(herrno::NO_DATA) } else { Ok(Answer { name, aliases, addrs }) })
        }
    }
}

/// The offset after the (possibly compressed) name at `at`.
fn skip_name(p: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let l = *p.get(at)? as usize;
        if l == 0 {
            return Some(at + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        at += 1 + l;
    }
}

/// The name at `at` as "a.b.c" (compression pointers followed, 64 at
/// most; 255 bytes at most).
fn read_name(p: &[u8], mut at: usize) -> Option<String> {
    let mut out = String::new();
    for _ in 0..64 {
        let l = *p.get(at)? as usize;
        if l == 0 {
            return (!out.is_empty()).then_some(out);
        }
        if l & 0xc0 == 0xc0 {
            at = ((l & 0x3f) << 8) | *p.get(at + 1)? as usize;
            continue;
        }
        let label = p.get(at + 1..at + 1 + l)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(core::str::from_utf8(label).ok()?);
        if out.len() > 255 {
            return None;
        }
        at += 1 + l;
    }
    None
}
