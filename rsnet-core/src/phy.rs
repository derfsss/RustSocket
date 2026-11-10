//! smoltcp's `Device` on a [`Link`]: received frames come from the link's
//! queue (their buffers go back to its pool once read), transmitted ones are
//! written straight into the link's write buffer and go out as raw writes.
//! A received frame's checksum checks that the card made (SANA-II
//! extensions) reach smoltcp as its PacketMeta (a patch of the vendored
//! copy), which skips them for that frame.

use alloc::boxed::Box;
use alloc::vec::Vec;

use smoltcp::phy::{Device, DeviceCapabilities, Loopback, Medium, PacketMeta, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::link::{Buf, Link, Pool};
use crate::s2xlogic;

/// A received frame, and the pool its buffer returns to.
pub struct Rx(Box<Buf>, Pool);

impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let frame = self.0.frame();
        crate::stats::frame(frame, true);
        let r = f(frame);
        self.1.give(self.0);
        r
    }

    /// The checks the card made on this frame: smoltcp skips them.
    fn meta(&self) -> PacketMeta {
        let mut m = PacketMeta::default();
        if self.0.trust & s2xlogic::TRUST_IP != 0 {
            m.rx_checked |= smoltcp::phy::RX_CHECKED_IPV4;
        }
        if self.0.trust & s2xlogic::TRUST_L4 != 0 {
            m.rx_checked |= smoltcp::phy::RX_CHECKED_L4;
        }
        m
    }
}

/// The right to send one frame on the link.
pub struct Tx<'a>(&'a mut Link);

impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.0
            .send_with(len, |b| {
                let r = f(b);
                crate::stats::frame(b, false);
                r
            })
            .0
    }
}

/// lo0: smoltcp's Loopback with the IP filter (ipfil.rs) on every frame as
/// it comes round, leaving lo0 and then arriving on it: Roadshow's ipf
/// counts and filters lo0's traffic too (ping 127.0.0.1).
pub struct Lo(pub Loopback);

/// A frame that came round lo0 and passed the filter.
pub struct LoRx(Vec<u8>);

impl RxToken for LoRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl Device for Lo {
    type RxToken<'a> = LoRx;
    type TxToken<'a> = <Loopback as Device>::TxToken<'a>;

    fn receive(&mut self, now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let ifp = crate::ipf::ifnet(crate::stack::LO as u8);
        loop {
            let (rx, tx) = self.0.receive(now)?;
            drop(tx);
            let mut frame = rx.consume(|f| f.to_vec());
            let ipv4 = frame.len() >= 34 && frame[12] == 0x08 && frame[13] == 0x00;
            let mut answer = None;
            if !ipv4 {
                return Some((LoRx(frame), self.0.transmit(now)?));
            }
            // Leaving lo0: the rules, then NAT; arriving: NAT, then the rules
            // (3.4's order; Roadshow translates on its loopback too).
            let (eth, ip) = frame.split_at_mut(14);
            let mut pass = crate::ipfil::check(ifp, eth, ip, true, &mut None);
            if pass && crate::ipfil::running() {
                let t = crate::ipfil::now();
                crate::ipnat::nat_out(ifp, ip, t);
                crate::ipnat::nat_in(ifp, ip, t);
            }
            pass = pass && crate::ipfil::check(ifp, eth, ip, false, &mut answer);
            if pass {
                return Some((LoRx(frame), self.0.transmit(now)?));
            }
            // return-rst / return-icmp: round lo0 again.
            if let Some(a) = answer {
                let mut f = Vec::with_capacity(14 + a.len());
                f.extend_from_slice(&frame[6..12]);
                f.extend_from_slice(&frame[0..6]);
                f.extend_from_slice(&[0x08, 0x00]);
                f.extend_from_slice(&a);
                if let Some(tx) = self.0.transmit(now) {
                    tx.consume(f.len(), |b| b.copy_from_slice(&f));
                }
            }
        }
    }

    fn transmit(&mut self, now: Instant) -> Option<Self::TxToken<'_>> {
        self.0.transmit(now)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.0.capabilities()
    }
}

impl Device for Link {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Frames a monitoring hook drops never reach smoltcp.
        let f = loop {
            let mut f = self.rx.pop_front()?;
            if crate::monitor::frame(f.frame(), true) {
                crate::bpf::tap(self.slot, f.frame(), true);
                // The IP filter hook may drop or replace it.
                let (data, len) = f.parts();
                let mut reply = None;
                let kept = crate::ipf::filter(self.slot, data, *len as usize, true, Some(&mut reply));
                if let Some(r) = reply {
                    self.send(&r);
                }
                if let Some(n) = kept {
                    let (_, len) = f.parts();
                    *len = n as u32;
                    // NAT and a filter hook may have changed the frame
                    // since the card checked it: smoltcp checks it again.
                    if f.trust != 0 && (crate::ipfil::running() || crate::ipf::hook() != 0) {
                        f.trust = 0;
                    }
                    // A time stamp request: answered here (smoltcp does
                    // not), while icmp.procesststamp says so (forward.rs).
                    let ts = if crate::settings::SETTINGS.get(crate::settings::Setting::IcmpProcessTstamp) == crate::settings::IR_PROCESS {
                        crate::forward::timestamp_reply(f.frame(), &self.local, self.mac)
                    } else {
                        None
                    };
                    if let Some(rd) = crate::forward::redirect_of(f.frame(), &self.local) {
                        self.redirects.push(rd);
                    }
                    if let Some(r) = ts {
                        self.send(&r);
                    } else if !self.to_forward(f.frame()) {
                        // For another host, while forwarding: to the stack
                        // process, not smoltcp (forward.rs).
                        if f.trust != 0 {
                            self.stats.rx_csum_ok += 1;
                        }
                        break f;
                    } else {
                        let copy = f.frame().to_vec();
                        self.fwd.push(copy);
                    }
                }
            }
            self.pool.give(f);
        };
        let pool = self.pool.clone();
        Some((Rx(f, pool), Tx(self)))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(Tx(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        // smoltcp counts the Ethernet header in the MTU of this medium.
        c.max_transmission_unit = self.mtu as usize + 14;
        c.max_burst_size = None;
        c
    }
}
