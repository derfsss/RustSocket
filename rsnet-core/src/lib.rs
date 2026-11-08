//! The core of rustsocket.library: TCP/IP for AmigaOS 4 on smoltcp, over a
//! SANA-II network device.
//!
//! - [`link`]: one SANA-II unit opened as a client: raw Ethernet frames in
//!   (a pool of pending reads per packet type, each re-posted as it comes
//!   back) and out (raw writes).
//! - [`phy`]: smoltcp's `Device` on a [`link::Link`].
//! - [`stack`]: the stack process that owns the link and smoltcp's
//!   interface and sockets, and the [`stack::Stack`] handle other tasks
//!   use to talk to it (typed exec messages).
//! - [`sock`]: the sockets that programs use through the library.

#![no_std]

extern crate alloc;

pub mod link;
pub mod phy;
pub mod stack;
pub mod sock;
pub mod settings;
pub mod aam;
pub mod route;
pub mod stats;
pub mod raw;
pub mod rtsock;
pub mod control;
pub mod monitor;
pub mod bpf;
pub mod mbuf;
pub mod ipf;
pub mod ipfil;
pub mod ipnat;
pub mod resolver;
pub mod forward;
pub mod perf;
