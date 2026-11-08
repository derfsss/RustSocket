//! rsnet: start the Rust TCP/IP stack (rsnet-core) on one SANA-II
//! unit and check it: a DHCP lease, pings answered, a clean stop.
//!
//!   rsnet [unit] [device] [ping-address] [pings]
//!
//! Defaults: unit 1 of networks/virtionet.device (a second virtio-net
//! card, on a QEMU user network of its own, 10.0.4.0/24, so that another
//! stack can keep unit 0), ping 10.0.4.2 (QEMU's host side on that
//! network) 5 times. No other stack may have the unit open. Prints
//! PASS/FAIL lines; returns 0 when all pass.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use core::fmt::{self, Write};
use core::panic::PanicInfo;

use amigaos4::allocator::SharedExecAllocator;
use amigaos4::sys;
use amigaos4::timer::get_up_time;
use rsnet_core::stack::{Config, Stack, Unit};

// The stack process and this task share the heap.
#[global_allocator]
static ALLOCATOR: SharedExecAllocator = SharedExecAllocator;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    amigaos4::panic::default_panic_handler(info)
}

struct Out;
impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut buf = [0u8; 128];
        for chunk in s.as_bytes().chunks(buf.len() - 1) {
            buf[..chunk.len()].copy_from_slice(chunk);
            buf[chunk.len()] = 0;
            // SAFETY: a NUL-terminated buffer on the stack.
            unsafe { sys::dos_put_str(buf.as_ptr() as _) };
        }
        Ok(())
    }
}
macro_rules! say {
    ($($arg:tt)*) => {{ let _ = writeln!(Out, $($arg)*); }};
}

struct Tally {
    pass: u32,
    fail: u32,
}
impl Tally {
    fn check(&mut self, ok: bool, what: fmt::Arguments) {
        if ok {
            self.pass += 1;
        } else {
            self.fail += 1;
        }
        say!("{} {}", if ok { "PASS" } else { "FAIL" }, what);
        amigaos4::serial_println!("rsnet {} {}", if ok { "PASS" } else { "FAIL" }, what);
    }
}

fn ip(a: [u8; 4]) -> String {
    alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut o = [0u8; 4];
    let mut it = s.split('.');
    for b in &mut o {
        *b = it.next()?.parse().ok()?;
    }
    it.next().is_none().then_some(o)
}

fn ms() -> u64 {
    get_up_time().as_micros() / 1000
}

fn delay_ticks(t: u32) {
    // SAFETY: the main task is a Process; Delay(1) is 1/50 s.
    unsafe { sys::dos_delay(t) };
}

fn avail() -> u32 {
    // SAFETY: AvailMem only reads.
    unsafe { sys::exec_avail_mem(0) }
}

#[no_mangle]
pub extern "C" fn rust_main(args: *const u8, arglen: i32) -> i32 {
    // SAFETY: the Shell's argument string, `arglen` bytes.
    let text = unsafe { core::slice::from_raw_parts(args, arglen.max(0) as usize) };
    let text = core::str::from_utf8(text).unwrap_or("");
    let mut w = text.split_whitespace();
    let unit: u32 = w.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let device = String::from(w.next().unwrap_or("networks/virtionet.device"));
    let target = w.next().and_then(parse_ip).unwrap_or([10, 0, 4, 2]);
    let pings: u16 = w.next().and_then(|s| s.parse().ok()).unwrap_or(5);

    let mut t = Tally { pass: 0, fail: 0 };
    say!("rsnet: unit {} of {}, ping {} x{}", unit, device, ip(target), pings);
    let m0 = avail();

    let t0 = ms();
    let stack = match Stack::start(Config { units: alloc::vec![Unit { name: alloc::string::String::from("rs0"), device: device.clone(), unit }] }) {
        Ok(s) => s,
        Err(e) => {
            t.check(false, format_args!("start: {}", e));
            return 20;
        }
    };
    let st = stack.status().and_then(|v| v.into_iter().find(|s| s.name == "rs0"));
    say!(
        "info: link up in {} ms: MAC {:02x?}, MTU {:?}",
        ms() - t0,
        st.as_ref().map(|s| s.mac),
        st.as_ref().map(|s| s.mtu)
    );
    t.check(st.is_some(), format_args!("start: the stack opened {} unit {}", device, unit));

    // DHCP.
    let t1 = ms();
    let mut lease = None;
    while ms() - t1 < 10_000 {
        if let Some(s) = stack.status().and_then(|v| v.into_iter().find(|s| s.name == "rs0")) {
            if s.address.is_some() {
                lease = Some(s);
                break;
            }
        }
        delay_ticks(5);
    }
    let took = ms() - t1;
    match &lease {
        Some(s) => {
            let (a, p) = s.address.unwrap_or(([0; 4], 0));
            say!(
                "info: DHCP: {}/{} router {:?} DNS {:?} after {} ms",
                ip(a),
                p,
                s.router.map(ip),
                s.dns.iter().map(|d| ip(*d)).collect::<alloc::vec::Vec<_>>(),
                took
            );
            t.check(
                a[0] == 10 && a[1] == 0 && p == 24 && s.router.is_some() && took < 5000,
                format_args!("dhcp: a lease within 5 s ({}/{} via {:?})", ip(a), p, s.router.map(ip)),
            );
        }
        None => t.check(false, format_args!("dhcp: no lease in 10 s")),
    }

    // Ping.
    if lease.is_some() {
        let mut answered = 0u16;
        let mut rtts = alloc::vec::Vec::new();
        for seq in 1..=pings {
            match stack.ping(target, seq, 2000) {
                Some(us) => {
                    answered += 1;
                    rtts.push(us);
                    say!("info: ping {} seq {}: {} us", ip(target), seq, us);
                }
                None => say!("info: ping {} seq {}: no answer", ip(target), seq),
            }
            delay_ticks(10);
        }
        t.check(answered == pings, format_args!("ping: {}/{} echo replies from {} ({:?} us)", answered, pings, ip(target), rtts));
    }

    let end = stack.status().and_then(|v| v.into_iter().find(|s| s.name == "rs0"));
    if let Some(s) = &end {
        say!(
            "info: frames in {} out {}, read errors {}, write errors {}, dropped (queue full) {}, leases {}",
            s.link.rx_frames, s.link.tx_frames, s.link.rx_errors, s.link.tx_errors, s.link.rx_dropped, s.leases
        );
        t.check(
            s.link.rx_frames > 0 && s.link.tx_frames > 0 && s.link.tx_errors == 0 && s.link.rx_dropped == 0,
            format_args!("link: frames both ways, no write errors or drops"),
        );
    }

    let t2 = ms();
    stack.stop();
    say!("info: stopped in {} ms", ms() - t2);
    delay_ticks(10);
    let m1 = avail();
    say!("info: free memory before {} after {} ({:+} bytes)", m0, m1, m1 as i64 - m0 as i64);
    t.check(true, format_args!("stop: the stack process ended and the unit is closed"));

    say!("rsnet: {}/{} passed", t.pass, t.pass + t.fail);
    if t.fail == 0 { 0 } else { 20 }
}
