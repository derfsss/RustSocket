//! `rstcp sigs [library]`: what a stack does with the break signal that
//! ends a blocking call (run on Roadshow and on rustsocket to compare): a
//! UDP recv with no datagram coming, interrupted by a signal of the break
//! mask sent before the call; is the signal still set afterwards, and is
//! the next recv interrupted at once again?

use core::ffi::c_void;

use amigaos4::bsdsocket::SocketLib;
use amigaos4::sys::{self, SocketIFace, TagItem, TAG_DONE, TAG_USER};

use super::{Out, Tally};
use core::fmt::Write;

pub fn run(lib: &SocketLib, t: &mut Tally) {
    let i: *mut SocketIFace = lib.iface();
    // SAFETY: plain calls; this task's own signals.
    unsafe {
        let sig = sys::exec_alloc_signal(-1);
        if sig < 0 {
            t.check(false, format_args!("sigs: no signal"));
            return;
        }
        let m = 1u32 << sig;
        let mut tags = [TagItem { ti_Tag: TAG_USER | (1 << 1) | 1, ti_Data: sys::SIGBREAKF_CTRL_C | m }, TagItem { ti_Tag: TAG_DONE, ti_Data: 0 }];
        ((*i).SocketBaseTagList)(i, tags.as_mut_ptr());
        let s = ((*i).socket)(i, 2, 2, 0);
        let mut sa = [0u8; 16];
        sa[0] = 16;
        sa[1] = 2;
        ((*i).bind)(i, s, sa.as_mut_ptr() as *mut c_void, 16);
        let mut buf = [0u8; 64];
        sys::exec_set_signal(0, m);
        sys::exec_signal(sys::exec_find_task(core::ptr::null_mut()), m);
        let t0 = super::us();
        let r1 = ((*i).recv)(i, s, buf.as_mut_ptr() as *mut c_void, 64, 0);
        let e1 = ((*i).Errno)(i);
        let still = sys::exec_set_signal(0, 0) & m != 0;
        let t1 = super::us();
        // A second recv: with the signal still set, is it interrupted at
        // once? (Bounded: Ctrl-C ends it otherwise, and a timeout.)
        let tv: [u32; 2] = [1, 0];
        ((*i).setsockopt)(i, s, 0xffff, 0x1006, tv.as_ptr() as *mut c_void, 8);
        let r2 = ((*i).recv)(i, s, buf.as_mut_ptr() as *mut c_void, 64, 0);
        let e2 = ((*i).Errno)(i);
        let ms2 = (super::us() - t1) / 1000;
        let still2 = sys::exec_set_signal(0, 0) & m != 0;
        say!(
            "sigs: first recv {} errno {} in {} ms; the signal still set after it: {}; second recv {} errno {} in {} ms; still set: {}",
            r1, e1, (t1 - t0) / 1000, still, r2, e2, ms2, still2
        );
        t.check(r1 == -1 && e1 == 4, format_args!("sigs: a break signal sent before a blocking recv interrupts it"));
        sys::exec_set_signal(0, m);
        ((*i).CloseSocket)(i, s);
        let mut back = [TagItem { ti_Tag: TAG_USER | (1 << 1) | 1, ti_Data: sys::SIGBREAKF_CTRL_C }, TagItem { ti_Tag: TAG_DONE, ti_Data: 0 }];
        ((*i).SocketBaseTagList)(i, back.as_mut_ptr());
        sys::exec_free_signal(sig);
    }
}
