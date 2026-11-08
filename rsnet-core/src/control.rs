//! Roadshow's "TCP/IP Control" public port, which NetShutdown looks for: a
//! MsgPort with the LONG 0x20040306 right after it (offset 34), taking
//! 40-byte messages whose LONG at offset 20 is the command (learnt from
//! NetShutdown 4.11's code):
//! - 1: shut the network down, as Roadshow does even while programs keep
//!   the library open (with Roadshow a server program's connection went at
//!   once): the stack takes every interface but lo0 away (their
//!   connections reset), clears the routes and name servers, and replies;
//!   NetShutdown then expunges bsdsocket.library (done at its last Close).
//!   The message's LONG at 24 points to a result LONG of the size at 28,
//!   set to 0.
//! - 2: stop waiting: the command-1 message it points to (LONG at 24) is
//!   replied at once, and so is this one.
//! The port lives in the stack process, from its start to its end.

use alloc::vec::Vec;

use amigaos4::sys::{self, Message, MsgPort, TagItem, TAG_DONE};

/// The magic NetShutdown checks after the MsgPort.
const MAGIC: u32 = 0x2004_0306;
/// sizeof(struct MsgPort) on AmigaOS 4.
const MSGPORT_SIZE: usize = 34;

pub struct Control {
    port: *mut MsgPort,
    /// Command-1 messages waiting for the stack to stop.
    pending: Vec<usize>,
}

impl Control {
    /// The public port, or None (the stack runs without it).
    pub fn new() -> Option<Self> {
        let tags = [
            TagItem { ti_Tag: sys::ASOPORT_SIZE, ti_Data: (MSGPORT_SIZE + 4) as u32 },
            TagItem { ti_Tag: sys::ASOPORT_NAME, ti_Data: b"TCP/IP Control\0".as_ptr() as u32 },
            TagItem { ti_Tag: sys::ASOPORT_COPYNAME, ti_Data: 1 },
            TagItem { ti_Tag: sys::ASOPORT_PUBLIC, ti_Data: 1 },
            TagItem { ti_Tag: TAG_DONE, ti_Data: 0 },
        ];
        // SAFETY: a TAG_DONE-ended list; the name is copied.
        let port = unsafe { sys::exec_alloc_sys_object(sys::ASOT_PORT, tags.as_ptr()) } as *mut MsgPort;
        if port.is_null() {
            return None;
        }
        // SAFETY: the port block is MSGPORT_SIZE + 4 bytes (ASOPORT_Size).
        unsafe { core::ptr::write_unaligned((port as *mut u8).add(MSGPORT_SIZE) as *mut u32, MAGIC) };
        Some(Control { port, pending: Vec::new() })
    }

    pub fn signal_mask(&self) -> u32 {
        // SAFETY: mp_SigBit (offset 15) of our port.
        let bit = unsafe { *(self.port as *const u8).add(15) };
        1u32 << bit
    }

    /// Take the messages that arrived: true when a shutdown was asked for
    /// (the stack does it, then calls [`finish`](Self::finish)).
    pub fn poll(&mut self) -> bool {
        let before = self.pending.len();
        self.take();
        self.pending.len() > before
    }

    /// Answer every shutdown request (result 0).
    pub fn finish(&mut self) {
        for m in core::mem::take(&mut self.pending) {
            // SAFETY: a command-1 message: its result LONG (pointer at 24,
            // size at 28) gets 0, then it goes back.
            unsafe {
                let r = core::ptr::read_unaligned((m + 24) as *const u32) as *mut u32;
                let size = core::ptr::read_unaligned((m + 28) as *const u32);
                if !r.is_null() && size == 4 {
                    core::ptr::write_unaligned(r, 0);
                }
                sys::exec_reply_msg(m as *mut Message);
            }
        }
    }

    fn take(&mut self) {
        loop {
            // SAFETY: our port.
            let m = unsafe { sys::exec_get_msg(self.port) } as usize;
            if m == 0 {
                return;
            }
            // SAFETY: a message for this port: at least the 40 bytes
            // NetShutdown sends (the command LONG at 20, a pointer at 24).
            let (cmd, arg) = unsafe { (core::ptr::read_unaligned((m + 20) as *const u32), core::ptr::read_unaligned((m + 24) as *const u32) as usize) };
            match cmd {
                1 => self.pending.push(m),
                2 => {
                    if let Some(k) = self.pending.iter().position(|&p| p == arg) {
                        let p = self.pending.swap_remove(k);
                        // SAFETY: the pending command-1 message.
                        unsafe { sys::exec_reply_msg(p as *mut Message) };
                    }
                    // SAFETY: the message just taken.
                    unsafe { sys::exec_reply_msg(m as *mut Message) };
                }
                // SAFETY: as above.
                _ => unsafe { sys::exec_reply_msg(m as *mut Message) },
            }
        }
    }
}

impl Drop for Control {
    /// The stack stops: every shutdown request is answered, the port goes.
    fn drop(&mut self) {
        self.take();
        self.finish();
        // SAFETY: our port, empty; FreeSysObject removes it from the public
        // list.
        unsafe { sys::exec_free_sys_object(sys::ASOT_PORT, self.port as _) };
    }
}
