//! rsprobe: rustsocket.library's openers, errno and stack lifecycle:
//! the first Open starts the stack process, each opener gets its own
//! interface and errno, SetErrnoPtr and SocketBaseTagList work, and the
//! last Close stops the stack.
//!
//!   rsprobe [library path]   (default RAM:rsprobe/rustsocket.library)
//!
//! Needs no network interface: the first Open starts the stack with lo0
//! only. Run it where no interface has been added to this library, since
//! a stack with interfaces keeps running after the last Close. Prints
//! PASS/FAIL; rc 0 when all pass.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use core::fmt::{self, Write};
use core::panic::PanicInfo;

use amigaos4::allocator::SharedExecAllocator;
use amigaos4::sys::{self, Interface, TagItem};

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

struct Tally(u32, u32);
impl Tally {
    fn check(&mut self, ok: bool, what: fmt::Arguments) {
        if ok { self.0 += 1 } else { self.1 += 1 }
        say!("{} {}", if ok { "PASS" } else { "FAIL" }, what);
    }
}

/// Vector `n` of a SocketIFace (InterfaceData is 60 bytes).
fn vec(i: *mut Interface, n: usize) -> usize {
    // SAFETY: a live interface with at least n+1 vectors.
    unsafe { core::ptr::read((i as *const u8).add(60 + 4 * n) as *const usize) }
}

fn socket(i: *mut Interface, d: i32, t: i32, p: i32) -> i32 {
    // SAFETY: slot 4, socket(Self, domain, type, protocol) -> LONG.
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Interface, i32, i32, i32) -> i32>(vec(i, 4))(i, d, t, p) }
}
fn errno(i: *mut Interface) -> i32 {
    // SAFETY: slot 26, Errno(Self) -> LONG.
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Interface) -> i32>(vec(i, 26))(i) }
}
fn set_errno_ptr(i: *mut Interface, p: *mut i32, size: i32) {
    // SAFETY: slot 27, SetErrnoPtr(Self, APTR, LONG).
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Interface, *mut i32, i32)>(vec(i, 27))(i, p, size) }
}
fn base_tags(i: *mut Interface, tags: &mut [TagItem]) -> i32 {
    // SAFETY: slot 49, SocketBaseTagList(Self, struct TagItem *) -> LONG.
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut Interface, *mut TagItem) -> i32>(vec(i, 49))(i, tags.as_mut_ptr()) }
}

const fn sbtm(code: u32, set: bool, by_ref: bool) -> u32 {
    sys::TAG_USER | if by_ref { 0x8000 } else { 0 } | (code << 1) | set as u32
}

fn stack_running() -> bool {
    // SAFETY: FindTask by a NUL-terminated name only reads the lists.
    !unsafe { sys::exec_find_task(b"rsnet stack\0".as_ptr() as _) }.is_null()
}

#[no_mangle]
pub extern "C" fn rust_main(args: *const u8, arglen: i32) -> i32 {
    // SAFETY: the Shell's argument string, `arglen` bytes.
    let text = unsafe { core::slice::from_raw_parts(args, arglen.max(0) as usize) };
    let path = core::str::from_utf8(text).unwrap_or("").split_whitespace().next().unwrap_or("RAM:rsprobe/rustsocket.library");
    let mut p = String::from(path);
    p.push('\0');
    let mut t = Tally(0, 0);

    // SAFETY: a NUL-terminated name.
    let base = unsafe { sys::exec_open_library(p.as_ptr(), 1) };
    if base.is_null() {
        t.check(false, format_args!("{} did not open (no stack unit?)", path));
        return 20;
    }
    t.check(stack_running(), format_args!("open: the stack process runs"));
    // SAFETY: an open library, a NUL-terminated name.
    let (a, b) = unsafe { (sys::exec_get_interface(base, b"main\0".as_ptr(), 1, core::ptr::null()), sys::exec_get_interface(base, b"main\0".as_ptr(), 1, core::ptr::null())) };
    t.check(!a.is_null() && !b.is_null() && a != b, format_args!("two openers get two interfaces"));
    if a.is_null() || b.is_null() {
        return 20;
    }

    t.check(errno(a) == 0, format_args!("errno starts at 0"));
    let r = socket(a, 99, 1, 0);
    t.check(r == -1 && errno(a) == 47, format_args!("socket of an unknown family gives -1, errno {} (EAFNOSUPPORT 47)", errno(a)));
    t.check(errno(b) == 0, format_args!("the other opener's errno is untouched ({})", errno(b)));

    let mut mine: i32 = 0;
    set_errno_ptr(a, &mut mine, 4);
    let _ = socket(a, 99, 1, 0);
    t.check(mine == 47, format_args!("SetErrnoPtr: errno written to the program's variable too ({})", mine));

    let mut got: u32 = 0;
    let mut dt: u32 = 0;
    let mut tags = [
        TagItem { ti_Tag: sbtm(6, false, true), ti_Data: &mut got as *mut u32 as u32 },
        TagItem { ti_Tag: sbtm(8, false, true), ti_Data: &mut dt as *mut u32 as u32 },
        TagItem { ti_Tag: sbtm(6, true, false), ti_Data: 0 },
        TagItem { ti_Tag: sys::TAG_DONE, ti_Data: 0 },
    ];
    let r = base_tags(a, &mut tags);
    t.check(r == 0 && got == 47 && dt == 64 && errno(a) == 0 && mine == 0, format_args!("SocketBaseTagList: errno read ({}), table size ({}), errno set to 0 (now {}, the variable {})", got, dt, errno(a), mine));
    let mut bad = [TagItem { ti_Tag: sbtm(6, false, true), ti_Data: &mut got as *mut u32 as u32 }, TagItem { ti_Tag: sbtm(999, false, false), ti_Data: 0 }, TagItem { ti_Tag: sys::TAG_DONE, ti_Data: 0 }];
    let r = base_tags(a, &mut bad);
    t.check(r == 2, format_args!("SocketBaseTagList: an unknown code gives its tag's number ({})", r));

    // SAFETY: what this task got, given back, then the library closed.
    unsafe {
        sys::exec_drop_interface(a);
        sys::exec_drop_interface(b);
        sys::exec_close_library(base);
    }
    t.check(!stack_running(), format_args!("close: the stack process is gone"));
    say!("rsprobe: {}/{} passed", t.0, t.0 + t.1);
    if t.1 == 0 { 0 } else { 20 }
}
