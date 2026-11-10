//! rsnet-core's modules that need no device, built for the host so that
//! `cargo test` here runs their tests.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

#[path = "../../src/s2xlogic.rs"]
pub mod s2xlogic;
