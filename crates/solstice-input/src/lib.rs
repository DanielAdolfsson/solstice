//! Keyboard translation tables for the GameStream -> RFB/SPICE bridge.
//!
//! Moonlight sends Windows virtual-key codes normalised to a **US English
//! layout**, plus a `MODIFIER_EXTENDED` bit that means "this key carries the
//! 0xE0 scancode prefix" (`Limelight.h:698-701`). That is already the XT
//! scancode distinction, so the primary path is
//!
//! ```text
//! VK + EXTENDED -> XT make scancode -> RFB QEMU Extended Key Event / SPICE key down
//! ```
//!
//! The keysym table is the fallback for RFB servers that do not implement
//! pseudo-encoding -258 (libvncserver and everything built on it). It is lossy:
//! it commits to the US reading of the key. See `docs/bridging-design.md` §4.1.
//!
//! This crate is pure data and has no dependencies.

#![forbid(unsafe_code)]

pub mod keysym;
pub mod scancode;
pub mod vk;

pub use keysym::keysym;
pub use scancode::scancode;
