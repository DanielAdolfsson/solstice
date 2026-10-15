//! The seam between the GameStream host half and whatever remote desktop is
//! behind it.
//!
//! Traits and neutral types only -- no I/O, no protocol. Both backends and the
//! video pipeline depend on this crate; nothing depends on both backends
//! (`PROJECT-LAYOUT.md` §3).

#![forbid(unsafe_code)]

pub mod audio;
pub mod backend;
pub mod damage;
pub mod framebuffer;
pub mod input;

pub use audio::{AudioFormat, AudioFrame};
pub use backend::{Backend, BackendError, Result, Session};
pub use damage::BackendEvent;
pub use framebuffer::{Framebuffer, FramebufferHandle, PixelFormat, Rect};
pub use input::{InputEvent, KeyEvent, MouseButton};
