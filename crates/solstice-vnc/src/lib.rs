//! The RFB (VNC) backend.
//!
//! Solstice is a **client** here: it dials an existing VNC server, pulls
//! framebuffer updates, and injects input. Three structural facts drive the
//! design (`docs/rfb-vnc-protocol.md` §8):
//!
//! 1. **There is no video stream to forward.** RFB produces dirty rectangles in
//!    a pixel format of its choosing; this crate composites them into a BGRA
//!    framebuffer and the video crate encodes that.
//! 2. **There is no frame clock.** A static screen produces no traffic at all,
//!    so the clock is synthesised upstream.
//! 3. **Input maps cleanly**, with one wrinkle: RFB has no press/release for
//!    the pointer, only a button mask, so the mask is state this crate keeps.
//!
//! Written directly rather than wrapped around `vnc-rs`, because a bridge needs
//! control over the update loop, zero-copy access to the framebuffer, and the
//! `ContinuousUpdates`/`Fence` pseudo-encodings -- the three things client
//! crates tend to hide (`PROJECT-LAYOUT.md` §2).

#![forbid(unsafe_code)]

pub mod auth;
pub mod backend;
pub mod cursor;
pub mod encodings;
pub mod handshake;
pub mod input;
pub mod pixel;
pub mod protocol;
pub mod session;

pub mod mock;

pub use auth::VncSecurity;
pub use backend::{connect, VncBackend, VncConfig};
pub use protocol::RfbError;
