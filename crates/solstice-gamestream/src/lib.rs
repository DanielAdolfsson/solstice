//! The GameStream host half.
//!
//! Moonlight is the *client*; Solstice is the host, so everything here is a
//! thing Solstice has to serve. See `docs/moonlight-sunshine-protocol.md`.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod input;
pub mod nvhttp;
pub mod rtsp;
pub mod stream;
pub mod wire;
