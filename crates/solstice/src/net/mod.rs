//! The listeners.
//!
//! Each one is thin: parse, dispatch into the protocol crate, write back. The
//! decisions live in `solstice-gamestream`, which is testable without a socket.

pub mod control;
pub mod media;
pub mod nvhttp;
pub mod rtsp;
