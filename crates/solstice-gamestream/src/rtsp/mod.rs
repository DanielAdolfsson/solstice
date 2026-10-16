//! RTSP on TCP 48010: the session negotiation.
//!
//! ```text
//! OPTIONS   rtsp://<host>:48010
//! DESCRIBE  rtsp://<host>:48010        -> SDP advertising codecs
//! SETUP     streamid=audio/0/0         -> Transport: ...;server_port=48000
//! SETUP     streamid=video/0/0         -> Transport: ...;server_port=47998
//! SETUP     streamid=control/13/0      -> Transport: ...;server_port=47999
//! ANNOUNCE  streamid=control/13/0      <- the client's full configuration
//! PLAY      rtsp://<host>:48010
//! ```

pub mod encrypted;
pub mod message;
pub mod sdp;

mod server;

pub use server::{RtspOutcome, RtspServer, SessionParams, StreamPorts};
