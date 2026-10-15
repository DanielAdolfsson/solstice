//! The encoder seam.

use crate::frame::I420Frame;

/// What went wrong in the encode path.
#[derive(Debug, thiserror::Error)]
pub enum VideoError {
    /// The encoder could not be created with the requested settings.
    #[error("encoder setup failed: {0}")]
    Setup(String),
    /// The encoder rejected a frame.
    #[error("encode failed: {0}")]
    Encode(String),
    /// A frame did not match the geometry the encoder was built for.
    #[error("frame is {got_w}x{got_h}, encoder expects {want_w}x{want_h}")]
    WrongGeometry {
        /// Frame width.
        got_w: usize,
        /// Frame height.
        got_h: usize,
        /// Configured width.
        want_w: usize,
        /// Configured height.
        want_h: usize,
    },
    /// The build has no encoder compiled in.
    #[error("no encoder available: build with --features openh264")]
    NoEncoder,
}

/// Settings taken from the client's ANNOUNCE.
#[derive(Clone, Copy, Debug)]
pub struct EncoderConfig {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Target framerate, which the rate control uses as its denominator.
    pub fps: u32,
    /// Target bitrate.
    pub bitrate_kbps: u32,
    /// Slices per frame, from `x-nv-video[0].videoEncoderSlicesPerFrame`.
    pub slices_per_frame: u32,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_kbps: 10_000,
            slices_per_frame: 1,
        }
    }
}

/// One encoded access unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedFrame {
    /// Annex-B bytes, start codes included.
    pub data: Vec<u8>,
    /// Whether this is an IDR.
    pub is_idr: bool,
}

/// An H.264 encoder.
///
/// The settings that matter for this workload are all about latency: no
/// B-frames, no lookahead, no reordering, and -- the one the control stream
/// depends on -- a keyframe on demand. The client asks for one with message
/// `0x0302` and will sit on a black screen until it arrives, so `force_idr`
/// must take effect on the *next* frame and not at the next GOP boundary.
pub trait VideoEncoder: Send {
    /// A name for logs.
    fn name(&self) -> &'static str;

    /// Encode one frame.
    fn encode(&mut self, frame: &I420Frame, force_idr: bool) -> Result<EncodedFrame, VideoError>;

    /// The geometry this encoder was built for.
    fn dimensions(&self) -> (u32, u32);
}
