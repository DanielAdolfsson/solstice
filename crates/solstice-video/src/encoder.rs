//! The encoder seam.

use solstice_backend::Rect;

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
    #[error("no such encoder in this build: build with --features x264 or openh264")]
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

/// What changed in a frame since the previous one given to the encoder.
///
/// An encoder may trust this and code everything outside the damage as
/// unchanged, so it must be a superset of what changed. The pipeline's comes
/// from the rectangles it converted, which is exactly what changed in the
/// frame; when it cannot say, it says [`FrameDamage::Unknown`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameDamage {
    /// No claim.
    Unknown,
    /// Nothing changed: a repeat of the previous frame.
    Nothing,
    /// Nothing changed outside this rectangle.
    Within(Rect),
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

    /// Encode one frame, told what changed since the last. An encoder that can
    /// skip what did not change does so; the default ignores `damage`.
    fn encode_with_damage(
        &mut self,
        frame: &I420Frame,
        force_idr: bool,
        damage: FrameDamage,
    ) -> Result<EncodedFrame, VideoError> {
        let _ = damage;
        self.encode(frame, force_idr)
    }

    /// The geometry this encoder was built for.
    fn dimensions(&self) -> (u32, u32);
}

/// Whether an Annex-B access unit contains an IDR NAL (type 5).
///
/// The frame type goes in `video_short_frame_header_t.frameType`, and the
/// client uses it to decide whether it can start decoding, so it is read out of
/// the bitstream rather than inferred from what was requested.
pub fn contains_idr(annex_b: &[u8]) -> bool {
    nal_types(annex_b).any(|t| t == 5)
}

/// The NAL unit types present in an Annex-B buffer.
pub fn nal_types(annex_b: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut positions = Vec::new();
    let mut i = 0;
    while i + 3 <= annex_b.len() {
        if annex_b[i] == 0 && annex_b[i + 1] == 0 {
            if annex_b[i + 2] == 1 {
                positions.push(i + 3);
                i += 3;
                continue;
            }
            if i + 4 <= annex_b.len() && annex_b[i + 2] == 0 && annex_b[i + 3] == 1 {
                positions.push(i + 4);
                i += 4;
                continue;
            }
        }
        i += 1;
    }
    positions
        .into_iter()
        .filter_map(move |p| annex_b.get(p).map(|b| b & 0x1F))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nal_type_scanning_handles_both_start_code_lengths() {
        let buf = [0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 9, 0, 0, 0, 1, 0x65];
        assert_eq!(nal_types(&buf).collect::<Vec<_>>(), vec![7, 8, 5]);
        assert!(contains_idr(&buf));
        assert!(!contains_idr(&[0, 0, 0, 1, 0x41]));
    }
}
