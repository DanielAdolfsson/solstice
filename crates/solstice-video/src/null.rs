//! An encoder that encodes nothing, for testing the plumbing.
//!
//! Everything downstream of the encoder -- packetisation, FEC, encryption,
//! pacing -- is byte plumbing that does not care whether its input is really
//! H.264. Testing it against a deterministic fake keeps those tests fast,
//! reproducible and free of a C dependency, and it makes a failure
//! unambiguous: if the null encoder's output does not survive the round trip,
//! the bug is in the plumbing and not in the codec.

use crate::encoder::{EncodedFrame, EncoderConfig, VideoEncoder, VideoError};
use crate::frame::I420Frame;

/// A deterministic non-encoder.
#[derive(Debug)]
pub struct NullEncoder {
    config: EncoderConfig,
    frame_counter: u32,
    idr_interval: u32,
    bytes_per_frame: usize,
}

impl NullEncoder {
    /// Build one that emits `bytes_per_frame` bytes per call.
    pub fn new(config: EncoderConfig, bytes_per_frame: usize) -> Self {
        Self {
            config,
            frame_counter: 0,
            idr_interval: 60,
            bytes_per_frame,
        }
    }
}

impl VideoEncoder for NullEncoder {
    fn name(&self) -> &'static str {
        "null"
    }

    fn encode(&mut self, frame: &I420Frame, force_idr: bool) -> Result<EncodedFrame, VideoError> {
        if frame.width() != self.config.width as usize
            || frame.height() != self.config.height as usize
        {
            return Err(VideoError::WrongGeometry {
                got_w: frame.width(),
                got_h: frame.height(),
                want_w: self.config.width as usize,
                want_h: self.config.height as usize,
            });
        }
        let n = self.frame_counter;
        self.frame_counter = self.frame_counter.wrapping_add(1);
        let is_idr = force_idr || n % self.idr_interval == 0;

        // An Annex-B-shaped payload: start code, a NAL header with the right
        // type, then deterministic filler derived from the frame counter.
        let mut data = vec![0x00, 0x00, 0x00, 0x01];
        data.push(if is_idr { 0x65 } else { 0x41 });
        data.extend((0..self.bytes_per_frame).map(|i| (n as usize + i) as u8));
        Ok(EncodedFrame { data, is_idr })
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.config.width, self.config.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoder() -> NullEncoder {
        NullEncoder::new(
            EncoderConfig {
                width: 64,
                height: 64,
                ..Default::default()
            },
            32,
        )
    }

    #[test]
    fn the_first_frame_is_an_idr() {
        let mut e = encoder();
        let frame = I420Frame::new(64, 64);
        assert!(e.encode(&frame, false).unwrap().is_idr);
        assert!(!e.encode(&frame, false).unwrap().is_idr);
    }

    #[test]
    fn force_idr_takes_effect_on_the_next_frame() {
        let mut e = encoder();
        let frame = I420Frame::new(64, 64);
        e.encode(&frame, false).unwrap();
        e.encode(&frame, false).unwrap();
        let forced = e.encode(&frame, true).unwrap();
        assert!(forced.is_idr);
        assert_eq!(forced.data[4], 0x65);
    }

    #[test]
    fn output_starts_with_an_annex_b_start_code() {
        let mut e = encoder();
        let out = e.encode(&I420Frame::new(64, 64), false).unwrap();
        assert_eq!(&out.data[..4], &[0, 0, 0, 1]);
    }

    #[test]
    fn a_frame_of_the_wrong_size_is_refused() {
        let mut e = encoder();
        assert!(matches!(
            e.encode(&I420Frame::new(32, 32), false),
            Err(VideoError::WrongGeometry { .. })
        ));
    }
}
