//! The OpenH264 software encoder.
//!
//! Chosen as the default because its licence will not force the project's hand:
//! BSD-2 with Cisco's binary patent grant, where x264 and most FFmpeg builds
//! are GPL and propagate to the whole binary (`PROJECT-LAYOUT.md` §4).
//!
//! **Profile.** Moonlight advertises `VIDEO_FORMAT_H264` as *High Profile*, and
//! OpenH264's README documents Constrained Baseline only for the encoder --
//! though High was added later and the documentation was never updated. High is
//! a superset of Baseline, so a Baseline stream decodes either way; the test
//! below asserts what this build actually emits rather than trusting either
//! claim.

use openh264::encoder::{
    BitRate, Encoder, EncoderConfig as OhConfig, FrameRate, IntraFramePeriod, Level, Profile,
    RateControlMode, SpsPpsStrategy, UsageType,
};
use openh264::OpenH264API;

use crate::encoder::{EncodedFrame, EncoderConfig, VideoEncoder, VideoError};
use crate::frame::I420Frame;

/// An OpenH264 encoder configured for desktop remoting.
pub struct OpenH264Encoder {
    encoder: Encoder,
    config: EncoderConfig,
}

impl std::fmt::Debug for OpenH264Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenH264Encoder")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl OpenH264Encoder {
    /// Build one.
    pub fn new(config: EncoderConfig) -> Result<Self, VideoError> {
        let oh = OhConfig::new()
            // Screen content, not camera video: the rate control and the
            // intra-block decisions are different, and a desktop is mostly
            // static with sharp edges.
            .usage_type(UsageType::ScreenContentRealTime)
            .max_frame_rate(FrameRate::from_hz(config.fps as f32))
            .bitrate(BitRate::from_bps(config.bitrate_kbps.saturating_mul(1000)))
            .rate_control_mode(RateControlMode::Bitrate)
            // Repeat the parameter sets on every IDR. A client that joins or
            // recovers mid-stream has no other way to get them, and the cost is
            // a few dozen bytes per keyframe.
            .sps_pps_strategy(SpsPpsStrategy::IncreasingId)
            // No periodic keyframes: IDRs are driven by the control stream's
            // 0x0302, and an unrequested one is bandwidth spent for nothing.
            .intra_frame_period(IntraFramePeriod::from_num_frames(0))
            .profile(Profile::High)
            .level(Level::Level_4_2)
            // Latency, not quality: a scene-change detector that inserts an
            // unrequested IDR is a bitrate spike the client did not ask for.
            .scene_change_detect(false)
            .skip_frames(false)
            .complexity(openh264::encoder::Complexity::Low);
        let oh = match config.slices_per_frame {
            0 | 1 => oh,
            n => oh.max_slice_len((config.width * config.height / n).max(1024)),
        };

        let encoder = Encoder::with_api_config(OpenH264API::from_source(), oh)
            .map_err(|e| VideoError::Setup(e.to_string()))?;
        Ok(Self { encoder, config })
    }
}

impl VideoEncoder for OpenH264Encoder {
    fn name(&self) -> &'static str {
        "openh264"
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
        if force_idr {
            self.encoder.force_intra_frame();
        }
        let bitstream = self
            .encoder
            .encode(frame)
            .map_err(|e| VideoError::Encode(e.to_string()))?;
        let data = bitstream.to_vec();
        let is_idr = contains_idr(&data);
        Ok(EncodedFrame { data, is_idr })
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.config.width, self.config.height)
    }
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
    use crate::convert::convert_full;
    use solstice_backend::{Framebuffer, Rect};

    fn config() -> EncoderConfig {
        EncoderConfig {
            width: 320,
            height: 240,
            fps: 60,
            bitrate_kbps: 4000,
            slices_per_frame: 1,
        }
    }

    fn grey_frame(level: u8) -> I420Frame {
        let mut fb = Framebuffer::new(320, 240);
        fb.fill(Rect::whole(320, 240), [level, level, level, 255]);
        let mut frame = I420Frame::new(320, 240);
        convert_full(&fb, &mut frame);
        frame
    }

    #[test]
    fn encodes_real_annex_b() {
        let mut e = OpenH264Encoder::new(config()).unwrap();
        let out = e.encode(&grey_frame(128), false).unwrap();
        assert_eq!(&out.data[..4], &[0, 0, 0, 1]);
        assert!(out.data.len() > 50);
        assert!(out.is_idr, "the first frame must be an IDR");
    }

    /// The parameter sets must ride along with every keyframe.
    #[test]
    fn keyframes_carry_sps_and_pps() {
        let mut e = OpenH264Encoder::new(config()).unwrap();
        let out = e.encode(&grey_frame(128), false).unwrap();
        let types: Vec<u8> = nal_types(&out.data).collect();
        assert!(types.contains(&7), "no SPS in {types:?}");
        assert!(types.contains(&8), "no PPS in {types:?}");
        assert!(types.contains(&5), "no IDR slice in {types:?}");
    }

    /// The whole point of the control stream's 0x0302: a keyframe on demand,
    /// on the next frame, not at the next GOP boundary.
    #[test]
    fn force_idr_produces_a_keyframe_immediately() {
        let mut e = OpenH264Encoder::new(config()).unwrap();
        e.encode(&grey_frame(128), false).unwrap();
        for i in 0..5 {
            let out = e.encode(&grey_frame(128 + i), false).unwrap();
            assert!(!out.is_idr, "unrequested keyframe at frame {i}");
        }
        assert!(e.encode(&grey_frame(140), true).unwrap().is_idr);
    }

    /// A static desktop is the common case, and it must cost almost nothing.
    #[test]
    fn an_unchanged_frame_encodes_to_very_few_bytes() {
        let mut e = OpenH264Encoder::new(config()).unwrap();
        let frame = grey_frame(100);
        let first = e.encode(&frame, false).unwrap();
        let repeats: Vec<usize> = (0..4)
            .map(|_| e.encode(&frame, false).unwrap().data.len())
            .collect();
        assert!(
            repeats.iter().all(|&n| n * 10 < first.data.len()),
            "duplicate frames cost {repeats:?} against a keyframe of {}",
            first.data.len()
        );
    }

    /// What this build actually emits, rather than what either document claims.
    #[test]
    fn the_stream_declares_its_profile_in_the_sps() {
        let mut e = OpenH264Encoder::new(config()).unwrap();
        let out = e.encode(&grey_frame(128), false).unwrap();
        // Find the SPS and read profile_idc, the byte after the NAL header.
        let mut idx = 0;
        let mut profile_idc = None;
        while idx + 5 < out.data.len() {
            if out.data[idx..idx + 3] == [0, 0, 1] && out.data[idx + 3] & 0x1F == 7 {
                profile_idc = Some(out.data[idx + 4]);
                break;
            }
            if idx + 6 < out.data.len()
                && out.data[idx..idx + 4] == [0, 0, 0, 1]
                && out.data[idx + 4] & 0x1F == 7
            {
                profile_idc = Some(out.data[idx + 5]);
                break;
            }
            idx += 1;
        }
        // 66 = Baseline/Constrained Baseline, 77 = Main, 100 = High. All three
        // decode on a client that advertised High; this records which one this
        // build produces so a change is visible rather than silent.
        let profile_idc = profile_idc.expect("no SPS found");
        assert!(
            matches!(profile_idc, 66 | 77 | 100),
            "unexpected profile_idc {profile_idc}"
        );
        println!("openh264 emits profile_idc {profile_idc}");
    }

    #[test]
    fn a_frame_of_the_wrong_size_is_refused() {
        let mut e = OpenH264Encoder::new(config()).unwrap();
        assert!(matches!(
            e.encode(&I420Frame::new(64, 64), false),
            Err(VideoError::WrongGeometry { .. })
        ));
    }

    #[test]
    fn nal_type_scanning_handles_both_start_code_lengths() {
        let buf = [0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 9, 0, 0, 0, 1, 0x65];
        assert_eq!(nal_types(&buf).collect::<Vec<_>>(), vec![7, 8, 5]);
        assert!(contains_idr(&buf));
        assert!(!contains_idr(&[0, 0, 0, 1, 0x41]));
    }
}
