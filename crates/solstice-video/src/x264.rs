//! The libx264 software encoder, the default.
//!
//! Chosen over OpenH264 on measurement (`docs/roadmap.md` §6). At 1080p on one
//! core its `ultrafast` preset encodes a changed frame in 3–4 ms against
//! OpenH264's 5–8, a keyframe in about 10 ms against 24, and its rate control
//! spends the bitrate the client asks for: a desktop settles near-lossless
//! within a 20 Mbit/s budget, where OpenH264 stays near 38 dB whatever it is
//! given. OpenH264 does code a desktop in fewer bits at equal quality; on a
//! link short of bandwidth that would matter, and it stays available as the
//! `openh264` feature.
//!
//! The FFI lives in `solstice-x264`, which owns the workspace's only `unsafe`.
//! This module is the policy: preset, threads, and the geometry check.

use solstice_x264::{Change, Encoder, Settings};

use crate::encoder::{
    contains_idr, EncodedFrame, EncoderConfig, FrameDamage, VideoEncoder, VideoError,
};
use crate::frame::I420Frame;

/// The fastest preset. It codes Constrained Baseline: no CABAC, no B-frames,
/// which every client that advertised High decodes. `veryfast` codes a desktop
/// in 20–30% fewer bits at equal quality for about twice the time per frame,
/// and bits are the cheaper of the two here.
const PRESET: &std::ffi::CStr = c"ultrafast";

/// Up to this many pixels one thread is enough: about 3.5 ms a frame at 1080p
/// with `ultrafast`, a fifth of a 60 fps frame time. Above it x264 chooses,
/// which with `zerolatency` means slice threads: less latency per frame for
/// more CPU in total.
const ONE_THREAD_UP_TO: u32 = 1920 * 1080;

/// An x264 encoder configured for desktop remoting.
pub struct X264Encoder {
    encoder: Encoder,
    config: EncoderConfig,
}

impl std::fmt::Debug for X264Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X264Encoder")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl X264Encoder {
    /// Build one.
    pub fn new(config: EncoderConfig) -> Result<Self, VideoError> {
        let threads = if config.width.saturating_mul(config.height) <= ONE_THREAD_UP_TO {
            1
        } else {
            0
        };
        let encoder = Encoder::new(&Settings {
            width: config.width,
            height: config.height,
            fps: config.fps,
            bitrate_kbps: config.bitrate_kbps,
            slices: config.slices_per_frame,
            threads,
            preset: PRESET,
        })
        .map_err(|e| VideoError::Setup(e.to_string()))?;
        Ok(Self { encoder, config })
    }
}

impl VideoEncoder for X264Encoder {
    fn name(&self) -> &'static str {
        "x264"
    }

    fn encode(&mut self, frame: &I420Frame, force_idr: bool) -> Result<EncodedFrame, VideoError> {
        self.encode_with_damage(frame, force_idr, FrameDamage::Unknown)
    }

    /// x264 skips the macroblocks `damage` says are unchanged instead of
    /// analysing them: at 1080p a still or typing frame in half the time, and
    /// a few bytes where it would re-polish a static screen
    /// (`docs/roadmap.md` §6).
    fn encode_with_damage(
        &mut self,
        frame: &I420Frame,
        force_idr: bool,
        damage: FrameDamage,
    ) -> Result<EncodedFrame, VideoError> {
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
        let out = self
            .encoder
            .encode(frame.y(), frame.u(), frame.v(), force_idr, change(damage))
            .map_err(|e| VideoError::Encode(e.to_string()))?;
        // Read out of the bitstream, as for OpenH264, rather than trusting the
        // flag: the client decides whether it can start decoding on this.
        let is_idr = contains_idr(&out.data);
        Ok(EncodedFrame {
            data: out.data,
            is_idr,
        })
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.config.width, self.config.height)
    }
}

fn change(damage: FrameDamage) -> Change {
    match damage {
        FrameDamage::Unknown => Change::Unknown,
        FrameDamage::Nothing => Change::Nothing,
        FrameDamage::Within(r) => Change::Within {
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::convert_full;
    use crate::encoder::nal_types;
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

    /// The payload of each NAL unit in an Annex-B buffer, header byte first.
    fn nal_payloads(annex_b: &[u8]) -> Vec<&[u8]> {
        let mut starts = Vec::new();
        let mut i = 0;
        while i + 3 <= annex_b.len() {
            if annex_b[i..i + 3] == [0, 0, 1] {
                starts.push(i + 3);
                i += 3;
            } else {
                i += 1;
            }
        }
        starts
            .iter()
            .enumerate()
            .map(|(n, &s)| {
                let end = starts.get(n + 1).map_or(annex_b.len(), |&next| next - 3);
                // A four-byte start code leaves its leading zero on the previous NAL.
                let end = if end > s && annex_b[end - 1] == 0 {
                    end - 1
                } else {
                    end
                };
                &annex_b[s..end]
            })
            .collect()
    }

    /// Exp-Golomb reading, enough of it for the head of an SPS.
    struct Bits {
        data: Vec<u8>,
        pos: usize,
    }

    impl Bits {
        fn new(nal: &[u8]) -> Self {
            // Strip emulation prevention bytes: 00 00 03 -> 00 00.
            let mut data = Vec::with_capacity(nal.len());
            let mut zeros = 0;
            for &b in nal {
                if zeros >= 2 && b == 3 {
                    zeros = 0;
                    continue;
                }
                zeros = if b == 0 { zeros + 1 } else { 0 };
                data.push(b);
            }
            Self { data, pos: 0 }
        }
        fn bit(&mut self) -> u32 {
            let b = (self.data[self.pos / 8] >> (7 - self.pos % 8)) & 1;
            self.pos += 1;
            u32::from(b)
        }
        fn bits(&mut self, n: u32) -> u32 {
            (0..n).fold(0, |v, _| (v << 1) | self.bit())
        }
        fn ue(&mut self) -> u32 {
            let mut zeros = 0;
            while self.bit() == 0 {
                zeros += 1;
            }
            (1 << zeros) - 1 + self.bits(zeros)
        }
    }

    /// `(profile_idc, pic_order_cnt_type)` from the first SPS in `annex_b`.
    fn sps_profile_and_poc_type(annex_b: &[u8]) -> (u32, u32) {
        let sps = nal_payloads(annex_b)
            .into_iter()
            .find(|n| n[0] & 0x1F == 7)
            .expect("no SPS");
        let mut r = Bits::new(&sps[1..]);
        let profile = r.bits(8);
        r.bits(16); // constraint flags, level_idc
        r.ue(); // seq_parameter_set_id
        if matches!(profile, 100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128) {
            if r.ue() == 3 {
                r.bit(); // separate_colour_plane_flag
            }
            r.ue(); // bit_depth_luma_minus8
            r.ue(); // bit_depth_chroma_minus8
            r.bit(); // qpprime_y_zero_transform_bypass_flag
            assert_eq!(r.bit(), 0, "scaling matrices are not expected here");
        }
        r.ue(); // log2_max_frame_num_minus4
        (profile, r.ue())
    }

    #[test]
    fn encodes_real_annex_b_starting_with_a_keyframe() {
        let mut e = X264Encoder::new(config()).unwrap();
        let out = e.encode(&grey_frame(128), false).unwrap();
        assert_eq!(&out.data[..4], &[0, 0, 0, 1]);
        assert!(out.is_idr, "the first frame must be an IDR");
    }

    /// The parameter sets must ride along with every keyframe, the requested
    /// ones included.
    #[test]
    fn keyframes_carry_sps_and_pps() {
        let mut e = X264Encoder::new(config()).unwrap();
        let first = e.encode(&grey_frame(128), false).unwrap();
        e.encode(&grey_frame(130), false).unwrap();
        let forced = e.encode(&grey_frame(132), true).unwrap();
        for out in [first, forced] {
            let types: Vec<u8> = nal_types(&out.data).collect();
            assert!(types.contains(&7), "no SPS in {types:?}");
            assert!(types.contains(&8), "no PPS in {types:?}");
            assert!(types.contains(&5), "no IDR slice in {types:?}");
        }
    }

    /// The control stream's 0x0302: a keyframe on the next frame, and none
    /// that nobody asked for.
    #[test]
    fn force_idr_produces_a_keyframe_immediately() {
        let mut e = X264Encoder::new(config()).unwrap();
        e.encode(&grey_frame(128), false).unwrap();
        for i in 0..30 {
            let out = e.encode(&grey_frame(128 + (i % 8)), false).unwrap();
            assert!(!out.is_idr, "unrequested keyframe at frame {i}");
        }
        assert!(e.encode(&grey_frame(140), true).unwrap().is_idr);
    }

    #[test]
    fn an_unchanged_frame_encodes_to_very_few_bytes() {
        let mut e = X264Encoder::new(config()).unwrap();
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

    /// Output order must be decode order, or a strict decoder holds frames
    /// back for reordering that never comes: up to a whole DPB of latency.
    /// `pic_order_cnt_type` 2 is the SPS saying so outright.
    #[test]
    fn the_stream_says_output_order_is_decode_order() {
        let mut e = X264Encoder::new(config()).unwrap();
        let out = e.encode(&grey_frame(128), false).unwrap();
        let (profile, poc_type) = sps_profile_and_poc_type(&out.data);
        assert!(matches!(profile, 66 | 77 | 100), "profile_idc {profile}");
        assert_eq!(poc_type, 2);
    }

    /// And a real decoder agrees: every access unit is a picture as soon as it
    /// arrives, with nothing buffered.
    #[test]
    fn every_access_unit_decodes_to_a_picture_immediately() {
        let mut e = X264Encoder::new(config()).unwrap();
        let mut decoder = ::openh264::decoder::Decoder::new().unwrap();
        for i in 0..30u8 {
            let out = e.encode(&grey_frame(60 + i * 4), i == 15).unwrap();
            let picture = decoder.decode(&out.data).unwrap();
            assert!(picture.is_some(), "frame {i} produced no picture");
        }
    }

    #[test]
    fn slices_per_frame_is_honoured() {
        let mut e = X264Encoder::new(EncoderConfig {
            slices_per_frame: 4,
            ..config()
        })
        .unwrap();
        for i in 0..3u8 {
            let out = e.encode(&grey_frame(100 + i * 20), false).unwrap();
            let slices = nal_types(&out.data).filter(|t| matches!(t, 1 | 5)).count();
            assert_eq!(slices, 4, "frame {i}");
        }
    }

    /// A 320x240 frame of fine detail, which is what makes skipping matter:
    /// flat grey costs x264 nothing to analyse anyway.
    fn detailed() -> Framebuffer {
        let mut fb = Framebuffer::new(320, 240);
        let mut seed = 0x9E37_79B9u32;
        for px in fb.data_mut().chunks_exact_mut(4) {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let v = (seed >> 24) as u8;
            px.copy_from_slice(&[v, v / 2 + 64, 255 - v, 255]);
        }
        fb
    }

    /// Luma PSNR of what the decoder made of `annex_b` against `source`.
    fn decoded_psnr(
        decoder: &mut ::openh264::decoder::Decoder,
        annex_b: &[u8],
        source: &I420Frame,
    ) -> f64 {
        use ::openh264::formats::YUVSource;
        let picture = decoder.decode(annex_b).unwrap().expect("no picture");
        let (stride, _, _) = picture.strides();
        let w = source.width();
        let se: f64 = (0..source.height())
            .flat_map(|y| (0..w).map(move |x| (x, y)))
            .map(|(x, y)| {
                let e = f64::from(picture.y()[y * stride + x]) - f64::from(source.y()[y * w + x]);
                e * e
            })
            .sum();
        let mse = se / (w * source.height()) as f64;
        if mse == 0.0 {
            99.0
        } else {
            10.0 * (255.0f64 * 255.0 / mse).log10()
        }
    }

    /// The decoder's luma plane for `annex_b`, tightly packed.
    fn decoded_luma(decoder: &mut ::openh264::decoder::Decoder, annex_b: &[u8]) -> Vec<u8> {
        use ::openh264::formats::YUVSource;
        let picture = decoder.decode(annex_b).unwrap().expect("no picture");
        let (stride, _, _) = picture.strides();
        let (w, h) = picture.dimensions();
        (0..h)
            .flat_map(|y| picture.y()[y * stride..y * stride + w].to_vec())
            .collect()
    }

    /// The mean of a 320-wide luma plane inside `r`.
    fn mean_in(luma: &[u8], r: Rect) -> f64 {
        let sum: u32 = (r.y..r.y + r.height)
            .flat_map(|y| (r.x..r.x + r.width).map(move |x| (x, y)))
            .map(|(x, y)| u32::from(luma[(y * 320 + x) as usize]))
            .sum();
        f64::from(sum) / f64::from(r.width * r.height)
    }

    /// Every change the damage covers reaches the picture, however little of
    /// the frame it is.
    #[test]
    fn damage_hints_lose_no_change() {
        let mut fb = detailed();
        let mut frame = I420Frame::new(320, 240);
        convert_full(&fb, &mut frame);
        let mut e = X264Encoder::new(config()).unwrap();
        let mut decoder = ::openh264::decoder::Decoder::new().unwrap();
        let first = e.encode(&frame, false).unwrap();
        decoder.decode(&first.data).unwrap();
        for i in 0..40u32 {
            let rect = Rect {
                x: (i * 23) % 300,
                y: (i * 37) % 228,
                width: 20,
                height: 12,
            };
            let v = (i * 61 % 200) as u8 + 40;
            fb.fill(rect, [v, v, v, 255]);
            crate::convert::convert_rect(&fb, rect, &mut frame);
            let out = e
                .encode_with_damage(&frame, false, FrameDamage::Within(rect))
                .unwrap();
            let psnr = decoded_psnr(&mut decoder, &out.data, &frame);
            // A missed rectangle is a 240-pixel block of the wrong colour,
            // far below this.
            assert!(psnr > 30.0, "frame {i}: {psnr:.1} dB");
        }
    }

    /// x264 believes the hint: a change outside the damage stays off the
    /// screen. This is why the damage must cover everything that changed.
    #[test]
    fn a_damage_hint_is_trusted() {
        let mut fb = Framebuffer::new(320, 240);
        fb.fill(Rect::whole(320, 240), [0, 0, 0, 255]);
        let mut frame = I420Frame::new(320, 240);
        convert_full(&fb, &mut frame);
        let mut e = X264Encoder::new(config()).unwrap();
        let mut decoder = ::openh264::decoder::Decoder::new().unwrap();
        for _ in 0..10 {
            let out = e
                .encode_with_damage(&frame, false, FrameDamage::Nothing)
                .unwrap();
            decoder.decode(&out.data).unwrap();
        }
        let told = Rect {
            x: 0,
            y: 0,
            width: 64,
            height: 64,
        };
        let untold = Rect {
            x: 192,
            y: 128,
            width: 64,
            height: 64,
        };
        fb.fill(told, [255, 255, 255, 255]);
        fb.fill(untold, [255, 255, 255, 255]);
        convert_full(&fb, &mut frame);
        let out = e
            .encode_with_damage(&frame, false, FrameDamage::Within(told))
            .unwrap();
        let luma = decoded_luma(&mut decoder, &out.data);
        // Studio swing: white is 235, black 16.
        let (told, untold) = (mean_in(&luma, told), mean_in(&luma, untold));
        assert!(
            told > 200.0,
            "the change it was told of is missing: {told:.0}"
        );
        assert!(
            untold < 40.0,
            "x264 coded a change it was told had not happened: {untold:.0}"
        );
    }

    /// A requested keyframe at a starved bitrate is soft, and an unchanged
    /// screen after it must still sharpen with hints, as it does without.
    #[test]
    fn a_hinted_still_screen_sharpens_after_a_keyframe() {
        let fb = detailed();
        let mut frame = I420Frame::new(320, 240);
        convert_full(&fb, &mut frame);
        let starved = EncoderConfig {
            bitrate_kbps: 300,
            ..config()
        };
        let mut finals = Vec::new();
        for hinted in [false, true] {
            let mut e = X264Encoder::new(starved).unwrap();
            let mut decoder = ::openh264::decoder::Decoder::new().unwrap();
            let damage = if hinted {
                FrameDamage::Nothing
            } else {
                FrameDamage::Unknown
            };
            let first = e.encode(&frame, true).unwrap();
            let keyframe = decoded_psnr(&mut decoder, &first.data, &frame);
            let mut last = keyframe;
            for _ in 0..90 {
                let out = e.encode_with_damage(&frame, false, damage).unwrap();
                last = decoded_psnr(&mut decoder, &out.data, &frame);
            }
            assert!(
                last > keyframe + 3.0,
                "hinted={hinted}: {keyframe:.1} dB at the keyframe, {last:.1} dB after"
            );
            finals.push(last);
        }
        assert!(
            finals[1] > finals[0] - 1.0,
            "hinted {:.1} dB against unhinted {:.1} dB",
            finals[1],
            finals[0]
        );
    }

    #[test]
    fn a_frame_of_the_wrong_size_is_refused() {
        let mut e = X264Encoder::new(config()).unwrap();
        assert!(matches!(
            e.encode(&I420Frame::new(64, 64), false),
            Err(VideoError::WrongGeometry { .. })
        ));
    }
}
