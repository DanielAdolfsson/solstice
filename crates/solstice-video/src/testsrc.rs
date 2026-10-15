//! Synthetic video sources.
//!
//! The first milestone is "serve a hard-coded colour-bar generator through the
//! full GameStream host stack until Moonlight displays it", because that
//! exercises pairing, TLS, RTSP, the SDP negotiation and the video packetiser
//! -- the half of the system that fails silently -- before any backend exists
//! to confuse the picture (`README.md`, `docs/bridging-design.md` §7).
//!
//! The barcode pattern is the other half of that: `docs/testing.md` §2.3 asks
//! for large black and white blocks encoding a frame counter, because they
//! survive H.264 at any sane bitrate and decode with a trivial threshold. That
//! gives correctness, frame identity (duplicate versus dropped, which matters
//! when the frame clock deliberately emits repeats) and end-to-end latency from
//! one pattern.

use solstice_backend::{Framebuffer, Rect};

/// The sliding marker's colour, chosen to differ from every bar.
pub const MARKER: [u8; 4] = [128, 128, 128, 255];

/// SMPTE-ish colour bars, as BGRA.
pub const BARS: [[u8; 4]; 8] = [
    [255, 255, 255, 255], // white
    [0, 255, 255, 255],   // yellow
    [255, 255, 0, 255],   // cyan
    [0, 255, 0, 255],     // green
    [255, 0, 255, 255],   // magenta
    [0, 0, 255, 255],     // red
    [255, 0, 0, 255],     // blue
    [0, 0, 0, 255],       // black
];

/// Draw colour bars with a marker that moves once per frame.
///
/// The moving marker is what makes a frozen stream distinguishable from a still
/// one: bars alone look identical whether the pipeline is running or stopped.
pub fn colour_bars(fb: &mut Framebuffer, frame_number: u64) {
    let (w, h) = (fb.width(), fb.height());
    let bar_width = (w / BARS.len() as u32).max(1);
    for (i, colour) in BARS.iter().enumerate() {
        let x = i as u32 * bar_width;
        let width = if i == BARS.len() - 1 {
            w.saturating_sub(x)
        } else {
            bar_width
        };
        fb.fill(
            Rect {
                x,
                y: 0,
                width,
                height: h,
            },
            *colour,
        );
    }

    // A square sliding along the bottom, one step per frame. Mid-grey, because
    // it has to contrast with every bar it crosses -- a white marker is
    // invisible against the white bar, which is a still frame wearing a moving
    // frame's clothes.
    let size = (h / 12).clamp(4, 64);
    let travel = w.saturating_sub(size).max(1);
    let x = (frame_number % travel as u64) as u32;
    fb.fill(
        Rect {
            x,
            y: h.saturating_sub(size),
            width: size.min(w - x),
            height: size,
        },
        MARKER,
    );
}

/// How many bits the barcode encodes.
pub const BARCODE_BITS: u32 = 24;

/// Draw a binary block barcode encoding `value` across the top of the
/// framebuffer.
///
/// Each bit is a large flat block: white for 1, black for 0, with a white
/// leading sentinel so a decoder can find the row and calibrate.
pub fn barcode(fb: &mut Framebuffer, value: u32) {
    let (w, h) = (fb.width(), fb.height());
    let cells = BARCODE_BITS + 1;
    let cell_w = (w / cells).max(1);
    let cell_h = (h / 8).clamp(4, 64);

    // Sentinel.
    fb.fill(
        Rect {
            x: 0,
            y: 0,
            width: cell_w,
            height: cell_h,
        },
        [255, 255, 255, 255],
    );
    for bit in 0..BARCODE_BITS {
        let on = value & (1 << (BARCODE_BITS - 1 - bit)) != 0;
        let colour = if on {
            [255, 255, 255, 255]
        } else {
            [0, 0, 0, 255]
        };
        let x = (bit + 1) * cell_w;
        if x + cell_w <= w {
            fb.fill(
                Rect {
                    x,
                    y: 0,
                    width: cell_w,
                    height: cell_h,
                },
                colour,
            );
        }
    }
}

/// Read a barcode back out of a framebuffer.
///
/// Samples the centre of each block and thresholds on luma, which is what makes
/// this survive a lossy encode: the blocks are large and flat, so the only way
/// to lose a bit is to lose the frame.
pub fn decode_barcode(fb: &Framebuffer) -> Option<u32> {
    let (w, h) = (fb.width(), fb.height());
    let cells = BARCODE_BITS + 1;
    let cell_w = (w / cells).max(1);
    let cell_h = (h / 8).clamp(4, 64);
    let sample_y = cell_h / 2;

    let bright = |x: u32| -> Option<bool> {
        let px = fb.pixel(x, sample_y)?;
        // Rec.601 luma, enough for a threshold.
        let luma = (px[2] as u32 * 77 + px[1] as u32 * 150 + px[0] as u32 * 29) >> 8;
        Some(luma > 128)
    };

    // The sentinel must be bright, or this is not a barcode row.
    if !bright(cell_w / 2)? {
        return None;
    }
    let mut value = 0u32;
    for bit in 0..BARCODE_BITS {
        let x = (bit + 1) * cell_w + cell_w / 2;
        if x >= w {
            return None;
        }
        value = (value << 1) | u32::from(bright(x)?);
    }
    Some(value)
}

/// A framebuffer-filling test source that advances one frame at a time.
#[derive(Debug)]
pub struct TestPattern {
    frame_number: u64,
}

impl Default for TestPattern {
    fn default() -> Self {
        Self::new()
    }
}

impl TestPattern {
    /// Start at frame zero.
    pub fn new() -> Self {
        Self { frame_number: 0 }
    }

    /// Draw the next frame: colour bars, a moving marker, and a barcode
    /// carrying the frame number.
    pub fn render(&mut self, fb: &mut Framebuffer) -> u64 {
        colour_bars(fb, self.frame_number);
        barcode(fb, (self.frame_number & 0xFF_FFFF) as u32);
        let n = self.frame_number;
        self.frame_number += 1;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colour_bars_cover_the_whole_framebuffer() {
        let mut fb = Framebuffer::new(640, 480);
        colour_bars(&mut fb, 0);
        // The leftmost bar is white, the rightmost black (above the marker).
        assert_eq!(fb.pixel(1, 100), Some([255, 255, 255, 255]));
        assert_eq!(fb.pixel(639, 100), Some([0, 0, 0, 255]));
        // Nothing was left at the initial black fill in the middle bars.
        assert_eq!(fb.pixel(640 / 8 + 1, 100), Some([0, 255, 255, 255]));
    }

    /// A still stream and a frozen one look the same without this.
    #[test]
    fn the_marker_moves_every_frame_against_every_bar() {
        let mut previous: Option<Vec<u8>> = None;
        // Walk the marker across all eight bars, white one included.
        for frame in 0..320u64 {
            let mut fb = Framebuffer::new(320, 240);
            colour_bars(&mut fb, frame);
            let data = fb.data().to_vec();
            if let Some(prev) = previous {
                assert_ne!(prev, data, "frames {} and {frame} are identical", frame - 1);
            }
            previous = Some(data);
        }
    }

    #[test]
    fn a_barcode_round_trips() {
        let mut fb = Framebuffer::new(640, 480);
        for value in [0u32, 1, 42, 0x55_5555, 0xFF_FFFF] {
            barcode(&mut fb, value);
            assert_eq!(decode_barcode(&fb), Some(value), "{value:#x}");
        }
    }

    #[test]
    fn a_framebuffer_without_a_barcode_decodes_to_none() {
        let mut fb = Framebuffer::new(640, 480);
        fb.fill(Rect::whole(640, 480), [0, 0, 0, 255]);
        assert_eq!(decode_barcode(&fb), None);
    }

    /// The property the barcode exists for: tell duplicate frames from dropped
    /// ones, which matters because the frame clock deliberately emits repeats.
    #[test]
    fn the_test_pattern_numbers_every_frame() {
        let mut fb = Framebuffer::new(640, 480);
        let mut pattern = TestPattern::new();
        for expected in 0..5u32 {
            assert_eq!(pattern.render(&mut fb), expected as u64);
            assert_eq!(decode_barcode(&fb), Some(expected));
        }
    }

    /// Flat blocks must survive a real encode and decode. This is the claim the
    /// whole barcode approach rests on.
    #[cfg(feature = "openh264")]
    #[test]
    fn barcodes_survive_a_round_trip_through_the_encoder() {
        use crate::convert::convert_full;
        use crate::encoder::{EncoderConfig, VideoEncoder};
        use crate::frame::I420Frame;
        use crate::openh264::OpenH264Encoder;

        let (w, h) = (640u32, 480u32);
        let mut fb = Framebuffer::new(w, h);
        let mut frame = I420Frame::new(w, h);
        let mut encoder = OpenH264Encoder::new(EncoderConfig {
            width: w,
            height: h,
            fps: 60,
            bitrate_kbps: 8000,
            slices_per_frame: 1,
        })
        .unwrap();
        let mut decoder = ::openh264::decoder::Decoder::new().unwrap();
        let mut pattern = TestPattern::new();

        let mut checked = 0;
        for _ in 0..6 {
            let expected = pattern.render(&mut fb) as u32;
            convert_full(&fb, &mut frame);
            let encoded = encoder.encode(&frame, false).unwrap();
            let Some(decoded) = decoder.decode(&encoded.data).unwrap() else {
                continue;
            };

            // Rebuild a framebuffer from the decoded luma plane. A barcode is
            // black-or-white, so luma alone is enough to threshold.
            use ::openh264::formats::YUVSource;
            let (dw, dh) = decoded.dimensions();
            let mut rgb = vec![0u8; dw * dh * 3];
            decoded.write_rgb8(&mut rgb);
            let mut out = Framebuffer::new(dw as u32, dh as u32);
            for y in 0..dh {
                for x in 0..dw {
                    let i = (y * dw + x) * 3;
                    out.blit(
                        Rect {
                            x: x as u32,
                            y: y as u32,
                            width: 1,
                            height: 1,
                        },
                        &[rgb[i + 2], rgb[i + 1], rgb[i], 255],
                    );
                }
            }
            assert_eq!(decode_barcode(&out), Some(expected), "frame {expected}");
            checked += 1;
        }
        assert!(
            checked >= 3,
            "only {checked} frames came back from the decoder"
        );
    }
}
