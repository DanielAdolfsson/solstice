//! GLZ -- LZ with a dictionary that outlives the image.
//!
//! GLZ is "global LZ": the same FastLZ-derived byte format as [`crate::lz`],
//! except that a match may reach back into an image the server sent *earlier
//! in the session* instead of only into the image being decoded. That is what
//! makes it worth having -- a cursor, a menu or a scrolled region can be sent
//! as a reference to the last time it appeared, for a few bytes -- and it is
//! also what makes it the hardest piece of the SPICE display channel:
//!
//! - **An image cannot be decoded in isolation.** Decoding one needs every
//!   image it refers back to, which means the client keeps a window of decoded
//!   images alive and the server must agree about what is in it. Testing a
//!   single frame proves nothing; `docs/testing.md` §4 asks for soak tests
//!   for exactly this reason.
//! - **The window has to be bounded by the client**, because its size is the
//!   server's choice. [`GlzWindow`] caps itself (see [`GlzWindow::with_limit`])
//!   and drops the oldest images past the cap rather than growing without
//!   limit. A later reference to something dropped fails with
//!   [`Error::GlzWindowMiss`] instead of exhausting memory.
//!
//! The control-byte encoding is *not* LZ's. It splits the bits differently to
//! make room for an image distance, so the two decode loops cannot be shared
//! even though everything downstream of them can.
//!
//! Ported from `src/decode-glz.c` and `src/decode-glz-tmpl.c` in `spice-gtk`.
//!
//! # Divergence from `spice-gtk`
//!
//! `spice-gtk` *blocks* when a match refers to an image that has not arrived
//! yet, which happens when a guest with several monitors spreads its display
//! channels over several sockets and they interleave. This decoder has no
//! coroutine to block in and returns [`Error::GlzWindowMiss`] instead. For a
//! single display channel -- which is what Solstice bridges -- the case does
//! not arise, because one channel delivers its images in order.

use std::collections::HashMap;

use crate::lz::{self, copy_match, ByteReader, LzFormat, LzHeader, LzImageType, MAX_COPY};
use crate::{Error, Image, Limits, Palette, PixelFormat};

/// One decoded image, kept because a later one may refer back to it.
struct WindowImage {
    /// Pixels, including any palette row padding -- a back-reference is an
    /// offset into the *gross* buffer, not the cropped one.
    gross_pixels: usize,
    /// How far back the server said the window reached when this was sent.
    win_head_dist: u32,
    /// Always BGRA: every image type GLZ codes decodes to it.
    data: Vec<u8>,
}

/// The history GLZ matches reach into.
///
/// One window belongs to one display channel and lives as long as it does.
/// Clearing it invalidates every match a later image might make, so it is only
/// correct to do when the channel itself resets.
pub struct GlzWindow {
    images: HashMap<u64, WindowImage>,
    /// Bytes currently held.
    bytes: usize,
    /// The cap on `bytes`.
    limit: usize,
    /// The oldest id not yet released.
    oldest: u64,
    /// One past the newest id with no gap below it.
    ///
    /// Images can arrive out of order, so "the newest image" and "the newest
    /// image with everything before it present" are different things, and the
    /// release decision is driven by the latter.
    tail_gap: u64,
}

impl Default for GlzWindow {
    fn default() -> Self {
        Self::with_limit(Limits::default().glz_window_bytes)
    }
}

impl GlzWindow {
    /// A window with the cap from [`Limits::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// A window holding at most `limit` bytes of decoded image.
    ///
    /// Past the cap the oldest images are dropped. That is a deliberate
    /// trade: a server that declares a window larger than the client will
    /// hold gets [`Error::GlzWindowMiss`] on its next long-range match, which
    /// the display channel can recover from by resetting, where growing to
    /// match it cannot be recovered from at all.
    pub fn with_limit(limit: usize) -> Self {
        GlzWindow {
            images: HashMap::new(),
            bytes: 0,
            limit,
            oldest: 0,
            tail_gap: 0,
        }
    }

    /// Forget every image. Only correct when the display channel resets.
    pub fn clear(&mut self) {
        self.images.clear();
        self.bytes = 0;
        self.oldest = 0;
        self.tail_gap = 0;
    }

    /// How many images are being held.
    pub fn len(&self) -> usize {
        self.images.len()
    }

    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// Bytes of decoded image currently held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    fn insert(&mut self, id: u64, image: WindowImage) {
        self.bytes += image.data.len();
        if let Some(old) = self.images.insert(id, image) {
            self.bytes -= old.data.len();
        }

        // `glz_decoder_window_add`: close the gap up to the id just added.
        while self.tail_gap <= id && self.images.contains_key(&self.tail_gap) {
            self.tail_gap += 1;
        }

        self.release();
        self.enforce_limit();
    }

    /// Drop everything the server has promised not to refer to again.
    fn release(&mut self) {
        if self.tail_gap == 0 {
            // Nothing contiguous yet: the first image arrived out of order,
            // so there is no newest-with-no-gap to take the horizon from.
            return;
        }
        let Some(newest) = self.images.get(&(self.tail_gap - 1)) else {
            return;
        };
        let oldest = (self.tail_gap - 1).saturating_sub(u64::from(newest.win_head_dist));
        if oldest <= self.oldest {
            return;
        }
        self.drop_below(oldest);
    }

    fn drop_below(&mut self, oldest: u64) {
        let mut freed = 0;
        self.images.retain(|&id, image| {
            if id < oldest {
                freed += image.data.len();
                false
            } else {
                true
            }
        });
        self.bytes -= freed;
        self.oldest = oldest;
    }

    /// Drop oldest-first until the window fits its cap.
    fn enforce_limit(&mut self) {
        while self.bytes > self.limit && !self.images.is_empty() {
            let Some(&id) = self.images.keys().min() else {
                break;
            };
            self.drop_below(id + 1);
        }
    }

    fn get(&self, id: u64) -> Option<&WindowImage> {
        self.images.get(&id)
    }
}

/// A GLZ decoder: one per display channel, holding that channel's window.
#[derive(Default)]
pub struct GlzDecoder {
    limits: Limits,
    window: GlzWindow,
}

impl GlzDecoder {
    /// A decoder with a default-sized window.
    pub fn new() -> Self {
        Self::default()
    }

    /// A decoder that will not allocate past `limits`.
    ///
    /// A SPICE backend should set [`Limits::max_pixels`] from the surface it
    /// is decoding into; see the type's documentation for why.
    pub fn with_limits(limits: Limits) -> Self {
        GlzDecoder {
            limits,
            window: GlzWindow::with_limit(limits.glz_window_bytes),
        }
    }

    /// Forget the window. Correct only when the display channel resets.
    pub fn reset(&mut self) {
        self.window.clear();
    }

    /// The window, for inspection.
    pub fn window(&self) -> &GlzWindow {
        &self.window
    }

    /// Decode one GLZ image, adding it to the window.
    ///
    /// The image is added even when a later one will never refer to it:
    /// whether it is referred to is the server's choice, and the window has
    /// to match what the server believes the client is holding.
    pub fn decode(&mut self, input: &[u8], palette: Option<&Palette>) -> Result<Image, Error> {
        let mut src = ByteReader::new(input);

        let magic = src.be_u32()?;
        if magic != lz::LZ_MAGIC {
            return Err(Error::BadMagic {
                codec: "GLZ",
                expected: lz::LZ_MAGIC,
                got: magic,
            });
        }
        let version = src.be_u32()?;
        if version != lz::LZ_VERSION {
            return Err(Error::BadVersion {
                codec: "GLZ",
                expected: lz::LZ_VERSION,
                got: version,
            });
        }

        // GLZ packs the type and the orientation into one byte, where LZ
        // spends two whole 32-bit fields on them.
        let packed = src.u8()?;
        let image_type = LzImageType::from_wire(u32::from(packed & 0x0f))?;
        let top_down = (packed >> 4) != 0;

        // `DECODE_TO_RGB32` in `decode-glz.c` runs out at RGBA: the
        // alpha-only types exist in the LZ format but no GLZ encoder emits
        // them and no GLZ decoder reads them. Rejected here rather than at
        // the dispatch below, because whether GLZ codes a type at all does
        // not depend on anything later in the header.
        if matches!(image_type, LzImageType::Xxxa | LzImageType::A8) {
            return Err(Error::BadImageType {
                codec: "GLZ",
                got: u32::from(packed & 0x0f),
            });
        }

        let width = src.be_u32()?;
        let height = src.be_u32()?;
        let stride = src.be_u32()?;
        let mut header = LzHeader::validate(image_type, width, height, stride, &self.limits)?;
        header.top_down = top_down;

        let id = src.be_u64()?;
        let win_head_dist = src.be_u32()?;

        let size = header.gross_pixels;
        let mut data = vec![0u8; size * 4];

        match image_type {
            LzImageType::Plt1Le => {
                self.run::<lz::Plt1Le>(&mut src, &mut data, size, id, palette)?
            }
            LzImageType::Plt1Be => {
                self.run::<lz::Plt1Be>(&mut src, &mut data, size, id, palette)?
            }
            LzImageType::Plt4Le => {
                self.run::<lz::Plt4Le>(&mut src, &mut data, size, id, palette)?
            }
            LzImageType::Plt4Be => {
                self.run::<lz::Plt4Be>(&mut src, &mut data, size, id, palette)?
            }
            LzImageType::Plt8 => self.run::<lz::Plt8>(&mut src, &mut data, size, id, palette)?,
            LzImageType::Rgb16 => {
                self.run::<lz::Rgb16To32>(&mut src, &mut data, size, id, palette)?
            }
            LzImageType::Rgb24 | LzImageType::Rgb32 => {
                self.run::<lz::Rgb32>(&mut src, &mut data, size, id, palette)?
            }
            LzImageType::Rgba => {
                self.run::<lz::Rgb32>(&mut src, &mut data, size, id, palette)?;
                self.run::<lz::AlphaPlane>(&mut src, &mut data, size, id, palette)?;
            }
            // Rejected above.
            LzImageType::Xxxa | LzImageType::A8 => unreachable!(),
        }

        self.window.insert(
            id,
            WindowImage {
                gross_pixels: size,
                win_head_dist,
                data: data.clone(),
            },
        );

        Ok(lz::crop(header, PixelFormat::Bgra8, data))
    }

    fn run<F: LzFormat>(
        &self,
        src: &mut ByteReader<'_>,
        out: &mut [u8],
        size: usize,
        id: u64,
        palette: Option<&Palette>,
    ) -> Result<(), Error> {
        decompress::<F>(&self.window, src, out, size, id, palette)
    }
}

/// Decode one GLZ segment.
///
/// Mirrors [`crate::lz::decompress`], but the control encoding is different
/// enough that sharing the loop would cost more in flags than it saved.
fn decompress<F: LzFormat>(
    window: &GlzWindow,
    src: &mut ByteReader<'_>,
    out: &mut [u8],
    size: usize,
    id: u64,
    palette: Option<&Palette>,
) -> Result<(), Error> {
    let mut at = 0usize;

    while at < size {
        let ctrl = src.u8()?;

        if ctrl >= MAX_COPY {
            let mut len = u32::from(ctrl >> 5);
            // Bit 4 of the control byte says whether the pixel offset is
            // long; it is re-read from the next byte when it is.
            let mut long_offset = (ctrl >> 4) & 0x01;
            let mut pixel_ofs = u32::from(ctrl & 0x0f);

            if len == 7 {
                loop {
                    let code = src.u8()?;
                    len += u32::from(code);
                    if code != 255 {
                        break;
                    }
                }
            }

            pixel_ofs += u32::from(src.u8()?) << 4;

            let code = src.u8()?;
            let image_flag = (code >> 6) & 0x03;
            let image_dist;

            if long_offset == 0 {
                // Short pixel offset: the rest of this byte starts the image
                // distance, which `image_flag` extends by up to three bytes.
                let mut dist = u32::from(code & 0x3f);
                for i in 0..image_flag {
                    dist += u32::from(src.u8()?) << (6 + 8 * i);
                }
                image_dist = dist;
            } else {
                long_offset = (code >> 5) & 0x01;
                pixel_ofs += u32::from(code & 0x1f) << 12;
                let mut dist = 0u32;
                for i in 0..image_flag {
                    dist += u32::from(src.u8()?) << (8 * i);
                }
                image_dist = dist;

                if long_offset != 0 {
                    pixel_ofs += u32::from(src.u8()?) << 17;
                }
            }

            len += F::GLZ_LEN_BIAS;
            // Within one image the offset is biased by one, because a
            // distance of zero would be the pixel being written. Across
            // images a zero offset is the first pixel and means what it says.
            if image_dist == 0 {
                pixel_ofs += 1;
            }

            let len = len as usize * F::SCALE;
            let pixel_ofs = pixel_ofs as usize * F::SCALE;

            if image_dist == 0 {
                copy_match::<F>(out, at, pixel_ofs, len, size)?;
            } else {
                let wanted = id
                    .checked_sub(u64::from(image_dist))
                    .ok_or(Error::GlzWindowMiss { id, wanted: 0 })?;
                let from = window
                    .get(wanted)
                    .ok_or(Error::GlzWindowMiss { id, wanted })?;

                // The C checks only that the offset is inside the referenced
                // image, not that the whole match is, and reads past the end
                // when it is not.
                if pixel_ofs + len > from.gross_pixels {
                    return Err(Error::GlzBadOffset {
                        length: len as u64,
                        offset: pixel_ofs as u64,
                        size: from.gross_pixels as u64,
                    });
                }
                if at + len > size {
                    return Err(Error::OutputOverrun {
                        length: len as u64,
                        offset: at as u64,
                        capacity: size as u64,
                    });
                }
                for n in 0..len {
                    F::copy_from(out, at + n, &from.data, pixel_ofs + n);
                }
            }
            at += len;
        } else {
            let count = usize::from(ctrl) + 1;
            let pixels = count * F::SCALE;
            if at + pixels > size {
                return Err(Error::OutputOverrun {
                    length: pixels as u64,
                    offset: at as u64,
                    capacity: size as u64,
                });
            }
            for n in 0..count {
                F::literal(src, out, at + n * F::SCALE, palette)?;
            }
            at += pixels;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lz::LZ_MAGIC;

    /// A GLZ header, which packs the type and orientation into one byte and
    /// then carries the image id and the window horizon.
    fn header(image_type: u8, width: u32, height: u32, stride: u32, id: u64, dist: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&LZ_MAGIC.to_be_bytes());
        out.extend_from_slice(&crate::lz::LZ_VERSION.to_be_bytes());
        out.push(image_type | 0x10); // top-down
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&stride.to_be_bytes());
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&dist.to_be_bytes());
        out
    }

    /// A 2x1 BGRA image of two literal pixels, with the given id.
    fn two_literal_pixels(id: u64, dist: u32, colours: [[u8; 3]; 2]) -> Vec<u8> {
        let mut out = header(8, 2, 1, 8, id, dist);
        out.push(0x01); // two literals
        out.extend_from_slice(&colours[0]);
        out.extend_from_slice(&colours[1]);
        out
    }

    #[test]
    fn a_stream_without_the_magic_is_refused() {
        let mut input = two_literal_pixels(0, 0, [[1, 2, 3], [4, 5, 6]]);
        input[0] ^= 0xff;
        assert!(matches!(
            GlzDecoder::new().decode(&input, None),
            Err(Error::BadMagic { codec: "GLZ", .. })
        ));
    }

    /// GLZ codes nine of the eleven LZ types. `DECODE_TO_RGB32` in
    /// `decode-glz.c` has no entry for the alpha-only pair, so a stream
    /// claiming one is malformed rather than merely unsupported.
    #[test]
    fn the_alpha_only_types_glz_does_not_code_are_refused() {
        for bad in [10u8, 11] {
            let input = header(bad, 2, 1, 8, 0, 0);
            assert!(
                matches!(
                    GlzDecoder::new().decode(&input, None),
                    Err(Error::BadImageType { codec: "GLZ", .. })
                ),
                "type {bad} should be refused"
            );
        }
    }

    /// The whole point of the codec: image 1 refers back into image 0.
    #[test]
    fn a_match_reaches_into_the_previous_image() {
        let mut decoder = GlzDecoder::new();
        let first = two_literal_pixels(0, 0, [[0x11, 0x22, 0x33], [0x44, 0x55, 0x66]]);
        decoder.decode(&first, None).expect("first image decodes");

        // Image 1: a match of 2 pixels at offset 0 of image 0.
        let mut second = header(8, 2, 1, 8, 1, 1);
        // len nibble 2 -> len = 2 + GLZ_LEN_BIAS(0) = 2; short offset 0;
        // image_flag 0 with a distance of 1 in the low six bits.
        second.push(0x40);
        second.push(0x00); // pixel offset high bits
        second.push(0x01); // image_flag 0, image_dist 1
        let image = decoder.decode(&second, None).expect("second image decodes");

        assert_eq!(
            image.data,
            vec![0x11, 0x22, 0x33, 0x00, 0x44, 0x55, 0x66, 0x00],
            "the match should have copied image 0 verbatim"
        );
    }

    /// Without the image it refers to, the same stream has to fail -- and
    /// fail in a way the caller can tell apart from a corrupt image, because
    /// the remedy is to reset the channel rather than to drop one frame.
    #[test]
    fn a_match_into_an_image_the_window_never_saw_is_a_window_miss() {
        let mut second = header(8, 2, 1, 8, 1, 1);
        second.push(0x40);
        second.push(0x00);
        second.push(0x01);

        assert_eq!(
            GlzDecoder::new().decode(&second, None),
            Err(Error::GlzWindowMiss { id: 1, wanted: 0 })
        );
    }

    /// Clearing the window is only correct when the channel resets, and this
    /// is what it costs: references that worked a moment ago stop working.
    #[test]
    fn clearing_the_window_invalidates_later_matches() {
        let mut decoder = GlzDecoder::new();
        let first = two_literal_pixels(0, 0, [[1, 2, 3], [4, 5, 6]]);
        decoder.decode(&first, None).unwrap();

        let mut second = header(8, 2, 1, 8, 1, 1);
        second.extend_from_slice(&[0x40, 0x00, 0x01]);
        assert!(decoder.decode(&second, None).is_ok());

        decoder.reset();
        assert!(decoder.window().is_empty());
        assert!(matches!(
            decoder.decode(&second, None),
            Err(Error::GlzWindowMiss { .. })
        ));
    }

    /// A distance larger than the image's own id would underflow.
    #[test]
    fn a_distance_past_the_start_of_the_session_is_a_window_miss() {
        let mut input = header(8, 2, 1, 8, 3, 0);
        input.push(0x40);
        input.push(0x00);
        input.push(0x3f); // image_dist 63, from image 3
        assert!(matches!(
            GlzDecoder::new().decode(&input, None),
            Err(Error::GlzWindowMiss { id: 3, .. })
        ));
    }

    /// The C checks that the *offset* is inside the referenced image but not
    /// that the whole match is, and reads past the end when it is not.
    #[test]
    fn a_match_running_past_the_end_of_the_referenced_image_is_refused() {
        let mut decoder = GlzDecoder::new();
        decoder
            .decode(&two_literal_pixels(0, 0, [[1, 2, 3], [4, 5, 6]]), None)
            .unwrap();

        // 4 px image, matching 4 px starting at offset 1 of a 2 px image.
        let mut second = header(8, 4, 1, 16, 1, 1);
        second.push(0x81); // len nibble 4, short offset, low nibble 1
        second.push(0x00);
        second.push(0x01); // image_dist 1
        assert!(matches!(
            decoder.decode(&second, None),
            Err(Error::GlzBadOffset { .. })
        ));
    }

    /// Images leave the window when the server says it has moved past them.
    #[test]
    fn the_window_releases_images_the_server_has_moved_past() {
        let mut decoder = GlzDecoder::new();
        for id in 0..4u64 {
            // win_head_dist 1: only the previous image is still referable.
            let input = two_literal_pixels(id, 1, [[id as u8, 0, 0], [0, id as u8, 0]]);
            decoder.decode(&input, None).unwrap();
        }
        assert_eq!(
            decoder.window().len(),
            2,
            "a horizon of one should leave the newest image and the one before it"
        );
    }

    /// A server declaring a window larger than the client will hold must not
    /// be able to grow it without limit. Dropping the oldest and failing a
    /// later match is recoverable; running out of memory is not.
    #[test]
    fn the_window_stays_inside_its_byte_limit() {
        // Each image is 2 px of BGRA: 8 bytes.
        let mut decoder = GlzDecoder::with_limits(Limits {
            glz_window_bytes: 24,
            ..Limits::default()
        });
        for id in 0..10u64 {
            // A horizon of 1000 asks the window to keep everything.
            let input = two_literal_pixels(id, 1000, [[1, 2, 3], [4, 5, 6]]);
            decoder.decode(&input, None).unwrap();
        }
        assert!(
            decoder.window().bytes() <= 24,
            "window grew to {} bytes past its 24 byte limit",
            decoder.window().bytes()
        );
        assert_eq!(decoder.window().len(), 3);
    }

    /// Totality again, with a window that already has something in it so the
    /// cross-image path is reachable from the random data.
    #[test]
    fn a_valid_header_followed_by_garbage_never_panics() {
        let mut state = 0xdead_beefu32;
        let palette = Palette {
            entries: (0..256).map(|i| i * 0x0001_0101).collect(),
        };

        for image_type in 1..=9u8 {
            let mut decoder = GlzDecoder::new();
            decoder
                .decode(&two_literal_pixels(0, 0, [[1, 2, 3], [4, 5, 6]]), None)
                .unwrap();

            for trial in 1..64u64 {
                let width = 13u32;
                let stride = LzImageType::from_wire(u32::from(image_type))
                    .unwrap()
                    .natural_stride(width) as u32;

                let mut input = header(image_type, width, 5, stride, trial, 1);
                for _ in 0..200 {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    input.extend_from_slice(&state.to_be_bytes());
                }
                let _ = decoder.decode(&input, Some(&palette));
            }
        }
    }
}
