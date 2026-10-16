//! Tight (`rfbproto.rst:3414-3627`, laid out in `docs/rfb-vnc-protocol.md`
//! §5.1): fill, and "basic" compression with a copy, palette or gradient
//! filter over one of four zlib streams.
//!
//! **Lossless only.** JPEG (compression type 9) is never requested -- Solstice
//! advertises no quality-level pseudo-encoding, and both TigerVNC and QEMU send
//! JPEG only to a client that did -- so a JPEG rectangle is a protocol error
//! rather than something to decode. A JPEG hop ahead of an H.264 encoder would
//! be double-lossy compression (`docs/roadmap.md` §1).
//!
//! **Four streams, not one.** Each stream is continuous for the life of the
//! connection, like ZRLE's, *and* individually resettable: the low four bits
//! of every rectangle's control byte name the streams to reset before it is
//! decoded, whatever its compression type. A missed reset is not an error --
//! it is a picture that slowly turns to garbage -- so the streams are owned by
//! the session and passed in, and the reset is applied before anything else.
//!
//! As with ZRLE, the wire parsing ([`decode`]) is separate from the pixel
//! decoding ([`decode_pixels`]), which is a pure function over an inflated
//! buffer and so can be tested and fuzzed without a zlib round trip.

use solstice_backend::{Framebuffer, Rect};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::zrle::ZlibStream;
use super::{check_rect, read_exact};
use crate::pixel::PixelFormat;
use crate::protocol::{Result, RfbError};

/// Widest rectangle basic compression may cover (`rfbproto.rst:3417-3421`).
/// Fill is exempt, as in TigerVNC's decoder: TigerVNC servers before 1.16 sent
/// wider fills, and a fill has no per-row state for the limit to protect.
pub const MAX_WIDTH: u32 = 2048;

/// Filtered data shorter than this is sent as is, without zlib and without
/// touching any stream (`rfbproto.rst:3596-3599`).
pub const MIN_TO_COMPRESS: usize = 12;

/// Compression types, the high nibble of the control byte.
const FILL: u8 = 0x8;
const JPEG: u8 = 0x9;
/// Bit 6 of the control byte, bit 2 of the nibble: a filter-id byte follows.
const EXPLICIT_FILTER: u8 = 0x4;

/// Filter ids (`rfbproto.rst:3543-3550`).
const FILTER_COPY: u8 = 0;
const FILTER_PALETTE: u8 = 1;
const FILTER_GRADIENT: u8 = 2;

/// Tight's four zlib streams.
#[derive(Debug, Default)]
pub struct TightStreams {
    streams: [ZlibStream; 4],
}

impl TightStreams {
    /// Four fresh streams.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset every stream whose bit is set in the low nibble of `mask`.
    pub fn reset(&mut self, mask: u8) {
        for (i, stream) in self.streams.iter_mut().enumerate() {
            if mask & (1 << i) != 0 {
                stream.reset();
            }
        }
    }

    /// Inflate `input` on stream `id`, which must produce exactly `expected`
    /// bytes. Both the server's deflate and this inflate run continuously, so
    /// a short or long chunk means the two windows no longer agree, and every
    /// later rectangle on the stream would decode wrong without complaint.
    fn inflate(&mut self, id: usize, input: &[u8], expected: usize) -> Result<Vec<u8>> {
        let out = self.streams[id].inflate_at_most(input, expected)?;
        if out.len() != expected {
            return Err(RfbError::Protocol(format!(
                "Tight stream {id} inflated to {} bytes, not {expected}",
                out.len()
            )));
        }
        Ok(out)
    }
}

/// The filter a basic-compression rectangle was encoded with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Pixels as they are.
    Copy,
    /// Indices into a palette of 1..=256 colours, already in BGRA. Two colours
    /// or fewer pack one bit per pixel; more take a byte each.
    Palette(Vec<[u8; 4]>),
    /// Per-component differences from a predicted intensity.
    Gradient,
}

/// Whether TPIXELs are three bytes, red then green then blue, rather than a
/// whole pixel (`rfbproto.rst:3488-3495`). The test is TigerVNC's `is888`,
/// which adds byte-aligned shifts to the spec's wording: without them the
/// components would not be whole bytes of the pixel, and "the three bytes"
/// would mean nothing.
pub fn is_888(format: &PixelFormat) -> bool {
    format.true_colour
        && format.bits_per_pixel == 32
        && format.depth == 24
        && format.maxima() == [255; 3]
        && [format.red_shift, format.green_shift, format.blue_shift]
            .iter()
            .all(|shift| shift % 8 == 0)
}

/// Size of one TPIXEL in this format.
pub fn tpixel_size(format: &PixelFormat) -> usize {
    if is_888(format) {
        3
    } else {
        format.bytes_per_pixel()
    }
}

/// Red, green and blue intensities of one TPIXEL, unscaled.
fn tpixel_components(format: &PixelFormat, bytes: &[u8]) -> [u32; 3] {
    if is_888(format) {
        [bytes[0] as u32, bytes[1] as u32, bytes[2] as u32]
    } else {
        format.components(bytes)
    }
}

fn tpixel_to_bgra(format: &PixelFormat, bytes: &[u8]) -> [u8; 4] {
    if is_888(format) {
        [bytes[2], bytes[1], bytes[0], 0xFF]
    } else {
        format.to_bgra(bytes)
    }
}

/// How many bytes of filtered data a rectangle carries, before compression.
pub fn data_size(format: &PixelFormat, rect: Rect, filter: &Filter) -> usize {
    let (w, h) = (rect.width as usize, rect.height as usize);
    match filter {
        Filter::Palette(palette) if palette.len() <= 2 => w.div_ceil(8) * h,
        Filter::Palette(_) => w * h,
        Filter::Copy | Filter::Gradient => w * h * tpixel_size(format),
    }
}

async fn read_u8<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u8> {
    Ok(reader.read_u8().await?)
}

/// Read a compact length: one to three bytes, seven bits at a time, least
/// significant first, the third byte contributing all eight
/// (`rfbproto.rst:3516-3531`).
pub async fn read_compact_length<R: AsyncRead + Unpin>(reader: &mut R) -> Result<usize> {
    let first = read_u8(reader).await?;
    let mut length = (first & 0x7F) as usize;
    if first & 0x80 != 0 {
        let second = read_u8(reader).await?;
        length |= ((second & 0x7F) as usize) << 7;
        if second & 0x80 != 0 {
            length |= (read_u8(reader).await? as usize) << 14;
        }
    }
    Ok(length)
}

/// The inverse of [`read_compact_length`], for the mock server and tests.
///
/// # Panics
/// If `length` does not fit in 22 bits.
pub fn compact_length(length: usize) -> Vec<u8> {
    assert!(length < 1 << 22, "a compact length is at most 22 bits");
    if length < 1 << 7 {
        vec![length as u8]
    } else if length < 1 << 14 {
        vec![length as u8 | 0x80, (length >> 7) as u8]
    } else {
        vec![
            length as u8 | 0x80,
            (length >> 7) as u8 | 0x80,
            (length >> 14) as u8,
        ]
    }
}

/// Decode a Tight rectangle.
pub async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    format: &PixelFormat,
    rect: Rect,
    fb: &mut Framebuffer,
    streams: &mut TightStreams,
) -> Result<()> {
    check_rect(rect, fb)?;
    let control = read_u8(reader).await?;
    // Before anything else, and for every compression type: a reset carried
    // by a fill rectangle still applies (`rfbproto.rst:3617-3621`).
    streams.reset(control & 0x0F);

    let kind = control >> 4;
    match kind {
        FILL => {
            let pixel = read_exact(reader, tpixel_size(format)).await?;
            if !rect.is_empty() {
                fb.fill(rect, tpixel_to_bgra(format, &pixel));
            }
            Ok(())
        }
        JPEG => Err(RfbError::Protocol(
            "Tight JPEG arrived, but no quality level was advertised".into(),
        )),
        0..=7 => basic(reader, format, rect, fb, streams, kind).await,
        // 0xA and 0xE are basic compression without zlib, which needs a
        // pseudo-encoding Solstice does not send; the rest are undefined.
        other => Err(RfbError::Protocol(format!(
            "Tight compression type {other:#x} was not requested"
        ))),
    }
}

async fn basic<R: AsyncRead + Unpin>(
    reader: &mut R,
    format: &PixelFormat,
    rect: Rect,
    fb: &mut Framebuffer,
    streams: &mut TightStreams,
    kind: u8,
) -> Result<()> {
    if rect.width > MAX_WIDTH {
        return Err(RfbError::Protocol(format!(
            "Tight rectangle {} wide exceeds {MAX_WIDTH}",
            rect.width
        )));
    }
    let stream = (kind & 0x3) as usize;
    let filter = if kind & EXPLICIT_FILTER == 0 {
        Filter::Copy
    } else {
        match read_u8(reader).await? {
            FILTER_COPY => Filter::Copy,
            FILTER_PALETTE => {
                let size = read_u8(reader).await? as usize + 1;
                let tpixel = tpixel_size(format);
                let entries = read_exact(reader, size * tpixel).await?;
                Filter::Palette(
                    entries
                        .chunks_exact(tpixel)
                        .map(|c| tpixel_to_bgra(format, c))
                        .collect(),
                )
            }
            FILTER_GRADIENT => Filter::Gradient,
            other => return Err(RfbError::Protocol(format!("Tight filter id {other}"))),
        }
    };

    let size = data_size(format, rect, &filter);
    let data = if size < MIN_TO_COMPRESS {
        read_exact(reader, size).await?
    } else {
        let length = read_compact_length(reader).await?;
        let compressed = read_exact(reader, length).await?;
        streams.inflate(stream, &compressed, size)?
    };
    decode_pixels(format, rect, fb, &filter, &data)
}

/// Decode a basic-compression rectangle's filtered data, already inflated.
pub fn decode_pixels(
    format: &PixelFormat,
    rect: Rect,
    fb: &mut Framebuffer,
    filter: &Filter,
    data: &[u8],
) -> Result<()> {
    let expected = data_size(format, rect, filter);
    if data.len() != expected {
        return Err(RfbError::Protocol(format!(
            "Tight rectangle carries {} bytes of pixel data, not {expected}",
            data.len()
        )));
    }
    if rect.is_empty() {
        return Ok(());
    }
    let (w, h) = (rect.width as usize, rect.height as usize);
    let mut bgra = Vec::with_capacity(w * h * 4);
    match filter {
        Filter::Copy => {
            for pixel in data.chunks_exact(tpixel_size(format)) {
                bgra.extend_from_slice(&tpixel_to_bgra(format, pixel));
            }
        }
        Filter::Palette(palette) => {
            let colour = |index: usize| {
                palette.get(index).copied().ok_or_else(|| {
                    RfbError::Protocol(format!(
                        "Tight palette index {index} with {} colours",
                        palette.len()
                    ))
                })
            };
            if palette.len() <= 2 {
                // Most significant bit leftmost; rows padded to a byte.
                for row in data.chunks_exact(w.div_ceil(8)) {
                    for x in 0..w {
                        let bit = (row[x / 8] >> (7 - x % 8)) & 1;
                        bgra.extend_from_slice(&colour(bit as usize)?);
                    }
                }
            } else {
                for &index in data {
                    bgra.extend_from_slice(&colour(index as usize)?);
                }
            }
        }
        Filter::Gradient => gradient(format, w, data, &mut bgra)?,
    }
    if !fb.blit(rect, &bgra) {
        return Err(RfbError::Protocol("Tight rectangle does not fit".into()));
    }
    Ok(())
}

/// Undo the gradient filter (`rfbproto.rst:3574-3594`): each component was
/// sent as its difference from `left + above - above_left`, clamped to the
/// channel's range, with everything outside the rectangle taken as zero.
fn gradient(format: &PixelFormat, width: usize, data: &[u8], bgra: &mut Vec<u8>) -> Result<()> {
    if format.bits_per_pixel == 8 {
        return Err(RfbError::Protocol(
            "the Tight gradient filter needs 16 or 32 bits per pixel".into(),
        ));
    }
    let tpixel = tpixel_size(format);
    let maxima = if is_888(format) {
        [255; 3]
    } else {
        format.maxima()
    };
    let mut above = vec![[0u32; 3]; width];
    let mut row = vec![[0u32; 3]; width];
    for line in data.chunks_exact(width * tpixel) {
        for x in 0..width {
            let residual = tpixel_components(format, &line[x * tpixel..(x + 1) * tpixel]);
            let (left, above_left) = if x == 0 {
                ([0; 3], [0; 3])
            } else {
                (row[x - 1], above[x - 1])
            };
            for c in 0..3 {
                let max = maxima[c] as i64;
                let predicted =
                    (left[c] as i64 + above[x][c] as i64 - above_left[c] as i64).clamp(0, max);
                // The difference was taken modulo the channel's range, so it
                // is added back the same way.
                row[x][c] = ((predicted + residual[c] as i64) % (max + 1)) as u32;
            }
            bgra.extend_from_slice(&if is_888(format) {
                [row[x][2] as u8, row[x][1] as u8, row[x][0] as u8, 0xFF]
            } else {
                format.bgra_from_components(row[x])
            });
        }
        std::mem::swap(&mut above, &mut row);
    }
    Ok(())
}

/// Apply the gradient filter to RGB triples, for the mock server and tests:
/// the encoder half of [`decode_pixels`] with [`Filter::Gradient`], in the
/// three-byte TPIXEL format.
pub fn gradient_filter_rgb(width: usize, rgb: &[u8]) -> Vec<u8> {
    let at = |x: usize, y: usize, c: usize| rgb[(y * width + x) * 3 + c] as i32;
    let height = rgb.len() / (width * 3).max(1);
    let mut out = Vec::with_capacity(rgb.len());
    for y in 0..height {
        for x in 0..width {
            for c in 0..3 {
                let left = if x > 0 { at(x - 1, y, c) } else { 0 };
                let above = if y > 0 { at(x, y - 1, c) } else { 0 };
                let above_left = if x > 0 && y > 0 {
                    at(x - 1, y - 1, c)
                } else {
                    0
                };
                let predicted = (left + above - above_left).clamp(0, 255);
                out.push((at(x, y, c) - predicted) as u8);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    const FORMAT: PixelFormat = PixelFormat::BGRA;

    fn rect(width: u32, height: u32) -> Rect {
        Rect {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    /// A server-side deflate stream: continuous, sync-flushed per rectangle,
    /// the way QEMU's `tight_compress_data` drives it.
    struct Deflater(Compress);

    impl Deflater {
        fn new() -> Self {
            Self(Compress::new(Compression::default(), true))
        }

        fn chunk(&mut self, data: &[u8]) -> Vec<u8> {
            let start = self.0.total_in();
            let mut out = Vec::with_capacity(data.len() + 1024);
            loop {
                let consumed = (self.0.total_in() - start) as usize;
                self.0
                    .compress_vec(&data[consumed..], &mut out, FlushCompress::Sync)
                    .unwrap();
                // Done once every byte is in and the flush left room to spare.
                if (self.0.total_in() - start) as usize == data.len() && out.len() < out.capacity()
                {
                    return out;
                }
                out.reserve(out.capacity());
            }
        }
    }

    /// Wire bytes for a basic-compression rectangle on `stream`.
    fn basic_rect(
        deflater: &mut Deflater,
        control: u8,
        filter_and_palette: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut wire = vec![control];
        wire.extend_from_slice(filter_and_palette);
        if data.len() < MIN_TO_COMPRESS {
            wire.extend_from_slice(data);
        } else {
            let compressed = deflater.chunk(data);
            wire.extend(compact_length(compressed.len()));
            wire.extend(compressed);
        }
        wire
    }

    async fn run(wire: Vec<u8>, area: Rect, fb: &mut Framebuffer, streams: &mut TightStreams) {
        let mut cursor = std::io::Cursor::new(wire);
        decode(&mut cursor, &FORMAT, area, fb, streams)
            .await
            .unwrap();
        assert_eq!(
            cursor.position() as usize,
            cursor.get_ref().len(),
            "the decoder must consume exactly one rectangle"
        );
    }

    #[test]
    fn compact_lengths_match_the_specs_worked_example() {
        // `rfbproto.rst:3529-3531`: 10000 is 0x90 0x4E.
        assert_eq!(compact_length(10000), vec![0x90, 0x4E]);
        assert_eq!(compact_length(127), vec![0x7F]);
        assert_eq!(compact_length(128), vec![0x80, 0x01]);
        assert_eq!(compact_length(4_194_303), vec![0xFF, 0xFF, 0xFF]);
    }

    #[tokio::test]
    async fn compact_lengths_round_trip_at_every_boundary() {
        for length in [0, 1, 127, 128, 16383, 16384, 4_194_303] {
            let mut cursor = std::io::Cursor::new(compact_length(length));
            assert_eq!(read_compact_length(&mut cursor).await.unwrap(), length);
        }
    }

    #[test]
    fn tpixels_are_three_bytes_only_for_888() {
        assert!(is_888(&FORMAT));
        assert_eq!(tpixel_size(&FORMAT), 3);
        let rgb565 = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
            ..FORMAT
        };
        assert_eq!(tpixel_size(&rgb565), 2);
        // 32 bits, but with a 30-bit depth: whole pixels.
        let deep = PixelFormat {
            depth: 30,
            red_max: 1023,
            green_max: 1023,
            blue_max: 1023,
            red_shift: 20,
            green_shift: 10,
            ..FORMAT
        };
        assert_eq!(tpixel_size(&deep), 4);
    }

    /// TPIXELs are red, green, blue -- not the byte order of a full pixel,
    /// which for the BGRA format Solstice asks for is the reverse.
    #[tokio::test]
    async fn a_fill_paints_the_rectangle_from_an_rgb_tpixel() {
        let mut fb = Framebuffer::new(8, 8);
        let mut streams = TightStreams::new();
        let area = Rect {
            x: 2,
            y: 2,
            width: 4,
            height: 4,
        };
        run(vec![0x80, 0x10, 0x20, 0x30], area, &mut fb, &mut streams).await;
        assert_eq!(fb.pixel(2, 2), Some([0x30, 0x20, 0x10, 0xFF]));
        assert_eq!(fb.pixel(5, 5), Some([0x30, 0x20, 0x10, 0xFF]));
        assert_eq!(fb.pixel(1, 1), Some([0, 0, 0, 0xFF]));
        assert_eq!(fb.pixel(6, 6), Some([0, 0, 0, 0xFF]));
    }

    /// A fill carries no length and touches no stream; routing it through the
    /// zlib path would eat the next rectangle's bytes.
    #[tokio::test]
    async fn a_fill_is_one_pixel_and_nothing_else() {
        let mut fb = Framebuffer::new(4, 4);
        let mut streams = TightStreams::new();
        let mut wire = vec![0x80, 1, 2, 3];
        wire.extend_from_slice(&[0x80, 4, 5, 6]);
        let mut cursor = std::io::Cursor::new(wire);
        for _ in 0..2 {
            decode(&mut cursor, &FORMAT, rect(4, 4), &mut fb, &mut streams)
                .await
                .unwrap();
        }
        assert_eq!(fb.pixel(0, 0), Some([6, 5, 4, 0xFF]));
    }

    /// Fill is exempt from the 2048-pixel width limit, as in TigerVNC.
    #[tokio::test]
    async fn a_wide_fill_is_accepted_but_wide_basic_is_not() {
        let mut fb = Framebuffer::new(4096, 1);
        let mut streams = TightStreams::new();
        run(vec![0x80, 9, 9, 9], rect(4096, 1), &mut fb, &mut streams).await;
        assert_eq!(fb.pixel(4095, 0), Some([9, 9, 9, 0xFF]));

        let mut cursor = std::io::Cursor::new(vec![0x00, 0x7F]);
        assert!(
            decode(&mut cursor, &FORMAT, rect(4096, 1), &mut fb, &mut streams)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn copy_decodes_both_with_and_without_a_filter_id() {
        for control_and_filter in [vec![0x00u8], vec![0x40, FILTER_COPY]] {
            let mut fb = Framebuffer::new(4, 4);
            let mut streams = TightStreams::new();
            let rgb: Vec<u8> = (0..48).collect();
            let wire = basic_rect(
                &mut Deflater::new(),
                control_and_filter[0],
                &control_and_filter[1..],
                &rgb,
            );
            run(wire, rect(4, 4), &mut fb, &mut streams).await;
            assert_eq!(fb.pixel(0, 0), Some([2, 1, 0, 0xFF]));
            assert_eq!(fb.pixel(3, 3), Some([47, 46, 45, 0xFF]));
        }
    }

    /// Under twelve bytes the data is sent raw, with no length and no zlib --
    /// and the stream must not be touched, or the next compressed rectangle on
    /// it would be inflated against the wrong window.
    #[tokio::test]
    async fn short_data_is_sent_raw_and_leaves_the_stream_alone() {
        let mut fb = Framebuffer::new(8, 8);
        let mut streams = TightStreams::new();
        // 3 pixels of copy: 9 bytes, under the threshold.
        let wire = basic_rect(
            &mut Deflater::new(),
            0x00,
            &[],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
        );
        assert_eq!(wire.len(), 10, "no length prefix below the threshold");
        run(wire, rect(3, 1), &mut fb, &mut streams).await;
        assert_eq!(fb.pixel(2, 0), Some([9, 8, 7, 0xFF]));

        // Stream 0 is still fresh: a brand-new deflater's output inflates.
        let rgb = vec![0x44u8; 8 * 8 * 3];
        let wire = basic_rect(&mut Deflater::new(), 0x00, &[], &rgb);
        run(wire, rect(8, 8), &mut fb, &mut streams).await;
        assert_eq!(fb.pixel(7, 7), Some([0x44, 0x44, 0x44, 0xFF]));
    }

    #[tokio::test]
    async fn a_two_colour_palette_packs_one_bit_per_pixel_msb_first() {
        let mut fb = Framebuffer::new(10, 2);
        let mut streams = TightStreams::new();
        // Palette: index 0 black, index 1 white.
        let header = [FILTER_PALETTE, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF];
        // Rows of 10 pixels pad to two bytes each.
        let data = [0b1000_0000, 0b0100_0000, 0b0000_0001, 0b1100_0000];
        let wire = basic_rect(&mut Deflater::new(), 0x50, &header, &data);
        run(wire, rect(10, 2), &mut fb, &mut streams).await;
        let white = Some([0xFF, 0xFF, 0xFF, 0xFF]);
        let black = Some([0, 0, 0, 0xFF]);
        assert_eq!(fb.pixel(0, 0), white);
        assert_eq!(fb.pixel(1, 0), black);
        assert_eq!(fb.pixel(9, 0), white, "the padded row's tail bit");
        assert_eq!(fb.pixel(7, 1), white);
        assert_eq!(fb.pixel(8, 1), white);
        assert_eq!(fb.pixel(9, 1), white);
        assert_eq!(fb.pixel(6, 1), black);
    }

    #[tokio::test]
    async fn a_larger_palette_takes_a_byte_per_pixel() {
        let mut fb = Framebuffer::new(4, 4);
        let mut streams = TightStreams::new();
        let mut header = vec![FILTER_PALETTE, 2];
        header.extend_from_slice(&[0xFF, 0, 0, 0, 0xFF, 0, 0, 0, 0xFF]);
        let data: Vec<u8> = (0..16).map(|i| (i % 3) as u8).collect();
        let wire = basic_rect(&mut Deflater::new(), 0x60, &header, &data);
        run(wire, rect(4, 4), &mut fb, &mut streams).await;
        assert_eq!(fb.pixel(0, 0), Some([0, 0, 0xFF, 0xFF]), "red");
        assert_eq!(fb.pixel(1, 0), Some([0, 0xFF, 0, 0xFF]), "green");
        assert_eq!(fb.pixel(2, 0), Some([0xFF, 0, 0, 0xFF]), "blue");
        assert_eq!(fb.pixel(3, 0), Some([0, 0, 0xFF, 0xFF]), "red again");
    }

    #[test]
    fn a_palette_index_past_the_end_is_an_error() {
        let mut fb = Framebuffer::new(4, 4);
        let palette = Filter::Palette(vec![[0; 4], [1; 4], [2; 4]]);
        let mut data = vec![0u8; 16];
        data[5] = 3;
        assert!(decode_pixels(&FORMAT, rect(4, 4), &mut fb, &palette, &data).is_err());
        // And a one-colour palette has no index 1, even in the packed form.
        let single = Filter::Palette(vec![[7; 4]]);
        assert!(decode_pixels(&FORMAT, rect(4, 1), &mut fb, &single, &[0b0100_0000]).is_err());
        assert!(decode_pixels(&FORMAT, rect(4, 1), &mut fb, &single, &[0]).is_ok());
    }

    #[tokio::test]
    async fn the_gradient_filter_round_trips_an_arbitrary_image() {
        let (w, h) = (13usize, 7usize);
        // Deliberately not smooth: wrap-around in both directions.
        let rgb: Vec<u8> = (0..w * h * 3)
            .map(|i| (i * 37 % 251) as u8 ^ ((i / 7) as u8))
            .collect();
        let residuals = gradient_filter_rgb(w, &rgb);
        let mut fb = Framebuffer::new(w as u32, h as u32);
        let mut streams = TightStreams::new();
        let wire = basic_rect(&mut Deflater::new(), 0x70, &[FILTER_GRADIENT], &residuals);
        run(wire, rect(w as u32, h as u32), &mut fb, &mut streams).await;
        for y in 0..h {
            for x in 0..w {
                let i = (y * w + x) * 3;
                assert_eq!(
                    fb.pixel(x as u32, y as u32),
                    Some([rgb[i + 2], rgb[i + 1], rgb[i], 0xFF]),
                    "pixel ({x}, {y})"
                );
            }
        }
    }

    /// The predictor by hand, for the corner cases the round trip hides behind
    /// symmetry: the first row and column predict from zero.
    #[test]
    fn the_gradient_predictor_starts_from_zero_outside_the_rectangle() {
        // 2x2, one channel varying: V = [[10, 30], [50, 20]] in red.
        // P(0,0) = 0, P(1,0) = 10, P(0,1) = 10, P(1,1) = 30 + 50 - 10 = 70.
        let mut data = Vec::new();
        for residual in [10u8, 20, 40, 20u8.wrapping_sub(70)] {
            data.extend_from_slice(&[residual, 0, 0]);
        }
        let mut fb = Framebuffer::new(2, 2);
        decode_pixels(&FORMAT, rect(2, 2), &mut fb, &Filter::Gradient, &data).unwrap();
        assert_eq!(fb.pixel(0, 0), Some([0, 0, 10, 0xFF]));
        assert_eq!(fb.pixel(1, 0), Some([0, 0, 30, 0xFF]));
        assert_eq!(fb.pixel(0, 1), Some([0, 0, 50, 0xFF]));
        assert_eq!(fb.pixel(1, 1), Some([0, 0, 20, 0xFF]));
    }

    /// Outside 888, the gradient works on each channel's own range.
    #[test]
    fn the_gradient_clamps_to_the_channel_maximum_in_565() {
        let rgb565 = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
            ..FORMAT
        };
        let pixel = |r: u16, g: u16, b: u16| ((r << 11) | (g << 5) | b).to_le_bytes();
        // 2x2: top row full red, bottom-left full red, so P(1,1) = 31 + 31 - 31
        // = 31; a residual of 0 keeps it at 31, and nothing overflows past max.
        let mut data = Vec::new();
        data.extend_from_slice(&pixel(31, 0, 0)); // V(0,0) = 31
        data.extend_from_slice(&pixel(0, 0, 0)); // V(1,0) = P = 31
        data.extend_from_slice(&pixel(0, 0, 0)); // V(0,1) = P = 31
        data.extend_from_slice(&pixel(1, 0, 0)); // P = 31, V = 32 mod 32 = 0
        let mut fb = Framebuffer::new(2, 2);
        decode_pixels(&rgb565, rect(2, 2), &mut fb, &Filter::Gradient, &data).unwrap();
        assert_eq!(fb.pixel(0, 0), Some([0, 0, 255, 0xFF]));
        assert_eq!(fb.pixel(1, 0), Some([0, 0, 255, 0xFF]));
        assert_eq!(fb.pixel(0, 1), Some([0, 0, 255, 0xFF]));
        assert_eq!(fb.pixel(1, 1), Some([0, 0, 0, 0xFF]));
    }

    #[test]
    fn the_gradient_filter_is_refused_at_eight_bits_per_pixel() {
        let bgr233 = PixelFormat {
            bits_per_pixel: 8,
            depth: 8,
            red_max: 7,
            green_max: 7,
            blue_max: 3,
            red_shift: 0,
            green_shift: 3,
            blue_shift: 6,
            ..FORMAT
        };
        let mut fb = Framebuffer::new(2, 2);
        assert!(decode_pixels(&bgr233, rect(2, 2), &mut fb, &Filter::Gradient, &[0; 4]).is_err());
    }

    /// The model is ZRLE's `the_zlib_stream_is_continuous_across_rectangles`,
    /// times four: rectangles interleave across all four streams, and each
    /// stream's window must carry from its previous rectangle, not from
    /// whichever rectangle came last.
    #[tokio::test]
    async fn four_streams_stay_continuous_independently() {
        let mut fb = Framebuffer::new(8, 8);
        let mut streams = TightStreams::new();
        let mut deflaters = [
            Deflater::new(),
            Deflater::new(),
            Deflater::new(),
            Deflater::new(),
        ];
        // Repeating content, so later chunks back-reference earlier ones and a
        // window mix-up cannot go unnoticed.
        for round in 0..3u8 {
            for id in [2usize, 0, 3, 1] {
                let colour = [round * 40 + id as u8, id as u8 * 50, 7];
                let rgb = colour.repeat(64);
                let control = (id as u8) << 4;
                let wire = basic_rect(&mut deflaters[id], control, &[], &rgb);
                run(wire, rect(8, 8), &mut fb, &mut streams).await;
                assert_eq!(
                    fb.pixel(7, 7),
                    Some([colour[2], colour[1], colour[0], 0xFF]),
                    "round {round}, stream {id}"
                );
            }
        }
    }

    /// A server may reset one stream mid-session. The reset applies before the
    /// rectangle that carries it, even a fill, and only to the streams named.
    #[tokio::test]
    async fn a_reset_mid_session_restarts_only_the_named_stream() {
        let mut fb = Framebuffer::new(8, 8);
        let mut streams = TightStreams::new();
        let mut zero = Deflater::new();
        let mut one = Deflater::new();
        let rgb_a = [10u8, 20, 30].repeat(64);
        let rgb_b = [40u8, 50, 60].repeat(64);

        run(
            basic_rect(&mut zero, 0x00, &[], &rgb_a),
            rect(8, 8),
            &mut fb,
            &mut streams,
        )
        .await;
        run(
            basic_rect(&mut one, 0x10, &[], &rgb_a),
            rect(8, 8),
            &mut fb,
            &mut streams,
        )
        .await;

        // The server resets stream 1, carried on a fill.
        one = Deflater::new();
        run(vec![0x82, 0, 0, 0], rect(8, 8), &mut fb, &mut streams).await;

        // Stream 1 now inflates a fresh deflate stream...
        run(
            basic_rect(&mut one, 0x10, &[], &rgb_b),
            rect(8, 8),
            &mut fb,
            &mut streams,
        )
        .await;
        assert_eq!(fb.pixel(0, 0), Some([60, 50, 40, 0xFF]));
        // ...and stream 0 still continues its old one.
        run(
            basic_rect(&mut zero, 0x00, &[], &rgb_b),
            rect(8, 8),
            &mut fb,
            &mut streams,
        )
        .await;
        assert_eq!(fb.pixel(0, 0), Some([60, 50, 40, 0xFF]));
    }

    /// And the negative: without the reset, a restarted server stream is a
    /// zlib header in the middle of a deflate stream, which must be an error
    /// rather than a quietly wrong picture.
    #[tokio::test]
    async fn a_missed_reset_is_an_error_not_garbage() {
        let mut fb = Framebuffer::new(8, 8);
        let mut streams = TightStreams::new();
        let rgb = [1u8, 2, 3].repeat(64);
        run(
            basic_rect(&mut Deflater::new(), 0x00, &[], &rgb),
            rect(8, 8),
            &mut fb,
            &mut streams,
        )
        .await;
        let wire = basic_rect(&mut Deflater::new(), 0x00, &[], &rgb);
        let mut cursor = std::io::Cursor::new(wire);
        assert!(
            decode(&mut cursor, &FORMAT, rect(8, 8), &mut fb, &mut streams)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn jpeg_and_undefined_compression_types_are_refused() {
        for control in [0x90u8, 0xA0, 0xB0, 0xE0, 0xF0] {
            let mut fb = Framebuffer::new(4, 4);
            let mut streams = TightStreams::new();
            let mut cursor = std::io::Cursor::new(vec![control, 0, 0, 0, 0]);
            assert!(
                decode(&mut cursor, &FORMAT, rect(4, 4), &mut fb, &mut streams)
                    .await
                    .is_err(),
                "control {control:#x}"
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_filter_id_is_refused() {
        let mut fb = Framebuffer::new(4, 4);
        let mut cursor = std::io::Cursor::new(vec![0x40, 3, 0, 0]);
        assert!(decode(
            &mut cursor,
            &FORMAT,
            rect(4, 4),
            &mut fb,
            &mut TightStreams::new()
        )
        .await
        .is_err());
    }

    /// A chunk that inflates to more than the rectangle needs is refused at
    /// the rectangle's size -- the cap that stops a decompression bomb
    /// (`docs/security.md` §5.4) -- and one that inflates to less is refused
    /// too, since either means the windows have parted company.
    #[tokio::test]
    async fn a_chunk_of_the_wrong_inflated_size_is_refused() {
        for actual in [47usize, 49, 64 * 1024 * 1024] {
            let mut fb = Framebuffer::new(4, 4);
            let mut deflater = Deflater::new();
            let compressed = deflater.chunk(&vec![0u8; actual]);
            let mut wire = vec![0x00];
            wire.extend(compact_length(compressed.len()));
            wire.extend(compressed);
            let mut cursor = std::io::Cursor::new(wire);
            assert!(
                decode(
                    &mut cursor,
                    &FORMAT,
                    rect(4, 4),
                    &mut fb,
                    &mut TightStreams::new()
                )
                .await
                .is_err(),
                "{actual} bytes for a 48-byte rectangle"
            );
        }
    }

    #[test]
    fn data_of_the_wrong_length_is_an_error_not_a_panic() {
        let mut fb = Framebuffer::new(4, 4);
        for filter in [
            Filter::Copy,
            Filter::Gradient,
            Filter::Palette(vec![[0; 4]; 2]),
            Filter::Palette(vec![[0; 4]; 200]),
        ] {
            for len in [0usize, 1, 15, 47, 49] {
                let _ = decode_pixels(&FORMAT, rect(4, 4), &mut fb, &filter, &vec![0; len]);
            }
        }
    }

    /// Every control byte must decode or error, never panic.
    #[tokio::test]
    async fn every_control_byte_is_handled() {
        for control in 0u8..=255 {
            for filter in 0u8..4 {
                let mut fb = Framebuffer::new(16, 16);
                let mut wire = vec![control, filter, 0x05];
                wire.extend(vec![0x5Au8; 1024]);
                let mut cursor = std::io::Cursor::new(wire);
                let _ = decode(
                    &mut cursor,
                    &FORMAT,
                    rect(16, 16),
                    &mut fb,
                    &mut TightStreams::new(),
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn an_empty_rectangle_still_consumes_its_bytes_and_applies_resets() {
        let mut fb = Framebuffer::new(4, 4);
        let mut streams = TightStreams::new();
        let empty = Rect::default();
        // An empty copy rectangle: no data at all.
        let mut wire = vec![0x00];
        // An empty fill: still a TPIXEL.
        wire.extend_from_slice(&[0x80, 1, 2, 3]);
        wire.push(0x80);
        wire.extend_from_slice(&[4, 5, 6]);
        let mut cursor = std::io::Cursor::new(wire);
        for _ in 0..3 {
            decode(&mut cursor, &FORMAT, empty, &mut fb, &mut streams)
                .await
                .unwrap();
        }
        assert_eq!(cursor.position() as usize, cursor.get_ref().len());
    }
}
