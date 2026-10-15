//! ZRLE: zlib run-length encoding over 64x64 tiles.
//!
//! The zlib stream is **continuous for the life of the connection**, not
//! per-rectangle: the deflate window carries across rectangles and across
//! updates, so the decompressor is owned by the session and passed in here. A
//! decoder that created a fresh one per rectangle would work against the first
//! update and produce garbage from the second.
//!
//! Pixels inside the zlib stream are CPIXELs: when the format is 32-bit with
//! depth 24 or less and the top byte is unused, only the three significant
//! bytes are sent.

use flate2::{Decompress, FlushDecompress, Status};
use solstice_backend::{Framebuffer, Rect};
use tokio::io::AsyncRead;

use super::{check_rect, read_exact};
use crate::pixel::PixelFormat;
use crate::protocol::{Result, RfbError};

/// Tile side length.
const TILE: u32 = 64;
/// Cap on what one rectangle may inflate to, so a decompression bomb cannot
/// exhaust memory (`docs/security.md` §5.4).
const MAX_INFLATED: usize = 64 * 1024 * 1024;

/// A connection-lifetime zlib stream.
pub struct ZlibStream {
    decompress: Decompress,
}

impl std::fmt::Debug for ZlibStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZlibStream")
            .field("total_out", &self.decompress.total_out())
            .finish()
    }
}

impl Default for ZlibStream {
    fn default() -> Self {
        Self::new()
    }
}

impl ZlibStream {
    /// Start a stream.
    pub fn new() -> Self {
        Self {
            decompress: Decompress::new(true),
        }
    }

    /// Inflate one chunk, continuing the stream.
    pub fn inflate(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len() * 4);
        let mut consumed = 0usize;
        let mut scratch = vec![0u8; 64 * 1024];
        loop {
            let before_in = self.decompress.total_in();
            let before_out = self.decompress.total_out();
            let status = self
                .decompress
                .decompress(&input[consumed..], &mut scratch, FlushDecompress::None)
                .map_err(|e| RfbError::Protocol(format!("zlib: {e}")))?;
            let read = (self.decompress.total_in() - before_in) as usize;
            let written = (self.decompress.total_out() - before_out) as usize;
            consumed += read;
            out.extend_from_slice(&scratch[..written]);
            if out.len() > MAX_INFLATED {
                return Err(RfbError::Limit(
                    "ZRLE rectangle inflated past the cap".into(),
                ));
            }
            match status {
                Status::StreamEnd => break,
                _ if consumed == input.len() && written == 0 => break,
                _ if read == 0 && written == 0 => break,
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Size of a CPIXEL for this format.
pub fn cpixel_size(format: &PixelFormat) -> usize {
    if format.bits_per_pixel == 32
        && format.depth <= 24
        && format.red_shift < 24
        && format.green_shift < 24
        && format.blue_shift < 24
    {
        3
    } else {
        format.bytes_per_pixel()
    }
}

fn read_cpixel(format: &PixelFormat, bytes: &[u8]) -> [u8; 4] {
    if cpixel_size(format) == 3 && format.bits_per_pixel == 32 {
        // The three significant bytes, in the same byte order as a full pixel.
        let mut full = [0u8; 4];
        if format.big_endian {
            full[1..4].copy_from_slice(&bytes[..3]);
        } else {
            full[0..3].copy_from_slice(&bytes[..3]);
        }
        format.to_bgra(&full)
    } else {
        format.to_bgra(bytes)
    }
}

/// Decode a ZRLE rectangle.
pub async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    format: &PixelFormat,
    rect: Rect,
    fb: &mut Framebuffer,
    zlib: &mut ZlibStream,
) -> Result<()> {
    check_rect(rect, fb)?;
    let len_bytes = read_exact(reader, 4).await?;
    let length = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    let compressed = read_exact(reader, length as usize).await?;
    if rect.is_empty() {
        // Still consume the stream: the zlib window must stay in step.
        zlib.inflate(&compressed)?;
        return Ok(());
    }
    let data = zlib.inflate(&compressed)?;
    decode_tiles(format, rect, fb, &data)
}

/// Decode the inflated tile stream. Separated out so it can be tested without
/// a zlib round trip.
pub fn decode_tiles(
    format: &PixelFormat,
    rect: Rect,
    fb: &mut Framebuffer,
    data: &[u8],
) -> Result<()> {
    let cpixel = cpixel_size(format);
    let mut pos = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        if pos + n > data.len() {
            return Err(RfbError::Protocol("ZRLE tile stream is truncated".into()));
        }
        let out = &data[pos..pos + n];
        pos += n;
        Ok(out)
    };

    let mut y = rect.y;
    while y < rect.bottom() {
        let tile_h = TILE.min(rect.bottom() - y);
        let mut x = rect.x;
        while x < rect.right() {
            let tile_w = TILE.min(rect.right() - x);
            let tile_rect = Rect {
                x,
                y,
                width: tile_w,
                height: tile_h,
            };
            let pixels = tile_w as usize * tile_h as usize;
            let subencoding = take(1)?[0];
            let run_length_encoded = subencoding & 0x80 != 0;
            let palette_size = (subencoding & 0x7F) as usize;

            let mut bgra = Vec::with_capacity(pixels * 4);
            match (run_length_encoded, palette_size) {
                // Raw CPIXELs.
                (false, 0) => {
                    let raw = take(pixels * cpixel)?;
                    for chunk in raw.chunks_exact(cpixel) {
                        bgra.extend_from_slice(&read_cpixel(format, chunk));
                    }
                }
                // A solid tile.
                (false, 1) => {
                    let colour = read_cpixel(format, take(cpixel)?);
                    fb.fill(tile_rect, colour);
                    x += tile_w;
                    continue;
                }
                // Packed palette.
                (false, n) => {
                    let palette: Vec<[u8; 4]> = take(n * cpixel)?
                        .chunks_exact(cpixel)
                        .map(|c| read_cpixel(format, c))
                        .collect();
                    let bits = match n {
                        2 => 1,
                        3..=4 => 2,
                        5..=16 => 4,
                        _ => return Err(RfbError::Protocol(format!("ZRLE palette of {n}"))),
                    };
                    let row_bytes = (tile_w as usize * bits).div_ceil(8);
                    let packed = take(row_bytes * tile_h as usize)?;
                    for row in 0..tile_h as usize {
                        let row_data = &packed[row * row_bytes..(row + 1) * row_bytes];
                        for col in 0..tile_w as usize {
                            let bit_index = col * bits;
                            let byte = row_data[bit_index / 8];
                            let shift = 8 - bits - (bit_index % 8);
                            let index = ((byte >> shift) as usize) & ((1 << bits) - 1);
                            let colour = palette.get(index).copied().ok_or_else(|| {
                                RfbError::Protocol("ZRLE palette index out of range".into())
                            })?;
                            bgra.extend_from_slice(&colour);
                        }
                    }
                }
                // Plain RLE.
                (true, 0) => {
                    let mut written = 0usize;
                    while written < pixels {
                        let colour = read_cpixel(format, take(cpixel)?);
                        let mut run = 1usize;
                        loop {
                            let byte = take(1)?[0];
                            run += byte as usize;
                            if byte != 255 {
                                break;
                            }
                        }
                        if written + run > pixels {
                            return Err(RfbError::Protocol("ZRLE run overruns its tile".into()));
                        }
                        for _ in 0..run {
                            bgra.extend_from_slice(&colour);
                        }
                        written += run;
                    }
                }
                // Palette RLE. Subencoding 129 is unused in the specification,
                // so a palette of one here is malformed rather than a solid
                // tile -- and `palette_size` is already the low seven bits, so
                // there is nothing to subtract.
                (true, 1) => {
                    return Err(RfbError::Protocol("ZRLE subencoding 129 is unused".into()))
                }
                (true, n) => {
                    let palette: Vec<[u8; 4]> = take(n * cpixel)?
                        .chunks_exact(cpixel)
                        .map(|c| read_cpixel(format, c))
                        .collect();
                    let mut written = 0usize;
                    while written < pixels {
                        let byte = take(1)?[0];
                        let index = (byte & 0x7F) as usize;
                        let colour = palette.get(index).copied().ok_or_else(|| {
                            RfbError::Protocol("ZRLE palette index out of range".into())
                        })?;
                        let mut run = 1usize;
                        if byte & 0x80 != 0 {
                            loop {
                                let more = take(1)?[0];
                                run += more as usize;
                                if more != 255 {
                                    break;
                                }
                            }
                        }
                        if written + run > pixels {
                            return Err(RfbError::Protocol("ZRLE run overruns its tile".into()));
                        }
                        for _ in 0..run {
                            bgra.extend_from_slice(&colour);
                        }
                        written += run;
                    }
                }
            }
            if !fb.blit(tile_rect, &bgra) {
                return Err(RfbError::Protocol("ZRLE tile does not fit".into()));
            }
            x += tile_w;
        }
        y += tile_h;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn cpixel_is_three_bytes_for_the_requested_format() {
        assert_eq!(cpixel_size(&PixelFormat::BGRA), 3);
        let wide = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            ..PixelFormat::BGRA
        };
        assert_eq!(cpixel_size(&wide), 2);
    }

    #[test]
    fn a_solid_tile_fills_it() {
        let mut fb = Framebuffer::new(64, 64);
        let data = vec![1u8, 11, 22, 33]; // subencoding 1, then one CPIXEL
        decode_tiles(
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 64,
                height: 64,
            },
            &mut fb,
            &data,
        )
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([11, 22, 33, 255]));
        assert_eq!(fb.pixel(63, 63), Some([11, 22, 33, 255]));
    }

    #[test]
    fn a_raw_tile_decodes() {
        let mut fb = Framebuffer::new(2, 2);
        let mut data = vec![0u8]; // raw
        for i in 0..4u8 {
            data.extend_from_slice(&[i, i + 1, i + 2]);
        }
        decode_tiles(
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            &mut fb,
            &data,
        )
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([0, 1, 2, 255]));
        assert_eq!(fb.pixel(1, 1), Some([3, 4, 5, 255]));
    }

    #[test]
    fn plain_rle_expands_runs() {
        let mut fb = Framebuffer::new(2, 2);
        // subencoding 128, colour, run length byte 3 => run of 4 pixels
        let data = vec![128u8, 9, 9, 9, 3];
        decode_tiles(
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            &mut fb,
            &data,
        )
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([9, 9, 9, 255]));
        assert_eq!(fb.pixel(1, 1), Some([9, 9, 9, 255]));
    }

    #[test]
    fn a_packed_palette_tile_decodes() {
        let mut fb = Framebuffer::new(2, 2);
        // Palette of 2, 1 bit per pixel: pixels 0,1 / 1,0
        let mut data = vec![2u8];
        data.extend_from_slice(&[0, 0, 0]); // index 0 = black
        data.extend_from_slice(&[255, 255, 255]); // index 1 = white
        data.push(0b0100_0000); // row 0: 0,1
        data.push(0b1000_0000); // row 1: 1,0
        decode_tiles(
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            &mut fb,
            &data,
        )
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([0, 0, 0, 255]));
        assert_eq!(fb.pixel(1, 0), Some([255, 255, 255, 255]));
        assert_eq!(fb.pixel(0, 1), Some([255, 255, 255, 255]));
        assert_eq!(fb.pixel(1, 1), Some([0, 0, 0, 255]));
    }

    /// Found by `cargo fuzz run rfb_rect`: the palette-RLE branch subtracted
    /// 128 from a value that was already masked to seven bits, so every
    /// palette-RLE tile underflowed and panicked. The subencoding byte comes
    /// straight off the wire, which made this reachable from any server.
    #[test]
    fn palette_rle_tiles_decode_rather_than_underflowing() {
        let mut fb = Framebuffer::new(2, 2);
        // Subencoding 130: palette RLE with a palette of two.
        let mut data = vec![130u8];
        data.extend_from_slice(&[0, 0, 0]); // index 0
        data.extend_from_slice(&[255, 255, 255]); // index 1
        data.push(0x80); // index 0, run follows
        data.push(1); // run of 2
        data.push(0x81); // index 1, run follows
        data.push(1); // run of 2
        decode_tiles(
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            &mut fb,
            &data,
        )
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([0, 0, 0, 255]));
        assert_eq!(fb.pixel(1, 1), Some([255, 255, 255, 255]));
    }

    #[test]
    fn the_unused_subencoding_129_is_refused() {
        let mut fb = Framebuffer::new(2, 2);
        assert!(decode_tiles(
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2
            },
            &mut fb,
            &[129u8, 0, 0, 0, 0]
        )
        .is_err());
    }

    /// Every subencoding byte must decode or error, never panic.
    #[test]
    fn every_subencoding_byte_is_handled() {
        for subencoding in 0u8..=255 {
            let mut fb = Framebuffer::new(64, 64);
            let mut data = vec![subencoding];
            data.extend(vec![0x5Au8; 4096]);
            let _ = decode_tiles(
                &PixelFormat::BGRA,
                Rect {
                    x: 0,
                    y: 0,
                    width: 64,
                    height: 64,
                },
                &mut fb,
                &data,
            );
        }
    }

    #[test]
    fn a_truncated_tile_stream_is_an_error() {
        let mut fb = Framebuffer::new(64, 64);
        assert!(decode_tiles(
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 64,
                height: 64
            },
            &mut fb,
            &[1u8, 11]
        )
        .is_err());
    }

    #[test]
    fn a_run_that_overruns_its_tile_is_an_error() {
        let mut fb = Framebuffer::new(2, 2);
        let data = vec![128u8, 9, 9, 9, 200];
        assert!(decode_tiles(
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2
            },
            &mut fb,
            &data
        )
        .is_err());
    }

    /// The zlib window carries across rectangles; a decoder that restarted it
    /// would work once and then produce garbage.
    #[tokio::test]
    async fn the_zlib_stream_is_continuous_across_rectangles() {
        let mut fb = Framebuffer::new(64, 128);
        let mut zlib = ZlibStream::new();

        // One zlib stream, two rectangles' worth of tiles, flushed separately.
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[1u8, 1, 2, 3]).unwrap();
        let first = encoder.flush_finish().unwrap();

        let mut wire = (first.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&first);
        let mut cursor = std::io::Cursor::new(wire);
        decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 64,
                height: 64,
            },
            &mut fb,
            &mut zlib,
        )
        .await
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([1, 2, 3, 255]));
    }

    #[tokio::test]
    async fn an_inflating_bomb_is_refused() {
        let mut zlib = ZlibStream::new();
        // 128 MB of zeroes compresses to a few hundred bytes.
        let bomb = deflate(&vec![0u8; 128 * 1024 * 1024]);
        assert!(zlib.inflate(&bomb).is_err());
    }
}
