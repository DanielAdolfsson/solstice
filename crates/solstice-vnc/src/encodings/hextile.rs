//! Hextile: 16x16 tiles, each either raw or a background plus sub-rectangles.
//!
//! The tile stream carries no overall length, so the only way to know where a
//! Hextile rectangle ends is to parse it. That is why these decoders read from
//! the connection rather than from a pre-read buffer.

use solstice_backend::{Framebuffer, Rect};
use tokio::io::AsyncRead;

use super::{check_rect, read_exact};
use crate::pixel::PixelFormat;
use crate::protocol::{Result, RfbError};

/// Tile subencoding bits (`rfbproto.rst`).
mod tile {
    pub const RAW: u8 = 0x01;
    pub const BACKGROUND_SPECIFIED: u8 = 0x02;
    pub const FOREGROUND_SPECIFIED: u8 = 0x04;
    pub const ANY_SUBRECTS: u8 = 0x08;
    pub const SUBRECTS_COLOURED: u8 = 0x10;
}

/// Decode a Hextile rectangle.
pub async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    format: &PixelFormat,
    rect: Rect,
    fb: &mut Framebuffer,
) -> Result<()> {
    check_rect(rect, fb)?;
    if rect.is_empty() {
        return Ok(());
    }
    let bpp = format.bytes_per_pixel();
    // Background and foreground persist across tiles unless a tile overrides
    // them; a first tile that relies on an unset one is malformed.
    let mut background: Option<[u8; 4]> = None;
    let mut foreground: Option<[u8; 4]> = None;

    let mut y = rect.y;
    while y < rect.bottom() {
        let tile_h = 16.min(rect.bottom() - y);
        let mut x = rect.x;
        while x < rect.right() {
            let tile_w = 16.min(rect.right() - x);
            let tile_rect = Rect {
                x,
                y,
                width: tile_w,
                height: tile_h,
            };
            let subencoding = read_exact(reader, 1).await?[0];

            if subencoding & tile::RAW != 0 {
                super::raw::decode(reader, format, tile_rect, fb).await?;
                // A raw tile leaves the running colours undefined.
                background = None;
                foreground = None;
                x += tile_w;
                continue;
            }

            if subencoding & tile::BACKGROUND_SPECIFIED != 0 {
                background = Some(format.to_bgra(&read_exact(reader, bpp).await?));
            }
            let bg = background
                .ok_or_else(|| RfbError::Protocol("hextile tile has no background".into()))?;
            fb.fill(tile_rect, bg);

            if subencoding & tile::FOREGROUND_SPECIFIED != 0 {
                foreground = Some(format.to_bgra(&read_exact(reader, bpp).await?));
            }
            if subencoding & tile::ANY_SUBRECTS == 0 {
                x += tile_w;
                continue;
            }

            let count = read_exact(reader, 1).await?[0] as usize;
            let coloured = subencoding & tile::SUBRECTS_COLOURED != 0;
            let stride = if coloured { bpp + 2 } else { 2 };
            let body = read_exact(reader, count * stride).await?;
            for chunk in body.chunks_exact(stride) {
                let (colour, pos) = if coloured {
                    (format.to_bgra(&chunk[..bpp]), &chunk[bpp..])
                } else {
                    (
                        foreground.ok_or_else(|| {
                            RfbError::Protocol("hextile sub-rectangle has no foreground".into())
                        })?,
                        chunk,
                    )
                };
                // Packed: x and y in the high and low nibbles of one byte, then
                // width-1 and height-1 the same way.
                let sx = (pos[0] >> 4) as u32;
                let sy = (pos[0] & 0x0F) as u32;
                let sw = (pos[1] >> 4) as u32 + 1;
                let sh = (pos[1] & 0x0F) as u32 + 1;
                if sx + sw > tile_w || sy + sh > tile_h {
                    return Err(RfbError::Protocol(
                        "hextile sub-rectangle escapes its tile".into(),
                    ));
                }
                fb.fill(
                    Rect {
                        x: x + sx,
                        y: y + sy,
                        width: sw,
                        height: sh,
                    },
                    colour,
                );
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

    #[tokio::test]
    async fn a_single_background_tile_fills_the_rectangle() {
        let mut fb = Framebuffer::new(16, 16);
        let bytes = {
            let mut v = vec![tile::BACKGROUND_SPECIFIED];
            v.extend_from_slice(&[7, 8, 9, 0]);
            v
        };
        let mut cursor = std::io::Cursor::new(bytes);
        decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 16,
                height: 16,
            },
            &mut fb,
        )
        .await
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([7, 8, 9, 255]));
        assert_eq!(fb.pixel(15, 15), Some([7, 8, 9, 255]));
    }

    #[tokio::test]
    async fn background_persists_across_tiles() {
        // 32x16 is two tiles; the second specifies nothing and must inherit.
        let mut fb = Framebuffer::new(32, 16);
        let mut bytes = vec![tile::BACKGROUND_SPECIFIED];
        bytes.extend_from_slice(&[1, 2, 3, 0]);
        bytes.push(0); // second tile: inherit everything
        let mut cursor = std::io::Cursor::new(bytes);
        decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 32,
                height: 16,
            },
            &mut fb,
        )
        .await
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([1, 2, 3, 255]));
        assert_eq!(fb.pixel(31, 15), Some([1, 2, 3, 255]));
    }

    #[tokio::test]
    async fn a_tile_with_no_background_at_all_is_an_error() {
        let mut fb = Framebuffer::new(16, 16);
        let mut cursor = std::io::Cursor::new(vec![0u8]);
        assert!(decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 16,
                height: 16
            },
            &mut fb
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn monochrome_sub_rectangles_use_the_running_foreground() {
        let mut fb = Framebuffer::new(16, 16);
        let mut bytes =
            vec![tile::BACKGROUND_SPECIFIED | tile::FOREGROUND_SPECIFIED | tile::ANY_SUBRECTS];
        bytes.extend_from_slice(&[0, 0, 0, 0]); // background
        bytes.extend_from_slice(&[255, 255, 255, 0]); // foreground
        bytes.push(1); // one sub-rectangle
        bytes.push(0x22); // x=2, y=2
        bytes.push(0x33); // w=4, h=4
        let mut cursor = std::io::Cursor::new(bytes);
        decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 16,
                height: 16,
            },
            &mut fb,
        )
        .await
        .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([0, 0, 0, 255]));
        assert_eq!(fb.pixel(3, 3), Some([255, 255, 255, 255]));
        assert_eq!(fb.pixel(6, 6), Some([0, 0, 0, 255]));
    }

    #[tokio::test]
    async fn coloured_sub_rectangles_carry_their_own_colour() {
        let mut fb = Framebuffer::new(16, 16);
        let mut bytes =
            vec![tile::BACKGROUND_SPECIFIED | tile::ANY_SUBRECTS | tile::SUBRECTS_COLOURED];
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.push(1);
        bytes.extend_from_slice(&[5, 6, 7, 0]);
        bytes.push(0x00);
        bytes.push(0x11); // 2x2 at 0,0
        let mut cursor = std::io::Cursor::new(bytes);
        decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 16,
                height: 16,
            },
            &mut fb,
        )
        .await
        .unwrap();
        assert_eq!(fb.pixel(1, 1), Some([5, 6, 7, 255]));
        assert_eq!(fb.pixel(2, 2), Some([0, 0, 0, 255]));
    }

    #[tokio::test]
    async fn a_sub_rectangle_may_not_escape_its_tile() {
        let mut fb = Framebuffer::new(16, 16);
        let mut bytes =
            vec![tile::BACKGROUND_SPECIFIED | tile::FOREGROUND_SPECIFIED | tile::ANY_SUBRECTS];
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(&[1, 1, 1, 0]);
        bytes.push(1);
        bytes.push(0xFF); // x=15, y=15
        bytes.push(0xFF); // w=16, h=16 -- runs off the tile
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 16,
                height: 16
            },
            &mut fb
        )
        .await
        .is_err());
    }

    /// A rectangle that is not a multiple of 16 has short tiles at its edges.
    #[tokio::test]
    async fn partial_tiles_at_the_edges_are_handled() {
        let mut fb = Framebuffer::new(20, 20);
        let mut bytes = Vec::new();
        for _ in 0..4 {
            bytes.push(tile::BACKGROUND_SPECIFIED);
            bytes.extend_from_slice(&[3, 3, 3, 0]);
        }
        let mut cursor = std::io::Cursor::new(bytes);
        decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 20,
                height: 20,
            },
            &mut fb,
        )
        .await
        .unwrap();
        assert_eq!(fb.pixel(19, 19), Some([3, 3, 3, 255]));
    }

    #[tokio::test]
    async fn a_raw_tile_is_decoded_inline() {
        let mut fb = Framebuffer::new(16, 16);
        let mut bytes = vec![tile::RAW];
        bytes.extend([4u8, 5, 6, 0].repeat(16 * 16));
        let mut cursor = std::io::Cursor::new(bytes);
        decode(
            &mut cursor,
            &PixelFormat::BGRA,
            Rect {
                x: 0,
                y: 0,
                width: 16,
                height: 16,
            },
            &mut fb,
        )
        .await
        .unwrap();
        assert_eq!(fb.pixel(8, 8), Some([4, 5, 6, 255]));
    }
}
