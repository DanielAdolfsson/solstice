//! RRE: a background colour plus a list of coloured sub-rectangles.

use solstice_backend::{Framebuffer, Rect};
use tokio::io::AsyncRead;

use super::{check_rect, read_exact};
use crate::pixel::PixelFormat;
use crate::protocol::{Result, RfbError};

/// Most sub-rectangles accepted in one RRE rectangle.
const MAX_SUBRECTS: u32 = 1 << 20;

/// Decode an RRE rectangle.
pub async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    format: &PixelFormat,
    rect: Rect,
    fb: &mut Framebuffer,
) -> Result<()> {
    check_rect(rect, fb)?;
    let bpp = format.bytes_per_pixel();
    let header = read_exact(reader, 4 + bpp).await?;
    let count = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if count > MAX_SUBRECTS {
        return Err(RfbError::Limit(format!("{count} RRE sub-rectangles")));
    }
    let background = format.to_bgra(&header[4..]);
    fb.fill(rect, background);

    let body = read_exact(reader, count as usize * (bpp + 8)).await?;
    for chunk in body.chunks_exact(bpp + 8) {
        let colour = format.to_bgra(&chunk[..bpp]);
        let sub = Rect {
            x: rect.x + u16::from_be_bytes([chunk[bpp], chunk[bpp + 1]]) as u32,
            y: rect.y + u16::from_be_bytes([chunk[bpp + 2], chunk[bpp + 3]]) as u32,
            width: u16::from_be_bytes([chunk[bpp + 4], chunk[bpp + 5]]) as u32,
            height: u16::from_be_bytes([chunk[bpp + 6], chunk[bpp + 7]]) as u32,
        };
        // A sub-rectangle that escapes its parent is a malformed update, not a
        // reason to paint outside it.
        if sub.right() > rect.right() || sub.bottom() > rect.bottom() {
            return Err(RfbError::Protocol(
                "RRE sub-rectangle escapes its parent".into(),
            ));
        }
        fb.fill(sub, colour);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rre_bytes(background: [u8; 4], subs: &[([u8; 4], u16, u16, u16, u16)]) -> Vec<u8> {
        let mut out = (subs.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&background);
        for (colour, x, y, w, h) in subs {
            out.extend_from_slice(colour);
            out.extend_from_slice(&x.to_be_bytes());
            out.extend_from_slice(&y.to_be_bytes());
            out.extend_from_slice(&w.to_be_bytes());
            out.extend_from_slice(&h.to_be_bytes());
        }
        out
    }

    #[tokio::test]
    async fn paints_background_then_sub_rectangles() {
        let mut fb = Framebuffer::new(16, 16);
        let rect = Rect {
            x: 0,
            y: 0,
            width: 16,
            height: 16,
        };
        let bytes = rre_bytes([9, 9, 9, 0], &[([1, 2, 3, 0], 2, 2, 4, 4)]);
        let mut cursor = std::io::Cursor::new(bytes);
        decode(&mut cursor, &PixelFormat::BGRA, rect, &mut fb)
            .await
            .unwrap();
        assert_eq!(fb.pixel(0, 0), Some([9, 9, 9, 255]));
        assert_eq!(fb.pixel(3, 3), Some([1, 2, 3, 255]));
        assert_eq!(fb.pixel(6, 6), Some([9, 9, 9, 255]));
    }

    #[tokio::test]
    async fn a_sub_rectangle_may_not_escape_its_parent() {
        let mut fb = Framebuffer::new(16, 16);
        let rect = Rect {
            x: 0,
            y: 0,
            width: 8,
            height: 8,
        };
        let bytes = rre_bytes([0, 0, 0, 0], &[([1, 1, 1, 0], 4, 4, 8, 8)]);
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(decode(&mut cursor, &PixelFormat::BGRA, rect, &mut fb)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn an_absurd_sub_rectangle_count_is_refused() {
        let mut fb = Framebuffer::new(16, 16);
        let mut bytes = u32::MAX.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let mut cursor = std::io::Cursor::new(bytes);
        let rect = Rect {
            x: 0,
            y: 0,
            width: 8,
            height: 8,
        };
        assert!(decode(&mut cursor, &PixelFormat::BGRA, rect, &mut fb)
            .await
            .is_err());
    }
}
