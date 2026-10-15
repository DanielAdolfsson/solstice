//! Raw: uncompressed pixels, row by row. Every server supports it.

use solstice_backend::{Framebuffer, Rect};
use tokio::io::AsyncRead;

use super::{check_rect, read_exact};
use crate::pixel::PixelFormat;
use crate::protocol::Result;

/// Decode a Raw rectangle.
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
    let row_bytes = rect.width as usize * format.bytes_per_pixel();
    let raw = read_exact(reader, row_bytes * rect.height as usize).await?;

    let mut bgra = Vec::with_capacity(rect.width as usize * rect.height as usize * 4);
    for row in raw.chunks_exact(row_bytes) {
        format.convert_run(row, &mut bgra);
    }
    fb.blit(rect, &bgra);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn decodes_native_bgra() {
        let mut fb = Framebuffer::new(4, 4);
        let rect = Rect {
            x: 1,
            y: 1,
            width: 2,
            height: 2,
        };
        let pixels: Vec<u8> = [10, 20, 30, 0].repeat(4);
        let mut cursor = std::io::Cursor::new(pixels);
        decode(&mut cursor, &PixelFormat::BGRA, rect, &mut fb)
            .await
            .unwrap();
        assert_eq!(fb.pixel(1, 1), Some([10, 20, 30, 255]));
        assert_eq!(fb.pixel(2, 2), Some([10, 20, 30, 255]));
        assert_eq!(fb.pixel(0, 0), Some([0, 0, 0, 255]));
    }

    #[tokio::test]
    async fn an_oversized_rectangle_is_refused_before_reading() {
        let mut fb = Framebuffer::new(4, 4);
        let mut cursor = std::io::Cursor::new(Vec::new());
        let rect = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
        };
        assert!(decode(&mut cursor, &PixelFormat::BGRA, rect, &mut fb)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_truncated_rectangle_is_an_error() {
        let mut fb = Framebuffer::new(4, 4);
        let mut cursor = std::io::Cursor::new(vec![0u8; 3]);
        let rect = Rect {
            x: 0,
            y: 0,
            width: 4,
            height: 4,
        };
        assert!(decode(&mut cursor, &PixelFormat::BGRA, rect, &mut fb)
            .await
            .is_err());
    }
}
