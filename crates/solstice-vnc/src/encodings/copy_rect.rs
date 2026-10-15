//! CopyRect: "this rectangle is already on screen, somewhere else."

use solstice_backend::{Framebuffer, Rect};
use tokio::io::AsyncRead;

use super::{check_rect, read_exact};
use crate::protocol::{Result, RfbError};

/// Decode a CopyRect rectangle.
pub async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    rect: Rect,
    fb: &mut Framebuffer,
) -> Result<()> {
    check_rect(rect, fb)?;
    let data = read_exact(reader, 4).await?;
    let src_x = u16::from_be_bytes([data[0], data[1]]) as u32;
    let src_y = u16::from_be_bytes([data[2], data[3]]) as u32;
    if !fb.copy_rect(rect, src_x, src_y) {
        return Err(RfbError::Protocol(format!(
            "CopyRect source {src_x},{src_y} is outside the framebuffer"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn copies_within_the_framebuffer() {
        let mut fb = Framebuffer::new(8, 8);
        fb.fill(
            Rect {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            },
            [1, 2, 3, 255],
        );
        let mut cursor = std::io::Cursor::new(vec![0, 0, 0, 0]); // source 0,0
        decode(
            &mut cursor,
            Rect {
                x: 4,
                y: 4,
                width: 2,
                height: 2,
            },
            &mut fb,
        )
        .await
        .unwrap();
        assert_eq!(fb.pixel(4, 4), Some([1, 2, 3, 255]));
        assert_eq!(fb.pixel(5, 5), Some([1, 2, 3, 255]));
    }

    /// The source coordinates come off the wire too.
    #[tokio::test]
    async fn a_source_outside_the_framebuffer_is_refused() {
        let mut fb = Framebuffer::new(8, 8);
        let mut cursor = std::io::Cursor::new(vec![0, 7, 0, 7]); // source 7,7
        assert!(decode(
            &mut cursor,
            Rect {
                x: 0,
                y: 0,
                width: 4,
                height: 4
            },
            &mut fb
        )
        .await
        .is_err());
    }
}
