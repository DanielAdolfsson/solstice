//! The pointer, drawn here because Moonlight draws none.
//!
//! A server that sees the Cursor pseudo-encoding (−239) stops drawing the
//! pointer into the framebuffer and sends its shape instead, leaving the
//! client to draw it wherever the client's own pointer is. Moonlight has no
//! host cursor to show, so without this a VNC desktop streams with no pointer
//! at all (`docs/roadmap.md` §8).
//!
//! # Where it is drawn
//!
//! RFB says nothing about where the pointer is; the client is meant to know.
//! Here that is the position Moonlight last sent, in framebuffer coordinates,
//! which is the same position the input encoder sends to the server
//! (`crate::input`). Until the first pointer event nothing is drawn, rather
//! than guessing.
//!
//! # How it is drawn
//!
//! The update loop decodes into a private surface and publishes damaged
//! regions into the shared framebuffer (`crate::session`), so decoding --
//! CopyRect in particular -- only ever sees clean pixels. The pointer is
//! composited at publication, with the pixels under it saved so that moving
//! it can put them back. Every write to the shared framebuffer goes through
//! [`Pointer`], under its lock and then the framebuffer's, so the saved pixels
//! are never stale.
//!
//! # The format
//!
//! The pseudo-rectangle's position is the hot spot and its size the shape's.
//! The body is `width * height` pixels in the connection's pixel format, then
//! a 1-bit mask, rows padded to a byte, most significant bit first, set where
//! the shape is opaque. A 0 x 0 shape means no pointer.

use std::sync::Arc;

use solstice_backend::{Framebuffer, Rect};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::encodings::read_exact;
use crate::pixel::PixelFormat;
use crate::protocol::{RectHeader, Result};

/// The largest shape this client will draw.
///
/// The header allows 65535 x 65535, which would be 17 GB before the mask.
/// Real cursors are 32 x 32 or 64 x 64; a larger one is read past and the
/// pointer hidden, rather than allocated or treated as an error.
pub const MAX_CURSOR_DIMENSION: u16 = 256;

/// A pointer shape: BGRA, alpha 0 or 255 from the mask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorShape {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Where the hot spot sits inside the shape.
    pub hot_x: u32,
    /// Where the hot spot sits inside the shape.
    pub hot_y: u32,
    /// `width * height` BGRA pixels, top row first.
    pub data: Vec<u8>,
}

/// Read a Cursor pseudo-rectangle's body. `None` means no pointer: a 0 x 0
/// shape, or one too large to draw.
pub async fn decode<R: AsyncRead + Unpin>(
    reader: &mut R,
    format: &PixelFormat,
    header: &RectHeader,
) -> Result<Option<CursorShape>> {
    let (width, height) = (header.width as usize, header.height as usize);
    let pixel_bytes = width * height * format.bytes_per_pixel();
    let mask_row = width.div_ceil(8);
    let mask_bytes = mask_row * height;
    if width == 0 || height == 0 {
        return Ok(None);
    }
    if header.width > MAX_CURSOR_DIMENSION || header.height > MAX_CURSOR_DIMENSION {
        tracing::warn!(
            width,
            height,
            "the server sent a cursor too large to draw; hiding the pointer"
        );
        let skip = (pixel_bytes + mask_bytes) as u64;
        let skipped =
            tokio::io::copy(&mut (&mut *reader).take(skip), &mut tokio::io::sink()).await?;
        if skipped < skip {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        return Ok(None);
    }

    let pixels = read_exact(reader, pixel_bytes).await?;
    let mask = read_exact(reader, mask_bytes).await?;
    let mut data = Vec::with_capacity(width * height * 4);
    format.convert_run(&pixels, &mut data);
    for y in 0..height {
        for x in 0..width {
            let opaque = mask[y * mask_row + x / 8] & (0x80 >> (x % 8)) != 0;
            data[(y * width + x) * 4 + 3] = if opaque { 0xFF } else { 0 };
        }
    }
    Ok(Some(CursorShape {
        width: width as u32,
        height: height as u32,
        // The hot spot is meant to lie inside the shape; clamped so that a
        // server that disagrees cannot push the drawing arbitrarily far off.
        hot_x: (header.x as u32).min(width as u32 - 1),
        hot_y: (header.y as u32).min(height as u32 - 1),
        data,
    }))
}

/// Where the pointer was drawn, and the clean pixels it covers.
#[derive(Debug)]
struct Drawn {
    rect: Rect,
    under: Vec<u8>,
}

/// The pointer's shape and position, and what drawing it covered.
///
/// Shared between the update loop, which publishes into the framebuffer, and
/// the session, which moves the pointer when input arrives. Lock it before
/// the framebuffer, never after.
#[derive(Debug, Default)]
pub struct Pointer {
    shape: Option<Arc<CursorShape>>,
    position: Option<(u32, u32)>,
    drawn: Option<Drawn>,
}

impl Pointer {
    /// Copy `rect` of the clean surface into the framebuffer and draw the
    /// pointer back over it. The damage is `rect`: outside it, the pointer is
    /// redrawn exactly where it was.
    pub fn publish(&mut self, fb: &mut Framebuffer, surface: &Framebuffer, rect: Rect) {
        self.erase(fb);
        fb.copy_from(surface, rect);
        self.draw(fb);
    }

    /// Move the hot spot. Returns the region that changed, if any.
    pub fn move_to(&mut self, fb: &mut Framebuffer, x: u32, y: u32) -> Option<Rect> {
        if self.position == Some((x, y)) {
            return None;
        }
        self.position = Some((x, y));
        self.redraw(fb)
    }

    /// Replace the shape, `None` hiding the pointer. Returns the region that
    /// changed, if any.
    pub fn set_shape(&mut self, fb: &mut Framebuffer, shape: Option<CursorShape>) -> Option<Rect> {
        self.shape = shape.map(Arc::new);
        self.redraw(fb)
    }

    /// The framebuffer was reallocated, so nothing is drawn on it any more and
    /// the saved pixels describe a buffer that is gone.
    pub fn forget_drawn(&mut self) {
        self.drawn = None;
    }

    /// Where the pointer is drawn now, if anywhere.
    pub fn drawn_rect(&self) -> Option<Rect> {
        self.drawn.as_ref().map(|d| d.rect)
    }

    fn redraw(&mut self, fb: &mut Framebuffer) -> Option<Rect> {
        let old = self.erase(fb);
        let new = self.draw(fb);
        match (old, new) {
            (Some(a), Some(b)) => Some(a.union(&b)),
            (a, b) => a.or(b),
        }
    }

    /// Put back what the pointer covered.
    fn erase(&mut self, fb: &mut Framebuffer) -> Option<Rect> {
        let drawn = self.drawn.take()?;
        fb.blit(drawn.rect, &drawn.under);
        Some(drawn.rect)
    }

    /// Save what is under the pointer's position, then draw it there.
    fn draw(&mut self, fb: &mut Framebuffer) -> Option<Rect> {
        debug_assert!(self.drawn.is_none(), "drawn twice without an erase");
        let shape = self.shape.as_ref()?;
        let (x, y) = self.position?;
        // Clip in signed arithmetic: the hot spot puts the shape's corner
        // above or left of the framebuffer whenever the pointer is near it.
        let left = x as i64 - shape.hot_x as i64;
        let top = y as i64 - shape.hot_y as i64;
        let x0 = left.max(0);
        let y0 = top.max(0);
        let x1 = (left + shape.width as i64).min(fb.width() as i64);
        let y1 = (top + shape.height as i64).min(fb.height() as i64);
        if x0 >= x1 || y0 >= y1 {
            return None;
        }
        let rect = Rect {
            x: x0 as u32,
            y: y0 as u32,
            width: (x1 - x0) as u32,
            height: (y1 - y0) as u32,
        };

        let stride = fb.stride();
        let row_bytes = rect.width as usize * 4;
        let mut under = Vec::with_capacity(row_bytes * rect.height as usize);
        let data = fb.data_mut();
        for row in 0..rect.height as usize {
            let fy = rect.y as usize + row;
            let off = fy * stride + rect.x as usize * 4;
            under.extend_from_slice(&data[off..off + row_bytes]);
            let sy = (fy as i64 - top) as usize;
            for col in 0..rect.width as usize {
                let fx = rect.x as usize + col;
                let sx = (fx as i64 - left) as usize;
                let s = (sy * shape.width as usize + sx) * 4;
                if shape.data[s + 3] != 0 {
                    let d = fy * stride + fx * 4;
                    data[d..d + 3].copy_from_slice(&shape.data[s..s + 3]);
                }
            }
        }
        self.drawn = Some(Drawn { rect, under });
        Some(rect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::encoding;

    const RED: [u8; 4] = [0, 0, 255, 255];
    const GREY: [u8; 4] = [80, 80, 80, 255];

    /// A 3 x 2 shape, hot spot (1, 0): red where opaque, the middle column of
    /// the top row transparent.
    fn shape() -> CursorShape {
        let mut data = RED.repeat(6);
        data[4 + 3] = 0;
        CursorShape {
            width: 3,
            height: 2,
            hot_x: 1,
            hot_y: 0,
            data,
        }
    }

    fn surface() -> Framebuffer {
        let mut fb = Framebuffer::new(8, 8);
        fb.fill(Rect::whole(8, 8), GREY);
        fb
    }

    #[tokio::test]
    async fn the_mask_decides_what_is_opaque() {
        let header = RectHeader {
            x: 1,
            y: 0,
            width: 3,
            height: 2,
            encoding: encoding::PSEUDO_CURSOR,
        };
        let mut body = [10u8, 20, 30, 0].repeat(6);
        // Rows padded to a byte, MSB first: 101 and 011.
        body.extend_from_slice(&[0b1010_0000, 0b0110_0000]);
        let shape = decode(&mut std::io::Cursor::new(body), &PixelFormat::BGRA, &header)
            .await
            .unwrap()
            .unwrap();
        let alpha: Vec<u8> = shape.data.chunks(4).map(|p| p[3]).collect();
        assert_eq!(alpha, [255, 0, 255, 0, 255, 255]);
        assert_eq!(&shape.data[..3], &[10, 20, 30]);
        assert_eq!((shape.hot_x, shape.hot_y), (1, 0));
    }

    #[tokio::test]
    async fn an_empty_shape_is_no_pointer_and_an_oversized_one_is_read_past() {
        let empty = RectHeader {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            encoding: encoding::PSEUDO_CURSOR,
        };
        let mut reader = std::io::Cursor::new(vec![]);
        assert_eq!(
            decode(&mut reader, &PixelFormat::BGRA, &empty)
                .await
                .unwrap(),
            None
        );

        let huge = RectHeader {
            width: 300,
            height: 2,
            ..empty
        };
        let body_len = 300 * 2 * 4 + 38 * 2;
        let mut body = vec![0u8; body_len];
        body.push(0xAB); // the next message's first byte
        let mut reader = std::io::Cursor::new(body);
        assert_eq!(
            decode(&mut reader, &PixelFormat::BGRA, &huge)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            reader.position(),
            body_len as u64,
            "the stream stays in step"
        );
    }

    #[test]
    fn nothing_is_drawn_until_the_client_has_said_where_the_pointer_is() {
        let clean = surface();
        let mut fb = clean.clone();
        let mut pointer = Pointer::default();
        assert_eq!(pointer.set_shape(&mut fb, Some(shape())), None);
        assert_eq!(fb.data(), clean.data());

        let changed = pointer.move_to(&mut fb, 4, 4).unwrap();
        assert_eq!(
            changed,
            Rect {
                x: 3,
                y: 4,
                width: 3,
                height: 2
            }
        );
        assert_eq!(fb.pixel(3, 4), Some(RED));
        assert_eq!(
            fb.pixel(4, 4),
            Some(GREY),
            "transparent where the mask is clear"
        );
        assert_eq!(fb.pixel(4, 5), Some(RED));
    }

    #[test]
    fn moving_the_pointer_puts_back_what_it_covered() {
        let clean = surface();
        let mut fb = clean.clone();
        let mut pointer = Pointer::default();
        pointer.set_shape(&mut fb, Some(shape()));
        pointer.move_to(&mut fb, 2, 2);
        let changed = pointer.move_to(&mut fb, 6, 6).unwrap();
        assert_eq!(
            changed,
            Rect {
                x: 1,
                y: 2,
                width: 7,
                height: 6
            }
        );
        assert_eq!(fb.pixel(1, 2), Some(GREY));
        assert_eq!(fb.pixel(5, 6), Some(RED));

        pointer.set_shape(&mut fb, None);
        assert_eq!(
            fb.data(),
            clean.data(),
            "hiding it leaves the clean surface"
        );
    }

    /// The pixels saved under the pointer must be the newest ones, or moving it
    /// would paint an old frame back.
    #[test]
    fn an_update_under_the_pointer_is_what_moving_it_reveals() {
        let mut surface = surface();
        let mut fb = surface.clone();
        let mut pointer = Pointer::default();
        pointer.set_shape(&mut fb, Some(shape()));
        pointer.move_to(&mut fb, 4, 4);

        let blue = [255, 0, 0, 255];
        let rect = Rect {
            x: 2,
            y: 3,
            width: 4,
            height: 3,
        };
        surface.fill(rect, blue);
        pointer.publish(&mut fb, &surface, rect);
        assert_eq!(fb.pixel(3, 4), Some(RED), "still drawn over the update");
        assert_eq!(fb.pixel(4, 4), Some(blue));

        pointer.move_to(&mut fb, 0, 0);
        pointer.set_shape(&mut fb, None);
        assert_eq!(fb.data(), surface.data());
    }

    #[test]
    fn a_pointer_at_the_edge_is_clipped() {
        let clean = surface();
        let mut fb = clean.clone();
        let mut pointer = Pointer::default();
        pointer.set_shape(&mut fb, Some(shape()));
        // The hot spot is one pixel in, so the shape starts left of the edge.
        let changed = pointer.move_to(&mut fb, 0, 7).unwrap();
        assert_eq!(
            changed,
            Rect {
                x: 0,
                y: 7,
                width: 2,
                height: 1
            }
        );
        pointer.move_to(&mut fb, 3, 3);
        pointer.set_shape(&mut fb, None);
        assert_eq!(fb.data(), clean.data());
    }

    #[test]
    fn a_reallocated_framebuffer_is_not_painted_with_the_old_ones_pixels() {
        let mut fb = surface();
        let mut pointer = Pointer::default();
        pointer.set_shape(&mut fb, Some(shape()));
        pointer.move_to(&mut fb, 4, 4);

        fb.resize(16, 16);
        pointer.forget_drawn();
        let fresh = fb.clone();
        let changed = pointer.move_to(&mut fb, 10, 10).unwrap();
        assert_eq!(changed.x, 9, "only the new position, nothing restored");
        assert_eq!(fb.pixel(3, 4), fresh.pixel(3, 4));
    }
}
