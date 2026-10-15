//! The composited framebuffer the encoder reads from.

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// A rectangle in framebuffer coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    /// Left edge.
    pub x: u32,
    /// Top edge.
    pub y: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl Rect {
    /// A rectangle covering a whole `width` x `height` framebuffer.
    pub const fn whole(width: u32, height: u32) -> Self {
        Self {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    /// Whether the rectangle has any area.
    pub const fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// The right edge, exclusive.
    pub const fn right(&self) -> u32 {
        self.x + self.width
    }

    /// The bottom edge, exclusive.
    pub const fn bottom(&self) -> u32 {
        self.y + self.height
    }

    /// Whether this rectangle fits inside a `width` x `height` framebuffer.
    ///
    /// Backends must check this before blitting: the rectangle comes off the
    /// wire and a server that lies about it would otherwise walk off the end of
    /// the buffer (`docs/security.md` §5.4).
    pub const fn fits_in(&self, width: u32, height: u32) -> bool {
        self.right() <= width && self.bottom() <= height
    }

    /// The smallest rectangle containing both inputs.
    pub fn union(&self, other: &Rect) -> Rect {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        Rect {
            x,
            y,
            width: self.right().max(other.right()) - x,
            height: self.bottom().max(other.bottom()) - y,
        }
    }
}

/// The pixel layout of a [`Framebuffer`].
///
/// Only one layout exists for now: the encoder wants a single predictable
/// input, so backends convert on the way in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PixelFormat {
    /// 32 bits per pixel, byte order B, G, R, A.
    Bgra8888,
}

impl PixelFormat {
    /// Bytes per pixel.
    pub const fn bytes_per_pixel(&self) -> usize {
        match self {
            PixelFormat::Bgra8888 => 4,
        }
    }
}

/// A BGRA framebuffer owned by a backend session.
#[derive(Clone, Debug)]
pub struct Framebuffer {
    width: u32,
    height: u32,
    format: PixelFormat,
    data: Vec<u8>,
}

impl Framebuffer {
    /// Allocate a black framebuffer.
    pub fn new(width: u32, height: u32) -> Self {
        let format = PixelFormat::Bgra8888;
        let len = width as usize * height as usize * format.bytes_per_pixel();
        let mut data = vec![0u8; len];
        // Opaque black rather than transparent black: alpha is ignored by the
        // colour conversion, but a debugger dumping the buffer should see an
        // image, not a blank.
        for px in data.chunks_exact_mut(4) {
            px[3] = 0xFF;
        }
        Self {
            width,
            height,
            format,
            data,
        }
    }

    /// Width in pixels.
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Height in pixels.
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Pixel layout.
    pub const fn format(&self) -> PixelFormat {
        self.format
    }

    /// Bytes per row.
    pub const fn stride(&self) -> usize {
        self.width as usize * 4
    }

    /// The raw pixels.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The raw pixels, mutably.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Resize, discarding the contents.
    pub fn resize(&mut self, width: u32, height: u32) {
        *self = Framebuffer::new(width, height);
    }

    /// Copy `src` -- tightly packed BGRA, `rect.width * rect.height` pixels --
    /// into `rect`.
    ///
    /// Returns `false` without touching the framebuffer if the rectangle does
    /// not fit or `src` is the wrong length.
    pub fn blit(&mut self, rect: Rect, src: &[u8]) -> bool {
        if !rect.fits_in(self.width, self.height) {
            return false;
        }
        let row_bytes = rect.width as usize * 4;
        if src.len() != row_bytes * rect.height as usize {
            return false;
        }
        let stride = self.stride();
        for row in 0..rect.height as usize {
            let dst_off = (rect.y as usize + row) * stride + rect.x as usize * 4;
            let src_off = row * row_bytes;
            self.data[dst_off..dst_off + row_bytes]
                .copy_from_slice(&src[src_off..src_off + row_bytes]);
        }
        true
    }

    /// Copy a rectangle from elsewhere in the same framebuffer (RFB CopyRect).
    ///
    /// Overlapping source and destination are handled correctly.
    pub fn copy_rect(&mut self, dst: Rect, src_x: u32, src_y: u32) -> bool {
        let src = Rect {
            x: src_x,
            y: src_y,
            width: dst.width,
            height: dst.height,
        };
        if !dst.fits_in(self.width, self.height) || !src.fits_in(self.width, self.height) {
            return false;
        }
        let stride = self.stride();
        let row_bytes = dst.width as usize * 4;
        let rows: Box<dyn Iterator<Item = usize>> = if src_y < dst.y {
            Box::new((0..dst.height as usize).rev())
        } else {
            Box::new(0..dst.height as usize)
        };
        for row in rows {
            let s = (src_y as usize + row) * stride + src_x as usize * 4;
            let d = (dst.y as usize + row) * stride + dst.x as usize * 4;
            self.data.copy_within(s..s + row_bytes, d);
        }
        true
    }

    /// Copy `rect` out of another framebuffer of the same geometry.
    ///
    /// Used to publish a decoded region from a scratch buffer into the shared
    /// one without holding the lock across the decode.
    pub fn copy_from(&mut self, src: &Framebuffer, rect: Rect) -> bool {
        if !rect.fits_in(self.width, self.height) || !rect.fits_in(src.width, src.height) {
            return false;
        }
        let row_bytes = rect.width as usize * 4;
        let dst_stride = self.stride();
        let src_stride = src.stride();
        for row in 0..rect.height as usize {
            let d = (rect.y as usize + row) * dst_stride + rect.x as usize * 4;
            let s = (rect.y as usize + row) * src_stride + rect.x as usize * 4;
            self.data[d..d + row_bytes].copy_from_slice(&src.data[s..s + row_bytes]);
        }
        true
    }

    /// Fill a rectangle with one BGRA colour.
    pub fn fill(&mut self, rect: Rect, colour: [u8; 4]) -> bool {
        if !rect.fits_in(self.width, self.height) {
            return false;
        }
        let stride = self.stride();
        for row in 0..rect.height as usize {
            let off = (rect.y as usize + row) * stride + rect.x as usize * 4;
            for px in self.data[off..off + rect.width as usize * 4].chunks_exact_mut(4) {
                px.copy_from_slice(&colour);
            }
        }
        true
    }

    /// Read one pixel, for tests and assertions.
    pub fn pixel(&self, x: u32, y: u32) -> Option<[u8; 4]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let off = y as usize * self.stride() + x as usize * 4;
        Some([
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ])
    }
}

/// A framebuffer shared between a backend session and the encoder.
///
/// The session owns the pixels; the encoder borrows them under a read lock for
/// the duration of one colour conversion.
#[derive(Clone, Debug)]
pub struct FramebufferHandle(Arc<RwLock<Framebuffer>>);

impl FramebufferHandle {
    /// Wrap a framebuffer.
    pub fn new(fb: Framebuffer) -> Self {
        Self(Arc::new(RwLock::new(fb)))
    }

    /// Allocate a black framebuffer and wrap it.
    pub fn with_size(width: u32, height: u32) -> Self {
        Self::new(Framebuffer::new(width, height))
    }

    /// Borrow for reading. Panics only if a writer panicked while holding the
    /// lock, which would mean the session is already broken.
    pub fn read(&self) -> RwLockReadGuard<'_, Framebuffer> {
        self.0.read().expect("framebuffer lock poisoned")
    }

    /// Borrow for writing.
    pub fn write(&self) -> RwLockWriteGuard<'_, Framebuffer> {
        self.0.write().expect("framebuffer lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blit_rejects_out_of_bounds_rects() {
        let mut fb = Framebuffer::new(16, 16);
        let rect = Rect {
            x: 8,
            y: 8,
            width: 16,
            height: 4,
        };
        assert!(!rect.fits_in(16, 16));
        assert!(!fb.blit(rect, &vec![0xAA; 16 * 4 * 4]));
    }

    #[test]
    fn blit_rejects_wrong_length_source() {
        let mut fb = Framebuffer::new(16, 16);
        assert!(!fb.blit(
            Rect {
                x: 0,
                y: 0,
                width: 4,
                height: 4
            },
            &[0u8; 3]
        ));
    }

    #[test]
    fn blit_places_pixels_where_asked() {
        let mut fb = Framebuffer::new(8, 8);
        let rect = Rect {
            x: 2,
            y: 3,
            width: 2,
            height: 2,
        };
        assert!(fb.blit(rect, &[1, 2, 3, 4].repeat(4)));
        assert_eq!(fb.pixel(2, 3), Some([1, 2, 3, 4]));
        assert_eq!(fb.pixel(3, 4), Some([1, 2, 3, 4]));
        assert_eq!(fb.pixel(4, 3), Some([0, 0, 0, 255]));
    }

    #[test]
    fn copy_rect_handles_overlap_downward() {
        let mut fb = Framebuffer::new(4, 4);
        fb.fill(
            Rect {
                x: 0,
                y: 0,
                width: 4,
                height: 1,
            },
            [9, 9, 9, 255],
        );
        // Copy row 0 down onto rows 1..3, overlapping as it goes.
        assert!(fb.copy_rect(
            Rect {
                x: 0,
                y: 1,
                width: 4,
                height: 3
            },
            0,
            0
        ));
        assert_eq!(fb.pixel(0, 1), Some([9, 9, 9, 255]));
    }

    #[test]
    fn copy_from_moves_only_the_requested_rectangle() {
        let mut src = Framebuffer::new(8, 8);
        src.fill(Rect::whole(8, 8), [1, 2, 3, 255]);
        let mut dst = Framebuffer::new(8, 8);
        assert!(dst.copy_from(
            &src,
            Rect {
                x: 2,
                y: 2,
                width: 2,
                height: 2
            }
        ));
        assert_eq!(dst.pixel(2, 2), Some([1, 2, 3, 255]));
        assert_eq!(dst.pixel(0, 0), Some([0, 0, 0, 255]));
        assert!(!dst.copy_from(
            &src,
            Rect {
                x: 0,
                y: 0,
                width: 16,
                height: 16
            }
        ));
    }

    #[test]
    fn union_ignores_empty() {
        let a = Rect {
            x: 4,
            y: 4,
            width: 2,
            height: 2,
        };
        assert_eq!(a.union(&Rect::default()), a);
        assert_eq!(Rect::default().union(&a), a);
        let b = Rect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        };
        assert_eq!(
            a.union(&b),
            Rect {
                x: 0,
                y: 0,
                width: 6,
                height: 6
            }
        );
    }
}
