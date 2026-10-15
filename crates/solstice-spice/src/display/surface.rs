//! Surfaces: the things draw commands draw onto.
//!
//! SPICE's display channel does not have *a* framebuffer. It has a set of
//! server-side surfaces, one of them flagged `PRIMARY`, and draw commands
//! name the surface they apply to. Off-screen surfaces are where a guest
//! composes things before blitting them to the screen, so a client that
//! ignored them would render a desktop with holes in it.
//!
//! Every surface is held as **BGRA**, whatever format the server declared.
//! SPICE's `16_555` and `16_565` formats exist for guests with 16-bit
//! displays and converting on the way in costs one pass over an image that is
//! about to be composited and H.264-encoded anyway; carrying two
//! representations through the rasteriser would cost a great deal more.
//! `A8` surfaces are the exception that still fits: they are alpha masks, and
//! an alpha-only surface is stored as BGRA with the value in all four bytes,
//! so reading either the alpha or the luminance gives the right answer.

use std::collections::HashMap;

use crate::error::{Result, SpiceError};
use crate::protocol::surface_fmt;

/// One surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surface {
    width: u32,
    height: u32,
    format: u32,
    has_alpha: bool,
    data: Vec<u8>,
}

impl Surface {
    /// Allocate a black surface.
    ///
    /// A surface with no alpha channel starts **opaque** black and one with
    /// an alpha channel starts **transparent**. The distinction matters: an
    /// off-screen ARGB surface is composed into another one later, and
    /// starting it opaque would paint a black rectangle wherever nothing had
    /// been drawn yet.
    pub fn new(width: u32, height: u32, format: u32) -> Self {
        let has_alpha = matches!(format, surface_fmt::RGB32_ARGB | surface_fmt::A8);
        let mut data = vec![0u8; width as usize * height as usize * 4];
        if !has_alpha {
            for pixel in data.chunks_exact_mut(4) {
                pixel[3] = 0xFF;
            }
        }
        Surface {
            width,
            height,
            format,
            has_alpha,
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

    /// The `SPICE_SURFACE_FMT_*` the server declared.
    pub const fn format(&self) -> u32 {
        self.format
    }

    /// Whether the alpha bytes mean anything.
    pub const fn has_alpha(&self) -> bool {
        self.has_alpha
    }

    /// Bytes per row.
    pub const fn stride(&self) -> usize {
        self.width as usize * 4
    }

    /// The pixels.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The pixels, mutably.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Read one pixel, or `None` outside the surface.
    pub fn pixel(&self, x: i64, y: i64) -> Option<[u8; 4]> {
        if x < 0 || y < 0 || x >= self.width as i64 || y >= self.height as i64 {
            return None;
        }
        let offset = y as usize * self.stride() + x as usize * 4;
        Some([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    /// Write one pixel. Out-of-bounds writes are dropped rather than
    /// panicking: coordinates come off the wire.
    pub fn set_pixel(&mut self, x: i64, y: i64, colour: [u8; 4]) {
        if x < 0 || y < 0 || x >= self.width as i64 || y >= self.height as i64 {
            return;
        }
        let offset = y as usize * self.stride() + x as usize * 4;
        self.data[offset..offset + 4].copy_from_slice(&colour);
    }

    /// Copy a rectangle from elsewhere in the same surface (`COPY_BITS`),
    /// handling overlap.
    pub fn copy_within(&mut self, dest: solstice_backend::Rect, src_x: i64, src_y: i64) -> bool {
        if !dest.fits_in(self.width, self.height) {
            return false;
        }
        if src_x < 0
            || src_y < 0
            || src_x + dest.width as i64 > self.width as i64
            || src_y + dest.height as i64 > self.height as i64
        {
            return false;
        }
        let stride = self.stride();
        let row_bytes = dest.width as usize * 4;
        let rows: Box<dyn Iterator<Item = usize>> = if (src_y as u32) < dest.y {
            Box::new((0..dest.height as usize).rev())
        } else {
            Box::new(0..dest.height as usize)
        };
        for row in rows {
            let from = (src_y as usize + row) * stride + src_x as usize * 4;
            let to = (dest.y as usize + row) * stride + dest.x as usize * 4;
            self.data.copy_within(from..from + row_bytes, to);
        }
        true
    }
}

/// The largest surface this client will allocate.
///
/// `SURFACE_CREATE` carries two `u32`s and the allocation happens before
/// anything else about the surface is known. 8K is past any display a guest
/// has; the number is the same order as the codec crate's own default
/// (`Limits::DEFAULT_MAX_PIXELS`).
pub const MAX_SURFACE_PIXELS: u64 = 1 << 25;

/// The most surfaces one display channel may hold at once.
///
/// Surface ids are a 32-bit space the server allocates from, and each one is
/// an allocation. A real guest uses a handful.
pub const MAX_SURFACES: usize = 1024;

/// Every surface a display channel knows about.
#[derive(Debug, Default)]
pub struct SurfaceSet {
    surfaces: HashMap<u32, Surface>,
    primary: Option<u32>,
}

impl SurfaceSet {
    /// An empty set.
    pub fn new() -> Self {
        SurfaceSet::default()
    }

    /// Create a surface, replacing any with the same id.
    pub fn create(
        &mut self,
        id: u32,
        width: u32,
        height: u32,
        format: u32,
        primary: bool,
    ) -> Result<()> {
        let pixels = width as u64 * height as u64;
        if width == 0 || height == 0 {
            return Err(SpiceError::protocol(format!(
                "surface {id} is {width}x{height}"
            )));
        }
        if pixels > MAX_SURFACE_PIXELS {
            return Err(SpiceError::limit(format!(
                "surface {id} of {width}x{height} exceeds the {MAX_SURFACE_PIXELS} pixel ceiling"
            )));
        }
        if !self.surfaces.contains_key(&id) && self.surfaces.len() >= MAX_SURFACES {
            return Err(SpiceError::limit(format!(
                "a {MAX_SURFACES}th surface; the server is not behaving"
            )));
        }
        self.surfaces
            .insert(id, Surface::new(width, height, format));
        if primary {
            self.primary = Some(id);
        }
        Ok(())
    }

    /// Destroy one.
    pub fn destroy(&mut self, id: u32) {
        self.surfaces.remove(&id);
        if self.primary == Some(id) {
            self.primary = None;
        }
    }

    /// Destroy all of them (`DISPLAY_RESET`).
    pub fn clear(&mut self) {
        self.surfaces.clear();
        self.primary = None;
    }

    /// Borrow one.
    pub fn get(&self, id: u32) -> Option<&Surface> {
        self.surfaces.get(&id)
    }

    /// Borrow one mutably.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Surface> {
        self.surfaces.get_mut(&id)
    }

    /// The id of the primary surface, if one has been created.
    pub fn primary_id(&self) -> Option<u32> {
        self.primary
    }

    /// The primary surface.
    pub fn primary(&self) -> Option<&Surface> {
        self.primary.and_then(|id| self.surfaces.get(&id))
    }

    /// How many surfaces exist.
    pub fn len(&self) -> usize {
        self.surfaces.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.surfaces.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_surface_with_alpha_starts_transparent_and_one_without_starts_opaque() {
        let argb = Surface::new(2, 2, surface_fmt::RGB32_ARGB);
        assert_eq!(argb.pixel(0, 0), Some([0, 0, 0, 0]));
        assert!(argb.has_alpha());

        let xrgb = Surface::new(2, 2, surface_fmt::RGB32_XRGB);
        assert_eq!(xrgb.pixel(0, 0), Some([0, 0, 0, 0xFF]));
        assert!(!xrgb.has_alpha());
    }

    #[test]
    fn writes_outside_the_surface_are_dropped_rather_than_panicking() {
        let mut surface = Surface::new(2, 2, surface_fmt::RGB32_XRGB);
        surface.set_pixel(-1, 0, [1, 2, 3, 4]);
        surface.set_pixel(5, 5, [1, 2, 3, 4]);
        assert_eq!(surface.pixel(0, 0), Some([0, 0, 0, 0xFF]));
        assert_eq!(surface.pixel(-1, 0), None);
    }

    #[test]
    fn copy_within_handles_an_overlapping_downward_move() {
        let mut surface = Surface::new(4, 4, surface_fmt::RGB32_XRGB);
        for x in 0..4 {
            surface.set_pixel(x, 0, [9, 9, 9, 255]);
        }
        assert!(surface.copy_within(
            solstice_backend::Rect {
                x: 0,
                y: 1,
                width: 4,
                height: 3
            },
            0,
            0
        ));
        // A block move, not a row repeat: destination row 1 takes source
        // row 0, and rows 2 and 3 take the rows that were below it.
        assert_eq!(surface.pixel(0, 1), Some([9, 9, 9, 255]));
        assert_eq!(surface.pixel(0, 3), Some([0, 0, 0, 255]));
    }

    #[test]
    fn copy_within_refuses_a_source_outside_the_surface() {
        let mut surface = Surface::new(4, 4, surface_fmt::RGB32_XRGB);
        assert!(!surface.copy_within(
            solstice_backend::Rect {
                x: 0,
                y: 0,
                width: 4,
                height: 4
            },
            2,
            2
        ));
        assert!(!surface.copy_within(
            solstice_backend::Rect {
                x: 0,
                y: 0,
                width: 4,
                height: 4
            },
            -1,
            0
        ));
    }

    #[test]
    fn a_surface_larger_than_the_ceiling_is_refused_before_allocating() {
        let mut set = SurfaceSet::new();
        assert!(set
            .create(0, 100_000, 100_000, surface_fmt::RGB32_XRGB, true)
            .is_err());
        assert!(set.create(0, 0, 10, surface_fmt::RGB32_XRGB, true).is_err());
        assert!(set.is_empty());
    }

    #[test]
    fn the_primary_surface_is_remembered_and_forgotten_with_it() {
        let mut set = SurfaceSet::new();
        set.create(0, 8, 8, surface_fmt::RGB32_XRGB, true).unwrap();
        set.create(1, 4, 4, surface_fmt::RGB32_XRGB, false).unwrap();
        assert_eq!(set.primary_id(), Some(0));
        set.destroy(1);
        assert_eq!(set.primary_id(), Some(0));
        set.destroy(0);
        assert_eq!(set.primary_id(), None);
        assert!(set.primary().is_none());
    }

    #[test]
    fn the_surface_count_is_capped() {
        let mut set = SurfaceSet::new();
        for id in 0..MAX_SURFACES as u32 {
            set.create(id, 1, 1, surface_fmt::RGB32_XRGB, false)
                .unwrap();
        }
        assert!(set
            .create(MAX_SURFACES as u32, 1, 1, surface_fmt::RGB32_XRGB, false)
            .is_err());
        // Replacing an existing one is still allowed.
        assert!(set.create(0, 2, 2, surface_fmt::RGB32_XRGB, false).is_ok());
    }
}
