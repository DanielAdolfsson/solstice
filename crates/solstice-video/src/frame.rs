//! The planar frame the encoder consumes.

/// An I420 (planar YUV 4:2:0) frame.
///
/// I420 rather than the NV12 the design sketch names: NV12 is what hardware
/// encoders want, and a VAAPI or NVENC backend should carry its own, but
/// OpenH264 takes three separate planes and converting twice would be the
/// worst of both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I420Frame {
    width: usize,
    height: usize,
    y: Vec<u8>,
    u: Vec<u8>,
    v: Vec<u8>,
}

impl I420Frame {
    /// Allocate a frame of mid-grey (Y=16 is black in studio swing, so the
    /// neutral chroma value makes an unconverted frame obviously wrong rather
    /// than plausibly dark).
    ///
    /// Dimensions are rounded up to even, since 4:2:0 chroma is subsampled by
    /// two in each direction.
    pub fn new(width: u32, height: u32) -> Self {
        let width = (width as usize).next_multiple_of(2).max(2);
        let height = (height as usize).next_multiple_of(2).max(2);
        Self {
            width,
            height,
            y: vec![16u8; width * height],
            u: vec![128u8; (width / 2) * (height / 2)],
            v: vec![128u8; (width / 2) * (height / 2)],
        }
    }

    /// Width in pixels, always even.
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Height in pixels, always even.
    pub const fn height(&self) -> usize {
        self.height
    }

    /// Luma plane.
    pub fn y(&self) -> &[u8] {
        &self.y
    }

    /// Blue-difference chroma plane.
    pub fn u(&self) -> &[u8] {
        &self.u
    }

    /// Red-difference chroma plane.
    pub fn v(&self) -> &[u8] {
        &self.v
    }

    /// Mutable access to all three planes at once, which is what the converter
    /// needs.
    pub fn planes_mut(&mut self) -> (&mut [u8], &mut [u8], &mut [u8]) {
        (&mut self.y, &mut self.u, &mut self.v)
    }

    /// Luma stride.
    pub const fn y_stride(&self) -> usize {
        self.width
    }

    /// Chroma stride.
    pub const fn uv_stride(&self) -> usize {
        self.width / 2
    }

    /// Read one pixel's YUV, for tests.
    pub fn sample(&self, x: usize, y: usize) -> Option<(u8, u8, u8)> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let c = (y / 2) * self.uv_stride() + x / 2;
        Some((self.y[y * self.width + x], self.u[c], self.v[c]))
    }
}

#[cfg(feature = "openh264")]
impl openh264::formats::YUVSource for I420Frame {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    fn strides(&self) -> (usize, usize, usize) {
        (self.y_stride(), self.uv_stride(), self.uv_stride())
    }

    fn y(&self) -> &[u8] {
        &self.y
    }

    fn u(&self) -> &[u8] {
        &self.u
    }

    fn v(&self) -> &[u8] {
        &self.v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimensions_are_rounded_up_to_even() {
        let f = I420Frame::new(1919, 1079);
        assert_eq!((f.width(), f.height()), (1920, 1080));
        assert_eq!(f.y().len(), 1920 * 1080);
        assert_eq!(f.u().len(), 960 * 540);
        assert_eq!(f.u().len(), f.v().len());
    }

    #[test]
    fn a_zero_sized_frame_is_clamped_rather_than_empty() {
        let f = I420Frame::new(0, 0);
        assert_eq!((f.width(), f.height()), (2, 2));
    }

    #[test]
    fn a_fresh_frame_is_black_with_neutral_chroma() {
        let f = I420Frame::new(16, 16);
        assert_eq!(f.sample(0, 0), Some((16, 128, 128)));
        assert_eq!(f.sample(16, 0), None);
    }
}
