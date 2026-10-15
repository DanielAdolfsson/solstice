//! BGRA to I420, one damaged rectangle at a time.
//!
//! The colour errors you will actually make are two: swapping the chroma planes
//! (BGRA read as RGBA) and confusing full range with studio swing. Both are
//! invisible on a colour-bar pattern and obvious on a flat fill, which is why
//! `docs/testing.md` §2.3 asks for flat fills rather than pixel diffs, and why
//! the tests below are flat fills.
//!
//! Coefficients are BT.601 **studio swing** (Y in 16..=235, chroma in
//! 16..=240), which is what an H.264 stream with no VUI colour information is
//! interpreted as, and what Moonlight's `encoderCscMode = 0` means.

use solstice_backend::{Framebuffer, Rect};

use crate::frame::I420Frame;

// BT.601 studio swing, in 16.8 fixed point.
const YR: i32 = 16_843; // 65.738 * 256
const YG: i32 = 33_030; // 129.057 * 256
const YB: i32 = 6_416; // 25.064 * 256
const UR: i32 = -9_714; // -37.945 * 256
const UG: i32 = -19_070; // -74.494 * 256
const UB: i32 = 28_784; // 112.439 * 256
const VR: i32 = 28_784;
const VG: i32 = -24_103; // -94.154 * 256
const VB: i32 = -4_681; // -18.285 * 256

#[inline]
fn luma(r: i32, g: i32, b: i32) -> u8 {
    (16 + ((YR * r + YG * g + YB * b) >> 16)).clamp(16, 235) as u8
}

#[inline]
fn chroma_u(r: i32, g: i32, b: i32) -> u8 {
    (128 + ((UR * r + UG * g + UB * b) >> 16)).clamp(16, 240) as u8
}

#[inline]
fn chroma_v(r: i32, g: i32, b: i32) -> u8 {
    (128 + ((VR * r + VG * g + VB * b) >> 16)).clamp(16, 240) as u8
}

/// Convert `rect` of `src` into `dst`, leaving the rest of `dst` untouched.
///
/// The rectangle is snapped outward to even coordinates, because a 4:2:0
/// chroma sample covers a 2x2 luma block and converting half of one would leave
/// the other half stale.
///
/// Returns `false` if the rectangle does not fit in either buffer.
pub fn convert_rect(src: &Framebuffer, rect: Rect, dst: &mut I420Frame) -> bool {
    if !rect.fits_in(src.width(), src.height()) {
        return false;
    }
    let x0 = (rect.x & !1) as usize;
    let y0 = (rect.y & !1) as usize;
    let x1 = (rect.right().next_multiple_of(2) as usize)
        .min(dst.width())
        .min(src.width() as usize);
    let y1 = (rect.bottom().next_multiple_of(2) as usize)
        .min(dst.height())
        .min(src.height() as usize);
    if x0 >= x1 || y0 >= y1 {
        return true;
    }

    let stride = src.stride();
    let data = src.data();
    let y_stride = dst.y_stride();
    let uv_stride = dst.uv_stride();
    let (y_plane, u_plane, v_plane) = dst.planes_mut();

    for y in (y0..y1).step_by(2) {
        for x in (x0..x1).step_by(2) {
            // Sum the 2x2 block for chroma while writing each pixel's luma.
            let mut sum = [0i32; 3];
            for (dy, dx) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
                let px = (x + dx).min(x1 - 1);
                let py = (y + dy).min(y1 - 1);
                let off = py * stride + px * 4;
                // BGRA: blue first. Reading this as RGBA is the bug the flat
                // fill tests exist to catch.
                let (b, g, r) = (data[off] as i32, data[off + 1] as i32, data[off + 2] as i32);
                y_plane[py * y_stride + px] = luma(r, g, b);
                sum[0] += r;
                sum[1] += g;
                sum[2] += b;
            }
            let (r, g, b) = (sum[0] / 4, sum[1] / 4, sum[2] / 4);
            let c = (y / 2) * uv_stride + x / 2;
            u_plane[c] = chroma_u(r, g, b);
            v_plane[c] = chroma_v(r, g, b);
        }
    }
    true
}

/// Convert the whole framebuffer.
pub fn convert_full(src: &Framebuffer, dst: &mut I420Frame) -> bool {
    convert_rect(src, Rect::whole(src.width(), src.height()), dst)
}

/// Convert the whole framebuffer, letterboxed into a differently sized frame.
///
/// Moonlight requests a resolution and the backend has its own idea. Asking the
/// backend to resize is the better answer and is tried first, but it needs
/// cooperation that may not be there -- so this is the fallback
/// (`docs/bridging-design.md` §2.2). Nearest-neighbour: a desktop is text and
/// sharp edges, where a smoothing filter costs CPU to make the result less
/// legible.
///
/// Returns the rectangle of `dst` the image was placed in, so the caller can
/// map pointer coordinates back through it.
pub fn convert_scaled(src: &Framebuffer, dst: &mut I420Frame) -> Rect {
    let (sw, sh) = (src.width().max(1), src.height().max(1));
    let (dw, dh) = (dst.width() as u32, dst.height() as u32);

    // Preserve aspect ratio; the remainder is black bars.
    let scale_num = (dw * sh).min(dh * sw);
    let out_w = ((scale_num / sh) & !1).clamp(2, dw);
    let out_h = ((scale_num / sw) & !1).clamp(2, dh);
    let off_x = ((dw - out_w) / 2) & !1;
    let off_y = ((dh - out_h) / 2) & !1;

    let stride = src.stride();
    let data = src.data();
    let y_stride = dst.y_stride();
    let uv_stride = dst.uv_stride();
    let (y_plane, u_plane, v_plane) = dst.planes_mut();

    // Black bars first, in studio swing.
    y_plane.fill(16);
    u_plane.fill(128);
    v_plane.fill(128);

    for dy in (0..out_h).step_by(2) {
        for dx in (0..out_w).step_by(2) {
            let mut sum = [0i32; 3];
            for (ey, ex) in [(0u32, 0u32), (0, 1), (1, 0), (1, 1)] {
                let ox = (dx + ex).min(out_w - 1);
                let oy = (dy + ey).min(out_h - 1);
                let sx = (ox as u64 * sw as u64 / out_w as u64).min(sw as u64 - 1) as usize;
                let sy = (oy as u64 * sh as u64 / out_h as u64).min(sh as u64 - 1) as usize;
                let off = sy * stride + sx * 4;
                let (b, g, r) = (data[off] as i32, data[off + 1] as i32, data[off + 2] as i32);
                let px = (off_x + ox) as usize;
                let py = (off_y + oy) as usize;
                y_plane[py * y_stride + px] = luma(r, g, b);
                sum[0] += r;
                sum[1] += g;
                sum[2] += b;
            }
            let (r, g, b) = (sum[0] / 4, sum[1] / 4, sum[2] / 4);
            let c = ((off_y + dy) as usize / 2) * uv_stride + (off_x + dx) as usize / 2;
            u_plane[c] = chroma_u(r, g, b);
            v_plane[c] = chroma_v(r, g, b);
        }
    }
    Rect {
        x: off_x,
        y: off_y,
        width: out_w,
        height: out_h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(colour: [u8; 4]) -> Framebuffer {
        let mut fb = Framebuffer::new(16, 16);
        fb.fill(Rect::whole(16, 16), colour);
        fb
    }

    /// Flat fills: the test `docs/testing.md` §2.3 prescribes for colour
    /// correctness, with the BT.601 studio-swing values each one must produce.
    #[test]
    fn flat_fills_land_on_the_bt601_studio_swing_values() {
        // BGRA, so [B, G, R, A].
        for (name, colour, expect) in [
            ("black", [0, 0, 0, 255], (16, 128, 128)),
            ("white", [255, 255, 255, 255], (235, 128, 128)),
            ("red", [0, 0, 255, 255], (81, 90, 240)),
            ("green", [0, 255, 0, 255], (144, 54, 34)),
            ("blue", [255, 0, 0, 255], (41, 240, 110)),
        ] {
            let fb = filled(colour);
            let mut frame = I420Frame::new(16, 16);
            assert!(convert_full(&fb, &mut frame));
            let got = frame.sample(4, 4).unwrap();
            let (y, u, v) = expect;
            assert!(
                got.0.abs_diff(y) <= 1 && got.1.abs_diff(u) <= 1 && got.2.abs_diff(v) <= 1,
                "{name}: got {got:?}, expected {expect:?}"
            );
        }
    }

    /// Reading BGRA as RGBA swaps red and blue, which flat red and flat blue
    /// detect and a colour-bar pattern does not.
    #[test]
    fn red_and_blue_are_not_interchangeable() {
        let mut red = I420Frame::new(16, 16);
        let mut blue = I420Frame::new(16, 16);
        convert_full(&filled([0, 0, 255, 255]), &mut red);
        convert_full(&filled([255, 0, 0, 255]), &mut blue);
        assert_ne!(red.sample(0, 0), blue.sample(0, 0));
        // Specifically: red has high V, blue has high U.
        assert!(red.sample(0, 0).unwrap().2 > 200);
        assert!(blue.sample(0, 0).unwrap().1 > 200);
    }

    /// Studio swing, not full range: pure black must be 16 and not 0.
    #[test]
    fn black_is_sixteen_not_zero() {
        let mut frame = I420Frame::new(16, 16);
        convert_full(&filled([0, 0, 0, 255]), &mut frame);
        assert_eq!(frame.sample(0, 0).unwrap().0, 16);
        convert_full(&filled([255, 255, 255, 255]), &mut frame);
        assert_eq!(frame.sample(0, 0).unwrap().0, 235);
    }

    #[test]
    fn a_partial_convert_leaves_the_rest_alone() {
        let mut fb = Framebuffer::new(16, 16);
        fb.fill(Rect::whole(16, 16), [0, 0, 0, 255]);
        let mut frame = I420Frame::new(16, 16);
        convert_full(&fb, &mut frame);

        fb.fill(
            Rect {
                x: 4,
                y: 4,
                width: 4,
                height: 4,
            },
            [255, 255, 255, 255],
        );
        assert!(convert_rect(
            &fb,
            Rect {
                x: 4,
                y: 4,
                width: 4,
                height: 4
            },
            &mut frame
        ));
        assert_eq!(frame.sample(5, 5).unwrap().0, 235);
        assert_eq!(frame.sample(0, 0).unwrap().0, 16);
        assert_eq!(frame.sample(12, 12).unwrap().0, 16);
    }

    /// A 4:2:0 chroma sample covers 2x2 luma, so an odd rectangle must be
    /// snapped outward or half the block keeps a stale chroma value.
    #[test]
    fn odd_rectangles_are_snapped_outward() {
        let mut fb = Framebuffer::new(16, 16);
        fb.fill(Rect::whole(16, 16), [0, 0, 0, 255]);
        let mut frame = I420Frame::new(16, 16);
        convert_full(&fb, &mut frame);

        fb.fill(
            Rect {
                x: 5,
                y: 5,
                width: 3,
                height: 3,
            },
            [255, 255, 255, 255],
        );
        assert!(convert_rect(
            &fb,
            Rect {
                x: 5,
                y: 5,
                width: 3,
                height: 3
            },
            &mut frame
        ));
        // The whole 2x2-aligned region covering 5..8 was reconverted.
        for y in 5..8 {
            for x in 5..8 {
                assert_eq!(frame.sample(x, y).unwrap().0, 235, "({x},{y})");
            }
        }
    }

    #[test]
    fn an_out_of_bounds_rectangle_is_refused() {
        let fb = Framebuffer::new(16, 16);
        let mut frame = I420Frame::new(16, 16);
        assert!(!convert_rect(
            &fb,
            Rect {
                x: 8,
                y: 8,
                width: 16,
                height: 16
            },
            &mut frame
        ));
    }

    /// Converting the same pixels twice must be idempotent; a converter that
    /// accumulated rather than assigned would drift.
    #[test]
    fn conversion_is_idempotent() {
        let fb = filled([12, 34, 56, 255]);
        let mut a = I420Frame::new(16, 16);
        convert_full(&fb, &mut a);
        let mut b = a.clone();
        convert_full(&fb, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn scaling_preserves_aspect_ratio_and_letterboxes_the_rest() {
        // A 16:9 source into a 4:3 frame: bars top and bottom.
        let mut src = Framebuffer::new(320, 180);
        src.fill(Rect::whole(320, 180), [255, 255, 255, 255]);
        let mut dst = I420Frame::new(320, 240);
        let placed = convert_scaled(&src, &mut dst);
        assert_eq!(placed.width, 320);
        assert_eq!(placed.height, 180);
        assert_eq!(placed.x, 0);
        assert_eq!(placed.y, 30);

        // Inside the image is white; the bars are black.
        assert_eq!(dst.sample(160, 120).unwrap().0, 235);
        assert_eq!(dst.sample(160, 5).unwrap().0, 16);
        assert_eq!(dst.sample(160, 235).unwrap().0, 16);
    }

    #[test]
    fn scaling_up_and_down_both_work() {
        let mut src = Framebuffer::new(64, 64);
        src.fill(Rect::whole(64, 64), [0, 0, 255, 255]);
        for (w, h) in [(32u32, 32u32), (256, 256), (640, 480)] {
            let mut dst = I420Frame::new(w, h);
            let placed = convert_scaled(&src, &mut dst);
            assert!(!placed.is_empty());
            let centre = dst.sample((w / 2) as usize, (h / 2) as usize).unwrap();
            // Still red: V high.
            assert!(centre.2 > 200, "{w}x{h} gave {centre:?}");
        }
    }

    #[test]
    fn an_identity_scale_matches_the_unscaled_conversion() {
        let mut src = Framebuffer::new(64, 64);
        src.fill(Rect::whole(64, 64), [12, 34, 56, 255]);
        let mut a = I420Frame::new(64, 64);
        let mut b = I420Frame::new(64, 64);
        convert_full(&src, &mut a);
        let placed = convert_scaled(&src, &mut b);
        assert_eq!(placed, Rect::whole(64, 64));
        assert_eq!(a.sample(10, 10), b.sample(10, 10));
    }

    #[test]
    fn a_framebuffer_larger_than_the_frame_does_not_overrun() {
        let fb = filled([255, 255, 255, 255]);
        let mut small = I420Frame::new(8, 8);
        assert!(convert_full(&fb, &mut small));
        assert_eq!(small.sample(7, 7).unwrap().0, 235);
    }
}
