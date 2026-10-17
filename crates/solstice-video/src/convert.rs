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
/// (`docs/bridging-design.md` §2.2).
///
/// Each output pixel is the area-weighted average of the source it covers, so
/// a downscale gives every source pixel the same total weight: nearest-
/// neighbour, which this replaced, dropped a third of the rows of a 1080p
/// desktop streamed at 720p, and with them strokes of text. The weights are
/// exact integers -- an output pixel spans `src` units of a grid on which a
/// source pixel is `out` units wide -- so a flat colour stays exactly flat.
/// Scaling up, each output pixel takes the nearest source pixel instead: a
/// desktop is text and sharp edges, where blending costs CPU to make it less
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
    let placed = Rect {
        x: off_x,
        y: off_y,
        width: out_w,
        height: out_h,
    };

    let y_stride = dst.y_stride();
    let uv_stride = dst.uv_stride();
    let (y_plane, u_plane, v_plane) = dst.planes_mut();

    // Black bars first, in studio swing.
    y_plane.fill(16);
    u_plane.fill(128);
    v_plane.fill(128);
    if src.width() == 0 || src.height() == 0 {
        return placed;
    }

    let (columns, rows) = (Taps::new(sw, out_w), Taps::new(sh, out_h));
    let scaler = Scaler {
        src,
        average: Divide::by(columns.norm as u64 * rows.norm as u64),
        columns,
        rows,
        off_x: off_x as usize,
    };

    // Bands of output rows, one per thread: the encoder waits on this, and
    // the other cores are idle while it does. Even heights, so each band owns
    // whole chroma rows. A small frame is not worth the threads.
    let threads = if out_w as usize * out_h as usize >= 640 * 480 {
        std::thread::available_parallelism().map_or(1, |n| n.get().min(MAX_THREADS))
    } else {
        1
    };
    let band = (out_h as usize).div_ceil(threads).next_multiple_of(2);
    let y_bands = y_plane[off_y as usize * y_stride..].chunks_mut(band * y_stride);
    let u_bands = u_plane[off_y as usize / 2 * uv_stride..].chunks_mut(band / 2 * uv_stride);
    let v_bands = v_plane[off_y as usize / 2 * uv_stride..].chunks_mut(band / 2 * uv_stride);
    let jobs = y_bands
        .zip(u_bands)
        .zip(v_bands)
        .enumerate()
        .map(|(i, ((y, u), v))| {
            let first = i * band;
            let rows = first..(first + band).min(out_h as usize);
            (
                rows,
                Planes {
                    y,
                    u,
                    v,
                    y_stride,
                    uv_stride,
                },
            )
        });
    std::thread::scope(|scope| {
        let scaler = &scaler;
        let mut jobs = jobs.filter(|(rows, _)| !rows.is_empty());
        // The first band on this thread, the rest on their own.
        let here = jobs.next();
        for (rows, planes) in jobs {
            scope.spawn(move || scaler.band(rows, planes));
        }
        if let Some((rows, planes)) = here {
            scaler.band(rows, planes);
        }
    });
    placed
}

/// The most threads one scaled conversion uses.
const MAX_THREADS: usize = 4;

/// One band of the destination's planes, starting at the band's first row.
struct Planes<'a> {
    y: &'a mut [u8],
    u: &'a mut [u8],
    v: &'a mut [u8],
    y_stride: usize,
    uv_stride: usize,
}

/// What every band of one scaled conversion shares.
struct Scaler<'a> {
    src: &'a Framebuffer,
    columns: Taps,
    rows: Taps,
    average: Divide,
    /// Where the image starts in each destination row.
    off_x: usize,
}

impl Scaler<'_> {
    /// Scale output rows `rows` -- an even start -- into `planes`, whose first
    /// row is output row `rows.start`.
    fn band(&self, rows: std::ops::Range<usize>, planes: Planes<'_>) {
        let Planes {
            y: y_plane,
            u: u_plane,
            v: v_plane,
            y_stride,
            uv_stride,
        } = planes;
        let w = self.columns.spans.len();
        // Two output rows of averaged RGB at a time: one 4:2:0 chroma row.
        let mut pair = [vec![[0i32; 3]; w], vec![[0i32; 3]; w]];
        // The vertical sums fit `u16` for every common ratio once the weights
        // are reduced, and `u16` vectorises twice as wide.
        let mut narrow = Vec::new();
        let mut wide = Vec::new();
        let narrow_fits = self.rows.norm as u64 * 255 <= u16::MAX as u64;

        for dy in rows.clone().step_by(2) {
            for (half, out) in pair.iter_mut().enumerate() {
                if narrow_fits {
                    combine_rows::<u16>(self.src, &self.rows, dy + half, &mut narrow);
                    filter_row(&narrow, &self.columns, self.average, out);
                } else {
                    combine_rows::<u32>(self.src, &self.rows, dy + half, &mut wide);
                    filter_row(&wide, &self.columns, self.average, out);
                }
            }
            let py = dy - rows.start;
            for dx in (0..w).step_by(2) {
                let px = self.off_x + dx;
                let mut sum = [0i32; 3];
                for (ey, row) in pair.iter().enumerate() {
                    for ex in 0..2 {
                        let [r, g, b] = row[dx + ex];
                        y_plane[(py + ey) * y_stride + px + ex] = luma(r, g, b);
                        sum[0] += r;
                        sum[1] += g;
                        sum[2] += b;
                    }
                }
                let (r, g, b) = (sum[0] / 4, sum[1] / 4, sum[2] / 4);
                let c = (py / 2) * uv_stride + px / 2;
                u_plane[c] = chroma_u(r, g, b);
                v_plane[c] = chroma_v(r, g, b);
            }
        }
    }
}

/// Which source pixels each output position takes, and with what weight, in
/// one dimension.
///
/// Scaling down, output `o` covers `[o * src, (o + 1) * src)` on a grid where
/// source pixel `i` is `[i * out, (i + 1) * out)`. The weight of each source
/// pixel is the overlap: `out` for one wholly inside, less for the partly
/// covered pixel at either end, and `src` in all. Scaling up, it is the one
/// nearest pixel at weight 1.
#[derive(Debug)]
struct Taps {
    /// Per output position: the source range, and the weights of its first
    /// and last pixel. Pixels between them weigh `inner`.
    spans: Vec<(usize, usize, u32, u32)>,
    inner: u32,
    /// What each position's weights sum to.
    norm: u32,
}

impl Taps {
    fn new(src: u32, out: u32) -> Self {
        let (s, o) = (src as u64, out as u64);
        if out > src {
            let spans = (0..o)
                .map(|i| {
                    let x = ((2 * i + 1) * s / (2 * o)).min(s - 1) as usize;
                    (x, x + 1, 1, 1)
                })
                .collect();
            return Self {
                spans,
                inner: 1,
                norm: 1,
            };
        }
        // Every boundary on the grid is a multiple of gcd(src, out), so every
        // weight is too. Dividing it out keeps the sums small: 2160 to 1080
        // weighs 1 and 1 out of 2, not 1080 and 1080 out of 2160.
        let g = gcd(s, o);
        let spans = (0..o)
            .map(|i| {
                let (from, to) = (i * s, (i + 1) * s);
                let start = from / o;
                let end = to.div_ceil(o);
                let first = ((((start + 1) * o).min(to) - from) / g) as u32;
                let last = ((to - (end - 1) * o) / g) as u32;
                (start as usize, end as usize, first, last)
            })
            .collect();
        Self {
            spans,
            inner: (o / g) as u32,
            norm: (s / g) as u32,
        }
    }

    /// The source pixels output `i` takes, with their weights.
    fn of(&self, i: usize) -> impl Iterator<Item = (usize, u32)> + '_ {
        let (start, end, first, last) = self.spans[i];
        (start..end).map(move |x| {
            let w = if x == start {
                first
            } else if x == end - 1 {
                last
            } else {
                self.inner
            };
            (x, w)
        })
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Combine output row `i`'s source rows into `combined`, weighted: BGRA, each
/// channel at most `rows.norm * 255`.
///
/// Vertically first, over whole rows of bytes in memory order, so the loop
/// vectorises; the horizontal pass then runs once per output row rather than
/// once per source row.
fn combine_rows<T>(src: &Framebuffer, rows: &Taps, i: usize, combined: &mut Vec<T>)
where
    T: Copy + From<u8> + TryFrom<u32> + std::ops::Mul<Output = T> + std::ops::Add<Output = T>,
{
    let stride = src.stride();
    let weight = |w: u32| T::try_from(w).ok().expect("weights fit the accumulator");
    let mut taps = rows.of(i);
    let (sy, wy) = taps.next().expect("every output row takes a source row");
    let wy = weight(wy);
    combined.clear();
    combined.extend(
        src.data()[sy * stride..(sy + 1) * stride]
            .iter()
            .map(|&b| wy * T::from(b)),
    );
    for (sy, wy) in taps {
        let wy = weight(wy);
        let row = &src.data()[sy * stride..(sy + 1) * stride];
        for (sum, &byte) in combined.iter_mut().zip(row) {
            *sum = *sum + wy * T::from(byte);
        }
    }
}

/// Average one vertically combined row horizontally into `out`, as RGB.
fn filter_row<T: Copy + Into<u64>>(
    combined: &[T],
    columns: &Taps,
    average: Divide,
    out: &mut [[i32; 3]],
) {
    for (o, &(x0, x1, first, last)) in out.iter_mut().zip(&columns.spans) {
        let span = &combined[x0 * 4..x1 * 4];
        // BGRA: blue first. The sums can pass `u32` for a large source.
        let weigh = |w: u32, px: &[T]| {
            let w = w as u64;
            [w * px[2].into(), w * px[1].into(), w * px[0].into()]
        };
        let mut sum = weigh(first, &span[..4]);
        if span.len() > 4 {
            let (middle, end) = span[4..].split_at(span.len() - 8);
            for px in middle.chunks_exact(4) {
                let [r, g, b] = weigh(columns.inner, px);
                sum[0] += r;
                sum[1] += g;
                sum[2] += b;
            }
            let [r, g, b] = weigh(last, end);
            sum[0] += r;
            sum[1] += g;
            sum[2] += b;
        }
        *o = sum.map(|c| average.rounded(c) as i32);
    }
}

/// Rounded division by a constant, as a multiply and a shift: three divisions
/// per output pixel cost more than the rest of the scaling put together.
///
/// The dividend is at most `255 * divisor`, so the product stays under 2^64.
/// The reciprocal is rounded up, which overshoots a quotient by less than
/// `dividend / 2^56`; that never reaches the next integer while
/// `dividend * divisor < 2^56`, which holds for a 4K source and anything
/// smaller. Larger, a sum lying within that margin of a rounding boundary can
/// come out one higher. A flat colour, half a divisor from either boundary, is
/// exact at any size.
#[derive(Clone, Copy, Debug)]
struct Divide {
    half: u64,
    reciprocal: u64,
}

impl Divide {
    const SHIFT: u32 = 56;

    fn by(divisor: u64) -> Self {
        Self {
            half: divisor / 2,
            reciprocal: (1u64 << Self::SHIFT).div_ceil(divisor),
        }
    }

    #[inline]
    fn rounded(self, n: u64) -> u64 {
        ((n + self.half) * self.reciprocal) >> Self::SHIFT
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
        assert_eq!(a, b);
    }

    /// One-pixel black and white columns, halved: every output pixel is the
    /// mid-grey average. Nearest-neighbour gave all one or all the other.
    #[test]
    fn a_downscale_averages_what_it_covers() {
        let mut src = Framebuffer::new(64, 64);
        for x in (0..64).step_by(2) {
            src.fill(
                Rect {
                    x,
                    y: 0,
                    width: 1,
                    height: 64,
                },
                [255, 255, 255, 255],
            );
        }
        let mut dst = I420Frame::new(32, 32);
        convert_scaled(&src, &mut dst);
        let mid = luma(128, 128, 128);
        for x in 0..32 {
            assert_eq!(dst.sample(x, 7).unwrap().0, mid, "column {x}");
        }
    }

    /// 1080 to 720 is a ratio of 1.5, at which nearest-neighbour skipped every
    /// third source row. A one-pixel line on each of those rows vanished
    /// entirely; averaged, every one of them still contributes its share.
    #[test]
    fn a_downscale_drops_no_rows() {
        let mut src = Framebuffer::new(90, 90);
        for y in (2..90).step_by(3) {
            src.fill(
                Rect {
                    x: 0,
                    y,
                    width: 90,
                    height: 1,
                },
                [255, 255, 255, 255],
            );
        }
        let mut dst = I420Frame::new(60, 60);
        let placed = convert_scaled(&src, &mut dst);
        assert_eq!(placed, Rect::whole(60, 60));

        // Brightness above black, summed down one column, is conserved up to
        // the area ratio: 30 white rows of 90 make a third of the column.
        let lit: u32 = (0..60)
            .map(|y| (dst.sample(30, y).unwrap().0 - 16) as u32)
            .sum();
        let expect = 60 * (235 - 16) / 3;
        assert!(
            lit.abs_diff(expect) * 20 < expect,
            "{lit} lit against {expect}: rows were dropped"
        );
    }

    /// Scaling up repeats pixels rather than blending them: a hard edge stays
    /// hard.
    #[test]
    fn an_upscale_keeps_edges_hard() {
        let mut src = Framebuffer::new(8, 8);
        src.fill(
            Rect {
                x: 4,
                y: 0,
                width: 4,
                height: 8,
            },
            [255, 255, 255, 255],
        );
        let mut dst = I420Frame::new(32, 32);
        convert_scaled(&src, &mut dst);
        let lumas: Vec<u8> = (0..32).map(|x| dst.sample(x, 16).unwrap().0).collect();
        assert!(lumas[..16].iter().all(|&y| y == 16), "{lumas:?}");
        assert!(lumas[16..].iter().all(|&y| y == 235), "{lumas:?}");
    }

    /// Large enough to be split into bands across threads: every luma sample,
    /// seams included, must equal a direct 2x2 box average of noise.
    #[test]
    fn a_banded_downscale_matches_a_direct_average_everywhere() {
        let (sw, sh) = (1280u32, 960u32);
        let mut src = Framebuffer::new(sw, sh);
        let mut seed = 0x2545_f491_u32;
        for px in src.data_mut().chunks_exact_mut(4) {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            px[..3].copy_from_slice(&seed.to_le_bytes()[1..]);
        }
        let mut dst = I420Frame::new(sw / 2, sh / 2);
        assert_eq!(convert_scaled(&src, &mut dst), Rect::whole(sw / 2, sh / 2));

        for y in 0..sh / 2 {
            for x in 0..sw / 2 {
                let mut sum = [0u32; 3];
                for (ex, ey) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                    let p = src.pixel(2 * x + ex, 2 * y + ey).unwrap();
                    for c in 0..3 {
                        sum[c] += p[2 - c] as u32;
                    }
                }
                let [r, g, b] = sum.map(|c| ((c + 2) / 4) as i32);
                assert_eq!(
                    dst.sample(x as usize, y as usize).unwrap().0,
                    luma(r, g, b),
                    "({x}, {y})"
                );
            }
        }
    }

    /// Every source pixel's weights, summed over the outputs it feeds, come
    /// to the same total, and each output's weights to `norm`.
    #[test]
    fn scaling_down_weighs_every_source_pixel_equally() {
        for (src, out) in [(1080u32, 720u32), (3840, 1920), (1000, 7), (5, 5), (7, 6)] {
            let taps = Taps::new(src, out);
            let mut per_source = vec![0u64; src as usize];
            for i in 0..out as usize {
                let total: u32 = taps
                    .of(i)
                    .map(|(x, w)| {
                        per_source[x] += w as u64;
                        w
                    })
                    .sum();
                assert_eq!(total, taps.norm, "{src}->{out}, output {i}");
            }
            let inner = taps.inner as u64;
            assert!(per_source.iter().all(|&w| w == inner), "{src}->{out}");
        }
        // Scaling up, each output takes one pixel, in range.
        let up = Taps::new(4, 9);
        assert!((0..9).all(|i| up.of(i).count() == 1 && up.of(i).all(|(x, _)| x < 4)));
    }

    #[test]
    fn a_framebuffer_larger_than_the_frame_does_not_overrun() {
        let fb = filled([255, 255, 255, 255]);
        let mut small = I420Frame::new(8, 8);
        assert!(convert_full(&fb, &mut small));
        assert_eq!(small.sample(7, 7).unwrap().0, 235);
    }
}
