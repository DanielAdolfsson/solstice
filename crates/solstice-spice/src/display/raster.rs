//! The 2D rasteriser.
//!
//! SPICE's display channel is a drawing command stream, not a video stream,
//! so a client has to be able to execute the commands. This is that: binary
//! and ternary raster operations, clipping, stencil masks, brushes, scaled
//! blits, lines and raster glyphs, over the BGRA surfaces in
//! [`crate::display::surface`].
//!
//! # Raster operations
//!
//! Two encodings, and they are different.
//!
//! **`ropd`** (`enums.h:253-267`) is a *description*: an operation bit
//! (`OP_PUT`, `OP_OR`, `OP_AND`, `OP_XOR`, …) plus invert bits for the
//! source, the brush, the destination and the result. It collapses to one of
//! sixteen binary operations, and the collapse depends on which of the three
//! inputs is playing the part of "source" and which "destination" for the
//! command in hand -- `DRAW_FILL` uses the brush as its source, `DRAW_COPY`
//! uses the bitmap. [`ropd_to_rop`] is a transcription of
//! `canvas_base.c:152-306`, which is the only place that mapping is written
//! down.
//!
//! **`rop3`** is the Windows ternary raster operation: a 256-entry truth
//! table over (pattern, source, destination), indexed `(P << 2) | (S << 1) | D`.
//! `rop3.c` encodes it as 256 generated functions; the convention is
//! confirmed by its own self-test at `rop3.c:129-142`, which evaluates each
//! formula with `d = 0xAA, s = 0xCC, p = 0xF0` and asserts the result is the
//! opcode -- those three constants being exactly the bit patterns of the
//! three inputs across the eight table positions.

use crate::display::image::{DecodedImage, Mask};
use crate::display::surface::Surface;
use crate::display::types::{Clip, Point, SpiceRect};
use crate::protocol::ropd;

/// One of the sixteen binary raster operations, numbered as X11 and
/// `pixman_utils.h:48-64` number them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rop(pub u8);

impl Rop {
    /// `src`.
    pub const COPY: Rop = Rop(3);
    /// `dst` -- draw nothing.
    pub const NOOP: Rop = Rop(5);
    /// All zeroes.
    pub const CLEAR: Rop = Rop(0);
    /// All ones.
    pub const SET: Rop = Rop(15);
    /// `!dst`.
    pub const INVERT: Rop = Rop(10);

    /// Apply to one channel.
    ///
    /// The opcode is a four-bit truth table whose bit `n` is the result for
    /// the input pair `n = ((!s) << 1) | (!d)`. That inverted indexing is
    /// what makes `COPY` 3 rather than 12, and it is the X11 convention the
    /// whole numbering comes from.
    pub const fn apply(self, src: u8, dst: u8) -> u8 {
        match self.0 & 0x0F {
            0 => 0,
            1 => src & dst,
            2 => src & !dst,
            3 => src,
            4 => !src & dst,
            5 => dst,
            6 => src ^ dst,
            7 => src | dst,
            8 => !src & !dst,
            9 => !(src ^ dst),
            10 => !dst,
            11 => src | !dst,
            12 => !src,
            13 => !src | dst,
            14 => !(src & dst),
            _ => 0xFF,
        }
    }

    /// Apply to a whole BGRA pixel.
    pub fn apply_pixel(self, src: [u8; 4], dst: [u8; 4]) -> [u8; 4] {
        [
            self.apply(src[0], dst[0]),
            self.apply(src[1], dst[1]),
            self.apply(src[2], dst[2]),
            self.apply(src[3], dst[3]),
        ]
    }

    /// Whether the operation ignores its source entirely.
    ///
    /// Worth knowing before decoding an image: `OP_BLACKNESS` over a bitmap
    /// does not need the bitmap.
    pub const fn ignores_source(self) -> bool {
        matches!(self.0 & 0x0F, 0 | 5 | 10 | 15)
    }
}

/// Which of a command's three inputs is playing a part in the binary
/// operation `ropd` collapses to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RopInput {
    /// The source bitmap.
    Src,
    /// The brush.
    Brush,
    /// The destination surface.
    Dest,
}

impl RopInput {
    const fn invert_mask(self) -> u16 {
        match self {
            RopInput::Src => ropd::INVERS_SRC,
            RopInput::Brush => ropd::INVERS_BRUSH,
            RopInput::Dest => ropd::INVERS_DEST,
        }
    }
}

/// Collapse a `ropd` description into a binary raster operation.
///
/// A transcription of `canvas_base.c:152-306`. `src_input` and `dest_input`
/// say which of the command's inputs stand in for "source" and "destination":
/// `DRAW_FILL` passes `(Brush, Dest)`, `DRAW_COPY` passes `(Src, Dest)`.
pub fn ropd_to_rop(descriptor: u16, src_input: RopInput, dest_input: RopInput) -> Rop {
    let original = descriptor;
    let mut desc = descriptor & !(ropd::INVERS_SRC | ropd::INVERS_DEST);
    if original & src_input.invert_mask() != 0 {
        desc |= ropd::INVERS_SRC;
    }
    if original & dest_input.invert_mask() != 0 {
        desc |= ropd::INVERS_DEST;
    }

    let invers_src = desc & ropd::INVERS_SRC != 0;
    let invers_dest = desc & ropd::INVERS_DEST != 0;
    let invers_res = desc & ropd::INVERS_RES != 0;

    if desc & ropd::OP_PUT != 0 {
        // The C's two branches here agree: inverting the source and
        // inverting the result cancel.
        return if invers_src != invers_res {
            Rop(12)
        } else {
            Rop::COPY
        };
    }
    if desc & ropd::OP_OR != 0 {
        return match (invers_res, invers_src, invers_dest) {
            (true, true, true) => Rop(1),    // src and dest
            (true, true, false) => Rop(2),   // src and !dest
            (true, false, true) => Rop(4),   // !src and dest
            (true, false, false) => Rop(8),  // nor
            (false, true, true) => Rop(14),  // nand
            (false, true, false) => Rop(13), // !src or dest
            (false, false, true) => Rop(11), // src or !dest
            (false, false, false) => Rop(7), // or
        };
    }
    if desc & ropd::OP_AND != 0 {
        return match (invers_res, invers_src, invers_dest) {
            (true, true, true) => Rop(7),    // or
            (true, true, false) => Rop(11),  // src or !dest
            (true, false, true) => Rop(13),  // !src or dest
            (true, false, false) => Rop(14), // nand
            (false, true, true) => Rop(8),   // nor
            (false, true, false) => Rop(4),  // !src and dest
            (false, false, true) => Rop(2),  // src and !dest
            (false, false, false) => Rop(1), // and
        };
    }
    if desc & ropd::OP_XOR != 0 {
        // Three inversions out of (src, dest, result) is xor; an even number
        // of them is equivalence.
        let inversions =
            usize::from(invers_src) + usize::from(invers_dest) + usize::from(invers_res);
        return if inversions % 2 == 0 { Rop(6) } else { Rop(9) };
    }
    if desc & ropd::OP_BLACKNESS != 0 {
        return Rop::CLEAR;
    }
    if desc & ropd::OP_WHITENESS != 0 {
        return Rop::SET;
    }
    if desc & ropd::OP_INVERS != 0 {
        return Rop::INVERT;
    }
    Rop::COPY
}

/// Apply a ternary raster operation to one channel.
///
/// Bit `(p << 2) | (s << 1) | d` of the opcode is the result for that
/// combination of inputs, taken a bit at a time across the byte.
pub fn apply_rop3(opcode: u8, pattern: u8, src: u8, dst: u8) -> u8 {
    let mut out = 0u8;
    for bit in 0..8 {
        let p = (pattern >> bit) & 1;
        let s = (src >> bit) & 1;
        let d = (dst >> bit) & 1;
        let index = (p << 2) | (s << 1) | d;
        out |= ((opcode >> index) & 1) << bit;
    }
    out
}

/// Apply a ternary raster operation to a whole BGRA pixel.
pub fn apply_rop3_pixel(opcode: u8, pattern: [u8; 4], src: [u8; 4], dst: [u8; 4]) -> [u8; 4] {
    [
        apply_rop3(opcode, pattern[0], src[0], dst[0]),
        apply_rop3(opcode, pattern[1], src[1], dst[1]),
        apply_rop3(opcode, pattern[2], src[2], dst[2]),
        apply_rop3(opcode, pattern[3], src[3], dst[3]),
    ]
}

/// A `QMask` resolved to pixels, ready to be consulted per pixel.
pub struct MaskRef<'a> {
    /// The stencil.
    pub mask: &'a Mask,
    /// Where its top-left corner sits in surface coordinates.
    pub pos: Point,
    /// Whether a set bit means "do not draw".
    pub inverted: bool,
}

impl MaskRef<'_> {
    fn allows(&self, x: i32, y: i32) -> bool {
        let covered = self
            .mask
            .covers(x as i64 - self.pos.x as i64, y as i64 - self.pos.y as i64);
        covered != self.inverted
    }
}

/// Walk the pixels of `box_` that survive the clip and the mask.
///
/// The destination bounds are passed rather than read from a surface so that
/// the caller can hold the surface mutably inside the closure.
pub fn visit(
    width: u32,
    height: u32,
    box_: &SpiceRect,
    clip: &Clip,
    mask: Option<&MaskRef<'_>>,
    mut f: impl FnMut(i32, i32),
) {
    let left = box_.left.max(0);
    let top = box_.top.max(0);
    let right = box_.right.min(width as i32);
    let bottom = box_.bottom.min(height as i32);
    if right <= left || bottom <= top {
        return;
    }
    for y in top..bottom {
        for x in left..right {
            if !clip.contains(x, y) {
                continue;
            }
            if let Some(mask) = mask {
                if !mask.allows(x, y) {
                    continue;
                }
            }
            f(x, y);
        }
    }
}

/// How a scaled blit picks its source pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScaleMode {
    /// `SPICE_IMAGE_SCALE_MODE_INTERPOLATE`.
    Interpolate,
    /// `SPICE_IMAGE_SCALE_MODE_NEAREST`.
    Nearest,
}

impl ScaleMode {
    /// Decode the wire value, defaulting to nearest for anything undefined.
    pub fn from_wire(value: u8) -> Self {
        match value {
            0 => ScaleMode::Interpolate,
            _ => ScaleMode::Nearest,
        }
    }
}

/// Samples a source bitmap for a possibly-scaled blit.
pub struct Sampler<'a> {
    image: &'a DecodedImage,
    src: SpiceRect,
    dest: SpiceRect,
    mode: ScaleMode,
}

impl<'a> Sampler<'a> {
    /// Map `src` within `image` onto `dest` in surface coordinates.
    pub fn new(image: &'a DecodedImage, src: SpiceRect, dest: SpiceRect, mode: ScaleMode) -> Self {
        Sampler {
            image,
            src,
            dest,
            mode,
        }
    }

    /// Whether source and destination are the same size, so no scaling is
    /// needed. Worth knowing because the unscaled path is exact and the
    /// scaled one is not.
    pub fn is_one_to_one(&self) -> bool {
        self.src.width() == self.dest.width() && self.src.height() == self.dest.height()
    }

    /// The source pixel for a destination position, in BGRA.
    pub fn at(&self, x: i32, y: i32) -> Option<[u8; 4]> {
        let dest_w = self.dest.width();
        let dest_h = self.dest.height();
        if dest_w == 0 || dest_h == 0 {
            return None;
        }
        let src_w = self.src.width();
        let src_h = self.src.height();
        let dx = (x - self.dest.left) as i64;
        let dy = (y - self.dest.top) as i64;

        if self.is_one_to_one() {
            return self
                .image
                .pixel_signed(self.src.left as i64 + dx, self.src.top as i64 + dy);
        }

        match self.mode {
            ScaleMode::Nearest => {
                let u = self.src.left as i64 + dx * src_w / dest_w;
                let v = self.src.top as i64 + dy * src_h / dest_h;
                self.image.pixel_signed(u, v)
            }
            ScaleMode::Interpolate => {
                // Fixed point with 8 fractional bits: enough for a bilinear
                // tap and no floating point in the inner loop.
                let fx = (dx * src_w * 256) / dest_w;
                let fy = (dy * src_h * 256) / dest_h;
                let u = self.src.left as i64 + (fx >> 8);
                let v = self.src.top as i64 + (fy >> 8);
                let tx = (fx & 0xFF) as u32;
                let ty = (fy & 0xFF) as u32;
                let p00 = self.image.pixel_signed(u, v)?;
                let p10 = self.image.pixel_signed(u + 1, v).unwrap_or(p00);
                let p01 = self.image.pixel_signed(u, v + 1).unwrap_or(p00);
                let p11 = self.image.pixel_signed(u + 1, v + 1).unwrap_or(p10);
                let mut out = [0u8; 4];
                for channel in 0..4 {
                    let top = p00[channel] as u32 * (256 - tx) + p10[channel] as u32 * tx;
                    let bottom = p01[channel] as u32 * (256 - tx) + p11[channel] as u32 * tx;
                    out[channel] = ((top * (256 - ty) + bottom * ty) >> 16) as u8;
                }
                Some(out)
            }
        }
    }
}

impl DecodedImage {
    /// [`DecodedImage::pixel`] over signed coordinates, for samplers whose
    /// arithmetic can go negative.
    pub fn pixel_signed(&self, x: i64, y: i64) -> Option<[u8; 4]> {
        if x < 0 || y < 0 || x > u32::MAX as i64 || y > u32::MAX as i64 {
            return None;
        }
        self.pixel(x as u32, y as u32)
    }

    /// The pixel a tiled pattern brush shows at a surface position.
    ///
    /// `origin` is the brush's anchor in surface coordinates; the tile
    /// repeats from there in both directions, including negatively.
    pub fn tile(&self, x: i32, y: i32, origin: Point) -> Option<[u8; 4]> {
        if self.width == 0 || self.height == 0 {
            return None;
        }
        let u = (x as i64 - origin.x as i64).rem_euclid(self.width as i64);
        let v = (y as i64 - origin.y as i64).rem_euclid(self.height as i64);
        self.pixel(u as u32, v as u32)
    }
}

/// The source of a draw command's colour, once brushes and bitmaps have been
/// resolved.
pub enum Source<'a> {
    /// One colour everywhere.
    Solid([u8; 4]),
    /// A tiled bitmap.
    Pattern {
        /// The tile.
        image: &'a DecodedImage,
        /// Its anchor in surface coordinates.
        origin: Point,
    },
    /// A bitmap mapped onto the destination rectangle.
    Bitmap(Sampler<'a>),
    /// Nothing -- the operation ignores its source.
    None,
}

impl Source<'_> {
    /// The colour at a surface position.
    pub fn at(&self, x: i32, y: i32) -> Option<[u8; 4]> {
        match self {
            Source::Solid(colour) => Some(*colour),
            Source::Pattern { image, origin } => image.tile(x, y, *origin),
            Source::Bitmap(sampler) => sampler.at(x, y),
            Source::None => Some([0, 0, 0, 0]),
        }
    }
}

/// Run a binary raster operation over a rectangle.
pub fn draw(
    surface: &mut Surface,
    box_: &SpiceRect,
    clip: &Clip,
    mask: Option<&MaskRef<'_>>,
    rop: Rop,
    source: &Source<'_>,
) {
    let (width, height) = (surface.width(), surface.height());
    let opaque = !surface.has_alpha();
    visit(width, height, box_, clip, mask, |x, y| {
        let Some(src) = source.at(x, y) else {
            return;
        };
        let Some(dst) = surface.pixel(x as i64, y as i64) else {
            return;
        };
        let mut out = rop.apply_pixel(src, dst);
        if opaque {
            // An x8r8g8b8 surface has no alpha to carry; leaving the
            // operation's output there would make a later ALPHA_BLEND read
            // whatever the raster op happened to produce.
            out[3] = 0xFF;
        }
        surface.set_pixel(x as i64, y as i64, out);
    });
}

/// Run a ternary raster operation over a rectangle.
pub fn draw_rop3(
    surface: &mut Surface,
    box_: &SpiceRect,
    clip: &Clip,
    mask: Option<&MaskRef<'_>>,
    opcode: u8,
    pattern: &Source<'_>,
    source: &Source<'_>,
) {
    let (width, height) = (surface.width(), surface.height());
    let opaque = !surface.has_alpha();
    visit(width, height, box_, clip, mask, |x, y| {
        let pattern = pattern.at(x, y).unwrap_or([0, 0, 0, 0]);
        let src = source.at(x, y).unwrap_or([0, 0, 0, 0]);
        let Some(dst) = surface.pixel(x as i64, y as i64) else {
            return;
        };
        let mut out = apply_rop3_pixel(opcode, pattern, src, dst);
        if opaque {
            out[3] = 0xFF;
        }
        surface.set_pixel(x as i64, y as i64, out);
    });
}

/// `DRAW_TRANSPARENT`: copy, treating one source colour as a hole.
///
/// The comparison is on the low 24 bits because `src_color` is an RGB value
/// and the bitmap's fourth byte may be padding rather than alpha.
pub fn draw_transparent(
    surface: &mut Surface,
    box_: &SpiceRect,
    clip: &Clip,
    sampler: &Sampler<'_>,
    src_color: u32,
) {
    let (width, height) = (surface.width(), surface.height());
    let opaque = !surface.has_alpha();
    let key = src_color & 0x00FF_FFFF;
    visit(width, height, box_, clip, None, |x, y| {
        let Some(src) = sampler.at(x, y) else {
            return;
        };
        let value = u32::from_le_bytes(src) & 0x00FF_FFFF;
        if value == key {
            return;
        }
        let mut out = src;
        if opaque {
            out[3] = 0xFF;
        }
        surface.set_pixel(x as i64, y as i64, out);
    });
}

/// `DRAW_ALPHA_BLEND`: source-over, with a constant alpha on top of the
/// bitmap's own.
pub fn draw_alpha_blend(
    surface: &mut Surface,
    box_: &SpiceRect,
    clip: &Clip,
    sampler: &Sampler<'_>,
    constant_alpha: u8,
    source_has_alpha: bool,
) {
    let (width, height) = (surface.width(), surface.height());
    let dest_has_alpha = surface.has_alpha();
    visit(width, height, box_, clip, None, |x, y| {
        let Some(src) = sampler.at(x, y) else {
            return;
        };
        let Some(dst) = surface.pixel(x as i64, y as i64) else {
            return;
        };
        // The bitmap's alpha is premultiplied, which is what SPICE's
        // a8r8g8b8 means and what makes source-over a multiply and an add
        // rather than a three-way interpolation.
        let src_alpha = if source_has_alpha { src[3] as u32 } else { 255 };
        let alpha = src_alpha * constant_alpha as u32 / 255;
        let inverse = 255 - alpha;
        let mut out = [0u8; 4];
        for channel in 0..4 {
            let contribution = src[channel] as u32 * constant_alpha as u32 / 255;
            out[channel] = (contribution + (dst[channel] as u32 * inverse) / 255).min(255) as u8;
        }
        if !dest_has_alpha {
            out[3] = 0xFF;
        }
        surface.set_pixel(x as i64, y as i64, out);
    });
}

/// Draw a one-pixel line between two points, clipped.
///
/// SPICE's `DRAW_STROKE` carries line styles, widths and Bézier segments.
/// This draws every stroke as a hairline: the alternative is a path
/// rasteriser, and a stroke that is one pixel off is a far smaller error than
/// a stroke that is missing. See [`stroke_path`].
pub fn draw_line(
    surface: &mut Surface,
    clip: &Clip,
    from: (f32, f32),
    to: (f32, f32),
    colour: [u8; 4],
    rop: Rop,
) {
    let (x0, y0) = (from.0.round() as i64, from.1.round() as i64);
    let (x1, y1) = (to.0.round() as i64, to.1.round() as i64);
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    let (mut x, mut y) = (x0, y0);
    let opaque = !surface.has_alpha();

    // A line is at most the diagonal of the surface; the bound stops a
    // degenerate pair of endpoints from looping forever.
    let limit = (surface.width() as i64 + surface.height() as i64) * 2 + 4;
    for _ in 0..limit {
        if clip.contains(x as i32, y as i32) {
            if let Some(dst) = surface.pixel(x, y) {
                let mut out = rop.apply_pixel(colour, dst);
                if opaque {
                    out[3] = 0xFF;
                }
                surface.set_pixel(x, y, out);
            }
        }
        if x == x1 && y == y1 {
            break;
        }
        let double = error * 2;
        if double >= dy {
            error += dy;
            x += sx;
        }
        if double <= dx {
            error += dx;
            y += sy;
        }
    }
}

/// How finely a Bézier segment is flattened into line segments.
const BEZIER_STEPS: usize = 16;

/// Stroke a path, flattening Bézier segments.
pub fn stroke_path(
    surface: &mut Surface,
    clip: &Clip,
    segments: &[crate::display::types::PathSegment],
    colour: [u8; 4],
    rop: Rop,
) {
    for segment in segments {
        let points = &segment.points;
        if points.len() < 2 {
            continue;
        }
        if segment.is_bezier() {
            // Cubic Béziers arrive as groups of four control points.
            for group in points.chunks(4) {
                if group.len() < 4 {
                    break;
                }
                let mut previous = group[0];
                for step in 1..=BEZIER_STEPS {
                    let t = step as f32 / BEZIER_STEPS as f32;
                    let point = cubic_bezier(group[0], group[1], group[2], group[3], t);
                    draw_line(surface, clip, previous, point, colour, rop);
                    previous = point;
                }
            }
        } else {
            for pair in points.windows(2) {
                draw_line(surface, clip, pair[0], pair[1], colour, rop);
            }
            if segment.is_closed() {
                draw_line(
                    surface,
                    clip,
                    points[points.len() - 1],
                    points[0],
                    colour,
                    rop,
                );
            }
        }
    }
}

fn cubic_bezier(
    p0: (f32, f32),
    p1: (f32, f32),
    p2: (f32, f32),
    p3: (f32, f32),
    t: f32,
) -> (f32, f32) {
    let u = 1.0 - t;
    let (a, b, c, d) = (u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t);
    (
        a * p0.0 + b * p1.0 + c * p2.0 + d * p3.0,
        a * p0.1 + b * p1.1 + c * p2.1 + d * p3.1,
    )
}

/// Run a raster operation over a rectangle, touching only the colour
/// channels.
///
/// `DRAW_BLACKNESS`, `DRAW_WHITENESS` and `DRAW_INVERS` are the three
/// commands the C implements with `fill_solid_rects` and `invert_rects`
/// rather than with the general rop path (`canvas_base.c:2483-2570`). Those
/// take an RGB value, so an alpha-bearing surface keeps its alpha -- which
/// matters, because inverting the alpha of an off-screen ARGB surface would
/// turn its transparent parts opaque.
pub fn draw_solid_rgb(
    surface: &mut Surface,
    box_: &SpiceRect,
    clip: &Clip,
    mask: Option<&MaskRef<'_>>,
    rop: Rop,
    rgb: [u8; 3],
) {
    let (width, height) = (surface.width(), surface.height());
    visit(width, height, box_, clip, mask, |x, y| {
        let Some(dst) = surface.pixel(x as i64, y as i64) else {
            return;
        };
        let out = [
            rop.apply(rgb[0], dst[0]),
            rop.apply(rgb[1], dst[1]),
            rop.apply(rgb[2], dst[2]),
            dst[3],
        ];
        surface.set_pixel(x as i64, y as i64, out);
    });
}

/// Blend one glyph's coverage into the surface.
///
/// `bits_per_pixel` is 1, 4 or 8 as the string's flags say; 1-bit coverage is
/// a hard stencil, and 4- and 8-bit coverage is antialiasing the guest's text
/// renderer produced.
pub fn draw_glyph(
    surface: &mut Surface,
    clip: &Clip,
    glyph: &crate::display::types::Glyph,
    bits_per_pixel: u8,
    source: &Source<'_>,
) {
    let row_bytes = (glyph.width as usize * bits_per_pixel as usize).div_ceil(8);
    let dest_has_alpha = surface.has_alpha();
    for row in 0..glyph.height as usize {
        let Some(line) = glyph.data.get(row * row_bytes..(row + 1) * row_bytes) else {
            return;
        };
        for column in 0..glyph.width as usize {
            let coverage = match bits_per_pixel {
                1 => {
                    let byte = line[column / 8];
                    // Glyph bitmaps are most-significant-bit first, the same
                    // order `SPICE_BITMAP_FMT_1BIT_BE` uses.
                    if (byte >> (7 - column % 8)) & 1 != 0 {
                        255
                    } else {
                        0
                    }
                }
                4 => {
                    let byte = line[column / 2];
                    let nibble = if column % 2 == 0 {
                        byte >> 4
                    } else {
                        byte & 0x0F
                    };
                    // 0..15 scaled to 0..255 without a divide that would
                    // stop short of full coverage.
                    nibble * 17
                }
                _ => line[column],
            };
            if coverage == 0 {
                continue;
            }
            let x = glyph.render_pos.x as i64 + column as i64;
            let y = glyph.render_pos.y as i64 + row as i64;
            if !clip.contains(x as i32, y as i32) {
                continue;
            }
            let Some(dst) = surface.pixel(x, y) else {
                continue;
            };
            let Some(colour) = source.at(x as i32, y as i32) else {
                continue;
            };
            let alpha = coverage as u32;
            let inverse = 255 - alpha;
            let mut out = [0u8; 4];
            for channel in 0..4 {
                out[channel] =
                    ((colour[channel] as u32 * alpha + dst[channel] as u32 * inverse) / 255) as u8;
            }
            if !dest_has_alpha {
                out[3] = 0xFF;
            }
            surface.set_pixel(x, y, out);
        }
    }
}

/// Unpack a SPICE colour word into BGRA.
///
/// Brush and text colours are `0x00rrggbb` (or `0xaarrggbb` on an ARGB
/// surface), which little-endian memory order already lays out as B, G, R, A.
pub fn colour_to_bgra(colour: u32, has_alpha: bool) -> [u8; 4] {
    let mut out = colour.to_le_bytes();
    if !has_alpha {
        out[3] = 0xFF;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display::image::Format;
    use crate::protocol::surface_fmt;

    #[test]
    fn the_sixteen_binary_operations_are_the_x11_truth_tables() {
        assert_eq!(Rop::COPY.apply(0xAB, 0xCD), 0xAB);
        assert_eq!(Rop::NOOP.apply(0xAB, 0xCD), 0xCD);
        assert_eq!(Rop::CLEAR.apply(0xFF, 0xFF), 0x00);
        assert_eq!(Rop::SET.apply(0x00, 0x00), 0xFF);
        assert_eq!(Rop::INVERT.apply(0xFF, 0x0F), 0xF0);
        assert_eq!(Rop(1).apply(0b1100, 0b1010), 0b1000);
        assert_eq!(Rop(6).apply(0b1100, 0b1010), 0b0110);
        assert_eq!(Rop(7).apply(0b1100, 0b1010), 0b1110);
    }

    #[test]
    fn op_put_is_a_plain_copy_and_inverting_twice_cancels() {
        assert_eq!(
            ropd_to_rop(ropd::OP_PUT, RopInput::Src, RopInput::Dest),
            Rop::COPY
        );
        assert_eq!(
            ropd_to_rop(
                ropd::OP_PUT | ropd::INVERS_SRC,
                RopInput::Src,
                RopInput::Dest
            ),
            Rop(12)
        );
        assert_eq!(
            ropd_to_rop(
                ropd::OP_PUT | ropd::INVERS_SRC | ropd::INVERS_RES,
                RopInput::Src,
                RopInput::Dest
            ),
            Rop::COPY
        );
    }

    #[test]
    fn de_morgan_holds_the_way_the_c_spells_it_out() {
        // !(!src or !dest) == src and dest
        assert_eq!(
            ropd_to_rop(
                ropd::OP_OR | ropd::INVERS_SRC | ropd::INVERS_DEST | ropd::INVERS_RES,
                RopInput::Src,
                RopInput::Dest
            ),
            Rop(1)
        );
        // !(!src and !dest) == src or dest
        assert_eq!(
            ropd_to_rop(
                ropd::OP_AND | ropd::INVERS_SRC | ropd::INVERS_DEST | ropd::INVERS_RES,
                RopInput::Src,
                RopInput::Dest
            ),
            Rop(7)
        );
    }

    #[test]
    fn an_even_number_of_inversions_turns_xor_into_equivalence() {
        assert_eq!(
            ropd_to_rop(ropd::OP_XOR, RopInput::Src, RopInput::Dest),
            Rop(6)
        );
        assert_eq!(
            ropd_to_rop(
                ropd::OP_XOR | ropd::INVERS_SRC,
                RopInput::Src,
                RopInput::Dest
            ),
            Rop(9)
        );
        assert_eq!(
            ropd_to_rop(
                ropd::OP_XOR | ropd::INVERS_SRC | ropd::INVERS_DEST,
                RopInput::Src,
                RopInput::Dest
            ),
            Rop(6)
        );
    }

    #[test]
    fn the_brush_invert_bit_only_applies_when_the_brush_is_the_source() {
        // DRAW_FILL passes the brush as its source, so INVERS_BRUSH inverts.
        assert_eq!(
            ropd_to_rop(
                ropd::OP_PUT | ropd::INVERS_BRUSH,
                RopInput::Brush,
                RopInput::Dest
            ),
            Rop(12)
        );
        // DRAW_COPY passes the bitmap, so the same bit does nothing.
        assert_eq!(
            ropd_to_rop(
                ropd::OP_PUT | ropd::INVERS_BRUSH,
                RopInput::Src,
                RopInput::Dest
            ),
            Rop::COPY
        );
    }

    #[test]
    fn rop3_reproduces_its_own_self_test_constants() {
        // `rop3.c:129-142` evaluates each formula with these three values
        // and asserts the result is the opcode. That is the convention, so
        // it is the thing to test against.
        for opcode in 0..=255u8 {
            assert_eq!(
                apply_rop3(opcode, 0xF0, 0xCC, 0xAA),
                opcode,
                "opcode {opcode:#04x}"
            );
        }
    }

    #[test]
    fn rop3_includes_the_familiar_two_operand_codes() {
        // SRCCOPY is 0xCC: result = source.
        assert_eq!(apply_rop3(0xCC, 0x00, 0xAB, 0xFF), 0xAB);
        // PATCOPY is 0xF0: result = pattern.
        assert_eq!(apply_rop3(0xF0, 0xAB, 0x00, 0xFF), 0xAB);
        // BLACKNESS and WHITENESS.
        assert_eq!(apply_rop3(0x00, 0xFF, 0xFF, 0xFF), 0x00);
        assert_eq!(apply_rop3(0xFF, 0x00, 0x00, 0x00), 0xFF);
    }

    fn solid_image(width: u32, height: u32, colour: [u8; 4]) -> DecodedImage {
        DecodedImage {
            width,
            height,
            format: Format::Bgra8,
            has_alpha: true,
            data: colour.repeat(width as usize * height as usize),
        }
    }

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> SpiceRect {
        SpiceRect {
            top,
            left,
            bottom,
            right,
        }
    }

    #[test]
    fn a_fill_covers_only_the_box_and_only_inside_the_clip() {
        let mut surface = Surface::new(4, 4, surface_fmt::RGB32_XRGB);
        let clip = Clip {
            rects: Some(vec![rect(0, 0, 2, 4)]),
        };
        draw(
            &mut surface,
            &rect(0, 0, 4, 4),
            &clip,
            None,
            Rop::COPY,
            &Source::Solid([1, 2, 3, 4]),
        );
        assert_eq!(surface.pixel(0, 0), Some([1, 2, 3, 255]));
        assert_eq!(surface.pixel(2, 0), Some([0, 0, 0, 255]));
    }

    #[test]
    fn a_fill_on_an_opaque_surface_leaves_alpha_opaque() {
        let mut surface = Surface::new(1, 1, surface_fmt::RGB32_XRGB);
        draw(
            &mut surface,
            &rect(0, 0, 1, 1),
            &Clip::default(),
            None,
            Rop::COPY,
            &Source::Solid([1, 2, 3, 0]),
        );
        assert_eq!(surface.pixel(0, 0), Some([1, 2, 3, 255]));
    }

    #[test]
    fn a_mask_stops_the_pixels_it_does_not_cover_and_inverts_on_request() {
        let mask = Mask {
            width: 2,
            height: 1,
            bits: vec![1, 0],
        };
        let mut surface = Surface::new(2, 1, surface_fmt::RGB32_XRGB);
        draw(
            &mut surface,
            &rect(0, 0, 2, 1),
            &Clip::default(),
            Some(&MaskRef {
                mask: &mask,
                pos: Point { x: 0, y: 0 },
                inverted: false,
            }),
            Rop::COPY,
            &Source::Solid([9, 9, 9, 255]),
        );
        assert_eq!(surface.pixel(0, 0), Some([9, 9, 9, 255]));
        assert_eq!(surface.pixel(1, 0), Some([0, 0, 0, 255]));

        let mut surface = Surface::new(2, 1, surface_fmt::RGB32_XRGB);
        draw(
            &mut surface,
            &rect(0, 0, 2, 1),
            &Clip::default(),
            Some(&MaskRef {
                mask: &mask,
                pos: Point { x: 0, y: 0 },
                inverted: true,
            }),
            Rop::COPY,
            &Source::Solid([9, 9, 9, 255]),
        );
        assert_eq!(surface.pixel(0, 0), Some([0, 0, 0, 255]));
        assert_eq!(surface.pixel(1, 0), Some([9, 9, 9, 255]));
    }

    #[test]
    fn an_unscaled_blit_lands_pixel_for_pixel() {
        let image = DecodedImage {
            width: 2,
            height: 2,
            format: Format::Bgra8,
            has_alpha: false,
            data: vec![
                1, 1, 1, 0, 2, 2, 2, 0, //
                3, 3, 3, 0, 4, 4, 4, 0,
            ],
        };
        let sampler = Sampler::new(
            &image,
            rect(0, 0, 2, 2),
            rect(1, 1, 3, 3),
            ScaleMode::Nearest,
        );
        assert!(sampler.is_one_to_one());
        let mut surface = Surface::new(4, 4, surface_fmt::RGB32_XRGB);
        draw(
            &mut surface,
            &rect(1, 1, 3, 3),
            &Clip::default(),
            None,
            Rop::COPY,
            &Source::Bitmap(sampler),
        );
        assert_eq!(surface.pixel(1, 1), Some([1, 1, 1, 255]));
        assert_eq!(surface.pixel(2, 2), Some([4, 4, 4, 255]));
        assert_eq!(surface.pixel(0, 0), Some([0, 0, 0, 255]));
    }

    #[test]
    fn a_doubled_blit_repeats_each_source_pixel_under_nearest() {
        let image = DecodedImage {
            width: 2,
            height: 1,
            format: Format::Bgra8,
            has_alpha: false,
            data: vec![10, 10, 10, 0, 20, 20, 20, 0],
        };
        let sampler = Sampler::new(
            &image,
            rect(0, 0, 2, 1),
            rect(0, 0, 4, 1),
            ScaleMode::Nearest,
        );
        assert!(!sampler.is_one_to_one());
        assert_eq!(sampler.at(0, 0).unwrap()[0], 10);
        assert_eq!(sampler.at(1, 0).unwrap()[0], 10);
        assert_eq!(sampler.at(2, 0).unwrap()[0], 20);
        assert_eq!(sampler.at(3, 0).unwrap()[0], 20);
    }

    #[test]
    fn an_interpolated_blit_lands_between_the_two_taps() {
        let image = DecodedImage {
            width: 2,
            height: 1,
            format: Format::Bgra8,
            has_alpha: false,
            data: vec![0, 0, 0, 0, 100, 100, 100, 0],
        };
        let sampler = Sampler::new(
            &image,
            rect(0, 0, 2, 1),
            rect(0, 0, 4, 1),
            ScaleMode::Interpolate,
        );
        let middle = sampler.at(1, 0).unwrap()[0];
        assert!((40..=60).contains(&middle), "got {middle}");
    }

    #[test]
    fn a_pattern_brush_tiles_in_both_directions_including_negatively() {
        let image = solid_image(1, 1, [7, 7, 7, 255]);
        let source = Source::Pattern {
            image: &image,
            origin: Point { x: 3, y: 3 },
        };
        assert_eq!(source.at(0, 0), Some([7, 7, 7, 255]));
        assert_eq!(source.at(-5, -5), Some([7, 7, 7, 255]));
    }

    #[test]
    fn transparent_leaves_the_keyed_colour_alone() {
        let image = DecodedImage {
            width: 2,
            height: 1,
            format: Format::Bgra8,
            has_alpha: false,
            data: vec![0xFF, 0x00, 0xFF, 0, 1, 2, 3, 0],
        };
        let sampler = Sampler::new(
            &image,
            rect(0, 0, 2, 1),
            rect(0, 0, 2, 1),
            ScaleMode::Nearest,
        );
        let mut surface = Surface::new(2, 1, surface_fmt::RGB32_XRGB);
        draw(
            &mut surface,
            &rect(0, 0, 2, 1),
            &Clip::default(),
            None,
            Rop::COPY,
            &Source::Solid([8, 8, 8, 255]),
        );
        // 0x00FF00FF little-endian is B=0xFF, G=0x00, R=0xFF.
        draw_transparent(
            &mut surface,
            &rect(0, 0, 2, 1),
            &Clip::default(),
            &sampler,
            0x00FF_00FF,
        );
        assert_eq!(surface.pixel(0, 0), Some([8, 8, 8, 255]));
        assert_eq!(surface.pixel(1, 0), Some([1, 2, 3, 255]));
    }

    #[test]
    fn alpha_blend_at_zero_changes_nothing_and_at_full_replaces() {
        let image = solid_image(1, 1, [200, 200, 200, 255]);
        let sampler = Sampler::new(
            &image,
            rect(0, 0, 1, 1),
            rect(0, 0, 1, 1),
            ScaleMode::Nearest,
        );
        let mut surface = Surface::new(1, 1, surface_fmt::RGB32_XRGB);
        draw(
            &mut surface,
            &rect(0, 0, 1, 1),
            &Clip::default(),
            None,
            Rop::COPY,
            &Source::Solid([10, 10, 10, 255]),
        );
        draw_alpha_blend(
            &mut surface,
            &rect(0, 0, 1, 1),
            &Clip::default(),
            &sampler,
            0,
            true,
        );
        assert_eq!(surface.pixel(0, 0), Some([10, 10, 10, 255]));

        draw_alpha_blend(
            &mut surface,
            &rect(0, 0, 1, 1),
            &Clip::default(),
            &sampler,
            255,
            true,
        );
        assert_eq!(surface.pixel(0, 0), Some([200, 200, 200, 255]));
    }

    #[test]
    fn a_line_reaches_both_of_its_endpoints() {
        let mut surface = Surface::new(8, 8, surface_fmt::RGB32_XRGB);
        draw_line(
            &mut surface,
            &Clip::default(),
            (0.0, 0.0),
            (7.0, 7.0),
            [5, 5, 5, 255],
            Rop::COPY,
        );
        assert_eq!(surface.pixel(0, 0), Some([5, 5, 5, 255]));
        assert_eq!(surface.pixel(7, 7), Some([5, 5, 5, 255]));
        assert_eq!(surface.pixel(0, 7), Some([0, 0, 0, 255]));
    }

    #[test]
    fn a_line_with_identical_endpoints_terminates() {
        let mut surface = Surface::new(4, 4, surface_fmt::RGB32_XRGB);
        draw_line(
            &mut surface,
            &Clip::default(),
            (2.0, 2.0),
            (2.0, 2.0),
            [1, 1, 1, 255],
            Rop::COPY,
        );
        assert_eq!(surface.pixel(2, 2), Some([1, 1, 1, 255]));
    }

    #[test]
    fn a_one_bit_glyph_covers_the_pixels_whose_bits_are_set() {
        let glyph = crate::display::types::Glyph {
            render_pos: Point { x: 1, y: 1 },
            origin: Point { x: 0, y: 0 },
            width: 2,
            height: 1,
            data: vec![0b1000_0000],
        };
        let mut surface = Surface::new(4, 4, surface_fmt::RGB32_XRGB);
        draw_glyph(
            &mut surface,
            &Clip::default(),
            &glyph,
            1,
            &Source::Solid([255, 255, 255, 255]),
        );
        assert_eq!(surface.pixel(1, 1), Some([255, 255, 255, 255]));
        assert_eq!(surface.pixel(2, 1), Some([0, 0, 0, 255]));
    }

    #[test]
    fn a_four_bit_glyph_scales_its_nibble_to_full_coverage() {
        let glyph = crate::display::types::Glyph {
            render_pos: Point { x: 0, y: 0 },
            origin: Point { x: 0, y: 0 },
            width: 2,
            height: 1,
            data: vec![0xF0],
        };
        let mut surface = Surface::new(2, 1, surface_fmt::RGB32_XRGB);
        draw_glyph(
            &mut surface,
            &Clip::default(),
            &glyph,
            4,
            &Source::Solid([100, 100, 100, 255]),
        );
        assert_eq!(surface.pixel(0, 0), Some([100, 100, 100, 255]));
        assert_eq!(surface.pixel(1, 0), Some([0, 0, 0, 255]));
    }

    #[test]
    fn a_colour_word_unpacks_little_endian_into_bgra() {
        assert_eq!(colour_to_bgra(0x00112233, false), [0x33, 0x22, 0x11, 0xFF]);
        assert_eq!(colour_to_bgra(0x44112233, true), [0x33, 0x22, 0x11, 0x44]);
    }

    #[test]
    fn operations_that_ignore_their_source_say_so() {
        assert!(Rop::CLEAR.ignores_source());
        assert!(Rop::SET.ignores_source());
        assert!(Rop::INVERT.ignores_source());
        assert!(Rop::NOOP.ignores_source());
        assert!(!Rop::COPY.ignores_source());
    }
}
