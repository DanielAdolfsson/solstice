//! Executing one draw command.
//!
//! Each `DRAW_*` message is parsed into the structures in
//! [`crate::display::types`], has its images decoded by
//! [`crate::display::image`], and is then run through
//! [`crate::display::raster`] onto a surface. This module is the join
//! between the three, and the place where each command's own quirks live.
//!
//! Three of those quirks are worth stating here, because they are not
//! guessable from the message layouts:
//!
//! * **`DRAW_BLEND` is `DRAW_COPY`.** Identical layout, identical handling;
//!   `canvas_base.c:3307` assigns the same function to both and says so in a
//!   comment.
//! * **`DRAW_OPAQUE` is two operations.** The bitmap is blitted with a plain
//!   copy and *then* the brush is applied over it with the command's raster
//!   operation -- which is why its `ropd` is resolved with the brush as the
//!   source and the **bitmap** as the destination
//!   (`canvas_base.c:2425-2427`), the only command where "destination" is not
//!   the surface.
//! * **`COPY_BITS` is read before it is written.** Source and destination are
//!   the same surface and may overlap, so the source rectangle is copied out
//!   first. That also makes it clip like every other command, which a
//!   straight `memmove` could not.

use std::sync::Arc;

use crate::display::image::{DecodedImage, Format, ImageDecoder, Mask};
use crate::display::raster::{self, MaskRef, Rop, RopInput, Sampler, ScaleMode, Source};
use crate::display::surface::SurfaceSet;
use crate::display::types::{self, Brush, DrawBase, Image, Point, QMask, SpiceRect};
use crate::error::{Result, SpiceError};
use crate::protocol::display_msg;
use crate::wire::Reader;

/// What executing a command changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Damage {
    /// Which surface.
    pub surface_id: u32,
    /// The rectangle that changed, in that surface's coordinates.
    pub rect: SpiceRect,
}

/// Decode a command's source bitmap and mask, if it has them.
struct Resolved {
    image: Option<Arc<DecodedImage>>,
    mask: Option<Mask>,
}

/// Execute one `DRAW_*` or `COPY_BITS` message.
///
/// Returns the damaged region, or `None` when the command drew nothing --
/// a no-op raster operation, an empty clip, or a rectangle entirely outside
/// the surface.
pub fn execute(
    kind: u16,
    body: &[u8],
    surfaces: &mut SurfaceSet,
    images: &mut ImageDecoder,
) -> Result<Option<Damage>> {
    let mut r = Reader::new(body);
    let base = DrawBase::parse(&mut r)?;

    let Some(surface) = surfaces.get(base.surface_id) else {
        // A command for a surface that does not exist is a protocol error,
        // but the recoverable kind: the session carries on with the
        // surfaces it does have.
        return Err(SpiceError::protocol(format!(
            "a draw command for surface {}, which does not exist",
            base.surface_id
        )));
    };
    let (width, height) = (surface.width(), surface.height());
    let has_alpha = surface.has_alpha();
    // `Limits::max_pixels` lowered to the destination, which is what the
    // codec crate asks a display channel to do: a bitmap cannot legitimately
    // be larger than the surface it lands on.
    let max_pixels = width as u64 * height as u64;

    // Nothing survives a destination rectangle outside the surface, and the
    // clip can empty it too.
    let visible = clipped_bounds(&base, width, height);
    if visible.is_empty() {
        return Ok(None);
    }

    match kind {
        display_msg::DRAW_FILL => {
            let brush = Brush::parse(&mut r)?;
            let descriptor = r.u16()?;
            let mask = QMask::parse(&mut r)?;
            let rop = raster::ropd_to_rop(descriptor, RopInput::Brush, RopInput::Dest);
            if rop == Rop::NOOP {
                return Ok(None);
            }
            let resolved = resolve(images, body, None, &mask, max_pixels)?;
            let brush_image = brush_image(images, body, &brush, max_pixels)?;
            let source = brush_source(&brush, brush_image.as_deref(), has_alpha);
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");
            raster::draw(
                surface,
                &base.box_,
                &base.clip,
                mask_ref(&resolved, &mask).as_ref(),
                rop,
                &source,
            );
        }

        display_msg::DRAW_COPY | display_msg::DRAW_BLEND => {
            let image = Image::parse_ptr(&mut r)?;
            let src_area = SpiceRect::parse(&mut r)?;
            let descriptor = r.u16()?;
            let scale_mode = ScaleMode::from_wire(r.u8()?);
            let mask = QMask::parse(&mut r)?;
            let rop = raster::ropd_to_rop(descriptor, RopInput::Src, RopInput::Dest);
            if rop == Rop::NOOP {
                return Ok(None);
            }
            let resolved = resolve(images, body, image.as_ref(), &mask, max_pixels)?;
            let Some(bitmap) = resolved.image.clone() else {
                return Ok(None);
            };
            let sampler = Sampler::new(&bitmap, src_area, base.box_, scale_mode);
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");
            raster::draw(
                surface,
                &base.box_,
                &base.clip,
                mask_ref(&resolved, &mask).as_ref(),
                rop,
                &Source::Bitmap(sampler),
            );
        }

        display_msg::DRAW_OPAQUE => {
            let image = Image::parse_ptr(&mut r)?;
            let src_area = SpiceRect::parse(&mut r)?;
            let brush = Brush::parse(&mut r)?;
            let descriptor = r.u16()?;
            let scale_mode = ScaleMode::from_wire(r.u8()?);
            let mask = QMask::parse(&mut r)?;
            // The brush is the source and the *bitmap* is the destination.
            let rop = raster::ropd_to_rop(descriptor, RopInput::Brush, RopInput::Src);
            let resolved = resolve(images, body, image.as_ref(), &mask, max_pixels)?;
            let brush_image = brush_image(images, body, &brush, max_pixels)?;
            let mask_ref = mask_ref(&resolved, &mask);
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");

            if let Some(bitmap) = resolved.image.clone() {
                let sampler = Sampler::new(&bitmap, src_area, base.box_, scale_mode);
                raster::draw(
                    surface,
                    &base.box_,
                    &base.clip,
                    mask_ref.as_ref(),
                    Rop::COPY,
                    &Source::Bitmap(sampler),
                );
            }
            if rop != Rop::NOOP {
                let source = brush_source(&brush, brush_image.as_deref(), has_alpha);
                raster::draw(
                    surface,
                    &base.box_,
                    &base.clip,
                    mask_ref.as_ref(),
                    rop,
                    &source,
                );
            }
        }

        display_msg::DRAW_BLACKNESS | display_msg::DRAW_WHITENESS | display_msg::DRAW_INVERS => {
            let mask = QMask::parse(&mut r)?;
            let resolved = resolve(images, body, None, &mask, max_pixels)?;
            let (rop, rgb) = match kind {
                display_msg::DRAW_BLACKNESS => (Rop::CLEAR, [0, 0, 0]),
                display_msg::DRAW_WHITENESS => (Rop::SET, [0xFF, 0xFF, 0xFF]),
                _ => (Rop::INVERT, [0, 0, 0]),
            };
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");
            raster::draw_solid_rgb(
                surface,
                &base.box_,
                &base.clip,
                mask_ref(&resolved, &mask).as_ref(),
                rop,
                rgb,
            );
        }

        display_msg::DRAW_ROP3 => {
            let image = Image::parse_ptr(&mut r)?;
            let src_area = SpiceRect::parse(&mut r)?;
            let brush = Brush::parse(&mut r)?;
            let opcode = r.u8()?;
            let scale_mode = ScaleMode::from_wire(r.u8()?);
            let mask = QMask::parse(&mut r)?;
            let resolved = resolve(images, body, image.as_ref(), &mask, max_pixels)?;
            let brush_image = brush_image(images, body, &brush, max_pixels)?;
            let pattern = brush_source(&brush, brush_image.as_deref(), has_alpha);
            let bitmap = resolved.image.clone();
            let source = match bitmap.as_deref() {
                Some(bitmap) => {
                    Source::Bitmap(Sampler::new(bitmap, src_area, base.box_, scale_mode))
                }
                None => Source::Solid([0, 0, 0, 0]),
            };
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");
            raster::draw_rop3(
                surface,
                &base.box_,
                &base.clip,
                mask_ref(&resolved, &mask).as_ref(),
                opcode,
                &pattern,
                &source,
            );
        }

        display_msg::DRAW_TRANSPARENT => {
            let image = Image::parse_ptr(&mut r)?;
            let src_area = SpiceRect::parse(&mut r)?;
            let src_color = r.u32()?;
            let _true_color = r.u32()?;
            let resolved = resolve(images, body, image.as_ref(), &QMask::none(), max_pixels)?;
            let Some(bitmap) = resolved.image.clone() else {
                return Ok(None);
            };
            let sampler = Sampler::new(&bitmap, src_area, base.box_, ScaleMode::Nearest);
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");
            raster::draw_transparent(surface, &base.box_, &base.clip, &sampler, src_color);
        }

        display_msg::DRAW_ALPHA_BLEND => {
            let flags = r.u8()?;
            let alpha = r.u8()?;
            let image = Image::parse_ptr(&mut r)?;
            let src_area = SpiceRect::parse(&mut r)?;
            let resolved = resolve(images, body, image.as_ref(), &QMask::none(), max_pixels)?;
            let Some(bitmap) = resolved.image.clone() else {
                return Ok(None);
            };
            let source_has_alpha = bitmap.has_alpha
                || flags & crate::protocol::alpha_flags::SRC_SURFACE_HAS_ALPHA != 0;
            let sampler = Sampler::new(&bitmap, src_area, base.box_, ScaleMode::Nearest);
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");
            raster::draw_alpha_blend(
                surface,
                &base.box_,
                &base.clip,
                &sampler,
                alpha,
                source_has_alpha,
            );
        }

        display_msg::DRAW_STROKE => {
            let path = types::parse_path(&mut r)?;
            parse_line_attr(&mut r)?;
            let brush = Brush::parse(&mut r)?;
            let _fore_mode = r.u16()?;
            let _back_mode = r.u16()?;
            let colour = match brush {
                Brush::Solid(colour) => raster::colour_to_bgra(colour, has_alpha),
                // A patterned stroke is rare enough that the pattern's first
                // pixel is a better approximation than skipping the line.
                Brush::Pattern { ref image, .. } => {
                    let decoded = images.decode(image, body, max_pixels)?;
                    decoded.pixel(0, 0).unwrap_or([0, 0, 0, 0xFF])
                }
                Brush::None => return Ok(None),
            };
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");
            raster::stroke_path(surface, &base.clip, &path, colour, Rop::COPY);
        }

        display_msg::DRAW_TEXT => {
            let string = types::parse_glyph_string(&mut r)?;
            let back_area = SpiceRect::parse(&mut r)?;
            let fore_brush = Brush::parse(&mut r)?;
            let back_brush = Brush::parse(&mut r)?;
            let _fore_mode = r.u16()?;
            let _back_mode = r.u16()?;

            let fore_image = brush_image(images, body, &fore_brush, max_pixels)?;
            let back_image = brush_image(images, body, &back_brush, max_pixels)?;
            let bits = string.bits_per_pixel();
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");

            if !matches!(back_brush, Brush::None) && !back_area.is_empty() {
                let source = brush_source(&back_brush, back_image.as_deref(), has_alpha);
                raster::draw(surface, &back_area, &base.clip, None, Rop::COPY, &source);
            }
            let source = brush_source(&fore_brush, fore_image.as_deref(), has_alpha);
            for glyph in &string.glyphs {
                raster::draw_glyph(surface, &base.clip, glyph, bits, &source);
            }
        }

        display_msg::COPY_BITS => {
            let src_pos = Point::parse(&mut r)?;
            // The snapshot is taken of `visible`, not of the command's own
            // box. The box is two `i32` pairs off the wire and a server that
            // asks to copy a billion pixels wide would otherwise have the
            // client allocate for it before anything else is checked -- a
            // fuzzer found exactly that, a 989986816 x 2883584 rectangle on
            // a 64 x 48 surface. `visible` is already intersected with the
            // surface and the clip, so it is bounded by what exists.
            let offset_x = visible.left as i64 - base.box_.left as i64;
            let offset_y = visible.top as i64 - base.box_.top as i64;
            let patch = snapshot(
                surfaces,
                base.surface_id,
                src_pos.x as i64 + offset_x,
                src_pos.y as i64 + offset_y,
                visible.width(),
                visible.height(),
            )?;
            let Some(patch) = patch else {
                return Ok(None);
            };
            let src_area = SpiceRect {
                top: 0,
                left: 0,
                bottom: patch.height as i32,
                right: patch.width as i32,
            };
            let surface = surfaces.get_mut(base.surface_id).expect("checked above");
            // `COPY_BITS` never scales, so the sampler is one-to-one and the
            // destination is the visible rectangle rather than the box.
            let sampler = Sampler::new(&patch, src_area, visible, ScaleMode::Nearest);
            raster::draw(
                surface,
                &visible,
                &base.clip,
                None,
                Rop::COPY,
                &Source::Bitmap(sampler),
            );
        }

        other => {
            return Err(SpiceError::protocol(format!(
                "draw command {other} is not one this client executes"
            )))
        }
    }

    Ok(Some(Damage {
        surface_id: base.surface_id,
        rect: visible,
    }))
}

impl QMask {
    /// The mask a command without one behaves as if it had.
    fn none() -> Self {
        QMask {
            flags: 0,
            pos: Point { x: 0, y: 0 },
            bitmap: None,
        }
    }
}

/// The part of a command's box that can actually change pixels.
fn clipped_bounds(base: &DrawBase, width: u32, height: u32) -> SpiceRect {
    let surface = SpiceRect {
        top: 0,
        left: 0,
        bottom: height as i32,
        right: width as i32,
    };
    let mut visible = base.box_.intersect(&surface);
    if let Some(clip) = base.clip.bounds() {
        visible = visible.intersect(&clip);
    }
    if visible.is_empty() {
        return SpiceRect::default();
    }
    visible
}

fn resolve(
    images: &mut ImageDecoder,
    body: &[u8],
    image: Option<&Image>,
    mask: &QMask,
    max_pixels: u64,
) -> Result<Resolved> {
    let decoded = match image {
        Some(image) => Some(images.decode(image, body, max_pixels)?),
        None => None,
    };
    let mask = match &mask.bitmap {
        Some(bitmap) => Some(images.decode_mask(bitmap, body, max_pixels)?),
        None => None,
    };
    Ok(Resolved {
        image: decoded,
        mask,
    })
}

fn mask_ref<'a>(resolved: &'a Resolved, mask: &QMask) -> Option<MaskRef<'a>> {
    resolved.mask.as_ref().map(|decoded| MaskRef {
        mask: decoded,
        pos: mask.pos,
        inverted: mask.inverted(),
    })
}

fn brush_image(
    images: &mut ImageDecoder,
    body: &[u8],
    brush: &Brush,
    max_pixels: u64,
) -> Result<Option<Arc<DecodedImage>>> {
    match brush {
        Brush::Pattern { image, .. } => Ok(Some(images.decode(image, body, max_pixels)?)),
        _ => Ok(None),
    }
}

fn brush_source<'a>(brush: &Brush, image: Option<&'a DecodedImage>, has_alpha: bool) -> Source<'a> {
    match brush {
        Brush::Solid(colour) => Source::Solid(raster::colour_to_bgra(*colour, has_alpha)),
        Brush::Pattern { pos, .. } => match image {
            Some(image) => Source::Pattern {
                image,
                origin: *pos,
            },
            None => Source::None,
        },
        Brush::None => Source::None,
    }
}

/// Copy a `width` x `height` rectangle out of a surface, for `COPY_BITS`.
///
/// The caller passes a rectangle already bounded by the surface: this is the
/// only allocation in the draw path whose size is not fixed by a decoder's
/// own ceiling, so it has to be bounded here.
fn snapshot(
    surfaces: &SurfaceSet,
    surface_id: u32,
    src_x: i64,
    src_y: i64,
    width: i64,
    height: i64,
) -> Result<Option<DecodedImage>> {
    let surface = surfaces.get(surface_id).ok_or_else(|| {
        SpiceError::protocol(format!("COPY_BITS on missing surface {surface_id}"))
    })?;
    if width <= 0 || height <= 0 {
        return Ok(None);
    }
    if width > surface.width() as i64 || height > surface.height() as i64 {
        return Err(SpiceError::limit(format!(
            "COPY_BITS of {width}x{height} on a {}x{} surface",
            surface.width(),
            surface.height()
        )));
    }
    let mut data = Vec::with_capacity((width * height * 4) as usize);
    for row in 0..height {
        for column in 0..width {
            // Outside the surface reads as transparent black rather than
            // failing: a scroll that reaches past an edge is ordinary.
            let pixel = surface
                .pixel(src_x + column, src_y + row)
                .unwrap_or([0, 0, 0, 0]);
            data.extend_from_slice(&pixel);
        }
    }
    Ok(Some(DecodedImage {
        width: width as u32,
        height: height as u32,
        format: Format::Bgra8,
        has_alpha: surface.has_alpha(),
        data,
    }))
}

/// Skip a `LineAttr`, which this client does not honour.
///
/// Styled lines are dashes and widths; [`raster::stroke_path`] draws every
/// stroke as a hairline. The structure still has to be *parsed*, because
/// everything after it in the message depends on its length.
fn parse_line_attr(r: &mut Reader<'_>) -> Result<()> {
    const STYLED: u8 = 1 << 3;
    let flags = r.u8()?;
    if flags & STYLED != 0 {
        let _segments = r.u8()?;
        // `fixed28_4 *style[style_nseg]` is a pointer to the array, not the
        // array itself, so it is four bytes however many segments there are.
        let _ = r.pointer()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        bitmap_flags, bitmap_fmt, brush_type, clip_type, image_type, ropd, surface_fmt,
    };
    use crate::wire::Writer;
    use solstice_spice_codec::Limits;

    fn surfaces(width: u32, height: u32) -> SurfaceSet {
        let mut set = SurfaceSet::new();
        set.create(0, width, height, surface_fmt::RGB32_XRGB, true)
            .unwrap();
        set
    }

    fn decoder() -> ImageDecoder {
        ImageDecoder::new(Limits::default(), 1 << 20)
    }

    /// `DisplayBase` with no clip.
    fn base(w: &mut Writer, left: i32, top: i32, right: i32, bottom: i32) {
        w.u32(0);
        w.i32(top).i32(left).i32(bottom).i32(right);
        w.u8(clip_type::NONE);
    }

    fn null_mask(w: &mut Writer) {
        w.u8(0).i32(0).i32(0).u32(0);
    }

    #[test]
    fn a_fill_paints_its_box_in_the_brush_colour() {
        let mut set = surfaces(4, 4);
        let mut images = decoder();
        let mut w = Writer::new();
        base(&mut w, 1, 1, 3, 3);
        w.u8(brush_type::SOLID).u32(0x0012_3456);
        w.u16(ropd::OP_PUT);
        null_mask(&mut w);

        let damage = execute(display_msg::DRAW_FILL, &w.finish(), &mut set, &mut images)
            .unwrap()
            .unwrap();
        assert_eq!(damage.surface_id, 0);
        assert_eq!(damage.rect.left, 1);
        let surface = set.get(0).unwrap();
        assert_eq!(surface.pixel(1, 1), Some([0x56, 0x34, 0x12, 0xFF]));
        assert_eq!(surface.pixel(0, 0), Some([0, 0, 0, 0xFF]));
    }

    #[test]
    fn no_raster_descriptor_actually_collapses_to_a_no_op() {
        // The `Rop::NOOP` guards in `execute` mirror the ones in
        // `canvas_base.c`, and in both places they are unreachable: the
        // sixteen operations `ropd` can name do not include "leave the
        // destination alone". Asserting that keeps the guards honest --
        // if a future descriptor ever does collapse to it, this fails
        // rather than the guard silently starting to fire.
        for descriptor in 0u16..=ropd::INVERS_RES.next_power_of_two() {
            for (src, dest) in [
                (RopInput::Src, RopInput::Dest),
                (RopInput::Brush, RopInput::Dest),
                (RopInput::Brush, RopInput::Src),
            ] {
                assert_ne!(
                    raster::ropd_to_rop(descriptor, src, dest),
                    Rop::NOOP,
                    "descriptor {descriptor:#x}"
                );
            }
        }
    }

    #[test]
    fn a_command_for_a_surface_that_does_not_exist_is_an_error() {
        let mut set = SurfaceSet::new();
        let mut images = decoder();
        let mut w = Writer::new();
        base(&mut w, 0, 0, 1, 1);
        w.u8(brush_type::SOLID).u32(0);
        w.u16(ropd::OP_PUT);
        null_mask(&mut w);
        assert!(execute(display_msg::DRAW_FILL, &w.finish(), &mut set, &mut images).is_err());
    }

    #[test]
    fn a_box_entirely_outside_the_surface_draws_nothing() {
        let mut set = surfaces(4, 4);
        let mut images = decoder();
        let mut w = Writer::new();
        base(&mut w, 100, 100, 110, 110);
        w.u8(brush_type::SOLID).u32(0x00FF_FFFF);
        w.u16(ropd::OP_PUT);
        null_mask(&mut w);
        assert_eq!(
            execute(display_msg::DRAW_FILL, &w.finish(), &mut set, &mut images).unwrap(),
            None
        );
    }

    /// A `DRAW_COPY` whose bitmap is a 2x2 raw BGRA image.
    fn copy_body(left: i32, top: i32, right: i32, bottom: i32) -> Vec<u8> {
        let mut w = Writer::new();
        base(&mut w, left, top, right, bottom);
        // The image pointer: the image goes at the end of the message, and
        // the fixed part is 4 (ptr) + 16 (src_area) + 2 (rop) + 1 (scale)
        // + 13 (mask) long.
        let header_len = w.len();
        let image_at = header_len + 4 + 16 + 2 + 1 + 13;
        w.u32(image_at as u32);
        w.i32(0).i32(0).i32(2).i32(2); // src_area: top, left, bottom, right
        w.u16(ropd::OP_PUT);
        w.u8(1); // nearest
        null_mask(&mut w);
        assert_eq!(w.len(), image_at);

        w.u64(1).u8(image_type::BITMAP).u8(0).u32(2).u32(2);
        w.u8(bitmap_fmt::BIT32).u8(bitmap_flags::TOP_DOWN);
        w.u32(2).u32(2).u32(8);
        w.u32(0); // no palette
        w.bytes(&[
            1, 1, 1, 0, 2, 2, 2, 0, //
            3, 3, 3, 0, 4, 4, 4, 0,
        ]);
        w.finish()
    }

    #[test]
    fn a_copy_blits_its_bitmap_through_a_pointer_at_the_end_of_the_message() {
        let mut set = surfaces(4, 4);
        let mut images = decoder();
        let damage = execute(
            display_msg::DRAW_COPY,
            &copy_body(1, 1, 3, 3),
            &mut set,
            &mut images,
        )
        .unwrap()
        .unwrap();
        assert_eq!(damage.rect.left, 1);
        let surface = set.get(0).unwrap();
        assert_eq!(surface.pixel(1, 1), Some([1, 1, 1, 0xFF]));
        assert_eq!(surface.pixel(2, 2), Some([4, 4, 4, 0xFF]));
        assert_eq!(surface.pixel(3, 3), Some([0, 0, 0, 0xFF]));
    }

    #[test]
    fn blend_is_handled_exactly_as_copy_is() {
        let mut copy_set = surfaces(4, 4);
        let mut blend_set = surfaces(4, 4);
        let mut images = decoder();
        let body = copy_body(0, 0, 2, 2);
        execute(display_msg::DRAW_COPY, &body, &mut copy_set, &mut images).unwrap();
        execute(display_msg::DRAW_BLEND, &body, &mut blend_set, &mut images).unwrap();
        assert_eq!(
            copy_set.get(0).unwrap().data(),
            blend_set.get(0).unwrap().data()
        );
    }

    #[test]
    fn blackness_and_whiteness_leave_the_alpha_channel_alone() {
        let mut set = SurfaceSet::new();
        set.create(0, 2, 2, surface_fmt::RGB32_ARGB, true).unwrap();
        let surface = set.get_mut(0).unwrap();
        surface.set_pixel(0, 0, [9, 9, 9, 0x80]);
        let mut images = decoder();

        let mut w = Writer::new();
        base(&mut w, 0, 0, 2, 2);
        null_mask(&mut w);
        let body = w.finish();

        execute(display_msg::DRAW_BLACKNESS, &body, &mut set, &mut images).unwrap();
        assert_eq!(set.get(0).unwrap().pixel(0, 0), Some([0, 0, 0, 0x80]));

        execute(display_msg::DRAW_WHITENESS, &body, &mut set, &mut images).unwrap();
        assert_eq!(
            set.get(0).unwrap().pixel(0, 0),
            Some([0xFF, 0xFF, 0xFF, 0x80])
        );

        execute(display_msg::DRAW_INVERS, &body, &mut set, &mut images).unwrap();
        assert_eq!(set.get(0).unwrap().pixel(0, 0), Some([0, 0, 0, 0x80]));
    }

    #[test]
    fn copy_bits_moves_a_region_within_one_surface_and_handles_overlap() {
        let mut set = surfaces(4, 4);
        {
            let surface = set.get_mut(0).unwrap();
            for x in 0..4 {
                surface.set_pixel(x, 0, [7, 7, 7, 0xFF]);
            }
        }
        let mut images = decoder();
        let mut w = Writer::new();
        base(&mut w, 0, 1, 4, 4);
        w.i32(0).i32(0); // src_pos
        execute(display_msg::COPY_BITS, &w.finish(), &mut set, &mut images).unwrap();
        let surface = set.get(0).unwrap();
        assert_eq!(surface.pixel(0, 1), Some([7, 7, 7, 0xFF]));
        assert_eq!(surface.pixel(0, 2), Some([0, 0, 0, 0xFF]));
    }

    #[test]
    fn copy_bits_with_an_absurd_rectangle_allocates_nothing() {
        // The regression `cargo fuzz run spice_draw` found in under a
        // minute: a destination box of 989986816 x 2883584 on a 64 x 48
        // surface, which asked for a 174 GB allocation.
        let mut set = surfaces(64, 48);
        let mut images = decoder();
        let mut w = Writer::new();
        w.u32(0);
        w.i32(0).i32(35).i32(2_883_584).i32(989_986_816);
        w.u8(clip_type::NONE);
        w.i32(0).i32(0);
        let damage = execute(display_msg::COPY_BITS, &w.finish(), &mut set, &mut images).unwrap();
        // It draws the part that exists, and nothing beyond it.
        let damage = damage.expect("the visible part is still drawn");
        assert!(damage.rect.width() <= 64);
        assert!(damage.rect.height() <= 48);
    }

    #[test]
    fn a_blit_with_wire_sized_rectangles_does_not_overflow() {
        // `tests/tools/fuzz.sh` found both in `spice_draw`'s first minutes,
        // two `DRAW_OPAQUE`s with i32 geometry at the extremes. The first
        // overflowed the sampler's fixed-point `dx * src_w * 256` in i64; the
        // second, with the destination's left edge at i32::MIN, overflowed
        // `x - dest.left` before it was widened. Replayed as the target runs
        // them, surfaces included.
        const BODIES: [&[u8]; 2] = [
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf2, 0x03, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7a, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x02, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0xe1, 0x8b,
            ],
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xf2, 0x03, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0xe1, 0x8b,
            ],
        ];
        for body in BODIES {
            let mut set = surfaces(64, 48);
            set.create(1, 16, 16, surface_fmt::RGB32_ARGB, false)
                .unwrap();
            let mut images = decoder();
            // Drawn or refused, either is fine; panicking is not.
            let _ = execute(display_msg::DRAW_OPAQUE, body, &mut set, &mut images);
        }
    }

    #[test]
    fn copy_bits_respects_the_clip_which_a_plain_memmove_could_not() {
        let mut set = surfaces(4, 4);
        {
            let surface = set.get_mut(0).unwrap();
            for x in 0..4 {
                surface.set_pixel(x, 0, [7, 7, 7, 0xFF]);
            }
        }
        let mut images = decoder();
        let mut w = Writer::new();
        w.u32(0);
        w.i32(1).i32(0).i32(4).i32(4); // box: rows 1..4
        w.u8(clip_type::RECTS).u32(1);
        w.i32(0).i32(0).i32(4).i32(2); // clip to the left two columns
        w.i32(0).i32(0); // src_pos
        execute(display_msg::COPY_BITS, &w.finish(), &mut set, &mut images).unwrap();
        let surface = set.get(0).unwrap();
        assert_eq!(surface.pixel(0, 1), Some([7, 7, 7, 0xFF]));
        assert_eq!(surface.pixel(2, 1), Some([0, 0, 0, 0xFF]));
    }

    #[test]
    fn a_truncated_draw_command_is_an_error_rather_than_a_panic() {
        let mut images = decoder();
        let body = copy_body(0, 0, 2, 2);
        for cut in 0..body.len() {
            let mut set = surfaces(4, 4);
            // Any outcome is acceptable except a panic.
            let _ = execute(display_msg::DRAW_COPY, &body[..cut], &mut set, &mut images);
        }
    }

    #[test]
    fn a_command_this_client_does_not_execute_is_reported_rather_than_ignored() {
        let mut set = surfaces(4, 4);
        let mut images = decoder();
        let mut w = Writer::new();
        base(&mut w, 0, 0, 1, 1);
        assert!(execute(
            display_msg::DRAW_COMPOSITE,
            &w.finish(),
            &mut set,
            &mut images
        )
        .is_err());
    }
}
