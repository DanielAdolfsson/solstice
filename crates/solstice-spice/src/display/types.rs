//! The structures the display channel's messages are built out of.
//!
//! Transcribed from `spice-common/spice.proto`, which is the authoritative
//! description of SPICE's wire format -- `messages.h` is generated from it
//! and the headers do not carry the layouts at all.
//!
//! Two properties of that format shape everything here.
//!
//! **Nothing is padded.** The marshaller appends fields one after another
//! with no alignment, so a `u8` followed by a `u32` occupies five bytes, not
//! eight. The C structs these parse into *are* padded; the wire is not.
//!
//! **Variable-length members are reached through 32-bit offsets.** A
//! `Image *src_bitmap` on the wire is an offset from the start of the message
//! body to where the image actually sits, with zero meaning null
//! (`python_modules/ptypes.py:564-590`). So parsing a draw command is not a
//! single forward pass: it reads a fixed part, then seeks. [`crate::wire::Reader`]
//! keeps the whole body for exactly this reason.

use crate::error::{Result, SpiceError};
use crate::protocol::{brush_type, clip_type, image_type, mask_flags, path_flags, string_flags};
use crate::wire::Reader;

/// `struct Point` -- two 32-bit signed coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    /// Horizontal.
    pub x: i32,
    /// Vertical.
    pub y: i32,
}

impl Point {
    /// Parse one.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Point {
            x: r.i32()?,
            y: r.i32()?,
        })
    }

    /// Parse a `Point16`.
    pub fn parse16(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Point {
            x: r.i16()? as i32,
            y: r.i16()? as i32,
        })
    }
}

/// `struct Rect`.
///
/// The field order on the wire is **top, left, bottom, right** -- not the
/// x/y/width/height every other protocol in this codebase uses, and not even
/// left-first. Getting it wrong produces a transposed picture rather than an
/// error, so it is converted to [`solstice_backend::Rect`] here, once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpiceRect {
    /// Top edge, inclusive.
    pub top: i32,
    /// Left edge, inclusive.
    pub left: i32,
    /// Bottom edge, exclusive.
    pub bottom: i32,
    /// Right edge, exclusive.
    pub right: i32,
}

impl SpiceRect {
    /// Parse one.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        Ok(SpiceRect {
            top: r.i32()?,
            left: r.i32()?,
            bottom: r.i32()?,
            right: r.i32()?,
        })
    }

    /// Width, clamped at zero.
    pub fn width(&self) -> i64 {
        (self.right as i64 - self.left as i64).max(0)
    }

    /// Height, clamped at zero.
    pub fn height(&self) -> i64 {
        (self.bottom as i64 - self.top as i64).max(0)
    }

    /// Whether the rectangle encloses anything.
    pub fn is_empty(&self) -> bool {
        self.width() == 0 || self.height() == 0
    }

    /// The overlap of two rectangles, which may be empty.
    pub fn intersect(&self, other: &SpiceRect) -> SpiceRect {
        SpiceRect {
            top: self.top.max(other.top),
            left: self.left.max(other.left),
            bottom: self.bottom.min(other.bottom),
            right: self.right.min(other.right),
        }
    }

    /// The smallest rectangle containing both.
    pub fn union(&self, other: &SpiceRect) -> SpiceRect {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        SpiceRect {
            top: self.top.min(other.top),
            left: self.left.min(other.left),
            bottom: self.bottom.max(other.bottom),
            right: self.right.max(other.right),
        }
    }

    /// Clamp to a `width` x `height` surface, as a backend rectangle.
    ///
    /// Returns `None` when nothing is left. Negative coordinates are legal on
    /// the wire -- a window being dragged off the left edge produces them --
    /// so they are clipped rather than refused.
    pub fn clamp_to(&self, width: u32, height: u32) -> Option<solstice_backend::Rect> {
        let left = self.left.max(0) as i64;
        let top = self.top.max(0) as i64;
        let right = (self.right as i64).min(width as i64);
        let bottom = (self.bottom as i64).min(height as i64);
        if right <= left || bottom <= top {
            return None;
        }
        Some(solstice_backend::Rect {
            x: left as u32,
            y: top as u32,
            width: (right - left) as u32,
            height: (bottom - top) as u32,
        })
    }
}

/// `struct Clip` -- either everything, or a list of rectangles.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Clip {
    /// `None` means unclipped. An empty vector means nothing is drawn, which
    /// is a different thing and a server does send it.
    pub rects: Option<Vec<SpiceRect>>,
}

/// The most clip rectangles one draw command may carry.
///
/// There is no protocol limit. A region with thousands of rectangles is
/// pathological rather than impossible, and the cost here is per-rectangle
/// work inside a per-pixel loop.
const MAX_CLIP_RECTS: u32 = 4096;

impl Clip {
    /// Parse one. The rectangles, when present, are inline rather than
    /// behind a pointer -- `spice.proto`'s `@to_ptr` on `ClipRects`.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let kind = r.u8()?;
        match kind {
            clip_type::NONE => Ok(Clip { rects: None }),
            clip_type::RECTS => {
                let count = r.u32()?;
                if count > MAX_CLIP_RECTS {
                    return Err(SpiceError::limit(format!(
                        "clip of {count} rectangles exceeds {MAX_CLIP_RECTS}"
                    )));
                }
                let count = r.count(count, 16)?;
                let mut rects = Vec::with_capacity(count);
                for _ in 0..count {
                    rects.push(SpiceRect::parse(r)?);
                }
                Ok(Clip { rects: Some(rects) })
            }
            other => Err(SpiceError::protocol(format!("clip type {other}"))),
        }
    }

    /// Whether a point survives the clip.
    pub fn contains(&self, x: i32, y: i32) -> bool {
        match &self.rects {
            None => true,
            Some(rects) => rects
                .iter()
                .any(|r| x >= r.left && x < r.right && y >= r.top && y < r.bottom),
        }
    }

    /// The bounding box of the clip, or `None` when it does not bound.
    pub fn bounds(&self) -> Option<SpiceRect> {
        let rects = self.rects.as_ref()?;
        Some(
            rects
                .iter()
                .fold(SpiceRect::default(), |acc, r| acc.union(r)),
        )
    }
}

/// `struct DisplayBase` -- the preamble on every draw command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawBase {
    /// Which surface to draw onto.
    pub surface_id: u32,
    /// The destination rectangle.
    pub box_: SpiceRect,
    /// The clip the whole command is subject to.
    pub clip: Clip,
}

impl DrawBase {
    /// Parse one.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        Ok(DrawBase {
            surface_id: r.u32()?,
            box_: SpiceRect::parse(r)?,
            clip: Clip::parse(r)?,
        })
    }
}

/// `struct ImageDescriptor` -- the wrapper around every bitmap.
///
/// The descriptor's `width` and `height` are the protocol's opinion of the
/// image's size and the codec stream's are the codec's. Where they disagree
/// the descriptor wins, because it is what the rest of the protocol believes
/// (`docs/roadmap.md` §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageDescriptor {
    /// Cache key.
    pub id: u64,
    /// `SPICE_IMAGE_TYPE_*`.
    pub kind: u8,
    /// `SPICE_IMAGE_FLAGS_*`.
    pub flags: u8,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl ImageDescriptor {
    /// Parse one.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ImageDescriptor {
            id: r.u64()?,
            kind: r.u8()?,
            flags: r.u8()?,
            width: r.u32()?,
            height: r.u32()?,
        })
    }

    /// Whether the server asked for this image to be kept in the pixmap
    /// cache.
    pub fn cache_me(&self) -> bool {
        self.flags & crate::protocol::image_flags::CACHE_ME != 0
    }
}

/// `struct Palette`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Palette {
    /// Cache key.
    pub unique: u64,
    /// Entries, each `0x00rrggbb`.
    pub entries: Vec<u32>,
}

impl Palette {
    /// Parse one.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let unique = r.u64()?;
        let num_ents = r.u16()?;
        let count = r.count(num_ents as u32, 4)?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(r.u32()?);
        }
        Ok(Palette { unique, entries })
    }

    /// The form the codec crate wants.
    pub fn to_codec(&self) -> solstice_spice_codec::Palette {
        solstice_spice_codec::Palette {
            entries: self.entries.clone(),
        }
    }
}

/// Where a palette came from: inline with the image, or out of the cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaletteRef {
    /// None was carried.
    None,
    /// Carried inline.
    Inline(Palette),
    /// `SPICE_BITMAP_FLAGS_PAL_FROM_CACHE`: look it up by id.
    Cached(u64),
}

/// `struct BitmapData` -- an uncompressed bitmap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBitmap {
    /// `SPICE_BITMAP_FMT_*`.
    pub format: u8,
    /// `SPICE_BITMAP_FLAGS_*`.
    pub flags: u8,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row, which is **not** always `width * bytes_per_pixel`.
    pub stride: u32,
    /// The palette indexed formats index into.
    pub palette: PaletteRef,
    /// Offset of the pixels within the message body, and their length.
    pub data: (usize, usize),
}

/// Where a compressed payload sits inside the message body.
///
/// Images are not copied out of the message while it is being parsed: a
/// full-screen bitmap is tens of megabytes and the draw command may turn out
/// to be clipped away entirely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payload {
    /// Offset from the start of the message body.
    pub offset: usize,
    /// Length in bytes.
    pub len: usize,
}

/// What an image's body turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageBody {
    /// An uncompressed bitmap.
    Raw(RawBitmap),
    /// A QUIC stream.
    Quic(Payload),
    /// An LZ or GLZ stream over RGB.
    LzRgb(Payload),
    /// An LZ stream over a palette, with the palette alongside.
    LzPlt {
        /// `SPICE_BITMAP_FLAGS_*`, for the top-down bit.
        flags: u8,
        /// Where the palette came from.
        palette: PaletteRef,
        /// Where the stream is.
        payload: Payload,
    },
    /// A GLZ stream wrapped in zlib.
    ZlibGlz {
        /// The size the inner GLZ stream inflates to.
        glz_size: u32,
        /// Where the deflate stream is.
        payload: Payload,
    },
    /// A JPEG stream.
    Jpeg(Payload),
    /// JPEG colour with a separately-LZ-compressed alpha plane.
    JpegAlpha {
        /// `SPICE_JPEG_ALPHA_FLAGS_*`.
        flags: u8,
        /// Bytes of the JPEG, which comes first.
        jpeg_size: u32,
        /// Where the JPEG and the alpha plane sit, end to end.
        payload: Payload,
    },
    /// An LZ4 stream.
    Lz4(Payload),
    /// The id in the descriptor refers to the pixmap cache.
    FromCache,
    /// The image is another surface.
    Surface(u32),
}

/// `struct Image` -- a descriptor and whatever the type says follows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// The descriptor.
    pub descriptor: ImageDescriptor,
    /// The payload.
    pub body: ImageBody,
}

impl Image {
    /// Parse the image a pointer member points at.
    ///
    /// `r` must be positioned at the start of the image; use
    /// [`crate::wire::Reader::at`] with the offset the pointer held.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let descriptor = ImageDescriptor::parse(r)?;
        let body = match descriptor.kind {
            image_type::BITMAP => {
                let format = r.u8()?;
                let flags = r.u8()?;
                let width = r.u32()?;
                let height = r.u32()?;
                let stride = r.u32()?;
                let palette = parse_palette_ref(r, flags)?;
                let len = (stride as u64)
                    .checked_mul(height as u64)
                    .filter(|n| *n <= r.remaining() as u64)
                    .ok_or(SpiceError::Truncated {
                        what: "raw bitmap",
                        wanted: stride as usize,
                        available: r.remaining(),
                    })? as usize;
                let offset = r.position();
                r.skip(len)?;
                ImageBody::Raw(RawBitmap {
                    format,
                    flags,
                    width,
                    height,
                    stride,
                    palette,
                    data: (offset, len),
                })
            }
            image_type::QUIC => ImageBody::Quic(parse_binary(r)?),
            image_type::LZ_RGB | image_type::GLZ_RGB => ImageBody::LzRgb(parse_binary(r)?),
            image_type::JPEG => ImageBody::Jpeg(parse_binary(r)?),
            image_type::LZ4 => ImageBody::Lz4(parse_binary(r)?),
            image_type::LZ_PLT => {
                let flags = r.u8()?;
                let data_size = r.u32()?;
                let palette = parse_palette_ref(r, flags)?;
                let len = r.count(data_size, 1)?;
                let offset = r.position();
                r.skip(len)?;
                ImageBody::LzPlt {
                    flags,
                    palette,
                    payload: Payload { offset, len },
                }
            }
            image_type::ZLIB_GLZ_RGB => {
                let glz_size = r.u32()?;
                let data_size = r.u32()?;
                let len = r.count(data_size, 1)?;
                let offset = r.position();
                r.skip(len)?;
                ImageBody::ZlibGlz {
                    glz_size,
                    payload: Payload { offset, len },
                }
            }
            image_type::JPEG_ALPHA => {
                let flags = r.u8()?;
                let jpeg_size = r.u32()?;
                let data_size = r.u32()?;
                let len = r.count(data_size, 1)?;
                if jpeg_size as usize > len {
                    return Err(SpiceError::protocol(format!(
                        "JPEG-with-alpha claims {jpeg_size} bytes of JPEG inside {len} bytes"
                    )));
                }
                let offset = r.position();
                r.skip(len)?;
                ImageBody::JpegAlpha {
                    flags,
                    jpeg_size,
                    payload: Payload { offset, len },
                }
            }
            image_type::FROM_CACHE | image_type::FROM_CACHE_LOSSLESS => ImageBody::FromCache,
            image_type::SURFACE => ImageBody::Surface(r.u32()?),
            other => {
                return Err(SpiceError::protocol(format!("image type {other}")));
            }
        };
        Ok(Image { descriptor, body })
    }

    /// Follow a pointer member, returning `None` for null.
    pub fn parse_ptr(r: &mut Reader<'_>) -> Result<Option<Self>> {
        let Some(offset) = r.pointer()? else {
            return Ok(None);
        };
        let mut at = r.at(offset)?;
        Image::parse(&mut at).map(Some)
    }
}

fn parse_binary(r: &mut Reader<'_>) -> Result<Payload> {
    let data_size = r.u32()?;
    let len = r.count(data_size, 1)?;
    let offset = r.position();
    r.skip(len)?;
    Ok(Payload { offset, len })
}

fn parse_palette_ref(r: &mut Reader<'_>, flags: u8) -> Result<PaletteRef> {
    if flags & crate::protocol::bitmap_flags::PAL_FROM_CACHE != 0 {
        return Ok(PaletteRef::Cached(r.u64()?));
    }
    match r.pointer()? {
        None => Ok(PaletteRef::None),
        Some(offset) => {
            let mut at = r.at(offset)?;
            Ok(PaletteRef::Inline(Palette::parse(&mut at)?))
        }
    }
}

/// `struct Brush`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Brush {
    /// Draws nothing.
    None,
    /// One colour, `0x00rrggbb` or `0xaarrggbb` depending on the surface.
    Solid(u32),
    /// A tiled image, anchored at a point.
    Pattern {
        /// The tile.
        image: Box<Image>,
        /// Where its origin sits in surface coordinates.
        pos: Point,
    },
}

impl Brush {
    /// Parse one.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let kind = r.u8()?;
        match kind {
            brush_type::NONE => Ok(Brush::None),
            brush_type::SOLID => Ok(Brush::Solid(r.u32()?)),
            brush_type::PATTERN => {
                let image = Image::parse_ptr(r)?;
                let pos = Point::parse(r)?;
                match image {
                    Some(image) => Ok(Brush::Pattern {
                        image: Box::new(image),
                        pos,
                    }),
                    // `@nonnull` in the proto; a null here is a server bug
                    // rather than an attack, and drawing nothing is the
                    // conservative reading.
                    None => Ok(Brush::None),
                }
            }
            other => Err(SpiceError::protocol(format!("brush type {other}"))),
        }
    }
}

/// `struct QMask` -- a 1-bit stencil over a draw command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QMask {
    /// `SPICE_MASK_FLAGS_*`.
    pub flags: u8,
    /// Where the mask's origin sits.
    pub pos: Point,
    /// The stencil, or `None` for an unmasked command.
    pub bitmap: Option<Box<Image>>,
}

impl QMask {
    /// Parse one.
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let flags = r.u8()?;
        let pos = Point::parse(r)?;
        let bitmap = Image::parse_ptr(r)?.map(Box::new);
        Ok(QMask { flags, pos, bitmap })
    }

    /// Whether the mask's sense is inverted.
    pub fn inverted(&self) -> bool {
        self.flags & mask_flags::INVERS != 0
    }
}

/// One segment of a `struct Path`.
#[derive(Clone, Debug, PartialEq)]
pub struct PathSegment {
    /// `SPICE_PATH_*`.
    pub flags: u8,
    /// The points, already converted out of 28.4 fixed point.
    pub points: Vec<(f32, f32)>,
}

impl PathSegment {
    /// Whether the points are Bézier control points rather than line ends.
    pub fn is_bezier(&self) -> bool {
        self.flags & path_flags::BEZIER != 0
    }

    /// Whether the segment closes back onto its first point.
    pub fn is_closed(&self) -> bool {
        self.flags & path_flags::CLOSE != 0
    }
}

/// The most path segments or points one stroke may carry.
const MAX_PATH_ELEMENTS: u32 = 65536;

/// `struct Path` -- a pointer to an array of pointers to segments.
pub fn parse_path(r: &mut Reader<'_>) -> Result<Vec<PathSegment>> {
    let Some(offset) = r.pointer()? else {
        return Ok(Vec::new());
    };
    let mut path = r.at(offset)?;
    let num_segments = path.u32()?;
    if num_segments > MAX_PATH_ELEMENTS {
        return Err(SpiceError::limit(format!(
            "path of {num_segments} segments exceeds {MAX_PATH_ELEMENTS}"
        )));
    }
    let count = path.count(num_segments, 4)?;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        offsets.push(path.u32()? as usize);
    }

    let mut segments = Vec::with_capacity(count);
    for offset in offsets {
        let mut seg = r.at(offset)?;
        let flags = seg.u8()?;
        let num_points = seg.u32()?;
        if num_points > MAX_PATH_ELEMENTS {
            return Err(SpiceError::limit(format!(
                "path segment of {num_points} points exceeds {MAX_PATH_ELEMENTS}"
            )));
        }
        let count = seg.count(num_points, 8)?;
        let mut points = Vec::with_capacity(count);
        for _ in 0..count {
            // `fixed28_4`: a signed 32-bit value with four fractional bits.
            let x = seg.i32()? as f32 / 16.0;
            let y = seg.i32()? as f32 / 16.0;
            points.push((x, y));
        }
        segments.push(PathSegment { flags, points });
    }
    Ok(segments)
}

/// One glyph out of a `struct String`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glyph {
    /// Where the glyph's box lands on the surface.
    pub render_pos: Point,
    /// The glyph's own origin, relative to its box.
    pub origin: Point,
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
    /// The coverage bitmap, 1, 4 or 8 bits per pixel as the string's flags
    /// say.
    pub data: Vec<u8>,
}

/// `struct String` -- the glyph run a `DRAW_TEXT` renders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlyphString {
    /// `SPICE_STRING_FLAGS_*`.
    pub flags: u8,
    /// The glyphs.
    pub glyphs: Vec<Glyph>,
}

impl GlyphString {
    /// Bits of coverage per pixel: 1, 4 or 8.
    pub fn bits_per_pixel(&self) -> u8 {
        if self.flags & string_flags::RASTER_A8 != 0 {
            8
        } else if self.flags & string_flags::RASTER_A4 != 0 {
            4
        } else {
            1
        }
    }
}

/// The most glyphs one `DRAW_TEXT` may carry.
const MAX_GLYPHS: u32 = 16384;

/// Follow the `String *str` member of a `DRAW_TEXT`.
pub fn parse_glyph_string(r: &mut Reader<'_>) -> Result<GlyphString> {
    let Some(offset) = r.pointer()? else {
        return Ok(GlyphString {
            flags: 0,
            glyphs: Vec::new(),
        });
    };
    let mut s = r.at(offset)?;
    let length = s.u16()?;
    let flags = s.u8()?;
    if length as u32 > MAX_GLYPHS {
        return Err(SpiceError::limit(format!(
            "glyph run of {length} exceeds {MAX_GLYPHS}"
        )));
    }
    let bits = if flags & string_flags::RASTER_A8 != 0 {
        8usize
    } else if flags & string_flags::RASTER_A4 != 0 {
        4
    } else {
        1
    };

    // The glyph array is `@ptr_array`: an array of 32-bit offsets.
    let count = s.count(length as u32, 4)?;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        offsets.push(s.u32()? as usize);
    }

    let mut glyphs = Vec::with_capacity(count);
    for offset in offsets {
        let mut g = r.at(offset)?;
        let render_pos = Point::parse(&mut g)?;
        let origin = Point::parse(&mut g)?;
        let width = g.u16()?;
        let height = g.u16()?;
        // `image_size(bits, width, height)`: rows padded to whole bytes.
        let row = (width as usize * bits).div_ceil(8);
        let len = row * height as usize;
        let data = g.bytes(len)?.to_vec();
        glyphs.push(Glyph {
            render_pos,
            origin,
            width,
            height,
            data,
        });
    }
    Ok(GlyphString { flags, glyphs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;

    #[test]
    fn a_rect_reads_top_left_bottom_right_in_that_order() {
        let mut w = Writer::new();
        w.i32(10).i32(20).i32(30).i32(50);
        let body = w.finish();
        let rect = SpiceRect::parse(&mut Reader::new(&body)).unwrap();
        assert_eq!(rect.top, 10);
        assert_eq!(rect.left, 20);
        assert_eq!(rect.width(), 30);
        assert_eq!(rect.height(), 20);
    }

    #[test]
    fn a_rect_clamps_into_the_surface_rather_than_refusing_negatives() {
        let rect = SpiceRect {
            top: -5,
            left: -5,
            bottom: 10,
            right: 10,
        };
        let clamped = rect.clamp_to(8, 8).unwrap();
        assert_eq!(clamped, solstice_backend::Rect::whole(8, 8));

        let outside = SpiceRect {
            top: 100,
            left: 100,
            bottom: 200,
            right: 200,
        };
        assert_eq!(outside.clamp_to(8, 8), None);
    }

    #[test]
    fn an_unclipped_clip_contains_everything() {
        let mut w = Writer::new();
        w.u8(clip_type::NONE);
        let body = w.finish();
        let clip = Clip::parse(&mut Reader::new(&body)).unwrap();
        assert!(clip.contains(-1000, 1000));
        assert_eq!(clip.bounds(), None);
    }

    #[test]
    fn clip_rectangles_are_inline_and_bound_the_command() {
        let mut w = Writer::new();
        w.u8(clip_type::RECTS).u32(2);
        w.i32(0).i32(0).i32(4).i32(4);
        w.i32(8).i32(8).i32(12).i32(12);
        let body = w.finish();
        let clip = Clip::parse(&mut Reader::new(&body)).unwrap();
        assert!(clip.contains(1, 1));
        assert!(!clip.contains(6, 6));
        assert!(clip.contains(9, 9));
        let bounds = clip.bounds().unwrap();
        assert_eq!(bounds.left, 0);
        assert_eq!(bounds.right, 12);
    }

    #[test]
    fn a_clip_count_past_the_body_is_refused_before_allocating() {
        let mut w = Writer::new();
        w.u8(clip_type::RECTS).u32(1000);
        let body = w.finish();
        assert!(Clip::parse(&mut Reader::new(&body)).is_err());
    }

    /// Build a message body holding a raw bitmap at a known offset, with a
    /// pointer to it at the front -- the shape every draw command has.
    fn body_with_raw_bitmap() -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(8); // the pointer, pointing just past itself plus padding
        w.zeros(4);
        // Image at offset 8.
        w.u64(0xAABB); // descriptor.id
        w.u8(image_type::BITMAP).u8(0);
        w.u32(2).u32(2); // descriptor width/height
        w.u8(crate::protocol::bitmap_fmt::BIT32).u8(0);
        w.u32(2).u32(2).u32(8); // bitmap width, height, stride
        w.u32(0); // null palette pointer
        w.bytes(&[0xFF; 16]);
        w.finish()
    }

    #[test]
    fn an_image_is_reached_through_its_pointer_and_its_pixels_stay_in_place() {
        let body = body_with_raw_bitmap();
        let mut r = Reader::new(&body);
        let image = Image::parse_ptr(&mut r).unwrap().unwrap();
        assert_eq!(image.descriptor.id, 0xAABB);
        assert_eq!(image.descriptor.width, 2);
        let ImageBody::Raw(raw) = image.body else {
            panic!("expected a raw bitmap");
        };
        assert_eq!(raw.stride, 8);
        assert_eq!(raw.palette, PaletteRef::None);
        let (offset, len) = raw.data;
        assert_eq!(len, 16);
        assert_eq!(&body[offset..offset + len], &[0xFF; 16]);
    }

    #[test]
    fn a_raw_bitmap_whose_stride_overruns_the_message_is_refused() {
        let mut w = Writer::new();
        w.u64(1).u8(image_type::BITMAP).u8(0).u32(2).u32(2);
        w.u8(crate::protocol::bitmap_fmt::BIT32).u8(0);
        w.u32(2).u32(2).u32(0xFFFF_FFFF);
        w.u32(0);
        let body = w.finish();
        assert!(Image::parse(&mut Reader::new(&body)).is_err());
    }

    #[test]
    fn a_null_image_pointer_is_none_rather_than_an_error() {
        let mut w = Writer::new();
        w.u32(0);
        let body = w.finish();
        let mut r = Reader::new(&body);
        assert_eq!(Image::parse_ptr(&mut r).unwrap(), None);
    }

    #[test]
    fn a_solid_brush_carries_its_colour_inline() {
        let mut w = Writer::new();
        w.u8(brush_type::SOLID).u32(0x00FF8000);
        let body = w.finish();
        assert_eq!(
            Brush::parse(&mut Reader::new(&body)).unwrap(),
            Brush::Solid(0x00FF8000)
        );
    }

    #[test]
    fn a_mask_with_a_null_bitmap_masks_nothing() {
        let mut w = Writer::new();
        w.u8(0).i32(0).i32(0).u32(0);
        let body = w.finish();
        let mask = QMask::parse(&mut Reader::new(&body)).unwrap();
        assert!(mask.bitmap.is_none());
        assert!(!mask.inverted());
    }

    #[test]
    fn a_path_is_an_array_of_pointers_to_segments() {
        let mut w = Writer::new();
        w.u32(4); // pointer to the path
                  // Path at 4: one segment, whose own pointer follows.
        w.u32(1).u32(12);
        // Segment at 12.
        w.u8(path_flags::BEGIN).u32(2);
        w.i32(16).i32(32).i32(48).i32(64);
        let body = w.finish();
        let mut r = Reader::new(&body);
        let path = parse_path(&mut r).unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path[0].points, vec![(1.0, 2.0), (3.0, 4.0)]);
    }

    #[test]
    fn a_glyph_run_pads_each_row_to_a_whole_byte() {
        let mut w = Writer::new();
        w.u32(4); // pointer to the String
                  // String at 4: length 1, A1 raster, then the glyph pointer.
        w.u16(1).u8(string_flags::RASTER_A1).u32(11);
        // Glyph at 11.
        w.i32(5).i32(6).i32(0).i32(0);
        w.u16(9).u16(2); // 9 px wide: two bytes a row
        w.bytes(&[0b1000_0000, 0b1000_0000, 0, 0]);
        let body = w.finish();
        let mut r = Reader::new(&body);
        let string = parse_glyph_string(&mut r).unwrap();
        assert_eq!(string.bits_per_pixel(), 1);
        assert_eq!(string.glyphs.len(), 1);
        assert_eq!(string.glyphs[0].render_pos, Point { x: 5, y: 6 });
        assert_eq!(string.glyphs[0].data.len(), 4);
    }
}
