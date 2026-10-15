//! From a `SpiceImage` to BGRA pixels.
//!
//! `solstice-spice-codec` decodes QUIC, LZ and GLZ, which are the three
//! schemes with no Rust implementation. This module is everything around
//! them: the descriptor that wraps the stream, the palette indexed types
//! index into, the pixmap cache the server expects the client to keep, and
//! the four schemes that *do* have crates -- raw bitmaps, JPEG, LZ4 and
//! zlib-over-GLZ (`docs/spice-protocol.md` §5.1).
//!
//! Everything comes out **top-down BGRA**, which is what
//! `solstice_backend::Framebuffer` wants. SPICE bitmaps are bottom-up unless
//! `SPICE_BITMAP_FLAGS_TOP_DOWN` says otherwise, and so are LZ and GLZ
//! images; the flip happens here rather than in the blitter, so that a cached
//! image is flipped once instead of once per use.
//!
//! # The pixel ceiling
//!
//! `Limits::max_pixels` exists because the cost of a decode is fixed by the
//! header and paid before any of it has been validated. The codec crate's
//! documentation asks the display channel to lower the default to the surface
//! being drawn into, and [`ImageDecoder::decode`] takes that ceiling as an
//! argument for exactly that reason: a bitmap cannot legitimately be larger
//! than the surface it lands on.

use std::collections::HashMap;
use std::sync::Arc;

use solstice_spice_codec::{GlzDecoder, Limits, QuicDecoder};

use crate::display::types::{Image, ImageBody, Palette, PaletteRef, RawBitmap};
use crate::error::{Result, SpiceError};
use crate::protocol::{bitmap_flags, bitmap_fmt};
use crate::wire::Reader;

/// How to read a [`DecodedImage`]'s bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Four bytes per pixel: `b`, `g`, `r`, `a`.
    Bgra8,
    /// One byte per pixel: coverage, as SPICE's A8 surfaces carry it.
    Gray8,
}

impl Format {
    /// Bytes one pixel takes.
    pub const fn bytes_per_pixel(self) -> usize {
        match self {
            Format::Bgra8 => 4,
            Format::Gray8 => 1,
        }
    }
}

/// A decoded bitmap, top-down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedImage {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Layout of [`DecodedImage::data`].
    pub format: Format,
    /// Whether the alpha bytes mean anything.
    pub has_alpha: bool,
    /// Tightly packed rows, top row first.
    pub data: Vec<u8>,
}

impl DecodedImage {
    /// Bytes per row.
    pub fn stride(&self) -> usize {
        self.width as usize * self.format.bytes_per_pixel()
    }

    /// One pixel as BGRA, or `None` outside the image.
    ///
    /// A [`Format::Gray8`] image reads as opaque grey, which is what makes a
    /// QUIC `GRAY` image blittable at all.
    pub fn pixel(&self, x: u32, y: u32) -> Option<[u8; 4]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let offset = y as usize * self.stride() + x as usize * self.format.bytes_per_pixel();
        match self.format {
            Format::Bgra8 => Some([
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ]),
            Format::Gray8 => {
                let v = self.data[offset];
                Some([v, v, v, 0xFF])
            }
        }
    }

    /// Bytes held, for the cache's accounting.
    fn bytes(&self) -> usize {
        self.data.len()
    }
}

/// A 1-bit stencil, unpacked to one byte per pixel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mask {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// One byte per pixel: non-zero where the command draws.
    pub bits: Vec<u8>,
}

impl Mask {
    /// Whether the command draws at this position. Outside the stencil is
    /// "do not draw", which is how SPICE's masks behave at their edges.
    pub fn covers(&self, x: i64, y: i64) -> bool {
        if x < 0 || y < 0 || x >= self.width as i64 || y >= self.height as i64 {
            return false;
        }
        self.bits[y as usize * self.width as usize + x as usize] != 0
    }
}

/// The pixmap cache the server believes the client is keeping.
///
/// `SPICE_IMAGE_FLAGS_CACHE_ME` on an image means "keep this, I will refer to
/// it by id"; `SPICE_IMAGE_TYPE_FROM_CACHE` is that reference. The size is
/// declared to the server in `DISPLAY_INIT`, so the two ends have to agree
/// about it -- but the server's own accounting is in pixels of the *source*
/// image and a client that trusted it would let a server set its memory use.
/// This caps bytes and evicts in insertion order, which is what
/// `spice-server` does with its own copy.
struct PixmapCache {
    images: HashMap<u64, Arc<DecodedImage>>,
    /// Insertion order, for eviction.
    order: std::collections::VecDeque<u64>,
    bytes: usize,
    limit: usize,
}

impl PixmapCache {
    fn new(limit: usize) -> Self {
        PixmapCache {
            images: HashMap::new(),
            order: std::collections::VecDeque::new(),
            bytes: 0,
            limit,
        }
    }

    fn get(&self, id: u64) -> Option<Arc<DecodedImage>> {
        self.images.get(&id).cloned()
    }

    fn insert(&mut self, id: u64, image: Arc<DecodedImage>) {
        if let Some(old) = self.images.remove(&id) {
            self.bytes -= old.bytes();
            self.order.retain(|&k| k != id);
        }
        self.bytes += image.bytes();
        self.images.insert(id, image);
        self.order.push_back(id);
        while self.bytes > self.limit {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(dropped) = self.images.remove(&oldest) {
                self.bytes -= dropped.bytes();
            }
        }
    }

    fn remove(&mut self, id: u64) {
        if let Some(old) = self.images.remove(&id) {
            self.bytes -= old.bytes();
            self.order.retain(|&k| k != id);
        }
    }

    fn clear(&mut self) {
        self.images.clear();
        self.order.clear();
        self.bytes = 0;
    }
}

/// Decodes images for one display channel.
///
/// Stateful on purpose: GLZ's window, the pixmap cache and the palette cache
/// all span the channel's lifetime, and resetting any of them without the
/// others would desynchronise it from the server.
pub struct ImageDecoder {
    quic: QuicDecoder,
    glz: GlzDecoder,
    pixmaps: PixmapCache,
    palettes: HashMap<u64, Palette>,
    limits: Limits,
}

impl ImageDecoder {
    /// A decoder with the given ceilings.
    ///
    /// `pixmap_cache_bytes` is what the client will actually hold; the number
    /// announced to the server in `DISPLAY_INIT` is derived from it so the
    /// two cannot drift.
    pub fn new(limits: Limits, pixmap_cache_bytes: usize) -> Self {
        ImageDecoder {
            quic: QuicDecoder::with_limits(limits),
            glz: GlzDecoder::with_limits(limits),
            pixmaps: PixmapCache::new(pixmap_cache_bytes),
            palettes: HashMap::new(),
            limits,
        }
    }

    /// Forget everything. Correct only on `DISPLAY_RESET`, where the server
    /// forgets too.
    pub fn reset(&mut self) {
        self.glz.reset();
        self.pixmaps.clear();
        self.palettes.clear();
    }

    /// Drop one cached pixmap (`INVAL_LIST`).
    pub fn invalidate_pixmap(&mut self, id: u64) {
        self.pixmaps.remove(id);
    }

    /// Drop every cached pixmap (`INVAL_ALL_PIXMAPS`).
    ///
    /// **The GLZ window does not go with it.** `spice.proto`'s comment on
    /// this message mentions GLZ synchronisation, which reads like an
    /// instruction to clear the window too -- but that would be wrong. The
    /// comment is about the `WAIT_FOR_CHANNELS` list the message carries, so
    /// that a multi-channel client processes the invalidation in the right
    /// order. The reference client clears only the image cache here
    /// (`channel-display.c:1290-1297`) and clears the GLZ window nowhere but
    /// at session connect (`spice-session.c:1675`). Dropping the window the
    /// server still believes in is precisely how an
    /// [`solstice_spice_codec::Error::GlzWindowMiss`] gets manufactured.
    pub fn invalidate_all_pixmaps(&mut self) {
        self.pixmaps.clear();
    }

    /// Drop one cached palette (`INVAL_PALETTE`).
    pub fn invalidate_palette(&mut self, id: u64) {
        self.palettes.remove(&id);
    }

    /// Drop every cached palette (`INVAL_ALL_PALETTES`).
    pub fn invalidate_all_palettes(&mut self) {
        self.palettes.clear();
    }

    /// Put an image into the pixmap cache directly, for tests that need to
    /// observe whether it survives a lifecycle message.
    #[cfg(test)]
    pub fn cache_for_test(&mut self, id: u64, image: DecodedImage) {
        self.pixmaps.insert(id, Arc::new(image));
    }

    /// Whether an id is in the pixmap cache, for tests.
    #[cfg(test)]
    pub fn is_cached_for_test(&self, id: u64) -> bool {
        self.pixmaps.get(id).is_some()
    }

    /// Decode one image, consulting and filling the caches.
    ///
    /// `body` is the whole message the image's offsets are relative to.
    /// `max_pixels` should be the destination surface's pixel count.
    pub fn decode(
        &mut self,
        image: &Image,
        body: &[u8],
        max_pixels: u64,
    ) -> Result<Arc<DecodedImage>> {
        let limits = Limits {
            max_pixels: self.limits.max_pixels.min(max_pixels.max(1)),
            glz_window_bytes: self.limits.glz_window_bytes,
        };

        if matches!(image.body, ImageBody::FromCache) {
            return self.pixmaps.get(image.descriptor.id).ok_or_else(|| {
                SpiceError::protocol(format!(
                    "image {:#x} is not in the pixmap cache",
                    image.descriptor.id
                ))
            });
        }

        let decoded = Arc::new(self.decode_body(image, body, &limits)?);
        if image.descriptor.cache_me() {
            self.pixmaps.insert(image.descriptor.id, decoded.clone());
        }
        Ok(decoded)
    }

    fn decode_body(&mut self, image: &Image, body: &[u8], limits: &Limits) -> Result<DecodedImage> {
        let slice = |offset: usize, len: usize| -> Result<&[u8]> {
            body.get(offset..offset + len).ok_or(SpiceError::Truncated {
                what: "image payload",
                wanted: len,
                available: body.len().saturating_sub(offset),
            })
        };

        match &image.body {
            ImageBody::Raw(raw) => self.decode_raw(raw, body, limits),
            ImageBody::Quic(payload) => {
                let decoded = self.quic.decode(slice(payload.offset, payload.len)?)?;
                Ok(from_codec(decoded))
            }
            ImageBody::LzRgb(payload) => {
                let data = slice(payload.offset, payload.len)?;
                let decoded = if image.descriptor.kind == crate::protocol::image_type::GLZ_RGB {
                    self.glz.decode(data, None)?
                } else {
                    solstice_spice_codec::lz::decode_with_limits(data, None, limits)?
                };
                Ok(from_codec(decoded))
            }
            ImageBody::LzPlt {
                palette, payload, ..
            } => {
                let palette = self.resolve_palette(palette)?;
                let decoded = solstice_spice_codec::lz::decode_with_limits(
                    slice(payload.offset, payload.len)?,
                    palette.as_ref(),
                    limits,
                )?;
                Ok(from_codec(decoded))
            }
            ImageBody::ZlibGlz { glz_size, payload } => {
                let inflated = inflate(slice(payload.offset, payload.len)?, *glz_size)?;
                let decoded = self.glz.decode(&inflated, None)?;
                Ok(from_codec(decoded))
            }
            ImageBody::Jpeg(payload) => decode_jpeg(
                slice(payload.offset, payload.len)?,
                image.descriptor.width,
                image.descriptor.height,
                limits,
            ),
            ImageBody::JpegAlpha {
                jpeg_size, payload, ..
            } => {
                let both = slice(payload.offset, payload.len)?;
                let (jpeg, alpha) = both.split_at(*jpeg_size as usize);
                let mut colour = decode_jpeg(
                    jpeg,
                    image.descriptor.width,
                    image.descriptor.height,
                    limits,
                )?;
                // The alpha plane is an LZ image of type `XXXA`; its alpha
                // bytes are the ones that matter.
                let plane = solstice_spice_codec::lz::decode_with_limits(alpha, None, limits)?;
                apply_alpha_plane(&mut colour, &plane);
                Ok(colour)
            }
            ImageBody::Lz4(payload) => decode_lz4(
                slice(payload.offset, payload.len)?,
                image.descriptor.width,
                image.descriptor.height,
                limits,
            ),
            ImageBody::FromCache => unreachable!("handled by the caller"),
            ImageBody::Surface(id) => Err(SpiceError::protocol(format!(
                "a draw command used surface {id} as an image, which this client does not composite"
            ))),
        }
    }

    /// Resolve a palette reference, caching an inline one on the way through.
    fn resolve_palette(
        &mut self,
        reference: &PaletteRef,
    ) -> Result<Option<solstice_spice_codec::Palette>> {
        match reference {
            PaletteRef::None => Ok(None),
            PaletteRef::Inline(palette) => {
                let codec = palette.to_codec();
                if palette.unique != 0 {
                    self.palettes.insert(palette.unique, palette.clone());
                }
                Ok(Some(codec))
            }
            PaletteRef::Cached(id) => self
                .palettes
                .get(id)
                .map(|p| Some(p.to_codec()))
                .ok_or_else(|| SpiceError::protocol(format!("palette {id:#x} is not cached"))),
        }
    }

    fn decode_raw(
        &mut self,
        raw: &RawBitmap,
        body: &[u8],
        limits: &Limits,
    ) -> Result<DecodedImage> {
        let pixels = raw.width as u64 * raw.height as u64;
        if pixels > limits.max_pixels {
            return Err(SpiceError::limit(format!(
                "raw bitmap of {pixels} pixels exceeds the {} pixel ceiling",
                limits.max_pixels
            )));
        }
        if raw.width == 0 || raw.height == 0 {
            return Err(SpiceError::protocol(format!(
                "raw bitmap of {}x{}",
                raw.width, raw.height
            )));
        }
        let palette = self.resolve_palette(&raw.palette)?;
        let (offset, len) = raw.data;
        let data = body
            .get(offset..offset + len)
            .ok_or(SpiceError::Truncated {
                what: "raw bitmap pixels",
                wanted: len,
                available: body.len().saturating_sub(offset),
            })?;
        convert_raw(raw, data, palette.as_ref())
    }

    /// Decode a `QMask`'s stencil.
    ///
    /// Masks are always 1-bit bitmaps (`canvas_base.c:1399-1470` handles no
    /// other format), and the two formats differ only in bit order within the
    /// byte: `1BIT_LE` is least-significant-bit first, `1BIT_BE` is the other
    /// way, which the C reaches by reversing each byte.
    pub fn decode_mask(&mut self, image: &Image, body: &[u8], max_pixels: u64) -> Result<Mask> {
        let ImageBody::Raw(raw) = &image.body else {
            return Err(SpiceError::protocol("a mask that is not a raw bitmap"));
        };
        let big_endian = match raw.format {
            bitmap_fmt::BIT1_LE => false,
            bitmap_fmt::BIT1_BE => true,
            other => {
                return Err(SpiceError::protocol(format!(
                    "a mask in bitmap format {other}"
                )))
            }
        };
        if raw.width == 0 || raw.height == 0 {
            return Err(SpiceError::protocol(format!(
                "a mask of {}x{}",
                raw.width, raw.height
            )));
        }
        let pixels = raw.width as u64 * raw.height as u64;
        if pixels > max_pixels.max(1) {
            return Err(SpiceError::limit(format!(
                "a mask of {pixels} pixels over a {max_pixels} pixel destination"
            )));
        }
        // A row of a 1-bit bitmap is `width` bits rounded up to a byte. The
        // stride is a `u32` off the wire and may be anything, including
        // zero, so it is checked rather than trusted -- a fuzzer found a
        // zero-stride mask with a non-zero width in under two minutes.
        let needed = (raw.width as usize).div_ceil(8);
        if (raw.stride as usize) < needed {
            return Err(SpiceError::protocol(format!(
                "a mask {} px wide with a stride of {} bytes, which needs {needed}",
                raw.width, raw.stride
            )));
        }

        let (offset, len) = raw.data;
        let data = body
            .get(offset..offset + len)
            .ok_or(SpiceError::Truncated {
                what: "mask pixels",
                wanted: len,
                available: body.len().saturating_sub(offset),
            })?;

        let width = raw.width as usize;
        let height = raw.height as usize;
        let stride = raw.stride as usize;
        if data.len() < stride * height {
            return Err(SpiceError::Truncated {
                what: "mask rows",
                wanted: stride * height,
                available: data.len(),
            });
        }
        let mut bits = vec![0u8; width * height];
        let top_down = raw.flags & bitmap_flags::TOP_DOWN != 0;
        for row in 0..height {
            let source_row = if top_down { row } else { height - 1 - row };
            let line = &data[source_row * stride..source_row * stride + stride];
            for x in 0..width {
                let byte = line[x / 8];
                let bit = if big_endian { 7 - (x % 8) } else { x % 8 };
                bits[row * width + x] = (byte >> bit) & 1;
            }
        }
        Ok(Mask {
            width: raw.width,
            height: raw.height,
            bits,
        })
    }
}

/// Convert a codec-crate image into this module's.
fn from_codec(image: solstice_spice_codec::Image) -> DecodedImage {
    let format = match image.format {
        solstice_spice_codec::PixelFormat::Bgra8 => Format::Bgra8,
        solstice_spice_codec::PixelFormat::Gray8 => Format::Gray8,
    };
    let stride = image.width as usize * format.bytes_per_pixel();
    let data = if image.top_down {
        image.data
    } else {
        flip(&image.data, stride, image.height as usize)
    };
    DecodedImage {
        width: image.width,
        height: image.height,
        format,
        has_alpha: image.has_alpha,
        data,
    }
}

/// Reverse row order in place of the blitter having to walk backwards.
fn flip(data: &[u8], stride: usize, height: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for row in (0..height).rev() {
        let start = row * stride;
        match data.get(start..start + stride) {
            Some(line) => out.extend_from_slice(line),
            // A short buffer cannot happen from the codec crate, which sizes
            // its output from the header; padding keeps this total anyway.
            None => out.resize(out.len() + stride, 0),
        }
    }
    out
}

/// Turn a raw SPICE bitmap into top-down BGRA.
fn convert_raw(
    raw: &RawBitmap,
    data: &[u8],
    palette: Option<&solstice_spice_codec::Palette>,
) -> Result<DecodedImage> {
    let width = raw.width as usize;
    let height = raw.height as usize;
    let stride = raw.stride as usize;
    let top_down = raw.flags & bitmap_flags::TOP_DOWN != 0;

    let (format, has_alpha) = match raw.format {
        bitmap_fmt::BIT8_A => (Format::Gray8, true),
        bitmap_fmt::RGBA => (Format::Bgra8, true),
        _ => (Format::Bgra8, false),
    };
    let out_stride = width * format.bytes_per_pixel();
    let mut out = vec![0u8; out_stride * height];

    let entry = |index: usize| -> Result<[u8; 4]> {
        let palette = palette.ok_or(SpiceError::Image(
            solstice_spice_codec::Error::MissingPalette,
        ))?;
        let value = palette.entries.get(index).copied().ok_or(
            solstice_spice_codec::Error::BadPaletteIndex {
                index: index as u32,
                entries: palette.entries.len() as u32,
            },
        )?;
        Ok(value.to_le_bytes())
    };

    for row in 0..height {
        let source_row = if top_down { row } else { height - 1 - row };
        let line = data
            .get(source_row * stride..source_row * stride + stride)
            .ok_or(SpiceError::Truncated {
                what: "bitmap row",
                wanted: stride,
                available: data.len(),
            })?;
        let dst = &mut out[row * out_stride..row * out_stride + out_stride];

        match raw.format {
            bitmap_fmt::BIT32 | bitmap_fmt::RGBA => {
                let need = width * 4;
                if line.len() < need {
                    return Err(SpiceError::Truncated {
                        what: "32-bit bitmap row",
                        wanted: need,
                        available: line.len(),
                    });
                }
                dst.copy_from_slice(&line[..need]);
            }
            bitmap_fmt::BIT24 => {
                let need = width * 3;
                if line.len() < need {
                    return Err(SpiceError::Truncated {
                        what: "24-bit bitmap row",
                        wanted: need,
                        available: line.len(),
                    });
                }
                for x in 0..width {
                    dst[x * 4] = line[x * 3];
                    dst[x * 4 + 1] = line[x * 3 + 1];
                    dst[x * 4 + 2] = line[x * 3 + 2];
                    dst[x * 4 + 3] = 0;
                }
            }
            bitmap_fmt::BIT16 => {
                let need = width * 2;
                if line.len() < need {
                    return Err(SpiceError::Truncated {
                        what: "16-bit bitmap row",
                        wanted: need,
                        available: line.len(),
                    });
                }
                for x in 0..width {
                    // 0555, little-endian.
                    let v = u16::from_le_bytes([line[x * 2], line[x * 2 + 1]]);
                    let r = ((v >> 10) & 0x1F) as u8;
                    let g = ((v >> 5) & 0x1F) as u8;
                    let b = (v & 0x1F) as u8;
                    // Replicate the top bits into the low ones so white stays
                    // white rather than landing at 248.
                    dst[x * 4] = (b << 3) | (b >> 2);
                    dst[x * 4 + 1] = (g << 3) | (g >> 2);
                    dst[x * 4 + 2] = (r << 3) | (r >> 2);
                    dst[x * 4 + 3] = 0;
                }
            }
            bitmap_fmt::BIT8 => {
                if line.len() < width {
                    return Err(SpiceError::Truncated {
                        what: "8-bit bitmap row",
                        wanted: width,
                        available: line.len(),
                    });
                }
                for x in 0..width {
                    dst[x * 4..x * 4 + 4].copy_from_slice(&entry(line[x] as usize)?);
                }
            }
            bitmap_fmt::BIT8_A => {
                if line.len() < width {
                    return Err(SpiceError::Truncated {
                        what: "alpha bitmap row",
                        wanted: width,
                        available: line.len(),
                    });
                }
                dst.copy_from_slice(&line[..width]);
            }
            bitmap_fmt::BIT4_BE | bitmap_fmt::BIT4_LE => {
                let need = width.div_ceil(2);
                if line.len() < need {
                    return Err(SpiceError::Truncated {
                        what: "4-bit bitmap row",
                        wanted: need,
                        available: line.len(),
                    });
                }
                let high_first = raw.format == bitmap_fmt::BIT4_BE;
                for x in 0..width {
                    let byte = line[x / 2];
                    let high = (x % 2 == 0) == high_first;
                    let index = if high { byte >> 4 } else { byte & 0x0F };
                    dst[x * 4..x * 4 + 4].copy_from_slice(&entry(index as usize)?);
                }
            }
            bitmap_fmt::BIT1_BE | bitmap_fmt::BIT1_LE => {
                let need = width.div_ceil(8);
                if line.len() < need {
                    return Err(SpiceError::Truncated {
                        what: "1-bit bitmap row",
                        wanted: need,
                        available: line.len(),
                    });
                }
                let big_endian = raw.format == bitmap_fmt::BIT1_BE;
                for x in 0..width {
                    let byte = line[x / 8];
                    let bit = if big_endian { 7 - (x % 8) } else { x % 8 };
                    let index = ((byte >> bit) & 1) as usize;
                    dst[x * 4..x * 4 + 4].copy_from_slice(&entry(index)?);
                }
            }
            other => {
                return Err(SpiceError::protocol(format!("bitmap format {other}")));
            }
        }
    }

    Ok(DecodedImage {
        width: raw.width,
        height: raw.height,
        format,
        has_alpha,
        data: out,
    })
}

/// The largest a zlib-over-GLZ stream may inflate to.
///
/// `glz_data_size` is the server's claim about the inflated size, and the
/// inflate is work paid before it can be checked. 256 MB is far past any
/// real image and far short of a denial of service.
const MAX_INFLATED: u32 = 256 * 1024 * 1024;

fn inflate(data: &[u8], expected: u32) -> Result<Vec<u8>> {
    use std::io::Read;

    if expected > MAX_INFLATED {
        return Err(SpiceError::limit(format!(
            "zlib-over-GLZ claims {expected} bytes, past the {MAX_INFLATED} byte ceiling"
        )));
    }
    let mut out = Vec::with_capacity(expected as usize);
    flate2::read::ZlibDecoder::new(data)
        .take(expected as u64)
        .read_to_end(&mut out)
        .map_err(|e| SpiceError::protocol(format!("inflating a zlib-over-GLZ image: {e}")))?;
    if out.len() != expected as usize {
        return Err(SpiceError::protocol(format!(
            "zlib-over-GLZ inflated to {} bytes, not the {expected} claimed",
            out.len()
        )));
    }
    Ok(out)
}

/// Decode a standalone JPEG, for the video-stream path.
///
/// The image path knows the descriptor's dimensions and checks them before
/// handing the bytes to the decoder; a stream frame has only the stream's,
/// so the ceiling is all there is.
pub fn decode_jpeg_frame(data: &[u8], max_pixels: u64) -> Result<DecodedImage> {
    let limits = Limits {
        max_pixels,
        ..Limits::default()
    };
    decode_jpeg(data, 0, 0, &limits)
}

fn decode_jpeg(data: &[u8], width: u32, height: u32, limits: &Limits) -> Result<DecodedImage> {
    let pixels = width as u64 * height as u64;
    if pixels > limits.max_pixels {
        return Err(SpiceError::limit(format!(
            "JPEG of {pixels} pixels exceeds the {} pixel ceiling",
            limits.max_pixels
        )));
    }
    let mut decoder = zune_jpeg::JpegDecoder::new(data);
    decoder
        .decode_headers()
        .map_err(|e| SpiceError::protocol(format!("JPEG header: {e}")))?;
    let info = decoder
        .info()
        .ok_or_else(|| SpiceError::protocol("JPEG with no frame header"))?;
    if info.width as u64 * info.height as u64 > limits.max_pixels {
        return Err(SpiceError::limit(format!(
            "JPEG of {}x{} exceeds the {} pixel ceiling",
            info.width, info.height, limits.max_pixels
        )));
    }
    decoder.set_options(
        zune_jpeg::zune_core::options::DecoderOptions::default()
            .jpeg_set_out_colorspace(zune_jpeg::zune_core::colorspace::ColorSpace::RGB),
    );
    let rgb = decoder
        .decode()
        .map_err(|e| SpiceError::protocol(format!("JPEG: {e}")))?;

    let width = info.width as u32;
    let height = info.height as u32;
    let mut data = vec![0u8; width as usize * height as usize * 4];
    for (pixel, out) in rgb.chunks_exact(3).zip(data.chunks_exact_mut(4)) {
        out[0] = pixel[2];
        out[1] = pixel[1];
        out[2] = pixel[0];
        out[3] = 0;
    }
    Ok(DecodedImage {
        width,
        height,
        format: Format::Bgra8,
        has_alpha: false,
        data,
    })
}

/// Take the alpha channel of an LZ-coded plane onto a decoded JPEG.
fn apply_alpha_plane(colour: &mut DecodedImage, plane: &solstice_spice_codec::Image) {
    colour.has_alpha = true;
    if plane.format != solstice_spice_codec::PixelFormat::Bgra8 {
        return;
    }
    let stride = plane.width as usize * 4;
    for y in 0..colour.height.min(plane.height) as usize {
        // The plane carries its own orientation; the colour image is already
        // top-down.
        let source_row = if plane.top_down {
            y
        } else {
            plane.height as usize - 1 - y
        };
        for x in 0..colour.width.min(plane.width) as usize {
            let from = source_row * stride + x * 4 + 3;
            let to = y * colour.width as usize * 4 + x * 4 + 3;
            if let (Some(&alpha), Some(slot)) = (plane.data.get(from), colour.data.get_mut(to)) {
                *slot = alpha;
            }
        }
    }
}

/// Decode SPICE's LZ4 image.
///
/// Two header bytes -- top-down flag and bitmap format -- then a run of
/// **big-endian length-prefixed LZ4 blocks** that are *linked*: a block may
/// match into the output of the ones before it (`canvas_base.c:570-603`, which
/// uses `LZ4_decompress_safe_continue`). That is the external-dictionary mode
/// of the block format, with the dictionary being everything decoded so far.
fn decode_lz4(data: &[u8], width: u32, height: u32, limits: &Limits) -> Result<DecodedImage> {
    let pixels = width as u64 * height as u64;
    if pixels > limits.max_pixels {
        return Err(SpiceError::limit(format!(
            "LZ4 image of {pixels} pixels exceeds the {} pixel ceiling",
            limits.max_pixels
        )));
    }
    let mut r = Reader::new(data);
    let top_down = r.u8()? != 0;
    let format = r.u8()?;
    let bytes_per_pixel = match format {
        bitmap_fmt::BIT16 => 2,
        bitmap_fmt::BIT24 => 3,
        bitmap_fmt::BIT32 | bitmap_fmt::RGBA => 4,
        other => {
            return Err(SpiceError::protocol(format!(
                "LZ4 image in bitmap format {other}"
            )))
        }
    };
    let stride = width as usize * bytes_per_pixel;
    let total = stride
        .checked_mul(height as usize)
        .ok_or_else(|| SpiceError::limit("LZ4 image larger than memory"))?;

    let mut out: Vec<u8> = Vec::with_capacity(total);
    while !r.is_empty() {
        // The block length is big-endian here and little-endian everywhere
        // else on the connection, because it is LZ4's framing rather than
        // SPICE's.
        let b = r.bytes(4)?;
        let block_len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        let block = r.bytes(block_len)?;
        let room = total - out.len();
        if room == 0 {
            return Err(SpiceError::protocol(
                "LZ4 image has blocks past the end of the image",
            ));
        }
        let mut scratch = vec![0u8; room];
        let written = lz4_flex::block::decompress_into_with_dict(block, &mut scratch, &out)
            .map_err(|e| SpiceError::protocol(format!("LZ4 block: {e}")))?;
        out.extend_from_slice(&scratch[..written]);
    }
    if out.len() != total {
        return Err(SpiceError::protocol(format!(
            "LZ4 image decoded to {} bytes, not the {total} its geometry needs",
            out.len()
        )));
    }

    let raw = RawBitmap {
        format,
        flags: if top_down { bitmap_flags::TOP_DOWN } else { 0 },
        width,
        height,
        stride: stride as u32,
        palette: PaletteRef::None,
        data: (0, total),
    };
    convert_raw(&raw, &out, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display::types::ImageDescriptor;
    use crate::protocol::image_type;

    fn raw_image(format: u8, width: u32, height: u32, stride: u32, flags: u8) -> RawBitmap {
        RawBitmap {
            format,
            flags,
            width,
            height,
            stride,
            palette: PaletteRef::None,
            data: (0, stride as usize * height as usize),
        }
    }

    #[test]
    fn a_32_bit_bitmap_is_already_bgra_and_is_copied_through() {
        let raw = raw_image(bitmap_fmt::BIT32, 2, 1, 8, bitmap_flags::TOP_DOWN);
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        let out = convert_raw(&raw, &data, None).unwrap();
        assert_eq!(out.data, data);
        assert!(!out.has_alpha);
    }

    #[test]
    fn a_bottom_up_bitmap_comes_out_top_down() {
        let raw = raw_image(bitmap_fmt::BIT32, 1, 2, 4, 0);
        let data = [1, 1, 1, 1, 2, 2, 2, 2];
        let out = convert_raw(&raw, &data, None).unwrap();
        assert_eq!(out.data, [2, 2, 2, 2, 1, 1, 1, 1]);
    }

    #[test]
    fn a_24_bit_bitmap_gains_a_fourth_byte() {
        let raw = raw_image(bitmap_fmt::BIT24, 2, 1, 6, bitmap_flags::TOP_DOWN);
        let data = [10, 20, 30, 40, 50, 60];
        let out = convert_raw(&raw, &data, None).unwrap();
        assert_eq!(out.data, [10, 20, 30, 0, 40, 50, 60, 0]);
    }

    #[test]
    fn a_16_bit_555_bitmap_replicates_its_high_bits_so_white_stays_white() {
        let raw = raw_image(bitmap_fmt::BIT16, 1, 1, 2, bitmap_flags::TOP_DOWN);
        let white = 0x7FFFu16.to_le_bytes();
        let out = convert_raw(&raw, &white, None).unwrap();
        assert_eq!(out.data, [0xFF, 0xFF, 0xFF, 0]);
    }

    #[test]
    fn an_indexed_bitmap_needs_its_palette_and_says_so_when_it_is_missing() {
        let raw = raw_image(bitmap_fmt::BIT8, 1, 1, 1, bitmap_flags::TOP_DOWN);
        let err = convert_raw(&raw, &[0], None).unwrap_err();
        assert!(matches!(err, SpiceError::Image(_)), "{err}");
    }

    #[test]
    fn a_one_bit_bitmap_reads_its_bits_in_the_order_the_format_says() {
        let palette = solstice_spice_codec::Palette {
            entries: vec![0x00000000, 0x00FFFFFF],
        };
        let data = [0b1000_0000u8];
        let be = raw_image(bitmap_fmt::BIT1_BE, 2, 1, 1, bitmap_flags::TOP_DOWN);
        let out = convert_raw(&be, &data, Some(&palette)).unwrap();
        assert_eq!(&out.data[0..4], &[0xFF, 0xFF, 0xFF, 0]);
        assert_eq!(&out.data[4..8], &[0, 0, 0, 0]);

        let le = raw_image(bitmap_fmt::BIT1_LE, 2, 1, 1, bitmap_flags::TOP_DOWN);
        let out = convert_raw(&le, &data, Some(&palette)).unwrap();
        assert_eq!(&out.data[0..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn a_four_bit_bitmap_takes_the_high_nibble_first_when_big_endian() {
        let palette = solstice_spice_codec::Palette {
            entries: (0..16).collect(),
        };
        let data = [0x12u8];
        let be = raw_image(bitmap_fmt::BIT4_BE, 2, 1, 1, bitmap_flags::TOP_DOWN);
        let out = convert_raw(&be, &data, Some(&palette)).unwrap();
        assert_eq!(out.data[0], 1);
        assert_eq!(out.data[4], 2);
    }

    #[test]
    fn a_palette_index_past_the_end_is_an_error_not_a_panic() {
        let palette = solstice_spice_codec::Palette {
            entries: vec![0, 1],
        };
        let raw = raw_image(bitmap_fmt::BIT8, 1, 1, 1, bitmap_flags::TOP_DOWN);
        assert!(convert_raw(&raw, &[200], Some(&palette)).is_err());
    }

    #[test]
    fn the_pixmap_cache_evicts_oldest_first_when_it_fills() {
        let mut cache = PixmapCache::new(8);
        let small = |id: u64| {
            Arc::new(DecodedImage {
                width: 1,
                height: 1,
                format: Format::Bgra8,
                has_alpha: false,
                data: vec![id as u8; 4],
            })
        };
        cache.insert(1, small(1));
        cache.insert(2, small(2));
        assert!(cache.get(1).is_some());
        cache.insert(3, small(3));
        assert!(cache.get(1).is_none(), "the oldest should have gone");
        assert!(cache.get(3).is_some());
    }

    #[test]
    fn a_cached_image_comes_back_by_id_and_an_uncached_one_is_an_error() {
        let mut decoder = ImageDecoder::new(Limits::default(), 1 << 20);
        let image = Image {
            descriptor: ImageDescriptor {
                id: 7,
                kind: image_type::FROM_CACHE,
                flags: 0,
                width: 1,
                height: 1,
            },
            body: ImageBody::FromCache,
        };
        assert!(decoder.decode(&image, &[], 16).is_err());

        decoder.pixmaps.insert(
            7,
            Arc::new(DecodedImage {
                width: 1,
                height: 1,
                format: Format::Bgra8,
                has_alpha: false,
                data: vec![1, 2, 3, 4],
            }),
        );
        let got = decoder.decode(&image, &[], 16).unwrap();
        assert_eq!(got.data, [1, 2, 3, 4]);
    }

    #[test]
    fn a_zlib_stream_that_inflates_to_the_wrong_size_is_refused() {
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"hello").unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(inflate(&compressed, 5).is_ok());
        assert!(inflate(&compressed, 6).is_err());
        assert!(inflate(&compressed, MAX_INFLATED + 1).is_err());
    }

    #[test]
    fn an_lz4_image_round_trips_through_a_single_block() {
        let pixels: Vec<u8> = (0..32u8).collect();
        let block = lz4_flex::block::compress(&pixels);
        let mut data = vec![1u8, bitmap_fmt::BIT32];
        data.extend_from_slice(&(block.len() as u32).to_be_bytes());
        data.extend_from_slice(&block);
        let out = decode_lz4(&data, 4, 2, &Limits::default()).unwrap();
        assert_eq!(out.width, 4);
        assert_eq!(out.data, pixels);
    }

    #[test]
    fn lz4_blocks_are_linked_so_a_later_one_may_match_into_an_earlier_one() {
        // This is the property `LZ4_decompress_safe_continue` provides and a
        // plain per-block decode does not. The second block is hand-built so
        // that it *has* to reach into the first one's output:
        //
        //   token 0x07  -> zero literals, match length 4 + 7 = 11
        //   offset 16   -> eleven bytes starting sixteen back, which is in
        //                  the previous block
        //   token 0x50  -> five literals, and the block ends on them, which
        //                  is what the format requires of a last sequence
        let first: Vec<u8> = (0..16u8).collect();
        let first_block = lz4_flex::block::compress(&first);
        let second_block = vec![0x07, 16, 0, 0x50, 100, 101, 102, 103, 104];

        let mut data = vec![1u8, bitmap_fmt::BIT32];
        data.extend_from_slice(&(first_block.len() as u32).to_be_bytes());
        data.extend_from_slice(&first_block);
        data.extend_from_slice(&(second_block.len() as u32).to_be_bytes());
        data.extend_from_slice(&second_block);

        let out = decode_lz4(&data, 2, 4, &Limits::default()).unwrap();
        assert_eq!(&out.data[..16], &first[..]);
        assert_eq!(
            &out.data[16..27],
            &first[..11],
            "the match should have resolved into the previous block"
        );
        assert_eq!(&out.data[27..], &[100, 101, 102, 103, 104]);
    }

    #[test]
    fn an_lz4_image_that_decodes_to_the_wrong_size_is_refused() {
        let block = lz4_flex::block::compress(&[0u8; 8]);
        let mut data = vec![1u8, bitmap_fmt::BIT32];
        data.extend_from_slice(&(block.len() as u32).to_be_bytes());
        data.extend_from_slice(&block);
        assert!(decode_lz4(&data, 4, 2, &Limits::default()).is_err());
    }

    #[test]
    fn a_mask_unpacks_one_byte_per_pixel_and_stops_at_its_edges() {
        let mut decoder = ImageDecoder::new(Limits::default(), 1 << 20);
        let image = Image {
            descriptor: ImageDescriptor {
                id: 0,
                kind: image_type::BITMAP,
                flags: 0,
                width: 2,
                height: 1,
            },
            body: ImageBody::Raw(RawBitmap {
                format: bitmap_fmt::BIT1_BE,
                flags: bitmap_flags::TOP_DOWN,
                width: 2,
                height: 1,
                stride: 1,
                palette: PaletteRef::None,
                data: (0, 1),
            }),
        };
        let mask = decoder
            .decode_mask(&image, &[0b1000_0000], 1 << 20)
            .unwrap();
        assert!(mask.covers(0, 0));
        assert!(!mask.covers(1, 0));
        assert!(!mask.covers(-1, 0));
        assert!(!mask.covers(0, 5));
    }

    #[test]
    fn a_mask_whose_stride_cannot_hold_its_width_is_refused() {
        let mut decoder = ImageDecoder::new(Limits::default(), 1 << 20);
        let image = Image {
            descriptor: ImageDescriptor {
                id: 0,
                kind: image_type::BITMAP,
                flags: 0,
                width: 16,
                height: 1,
            },
            body: ImageBody::Raw(RawBitmap {
                format: bitmap_fmt::BIT1_BE,
                flags: bitmap_flags::TOP_DOWN,
                width: 16,
                height: 1,
                // Zero is legal on the wire and needs two bytes a row.
                stride: 0,
                palette: PaletteRef::None,
                data: (0, 0),
            }),
        };
        let err = decoder.decode_mask(&image, &[], 1 << 20).unwrap_err();
        assert!(matches!(err, SpiceError::Protocol(_)), "{err}");
    }

    #[test]
    fn a_mask_larger_than_the_destination_is_refused_before_allocating() {
        let mut decoder = ImageDecoder::new(Limits::default(), 1 << 20);
        let image = Image {
            descriptor: ImageDescriptor {
                id: 0,
                kind: image_type::BITMAP,
                flags: 0,
                width: 1 << 16,
                height: 1 << 16,
            },
            body: ImageBody::Raw(RawBitmap {
                format: bitmap_fmt::BIT1_BE,
                flags: bitmap_flags::TOP_DOWN,
                width: 1 << 16,
                height: 1 << 16,
                stride: 1 << 13,
                palette: PaletteRef::None,
                data: (0, 0),
            }),
        };
        let err = decoder.decode_mask(&image, &[], 64 * 48).unwrap_err();
        assert!(matches!(err, SpiceError::Limit(_)), "{err}");
    }
}
