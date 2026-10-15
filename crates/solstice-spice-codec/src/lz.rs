//! LZ -- SPICE's pixel-oriented FastLZ derivative.
//!
//! The byte format is FastLZ's: a stream of control bytes, each introducing
//! either a run of literals or a back-reference into what has already been
//! decoded. What SPICE changed is the *unit*. Distances and lengths count
//! **pixels**, not bytes, and a literal is one pixel in the source image's
//! layout, so a 24-bit image spends three bytes per literal and a 1-bit
//! palette image produces eight pixels from one. That is why this cannot be
//! served by an off-the-shelf FastLZ crate, and why the internal `LzFormat`
//! trait has to know both how wide a literal is on the wire and how many
//! pixels it becomes.
//!
//! The header is seven **big-endian** 32-bit fields -- magic, version, type,
//! width, height, stride, top-down -- which is worth flagging because every
//! other integer in SPICE is little-endian.
//!
//! Ported from `common/lz.c` and `common/lz_decompress_tmpl.c`.

use crate::{Error, Image, Limits, Palette, PixelFormat};

/// ASCII `"LZ  "`.
pub(crate) const LZ_MAGIC: u32 = 0x2020_5a4c;
/// Major 1, minor 1.
pub(crate) const LZ_VERSION: u32 = (1 << 16) | 1;
/// Control bytes below this introduce literals, at or above it a match.
pub(crate) const MAX_COPY: u8 = 32;
/// The largest distance expressible without the 16-bit escape.
const MAX_DISTANCE: u32 = 8191;

/// The image types an LZ or GLZ stream can declare, `LzImageType` in
/// `lz_common.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzImageType {
    /// 1 bit per pixel, palette indexed, least-significant bit leftmost.
    Plt1Le,
    /// 1 bit per pixel, palette indexed, most-significant bit leftmost.
    Plt1Be,
    /// 4 bits per pixel, palette indexed, low nibble leftmost.
    Plt4Le,
    /// 4 bits per pixel, palette indexed, high nibble leftmost.
    Plt4Be,
    /// 8 bits per pixel, palette indexed.
    Plt8,
    /// 16 bits per pixel, 5 bits per channel.
    Rgb16,
    /// 24 bits per pixel.
    Rgb24,
    /// 32 bits per pixel, the fourth byte unused.
    Rgb32,
    /// 32 bits per pixel with a separately coded alpha plane.
    Rgba,
    /// 32 bits per pixel of which only the alpha plane is coded.
    Xxxa,
    /// 8 bits of alpha per pixel.
    A8,
}

impl LzImageType {
    pub(crate) fn from_wire(v: u32) -> Result<Self, Error> {
        Ok(match v {
            1 => LzImageType::Plt1Le,
            2 => LzImageType::Plt1Be,
            3 => LzImageType::Plt4Le,
            4 => LzImageType::Plt4Be,
            5 => LzImageType::Plt8,
            6 => LzImageType::Rgb16,
            7 => LzImageType::Rgb24,
            8 => LzImageType::Rgb32,
            9 => LzImageType::Rgba,
            10 => LzImageType::Xxxa,
            11 => LzImageType::A8,
            got => return Err(Error::BadImageType { codec: "LZ", got }),
        })
    }

    /// Whether pixels are palette indices.
    pub(crate) fn is_palette(self) -> bool {
        matches!(
            self,
            LzImageType::Plt1Le
                | LzImageType::Plt1Be
                | LzImageType::Plt4Le
                | LzImageType::Plt4Be
                | LzImageType::Plt8
        )
    }

    /// Pixels per byte of stride, for palette types.
    pub(crate) fn pixels_per_byte(self) -> usize {
        match self {
            LzImageType::Plt1Le | LzImageType::Plt1Be => 8,
            LzImageType::Plt4Le | LzImageType::Plt4Be => 2,
            _ => 1,
        }
    }

    /// Bytes per pixel in the *source* image, for the stride check.
    pub(crate) fn source_bytes_per_pixel(self) -> u32 {
        match self {
            LzImageType::Rgb16 => 2,
            LzImageType::Rgb24 => 3,
            LzImageType::Rgb32 | LzImageType::Rgba | LzImageType::Xxxa => 4,
            _ => 1,
        }
    }

    /// The layout this crate decodes the type into.
    pub(crate) fn output_format(self) -> PixelFormat {
        match self {
            // A8 is an alpha mask, and SPICE uses it as one. Decoding it to
            // black BGRA with the mask in the alpha byte -- which is what the
            // C's A8-to-RGB32 path does -- would quadruple it for nothing.
            LzImageType::A8 => PixelFormat::Gray8,
            _ => PixelFormat::Bgra8,
        }
    }

    pub(crate) fn has_alpha(self) -> bool {
        matches!(
            self,
            LzImageType::Rgba | LzImageType::Xxxa | LzImageType::A8
        )
    }

    /// How many pixels a decoded image holds, which is **not** always
    /// `width * height`.
    ///
    /// A palette row is padded out to a whole number of bytes, so a 5-pixel
    /// wide 1-bit image has a stride of 1 byte and decodes 8 pixels per row.
    /// `out_n_pixels` in `lz_decode_begin`.
    pub(crate) fn gross_pixels(self, stride: u32, width: u32, height: u32) -> u64 {
        if self.is_palette() {
            u64::from(stride) * self.pixels_per_byte() as u64 * u64::from(height)
        } else {
            u64::from(width) * u64::from(height)
        }
    }

    /// Pixels in one decoded row, before cropping to `width`.
    ///
    /// Never less than `width`: [`LzImageType::check_stride`] has already
    /// refused a stride too small to hold the row, which is what lets
    /// [`crop`] slice `width` pixels out of every row without checking.
    pub(crate) fn row_pixels(self, stride: u32, width: u32) -> usize {
        if self.is_palette() {
            stride as usize * self.pixels_per_byte()
        } else {
            width as usize
        }
    }

    /// The only stride a well-formed header can carry for `width` pixels.
    ///
    /// `lz.h` says as much for the palette types -- "stride equals the min
    /// number of bytes to hold a line" -- and the RGB types have no slack at
    /// all.
    ///
    /// In `u64` because it is not: a width the header is otherwise allowed to
    /// claim, times four bytes a pixel, does not fit a `u32`.
    pub(crate) fn natural_stride(self, width: u32) -> u64 {
        if self.is_palette() {
            u64::from(width).div_ceil(self.pixels_per_byte() as u64)
        } else {
            u64::from(width) * u64::from(self.source_bytes_per_pixel())
        }
    }

    /// `lz_set_sizes`: the stride has to agree with the width and the type,
    /// or the pixel count derived from it is a lie.
    ///
    /// Stricter than the C, in the direction the C forgot. `lz_set_sizes`
    /// only rejects a palette stride that is too *large*; one that is too
    /// small passes, and then the decoded rows are narrower than the width
    /// the same header claims. In the C that produces a surface quietly
    /// missing its right-hand edge. Here it would mean reading a `width`-wide
    /// row out of a buffer that only holds `stride * pixels_per_byte` of
    /// them, so it is refused.
    ///
    /// The two bounds together leave exactly one legal value, which is why
    /// this is an equality.
    pub(crate) fn check_stride(self, stride: u32, width: u32) -> Result<(), Error> {
        if u64::from(stride) == self.natural_stride(width) {
            Ok(())
        } else {
            Err(Error::BadStride {
                stride,
                width,
                image_type: self,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Byte reader
// ---------------------------------------------------------------------------

/// A bounds-checked cursor over the compressed bytes.
///
/// Unlike QUIC's reader this one must fail rather than yield zeroes: LZ is a
/// dictionary codec, so the bytes it returns decide *where* the decoder
/// writes, and inventing them would be inventing destinations.
pub(crate) struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        ByteReader { bytes, pos: 0 }
    }

    #[inline]
    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        let b = *self.bytes.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn be_u32(&mut self) -> Result<u32, Error> {
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 8) | u32::from(self.u8()?);
        }
        Ok(v)
    }

    pub(crate) fn be_u64(&mut self) -> Result<u64, Error> {
        Ok((u64::from(self.be_u32()?) << 32) | u64::from(self.be_u32()?))
    }
}

// ---------------------------------------------------------------------------
// Output layouts
// ---------------------------------------------------------------------------

/// How one image type turns stream bytes into output pixels.
///
/// The two length biases differ because LZ and GLZ bias their match lengths
/// differently for the same image type -- LZ subtracts one from the control
/// nibble and adds a type-dependent constant, GLZ does not subtract. Carrying
/// both here keeps the two decode loops able to share everything else.
pub(crate) trait LzFormat {
    /// Pixels one literal unit expands to: 8 for 1-bit, 2 for 4-bit, else 1.
    ///
    /// `CAST_PLT_DISTANCE` in the C, which scales match lengths and distances
    /// by the same factor so they stay in pixels.
    const SCALE: usize;
    /// Added to a match length by the LZ decoder.
    const LZ_LEN_BIAS: u32;
    /// Added to a match length by the GLZ decoder.
    const GLZ_LEN_BIAS: u32;
    /// Read one literal unit and write the [`LzFormat::SCALE`] pixels it
    /// expands to at pixel index `at`.
    fn literal(
        src: &mut ByteReader<'_>,
        out: &mut [u8],
        at: usize,
        palette: Option<&Palette>,
    ) -> Result<(), Error>;

    /// Copy one pixel inside the output buffer.
    ///
    /// Not always a whole pixel: the alpha pass of an RGBA image moves only
    /// the byte it owns, leaving the colour the first pass wrote.
    fn copy_within(out: &mut [u8], dst: usize, src: usize);

    /// Copy one pixel from another image, for a GLZ cross-image match.
    fn copy_from(out: &mut [u8], dst: usize, from: &[u8], src: usize);
}

/// Write a BGRA pixel from a `0x00rrggbb` palette entry.
#[inline]
fn put_palette_entry(out: &mut [u8], at: usize, entry: u32) {
    out[at * 4] = entry as u8;
    out[at * 4 + 1] = (entry >> 8) as u8;
    out[at * 4 + 2] = (entry >> 16) as u8;
    out[at * 4 + 3] = 0;
}

/// The four-byte copies every BGRA format shares.
macro_rules! bgra_copies {
    () => {
        #[inline]
        fn copy_within(out: &mut [u8], dst: usize, src: usize) {
            out.copy_within(src * 4..src * 4 + 4, dst * 4);
        }
        #[inline]
        fn copy_from(out: &mut [u8], dst: usize, from: &[u8], src: usize) {
            out[dst * 4..dst * 4 + 4].copy_from_slice(&from[src * 4..src * 4 + 4]);
        }
    };
}

/// 32-bit colour. Serves source types RGB24, RGB32 and the colour pass of
/// RGBA alike: all three spend three bytes per literal, differing only in a
/// fourth source byte the decoder never reads.
pub(crate) struct Rgb32;

impl LzFormat for Rgb32 {
    const SCALE: usize = 1;
    const LZ_LEN_BIAS: u32 = 1;
    const GLZ_LEN_BIAS: u32 = 0;

    fn literal(
        src: &mut ByteReader<'_>,
        out: &mut [u8],
        at: usize,
        _palette: Option<&Palette>,
    ) -> Result<(), Error> {
        out[at * 4] = src.u8()?; // b
        out[at * 4 + 1] = src.u8()?; // g
        out[at * 4 + 2] = src.u8()?; // r
        out[at * 4 + 3] = 0;
        Ok(())
    }

    bgra_copies!();
}

/// 16-bit colour expanded to BGRA.
///
/// The source pixel arrives most-significant byte first and is
/// `0rrrrrgggggbbbbb`. Each 5-bit channel is widened by replicating its top
/// three bits into the bottom, so 0x1f becomes 0xff rather than 0xf8.
pub(crate) struct Rgb16To32;

impl LzFormat for Rgb16To32 {
    const SCALE: usize = 1;
    const LZ_LEN_BIAS: u32 = 2;
    const GLZ_LEN_BIAS: u32 = 1;

    fn literal(
        src: &mut ByteReader<'_>,
        out: &mut [u8],
        at: usize,
        _palette: Option<&Palette>,
    ) -> Result<(), Error> {
        let hi = src.u8()?;
        let lo = src.u8()?;

        let mut g = ((hi << 6) | (lo >> 2)) & !0x07;
        g |= g >> 5;
        let r = ((hi << 1) & !0x07) | ((hi >> 4) & 0x07);
        let b = (lo << 3) | ((lo >> 2) & 0x07);

        out[at * 4] = b;
        out[at * 4 + 1] = g;
        out[at * 4 + 2] = r;
        out[at * 4 + 3] = 0;
        Ok(())
    }

    bgra_copies!();
}

/// 8-bit palette indices to BGRA.
pub(crate) struct Plt8;

impl LzFormat for Plt8 {
    const SCALE: usize = 1;
    const LZ_LEN_BIAS: u32 = 3;
    const GLZ_LEN_BIAS: u32 = 2;

    fn literal(
        src: &mut ByteReader<'_>,
        out: &mut [u8],
        at: usize,
        palette: Option<&Palette>,
    ) -> Result<(), Error> {
        let palette = palette.ok_or(Error::MissingPalette)?;
        let entry = palette.get(u32::from(src.u8()?))?;
        put_palette_entry(out, at, entry);
        Ok(())
    }

    bgra_copies!();
}

/// Build the two 4-bit and two 1-bit palette formats, which differ only in
/// which end of the byte the leftmost pixel comes from.
macro_rules! palette_format {
    ($name:ident, $scale:literal, $doc:literal, |$byte:ident, $i:ident| $index:expr) => {
        #[doc = $doc]
        pub(crate) struct $name;

        impl LzFormat for $name {
            const SCALE: usize = $scale;
            const LZ_LEN_BIAS: u32 = 3;
            const GLZ_LEN_BIAS: u32 = 2;

            fn literal(
                src: &mut ByteReader<'_>,
                out: &mut [u8],
                at: usize,
                palette: Option<&Palette>,
            ) -> Result<(), Error> {
                let palette = palette.ok_or(Error::MissingPalette)?;
                let $byte = src.u8()?;
                for $i in 0..$scale {
                    let entry = palette.get($index)?;
                    put_palette_entry(out, at + $i, entry);
                }
                Ok(())
            }

            bgra_copies!();
        }
    };
}

palette_format!(
    Plt4Be,
    2,
    "4-bit palette indices, high nibble leftmost.",
    |byte, i| u32::from(if i == 0 { byte >> 4 } else { byte & 0x0f })
);
palette_format!(
    Plt4Le,
    2,
    "4-bit palette indices, low nibble leftmost.",
    |byte, i| u32::from(if i == 0 { byte & 0x0f } else { byte >> 4 })
);
palette_format!(
    Plt1Be,
    8,
    "1-bit palette indices, most-significant bit leftmost.",
    |byte, i| u32::from((byte >> (7 - i)) & 1)
);
palette_format!(
    Plt1Le,
    8,
    "1-bit palette indices, least-significant bit leftmost.",
    |byte, i| u32::from((byte >> i) & 1)
);

/// The alpha pass of an RGBA or XXXA image: one byte per pixel, written into
/// the fourth byte and touching nothing else.
pub(crate) struct AlphaPlane;

impl LzFormat for AlphaPlane {
    const SCALE: usize = 1;
    const LZ_LEN_BIAS: u32 = 3;
    const GLZ_LEN_BIAS: u32 = 2;

    fn literal(
        src: &mut ByteReader<'_>,
        out: &mut [u8],
        at: usize,
        _palette: Option<&Palette>,
    ) -> Result<(), Error> {
        out[at * 4 + 3] = src.u8()?;
        Ok(())
    }

    #[inline]
    fn copy_within(out: &mut [u8], dst: usize, src: usize) {
        out[dst * 4 + 3] = out[src * 4 + 3];
    }
    #[inline]
    fn copy_from(out: &mut [u8], dst: usize, from: &[u8], src: usize) {
        out[dst * 4 + 3] = from[src * 4 + 3];
    }
}

/// An 8-bit alpha mask, decoded as one byte per pixel.
pub(crate) struct A8;

impl LzFormat for A8 {
    const SCALE: usize = 1;
    const LZ_LEN_BIAS: u32 = 3;
    // GLZ has no A8: `DECODE_TO_RGB32` in `decode-glz.c` stops at RGBA.
    const GLZ_LEN_BIAS: u32 = 2;

    fn literal(
        src: &mut ByteReader<'_>,
        out: &mut [u8],
        at: usize,
        _palette: Option<&Palette>,
    ) -> Result<(), Error> {
        out[at] = src.u8()?;
        Ok(())
    }

    #[inline]
    fn copy_within(out: &mut [u8], dst: usize, src: usize) {
        out[dst] = out[src];
    }
    #[inline]
    fn copy_from(out: &mut [u8], dst: usize, from: &[u8], src: usize) {
        out[dst] = from[src];
    }
}

// ---------------------------------------------------------------------------
// The decode loop
// ---------------------------------------------------------------------------

/// Decode one LZ segment into `out`, which holds exactly `size` pixels.
///
/// Returns with `src` positioned after the segment, so an RGBA image can run
/// this twice -- once for colour, once for alpha -- over the same buffer.
///
/// The C asserts the three bounds this checks and compiles the assertions out
/// in release builds, which is how a hostile stream gets to read and write
/// outside the image there.
pub(crate) fn decompress<F: LzFormat>(
    src: &mut ByteReader<'_>,
    out: &mut [u8],
    size: usize,
    palette: Option<&Palette>,
) -> Result<(), Error> {
    let mut at = 0usize;

    while at < size {
        let ctrl = src.u8()?;

        if ctrl >= MAX_COPY {
            let mut len = u32::from(ctrl >> 5) - 1;
            let mut ofs = u32::from(ctrl & 31) << 8;

            if len == 6 {
                // 7 in the control byte means "the length follows".
                loop {
                    let code = src.u8()?;
                    len += u32::from(code);
                    if code != 255 {
                        break;
                    }
                }
            }

            let code = src.u8()?;
            ofs += u32::from(code);

            // A full low nibble plus a 0xff continuation escapes to a
            // 16-bit distance biased by MAX_DISTANCE.
            if code == 255 && (ctrl & 31) == 31 {
                ofs = u32::from(src.u8()?) << 8;
                ofs += u32::from(src.u8()?);
                ofs += MAX_DISTANCE;
            }

            len += F::LZ_LEN_BIAS;
            ofs += 1;

            let len = len as usize * F::SCALE;
            let ofs = ofs as usize * F::SCALE;

            copy_match::<F>(out, at, ofs, len, size)?;
            at += len;
        } else {
            let count = usize::from(ctrl) + 1;
            let pixels = count * F::SCALE;
            if at + pixels > size {
                return Err(Error::OutputOverrun {
                    length: pixels as u64,
                    offset: at as u64,
                    capacity: size as u64,
                });
            }
            for n in 0..count {
                F::literal(src, out, at + n * F::SCALE, palette)?;
            }
            at += pixels;
        }
    }

    Ok(())
}

/// Copy `len` pixels from `ofs` pixels back, one pixel at a time.
///
/// The one-at-a-time loop is not a missed optimisation: when `ofs < len` the
/// match overlaps its own output, and reading each pixel only after the
/// previous one has been written is what turns that into a repeating pattern.
/// It is how LZ encodes runs, and `copy_within` on the whole range would
/// produce something else entirely.
#[inline]
pub(crate) fn copy_match<F: LzFormat>(
    out: &mut [u8],
    at: usize,
    ofs: usize,
    len: usize,
    size: usize,
) -> Result<(), Error> {
    if ofs > at {
        return Err(Error::BadBackReference {
            distance: ofs as u64,
            offset: at as u64,
        });
    }
    if at + len > size {
        return Err(Error::OutputOverrun {
            length: len as u64,
            offset: at as u64,
            capacity: size as u64,
        });
    }
    for n in 0..len {
        F::copy_within(out, at + n, at - ofs + n);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// What an LZ or GLZ header says about the image.
pub(crate) struct LzHeader {
    pub(crate) image_type: LzImageType,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) stride: u32,
    pub(crate) top_down: bool,
    pub(crate) gross_pixels: usize,
}

impl LzHeader {
    pub(crate) fn validate(
        image_type: LzImageType,
        width: u32,
        height: u32,
        stride: u32,
        limits: &Limits,
    ) -> Result<Self, Error> {
        // The C reads these as `int` and rejects negatives, so the top bit
        // being set is a negative dimension there rather than a huge one.
        if width > i32::MAX as u32 || height > i32::MAX as u32 || stride > i32::MAX as u32 {
            return Err(Error::BadSize {
                width: i64::from(width as i32),
                height: i64::from(height as i32),
            });
        }
        image_type.check_stride(stride, width)?;

        // The gross count, not `width * height`: a palette row is padded out
        // to a whole byte, so it is the gross count that is allocated and
        // written. It also bounds the stride, which the C checks separately
        // by comparing a byte count against its pixel ceiling.
        let gross_pixels = image_type.gross_pixels(stride, width, height);
        limits.check_pixels(gross_pixels)?;

        Ok(LzHeader {
            image_type,
            width,
            height,
            stride,
            top_down: false,
            gross_pixels: gross_pixels as usize,
        })
    }
}

/// Decode a complete LZ image with [`Limits::default`].
///
/// `palette` is required for the indexed types and ignored otherwise; the
/// display channel delivers it alongside the image.
pub fn decode(input: &[u8], palette: Option<&Palette>) -> Result<Image, Error> {
    decode_with_limits(input, palette, &Limits::default())
}

/// Decode a complete LZ image, refusing anything past `limits`.
pub fn decode_with_limits(
    input: &[u8],
    palette: Option<&Palette>,
    limits: &Limits,
) -> Result<Image, Error> {
    let mut src = ByteReader::new(input);

    let magic = src.be_u32()?;
    if magic != LZ_MAGIC {
        return Err(Error::BadMagic {
            codec: "LZ",
            expected: LZ_MAGIC,
            got: magic,
        });
    }
    let version = src.be_u32()?;
    if version != LZ_VERSION {
        return Err(Error::BadVersion {
            codec: "LZ",
            expected: LZ_VERSION,
            got: version,
        });
    }

    let image_type = LzImageType::from_wire(src.be_u32()?)?;
    let width = src.be_u32()?;
    let height = src.be_u32()?;
    let stride = src.be_u32()?;
    let mut header = LzHeader::validate(image_type, width, height, stride, limits)?;
    header.top_down = src.be_u32()? != 0;

    let format = image_type.output_format();
    let mut data = vec![0u8; header.gross_pixels * format.bytes_per_pixel()];
    let size = header.gross_pixels;

    match image_type {
        LzImageType::Plt1Le => decompress::<Plt1Le>(&mut src, &mut data, size, palette)?,
        LzImageType::Plt1Be => decompress::<Plt1Be>(&mut src, &mut data, size, palette)?,
        LzImageType::Plt4Le => decompress::<Plt4Le>(&mut src, &mut data, size, palette)?,
        LzImageType::Plt4Be => decompress::<Plt4Be>(&mut src, &mut data, size, palette)?,
        LzImageType::Plt8 => decompress::<Plt8>(&mut src, &mut data, size, palette)?,
        LzImageType::Rgb16 => decompress::<Rgb16To32>(&mut src, &mut data, size, palette)?,
        LzImageType::Rgb24 | LzImageType::Rgb32 => {
            decompress::<Rgb32>(&mut src, &mut data, size, palette)?
        }
        LzImageType::Rgba => {
            // Colour first, then a second complete pass for alpha. Unlike
            // QUIC's RGBA the two do not interleave by row.
            decompress::<Rgb32>(&mut src, &mut data, size, palette)?;
            decompress::<AlphaPlane>(&mut src, &mut data, size, palette)?;
        }
        LzImageType::Xxxa => {
            // Only the alpha plane is coded; the colour bytes stay zero,
            // where the C leaves whatever was in its buffer.
            decompress::<AlphaPlane>(&mut src, &mut data, size, palette)?;
        }
        LzImageType::A8 => decompress::<A8>(&mut src, &mut data, size, palette)?,
    }

    Ok(crop(header, format, data))
}

/// Trim the row padding a palette image decodes with.
///
/// A palette row is a whole number of bytes, so a 5-pixel wide 1-bit image
/// decodes 8 pixels per row. The caller wants rows of `width`.
pub(crate) fn crop(header: LzHeader, format: PixelFormat, data: Vec<u8>) -> Image {
    let bpp = format.bytes_per_pixel();
    let row_pixels = header.image_type.row_pixels(header.stride, header.width);
    let width = header.width as usize;

    let data = if row_pixels == width {
        data
    } else {
        let mut cropped = Vec::with_capacity(width * bpp * header.height as usize);
        for row in 0..header.height as usize {
            let start = row * row_pixels * bpp;
            cropped.extend_from_slice(&data[start..start + width * bpp]);
        }
        cropped
    };

    Image {
        format,
        width: header.width,
        height: header.height,
        has_alpha: header.image_type.has_alpha(),
        top_down: header.top_down,
        data,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::Limits;

    /// Build an LZ header: seven big-endian words, unlike everything else in
    /// SPICE.
    pub(crate) fn header(image_type: u32, width: u32, height: u32, stride: u32) -> Vec<u8> {
        let mut out = Vec::new();
        for word in [
            LZ_MAGIC, LZ_VERSION, image_type, width, height, stride, 1, // top_down
        ] {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// A 4x1 BGRA image, the smallest thing with room for a match.
    fn rgb32_header() -> Vec<u8> {
        header(8, 4, 1, 16)
    }

    #[test]
    fn a_stream_without_the_magic_is_refused() {
        let mut input = rgb32_header();
        input[0] ^= 0xff;
        assert!(matches!(
            decode(&input, None),
            Err(Error::BadMagic { codec: "LZ", .. })
        ));
    }

    #[test]
    fn a_future_version_is_refused() {
        let mut input = rgb32_header();
        input[4..8].copy_from_slice(&((2u32 << 16) | 1).to_be_bytes());
        assert!(matches!(
            decode(&input, None),
            Err(Error::BadVersion { codec: "LZ", .. })
        ));
    }

    #[test]
    fn an_undefined_image_type_is_refused() {
        for bad in [0u32, 12, 0xffff_ffff] {
            let input = header(bad, 4, 1, 16);
            assert!(
                matches!(decode(&input, None), Err(Error::BadImageType { .. })),
                "type {bad} should be refused"
            );
        }
    }

    /// The stride is what the pixel count is derived from, so a stride that
    /// disagrees with the width is a header that lies about how big the image
    /// is.
    #[test]
    fn a_stride_that_disagrees_with_the_width_is_refused() {
        // RGB32 at 4 px wide must be 16 bytes, not 12 or 20.
        for stride in [0u32, 12, 20, 0xffff] {
            let input = header(8, 4, 1, stride);
            assert!(
                matches!(decode(&input, None), Err(Error::BadStride { .. })),
                "stride {stride} should be refused for a 4 px RGB32 row"
            );
        }
    }

    /// The first instruction cannot be a match: there is nothing behind the
    /// cursor to match against. The C asserts this and compiles the assertion
    /// out, then reads before the start of its buffer.
    #[test]
    fn a_back_reference_before_the_start_of_the_image_is_refused() {
        let mut input = rgb32_header();
        input.extend_from_slice(&[0x20, 0x00]); // match, length 1, distance 1
        assert!(matches!(
            decode(&input, None),
            Err(Error::BadBackReference {
                distance: 1,
                offset: 0
            })
        ));
    }

    /// A literal run longer than the image is the other half of the same
    /// problem, on the write side.
    #[test]
    fn a_literal_run_past_the_end_of_the_image_is_refused() {
        let mut input = rgb32_header();
        input.push(0x1f); // 32 literal pixels into a 4 pixel image
        input.extend_from_slice(&[0u8; 96]);
        assert!(matches!(
            decode(&input, None),
            Err(Error::OutputOverrun {
                length: 32,
                offset: 0,
                capacity: 4
            })
        ));
    }

    /// And a match that starts inside the image but runs off the end.
    #[test]
    fn a_match_past_the_end_of_the_image_is_refused() {
        let mut input = rgb32_header();
        input.push(0x00); // one literal
        input.extend_from_slice(&[1, 2, 3]);
        // Match of length 7: (7 >> 5 == 0 is not a match, so use len nibble 7)
        input.push(0xe0); // ctrl = 0b111_00000: len nibble 7 -> long length
        input.push(0x00); // length continuation: len = 6 + 0
        input.push(0x00); // distance low byte
        assert!(matches!(
            decode(&input, None),
            Err(Error::OutputOverrun { .. })
        ));
    }

    #[test]
    fn a_stream_that_ends_mid_instruction_is_truncated() {
        for tail in [
            vec![],
            vec![0x00],
            vec![0x00, 1],
            vec![0x00, 1, 2],
            vec![0x20],
        ] {
            let mut input = rgb32_header();
            input.extend_from_slice(&tail);
            assert_eq!(decode(&input, None), Err(Error::Truncated), "tail {tail:?}");
        }
    }

    /// The same ceiling applies to LZ, and for a palette image it has to be
    /// applied to the *gross* pixel count -- the one that includes row
    /// padding -- because that is what gets allocated.
    #[test]
    fn an_image_past_the_pixel_ceiling_is_refused() {
        let limits = Limits {
            max_pixels: 64,
            ..Limits::default()
        };
        // 100 x 1 RGB32: 100 pixels.
        let input = header(8, 100, 1, 400);
        assert_eq!(
            decode_with_limits(&input, None, &limits),
            Err(Error::TooLarge {
                pixels: 100,
                limit: 64
            })
        );

        // 65 x 1 PLT1: 9 bytes of stride, so 72 gross pixels for 65 of width.
        let input = header(1, 65, 1, 9);
        assert!(matches!(
            decode_with_limits(&input, None, &limits),
            Err(Error::TooLarge { pixels: 72, .. }),
        ));
    }

    /// A palette stride too small to hold its own row. The C accepts this --
    /// its check is one-sided -- and it leaves the decoded rows narrower than
    /// the width the same header claims, which is a buffer overrun on the way
    /// out rather than on the way in.
    #[test]
    fn a_palette_stride_too_small_for_its_own_row_is_refused() {
        // PLT1_LE, 16 px wide: a row needs 2 bytes, not 1.
        let input = header(1, 16, 1, 1);
        assert_eq!(
            decode(&input, None),
            Err(Error::BadStride {
                stride: 1,
                width: 16,
                image_type: LzImageType::Plt1Le,
            })
        );

        // And the stride that does hold it is accepted.
        let mut ok = header(1, 16, 1, 2);
        ok.push(0x01);
        ok.extend_from_slice(&[0x00, 0x00]);
        let palette = Palette {
            entries: vec![0x0000_0000, 0x00ff_ffff],
        };
        let image = decode(&ok, Some(&palette)).expect("decodes");
        assert_eq!(image.data.len(), 16 * 4);
    }

    /// A width the header may legally claim, times four bytes a pixel, does
    /// not fit a `u32` -- and the stride check is the first thing to compute
    /// that product. Found by `cargo fuzz run spice_lz` in under a minute.
    #[test]
    fn a_width_whose_natural_stride_overflows_is_refused_not_wrapped() {
        // Both widths need a stride past 2^32, so no `u32` stride can match.
        for width in [0x4000_0000u32, 0x7fff_ffff] {
            for stride in [0u32, 4, width, 0x7fff_ffff] {
                let input = header(8, width, 1, stride); // RGB32, 4 bytes a px
                assert!(
                    matches!(decode(&input, None), Err(Error::BadStride { .. })),
                    "{width} x 1 with stride {stride} should be refused"
                );
            }
        }

        // A stride past `i32::MAX` is a negative stride to the C, and is
        // refused one step earlier as a bad size.
        let input = header(8, 4, 1, 0xffff_ffff);
        assert!(matches!(decode(&input, None), Err(Error::BadSize { .. })));
    }

    /// The same, one byte over: a palette row padded past the minimum is a
    /// header the pixel count cannot be derived from either.
    #[test]
    fn a_palette_stride_larger_than_the_minimum_is_refused() {
        for stride in [3u32, 4, 100] {
            assert!(
                matches!(
                    decode(&header(1, 16, 1, stride), None),
                    Err(Error::BadStride { .. })
                ),
                "stride {stride} should be refused for a 16 px 1-bit row"
            );
        }
    }

    #[test]
    fn a_palette_image_without_a_palette_is_refused() {
        let mut input = header(5, 4, 1, 4); // PLT8
        input.push(0x00);
        input.push(0x00);
        assert_eq!(decode(&input, None), Err(Error::MissingPalette));
    }

    /// The C takes `index % num_ents` for the 4- and 1-bit types and indexes
    /// unchecked for 8-bit, which reads past the end of a short palette.
    #[test]
    fn a_palette_index_past_the_end_is_refused_rather_than_wrapped() {
        let mut input = header(5, 4, 1, 4); // PLT8
        input.push(0x00); // one literal
        input.push(9); // index 9 into a 2-entry palette
        let palette = Palette {
            entries: vec![0x00ff_0000, 0x0000_00ff],
        };
        assert_eq!(
            decode(&input, Some(&palette)),
            Err(Error::BadPaletteIndex {
                index: 9,
                entries: 2
            })
        );
    }

    /// A palette row is padded out to a whole byte, so a 5-pixel 1-bit image
    /// decodes 8 pixels per row and the padding has to be trimmed off.
    #[test]
    fn a_palette_row_is_cropped_back_to_the_images_width() {
        // 5 px wide, 1 bit per pixel: stride 1 byte, 8 decoded pixels a row.
        let mut input = header(1, 5, 2, 1); // PLT1_LE
        input.push(0x01); // two literal bytes, one per row
        input.push(0b0000_0001);
        input.push(0b1111_1110);
        let palette = Palette {
            entries: vec![0x0000_0000, 0x00ff_ffff],
        };
        let image = decode(&input, Some(&palette)).expect("decodes");

        assert_eq!(image.width, 5);
        assert_eq!(image.height, 2);
        assert_eq!(image.data.len(), 5 * 2 * 4, "rows must be trimmed to 5 px");
        // Least-significant bit leftmost: 0b0000_0001 is one set pixel first.
        assert_eq!(&image.data[0..4], &[0xff, 0xff, 0xff, 0x00]);
        assert_eq!(&image.data[4..8], &[0x00, 0x00, 0x00, 0x00]);
        // Second row, bits 1..5 of 0b1111_1110 are all set, bit 0 is not.
        assert_eq!(&image.data[20..24], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&image.data[24..28], &[0xff, 0xff, 0xff, 0x00]);
    }

    /// A match whose distance is shorter than its length overlaps its own
    /// output. Copying the range in one go would repeat the source instead of
    /// the pattern, which is how LZ encodes runs.
    #[test]
    fn an_overlapping_match_repeats_the_pattern_rather_than_the_source() {
        let mut input = header(8, 6, 1, 24);
        input.push(0x01); // two literals
        input.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        // Match: length nibble 4 -> len = 4 - 1 + 1 = 4, distance 2.
        input.push(0x80);
        input.push(0x01); // distance byte: ofs = 1, +1 bias = 2
        let image = decode(&input, None).expect("decodes");

        let px: Vec<&[u8]> = image.data.chunks(4).collect();
        assert_eq!(px[0], [1, 2, 3, 0]);
        assert_eq!(px[1], [4, 5, 6, 0]);
        assert_eq!(px[2], [1, 2, 3, 0], "the pattern must repeat");
        assert_eq!(px[3], [4, 5, 6, 0]);
        assert_eq!(px[4], [1, 2, 3, 0]);
        assert_eq!(px[5], [4, 5, 6, 0]);
    }

    /// Totality, as for QUIC: a well-formed header followed by anything at
    /// all must come back as pixels or as an error.
    #[test]
    fn a_valid_header_followed_by_garbage_never_panics() {
        let mut state = 0x2545_f491u32;
        let palette = Palette {
            entries: (0..256).map(|i| i * 0x0001_0101).collect(),
        };

        for image_type in 1..=11u32 {
            let width = 13u32;
            let stride = LzImageType::from_wire(image_type)
                .unwrap()
                .natural_stride(width) as u32;

            for _ in 0..64 {
                let mut input = header(image_type, width, 5, stride);
                for _ in 0..200 {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    input.extend_from_slice(&state.to_be_bytes());
                }
                let _ = decode(&input, Some(&palette));
            }
        }
    }
}
